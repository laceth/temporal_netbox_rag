"""NetOps intent LLM — provider abstraction (OpenAI ⇄ Bedrock DeepSeek-R1).

The NetBox-RAG turns a natural-language network intent into a structured
``emit_intent`` JSON ({intent, entities, dry_run}). This module makes the model
behind that step pluggable:

  NETBOX_RAG_PROVIDER = openai | bedrock_deepseek      (default: openai)

…with an **availability-aware fallback chain** (the non-primary provider is tried
only when its credentials are present), mirroring TestPulse's own
``TESTPULSE_ML_ROUTING_MODE`` so the config-planner and the AAA-triage engine can
share one reasoning backbone (your AWS Bedrock account, ``us.deepseek.r1-v1:0``).

Task split (latency vs reasoning):
  • task="parse"  → fast/cheap model (NETBOX_RAG_PARSE_MODEL). Interactive hot path.
  • task="plan"   → reasoning model  (NETBOX_RAG_PLAN_MODEL, default DeepSeek-R1).

Both providers expose the SAME stateless ``emit_intent(text, task)`` contract — no
OpenAI-Assistants threads required — so swapping providers is a config flip, never
a caller rewrite. Every call degrades gracefully: a provider that errors or lacks
credentials raises ``ProviderUnavailable`` and the chain falls through; only when
ALL providers fail does ``emit_intent`` raise.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

log = logging.getLogger(__name__)

# The structured intent contract (shared by every provider). Kept identical to the
# legacy OpenAI-Assistants function schema so downstream consumers are unaffected.
EMIT_INTENT_SCHEMA: dict[str, Any] = {
    "name": "emit_intent",
    "description": "Emit a structured NetOps intent JSON for switch/router bootstrap or config change.",
    "parameters": {
        "type": "object",
        "properties": {
            "intent": {"type": "string"},
            "entities": {"type": "object", "additionalProperties": True},
            "dry_run": {"type": "boolean", "default": True},
        },
        "required": ["intent", "entities"],
    },
}

_SYSTEM_PROMPT = (
    "You are a NetOps NLU engine. Read the user's request and return ONLY a single "
    "JSON object matching this schema: "
    '{"intent": string, "entities": object, "dry_run": boolean}. '
    "Expand VLAN ranges like 37-40 into [37,38,39,40]. Do not write prose, do not "
    "wrap the JSON in markdown fences — emit the raw JSON object and nothing else."
)

_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_JSON_OBJ = re.compile(r"\{.*\}", re.DOTALL)


class ProviderUnavailable(Exception):
    """Raised when a provider cannot serve a request (no creds, SDK, or API error)."""

    def __init__(self, provider: str, reason: str):
        self.provider = provider
        self.reason = reason
        super().__init__(f"{provider}: {reason}")


@dataclass
class IntentResult:
    """Normalized result of a provider intent parse."""

    emitted: dict[str, Any]            # {intent, entities, dry_run}
    provider: str
    model: str
    raw: str = ""
    fallback_used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "emitted": self.emitted,
            "provider": self.provider,
            "model": self.model,
            "fallback_used": self.fallback_used,
        }


def _extract_intent_json(text: str) -> dict[str, Any]:
    """Pull the emit_intent JSON object out of a free-text completion.

    Strips any DeepSeek-R1 ``<think>`` block, then takes the first/largest JSON
    object. Raises ValueError when nothing parseable + schema-valid is present.
    """
    cleaned = _THINK_BLOCK.sub("", text or "").strip()
    candidates: list[str] = []
    if cleaned.startswith("{"):
        candidates.append(cleaned)
    m = _JSON_OBJ.search(cleaned)
    if m:
        candidates.append(m.group(0))
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "intent" in obj:
            obj.setdefault("entities", {})
            obj.setdefault("dry_run", True)
            return obj
    raise ValueError(f"no schema-valid emit_intent JSON in completion: {cleaned[:200]!r}")


class LLMProvider(Protocol):
    name: str

    def available(self) -> bool: ...
    def emit_intent(self, text: str, task: str = "parse") -> IntentResult: ...


# ── OpenAI (chat-completions + function calling — stateless, no Assistants) ───
class OpenAIProvider:
    name = "openai"

    def __init__(self) -> None:
        self._client = None

    def _model(self, task: str) -> str:
        if task == "plan":
            return os.environ.get("NETBOX_RAG_PLAN_MODEL_OPENAI", os.environ.get("INTENT_ASSISTANT_MODEL", "gpt-4o"))
        return os.environ.get("NETBOX_RAG_PARSE_MODEL_OPENAI", os.environ.get("INTENT_ASSISTANT_MODEL", "gpt-4o-mini"))

    def available(self) -> bool:
        if not os.environ.get("OPENAI_API_KEY"):
            return False
        try:
            import openai  # noqa: F401
            return True
        except ImportError:
            return False

    def _oai(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        return self._client

    def emit_intent(self, text: str, task: str = "parse") -> IntentResult:
        model = self._model(task)
        try:
            resp = self._oai().chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": text},
                ],
                tools=[{"type": "function", "function": EMIT_INTENT_SCHEMA}],
                tool_choice={"type": "function", "function": {"name": "emit_intent"}},
                temperature=0.1,
            )
        except Exception as exc:  # noqa: BLE001
            raise ProviderUnavailable(self.name, str(exc)) from exc

        msg = resp.choices[0].message
        raw = ""
        if msg.tool_calls:
            raw = msg.tool_calls[0].function.arguments or ""
        elif msg.content:
            raw = msg.content
        try:
            emitted = _extract_intent_json(raw)
        except ValueError as exc:
            raise ProviderUnavailable(self.name, f"unparseable output: {exc}") from exc
        return IntentResult(emitted=emitted, provider=self.name, model=model, raw=raw)


# ── AWS Bedrock DeepSeek-R1 (Converse API — serverless, your AWS account) ─────
class BedrockDeepSeekProvider:
    name = "bedrock_deepseek"
    # Bare DeepSeek ids have no on-demand throughput — route via the us. cross-region
    # inference profile (the live-verified TestPulse default).
    _DEFAULT_MODEL = "us.deepseek.r1-v1:0"
    _ONDEMAND_IDS = ("deepseek.r1-v1:0", "deepseek.deepseek-r1-v1:0")

    def _model(self, task: str) -> str:
        if task == "plan":
            mid = os.environ.get("NETBOX_RAG_PLAN_MODEL", self._DEFAULT_MODEL)
        else:
            # Parse is latency-sensitive: allow a faster model (e.g. DeepSeek-V3)
            # via NETBOX_RAG_PARSE_MODEL; default to R1 if not configured.
            mid = os.environ.get("NETBOX_RAG_PARSE_MODEL", self._DEFAULT_MODEL)
        return self._DEFAULT_MODEL if mid in self._ONDEMAND_IDS else mid

    def _region(self) -> str:
        return (os.environ.get("NETBOX_RAG_AWS_REGION")
                or os.environ.get("AWS_DEFAULT_REGION")
                or os.environ.get("AWS_REGION") or "us-east-1")

    def available(self) -> bool:
        if not (os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE")):
            return False
        try:
            import boto3  # noqa: F401
            return True
        except ImportError:
            return False

    def emit_intent(self, text: str, task: str = "parse") -> IntentResult:
        try:
            import boto3  # type: ignore[import]
        except ImportError:
            raise ProviderUnavailable(self.name, "boto3 not installed")

        model_id = self._model(task)
        # DeepSeek-R1 on Bedrock rejects a `system` field — fold it into the user turn.
        prompt = f"{_SYSTEM_PROMPT}\n\nRequest: {text}"
        # Parse caps reasoning to keep latency down; plan gives R1 room to reason.
        max_tokens = 1024 if task == "parse" else 4096
        try:
            client = boto3.client("bedrock-runtime", region_name=self._region())
            resp = client.converse(
                modelId=model_id,
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={"maxTokens": max_tokens, "temperature": 0.1, "topP": 0.9},
            )
        except Exception as exc:  # noqa: BLE001
            raise ProviderUnavailable(self.name, str(exc)) from exc

        blocks = resp.get("output", {}).get("message", {}).get("content", [])
        raw = "\n".join(b["text"] for b in blocks if "text" in b)
        try:
            emitted = _extract_intent_json(raw)
        except ValueError as exc:
            raise ProviderUnavailable(self.name, f"unparseable output: {exc}") from exc
        return IntentResult(emitted=emitted, provider=self.name, model=model_id, raw=raw)


_REGISTRY: dict[str, type] = {
    OpenAIProvider.name: OpenAIProvider,
    BedrockDeepSeekProvider.name: BedrockDeepSeekProvider,
}


def _chain() -> list[str]:
    """Provider preference order from NETBOX_RAG_PROVIDER, with the other as fallback."""
    primary = os.environ.get("NETBOX_RAG_PROVIDER", "openai").strip().lower()
    if primary not in _REGISTRY:
        primary = "openai"
    order = [primary] + [p for p in _REGISTRY if p != primary]
    return order


@dataclass
class _ChainProvider:
    """Tries each available provider in order; falls through on ProviderUnavailable."""

    order: list[str] = field(default_factory=_chain)

    def emit_intent(self, text: str, task: str = "parse") -> IntentResult:
        errors: list[str] = []
        first = True
        for pname in self.order:
            prov = _REGISTRY[pname]()
            if not prov.available():
                errors.append(f"{pname}: unavailable (no creds/SDK)")
                first = False
                continue
            try:
                result = prov.emit_intent(text, task=task)
                result.fallback_used = not first
                return result
            except ProviderUnavailable as exc:
                errors.append(str(exc))
                first = False
        raise ProviderUnavailable("chain", f"all providers failed: {'; '.join(errors)}")


def get_provider() -> _ChainProvider:
    """Return the configured intent-LLM provider chain (primary + fallback)."""
    return _ChainProvider()


def active_provider_info() -> dict[str, Any]:
    """Introspection for ops/UI: configured order + which are currently available."""
    order = _chain()
    avail = {p: _REGISTRY[p]().available() for p in order}
    active = next((p for p in order if avail[p]), None)
    return {
        "configured": os.environ.get("NETBOX_RAG_PROVIDER", "openai"),
        "order": order,
        "available": avail,
        "active": active,
        "models": {
            "parse": os.environ.get("NETBOX_RAG_PARSE_MODEL", "(provider default)"),
            "plan": os.environ.get("NETBOX_RAG_PLAN_MODEL", "(provider default)"),
        },
    }
