"""NetOps intent LLM router — provider-abstracted (OpenAI ⇄ Bedrock DeepSeek-R1).

`/intent/llm/parse` now routes through the pluggable provider chain
(`server.llm.provider`): pick the model with `NETBOX_RAG_PROVIDER`, with the other
provider as an availability-aware fallback. The legacy OpenAI-Assistants
(threads/function-call) flow is preserved at `/intent/llm/parse_assistant` for
back-compat. `/intent/llm/provider` reports the active provider + availability.
"""
import json, os, time
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from ..llm import EMIT_INTENT_SCHEMA, ProviderUnavailable, active_provider_info, get_provider

load_dotenv()

router = APIRouter(prefix="/intent/llm", tags=["intent-llm"])

INTENT_ASSISTANT_NAME = os.environ.get("INTENT_ASSISTANT_NAME", "NetOps Intent LLM")
INTENT_ASSISTANT_MODEL = os.environ.get("INTENT_ASSISTANT_MODEL", "gpt-4o-mini")


# ── Provider-abstracted parse (default path) ─────────────────────────────────
class LLMParseIn(BaseModel):
    text: str
    task: str = "parse"                 # "parse" (fast) | "plan" (reasoning)
    thread_id: Optional[str] = None     # only meaningful for the legacy assistant path


class LLMParseOut(BaseModel):
    status: str
    emitted: Optional[Dict[str, Any]] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    fallback_used: bool = False
    # Legacy OpenAI-Assistants fields (present only on /parse_assistant):
    assistant_id: Optional[str] = None
    thread_id: Optional[str] = None
    run_id: Optional[str] = None
    tool_call_id: Optional[str] = None
    assistant_message_id: Optional[str] = None


@router.get("/provider")
def provider_info() -> Dict[str, Any]:
    """Which intent-LLM provider is configured + currently available (ops/UI)."""
    return active_provider_info()


@router.post("/parse", response_model=LLMParseOut)
def llm_parse(payload: LLMParseIn):
    """Parse a NetOps intent into structured emit_intent JSON via the provider chain.

    503 only when EVERY configured provider is unavailable/failing.
    """
    try:
        result = get_provider().emit_intent(payload.text, task=payload.task)
    except ProviderUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"intent LLM unavailable — {exc}")
    return LLMParseOut(
        status="completed",
        emitted=result.emitted,
        provider=result.provider,
        model=result.model,
        fallback_used=result.fallback_used,
        thread_id=payload.thread_id,
    )


# ── Legacy OpenAI-Assistants flow (stateful threads) — preserved ──────────────
_client = None


def _oai():
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    return _client


def ensure_intent_assistant() -> str:
    page = _oai().beta.assistants.list(order="desc", limit=20)
    for a in page.data:
        if a.name == INTENT_ASSISTANT_NAME:
            has_fn = any(
                (getattr(t, "type", None) == "function"
                 and getattr(getattr(t, "function", None), "name", None) == "emit_intent")
                for t in (a.tools or [])
            )
            if not has_fn:
                a = _oai().beta.assistants.update(
                    assistant_id=a.id,
                    model=INTENT_ASSISTANT_MODEL,
                    tools=[{"type": "function", "function": EMIT_INTENT_SCHEMA}],
                )
            return a.id
    a = _oai().beta.assistants.create(
        name=INTENT_ASSISTANT_NAME,
        model=INTENT_ASSISTANT_MODEL,
        instructions=(
            "You are a NetOps NLU assistant. Read the user's request and call the emit_intent function exactly once "
            "with a normalized JSON. Expand VLAN ranges like 37-40. Do not write prose; only call the function."
        ),
        tools=[{"type": "function", "function": EMIT_INTENT_SCHEMA}],
    )
    return a.id


def poll(thread_id: str, run_id: str):
    while True:
        r = _oai().beta.threads.runs.retrieve(thread_id=thread_id, run_id=run_id)
        if r.status in ("completed", "failed", "cancelled", "expired"):
            return r
        if r.status == "requires_action":
            return r
        time.sleep(0.4)


@router.post("/parse_assistant", response_model=LLMParseOut)
def llm_parse_assistant(payload: LLMParseIn):
    """Legacy OpenAI-Assistants parse (stateful threads). Requires OPENAI_API_KEY."""
    if not os.environ.get("OPENAI_API_KEY"):
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY not set (assistant path is OpenAI-only)")
    aid = ensure_intent_assistant()
    tid = payload.thread_id or _oai().beta.threads.create().id
    _oai().beta.threads.messages.create(thread_id=tid, role="user", content=payload.text)
    run = _oai().beta.threads.runs.create(thread_id=tid, assistant_id=aid)
    r = poll(tid, run.id)

    emitted = None
    tool_call_id = None
    if r.status == "requires_action":
        calls = r.required_action.submit_tool_outputs.tool_calls
        for tc in calls:
            if tc.type == "function" and tc.function.name == "emit_intent":
                tool_call_id = tc.id
                try:
                    emitted = json.loads(tc.function.arguments)
                except Exception:
                    emitted = {"_raw_args": tc.function.arguments}
                _oai().beta.threads.runs.submit_tool_outputs(
                    thread_id=tid, run_id=run.id,
                    tool_outputs=[{"tool_call_id": tc.id, "output": "ok"}],
                )
        r = poll(tid, run.id)

    msgs = _oai().beta.threads.messages.list(thread_id=tid, order="desc", limit=5)
    asst_msg_id = next((m.id for m in msgs.data if m.role == "assistant"), None)

    return LLMParseOut(
        status=r.status, emitted=emitted, provider="openai_assistants",
        model=INTENT_ASSISTANT_MODEL, assistant_id=aid, thread_id=tid,
        run_id=run.id, tool_call_id=tool_call_id, assistant_message_id=asst_msg_id,
    )
