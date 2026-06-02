"""Provider-abstraction tests — selection, fallback chain, JSON extraction.

No live OpenAI/Bedrock calls: providers are monkeypatched so the chain logic,
env-driven selection, graceful degradation, and DeepSeek <think>/JSON parsing are
verified in isolation (the kind of contract a config flip must not break).
"""
import sys
from pathlib import Path

import pytest

# make `server` importable when run from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.llm import provider as P  # noqa: E402


# ── JSON extraction (DeepSeek-R1 <think> + fenced + bare) ────────────────────
def test_extract_strips_think_block():
    raw = '<think>the user wants vlans</think>{"intent":"netops.device_config_change","entities":{"vlans":[8,10]}}'
    obj = P._extract_intent_json(raw)
    assert obj["intent"] == "netops.device_config_change"
    assert obj["entities"]["vlans"] == [8, 10]
    assert obj["dry_run"] is True  # defaulted


def test_extract_finds_embedded_json():
    raw = 'Sure, here is the result:\n{"intent":"x","entities":{}}\nhope that helps'
    assert P._extract_intent_json(raw)["intent"] == "x"


def test_extract_rejects_non_schema():
    with pytest.raises(ValueError):
        P._extract_intent_json("no json here")
    with pytest.raises(ValueError):
        P._extract_intent_json('{"entities":{}}')  # missing required "intent"


# ── Provider selection from env ──────────────────────────────────────────────
def test_chain_order_defaults_to_openai(monkeypatch):
    monkeypatch.delenv("NETBOX_RAG_PROVIDER", raising=False)
    assert P._chain()[0] == "openai"


def test_chain_order_bedrock_primary(monkeypatch):
    monkeypatch.setenv("NETBOX_RAG_PROVIDER", "bedrock_deepseek")
    order = P._chain()
    assert order[0] == "bedrock_deepseek" and "openai" in order


def test_unknown_provider_falls_back_to_openai(monkeypatch):
    monkeypatch.setenv("NETBOX_RAG_PROVIDER", "nonsense")
    assert P._chain()[0] == "openai"


# ── Fallback chain behaviour ─────────────────────────────────────────────────
class _StubProv:
    def __init__(self, name, avail, result=None, fail=False):
        self.name = name
        self._avail = avail
        self._result = result
        self._fail = fail

    def available(self):
        return self._avail

    def emit_intent(self, text, task="parse"):
        if self._fail:
            raise P.ProviderUnavailable(self.name, "boom")
        return self._result


def test_chain_uses_primary_when_available(monkeypatch):
    good = P.IntentResult(emitted={"intent": "a", "entities": {}}, provider="bedrock_deepseek", model="r1")
    monkeypatch.setattr(P, "_REGISTRY", {
        "bedrock_deepseek": lambda: _StubProv("bedrock_deepseek", True, good),
        "openai": lambda: _StubProv("openai", True, None),
    })
    monkeypatch.setenv("NETBOX_RAG_PROVIDER", "bedrock_deepseek")
    r = P.get_provider().emit_intent("vlan 8")
    assert r.provider == "bedrock_deepseek" and r.fallback_used is False


def test_chain_falls_through_to_secondary(monkeypatch):
    good = P.IntentResult(emitted={"intent": "a", "entities": {}}, provider="openai", model="gpt")
    monkeypatch.setattr(P, "_REGISTRY", {
        "bedrock_deepseek": lambda: _StubProv("bedrock_deepseek", True, fail=True),  # available but errors
        "openai": lambda: _StubProv("openai", True, good),
    })
    monkeypatch.setenv("NETBOX_RAG_PROVIDER", "bedrock_deepseek")
    r = P.get_provider().emit_intent("vlan 8")
    assert r.provider == "openai" and r.fallback_used is True


def test_chain_skips_unavailable_provider(monkeypatch):
    good = P.IntentResult(emitted={"intent": "a", "entities": {}}, provider="openai", model="gpt")
    monkeypatch.setattr(P, "_REGISTRY", {
        "bedrock_deepseek": lambda: _StubProv("bedrock_deepseek", False),  # no creds
        "openai": lambda: _StubProv("openai", True, good),
    })
    monkeypatch.setenv("NETBOX_RAG_PROVIDER", "bedrock_deepseek")
    r = P.get_provider().emit_intent("vlan 8")
    assert r.provider == "openai" and r.fallback_used is True


def test_chain_raises_when_all_fail(monkeypatch):
    monkeypatch.setattr(P, "_REGISTRY", {
        "bedrock_deepseek": lambda: _StubProv("bedrock_deepseek", False),
        "openai": lambda: _StubProv("openai", False),
    })
    with pytest.raises(P.ProviderUnavailable):
        P.get_provider().emit_intent("vlan 8")


# ── Introspection ────────────────────────────────────────────────────────────
def test_active_provider_info_shape(monkeypatch):
    monkeypatch.setenv("NETBOX_RAG_PROVIDER", "bedrock_deepseek")
    info = P.active_provider_info()
    assert info["configured"] == "bedrock_deepseek"
    assert info["order"][0] == "bedrock_deepseek"
    assert set(info["available"]) == {"bedrock_deepseek", "openai"}
