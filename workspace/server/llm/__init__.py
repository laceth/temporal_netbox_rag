"""Provider-abstraction package for the NetOps intent LLM.

Lets the NetBox-RAG route its intent NLU through either OpenAI or AWS Bedrock
(DeepSeek-R1), selected by ``NETBOX_RAG_PROVIDER`` with an availability-aware
fallback chain. Mirrors TestPulse's own ``TESTPULSE_ML_ROUTING_MODE`` pattern so
the closed learning loop (config-plan ↔ AAA-triage) shares one reasoning
backbone. See ``provider.py``.
"""
from .provider import (
    EMIT_INTENT_SCHEMA,
    IntentResult,
    LLMProvider,
    ProviderUnavailable,
    active_provider_info,
    get_provider,
)

__all__ = [
    "EMIT_INTENT_SCHEMA",
    "IntentResult",
    "LLMProvider",
    "ProviderUnavailable",
    "active_provider_info",
    "get_provider",
]
