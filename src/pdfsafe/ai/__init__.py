"""AI triage layer: evidence packaging, provider abstraction and cost gating."""

from pdfsafe.ai.base import LLMProvider
from pdfsafe.ai.evidence import build_evidence
from pdfsafe.ai.registry import available_providers, get_provider, register_provider
from pdfsafe.ai.triage import EscalationDecision, should_escalate, triage

__all__ = [
    "EscalationDecision",
    "LLMProvider",
    "available_providers",
    "build_evidence",
    "get_provider",
    "register_provider",
    "should_escalate",
    "triage",
]
