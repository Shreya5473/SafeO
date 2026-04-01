"""
Tiered LLM invocation: skip API calls when heuristics are already decisive
(gray-zone + small sampling only) to reduce cost and latency.
"""
import hashlib
from typing import List, Tuple

from .llm_guard import llm_enabled


def should_invoke_llm(risk_score: float, patterns: List[str], text: str) -> Tuple[bool, str]:
    """
    Returns (call_openrouter, skip_reason_if_false).
    """
    if not llm_enabled():
        return False, "llm_disabled"

    has_sig = bool(patterns)
    # Decisive high-risk from deterministic layer — LLM rarely changes outcome.
    if risk_score >= 0.82:
        return False, "high_confidence_heuristic"
    # Clearly benign
    if risk_score < 0.16 and not has_sig:
        return False, "low_risk_clear"
    # Ambiguous band — LLM adds semantic value.
    if 0.20 <= risk_score <= 0.68:
        return True, "gray_zone"
    # Low-rate sampling for drift / zero-day phrasing (deterministic miss).
    sample = int(hashlib.sha256((text[:1200] + str(len(text))).encode()).hexdigest(), 16) % 100
    if sample < 6:
        return True, "sampled_drift_check"
    return False, "heuristic_sufficient"
