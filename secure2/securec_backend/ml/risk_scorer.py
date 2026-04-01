from urllib.parse import unquote

from typing import Tuple, List
from .entropy import (
    shannon_entropy,
    character_distribution_anomaly,
    repetition_score,
    compression_anomaly,
    token_burst_score,
)
from .keyword_detector import detect_threats


def _iterative_decode(text: str, rounds: int = 2) -> str:
    decoded = text
    for _ in range(rounds):
        candidate = unquote(decoded)
        if candidate == decoded:
            break
        decoded = candidate
    return decoded


def calculate_risk_score(text: str) -> Tuple[float, str, List[str], List[str]]:
    """
    Combine ML signals into a single 0-1 risk score.
    Returns: (risk_score, decision, detected_patterns, explanation_parts)
    """
    if not text or not text.strip():
        return 0.0, "allow", [], ["Empty input — no risk detected"]

    decoded_text = _iterative_decode(text)

    entropy_val = shannon_entropy(text)
    char_anomaly = character_distribution_anomaly(text)
    repetition = repetition_score(text)
    compress = compression_anomaly(text)
    burst = token_burst_score(text)
    categories, keyword_score, patterns = detect_threats(text)

    decoded_categories, decoded_keyword_score, decoded_patterns = detect_threats(decoded_text)
    if decoded_text != text and decoded_patterns:
        patterns.extend([f"decoded:{p}" for p in decoded_patterns])
        categories = list(set(categories + decoded_categories))
    keyword_signal = max(keyword_score, decoded_keyword_score)

    # Ensemble score: signature + structural anomaly + encoded payload decoding.
    score = (
        keyword_signal * 0.52
        + entropy_val * 0.11
        + char_anomaly * 0.11
        + repetition * 0.08
        + compress * 0.09
        + burst * 0.09
    )

    # Boost when multiple attack categories co-occur (composite attack chain).
    if len(categories) > 1:
        score = min(score * 1.2, 1.0)

    # Strong evidence guardrail: known dangerous signatures should not be diluted.
    if keyword_signal >= 0.90:
        score = max(score, 0.83)

    explanations: List[str] = []
    if keyword_signal > 0:
        explanations.append(f"Threat patterns matched: {', '.join(categories)}")
    if entropy_val > 0.72:
        explanations.append(f"High Shannon entropy ({entropy_val:.2f}) — possible obfuscation")
    if char_anomaly > 0.50:
        explanations.append(f"Abnormal special-character density ({char_anomaly:.2f})")
    if repetition > 0.60:
        explanations.append(f"Repetitive pattern detected ({repetition:.2f}) — possible fuzzing")
    if compress > 0.50:
        explanations.append(f"Compression anomaly ({compress:.2f}) — payload structure is machine-like")
    if burst > 0.45:
        explanations.append(f"Delimiter/operator burst ({burst:.2f}) — exploit grammar detected")
    if decoded_text != text and decoded_patterns:
        explanations.append("Encoded payload unfolded into known malicious signatures")
    if not explanations:
        explanations.append("Input appears safe based on current rule set")

    risk_score = round(min(score, 1.0), 3)

    if risk_score >= 0.70:
        decision = "block"
    elif risk_score >= 0.30:
        decision = "warn"
    else:
        decision = "allow"

    return risk_score, decision, patterns, explanations
