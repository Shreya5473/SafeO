import math
import zlib
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Shannon entropy normalized to 0-1 (high entropy = possible obfuscation)."""
    if not text or len(text) < 2:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    # Max entropy for 95 printable ASCII chars ≈ 6.57 bits
    return min(entropy / 6.57, 1.0)


def character_distribution_anomaly(text: str) -> float:
    """Detects abnormal special-character ratio — common in encoded payloads."""
    if not text:
        return 0.0
    special = sum(1 for c in text if not c.isalnum() and not c.isspace())
    ratio = special / len(text)
    return min(ratio / 0.30, 1.0)  # >30% special chars = suspicious


def repetition_score(text: str) -> float:
    """Detects repeated substrings — common in buffer-overflow and fuzzing payloads."""
    if len(text) < 10:
        return 0.0
    chunk = 4
    chunks = [text[i:i + chunk] for i in range(0, len(text) - chunk, chunk)]
    if not chunks:
        return 0.0
    unique_ratio = len(set(chunks)) / len(chunks)
    return max(0.0, 1.0 - unique_ratio)


def compression_anomaly(text: str) -> float:
    """
    Compression-based anomaly score.
    Highly repetitive or machine-generated payloads compress unusually well.
    """
    if not text or len(text) < 24:
        return 0.0
    raw = text.encode("utf-8", errors="ignore")
    if not raw:
        return 0.0
    compressed = zlib.compress(raw, level=9)
    ratio = len(compressed) / max(len(raw), 1)
    return min(max((0.85 - ratio) / 0.55, 0.0), 1.0)


def token_burst_score(text: str) -> float:
    """
    Burst score for repeated dangerous delimiters and operators.
    Captures payload grammar often seen in exploits.
    """
    if not text:
        return 0.0
    suspicious_tokens = [
        "<", ">", "{", "}", ";", "--", "/*", "*/", "||", "&&", "$(", "`",
    ]
    hits = 0
    lowered = text.lower()
    for token in suspicious_tokens:
        hits += lowered.count(token.lower())
    density = hits / max(len(text), 1)
    return min(density / 0.09, 1.0)
