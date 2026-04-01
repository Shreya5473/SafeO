import re
from typing import List, Tuple

THREAT_PATTERNS = {
    "sql_injection": [
        r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from|exec\s*\(|execute\s*\()",
        r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1)",
        r"(?i)(--\s*$|;\s*drop|;\s*delete|;\s*truncate|xp_cmdshell|sp_executesql)",
        r"(?i)(select\s+.+\s+from\s+\w+)",
    ],
    "xss": [
        r"(?i)(<script[\s>]|</script>|javascript\s*:|on\w+\s*=\s*[\"'])",
        r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie|window\.location)",
        r"(?i)(<iframe|<object|<embed|<svg\s+on\w+)",
        r"(?i)(eval\s*\(|innerHTML\s*=|outerHTML\s*=)",
    ],
    "prompt_injection": [
        r"(?i)(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context))",
        r"(?i)(you\s+are\s+now|act\s+as\s+|pretend\s+(you|to\s+be)|forget\s+your)",
        r"(?i)(system\s*prompt|jailbreak|dan\s+mode|developer\s+mode|god\s+mode)",
        r"(?i)(override\s+(safety|guidelines|rules)|bypass\s+(filter|security|restriction))",
        r"(?i)(new\s+instructions?:|revised\s+prompt:|updated\s+system:|\[INST\])",
    ],
    "path_traversal": [
        r"(?i)(\.\./|\.\.[/\\]|%2e%2e%2f|%252e%252e)",
        r"(?i)(/etc/passwd|/etc/shadow|/proc/self|windows/system32)",
    ],
    "command_injection": [
        r"(?i)(;\s*ls\s|;\s*cat\s|;\s*rm\s|;\s*wget\s|;\s*curl\s)",
        r"(?i)(`[^`]+`|\$\([^)]+\)|&&\s*\w+|\|\|\s*\w+)",
        r"(?i)(system\s*\(|popen\s*\(|subprocess\.)",
    ],
    "ssti_template_injection": [
        r"(\{\{.*\}\}|\$\{.*\}|<%=?\s*.*\s*%>)",
        r"(?i)(__class__|__mro__|__subclasses__|config\[['\"])",
    ],
    "ssrf": [
        r"(?i)(169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1)",
        r"(?i)(file://|gopher://|dict://|ftp://)",
    ],
    "sensitive_data": [
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        r"(?i)(password\s*[:=]\s*\S{4,}|api[_\s]?key\s*[:=]\s*\S{10,}|secret\s*[:=]\s*\S{6,})",
        r"(?i)(bearer\s+[a-zA-Z0-9\-._~+/]{20,}|authorization\s*[:=])",
    ],
    "obfuscation": [
        r"(?i)(%[0-9a-f]{2}){4,}",
        r"(?i)(\\x[0-9a-f]{2}){4,}",
        r"(?i)(base64_decode|atob\s*\(|String\.fromCharCode\s*\()",
        r"(?i)(&#[0-9]{2,4};){3,}",
    ],
}

CATEGORY_WEIGHTS = {
    "sql_injection": 0.92,
    "command_injection": 0.92,
    "ssti_template_injection": 0.90,
    "prompt_injection": 0.87,
    "path_traversal": 0.85,
    "ssrf": 0.84,
    "xss": 0.82,
    "obfuscation": 0.70,
    "sensitive_data": 0.60,
}


def detect_threats(text: str) -> Tuple[List[str], float, List[str]]:
    """Returns (detected_categories, max_severity, matched_snippets)."""
    if not text:
        return [], 0.0, []

    detected: List[str] = []
    matched: List[str] = []
    max_score = 0.0

    for category, patterns in THREAT_PATTERNS.items():
        for pattern in patterns:
            m = re.search(pattern, text)
            if m:
                detected.append(category)
                matched.append(f"{category}: '{m.group()[:60]}'")
                max_score = max(max_score, CATEGORY_WEIGHTS.get(category, 0.5))
                break

    return list(set(detected)), max_score, matched
