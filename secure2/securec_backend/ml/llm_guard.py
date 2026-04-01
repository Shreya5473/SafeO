import json
import os
from typing import Dict, Any

import requests

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def llm_enabled() -> bool:
    return os.getenv("SECUREC_ENABLE_LLM_AUGMENTATION", "false").lower() in {"1", "true", "yes"}


def llm_assess_payload(text: str) -> Dict[str, Any]:
    """
    Optional LLM-assisted semantic risk scoring.
    Disabled by default; requires:
      - SECUREC_ENABLE_LLM_AUGMENTATION=true
      - OPENROUTER_API_KEY=<key>
    """
    if not llm_enabled():
        return {"enabled": False}

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return {"enabled": False, "error": "missing_openrouter_api_key"}

    model = os.getenv("SECUREC_OPENROUTER_MODEL", "openai/gpt-4.1-mini")
    prompt = (
        "You are a web application firewall classifier.\n"
        "Analyze the payload for exploit intent (SQLi, XSS, command injection, prompt injection, SSRF, traversal, SSTI).\n"
        "Return STRICT JSON only with keys: risk_score (0..1), attack_types (array), rationale (string).\n"
    )
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": text[:4000]},
        ],
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=4)
        resp.raise_for_status()
        body = resp.json()
        content = body["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        risk_score = float(parsed.get("risk_score", 0.0))
        attack_types = parsed.get("attack_types", []) or []
        rationale = parsed.get("rationale", "")
        return {
            "enabled": True,
            "risk_score": max(0.0, min(risk_score, 1.0)),
            "attack_types": [str(x) for x in attack_types][:6],
            "rationale": str(rationale)[:500],
            "model": model,
        }
    except Exception as exc:
        return {"enabled": True, "error": str(exc)}
