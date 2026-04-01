from fastapi import APIRouter
from collections import defaultdict
from ..models.schemas import MetricsResponse
from .waf import get_request_log, get_engine_stats

router = APIRouter(prefix="/metrics", tags=["Metrics"])


@router.get("/", response_model=MetricsResponse)
async def get_metrics():
    logs = get_request_log()
    if not logs:
        return _demo_metrics()

    total = len(logs)
    blocked = sum(1 for l in logs if l.get("decision") == "block")
    warned = sum(1 for l in logs if l.get("decision") == "warn")
    allowed = total - blocked - warned
    avg_risk = sum(l.get("risk_score", 0) for l in logs) / total

    by_module: dict = defaultdict(int)
    for l in logs:
        if l.get("decision") in ("block", "warn"):
            by_module[l.get("module", "unknown")] += 1

    dist = {
        "low": sum(1 for l in logs if l.get("risk_score", 0) < 0.30),
        "medium": sum(1 for l in logs if 0.30 <= l.get("risk_score", 0) < 0.70),
        "high": sum(1 for l in logs if l.get("risk_score", 0) >= 0.70),
    }

    recent = [
        {
            "request_id": l.get("request_id", ""),
            "module": l.get("module", ""),
            "risk_score": l.get("risk_score", 0),
            "decision": l.get("decision", ""),
            "patterns": l.get("patterns", [])[:2],
        }
        for l in reversed(logs)
        if l.get("decision") in ("block", "warn")
    ][:10]

    eng = get_engine_stats()

    return MetricsResponse(
        total_requests=total,
        blocked_count=blocked,
        warned_count=warned,
        allowed_count=allowed,
        block_rate=round(blocked / total * 100, 1),
        avg_risk_score=round(avg_risk, 3),
        threats_by_module=dict(by_module),
        risk_distribution=dist,
        recent_attacks=recent,
        llm_calls_total=eng.get("llm_calls", 0),
        llm_calls_skipped=eng.get("llm_skipped", 0),
        decision_cache_hits=eng.get("cache_hits", 0),
    )


def _demo_metrics() -> MetricsResponse:
    return MetricsResponse(
        total_requests=312,
        blocked_count=18,
        warned_count=41,
        allowed_count=253,
        block_rate=5.8,
        avg_risk_score=0.21,
        threats_by_module={"CRM": 35, "Email": 14, "Forms": 10},
        risk_distribution={"low": 253, "medium": 41, "high": 18},
        recent_attacks=[
            {"request_id": "a1b2c3", "module": "CRM", "risk_score": 0.94, "decision": "block", "patterns": ["sql_injection: 'DROP TABLE"]},
            {"request_id": "d4e5f6", "module": "CRM", "risk_score": 0.88, "decision": "block", "patterns": ["prompt_injection: 'ignore all"]},
            {"request_id": "g7h8i9", "module": "Email", "risk_score": 0.47, "decision": "warn", "patterns": ["xss: '<script"]},
        ],
        llm_calls_total=42,
        llm_calls_skipped=198,
        decision_cache_hits=61,
    )
