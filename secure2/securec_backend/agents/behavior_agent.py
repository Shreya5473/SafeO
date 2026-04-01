from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List
from ..models.schemas import BehaviorResponse

_action_log: Dict[str, List[datetime]] = defaultdict(list)
_baselines: Dict[str, float] = {}

WINDOW_HOURS = 1
ANOMALY_MULTIPLIER = 3.0
HARD_LIMIT = 60


class BehaviorAgent:
    name = "BehaviorWatch"
    description = "Monitors user action patterns for insider threat detection"

    def track_action(self, user_id: str, action: str) -> BehaviorResponse:
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=WINDOW_HOURS)

        _action_log[user_id].append(now)
        _action_log[user_id] = [t for t in _action_log[user_id] if t > cutoff]
        count = len(_action_log[user_id])

        if user_id not in _baselines:
            _baselines[user_id] = float(count)
        else:
            _baselines[user_id] = 0.3 * count + 0.7 * _baselines[user_id]

        baseline = _baselines[user_id]
        anomaly = False
        risk = 0.0
        explanation = "Behavior within normal parameters"

        if baseline > 2 and count > baseline * ANOMALY_MULTIPLIER:
            anomaly = True
            risk = min((count / (baseline * ANOMALY_MULTIPLIER)) * 0.85, 1.0)
            explanation = (
                f"Unusual activity spike: {count} actions/hr vs baseline {baseline:.1f}. "
                "Possible insider threat or account compromise."
            )
        elif count >= HARD_LIMIT:
            anomaly = True
            risk = min(count / 100, 1.0)
            explanation = f"Rate limit breach: {count} actions in the last hour"

        return BehaviorResponse(
            user_id=user_id,
            risk_score=round(risk, 3),
            anomaly_detected=anomaly,
            explanation=explanation,
            action_count=count,
            baseline_avg=round(baseline, 1),
        )

    def get_history(self, user_id: str) -> Dict:
        return {
            "user_id": user_id,
            "action_count_last_hour": len(_action_log.get(user_id, [])),
            "baseline_avg": round(_baselines.get(user_id, 0), 1),
        }
