from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class WAFInputRequest(BaseModel):
    input_text: str
    user_id: Optional[str] = "anonymous"
    module: Optional[str] = "generic"
    context: Optional[Dict[str, Any]] = {}


class AgentResult(BaseModel):
    agent_name: str
    status: str
    decision: str
    confidence: float
    detected_patterns: List[str]


class WAFResponse(BaseModel):
    risk_score: float
    decision: str
    explanation: str
    detected_patterns: List[str]
    agents: List[AgentResult]
    sanitized_text: Optional[str] = None
    request_id: str
    llm_used: Optional[bool] = None
    decision_cache_hit: Optional[bool] = None
    engine_note: Optional[str] = None


class WAFOutputRequest(BaseModel):
    output_text: str
    user_id: Optional[str] = "anonymous"
    module: Optional[str] = "generic"


class BehaviorRequest(BaseModel):
    user_id: str
    action: str
    module: Optional[str] = "generic"
    timestamp: Optional[datetime] = None


class BehaviorResponse(BaseModel):
    user_id: str
    risk_score: float
    anomaly_detected: bool
    explanation: str
    action_count: int
    baseline_avg: float


class SimulateRequest(BaseModel):
    attack_types: Optional[List[str]] = None


class SimulationResult(BaseModel):
    attack_type: str
    payload: str
    detected: bool
    risk_score: float
    decision: str
    explanation: str


class SimulateResponse(BaseModel):
    total_attacks: int
    detected_count: int
    detection_rate: float
    results: List[SimulationResult]


class FeedbackRequest(BaseModel):
    request_id: str
    correct_decision: str
    notes: Optional[str] = None


class MetricsResponse(BaseModel):
    total_requests: int
    blocked_count: int
    warned_count: int
    allowed_count: int
    block_rate: float
    avg_risk_score: float
    threats_by_module: Dict[str, int]
    risk_distribution: Dict[str, int]
    recent_attacks: List[Dict[str, Any]]
    llm_calls_total: int = 0
    llm_calls_skipped: int = 0
    decision_cache_hits: int = 0
