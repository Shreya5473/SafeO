from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import waf, simulate, feedback, metrics
from .agents.behavior_agent import BehaviorAgent
from .models.schemas import BehaviorRequest

app = FastAPI(
    title="SafeO / SecureC WAF API",
    description="SafeO — AI-native Web Application Firewall (multi-agent ML engine, tiered LLM, decision cache)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(waf.router)
app.include_router(simulate.router)
app.include_router(feedback.router)
app.include_router(metrics.router)

_behavior_agent = BehaviorAgent()


@app.post("/waf/behavior")
async def track_behavior(req: BehaviorRequest):
    return _behavior_agent.track_action(req.user_id, req.action)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "SafeO WAF", "version": "1.0.0"}


@app.get("/")
async def root():
    return {
        "service": "SafeO AI WAF",
        "version": "1.0.0",
        "endpoints": ["/waf/input", "/waf/output", "/waf/behavior", "/simulate/attack", "/feedback", "/metrics"],
    }
