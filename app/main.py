"""
LLM Guardian — FastAPI entry point
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.config import settings
from app.routers import proxy, stats
from app.db.mongo import close_client

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("LLM Guardian starting up...")
    yield
    logger.info("LLM Guardian shutting down...")
    await close_client()


app = FastAPI(
    title="LLM Guardian",
    description=(
        "A safety and compliance proxy for LLM applications. "
        "Detects and blocks prompt injection, jailbreaks, and PII leakage "
        "before prompts reach any LLM."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(proxy.router)
app.include_router(stats.router)


@app.get("/health", tags=["Health"])
async def health():
    from app.services.rule_engine import rule_engine
    return {
        "status": "ok",
        "rules_loaded": len(rule_engine._rules),
        "rules_path": settings.rules_path,
    }
