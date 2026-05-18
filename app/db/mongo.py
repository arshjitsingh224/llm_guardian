from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timezone
from app.config import settings
import logging

logger = logging.getLogger(__name__)

_client: AsyncIOMotorClient = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.mongodb_url)
    return _client


def get_db():
    return get_client()[settings.mongodb_db_name]


async def log_request(
    request_id: str,
    original_messages: list[dict],
    sanitized_messages: list[dict],
    status: str,
    threats: list[dict],
    blocked_reason: str | None,
    latency_ms: float,
    metadata: dict,
):
    """Write a single inspection event to MongoDB."""
    db = get_db()
    doc = {
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc),
        "status": status,
        "original_messages": original_messages,
        "sanitized_messages": sanitized_messages,
        "threats": threats,
        "blocked_reason": blocked_reason,
        "latency_ms": latency_ms,
        "metadata": metadata,
        # denormalised for easy aggregation
        "threat_types": list({t["type"] for t in threats}),
        "rule_ids": [t["rule_id"] for t in threats if t.get("rule_id")],
    }
    try:
        await db["request_logs"].insert_one(doc)
    except Exception as e:
        # Never let a logging failure break the main flow
        logger.error(f"Failed to write log to MongoDB: {e}")


async def close_client():
    global _client
    if _client:
        _client.close()
        _client = None
