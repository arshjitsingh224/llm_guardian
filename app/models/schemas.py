from pydantic import BaseModel, Field
from typing import Literal, Optional
from datetime import datetime, timezone
import uuid


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str


class InspectRequest(BaseModel):
    messages: list[Message]
    metadata: Optional[dict] = Field(default_factory=dict)  # caller can pass context


class ThreatDetail(BaseModel):
    type: Literal["PROMPT_INJECTION", "JAILBREAK", "PII", "KEYWORD_BLOCK", "PATTERN_MATCH", "SUSPICIOUS"]
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    source: Literal["rule_engine", "pii_scanner", "llm_judge"]
    detail: str  # human-readable explanation
    rule_id: Optional[str] = None  # which rule fired, if applicable


class InspectResponse(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: Literal["allowed", "blocked", "sanitized"]
    sanitized_messages: list[Message]  # clean messages, safe to forward to LLM
    threats: list[ThreatDetail] = Field(default_factory=list)
    blocked_reason: Optional[str] = None  # summary if blocked
    latency_ms: Optional[float] = None


# ── Stats schemas ──────────────────────────────────────────────────────────────

class SummaryStats(BaseModel):
    total_requests: int
    allowed: int
    blocked: int
    sanitized: int
    block_rate_pct: float
    period: str  # e.g. "today", "7d"


class ThreatBreakdown(BaseModel):
    threat_type: str
    count: int


class RuleFireCount(BaseModel):
    rule_id: str
    rule_name: str
    count: int


class TimelinePoint(BaseModel):
    date: str
    total: int
    blocked: int
    sanitized: int
