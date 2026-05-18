"""
Proxy Router — exposes POST /v1/inspect
This is the single endpoint callers use to validate prompts before
sending them to any LLM.
"""
import time
import logging
from fastapi import APIRouter, HTTPException
from app.models.schemas import InspectRequest, InspectResponse
from app.services.decision import inspect
from app.db.mongo import log_request

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["Inspect"])


@router.post("/inspect", response_model=InspectResponse)
async def inspect_prompt(body: InspectRequest) -> InspectResponse:
    """
    Inspect a messages array for safety threats.

    - Runs YAML rule engine (keyword + regex)
    - Runs Presidio PII detection + redaction
    - Runs Groq LLM judge for sophisticated attacks

    Returns a verdict (allowed / blocked / sanitized) and
    sanitized_messages safe to forward to your LLM.
    """
    t0 = time.perf_counter()

    try:
        status, clean_messages, threats, blocked_reason = await inspect(body.messages)
    except Exception as e:
        logger.error(f"Inspection pipeline error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Inspection pipeline failed.")

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    response = InspectResponse(
        status=status,
        sanitized_messages=clean_messages,
        threats=threats,
        blocked_reason=blocked_reason,
        latency_ms=latency_ms,
    )

    # Fire-and-forget log — don't let DB slowness affect response time
    await log_request(
        request_id=response.request_id,
        original_messages=[m.model_dump() for m in body.messages],
        sanitized_messages=[m.model_dump() for m in clean_messages],
        status=status,
        threats=[t.model_dump() for t in threats],
        blocked_reason=blocked_reason,
        latency_ms=latency_ms,
        metadata=body.metadata or {},
    )

    return response


@router.get("/debug/sanitize", tags=["Admin"])
async def debug_sanitize(text: str):
    """Debug endpoint to test rule sanitization directly."""
    from app.services.rule_engine import rule_engine
    sanitize_rules = [(r.id, r.action, r.replacement, r.match(text)) for r in rule_engine._rules if r.type == "pattern_match"]
    result, changed = rule_engine.apply_sanitizations(text)
    return {
        "input": text,
        "output": result,
        "changed": changed,
        "pattern_rules": [
            {"id": rid, "action": action, "replacement": repl, "matches": matches}
            for rid, action, repl, matches in sanitize_rules
        ]
    }
async def reload_rules():
    """Hot-reload YAML rules without restarting the server."""
    from app.services.rule_engine import rule_engine
    rule_engine.reload()
    return {"message": f"Rules reloaded. {len(rule_engine._rules)} rules active."}