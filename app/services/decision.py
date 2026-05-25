"""
Decision Service — orchestrates rule engine → PII scanner → LLM judge
and produces the final verdict + sanitized messages.

Flow:
  1. Flatten all messages to a single text blob for scanning
  2. Run YAML rule engine (fast, no I/O)
  3. Run Presidio PII scanner (fast, local)
  4. If no hard-block yet → run Groq LLM judge (async, I/O)
  5. Combine all threats → decide: block / sanitize / allow
"""
import logging
from copy import deepcopy
from app.models.schemas import Message, ThreatDetail
from app.services.rule_engine import is_benign_security_context, rule_engine
from app.services.pii_scanner import pii_scanner
from app.services.llm_judge import llm_judge

logger = logging.getLogger(__name__)

# Which threat sources / types constitute a hard block
BLOCK_SOURCES = {"rule_engine", "llm_judge"}
BLOCK_VERDICTS = {"PROMPT_INJECTION", "JAILBREAK", "KEYWORD_BLOCK", "PATTERN_MATCH"}


async def inspect(messages: list[Message]) -> tuple[str, list[Message], list[ThreatDetail], str | None]:
    """
    Returns:
        status          — "allowed" | "blocked" | "sanitized"
        clean_messages  — sanitized copy of messages (or originals if allowed)
        threats         — all detected threats
        blocked_reason  — human-readable reason if blocked, else None
    """
    all_threats: list[ThreatDetail] = []
    clean_messages = deepcopy(messages)

    # ── Step 1: Run rule engine on all user/system message content ────────────
    combined_text = _extract_text(messages)
    rule_threats = rule_engine.evaluate(combined_text)
    all_threats.extend(rule_threats)

    # ── Step 2: PII scan + redact on each message individually ───────────────
    pii_triggered = False
    for i, msg in enumerate(clean_messages):
        redacted, pii_threats = pii_scanner.scan_and_redact(msg.content)
        if pii_threats:
            clean_messages[i] = Message(role=msg.role, content=redacted)
            all_threats.extend(pii_threats)
            if any(
                r.action == "sanitize"
                for r in rule_engine.pii_rules
                if r.id in {t.rule_id for t in pii_threats}
            ):
                pii_triggered = True

    # ── Step 2b: Apply regex sanitize rules AFTER Presidio ───────────────────
    # Must run after PII scanner so Presidio can't overwrite regex redactions
    rule_sanitized = False
    for i, msg in enumerate(clean_messages):
        sanitized_content, changed = rule_engine.apply_sanitizations(msg.content)
        if changed:
            clean_messages[i] = Message(role=msg.role, content=sanitized_content)
            rule_sanitized = True

    # ── Step 3: Check for hard block from rules ───────────────────────────────
    hard_block = _find_hard_block(rule_threats)
    if hard_block:
        return (
            "blocked",
            clean_messages,
            all_threats,
            hard_block.detail,
        )

    # ── Step 4: LLM judge — only runs if rules didn't hard-block ─────────────
    judge_threat = None if is_benign_security_context(combined_text) else await llm_judge.judge(combined_text)
    if judge_threat:
        all_threats.append(judge_threat)
        if judge_threat.type in {"PROMPT_INJECTION", "JAILBREAK"}:
            return (
                "blocked",
                clean_messages,
                all_threats,
                f"LLM judge detected {judge_threat.type}: {judge_threat.detail}",
            )

    # ── Step 5: Final status ──────────────────────────────────────────────────
    if pii_triggered or rule_sanitized:
        status = "sanitized"
    elif all_threats:
        status = "allowed"
    else:
        status = "allowed"

    return status, clean_messages, all_threats, None


def _extract_text(messages: list[Message]) -> str:
    """Concatenate all message content for full-context scanning."""
    return "\n".join(m.content for m in messages if m.role in ("user", "system"))


def _find_hard_block(threats: list[ThreatDetail]) -> ThreatDetail | None:
    """Return the first threat that should trigger an immediate block."""
    for t in threats:
        if t.source in BLOCK_SOURCES and t.type in BLOCK_VERDICTS:
            return t
    return None
