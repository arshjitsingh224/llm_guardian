"""
Stats Router — simple aggregations over request_logs collection.
Endpoints:
  GET /stats/summary    — totals for a time period
  GET /stats/threats    — breakdown by threat type
  GET /stats/rules      — which rules fired most
  GET /stats/timeline   — daily totals for last N days
"""
from fastapi import APIRouter, Query
from datetime import datetime, timedelta, timezone
from app.db.mongo import get_db
from app.models.schemas import SummaryStats, ThreatBreakdown, RuleFireCount, TimelinePoint

router = APIRouter(prefix="/stats", tags=["Stats"])


def _since(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


@router.get("/summary", response_model=SummaryStats)
async def summary(period: str = Query("today", pattern="^(today|7d|30d)$")):
    """Total requests and block/sanitize rates."""
    days = {"today": 1, "7d": 7, "30d": 30}[period]
    db = get_db()

    pipeline = [
        {"$match": {"timestamp": {"$gte": _since(days)}}},
        {"$group": {
            "_id": "$status",
            "count": {"$sum": 1},
        }},
    ]
    rows = await db["request_logs"].aggregate(pipeline).to_list(None)
    counts = {r["_id"]: r["count"] for r in rows}

    total = sum(counts.values())
    blocked = counts.get("blocked", 0)
    sanitized = counts.get("sanitized", 0)
    allowed = counts.get("allowed", 0)
    block_rate = round(blocked / total * 100, 1) if total else 0.0

    return SummaryStats(
        total_requests=total,
        allowed=allowed,
        blocked=blocked,
        sanitized=sanitized,
        block_rate_pct=block_rate,
        period=period,
    )


@router.get("/threats", response_model=list[ThreatBreakdown])
async def threats(period: str = Query("7d", pattern="^(today|7d|30d)$")):
    """Count of each threat type detected."""
    days = {"today": 1, "7d": 7, "30d": 30}[period]
    db = get_db()

    pipeline = [
        {"$match": {"timestamp": {"$gte": _since(days)}}},
        {"$unwind": "$threat_types"},
        {"$group": {
            "_id": "$threat_types",
            "count": {"$sum": 1},
        }},
        {"$sort": {"count": -1}},
    ]
    rows = await db["request_logs"].aggregate(pipeline).to_list(None)
    return [ThreatBreakdown(threat_type=r["_id"], count=r["count"]) for r in rows]


@router.get("/rules", response_model=list[RuleFireCount])
async def rules_fired(period: str = Query("7d", pattern="^(today|7d|30d)$")):
    """Which rules fired most frequently."""
    days = {"today": 1, "7d": 7, "30d": 30}[period]
    db = get_db()

    pipeline = [
        {"$match": {"timestamp": {"$gte": _since(days)}}},
        {"$unwind": "$rule_ids"},
        {"$group": {
            "_id": "$rule_ids",
            "count": {"$sum": 1},
        }},
        {"$sort": {"count": -1}},
        {"$limit": 20},
    ]
    rows = await db["request_logs"].aggregate(pipeline).to_list(None)

    # Enrich with rule names from the engine
    from app.services.rule_engine import rule_engine
    rule_names = {r.id: r.name for r in rule_engine._rules}

    return [
        RuleFireCount(
            rule_id=r["_id"],
            rule_name=rule_names.get(r["_id"], r["_id"]),
            count=r["count"],
        )
        for r in rows
    ]


@router.get("/timeline", response_model=list[TimelinePoint])
async def timeline(days: int = Query(7, ge=1, le=30)):
    """Daily request counts for the last N days."""
    db = get_db()

    pipeline = [
        {"$match": {"timestamp": {"$gte": _since(days)}}},
        {"$group": {
            "_id": {
                "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "status": "$status",
            },
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id.date": 1}},
    ]
    rows = await db["request_logs"].aggregate(pipeline).to_list(None)

    # Pivot into {date: {status: count}}
    pivot: dict[str, dict] = {}
    for r in rows:
        date = r["_id"]["date"]
        status = r["_id"]["status"]
        pivot.setdefault(date, {"total": 0, "blocked": 0, "sanitized": 0})
        pivot[date][status] = r["count"]
        pivot[date]["total"] += r["count"]

    return [
        TimelinePoint(
            date=date,
            total=v["total"],
            blocked=v.get("blocked", 0),
            sanitized=v.get("sanitized", 0),
        )
        for date, v in sorted(pivot.items())
    ]
