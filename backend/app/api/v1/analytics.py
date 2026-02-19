from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.models.alert import Alert
from sqlalchemy import case

from datetime import datetime, timezone, timedelta
from app.models.campaign import Campaign
from app.models.endpoint import Endpoint


router = APIRouter(prefix="/analytics", tags=["analytics"])


# ─────────────────────────────────────────────
# GET /analytics/severity-distribution
# ─────────────────────────────────────────────
@router.get("/severity-distribution")
def severity_distribution(db: Session = Depends(get_db)):
    """
    Returns aggregated alert counts grouped by severity and status.
    SQL-level aggregation only.
    """

    results = (
        db.query(
            Alert.severity.label("severity"),
            Alert.status.label("status"),
            func.count(Alert.id).label("count"),
        )
        .group_by(Alert.severity, Alert.status)
        .all()
    )

    return [
        {
            "severity": row.severity,
            "status": row.status,
            "count": row.count,
        }
        for row in results
    ]


# ─────────────────────────────────────────────
# GET /analytics/alerts-per-endpoint
# ─────────────────────────────────────────────
@router.get("/alerts-per-endpoint")
def alerts_per_endpoint(db: Session = Depends(get_db)):
    """
    Returns aggregated alert metrics per endpoint.
    SQL aggregation only.
    """

    results = (
        db.query(
            Alert.endpoint_id.label("endpoint_id"),
            func.count(Alert.id).label("total_alerts"),
            func.count(case((Alert.status == "open", 1))).label("open_alerts"),
            func.count(case((Alert.status == "resolved", 1))).label("resolved_alerts"),
            func.avg(Alert.risk_score).label("avg_risk_score"),
        )
        .group_by(Alert.endpoint_id)
        .all()
    )

    return [
        {
            "endpoint_id": row.endpoint_id,
            "total_alerts": row.total_alerts,
            "open_alerts": row.open_alerts,
            "resolved_alerts": row.resolved_alerts,
            "avg_risk_score": (
                float(row.avg_risk_score) if row.avg_risk_score is not None else 0.0
            ),
        }
        for row in results
    ]


# ─────────────────────────────────────────────
# GET /analytics/top-rules
# ─────────────────────────────────────────────
@router.get("/top-rules")
def top_rules(
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1),
):
    """
    Returns top detection rules ranked by alert volume.
    Fully aggregated in SQL.
    """

    MAX_PAGE_SIZE = 100

    if page_size > MAX_PAGE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"page_size cannot exceed {MAX_PAGE_SIZE}",
        )

    base_query = (
        db.query(
            Alert.rule_name.label("rule_name"),
            func.count(Alert.id).label("alert_count"),
            func.avg(Alert.risk_score).label("avg_risk_score"),
            func.max(Alert.created_at).label("last_seen"),
        )
        .group_by(Alert.rule_name)
        .order_by(func.count(Alert.id).desc())
    )

    total = base_query.count()

    offset = (page - 1) * page_size

    results = base_query.offset(offset).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "results": [
            {
                "rule_name": row.rule_name,
                "alert_count": row.alert_count,
                "avg_risk_score": (
                    float(row.avg_risk_score) if row.avg_risk_score is not None else 0.0
                ),
                "last_seen": row.last_seen,
            }
            for row in results
        ],
    }


# ─────────────────────────────────────────────
# GET /analytics/endpoint-risk
# ─────────────────────────────────────────────
@router.get("/endpoint-risk")
def endpoint_risk(
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1),
):
    """
    Computes rolling 7-day deterministic risk index per endpoint.
    Fully aggregated in SQL.
    """

    MAX_PAGE_SIZE = 100

    if page_size > MAX_PAGE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"page_size cannot exceed {MAX_PAGE_SIZE}",
        )

    window_start = datetime.now(timezone.utc) - timedelta(days=7)

    # ─────────────────────────
    # Alerts Subquery
    # ─────────────────────────
    alerts_subq = (
        db.query(
            Alert.endpoint_id.label("endpoint_id"),
            func.count(case((Alert.status == "open", 1))).label("open_alerts"),
            func.avg(Alert.risk_score).label("avg_risk_score"),
            func.max(Alert.created_at).label("last_alert_time"),
        )
        .filter(Alert.created_at >= window_start)
        .group_by(Alert.endpoint_id)
        .subquery()
    )

    # ─────────────────────────
    # Campaigns Subquery
    # ─────────────────────────
    campaigns_subq = (
        db.query(
            Campaign.endpoint_id.label("endpoint_id"),
            func.sum(Campaign.campaign_risk_score).label("recent_campaign_risk"),
            func.max(Campaign.updated_at).label("last_campaign_time"),
        )
        .filter(Campaign.updated_at >= window_start)
        .group_by(Campaign.endpoint_id)
        .subquery()
    )

    # ─────────────────────────
    # Main Aggregation
    # ─────────────────────────
    query = (
        db.query(
            Endpoint.id.label("endpoint_id"),
            func.coalesce(alerts_subq.c.open_alerts, 0).label("open_alerts"),
            func.coalesce(alerts_subq.c.avg_risk_score, 0.0).label("avg_risk_score"),
            func.coalesce(campaigns_subq.c.recent_campaign_risk, 0).label(
                "recent_campaign_risk"
            ),
            func.greatest(
                func.coalesce(
                    alerts_subq.c.last_alert_time,
                    datetime(1970, 1, 1, tzinfo=timezone.utc),
                ),
                func.coalesce(
                    campaigns_subq.c.last_campaign_time,
                    datetime(1970, 1, 1, tzinfo=timezone.utc),
                ),
            ).label("last_activity"),
        )
        .outerjoin(
            alerts_subq,
            Endpoint.id == alerts_subq.c.endpoint_id,
        )
        .outerjoin(
            campaigns_subq,
            Endpoint.id == campaigns_subq.c.endpoint_id,
        )
    )

    total = query.count()

    offset = (page - 1) * page_size
    results = query.offset(offset).limit(page_size).all()

    response = []

    for row in results:
        open_alerts = row.open_alerts or 0
        avg_risk = float(row.avg_risk_score or 0.0)
        campaign_risk = row.recent_campaign_risk or 0

        risk_index = (open_alerts * 2) + (avg_risk * 1.5) + (campaign_risk * 1)

        response.append(
            {
                "endpoint_id": row.endpoint_id,
                "risk_index": round(risk_index, 2),
                "breakdown": {
                    "open_alerts": open_alerts,
                    "avg_risk_score": round(avg_risk, 2),
                    "recent_campaign_risk": campaign_risk,
                },
                "last_activity": row.last_activity,
            }
        )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "results": response,
    }
