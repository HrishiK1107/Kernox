from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import asc, desc

from app.db.session import get_db
from app.models.campaign import Campaign
from app.schemas.campaign_read_schema import (
    CampaignRead,
    CampaignListResponse,
)

router = APIRouter()

MAX_PAGE_SIZE = 100

SORTABLE_FIELDS = {
    "created_at": Campaign.created_at,
    "campaign_risk_score": Campaign.campaign_risk_score,
    "chain_length": Campaign.chain_length,
}


# ─────────────────────────────────────────────
# List Campaigns
# ─────────────────────────────────────────────
@router.get("/campaigns", response_model=CampaignListResponse)
def list_campaigns(
    db: Session = Depends(get_db),
    endpoint_id: int | None = Query(default=None),
    min_risk: int | None = Query(default=None, ge=0),
    max_risk: int | None = Query(default=None, ge=0),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1),
    sort_by: str = Query(default="created_at"),
    sort_order: str = Query(default="desc"),
):
    # Page size cap
    if page_size > MAX_PAGE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"page_size cannot exceed {MAX_PAGE_SIZE}",
        )

    # Validate sort field
    if sort_by not in SORTABLE_FIELDS:
        raise HTTPException(
            status_code=400,
            detail="Invalid sort_by field",
        )

    query = db.query(Campaign)

    # Filtering
    if endpoint_id is not None:
        query = query.filter(Campaign.endpoint_id == endpoint_id)

    if min_risk is not None:
        query = query.filter(Campaign.campaign_risk_score >= min_risk)

    if max_risk is not None:
        query = query.filter(Campaign.campaign_risk_score <= max_risk)

    total = query.count()

    # Sorting
    sort_column = SORTABLE_FIELDS[sort_by]
    if sort_order == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))

    # Pagination
    offset = (page - 1) * page_size
    campaigns = query.offset(offset).limit(page_size).all()

    return CampaignListResponse(
        total=total,
        page=page,
        page_size=page_size,
        results=[CampaignRead.model_validate(c) for c in campaigns],
    )


# ─────────────────────────────────────────────
# Get Campaign by ID
# ─────────────────────────────────────────────
@router.get("/campaigns/{campaign_id}", response_model=CampaignRead)
def get_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()

    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    return CampaignRead.model_validate(campaign)
