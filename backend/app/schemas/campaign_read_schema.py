from pydantic import BaseModel
from datetime import datetime


class CampaignRead(BaseModel):
    id: int
    endpoint_id: int
    chain_length: int
    campaign_risk_score: int
    score_breakdown: dict
    first_alert_id: int
    last_alert_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CampaignListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    results: list[CampaignRead]
