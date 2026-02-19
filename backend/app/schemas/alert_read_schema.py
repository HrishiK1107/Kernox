from datetime import datetime
from pydantic import BaseModel
from typing import List


class AlertRead(BaseModel):
    id: int
    rule_name: str
    endpoint_id: int
    severity: str
    risk_score: int
    status: str
    event_count: int
    first_event_id: str
    last_event_id: str
    linked_event_ids: List[str]
    is_escalated: bool
    created_at: datetime

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[AlertRead]
