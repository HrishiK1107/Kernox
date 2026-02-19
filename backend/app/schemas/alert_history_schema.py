from pydantic import BaseModel
from datetime import datetime


class AlertStatusHistoryRead(BaseModel):
    previous_status: str
    new_status: str
    changed_at: datetime

    class Config:
        from_attributes = True
