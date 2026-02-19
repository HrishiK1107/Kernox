from pydantic import BaseModel, Field


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., min_length=3, max_length=50)

    model_config = {"extra": "forbid"}
