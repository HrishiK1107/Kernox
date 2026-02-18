from sqlalchemy import (
    Integer,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime, timezone

from app.db.base import Base


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(primary_key=True)

    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="RESTRICT"),
        nullable=False,
    )

    chain_length: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    campaign_risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    first_alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="RESTRICT"),
        nullable=False,
    )

    last_alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="RESTRICT"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


Index("idx_campaigns_endpoint_id", Campaign.endpoint_id)
Index("idx_campaigns_created_at", Campaign.created_at)


class CampaignAlert(Base):
    __tablename__ = "campaign_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)

    campaign_id: Mapped[int] = mapped_column(
        ForeignKey("campaigns.id", ondelete="RESTRICT"),
        nullable=False,
    )

    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="RESTRICT"),
        nullable=False,
    )

    position: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


Index("idx_campaign_alerts_campaign_id", CampaignAlert.campaign_id)
Index("idx_campaign_alerts_alert_id", CampaignAlert.alert_id)
