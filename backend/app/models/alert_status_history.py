from sqlalchemy import (
    String,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime, timezone

from app.db.base import Base


class AlertStatusHistory(Base):
    __tablename__ = "alert_status_history"

    id: Mapped[int] = mapped_column(primary_key=True)

    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="RESTRICT"),
        nullable=False,
    )

    previous_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    new_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


Index("idx_alert_status_alert_id", AlertStatusHistory.alert_id)
Index("idx_alert_status_changed_at", AlertStatusHistory.changed_at)
