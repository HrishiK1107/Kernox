from sqlalchemy import (
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Enum,
    CheckConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime, timezone
import enum

from app.db.base import Base


# ─────────────────────────────────────────────
# Dialect-aware JSON
# ─────────────────────────────────────────────
class JSONBCompat(TypeDecorator):
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


# ─────────────────────────────────────────────
# Alert Status Enum
# ─────────────────────────────────────────────
class AlertStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


# ─────────────────────────────────────────────
# Alert Model
# ─────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved')",
            name="chk_alert_status_valid",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    rule_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    endpoint_id: Mapped[int] = mapped_column(
        ForeignKey("endpoints.id", ondelete="RESTRICT"),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    event_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    first_event_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    last_event_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    linked_event_ids: Mapped[list] = mapped_column(
        JSONBCompat(),
        nullable=False,
    )

    is_escalated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    # 🔐 Store ENUM VALUE (not name)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(
            AlertStatus,
            native_enum=False,
            values_callable=lambda enum_cls: [e.value for e in enum_cls],
        ),
        nullable=False,
        default=AlertStatus.OPEN,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ─────────────────────────────────────────────
# Indexes
# ─────────────────────────────────────────────
Index("idx_alerts_endpoint_id", Alert.endpoint_id)
Index("idx_alerts_rule_name", Alert.rule_name)
Index("idx_alerts_created_at", Alert.created_at)
