from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.alert import Alert
from app.models.alert_status_history import AlertStatusHistory


ALLOWED_TRANSITIONS = {
    "open": {"acknowledged"},
    "acknowledged": {"resolved"},
    "resolved": set(),
}


class StatusTransitionService:
    @staticmethod
    def transition(
        db: Session,
        *,
        alert_id: int,
        new_status: str,
    ) -> None:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()

        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found",
            )

        current_status = alert.status

        # Validate target status exists
        if new_status not in ALLOWED_TRANSITIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status value",
            )

        # Validate transition
        if new_status not in ALLOWED_TRANSITIONS[current_status]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status transition",
            )

        # Write history first (immutable record)
        history = AlertStatusHistory(
            alert_id=alert.id,
            previous_status=current_status,
            new_status=new_status,
        )

        db.add(history)

        # Now update alert status
        alert.status = new_status

        db.commit()
