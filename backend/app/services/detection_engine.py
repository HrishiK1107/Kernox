from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.models.event import Event
from app.models.alert import Alert
from app.services.rule_registry import RULES, DetectionResult
from app.services.correlation_engine import CorrelationEngine


class DetectionEngine:
    """
    Deterministic detection executor.
    Runs inside existing DB transaction.
    Does NOT commit.
    """

    @staticmethod
    def run(db: Session, event: Event) -> None:
        """
        Execute all rules against a single event.
        """

        for rule in RULES:
            results = rule.evaluate(db, event)

            for result in results:
                DetectionEngine._create_alert_if_not_exists(
                    db=db,
                    result=result,
                    endpoint_id=event.endpoint_id,
                )

    @staticmethod
    def _create_alert_if_not_exists(
        db: Session,
        *,
        result: DetectionResult,
        endpoint_id: int,
    ) -> None:
        """
        Prevent duplicate alerts for same rule + same last_event_id.
        """

        last_event_id = result.matched_events[-1].event_id

        existing = (
            db.query(Alert)
            .filter(
                and_(
                    Alert.rule_name == result.rule_name,
                    Alert.endpoint_id == endpoint_id,
                    Alert.last_event_id == last_event_id,
                )
            )
            .first()
        )

        if existing:
            return

        alert = Alert(
            rule_name=result.rule_name,
            endpoint_id=endpoint_id,
            severity=result.severity,
            risk_score=result.risk_score,
            event_count=len(result.matched_events),
            first_event_id=result.matched_events[0].event_id,
            last_event_id=last_event_id,
            linked_event_ids=[e.event_id for e in result.matched_events],
            is_escalated=False,
        )

        # Add alert inside current transaction
        db.add(alert)
        db.flush()  # ensure alert.id is generated before correlation

        # 🔥 Phase 5 — Correlate alert into campaign
        CorrelationEngine.run(db, alert)
