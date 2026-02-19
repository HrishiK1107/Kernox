from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.alert import Alert
from app.models.campaign import Campaign, CampaignAlert
from app.services.risk_engine import RiskEngine


CORRELATION_WINDOW_MINUTES = 15


class CorrelationEngine:
    @staticmethod
    def run(db: Session, new_alert: Alert) -> None:
        window_start = datetime.now(timezone.utc) - timedelta(
            minutes=CORRELATION_WINDOW_MINUTES
        )

        campaign = (
            db.query(Campaign)
            .filter(Campaign.endpoint_id == new_alert.endpoint_id)
            .order_by(desc(Campaign.created_at))
            .first()
        )

        if campaign:
            last_alert = (
                db.query(Alert).filter(Alert.id == campaign.last_alert_id).first()
            )

            if last_alert:
                last_created = last_alert.created_at

                if last_created.tzinfo is None:
                    last_created = last_created.replace(tzinfo=timezone.utc)

                if last_created >= window_start:
                    CorrelationEngine._extend_campaign(db, campaign, new_alert)
                    return

        CorrelationEngine._create_campaign(db, new_alert)

    # ─────────────────────────────────────────────

    @staticmethod
    def _create_campaign(db: Session, alert: Alert) -> None:
        campaign = Campaign(
            endpoint_id=alert.endpoint_id,
            chain_length=1,
            campaign_risk_score=0,
            first_alert_id=alert.id,
            last_alert_id=alert.id,
        )

        db.add(campaign)
        db.flush()

        link = CampaignAlert(
            campaign_id=campaign.id,
            alert_id=alert.id,
            position=1,
        )

        db.add(link)
        db.flush()

        CorrelationEngine._recalculate_score(db, campaign)

    # ─────────────────────────────────────────────

    @staticmethod
    def _extend_campaign(
        db: Session,
        campaign: Campaign,
        alert: Alert,
    ) -> None:
        next_position = campaign.chain_length + 1

        link = CampaignAlert(
            campaign_id=campaign.id,
            alert_id=alert.id,
            position=next_position,
        )

        db.add(link)

        campaign.chain_length = next_position
        campaign.last_alert_id = alert.id

        db.flush()

        CorrelationEngine._recalculate_score(db, campaign)

    # ─────────────────────────────────────────────

    @staticmethod
    def _recalculate_score(db: Session, campaign: Campaign) -> None:
        links = (
            db.query(CampaignAlert)
            .filter(CampaignAlert.campaign_id == campaign.id)
            .all()
        )

        alert_ids = [link.alert_id for link in links]

        if not alert_ids:
            campaign.campaign_risk_score = 0
            return

        alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()

        score_data = RiskEngine.compute_campaign_score(alerts)

        campaign.campaign_risk_score = score_data["final_score"]
        campaign.score_breakdown = score_data
