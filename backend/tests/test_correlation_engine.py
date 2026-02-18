from datetime import datetime, timezone, timedelta

from app.models.alert import Alert
from app.models.campaign import Campaign
from app.services.correlation_engine import CorrelationEngine


def create_alert(db, endpoint_id, rule, severity, risk_score, created_at=None):
    alert = Alert(
        rule_name=rule,
        endpoint_id=endpoint_id,
        severity=severity,
        risk_score=risk_score,
        event_count=1,
        first_event_id="e1",
        last_event_id="e1",
        linked_event_ids=["e1"],
        is_escalated=False,
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.add(alert)
    db.flush()
    return alert


def test_campaign_created(db_session):
    alert = create_alert(db_session, 1, "rule1", "low", 10)

    CorrelationEngine.run(db_session, alert)
    db_session.commit()

    campaigns = db_session.query(Campaign).all()
    assert len(campaigns) == 1
    assert campaigns[0].chain_length == 1


def test_campaign_extended(db_session):
    alert1 = create_alert(db_session, 1, "rule1", "low", 10)
    CorrelationEngine.run(db_session, alert1)
    db_session.commit()

    alert2 = create_alert(db_session, 1, "rule2", "medium", 20)
    CorrelationEngine.run(db_session, alert2)
    db_session.commit()

    campaign = db_session.query(Campaign).first()
    assert campaign.chain_length == 2
    assert campaign.campaign_risk_score > 30


def test_new_campaign_after_window(db_session):
    old_time = datetime.now(timezone.utc) - timedelta(minutes=20)

    alert1 = create_alert(db_session, 1, "rule1", "low", 10, created_at=old_time)
    CorrelationEngine.run(db_session, alert1)
    db_session.commit()

    alert2 = create_alert(db_session, 1, "rule2", "low", 10)
    CorrelationEngine.run(db_session, alert2)
    db_session.commit()

    campaigns = db_session.query(Campaign).all()
    assert len(campaigns) == 2


def test_critical_bonus_applied(db_session):
    alert1 = create_alert(db_session, 1, "rule1", "critical", 30)
    CorrelationEngine.run(db_session, alert1)
    db_session.commit()

    campaign = db_session.query(Campaign).first()
    assert campaign.campaign_risk_score >= 50  # 30 + 20 bonus


def test_score_cap_at_100(db_session):
    alert1 = create_alert(db_session, 1, "rule1", "critical", 90)
    CorrelationEngine.run(db_session, alert1)

    alert2 = create_alert(db_session, 1, "rule2", "critical", 90)
    CorrelationEngine.run(db_session, alert2)

    db_session.commit()

    campaign = db_session.query(Campaign).first()
    assert campaign.campaign_risk_score <= 100
