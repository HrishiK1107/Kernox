from app.models.alert import Alert
from app.services.correlation_engine import CorrelationEngine
from app.models.campaign import Campaign


def make_alert(rule, severity, score):
    return Alert(
        rule_name=rule,
        endpoint_id=1,
        severity=severity,
        risk_score=score,
        event_count=1,
        first_event_id="e1",
        last_event_id="e1",
        linked_event_ids=["e1"],
        is_escalated=False,
    )


def test_score_breakdown_contract(db_session):
    alert1 = make_alert("r1", "critical", 30)
    alert2 = make_alert("r2", "low", 20)

    db_session.add(alert1)
    db_session.flush()
    CorrelationEngine.run(db_session, alert1)

    db_session.add(alert2)
    db_session.flush()
    CorrelationEngine.run(db_session, alert2)

    db_session.commit()

    campaign = db_session.query(Campaign).first()

    breakdown = campaign.score_breakdown

    # Required keys
    expected_keys = {
        "base_score",
        "critical_bonus",
        "multi_rule_bonus",
        "chain_bonus",
        "raw_score",
        "final_score",
        "capped",
    }

    assert set(breakdown.keys()) == expected_keys

    # Base score correctness
    assert breakdown["base_score"] == 50

    # Critical bonus applied
    assert breakdown["critical_bonus"] == 20

    # Multi-rule bonus applied
    assert breakdown["multi_rule_bonus"] == 15

    # Raw score math
    assert breakdown["raw_score"] == (
        breakdown["base_score"]
        + breakdown["critical_bonus"]
        + breakdown["multi_rule_bonus"]
        + breakdown["chain_bonus"]
    )

    # Final score consistency
    assert breakdown["final_score"] == campaign.campaign_risk_score
