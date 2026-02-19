from app.services.risk_engine import RiskEngine
from app.models.alert import Alert


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


def test_base_score_only():
    alerts = [
        make_alert("r1", "low", 10),
        make_alert("r1", "low", 20),
    ]

    result = RiskEngine.compute_campaign_score(alerts)

    assert result["base_score"] == 30
    assert result["critical_bonus"] == 0
    assert result["multi_rule_bonus"] == 0
    assert result["chain_bonus"] == 0
    assert result["final_score"] == 30
    assert result["capped"] is False


def test_critical_bonus():
    alerts = [
        make_alert("r1", "critical", 30),
    ]

    result = RiskEngine.compute_campaign_score(alerts)

    assert result["critical_bonus"] == 20
    assert result["final_score"] == 50


def test_multi_rule_bonus():
    alerts = [
        make_alert("r1", "low", 10),
        make_alert("r2", "low", 10),
    ]

    result = RiskEngine.compute_campaign_score(alerts)

    assert result["multi_rule_bonus"] == 15
    assert result["final_score"] == 35


def test_chain_bonus():
    alerts = [
        make_alert("r1", "low", 10),
        make_alert("r1", "low", 10),
        make_alert("r1", "low", 10),
    ]

    result = RiskEngine.compute_campaign_score(alerts)

    assert result["chain_bonus"] == 10
    assert result["final_score"] == 40


def test_score_cap():
    alerts = [
        make_alert("r1", "critical", 90),
        make_alert("r2", "critical", 90),
    ]

    result = RiskEngine.compute_campaign_score(alerts)

    assert result["final_score"] == 100
    assert result["capped"] is True


def test_empty_alert_list():
    result = RiskEngine.compute_campaign_score([])

    assert result["final_score"] == 0
    assert result["capped"] is False
