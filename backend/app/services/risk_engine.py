from typing import Dict, List
from app.models.alert import Alert


class RiskEngine:
    """
    Deterministic, explainable risk scoring engine.
    Pure function. No DB access. No side effects.
    """

    CRITICAL_BONUS = 20
    MULTI_RULE_BONUS = 15
    CHAIN_LENGTH_THRESHOLD = 3
    CHAIN_BONUS = 10
    MAX_SCORE = 100

    @staticmethod
    def compute_campaign_score(alerts: List[Alert]) -> Dict:
        """
        Deterministic scoring contract.

        Returns:
        {
            "base_score": int,
            "critical_bonus": int,
            "multi_rule_bonus": int,
            "chain_bonus": int,
            "raw_score": int,
            "final_score": int,
            "capped": bool
        }
        """

        if not alerts:
            return {
                "base_score": 0,
                "critical_bonus": 0,
                "multi_rule_bonus": 0,
                "chain_bonus": 0,
                "raw_score": 0,
                "final_score": 0,
                "capped": False,
            }

        # ─────────────────────────────
        # Base score
        # ─────────────────────────────
        base_score = sum(alert.risk_score for alert in alerts)

        # ─────────────────────────────
        # Critical bonus
        # ─────────────────────────────
        critical_bonus = (
            RiskEngine.CRITICAL_BONUS
            if any(alert.severity == "critical" for alert in alerts)
            else 0
        )

        # ─────────────────────────────
        # Multi-rule bonus
        # ─────────────────────────────
        unique_rules = {alert.rule_name for alert in alerts}
        multi_rule_bonus = RiskEngine.MULTI_RULE_BONUS if len(unique_rules) >= 2 else 0

        # ─────────────────────────────
        # Chain bonus
        # ─────────────────────────────
        chain_bonus = (
            RiskEngine.CHAIN_BONUS
            if len(alerts) >= RiskEngine.CHAIN_LENGTH_THRESHOLD
            else 0
        )

        # ─────────────────────────────
        # Raw score
        # ─────────────────────────────
        raw_score = base_score + critical_bonus + multi_rule_bonus + chain_bonus

        # ─────────────────────────────
        # Cap enforcement
        # ─────────────────────────────
        capped = raw_score > RiskEngine.MAX_SCORE
        final_score = min(raw_score, RiskEngine.MAX_SCORE)

        return {
            "base_score": base_score,
            "critical_bonus": critical_bonus,
            "multi_rule_bonus": multi_rule_bonus,
            "chain_bonus": chain_bonus,
            "raw_score": raw_score,
            "final_score": final_score,
            "capped": capped,
        }
