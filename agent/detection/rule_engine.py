"""
Kernox — Detection Rule Engine

A Sigma-style behavioral detection DSL that allows security teams
to define custom rules for threat detection. Rules are YAML files
loaded at agent startup.

Rule Format:
    name: Suspicious curl to external IP
    description: Detects curl downloading from external IPs
    severity: high
    conditions:
      - field: process_name
        operator: equals
        value: curl
      - field: event_type
        operator: equals
        value: network_connect
    match: all  # all | any
    action: alert

Supports operators: equals, contains, regex, gt, lt, in, not_equals
"""

import os
import re
import glob

from agent.logging_config import logger

# Try to import yaml, fall back to basic parser
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class RuleCondition:
    """A single condition in a detection rule."""

    VALID_OPERATORS = {
        "equals", "not_equals", "contains",
        "regex", "gt", "lt", "gte", "lte", "in",
    }

    def __init__(self, field: str, operator: str, value):
        if operator not in self.VALID_OPERATORS:
            raise ValueError(f"Invalid operator: {operator}")
        self.field = field
        self.operator = operator
        self.value = value
        self._regex = None
        if operator == "regex":
            self._regex = re.compile(str(value), re.IGNORECASE)

    def evaluate(self, event: dict) -> bool:
        """Check if this condition matches the event."""
        event_value = self._get_nested(event, self.field)
        if event_value is None:
            return False

        try:
            if self.operator == "equals":
                return str(event_value) == str(self.value)
            elif self.operator == "not_equals":
                return str(event_value) != str(self.value)
            elif self.operator == "contains":
                return str(self.value) in str(event_value)
            elif self.operator == "regex":
                return bool(self._regex.search(str(event_value)))
            elif self.operator == "gt":
                return float(event_value) > float(self.value)
            elif self.operator == "lt":
                return float(event_value) < float(self.value)
            elif self.operator == "gte":
                return float(event_value) >= float(self.value)
            elif self.operator == "lte":
                return float(event_value) <= float(self.value)
            elif self.operator == "in":
                if isinstance(self.value, list):
                    return str(event_value) in [str(v) for v in self.value]
                return str(event_value) in str(self.value)
        except (ValueError, TypeError):
            return False

        return False

    @staticmethod
    def _get_nested(data: dict, key: str):
        """Get a value from a nested dict using dot notation (e.g. 'process.name')."""
        parts = key.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current


class DetectionRule:
    """A complete detection rule with conditions and metadata."""

    def __init__(self, name: str, description: str, severity: str,
                 conditions: list[RuleCondition], match: str = "all",
                 action: str = "alert"):
        self.name = name
        self.description = description
        self.severity = severity
        self.conditions = conditions
        self.match = match  # "all" or "any"
        self.action = action
        self.hit_count = 0

    def evaluate(self, event: dict) -> bool:
        """Check if this rule matches the event."""
        if not self.conditions:
            return False

        if self.match == "all":
            result = all(c.evaluate(event) for c in self.conditions)
        else:
            result = any(c.evaluate(event) for c in self.conditions)

        if result:
            self.hit_count += 1
        return result


class RuleEngine:
    """
    Loads and evaluates detection rules against incoming events.
    """

    def __init__(self, emitter, rules_dir: str = None):
        self._emitter = emitter
        self._rules: list[DetectionRule] = []
        self._rules_dir = rules_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "rules"
        )

    def load_rules(self) -> int:
        """Load all YAML rule files from the rules directory."""
        if not os.path.isdir(self._rules_dir):
            logger.info("No rules directory found at %s, skipping", self._rules_dir)
            return 0

        if not HAS_YAML:
            logger.warning("PyYAML not installed — rule engine disabled")
            return 0

        rule_files = glob.glob(os.path.join(self._rules_dir, "*.yml"))
        rule_files += glob.glob(os.path.join(self._rules_dir, "*.yaml"))

        loaded = 0
        for path in sorted(rule_files):
            try:
                rule = self._parse_rule_file(path)
                if rule:
                    self._rules.append(rule)
                    loaded += 1
            except Exception as e:
                logger.warning("Failed to load rule %s: %s", path, e)

        logger.info("Loaded %d detection rules from %s", loaded, self._rules_dir)
        return loaded

    def evaluate(self, event: dict) -> None:
        """Evaluate all rules against an event, emit alerts for matches."""
        for rule in self._rules:
            try:
                if rule.evaluate(event):
                    self._emit_rule_match(rule, event)
            except Exception:
                pass

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules)

    def _parse_rule_file(self, path: str) -> DetectionRule | None:
        """Parse a YAML rule file into a DetectionRule."""
        with open(path) as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            return None

        name = data.get("name", os.path.basename(path))
        description = data.get("description", "")
        severity = data.get("severity", "medium")
        match = data.get("match", "all")
        action = data.get("action", "alert")

        raw_conditions = data.get("conditions", [])
        conditions = []
        for cond in raw_conditions:
            if isinstance(cond, dict):
                conditions.append(RuleCondition(
                    field=cond.get("field", ""),
                    operator=cond.get("operator", "equals"),
                    value=cond.get("value", ""),
                ))

        return DetectionRule(
            name=name,
            description=description,
            severity=severity,
            conditions=conditions,
            match=match,
            action=action,
        )

    def _emit_rule_match(self, rule: DetectionRule, event: dict) -> None:
        """Emit an alert event when a rule matches."""
        self._emitter.emit({
            "event_type": "alert_rule_match",
            "severity": rule.severity,
            "rule_name": rule.name,
            "rule_description": rule.description,
            "process_name": event.get("process", {}).get("name", "")
                if isinstance(event.get("process"), dict)
                else event.get("process_name", "unknown"),
            "username": event.get("process", {}).get("user", "")
                if isinstance(event.get("process"), dict)
                else event.get("username", "unknown"),
            "matched_event_type": event.get("event_type", ""),
        })
