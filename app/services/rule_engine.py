"""
Rule Engine — loads YAML rules and evaluates them against prompt text.
Handles keyword_block and pattern_match rules.
PII rules are handed off to pii_scanner.py.
"""
import re
import yaml
import logging
from pathlib import Path
from app.models.schemas import ThreatDetail
from app.config import settings

logger = logging.getLogger(__name__)


class Rule:
    def __init__(self, data: dict):
        self.id = data["id"]
        self.name = data["name"]
        self.type = data["type"]
        self.action = data["action"]  # block | sanitize | warn
        self.severity = data.get("severity", "MEDIUM")
        self.description = data.get("description", "")
        # type-specific fields
        self.keywords = [k.lower() for k in data.get("keywords", [])]
        self.pattern = data.get("pattern")
        self.pii_entities = data.get("pii_entities", [])
        self._compiled = re.compile(self.pattern) if self.pattern else None

    def match(self, text: str) -> bool:
        if self.type == "keyword_block":
            lower = text.lower()
            return any(kw in lower for kw in self.keywords if kw)
        if self.type == "pattern_match":
            return bool(self._compiled and self._compiled.search(text))
        return False  # pii rules are handled separately


class RuleEngine:
    def __init__(self):
        self._rules: list[Rule] = []
        self.load_rules()

    def load_rules(self):
        path = Path(settings.rules_path)
        if not path.exists():
            logger.warning(f"Rules file not found at {path}, using empty ruleset")
            return
        with open(path) as f:
            data = yaml.safe_load(f)
        self._rules = [Rule(r) for r in data.get("rules", [])]
        logger.info(f"Loaded {len(self._rules)} rules from {path}")

    def reload(self):
        """Hot-reload rules without restarting the server."""
        self._rules = []
        self.load_rules()

    @property
    def pii_rules(self) -> list[Rule]:
        return [r for r in self._rules if r.type == "pii"]

    def evaluate(self, text: str) -> list[ThreatDetail]:
        """
        Run all non-PII rules against text.
        Returns list of ThreatDetail for every rule that fired.
        """
        threats: list[ThreatDetail] = []
        for rule in self._rules:
            if rule.type == "pii":
                continue  # handled by pii_scanner
            if rule.match(text):
                threat_type = _action_to_threat(rule)
                threats.append(ThreatDetail(
                    type=threat_type,
                    severity=rule.severity,
                    source="rule_engine",
                    detail=f"Rule '{rule.name}' matched: {rule.description}",
                    rule_id=rule.id,
                ))
        return threats


def _action_to_threat(rule: Rule) -> str:
    """Map rule id prefix / name to a canonical threat type."""
    rid = rule.id.lower()
    if "injection" in rid:
        return "PROMPT_INJECTION"
    if "jailbreak" in rid:
        return "JAILBREAK"
    if "pii" in rid:
        return "PII"
    return "SUSPICIOUS"


# Singleton — loaded once at startup
rule_engine = RuleEngine()
