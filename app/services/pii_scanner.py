"""
PII Scanner — wraps Microsoft Presidio for detection and anonymization.
Reads which PII entities to scan from YAML pii rules.
"""
import logging
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from app.models.schemas import ThreatDetail
from app.services.rule_engine import rule_engine

logger = logging.getLogger(__name__)


class PIIScanner:
    def __init__(self):
        logger.info("Initialising Presidio engines...")
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        logger.info("Presidio ready.")

    def scan_and_redact(self, text: str) -> tuple[str, list[ThreatDetail]]:
        """
        Scan text for PII defined in YAML pii rules.
        Returns (redacted_text, threats).
        Threats have action embedded so decision.py can act on them.
        """
        threats: list[ThreatDetail] = []
        redacted = text

        for rule in rule_engine.pii_rules:
            if not rule.pii_entities:
                continue

            results = self.analyzer.analyze(
                text=text,
                entities=rule.pii_entities,
                language="en",
            )

            if not results:
                continue

            entity_types = list({r.entity_type for r in results})

            # Redact if action is sanitize; otherwise just record threat
            if rule.action == "sanitize":
                operators = {
                    entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
                    for entity in entity_types
                }
                anonymized = self.anonymizer.anonymize(
                    text=redacted,
                    analyzer_results=results,
                    operators=operators,
                )
                redacted = anonymized.text

            threats.append(ThreatDetail(
                type="PII",
                severity=rule.severity,
                source="pii_scanner",
                detail=f"Detected PII entities: {', '.join(entity_types)}",
                rule_id=rule.id,
            ))

        return redacted, threats


# Singleton
pii_scanner = PIIScanner()
