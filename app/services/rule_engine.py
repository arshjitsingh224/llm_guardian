"""
Rule Engine — loads YAML rules and evaluates them against prompt text.
Handles keyword_block and pattern_match rules.
PII rules are handed off to pii_scanner.py.
"""
import re
import yaml
import logging
import base64
import binascii
import unicodedata
from urllib.parse import unquote
from pathlib import Path
from app.models.schemas import ThreatDetail
from app.config import settings

logger = logging.getLogger(__name__)


HOMOGLYPH_TRANSLATION = str.maketrans({
    "і": "i",  # Cyrillic small i
    "І": "I",
    "ɪ": "i",
    "ɢ": "g",
    "ɴ": "n",
    "ᴏ": "o",
    "ʀ": "r",
    "ᴇ": "e",
})


SAFE_CONTEXT_PATTERNS = [
    re.compile(
        r"(?i)\b(explain|define|what is|what are|meaning of|phrase|term|concept)\b"
        r".{0,80}\b(jailbreak|prompt injection|ignore previous instructions)\b"
    ),
    re.compile(
        r"(?i)\b(previous instructions were unclear|let me rephrase|corrected version|forget my last message)\b"
    ),
]


class Rule:
    def __init__(self, data: dict):
        self.id = data["id"]
        self.name = data["name"]
        self.type = data["type"]
        self.action = data["action"]  # block | sanitize | warn
        self.severity = data.get("severity", "MEDIUM")
        self.description = data.get("description", "")
        self.replacement = data.get("replacement", "")  # for sanitize action
        # type-specific fields
        self.keywords = [k.lower() for k in data.get("keywords", [])]
        self.pattern = data.get("pattern")
        self.pii_entities = data.get("pii_entities", [])
        self._compiled = re.compile(self.pattern) if self.pattern else None

    def match(self, text: str) -> bool:
        if self.type == "keyword_block":
            lower = normalize_for_detection(text).lower()
            return any(kw in lower for kw in self.keywords if kw)
        if self.type == "pattern_match":
            if _is_safe_context(text, self.id):
                return False
            return bool(self._compiled and any(self._compiled.search(candidate) for candidate in detection_variants(text)))
        return False  # pii rules are handled separately

    def sanitize(self, text: str) -> str:
        """Replace matched pattern with the replacement string."""
        if self.type == "pattern_match" and self._compiled and self.replacement:
            return self._compiled.sub(self.replacement, text)
        return text


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

    def apply_sanitizations(self, text: str) -> tuple[str, bool]:
        """
        Apply all sanitize-action pattern rules to text.
        Returns (sanitized_text, was_changed).
        """
        result = text
        for rule in self._rules:
            if rule.type == "pii":
                continue
            if rule.action == "sanitize" and rule._compiled and rule._compiled.search(result):
                result = rule.sanitize(result)
        return result, result != text


def detection_variants(text: str) -> list[str]:
    """Return normalized/decoded views of text for adversarial rule matching."""
    variants = [text, normalize_for_detection(text)]

    url_decoded = unquote(text)
    if url_decoded != text:
        variants.append(normalize_for_detection(url_decoded))

    stripped = text.strip()
    if _looks_like_base64(stripped):
        try:
            decoded = base64.b64decode(stripped, validate=True).decode("utf-8")
            variants.append(normalize_for_detection(decoded))
        except (binascii.Error, UnicodeDecodeError):
            pass

    return list(dict.fromkeys(variants))


def normalize_for_detection(text: str) -> str:
    """Normalize common prompt-obfuscation characters before regex matching."""
    return unicodedata.normalize("NFKC", text).translate(HOMOGLYPH_TRANSLATION)


def _looks_like_base64(text: str) -> bool:
    return bool(
        len(text) >= 16
        and len(text) % 4 == 0
        and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text)
    )


def _is_safe_context(text: str, rule_id: str) -> bool:
    if not (rule_id.startswith("injection_") or rule_id.startswith("jailbreak_")):
        return False
    return is_benign_security_context(text)


def is_benign_security_context(text: str) -> bool:
    """True for educational security questions or ordinary message corrections."""
    return any(pattern.search(text) for pattern in SAFE_CONTEXT_PATTERNS)


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
