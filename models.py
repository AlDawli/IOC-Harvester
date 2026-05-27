"""
IOC Harvester - Data Models
Pydantic models for normalized IOC representation across all sources.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


class ThreatCategory(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    EXPLOIT = "exploit"
    C2 = "c2"
    SPAM = "spam"
    SCANNER = "scanner"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class MitreAttack(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    sub_technique_id: Optional[str] = None


class IOC(BaseModel):
    """Normalized Indicator of Compromise."""

    # Core fields
    value: str
    ioc_type: IOCType
    source: str

    # Threat intelligence
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    malware_family: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN

    # Timestamps
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    collected_at: datetime = Field(default_factory=datetime.utcnow)

    # Attribution & context
    mitre_techniques: list[MitreAttack] = Field(default_factory=list)
    country: Optional[str] = None
    asn: Optional[str] = None
    description: Optional[str] = None

    # Source-specific metadata
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        return v.strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "type": self.ioc_type.value,
            "source": self.source,
            "threat_category": self.threat_category.value,
            "malware_family": self.malware_family or "",
            "tags": ",".join(self.tags),
            "confidence": self.confidence.value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else "",
            "last_seen": self.last_seen.isoformat() if self.last_seen else "",
            "collected_at": self.collected_at.isoformat(),
            "country": self.country or "",
            "asn": self.asn or "",
            "description": self.description or "",
        }


# ──────────────────────────────────────────────────
# MITRE ATT&CK Mapping Registry
# Maps threat categories / malware families → techniques
# ──────────────────────────────────────────────────

MITRE_MAPPING: dict[str, list[MitreAttack]] = {
    "c2": [
        MitreAttack(
            technique_id="T1071",
            technique_name="Application Layer Protocol",
            tactic="command-and-control",
        ),
        MitreAttack(
            technique_id="T1095",
            technique_name="Non-Application Layer Protocol",
            tactic="command-and-control",
        ),
    ],
    "botnet": [
        MitreAttack(
            technique_id="T1583.001",
            technique_name="Acquire Infrastructure: Domains",
            tactic="resource-development",
        ),
        MitreAttack(
            technique_id="T1071.001",
            technique_name="Web Protocols",
            tactic="command-and-control",
        ),
    ],
    "ransomware": [
        MitreAttack(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic="impact",
        ),
        MitreAttack(
            technique_id="T1490",
            technique_name="Inhibit System Recovery",
            tactic="impact",
        ),
        MitreAttack(
            technique_id="T1071",
            technique_name="Application Layer Protocol",
            tactic="command-and-control",
        ),
    ],
    "phishing": [
        MitreAttack(
            technique_id="T1566.001",
            technique_name="Spearphishing Attachment",
            tactic="initial-access",
        ),
        MitreAttack(
            technique_id="T1566.002",
            technique_name="Spearphishing Link",
            tactic="initial-access",
        ),
    ],
    "malware": [
        MitreAttack(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
        ),
        MitreAttack(
            technique_id="T1055",
            technique_name="Process Injection",
            tactic="defense-evasion",
        ),
    ],
    "trojan": [
        MitreAttack(
            technique_id="T1055",
            technique_name="Process Injection",
            tactic="defense-evasion",
        ),
        MitreAttack(
            technique_id="T1027",
            technique_name="Obfuscated Files or Information",
            tactic="defense-evasion",
        ),
    ],
    "exploit": [
        MitreAttack(
            technique_id="T1203",
            technique_name="Exploitation for Client Execution",
            tactic="execution",
        ),
        MitreAttack(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
        ),
    ],
    "scanner": [
        MitreAttack(
            technique_id="T1595",
            technique_name="Active Scanning",
            tactic="reconnaissance",
        ),
        MitreAttack(
            technique_id="T1046",
            technique_name="Network Service Discovery",
            tactic="discovery",
        ),
    ],
}


def enrich_mitre(ioc: IOC) -> IOC:
    """Attach MITRE ATT&CK techniques based on threat category."""
    key = ioc.threat_category.value
    if key in MITRE_MAPPING:
        ioc.mitre_techniques = MITRE_MAPPING[key]
    return ioc
