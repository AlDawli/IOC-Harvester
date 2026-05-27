"""
IOC Harvester - Sigma Rule Exporter
Generates Sigma detection rules from harvested IOCs.
https://sigmahq.io/
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ioc_harvester.models import IOC, IOCType, ThreatCategory

logger = logging.getLogger(__name__)

# ── Sigma templates per IOC type ─────────────────────────────

_TACTIC_TO_SIGMA_CATEGORY = {
    "command-and-control": "network_connection",
    "initial-access": "webserver",
    "execution": "process_creation",
    "defense-evasion": "process_creation",
    "impact": "process_creation",
    "reconnaissance": "network_connection",
    "resource-development": "dns_query",
}


def _make_network_rule(iocs: list[IOC], ioc_type: IOCType) -> dict:
    """Build a Sigma rule for network-based IOCs (IPs, domains, URLs)."""
    values = sorted({i.value for i in iocs})
    sources = sorted({i.source for i in iocs})
    threats = sorted({i.threat_category.value for i in iocs if i.threat_category.value != "unknown"})
    mitre_ids = []
    for ioc in iocs:
        for t in ioc.mitre_techniques:
            if t.technique_id not in mitre_ids:
                mitre_ids.append(t.technique_id)

    type_label = {
        IOCType.IP: "IP",
        IOCType.DOMAIN: "Domain",
        IOCType.URL: "URL",
    }.get(ioc_type, ioc_type.value.upper())

    field_map = {
        IOCType.IP: {"detection_field": "DestinationIp", "category": "network_connection"},
        IOCType.DOMAIN: {"detection_field": "query", "category": "dns_query"},
        IOCType.URL: {"detection_field": "c-uri|contains", "category": "proxy"},
    }
    fm = field_map.get(ioc_type, {"detection_field": "DestinationIp", "category": "network_connection"})

    rule = {
        "title": f"IOC Harvester - Malicious {type_label} Connections",
        "id": _generate_uuid(f"ioc-{ioc_type.value}"),
        "status": "experimental",
        "description": (
            f"Detects connections to malicious {type_label.lower()}s harvested from "
            f"{', '.join(sources)}. Threats: {', '.join(threats) or 'unknown'}."
        ),
        "references": [
            "https://urlhaus.abuse.ch",
            "https://otx.alienvault.com",
            "https://threatfox.abuse.ch",
        ],
        "author": "IOC Harvester",
        "date": datetime.now(tz=timezone.utc).strftime("%Y/%m/%d"),
        "tags": [f"attack.{t}" for t in mitre_ids[:5]] + ["tlp.white"],
        "logsource": {"category": fm["category"]},
        "detection": {
            "selection": {fm["detection_field"]: values[:500]},  # cap at 500 per rule
            "condition": "selection",
        },
        "falsepositives": ["Legitimate use of listed infrastructure (review before blocking)"],
        "level": "high",
    }
    return rule


def _make_hash_rule(iocs: list[IOC], ioc_type: IOCType) -> dict:
    """Build a Sigma rule for file hash IOCs."""
    values = sorted({i.value for i in iocs})
    sources = sorted({i.source for i in iocs})
    families = sorted({i.malware_family for i in iocs if i.malware_family})
    mitre_ids = []
    for ioc in iocs:
        for t in ioc.mitre_techniques:
            if t.technique_id not in mitre_ids:
                mitre_ids.append(t.technique_id)

    hash_field_map = {
        IOCType.HASH_MD5: "md5",
        IOCType.HASH_SHA1: "sha1",
        IOCType.HASH_SHA256: "sha256",
    }
    field = hash_field_map.get(ioc_type, "sha256")

    return {
        "title": f"IOC Harvester - Malicious File Hash ({field.upper()})",
        "id": _generate_uuid(f"ioc-{ioc_type.value}"),
        "status": "experimental",
        "description": (
            f"Detects execution of files matching malicious {field.upper()} hashes "
            f"from {', '.join(sources)}. Families: {', '.join(families) or 'unknown'}."
        ),
        "references": ["https://bazaar.abuse.ch", "https://threatfox.abuse.ch"],
        "author": "IOC Harvester",
        "date": datetime.now(tz=timezone.utc).strftime("%Y/%m/%d"),
        "tags": [f"attack.{t}" for t in mitre_ids[:5]] + ["tlp.white"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {f"Hashes|contains": [f"{field.upper()}={v}" for v in values[:200]]},
            "condition": "selection",
        },
        "falsepositives": ["Legitimate software sharing hash values (extremely unlikely for SHA256)"],
        "level": "critical" if ioc_type == IOCType.HASH_SHA256 else "high",
    }


def _generate_uuid(seed: str) -> str:
    import hashlib
    h = hashlib.md5(seed.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def export_sigma(iocs: list[IOC], output_dir: Path | str | None = None) -> list[str]:
    """
    Export IOCs as Sigma YAML rules, grouped by IOC type.

    Args:
        iocs: List of IOC objects.
        output_dir: Directory to write .yml files. If None, returns list of YAML strings.

    Returns:
        List of Sigma rule YAML strings.
    """
    grouped: dict[IOCType, list[IOC]] = defaultdict(list)
    for ioc in iocs:
        grouped[ioc.ioc_type].append(ioc)

    rules: list[str] = []
    rule_builders = {
        IOCType.IP: _make_network_rule,
        IOCType.DOMAIN: _make_network_rule,
        IOCType.URL: _make_network_rule,
        IOCType.HASH_MD5: _make_hash_rule,
        IOCType.HASH_SHA1: _make_hash_rule,
        IOCType.HASH_SHA256: _make_hash_rule,
    }

    for ioc_type, ioc_list in grouped.items():
        builder = rule_builders.get(ioc_type)
        if not builder or not ioc_list:
            continue
        rule_dict = builder(ioc_list, ioc_type)
        rule_yaml = yaml.dump(rule_dict, default_flow_style=False, allow_unicode=True, sort_keys=False)
        rules.append(rule_yaml)

        if output_dir:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            fname = f"ioc_harvester_{ioc_type.value}.yml"
            (out / fname).write_text(rule_yaml, encoding="utf-8")
            logger.info("Sigma: wrote rule → %s/%s (%d IOCs)", out, fname, len(ioc_list))

    logger.info("Sigma: generated %d rules total", len(rules))
    return rules
