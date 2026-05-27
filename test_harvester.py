"""
IOC Harvester - Test Suite
"""

from __future__ import annotations

import pytest
import respx
import httpx
from datetime import datetime

from ioc_harvester.models import (
    IOC,
    IOCType,
    ThreatCategory,
    Confidence,
    MitreAttack,
    enrich_mitre,
    MITRE_MAPPING,
)
from ioc_harvester.exporters.csv_exporter import export_csv
from ioc_harvester.exporters.sigma_exporter import export_sigma
from ioc_harvester.exporters.firewall_exporter import (
    export_iptables,
    export_nftables,
    export_dns_blocklist,
    export_plaintext,
)


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def sample_iocs() -> list[IOC]:
    return [
        IOC(
            value="192.168.1.100",
            ioc_type=IOCType.IP,
            source="threatfox",
            threat_category=ThreatCategory.C2,
            confidence=Confidence.HIGH,
            tags=["c2", "botnet"],
        ),
        IOC(
            value="malicious-domain.example.com",
            ioc_type=IOCType.DOMAIN,
            source="urlhaus",
            threat_category=ThreatCategory.MALWARE,
            confidence=Confidence.MEDIUM,
        ),
        IOC(
            value="https://evil.example.com/payload",
            ioc_type=IOCType.URL,
            source="urlhaus",
            threat_category=ThreatCategory.MALWARE,
        ),
        IOC(
            value="d41d8cd98f00b204e9800998ecf8427e",
            ioc_type=IOCType.HASH_MD5,
            source="malwarebazaar",
            threat_category=ThreatCategory.RANSOMWARE,
            malware_family="LockBit",
            confidence=Confidence.HIGH,
        ),
        IOC(
            value="a" * 64,  # fake SHA256
            ioc_type=IOCType.HASH_SHA256,
            source="malwarebazaar",
            threat_category=ThreatCategory.TROJAN,
            malware_family="Emotet",
        ),
    ]


# ── Model Tests ───────────────────────────────────────────────

class TestIOCModel:
    def test_basic_creation(self):
        ioc = IOC(value="1.2.3.4", ioc_type=IOCType.IP, source="test")
        assert ioc.value == "1.2.3.4"
        assert ioc.ioc_type == IOCType.IP

    def test_value_stripped(self):
        ioc = IOC(value="  1.2.3.4  ", ioc_type=IOCType.IP, source="test")
        assert ioc.value == "1.2.3.4"

    def test_to_dict(self):
        ioc = IOC(value="1.2.3.4", ioc_type=IOCType.IP, source="test", tags=["c2", "botnet"])
        d = ioc.to_dict()
        assert d["value"] == "1.2.3.4"
        assert d["type"] == "ip"
        assert "c2" in d["tags"]

    def test_defaults(self):
        ioc = IOC(value="example.com", ioc_type=IOCType.DOMAIN, source="test")
        assert ioc.threat_category == ThreatCategory.UNKNOWN
        assert ioc.confidence == Confidence.UNKNOWN
        assert ioc.mitre_techniques == []

    def test_collected_at_set_automatically(self):
        ioc = IOC(value="x.com", ioc_type=IOCType.DOMAIN, source="test")
        assert isinstance(ioc.collected_at, datetime)


class TestMitreEnrichment:
    def test_enrich_c2(self):
        ioc = IOC(value="1.2.3.4", ioc_type=IOCType.IP, source="test",
                  threat_category=ThreatCategory.C2)
        enriched = enrich_mitre(ioc)
        assert len(enriched.mitre_techniques) > 0
        ids = [t.technique_id for t in enriched.mitre_techniques]
        assert "T1071" in ids

    def test_enrich_ransomware(self):
        ioc = IOC(value="abc123", ioc_type=IOCType.HASH_SHA256, source="test",
                  threat_category=ThreatCategory.RANSOMWARE)
        enriched = enrich_mitre(ioc)
        ids = [t.technique_id for t in enriched.mitre_techniques]
        assert "T1486" in ids

    def test_unknown_no_techniques(self):
        ioc = IOC(value="x.com", ioc_type=IOCType.DOMAIN, source="test",
                  threat_category=ThreatCategory.UNKNOWN)
        enriched = enrich_mitre(ioc)
        assert enriched.mitre_techniques == []

    def test_all_categories_have_techniques(self):
        for key in MITRE_MAPPING:
            assert len(MITRE_MAPPING[key]) > 0, f"No techniques for {key}"


# ── CSV Exporter Tests ────────────────────────────────────────

class TestCSVExporter:
    def test_output_has_header(self, sample_iocs):
        csv_content = export_csv(sample_iocs)
        assert "value" in csv_content
        assert "type" in csv_content
        assert "source" in csv_content

    def test_all_iocs_in_output(self, sample_iocs):
        csv_content = export_csv(sample_iocs)
        for ioc in sample_iocs:
            assert ioc.value in csv_content

    def test_deduplication(self):
        ioc = IOC(value="1.2.3.4", ioc_type=IOCType.IP, source="test")
        csv_content = export_csv([ioc, ioc, ioc])
        # Count occurrences of value (minus header)
        assert csv_content.count("1.2.3.4") == 1

    def test_mitre_in_output(self, sample_iocs):
        iocs = [enrich_mitre(i) for i in sample_iocs]
        csv_content = export_csv(iocs)
        assert "T1" in csv_content  # MITRE technique IDs start with T1

    def test_write_to_file(self, sample_iocs, tmp_path):
        out = tmp_path / "iocs.csv"
        export_csv(sample_iocs, out)
        assert out.exists()
        assert out.stat().st_size > 0


# ── Sigma Exporter Tests ──────────────────────────────────────

class TestSigmaExporter:
    def test_generates_rules(self, sample_iocs):
        rules = export_sigma(sample_iocs)
        assert len(rules) > 0

    def test_rule_has_required_fields(self, sample_iocs):
        import yaml
        rules = export_sigma(sample_iocs)
        for rule_yaml in rules:
            rule = yaml.safe_load(rule_yaml)
            assert "title" in rule
            assert "detection" in rule
            assert "logsource" in rule
            assert "level" in rule

    def test_ip_rule_network_category(self, sample_iocs):
        import yaml
        ip_iocs = [i for i in sample_iocs if i.ioc_type == IOCType.IP]
        rules = export_sigma(ip_iocs)
        assert len(rules) == 1
        rule = yaml.safe_load(rules[0])
        assert rule["logsource"]["category"] == "network_connection"

    def test_hash_rule_process_category(self, sample_iocs):
        import yaml
        hash_iocs = [i for i in sample_iocs if i.ioc_type == IOCType.HASH_SHA256]
        rules = export_sigma(hash_iocs)
        assert len(rules) == 1
        rule = yaml.safe_load(rules[0])
        assert rule["logsource"]["category"] == "process_creation"

    def test_write_to_directory(self, sample_iocs, tmp_path):
        export_sigma(sample_iocs, tmp_path)
        yml_files = list(tmp_path.glob("*.yml"))
        assert len(yml_files) > 0


# ── Firewall Exporter Tests ───────────────────────────────────

class TestFirewallExporter:
    def test_iptables_contains_ips(self, sample_iocs):
        result = export_iptables(sample_iocs)
        assert "192.168.1.100" in result
        assert "iptables" in result
        assert "IOC_BLOCK" in result

    def test_nftables_contains_ips(self, sample_iocs):
        result = export_nftables(sample_iocs)
        assert "192.168.1.100" in result
        assert "nftables" in result.lower() or "inet" in result

    def test_dns_blocklist_contains_domains(self, sample_iocs):
        result = export_dns_blocklist(sample_iocs)
        assert "malicious-domain.example.com" in result
        assert "0.0.0.0" in result

    def test_plaintext_contains_all_network(self, sample_iocs):
        result = export_plaintext(sample_iocs)
        assert "192.168.1.100" in result
        assert "malicious-domain.example.com" in result

    def test_header_in_all_formats(self, sample_iocs):
        for fn in [export_iptables, export_nftables, export_dns_blocklist, export_plaintext]:
            result = fn(sample_iocs)
            assert "IOC Harvester" in result

    def test_write_to_file(self, sample_iocs, tmp_path):
        out = tmp_path / "blocklist.sh"
        export_iptables(sample_iocs, out)
        assert out.exists()
