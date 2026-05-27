"""
IOC Harvester - Firewall Blocklist Exporter
Generates firewall-ready blocklists in multiple formats:
  - Plain text (one entry per line)
  - iptables / nftables
  - Palo Alto Networks EDL format
  - Cisco ASA / FTD object-group
  - Windows Firewall (PowerShell)
  - Generic DNS blocklist
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from ioc_harvester.models import IOC, IOCType

logger = logging.getLogger(__name__)

_HEADER = """\
# ============================================================
# IOC Harvester - Firewall Blocklist
# Generated : {ts}
# Total IOCs : {count}
# Sources   : {sources}
# ============================================================
"""


def _ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def export_plaintext(iocs: list[IOC], output: Path | str | None = None) -> str:
    """One IP/domain/URL per line — generic blocklist."""
    targets = _extract_network_iocs(iocs)
    sources = _source_list(iocs)
    lines = [
        _HEADER.format(ts=_ts(), count=len(targets), sources=sources),
        *targets,
    ]
    return _write("\n".join(lines), output)


def export_iptables(iocs: list[IOC], output: Path | str | None = None) -> str:
    """
    iptables DROP rules for malicious IPs.
    Suitable for Linux hosts and simple perimeter firewalls.
    """
    ips = _extract_by_type(iocs, IOCType.IP)
    sources = _source_list(iocs)
    lines = [
        _HEADER.format(ts=_ts(), count=len(ips), sources=sources),
        "# Apply with: bash <blocklist_file>",
        "",
        "#!/bin/bash",
        "set -e",
        "",
        "# Flush existing IOC chain (idempotent)",
        "iptables -F IOC_BLOCK 2>/dev/null || iptables -N IOC_BLOCK",
        "ip6tables -F IOC_BLOCK 2>/dev/null || ip6tables -N IOC_BLOCK",
        "",
        "# Hook into INPUT and FORWARD",
        "iptables  -C INPUT   -j IOC_BLOCK 2>/dev/null || iptables  -I INPUT   -j IOC_BLOCK",
        "iptables  -C FORWARD -j IOC_BLOCK 2>/dev/null || iptables  -I FORWARD -j IOC_BLOCK",
        "",
    ]
    for ip in ips:
        lines.append(f"iptables -A IOC_BLOCK -s {ip} -j DROP -m comment --comment 'IOC_HARVESTER'")
    lines += [
        "",
        'echo "Loaded ' + str(len(ips)) + ' IOC block rules."',
    ]
    return _write("\n".join(lines), output)


def export_nftables(iocs: list[IOC], output: Path | str | None = None) -> str:
    """nftables set-based blocklist for modern Linux firewalls."""
    ips = _extract_by_type(iocs, IOCType.IP)
    sources = _source_list(iocs)
    elements = ", ".join(ips) if ips else ""
    content = f"""{_HEADER.format(ts=_ts(), count=len(ips), sources=sources)}
#!/usr/sbin/nft -f

# Delete old table if it exists
table inet ioc_block {{ }}
delete table inet ioc_block

table inet ioc_block {{
    set malicious_ips {{
        type ipv4_addr
        flags interval
        elements = {{ {elements} }}
    }}

    chain input {{
        type filter hook input priority 0; policy accept;
        ip saddr @malicious_ips drop comment "IOC Harvester block"
    }}

    chain forward {{
        type filter hook forward priority 0; policy accept;
        ip saddr @malicious_ips drop comment "IOC Harvester block"
        ip daddr @malicious_ips drop comment "IOC Harvester block"
    }}
}}
"""
    return _write(content, output)


def export_palo_alto_edl(iocs: list[IOC], output: Path | str | None = None) -> str:
    """
    Palo Alto Networks External Dynamic List (EDL) format.
    Host this file via HTTPS and reference in PAN-OS Security Policy.
    """
    targets = _extract_network_iocs(iocs)
    sources = _source_list(iocs)
    lines = [
        _HEADER.format(ts=_ts(), count=len(targets), sources=sources),
        *targets,
    ]
    return _write("\n".join(lines), output)


def export_cisco_asa(iocs: list[IOC], output: Path | str | None = None) -> str:
    """Cisco ASA / FTD object-group configuration."""
    ips = _extract_by_type(iocs, IOCType.IP)
    domains = _extract_by_type(iocs, IOCType.DOMAIN)
    sources = _source_list(iocs)

    lines = [
        _HEADER.format(ts=_ts(), count=len(ips) + len(domains), sources=sources),
        "! Cisco ASA / FTD blocklist — IOC Harvester",
        "!",
        "object-group network IOC_HARVESTER_IPS",
        f" description Malicious IPs - {_ts()}",
    ]
    for ip in ips:
        lines.append(f" network-object host {ip}")
    lines += [
        "!",
        "object-group network IOC_HARVESTER_DOMAINS",
        f" description Malicious Domains - {_ts()}",
    ]
    for domain in domains:
        lines.append(f" network-object host {domain}")
    lines += [
        "!",
        "! Apply with:",
        "! access-list OUTSIDE_IN extended deny ip object-group IOC_HARVESTER_IPS any",
        "! access-list OUTSIDE_IN extended deny ip any object-group IOC_HARVESTER_IPS",
    ]
    return _write("\n".join(lines), output)


def export_windows_firewall(iocs: list[IOC], output: Path | str | None = None) -> str:
    """Windows Firewall PowerShell blocklist script."""
    ips = _extract_by_type(iocs, IOCType.IP)
    sources = _source_list(iocs)
    ip_list = '", "'.join(ips)

    content = f"""{_HEADER.format(ts=_ts(), count=len(ips), sources=sources)}
# Windows Firewall - IOC Harvester Blocklist
# Run as Administrator: powershell -ExecutionPolicy Bypass -File blocklist.ps1

$IPs = @("{ip_list}")

# Remove old rule
Remove-NetFirewallRule -DisplayName "IOC-Harvester-Block" -ErrorAction SilentlyContinue

if ($IPs.Length -gt 0) {{
    New-NetFirewallRule `
        -DisplayName "IOC-Harvester-Block" `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $IPs `
        -Description "IOC Harvester auto-generated blocklist" `
        -Protocol Any

    New-NetFirewallRule `
        -DisplayName "IOC-Harvester-Block-Out" `
        -Direction Outbound `
        -Action Block `
        -RemoteAddress $IPs `
        -Description "IOC Harvester auto-generated blocklist" `
        -Protocol Any

    Write-Host "Blocked $($IPs.Length) malicious IP addresses."
}} else {{
    Write-Host "No IPs to block."
}}
"""
    return _write(content, output)


def export_dns_blocklist(iocs: list[IOC], output: Path | str | None = None) -> str:
    """
    DNS-based blocklist (compatible with Pi-hole, Unbound, BIND RPZ).
    Format: 0.0.0.0 malicious-domain.com
    """
    domains = _extract_by_type(iocs, IOCType.DOMAIN)
    sources = _source_list(iocs)
    lines = [
        _HEADER.format(ts=_ts(), count=len(domains), sources=sources),
        "# DNS Blocklist - add to /etc/hosts or Pi-hole custom list",
        "",
    ]
    for domain in domains:
        lines.append(f"0.0.0.0 {domain}")
    return _write("\n".join(lines), output)


def export_all_firewall(iocs: list[IOC], output_dir: Path | str) -> dict[str, str]:
    """Export all firewall formats to a directory."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    formats = {
        "blocklist_plain.txt": export_plaintext,
        "blocklist_iptables.sh": export_iptables,
        "blocklist_nftables.nft": export_nftables,
        "blocklist_palo_alto_edl.txt": export_palo_alto_edl,
        "blocklist_cisco_asa.txt": export_cisco_asa,
        "blocklist_windows.ps1": export_windows_firewall,
        "blocklist_dns.txt": export_dns_blocklist,
    }

    results = {}
    for fname, fn in formats.items():
        content = fn(iocs, out / fname)
        results[fname] = content
        logger.info("Firewall: wrote %s", out / fname)

    return results


# ── helpers ───────────────────────────────────────────────────

def _extract_by_type(iocs: list[IOC], ioc_type: IOCType) -> list[str]:
    seen: set[str] = set()
    result = []
    for ioc in iocs:
        if ioc.ioc_type == ioc_type and ioc.value not in seen:
            seen.add(ioc.value)
            result.append(ioc.value)
    return sorted(result)


def _extract_network_iocs(iocs: list[IOC]) -> list[str]:
    network_types = {IOCType.IP, IOCType.DOMAIN, IOCType.URL}
    seen: set[str] = set()
    result = []
    for ioc in iocs:
        if ioc.ioc_type in network_types and ioc.value not in seen:
            seen.add(ioc.value)
            result.append(ioc.value)
    return sorted(result)


def _source_list(iocs: list[IOC]) -> str:
    return ", ".join(sorted({i.source for i in iocs})) or "unknown"


def _write(content: str, output: Path | str | None) -> str:
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return content
