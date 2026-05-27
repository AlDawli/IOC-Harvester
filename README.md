# IOC Harvester

[![CI/CD](https://github.com/example/ioc-harvester/actions/workflows/ci.yml/badge.svg)](https://github.com/example/ioc-harvester/actions)
[![Coverage](https://codecov.io/gh/example/ioc-harvester/branch/main/graph/badge.svg)](https://codecov.io/gh/example/ioc-harvester)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue?logo=docker)](https://ghcr.io/example/ioc-harvester)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red.svg)](https://attack.mitre.org/)
[![Sigma](https://img.shields.io/badge/Sigma-rules-orange.svg)](https://sigmahq.io/)

> **Automated Threat Intelligence Aggregator** — Pull Indicators of Compromise from Abuse.ch, AlienVault OTX, and ThreatFox; export to CSV, Sigma detection rules, and firewall blocklists — all in one command.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Docker](#docker)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Output Formats](#output-formats)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Sources Reference](#sources-reference)
- [Development](#development)
- [CI/CD Pipeline](#cicd-pipeline)
- [Security Considerations](#security-considerations)

---

## Overview

IOC Harvester aggregates threat intelligence from multiple free and open-source feeds, normalises the data into a unified model, enriches indicators with MITRE ATT&CK technique mappings, deduplicates across sources, and exports actionable outputs for your SIEM, EDR, and perimeter defences.

```
Sources          →   Normalise   →   Enrich (MITRE)   →   Deduplicate   →   Export
─────────────        ──────────      ───────────────       ───────────       ──────
Abuse.ch URLhaus      IOC Model       T1071 / T1566 …       value+type        CSV
Abuse.ch Bazaar       Pydantic v2     per threat cat.       keyed set         Sigma YAML
AlienVault OTX    →   validated   →   auto-mapped      →   ~30% reduction →  iptables
ThreatFox             async gen       confidence score       deduped list      nftables
                                                                               PAN EDL
                                                                               Cisco ASA
                                                                               Win FW PS1
                                                                               DNS hosts
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        IOC Harvester                                 │
│                                                                       │
│  ┌─────────────┐   ┌─────────────┐   ┌──────────────────────────┐  │
│  │   CLI (Click)│   │ Config YAML │   │  Python API / Library    │  │
│  │  ioc-harvest │   │  + env vars │   │  from ioc_harvester      │  │
│  │  er run/init │   │             │   │  import harvest          │  │
│  └──────┬──────┘   └──────┬──────┘   └────────────┬─────────────┘  │
│         └─────────────────┴──────────────────┐     │                │
│                                               ▼     ▼                │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                     Harvester Orchestrator                      │  │
│  │  asyncio.gather() — all sources run concurrently               │  │
│  └─────┬──────────────┬────────────────────────┬──────────────────┘  │
│        │              │                        │                      │
│        ▼              ▼                        ▼                      │
│  ┌──────────┐  ┌──────────────┐  ┌─────────────────────────┐        │
│  │ Abuse.ch │  │ AlienVault   │  │      ThreatFox           │        │
│  │          │  │    OTX       │  │                          │        │
│  │ URLhaus  │  │              │  │  IP:port → IP            │        │
│  │ Bazaar   │  │ Subscribed   │  │  botnet_cc → C2          │        │
│  │          │  │ or public    │  │  malware_family          │        │
│  └────┬─────┘  │ pulses       │  └────────────┬────────────┘        │
│       │        └──────┬───────┘               │                      │
│       │               │                       │                       │
│       └───────────────┼───────────────────────┘                      │
│                       │                                               │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                     IOC Data Model (Pydantic v2)                │  │
│  │  value · ioc_type · source · threat_category · malware_family  │  │
│  │  confidence · first_seen · last_seen · mitre_techniques · tags │  │
│  └────────────────────────┬───────────────────────────────────────┘  │
│                            │                                          │
│                            ▼                                          │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │              MITRE ATT&CK Enrichment                            │  │
│  │  threat_category → technique_id + tactic auto-map              │  │
│  └────────────────────────┬───────────────────────────────────────┘  │
│                            │                                          │
│                            ▼                                          │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                Deduplication (value + type key)                 │  │
│  └────────────────────────┬───────────────────────────────────────┘  │
│                            │                                          │
│           ┌────────────────┼───────────────┐                         │
│           ▼                ▼               ▼                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  CSV Export  │  │ Sigma Rules  │  │  Firewall Blocklists      │  │
│  │              │  │              │  │                            │  │
│  │ iocs.csv     │  │ ip.yml       │  │  plain.txt                │  │
│  │ 13 fields    │  │ domain.yml   │  │  iptables.sh              │  │
│  │ deduped      │  │ url.yml      │  │  nftables.nft             │  │
│  │              │  │ sha256.yml   │  │  palo_alto_edl.txt        │  │
│  │              │  │ md5.yml      │  │  cisco_asa.txt            │  │
│  └──────────────┘  └──────────────┘  │  windows.ps1             │  │
│                                       │  dns_hosts.txt           │  │
│                                       └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Diagram

```
ioc_harvester/
├── __init__.py          — public API surface
├── cli.py               — Click CLI (run / init / sources)
├── config.py            — YAML + env-var config loader
├── harvester.py         — async orchestrator, dedup, capping
├── models.py            — IOC Pydantic model + MITRE registry
├── sources/
│   ├── base.py          — BaseSource ABC (retry, rate-limit)
│   ├── abusech.py       — URLhaus + MalwareBazaar connectors
│   ├── alienvault.py    — AlienVault OTX connector
│   └── threatfox.py    — ThreatFox connector
└── exporters/
    ├── csv_exporter.py      — CSV with 13 normalised columns
    ├── sigma_exporter.py    — Sigma YAML rules by IOC type
    └── firewall_exporter.py — 7 firewall-platform formats
```

---

## Features

| Feature | Details |
|---|---|
| **3 threat intel sources** | URLhaus, MalwareBazaar, AlienVault OTX, ThreatFox |
| **4 IOC types** | IP addresses, domains, URLs, file hashes (MD5/SHA1/SHA256) |
| **MITRE ATT&CK enrichment** | Auto-maps 9 threat categories → technique IDs + tactics |
| **Deduplication** | Cross-source dedup on value+type key |
| **7 firewall formats** | plain, iptables, nftables, PAN EDL, Cisco ASA, Windows PS, DNS |
| **Sigma rules** | Per-IOC-type YAML rules for network, DNS, proxy, process |
| **Async collection** | All sources run concurrently via `asyncio.gather()` |
| **Retry + rate-limit** | Exponential backoff, configurable retries per source |
| **Docker support** | Multi-stage image, non-root, multi-arch (amd64/arm64) |
| **CLI + Python API** | Use as a command-line tool or import as a library |
| **GitHub Actions CI/CD** | Lint → test → scan → Docker push → release |

---

## Quick Start

```bash
# 1. Clone and set up
git clone https://github.com/example/ioc-harvester.git
cd ioc-harvester
bash setup.sh

# 2. Activate virtualenv
source .venv/bin/activate

# 3. Harvest IOCs (no API keys required for basic usage)
ioc-harvester run

# 4. Check your output
ls output/
# iocs.csv   sigma/   firewall/
```

Output after a typical run:

```
2025-05-23T10:00:01  INFO      Running 4 source(s) concurrently …
2025-05-23T10:00:04  INFO      [URLhaus] Yielded 847 IOCs
2025-05-23T10:00:06  INFO      [MalwareBazaar] Yielded 300 IOCs
2025-05-23T10:00:09  INFO      [OTX] Processed 20 pulses
2025-05-23T10:00:11  INFO      [ThreatFox] Yielded 412 IOCs
2025-05-23T10:00:11  INFO      Deduplication: 1559 → 1203 unique IOCs
════════════════════════════════════════════════════════
IOC HARVEST COMPLETE
  Total IOCs : 1203
  Elapsed    : 10.42s
  By Type    : {'ip': 512, 'url': 341, 'sha256': 198, 'domain': 152}
  By Source  : {'urlhaus': 601, 'threatfox': 312, 'malwarebazaar': 200, 'otx': 90}
  Outputs    : ['csv', 'sigma', 'firewall']
════════════════════════════════════════════════════════

✅  Collected 1203 IOCs in 10.42s
   📁  csv          → ./output/iocs.csv
   📁  sigma        → ./output/sigma
   📁  firewall     → ./output/firewall
```

---

## Installation

### Requirements

- Python 3.11 or 3.12
- pip / virtualenv

### From Source

```bash
git clone https://github.com/example/ioc-harvester.git
cd ioc-harvester

# Automated setup (recommended)
bash setup.sh

# Or manual
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Development Install

```bash
bash setup.sh --dev
# Installs pytest, ruff, mypy, respx
```

### pip install (PyPI)

```bash
pip install ioc-harvester
```

---

## Docker

### One-Shot Run

```bash
# Pull latest image
docker pull ghcr.io/example/ioc-harvester:latest

# Run with output saved locally
docker run --rm \
  -v "$(pwd)/output:/app/output" \
  -e OTX_API_KEY=your_key_here \
  -e THREATFOX_API_KEY=your_key_here \
  ghcr.io/example/ioc-harvester:latest
```

### Docker Compose

```bash
# Copy and edit environment variables
cp .env.example .env
nano .env  # add your API keys

# Build and run
docker compose run --rm ioc-harvester

# Scheduled mode (runs every 6 hours)
docker compose --profile scheduled up -d
```

### docker-compose.yml key variables

| Variable | Default | Description |
|---|---|---|
| `OTX_API_KEY` | — | AlienVault OTX API key |
| `THREATFOX_API_KEY` | — | ThreatFox API key |
| `OTX_DAYS_BACK` | `7` | How many days back to pull from OTX |
| `THREATFOX_DAYS` | `3` | How many days back for ThreatFox |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `MAX_IOCS` | — | Cap on total IOCs collected |
| `OUTPUT_CSV` | `true` | Enable/disable CSV export |
| `OUTPUT_SIGMA` | `true` | Enable/disable Sigma export |
| `OUTPUT_FIREWALL` | `true` | Enable/disable firewall export |
| `CRON_SCHEDULE` | `0 */6 * * *` | Cron schedule for scheduled mode |

### Build from Source

```bash
docker compose build
# or
docker build -t ioc-harvester .
```

---

## Configuration

Generate a config file:

```bash
ioc-harvester init
```

This creates `config.yml`:

```yaml
log_level: INFO
deduplicate: true
# max_iocs: 10000

abusech:
  enabled: true
  urlhaus_enabled: true
  bazaar_enabled: true
  bazaar_limit: 100

otx:
  enabled: true
  api_key:        # or set OTX_API_KEY env var
  days_back: 7
  limit_pulses: 20

threatfox:
  enabled: true
  api_key:        # or set THREATFOX_API_KEY env var
  days: 3

output:
  directory: ./output
  csv: true
  sigma: true
  firewall: true
```

### Environment Variables

All config keys can be overridden by environment variables:

```bash
export OTX_API_KEY="your-key"
export THREATFOX_API_KEY="your-key"
export OTX_DAYS_BACK=14
export MAX_IOCS=5000
export OUTPUT_DIR=/data/iocs
ioc-harvester run
```

---

## CLI Reference

```
ioc-harvester --help

Commands:
  run      Harvest IOCs from all enabled sources
  init     Generate a default configuration file
  sources  List configured sources and their status
```

### `ioc-harvester run`

```
Options:
  -c, --config PATH          Path to config YAML file
  -o, --output-dir PATH      Override output directory
  --no-csv                   Disable CSV export
  --no-sigma                 Disable Sigma rule export
  --no-firewall              Disable firewall blocklist export
  --otx-key TEXT             AlienVault OTX API key  [env: OTX_API_KEY]
  --threatfox-key TEXT       ThreatFox API key  [env: THREATFOX_API_KEY]
  --log-level TEXT           Logging verbosity  [default: INFO]
  --json-summary             Print JSON summary to stdout
```

Examples:

```bash
# Run with config file
ioc-harvester run -c config.yml

# Run with inline API key, CSV only
ioc-harvester run --otx-key abc123 --no-sigma --no-firewall

# Output to custom directory
ioc-harvester run -o /data/threat-intel

# Get machine-readable summary
ioc-harvester run --json-summary | jq '.by_type'
```

### `ioc-harvester sources`

```bash
$ ioc-harvester sources

Configured Sources:
  Source               Enabled    API Key
  --------------------------------------------------
  URLhaus              enabled    not required
  MalwareBazaar        enabled    not required
  AlienVault OTX       enabled    ✗ (anonymous mode)
  ThreatFox            enabled    ✗ (anonymous mode)
```

---

## Output Formats

### CSV (`output/iocs.csv`)

13 columns covering all normalised IOC fields:

| Column | Description |
|---|---|
| `value` | The indicator value (IP, domain, URL, hash) |
| `type` | IOC type: `ip`, `domain`, `url`, `md5`, `sha256` … |
| `source` | Origin: `urlhaus`, `malwarebazaar`, `alienvault_otx`, `threatfox` |
| `threat_category` | `malware`, `ransomware`, `c2`, `phishing`, `botnet` … |
| `malware_family` | e.g. `LockBit`, `Emotet`, `Cobalt Strike` |
| `tags` | Comma-separated source tags |
| `confidence` | `high`, `medium`, `low` |
| `first_seen` | ISO 8601 timestamp |
| `last_seen` | ISO 8601 timestamp |
| `collected_at` | When the harvester collected it |
| `country` | Origin country (if available) |
| `asn` | ASN (if available) |
| `description` | Human-readable context |
| `mitre_techniques` | Semicolon-separated `TXXXX:Name` pairs |

### Sigma Rules (`output/sigma/`)

One YAML rule file per IOC type:

```yaml
# output/sigma/ioc_harvester_ip.yml
title: IOC Harvester - Malicious IP Connections
id: 3a1f2b9c-...
status: experimental
description: Detects connections to malicious IPs from threatfox, urlhaus
tags:
  - attack.T1071
  - attack.T1095
  - tlp.white
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp:
      - 1.2.3.4
      - 5.6.7.8
  condition: selection
level: high
```

Files generated:
- `ioc_harvester_ip.yml` — network_connection rules
- `ioc_harvester_domain.yml` — DNS query rules
- `ioc_harvester_url.yml` — proxy / web rules
- `ioc_harvester_sha256.yml` — process creation (SHA256)
- `ioc_harvester_md5.yml` — process creation (MD5)

### Firewall Blocklists (`output/firewall/`)

| File | Platform | Usage |
|---|---|---|
| `blocklist_plain.txt` | Universal | Copy/paste, custom scripts |
| `blocklist_iptables.sh` | Linux iptables | `bash blocklist_iptables.sh` |
| `blocklist_nftables.nft` | Linux nftables | `nft -f blocklist_nftables.nft` |
| `blocklist_palo_alto_edl.txt` | Palo Alto PAN-OS | Host via HTTPS, reference as EDL |
| `blocklist_cisco_asa.txt` | Cisco ASA/FTD | Paste into configuration mode |
| `blocklist_windows.ps1` | Windows Firewall | `powershell -File blocklist_windows.ps1` |
| `blocklist_dns.txt` | Pi-hole/BIND/Unbound | Add as custom list |

#### iptables example

```bash
# Preview
head -30 output/firewall/blocklist_iptables.sh

# Apply (as root)
sudo bash output/firewall/blocklist_iptables.sh

# Verify
sudo iptables -L IOC_BLOCK -n | head
```

#### Pi-hole DNS blocklist

```bash
# Copy to Pi-hole custom list
sudo cp output/firewall/blocklist_dns.txt /etc/pihole/custom.list
pihole restartdns
```

---

## MITRE ATT&CK Mapping

IOC Harvester automatically maps each IOC's threat category to relevant MITRE ATT&CK techniques and tactics:

| Threat Category | Technique IDs | Tactic |
|---|---|---|
| **C2** | T1071 Application Layer Protocol | command-and-control |
| **C2** | T1095 Non-Application Layer Protocol | command-and-control |
| **Botnet** | T1583.001 Acquire Infrastructure: Domains | resource-development |
| **Botnet** | T1071.001 Web Protocols | command-and-control |
| **Ransomware** | T1486 Data Encrypted for Impact | impact |
| **Ransomware** | T1490 Inhibit System Recovery | impact |
| **Ransomware** | T1071 Application Layer Protocol | command-and-control |
| **Phishing** | T1566.001 Spearphishing Attachment | initial-access |
| **Phishing** | T1566.002 Spearphishing Link | initial-access |
| **Malware** | T1059 Command and Scripting Interpreter | execution |
| **Malware** | T1055 Process Injection | defense-evasion |
| **Trojan** | T1055 Process Injection | defense-evasion |
| **Trojan** | T1027 Obfuscated Files or Information | defense-evasion |
| **Exploit** | T1203 Exploitation for Client Execution | execution |
| **Exploit** | T1190 Exploit Public-Facing Application | initial-access |
| **Scanner** | T1595 Active Scanning | reconnaissance |
| **Scanner** | T1046 Network Service Discovery | discovery |

Techniques appear in the `mitre_techniques` column of the CSV and in the `tags` field of Sigma rules as `attack.TXXXX`.

---

## Sources Reference

### Abuse.ch URLhaus

- **URL:** https://urlhaus.abuse.ch/
- **Feed:** https://urlhaus.abuse.ch/downloads/csv_recent/
- **Auth:** Not required
- **IOC Types:** URL, domain, IP
- **Rate Limit:** None documented; harvester throttles automatically

### Abuse.ch MalwareBazaar

- **URL:** https://bazaar.abuse.ch/
- **API:** https://mb-api.abuse.ch/api/v1/
- **Auth:** Not required (free tier)
- **IOC Types:** MD5, SHA1, SHA256
- **Rate Limit:** 100 queries/minute (anonymous)

### AlienVault OTX

- **URL:** https://otx.alienvault.com/
- **API:** https://otx.alienvault.com/api/v1/
- **Auth:** Optional (API key recommended for subscribed pulses)
- **IOC Types:** IP, domain, URL, MD5, SHA1, SHA256, email
- **API Key:** Register free at https://otx.alienvault.com/accounts/signup

### ThreatFox

- **URL:** https://threatfox.abuse.ch/
- **API:** https://threatfox-api.abuse.ch/api/v1/
- **Auth:** Optional (key required for full access)
- **IOC Types:** IP, domain, URL, MD5, SHA256
- **API Key:** Request at https://threatfox.abuse.ch/

---

## Development

### Setup

```bash
bash setup.sh --dev
source .venv/bin/activate
```

### Run Tests

```bash
pytest tests/ -v
pytest tests/ --cov=ioc_harvester --cov-report=html
open htmlcov/index.html
```

### Lint and Format

```bash
ruff check ioc_harvester/ tests/
ruff format ioc_harvester/ tests/
mypy ioc_harvester/
```

### Add a New Source

1. Create `ioc_harvester/sources/mysource.py` extending `BaseSource`
2. Implement the `fetch()` async generator
3. Register in `ioc_harvester/sources/__init__.py`
4. Add to `harvester.py` orchestrator
5. Add config fields in `config.py`
6. Write tests in `tests/`

```python
# ioc_harvester/sources/mysource.py
from ioc_harvester.sources.base import BaseSource
from ioc_harvester.models import IOC, IOCType
from typing import AsyncGenerator

class MySource(BaseSource):
    NAME = "mysource"

    async def fetch(self) -> AsyncGenerator[IOC, None]:
        resp = await self._get("https://api.example.com/iocs")
        for entry in resp.json()["data"]:
            yield IOC(
                value=entry["indicator"],
                ioc_type=IOCType.IP,
                source=self.NAME,
            )
```

### Use as a Python Library

```python
import asyncio
from ioc_harvester import harvest
from ioc_harvester.config import load_config
from ioc_harvester.exporters import export_csv, export_sigma

cfg = load_config("config.yml")
cfg.otx.api_key = "your-key"

iocs = asyncio.run(harvest(cfg))

# Filter to just IPs
from ioc_harvester.models import IOCType
malicious_ips = [i.value for i in iocs if i.ioc_type == IOCType.IP]

# Export
export_csv(iocs, "my_iocs.csv")
export_sigma(iocs, "sigma_rules/")
```

---

## CI/CD Pipeline

```
push / PR
    │
    ├─► lint        — ruff check + ruff format --check + mypy
    │
    ├─► test        — pytest (Python 3.11 + 3.12) + codecov
    │       ↓
    ├─► security    — Bandit SAST + Safety dependency scan → SARIF upload
    │       ↓
    ├─► docker-build — multi-arch (amd64/arm64) → ghcr.io (main branch only)
    │       ↓
    └─► release     — GitHub Release + distribution build (on v* tags)

schedule: Monday 06:00 UTC — dependency check run
```

### Secrets Required

| Secret | Description |
|---|---|
| `CODECOV_TOKEN` | Coverage reporting (optional) |
| `OTX_API_KEY` | For scheduled harvest jobs |
| `THREATFOX_API_KEY` | For scheduled harvest jobs |

---

## Security Considerations

- **API keys** — never hardcode in source; use environment variables or `config.yml` (ensure it is in `.gitignore`)
- **SSL verification** — enabled by default; do not disable `verify_ssl` in production
- **False positives** — all Sigma rules are marked `status: experimental`; review before deploying to production SIEM
- **Blocklists** — test in a staging environment before applying to production firewalls
- **Non-root Docker** — the container image runs as the `harvester` user, not root
- **Read-only container** — the filesystem is mostly read-only; only `/app/output` and `/tmp` are writable

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

- [Abuse.ch](https://abuse.ch/) — URLhaus, MalwareBazaar, ThreatFox
- [AlienVault OTX](https://otx.alienvault.com/) — Open Threat Exchange
- [Sigma HQ](https://sigmahq.io/) — Generic SIEM detection rule format
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversary tactics & techniques framework
