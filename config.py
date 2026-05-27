"""
IOC Harvester - Configuration
Loads settings from environment variables or a YAML config file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class SourceConfig:
    enabled: bool = True
    api_key: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3


@dataclass
class AbuseCHConfig(SourceConfig):
    urlhaus_enabled: bool = True
    bazaar_enabled: bool = True
    bazaar_limit: int = 100


@dataclass
class OTXConfig(SourceConfig):
    days_back: int = 7
    limit_pulses: int = 20


@dataclass
class ThreatFoxConfig(SourceConfig):
    days: int = 3


@dataclass
class OutputConfig:
    directory: str = "./output"
    csv: bool = True
    sigma: bool = True
    firewall: bool = True
    firewall_formats: list[str] = field(default_factory=lambda: [
        "plain", "iptables", "nftables", "palo_alto", "cisco_asa", "windows", "dns"
    ])


@dataclass
class Config:
    abusech: AbuseCHConfig = field(default_factory=AbuseCHConfig)
    otx: OTXConfig = field(default_factory=OTXConfig)
    threatfox: ThreatFoxConfig = field(default_factory=ThreatFoxConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    log_level: str = "INFO"
    deduplicate: bool = True
    max_iocs: Optional[int] = None


def load_config(path: str | Path | None = None) -> Config:
    """
    Load configuration. Priority:
      1. YAML config file (if provided)
      2. Environment variables
      3. Defaults
    """
    cfg = Config()

    # Load YAML if provided
    if path and Path(path).exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        _apply_yaml(cfg, data)

    # Environment variable overrides
    _apply_env(cfg)
    return cfg


def _apply_env(cfg: Config) -> None:
    # OTX
    if key := os.getenv("OTX_API_KEY"):
        cfg.otx.api_key = key
    if val := os.getenv("OTX_DAYS_BACK"):
        cfg.otx.days_back = int(val)
    if val := os.getenv("OTX_ENABLED", "").lower():
        cfg.otx.enabled = val not in ("false", "0", "no")

    # ThreatFox
    if key := os.getenv("THREATFOX_API_KEY"):
        cfg.threatfox.api_key = key
    if val := os.getenv("THREATFOX_DAYS"):
        cfg.threatfox.days = int(val)
    if val := os.getenv("THREATFOX_ENABLED", "").lower():
        cfg.threatfox.enabled = val not in ("false", "0", "no")

    # Abuse.ch
    if val := os.getenv("ABUSECH_ENABLED", "").lower():
        cfg.abusech.enabled = val not in ("false", "0", "no")
    if val := os.getenv("URLHAUS_ENABLED", "").lower():
        cfg.abusech.urlhaus_enabled = val not in ("false", "0", "no")
    if val := os.getenv("BAZAAR_ENABLED", "").lower():
        cfg.abusech.bazaar_enabled = val not in ("false", "0", "no")

    # Output
    if val := os.getenv("OUTPUT_DIR"):
        cfg.output.directory = val
    if val := os.getenv("OUTPUT_CSV", "").lower():
        cfg.output.csv = val not in ("false", "0", "no")
    if val := os.getenv("OUTPUT_SIGMA", "").lower():
        cfg.output.sigma = val not in ("false", "0", "no")
    if val := os.getenv("OUTPUT_FIREWALL", "").lower():
        cfg.output.firewall = val not in ("false", "0", "no")

    # General
    if val := os.getenv("LOG_LEVEL"):
        cfg.log_level = val.upper()
    if val := os.getenv("MAX_IOCS"):
        cfg.max_iocs = int(val)


def _apply_yaml(cfg: Config, data: dict) -> None:
    if "abusech" in data:
        d = data["abusech"]
        cfg.abusech.enabled = d.get("enabled", cfg.abusech.enabled)
        cfg.abusech.urlhaus_enabled = d.get("urlhaus_enabled", cfg.abusech.urlhaus_enabled)
        cfg.abusech.bazaar_enabled = d.get("bazaar_enabled", cfg.abusech.bazaar_enabled)
        cfg.abusech.bazaar_limit = d.get("bazaar_limit", cfg.abusech.bazaar_limit)

    if "otx" in data:
        d = data["otx"]
        cfg.otx.enabled = d.get("enabled", cfg.otx.enabled)
        cfg.otx.api_key = d.get("api_key", cfg.otx.api_key)
        cfg.otx.days_back = d.get("days_back", cfg.otx.days_back)
        cfg.otx.limit_pulses = d.get("limit_pulses", cfg.otx.limit_pulses)

    if "threatfox" in data:
        d = data["threatfox"]
        cfg.threatfox.enabled = d.get("enabled", cfg.threatfox.enabled)
        cfg.threatfox.api_key = d.get("api_key", cfg.threatfox.api_key)
        cfg.threatfox.days = d.get("days", cfg.threatfox.days)

    if "output" in data:
        d = data["output"]
        cfg.output.directory = d.get("directory", cfg.output.directory)
        cfg.output.csv = d.get("csv", cfg.output.csv)
        cfg.output.sigma = d.get("sigma", cfg.output.sigma)
        cfg.output.firewall = d.get("firewall", cfg.output.firewall)

    cfg.log_level = data.get("log_level", cfg.log_level)
    cfg.deduplicate = data.get("deduplicate", cfg.deduplicate)
    cfg.max_iocs = data.get("max_iocs", cfg.max_iocs)


DEFAULT_CONFIG_YAML = """\
# IOC Harvester Configuration
# All values can be overridden by environment variables.

log_level: INFO
deduplicate: true
# max_iocs: 10000  # Uncomment to cap total IOCs

abusech:
  enabled: true
  urlhaus_enabled: true
  bazaar_enabled: true
  bazaar_limit: 100

otx:
  enabled: true
  api_key:   # Set OTX_API_KEY env var or here
  days_back: 7
  limit_pulses: 20

threatfox:
  enabled: true
  api_key:   # Set THREATFOX_API_KEY env var or here
  days: 3

output:
  directory: ./output
  csv: true
  sigma: true
  firewall: true
"""
