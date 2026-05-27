"""
IOC Harvester - CLI
Command-line interface powered by Click.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

from ioc_harvester.config import DEFAULT_CONFIG_YAML, load_config
from ioc_harvester.harvester import run_and_export


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )
    # Quiet noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


@click.group()
@click.version_option(version="1.0.0", prog_name="ioc-harvester")
def cli():
    """
    \b
    ╔══════════════════════════════════╗
    ║       IOC HARVESTER v1.0         ║
    ║  Threat Intelligence Aggregator  ║
    ╚══════════════════════════════════╝

    Pull IOCs from Abuse.ch, AlienVault OTX, and ThreatFox.
    Export to CSV, Sigma rules, and firewall blocklists.
    """


@cli.command()
@click.option("-c", "--config", "config_path", default=None, help="Path to config YAML file.")
@click.option("--output-dir", "-o", default=None, help="Override output directory.")
@click.option("--no-csv", is_flag=True, help="Disable CSV export.")
@click.option("--no-sigma", is_flag=True, help="Disable Sigma rule export.")
@click.option("--no-firewall", is_flag=True, help="Disable firewall blocklist export.")
@click.option("--otx-key", envvar="OTX_API_KEY", default=None, help="AlienVault OTX API key.")
@click.option("--threatfox-key", envvar="THREATFOX_API_KEY", default=None, help="ThreatFox API key.")
@click.option("--log-level", default="INFO", show_default=True, help="Logging verbosity.")
@click.option("--json-summary", is_flag=True, help="Print JSON summary to stdout.")
def run(
    config_path,
    output_dir,
    no_csv,
    no_sigma,
    no_firewall,
    otx_key,
    threatfox_key,
    log_level,
    json_summary,
):
    """Harvest IOCs from all enabled sources and export results."""
    _setup_logging(log_level)

    cfg = load_config(config_path)

    # CLI flag overrides
    if output_dir:
        cfg.output.directory = output_dir
    if no_csv:
        cfg.output.csv = False
    if no_sigma:
        cfg.output.sigma = False
    if no_firewall:
        cfg.output.firewall = False
    if otx_key:
        cfg.otx.api_key = otx_key
    if threatfox_key:
        cfg.threatfox.api_key = threatfox_key
    cfg.log_level = log_level

    summary = run_and_export(cfg)

    if json_summary:
        click.echo(json.dumps(summary, indent=2))
    else:
        click.echo(f"\n✅  Collected {summary['total']} IOCs in {summary['elapsed_seconds']}s")
        for fmt, path in summary.get("outputs", {}).items():
            if not fmt.endswith("_rules"):
                click.echo(f"   📁  {fmt:12s} → {path}")


@cli.command()
@click.option("-o", "--output", default="config.yml", show_default=True, help="Output path.")
def init(output):
    """Generate a default configuration file."""
    path = Path(output)
    if path.exists():
        click.confirm(f"{path} already exists. Overwrite?", abort=True)
    path.write_text(DEFAULT_CONFIG_YAML)
    click.echo(f"✅  Config written to {path}")
    click.echo("   Edit API keys and settings, then run: ioc-harvester run -c config.yml")


@cli.command()
@click.option("-c", "--config", "config_path", default=None)
def sources(config_path):
    """List configured sources and their status."""
    cfg = load_config(config_path)
    click.echo("\nConfigured Sources:")
    click.echo(f"  {'Source':<20} {'Enabled':<10} {'API Key'}")
    click.echo("  " + "-" * 50)

    rows = [
        ("URLhaus",        cfg.abusech.enabled and cfg.abusech.urlhaus_enabled, "not required"),
        ("MalwareBazaar",  cfg.abusech.enabled and cfg.abusech.bazaar_enabled,  "not required"),
        ("AlienVault OTX", cfg.otx.enabled,        "✓" if cfg.otx.api_key else "✗ (anonymous mode)"),
        ("ThreatFox",      cfg.threatfox.enabled,  "✓" if cfg.threatfox.api_key else "✗ (anonymous mode)"),
    ]
    for name, enabled, key_status in rows:
        status = click.style("enabled ", fg="green") if enabled else click.style("disabled", fg="red")
        click.echo(f"  {name:<20} {status}  {key_status}")
    click.echo()


def main():
    cli()


if __name__ == "__main__":
    main()
