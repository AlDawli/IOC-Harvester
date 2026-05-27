"""
IOC Harvester - Core Orchestrator
Runs all enabled sources concurrently and feeds IOCs into exporters.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from ioc_harvester.config import Config, load_config
from ioc_harvester.exporters import (
    export_all_firewall,
    export_csv,
    export_sigma,
)
from ioc_harvester.models import IOC
from ioc_harvester.sources import (
    AlienVaultOTXSource,
    MalwareBazaarSource,
    ThreatFoxSource,
    URLhausSource,
)

logger = logging.getLogger(__name__)


async def _run_source(source, label: str) -> list[IOC]:
    """Run a single source and collect all IOCs."""
    iocs: list[IOC] = []
    try:
        async with source:
            async for ioc in source.fetch():
                iocs.append(ioc)
        logger.info("[%s] Collected %d IOCs", label, len(iocs))
    except Exception as exc:
        logger.error("[%s] Source error: %s", label, exc, exc_info=True)
    return iocs


async def harvest(config: Config | None = None) -> list[IOC]:
    """
    Run all configured sources concurrently and return collected IOCs.
    """
    if config is None:
        config = load_config()

    tasks = []

    # ── Abuse.ch ─────────────────────────────────────────────
    if config.abusech.enabled:
        if config.abusech.urlhaus_enabled:
            tasks.append(_run_source(
                URLhausSource(timeout=config.abusech.timeout),
                "URLhaus",
            ))
        if config.abusech.bazaar_enabled:
            tasks.append(_run_source(
                MalwareBazaarSource(
                    limit=config.abusech.bazaar_limit,
                    timeout=config.abusech.timeout,
                ),
                "MalwareBazaar",
            ))

    # ── AlienVault OTX ───────────────────────────────────────
    if config.otx.enabled:
        tasks.append(_run_source(
            AlienVaultOTXSource(
                api_key=config.otx.api_key,
                days_back=config.otx.days_back,
                limit_pulses=config.otx.limit_pulses,
                timeout=config.otx.timeout,
            ),
            "OTX",
        ))

    # ── ThreatFox ────────────────────────────────────────────
    if config.threatfox.enabled:
        tasks.append(_run_source(
            ThreatFoxSource(
                api_key=config.threatfox.api_key,
                days=config.threatfox.days,
                timeout=config.threatfox.timeout,
            ),
            "ThreatFox",
        ))

    if not tasks:
        logger.warning("No sources enabled — nothing to do.")
        return []

    logger.info("Running %d source(s) concurrently …", len(tasks))
    results = await asyncio.gather(*tasks)
    all_iocs: list[IOC] = [ioc for batch in results for ioc in batch]

    # Deduplication
    if config.deduplicate:
        seen: set[str] = set()
        deduped: list[IOC] = []
        for ioc in all_iocs:
            key = f"{ioc.value.lower()}:{ioc.ioc_type.value}"
            if key not in seen:
                seen.add(key)
                deduped.append(ioc)
        logger.info("Deduplication: %d → %d unique IOCs", len(all_iocs), len(deduped))
        all_iocs = deduped

    # Cap
    if config.max_iocs and len(all_iocs) > config.max_iocs:
        all_iocs = all_iocs[: config.max_iocs]
        logger.info("Capped at %d IOCs", config.max_iocs)

    return all_iocs


def run_and_export(config: Config | None = None) -> dict:
    """
    Synchronous entry point: harvest IOCs and write all configured outputs.
    Returns a summary dict.
    """
    if config is None:
        config = load_config()

    start = time.perf_counter()
    iocs = asyncio.run(harvest(config))
    elapsed = time.perf_counter() - start

    if not iocs:
        logger.warning("No IOCs collected.")
        return {"total": 0, "elapsed": elapsed, "outputs": {}}

    out_dir = Path(config.output.directory)
    outputs: dict[str, str | list] = {}

    if config.output.csv:
        csv_path = out_dir / "iocs.csv"
        export_csv(iocs, csv_path)
        outputs["csv"] = str(csv_path)

    if config.output.sigma:
        sigma_dir = out_dir / "sigma"
        rules = export_sigma(iocs, sigma_dir)
        outputs["sigma"] = str(sigma_dir)
        outputs["sigma_rules"] = len(rules)

    if config.output.firewall:
        fw_dir = out_dir / "firewall"
        export_all_firewall(iocs, fw_dir)
        outputs["firewall"] = str(fw_dir)

    summary = {
        "total": len(iocs),
        "elapsed_seconds": round(elapsed, 2),
        "outputs": outputs,
        "by_type": _count_by_type(iocs),
        "by_source": _count_by_source(iocs),
    }
    _print_summary(summary)
    return summary


def _count_by_type(iocs: list[IOC]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ioc in iocs:
        counts[ioc.ioc_type.value] = counts.get(ioc.ioc_type.value, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def _count_by_source(iocs: list[IOC]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ioc in iocs:
        counts[ioc.source] = counts.get(ioc.source, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def _print_summary(summary: dict) -> None:
    logger.info("=" * 60)
    logger.info("IOC HARVEST COMPLETE")
    logger.info("  Total IOCs : %d", summary["total"])
    logger.info("  Elapsed    : %.2fs", summary["elapsed_seconds"])
    logger.info("  By Type    : %s", summary["by_type"])
    logger.info("  By Source  : %s", summary["by_source"])
    logger.info("  Outputs    : %s", list(summary["outputs"].keys()))
    logger.info("=" * 60)
