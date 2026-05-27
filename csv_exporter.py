"""
IOC Harvester - CSV Exporter
Writes normalized IOCs to a structured CSV file.
"""

from __future__ import annotations

import csv
import io
import logging
from pathlib import Path

from ioc_harvester.models import IOC

logger = logging.getLogger(__name__)

CSV_FIELDNAMES = [
    "value",
    "type",
    "source",
    "threat_category",
    "malware_family",
    "tags",
    "confidence",
    "first_seen",
    "last_seen",
    "collected_at",
    "country",
    "asn",
    "description",
    "mitre_techniques",
]


def export_csv(iocs: list[IOC], output: Path | str | None = None) -> str:
    """
    Export a list of IOCs to CSV.

    Args:
        iocs: List of IOC objects.
        output: Optional file path. If None, returns CSV as string.

    Returns:
        CSV content as string.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=CSV_FIELDNAMES,
        extrasaction="ignore",
        lineterminator="\r\n",
    )
    writer.writeheader()

    seen: set[str] = set()
    written = 0
    for ioc in iocs:
        dedup_key = f"{ioc.value}:{ioc.ioc_type.value}:{ioc.source}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        row = ioc.to_dict()
        row["mitre_techniques"] = ";".join(
            f"{t.technique_id}:{t.technique_name}" for t in ioc.mitre_techniques
        )
        writer.writerow(row)
        written += 1

    content = buf.getvalue()

    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info("CSV: wrote %d unique IOCs → %s", written, path)
    else:
        logger.info("CSV: produced %d unique IOCs (in-memory)", written)

    return content
