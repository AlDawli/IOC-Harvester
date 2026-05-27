"""
IOC Harvester - Abuse.ch Sources
Fetches IOCs from:
  - URLhaus  (malicious URLs / domains / IPs)
  - MalwareBazaar (file hashes)
  - ThreatFox is a separate source; Bazaar & URLhaus live here.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
from datetime import datetime
from typing import AsyncGenerator

from ioc_harvester.models import (
    Confidence,
    IOC,
    IOCType,
    ThreatCategory,
    enrich_mitre,
)
from ioc_harvester.sources.base import BaseSource

logger = logging.getLogger(__name__)

# ── category mapping ──────────────────────────────────────────
_URLHAUS_TAG_MAP: dict[str, ThreatCategory] = {
    "malware": ThreatCategory.MALWARE,
    "phishing": ThreatCategory.PHISHING,
    "botnet": ThreatCategory.BOTNET,
    "ransomware": ThreatCategory.RANSOMWARE,
    "exploit": ThreatCategory.EXPLOIT,
    "spam": ThreatCategory.SPAM,
}

_BAZAAR_TAG_MAP: dict[str, ThreatCategory] = {
    "ransomware": ThreatCategory.RANSOMWARE,
    "trojan": ThreatCategory.TROJAN,
    "botnet": ThreatCategory.BOTNET,
    "loader": ThreatCategory.MALWARE,
    "dropper": ThreatCategory.MALWARE,
    "infostealer": ThreatCategory.TROJAN,
    "rat": ThreatCategory.TROJAN,
}


def _parse_ts(val: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(val.strip(), fmt)
        except (ValueError, AttributeError):
            continue
    return None


def _map_tags(tags: list[str], mapping: dict[str, ThreatCategory]) -> ThreatCategory:
    for tag in tags:
        cat = mapping.get(tag.lower())
        if cat:
            return cat
    return ThreatCategory.UNKNOWN


class URLhausSource(BaseSource):
    """
    Pulls the URLhaus CSV feed (online + recent URLs).
    https://urlhaus.abuse.ch/downloads/csv_recent/
    """

    NAME = "urlhaus"
    BASE_URL = "https://urlhaus.abuse.ch"
    FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    async def fetch(self) -> AsyncGenerator[IOC, None]:
        logger.info("[URLhaus] Fetching recent URL feed …")
        try:
            resp = await self._get(self.FEED_URL)
        except Exception as exc:
            logger.error("[URLhaus] Failed to fetch feed: %s", exc)
            return

        # Feed starts with comment lines beginning with '#'
        lines = [
            line for line in resp.text.splitlines() if not line.startswith("#") and line.strip()
        ]

        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        count = 0
        for row in reader:
            try:
                url_val = row.get("url", "").strip()
                if not url_val:
                    continue

                tags_raw = [t.strip() for t in row.get("tags", "").split(",") if t.strip()]
                threat = _map_tags(tags_raw, _URLHAUS_TAG_MAP)
                status = row.get("url_status", "").lower()
                confidence = Confidence.HIGH if status == "online" else Confidence.MEDIUM

                ioc = IOC(
                    value=url_val,
                    ioc_type=IOCType.URL,
                    source=self.NAME,
                    threat_category=threat,
                    tags=tags_raw,
                    confidence=confidence,
                    first_seen=_parse_ts(row.get("dateadded", "")),
                    description=f"URLhaus | status={status} | host={row.get('host', '')}",
                    raw_metadata={
                        "url_id": row.get("id", ""),
                        "host": row.get("host", ""),
                        "url_status": status,
                    },
                )
                ioc = enrich_mitre(ioc)
                yield ioc
                count += 1

                # Also yield the host as a separate domain/IP IOC
                host = row.get("host", "").strip()
                if host:
                    host_type = IOCType.IP if _looks_like_ip(host) else IOCType.DOMAIN
                    yield enrich_mitre(
                        IOC(
                            value=host,
                            ioc_type=host_type,
                            source=self.NAME,
                            threat_category=threat,
                            tags=tags_raw,
                            confidence=confidence,
                            first_seen=_parse_ts(row.get("dateadded", "")),
                            description=f"URLhaus host | status={status}",
                            raw_metadata={"url_id": row.get("id", "")},
                        )
                    )
            except Exception as exc:
                logger.debug("[URLhaus] Row parse error: %s", exc)

        logger.info("[URLhaus] Yielded %d IOCs", count)


class MalwareBazaarSource(BaseSource):
    """
    Pulls recent samples from MalwareBazaar via the API.
    https://bazaar.abuse.ch/api/
    """

    NAME = "malwarebazaar"
    BASE_URL = "https://mb-api.abuse.ch"
    API_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, limit: int = 100, **kwargs):
        super().__init__(**kwargs)
        self.limit = limit

    async def fetch(self) -> AsyncGenerator[IOC, None]:
        logger.info("[MalwareBazaar] Fetching recent samples (limit=%d) …", self.limit)
        try:
            resp = await self._post(
                self.API_URL,
                data={"query": "get_recent", "selector": "100"},
            )
            data = resp.json()
        except Exception as exc:
            logger.error("[MalwareBazaar] API error: %s", exc)
            return

        if data.get("query_status") != "ok":
            logger.warning("[MalwareBazaar] Unexpected status: %s", data.get("query_status"))
            return

        count = 0
        for sample in data.get("data", [])[: self.limit]:
            try:
                tags_raw = sample.get("tags") or []
                if isinstance(tags_raw, str):
                    tags_raw = [tags_raw]
                threat = _map_tags(tags_raw, _BAZAAR_TAG_MAP)

                for hash_type, ioc_type in (
                    ("sha256_hash", IOCType.HASH_SHA256),
                    ("sha1_hash", IOCType.HASH_SHA1),
                    ("md5_hash", IOCType.HASH_MD5),
                ):
                    h = sample.get(hash_type, "").strip()
                    if not h:
                        continue
                    yield enrich_mitre(
                        IOC(
                            value=h,
                            ioc_type=ioc_type,
                            source=self.NAME,
                            threat_category=threat,
                            malware_family=sample.get("signature"),
                            tags=tags_raw,
                            confidence=Confidence.HIGH,
                            first_seen=_parse_ts(sample.get("first_seen", "")),
                            last_seen=_parse_ts(sample.get("last_seen", "")),
                            description=(
                                f"MalwareBazaar | {sample.get('file_name', 'unknown')} "
                                f"| {sample.get('file_type', '')}"
                            ),
                            raw_metadata={
                                "bazaar_id": sample.get("sha256_hash", ""),
                                "file_name": sample.get("file_name", ""),
                                "file_size": sample.get("file_size", ""),
                                "imphash": sample.get("imphash", ""),
                                "reporter": sample.get("reporter", ""),
                            },
                        )
                    )
                    count += 1
                    await asyncio.sleep(0)  # yield control

            except Exception as exc:
                logger.debug("[MalwareBazaar] Sample parse error: %s", exc)

        logger.info("[MalwareBazaar] Yielded %d IOCs", count)


def _looks_like_ip(value: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))
