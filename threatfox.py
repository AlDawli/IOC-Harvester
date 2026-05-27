"""
IOC Harvester - ThreatFox Source
Fetches IOCs from ThreatFox (abuse.ch).
https://threatfox.abuse.ch/api/
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
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

_TF_IOC_TYPE_MAP: dict[str, IOCType] = {
    "ip:port": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "md5_hash": IOCType.HASH_MD5,
    "sha256_hash": IOCType.HASH_SHA256,
}

_TF_THREAT_MAP: dict[str, ThreatCategory] = {
    "botnet_cc": ThreatCategory.C2,
    "payload_delivery": ThreatCategory.MALWARE,
    "staging": ThreatCategory.MALWARE,
    "phishing": ThreatCategory.PHISHING,
}

_TF_MALWARE_MAP: dict[str, ThreatCategory] = {
    "ransomware": ThreatCategory.RANSOMWARE,
    "trojan": ThreatCategory.TROJAN,
    "botnet": ThreatCategory.BOTNET,
    "rat": ThreatCategory.TROJAN,
    "loader": ThreatCategory.MALWARE,
    "infostealer": ThreatCategory.TROJAN,
    "banker": ThreatCategory.TROJAN,
}


def _parse_ts(val: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(val.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            continue
    return None


def _normalize_ip_port(value: str) -> str:
    """Strip port from ip:port IOC values."""
    if ":" in value:
        return value.rsplit(":", 1)[0]
    return value


def _map_threat(threat_type: str, malware_name: str) -> ThreatCategory:
    cat = _TF_THREAT_MAP.get(threat_type.lower())
    if cat:
        return cat
    # Try malware name keywords
    malware_lower = malware_name.lower()
    for keyword, cat in _TF_MALWARE_MAP.items():
        if keyword in malware_lower:
            return cat
    return ThreatCategory.UNKNOWN


class ThreatFoxSource(BaseSource):
    """
    Fetches IOCs from the ThreatFox API.
    API key is optional (anonymous requests have lower limits).
    """

    NAME = "threatfox"
    API_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, api_key: str | None = None, days: int = 3, **kwargs) -> None:
        super().__init__(api_key=api_key, **kwargs)
        self.days = days

    def _default_headers(self) -> dict[str, str]:
        headers = super()._default_headers()
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    async def fetch(self) -> AsyncGenerator[IOC, None]:
        logger.info("[ThreatFox] Querying recent IOCs (days=%d) …", self.days)
        try:
            resp = await self._post(
                self.API_URL,
                json={"query": "get_iocs", "days": self.days},
            )
            data = resp.json()
        except Exception as exc:
            logger.error("[ThreatFox] API error: %s", exc)
            return

        status = data.get("query_status", "")
        if status == "no_results":
            logger.info("[ThreatFox] No results for this window.")
            return
        if status != "ok":
            logger.warning("[ThreatFox] Unexpected status: %s", status)
            return

        count = 0
        for entry in data.get("data", []):
            try:
                raw_type = entry.get("ioc_type", "").lower()
                ioc_type = _TF_IOC_TYPE_MAP.get(raw_type, IOCType.UNKNOWN)
                if ioc_type == IOCType.UNKNOWN:
                    continue

                value = entry.get("ioc", "").strip()
                if not value:
                    continue

                # Normalize ip:port → just the IP
                if raw_type == "ip:port":
                    value = _normalize_ip_port(value)

                malware = entry.get("malware", "") or ""
                threat_type = entry.get("threat_type", "") or ""
                threat_cat = _map_threat(threat_type, malware)

                tags = []
                if entry.get("tags"):
                    tags = [t.strip() for t in (entry["tags"] or [])]

                confidence_val = entry.get("confidence_level", 50)
                if confidence_val >= 75:
                    confidence = Confidence.HIGH
                elif confidence_val >= 50:
                    confidence = Confidence.MEDIUM
                else:
                    confidence = Confidence.LOW

                ioc = IOC(
                    value=value,
                    ioc_type=ioc_type,
                    source=self.NAME,
                    threat_category=threat_cat,
                    malware_family=entry.get("malware_printable") or malware or None,
                    tags=tags,
                    confidence=confidence,
                    first_seen=_parse_ts(entry.get("first_seen", "")),
                    last_seen=_parse_ts(entry.get("last_seen", "")),
                    country=entry.get("reporter_country", None),
                    description=(
                        f"ThreatFox | {threat_type} | "
                        f"malware={entry.get('malware_printable', malware)}"
                    ),
                    raw_metadata={
                        "ioc_id": entry.get("id", ""),
                        "threat_type": threat_type,
                        "threat_type_desc": entry.get("threat_type_desc", ""),
                        "malware_malpedia": entry.get("malware_malpedia", ""),
                        "reporter": entry.get("reporter", ""),
                        "confidence_level": confidence_val,
                    },
                )
                yield enrich_mitre(ioc)
                count += 1
                await asyncio.sleep(0)
            except Exception as exc:
                logger.debug("[ThreatFox] Entry parse error: %s", exc)

        logger.info("[ThreatFox] Yielded %d IOCs", count)
