"""
IOC Harvester - AlienVault OTX Source
Fetches IOCs from AlienVault Open Threat Exchange (OTX).
https://otx.alienvault.com/api/v1/
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
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

_OTX_TYPE_MAP: dict[str, IOCType] = {
    "IPv4": IOCType.IP,
    "IPv6": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "URL": IOCType.URL,
    "FileHash-MD5": IOCType.HASH_MD5,
    "FileHash-SHA1": IOCType.HASH_SHA1,
    "FileHash-SHA256": IOCType.HASH_SHA256,
    "email": IOCType.EMAIL,
}

_OTX_CATEGORY_MAP: dict[str, ThreatCategory] = {
    "malware": ThreatCategory.MALWARE,
    "ransomware": ThreatCategory.RANSOMWARE,
    "phishing": ThreatCategory.PHISHING,
    "botnet": ThreatCategory.BOTNET,
    "c2": ThreatCategory.C2,
    "exploit": ThreatCategory.EXPLOIT,
    "trojan": ThreatCategory.TROJAN,
    "spam": ThreatCategory.SPAM,
    "scanner": ThreatCategory.SCANNER,
}


def _parse_ts(val: str) -> datetime | None:
    if not val:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _map_category(tags: list[str]) -> ThreatCategory:
    for tag in tags:
        cat = _OTX_CATEGORY_MAP.get(tag.lower())
        if cat:
            return cat
    return ThreatCategory.UNKNOWN


class AlienVaultOTXSource(BaseSource):
    """
    Fetches IOC indicators from AlienVault OTX.

    Two modes:
      - subscribed pulses (requires API key, default)
      - recent public pulses  (no API key needed)
    """

    NAME = "alienvault_otx"
    BASE_URL = "https://otx.alienvault.com"

    def __init__(
        self,
        api_key: str | None = None,
        days_back: int = 7,
        limit_pulses: int = 20,
        ioc_types: list[str] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(api_key=api_key, **kwargs)
        self.days_back = days_back
        self.limit_pulses = limit_pulses
        self.ioc_types = set(ioc_types or list(_OTX_TYPE_MAP.keys()))

    def _default_headers(self) -> dict[str, str]:
        headers = super()._default_headers()
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        return headers

    async def fetch(self) -> AsyncGenerator[IOC, None]:
        since = (datetime.now(tz=timezone.utc) - timedelta(days=self.days_back)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )

        if self.api_key:
            endpoint = f"{self.BASE_URL}/api/v1/pulses/subscribed"
            logger.info("[OTX] Fetching subscribed pulses since %s …", since)
        else:
            endpoint = f"{self.BASE_URL}/api/v1/pulses/activity"
            logger.info("[OTX] Fetching public pulses since %s (no API key) …", since)

        page = 1
        pulses_fetched = 0

        while pulses_fetched < self.limit_pulses:
            try:
                resp = await self._get(
                    endpoint,
                    params={"modified_since": since, "page": page, "limit": 20},
                )
                data = resp.json()
            except Exception as exc:
                logger.error("[OTX] Fetch error on page %d: %s", page, exc)
                break

            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                async for ioc in self._parse_pulse(pulse):
                    yield ioc
                pulses_fetched += 1
                if pulses_fetched >= self.limit_pulses:
                    break

            if not data.get("next"):
                break
            page += 1
            await asyncio.sleep(self.RATE_LIMIT_DELAY)

        logger.info("[OTX] Processed %d pulses", pulses_fetched)

    async def _parse_pulse(self, pulse: dict) -> AsyncGenerator[IOC, None]:
        pulse_name = pulse.get("name", "unknown")
        pulse_id = pulse.get("id", "")
        tags = [t.lower() for t in pulse.get("tags", [])]
        adversary = pulse.get("adversary", "")
        threat_cat = _map_category(tags)

        for indicator in pulse.get("indicators", []):
            try:
                raw_type = indicator.get("type", "")
                ioc_type = _OTX_TYPE_MAP.get(raw_type, IOCType.UNKNOWN)
                if ioc_type == IOCType.UNKNOWN:
                    continue

                value = indicator.get("indicator", "").strip()
                if not value:
                    continue

                # Build confidence from pulse tlp
                tlp = pulse.get("tlp", "white").lower()
                confidence = {
                    "red": Confidence.HIGH,
                    "amber": Confidence.HIGH,
                    "green": Confidence.MEDIUM,
                    "white": Confidence.LOW,
                }.get(tlp, Confidence.UNKNOWN)

                ioc = IOC(
                    value=value,
                    ioc_type=ioc_type,
                    source=self.NAME,
                    threat_category=threat_cat,
                    malware_family=adversary or None,
                    tags=tags,
                    confidence=confidence,
                    first_seen=_parse_ts(indicator.get("created", "")),
                    last_seen=_parse_ts(pulse.get("modified", "")),
                    description=f"OTX Pulse: {pulse_name}",
                    raw_metadata={
                        "pulse_id": pulse_id,
                        "pulse_name": pulse_name,
                        "tlp": tlp,
                        "indicator_id": indicator.get("id", ""),
                    },
                )
                yield enrich_mitre(ioc)
            except Exception as exc:
                logger.debug("[OTX] Indicator parse error: %s", exc)
