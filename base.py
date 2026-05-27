"""
IOC Harvester - Base Source
Abstract base class for all threat intelligence sources.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import AsyncGenerator

import httpx

from ioc_harvester.models import IOC

logger = logging.getLogger(__name__)


class BaseSource(ABC):
    """Abstract base class every source connector must implement."""

    NAME: str = "base"
    BASE_URL: str = ""
    RATE_LIMIT_DELAY: float = 0.5  # seconds between requests

    def __init__(
        self,
        api_key: str | None = None,
        timeout: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = True,
    ) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None
        self._verify_ssl = verify_ssl

    async def __aenter__(self) -> "BaseSource":
        headers = self._default_headers()
        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        return self

    async def __aexit__(self, *_) -> None:
        if self._client:
            await self._client.aclose()

    def _default_headers(self) -> dict[str, str]:
        return {"User-Agent": "ioc-harvester/1.0 (https://github.com/example/ioc-harvester)"}

    async def _get(self, url: str, **kwargs) -> httpx.Response:
        assert self._client is not None, "Use async context manager"
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                r = await self._client.get(url, **kwargs)
                r.raise_for_status()
                return r
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    import asyncio
                    wait = 2 ** attempt
                    logger.warning("[%s] Rate limited, waiting %ss", self.NAME, wait)
                    await asyncio.sleep(wait)
                    last_exc = e
                elif e.response.status_code >= 500:
                    last_exc = e
                else:
                    raise
            except httpx.RequestError as e:
                last_exc = e
                import asyncio
                await asyncio.sleep(1)
        raise RuntimeError(f"[{self.NAME}] Failed after {self.max_retries} attempts") from last_exc

    async def _post(self, url: str, **kwargs) -> httpx.Response:
        assert self._client is not None, "Use async context manager"
        r = await self._client.post(url, **kwargs)
        r.raise_for_status()
        return r

    @abstractmethod
    async def fetch(self) -> AsyncGenerator[IOC, None]:
        """Yield normalized IOC objects from the source."""
        ...

    @property
    def source_name(self) -> str:
        return self.NAME
