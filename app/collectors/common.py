"""Shared base for offline-first collectors."""

from __future__ import annotations

from abc import abstractmethod

from app.collectors.base import CollectedIndicator, Collector
from app.collectors.samples import sample_for
from app.config import Settings
from app.core.logging import get_logger

log = get_logger(__name__)


class OfflineFirstCollector(Collector):
    """A collector that serves bundled samples unless live collection is enabled.

    Subclasses implement :meth:`_collect_live`; the base decides whether to call
    it based on the server policy and key availability, falling back to samples
    (and never raising to the caller merely because a source is offline).
    """

    name: str = "base"
    requires_key: bool = False

    def __init__(self, settings: Settings, *, api_key: str = "") -> None:
        self._settings = settings
        self._api_key = api_key

    @property
    def is_live(self) -> bool:
        if not self._settings.enable_live_collectors:
            return False
        # Keyed sources stay offline until a key is configured.
        return not (self.requires_key and not self._api_key)

    async def collect(self, *, limit: int = 100) -> list[CollectedIndicator]:
        if not self.is_live:
            return sample_for(self.name, limit)
        try:
            return await self._collect_live(limit=limit)
        except Exception as exc:  # noqa: BLE001 - degrade gracefully to samples
            log.warning("collector_live_failed", collector=self.name, error=str(exc))
            return sample_for(self.name, limit)

    @abstractmethod
    async def _collect_live(self, *, limit: int) -> list[CollectedIndicator]:
        """Perform the real network call and normalise the response."""
