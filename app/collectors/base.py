"""Collector abstraction — the port every threat-feed source plugs into.

A concrete collector knows how to fetch and normalise intelligence from one
source. Collectors are **offline-first**: when live collection is disabled (or no
API key is configured) they return bundled sample intelligence, so the whole
platform runs and is testable without network access or secrets. When enabled
with a key, the same collector performs the real request and normalises the
response into :class:`CollectedIndicator` objects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from app.ioc.types import Confidence, Severity


@dataclass(frozen=True, slots=True)
class CollectedIndicator:
    """A normalised indicator emitted by a collector (pre-classification)."""

    value: str  # raw indicator value (may be defanged; ingestion refangs it)
    source: str
    confidence: Confidence = Confidence.medium
    severity: Severity = Severity.medium
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    description: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw: dict = field(default_factory=dict)


class Collector(ABC):
    """Fetch-and-normalise interface for a single source."""

    name: str
    #: whether live collection needs an API key
    requires_key: bool = False

    @abstractmethod
    async def collect(self, *, limit: int = 100) -> list[CollectedIndicator]:
        """Return up to ``limit`` normalised indicators from the source."""

    @property
    @abstractmethod
    def is_live(self) -> bool:
        """Whether this instance performs real network calls."""
