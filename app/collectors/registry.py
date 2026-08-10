"""Registry of supported threat-intelligence collectors.

Adding a source is a matter of implementing a :class:`~app.collectors.base.Collector`
and appending one :class:`CollectorInfo` entry here — the factory and API pick it
up automatically. This is the single source of truth for "which feeds exist".
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CollectorInfo:
    name: str  # stable id
    label: str  # human-readable
    category: str  # ip | url | hash | vuln | advisory | actor
    requires_key: bool = False
    fmt: str = "json"  # json | rss | csv | xml


SUPPORTED_COLLECTORS: dict[str, CollectorInfo] = {
    c.name: c
    for c in [
        CollectorInfo("abuseipdb", "AbuseIPDB", "ip", requires_key=True),
        CollectorInfo("urlhaus", "URLHaus", "url", requires_key=False),
        CollectorInfo("malwarebazaar", "MalwareBazaar", "hash", requires_key=False),
        CollectorInfo("otx", "AlienVault OTX", "ip", requires_key=True),
        CollectorInfo("cisa_kev", "CISA KEV", "vuln", requires_key=False),
        CollectorInfo("rss", "Security RSS", "advisory", requires_key=False, fmt="rss"),
    ]
}


def is_supported(name: str) -> bool:
    return name.lower() in SUPPORTED_COLLECTORS


def get_info(name: str) -> CollectorInfo | None:
    return SUPPORTED_COLLECTORS.get(name.lower())
