"""MISP event export.

Produces the JSON shape MISP accepts on ``POST /events`` — an ``Event`` wrapping
one ``Attribute`` per indicator. Distribution defaults to ``0`` ("your
organisation only"): sharing wider is a deliberate operator decision, never a
default of ours.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime

from app.ioc.types import IOCType
from app.models.ioc import IOC

_NAMESPACE = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")

_ATTRIBUTE_TYPE = {
    IOCType.ipv4: "ip-dst",
    IOCType.ipv6: "ip-dst",
    IOCType.domain: "domain",
    IOCType.hostname: "hostname",
    IOCType.url: "url",
    IOCType.md5: "md5",
    IOCType.sha1: "sha1",
    IOCType.sha256: "sha256",
    IOCType.email: "email-src",
    IOCType.cve: "vulnerability",
    IOCType.yara: "yara",
    IOCType.sigma: "sigma",
}

_CATEGORY = {
    "ip-dst": "Network activity",
    "domain": "Network activity",
    "hostname": "Network activity",
    "url": "Network activity",
    "md5": "Payload delivery",
    "sha1": "Payload delivery",
    "sha256": "Payload delivery",
    "email-src": "Payload delivery",
    "vulnerability": "External analysis",
    "yara": "Payload installation",
    "sigma": "Payload installation",
}

# MISP threat levels: 1 high, 2 medium, 3 low, 4 undefined.
_THREAT_LEVEL = {"critical": 1, "high": 1, "medium": 2, "low": 3, "clean": 4}

# Types MISP can turn into detection rules; only these are worth to_ids=True.
_DETECTABLE = frozenset({"ip-dst", "domain", "hostname", "url", "md5", "sha1", "sha256"})

#: Indicators scoring at or above this are exported as detection-worthy.
TO_IDS_MIN_SCORE = 50


def _deterministic_uuid(value: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, value))


def _as_utc(value: datetime | None) -> datetime:
    moment = value or datetime.now(UTC)
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment  # stored times are UTC


def _epoch(value: datetime | None) -> str:
    """MISP's ``timestamp`` field is seconds since the epoch, as a string."""
    return str(int(_as_utc(value).timestamp()))


def _iso(value: datetime | None) -> str:
    """MISP's ``first_seen``/``last_seen`` fields are ISO 8601, not epochs."""
    return _as_utc(value).isoformat()


def _attribute(ioc: IOC) -> dict | None:
    try:
        attribute_type = _ATTRIBUTE_TYPE[IOCType(ioc.type)]
    except (ValueError, KeyError):
        return None
    tags = [{"name": tag} for tag in sorted(ioc.tags or [])]
    tags.append({"name": f'tip:threat-level="{ioc.threat_level}"'})
    return {
        "uuid": _deterministic_uuid(f"{ioc.type}:{ioc.value}"),
        "type": attribute_type,
        "category": _CATEGORY.get(attribute_type, "External analysis"),
        "value": ioc.value,
        "to_ids": attribute_type in _DETECTABLE and ioc.threat_score >= TO_IDS_MIN_SCORE,
        "distribution": "5",  # inherit the event's distribution
        "comment": (
            ioc.description or f"score {ioc.threat_score}/100 ({ioc.threat_level}) via {ioc.source}"
        ),
        "timestamp": _epoch(ioc.last_seen),
        "first_seen": _iso(ioc.first_seen),
        "last_seen": _iso(ioc.last_seen),
        "Tag": tags,
    }


def _worst_level(iocs: Sequence[IOC]) -> int:
    return min((_THREAT_LEVEL.get(i.threat_level, 4) for i in iocs), default=4)


def to_misp_event(
    iocs: Sequence[IOC],
    *,
    info: str = "Threat Intel Platform export",
    event_date: date | None = None,
    distribution: str = "0",
) -> dict:
    """Serialise indicators as a MISP event.

    ATT&CK techniques are attached as event-level galaxy tags rather than
    attributes, which is how MISP models technique attribution.
    """
    day = event_date or datetime.now(UTC).date()
    attributes = [attr for ioc in iocs if (attr := _attribute(ioc)) is not None]
    technique_tags = [
        {"name": f'misp-galaxy:mitre-attack-pattern="{ioc.value}"'}
        for ioc in iocs
        if ioc.type == IOCType.mitre_technique.value
    ]
    return {
        "Event": {
            "uuid": _deterministic_uuid(f"{info}:{day.isoformat()}"),
            "info": info,
            "date": day.isoformat(),
            "threat_level_id": str(_worst_level(iocs)),
            "analysis": "2",  # completed
            "distribution": distribution,
            "published": False,
            "Attribute": attributes,
            "Tag": [{"name": "tlp:amber"}, *technique_tags],
        }
    }
