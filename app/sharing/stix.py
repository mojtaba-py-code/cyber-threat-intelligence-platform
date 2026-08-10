"""STIX 2.1 export.

Each indicator becomes an ``indicator`` SDO carrying a STIX pattern, except for
CVEs and ATT&CK techniques, which have first-class SDOs (``vulnerability`` and
``attack-pattern``) and no pattern representation. Object ids are UUIDv5 over the
identifying property, as the specification recommends for deterministic sharing:
re-exporting the same indicator yields the same id, so consumers deduplicate
instead of accumulating copies.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from app.ioc.types import IOCType
from app.models.ioc import IOC

SPEC_VERSION = "2.1"
#: Namespace defined by the STIX 2.1 specification for deterministic ids.
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

_HASH_ALGORITHM = {IOCType.md5: "MD5", IOCType.sha1: "SHA-1", IOCType.sha256: "SHA-256"}

# Admiralty-style buckets → the STIX confidence scale (0–100).
_CONFIDENCE = {"unknown": 15, "low": 30, "medium": 50, "high": 75, "confirmed": 95}

# indicator-type-ov terms, chosen from our own scoring verdict.
_INDICATOR_TYPE = {
    "clean": "benign",
    "low": "anomalous-activity",
    "medium": "anomalous-activity",
    "high": "malicious-activity",
    "critical": "malicious-activity",
}


def _timestamp(value: datetime | None) -> str:
    """Format a datetime as a STIX timestamp (UTC, millisecond precision)."""
    moment = value or datetime.now(UTC)
    if moment.tzinfo is None:  # SQLite hands back naive datetimes; they are UTC.
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _escape(value: str) -> str:
    """Escape a value for embedding in a STIX pattern string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _deterministic_id(sdo_type: str, name: str) -> str:
    return f"{sdo_type}--{uuid.uuid5(STIX_NAMESPACE, f'{sdo_type}:{name}')}"


def stix_pattern(ioc_type: IOCType, value: str) -> str | None:
    """Return the STIX pattern for an indicator, or ``None`` if it has no pattern."""
    escaped = _escape(value)
    if ioc_type in (IOCType.ipv4, IOCType.ipv6, IOCType.domain, IOCType.url, IOCType.email):
        # These IOCType values are deliberately named after their STIX SCO types.
        return f"[{ioc_type.value}:value = '{escaped}']"
    if ioc_type is IOCType.hostname:
        return f"[domain-name:value = '{escaped}']"
    algorithm = _HASH_ALGORITHM.get(ioc_type)
    if algorithm is not None:
        return f"[file:hashes.'{algorithm}' = '{escaped}']"
    return None


def _identity(name: str) -> dict:
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": _deterministic_id("identity", name),
        "created": _timestamp(None),
        "modified": _timestamp(None),
        "name": name,
        "identity_class": "system",
    }


def _external_references(ioc: IOC) -> list[dict]:
    references = [{"source_name": ioc.source}]
    references.extend(
        {"source_name": ioc.source, "url": url}
        for url in (ioc.references or [])
        if url.startswith(("http://", "https://"))
    )
    return references


def _sdo_for(ioc: IOC, *, created_by_ref: str) -> dict | None:
    try:
        ioc_type = IOCType(ioc.type)
    except ValueError:
        return None

    created = _timestamp(ioc.first_seen)
    modified = _timestamp(ioc.last_seen)

    if ioc_type is IOCType.cve:
        return {
            "type": "vulnerability",
            "spec_version": SPEC_VERSION,
            "id": _deterministic_id("vulnerability", ioc.value),
            "created_by_ref": created_by_ref,
            "created": created,
            "modified": modified,
            "name": ioc.value,
            "description": ioc.description or f"Vulnerability {ioc.value}",
            "external_references": [{"source_name": "cve", "external_id": ioc.value}],
        }

    if ioc_type is IOCType.mitre_technique:
        base = ioc.value.split(".")[0]
        path = ioc.value.replace(".", "/")
        return {
            "type": "attack-pattern",
            "spec_version": SPEC_VERSION,
            "id": _deterministic_id("attack-pattern", ioc.value),
            "created_by_ref": created_by_ref,
            "created": created,
            "modified": modified,
            "name": ioc.description or f"ATT&CK technique {ioc.value}",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": ioc.value,
                    "url": f"https://attack.mitre.org/techniques/{path}/",
                }
            ],
            "x_mitre_parent_technique": base if base != ioc.value else None,
        }

    pattern = stix_pattern(ioc_type, ioc.value)
    if pattern is None:
        return None

    indicator = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _deterministic_id("indicator", pattern),
        "created_by_ref": created_by_ref,
        "created": created,
        "modified": modified,
        "name": ioc.defanged_value,
        "description": ioc.description
        or f"{ioc.type} observed by {ioc.source}; threat score {ioc.threat_score}/100.",
        "indicator_types": [_INDICATOR_TYPE.get(ioc.threat_level, "unknown")],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "confidence": _CONFIDENCE.get(ioc.confidence, 50),
        "labels": sorted({*(ioc.tags or []), ioc.severity}),
        "external_references": _external_references(ioc),
        # Custom properties must be namespaced with an ``x_`` prefix.
        "x_threat_score": ioc.threat_score,
        "x_threat_level": ioc.threat_level,
        "x_sightings": ioc.sightings,
    }
    return indicator


def to_stix_bundle(
    iocs: Sequence[IOC],
    *,
    producer: str = "Threat Intel Platform",
    bundle_id: str | None = None,
) -> dict:
    """Serialise indicators into a STIX 2.1 bundle.

    Indicators whose type has no STIX representation (YARA/Sigma rules) are
    skipped rather than emitted as invalid objects.
    """
    identity = _identity(producer)
    objects: list[dict] = [identity]
    for ioc in iocs:
        sdo = _sdo_for(ioc, created_by_ref=identity["id"])
        if sdo is not None:
            objects.append({k: v for k, v in sdo.items() if v is not None})
    return {
        "type": "bundle",
        # A bundle is transient, so — unlike the SDOs above — its id is random.
        "id": bundle_id or f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
