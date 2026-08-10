"""Canonical enumerations for indicators of compromise (IOCs)."""

from __future__ import annotations

from enum import StrEnum


class IOCType(StrEnum):
    """The kind of indicator, using STIX-like naming."""

    ipv4 = "ipv4-addr"
    ipv6 = "ipv6-addr"
    domain = "domain-name"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"
    email = "email-addr"
    hostname = "hostname"
    cve = "cve"
    mitre_technique = "attack-pattern"
    yara = "yara"
    sigma = "sigma"


HASH_TYPES: frozenset[IOCType] = frozenset({IOCType.md5, IOCType.sha1, IOCType.sha256})
NETWORK_TYPES: frozenset[IOCType] = frozenset(
    {IOCType.ipv4, IOCType.ipv6, IOCType.domain, IOCType.url, IOCType.hostname}
)


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Confidence(StrEnum):
    """Analyst/source confidence in an indicator (Admiralty-style buckets)."""

    unknown = "unknown"
    low = "low"
    medium = "medium"
    high = "high"
    confirmed = "confirmed"


class ThreatLevel(StrEnum):
    """The bucketed output of the threat-scoring engine."""

    clean = "clean"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IOCStatus(StrEnum):
    active = "active"
    expired = "expired"
    whitelisted = "whitelisted"
    false_positive = "false_positive"
