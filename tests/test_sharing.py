"""Tests for STIX 2.1 and MISP export."""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from app.ioc.indicators import defang
from app.ioc.types import IOCType
from app.models.ioc import IOC
from app.sharing.misp import to_misp_event
from app.sharing.stix import STIX_NAMESPACE, stix_pattern, to_stix_bundle

SEEN = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def make_ioc(ioc_type: IOCType, value: str, **kwargs) -> IOC:
    defaults = {
        "type": ioc_type.value,
        "value": value,
        "defanged_value": defang(value),
        "source": "urlhaus",
        "confidence": "high",
        "severity": "high",
        "status": "active",
        "threat_score": 80,
        "threat_level": "high",
        "sightings": 3,
        "tags": ["c2"],
        "references": ["https://example.com/report"],
        "description": None,
        "first_seen": SEEN,
        "last_seen": SEEN,
    }
    return IOC(**{**defaults, **kwargs})


# --- STIX -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected"),
    [
        (IOCType.ipv4, "198.51.100.3", "[ipv4-addr:value = '198.51.100.3']"),
        (IOCType.ipv6, "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        (IOCType.domain, "evil.example", "[domain-name:value = 'evil.example']"),
        (IOCType.url, "http://evil.example/x", "[url:value = 'http://evil.example/x']"),
        (IOCType.email, "a@evil.example", "[email-addr:value = 'a@evil.example']"),
        (IOCType.hostname, "host.example", "[domain-name:value = 'host.example']"),
        (
            IOCType.md5,
            "d41d8cd98f00b204e9800998ecf8427e",
            "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']",
        ),
    ],
)
def test_patterns_match_the_stix_grammar(ioc_type, value, expected):
    assert stix_pattern(ioc_type, value) == expected


def test_pattern_escapes_quotes_so_the_grammar_cannot_be_broken():
    pattern = stix_pattern(IOCType.url, "http://evil.example/it's")
    assert pattern == "[url:value = 'http://evil.example/it\\'s']"


def test_types_without_a_pattern_return_none():
    assert stix_pattern(IOCType.cve, "CVE-2024-1") is None
    assert stix_pattern(IOCType.yara, "rule x {}") is None


def test_bundle_shape_and_indicator_properties():
    bundle = to_stix_bundle([make_ioc(IOCType.ipv4, "198.51.100.3")])
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")

    identity, indicator = bundle["objects"]
    assert identity["type"] == "identity"
    assert indicator["type"] == "indicator"
    assert indicator["spec_version"] == "2.1"
    assert indicator["id"].startswith("indicator--")
    assert indicator["created_by_ref"] == identity["id"]
    assert indicator["pattern_type"] == "stix"
    assert indicator["pattern"] == "[ipv4-addr:value = '198.51.100.3']"
    assert indicator["indicator_types"] == ["malicious-activity"]
    assert indicator["confidence"] == 75  # "high"
    assert indicator["created"] == "2026-01-02T03:04:05.000Z"
    assert indicator["x_threat_score"] == 80
    assert "high" in indicator["labels"] and "c2" in indicator["labels"]


def test_indicator_ids_are_deterministic_across_exports():
    first = to_stix_bundle([make_ioc(IOCType.domain, "evil.example")])["objects"][1]["id"]
    second = to_stix_bundle([make_ioc(IOCType.domain, "evil.example")])["objects"][1]["id"]
    assert first == second
    # The id is a UUIDv5 in the namespace the STIX spec reserves for this.
    assert str(STIX_NAMESPACE) == "00abedb4-aa42-466c-9c01-fed23315a9b7"


def test_clean_indicators_are_labelled_benign():
    ioc = make_ioc(IOCType.ipv4, "203.0.113.1", threat_level="clean", threat_score=2)
    assert to_stix_bundle([ioc])["objects"][1]["indicator_types"] == ["benign"]


def test_cve_becomes_a_vulnerability_sdo():
    sdo = to_stix_bundle([make_ioc(IOCType.cve, "CVE-2024-21412")])["objects"][1]
    assert sdo["type"] == "vulnerability"
    assert sdo["external_references"][0]["external_id"] == "CVE-2024-21412"


def test_technique_becomes_an_attack_pattern_sdo():
    sdo = to_stix_bundle([make_ioc(IOCType.mitre_technique, "T1059.001")])["objects"][1]
    assert sdo["type"] == "attack-pattern"
    ref = sdo["external_references"][0]
    assert ref["source_name"] == "mitre-attack"
    assert ref["url"] == "https://attack.mitre.org/techniques/T1059/001/"
    assert sdo["x_mitre_parent_technique"] == "T1059"


def test_unrepresentable_types_are_skipped_not_emitted_broken():
    bundle = to_stix_bundle([make_ioc(IOCType.yara, "rule x {}")])
    assert [o["type"] for o in bundle["objects"]] == ["identity"]


def test_external_references_only_carry_real_urls():
    ioc = make_ioc(IOCType.ipv4, "198.51.100.9", references=["not-a-url", "https://ok.example/a"])
    refs = to_stix_bundle([ioc])["objects"][1]["external_references"]
    assert [r.get("url") for r in refs] == [None, "https://ok.example/a"]


# --- MISP -------------------------------------------------------------------


def test_misp_event_shape():
    event = to_misp_event(
        [make_ioc(IOCType.ipv4, "198.51.100.3")],
        info="Op Example",
        event_date=date(2026, 1, 2),
    )["Event"]
    assert event["info"] == "Op Example"
    assert event["date"] == "2026-01-02"
    assert event["threat_level_id"] == "1"  # "high" → MISP level 1
    assert event["published"] is False
    assert event["distribution"] == "0"  # organisation-only by default

    attribute = event["Attribute"][0]
    assert attribute["type"] == "ip-dst"
    assert attribute["category"] == "Network activity"
    assert attribute["value"] == "198.51.100.3"
    assert attribute["to_ids"] is True
    assert {"name": 'tip:threat-level="high"'} in attribute["Tag"]
    # ``timestamp`` is an epoch; ``first_seen``/``last_seen`` are ISO 8601.
    assert attribute["timestamp"] == str(int(SEEN.timestamp()))
    assert attribute["first_seen"] == "2026-01-02T03:04:05+00:00"


def test_low_scoring_indicators_are_not_marked_for_detection():
    ioc = make_ioc(IOCType.domain, "maybe.example", threat_score=10, threat_level="low")
    assert to_misp_event([ioc])["Event"]["Attribute"][0]["to_ids"] is False


def test_threat_level_is_the_worst_indicator_in_the_set():
    iocs = [
        make_ioc(IOCType.ipv4, "203.0.113.1", threat_level="low"),
        make_ioc(IOCType.ipv4, "203.0.113.2", threat_level="critical"),
    ]
    assert to_misp_event(iocs)["Event"]["threat_level_id"] == "1"


def test_techniques_become_galaxy_tags_not_attributes():
    event = to_misp_event([make_ioc(IOCType.mitre_technique, "T1059")])["Event"]
    assert event["Attribute"] == []
    assert {"name": 'misp-galaxy:mitre-attack-pattern="T1059"'} in event["Tag"]


def test_empty_export_is_still_a_valid_event():
    event = to_misp_event([])["Event"]
    assert event["Attribute"] == []
    assert event["threat_level_id"] == "4"  # undefined


def test_attribute_uuids_are_stable_for_the_same_indicator():
    one = to_misp_event([make_ioc(IOCType.domain, "evil.example")])["Event"]["Attribute"][0]
    two = to_misp_event([make_ioc(IOCType.domain, "evil.example")])["Event"]["Attribute"][0]
    assert one["uuid"] == two["uuid"]
