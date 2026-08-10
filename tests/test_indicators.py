"""Tests for IOC parsing, classification and (de)fanging."""

from __future__ import annotations

import pytest
from app.core.exceptions import UnknownIndicatorError
from app.ioc.indicators import classify_indicator, defang, is_hash, refang
from app.ioc.types import IOCType


@pytest.mark.parametrize(
    ("raw", "expected_type", "expected_value"),
    [
        ("8.8.8.8", IOCType.ipv4, "8.8.8.8"),
        ("2001:4860:4860::8888", IOCType.ipv6, "2001:4860:4860::8888"),
        ("evil.example.com", IOCType.domain, "evil.example.com"),
        ("http://bad.example/x", IOCType.url, "http://bad.example/x"),
        ("44d88612fea8a8f36de82e1278abb02f", IOCType.md5, "44d88612fea8a8f36de82e1278abb02f"),
        ("a" * 40, IOCType.sha1, "a" * 40),
        ("b" * 64, IOCType.sha256, "b" * 64),
        ("user@phish.example", IOCType.email, "user@phish.example"),
        ("CVE-2021-44228", IOCType.cve, "CVE-2021-44228"),
        ("T1059.003", IOCType.mitre_technique, "T1059.003"),
    ],
)
def test_classify(raw, expected_type, expected_value):
    parsed = classify_indicator(raw)
    assert parsed.type is expected_type
    assert parsed.value == expected_value


def test_refang_defanged_url():
    parsed = classify_indicator("hxxps://evil[.]example[.]com/payload")
    assert parsed.type is IOCType.url
    assert parsed.value == "https://evil.example.com/payload"


def test_refang_defanged_ip():
    assert refang("198[.]51[.]100[.]23") == "198.51.100.23"


def test_defang_roundtrip_domain():
    assert defang("evil.com") == "evil[.]com"


def test_is_hash():
    assert is_hash("44d88612fea8a8f36de82e1278abb02f")
    assert not is_hash("nothash")


def test_uppercase_cve_normalised():
    assert classify_indicator("cve-2024-3400").value == "CVE-2024-3400"


def test_unknown_indicator_raises():
    with pytest.raises(UnknownIndicatorError):
        classify_indicator("this is not an indicator!!")


def test_empty_raises():
    with pytest.raises(UnknownIndicatorError):
        classify_indicator("   ")
