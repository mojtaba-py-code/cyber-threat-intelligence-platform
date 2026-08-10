"""Bundled sample intelligence served when live collection is disabled.

Sample indicators deliberately use RFC 5737 documentation IP ranges
(``198.51.100.0/24``, ``203.0.113.0/24``) and ``.example`` domains so nothing
here points at real infrastructure — safe to ship, demo and test.
"""

from __future__ import annotations

from app.collectors.base import CollectedIndicator
from app.ioc.types import Confidence, Severity

SAMPLES: dict[str, list[CollectedIndicator]] = {
    "abuseipdb": [
        CollectedIndicator(
            value="198.51.100.23",
            source="abuseipdb",
            confidence=Confidence.high,
            severity=Severity.high,
            tags=("bruteforce", "ssh"),
            description="SSH brute-force source (sample).",
            raw={"abuseConfidenceScore": 92, "totalReports": 148, "countryCode": "RU"},
        ),
        CollectedIndicator(
            value="203.0.113.77",
            source="abuseipdb",
            confidence=Confidence.medium,
            severity=Severity.medium,
            tags=("scanner",),
            description="Port scanner (sample).",
            raw={"abuseConfidenceScore": 55, "totalReports": 20, "countryCode": "CN"},
        ),
    ],
    "urlhaus": [
        CollectedIndicator(
            value="http://malware-drop.example/payload.bin",
            source="urlhaus",
            confidence=Confidence.high,
            severity=Severity.critical,
            tags=("malware_download", "elf"),
            references=("https://urlhaus.abuse.ch/",),
            description="Malware distribution URL (sample).",
            raw={"threat": "malware_download", "url_status": "online"},
        ),
    ],
    "malwarebazaar": [
        CollectedIndicator(
            value="44d88612fea8a8f36de82e1278abb02f",
            source="malwarebazaar",
            confidence=Confidence.confirmed,
            severity=Severity.critical,
            tags=("trojan", "agenttesla"),
            description="AgentTesla sample (EICAR-style test hash).",
            raw={"file_type": "exe", "signature": "AgentTesla"},
        ),
    ],
    "otx": [
        CollectedIndicator(
            value="phishing-login.example",
            source="otx",
            confidence=Confidence.medium,
            severity=Severity.high,
            tags=("phishing", "credential_harvesting"),
            description="Phishing landing domain (sample).",
            raw={"pulse": "Credential Phishing Campaign"},
        ),
    ],
    "cisa_kev": [
        CollectedIndicator(
            value="CVE-2021-44228",
            source="cisa_kev",
            confidence=Confidence.confirmed,
            severity=Severity.critical,
            tags=("kev", "rce", "log4j"),
            references=("https://www.cisa.gov/known-exploited-vulnerabilities-catalog",),
            description="Apache Log4j2 RCE (Log4Shell) — known exploited.",
            raw={"vendorProject": "Apache", "product": "Log4j2", "knownRansomwareUse": "Known"},
        ),
    ],
    "rss": [
        CollectedIndicator(
            value="CVE-2024-3400",
            source="rss",
            confidence=Confidence.high,
            severity=Severity.high,
            tags=("advisory", "firewall"),
            description="Sample advisory feed item referencing a CVE.",
            raw={"title": "Critical firewall advisory"},
        ),
    ],
}


def sample_for(collector: str, limit: int = 100) -> list[CollectedIndicator]:
    return SAMPLES.get(collector, [])[:limit]
