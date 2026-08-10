"""Concrete collectors for supported sources.

Each implements ``_collect_live`` (the real request + response normalisation);
the offline path (bundled samples) is handled by the shared base. Live
normalisers map each provider's JSON into :class:`CollectedIndicator`.
"""

from __future__ import annotations

from app.collectors.base import CollectedIndicator
from app.collectors.common import OfflineFirstCollector
from app.collectors.http import ProviderHttpClient
from app.ioc.types import Confidence, Severity


class AbuseIPDBCollector(OfflineFirstCollector):
    name = "abuseipdb"
    requires_key = True

    async def _collect_live(self, *, limit: int) -> list[CollectedIndicator]:
        client = ProviderHttpClient(self.name)
        data = await client.get_json(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": self._api_key, "Accept": "application/json"},
            params={"confidenceMinimum": 75, "limit": limit},
        )
        out: list[CollectedIndicator] = []
        for row in data.get("data", [])[:limit]:
            score = int(row.get("abuseConfidenceScore", 0))
            out.append(
                CollectedIndicator(
                    value=row["ipAddress"],
                    source=self.name,
                    confidence=Confidence.high if score >= 90 else Confidence.medium,
                    severity=Severity.high if score >= 90 else Severity.medium,
                    tags=("blacklist",),
                    raw=row,
                )
            )
        return out


class URLHausCollector(OfflineFirstCollector):
    name = "urlhaus"
    requires_key = False

    async def _collect_live(self, *, limit: int) -> list[CollectedIndicator]:
        client = ProviderHttpClient(self.name)
        data = await client.get_json("https://urlhaus.abuse.ch/downloads/json_recent/")
        out: list[CollectedIndicator] = []
        # URLHaus returns {id: [ {url, threat, tags, ...} ]}
        for entries in list(data.values())[:limit]:
            entry = entries[0] if isinstance(entries, list) and entries else {}
            url = entry.get("url")
            if not url:
                continue
            out.append(
                CollectedIndicator(
                    value=url,
                    source=self.name,
                    confidence=Confidence.high,
                    severity=Severity.critical,
                    tags=tuple(entry.get("tags") or ()),
                    references=("https://urlhaus.abuse.ch/",),
                    description=entry.get("threat"),
                    raw=entry,
                )
            )
            if len(out) >= limit:
                break
        return out


class MalwareBazaarCollector(OfflineFirstCollector):
    name = "malwarebazaar"
    requires_key = False

    async def _collect_live(self, *, limit: int) -> list[CollectedIndicator]:
        client = ProviderHttpClient(self.name)
        data = await client.get_json(
            "https://mb-api.abuse.ch/api/v1/", params={"query": "get_recent", "selector": "time"}
        )
        out: list[CollectedIndicator] = []
        for row in data.get("data", [])[:limit]:
            sha256 = row.get("sha256_hash")
            if not sha256:
                continue
            out.append(
                CollectedIndicator(
                    value=sha256,
                    source=self.name,
                    confidence=Confidence.confirmed,
                    severity=Severity.critical,
                    tags=tuple(row.get("tags") or ()),
                    description=row.get("signature"),
                    raw=row,
                )
            )
        return out


class OTXCollector(OfflineFirstCollector):
    name = "otx"
    requires_key = True

    async def _collect_live(self, *, limit: int) -> list[CollectedIndicator]:
        client = ProviderHttpClient(self.name)
        data = await client.get_json(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": self._api_key},
            params={"limit": limit},
        )
        out: list[CollectedIndicator] = []
        for pulse in data.get("results", []):
            for ind in pulse.get("indicators", []):
                value = ind.get("indicator")
                if not value:
                    continue
                out.append(
                    CollectedIndicator(
                        value=value,
                        source=self.name,
                        confidence=Confidence.medium,
                        severity=Severity.high,
                        tags=tuple(pulse.get("tags") or ()),
                        description=pulse.get("name"),
                        raw=ind,
                    )
                )
                if len(out) >= limit:
                    return out
        return out


class CisaKevCollector(OfflineFirstCollector):
    name = "cisa_kev"
    requires_key = False

    async def _collect_live(self, *, limit: int) -> list[CollectedIndicator]:
        client = ProviderHttpClient(self.name)
        data = await client.get_json(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        out: list[CollectedIndicator] = []
        for row in data.get("vulnerabilities", [])[:limit]:
            cve = row.get("cveID")
            if not cve:
                continue
            out.append(
                CollectedIndicator(
                    value=cve,
                    source=self.name,
                    confidence=Confidence.confirmed,
                    severity=Severity.critical,
                    tags=("kev",),
                    references=("https://www.cisa.gov/known-exploited-vulnerabilities-catalog",),
                    description=row.get("vulnerabilityName"),
                    raw=row,
                )
            )
        return out


class RSSCollector(OfflineFirstCollector):
    name = "rss"
    requires_key = False

    #: default feeds; operators can extend this list
    FEEDS = ("https://www.cisa.gov/cybersecurity-advisories/all.xml",)

    async def _collect_live(self, *, limit: int) -> list[CollectedIndicator]:
        import feedparser  # lazy import; only needed for live RSS
        import httpx

        out: list[CollectedIndicator] = []
        async with httpx.AsyncClient(timeout=10.0) as client:
            for feed_url in self.FEEDS:
                resp = await client.get(feed_url)
                parsed = feedparser.parse(resp.text)
                for entry in parsed.entries[:limit]:
                    title = entry.get("title", "advisory")
                    out.append(
                        CollectedIndicator(
                            value=title,
                            source=self.name,
                            confidence=Confidence.medium,
                            severity=Severity.medium,
                            tags=("advisory",),
                            references=(entry.get("link", ""),),
                            description=entry.get("summary"),
                            raw={"title": title},
                        )
                    )
                    if len(out) >= limit:
                        return out
        return out


COLLECTOR_CLASSES: dict[str, type[OfflineFirstCollector]] = {
    "abuseipdb": AbuseIPDBCollector,
    "urlhaus": URLHausCollector,
    "malwarebazaar": MalwareBazaarCollector,
    "otx": OTXCollector,
    "cisa_kev": CisaKevCollector,
    "rss": RSSCollector,
}
