"""Tests for collectors (offline-first policy) and the enrichment engine."""

from __future__ import annotations

import pytest
from app.collectors.factory import CollectorFactory
from app.config.settings import Settings
from app.core.exceptions import ValidationError
from app.enrichment.engine import EnrichmentEngine
from app.ioc.types import IOCType


def _offline_settings() -> Settings:
    return Settings(enable_live_collectors=False)


@pytest.mark.asyncio
async def test_collectors_offline_serve_samples():
    factory = CollectorFactory(_offline_settings())
    for name in factory.available():
        collector = factory.build(name)
        assert collector.is_live is False
        indicators = await collector.collect(limit=10)
        # Every sample collector yields at least one indicator.
        assert all(ind.source == name for ind in indicators)


@pytest.mark.asyncio
async def test_key_required_collector_stays_offline_without_key():
    # Live enabled but no API key configured → still offline for keyed sources.
    factory = CollectorFactory(Settings(enable_live_collectors=True))
    collector = factory.build("abuseipdb")  # requires key
    assert collector.is_live is False


def test_unknown_collector_rejected():
    factory = CollectorFactory(_offline_settings())
    with pytest.raises(ValidationError):
        factory.build("not-a-collector")


@pytest.mark.asyncio
async def test_enrichment_offline_deterministic():
    engine = EnrichmentEngine(_offline_settings())
    a = await engine.enrich(ioc_type=IOCType.ipv4, value="198.51.100.23")
    b = await engine.enrich(ioc_type=IOCType.ipv4, value="198.51.100.23")
    assert a == b  # deterministic offline heuristic
    assert a["geoip"]["source"] == "offline-heuristic"
    assert "reputation" in a


@pytest.mark.asyncio
async def test_enrichment_hash_reputation_only():
    engine = EnrichmentEngine(_offline_settings())
    result = await engine.enrich(ioc_type=IOCType.sha256, value="b" * 64)
    assert "reputation" in result
    assert "geoip" not in result


@pytest.mark.asyncio
async def test_signals_from_enrichment():
    engine = EnrichmentEngine(_offline_settings())
    enrichment = await engine.enrich(ioc_type=IOCType.ipv4, value="203.0.113.9")
    signals = engine.signals_from(enrichment=enrichment, source="abuseipdb", blacklisted=True)
    assert 0.0 <= signals.detection_ratio <= 1.0
    assert signals.blacklist_presence == 1.0
