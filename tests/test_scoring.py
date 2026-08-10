"""Tests for the threat-scoring engine."""

from __future__ import annotations

import pytest
from app.ioc.types import Confidence, ThreatLevel
from app.scoring.engine import (
    ScoreSignals,
    compute_threat_score,
    detection_ratio,
    frequency_score,
    geo_risk_score,
    level_for_score,
    port_risk_score,
    recency_score,
)


def test_all_max_signals_is_critical():
    signals = ScoreSignals(
        source_reputation=1,
        detection_ratio=1,
        blacklist_presence=1,
        confidence=1,
        recency=1,
        frequency=1,
        geo_risk=1,
        port_risk=1,
        historical_activity=1,
    )
    result = compute_threat_score(signals)
    assert result.score == 100
    assert result.level is ThreatLevel.critical


def test_all_zero_is_clean():
    result = compute_threat_score(ScoreSignals())
    assert result.score == 0
    assert result.level is ThreatLevel.clean


def test_contributions_sum_close_to_score():
    signals = ScoreSignals(source_reputation=1, detection_ratio=1, confidence=1)
    result = compute_threat_score(signals)
    assert round(sum(result.contributions.values())) == result.score


def test_level_thresholds():
    assert level_for_score(90) is ThreatLevel.critical
    assert level_for_score(70) is ThreatLevel.high
    assert level_for_score(50) is ThreatLevel.medium
    assert level_for_score(20) is ThreatLevel.low
    assert level_for_score(5) is ThreatLevel.clean


def test_detection_ratio():
    assert detection_ratio(35, 70) == pytest.approx(0.5)
    assert detection_ratio(0, 0) == 0.0


def test_recency_decays():
    assert recency_score(0) == pytest.approx(1.0)
    assert recency_score(30, half_life_days=30) == pytest.approx(0.5)
    assert recency_score(60, half_life_days=30) == pytest.approx(0.25)


def test_frequency_monotonic():
    assert frequency_score(1) < frequency_score(10) <= frequency_score(100)


def test_geo_and_port_risk():
    assert geo_risk_score("RU") == 1.0
    assert geo_risk_score("US") == 0.0
    assert port_risk_score([4444, 445, 3389]) == pytest.approx(1.0)
    assert port_risk_score([80]) == 0.0


def test_from_confidence_helper():
    s = ScoreSignals.from_confidence(Confidence.confirmed, detection_ratio=1)
    assert s.confidence == 1.0
