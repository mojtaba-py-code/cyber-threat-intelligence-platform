"""Dynamic threat-scoring engine.

Combines normalised signals into a single 0–100 threat score and a bucketed
:class:`~app.ioc.types.ThreatLevel`. The engine is a pure function of its inputs
(no I/O), which makes the scoring transparent, reproducible and unit-testable —
each signal's contribution is returned alongside the score for explainability.

All signal inputs are normalised to ``[0, 1]``; helpers derive several of them
from raw values (detection counts, age in days, geo/port risk).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from app.ioc.types import Confidence, ThreatLevel

# Weighting of each signal. Weights need not sum to 1; the score is the weighted
# average, so relative magnitudes are what matter. Chosen to reflect typical TIP
# practice: corroborating sources and AV detections dominate.
WEIGHTS: dict[str, float] = {
    "source_reputation": 0.22,
    "detection_ratio": 0.20,
    "blacklist_presence": 0.14,
    "confidence": 0.12,
    "recency": 0.10,
    "frequency": 0.08,
    "geo_risk": 0.06,
    "port_risk": 0.05,
    "historical_activity": 0.03,
}

_CONFIDENCE_SCORE: dict[Confidence, float] = {
    Confidence.unknown: 0.2,
    Confidence.low: 0.4,
    Confidence.medium: 0.6,
    Confidence.high: 0.8,
    Confidence.confirmed: 1.0,
}

# Ports commonly abused by malware C2 / exposed risky services.
RISKY_PORTS: frozenset[int] = frozenset(
    {21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 4444, 5900, 6379, 8080, 9001, 9050}
)

# ISO country codes frequently associated with bulletproof hosting / high abuse.
# This is a coarse heuristic knob, not a judgement about any country.
HIGH_RISK_GEOS: frozenset[str] = frozenset({"RU", "CN", "KP", "IR", "BY"})


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def detection_ratio(detected: int, total: int) -> float:
    """AV detection ratio in ``[0, 1]`` (VirusTotal-style)."""
    if total <= 0:
        return 0.0
    return _clamp01(detected / total)


def recency_score(age_days: float, half_life_days: float = 30.0) -> float:
    """Fresh indicators score higher; exponential decay by ``half_life_days``."""
    if age_days < 0:
        age_days = 0.0
    return _clamp01(math.pow(0.5, age_days / half_life_days))


def frequency_score(sightings: int, saturate_at: int = 20) -> float:
    """More sightings → higher, saturating (log-shaped) at ``saturate_at``."""
    if sightings <= 0:
        return 0.0
    return _clamp01(math.log1p(sightings) / math.log1p(saturate_at))


def source_reputation_score(reputable_sources: int, saturate_at: int = 4) -> float:
    """Corroboration across independent reputable sources."""
    if reputable_sources <= 0:
        return 0.0
    return _clamp01(reputable_sources / saturate_at)


def geo_risk_score(country_code: str | None) -> float:
    if not country_code:
        return 0.0
    return 1.0 if country_code.upper() in HIGH_RISK_GEOS else 0.0


def port_risk_score(open_ports: list[int] | None) -> float:
    if not open_ports:
        return 0.0
    risky = sum(1 for p in open_ports if p in RISKY_PORTS)
    return _clamp01(risky / 3)  # 3+ risky ports saturates


@dataclass(frozen=True, slots=True)
class ScoreSignals:
    """Normalised inputs (each in ``[0, 1]`` unless derived by a helper)."""

    source_reputation: float = 0.0
    detection_ratio: float = 0.0
    blacklist_presence: float = 0.0
    confidence: float = 0.0
    recency: float = 0.0
    frequency: float = 0.0
    geo_risk: float = 0.0
    port_risk: float = 0.0
    historical_activity: float = 0.0

    @classmethod
    def from_confidence(cls, confidence: Confidence, **kwargs: float) -> ScoreSignals:
        return cls(confidence=_CONFIDENCE_SCORE.get(confidence, 0.2), **kwargs)


@dataclass(frozen=True, slots=True)
class ScoreResult:
    score: int  # 0..100
    level: ThreatLevel
    contributions: dict[str, float] = field(default_factory=dict)


def level_for_score(score: float) -> ThreatLevel:
    if score >= 85:
        return ThreatLevel.critical
    if score >= 65:
        return ThreatLevel.high
    if score >= 40:
        return ThreatLevel.medium
    if score >= 15:
        return ThreatLevel.low
    return ThreatLevel.clean


def compute_threat_score(signals: ScoreSignals) -> ScoreResult:
    """Return the weighted 0–100 score, its level, and per-signal contributions."""
    values = {
        "source_reputation": _clamp01(signals.source_reputation),
        "detection_ratio": _clamp01(signals.detection_ratio),
        "blacklist_presence": _clamp01(signals.blacklist_presence),
        "confidence": _clamp01(signals.confidence),
        "recency": _clamp01(signals.recency),
        "frequency": _clamp01(signals.frequency),
        "geo_risk": _clamp01(signals.geo_risk),
        "port_risk": _clamp01(signals.port_risk),
        "historical_activity": _clamp01(signals.historical_activity),
    }
    total_weight = sum(WEIGHTS.values())
    contributions = {name: values[name] * WEIGHTS[name] for name in WEIGHTS}
    raw = sum(contributions.values()) / total_weight
    score = round(raw * 100)
    return ScoreResult(
        score=score,
        level=level_for_score(score),
        contributions={k: round(v / total_weight * 100, 2) for k, v in contributions.items()},
    )
