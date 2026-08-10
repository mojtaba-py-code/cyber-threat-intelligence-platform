"""Indicator of Compromise (IOC) model — the core intelligence record."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKey
from app.ioc.types import Confidence, IOCStatus, Severity, ThreatLevel

if TYPE_CHECKING:
    from app.models.enrichment import EnrichmentRecord


class IOC(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_ioc_type_value"),)

    # ``type`` is an IOCType value; ``value`` is the normalised canonical form.
    type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(2048), index=True, nullable=False)
    defanged_value: Mapped[str] = mapped_column(String(2100), nullable=False)

    source: Mapped[str] = mapped_column(String(64), index=True, default="manual")
    confidence: Mapped[str] = mapped_column(String(16), default=Confidence.unknown.value)
    severity: Mapped[str] = mapped_column(String(16), default=Severity.info.value)
    status: Mapped[str] = mapped_column(String(20), index=True, default=IOCStatus.active.value)

    threat_score: Mapped[int] = mapped_column(Integer, index=True, default=0)
    threat_level: Mapped[str] = mapped_column(
        String(16), index=True, default=ThreatLevel.clean.value
    )
    # Number of times this indicator has been seen/submitted (drives frequency).
    sightings: Mapped[int] = mapped_column(Integer, default=1)

    tags: Mapped[list] = mapped_column(JSON, default=list)
    references: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    enrichments: Mapped[list[EnrichmentRecord]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"IOC(type={self.type!r}, value={self.defanged_value!r}, score={self.threat_score})"
