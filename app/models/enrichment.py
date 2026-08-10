"""Per-provider enrichment result attached to an IOC."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import JSON, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.ioc import IOC


class EnrichmentRecord(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "enrichments"
    __table_args__ = (UniqueConstraint("ioc_id", "provider", name="uq_enrichment_ioc_provider"),)

    ioc_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("iocs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    provider: Mapped[str] = mapped_column(String(48), nullable=False)
    # Normalised enrichment payload (geo/asn/dns/reputation/detections/...).
    data: Mapped[dict] = mapped_column(JSON, default=dict)

    ioc: Mapped[IOC] = relationship(back_populates="enrichments")
