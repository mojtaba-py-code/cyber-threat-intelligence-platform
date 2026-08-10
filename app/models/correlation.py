"""Correlation graph edge.

Relationships between entities are stored as directed edges using STIX-style
references (``"<type>:<value>"``, e.g. ``"domain-name:evil.com"``). The graph is
materialised in-process (networkx) from these rows for traversal/pivoting.
"""

from __future__ import annotations

from sqlalchemy import Float, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDPrimaryKey


class CorrelationEdge(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "correlation_edges"
    __table_args__ = (
        UniqueConstraint("source_ref", "target_ref", "relationship", name="uq_edge_triple"),
    )

    source_ref: Mapped[str] = mapped_column(String(2100), index=True, nullable=False)
    target_ref: Mapped[str] = mapped_column(String(2100), index=True, nullable=False)
    # resolves-to | communicates-with | drops | exploits | attributed-to | uses | related-to
    relationship: Mapped[str] = mapped_column(String(32), default="related-to")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    source: Mapped[str] = mapped_column(String(64), default="manual")
