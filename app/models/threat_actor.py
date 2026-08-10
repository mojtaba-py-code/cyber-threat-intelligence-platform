"""Threat-actor / group profile."""

from __future__ import annotations

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDPrimaryKey


class ThreatActor(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "threat_actors"

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    # apt | ransomware | hacktivist | nation-state | cybercrime
    actor_type: Mapped[str] = mapped_column(String(32), default="unknown")
    country: Mapped[str | None] = mapped_column(String(4), nullable=True)

    aliases: Mapped[list] = mapped_column(JSON, default=list)
    motivations: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)  # MITRE technique ids
    known_malware: Mapped[list] = mapped_column(JSON, default=list)
    targets: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
