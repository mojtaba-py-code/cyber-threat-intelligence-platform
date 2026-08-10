"""Alert rule and generated alert models."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin, UUIDPrimaryKey


class AlertRule(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "alert_rules"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # metric: threat_score | new_ioc | severity | ioc_type
    metric: Mapped[str] = mapped_column(String(32), nullable=False)
    operator: Mapped[str] = mapped_column(String(4), default="gte")  # gte | lte | eq
    threshold: Mapped[int] = mapped_column(Integer, default=0)
    # delivery channel: webhook | slack | discord | telegram | email | log
    channel: Mapped[str] = mapped_column(String(16), default="log")
    channel_config: Mapped[dict] = mapped_column(JSON, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Alert(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "alerts"

    rule_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("alert_rules.id", ondelete="SET NULL"), nullable=True
    )
    ioc_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("iocs.id", ondelete="CASCADE"), index=True, nullable=True
    )
    severity: Mapped[str] = mapped_column(String(16), index=True, default="medium")
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
