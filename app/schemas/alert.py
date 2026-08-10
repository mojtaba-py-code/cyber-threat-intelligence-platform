"""Alert-rule and alert schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AlertMetric = Literal["new_ioc", "threat_score"]
AlertOperator = Literal["gte", "lte", "eq"]
AlertChannel = Literal["log", "webhook", "slack", "discord"]


class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120, pattern=r"^[\w .\-]{1,120}$")
    metric: AlertMetric
    operator: AlertOperator = "gte"
    threshold: int = Field(default=0, ge=0, le=100)
    channel: AlertChannel = "log"
    # For webhook/slack/discord channels; the URL is validated by the SSRF guard
    # at delivery time and is operator-supplied only.
    channel_config: dict = Field(default_factory=dict)


class AlertRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    metric: str
    operator: str
    threshold: int
    channel: str
    is_active: bool
    created_at: datetime


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str | None
    ioc_id: str | None
    title: str
    message: str | None
    severity: str
    delivered: bool
    created_at: datetime
