"""Threat-actor schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ActorType = Literal["apt", "ransomware", "hacktivist", "nation-state", "cybercrime", "unknown"]


class ThreatActorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[\w .\-/]{1,128}$")
    actor_type: ActorType = "unknown"
    country: str | None = Field(default=None, max_length=4, pattern=r"^[A-Za-z]{2,4}$")
    aliases: list[str] = Field(default_factory=list, max_length=50)
    motivations: list[str] = Field(default_factory=list, max_length=20)
    techniques: list[str] = Field(default_factory=list, max_length=200)
    known_malware: list[str] = Field(default_factory=list, max_length=200)
    targets: list[str] = Field(default_factory=list, max_length=100)
    description: str | None = Field(default=None, max_length=4000)


class ThreatActorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    actor_type: str
    country: str | None
    aliases: list[str]
    motivations: list[str]
    techniques: list[str]
    known_malware: list[str]
    targets: list[str]
    description: str | None
    created_at: datetime
