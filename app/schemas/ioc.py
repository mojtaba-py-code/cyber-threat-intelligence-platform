from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.ioc.extract import MAX_CONTENT_CHARS, MAX_INDICATORS
from app.ioc.types import Confidence, IOCType, Severity, ThreatLevel

#: A tag is a short label, not free text. Constraining the character set keeps
#: hostile input out of every downstream renderer at the point of entry: a tag
#: beginning "=" or "@" is a live formula once the CSV export is opened in a
#: spreadsheet, and "|" would break a Markdown report's table.
Tag = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[\w.:\-]{1,64}$")]
TagList = Annotated[list[Tag], Field(max_length=32)]
#: References are URLs an analyst can follow; bounded so a single submission
#: cannot carry an unlimited payload.
ReferenceList = Annotated[list[Annotated[str, Field(max_length=2048)]], Field(max_length=32)]


class IOCCreate(BaseModel):
    # Raw indicator; may be defanged (hxxp://evil[.]com) — the server refangs it.
    value: str = Field(min_length=1, max_length=2048)
    source: str = Field(default="manual", max_length=64, pattern=r"^[\w.\-]{1,64}$")
    confidence: Confidence = Confidence.medium
    severity: Severity = Severity.medium
    tags: TagList = Field(default_factory=list)
    references: ReferenceList = Field(default_factory=list)
    description: str | None = Field(default=None, max_length=2000)
    enrich: bool = True


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    type: IOCType
    value: str
    defanged_value: str
    source: str
    confidence: Confidence
    severity: Severity
    status: str
    threat_score: int
    threat_level: ThreatLevel
    tags: list[str]
    references: list[str]
    description: str | None
    first_seen: datetime | None
    last_seen: datetime | None


class EnrichmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: str
    data: dict


class IOCDetailOut(IOCOut):
    enrichments: list[EnrichmentOut] = Field(default_factory=list)


class LookupRequest(BaseModel):
    value: str = Field(min_length=1, max_length=2048)


class ScoreExplainOut(BaseModel):
    score: int
    level: ThreatLevel
    contributions: dict[str, float]


class BulkImportRequest(BaseModel):
    """Ingest a whole document: a pasted report, a CSV export or a STIX bundle."""

    content: str = Field(min_length=1, max_length=MAX_CONTENT_CHARS)
    format: Literal["auto", "text", "csv", "stix"] = "auto"
    source: str = Field(default="import", max_length=64, pattern=r"^[\w.\-]{1,64}$")
    confidence: Confidence = Confidence.low
    severity: Severity = Severity.medium
    tags: TagList = Field(default_factory=list)
    # Enrichment is off by default here: a report can carry hundreds of
    # indicators, and the caller can enrich the ones that matter afterwards.
    enrich: bool = False
    limit: int = Field(default=MAX_INDICATORS, ge=1, le=MAX_INDICATORS)


class BulkImportItem(BaseModel):
    value: str
    type: IOCType | None = None
    status: Literal["imported", "failed"]
    threat_score: int | None = None
    error: str | None = None


class BulkImportResult(BaseModel):
    extracted: int
    imported: int
    failed: int
    items: list[BulkImportItem]


class ExtractRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_CONTENT_CHARS)
    format: Literal["auto", "text", "csv", "stix"] = "auto"


class ExtractedIndicator(BaseModel):
    value: str
    defanged_value: str
    type: IOCType


class ExtractResult(BaseModel):
    count: int
    indicators: list[ExtractedIndicator]
