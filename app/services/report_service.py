"""Report generation and export (JSON / CSV / Markdown / STIX 2.1 / MISP).

Pure formatting over IOC records — PDF/Excel are intentionally out of scope
(documented), but these formats cover the analyst, executive and
machine-to-machine sharing paths without heavy dependencies.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence

from app.models.ioc import IOC
from app.sharing import to_misp_event, to_stix_bundle


def _row(ioc: IOC) -> dict:
    return {
        "type": ioc.type,
        "value": ioc.defanged_value,
        "threat_score": ioc.threat_score,
        "threat_level": ioc.threat_level,
        "severity": ioc.severity,
        "source": ioc.source,
        "tags": ",".join(ioc.tags or []),
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
    }


class ReportService:
    @staticmethod
    def to_json(iocs: Sequence[IOC]) -> str:
        return json.dumps([_row(i) for i in iocs], indent=2)

    @staticmethod
    def to_csv(iocs: Sequence[IOC]) -> str:
        columns = ["type", "value", "threat_score", "threat_level", "severity", "source", "tags"]
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(columns)
        for ioc in iocs:
            r = _row(ioc)
            writer.writerow([r[c] for c in columns])
        return buffer.getvalue()

    @staticmethod
    def to_markdown(iocs: Sequence[IOC], *, title: str = "Threat Intelligence Report") -> str:
        lines = [f"# {title}", "", f"Total indicators: **{len(iocs)}**", ""]
        lines.append("| Type | Indicator | Score | Level | Source |")
        lines.append("| --- | --- | --- | --- | --- |")
        for ioc in iocs:
            lines.append(
                f"| {ioc.type} | `{ioc.defanged_value}` | {ioc.threat_score} "
                f"| {ioc.threat_level} | {ioc.source} |"
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def to_stix(iocs: Sequence[IOC]) -> str:
        """Serialise as a STIX 2.1 bundle for TAXII/SIEM consumers."""
        return json.dumps(to_stix_bundle(iocs), indent=2)

    @staticmethod
    def to_misp(iocs: Sequence[IOC], *, info: str = "Threat Intel Platform export") -> str:
        """Serialise as a MISP event ready for ``POST /events``."""
        return json.dumps(to_misp_event(iocs, info=info), indent=2)

    @staticmethod
    def executive_summary(stats: dict) -> str:
        lines = ["# Executive Threat Summary", ""]
        lines.append(f"- Total indicators tracked: **{stats.get('total', 0)}**")
        by_level = stats.get("by_level", {})
        for level in ("critical", "high", "medium", "low", "clean"):
            if level in by_level:
                lines.append(f"- {level.capitalize()}: {by_level[level]}")
        return "\n".join(lines) + "\n"
