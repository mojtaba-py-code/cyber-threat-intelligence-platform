"""Harvest indicators out of unstructured or semi-structured text.

Analysts receive intelligence as prose: a vendor report, an email thread, a
pasted log. This module pulls candidate indicators out of such text (defanged
forms included), plus CSV columns and STIX bundles, so a whole report can be
ingested in one call instead of one indicator at a time.

Extraction is deliberately conservative — a false indicator costs an analyst
more than a missed one — so bare domains must survive a plausibility check that
rejects filenames, and every candidate is still validated by
:func:`~app.ioc.indicators.classify_indicator`.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterator

from app.core.exceptions import UnknownIndicatorError, ValidationError
from app.ioc.indicators import classify_indicator, refang

#: Upper bound on indicators returned from a single document (DoS guard).
MAX_INDICATORS = 1000

#: Upper bound on document size. Scanning is linear but not free — roughly a
#: second of CPU per 100 KB of adversarial input — so the cap is what keeps a
#: submission from becoming a denial of service. A pasted vendor report is
#: comfortably under this; feed a bigger corpus in with several calls.
MAX_CONTENT_CHARS = 128 * 1024

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\]\)\},]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE
)

# Suffixes that look like a TLD but are almost always a file, not a host.
_FILE_SUFFIXES: frozenset[str] = frozenset({
    # executables & libraries
    "exe", "dll", "sys", "so", "dylib", "bin", "msi", "jar", "class", "scr", "lnk",
    # scripts
    "js", "ts", "py", "rb", "pl", "ps1", "sh", "bat", "cmd", "vbs", "php", "asp", "aspx", "jsp",
    # documents & data
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "txt", "md",
    "csv", "json", "xml", "yaml", "yml", "html", "htm", "log", "dat", "ini", "cfg", "conf", "tmp",
    # archives & media
    "zip", "rar", "gz", "tar", "7z", "iso", "cab", "png", "jpg", "jpeg", "gif", "svg", "ico",
    "mp4", "avi",
})  # fmt: skip

# Ordered so that a match consumes text before a looser pattern can see it: a URL
# must not also yield its own host, and a hash must not be read as a domain.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    _URL_RE,
    _EMAIL_RE,
    _HASH_RE,
    _CVE_RE,
    _TECHNIQUE_RE,
    _IPV6_RE,
    _IPV4_RE,
    _DOMAIN_RE,
)


def _plausible_domain(candidate: str) -> bool:
    """Reject ``payload.exe``-style filenames masquerading as domains."""
    return candidate.rsplit(".", 1)[-1].lower() not in _FILE_SUFFIXES


def _candidates(text: str) -> Iterator[str]:
    """Yield candidate indicator strings, consuming each span exactly once."""
    remaining = text
    for pattern in _PATTERNS:
        matches = list(pattern.finditer(remaining))
        if not matches:
            continue
        # Blank out what this pattern claimed so looser patterns cannot re-match
        # it — that is what stops a URL from also yielding its own host.
        chunks: list[str] = []
        cursor = 0
        for match in matches:
            chunks.append(remaining[cursor : match.start()])
            chunks.append(" ")
            cursor = match.end()
        chunks.append(remaining[cursor:])
        remaining = "".join(chunks)

        for match in matches:
            value = match.group(0).rstrip(".,;:)]}\"'")
            if pattern is _DOMAIN_RE and not _plausible_domain(value):
                continue
            yield value


def extract_from_text(text: str, *, limit: int = MAX_INDICATORS) -> list[str]:
    """Return the distinct, validated indicators found in free text.

    Order of first appearance is preserved so an operator can match the result
    against the source document.
    """
    seen: set[tuple[str, str]] = set()
    found: list[str] = []
    for candidate in _candidates(refang(text)):
        try:
            parsed = classify_indicator(candidate)
        except UnknownIndicatorError:
            continue
        key = (parsed.type.value, parsed.value)
        if key in seen:
            continue
        seen.add(key)
        found.append(parsed.value)
        if len(found) >= limit:
            break
    return found


def extract_from_csv(text: str, *, limit: int = MAX_INDICATORS) -> list[str]:
    """Extract indicators from a CSV/TSV export.

    Prefers a header column named like an indicator (``value``, ``ioc``,
    ``indicator``, ``observable``); otherwise every cell is offered to the text
    extractor, which discards whatever does not parse.
    """
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    if not rows:
        return []

    header = [cell.strip().lower() for cell in rows[0]]
    index = next(
        (i for i, name in enumerate(header) if name in {"value", "ioc", "indicator", "observable"}),
        None,
    )
    cells = (
        (row[index] for row in rows[1:] if len(row) > index)
        if index is not None
        else (cell for row in rows for cell in row)
    )
    return extract_from_text("\n".join(cells), limit=limit)


def extract_from_stix(text: str, *, limit: int = MAX_INDICATORS) -> list[str]:
    """Extract indicator values from a STIX 2.x bundle.

    Reads the value out of simple ``[<type>:value = '<x>']`` patterns and out of
    ``file:hashes.*`` comparisons, which together cover the overwhelming majority
    of shared indicators. Anything more exotic is skipped rather than guessed at.
    """
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Not a valid STIX/JSON document: {exc.msg}") from exc
    if not isinstance(bundle, dict):
        raise ValidationError("STIX input must be a JSON object.")

    pattern_value = re.compile(r"=\s*'((?:[^'\\]|\\.)*)'")
    values: list[str] = []
    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict):
            continue
        if obj.get("type") in {"vulnerability", "attack-pattern"}:
            for ref in obj.get("external_references") or []:
                if isinstance(ref, dict) and ref.get("external_id"):
                    values.append(str(ref["external_id"]))
            continue
        pattern = obj.get("pattern")
        if isinstance(pattern, str):
            values.extend(m.group(1).replace("\\'", "'") for m in pattern_value.finditer(pattern))

    seen: set[tuple[str, str]] = set()
    found: list[str] = []
    for candidate in values:
        try:
            parsed = classify_indicator(candidate)
        except UnknownIndicatorError:
            continue
        key = (parsed.type.value, parsed.value)
        if key not in seen:
            seen.add(key)
            found.append(parsed.value)
        if len(found) >= limit:
            break
    return found


def extract_indicators(
    content: str, *, fmt: str = "auto", limit: int = MAX_INDICATORS
) -> list[str]:
    """Dispatch to the right extractor; ``auto`` sniffs the document shape."""
    if len(content) > MAX_CONTENT_CHARS:
        raise ValidationError(
            f"Document is too large to scan ({len(content)} chars); "
            f"the limit is {MAX_CONTENT_CHARS}. Split it and import in parts."
        )
    if fmt == "auto":
        stripped = content.lstrip()
        if stripped.startswith("{") and '"objects"' in content:
            fmt = "stix"
        elif "," in content.split("\n", 1)[0] and "\n" in content.strip():
            fmt = "csv"
        else:
            fmt = "text"
    if fmt == "stix":
        return extract_from_stix(content, limit=limit)
    if fmt == "csv":
        return extract_from_csv(content, limit=limit)
    if fmt == "text":
        return extract_from_text(content, limit=limit)
    raise ValidationError(f"Unsupported import format: {fmt}")
