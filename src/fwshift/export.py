# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The results of FWShift as SARIF, CSV and HTML (0.36.0).

Every result already has a JSON form (``to_dict``): the report of a conversion (with its audit), an audit, the zone
matrix, the check against a zone and conduit model, a comparison. This module renders that JSON:

* **SARIF 2.1.0**, for code-scanning tools and pipelines (GitHub code scanning, GitLab, Azure DevOps): one result per
  finding, its rule the finding's code, its level from its weight, its place the rule or object it is about (with the
  line of the configuration where its name first stands, where that can be told), a fingerprint made of what the
  finding is about and not of its wording (so that it stays the same while the finding does), accepted findings of the
  audit as suppressed, and what was not checked as properties of the run. The matrix holds no findings, and is not
  written as SARIF.
* **CSV**, for a spreadsheet or a ticketing system: one row per finding, cell or difference, with a header also when
  there is none. A cell that a spreadsheet would take for a formula (=, +, -, @ first, also after spaces or as their
  full-width forms) is written with a ' before it.
* **HTML**, one page with nothing to fetch, for a report someone reads and signs: what was read (each file and its
  SHA-256), the counts, the findings, what was accepted, what was not checked, and a place for a name, a date and a
  signature.

Nothing here reads a configuration: the input is the JSON of a result, and ``Source`` (the files it came from).
"""

from __future__ import annotations

import csv
import hashlib
import ntpath
import os
import posixpath
import html
import io
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote

from . import __version__
from .errors import FwshiftError

FORMATS = ("text", "json", "sarif", "csv", "html")
INFORMATION_URI = "https://github.com/jkobierczynski/FWShift"
MANUAL_URI = INFORMATION_URI + "/blob/HEAD/docs/MANUAL.md"
SARIF_RESULT_LIMIT = 25_000  # (GitHub code scanning refuses a run with more results)
_TITLES = {"report": "Conversion report", "audit": "Audit", "matrix": "Zone matrix", "conduits": "Zone and conduit check",
           "compare": "Comparison"}  # fmt: skip
# Where each kind of finding is described in the manual (for helpUri).
_SECTIONS = {"report": "#7-finding-reference", "audit": "#13-auditing-a-policy", "conduits": "#16-the-zone-and-conduit-model",
             "compare": "#17-the-equivalence-check"}  # fmt: skip
# The columns of CSV and HTML, per kind: written as a header also when there are no rows.
_COLUMNS = {
    "audit": ("phase", "level", "check", "kind", "name", "message", "action", "related", "reason", "proposal", "source_ids"),
    "report": ("section", "severity", "code", "kind", "name", "status", "message", "phase", "level", "check", "action", "related",
               "reason", "proposal", "source_ids"),
    "conduits": ("level", "check", "from", "to", "rule", "services", "possible", "message"),
    "compare": ("weight", "from", "to", "inside", "second_zones", "for", "connections", "first", "second"),
    "matrix": ("from", "to", "allowed", "any_service", "approximate", "rules"),
}  # fmt: skip
# Ids of the source that are where a rule stands, not what it is: they change when a line is added above it.
_PLACES = ("azure.priority", "gcp.priority", "ios.sequence", "meraki.rule", "routeros.rule", "stormshield.rule")
_QUOTED = re.compile(r'"((?:[^"\\\n]|\\.)*)"|\'([^\'\n]*)\'|>([^<\n]+)<')
_WORD = re.compile(r"[^\s\"'<>=,;\[\]{}()]+")


@dataclass
class Source:
    """A configuration (or model) a result was read from: its path as given, its contents."""

    path: str = ""
    data: bytes = b""
    _lines: Optional[Dict[str, int]] = field(default=None, repr=False, compare=False)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.data).hexdigest() if self.data else ""

    @property
    def standard_input(self) -> bool:
        return self.path in ("", "-")

    def uri(self) -> str:
        """The path as a URI reference: relative ones percent-encoded, absolute ones (also of Windows) as file: URIs."""
        windows = PureWindowsPath(self.path)
        if windows.drive or self.path.startswith("\\\\"):
            if windows.is_absolute():
                return PureWindowsPath(ntpath.normpath(self.path)).as_uri()
            return quote(self.path.replace("\\", "/"), safe="/")
        posix = posixpath.normpath(self.path.replace("\\", "/"))
        return PurePosixPath(posix).as_uri() if posix.startswith("/") else quote(posix, safe="/")

    def category(self) -> str:
        """The path as a category of code scanning: relative to the working directory where it lies under it."""
        if self.standard_input:
            return "standard-input"
        path = self.path.replace("\\", "/")
        if posixpath.isabs(path) or PureWindowsPath(self.path).drive:
            try:
                relative = os.path.relpath(self.path)
            except ValueError:
                relative = ""
            path = relative.replace("\\", "/") if relative and not relative.startswith("..") else posixpath.basename(path)
        return quote(posixpath.normpath(path), safe="/._-") or "input"

    def line_at(self, ids: Dict[str, str]) -> Optional[int]:
        """The line a source id names (the parsers of IOS, Huawei and Stormshield keep the line of a rule)."""
        for key, value in ids.items():
            if key.endswith(".line") and str(value).isdigit() and int(value) >= 1:
                return int(value)
        return None

    def line_of(self, *names: str) -> Optional[int]:
        """The first line one of the names stands on (quoted, between tags, or as a word); None when it cannot be told.
        The file is read once for all names."""
        if self._lines is None:
            self._lines = {}
            text = self.data.decode("utf-8", errors="replace")
            number = 1
            for line in text.split("\n"):
                for match in _QUOTED.finditer(line):
                    token = next(group for group in match.groups() if group is not None)
                    for variant in (token, html.unescape(token), _unescape_json(token)):
                        self._lines.setdefault(variant.strip(), number)
                for match in _WORD.finditer(line):
                    self._lines.setdefault(match.group(0), number)
                number += 1
        for name in names:
            if name and name.strip() in self._lines:
                return self._lines[name.strip()]
        return None


def _unescape_json(token: str) -> str:
    if "\\" not in token:
        return token
    try:
        return str(json.loads('"' + token + '"'))
    except ValueError:
        return token


def render(kind: str, data: Dict[str, Any], fmt: str, sources: Sequence[Source] = (), warnings: Optional[List[str]] = None) -> str:
    """The result ``data`` (the JSON of a ``kind``: report, audit, matrix, conduits, compare) as ``fmt``; what a reader
    of the output should know (a SARIF run GitHub refuses) is added to ``warnings``."""
    if fmt == "json":
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if kind not in _COLUMNS:
        raise FwshiftError(f"unknown kind of result '{kind}'")
    rows = _ROWS[kind](data)
    if fmt == "sarif":
        if kind == "matrix":
            raise FwshiftError("the zone matrix holds no findings to write as SARIF: write it as csv, html or json")
        return _sarif(kind, data, rows, sources, warnings if warnings is not None else [])
    if fmt == "csv":
        columns = _COLUMNS[kind]
        if kind == "report" and not isinstance(data.get("audit"), dict):
            columns = columns[: columns.index("phase")]  # (the columns of the audit, where there is one)
        return _csv(columns, rows)
    if fmt == "html":
        return _html(kind, data, rows, sources)
    raise FwshiftError(f"unknown format '{fmt}'; expected one of {', '.join(FORMATS)}")


# -- rows: the findings of each kind, flat --------------------------------------------------------------------------


@dataclass
class Row:
    """One finding (or cell, or difference), as every format writes it."""

    code: str  # the rule of SARIF: a finding's code
    level: str  # error, warning, note (SARIF's levels)
    message: str
    subject: str = ""  # what it is about: a rule, an object, a pair of zones
    subject_kind: str = ""
    fields: Optional[Dict[str, str]] = None  # the columns of CSV and HTML
    suppressed: str = ""  # why it was accepted (audit), or ''
    identity: Tuple[str, ...] = ()  # what else tells it apart, for the fingerprint (source ids, the pair of zones, ...)
    source: int = 0  # the file it is about (conduits: 1 is the model; compare: 1 is the second)
    names: Tuple[str, ...] = ()  # what to look for in the file, for its line (an id first, then the name)
    run: str = ""  # the run of SARIF it belongs to ('' : the kind's own; 'audit': the audit of a conversion)
    ids: Dict[str, str] = field(default_factory=dict)  # the ids of the source (a line among them, for some)


def _distinctive(value: str) -> bool:
    """An id worth looking for in a file: a uid, a path; not a number, which stands anywhere."""
    return len(value) >= 8 and not value.isdigit()


def _join(values: Any) -> str:
    if isinstance(values, (list, tuple)):
        return ", ".join(_join(v) for v in values)
    if isinstance(values, dict):
        return "; ".join(f"{k}={_join(v)}" for k, v in values.items())
    return "" if values is None else str(values)


_AUDIT_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
_REPORT_LEVEL = {"needs-review": "error", "approximated": "warning", "info": "note"}
_PHASES = (("findings", "in the source"), ("new", "after conversion: new"), ("revived", "after conversion: revived"),
           ("gone", "after conversion: gone"))  # fmt: skip


def _audit_rows(data: Dict[str, Any], section: str = "") -> List[Row]:
    out: List[Row] = []
    after: Dict[str, Any] = data["after_conversion"] if isinstance(data.get("after_conversion"), dict) else {}
    for key, phase in _PHASES:
        for finding in (data if key == "findings" else after).get(key, []) or []:
            accepted = finding.get("action") == "accept"
            ids = finding.get("source_ids") or {}
            level = "note" if key == "gone" else _AUDIT_LEVEL.get(finding.get("level", ""), "note")
            fields = {"phase": phase, "level": finding.get("level", ""), "check": finding.get("check", ""), "kind": finding.get("kind", ""),
                      "name": finding.get("name", ""), "message": finding.get("message", ""), "action": finding.get("action", ""),
                      "related": _join(finding.get("related", "")), "reason": finding.get("reason", ""), "proposal": _join(finding.get("proposal", "")),
                      "source_ids": _join(ids)}  # fmt: skip
            if section:
                fields["section"] = section
            out.append(Row(finding.get("check", ""), level, finding.get("message", "") + (f" ({phase})" if key != "findings" else ""),
                           finding.get("name", ""), finding.get("kind", ""), fields,
                           (finding.get("reason", "") or "accepted") if accepted else "",
                           (phase, *(f"{k}={v}" for k, v in sorted(ids.items()) if k not in _PLACES and not k.endswith(".line"))), 0,
                           (*[str(v) for v in ids.values() if _distinctive(str(v))], finding.get("name", "")), "audit" if section else "",
                           {k: str(v) for k, v in ids.items()}))  # fmt: skip
    return out


def _report_rows(data: Dict[str, Any]) -> List[Row]:
    out: List[Row] = []
    for note in data.get("notes", []):
        out.append(Row(note.get("code", ""), _REPORT_LEVEL.get(note.get("severity", ""), "note"), note.get("message", ""), "", "policy",
                       {"section": "conversion", "severity": note.get("severity", ""), "code": note.get("code", ""), "kind": "policy",
                        "name": "", "status": "", "message": note.get("message", "")}))  # fmt: skip
    for item in data.get("items", []):
        for finding in item.get("findings", []):
            out.append(Row(finding.get("code", ""), _REPORT_LEVEL.get(finding.get("severity", ""), "note"), finding.get("message", ""),
                           item.get("name", ""), item.get("kind", ""),
                           {"section": "conversion", "severity": finding.get("severity", ""), "code": finding.get("code", ""),
                            "kind": item.get("kind", ""), "name": item.get("name", ""),
                            "status": item.get("status", "") + (", disabled" if item.get("disabled") else ""),
                            "message": finding.get("message", "")}, names=(item.get("name", ""),)))  # fmt: skip
    if isinstance(data.get("audit"), dict):
        out += _audit_rows(data["audit"], section="audit")
    return out


def _conduit_rows(data: Dict[str, Any]) -> List[Row]:
    out: List[Row] = []
    for finding in data.get("findings", []):
        pair = f"{finding.get('from', '')} -> {finding.get('to', '')}"
        rule = finding.get("rule", "")
        conduit = finding.get("check") == "CONDUIT_CLOSED"
        kind = "conduit" if conduit else "default" if rule.startswith("(") else "rule" if rule else "pair of zones"
        out.append(Row(finding.get("check", ""), _AUDIT_LEVEL.get(finding.get("level", ""), "note"), finding.get("message", ""),
                       rule or pair, kind,
                       {"level": finding.get("level", ""), "check": finding.get("check", ""), "from": finding.get("from", ""),
                        "to": finding.get("to", ""), "rule": rule, "services": _join(finding.get("services", [])),
                        "possible": "yes" if finding.get("possible") else "", "message": finding.get("message", "")},
                       identity=(finding.get("from", ""), finding.get("to", ""), _join(finding.get("services", []))),
                       source=1 if conduit else 0, names=(rule,)))  # fmt: skip
    return out


def _compare_rows(data: Dict[str, Any]) -> List[Row]:
    out: List[Row] = []
    for difference in data.get("differences", []):
        change, certain = difference.get("change", ""), bool(difference.get("certain"))
        level = ("error" if certain else "warning") if change == "opened" else ("warning" if certain else "note")
        inside = bool(difference.get("inside_the_zone"))
        pair = f"{difference.get('from', '')} -> {difference.get('to', '')}" + (" (inside the zone)" if inside else "")
        connections = difference.get("connections", [])
        described = "; ".join(f"{_join(c.get('sources', []))} -> {_join(c.get('destinations', []))}: {_join(c.get('services', []))}"
                              for c in connections)  # fmt: skip
        message = (f"{pair}: the second {'allows' if change == 'opened' else 'blocks'} what the first "
                   f"{'blocks' if change == 'opened' else 'allows'} ({'for certain' if certain else 'possibly'})"
                   + (f", {difference['for']}" if difference.get("for") else "") + f": {described}. First: {difference.get('first_policy', '')}; "
                   f"second: {difference.get('second_policy', '')}")  # fmt: skip
        rules = re.findall(r"'([^']+)'", difference.get("second_policy" if change == "opened" else "first_policy", ""))
        out.append(Row(f"COMPARE_{change.upper()}", level, message, pair, "pair of zones",
                       {"weight": f"{change}, {'certain' if certain else 'possible'}", "from": difference.get("from", ""),
                        "to": difference.get("to", ""), "inside": "yes" if inside else "",
                        "second_zones": _join(difference.get("second_policy_zones", "")), "for": difference.get("for", ""),
                        "connections": described, "first": difference.get("first_policy", ""), "second": difference.get("second_policy", "")},
                       identity=(change, str(certain), str(inside), difference.get("for", "")),
                       source=1 if change == "opened" else 0, names=tuple(rules)))  # fmt: skip
    return out


def _matrix_rows(data: Dict[str, Any]) -> List[Row]:
    out: List[Row] = []
    for cell in data.get("conduits", []):
        pair = f"{cell.get('from', '')} -> {cell.get('to', '')}"
        rules = [rule.get("rule", "") for rule in cell.get("rules", [])]
        allowed = _join(cell.get("allowed", []))
        out.append(Row("MATRIX_CELL", "note", f"{pair}: {allowed or '-'}", pair, "pair of zones",
                       {"from": cell.get("from", ""), "to": cell.get("to", ""), "allowed": allowed or "-",
                        "any_service": "yes" if cell.get("any_service") else "", "approximate": "yes" if cell.get("approximate") else "",
                        "rules": ", ".join(rules)}))  # fmt: skip
    return out


_ROWS: Dict[str, Callable[[Dict[str, Any]], List[Row]]] = {"audit": _audit_rows, "report": _report_rows, "conduits": _conduit_rows, "compare": _compare_rows, "matrix": _matrix_rows}


def _limits(kind: str, data: Dict[str, Any]) -> List[Tuple[str, str]]:
    """What a result says was not checked, or was read in part: (what, the list)."""
    out: List[Tuple[str, str]] = []
    source = data.get("audit") if kind == "report" and isinstance(data.get("audit"), dict) else data
    labels = {"not_followed": "Not followed", "read_approximately": "Read approximately", "accepted_nothing": "Accepted, and matched nothing",
              "hit_counters": "Hit counters", "usage_store": "Logs", "inside_not_checked": "Inside these zones: not checked",
              "rules_not_read": "Rules not read", "rules_in_no_conduit": "Rules in no conduit", "from_reading": "From the reading",
              "compared_by_name_only": "Compared by name only", "not_followed_in_detail": "Not followed in detail"}  # fmt: skip
    for key, label in labels.items():
        value = (source or {}).get(key) if key not in ("hit_counters", "usage_store") else data.get(key)
        if value:
            out.append((label, _join(value)))
    return out


# -- SARIF ----------------------------------------------------------------------------------------------------------


def _fingerprints(kind: str, rows: Sequence[Row]) -> List[str]:
    """What a finding is about, hashed: its code, its subject and what else tells it apart; not its wording, which holds
    counts and dates. Findings alike get an ordinal."""
    seen: Dict[str, int] = {}
    out: List[str] = []
    for row in rows:
        digest = hashlib.sha256("\0".join(("audit" if row.run else kind, row.code, row.subject_kind, row.subject, *row.identity))
                                .encode("utf-8")).hexdigest()  # (an audit is the same in a conversion and alone)
        seen[digest] = seen.get(digest, 0) + 1
        out.append(digest if seen[digest] == 1 else hashlib.sha256(f"{digest}:{seen[digest]}".encode()).hexdigest())
    return out


def _run(kind: str, rows: Sequence[Row], sources: Sequence[Source], properties: Dict[str, Any]) -> Dict[str, Any]:
    codes = list(dict.fromkeys(row.code for row in rows))
    index = {code: position for position, code in enumerate(codes)}
    help_uri = MANUAL_URI + _SECTIONS.get(kind, "")
    rules = [{"id": code, "name": "".join(part.title() for part in code.split("_")), "shortDescription": {"text": code.replace("_", " ").lower()},
              "helpUri": help_uri} for code in codes]  # fmt: skip
    artifacts: List[Dict[str, Any]] = []
    artifact_of: Dict[int, int] = {}  # source -> its artifact
    keys: Dict[Tuple[str, str], int] = {}
    for position, source in enumerate(sources):
        described: Dict[str, Any] = {"description": {"text": "standard input"}} if source.standard_input else {"location": {"uri": source.uri()}}
        key = ("-" if source.standard_input else source.uri(), source.digest)
        if key not in keys:
            keys[key] = len(artifacts)
            artifacts.append({**described, **({"hashes": {"sha-256": source.digest}} if source.digest else {})})
        artifact_of[position] = keys[key]
    results: List[Dict[str, Any]] = []
    for row, fingerprint in zip(rows, _fingerprints(kind, rows)):
        result: Dict[str, Any] = {"ruleId": row.code, "ruleIndex": index[row.code], "level": row.level, "message": {"text": row.message},
                                  "partialFingerprints": {"fwshiftFinding/v1": fingerprint, "primaryLocationLineHash": f"{fingerprint[:16]}:1"}}  # fmt: skip
        source_position = row.source if row.source < len(sources) else 0
        location: Dict[str, Any] = {}
        if sources and not sources[source_position].standard_input:
            physical: Dict[str, Any] = {"artifactLocation": {"uri": sources[source_position].uri(), "index": artifact_of[source_position]}}
            line = sources[source_position].line_at(row.ids) if source_position == 0 else None
            if line is None and row.names:
                line = sources[source_position].line_of(*row.names)
            if line is not None:
                physical["region"] = {"startLine": line}
            location["physicalLocation"] = physical
        if row.subject:
            location["logicalLocations"] = [{"name": row.subject, "kind": row.subject_kind or "object"}]
        if location:
            result["locations"] = [location]
        if row.suppressed:
            result["suppressions"] = [{"kind": "external", "justification": row.suppressed}]
        if row.fields:
            result["properties"] = {key: value for key, value in row.fields.items() if value and key != "message"}
        results.append(result)
    category = sources[0].category() if sources else "input"
    run: Dict[str, Any] = {
        "tool": {"driver": {"name": "FWShift", "version": __version__, "semanticVersion": __version__, "informationUri": INFORMATION_URI,
                            "rules": rules}},
        "automationDetails": {"id": f"fwshift/{kind}/{category}/"},
        "results": results,
        "properties": properties,
    }  # fmt: skip
    if artifacts:
        run["artifacts"] = artifacts
    return run


def _properties(kind: str, data: Dict[str, Any]) -> Dict[str, Any]:
    keep = {"report": ("source", "target", "summary"), "audit": ("source", "scope", "summary"), "conduits": ("source", "model", "counts"),
            "compare": ("first", "second", "equivalent", "counts")}[kind]  # fmt: skip
    out: Dict[str, Any] = {key: data[key] for key in keep if key in data}
    limits = {label: text for label, text in _limits(kind, data)}
    if limits:
        out["notChecked"] = limits
    if data.get("notes") and kind != "report":
        out["notes"] = [str(note) for note in data["notes"]]
    return out


def _sarif(kind: str, data: Dict[str, Any], rows: Sequence[Row], sources: Sequence[Source], warnings: List[str]) -> str:
    own = [row for row in rows if not row.run]
    runs = [_run(kind, own, sources, _properties(kind, data))]
    audited = [row for row in rows if row.run == "audit"]
    if kind == "report" and isinstance(data.get("audit"), dict):
        runs.append(_run("audit", audited, sources, _properties("audit", data["audit"])))
    for run in runs:
        if len(run["results"]) > SARIF_RESULT_LIMIT:
            warnings.append(f"the SARIF run '{run['automationDetails']['id']}' has {len(run['results'])} results; GitHub code scanning "
                            f"refuses a run of more than {SARIF_RESULT_LIMIT} (and shows at most 5,000)")  # fmt: skip
    document = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


# -- CSV ------------------------------------------------------------------------------------------------------------


def formula_safe(value: str) -> str:
    """A cell a spreadsheet does not take for a formula: one that starts with =, +, -, @ (also after spaces, or as the
    full-width forms), a tab or a carriage return gets a ' before it."""
    if value[:1] in ("\t", "\r"):
        return "'" + value
    first = unicodedata.normalize("NFKC", value.lstrip(" "))[:1]
    return "'" + value if first in ("=", "+", "-", "@") else value


def _csv(columns: Sequence[str], rows: Sequence[Row]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    used = list(columns)
    writer.writerow(used)
    for row in rows:
        fields = row.fields or {}
        writer.writerow([formula_safe(re.sub(r"\r\n|[\r\n]", " ", str(fields.get(column, "")))) for column in used])
    return buffer.getvalue()


# -- HTML -----------------------------------------------------------------------------------------------------------

_STYLE = """
:root { color-scheme: light; }
body { font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #1d2433; background: #fff; margin: 2rem auto;
       max-width: 72rem; padding: 0 1rem; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; } h2 { font-size: 1.15rem; margin: 2rem 0 .5rem; border-bottom: 1px solid #d5dae3; }
.meta { color: #5a6475; margin: 0 0 1rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: 13px; }
th, td { border: 1px solid #d5dae3; padding: .3rem .45rem; text-align: left; vertical-align: top; }
th { background: #f2f4f8; } td { overflow-wrap: break-word; } td.code { white-space: nowrap; font-family: ui-monospace, monospace; font-size: 12px; }
td.error { color: #9b1c1c; font-weight: 600; } td.warning { color: #8a5300; font-weight: 600; } td.note { color: #3d4b63; }
td.accepted { color: #3d4b63; font-style: italic; }
.counts td:first-child, .limits td:first-child { width: 16rem; } .sign td { height: 2.5rem; } .sign td:first-child { width: 10rem; font-weight: 600; }
@media print { body { margin: 0; max-width: none; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
"""


def _table(headers: Sequence[str], body: Iterable[Sequence[str]], levels: Sequence[str] = (), css: str = "") -> str:
    """A table; ``levels`` colours the first cell of each row (error, warning, note, accepted); a column of codes is
    not broken."""
    lines = [f'<table class="{css}">' if css else "<table>"]
    if any(headers):
        lines.append("<tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in headers) + "</tr>")
    codes = {position for position, header in enumerate(headers) if header in ("code", "check")}
    for row, cells in enumerate(body):
        out = []
        for position, cell in enumerate(cells):
            style = levels[row] if position == 0 and row < len(levels) else "code" if position in codes else ""
            out.append((f'<td class="{style}">' if style else "<td>") + html.escape(str(cell)) + "</td>")
        lines.append("<tr>" + "".join(out) + "</tr>")
    lines.append("</table>")
    return "\n".join(lines)


def _counts(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for key in ("summary", "counts", "rules"):
        value = data.get(key)
        if isinstance(value, dict):
            for name, count in value.items():
                out.append((str(name), ", ".join(f"{k} {v}" for k, v in count.items()) if isinstance(count, dict) else _join(count)))
    if "equivalent" in data:
        out.insert(0, ("equivalent", "yes" if data["equivalent"] else "no"))
    if "pairs_of_zones" in data:
        out.append(("pairs of zones compared", str(data["pairs_of_zones"])))
    audited = data.get("audit")
    if isinstance(audited, dict):
        summary = audited.get("summary", {})
        out.append(("audit", ", ".join(f"{k} {v}" for k, v in summary.items())))
        after = audited.get("after_conversion")
        if isinstance(after, dict):
            out.append(("audit after the conversion", ", ".join(f"{k} {v}" for k, v in after.get("summary", {}).items())))
    return out


def _rows_html(title: str, columns: Sequence[str], rows: Sequence[Row]) -> str:
    if not rows:
        return f"<h2>{html.escape(title)}</h2>\n<p>None.</p>"
    used = [column for column in columns if any((row.fields or {}).get(column) for row in rows)]
    body = [[(row.fields or {}).get(column, "") for column in used] for row in rows]
    return f"<h2>{html.escape(title)} ({len(rows)})</h2>\n" + _table(used, body, ["accepted" if row.suppressed else row.level for row in rows])


def _html(kind: str, data: Dict[str, Any], rows: Sequence[Row], sources: Sequence[Source]) -> str:
    title = _TITLES[kind]
    parts = ["<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">', f"<title>FWShift {html.escape(title)}</title>",
             f"<style>{_STYLE}</style>", "</head>", "<body>", f"<h1>FWShift: {html.escape(title)}</h1>"]  # fmt: skip
    meta = [f"FWShift {html.escape(__version__)}"]
    for key in ("source", "scope", "target", "first", "second", "model"):
        if data.get(key):
            meta.append(f"{html.escape(key)}: {html.escape(str(data[key]))}")
    parts.append(f'<p class="meta">{" · ".join(meta)}</p>')
    if sources:
        parts.append("<h2>What was read</h2>")
        parts.append(_table(["file", "SHA-256"], [("standard input" if s.standard_input else s.path, s.digest) for s in sources]))
    counts = _counts(data)
    if counts:
        parts.append("<h2>Counts</h2>")
        parts.append(_table(["", ""], counts, css="counts"))
    columns = _COLUMNS[kind]
    if kind == "report":
        conversion = [row for row in rows if not row.run]
        audited = [row for row in rows if row.run]
        parts.append(_rows_html("Conversion findings", columns, conversion))
        if isinstance(data.get("audit"), dict):
            parts.append(_rows_html("Audit findings", _COLUMNS["audit"], [row for row in audited if not row.suppressed]))
            accepted = [row for row in audited if row.suppressed]
            if accepted:
                parts.append(_rows_html("Accepted", _COLUMNS["audit"], accepted))
    else:
        label = {"audit": "Findings", "conduits": "Findings", "compare": "Differences", "matrix": "Cells"}[kind]
        parts.append(_rows_html(label, columns, [row for row in rows if not row.suppressed]))
        accepted = [row for row in rows if row.suppressed]
        if accepted:
            parts.append(_rows_html("Accepted", columns, accepted))
    if kind == "conduits" and data.get("conduits"):
        parts.append("<h2>Conduits of the model</h2>")
        parts.append(_table(["conduit", "from", "to", "both ways", "SL-T", "services", "allowed by the policy", "closed by the policy"],
                            [(c.get("name", ""), c.get("from", ""), c.get("to", ""), "yes" if c.get("both_ways") else "",
                              _join(c.get("sl_t", "")), _join(c.get("services", [])), _join(c.get("allowed_by_the_policy", [])),
                              _join(c.get("closed_by_the_policy", []))) for c in data["conduits"]]))  # fmt: skip
    limits = _limits(kind, data)
    if limits:
        parts.append("<h2>Not checked, or read in part</h2>")
        parts.append(_table(["", ""], limits, css="limits"))
    notes = data.get("notes", []) if kind != "report" else []
    if notes:
        parts.append("<h2>Notes</h2>\n<ul>" + "".join(f"<li>{html.escape(str(note))}</li>" for note in notes) + "</ul>")
    parts.append("<h2>Reviewed</h2>")
    parts.append(_table(["", ""], [("Name", ""), ("Role", ""), ("Date", ""), ("Signature", "")], css="sign"))
    parts += ["</body>", "</html>", ""]
    return "\n".join(parts)
