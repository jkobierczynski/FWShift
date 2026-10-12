# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Check Point firewall logs: what Log Exporter sends, and what the Management API's show-logs answers.

Formats read (detected per line, or for the whole file when it is JSON):

* Log Exporter **syslog** (its default): ``<134>1 2026-09-30T08:00:00Z host CheckPoint 1234 - [key:"value"; ...]``.
  Values escape ``\\``, ``"`` and ``]`` with a backslash; ``;`` is not escaped, so the line is read quote by quote.
  A key may end in a colon of its own (``key::"value"``).
* Log Exporter **splunk**: ``key=value|key=value|``; ``=`` in a value is ``\\=``, ``|`` became ``;``.
* Log Exporter **cef**: ``CEF:0|Check Point|<product>|Check Point|Log|<name>|Unknown|key=value key=value``; a value
  runs up to the next `` key=``. ``act``, ``rt`` (milliseconds), ``spt``, ``dpt``, ``cs2`` (rule name), ``suser``,
  ``c6a2``/``c6a3`` (IPv6 addresses) are read as the fields they stand for.
* The JSON answer of the Management API command **show-logs**, where each log has a ``match_table`` of rows.

The match table is the key: one row per layer the connection went through, outer first, each with the layer's
uuid, the number of the rule (``match_id``), the number of the rule applying an inline layer (``parent_rule``)
and the rule's uid. In the Log Exporter formats the rows are flattened column by column, and a row without a rule
uid (the implicit cleanup of a layer) or without a rule name leaves that column short: uids are put on rows only
where their number fits, else the line names its rules loosely.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import re
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from . import LayerMatch, Line, LogRecord

Fields = List[Tuple[str, str]]

_FIREWALL = ("vpn-1 & firewall-1", "firewall", "vpn-1 & firewall-1 ")
_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "sctp": 132, "icmp6": 58, "ipv6-icmp": 58, "gre": 47, "esp": 50, "ah": 51}
_PORTED = (6, 17, 132)
_UNSET = 4294967295
_SYSLOG = re.compile(r'\[(?=[A-Za-z_][\w\-]*:{1,2}")')  # the structured data, after whatever header a relay put in front
_HEADER_TIME = re.compile(r'^(?:<\d{1,3}>)?\d? ?(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)')
_CHECK_POINT = re.compile(r"(?i)check ?point|rule_uid|layer_uuid|Fields@1\.3\.6\.1\.4\.1\.2620")
_SPLUNK_START = re.compile(r'(?:^|\s)(?=[A-Za-z_][\w:\-]*=[^|]*\|)')
_CEF_KEY = re.compile(r'(?:^|(?<=\s))([A-Za-z0-9_.\-]+)=')
_CN = re.compile(r'(?i)(?:^|,)\s*cn=([^,]+)')
_CEF_NAMES = {"act": "action", "spt": "s_port", "dpt": "service", "cs2": "rule_name", "suser": "user", "c6a2": "ipv6_src",
              "c6a3": "ipv6_dst"}  # fmt: skip
_MAX_LINE = 1_000_000
_GAP = re.compile(r"[ ;\t]*")
_KEY = re.compile(r'([A-Za-z_][\w\-]*)::?"')
_VALUE = re.compile(r'((?:[^"\\]|\\.)*)"', re.S)
_ESCAPED = re.compile(r"\\(.)", re.S)


class _Bad(Exception):
    pass


def read(data: bytes, name: str = "") -> Iterator[Line]:
    """Every line of a log file, read."""
    text = data.decode("utf-8", errors="replace")
    head = text.lstrip("\ufeff \t\r\n")
    if head.startswith("{") or (head.startswith("[") and head[1:].lstrip()[:1] in ("{", "]")):
        documents = _documents(head)
        if documents is not None:
            for document in documents:
                yield from _show_logs(document)
            return
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line:
            continue
        yield read_line(line)


def _documents(text: str) -> Optional[List[Any]]:
    """The JSON documents of a file: one, or several one after the other (pages of show-logs); None if it is not JSON."""
    decoder = json.JSONDecoder()
    out: List[Any] = []
    position = 0
    try:
        while position < len(text):
            document, position = decoder.raw_decode(text, position)
            out.append(document)
            while position < len(text) and text[position] in " \t\r\n,":
                position += 1
    except (ValueError, RecursionError):
        return None if not out else out + [_UNREADABLE]
    return out


_UNREADABLE = object()


def read_line(line: str) -> Line:
    """One line of Log Exporter output, in whichever of its formats."""
    if len(line) > _MAX_LINE:
        return Line(reason="a line longer than a log line can be", doubt=True)
    try:
        cef = line.find("CEF:")
        if cef >= 0:
            fields, moment = _cef(line[cef:])
        else:
            match = _SYSLOG.search(line)
            if match:
                header = _HEADER_TIME.match(line)
                fields, moment = _syslog(line, match.end()), _iso(header.group(1) if header else "")
            elif "=" in line and "|" in line and _SPLUNK_START.search(line):
                fields, moment = _splunk(line), None
            elif _CHECK_POINT.search(line):
                # A log of Check Point in a format this version does not read (the gateway's own syslog, Log Exporter's
                # json, leef or generic): it may have been a connection of any rule.
                return Line(reason="a Check Point log in a format this version does not read", doubt=True)
            else:
                return Line(reason="not a line of Check Point's Log Exporter")
    except _Bad as error:
        return Line(reason=f"a Log Exporter line that cannot be read ({error})", doubt=True)
    return record(fields, moment)


# -- the formats -----------------------------------------------------------------------------------


def _syslog(line: str, start: int) -> Fields:
    """``key:"value"; key:"value"]``, from just after the bracket."""
    out: Fields = []
    i, end = start, len(line)
    while True:
        gap = _GAP.match(line, i)
        i = gap.end() if gap else i
        if i >= end:
            raise _Bad("the closing bracket is missing")
        if line[i] == "]":
            return out
        key = _KEY.match(line, i)  # (a name may end in a colon of its own: key::"value")
        if key is None:
            raise _Bad('a field that is not name:"value"')
        value = _VALUE.match(line, key.end())
        if value is None:
            raise _Bad("a value that does not end")
        text = value.group(1)
        out.append((key.group(1), _ESCAPED.sub(r"\1", text) if "\\" in text else text))
        i = value.end()


def _splunk(line: str) -> Fields:
    match = _SPLUNK_START.search(line)
    body = line[match.end() if match else 0 :]
    out: Fields = []
    for token in body.split("|"):
        if not token.strip():
            continue
        position = 0
        while True:
            position = token.find("=", position)
            if position <= 0:
                raise _Bad("a part without a value")
            if token[position - 1] != "\\":
                break
            position += 1
        key = token[:position].strip()
        if not re.fullmatch(r"[A-Za-z_][\w:\-]*", key):
            raise _Bad("a field name that is not one")
        out.append((key.rstrip(":"), token[position + 1 :].replace("\\=", "=")))
    if not out:
        raise _Bad("no fields")
    return out


def _cef(line: str) -> Tuple[Fields, Optional[int]]:
    parts: List[str] = []
    current: List[str] = []
    i = len("CEF:")
    while i < len(line) and len(parts) < 7:
        char = line[i]
        if char == "\\" and i + 1 < len(line):
            current.append(line[i + 1])
            i += 2
            continue
        if char == "|":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    if len(parts) < 7:
        raise _Bad("a CEF header without its seven parts")
    extension = line[i:]
    out: Fields = [("product", parts[2].strip())]
    keys = list(_CEF_KEY.finditer(extension))
    for index, key in enumerate(keys):
        stop = keys[index + 1].start() if index + 1 < len(keys) else len(extension)
        value = extension[key.end() : stop].rstrip().replace("\\=", "=").replace("\\\\", "\\")
        out.append((_CEF_NAMES.get(key.group(1), key.group(1)), value))
    moment = None
    for name, value in out:
        if name == "rt" and value.isdigit():
            moment = _epoch(value)
            break
    return out, moment


def _show_logs(document: Any) -> Iterator[Line]:
    """The answer of show-logs: {"logs": [...]}, several of them in an array, or the array of logs itself."""
    if document is _UNREADABLE:
        yield Line(reason="JSON that does not end where it should", doubt=True)
        return
    pages = document if isinstance(document, list) else [document]
    for page in pages:
        logs = page.get("logs") if isinstance(page, dict) and "logs" in page else [page] if isinstance(page, dict) else None
        if not isinstance(logs, list):
            yield Line(reason="JSON that is not an answer of show-logs", doubt=True)
            continue
        for log in logs:
            if not isinstance(log, dict):
                yield Line(reason="an entry of show-logs that is not an object", doubt=True)
                continue
            fields: Fields = []
            table = log.get("match_table")
            rows = [row for row in table if isinstance(row, dict)] if isinstance(table, list) else []
            for key, value in log.items():
                if rows and key in _ROW_FIELDS:
                    continue  # (the rows say it, each for its own layer)
                if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    fields.append((str(key), _text(value)))
            for column in ("layer_uuid", "layer_name", "match_id", "parent_rule", "rule_action"):
                fields += [(column, _text(row.get(column))) for row in rows]
            if rows and all(row.get("rule_uid") for row in rows if not _implicit(row.get("match_id"))):
                fields += [("rule_uid", _text(row.get("rule_uid"))) for row in rows if row.get("rule_uid")]
            moment = _iso(_text(log.get("time"))) if isinstance(log.get("time"), str) else None
            if "orig" in log and not any(key in log for key in ("originsicname", "origin_sic_name")):
                fields.append(("originsicname", f"CN={_text(log.get('orig'))}"))
            yield record(fields, moment)


_ROW_FIELDS = ("layer_uuid", "layer_name", "match_id", "parent_rule", "rule_action", "rule_uid", "rule_name", "rule")


def _implicit(match_id: Any) -> bool:
    number = _whole(_text(match_id))
    return number is not None and number & 0xFFFFFF == 0xFFFFFF


def _text(value: Any) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return "" if value is None else str(value)


# -- from fields to a connection ---------------------------------------------------------------------


def _iso(text: str) -> Optional[int]:
    """A time as Log Exporter writes it in its header: UTC, with Z or without a zone, or with an offset."""
    text = text.strip()
    if not text:
        return None
    try:
        moment = datetime.datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T", 1))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)  # Log Exporter always sends UTC
    return int(moment.timestamp())


def _epoch(text: str) -> Optional[int]:
    """Seconds since 1970, or milliseconds (more than ten digits)."""
    if not (text.isascii() and text.isdigit() and len(text) <= 16):
        return None
    value = int(text)
    return value // 1000 if len(text) > 10 else value


def _whole(text: str) -> Optional[int]:
    text = text.strip()
    return int(text) if text.isascii() and text.isdigit() and len(text) <= 10 else None


def _address(text: str) -> str:
    """An address in its plain form; empty when there is none (0.0.0.0 is none) or it cannot be read."""
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return ""
    return "" if address.is_unspecified else str(address)


def _printable(text: str) -> str:
    return re.sub(r"[^\w &.\-]", "", text)[:40] or "unnamed"


def _uid(text: str) -> str:
    return text.strip().strip("{}").lower()


def record(fields: Fields, header_time: Optional[int] = None) -> Line:
    """A connection from the fields of one log, or why it is not one."""
    first: Dict[str, str] = {}
    every: Dict[str, List[str]] = {}
    for key, value in fields:
        first.setdefault(key, value)
        every.setdefault(key, []).append(value)
    moment = _epoch(first.get("time", "")) if first.get("time") else None
    moment = moment if moment is not None else header_time
    sic = first.get("originsicname") or first.get("origin_sic_name") or ""
    cn = _CN.search(sic.replace("\\=", "="))
    gateway = (cn.group(1).strip() if cn else "") or first.get("origin", "").strip()
    if moment is None:
        return Line(reason="a log line without a time", doubt=True, gateway=gateway)
    if not gateway:
        return Line(reason="a log line without its gateway (origin)", doubt=True, time=moment)

    def skip(reason: str, doubt: bool = False) -> Line:
        return Line(reason=reason, doubt=doubt, time=moment, gateway=gateway)

    product = first.get("product", "").strip()
    if product.lower() == "log update":
        return skip("an update of a connection logged before (Log Update)")
    names = [key for key in ("layer_uuid", "rule_uid") if key in every]
    if not names:
        if product and product.lower() not in _FIREWALL:
            return skip(f"a log of another blade ({_printable(product)})")
        if first.get("drop_reason", "").strip().lower() == "matched optimized drop":
            return skip("several dropped packets in one log (optimized drop), without a rule")
        return skip("a firewall log that names no rule (an update, a packet out of state, a NAT event)")
    # From here on the log names rules: whatever blade wrote it, it is a connection of them. What it does not tell
    # (an address, the protocol, a port) is left open, and then counts for whatever it may have been.
    action = first.get("action", "").strip()
    proto_text = first.get("proto", "").strip().lower()
    protocol = _PROTOCOLS.get(proto_text) if not proto_text.isdigit() else _whole(proto_text)
    if protocol is None or protocol in (0, _UNSET) or protocol > 255:
        protocol = -1
    src, dst = first.get("src") or first.get("ipv6_src") or "", first.get("dst") or first.get("ipv6_dst") or ""
    src, dst = _address(src), _address(dst)
    port: Optional[int] = None
    if protocol in _PORTED:
        port = _whole(first.get("service") or first.get("svc") or "")
        if port is not None and port > 65535:
            port = None
    elif protocol in (1, 58):
        port = _whole(first.get("icmp_type", "") or first.get("ICMP Type", ""))
    count = 1
    for key in ("connection_count", "aggregated_log_count"):
        number = _whole(first.get(key, ""))
        if number:
            count = number
            break
    layers, loose = _layers(every)
    if layers is None:
        return skip("a log whose rule fields do not line up", doubt=True)
    users = [value.strip() for key in ("src_user_name", "user") for value in every.get(key, []) if value.strip()]
    return Line(LogRecord(moment, gateway, src, dst, protocol, port, action, layers, loose, list(dict.fromkeys(users)), count,
                          first.get("origin", "").strip()), time=moment, gateway=gateway)  # fmt: skip


def _layers(every: Dict[str, List[str]]) -> Tuple[Optional[List[LayerMatch]], List[str]]:
    """The rows of the match table, and the rule uids that could not be put on a row."""
    uuids = every.get("layer_uuid", [])
    uids = [_uid(value) for value in every.get("rule_uid", []) if _uid(value)]
    if not uuids:
        # A log from before layers: one rule, by uid.
        return ([LayerMatch("", _whole((every.get("rule") or [""])[0]), 0, uids[0])] if len(uids) == 1 else None), []
    count = len(uuids)
    columns: Dict[str, Sequence[str]] = {key: every.get(key, []) for key in ("match_id", "parent_rule")}
    if any(len(values) != count for values in columns.values()):
        return None, []
    names = every.get("layer_name", [])
    rows: List[LayerMatch] = []
    for index in range(count):
        match_id, parent = _whole(columns["match_id"][index]), _whole(columns["parent_rule"][index])
        # The implicit cleanup of a layer has the rule number with all 24 low bits set (0x..FFFFFF) and no uid.
        implicit = match_id is not None and match_id & 0xFFFFFF == 0xFFFFFF
        rows.append(LayerMatch(_uid(uuids[index]), match_id, parent, "", implicit, names[index] if len(names) == count else ""))
    explicit = [row for row in rows if not row.implicit]
    if len(uids) == count:
        for row, uid in zip(rows, uids):
            row.rule_uid = uid
        return rows, []
    if len(uids) == len(explicit):
        for row, uid in zip(explicit, uids):
            row.rule_uid = uid
        return rows, []
    return rows, uids


__all__ = ["read", "read_line", "record"]
