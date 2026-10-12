# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""PAN-OS traffic logs: the comma-separated lines a firewall (or Panorama) sends to syslog, and the CSV export.

    <14>Oct 12 10:00:00 pa-edge 1,2026/10/12 10:00:00,012801000001,TRAFFIC,end,2562,2026/10/12 10:00:00,10.10.4.20,...

The fields are in a fixed order that later versions only add to (PAN-OS "Traffic Log Fields"): 1 receive time,
2 serial number, 3 type, 4 subtype, 6 generated time, 7 source, 8 destination (before NAT), 11 rule, 12 source user,
15 virtual system, 22 session ID, 23 repeat count, 25 destination port, 28 flags, 29 protocol, 30 action,
35 start time, 52 device name, 65 rule UUID (9.0 and later), 102 high resolution timestamp (10.0 and later). A
field with a comma is in double quotes; the link switches (69) are in braces.

A line names its rule: by UUID where it has one, and by name. What counts:

* ``end``, ``drop``, ``deny``: a connection of the rule the line names. The repeat count is the number of sessions
  the line stands for.
* ``start``: logged when a rule logs at session start. A start whose end is in the same file, naming the same rule,
  is the same connection and counted once. A start naming another rule than its end (the application changed and
  the rules were looked up again) is a connection of that rule too. A start without an end in the file is possible
  only: the rule may have been left for another once the application was known.
* A line with flag 0x2000 (a temporary match for an implicit application dependency) is possible only.

The gateway is the serial number, which is what Panorama's targets name. The times have no zone (the firewall's
local time): the high resolution timestamp has one, where the line has it; otherwise the offset is given
(``offset``, minutes), or the time is read as UTC and ``zoneless`` counts the lines that were.
"""

from __future__ import annotations

import csv
import datetime
import ipaddress
import re
from typing import Dict, Iterator, List, Optional, Tuple

from . import Line, LogRecord

_BODY = re.compile(r"(?:^|[\s>])(\d*),(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d),([^,]*),([A-Z][A-Z0-9-]*),")
_HEADER = re.compile(r"^\ufeff?\"?(?:Domain|FUTURE_USE)\"?,\"?Receive Time\"?,", re.IGNORECASE)
_DATE = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d$")
_BRACES = re.compile(r"\{[^{}\"]*\}")
_ZONED = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|([+-])(\d\d):?(\d\d))$")
_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58, "icmp6": 58, "icmpv6": 58, "sctp": 132, "gre": 47, "esp": 50,
              "ah": 51, "ospf": 89, "igmp": 2, "pim": 103, "vrrp": 112, "l2tp": 115, "ipip": 4, "ipv6": 41}  # fmt: skip
_ALLOWED = "allow"
_MAX_LINE = 100_000
_MIN_FIELDS = 31  # up to the action: a line shorter than that is not a traffic log that can be read
_TEMPORARY = 0x2000  # flag: a temporary match on a rule for implicit application dependency handling

Key = Tuple[str, str, str, str]  # serial, virtual system, session ID, start time


class Reader:
    """Reads one file at a time; ``zoneless`` counts the lines whose time had no zone and no offset was given."""

    def __init__(self, offset: Optional[int] = None) -> None:
        self.offset = offset
        self.zoneless = 0

    def read(self, data: bytes, name: str = "") -> Iterator[Line]:
        starts: Dict[Key, List[Line]] = {}  # session -> its start lines not matched by an end yet
        for raw in data.decode("utf-8", errors="replace").splitlines():
            text = raw.strip()
            if not text:
                continue
            line, session, subtype = self._read(text)
            record = line.record
            if record is not None and session is not None and subtype == "start":
                starts.setdefault(session, []).append(line)
                continue
            if record is not None and session is not None and subtype == "end":
                rules = set()
                for start in starts.pop(session, []):
                    rule = _rule_of(start.record) if start.record is not None else ""
                    if rule == _rule_of(record) or rule in rules:
                        yield Line(reason="the start of a session whose end is logged too (counted once)", time=start.time,
                                   gateway=start.gateway)  # fmt: skip
                    else:
                        rules.add(rule)
                        yield start  # (another rule matched the session before its application was known: it was used too)
            yield line
        for lines in starts.values():
            for line in lines:
                if line.record is not None:
                    line.record.possible = True  # (the rule may have been left once the application was known)
                yield line

    def read_line(self, text: str) -> Line:
        """One line on its own (a start is then a connection that is possible only)."""
        line, _, subtype = self._read(text)
        if line.record is not None and subtype == "start":
            line.record.possible = True
        return line

    def _read(self, text: str) -> Tuple[Line, Optional[Key], str]:
        if len(text) > _MAX_LINE:
            return Line(reason="a line longer than a log line can be", doubt=True), None, ""
        if _HEADER.match(text):
            return Line(reason="the header of a CSV export"), None, ""
        body = _BODY.search(text)
        quoted = body is None and text.startswith('"')  # (a row of an export with every field in quotes)
        if body is None and not quoted:
            if "CEF:0|Palo Alto Networks|" in text or "LEEF:" in text and "|Palo Alto Networks|" in text:
                return Line(reason="a PAN-OS log in CEF or LEEF, a format that is not read (send the default format)", doubt=True), None, ""
            if ",TRAFFIC," in text:
                return Line(reason="a PAN-OS traffic log that cannot be read", doubt=True), None, ""
            return Line(reason="not a PAN-OS log"), None, ""
        try:
            fields = next(csv.reader([_BRACES.sub(lambda m: m.group(0).replace(",", ";"), text[body.start(1) if body else 0:])]))
        except (csv.Error, StopIteration):
            fields = []
        if quoted and not (len(fields) > 3 and _DATE.match(fields[1].strip())):
            return Line(reason="not a PAN-OS log"), None, ""
        if len(fields) > 3 and fields[3].strip() != "TRAFFIC":
            return Line(reason="a PAN-OS log of another type than TRAFFIC (threat, system, config, ...)"), None, ""
        if len(fields) < _MIN_FIELDS:
            return Line(reason="a PAN-OS traffic log that cannot be read", doubt=True), None, ""

        def at(index: int) -> str:
            return fields[index].strip() if index < len(fields) else ""

        serial = at(2)
        moment = self._when(at(6) or at(1), at(102))
        gateway = serial or at(52)
        if moment is None:
            return Line(reason="a time that cannot be read", doubt=True, gateway=gateway), None, ""
        if not gateway:
            return Line(reason="a line without the serial number of the firewall", doubt=True, time=moment), None, ""
        subtype = at(4).lower()
        if subtype not in ("start", "end", "drop", "deny"):
            return Line(reason=f"a traffic log of a kind that is no connection ({subtype[:20] or 'none'})", time=moment, gateway=gateway), None, ""
        rule, uuid = at(11), at(65).lower()
        if not rule and not uuid:
            return Line(reason="a traffic log that names no rule", doubt=True, time=moment, gateway=gateway), None, ""
        name = at(29).lower()
        protocol = _PROTOCOLS.get(name, int(name) if name.isascii() and name.isdigit() and int(name) < 256 else -1)
        port = _whole(at(25)) if protocol in (6, 17, 132) else None
        port = port if port is not None and port <= 65535 else None
        action = at(30).lower()
        flags = _hex(at(28))
        repeat = _whole(at(23))
        ids = {"panos.name": rule, "panos.uuid": uuid if _UUID.match(uuid) else "", "vsys": at(15)}
        record = LogRecord(moment, gateway, _address(at(7)), _address(at(8)), protocol, port, "accept" if action == _ALLOWED else "drop",
                           users=[at(12)] if at(12) else [], count=max(1, repeat or 1), gateway_address=at(52), in_zone=at(16),
                           out_zone=at(17), ids={key: value for key, value in ids.items() if value},
                           possible=bool(flags is not None and flags & _TEMPORARY))  # fmt: skip
        session = at(22)
        key = (serial, at(15), session, at(35)) if session and session != "0" else None
        return Line(record, time=moment, gateway=gateway, scope=at(15)), key, subtype

    def _when(self, local: str, zoned: str) -> Optional[int]:
        match = _ZONED.match(zoned)
        if match and not zoned.startswith("1969-") and not zoned.startswith("1970-"):
            try:
                parts = [int(match.group(i)) for i in range(1, 7)]
                moment = datetime.datetime(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
                if match.group(7) == "Z":
                    zone = datetime.timezone.utc
                else:
                    minutes = int(match.group(9)) * 60 + int(match.group(10))
                    zone = datetime.timezone(datetime.timedelta(minutes=-minutes if match.group(8) == "-" else minutes))
                return int(moment.replace(tzinfo=zone).timestamp())
            except (ValueError, OverflowError):
                pass
        try:
            moment = datetime.datetime.strptime(local, "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return None
        if self.offset is None:
            self.zoneless += 1
            return int(moment.replace(tzinfo=datetime.timezone.utc).timestamp())
        return int(moment.replace(tzinfo=datetime.timezone(datetime.timedelta(minutes=self.offset))).timestamp())


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _rule_of(record: LogRecord) -> str:
    return record.ids.get("panos.uuid") or record.ids.get("panos.name", "")


def _address(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _whole(text: str) -> Optional[int]:
    return int(text) if text.isascii() and text.isdigit() and int(text) <= 0xFFFFFFFF else None


def _hex(text: str) -> Optional[int]:
    try:
        return int(text, 16) if text else None
    except ValueError:
        return None


__all__ = ["Reader"]
