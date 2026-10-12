# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""FortiOS traffic logs: the key=value lines a FortiGate sends to syslog (its default format), as such or behind a
syslog header, also as FortiAnalyzer forwards them (``logver=... timestamp=...`` in front).

    date=2026-10-12 time=10:00:00 devname="fgt-edge" devid="FGT60F0000000001" eventtime=1791799200000000000 tz="+0200"
    logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.4.20 srcport=40000
    srcintf="port2" dstip=192.0.2.80 dstport=443 dstintf="port1" poluuid="..." sessionid=1 proto=6 action="close"
    policyid=3 policytype="policy" service="HTTPS" ...

A line names its policy by ``poluuid`` and ``policyid``; ``vd`` is the VDOM. What counts: a forward traffic log of
a firewall policy (``policytype`` "policy", or none in older versions). Its action says whether the policy let the
session through: ``deny`` is a drop; ``accept``, ``close``, ``timeout``, ``client-rst``, ``server-rst``, ``start``,
and the failed connections ``ip-conn`` and ``dns`` were let through. A start whose end is in the same file is counted
once. Not counted, each with its reason: the firewall's own traffic (subtype ``local``), multicast and sniffer logs,
other kinds of policy (local-in, proxy), the interim statistics of a long session (log ID 20).

The time: ``eventtime`` is UTC (seconds before 6.2, nanoseconds since; milliseconds in some exports). Without it,
``date`` and ``time`` are the FortiGate's local time, with ``tz`` where the line has it; otherwise the offset is given
(``offset``, minutes), or the time is read as UTC and ``zoneless`` counts the lines that were.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from typing import Dict, Iterator, List, Optional, Tuple

from . import Line, LogRecord

_FIRST = re.compile(r"(?:^|[\s>])(logver|date|eventtime|logid|devname|devid)=")  # where the fields begin, after any header
_PAIR = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|\S*)')
_ZONE = re.compile(r"^(?:UTC|GMT)?\s*([+-])(\d{1,2}):?(\d\d)?$")
_ALLOWED = {"accept", "close", "timeout", "client-rst", "server-rst", "start", "ip-conn", "dns"}
_INTERIM = 20  # log ID message number: the statistics of a long session, before its end
_MAX_LINE = 100_000

Key = Tuple[str, ...]  # device, VDOM, session ID, policy, addresses, protocol, port


class Reader:
    """Reads one file at a time; ``zoneless`` counts the lines whose time had no zone and no offset was given."""

    def __init__(self, offset: Optional[int] = None) -> None:
        self.offset = offset
        self.zoneless = 0

    def read(self, data: bytes, name: str = "") -> Iterator[Line]:
        starts: Dict[Key, List[Line]] = {}
        for raw in data.decode("utf-8", errors="replace").splitlines():
            text = raw.strip()
            if not text:
                continue
            line, session, action = self._read(text)
            if line.record is not None and session is not None and action == "start":
                starts.setdefault(session, []).append(line)
                continue
            if line.record is not None and session is not None:
                for start in starts.pop(session, []):
                    yield Line(reason="the start of a session whose end is logged too (counted once)", time=start.time, gateway=start.gateway)
            yield line
        for lines in starts.values():
            yield from lines  # (sessions still open when the file ends: the policy is chosen once, at the start)

    def read_line(self, text: str) -> Line:
        return self._read(text)[0]

    def _read(self, text: str) -> Tuple[Line, Optional[Key], str]:
        if len(text) > _MAX_LINE:
            return Line(reason="a line longer than a log line can be", doubt=True), None, ""
        if "CEF:" in text and "|Fortinet|Fortigate|" in text:
            return Line(reason="a FortiOS log in CEF, a format that is not read (send the default format)", doubt=True), None, ""
        first = _FIRST.search(text)
        if first is None or "type=" not in text:
            return Line(reason="not a FortiOS log"), None, ""
        fields: Dict[str, str] = {}
        for match in _PAIR.finditer(text[first.start(1):]):
            key, value = match.group(1), match.group(2)
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = re.sub(r"\\(.)", r"\1", value[1:-1])
            fields.setdefault(key, value)  # (the first of a key: a value cannot hold a key of the header)
        gateway = fields.get("devname") or fields.get("devid", "")
        moment = self._when(fields)
        if moment is None:
            return Line(reason="a time that cannot be read", doubt=True, gateway=gateway), None, ""
        kind = fields.get("type", "").lower()
        if kind != "traffic":
            return Line(reason="a FortiOS log of another type than traffic (event, utm, ...)"), None, ""
        if not gateway:
            return Line(reason="a line without the name or serial number of the FortiGate", doubt=True, time=moment), None, ""
        subtype = fields.get("subtype", "").lower()
        if subtype == "local":
            return Line(reason="traffic to or from the FortiGate itself (subtype local), not forwarded", time=moment, gateway=gateway), None, ""
        if subtype != "forward":
            return Line(reason=f"a traffic log of another kind than forward ({subtype[:20] or 'none'})", time=moment, gateway=gateway), None, ""
        logid = fields.get("logid", "")
        if logid.isdigit() and len(logid) >= 6 and int(logid[-6:]) == _INTERIM:
            return Line(reason="the interim statistics of a session logged at its end", time=moment, gateway=gateway), None, ""
        policytype = fields.get("policytype", "policy").lower()
        if policytype not in ("policy", ""):
            return Line(reason=f"a log of another kind of policy than a firewall policy ({policytype[:24]})", time=moment, gateway=gateway), None, ""
        policyid, uuid = fields.get("policyid", ""), fields.get("poluuid", "").lower()
        if not policyid.isdigit() and not uuid:
            return Line(reason="a forward traffic log that names no policy", doubt=True, time=moment, gateway=gateway), None, ""
        action = fields.get("action", "").lower()
        protocol = _whole(fields.get("proto", ""))
        protocol = protocol if protocol is not None and protocol < 256 else -1
        port: Optional[int] = None
        if protocol in (6, 17, 132):
            port = _whole(fields.get("dstport", ""))
        elif protocol in (1, 58):
            port = _number(fields.get("icmptype", ""))
        port = port if port is not None and port <= 65535 else None
        user = fields.get("user", "")
        ids = {"fortios.policyid": policyid if policyid.isdigit() else "", "fortios.uuid": uuid, "vdom": fields.get("vd", "")}
        nat_dst, nat_port = "", None
        if "dnat" in fields.get("trandisp", "").lower():
            # A virtual IP: the policy may name the address and port after the translation (central NAT, port forwarding).
            nat_dst = _address(fields.get("tranip", ""))
            nat_port = _whole(fields.get("tranport", "")) if protocol in (6, 17, 132) else None
            nat_port = nat_port if nat_port is not None and nat_port <= 65535 else None
        record = LogRecord(moment, gateway, _address(fields.get("srcip", "")), _address(fields.get("dstip", "")), protocol, port,
                           "accept" if action in _ALLOWED else "drop" if action == "deny" else action, users=[user] if user else [],
                           gateway_address=fields.get("devid", ""), in_zone=fields.get("srcintf", ""), out_zone=fields.get("dstintf", ""),
                           ids={key: value for key, value in ids.items() if value}, nat_dst=nat_dst, nat_port=nat_port)  # fmt: skip
        session = fields.get("sessionid", "")
        # The start and the end of a session agree on all of this; a session ID taken again later does not.
        key = (gateway, fields.get("vd", ""), session, policyid, uuid, record.src, record.dst, str(protocol), str(port)) \
            if session.isdigit() and session != "0" else None  # fmt: skip
        return Line(record, time=moment, gateway=gateway, scope=fields.get("vd", "")), key, action

    def _when(self, fields: Dict[str, str]) -> Optional[int]:
        stamp = fields.get("eventtime", "")
        if stamp.isascii() and stamp.isdigit() and len(stamp) >= 9:
            value = int(stamp)
            for divisor in (1, 1000, 1_000_000, 1_000_000_000):
                if value // divisor < 10_000_000_000:  # (seconds until the year 2286)
                    return value // divisor
        try:
            moment = datetime.datetime.strptime(f"{fields.get('date', '')} {fields.get('time', '')}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
        zone = _ZONE.match(fields.get("tz", "").strip())
        if zone:
            minutes = int(zone.group(2)) * 60 + int(zone.group(3) or 0)
            if minutes <= 18 * 60:
                offset = datetime.timezone(datetime.timedelta(minutes=-minutes if zone.group(1) == "-" else minutes))
                return int(moment.replace(tzinfo=offset).timestamp())
        if self.offset is None:
            self.zoneless += 1
            return int(moment.replace(tzinfo=datetime.timezone.utc).timestamp())
        return int(moment.replace(tzinfo=datetime.timezone(datetime.timedelta(minutes=self.offset))).timestamp())


def _address(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _whole(text: str) -> Optional[int]:
    return int(text) if text.isascii() and text.isdigit() and len(text) < 10 else None


def _number(text: str) -> Optional[int]:
    """A number written in decimal or hexadecimal (FortiOS writes the ICMP type as 0x08)."""
    try:
        return int(text, 16) if text.lower().startswith("0x") else _whole(text)
    except ValueError:
        return None


__all__ = ["Reader"]
