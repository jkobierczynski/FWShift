# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The lines the kernel writes for an iptables or ip6tables LOG rule, as syslog or the journal keeps them.

    Oct 12 10:00:00 fw1 kernel: [123.456] fw-new IN=eth1 OUT=eth0 MAC=... SRC=10.10.4.20 DST=192.0.2.53 LEN=60 TOS=0x00
        PREC=0x00 TTL=63 ID=1 DF PROTO=UDP SPT=40000 DPT=53 LEN=40
    2026-10-12T10:00:00.123456+02:00 fw1 kernel: fw-new IN=eth1 OUT=eth0 SRC=2001:db8::5 DST=2001:db8::10 ... PROTO=ICMPv6 TYPE=128 CODE=0

A line names no rule: which one it was is worked out from the policy (simulate.py). Only forwarded packets are
connections of the policy FWShift reads (the FORWARD chain): a line with IN= or OUT= empty is the firewall's own.
A TCP line whose flags are not SYN alone is a packet of a connection already open, not a connection. A line that
says that lines were lost (the kernel, the journal or rsyslog dropped some) is a doubt on its gateway and day.
The gateway is the host name of the line. A time in the old syslog form has no year and no zone: the year is given
(``year``), and changes where the months run back, and the zone is given as an offset from UTC (``offset``,
minutes); without one the time is read as UTC and ``zoneless`` counts the lines that were.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from typing import Dict, Iterator, Optional, Set, Tuple

from . import Line, LogRecord

_MONTHS = {name: number for number, name in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_BSD = re.compile(r"^(?:<\d{1,3}>)?([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d)(?:\.\d+)? +(\S+) ")
_ISO = re.compile(r"^(?:<\d{1,3}>)?(?:1 )?(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|([+-])(\d\d):?(\d\d))? +(\S+) ")
# The interfaces the kernel puts first: "IN=eth1 OUT=eth0 " (a prefix may hold the same words: the last are the fields).
_INTERFACES = re.compile(r"(?:^|\s)IN=(\S*) OUT=(\S*)(?= )")
# Lines that say that lines were lost: the kernel's ring buffer, the journal or rsyslog dropped some.
_LOST = re.compile(r"\b(?:kernel|systemd-journald|rsyslogd|syslog-ng)(?:\[\d+\])?: .*(?:messages dropped|callbacks suppressed|"
                   r"Missed \d+ kernel messages|messages? lost|Suppressed \d+ messages|rate-?limit)", re.IGNORECASE)  # fmt: skip
_PROTOCOLS = {"TCP": 6, "UDP": 17, "UDPLITE": 136, "SCTP": 132, "ICMP": 1, "ICMPV6": 58, "GRE": 47, "ESP": 50, "AH": 51}
_MAX_LINE = 100_000


class Reader:
    """Reads one file at a time; ``zoneless`` counts the lines whose time had no zone and no offset was given.

    ``year`` is the year of the first line of a file whose times have none: a line whose month is more than six
    before the line above it is in the next year (December, then January), one more than six after it in the year
    before (a line out of order around New Year).
    """

    def __init__(self, year: Optional[int] = None, offset: Optional[int] = None) -> None:
        self.year = year
        self.offset = offset
        self.zoneless = 0
        self.current = year  # the year of the line before
        self.month = 0  # and its month

    def read(self, data: bytes, name: str = "") -> Iterator[Line]:
        self.current, self.month = self.year, 0
        for raw in data.decode("utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line:
                yield self.read_line(line)

    def read_line(self, line: str) -> Line:
        if len(line) > _MAX_LINE:
            return Line(reason="a line longer than a log line can be", doubt=True)
        found = [match for match in _INTERFACES.finditer(line) if " SRC=" in line[match.end():]]
        if not found:
            if _LOST.search(line):
                moment, gateway, problem = self._when(line)
                return Line(reason="a line that says that log lines were lost", doubt=True, time=moment, gateway=gateway)
            if "IN=" in line and " SRC=" in line:
                moment, gateway, problem = self._when(line)
                return Line(reason="a line of a LOG rule without its interfaces (cut short or garbled?)", doubt=True, time=moment,
                            gateway=gateway)  # fmt: skip
            return Line(reason="not a line of an iptables LOG rule")
        moment, gateway, problem = self._when(line)
        if moment is None:
            return Line(reason=problem, doubt=True, gateway=gateway)
        if not gateway:
            return Line(reason="a line without the host it came from", doubt=True, time=moment)
        interfaces = found[-1]
        if "TRACE:" in line[:interfaces.start()]:
            return Line(reason="a line of rule tracing (TRACE), not of a LOG rule", time=moment, gateway=gateway)
        rest = line[interfaces.end():]
        if " MAC source = " in rest:
            return Line(reason="a line of ebtables (a bridge), not of iptables", time=moment, gateway=gateway)
        in_zone, out_zone = interfaces.group(1), interfaces.group(2)
        if not in_zone or not out_zone:
            return Line(reason="a packet to or from the firewall itself (INPUT or OUTPUT), not forwarded", time=moment, gateway=gateway)
        fields, flags = _fields(rest)
        try:
            src, dst = str(ipaddress.ip_address(fields.get("SRC", ""))), str(ipaddress.ip_address(fields.get("DST", "")))
        except ValueError:
            src, dst = _address(fields.get("SRC", "")), _address(fields.get("DST", ""))
        name = fields.get("PROTO", "").upper()
        protocol = _PROTOCOLS.get(name, int(name) if name.isascii() and name.isdigit() and int(name) < 256 else -1)
        port: Optional[int] = None
        if protocol in (6, 17, 132, 136):
            port = _whole(fields.get("DPT", ""))
        elif protocol in (1, 58):
            port = _whole(fields.get("TYPE", ""))
        if protocol == 6 and "URGP" in fields and not ("SYN" in flags and "ACK" not in flags):
            # The flags are in the line (URGP= ends them): this packet opened no connection. A LOG rule that logs every
            # packet, or one ahead of the rule that accepts established connections, logs the rest of them too.
            return Line(reason="a TCP packet that opens no connection (not SYN alone): a packet of one already open", time=moment,
                        gateway=gateway)  # fmt: skip
        record = LogRecord(moment, gateway, src, dst, protocol, port, "", in_zone=in_zone, out_zone=out_zone)
        return Line(record, time=moment, gateway=gateway)

    def _when(self, line: str) -> "tuple[Optional[int], str, str]":
        iso = _ISO.match(line)
        if iso:
            parts = [int(iso.group(i)) for i in range(1, 7)]
            try:
                moment = datetime.datetime(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
                if iso.group(7) == "Z":
                    moment = moment.replace(tzinfo=datetime.timezone.utc)
                elif iso.group(7):
                    minutes = int(iso.group(9)) * 60 + int(iso.group(10))
                    zone = datetime.timezone(datetime.timedelta(minutes=-minutes if iso.group(8) == "-" else minutes))
                    moment = moment.replace(tzinfo=zone)
                else:
                    moment = self._zone(moment)
            except ValueError:
                return None, iso.group(11), "a time that cannot be read"
            return int(moment.timestamp()), iso.group(11), ""
        bsd = _BSD.match(line)
        if not bsd:
            return None, "", "a line without a time and host before the log (dmesg keeps neither)"
        month = _MONTHS.get(bsd.group(1))
        if month is None:
            return None, bsd.group(6), "a time that cannot be read"
        if self.current is None:
            return None, bsd.group(6), "a time without a year (give the year of the log)"
        year = self.current
        if self.month and month < self.month - 6:
            self.current += 1  # (December, then January)
            year, self.month = self.current, month
        elif self.month and month > self.month + 6:
            year -= 1  # (a line of December among those of January: the year before, and the order goes on)
        else:
            self.month = month
        try:
            moment = datetime.datetime(year, month, int(bsd.group(2)), int(bsd.group(3)), int(bsd.group(4)), int(bsd.group(5)))
        except ValueError:
            return None, bsd.group(6), "a time that cannot be read"
        return int(self._zone(moment).timestamp()), bsd.group(6), ""

    def _zone(self, moment: datetime.datetime) -> datetime.datetime:
        if self.offset is None:
            self.zoneless += 1
            return moment.replace(tzinfo=datetime.timezone.utc)
        return moment.replace(tzinfo=datetime.timezone(datetime.timedelta(minutes=self.offset)))


def _fields(text: str) -> Tuple[Dict[str, str], Set[str]]:
    """KEY=value of the line, the first of each key, and the words without a value (the TCP flags); what is in
    brackets (the packet an ICMP error quotes) is left out."""
    out: Dict[str, str] = {}
    words: Set[str] = set()
    depth = 0
    for token in text.split(" "):
        if depth or token.startswith("["):
            depth += token.count("[") - token.count("]")
            depth = max(depth, 0)
            continue
        key, sep, value = token.partition("=")
        if sep and key.isupper() and key not in out:
            out[key] = value
        elif not sep and token.isupper():
            words.add(token)
    return out, words


def _address(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _whole(text: str) -> Optional[int]:
    return int(text) if text.isascii() and text.isdigit() and int(text) <= 65535 else None


__all__ = ["Reader"]
