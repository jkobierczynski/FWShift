# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Sets of connections as boxes, for platforms whose rules cannot say what a first-match rulebase says.

A box is (IP version, sources, destinations, services): every connection of that version from one of the sources to
one of the destinations on one of the services. A first-match rule that allows becomes what it matches without what
the blocking rules above it match: that is a list of boxes, and a platform that only allows (AWS security groups)
can hold it exactly. The other way round, an ordered list of allow and deny entries (an AWS network ACL) becomes the
boxes it denies.

The services are the sets of the audit (:class:`fwshift.audit.Services`): rectangles of (source port, destination
port) per protocol, or (ICMP type, ICMP code), and "every other protocol".
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from .audit import _ALL_SERVICES, _WHOLE, _entry_services, _rects_minus, _union
from .audit import Services as Services
from .model import Protocol, ServiceEntry
from .netutil import FULL_V4, FULL_V6, Interval, intersect, normalize, subtract

Box = Tuple[int, List[Interval], List[Interval], Services]
ALL_SERVICES = _ALL_SERVICES
WHOLE = _WHOLE
_NAMES = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP, 1: Protocol.ICMP, 58: Protocol.ICMP6}
_FOREIGN_ICMP = {4: 58, 6: 1}  # the ICMP of the other IP version: it never meets a packet of this one


def full(version: int) -> Interval:
    return FULL_V4 if version == 4 else FULL_V6


def service_set(entries: Sequence[ServiceEntry]) -> Optional[Services]:
    """The set a list of service entries matches; None when an entry cannot be read."""
    sets: List[Services] = []
    for entry in entries:
        found = _entry_services(entry)
        if found is None:
            return None
        sets.append(found)
    return _union(sets)


def box_and(a: Box, b: Box) -> Optional[Box]:
    if a[0] != b[0]:
        return None
    src, dst = intersect(a[1], b[1]), intersect(a[2], b[2])
    if not src or not dst:
        return None
    svc = a[3].and_(b[3])
    return None if svc.empty() else (a[0], src, dst, svc)


def box_minus(a: Box, b: Box) -> List[Box]:
    """What of ``a`` is not in ``b``: at most three boxes, which do not overlap."""
    if a[0] != b[0]:
        return [a]
    version, src, dst, svc = a
    src_in, dst_in = intersect(src, b[1]), intersect(dst, b[2])
    if not src_in or not dst_in:
        return [a]
    svc_in = svc.and_(b[3])
    if svc_in.empty():
        return [a]
    out: List[Box] = []
    src_out = subtract(src, b[1])
    if src_out:
        out.append((version, src_out, dst, svc))
    dst_out = subtract(dst, b[2])
    if dst_out:
        out.append((version, src_in, dst_out, svc))
    svc_out = svc.minus(b[3])
    if not svc_out.empty():
        out.append((version, src_in, dst_in, svc_out))
    return out


def minus_all(boxes: List[Box], cuts: Sequence[Box], limit: int = 512) -> Optional[List[Box]]:
    """``boxes`` without every box of ``cuts``; None when the pieces would be more than ``limit``."""
    for cut in cuts:
        if not boxes:
            break
        boxes = [piece for box in boxes for piece in box_minus(box, cut)]
        if len(boxes) > limit:
            return None
    return boxes


def empty(box: Box) -> bool:
    return not box[1] or not box[2] or box[3].empty()


def _ports(low: int, high: int) -> str:
    if (low, high) == (0, 65535):
        return ""
    return str(low) if low == high else f"{low}-{high}"


def icmp_values(low: int, high: int) -> Optional[List[Optional[int]]]:
    """The ICMP types (or codes) of a range of the audit's sets: None for all of them."""
    low, high = max(low, 0), min(high, 255)
    if low <= 0 and high >= 255:
        return [None]
    return list(range(low, high + 1)) if low <= high else []


def entries_of(svc: Services, version: int, limit: int = 4096) -> Optional[Tuple[List[ServiceEntry], bool]]:
    """Service entries for a set, for one IP version: (entries, negated). Negated means every service but those
    entries, and no entries with negated means every service. None when there would be more than ``limit``."""
    foreign = _FOREIGN_ICMP[version]
    if svc.rest:
        rest = Services({n: _rects_minus([_WHOLE], svc.of(n)) for n in svc.protocols if n != foreign}, False)
        found = _positive(rest, version, limit)
        return None if found is None else (found, True)
    found = _positive(svc, version, limit)
    return None if found is None else (found, False)


def _positive(svc: Services, version: int, limit: int) -> Optional[List[ServiceEntry]]:
    out: List[ServiceEntry] = []
    for number in sorted(svc.protocols):
        if number == _FOREIGN_ICMP[version]:
            continue
        for rect in svc.protocols[number]:
            if number in (6, 17, 132):
                out.append(ServiceEntry(_NAMES[number], dst_ports=_ports(rect[2], rect[3]), src_ports=_ports(rect[0], rect[1])))
            elif number in (1, 58):
                types, codes = icmp_values(rect[0], rect[1]), icmp_values(rect[2], rect[3])
                if types is None or codes is None:
                    return None
                if types == [None] and codes != [None]:
                    types = list(range(256))
                for kind in types:
                    for code in codes:
                        out.append(ServiceEntry(_NAMES[number], icmp_type=kind, icmp_code=code))
            else:
                out.append(ServiceEntry(Protocol.IP, ip_protocol=number))
            if len(out) > limit:
                return None
    unique: List[ServiceEntry] = []
    for entry in out:
        if entry not in unique:
            unique.append(entry)
    return unique


def merge_ranges(ranges: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Port ranges sorted, the ones that overlap or touch joined."""
    out: List[Tuple[int, int]] = []
    for low, high in sorted(ranges):
        if out and low <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], high))
        else:
            out.append((low, high))
    return out


def everywhere(version: int) -> List[Interval]:
    return [full(version)]


def addresses(intervals: Sequence[Interval], version: int) -> List[Interval]:
    return normalize([i for i in intervals if i[0] == version])
