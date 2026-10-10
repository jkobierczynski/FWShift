# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""IP address helpers. An interval is ``(version, first, last)`` with integer bounds."""

from __future__ import annotations

import ipaddress
from typing import List, Optional, Sequence, Tuple, Union

Interval = Tuple[int, int, int]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

FULL_V4: Interval = (4, 0, 2**32 - 1)
FULL_V6: Interval = (6, 0, 2**128 - 1)


def parse_literal(text: str) -> Optional[Interval]:
    """Parse ``10.0.0.1``, ``10.0.0.0/24`` or ``10.0.0.1-10.0.0.9``; None if it is none of these."""
    text = text.strip()
    if not text:
        return None
    try:
        if "-" in text and "/" not in text:
            first_text, last_text = text.split("-", 1)
            first = ipaddress.ip_address(first_text.strip())
            last = ipaddress.ip_address(last_text.strip())
            if first.version != last.version or int(last) < int(first):
                return None
            return (first.version, int(first), int(last))
        net = ipaddress.ip_network(text, strict=False)
        return (net.version, int(net.network_address), int(net.broadcast_address))
    except ValueError:
        return None


def is_network(text: str) -> bool:
    """True for a host or subnet (``10.0.0.1``, ``10.0.0.0/24``), false for a range or anything else."""
    if "-" in text:
        return False
    try:
        ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return False
    return True


def is_range(text: str) -> bool:
    return "-" in text and "/" not in text and parse_literal(text) is not None


def int_to_ip(version: int, value: int) -> IPAddress:
    return ipaddress.IPv4Address(value) if version == 4 else ipaddress.IPv6Address(value)


def range_text(interval: Interval) -> str:
    """``first`` for a single address, else ``first-last``."""
    version, first, last = interval
    if first == last:
        return str(int_to_ip(version, first))
    return f"{int_to_ip(version, first)}-{int_to_ip(version, last)}"


def size(interval: Interval) -> int:
    return interval[2] - interval[1] + 1


def normalize(intervals: Sequence[Interval]) -> List[Interval]:
    """Sort and merge overlapping or adjacent intervals."""
    out: List[Interval] = []
    for version, first, last in sorted(intervals):
        if out and out[-1][0] == version and first <= out[-1][2] + 1:
            out[-1] = (version, out[-1][1], max(out[-1][2], last))
        else:
            out.append((version, first, last))
    return out


def overlaps(a: Sequence[Interval], b: Sequence[Interval]) -> bool:
    return any(x[0] == y[0] and x[1] <= y[2] and y[1] <= x[2] for x in a for y in b)


def within(inner: Sequence[Interval], outer: Sequence[Interval]) -> bool:
    """True when every address of ``inner`` is in ``outer``."""
    merged = normalize(outer)
    return all(any(o[0] == i[0] and o[1] <= i[1] and i[2] <= o[2] for o in merged) for i in normalize(inner))


def netmask_to_cidr(address: str, mask: str) -> Optional[str]:
    """``10.0.0.0`` + ``255.255.255.0`` -> ``10.0.0.0/24``; None for a non-contiguous mask."""
    try:
        return str(ipaddress.ip_network(f"{address}/{mask}", strict=False))
    except ValueError:
        return None
