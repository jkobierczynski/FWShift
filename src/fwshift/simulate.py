# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Which rule a connection went through, worked out from the policy where its log does not say (docs/RULE_USAGE.md, 6.5).

The rules are taken in their order, the first that matches decides. Each rule is read as the audit reads it
(``audit._Reader.match``): what it *surely* matches and what it *might* match. A connection that the first rule it
might meet surely matches went through that rule: **certain**. A connection that meets a rule it might, but not
surely, match (a host name, a negation that cannot be read, a criterion the model does not hold, a rule read
approximately, a zone or port the log does not give) may have gone through it or further down: it is **possible**
for every rule from there to the first rule that surely matches it, and certain for none.

The verdict of the log, where it has one, must agree: a rule whose action is not the one the log saw is passed over,
as the gateway passed it over; and a connection whose log the first rule that surely matches it contradicts is not
attributed at all (the policy is not what the gateway ran).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .audit import _DIFFERENT, _SAME, Reading, _Match, _Reader, _blocks
from .model import ANY, Policy, Rule
from .netutil import Interval

Point = Tuple[str, str, str, str, int, Optional[int]]  # in zone, out zone, source, destination, protocol, port


@dataclass
class Attribution:
    certain: Optional[Rule] = None
    possible: List[Rule] = field(default_factory=list)
    reason: str = ""  # why neither, where that is the answer


Span = Tuple[int, int, int]  # version, first, last: an address, or the network a store keeps addresses beyond its cap as


def _span(address: str) -> Optional[Span]:
    try:
        network = ipaddress.ip_network(address, strict=False)
    except ValueError:
        return None
    return network.version, int(network.network_address), int(network.broadcast_address)


def _holds(intervals: Sequence[Interval], span: Optional[Span]) -> bool:
    """Whether every address of the span is in the intervals (in one of them: a span across two is only possible)."""
    return span is not None and any(version == span[0] and first <= span[1] and span[2] <= last for version, first, last in intervals)


def _touches(intervals: Sequence[Interval], span: Span) -> bool:
    return any(version == span[0] and first <= span[2] and span[1] <= last for version, first, last in intervals)


class Simulator:
    """First match on the rules of a policy, for one connection at a time."""

    def __init__(self, p: Policy, reading: Optional[Reading] = None) -> None:
        self.p = p
        self.reader = _Reader(p, reading)
        self.rules: List[Tuple[Rule, _Match]] = [(rule, self.reader.match(rule, index)) for index, rule in enumerate(p.rules) if rule.enabled]
        self.memo: Dict[Tuple[object, ...], Tuple[Optional[int], Tuple[int, ...], str]] = {}

    def attribute(self, point: Point, action: str = "") -> Attribution:
        """The rule a connection went through: (in zone, out zone, source, destination, protocol, port); "", -1 or None
        for unknown. A source or destination may be a network: the connection came from (or went to) one of its addresses."""
        if point[5] is not None and point[5] < 0:
            point = point[:5] + (None,)
        key: Tuple[object, ...] = point + (action,)
        cached = self.memo.get(key)
        if cached is None:
            cached = self._attribute(point, action.strip().lower())
            self.memo[key] = cached
        certain, possible, reason = cached
        return Attribution(self.rules[certain][0] if certain is not None else None, [self.rules[i][0] for i in possible], reason)

    def _attribute(self, point: Point, action: str) -> Tuple[Optional[int], Tuple[int, ...], str]:
        in_zone, out_zone, src, dst, protocol, port = point
        source, destination = _span(src), _span(dst)
        possible: List[int] = []
        for index, (rule, match) in enumerate(self.rules):
            might = self._zones(match, in_zone, out_zone, sure=False) and self._addresses(match, source, destination, sure=False) and \
                self._services(match, protocol, port, sure=False)  # fmt: skip
            if not might:
                continue
            verdict = "allow" if not _blocks(rule) else "block"
            agrees = not action or (verdict == "allow") == (action == "accept")
            sure = match.covers and not match.loose and self._exact(rule) and self._zones(match, in_zone, out_zone, sure=True) and \
                self._addresses(match, source, destination, sure=True) and self._services(match, protocol, port, sure=True)  # fmt: skip
            if sure:
                if not agrees:
                    if possible:
                        return None, tuple(possible), ""
                    return None, (), "the first rule that matches decides otherwise than the log says (is this the policy that ran?)"
                return (index, (), "") if not possible else (None, tuple(possible + [index]), "")
            if agrees:
                possible.append(index)
        if possible:
            return None, tuple(possible), ""
        return None, (), "no rule matches it: the default of the policy"

    @staticmethod
    def _exact(rule: Rule) -> bool:
        """Whether nothing beyond zones, addresses and services decides: no users, applications, URL categories, schedule."""
        return rule.users == [ANY] and rule.applications == [ANY] and rule.url_categories == [ANY] and not rule.schedule

    def _zones(self, match: _Match, in_zone: str, out_zone: str, sure: bool) -> bool:
        zones = self.reader.zones
        src_bits, dst_bits, relation = match.zones
        if not in_zone or not out_zone:
            # A zone the log does not give: a rule for every zone takes it surely, any other perhaps.
            whole = src_bits == zones.all and dst_bits == zones.all and relation == _SAME | _DIFFERENT
            return whole or (not sure and zones.possible(src_bits, dst_bits, relation))
        a, b = zones.bits([in_zone]) or zones.other, zones.bits([out_zone]) or zones.other
        same = in_zone == out_zone
        return bool(src_bits & a and dst_bits & b and relation & (_SAME if same else _DIFFERENT))

    @staticmethod
    def _addresses(match: _Match, source: Optional[Span], destination: Optional[Span], sure: bool) -> bool:
        if sure:
            return _holds(match.src_under, source) and _holds(match.dst_under, destination)
        # An address the log does not give may be any; of a network, any of its addresses.
        return (source is None or _touches(match.src_over, source)) and (destination is None or _touches(match.dst_over, destination))

    @staticmethod
    def _services(match: _Match, protocol: int, port: Optional[int], sure: bool) -> bool:
        services = match.svc_under if sure else match.svc_over
        if protocol < 0:
            return services.everything() if sure else not services.empty()
        rects = services.of(protocol)
        if protocol in (6, 17, 132):
            # (source first, last, destination first, last); the source port is not in the log.
            if port is None:
                return any(r[0] == 0 and r[1] == 65535 and r[2] == 0 and r[3] == 65535 for r in rects) if sure else bool(rects)
            if sure:
                return any(r[0] == 0 and r[1] == 65535 and r[2] <= port <= r[3] for r in rects)
            return any(r[2] <= port <= r[3] for r in rects)
        if protocol in (1, 58):
            # (type first, last, code first, last); the code is not in the log.
            if port is None:
                return any(r[0] == 0 and r[1] == 65535 and r[2] == 0 and r[3] == 65535 for r in rects) if sure else bool(rects)
            if sure:
                return any(r[0] <= port <= r[1] and r[2] == 0 and r[3] == 65535 for r in rects)
            return any(r[0] <= port <= r[1] for r in rects)
        return any(r == (0, 65535, 0, 65535) for r in rects) if sure else bool(rects)


__all__ = ["Attribution", "Point", "Simulator"]
