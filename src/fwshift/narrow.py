# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""A narrower allow rule, from what the logs show went through it (docs/RULE_USAGE.md, 6.7; 0.17.0).

The proposal keeps the rule as it is and narrows three cells: its sources, its destinations and its services, each
to what its connections used, certain and possible alike. A cell is narrowed only where the audit knows all of
what it holds (no host name, no object it cannot read, not negated, not a destination NAT), where every
connection said what it used in that cell, and where what they used lies inside it. Addresses are taken as they
were, then grouped into networks (/24 and /16, /64 and /48) while there are more than ``MAX_PARTS``; whatever the
grouping, the result is cut back to the cell, so it is never wider than the rule. Services become the protocols,
ports and ICMP types the connections used. A rule that is not read exactly, a blocking rule, a part of a split
rule and a rule whose logs prove nothing get no proposal.

The share of a cell is what the proposal holds of what the cell holds: of the addresses of each IP version (the
largest of the two), of the ports of each protocol.
"""

from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import transform
from .model import Address, AddressKind, Policy, Protocol, Rule, Service, ServiceEntry
from .netutil import Interval

MAX_PARTS = 16  # networks of a cell, or protocol and port pairs, in a proposal; with more, the cell is not narrowed
Span = Tuple[int, int, int]


@dataclass
class Cell:
    name: str  # "sources", "destinations", "services"
    proposed: List[str]  # networks ("10.1.2.0/24", "192.0.2.10/32"), or services ("tcp/443", "icmp/8", "ip/47")
    held: int  # how much the cell holds (addresses of the IP version that decides the share, or ports)
    kept: int  # and the proposal
    share: float


@dataclass
class Proposal:
    rule: Rule
    cells: List[Cell] = field(default_factory=list)

    def narrowest(self) -> float:
        return min((cell.share for cell in self.cells), default=1.0)


def _span(text: str) -> Optional[Span]:
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return network.version, int(network.network_address), int(network.broadcast_address)


def _within(span: Span, intervals: Sequence[Interval]) -> bool:
    return any(version == span[0] and first <= span[1] and span[2] <= last for version, first, last in intervals)


def _merge(intervals: Sequence[Interval]) -> List[Interval]:
    out: List[Interval] = []
    for version, first, last in sorted(intervals):
        if out and out[-1][0] == version and first <= out[-1][2] + 1:
            out[-1] = (version, out[-1][1], max(out[-1][2], last))
        else:
            out.append((version, first, last))
    return out


def _networks(intervals: Sequence[Interval]) -> List[str]:
    out: List[str] = []
    for version, first, last in _merge(intervals):
        make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        out += [str(network) for network in ipaddress.summarize_address_range(make(first), make(last))]
    return out


def _size(intervals: Sequence[Interval], version: int) -> int:
    return sum(last - first + 1 for v, first, last in _merge(intervals) if v == version)


def addresses(seen: Sequence[str], cell: Sequence[Interval]) -> Optional[Tuple[List[str], int, int, float]]:
    """The networks of a cell that hold what was seen, as few as MAX_PARTS: (networks, held, kept, share); None
    where something seen is not inside the cell (the model and the log disagree) or it cannot be done in so few."""
    spans = [_span(text) for text in seen]
    if not spans or any(span is None or not _within(span, cell) for span in spans):
        return None
    known = [span for span in spans if span is not None]
    for v4, v6 in ((32, 128), (24, 64), (16, 48)):
        grown: List[Interval] = []
        for version, first, _ in known:
            bits = 32 if version == 4 else 128
            keep = v4 if version == 4 else v6
            mask = ((1 << bits) - 1) ^ ((1 << (bits - keep)) - 1)
            base = first & mask
            grown.append((version, base, base | ((1 << (bits - keep)) - 1)))
        # A network that grew is cut back to the cell: never wider than the rule.
        cut = [(v, max(a, c), min(b, d)) for v, a, b in _merge(grown) for w, c, d in _merge(cell) if v == w and max(a, c) <= min(b, d)]
        parts = _merge(cut + [span for span in known])
        networks = _networks(parts)
        if len(networks) <= MAX_PARTS:
            shares = []
            for version in (4, 6):
                held = _size(cell, version)
                if held:
                    shares.append((_size(parts, version) / held, held, _size(parts, version)))
            share, held, kept = max(shares)
            return networks, held, kept, share
    return None


_NAMES = {6: "tcp", 17: "udp", 132: "sctp", 1: "icmp", 58: "icmp6"}
_PORTED = (6, 17, 132)
_TYPED = (1, 58)


def _points(services: object) -> Dict[int, int]:
    """Per protocol, how many destination ports (or ICMP types, or 1 for another protocol) a set of services holds
    for any source port (any code); every other protocol counts 1."""
    from .audit import Services

    assert isinstance(services, Services)
    out: Dict[int, int] = {}
    for number in set(services.protocols) | set(_NAMES):
        rects = services.of(number)
        if number in _PORTED + _TYPED:
            whole = [(r[2], r[3]) if number in _PORTED else (r[0], r[1]) for r in rects
                     if (number in _PORTED and r[0] == 0 and r[1] == 65535) or (number in _TYPED and r[2] == 0 and r[3] == 65535)]  # fmt: skip
            merged = _merge([(0, a, b) for a, b in whole])
            count = sum(b - a + 1 for _, a, b in merged)
            if number in _TYPED:
                count = min(count, 256)
            if count:
                out[number] = count
        elif any(r == (0, 65535, 0, 65535) for r in rects):
            out[number] = 1
    if services.rest:
        out[-1] = 256 - len([n for n in out if n >= 0])  # (every other protocol)
    return out


def services(seen: Sequence[str], cell: object) -> Optional[Tuple[List[str], int, int, float]]:
    """The services the connections used, as (services, held, kept, share); None where one is not in the cell, or
    there are more than MAX_PARTS."""
    from .audit import Services

    assert isinstance(cell, Services)
    used: Set[Tuple[int, int]] = set()
    for text in seen:
        head, _, tail = text.partition("/")
        try:
            used.add((int(head), int(tail)))
        except ValueError:
            return None
    if not used or len(used) > MAX_PARTS:
        return None
    for number, port in used:
        rects = cell.of(number)
        if number in _PORTED:
            inside = any(r[0] == 0 and r[1] == 65535 and r[2] <= port <= r[3] for r in rects)
        elif number in _TYPED:
            inside = any(r[0] <= port <= r[1] and r[2] == 0 and r[3] == 65535 for r in rects)
        else:
            inside = port < 0 and any(r == (0, 65535, 0, 65535) for r in rects)
        if not inside:
            return None
    held = sum(_points(cell).values())
    proposed = [f"{_NAMES.get(number, 'ip')}/{port if number in _PORTED + _TYPED else number}" for number, port in sorted(used)]
    return proposed, held, len(used), len(used) / held if held else 1.0


def propose(rule: Rule, seen: Dict[str, List[str]], blind: Sequence[str], src: Sequence[Interval], src_whole: bool,
            dst: Sequence[Interval], dst_whole: bool, svc: object, svc_whole: bool) -> Proposal:  # fmt: skip
    """The narrower cells of a rule: ``src``, ``dst`` and ``svc`` are what the audit knows the cells hold, ``*_whole``
    whether that is all they hold."""
    out = Proposal(rule)
    for name, cell, whole, key in (("sources", src, src_whole, "source"), ("destinations", dst, dst_whole, "destination")):
        if not whole or key in blind or not seen.get(key):
            continue
        found = addresses(seen[key], cell)
        if found is not None and found[3] < 1:
            out.cells.append(Cell(name, found[0], found[1], found[2], found[3]))
    if svc_whole and "service" not in blind and seen.get("service"):
        found_services = services(seen["service"], svc)
        if found_services is not None and found_services[3] < 1:
            out.cells.append(Cell("services", *found_services))
    return out


def narrowed(rule: Rule, proposal: Proposal) -> Dict[str, List[str]]:
    """What the proposed rule's cells are, by the names the proposal gives them; cells not narrowed stay as they are."""
    cells: Dict[str, List[str]] = {"sources": list(rule.sources), "destinations": list(rule.destinations), "services": list(rule.services)}
    for cell in proposal.cells:
        cells[cell.name] = list(cell.proposed)
    return cells


_PROTOCOLS = {"tcp": Protocol.TCP, "udp": Protocol.UDP, "sctp": Protocol.SCTP, "icmp": Protocol.ICMP, "icmp6": Protocol.ICMP6}


def build(p: Policy, proposals: Sequence[Tuple[Rule, Dict[str, List[str]]]], window: str = "") -> Policy:
    """A policy of the proposed rules alone, with the objects they need, for an emitter to write.

    Each proposed rule is a copy of its rule named ``<name>-narrowed``, with the narrowed cells; it is a new rule, to
    be put where the rule is, after review. The networks and services of the proposal become objects named by
    what they hold ("10.1.2.0/24", "tcp-443"), unless the policy has such an object with another content.
    """
    out = copy.deepcopy(p)
    out.nat_rules = []
    out.rules = []
    for rule, cells in proposals:
        new = copy.deepcopy(rule)
        new.name = new.origin = f"{rule.name}-narrowed"
        new.description = f"narrowed from '{rule.name}' by fwshift usage" + (f", from the logs of {window}" if window else "")
        new.source_ids, new.hits, new.log_usage, new.changed = {}, None, None, None
        new.sources = [_address(out, value) if _span(value) else value for value in cells["sources"]] \
            if cells["sources"] != rule.sources else list(rule.sources)  # fmt: skip
        new.destinations = [_address(out, value) if _span(value) else value for value in cells["destinations"]] \
            if cells["destinations"] != rule.destinations else list(rule.destinations)  # fmt: skip
        if p.lookup_after_dnat and not p.named_translations and rule.nat_added and new.destinations == list(rule.destinations):
            # The pre-NAT addresses the parser added stand for the translated traffic of NAT rules this policy no longer
            # holds: without them they would be destinations of their own, wider than the rule.
            new.destinations = [member for member in rule.destinations if member not in rule.nat_added] or list(rule.destinations)
        new.nat_added = {}
        new.services = [_service(out, value) for value in cells["services"]] if cells["services"] != rule.services else list(rule.services)
        # A narrowed cell lists what was used, inside what the cell matched: it is not negated any more.
        new.negate_source = rule.negate_source and new.sources == list(rule.sources)
        new.negate_destination = rule.negate_destination and new.destinations == list(rule.destinations)
        new.negate_service = rule.negate_service and new.services == list(rule.services)
        out.rules.append(new)
    transform.prune_unused(out)
    return out


def _address(p: Policy, network: str) -> str:
    parsed = ipaddress.ip_network(network, strict=False)
    value = str(parsed)
    name = str(parsed.network_address) if parsed.prefixlen == parsed.max_prefixlen else value  # (a host by its address)
    for existing, address in p.addresses.items():
        if address.kind == AddressKind.NETWORK and _span(address.value) == _span(value):
            return existing  # (an object of the policy that holds just that: no second one)
    for candidate in [name] + [f"{name}-narrow{n if n > 1 else ''}" for n in range(1, 100)]:
        known = p.addresses.get(candidate)
        if candidate in p.address_groups:
            continue
        if known is None:
            p.addresses[candidate] = Address(candidate, AddressKind.NETWORK, value, description="fwshift usage: narrowed")
            return candidate
        if known.kind == AddressKind.NETWORK and _span(known.value) == _span(value):
            return candidate
    raise ValueError(f"no free name for the network {value}")


def _service(p: Policy, text: str) -> str:
    protocol, _, value = text.partition("/")
    number = int(value)
    if protocol in ("tcp", "udp", "sctp"):
        entry = ServiceEntry(_PROTOCOLS[protocol], dst_ports=str(number))
    elif protocol in ("icmp", "icmp6"):
        entry = ServiceEntry(_PROTOCOLS[protocol], icmp_type=number)
    else:
        entry = ServiceEntry(Protocol.IP, ip_protocol=number)
    base = f"{protocol}-{number}"
    for existing, service in p.services.items():
        if service.entries == [entry] and not service.unsupported and not service.builtin:
            return existing
    for candidate in [base] + [f"{base}-narrow{n if n > 1 else ''}" for n in range(1, 100)]:
        known = p.services.get(candidate)
        if candidate in p.service_groups:
            continue
        if known is None:
            p.services[candidate] = Service(candidate, [entry], description="fwshift usage: narrowed")
            return candidate
        if known.entries == [entry]:
            return candidate
    raise ValueError(f"no free name for the service {text}")


__all__ = ["Cell", "MAX_PARTS", "Proposal", "addresses", "build", "narrowed", "propose", "services"]
