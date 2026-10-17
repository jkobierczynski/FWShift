# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The networks behind the zones of a policy, as its source tells them (0.35.0).

A firewall that routes knows where an address lies: behind the interface whose network holds it, or the interface a
static route sends it to, the longest prefix first. The parsers of FortiOS, PAN-OS and the ASA give what they read of
that (the networks of the interfaces, the static routes, the address pools of remote-access VPNs) to ``place``, which
puts each network in the zone of its interface (``Policy.zone_networks``). What needs the networks of the zones (the
targets without zones, an ASA or pfSense target that keeps a rule to its destination zone, ``--compare``) takes them
from there where ``--zone-network`` does not give them (``for_target``).

What the source routes to no zone of the policy is kept as well (``Policy.unzoned_networks``): the networks of an
interface in no zone (management), of one that is down, routes that drop or lead to another router, networks routed by
two zones alike, routes whose next hop leads nowhere known. They are no zone's, and not "everything else" either: the
zone with the default route does not take them (``zone_spaces``), so that an allow for that zone does not reach them.

Of two routes to one network by different zones, the connected one wins, then the one the firewall prefers (its
distance, then its metric). With routing protocols configured, the networks they learn are not known: the default route
is then not taken as "everything else".
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from typing import AbstractSet, Dict, List, Mapping, Optional, Sequence, Tuple

from .netutil import Interval, int_to_ip, interval_text, parse_literal, within
from .report import Report, Severity

_DEFAULTS = {(4, 0, 2**32 - 1), (6, 0, 2**128 - 1)}


@dataclass
class Route:
    """A network, and the interface the firewall sends it to (connected, or a static route)."""

    network: Interval
    interface: str = ""  # '' when the route names only its next hop
    gateway: Optional[Interval] = None  # the next hop, an address
    preference: Tuple[int, int] = (0, 0)  # (distance, metric): lower is preferred
    connected: bool = False
    nowhere: str = ""  # why the network lies behind no zone (a route that drops, an interface that is down), or ''
    table: str = ""  # the routing table (virtual router) it is in; a next hop is looked up in its own table


@dataclass
class Placed:
    """What ``place`` found: the networks of each zone, and those behind no zone of the policy."""

    zones: Dict[str, List[str]]
    unzoned: List[str]


def place(routes: Sequence[Route], zone_of: Mapping[str, str], report: Report, *, partial: str = "",
          unread: Sequence[str] = ()) -> Placed:  # fmt: skip
    """The networks behind each zone: each route's network in the zone of its interface (``zone_of``: interface ->
    zone; an interface in no zone of the policy places its networks behind none). A route that names only its next
    hop leaves by the interface whose network holds that address, or by the route that holds it (in its own table).
    A range (an address pool) is taken as the networks it is made of. ``partial`` says why not every network behind a
    zone is known (routing protocols, zones without layer-3 interfaces): the default routes are then not taken as
    "everything else". Said: what was found (``ZONE_NETWORKS``), networks routed by two zones alike
    (``ZONE_NETWORKS_CONFLICT``), ``partial`` (``ZONE_NETWORKS_PARTIAL``) and ``unread`` (``ZONE_ROUTES_NOT_READ``)."""
    routes = [replace(route, network=piece) for route in routes for piece in _blocks(route.network)]

    def skipped(route: Route) -> bool:
        return bool(partial) and not route.connected and route.network in _DEFAULTS and not route.nowhere

    def rank(route: Route) -> Tuple[int, int, int]:
        return (0 if route.connected else 1, route.preference[0], route.preference[1])

    memo: Dict[int, Route] = {}

    def resolve(route: Route, depth: int = 0) -> Route:
        """The route as the firewall uses it: one that names its next hop only leaves by the interface of the route to
        that address (the longest prefix, in its own table); or by none (``nowhere``)."""
        if route.interface or route.nowhere or route.gateway is None:
            return route
        if id(route) in memo:
            return memo[id(route)]
        gateway = route.gateway
        holders = [r for r in routes if r is not route and r.network != route.network and r.network[0] == gateway[0]
                   and r.network[1] <= gateway[1] <= r.network[2] and not skipped(r)
                   and (not route.table or not r.table or r.table == route.table)]  # fmt: skip
        why = "its next hop leads nowhere known"
        found = Route(route.network, "", None, route.preference, route.connected, why, route.table)
        if holders and depth < 8:
            longest = max(r.network[1] - r.network[2] for r in holders)
            top = [r for r in holders if r.network[1] - r.network[2] == longest]
            best_rank = min(rank(r) for r in top)
            winners = [resolve(r, depth + 1) for r in top if rank(r) == best_rank]
            zones = {"" if w.nowhere else zone_of.get(w.interface, "") for w in winners}
            if len(zones) == 1 and "" not in zones:
                found = Route(route.network, winners[0].interface, None, route.preference, route.connected, "", route.table)
            elif len(zones) > 1:
                found.nowhere = "its next hop is reached by several zones alike"
        memo[id(route)] = found
        return found

    resolved = [(r, resolve(r)) for r in routes]
    lost: List[str] = []  # why networks lie behind no zone, for the note
    unzoned: List[Interval] = []
    aside: Dict[str, List[Interval]] = {}  # interface in no zone of the policy -> its networks
    # network -> zone -> its best (connected?, distance, metric); behind no zone: NUL and why, or NUL NUL and the interface
    best: Dict[Interval, Dict[str, Tuple[int, int, int]]] = {}
    skipped_defaults: List[str] = []
    for original, route in resolved:
        if skipped(original):
            skipped_defaults.append(interval_text(original.network))
            continue
        if route.nowhere:
            zone = "\0" + route.nowhere
        else:
            zone = zone_of.get(route.interface, "") or "\0\0" + (route.interface or "(no interface)")
        held = best.setdefault(route.network, {})
        if zone not in held or rank(route) < held[zone]:
            held[zone] = rank(route)
    out: Dict[str, List[Interval]] = {}
    conflicts: List[str] = []
    for network, zones in best.items():
        ranked = sorted(zones.items(), key=lambda item: item[1])
        if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
            alike = [zone.lstrip("\0") for zone, rank in ranked if rank == ranked[0][1]]
            conflicts.append(f"{interval_text(network)} ({', '.join(alike)})")
            unzoned.append(network)
            continue
        winner = ranked[0][0]
        if winner.startswith("\0\0"):
            unzoned.append(network)
            aside.setdefault(winner[2:], []).append(network)
        elif winner.startswith("\0"):
            unzoned.append(network)
            lost.append(f"{interval_text(network)} ({winner[1:]})")
        else:
            out.setdefault(winner, []).append(network)
    placed = {zone: [interval_text(n) for n in sorted(set(networks))] for zone, networks in sorted(out.items())}
    apart = [interval_text(n) for n in sorted(set(unzoned))]
    if placed or aside or lost:
        report.note(Severity.INFO, "ZONE_NETWORKS",
                    ("the networks behind the zones, from the addresses of their interfaces and the static routes: "
                     + "; ".join(f"{zone}={','.join(networks)}" for zone, networks in placed.items())
                     + ". Targets and --compare that need the networks of the zones take them from here where --zone-network "
                     "does not give them" if placed else "no networks behind the zones of the policy could be told")
                    + _aside(aside) + _lost(lost))  # fmt: skip
    if conflicts:
        report.note(Severity.REVIEW, "ZONE_NETWORKS_CONFLICT",
                    "networks the configuration routes by several zones alike (equal-cost paths), placed behind no zone: "
                    + _listing(conflicts) + ". Give them with --zone-network")  # fmt: skip
    if partial:
        report.note(Severity.REVIEW, "ZONE_NETWORKS_PARTIAL",
                    f"{partial}: not every network behind the zones is known, so the default route"
                    + (f" ({', '.join(sorted(set(skipped_defaults)))})" if skipped_defaults else "")
                    + " is not taken as 'everything behind no other zone'. Give the networks of the zones these lead to with "
                    "--zone-network (the zone of the default route as 0.0.0.0/0,::/0)")  # fmt: skip
    if unread:
        report.note(Severity.INFO, "ZONE_ROUTES_NOT_READ", "routes and interfaces that place no network: " + _listing(unread))
    return Placed(placed, apart)


def _blocks(interval: Interval) -> List[Interval]:
    """The networks (prefixes) a range is made of; a network is itself."""
    version, first, last = interval
    low, high = int_to_ip(version, first), int_to_ip(version, last)
    return [(version, int(n.network_address), int(n.broadcast_address)) for n in ipaddress.summarize_address_range(low, high)]


def _listing(items: Sequence[str], limit: int = 20) -> str:
    return "; ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _aside(aside: Dict[str, List[Interval]]) -> str:
    if not aside:
        return ""
    listed = [f"{interface}={','.join(interval_text(n) for n in sorted(set(networks)))}" for interface, networks in sorted(aside.items())]
    return (". Behind interfaces that are in no zone of the policy, so behind none of its zones (an allow for the zone of "
            "the default route does not reach them): " + _listing(listed, 10))


def _lost(lost: List[str]) -> str:
    return (". Behind no zone: " + _listing(lost, 10)) if lost else ""


def for_target(source: Mapping[str, Sequence[str]], unzoned: Sequence[str], zone_map: Mapping[str, str],
               given: Mapping[str, Sequence[str]], report: Report,
               versions: AbstractSet[int] = frozenset({4, 6})) -> Tuple[Dict[str, List[str]], List[str]]:  # fmt: skip
    """The networks of the zones for a target, and those behind no zone: ``--zone-network`` (``given``, by the names
    after ``--zone-map``), and for the other zones those of the source, renamed and merged by the map. A network of the
    source that ``--zone-network`` gives to another zone is left out (what was given decides); one of a zone that
    ``--zone-network`` gives other networks, and that they do not hold, is behind no zone. Said
    (``ZONE_NETWORKS_FROM_SOURCE``; ``ZONE_NETWORKS_ONE_VERSION`` where the policy has addresses of an IP version
    ``versions`` names that no zone's networks have)."""
    taken: Dict[str, List[str]] = {}
    apart: List[str] = list(unzoned)
    for zone, networks in source.items():
        target = zone_map.get(zone, zone)
        if target in given:
            mine = [i for i in map(parse_literal, given[target]) if i]
            apart += [n for n in networks for i in [parse_literal(n)] if i and not within([i], mine)]
            continue
        listed = taken.setdefault(target, [])
        listed += [n for n in networks if n not in listed]
    claimed = {parse_literal(n) for networks in given.values() for n in networks}
    dropped: List[str] = []
    for zone in list(taken):
        kept = [n for n in taken[zone] if parse_literal(n) not in claimed]
        dropped += [f"{n} ({zone})" for n in taken[zone] if n not in kept]
        if kept:
            taken[zone] = kept
        else:
            del taken[zone]
    apart = [n for n in dict.fromkeys(apart) if parse_literal(n) not in claimed]
    out = {zone: list(networks) for zone, networks in given.items()}
    if not taken and not apart:
        return out, []
    report.note(Severity.INFO, "ZONE_NETWORKS_FROM_SOURCE",
                ("the networks of these zones are taken from the configuration (its interfaces and static routes), as if given with "
                 "--zone-network: " + "; ".join(f"{zone}={','.join(networks)}" for zone, networks in taken.items())
                 if taken else "no networks of the zones are taken from the configuration")
                + (". Behind no zone, as the configuration routes them (no zone's networks hold them): " + _listing(apart, 12) if apart else "")
                + (". Left out, as --zone-network gives them to another zone: " + ", ".join(dropped) if dropped else "")
                + ". --no-source-networks takes none of them")  # fmt: skip
    out.update(taken)
    have = {interval[0] for networks in out.values() for n in networks for interval in [parse_literal(n)] if interval}
    missing = sorted(set(versions) - have)
    if taken and have and missing:
        name = "IPv6" if missing == [6] else "IPv4"
        report.note(Severity.REVIEW, "ZONE_NETWORKS_ONE_VERSION",
                    f"the policy has {name} addresses, and the networks of the zones are all of the other IP version: no {name} "
                    f"address lies behind any zone, so a rule for {name} that is kept to its zones matches nothing (an allow is "
                    f"left out; a deny keeps the addresses no zone holds). Where the firewall passes {name}, give its networks "
                    "with --zone-network")  # fmt: skip
    return out, apart
