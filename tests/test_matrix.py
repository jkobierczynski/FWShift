# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The zone matrix: every packet a policy allows is in it, and where a policy can be read exactly, nothing else.

The oracle is the small world of the audit tests: every packet is walked through the rules, first
match. Per pair of zones it notes which services each allow rule passes that no blocking rule
above it takes, and which services no rule decides. That is what the matrix says it shows.
"""

from __future__ import annotations

import csv
import io
import itertools
import json
import os
import random
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

import pytest
from helpers import DATA
from test_audit import NAMED, World, one_reading, policy, small_model
from test_iptables import Packet

from fwshift import audit, cli, matrix, transform
from fwshift.audit import Services
from fwshift.errors import FwshiftError
from fwshift.matrix import DEFAULT, ELSEWHERE, OTHER
from fwshift.model import ANY, APP_DEFAULT, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, RuleScope
from fwshift.model import Service, ServiceEntry, Zone
from fwshift.netutil import parse_literal
from fwshift.report import Report, Severity

GOLDEN = DATA / "expected"
Pair = Tuple[str, str]


def _inside(services: Services, pkt: Packet) -> bool:
    number = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}.get(pkt.proto) or int(pkt.proto)
    a, b = (pkt.icmp_type, 0) if number in (1, 58) else (pkt.sport, pkt.dport)
    return any(r[0] <= a <= r[1] and r[2] <= b <= r[3] for r in services.of(number))


def _points(world: World, services: Services) -> Set[int]:
    return {index for index, pkt in enumerate(world.services) if _inside(services, pkt)}


class Walk:
    """What a world lets through, per pair of zones as ``place`` names them (None: a packet that is left out)."""

    def __init__(self, world: World, place: Callable[[str, str, str, str], Optional[Pair]]) -> None:
        p = world.p
        self.allowed: Dict[Pair, Dict[str, Set[Tuple[int, int]]]] = {}  # rule -> (application, service) it decides
        self.may: Dict[Pair, Dict[str, Set[int]]] = {}  # rule -> services it matches that no block above it takes
        self.free_inside: Dict[Tuple[Pair, str], Set[int]] = {}  # (cell, zone) -> services no rule decides, inside that zone
        self.free_between: Dict[Pair, Set[int]] = {}
        every = frozenset(range(len(world.services)))
        live = [(index, sets) for index, sets in enumerate(world.rules) if sets is not None]
        sizes = [range(len(world.zones)), range(len(world.addresses)), range(len(world.addresses)), range(len(world.apps)),
                 range(len(world.times))]  # fmt: skip
        for zone in sizes[0]:
            here = [(index, sets) for index, sets in live if zone in sets[0]]
            src_zone, dst_zone = world.zones[zone]
            for src, dst in itertools.product(sizes[1], sizes[2]):
                if world.six[src] != world.six[dst]:
                    continue
                cell = place(src_zone, dst_zone, world.addresses[src], world.addresses[dst])
                if cell is None:
                    continue
                there = [(index, sets) for index, sets in here if src in sets[1] and dst in sets[2]]
                for app, time in itertools.product(sizes[3], sizes[4]):
                    left, blocked = every, frozenset()
                    for index, sets in there:
                        if app not in sets[3] or time not in sets[4]:
                            continue
                        rule = p.rules[index]
                        if rule.action == Action.ALLOW:
                            if sets[5] - blocked:
                                self.may.setdefault(cell, {}).setdefault(rule.name, set()).update(sets[5] - blocked)
                            if sets[5] & left:
                                self.allowed.setdefault(cell, {}).setdefault(rule.name, set()).update((app, s) for s in sets[5] & left)
                        else:
                            blocked = blocked | sets[5]
                        left = left - sets[5]
                    if left and src_zone == dst_zone:
                        self.free_inside.setdefault((cell, src_zone), set()).update(left)
                    elif left:
                        self.free_between.setdefault(cell, set()).update(left)


def _shown(zone: str) -> str:
    return zone if zone in NAMED else OTHER


def _by_zone(src_zone: str, dst_zone: str, src: str, dst: str) -> Optional[Pair]:
    return _shown(src_zone), _shown(dst_zone)


def _random_defaults(p: Policy, rng: random.Random) -> None:
    p.default_interzone = rng.choice([Action.DENY, Action.DENY, Action.DENY, Action.ALLOW])
    p.default_intrazone = rng.choice([Action.ALLOW, Action.DENY])
    for zone in p.zones.values():
        zone.intrazone_allow = rng.choice([None, None, True, False])


def _inside_allowed(p: Policy, zone: str) -> bool:
    known = p.zones.get(zone)
    if known is not None and known.intrazone_allow is not None:
        return known.intrazone_allow
    return p.default_intrazone == Action.ALLOW


def _by_default(p: Policy, walk: Walk) -> Dict[Pair, Set[int]]:
    out: Dict[Pair, Set[int]] = {}
    for (cell, zone), services in walk.free_inside.items():
        if _inside_allowed(p, zone):
            out.setdefault(cell, set()).update(services)
    if p.default_interzone == Action.ALLOW:
        for cell, services in walk.free_between.items():
            out.setdefault(cell, set()).update(services)
    return out


def _entries(m: matrix.Matrix, cell: Pair) -> Dict[str, matrix.Entry]:
    return {entry.rule: entry for entry in m.cell(*cell).entries}


@pytest.mark.parametrize("seed", range(150))
def test_matrix_holds_what_a_policy_allows_and_nothing_else(seed: int) -> None:
    rng = random.Random(seed)
    p = small_model(rng)
    _random_defaults(p, rng)
    m = matrix.build(p)
    world = World(p)
    walk = Walk(world, _by_zone)
    default = _by_default(p, walk)
    deciding = {rule for by_rule in walk.allowed.values() for rule in by_rule}
    if OTHER not in m.zones:
        # The zones nobody names are left out only when no rule reaches them and nothing is open between zones.
        # (That traffic inside such a zone may be allowed by default is then not said: there is no such zone to name.)
        assert not any(OTHER in cell for cell in walk.allowed), seed
        assert p.default_interzone != Action.ALLOW or not any(OTHER in cell for cell in default), seed
    shown = set(m.zones)
    # Every packet that gets through is in its cell, under the rule that let it through.
    for cell, by_rule in walk.allowed.items():
        entries = _entries(m, cell)
        for rule, packets in by_rule.items():
            assert rule in entries, (seed, cell, rule)
            assert {service for _, service in packets} <= _points(world, entries[rule].services), (seed, cell, rule)
    for cell, services in default.items():
        if cell[0] in shown and cell[1] in shown:
            assert DEFAULT in _entries(m, cell) and services <= _points(world, _entries(m, cell)[DEFAULT].services), (seed, cell)
    # And nothing else: a rule is shown with what it passes of the traffic no blocking rule above it takes.
    for cell, held in m.cells.items():
        assert held.entries and cell[0] in shown and cell[1] in shown
        for entry in held.entries:
            points = _points(world, entry.services)
            assert points and not entry.approximate, (seed, cell, entry.rule)
            if entry.rule == DEFAULT:
                assert points == default.get(cell, set()), (seed, cell)
            else:
                assert entry.rule in deciding, (seed, cell, entry.rule)  # a rule that never matches is not in the matrix
                assert points == walk.may.get(cell, {}).get(entry.rule, set()), (seed, cell, entry.rule)
        assert _points(world, held.services) == set().union(*[_points(world, entry.services) for entry in held.entries])


@pytest.mark.parametrize("seed", range(40))
def test_matrix_never_shows_less_than_a_policy_with_unknowns_allows(seed: int) -> None:
    """Host names, applications on their default ports, schedules, criteria the model does not hold: whatever they turn out
    to be, what gets through is in the matrix."""
    rng = random.Random(7000 + seed)
    model = small_model(rng, static=False)
    _random_defaults(model, rng)
    m = matrix.build(model)
    for _ in range(3):
        p = one_reading(model, rng)
        world = World(p, guards=True)
        walk = Walk(world, _by_zone)
        for cell, by_rule in walk.allowed.items():
            entries = _entries(m, cell)
            for rule, packets in by_rule.items():
                assert rule in entries, (seed, cell, rule)
                entry = entries[rule]
                points = _points(world, entry.services)
                for app, service in packets:
                    assert not entry.applications or world.apps[app] in entry.applications, (seed, cell, rule)
                    assert service in points, (seed, cell, rule, world.services[service])
        for cell, services in _by_default(p, walk).items():
            if cell[0] in m.zones and cell[1] in m.zones:
                assert DEFAULT in _entries(m, cell) and services <= _points(world, _entries(m, cell)[DEFAULT].services), (seed, cell)


NETWORKS = {"za": ["10.0.0.0/24"], "zb": ["10.0.1.0/24", "2001:db8::/64"]}


def _network_of(address: str) -> str:
    one = parse_literal(address)
    assert one is not None
    for zone, networks in NETWORKS.items():
        for network in networks:
            net = parse_literal(network)
            assert net is not None
            if net[0] == one[0] and net[1] <= one[1] and one[2] <= net[2]:
                return zone
    return ELSEWHERE


@pytest.mark.parametrize("seed", range(90))
def test_matrix_between_zones_given_as_networks(seed: int) -> None:
    rng = random.Random(9000 + seed)
    p = small_model(rng)
    _random_defaults(p, rng)
    # Not known where the networks lie; each behind a zone of its own; both behind one zone.
    behind = [{}, {"za": ["a"], "zb": ["b"]}, {"za": ["a", "c"], "zb": ["a"]}][seed % 3]
    given = matrix.parse_networks([f"{zone}{'@' + ','.join(behind[zone]) if zone in behind else ''}={','.join(networks)}"
                                   for zone, networks in NETWORKS.items()])  # fmt: skip
    m = matrix.build(p, None, None, given)
    # (Rows for the rest of a zone of the policy come after the zones given: see the tests for them below.)
    assert m.by_network and m.zones[:3] == ["za", "zb", ELSEWHERE] and all(zone.startswith("(") for zone in m.zones[3:])
    assert len(m.zones) == 3 or behind

    def place(src_zone: str, dst_zone: str, src: str, dst: str) -> Optional[Pair]:
        cell = _network_of(src), _network_of(dst)
        # A packet from a network that is said to lie behind zone a does not arrive from zone b.
        if (cell[0] in behind and src_zone not in behind[cell[0]]) or (cell[1] in behind and dst_zone not in behind[cell[1]]):
            return None
        return cell

    world = World(p)
    walk = Walk(world, place)
    for cell, by_rule in walk.allowed.items():
        entries = _entries(m, cell)
        for rule, packets in by_rule.items():
            assert rule in entries and {service for _, service in packets} <= _points(world, entries[rule].services), (seed, cell, rule)
    # By default: between zones wherever that is open; inside a zone only between networks known to lie behind it.
    default: Dict[Pair, Set[int]] = {}
    if p.default_interzone == Action.ALLOW:
        default = {cell: set(services) for cell, services in walk.free_between.items()}
    for (cell, zone), services in walk.free_inside.items():
        if _inside_allowed(p, zone) and zone in behind.get(cell[0], []) and zone in behind.get(cell[1], []):
            default.setdefault(cell, set()).update(services)
    deciding = {rule for by_rule in walk.allowed.values() for rule in by_rule}
    for cell, held in m.cells.items():
        if cell[0] in m.zones[3:] or cell[1] in m.zones[3:]:
            continue
        for entry in held.entries:
            points = _points(world, entry.services)
            assert not entry.approximate
            if entry.default:
                assert points == default.get(cell, set()), (seed, cell)
            elif entry.rule in deciding or not behind:
                assert points == walk.may.get(cell, {}).get(entry.rule, set()), (seed, cell, entry.rule)
    for cell, services in default.items():
        assert services and DEFAULT in _entries(m, cell), (seed, cell)
    noted = any("is not known which zone of the policy they lie behind" in note for note in m.notes)
    assert noted == (len(behind) < 3)  # (elsewhere) is never behind a zone


# -- what it says ----------------------------------------------------------------------------------


def test_services_as_text() -> None:
    def text(*entries: ServiceEntry, without: Optional[List[ServiceEntry]] = None) -> List[str]:
        services = audit._union([s for s in map(audit._entry_services, entries) if s is not None])
        if without is not None:
            services = services.minus(audit._union([s for s in map(audit._entry_services, without) if s is not None]))
        return matrix.service_items(services)

    tcp, udp = Protocol.TCP, Protocol.UDP
    assert text(ServiceEntry(tcp, "443"), ServiceEntry(tcp, "80"), ServiceEntry(udp, "53")) == ["tcp/80", "tcp/443", "udp/53"]
    # Ports that touch become one range; a range inside another is not said twice.
    assert text(ServiceEntry(tcp, "80-90"), ServiceEntry(tcp, "91-100,85"), ServiceEntry(tcp, "8080")) == ["tcp/80-100", "tcp/8080"]
    assert text(ServiceEntry(tcp, "25", "1024-65535"), ServiceEntry(tcp, "443")) == ["tcp/443", "tcp/25 from port 1024-65535"]
    assert text(ServiceEntry(tcp, "25", "1024-65535"), ServiceEntry(tcp, "20-30")) == ["tcp/20-30"]
    assert text(ServiceEntry(tcp), ServiceEntry(udp, "0-65535")) == ["tcp", "udp"]
    assert text(ServiceEntry(Protocol.ICMP, icmp_type=8), ServiceEntry(Protocol.ICMP, icmp_type=0)) == ["icmp type 0", "icmp type 8"]
    assert text(ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4), ServiceEntry(Protocol.ICMP6)) == ["icmp type 3 code 4", "icmp6"]
    assert text(ServiceEntry(Protocol.IP, ip_protocol=47), ServiceEntry(Protocol.IP, ip_protocol=99)) == ["ip/47 (gre)", "ip/99"]
    assert text(ServiceEntry(Protocol.IP)) == ["any"] and text() == []
    assert text(ServiceEntry(Protocol.IP), without=[ServiceEntry(tcp, "23")]) == ["any except tcp/23"]
    assert text(ServiceEntry(tcp), without=[ServiceEntry(tcp, "23")]) == ["tcp/0-22", "tcp/24-65535"]


def test_cell_of_the_grid_fits_its_column() -> None:
    def cell(*services: str, approximate: bool = False, applications: Optional[List[str]] = None) -> matrix.Cell:
        held = audit._union([s for s in map(audit._spec_services, services) if s is not None])
        return matrix.Cell("a", "b", [matrix.Entry("r", "r", "any", "any", held, applications or [], approximate=approximate)])

    assert cell("tcp/80", "tcp/443").brief(16) == "tcp/80 tcp/443"
    assert cell("tcp/80", "tcp/443", "udp/53", "tcp/8080").brief(16) == "tcp/80 +3"
    assert cell("tcp/80", "tcp/443", "udp/53", "tcp/8080").brief(24) == "tcp/80 tcp/443 +2"
    assert cell("tcp/80", approximate=True).brief(16) == "tcp/80~"
    assert cell("udp/34962-34964", "tcp/1").brief(12) == "tcp/1 +1" and cell("udp/34962-34964", "udp/40000-40010").brief(12) == "udp/3496… +1"
    assert cell(applications=["web-browsing"]).brief(16) == "app:web-browsing" and cell(applications=["web-browsing", "ssl"]).brief(16) == "app:web-brow… +1"
    for width in range(8, 30):
        for one in (cell("tcp/80", "tcp/443", "udp/53", "tcp/8080", approximate=True), cell(applications=["a-very-long-application", "b"])):
            assert len(one.brief(width)) <= max(width, 9), (width, one.brief(width))
    everything = matrix.Cell("a", "b", [matrix.Entry("r", "r", "any", "any", audit._ALL_SERVICES)])
    assert everything.brief(16) == "any" and everything.everything


def test_rules_of_a_conduit() -> None:
    p = policy(
        Rule("no-telnet", ["inside"], ["dmz"], services=["telnet"], action=Action.DROP),
        Rule("to-dmz", ["inside"], ["dmz"], ["lan"], ["web"]),
        Rule("web-in", ["outside"], ["dmz"], destinations=["web"], services=["https"]),
        Rule("never", ["outside"], ["dmz"], ["lan"], ["web"], ["https"]),
        Rule("off", ["outside"], ["inside"]),
        Rule("plc", ["inside"], ["dmz"], ["10.10.7.15"], ["10.20.0.0/24"], ["modbus", "telnet"]),
        Rule("by-app", ["dmz"], ["outside"], applications=["ssl", "telnet"], services=[APP_DEFAULT]),
        Rule("by-name", ["dmz"], ["outside"], ["site"], services=["https"]),
        Rule("users", [ANY], ["outside"], services=["high"]),
    )
    p.rules[4].enabled = False
    p.rules[8].users, p.rules[8].schedule = ["alice", "bob"], "office-hours"
    m = matrix.build(p)
    assert m.zones == ["inside", "outside", "dmz", OTHER] and (m.rules, m.disabled, m.dead) == (9, 1, 1)
    held = m.cell("inside", "dmz")
    assert [entry.rule for entry in held.entries] == ["to-dmz", "plc"]
    # What the blocking rule above it takes is not allowed by the rule below.
    assert held.entries[0].what() == "any except tcp/23" and held.entries[1].what() == "tcp/502"
    assert (held.entries[0].sources, held.entries[0].destinations) == ("lan", "web") and not held.everything
    assert held.entries[1].industrial == ["modbus"] and not held.entries[1].risky
    assert not m.cell("outside", "inside").entries and [entry.rule for entry in m.cell("outside", "dmz").entries] == ["web-in"]
    out = m.cell("dmz", "outside")
    assert [(entry.rule, entry.what(), entry.approximate) for entry in out.entries] == [
        ("by-app", "applications ssl, telnet on their default ports", False),
        ("by-name", "tcp/443", True),  # from a host name: which addresses is not known
        ("users", "tcp/1024-65535", False),
    ]
    assert out.entries[0].risky == ["telnet"] and out.entries[2].conditions == ["users alice, bob", "schedule office-hours"]
    assert out.items() == ["tcp/443", "tcp/1024-65535", "app:ssl", "app:telnet"] and out.approximate
    # A rule from any zone is in the row of every zone, also of those nobody names, and inside 'outside' itself.
    assert [zone for zone in m.zones if "users" in _entries(m, (zone, "outside"))] == ["inside", "outside", "dmz", OTHER]
    text = m.to_text()
    assert "inside -> dmz\n  allowed: any except tcp/23\n  industrial protocols: modbus (rule 'plc')\n" in text
    assert "  rule 'to-dmz': lan -> web: any except tcp/23\n  rule 'plc': 10.10.7.15 -> 10.20.0.0/24: tcp/502\n" in text
    assert "  rule 'users': any -> any: tcp/1024-65535 (users alice, bob; schedule office-hours)\n" in text
    assert "  rule 'by-name': site -> any: tcp/443 ~\n" in text and "1 rule(s) never match and are left out" in text
    assert "rule 'plc':" not in m.to_text(summary=True) and "industrial protocols: modbus (rule 'plc')" in m.to_text(summary=True)
    assert f"{OTHER}: zones the policy does not name" in text


def test_what_cannot_be_read_is_named_not_left_out() -> None:
    p = policy(
        Rule("social", ["inside"], ["outside"], ["lan"], services=["https", "Facebook"]),
        Rule("vpn", ["inside"], ["outside"], ["lan"], ["web"]),
        Rule("loose", ["inside"], ["dmz"], ["lan"], ["web"], ["https"]),
        Rule("not-those", ["inside"], ["dmz"], ["lan"], ["corp"], ["Facebook"]),
    )
    p.services["Facebook"] = Service("Facebook", [], unsupported="an application of the vendor")
    p.rules[1].unsupported = ["VPN community match Partner-VPN"]
    p.rules[3].negate_service = True
    report = Report()
    report.add("rule", "loose", Severity.APPROX, "DEVICE_TARGET", "installed on one gateway only")
    m = matrix.build(p, None, report)
    social, vpn = m.cell("inside", "outside").entries
    # A service that cannot be read is named: the rule is not shown as open for everything, and not left out either.
    assert social.what() == "tcp/443, service 'Facebook' (not read)" and social.approximate and not social.everything
    assert social.services.everything()  # for whoever asks the matrix what could get through
    assert m.cell("inside", "outside").items() == ["any"]  # 'vpn' is for any service
    assert vpn.conditions == ["only with VPN community match Partner-VPN, which is not in the model"] and vpn.approximate
    loose, negated = m.cell("inside", "dmz").entries
    assert loose.approximate and loose.what() == "tcp/443"
    assert negated.what() == "any" and negated.approximate and not negated.unread  # "not something unknown" may be anything
    text = m.to_text()
    assert "svc:NAME: a service of the source that could not be read" in text and "~ at most this." in text
    assert "allowed: tcp/443, svc:Facebook ~" not in text and "  allowed: any ~\n" in text


def test_default_of_the_policy() -> None:
    p = policy(Rule("no-smb", ["inside"], ["inside"], services=["telnet"], action=Action.DROP), Rule("out", ["inside"], ["outside"]))
    p.default_intrazone = Action.ALLOW
    p.zones["dmz"].intrazone_allow = False
    m = matrix.build(p)
    assert m.zones == ["inside", "outside", "dmz"]  # nothing reaches a zone nobody names
    assert [(e.rule, e.what()) for e in m.cell("inside", "inside").entries] == [(DEFAULT, "any except tcp/23")]
    assert [(e.rule, e.what()) for e in m.cell("outside", "outside").entries] == [(DEFAULT, "any")]
    assert not m.cell("dmz", "dmz").entries and not m.cell("outside", "inside").entries
    assert "inside -> inside (inside the zone)\n  allowed: any except tcp/23\n  by default, what no rule decides: any except tcp/23\n" in m.to_text()
    # A rule that decides everything leaves nothing to the default.
    p.rules.append(Rule("clean-up", action=Action.DROP))
    p.rules[-1].origin = "clean-up"
    assert set(matrix.build(p).cells) == {("inside", "outside")}
    # Open between zones: every pair of zones, also those nobody names.
    q = policy(Rule("no-telnet", services=["telnet"], action=Action.DROP))
    q.default_interzone = Action.ALLOW
    m = matrix.build(q)
    assert m.zones == ["inside", "outside", "dmz", OTHER] and len(m.cells) == 13
    assert all(held.entries[0].what() == "any except tcp/23" for held in m.cells.values())
    assert (OTHER, OTHER) in m.cells and ("inside", "inside") not in m.cells


def test_nothing_to_show_and_no_zones() -> None:
    p = Policy(vendor="checkpoint")
    assert matrix.build(p).to_text() == "Nothing to show: no rule of the policy allows anything, and nothing is allowed by default.\n"
    rule = Rule("web", services=["https"])
    rule.origin = "web"
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.rules.append(rule)
    m = matrix.build(p)
    assert m.zones == [OTHER] and "The policy names no zones, so the matrix has one cell" in m.to_text()
    given = matrix.parse_networks(["lan=10.10.0.0/16", "dmz=10.20.0.0/24"])
    assert matrix.build(p, None, None, given).cell("lan", "dmz").items() == ["tcp/443"]


# -- zones given as networks -----------------------------------------------------------------------


def test_network_zones_from_the_command_line() -> None:
    given = matrix.parse_networks(["office@trust=10.10.0.0/16, 2001:db8:10::/48", "plant @ ot , ot2 = 10.30.0.0-10.30.9.255", "office=10.11.0.0/16"])
    assert given["office"].networks == ["10.10.0.0/16", "2001:db8:10::/48", "10.11.0.0/16"] and given["office"].behind == ["trust"]
    assert given["plant"].behind == ["ot", "ot2"] and matrix.parse_networks([]) == {}
    for bad in ("office", "=10.0.0.0/8", "office=", "office=10.0.0.0/8,,", "office=ten", "(elsewhere)=10.0.0.0/8", "any=10.0.0.0/8", "a\tb=10.0.0.0/8"):
        with pytest.raises(FwshiftError):
            matrix.parse_networks([bad])
    p = policy(Rule("r"))
    with pytest.raises(FwshiftError, match="10.10.0.0/16 is in zone 'a' and in zone 'b'"):
        matrix.build(p, None, None, matrix.parse_networks(["a=10.10.0.0/16", "b=10.10.0.0/16"]))
    with pytest.raises(FwshiftError, match="10.10.128.0/17 is in zone 'a' and in zone 'b'"):
        matrix.build(p, None, None, matrix.parse_networks(["a=10.10.0.0/16", "b=10.10.128.0-10.11.0.255"]))
    # A zone the policy does not name is not refused (an interface without a rule is not in an iptables ruleset): it is
    # one of the zones nobody names, a rule for any zone is for it, and a note asks to check the spelling.
    m = matrix.build(p, None, None, matrix.parse_networks(["a@trust=10.10.0.0/16", "b@dmz=10.20.0.0/24"]))
    assert [e.rule for e in m.cell("a", "b").entries] == ["r"]
    assert any(note.startswith("The policy names no zone 'trust' (it names inside, outside, dmz): only rules for 'any' zone") for note in m.notes)
    q = policy(Rule("r", ["inside"], ["dmz"]))
    assert ("a", "b") not in matrix.build(q, None, None, matrix.parse_networks(["a@trust=10.10.0.0/16", "b@dmz=10.20.0.0/24"])).cells


def test_smaller_network_decides_and_the_rest_is_elsewhere() -> None:
    p = policy(Rule("lan-out", sources=["lan"], destinations=["192.0.2.0/24"], services=["https"]),
               Rule("servers", sources=["10.10.5.0/24"], destinations=["web"], services=["telnet"]))  # fmt: skip
    m = matrix.build(p, None, None, matrix.parse_networks(["office=10.10.0.0/16", "servers=10.10.5.0/24", "dmz=10.20.0.0/24"]))
    assert m.zones == ["office", "servers", "dmz", ELSEWHERE]
    assert {cell: [e.rule for e in held.entries] for cell, held in m.cells.items()} == {
        ("office", ELSEWHERE): ["lan-out"], ("servers", ELSEWHERE): ["lan-out"], ("servers", "dmz"): ["servers"],
    }  # fmt: skip
    assert m.cell("servers", "dmz").entries[0].risky == ["telnet"]
    # With a zone for everything else there is no 'elsewhere'.
    m = matrix.build(p, None, None, matrix.parse_networks(["office=10.10.0.0/16", "internet=0.0.0.0/0,::/0"]))
    assert m.zones == ["office", "internet"] and set(m.cells) == {("office", "internet")}
    text = m.to_text()
    assert "  office: 10.10.0.0/16\n  internet: 0.0.0.0/0, ::/0\n  (of two networks, one inside the other, the smaller one decides)\n" in text


def test_network_zone_behind_a_zone_of_the_policy() -> None:
    p = policy(
        Rule("web-out", ["inside"], ["outside"], services=["https"]),
        Rule("to-web", ["inside"], ["dmz"], destinations=["web"], services=["https"]),
        Rule("from-dmz", ["dmz"], ["outside"], services=["telnet"]),
    )
    p.default_intrazone = Action.ALLOW
    loose = matrix.build(p, None, None, matrix.parse_networks(["office=10.10.0.0/16", "plant=10.30.0.0/16", "servers=10.20.0.0/24"]))
    # Not known where the networks lie: a rule for any address is in every row and column it could be.
    assert [zone for zone in loose.zones if "web-out" in _entries(loose, ("plant", zone))] == ["office", "plant", "servers", ELSEWHERE]
    assert "For office, plant, servers, (elsewhere) it is not known which zone of the policy they lie behind" in loose.notes[0]
    assert any("Traffic inside every zone of the policy that no rule decides is allowed" in note for note in loose.notes)
    assert not any(DEFAULT in _entries(loose, cell) for cell in loose.cells)
    tied = matrix.build(p, None, None, matrix.parse_networks(
        ["office@inside=10.10.0.0/16", "plant@inside=10.30.0.0/16", "servers@dmz=10.20.0.0/24", "internet@outside=0.0.0.0/0,::/0"]))  # fmt: skip
    rules = {cell: [e.rule for e in held.entries] for cell, held in tied.cells.items()}
    assert rules == {
        ("office", "internet"): ["web-out"], ("plant", "internet"): ["web-out"], ("office", "servers"): ["to-web"],
        ("plant", "servers"): ["to-web"], ("servers", "internet"): ["from-dmz"],
        # Two networks behind one zone: what the firewall lets pass inside that zone.
        ("office", "office"): [DEFAULT], ("office", "plant"): [DEFAULT], ("plant", "office"): [DEFAULT], ("plant", "plant"): [DEFAULT],
        ("servers", "servers"): [DEFAULT], ("internet", "internet"): [DEFAULT],
    }  # fmt: skip
    assert not any("is not known which zone" in note for note in tied.notes)
    assert "  office: 10.10.0.0/16 (behind zone inside of the policy)\n" in tied.to_text()


def _with_nat(vendor: str, after_dnat: bool) -> Policy:
    p = policy(Rule("web-in", ["outside"], ["dmz"], destinations=["web-public"] if not after_dnat else ["web", "web-public"],
                    services=["https"]), vendor=vendor)  # fmt: skip
    p.addresses["web-public"] = Address("web-public", AddressKind.NETWORK, "203.0.113.10/32")
    nat = NatRule("publish", ["outside"], ["outside"], destinations=["web-public"], destination_translation=DestNat("web"))
    nat.origin = "publish"
    p.nat_rules.append(nat)
    if after_dnat:
        p.lookup_after_dnat = True
        p.rules[0].nat_added = {"web-public": ["publish"]}
    return p


def test_published_server_is_shown_where_the_server_is() -> None:
    given = matrix.parse_networks(["dmz=10.20.0.0/24", "office=10.10.0.0/16"])
    # A source that matches before destination NAT: the rule names the public address, the traffic ends at the server.
    m = matrix.build(_with_nat("panos", False), None, None, given)
    assert set(m.cells) == {(src, dst) for src in ("dmz", "office", ELSEWHERE) for dst in ("dmz", ELSEWHERE)}
    assert m.cell(ELSEWHERE, "dmz").entries[0].through_nat == ["publish"] and not m.cell(ELSEWHERE, ELSEWHERE).entries[0].through_nat
    assert "rule 'web-in': any -> web-public: tcp/443 (through NAT rule publish)" in m.to_text()
    assert any("1 destination NAT rule(s): this source matches its rules on the address before translation" in note for note in m.notes)
    # A source that matches after it: the rule is for the server, the address the parser added is not what it matched.
    m = matrix.build(_with_nat("iptables", True), None, None, given)
    assert set(m.cells) == {(src, "dmz") for src in ("dmz", "office", ELSEWHERE)}
    assert m.cell(ELSEWHERE, "dmz").entries[0].destinations == "web" and not m.cell(ELSEWHERE, "dmz").entries[0].through_nat
    assert any("matches its rules after destination NAT" in note for note in m.notes)
    # Between the zones of the policy the destination zone says it either way.
    assert set(matrix.build(_with_nat("panos", False)).cells) == set(matrix.build(_with_nat("iptables", True)).cells) == {("outside", "dmz")}


def test_fortios_virtual_ip_in_a_policy() -> None:
    conf = (
        'config firewall vip\n    edit "vip-web"\n        set extip 203.0.113.10\n        set mappedip "10.20.0.10"\n'
        '        set extintf "wan1"\n    next\nend\n'
        "config firewall policy\n"
        '    edit 1\n        set name "web-in"\n        set srcintf "wan1"\n        set dstintf "dmz"\n        set action accept\n'
        '        set srcaddr "all"\n        set dstaddr "vip-web"\n        set schedule "always"\n        set service "HTTPS"\n    next\n'
        '    edit 2\n        set name "no-vip"\n        set srcintf "lan"\n        set dstintf "dmz"\n        set action deny\n'
        '        set srcaddr "all"\n        set dstaddr "vip-web"\n        set schedule "always"\n        set service "ALL"\n    next\n'
        '    edit 3\n        set name "lan-to-dmz"\n        set srcintf "lan"\n        set dstintf "dmz"\n        set action accept\n'
        '        set srcaddr "all"\n        set dstaddr "all"\n        set schedule "always"\n        set service "HTTPS"\n    next\nend\n'
    )
    report = Report()
    p = cli.load(conf.encode(), "fortios", report)
    m = matrix.build(p, None, report, matrix.parse_networks(["dmz=10.20.0.0/24"]))
    # The policy for the virtual IP allows the traffic it translates: that ends in the DMZ, and nowhere else.
    assert [cell for cell, held in m.cells.items() if "web-in" in [e.rule for e in held.entries]] == [("dmz", "dmz"), (ELSEWHERE, "dmz")]
    assert m.cell(ELSEWHERE, "dmz").entries[0].destinations == "vip-web"
    # A blocking policy for a virtual IP blocks less than "everything to that server": nothing is taken out on its word.
    assert [e.what() for e in matrix.build(p, None, report).cell("lan", "dmz").entries] == ["tcp/443"]


# -- the command -----------------------------------------------------------------------------------

SAMPLES = ["asa_sample.cfg", "checkpoint_sample.json", "fortios_sample.conf", "iptables_sample.rules", "panos_sample.xml",
           "sophos_sample.xml", "fmc_sample.json", "fdm_sample.txt", "pfsense_sample.xml", "sonicwall_sample.exp",
           "watchguard_sample.xml", "barracuda_sample.json",
           "junos_sample.conf", "nftables_sample.nft", "nsx_sample.json", "aws_sample.json", "azure_sample.json",
           "routeros_sample.rsc", "opnsense_sample.xml", "forcepoint_sample.json"]  # fmt: skip


@pytest.mark.parametrize("sample", SAMPLES)
def test_matrix_of_the_samples(sample: str, tmp_path: Path) -> None:
    out = tmp_path / "matrix.txt"
    assert cli.main(["matrix", str(DATA / sample), "-o", str(out)]) == 0
    golden = GOLDEN / (sample.rsplit(".", 1)[0] + ".matrix.txt")
    if os.environ.get("FWSHIFT_UPDATE_GOLDEN"):
        golden.write_text(out.read_text(encoding="utf-8"), encoding="utf-8")
    assert out.read_text(encoding="utf-8") == golden.read_text(encoding="utf-8")
    # The other forms hold the same conduits.
    as_json, as_csv = tmp_path / "matrix.json", tmp_path / "matrix.csv"
    assert cli.main(["matrix", str(DATA / sample), "-o", str(as_json), "--json"]) == 0
    assert cli.main(["matrix", str(DATA / sample), "-o", str(as_csv), "--csv"]) == 0
    data = json.loads(as_json.read_text(encoding="utf-8"))
    rows = list(csv.DictReader(io.StringIO(as_csv.read_text(encoding="utf-8"))))
    pairs = [(conduit["from"], conduit["to"], rule["rule"]) for conduit in data["conduits"] for rule in conduit["rules"]]
    assert pairs and [(row["from"], row["to"], row["rule"]) for row in rows] == pairs
    assert data["zones_are"] == "the zones of the policy" and data["source"] == sample.split("_")[0]
    text = out.read_text(encoding="utf-8")
    assert all(f"{conduit['from']} -> {conduit['to']}" in text for conduit in data["conduits"])


def test_matrix_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sample = str(DATA / "panos_sample.xml")
    zones = ["--network-zone", "office@trust=10.10.0.0/16", "--network-zone", "plant@ot=10.30.0.0/16"]
    assert cli.main(["matrix", sample, "--summary"] + zones) == 0
    text = capsys.readouterr().out
    assert text.startswith("FWShift zone matrix\n  source: panos (vsys1)\n  security rules: 14 (1 disabled, 0 never match)\n\nZones (given as networks)\n")
    assert "office -> plant\n  allowed: app:modbus, app:siemens-s7\n  industrial protocols: modbus (rule 'Engineering to PLCs')" in text
    assert "rule 'Engineering to PLCs': eng-station" not in text
    assert cli.main(["matrix", sample, "--json"] + zones) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["zones"] == ["office", "plant", ELSEWHERE] and data["behind"] == {"office": ["trust"], "plant": ["ot"]}
    conduit = next(c for c in data["conduits"] if (c["from"], c["to"]) == ("office", "plant"))
    assert conduit["allowed"] == ["app:modbus", "app:siemens-s7"] and conduit["rules"][0]["industrial"] == ["modbus", "siemens-s7"]
    # The lists of the audit configuration are the lists of the matrix.
    config = tmp_path / "audit.json"
    config.write_text(json.dumps({"applications": {"industrial": ["siemens-s7"]}}), encoding="utf-8")
    assert cli.main(["matrix", sample, "--json", "--audit-config", str(config)] + zones) == 0
    data = json.loads(capsys.readouterr().out)
    assert next(c for c in data["conduits"] if (c["from"], c["to"]) == ("office", "plant"))["rules"][0]["industrial"] == ["siemens-s7"]
    for bad in (["--json", "--csv"], ["--network-zone", "office"], ["--network-zone", "office@=10.10.0.0/16"],
                ["--network-zone", "a=10.0.0.0/8", "--network-zone", "b=10.0.0.0/8"], ["--audit-config", str(tmp_path / "none.json")]):  # fmt: skip
        assert cli.main(["matrix", sample] + bad) == 1, bad
        assert capsys.readouterr().err.startswith("fwshift: error: "), bad


def test_csv_is_no_formula_and_names_stay_on_their_line(tmp_path: Path) -> None:
    p = policy(Rule("=cmd|' /C calc'!A0", ["inside"], ["outside"], ["lan"], services=["https"]), Rule("+1", ["inside"], ["outside"], ["web"]))
    rows = list(csv.reader(io.StringIO(matrix.build(p).to_csv())))
    assert rows[0][:3] == ["from", "to", "rule"] and [row[2] for row in rows[1:]] == ["'=cmd|' /C calc'!A0", "'+1"]
    # Through the command a name from the input cannot start a line of its own.
    source = tmp_path / "in.rules"
    source.write_text('*filter\n:FORWARD DROP [0:0]\n-A FORWARD -i eth0 -o eth1 -p tcp --dport 443 -m comment --comment "a\\nallowed: any" -j ACCEPT\n'
                      "COMMIT\n", encoding="utf-8")  # fmt: skip
    out = tmp_path / "matrix.txt"
    assert cli.main(["matrix", str(source), "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").count("allowed: ") == 2 and "\n  allowed: tcp/443\n" in out.read_text(encoding="utf-8")


def test_matrix_of_a_large_policy() -> None:
    import time

    rng = random.Random(5)
    p = Policy(vendor="panos")
    for index in range(30):
        p.zones[f"z{index}"] = Zone(f"z{index}")
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.address_groups["servers"] = AddressGroup("servers", ["10.200.0.0/16"])
    for index in range(2000):
        rule = Rule(f"r{index}", [f"z{rng.randrange(30)}"], [ANY] if index % 50 == 0 else [f"z{rng.randrange(30)}"],
                    [f"10.{rng.randrange(200)}.{rng.randrange(250)}.0/24"], [rng.choice(["servers", ANY, f"10.{rng.randrange(200)}.0.0/16"])],
                    [rng.choice(["https", ANY])], action=rng.choice([Action.ALLOW, Action.ALLOW, Action.DROP]))  # fmt: skip
        rule.origin = rule.name
        rule.scope = RuleScope.UNIVERSAL
        p.rules.append(rule)
    start = time.perf_counter()
    m = matrix.build(p)
    assert time.perf_counter() - start < 60
    assert len(m.zones) == 31 and len(m.cells) > 500 and len(m.to_text().splitlines()) > 1000


# -- found in review ---------------------------------------------------------------------------------

TIED = ["internet@outside=0.0.0.0/0,::/0", "servers@dmz=10.20.0.0/24", "office@inside=10.10.0.0/16"]


def _published(nat: NatRule, *more: Rule) -> Policy:
    p = policy(Rule("web", ["outside"], ["dmz"], destinations=["pub1"], services=["https"]), *more)
    for name, value in (("pub1", "203.0.113.10/32"), ("pub2", "203.0.113.11/32"), ("srv2", "10.20.0.11/32")):
        p.addresses[name] = Address(name, AddressKind.NETWORK, value)
    p.addresses["by-name"] = Address("by-name", AddressKind.FQDN, "web.example.com")
    nat.origin = nat.name
    p.nat_rules.append(nat)
    return p


def test_rule_for_a_published_address_is_shown_whatever_the_shape_of_its_nat_rule() -> None:
    from fwshift.model import SnatKind, SourceNat

    given = matrix.parse_networks(TIED)
    shapes = {
        "one address": (NatRule("n", ["outside"], ["outside"], destinations=["pub1"], destination_translation=DestNat("web")), False),
        "two published addresses": (NatRule("n", ["outside"], ["outside"], destinations=["pub1", "pub2"],
                                            destination_translation=DestNat("web")), False),  # fmt: skip
        "to a host name": (NatRule("n", ["outside"], ["outside"], destinations=["pub1"], destination_translation=DestNat("by-name")), True),
        "published as any": (NatRule("n", ["outside"], ["outside"], destination_translation=DestNat("web")), False),
        "static, two servers both ways": (NatRule("n", ["dmz"], ["outside"], sources=["web", "srv2"], source_translation=SourceNat(
            SnatKind.STATIC, ["203.0.113.10-203.0.113.11"], bidirectional=True)), False),  # fmt: skip
    }
    for shape, (nat, unsure) in shapes.items():
        m = matrix.build(_published(nat), None, None, given)
        assert m.zones == ["internet", "servers", "office"] and not m.not_shown, shape
        entries = m.cell("internet", "servers").entries
        assert [(e.rule, e.through_nat, e.approximate) for e in entries] == [("web", ["n"], unsure)], shape
        assert ("internet", "internet") not in m.cells, shape  # the published address is not where the traffic ends
    # A NAT rule that is switched off translates nothing: the rule names an address that is not in the DMZ given.
    nat = NatRule("n", ["outside"], ["outside"], destinations=["pub1"], destination_translation=DestNat("web"), enabled=False)
    m = matrix.build(_published(nat), None, None, given)
    assert m.zones == ["internet", "servers", "office", "(dmz: other addresses)"] and not m.not_shown
    assert [e.rule for e in m.cell("internet", "(dmz: other addresses)").entries] == ["web"] and ("internet", "servers") not in m.cells
    assert any(note.startswith("(ZONE: other addresses): traffic of zone ZONE of the policy at addresses that are in none") for note in m.notes)
    assert "internet -> (dmz: other addresses)\n  allowed: tcp/443\n  rule 'web': any -> pub1: tcp/443\n" in m.to_text()


def test_rule_that_fits_no_zone_given_is_not_left_out() -> None:
    p = policy(
        Rule("guests-out", ["guest"], ["outside"], services=["https"]),  # nothing given lies behind zone guest
        Rule("odd", ["inside"], ["dmz"], ["10.20.0.5"], ["web"], ["telnet"]),  # from a server address, in zone inside
        Rule("normal", ["inside"], ["dmz"], ["lan"], ["web"], ["https"]),
        Rule("any-in", ["inside"], ["dmz"], destinations=["web"], services=["modbus"]),
    )
    m = matrix.build(p, None, None, matrix.parse_networks(TIED))
    assert m.zones == ["internet", "servers", "office", "(guest: other addresses)", "(inside: other addresses)"]
    assert {cell: [e.rule for e in held.entries] for cell, held in m.cells.items()} == {
        ("(guest: other addresses)", "internet"): ["guests-out"],
        ("(inside: other addresses)", "servers"): ["odd"],
        # A rule for any source is for the networks given behind its zone: nothing says there are others.
        ("office", "servers"): ["normal", "any-in"],
    }
    assert not m.not_shown and not any(e.approximate for held in m.cells.values() for e in held.entries)
    assert "(inside: other addresses) -> servers\n  allowed: tcp/23\n" in m.to_text()
    # Nothing given behind a zone of the policy: all of that zone is its own row, rules for any address and published
    # servers included (the server's address lies, by the networks given, somewhere the rule is not for).
    sample = Report()
    pan = cli.load((DATA / "panos_sample.xml").read_bytes(), "panos", sample)
    m = matrix.build(pan, None, sample, matrix.parse_networks(["office@trust=10.10.0.0/16", "plant@ot=10.30.0.0/16", "internet@untrust=0.0.0.0/0,::/0"]))
    assert m.zones == ["office", "plant", "internet", "(dmz: other addresses)"] and not m.not_shown
    assert [e.rule for e in m.cell("(dmz: other addresses)", "internet").entries] == ["Allow-DNS", "Tagged-Servers-Updates"]
    assert [e.rule for e in m.cell("internet", "(dmz: other addresses)").entries] == ["Inbound-Web", "Inbound-Mail"]
    assert "Allow-DNS" in _entries(m, ("office", "internet"))
    # A rule with an address that fits and one that does not is shown for both.
    mixed = policy(Rule("mixed", ["inside"], ["dmz"], ["lan", "10.20.0.5"], ["web"], ["https"]))
    assert set(matrix.build(mixed, None, None, matrix.parse_networks(TIED)).cells) == {
        ("office", "servers"), ("(inside: other addresses)", "servers")}  # fmt: skip
    # Without a zone for it there is still 'elsewhere'; with every address given away and nothing behind the zone, a note.
    loose = matrix.build(p, None, None, matrix.parse_networks(["servers@dmz=10.20.0.0/24", "office@inside=10.10.0.0/16"]))
    assert [e.rule for e in loose.cell(ELSEWHERE, ELSEWHERE).entries] == ["guests-out"]
    q = policy(Rule("r", ["inside"], ["dmz"], ["lan"], ["web"], ["https"]))
    nowhere = matrix.build(q, None, None, matrix.parse_networks(["all@outside=0.0.0.0/0,::/0"]))
    assert not nowhere.not_shown
    assert [e.rule for e in nowhere.cell("(inside: other addresses)", "(dmz: other addresses)").entries] == ["r"]


def test_what_the_parser_did_not_read_is_said_with_the_matrix(tmp_path: Path) -> None:
    conf = (
        "config firewall policy6\n    edit 1\n        set srcintf \"wan\"\n        set dstintf \"dmz\"\n        set action accept\n"
        "        set srcaddr \"all\"\n        set dstaddr \"all\"\n        set schedule \"always\"\n        set service \"ALL\"\n    next\nend\n"
        'config firewall policy\n    edit 1\n        set name "nothing"\n        set srcintf "wan"\n        set dstintf "dmz"\n'
        '        set action deny\n        set srcaddr "all"\n        set dstaddr "all"\n        set schedule "always"\n        set service "ALL"\n'
        "    next\nend\n"
    )
    source, out = tmp_path / "in.conf", tmp_path / "matrix.txt"
    source.write_text(conf, encoding="utf-8")
    assert cli.main(["matrix", str(source), "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "  none: no rule that was read allows anything between these zones\n" in text
    assert "\nFrom reading the configuration\n  TABLE_NOT_CONVERTED: 'config firewall policy6' has entries and is not converted\n" in text
    assert cli.main(["matrix", str(source), "-o", str(out), "--json"]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["from_reading"] == ["TABLE_NOT_CONVERTED: 'config firewall policy6' has entries and is not converted"]
    # A rule the parser left out is named.
    report = Report()
    report.skip("rule", "odd-one", "NOT_READ", "a rule of a kind this parser does not read")
    m = matrix.build(policy(Rule("r")), None, report)
    assert m.not_read == ["odd-one"] and "Not in the matrix\n  1 rule(s) of the source could not be read; what they allow is not shown: 'odd-one'" in m.to_text()


def test_default_of_an_iptables_ruleset_is_for_its_ip_version(tmp_path: Path) -> None:
    source, out = tmp_path / "in.rules", tmp_path / "matrix.txt"
    source.write_text("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
                      "-A FORWARD -i eth0 -o eth2 -p tcp -m tcp --dport 23 -j DROP\n-A FORWARD -i eth0 -o eth2 -p udp -j DROP\nCOMMIT\n",
                      encoding="utf-8")  # fmt: skip
    assert cli.main(["matrix", str(source), "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    # (What the IPv6 ruleset of the host does is not in this file: it does not make "any" of what IPv4 drops.)
    assert "eth0 -> eth2\n  allowed: any except tcp/23, udp\n  by default, what no rule decides: any except tcp/23, udp\n" in text
    assert "eth2 -> eth0\n  allowed: any\n" in text
    assert "An iptables ruleset is for one IP version, here IPv4: the matrix says nothing about the other." in text


def test_fortios_blocking_policy_for_the_same_virtual_ip_takes_its_part() -> None:
    def conf(blocked: str) -> str:
        return (
            'config firewall vip\n    edit "web"\n        set extip 203.0.113.10\n        set mappedip "10.20.0.10"\n'
            '        set extintf "wan"\n    next\nend\nconfig firewall policy\n'
            '    edit 1\n        set name "no-ssh"\n        set srcintf "wan"\n        set dstintf "dmz"\n        set action deny\n'
            f'        set srcaddr "all"\n        set dstaddr "{blocked}"\n        set schedule "always"\n        set service "SSH"\n    next\n'
            '    edit 2\n        set name "publish"\n        set srcintf "wan"\n        set dstintf "dmz"\n        set action accept\n'
            '        set srcaddr "all"\n        set dstaddr "web"\n        set schedule "always"\n        set service "ALL"\n    next\nend\n'
        )

    report = Report()
    p = cli.load(conf("web").encode(), "fortios", report)
    entry = matrix.build(p, None, report).cell("wan", "dmz").entries[0]
    assert (entry.rule, entry.what(), entry.approximate, entry.destinations) == ("publish", "any except tcp/22", False, "web")
    # By networks the policy is still shown where the server is, and nowhere else.
    m = matrix.build(p, None, report, matrix.parse_networks(["dmz=10.20.0.0/24"]))
    assert {cell for cell, held in m.cells.items()} == {("dmz", "dmz"), (ELSEWHERE, "dmz")}
    assert m.cell(ELSEWHERE, "dmz").entries[0].what() == "any except tcp/22"
    # A blocking policy for "all" does not match the traffic of a virtual IP on a FortiGate: nothing is taken out for it.
    report = Report()
    p = cli.load(conf("all").encode(), "fortios", report)
    assert matrix.build(p, None, report).cell("wan", "dmz").entries[0].what() == "any"


def test_names_from_the_input_are_not_taken_for_the_matrix_s_own() -> None:
    p = policy(Rule(DEFAULT, ["inside"], ["dmz"], services=["https"]), Rule("any-zone", services=["telnet"]))
    p.zones[OTHER] = Zone(OTHER)
    p.rules.append(Rule("to-it", ["inside"], [OTHER], services=["modbus"]))
    p.rules[-1].origin = "to-it"
    p.default_intrazone = Action.ALLOW
    m = matrix.build(p)
    assert m.zones == ["inside", "outside", "dmz", OTHER, OTHER + "*"] and m.other == OTHER + "*"
    held = m.cell("inside", "dmz")
    assert [(e.rule, e.default) for e in held.entries] == [(DEFAULT, False), ("any-zone", False)]
    assert [(e.rule, e.default) for e in m.cell("inside", "inside").entries] == [("any-zone", False), (DEFAULT, True)]
    text = m.to_text()
    assert "inside -> dmz\n  allowed: tcp/23, tcp/443\n  cleartext or remote administration: telnet (rule 'any-zone')\n  rule '(default)': any -> any: tcp/443\n" in text
    assert "  by default, what no rule decides: any except tcp/23\n" in text
    assert f"inside -> {OTHER}\n  allowed: tcp/23, tcp/502\n" in text and f"{OTHER}*: zones the policy does not name" in text
    data = m.to_dict()
    assert [c["rules"][0].get("by_default", False) for c in data["conduits"] if (c["from"], c["to"]) == ("inside", "dmz")] == [False]
    rows = list(csv.DictReader(io.StringIO(m.to_csv())))
    assert {row["by_default"] for row in rows if row["rule"] == DEFAULT} == {"yes", "no"}
    assert len({(c["from"], c["to"]) for c in data["conduits"]}) == len(data["conduits"])


def test_rule_for_every_zone_is_said_once() -> None:
    p = policy(Rule("everywhere", services=["https"]), Rule("here", ["inside"], ["dmz"], services=["telnet"]))
    for index in range(6):
        p.zones[f"z{index}"] = Zone(f"z{index}")
    m = matrix.build(p)
    text = m.to_text()
    assert len(m.cells) == 100 and text.count("rule 'everywhere'") == 1
    assert "\nIn every conduit\n  rule 'everywhere': any -> any: tcp/443\n\nConduits\n" in text
    assert "inside -> dmz\n  allowed: tcp/23, tcp/443\n  cleartext or remote administration: telnet (rule 'here')\n  rule 'here': any -> any: tcp/23\n" \
           "  and the 1 listed under 'In every conduit'\n" in text  # fmt: skip
    assert len(m.to_text(summary=True)) < len(text) and "In every conduit" not in m.to_text(summary=True)
    # The cells share what they hold of the rule.
    assert len({id(held.entries[0]) for held in m.cells.values()}) == 1


def test_odd_zones_on_the_command_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    given = matrix.parse_networks(["a=10.0.0.1/8,10.0.0.0/8", "a=10.0.0.0/8", "b@x,x,y=192.0.2.0/24", "b@y,z=192.0.2.0/24"])
    assert given["a"].networks == ["10.0.0.0/8"] and given["b"].behind == ["x", "y", "z"]  # one network, as it is; the zones together
    for bad in ("a@=10.0.0.0/8", "a@x,=10.0.0.0/8", "a\x7fb=10.0.0.0/8", "a b=10.0.0.0/8", "(default)=10.0.0.0/8"):
        with pytest.raises(FwshiftError) as error:
            matrix.parse_networks([bad])
        assert str(error.value).isprintable(), bad
    p = policy(Rule("r"))
    with pytest.raises(FwshiftError, match="--network-zone: ::/0 is in zone 'a' and in zone 'b'"):
        matrix.build(p, None, None, matrix.parse_networks(["a=::/0,10.0.0.0/8", "b=::/0"]))
    # "-" is standard output, as it is standard input.
    sample = str(DATA / "iptables_sample.rules")
    assert cli.main(["matrix", sample, "-o", "-", "--summary"]) == 0
    assert capsys.readouterr().out.startswith("FWShift zone matrix\n") and not (Path.cwd() / "-").exists()
    # A line separator of Unicode in a name does not start a line: names are made safe before anything is written.
    q = policy(Rule("a\u2028allowed: any", ["inside"], ["dmz"], ["lan"], ["web"], ["https"]))
    transform.harden(q, Report())
    assert "rule 'a_allowed: any': lan -> web: tcp/443" in matrix.build(q).to_text() and "\u2028" not in matrix.build(q).to_csv()
    # A very long name does not make a very long line.
    q = policy(Rule("n" * 5000, ["inside"], ["dmz"], ["lan"], ["web"], ["https"]))
    assert max(len(line) for line in matrix.build(q).to_text().splitlines()) < 400
