# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The audit: what it finds, what it does about it, and that what it calls dead is dead.

The order checks are tested against an oracle that knows nothing of the audit's sets: every packet
of a small world is walked through the rules, first match, with the matching code of the other
tests. The world is small enough to try every packet that can tell two rules apart.
"""

from __future__ import annotations

import copy
import itertools
import json
import os
import random
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

import pytest
from helpers import DATA, load
from test_iptables import Packet, _entry_matches, _member_matches

from fwshift import audit, cli, transform
from fwshift.audit import AuditConfig, Level, Services
from fwshift.errors import FwshiftError
from fwshift.model import ANY, APP_DEFAULT, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy, Protocol, Rule
from fwshift.model import RuleScope, Service, ServiceEntry, ServiceGroup, SnatKind, SourceNat, Zone
from fwshift.netutil import int_to_ip, parse_literal
from fwshift.report import Report

GOLDEN = DATA / "expected"

# -- sets of services --------------------------------------------------------------------------------


def _random_services(rng: random.Random) -> Tuple[Services, List[ServiceEntry]]:
    entries: List[ServiceEntry] = []
    for _ in range(rng.randint(0, 4)):
        kind = rng.random()
        ports = rng.choice(["", "80", "80,443", "1-1023", "1024-65535", "8000-8010", "22,8000-8005"])
        if kind < 0.5:
            entries.append(ServiceEntry(rng.choice([Protocol.TCP, Protocol.UDP]), ports, rng.choice(["", "", "1024-2000"])))
        elif kind < 0.7:
            entries.append(ServiceEntry(Protocol.ICMP, icmp_type=rng.choice([None, 0, 8])))
        elif kind < 0.9:
            entries.append(ServiceEntry(Protocol.IP, ip_protocol=rng.choice([6, 17, 47, 50])))
        else:
            entries.append(ServiceEntry(Protocol.IP))
    sets = [audit._entry_services(entry) for entry in entries]
    assert all(one is not None for one in sets)
    return audit._union([one for one in sets if one is not None]), entries


SERVICE_POINTS = [
    Packet("", "", "", "", proto, sport, dport, kind)
    for proto in ("tcp", "udp", "icmp", "47", "50", "99")
    for sport in (0, 1023, 1024, 2000, 2001)
    for dport in (0, 1, 22, 79, 80, 81, 443, 1023, 1024, 7999, 8000, 8005, 8006, 8010, 8011, 65535)
    for kind in (0, 8, 9)
    if proto in ("tcp", "udp") or (sport == 0 and dport == 0 and (proto == "icmp" or kind == 0))
]


def _holds(services: Services, pkt: Packet) -> bool:
    number = {"tcp": 6, "udp": 17, "icmp": 1}.get(pkt.proto) or int(pkt.proto)
    a, b = (pkt.icmp_type, 0) if pkt.proto == "icmp" else (pkt.sport, pkt.dport)
    return any(r[0] <= a <= r[1] and r[2] <= b <= r[3] for r in services.of(number))


@pytest.mark.parametrize("seed", range(60))
def test_service_sets_behave_like_sets(seed: int) -> None:
    rng = random.Random(seed)
    first, first_entries = _random_services(rng)
    second, second_entries = _random_services(rng)
    for pkt in SERVICE_POINTS:
        in_first = any(_entry_matches(entry, pkt) for entry in first_entries)
        in_second = any(_entry_matches(entry, pkt) for entry in second_entries)
        assert _holds(first, pkt) == in_first, (seed, pkt)
        assert _holds(first.and_(second), pkt) == (in_first and in_second), (seed, pkt)
        assert _holds(first.minus(second), pkt) == (in_first and not in_second), (seed, pkt)
    assert first.empty() == (not first_entries)
    assert first.meets(second) == (not first.and_(second).empty())
    assert first.minus(first).empty() and audit._ALL_SERVICES.minus(first).minus(audit._ALL_SERVICES.minus(first)).empty()
    assert audit._ALL_SERVICES.everything() and first.everything() == audit._ALL_SERVICES.minus(first).empty()


def test_services_from_the_configuration() -> None:
    assert _holds(audit._spec_services("tcp/23") or Services(), Packet("", "", "", "", "tcp", 5, 23))
    assert _holds(audit._spec_services(" UDP/161-162 ") or Services(), Packet("", "", "", "", "udp", 5, 162))
    for bad in ("23", "tcp", "tcp/", "icmp/8", "tcp/0-70000", "tcp/9-1", "tcp/a"):
        assert audit._spec_services(bad) is None, bad


# -- a small world ---------------------------------------------------------------------------------

NAMED = ["a", "b", "c"]
WORLD_ZONES = NAMED + ["x1", "x2"]  # two zones no rule names: "any" takes them in
APPS = ["web-browsing", "ssl", "other-app"]
TIMES: List[FrozenSet[str]] = [frozenset(), frozenset({"day"}), frozenset({"night"}), frozenset({"day", "night"})]
APP_PORTS = {"web-browsing": "web", "ssl": "https", "other-app": "hi"}


def small_model(rng: random.Random, static: bool = True) -> Policy:
    p = Policy(vendor="panos")
    for zone in NAMED:
        p.zones[zone] = Zone(zone)
    for name, value in (("n0", "10.0.0.0/24"), ("n1", "10.0.1.0/24"), ("big", "10.0.0.0/23"), ("h", "10.0.0.5/32"),
                        ("six", "2001:db8::/64"), ("h6", "2001:db8::5/128")):  # fmt: skip
        p.addresses[name] = Address(name, AddressKind.NETWORK, value)
    p.addresses["r"] = Address("r", AddressKind.RANGE, "10.0.0.200-10.0.1.20")
    p.address_groups["g"] = AddressGroup("g", ["n0", "six"])
    p.address_groups["gg"] = AddressGroup("gg", ["g", "h", "r"])
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")])
    p.services["hi"] = Service("hi", [ServiceEntry(Protocol.TCP, "1024-65535")])
    p.services["rng"] = Service("rng", [ServiceEntry(Protocol.TCP, "8000-8010", "1024-2000")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["icmp"] = Service("icmp", [ServiceEntry(Protocol.ICMP)])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    p.services["alltcp"] = Service("alltcp", [ServiceEntry(Protocol.IP, ip_protocol=6)])
    p.service_groups["mix"] = ServiceGroup("mix", ["web", "ping", "gre"])
    addresses = list(p.addresses) + list(p.address_groups) + ["10.0.1.128/25", "10.0.0.5"]
    services = list(p.services) + list(p.service_groups)
    if not static:
        p.addresses["f1"] = Address("f1", AddressKind.FQDN, "one.example.com")
        p.addresses["f2"] = Address("f2", AddressKind.FQDN, "two.example.com")
        p.address_groups["gf"] = AddressGroup("gf", ["n1", "f1"])
        addresses += ["f1", "f2", "gf"]

    def members(pool: List[str]) -> List[str]:
        return [ANY] if rng.random() < 0.3 else rng.sample(pool, rng.randint(1, 3))

    def zones() -> List[str]:
        return [ANY] if rng.random() < 0.35 else rng.sample(NAMED, rng.randint(1, 2))

    for index in range(rng.randint(4, 9)):
        if p.rules and rng.random() < 0.4:
            # A rule made from one above it, the same or narrower: this is how policies grow dead wood.
            rule = copy.deepcopy(rng.choice(p.rules))
            rule.name = f"r{index}"
            if rule.sources != [ANY] and not rule.negate_source and rng.random() < 0.5:
                rule.sources = rule.sources[:1]
            if rule.services == [ANY] and rng.random() < 0.5:
                rule.services = [rng.choice(services)]
            if rule.dst_zones == [ANY] and rule.scope == RuleScope.UNIVERSAL and rng.random() < 0.5:
                rule.dst_zones = [rng.choice(NAMED)]
        else:
            rule = Rule(name=f"r{index}", src_zones=zones(), dst_zones=zones(), sources=members(addresses),
                        destinations=members(addresses), services=members(services))  # fmt: skip
            rule.negate_source = rule.sources != [ANY] and rng.random() < 0.2
            rule.negate_destination = rule.destinations != [ANY] and rng.random() < 0.2
            rule.negate_service = rule.services != [ANY] and rng.random() < 0.15
            if rng.random() < 0.2:
                rule.scope = rng.choice([RuleScope.INTRAZONE, RuleScope.INTERZONE])
        rule.origin = rule.name
        rule.action = rng.choice([Action.ALLOW, Action.ALLOW, Action.DROP, Action.DENY])
        rule.log_end = rng.random() < 0.8
        rule.enabled = rng.random() > 0.1
        if not static:
            if rng.random() < 0.3:
                rule.applications = rng.sample(APPS, rng.randint(1, 2))
                if rng.random() < 0.5:
                    rule.services, rule.negate_service = [APP_DEFAULT], False
            if rng.random() < 0.2:
                rule.schedule = rng.choice(["day", "night"])
            if rng.random() < 0.1:
                rule.unsupported = ["something the model does not hold"]
        p.rules.append(rule)
    return p


def one_reading(model: Policy, rng: random.Random) -> Policy:
    """The model with everything it leaves open filled in, one way of the many there are."""
    p = copy.deepcopy(model)
    for address in p.addresses.values():
        if address.kind == AddressKind.FQDN:
            address.kind = AddressKind.NETWORK
            address.value = rng.choice(["10.0.0.5/32", "10.0.1.77/32", "192.0.2.9/32", "2001:db8::5/128", "10.0.0.0/23"])
    for rule in p.rules:
        if rule.services == [APP_DEFAULT]:
            apps = APPS if rule.applications == [ANY] else rule.applications
            rule.services = [APP_PORTS[app] for app in apps]
        if rule.unsupported:
            rule.unsupported = []
            how = rng.random()
            if how < 0.3:
                rule.enabled = False  # what the model does not hold never lets the rule match
            elif how < 0.6 and ANY in rule.src_zones:
                rule.src_zones = ["a"]
    return p


def _cells(spans: Sequence[Tuple[int, int]], top: int) -> List[int]:
    """One value out of every stretch that a set of ranges cannot tell apart: the first of each."""
    starts = {0}
    for first, last in spans:
        starts |= {first, last + 1}
    return sorted(value for value in starts if 0 <= value <= top)


Prefix = Tuple[int, int, int, int, int]  # zone pair, source, destination, application, time


class World:
    """Every packet that can tell two rules of a policy apart, and which rule decides each.

    A packet is a zone pair, a source, a destination of the same IP version, an application, a time
    and a service. The first five are walked through; for the services the rules are asked in turn,
    each taking what is left of them.
    """

    def __init__(self, p: Policy, guards: bool = False) -> None:
        self.p = p
        spans: Dict[int, List[Tuple[int, int]]] = {4: [], 6: []}
        literals = [a.value for a in p.addresses.values() if a.kind != AddressKind.FQDN]
        literals += [m for r in p.rules for m in r.sources + r.destinations if m != ANY and parse_literal(m) is not None]
        for literal in literals:
            interval = parse_literal(literal)
            assert interval is not None
            spans[interval[0]].append((interval[1], interval[2]))
        self.addresses = [str(int_to_ip(version, value)) for version in (4, 6)
                          for value in _cells(spans[version], 2 ** (32 if version == 4 else 128) - 1)]  # fmt: skip
        self.six = [":" in address for address in self.addresses]
        dports: List[Tuple[int, int]] = []
        sports: List[Tuple[int, int]] = []
        for service in p.services.values():
            for entry in service.entries:
                for spec, into in ((entry.dst_ports, dports), (entry.src_ports, sports)):
                    for part in filter(None, spec.split(",")):
                        low, _, high = part.partition("-")
                        into.append((int(low), int(high or low)))
        self.services = [Packet("", "", "", "", proto, s, d) for proto in ("tcp", "udp")
                         for s in _cells(sports, 65535) for d in _cells(dports, 65535)]  # fmt: skip
        self.services += [Packet("", "", "", "", "icmp", icmp_type=kind) for kind in (0, 8)]
        self.services += [Packet("", "", "", "", proto) for proto in ("icmp6", "47", "99")]
        self.zones = list(itertools.product(WORLD_ZONES, WORLD_ZONES))
        self.apps = APPS if guards else [APPS[0]]
        self.times = TIMES if guards else [TIMES[0]]
        self.rules = [self._sets(rule) for rule in p.rules]
        self.decided: Dict[Prefix, List[Tuple[int, FrozenSet[int]]]] = {}
        self._walk()

    def _sets(self, rule: Rule) -> Optional[Tuple[FrozenSet[int], ...]]:
        if not rule.enabled:
            return None
        p = self.p
        zones = []
        for index, (src, dst) in enumerate(self.zones):
            ok = (ANY in rule.src_zones or src in rule.src_zones) and (ANY in rule.dst_zones or dst in rule.dst_zones)
            if rule.scope == RuleScope.INTRAZONE:
                ok = src == dst and (ANY in rule.src_zones or src in rule.src_zones)
            elif rule.scope == RuleScope.INTERZONE:
                ok = ok and src != dst
            if ok:
                zones.append(index)
        sources = [i for i, a in enumerate(self.addresses) if any(_member_matches(p, m, a) for m in rule.sources) != rule.negate_source]
        targets = [i for i, a in enumerate(self.addresses)
                   if any(_member_matches(p, m, a) for m in rule.destinations) != rule.negate_destination]  # fmt: skip
        if rule.services == [ANY]:
            services = list(range(len(self.services)))
        else:
            entries = [e for s in rule.services for e in (transform.flatten_services(p, s) or [])]
            services = [i for i, pkt in enumerate(self.services) if any(_entry_matches(e, pkt) for e in entries) != rule.negate_service]
        apps = [i for i, app in enumerate(self.apps) if rule.applications == [ANY] or app in rule.applications]
        times = [i for i, active in enumerate(self.times) if not rule.schedule or rule.schedule in active]
        return tuple(frozenset(part) for part in (zones, sources, targets, apps, times, services))

    def _walk(self) -> None:
        live = [(index, sets) for index, sets in enumerate(self.rules) if sets is not None]
        sizes = [len(self.zones), len(self.addresses), len(self.addresses), len(self.apps), len(self.times)]
        everything = frozenset(range(len(self.services)))

        def descend(depth: int, rules: List[Tuple[int, Tuple[FrozenSet[int], ...]]], prefix: Tuple[int, ...]) -> None:
            if not rules:
                return
            if depth == len(sizes):
                left, parts = everything, []
                for index, sets in rules:
                    hit = sets[5] & left
                    if hit:
                        parts.append((index, hit))
                        left = left - hit
                if parts:
                    self.decided[prefix] = parts  # type: ignore[index]
                return
            for value in range(sizes[depth]):
                if depth == 2 and self.six[value] != self.six[prefix[1]]:
                    continue  # no packet goes from an IPv4 address to an IPv6 one
                descend(depth + 1, [(index, sets) for index, sets in rules if value in sets[depth]], prefix + (value,))

        descend(0, live, ())

    def _packets(self, sets: Tuple[FrozenSet[int], ...]) -> List[Tuple[int, ...]]:
        """The packets a rule would match if it stood alone, without their service."""
        return [prefix for prefix in itertools.product(*[sorted(part) for part in sets[:5]]) if self.six[prefix[1]] == self.six[prefix[2]]]

    def deciders(self) -> Set[int]:
        return {index for parts in self.decided.values() for index, _ in parts}

    def takers(self, index: int) -> Set[int]:
        """The rules that decide the packets a rule would match if it stood alone."""
        sets = self.rules[index]
        out: Set[int] = set()
        if sets is not None:
            for prefix in self._packets(sets):
                out |= {taker for taker, hit in self.decided.get(prefix, []) if hit & sets[5]}  # type: ignore[call-overload]
        return out

    def held_by_like(self, index: int) -> bool:
        """Whether every packet a rule matches is matched by a rule above it that does the same kind of thing (and ever matches)."""
        sets = self.rules[index]
        assert sets is not None
        blocks = self.p.rules[index].action != Action.ALLOW
        alive = self.deciders()
        like = [other for i, other in enumerate(self.rules[:index])
                if other is not None and i in alive and (self.p.rules[i].action != Action.ALLOW) == blocks]  # fmt: skip
        for prefix in self._packets(sets):
            left = sets[5]
            for other in like:
                if all(value in other[depth] for depth, value in enumerate(prefix)):
                    left = left - other[5]
            if left:
                return False
        return True

    def by_packet(self) -> Dict[Tuple[int, ...], str]:
        """The name of the rule that decides each packet."""
        return {prefix + (service,): self.p.rules[index].name
                for prefix, parts in self.decided.items() for index, hit in parts for service in hit}  # fmt: skip

    def outcome(self) -> Dict[Prefix, FrozenSet[Tuple[object, ...]]]:
        """What happens to each packet that some rule matches: the verdict and what goes with it."""
        out: Dict[Prefix, FrozenSet[Tuple[object, ...]]] = {}
        for prefix, parts in self.decided.items():
            handled: Dict[Tuple[object, ...], FrozenSet[int]] = {}
            for index, hit in parts:
                rule = self.p.rules[index]
                key = (rule.action, rule.log_start, rule.log_end)
                handled[key] = handled.get(key, frozenset()) | hit
            out[prefix] = frozenset((key, hit) for key, hit in handled.items())
        return out


def order_findings(p: Policy, **actions: str) -> Tuple[audit.AuditResult, AuditConfig]:
    config = AuditConfig()
    for check in audit.CHECKS:
        config.actions[check] = audit.OFF
    config.actions.update({"SHADOWED_RULE": audit.REPORT, "REDUNDANT_RULE": audit.REPORT, "EMPTY_RULE": audit.REPORT})
    config.actions.update(actions)
    return audit.run(p, config), config


@pytest.mark.parametrize("seed", range(150))
def test_rules_called_dead_are_dead_and_all_dead_rules_are_called(seed: int) -> None:
    """Where everything can be read off the model, the audit and the walk through every packet agree to the rule."""
    rng = random.Random(seed)
    p = small_model(rng)
    result, _ = order_findings(p)
    assert not result.undecided
    world = World(p)
    alive = world.deciders()
    dead = {rule.name for index, rule in enumerate(p.rules) if rule.enabled and index not in alive}
    never = {f.name: f for f in result.before if "never matches" in f.message or f.check == "EMPTY_RULE"}
    assert set(never) == dead, (seed, sorted(never), sorted(dead))
    by_name = {rule.name: index for index, rule in enumerate(p.rules)}
    for name, finding in never.items():
        rule = p.rules[by_name[name]]
        takers = {p.rules[i].name for i in world.takers(by_name[name])}
        if not takers:
            assert finding.check == "EMPTY_RULE", (seed, name)
        elif world.held_by_like(by_name[name]):
            # Rules above it that do the same hold all of it: it has nothing of its own, whoever takes the traffic.
            assert finding.check == "REDUNDANT_RULE" and finding.related, (seed, name)
            assert all((p.rules[by_name[other]].action != Action.ALLOW) == (rule.action != Action.ALLOW) for other in finding.related)
        else:
            # Some of what it is for is only ever taken by rules that do otherwise: the finding names who takes what.
            assert finding.check == "SHADOWED_RULE" and set(finding.related) == takers, (seed, name)


@pytest.mark.parametrize("seed", range(150))
def test_disabling_what_the_audit_calls_redundant_or_shadowed_changes_nothing(seed: int) -> None:
    rng = random.Random(1000 + seed)
    p = small_model(rng)
    before = World(p).outcome()
    result, config = order_findings(p, SHADOWED_RULE=audit.DISABLE, REDUNDANT_RULE=audit.DISABLE, EMPTY_RULE=audit.DISABLE)
    flagged = {f.name for f in result.before}
    done = audit.apply(p, result, config)
    assert {origin for origin, _, _, _ in done} == flagged and not any(changes for _, _, changes, _ in done), seed
    assert all(not rule.enabled for rule in p.rules if rule.name in flagged)
    assert World(p).outcome() == before, seed
    # Nothing is left to find, and a second run does nothing.
    again, config = order_findings(p, SHADOWED_RULE=audit.DISABLE, REDUNDANT_RULE=audit.DISABLE, EMPTY_RULE=audit.DISABLE)
    assert not again.before, (seed, [f.name for f in again.before])


@pytest.mark.parametrize("seed", range(50))
def test_what_cannot_be_read_never_makes_a_rule_dead(seed: int) -> None:
    """Host names, applications on their default ports, schedules, criteria the model does not hold:
    whatever they turn out to be, a rule the audit calls dead decides nothing, and disabling it changes nothing."""
    rng = random.Random(2000 + seed)
    model = small_model(rng, static=False)
    result, config = order_findings(model, SHADOWED_RULE=audit.DISABLE, REDUNDANT_RULE=audit.DISABLE, EMPTY_RULE=audit.DISABLE)
    never = {f.name for f in result.before if "never matches" in f.message or f.check == "EMPTY_RULE"}
    trimmed = copy.deepcopy(model)
    audit.apply(trimmed, result, config)
    gone = {rule.name for rule, was in zip(trimmed.rules, model.rules) if was.enabled and not rule.enabled}
    assert gone == {f.name for f in result.before}
    for _ in range(2):
        state = rng.getstate()
        reading = one_reading(model, rng)
        world = World(reading, guards=True)
        alive = {reading.rules[index].name for index in world.deciders()}
        assert not never & alive, (seed, never & alive)
        rng.setstate(state)
        assert World(one_reading(trimmed, rng), guards=True).outcome() == world.outcome(), seed


@pytest.mark.parametrize("seed", range(100))
def test_moving_a_shadowed_rule_up_brings_it_to_life_and_touches_nothing_else(seed: int) -> None:
    rng = random.Random(3000 + seed)
    p = small_model(rng)
    before = World(p).by_packet()
    result, config = order_findings(p, SHADOWED_RULE=audit.REORDER, REDUNDANT_RULE=audit.OFF, EMPTY_RULE=audit.OFF)
    names = [rule.name for rule in p.rules]
    done = audit.apply(p, result, config)
    moved = {origin for origin, _, changes, what in done if changes and what.startswith("moved")}
    assert moved == {f.name for f in result.before if f.done.startswith("moved")}
    assert sorted(rule.name for rule in p.rules) == sorted(names)
    after_world = World(p)
    after = after_world.by_packet()
    assert set(after) == set(before)
    changed = {pkt for pkt in before if before[pkt] != after[pkt]}
    # Only what a moved rule matches is decided by another rule than before, and by a moved rule now.
    assert {after[pkt] for pkt in changed} <= moved, seed
    # A moved rule decides traffic now, or the audit says that it still does not.
    alive = {p.rules[index].name for index in after_world.deciders()}
    assert {f.name for f in result.before if f.done.startswith("moved") and "still never matches" not in f.done} == moved & alive, seed
    # The rules that were not moved keep their order.
    assert [n for n in names if n not in moved] == [rule.name for rule in p.rules if rule.name not in moved]


def test_zone_pairs_as_two_sets_and_a_relation() -> None:
    zones = audit._Zones(["a", "b", ANY, "a"])
    assert zones.names == ["a", "b", audit._OTHER]
    names = ["a", "b", "x1", "x2"]  # two zones that no rule names stand behind the one bit for the others

    def bit(zone: str) -> int:
        return 1 << zones.index.get(zone, len(zones.names) - 1)

    def pairs(src: Sequence[str], dst: Sequence[str], scope: RuleScope) -> Set[Tuple[str, str]]:
        sources, targets, relation = zones.of(src, dst, scope)
        return {(s, d) for s in names for d in names
                if sources & bit(s) and targets & bit(d) and relation & (audit._SAME if s == d else audit._DIFFERENT)}  # fmt: skip

    assert pairs(["a"], ["b"], RuleScope.UNIVERSAL) == {("a", "b")}
    assert pairs(["a"], [ANY], RuleScope.UNIVERSAL) == {("a", "a"), ("a", "b"), ("a", "x1"), ("a", "x2")}
    assert pairs([ANY], ["b"], RuleScope.INTRAZONE) == {(name, name) for name in names}  # the destination zones are not asked
    assert pairs(["a", "b"], ["a", "b"], RuleScope.INTERZONE) == {("a", "b"), ("b", "a")}
    assert pairs([ANY], [ANY], RuleScope.INTERZONE) == {(s, d) for s in names for d in names if s != d}
    assert pairs([ANY], [ANY], RuleScope.UNIVERSAL) == {(s, d) for s in names for d in names}
    # Whether a set holds any pair at all.
    a, b, other, both = bit("a"), bit("b"), zones.other, audit._SAME | audit._DIFFERENT
    assert zones.possible(a, b, both) and zones.possible(a, a, both) and zones.possible(a, a | b, audit._DIFFERENT)
    assert not zones.possible(a, a, audit._DIFFERENT) and not zones.possible(a, b, audit._SAME)
    assert not zones.possible(0, b, both) and not zones.possible(a, b, 0)
    # The zones nobody names may be two: traffic between them is possible, and so is traffic inside one.
    assert zones.possible(other, other, audit._DIFFERENT) and zones.possible(other, other, audit._SAME)


# -- the checks on policies written for them ---------------------------------------------------------


def policy(*rules: Rule, vendor: str = "panos") -> Policy:
    p = Policy(vendor=vendor)
    for zone in ("inside", "outside", "dmz"):
        p.zones[zone] = Zone(zone)
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.20.0.10/32")
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.10.0.0/16")
    p.addresses["corp"] = Address("corp", AddressKind.NETWORK, "10.0.0.0/8")
    p.addresses["site"] = Address("site", AddressKind.FQDN, "www.example.com")
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["telnet"] = Service("telnet", [ServiceEntry(Protocol.TCP, "23")])
    p.services["high"] = Service("high", [ServiceEntry(Protocol.TCP, "1024-65535")])
    p.services["modbus"] = Service("modbus", [ServiceEntry(Protocol.TCP, "502")])
    for rule in rules:
        rule.origin = rule.name
        rule.profiles = rule.profiles or {"group": "default"}
        p.rules.append(rule)
    return p


def found(p: Policy, config: Optional[AuditConfig] = None) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for finding in audit.run(p, config).before:
        if finding.action != audit.ACCEPT:
            out.setdefault(finding.shown or finding.name, []).append(finding.check)
    return out


def test_rules_that_allow_a_lot() -> None:
    p = policy(
        Rule("everything"),
        Rule("out", src_zones=["inside"], dst_zones=["outside"]),
        Rule("any-service", sources=["lan"], destinations=["web"]),
        Rule("any-to-any", services=["https"]),
        Rule("published", destinations=["web"], services=["https"]),
        Rule("surfing", sources=["lan"], services=["https"]),
        Rule("exact", sources=["lan"], destinations=["web"], services=["https"]),
        Rule("drop-all", action=Action.DROP),
        Rule("off", enabled=False),
    )
    assert {rule.name: checks_of(p, rule.name) for rule in p.rules} == {
        "everything": ["ANY_ANY_ANY"], "out": ["ANY_ANY_ANY"], "any-service": ["ANY_SERVICE"], "any-to-any": ["ANY_TO_ANY"],
        "published": ["ANY_SOURCE"], "surfing": ["ANY_DESTINATION"], "exact": [], "drop-all": [], "off": ["DISABLED_RULE"],
    }  # fmt: skip
    levels = {f.shown or f.name: f.level for f in audit.run(p).before if f.check == "ANY_ANY_ANY"}
    # Zones on both sides keep the rule to one path through the firewall.
    assert levels == {"everything": Level.HIGH, "out": Level.MEDIUM}


ORDER = ("SHADOWED_RULE", "REDUNDANT_RULE", "EMPTY_RULE")


def _dead(p: Policy) -> Dict[str, List[str]]:
    """The findings about rules that decide nothing."""
    return {f.shown or f.name: [f.check] for f in audit.run(p).before if f.check in ORDER}


def checks_of(p: Policy, name: str, config: Optional[AuditConfig] = None) -> List[str]:
    """The findings of a rule about what it allows: the rules of these policies stand in each other's way on purpose."""
    return [check for check in found(p, config).get(name, []) if check not in ORDER]


def test_wide_networks_and_ports_and_what_runs_on_them() -> None:
    p = policy(
        Rule("corp", sources=["corp"], destinations=["web"], services=["https"]),
        Rule("ten", sources=["10.0.0.0/9"], destinations=["web"], services=["https"]),
        Rule("all-but", sources=["lan"], negate_source=True, destinations=["web"], services=["https"]),
        Rule("high", sources=["lan"], destinations=["web"], services=["high"]),
        Rule("telnet", sources=["lan"], destinations=["web"], services=["telnet"]),
        Rule("plc", sources=["lan"], destinations=["web"], services=["modbus"]),
        Rule("app", sources=["lan"], destinations=["web"], applications=["ms-rdp", "ssl"], services=[APP_DEFAULT]),
        Rule("not-https", sources=["lan"], destinations=["web"], services=["https"], negate_service=True),
        Rule("block", sources=["corp"], services=["telnet"], action=Action.DENY),
    )
    assert checks_of(p, "corp") == ["WIDE_NETWORK"] and checks_of(p, "ten") == []
    assert checks_of(p, "all-but") == ["ANY_SOURCE"]  # "all but the LAN" is all of IPv6, for one
    assert checks_of(p, "high") == ["WIDE_PORTS", "RISKY_SERVICE", "INDUSTRIAL_SERVICE"]  # RDP and the rest are in there
    assert checks_of(p, "telnet") == ["RISKY_SERVICE"] and checks_of(p, "plc") == ["INDUSTRIAL_SERVICE"]
    assert checks_of(p, "app") == ["RISKY_SERVICE"]
    # "Everything but HTTPS" holds every port there is.
    assert checks_of(p, "not-https") == ["WIDE_PORTS", "RISKY_SERVICE", "INDUSTRIAL_SERVICE"]
    assert checks_of(p, "block") == []
    config = AuditConfig(wide_network_v4=9, wide_ports=65000)
    config.risky_services, config.industrial_services = {"https": ["tcp/443"]}, {}
    assert checks_of(p, "ten", config) == ["WIDE_NETWORK", "RISKY_SERVICE"] and checks_of(p, "high", config) == []
    assert checks_of(p, "telnet", config) == [] and checks_of(p, "plc", config) == []


def test_any_application_on_its_default_ports_is_any_service() -> None:
    p = policy(Rule("apps", sources=["lan"], destinations=["web"], services=[APP_DEFAULT]),
               Rule("one", sources=["lan"], destinations=["web"], services=[APP_DEFAULT], applications=["ssl"]))  # fmt: skip
    assert checks_of(p, "apps") == ["ANY_SERVICE"] and checks_of(p, "one") == []


def test_logging_and_profiles_where_a_rule_decides_them() -> None:
    quiet = Rule("quiet", sources=["lan"], destinations=["web"], services=["https"], log_end=False)
    bare = Rule("bare", sources=["lan"], destinations=["web"], services=["telnet"], action=Action.DROP, log_end=False)
    p = policy(quiet, bare)
    quiet.profiles = {}
    assert checks_of(p, "quiet") == ["NO_LOG", "NO_PROFILE"] and checks_of(p, "bare") == ["NO_LOG"]
    # (The model does not tell a FortiOS policy that logs security events only from one that logs nothing.)
    for vendor, expected in (("fortios", ["NO_PROFILE"]), ("checkpoint", ["NO_LOG"]), ("asa", []), ("iptables", [])):
        p.vendor = vendor
        assert checks_of(p, "quiet") == expected, vendor
    # Neither is a reason to switch a rule off: a blocking rule that does not log would stop blocking.
    for check in ("NO_LOG", "NO_PROFILE"):
        with pytest.raises(FwshiftError, match="cannot be done"):
            AuditConfig().set_action(check, "disable")


def test_shadowed_redundant_and_overlapping() -> None:
    p = policy(
        Rule("deny-web", destinations=["web"], action=Action.DROP),
        Rule("allow-web", sources=["lan"], destinations=["web"], services=["https"]),  # never reached
        Rule("lan-out", sources=["lan"], services=["https"]),
        Rule("lan-out-again", sources=["10.10.5.0/24"], services=["https"]),  # same verdict as the rule above
        Rule("narrow", sources=["lan"], destinations=["10.30.0.0/24"], services=["telnet"]),
        Rule("wide", sources=["lan"], services=["telnet"]),  # holds "narrow", with the same handling
        Rule("site", sources=["lan"], destinations=["site"], services=["https"]),  # a host name: still inside lan-out
    )
    result = audit.run(p)
    by_name = {f.shown or f.name: f for f in result.before if f.check in ("SHADOWED_RULE", "REDUNDANT_RULE")}
    assert {name: f.check for name, f in by_name.items()} == {
        "allow-web": "SHADOWED_RULE", "lan-out-again": "REDUNDANT_RULE", "narrow": "REDUNDANT_RULE", "site": "REDUNDANT_RULE"}  # fmt: skip
    assert "'deny-web' blocks it" in by_name["allow-web"].message and by_name["allow-web"].level == Level.MEDIUM
    assert by_name["allow-web"].related == ["deny-web"]
    # What 'deny-web' takes of it, it takes of 'lan-out' as well: the rule is a copy of part of 'lan-out', no more.
    assert by_name["lan-out-again"].message == "never matches: 'lan-out' above it already allows everything it could match"
    assert by_name["lan-out-again"].related == ["lan-out"] and "adds nothing: 'wide'" in by_name["narrow"].message
    # Part blocked, part allowed by rules above, and no rule above that allows all of it.
    q = policy(Rule("deny-web", destinations=["web"], action=Action.DROP), Rule("lan-mail", sources=["lan"], destinations=["10.30.0.0/24"]),
               Rule("lan-both", sources=["lan"], destinations=["web", "10.30.0.0/24"]))  # fmt: skip
    mixed = next(f for f in audit.run(q).before if f.check == "SHADOWED_RULE")
    assert mixed.name == "lan-both" and "'deny-web' blocks part of it, 'lan-mail' allows the rest" in mixed.message
    # A blocking rule that is never reached weighs more.
    q = policy(Rule("allow", sources=["lan"]), Rule("deny-telnet", sources=["lan"], services=["telnet"], action=Action.DENY))
    finding = next(f for f in audit.run(q).before if f.check == "SHADOWED_RULE")
    assert finding.level == Level.HIGH and "'allow' allows it" in finding.message
    # Off by default: the rule that a blocking rule above it takes part of.
    config = AuditConfig()
    config.set_action("overlapping-rules", "report")
    assert "OVERLAPPING_RULES" in found(p, config)["lan-out"]


def test_a_rule_between_that_does_something_else_keeps_a_rule_needed() -> None:
    narrow = Rule("narrow", sources=["lan"], destinations=["web"], services=["https"])
    between = Rule("between", sources=["lan"], destinations=["10.20.0.0/24"], services=["https"], action=Action.DROP)
    wide = Rule("wide", sources=["lan"], services=["https"])
    assert "narrow" not in _dead(policy(narrow, between, wide))
    # Without it, or with one that touches nothing of the rule, the rule adds nothing.
    assert _dead(policy(copy.deepcopy(narrow), copy.deepcopy(wide))) == {"narrow": ["REDUNDANT_RULE"]}
    aside = Rule("aside", sources=["lan"], destinations=["10.99.0.0/24"], services=["https"], action=Action.DROP)
    assert _dead(policy(copy.deepcopy(narrow), aside, copy.deepcopy(wide)))["narrow"] == ["REDUNDANT_RULE"]
    # The same verdict with other logging is not the same handling.
    quiet = copy.deepcopy(wide)
    quiet.log_end = False
    assert _dead(policy(copy.deepcopy(narrow), quiet)) == {}
    # Two rules alike: the second is the one that goes, not both.
    p = policy(copy.deepcopy(narrow), Rule("twin", sources=["lan"], destinations=["web"], services=["https"]))
    assert _dead(p) == {"twin": ["REDUNDANT_RULE"]}


def test_criteria_the_sets_do_not_hold() -> None:
    def pair(first: Rule, second: Rule) -> Dict[str, List[str]]:
        return _dead(policy(first, second))

    base = dict(sources=["lan"], destinations=["web"], services=["https"])
    # An application, a user, a category or a schedule on the earlier rule keeps it from covering.
    for extra in (dict(applications=["ssl"]), dict(users=["alice"]), dict(url_categories=["news"]), dict(schedule="office")):
        # (It is the earlier rule that adds nothing then: the later one does the same for more.)
        assert pair(Rule("first", **base, **extra), Rule("second", **base)) == {"first": ["REDUNDANT_RULE"]}, extra  # type: ignore[arg-type]
        # The other way round the later rule is the narrower one.
        assert pair(Rule("first", **base), Rule("second", **base, **extra)) == {"second": ["REDUNDANT_RULE"]}, extra  # type: ignore[arg-type]
        assert pair(Rule("first", **base, **extra), Rule("second", **base, **extra)) == {"second": ["REDUNDANT_RULE"]}  # type: ignore[arg-type]
    assert pair(Rule("first", **base, applications=["ssl", "web-browsing"]), Rule("second", **base, applications=["ssl"])) != {}  # type: ignore[arg-type]
    assert pair(Rule("first", **base, schedule="office"), Rule("second", **base, schedule="night")) == {}  # type: ignore[arg-type]
    # A rule with something the model does not hold covers nothing, and can be covered.
    odd = Rule("first", **base)  # type: ignore[arg-type]
    odd.unsupported = ["a match the model does not hold"]
    assert pair(odd, Rule("second", **base)) == {}  # type: ignore[arg-type]
    odd = Rule("second", **base)  # type: ignore[arg-type]
    odd.unsupported = ["a match the model does not hold"]
    assert pair(Rule("first", **base), odd) == {"second": ["REDUNDANT_RULE"]}  # type: ignore[arg-type]
    # A host name covers nothing but itself.
    assert pair(Rule("first", destinations=["site"]), Rule("second", destinations=["web"])) == {}
    assert pair(Rule("first", destinations=["site", "web"]), Rule("second", destinations=["site"])) == {"second": ["REDUNDANT_RULE"]}
    # A disabled rule covers nothing and is not looked at.
    assert pair(Rule("first", enabled=False), Rule("second")) == {}


def test_nat_rules_that_never_match() -> None:
    p = policy()
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "203.0.113.10/32")
    wide = NatRule("wide", ["inside"], ["outside"], ["corp"], source_translation=SourceNat(SnatKind.INTERFACE))
    narrow = NatRule("narrow", ["inside"], ["outside"], ["lan"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pub"]))
    inbound = NatRule("inbound", ["outside"], ["outside"], destinations=["pub"], destination_translation=DestNat("web"))
    for nat in (wide, narrow, inbound):
        nat.origin = nat.name
    p.nat_rules = [wide, narrow, inbound]
    result = audit.run(p)
    assert [(f.check, f.name) for f in result.before if f.kind == "nat"] == [("SHADOWED_NAT", "narrow")]
    # Where a rule for the destination and one for the source apply together, the first match is not all there is.
    wide.combines = narrow.combines = True
    assert not [f for f in audit.run(p).before if f.kind == "nat"]


def test_loose_ends() -> None:
    p = policy(Rule("only", sources=["lan"], destinations=["web"], services=["https"], description="  "))
    p.addresses["lan-again"] = Address("lan-again", AddressKind.NETWORK, "10.10.0.0/16")
    p.addresses["web-range"] = Address("web-range", AddressKind.RANGE, "10.20.0.10-10.20.0.10")
    p.services["tls"] = Service("tls", [ServiceEntry(Protocol.TCP, "443")])
    p.services["predefined"] = Service("predefined", [ServiceEntry(Protocol.TCP, "443")], builtin="panos")
    p.address_groups["empty"] = AddressGroup("empty")
    p.address_groups["tagged"] = AddressGroup("tagged", dynamic_filter="'web'")
    p.service_groups["none"] = ServiceGroup("none")
    p.default_interzone = Action.ALLOW
    config = AuditConfig()
    config.set_action("NO_DESCRIPTION", "report")
    result = audit.run(p, config)
    by_check: Dict[str, List[str]] = {}
    for finding in result.before:
        by_check.setdefault(finding.check, []).append(finding.message)
    assert by_check["NO_DESCRIPTION"] == ["has no description"]
    assert sorted(by_check["EMPTY_GROUP"]) == ["has no members: it matches no address", "has no members: it matches no service"]
    assert by_check["DEFAULT_ALLOW"] == ["traffic between zones that no rule matches is allowed"]
    duplicates = sorted(by_check["DUPLICATE_OBJECT"])
    assert duplicates == [
        "the same address under 2 names: 'lan', 'lan-again'", "the same address under 2 names: 'web', 'web-range'",
        "the same service under 2 names: 'https', 'tls'"]  # fmt: skip
    unused = " ".join(by_check["UNUSED_OBJECT"])
    assert "'lan-again'" in unused and "'tls'" in unused and "'predefined'" not in unused and "'lan'" not in unused.replace("'lan-again'", "")
    assert "1 service group no rule uses: 'none'" in unused and "2 address groups no rule uses: 'empty', 'tagged'" in unused


# -- what is done about findings ------------------------------------------------------------------


def test_actions_and_what_takes_them() -> None:
    config = AuditConfig()
    config.set_action("shadowed-rule", "Reorder", "--audit-action")
    assert config.action("SHADOWED_RULE") == audit.REORDER and config.action("ANY_SOURCE") == audit.REPORT
    assert config.action("NO_DESCRIPTION") == audit.OFF
    for check, action, message in (
        ("NO_SUCH", "report", "there is no check 'NO_SUCH'"),
        ("ANY_SOURCE", "reorder", "'reorder' cannot be done with ANY_SOURCE"),
        ("UNUSED_OBJECT", "disable", "cannot be done with UNUSED_OBJECT"),
        ("SHADOWED_RULE", "delete", "'delete' cannot be done"),
    ):
        with pytest.raises(FwshiftError, match=message):
            config.set_action(check, action, "--audit-action")
    with pytest.raises(FwshiftError, match="not a level"):
        audit.level_of("severe", "--audit-fail-on")


def test_accepting_a_rule() -> None:
    p = policy(Rule("Web in", destinations=["web"], services=["https"]), Rule("Mail in", destinations=["web"], services=["telnet"]))
    config = AuditConfig()
    config.accept("Web*", ["any-source"], "the public web server")
    result = audit.run(p, config)
    accepted = [f for f in result.before if f.action == audit.ACCEPT]
    assert [(f.check, f.shown or f.name, f.reason) for f in accepted] == [("ANY_SOURCE", "Web in", "the public web server")]
    assert "ANY_SOURCE" in found(p, config)["Mail in"] and "RISKY_SERVICE" in found(p, config)["Mail in"]
    text = result.to_text()
    assert "Accepted\n  ANY_SOURCE: rule 'Web in' (the public web server)" in text and "accepted 1" in text
    # Without a check named, the rule passes all of them. An object is accepted by its name too.
    assert "'corp'" in next(f.message for f in audit.run(p, config).before if f.check == "UNUSED_OBJECT" and f.kind == "address")
    config = AuditConfig()
    config.accept("Mail in")
    config.accept("corp")
    assert "Mail in" not in found(p, config)
    unused = [f for f in audit.run(p, config).before if f.check == "UNUSED_OBJECT" and f.kind == "address"]
    assert [(f.name, f.action) for f in unused] == [("corp", "accept"), ("2 addresses", "report")] and "'corp'" not in unused[1].message
    # Accepted findings do not fail a run.
    assert audit.run(p, config).fails(Level.LOW) and not audit.run(policy(Rule("x", enabled=False)), config).fails(Level.LOW)
    with pytest.raises(FwshiftError, match="there is no check"):
        config.accept("rule", ["NOPE"])


def test_disabling_for_what_a_rule_allows_comes_before_the_order() -> None:
    """A rule that only looked redundant next to a rule that is disabled for what it allows is kept."""
    narrow = Rule("narrow", sources=["lan"], destinations=["web"])
    wide = Rule("wide", sources=["lan"])
    p = policy(narrow, wide)
    assert _dead(p) == {"narrow": ["REDUNDANT_RULE"]}
    config = AuditConfig()
    config.set_action("REDUNDANT_RULE", "disable")
    config.set_action("ANY_SERVICE", "disable")
    config.accept("narrow", ["ANY_SERVICE"])
    result = audit.run(p, config)
    assert next(f for f in result.before if f.check == "REDUNDANT_RULE").done == "would be disabled by a conversion"
    done = audit.apply(p, result, config)
    assert done == [("wide", "ANY_SERVICE", True, "disabled")]
    assert narrow.enabled and not wide.enabled
    assert next(f for f in result.before if f.check == "REDUNDANT_RULE").done.startswith("kept: with the other changes")


def test_moving_a_shadowed_rule() -> None:
    p = policy(
        Rule("first", sources=["web"]),
        Rule("allow-lan", sources=["lan"]),
        Rule("more", sources=["corp"], services=["https"]),
        Rule("no-telnet", sources=["lan"], services=["telnet"], action=Action.DENY),
    )
    config = AuditConfig()
    config.set_action("SHADOWED_RULE", "reorder")
    result = audit.run(p, config)
    done = audit.apply(p, result, config)
    assert [rule.name for rule in p.rules] == ["first", "no-telnet", "allow-lan", "more"]
    assert done == [("no-telnet", "SHADOWED_RULE", True, "moved up, in front of 'allow-lan'")]
    assert "SHADOWED_RULE" not in [f.check for f in audit.run(p).before]


# -- the configuration file ------------------------------------------------------------------------


def test_configuration_file() -> None:
    config = audit.load_config(json.dumps({
        "checks": {"SHADOWED_RULE": "reorder", "any-source": {"action": "accept", "level": "info"}, "NO_LOG": "off",
                   "REDUNDANT_RULE": {"level": "high"}},
        "accept": ["Old*", {"rule": "Web in", "checks": ["ANY_SOURCE", "RISKY_SERVICE"], "reason": "public"},
                   {"rule": "x", "checks": "NO_PROFILE"}],
        "thresholds": {"wide_network_v4": 12, "wide_ports": 100},
        "services": {"risky": {"telnet": ["tcp/23"]}, "industrial": {}},
        "fail_on": "medium",
    }))  # fmt: skip
    assert config.action("SHADOWED_RULE") == "reorder" and config.action("ANY_SOURCE") == "accept" and config.action("NO_LOG") == "off"
    assert config.level("ANY_SOURCE") == Level.INFO and config.level("REDUNDANT_RULE") == Level.HIGH
    assert config.action("REDUNDANT_RULE") == "report"
    assert [(a.pattern, a.checks, a.reason) for a in config.accepted] == [
        ("Old*", [], ""), ("Web in", ["ANY_SOURCE", "RISKY_SERVICE"], "public"), ("x", ["NO_PROFILE"], "")]
    assert (config.wide_network_v4, config.wide_network_v6, config.wide_ports) == (12, 32, 100)
    assert config.risky_services == {"telnet": ["tcp/23"]} and config.industrial_services == {} and config.fail_on == Level.MEDIUM
    assert audit.load_config("{}").actions == {}
    for text, message in (
        ("[", "is not JSON"), ("[]", "a JSON object is expected"), ('{"check": {}}', "unknown key 'check'"),
        ('{"checks": []}', "'checks' maps"), ('{"checks": {"X": "off"}}', "no check 'X'"),
        ('{"checks": {"NO_LOG": "reorder"}}', "cannot be done with NO_LOG"), ('{"checks": {"NO_LOG": {"level": "x"}}}', "not a level"),
        ('{"accept": {}}', "'accept' is a list"), ('{"accept": [3]}', "an entry of 'accept'"), ('{"accept": [{"rule": "x", "checks": 3}]}', "list of checks"),
        ('{"thresholds": {"wide_ports": 1}}', "between 2 and 65536"), ('{"thresholds": {"x": 1}}', "is not known"),
        ('{"thresholds": {"wide_ports": true}}', "not a whole number"), ('{"services": {"x": {}}}', "'risky' and 'industrial'"),
        ('{"services": {"risky": {"x": ["icmp"]}}}', "is not like tcp/23"), ('{"services": {"risky": {"x": "tcp/1"}}}', "maps a name to a list"),
        ('{"fail_on": "never"}', "not a level"),
    ):  # fmt: skip
        with pytest.raises(FwshiftError, match=message):
            audit.load_config(text)


# -- the command line ------------------------------------------------------------------------------

SAMPLES = ["panos_sample.xml", "fortios_sample.conf", "checkpoint_sample.json", "asa_sample.cfg", "iptables_sample.rules",
           "sophos_sample.xml", "fmc_sample.json", "fdm_sample.txt", "pfsense_sample.xml", "sonicwall_sample.exp",
           "watchguard_sample.xml", "barracuda_sample.json",
           "junos_sample.conf", "nftables_sample.nft", "nsx_sample.json", "aws_sample.json", "azure_sample.json",
           "routeros_sample.rsc", "opnsense_sample.xml", "forcepoint_sample.json",
           "terraform_aws_sample.json", "terraform_azure_sample.json", "gcp_sample.json", "ios_sample.cfg",
           "terraform_google_sample.json"]  # fmt: skip


@pytest.mark.parametrize("sample", SAMPLES)
def test_audit_of_the_samples(sample: str, tmp_path: Path) -> None:
    """The audit of each sample, byte for byte. Regenerate with FWSHIFT_UPDATE_GOLDEN=1 and review the diff."""
    out = tmp_path / "audit.txt"
    assert cli.main(["audit", str(DATA / sample), "-o", str(out)]) == 0
    golden = GOLDEN / (sample.split(".")[0] + ".audit.txt")
    if os.environ.get("FWSHIFT_UPDATE_GOLDEN"):
        golden.write_text(out.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    assert out.read_text(encoding="utf-8") == golden.read_text(encoding="utf-8")
    # The samples hold nothing the audit cannot follow, and the JSON says the same as the text.
    json_out = tmp_path / "audit.json"
    assert cli.main(["audit", str(DATA / sample), "-o", str(json_out), "--json"]) == 0
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["not_followed"] == [] and sum(data["summary"].values()) == len(data["findings"])
    for finding in data["findings"]:
        assert finding["check"] in audit.CHECKS and finding["check"] + ":" in out.read_text(encoding="utf-8")


def test_audit_command(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    sample = str(DATA / "asa_sample.cfg")
    assert cli.main(["audit", "--list-checks"]) == 0
    listed = capsys.readouterr().out
    assert all(check in listed for check in audit.CHECKS) and "can be: off, accept, report, disable, reorder" in listed
    assert cli.main(["audit"]) == 1 and "a configuration file is needed" in capsys.readouterr().err
    assert cli.main(["audit", sample, "--audit-fail-on", "medium"]) == 3
    assert "RISKY_SERVICE: rule 'inside_access_in-7' allows rdp" in capsys.readouterr().out
    assert cli.main(["audit", sample, "--audit-fail-on", "high"]) == 0
    capsys.readouterr()
    quiet = ["--audit-action", "RISKY_SERVICE=accept", "--audit-accept", "implicit-guest", "--audit-accept", "*=ANY_SERVICE,ANY_TO_ANY"]
    assert cli.main(["audit", sample, "--audit-fail-on", "medium"] + quiet) == 0
    assert "accepted 4" in capsys.readouterr().out
    assert cli.main(["audit", sample, "--audit-action", "REDUNDANT_RULE=disable"]) == 0
    assert "-> would be disabled by a conversion" in capsys.readouterr().out
    for bad, message in ((["--audit-action", "NO_LOG"], "expects CHECK=ACTION"), (["--audit-action", "NO_LOG=reorder"], "cannot be done"),
                         (["--audit-accept", "x=NOPE"], "there is no check"), (["--audit-fail-on", "x"], "not a level"),
                         (["--audit-config", str(tmp_path / "missing.json")], "cannot read")):  # fmt: skip
        assert cli.main(["audit", sample] + bad) == 1
        assert message in capsys.readouterr().err, bad
    config = tmp_path / "audit.json"
    config.write_text('{"checks": {"ANY_DESTINATION": "off", "ANY_SOURCE": "off"}, "fail_on": "medium"}', encoding="utf-8")
    assert cli.main(["audit", sample, "--audit-config", str(config)]) == 3
    out = capsys.readouterr().out
    assert "ANY_DESTINATION" not in out and "ANY_SERVICE" in out
    # The command line has the last word.
    assert cli.main(["audit", sample, "--audit-config", str(config), "--audit-fail-on", "high"]) == 0


def test_conversion_with_audit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sample = str(DATA / "asa_sample.cfg")
    report, as_json, out = tmp_path / "report.txt", tmp_path / "report.json", tmp_path / "out"
    args = ["convert", sample, "--to", "panos", "-o", str(out), "--report", str(report), "--report-json", str(as_json), "-q"]
    assert cli.main(args) == 0 and "Audit" not in report.read_text(encoding="utf-8")
    plain = out.read_text(encoding="utf-8")
    assert "audit" not in json.loads(as_json.read_text(encoding="utf-8"))
    # Reporting changes nothing in the output.
    assert cli.main(args + ["--audit"]) == 0 and out.read_text(encoding="utf-8") == plain
    text = report.read_text(encoding="utf-8")
    assert "\nAudit\n" in text and "REDUNDANT_RULE: rule 'inside_access_in-4' never matches" in text
    assert "After the conversion\n  nothing new" in text
    data = json.loads(as_json.read_text(encoding="utf-8"))
    after = data["audit"]["after_conversion"]
    # (The rule with a schedule is written disabled for PAN-OS: there it is no longer a rule that never matches.)
    assert data["audit"]["summary"]["low"] > 0 and after["new"] == [] and [f["name"] for f in after["gone"]] == ["inside_access_in-4"]
    # Disabling: the rule is in the output, switched off, and both reports say why.
    assert cli.main(args + ["--audit-action", "REDUNDANT_RULE=disable", "--audit-action", "ANY_ANY_ANY=disable"]) == 0
    changed = out.read_text(encoding="utf-8")
    assert "set rulebase security rules implicit-guest disabled yes" in changed and "implicit-guest disabled yes" not in plain
    text = report.read_text(encoding="utf-8")
    assert "[approximated] AUDIT_DISABLED: disabled by the audit (ANY_ANY_ANY), as asked" in text and "      -> disabled\n" in text
    # (The redundant rule has a schedule, which PAN-OS output does not get: it is written disabled for that.)
    assert "-> not in the output anyway" in text and "AUDIT_DISABLED: disabled by the audit (REDUNDANT_RULE)" not in text
    # A finding fails the run unless the rule was disabled for it.
    assert cli.main(args + ["--audit-fail-on", "medium"]) == 3
    assert cli.main(args + ["--audit-fail-on", "medium", "--strict"]) == 2
    rest = [option for check in ("RISKY_SERVICE", "ANY_ANY_ANY", "ANY_SERVICE", "ANY_TO_ANY") for option in ("--audit-action", f"{check}=disable")]
    assert cli.main(args + ["--audit-fail-on", "medium"] + rest) == 0
    # The model as it was read has nothing to audit into, and says so.
    capsys.readouterr()
    assert cli.main(["convert", sample, "--to", "json", "--audit", "-o", str(out)]) == 1
    assert "audit the configuration with 'fwshift audit'" in capsys.readouterr().err


def test_redundant_rule_disabled_in_a_conversion(tmp_path: Path) -> None:
    rules = (
        "*filter\n:FORWARD DROP [0:0]\n"
        "-A FORWARD -i eth1 -o eth0 -s 10.10.0.0/16 -p tcp --dport 443 -j ACCEPT\n"
        "-A FORWARD -i eth1 -o eth0 -s 10.10.5.0/24 -p tcp --dport 443 -j ACCEPT\n"
        "COMMIT\n"
    )
    source, out, report = tmp_path / "in.rules", tmp_path / "out.rules", tmp_path / "report.txt"
    source.write_text(rules, encoding="utf-8")
    args = ["convert", str(source), "--to", "iptables", "-o", str(out), "--report", str(report), "-q"]
    assert cli.main(args + ["--audit-action", "REDUNDANT_RULE=disable"]) == 0
    forward = [line for line in out.read_text(encoding="utf-8").splitlines() if line.startswith("-A FORWARD") and "eth1" in line]
    assert len(forward) == 1 and "10.10.0.0/16" in forward[0]
    text = report.read_text(encoding="utf-8")
    assert "[info] AUDIT_DISABLED: disabled by the audit (REDUNDANT_RULE): the rule decided no traffic" in text
    assert "-> disabled; no traffic is decided differently" in text


def test_moved_rule_in_a_conversion(tmp_path: Path) -> None:
    rules = (
        "*filter\n:FORWARD DROP [0:0]\n"
        "-A FORWARD -i eth1 -o eth0 -s 10.10.0.0/16 -j ACCEPT\n"
        "-A FORWARD -i eth1 -o eth0 -s 10.10.0.0/16 -p tcp --dport 23 -j DROP\n"
        "COMMIT\n"
    )
    source, out, report = tmp_path / "in.rules", tmp_path / "out.rules", tmp_path / "report.txt"
    source.write_text(rules, encoding="utf-8")
    args = ["convert", str(source), "--to", "iptables", "-o", str(out), "--report", str(report), "-q"]
    assert cli.main(args + ["--audit-action", "SHADOWED_RULE=reorder"]) == 0
    forward = [line for line in out.read_text(encoding="utf-8").splitlines() if line.startswith("-A FORWARD") and "eth1" in line]
    assert "--dport 23" in forward[0] and "DROP" in forward[0] and "ACCEPT" in forward[1]
    text = report.read_text(encoding="utf-8")
    assert "[needs-review] AUDIT_MOVED: moved up, in front of 'FORWARD-1' by the audit (SHADOWED_RULE), as asked" in text
    assert "SHADOWED_RULE: rule 'FORWARD-2' never matches" in text and "-> moved up, in front of 'FORWARD-1'" in text
    assert "no longer found" not in text


def test_blocking_rule_lost_in_a_conversion_is_named_with_what_it_exposes() -> None:
    """To an ASA a rule 'to zone outside, any address' is written inactive: the allow rule below then takes its traffic."""
    p = policy(
        Rule("no-telnet-out", src_zones=["inside"], dst_zones=["outside"], services=["telnet"], action=Action.DENY),
        Rule("inside-anywhere", src_zones=["inside"], sources=["lan"]),
        Rule("dmz-web", src_zones=["dmz"], sources=["web"], services=["https"]),
    )
    report = Report()
    config = AuditConfig()
    result = report.audit = audit.run(p, config)
    cli.convert(p, "asa", report)
    assert report.item("rule", "no-telnet-out").disabled
    cli._audit_after(p, result, config, report)
    exposed = [f for f in result.after or [] if f.check == "EXPOSED_BY_CONVERSION"]
    assert len(exposed) == 1 and exposed[0].name == "no-telnet-out" and exposed[0].level == Level.HIGH
    assert "'inside-anywhere' below it now allows part of what it blocked" in exposed[0].message
    text = report.to_text()
    # The count at the top is of the policy as it was read; what the conversion added has its own.
    assert "After the conversion\n  high 1, medium 0, low 0, info 0\n  [high] EXPOSED_BY_CONVERSION: rule 'no-telnet-out' blocks traffic" in text
    assert result.fails(Level.HIGH)
    # Written as it is (PAN-OS can say it), nothing is exposed.
    report = Report()
    result = report.audit = audit.run(p, config)
    cli.convert(p, "panos", report)
    cli._audit_after(p, result, config, report)
    assert result.after == []


def test_audit_reads_every_sample_like_the_converter() -> None:
    for sample in SAMPLES:
        p, _ = load(sample)
        result = audit.run(p)
        assert result.rules == len(p.rules) and not result.undecided
        assert all(f.check in audit.CHECKS for f in result.before)


def test_a_long_policy_is_audited_in_reasonable_time() -> None:
    import time

    rng = random.Random(7)
    p = Policy(vendor="panos")
    for index in range(40):
        p.zones[f"z{index}"] = Zone(f"z{index}")
    for index in range(1500):
        rule = Rule(
            f"r{index}", [f"z{rng.randrange(40)}"], [f"z{rng.randrange(40)}"], [f"10.{rng.randrange(200)}.{rng.randrange(250)}.0/24"],
            [f"10.{rng.randrange(200)}.0.0/16"], action=rng.choice([Action.ALLOW, Action.DROP]),
        )  # fmt: skip
        rule.origin = rule.name
        p.rules.append(rule)
    start = time.perf_counter()
    result = audit.run(p)
    assert time.perf_counter() - start < 30 and not result.undecided


def test_manual_lists_the_checks_as_the_code_has_them() -> None:
    """Section 13 of the manual is the reference for the checks: code, level and what can be done with each."""
    manual = (Path(__file__).resolve().parents[1] / "docs" / "MANUAL.md").read_text(encoding="utf-8")
    section = manual.split("## 13. Auditing a policy")[1]
    table = section.split("### The checks")[1].split("### Rules that never match")[0]
    rows = {}
    for line in table.splitlines():
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) == 4 and cells[0].startswith("`"):
            rows[cells[0].strip("`")] = (cells[1], cells[3])
    expected = {code: (level, actions) for code, level, _, actions, _ in audit.checks_table()}
    assert rows == expected
    off = {code for code, _, default, _, _ in audit.checks_table() if default == "off"}
    assert off == {"OVERLAPPING_RULES", "NO_DESCRIPTION"} and all(f"`{code}`" in section for code in off)
    # The thresholds and lists the manual names are the ones the code starts with.
    config = AuditConfig()
    assert (config.wide_network_v4, config.wide_network_v6, config.wide_ports, config.usage_days, config.wider_than_traffic) == (8, 32, 1024, 90, 10)
    assert ('"thresholds": {"wide_network_v4": 8, "wide_network_v6": 32, "wide_ports": 1024, "usage_days": 90, "wider_than_traffic": 10}'
            in section)  # fmt: skip
    assert str(audit._MAX_BOXES) in section
    example = section.split("```json")[1].split("```")[0]
    assert audit.load_config(example).action("SHADOWED_RULE") == "reorder"


# -- found in review ----------------------------------------------------------------------------

IPT_NAT = (
    "*nat\n:PREROUTING ACCEPT [0:0]\n"
    "-A PREROUTING -i eth0 -d 203.0.113.11/32 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.20.0.11:8080\nCOMMIT\n"
    "*filter\n:FORWARD DROP [0:0]\n"
    "-A FORWARD -i eth0 -o eth2 -d 10.20.0.11/32 -j ACCEPT\n"
    "-A FORWARD -i eth0 -o eth2 -d 203.0.113.11/32 -p tcp -m tcp --dport 22 -j DROP\n"
    "-A FORWARD -i eth0 -o eth2 -d 203.0.113.0/24 -j ACCEPT\nCOMMIT\n"
)
EVERY_DEAD = ["--audit-action", "SHADOWED_RULE=disable", "--audit-action", "REDUNDANT_RULE=disable", "--audit-action", "EMPTY_RULE=disable"]


def test_a_source_that_matches_after_nat_is_audited_as_it_matched(tmp_path: Path) -> None:
    """The parser adds the public address to a rule for the server: that stands for the translated traffic,
    not for everything sent to the public address. SSH to it was never the first rule's."""
    report = Report()
    p = cli.load(IPT_NAT.encode(), "iptables", report)
    assert p.rules[0].nat_added and len(p.rules[0].destinations) == 2
    result = audit.run(p, None, report)
    assert not [f for f in result.before if f.check in ORDER]
    source, out = tmp_path / "in.rules", tmp_path / "out.rules"
    source.write_text(IPT_NAT, encoding="utf-8")
    assert cli.main(["convert", str(source), "--to", "iptables", "-o", str(out), "-q"] + EVERY_DEAD) == 0
    assert "-d 203.0.113.11/32 -p tcp -m tcp --dport 22" in out.read_text(encoding="utf-8")
    # A rule that is dead on the source is still found: the same destination twice.
    twice = IPT_NAT.replace("-A FORWARD -i eth0 -o eth2 -d 203.0.113.0/24 -j ACCEPT\n",
                            "-A FORWARD -i eth0 -o eth2 -d 10.20.0.11/32 -p tcp -m tcp --dport 8080 -j ACCEPT\n")  # fmt: skip
    report = Report()
    found_dead = [f for f in audit.run(cli.load(twice.encode(), "iptables", report), None, report).before if f.check in ORDER]
    assert [(f.check, f.shown or f.name) for f in found_dead] == [("REDUNDANT_RULE", "FORWARD-3")]


def _random_iptables_with_nat(rng: random.Random) -> str:
    publics, servers = ["203.0.113.10", "203.0.113.11"], ["10.20.0.10", "10.20.0.11"]
    nat = []
    for public in rng.sample(publics, rng.randint(1, 2)):
        port = rng.choice(["", "", "80", "443"])
        match = f" -p tcp -m tcp --dport {port}" if port else ""
        to = rng.choice(servers) + (f":{rng.choice(['8080', port])}" if port and rng.random() < 0.5 else "")
        nat.append(f"-A PREROUTING -i eth0 -d {public}/32{match} -j DNAT --to-destination {to}")
    rules = []
    for _ in range(rng.randint(4, 9)):
        parts = ["-A FORWARD"]
        if rng.random() < 0.7:
            parts.append(f"-i {rng.choice(['eth0', 'eth0', 'eth1'])}")
        if rng.random() < 0.5:
            parts.append(f"-o {rng.choice(['eth2', 'eth1'])}")
        if rng.random() < 0.8:
            parts.append("-d " + rng.choice([f"{a}/32" for a in publics + servers] + ["203.0.113.0/24", "10.20.0.0/24", "10.20.0.0/16"]))
        if rng.random() < 0.6:
            parts.append(f"-p tcp -m tcp --dport {rng.choice(['22', '80', '443', '8080'])}")
        parts.append("-j " + rng.choice(["ACCEPT", "ACCEPT", "DROP"]))
        rules.append(" ".join(parts))
    return ("*nat\n:PREROUTING ACCEPT [0:0]\n" + "\n".join(nat) + "\nCOMMIT\n*filter\n:FORWARD "
            + rng.choice(["DROP", "ACCEPT"]) + " [0:0]\n" + "\n".join(rules) + "\nCOMMIT\n")  # fmt: skip


def test_disabling_dead_rules_of_an_iptables_source_with_nat_changes_no_packet(tmp_path: Path) -> None:
    """iptables to iptables, with and without the audit's disabling: the two outputs decide every packet alike."""
    from test_iptables import iptables_allows

    packets = [Packet(in_if, out_if, "192.0.2.9", dst, proto, 1024, port)
               for in_if in ("eth0", "eth1") for out_if in ("eth1", "eth2")
               for dst in ("203.0.113.10", "203.0.113.11", "203.0.113.99", "10.20.0.10", "10.20.0.11", "10.20.0.99", "10.20.9.9", "192.0.2.1")
               for proto, port in (("tcp", 22), ("tcp", 80), ("tcp", 443), ("tcp", 8080), ("tcp", 9), ("udp", 80))]  # fmt: skip
    source, plain, trimmed, report = (tmp_path / name for name in ("in.rules", "plain.rules", "trimmed.rules", "report.txt"))
    disabled = 0
    for seed in range(250):
        source.write_text(_random_iptables_with_nat(random.Random(seed)), encoding="utf-8")
        assert cli.main(["convert", str(source), "--to", "iptables", "-o", str(plain), "-q"]) == 0
        assert cli.main(["convert", str(source), "--to", "iptables", "-o", str(trimmed), "--report", str(report), "-q"] + EVERY_DEAD) == 0
        before, after = plain.read_text(encoding="utf-8"), trimmed.read_text(encoding="utf-8")
        disabled += report.read_text(encoding="utf-8").count("-> disabled; no traffic is decided differently")
        for pkt in packets:
            assert iptables_allows(after, pkt) == iptables_allows(before, pkt), (seed, pkt, source.read_text(encoding="utf-8"))
    assert disabled > 150


FORTI_VIP = (
    'config system settings\n    set central-nat enable\nend\n'
    'config firewall address\n    edit "srv2"\n        set subnet 10.20.0.11 255.255.255.255\n    next\n'
    '    edit "pubhost"\n        set subnet 203.0.113.11 255.255.255.255\n    next\n'
    '    edit "pubnet"\n        set subnet 203.0.113.0 255.255.255.0\n    next\nend\n'
    'config firewall service custom\n    edit "SSH"\n        set tcp-portrange 22\n    next\nend\n'
    'config firewall vip\n    edit "web"\n        set extip 203.0.113.11\n        set mappedip "10.20.0.11"\n        set extintf "wan"\n'
    '        set portforward enable\n        set protocol tcp\n        set extport 80\n        set mappedport 8080\n    next\nend\n'
    'config firewall policy\n'
    + "".join(
        f'    edit {number}\n        set name "{name}"\n        set srcintf "wan"\n        set dstintf "dmz"\n        set action {action}\n'
        f'        set srcaddr "all"\n        set dstaddr "{dst}"\n        set schedule "always"\n        set service "{service}"\n'
        f'        set logtraffic all\n{extra}    next\n'
        for number, name, action, dst, service, extra in (
            (1, "to-server", "accept", "srv2", "ALL", ""),
            (2, "no-ssh-to-public", "deny", "pubhost", "SSH", "        set match-vip enable\n"),
            (3, "public-net", "accept", "pubnet", "ALL", ""),
        )
    )
    + "end\n"
)


def test_fortios_policy_for_the_address_a_virtual_ip_publishes() -> None:
    report = Report()
    p = cli.load(FORTI_VIP.encode(), "fortios", report)
    result = audit.run(p, None, report)
    assert not [f for f in result.before if f.check in ORDER] and not result.loose


def test_listed_members_of_a_group_with_excluded_members_prove_nothing() -> None:
    conf = (
        'config firewall address\n    edit "lan"\n        set subnet 10.10.0.0 255.255.0.0\n    next\n'
        '    edit "admins"\n        set subnet 10.10.0.5 255.255.255.255\n    next\nend\n'
        'config firewall addrgrp\n    edit "lan-without-admins"\n        set member "lan"\n        set exclude enable\n'
        '        set exclude-member "admins"\n    next\nend\n'
        'config firewall policy\n'
        '    edit 1\n        set name "users-no-mgmt"\n        set srcintf "lan"\n        set dstintf "mgmt"\n        set action deny\n'
        '        set srcaddr "lan-without-admins"\n        set dstaddr "all"\n        set schedule "always"\n        set service "ALL"\n    next\n'
        '    edit 2\n        set name "admins-to-mgmt"\n        set srcintf "lan"\n        set dstintf "mgmt"\n        set action accept\n'
        '        set srcaddr "admins"\n        set dstaddr "all"\n        set schedule "always"\n        set service "ALL"\n    next\nend\n'
    )
    report = Report()
    p = cli.load(conf.encode(), "fortios", report)
    assert p.address_groups["lan-without-admins"].unsupported
    assert not [f for f in audit.run(p, None, report).before if f.check in ORDER]
    # The same in the model: a group that cannot be converted, a dynamic one, and a group that holds one.
    for change in ("unsupported", "dynamic_filter"):
        q = policy(Rule("deny-group", sources=["grp"], action=Action.DROP), Rule("allow-web", sources=["web"]))
        q.address_groups["grp"] = AddressGroup("grp", ["web", "lan"])
        assert _dead(q) == {"allow-web": ["SHADOWED_RULE"]}
        setattr(q.address_groups["grp"], change, "something")
        assert _dead(q) == {}, change
        q.address_groups["outer"] = AddressGroup("outer", ["grp", "lan"])
        q.rules[0].sources = ["outer"]
        assert _dead(q) == {}, change
        # What stands next to such a group in a group is still known.
        q.address_groups["outer"].members = ["grp", "corp"]
        assert _dead(q) == {"allow-web": ["SHADOWED_RULE"]}, change


def test_rules_the_parser_read_approximately_are_left_out() -> None:
    p = policy(Rule("first", sources=["lan"], action=Action.DROP), Rule("second", sources=["lan"], services=["https"]),
               Rule("third", sources=["web"]), Rule("fourth", sources=["web"], services=["https"]))  # fmt: skip
    assert _dead(p) == {"second": ["SHADOWED_RULE"], "fourth": ["REDUNDANT_RULE"]}
    # "Installed on one gateway only", "attributes this converter does not know": what such a rule takes is not known.
    report = Report()
    report.add("rule", "first", audit_severity("review"), "DEVICE_TARGET", "the rule is installed only on gw-a")
    result = audit.run(p, None, report)
    assert {f.name for f in result.before if f.check in ORDER} == {"fourth"} and result.loose == {"first": ["DEVICE_TARGET"]}
    assert "Left out of the order checks\n  1 rule(s) that the model holds only approximately" in result.to_text()
    assert "'first' (DEVICE_TARGET)" in result.to_text()
    # Nor is such a rule called dead itself: it may match more than the model says.
    report = Report()
    report.add("rule", "fourth", audit_severity("approximated"), "SOMETHING_NEW", "the model is not the rule")
    assert {f.name for f in audit.run(p, None, report).before if f.check in ORDER} == {"second"}
    # A note for the reader, or a finding about NAT (which the audit reads as the source did), changes nothing.
    report = Report()
    report.add("rule", "first", audit_severity("info"), "IMPLICIT_PERMIT", "said for the record")
    report.add("rule", "third", audit_severity("approximated"), "NAT_DESTINATION_REWRITTEN", "added a pre-NAT destination")
    assert {f.name for f in audit.run(p, None, report).before if f.check in ORDER} == {"second", "fourth"}
    # An object that is only partly known (a gateway with its main address) stands for more than the model has:
    # its addresses prove nothing. Two rules that name it still say the same, whatever it stands for.
    p.rules.append(Rule("fifth", sources=["10.20.0.10"], services=["https"]))
    p.rules[-1].origin, p.rules[-1].profiles = "fifth", {"group": "default"}
    assert {f.name for f in audit.run(p).before if f.check in ORDER} == {"second", "fourth", "fifth"}
    report = Report()
    report.add("address", "web", audit_severity("approximated"), "GATEWAY_OBJECT", "only its main address is in the export")
    assert {f.name for f in audit.run(p, None, report).before if f.check in ORDER} == {"second", "fourth"}


def audit_severity(label: str) -> "object":
    from fwshift.report import Severity

    return {"info": Severity.INFO, "approximated": Severity.APPROX, "review": Severity.REVIEW}[label]


def test_what_a_rule_does_besides_its_verdict_is_part_of_how_it_handles_traffic() -> None:
    conf = (
        'config firewall address\n    edit "lan"\n        set subnet 10.10.0.0 255.255.0.0\n    next\n'
        '    edit "guests"\n        set subnet 10.10.9.0 255.255.255.0\n    next\nend\n'
        'config firewall policy\n'
        '    edit 1\n        set name "guests-out"\n        set srcintf "lan"\n        set dstintf "wan"\n        set action accept\n'
        '        set srcaddr "guests"\n        set dstaddr "all"\n        set schedule "always"\n        set service "ALL"\n'
        '        set logtraffic all\nEXTRA    next\n'
        '    edit 2\n        set name "lan-out"\n        set srcintf "lan"\n        set dstintf "wan"\n        set action accept\n'
        '        set srcaddr "lan"\n        set dstaddr "all"\n        set schedule "always"\n        set service "ALL"\n'
        '        set logtraffic all\n    next\nend\n'
    )

    def dead(extra: str) -> List[str]:
        report = Report()
        p = cli.load(conf.replace("EXTRA", extra).encode(), "fortios", report)
        return [f.shown or f.name for f in audit.run(p, None, report).before if f.check in ORDER]

    assert dead("") == ["guests-out"]
    # Source NAT, a shaper: without the first policy that traffic would be handled differently by the second.
    assert dead("        set nat enable\n") == [] and dead('        set traffic-shaper "guest-limit"\n') == []
    assert dead('        set comments "for the guests"\n') == ["guests-out"]
    first, second = Rule("first", sources=["web"]), Rule("second", sources=["web"])
    first.handling = {"log-setting": "to-siem"}
    assert _dead(policy(first, second)) == {"second": ["REDUNDANT_RULE"]}  # the second never matches, whatever it does
    assert _dead(policy(Rule("narrow", sources=["web"]), Rule("wide"))) == {"narrow": ["REDUNDANT_RULE"]}
    narrow = Rule("narrow", sources=["web"])
    narrow.handling = {"log-setting": "to-siem"}
    assert _dead(policy(narrow, Rule("wide"))) == {}


PAN_LOST = (
    '<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
    '<address><entry name="partner"><ip-netmask>198.51.100.0/24</ip-netmask></entry></address>'
    "<rulebase><security><rules>"
    + "".join(
        f'<entry name="{name}"><from><member>{src}</member></from><to><member>{dst}</member></to><source><member>any</member></source>'
        f"<destination><member>{target}</member></destination><application><member>any</member></application>"
        f"<service><member>any</member></service><action>{action}</action>{extra}</entry>"
        for name, src, dst, target, action, extra in (
            ("no-out", "trust", "untrust", "any", "deny", ""),
            ("no-partner", "trust", "untrust", "partner", "deny", ""),
            ("rest", "trust", "any", "any", "allow", ""),
            ("dmz-out", "dmz", "untrust", "partner", "allow", ""),
        )
    )
    + "</rules></security></rulebase></entry></vsys></entry></devices></config>"
)


def test_rule_is_not_disabled_as_redundant_next_to_a_rule_the_target_cannot_take(tmp_path: Path) -> None:
    """To an ASA 'deny to zone untrust, any address' is written inactive: the deny for the partner network below it,
    redundant on the source, is the one that still blocks."""
    source, out, report = tmp_path / "in.xml", tmp_path / "out.cfg", tmp_path / "report.txt"
    source.write_text(PAN_LOST, encoding="utf-8")
    args = ["convert", str(source), "--to", "asa", "-o", str(out), "--report", str(report), "-q"]
    assert cli.main(args + ["--audit-action", "REDUNDANT_RULE=disable"]) == 0
    text, written = report.read_text(encoding="utf-8"), out.read_text(encoding="utf-8")
    assert "access-list trust_access_in extended deny ip any object partner\n" in written
    assert "REDUNDANT_RULE: rule 'no-partner' never matches" in text and "-> kept: with the other changes, or without the rules" in text
    assert "AUDIT_DISABLED" not in text and "EXPOSED_BY_CONVERSION: rule 'no-out'" in text
    assert "these never matched on the source and do in the output, because rules above them were not written: 'no-partner'" in text
    # To a target that takes the rule above it, it goes.
    assert cli.main(["convert", str(source), "--to", "panos", "-o", str(out), "--report", str(report), "-q",
                     "--audit-action", "REDUNDANT_RULE=disable"]) == 0  # fmt: skip
    assert "set rulebase security rules no-partner disabled yes" in out.read_text(encoding="utf-8")
    # The net under it: a rule that was disabled as redundant and is needed after all is said to be.
    p = policy(Rule("no-out", action=Action.DROP), Rule("no-web", destinations=["web"], action=Action.DROP), Rule("rest"))
    config = AuditConfig()
    config.set_action("REDUNDANT_RULE", "disable")
    result = audit.run(p, config)
    audit.apply(p, result, config)
    assert not p.rules[1].enabled
    audit.compare(result, audit.effective(p, ["no-out"]), config, ["no-out"])
    needed = [f for f in result.after or [] if f.name == "no-web"]
    assert len(needed) == 1 and needed[0].check == "EXPOSED_BY_CONVERSION" and "is needed again" in needed[0].message


def test_blocking_rule_inside_a_zone_lost_in_a_conversion() -> None:
    p = policy(Rule("no-lateral", src_zones=["inside"], scope=RuleScope.INTRAZONE, action=Action.DENY),
               Rule("out", src_zones=["inside"], dst_zones=["outside"], sources=["lan"], services=["https"]))  # fmt: skip
    for default, expected in ((Action.ALLOW, 1), (Action.DENY, 0)):
        p.default_intrazone = default
        result = audit.run(p)
        audit.compare(result, audit.effective(p, ["no-lateral"]), AuditConfig(), ["no-lateral"])
        exposed = [f for f in result.after or [] if f.check == "EXPOSED_BY_CONVERSION"]
        assert len(exposed) == expected
        if exposed:
            assert "the default for traffic inside a zone now allows part of what it blocked" in exposed[0].message
    # A rule between two zones is not about traffic inside one.
    q = policy(Rule("no-out", src_zones=["inside"], dst_zones=["outside"], action=Action.DENY))
    q.default_intrazone = Action.ALLOW
    result = audit.run(q)
    audit.compare(result, audit.effective(q, ["no-out"]), AuditConfig(), ["no-out"])
    assert result.after == []


def test_rule_for_every_other_zone_is_not_kept_to_one_path() -> None:
    """What 'permit ip any any' on an interface becomes: a rule from that zone to all the others."""
    text = (
        "ASA Version 9.12(4)\ninterface GigabitEthernet0/0\n nameif outside\n security-level 0\n ip address 203.0.113.2 255.255.255.0\n"
        "interface GigabitEthernet0/1\n nameif inside\n security-level 100\n ip address 10.10.0.1 255.255.0.0\n"
        "interface GigabitEthernet0/2\n nameif dmz\n security-level 50\n ip address 10.20.0.1 255.255.255.0\n"
        "access-list O extended permit ip any any\naccess-group O in interface outside\n"
    )
    report = Report()
    result = audit.run(cli.load(text.encode(), "asa", report), None, report)
    levels = {f.shown or f.name: f.level for f in result.before if f.check == "ANY_ANY_ANY"}
    assert levels["O-1"] == Level.HIGH and levels["implicit-inside"] == Level.HIGH
    assert levels["implicit-dmz"] == Level.MEDIUM  # the dmz reaches the outside only: its security level keeps it there
    assert result.fails(Level.HIGH)
    p = policy(Rule("two", src_zones=["inside"], dst_zones=["outside", "dmz"]), Rule("one", src_zones=["dmz"], dst_zones=["outside"]),
               Rule("within", src_zones=["dmz"], scope=RuleScope.INTRAZONE))  # fmt: skip
    assert {f.name: f.level for f in audit.run(p).before if f.check == "ANY_ANY_ANY"} == {
        "two": Level.HIGH, "one": Level.MEDIUM, "within": Level.MEDIUM}  # fmt: skip


def test_addresses_of_different_ip_versions_meet_in_no_packet() -> None:
    v4, v6 = "10.10.0.0/16", "2001:db8::/32"
    cross = Rule("cross", sources=[v4], destinations=[v6])
    assert _dead(policy(cross)) == {"cross": ["EMPTY_RULE"]}
    assert "no IP version in common" in next(f.message for f in audit.run(policy(Rule("cross", sources=[v4], destinations=[v6]))).before
                                             if f.check == "EMPTY_RULE")  # fmt: skip
    # "From the LAN to every IPv4 address" holds all that "from the LAN to any" can match.
    p = policy(Rule("no-lan", sources=[v4], destinations=["0.0.0.0/0"], action=Action.DROP), Rule("lan-web", sources=[v4], services=["https"]))
    assert _dead(p) == {"lan-web": ["SHADOWED_RULE"]}
    p = policy(Rule("v4", sources=[v4], destinations=["0.0.0.0/0"]), Rule("v6", sources=[v6], destinations=["::/0"]),
               Rule("both", sources=[v4, v6]))  # fmt: skip
    assert _dead(p) == {"both": ["REDUNDANT_RULE"]}


def test_names_that_look_like_patterns_and_names_that_match_nothing() -> None:
    p = policy(Rule("Allow [DMZ]", destinations=["web"], services=["https"]), Rule("Allow D", destinations=["web"], services=["https"]))
    p.default_interzone = Action.ALLOW
    config = AuditConfig()
    config.accept("Allow [DMZ]", ["ANY_SOURCE"])
    config.accept("No-Such-Rule")
    config.accept("default")
    result = audit.run(p, config)
    accepted = [(f.check, f.shown or f.name) for f in result.before if f.action == audit.ACCEPT]
    assert accepted == [("ANY_SOURCE", "Allow [DMZ]")]
    assert result.unmatched == ["No-Such-Rule", "default"]
    assert "Accepted, but not found\n  nothing answers to 'No-Such-Rule', 'default': check the names" in result.to_text()
    # What holds for the whole policy is accepted by the name of its check only.
    assert result.fails(Level.HIGH)
    config = AuditConfig()
    config.accept("*", ["DEFAULT_ALLOW"])
    assert not [f for f in audit.run(p, config).before if f.check == "DEFAULT_ALLOW" and f.action != audit.ACCEPT]
    # A second run starts from scratch.
    assert audit.run(p, config).unmatched == []


def test_configuration_file_is_strict_about_what_it_does_not_know() -> None:
    for text, message in (
        ('{"checks": {"ANY_SOURCES": {"level": "info"}}}', "there is no check 'ANY_SOURCES'"),
        ('{"checks": {"NO_LOG": {"action": "report", "levle": "high"}}}', "unknown key 'levle' in the settings of NO_LOG"),
        ('{"checks": {"NO_LOG": 3}}', "is an action, or an object"),
        ('{"accept": [{"rule": "x", "cheks": ["NO_LOG"]}]}', "unknown key 'cheks' in an entry of 'accept'"),
        ('{"applications": {"risky": "telnet"}}', "applications.risky is a list"),
        ('{"applications": {"other": []}}', "'applications' holds"),
        ("[" * 100000, "is not JSON"),
    ):
        with pytest.raises(FwshiftError, match=message):
            audit.load_config(text)
    config = audit.load_config('{"services": {"risky": {}}, "applications": {"risky": ["ssh"], "industrial": []}}')
    p = policy(Rule("apps", sources=["lan"], destinations=["web"], applications=["ssh", "ms-rdp", "modbus"], services=[APP_DEFAULT]))
    assert checks_of(p, "apps", config) == ["RISKY_SERVICE"]
    assert "allows ssh, " in next(f.message for f in audit.run(p, config).before if f.check == "RISKY_SERVICE")


def test_many_zones_and_many_rules_on_one_path() -> None:
    import time

    rng = random.Random(3)
    p = Policy(vendor="iptables")
    for index in range(1500):
        rule = Rule(f"r{index}", [f"if{index}"], [f"if{rng.randrange(1500)}"], ["10.0.0.0/8"], [f"10.{rng.randrange(250)}.0.0/16"],
                    action=rng.choice([Action.ALLOW, Action.DROP]))  # fmt: skip
        rule.origin = rule.name
        p.rules.append(rule)
    start = time.perf_counter()
    assert not audit.run(p).undecided
    assert time.perf_counter() - start < 20
    q = Policy(vendor="iptables")
    for index in range(2000):
        rule = Rule(f"r{index}", ["a"], ["b"], [f"10.{index // 250}.{index % 250}.1"], [f"10.9.{rng.randrange(250)}.{rng.randrange(250)}"])
        rule.origin = rule.name
        q.rules.append(rule)
    start = time.perf_counter()
    audit.run(q)
    assert time.perf_counter() - start < 20


@pytest.mark.parametrize("seed", range(40))
def test_counting_services_counts_each_of_them_once(seed: int) -> None:
    rng = random.Random(seed)
    a, _ = _random_services(rng)
    b, _ = _random_services(rng)
    # A count is a count when a set is as large as its two parts.
    assert a.volume() == a.and_(b).volume() + a.minus(b).volume()
    assert audit._union([a, b]).volume() == a.volume() + b.minus(a).volume()
    assert a.volume(exact=False) >= a.volume()
    assert (a.volume() == 0) == a.empty() and Services({}, True).volume() == 256 * 65536 * 65536


def test_broad_rule_below_thousands_of_narrow_ones() -> None:
    """A broad rule is not cut into pieces by every host rule above it before the rule that holds all of it is seen."""
    import time

    def build(tail: Sequence[Rule]) -> Policy:
        p = Policy(vendor="asa")
        p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
        for index in range(2500):
            p.rules.append(Rule(f"host{index}", ["inside"], ["outside"], [f"10.{index // 250}.{index % 250}.7"],
                                [f"172.16.{index // 250}.{index % 250}"], ["https"]))  # fmt: skip
        p.rules += tail
        for rule in p.rules:
            rule.origin = rule.name
        return p

    start = time.perf_counter()
    # Nothing above it holds a broad rule: counting says so.
    result = audit.run(build([Rule("broad", ["inside"], [ANY], ["10.0.0.0/8"], action=Action.DROP)]))
    assert not result.undecided and not [f for f in result.before if f.check in ORDER]
    # A rule that blocks everything, and broad rules below it: each is dead, and the rules that take part are named in their order.
    result = audit.run(build([
        Rule("clean-up", ["inside"], [ANY], action=Action.DROP),
        Rule("after-1", ["inside"], [ANY], ["10.0.0.0/8"]),
        Rule("after-2", ["inside"], [ANY], ["10.0.0.0/8"], services=["https"], action=Action.DROP),
        Rule("after-3", ["inside"], ["outside"], ["10.0.0.7"], ["172.16.0.0"], ["https"]),
    ]))  # fmt: skip
    assert not result.undecided
    dead = {f.name: f for f in result.before if f.check in ORDER}
    assert {name: f.check for name, f in dead.items()} == {"after-1": "SHADOWED_RULE", "after-2": "REDUNDANT_RULE", "after-3": "REDUNDANT_RULE"}
    assert len(dead["after-1"].related) == 2501 and dead["after-1"].related[0] == "clean-up"
    assert dead["after-2"].related == ["clean-up"]  # the host rules allow part of it, but the rule above them blocks all of it
    assert dead["after-3"].related == ["host0"]
    assert time.perf_counter() - start < 30


# -- found in the second review of the audit ---------------------------------------------------------------------

IPT_CROSS = """*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -i eth0 -d 203.0.113.11/32 -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.20.0.11
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i eth0 -o eth2 -d 10.20.0.11/32 -p tcp -m tcp --dport 80 -j DROP
-A FORWARD -i eth0 -o eth2 -d 203.0.113.11/32 -j ACCEPT
-A FORWARD -i eth0 -o eth2 -d 10.20.0.0/24 -j DROP
COMMIT
"""

PAN_CROSS = (
    '<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><address>'
    '<entry name="pub"><ip-netmask>203.0.113.11/32</ip-netmask></entry><entry name="srv"><ip-netmask>10.20.0.11/32</ip-netmask></entry>'
    '<entry name="pubnet"><ip-netmask>203.0.113.0/24</ip-netmask></entry></address><rulebase><security><rules>'
    + "".join(
        f'<entry name="{name}"><from><member>untrust</member></from><to><member>dmz</member></to><source><member>any</member></source>'
        f"<destination><member>{target}</member></destination><application><member>any</member></application>"
        f"<service><member>any</member></service><action>{action}</action><log-end>yes</log-end></entry>"
        for name, target, action in (("no-web", "pub", "deny"), ("direct", "srv", "allow"), ("no-pubnet", "pubnet", "deny"))
    )
    + '</rules></security><nat><rules><entry name="web"><from><member>untrust</member></from><to><member>untrust</member></to>'
    "<source><member>any</member></source><destination><member>pub</member></destination><service>any</service>"
    "<destination-translation><translated-address>srv</translated-address></destination-translation></entry></rules></nat>"
    "</rulebase></entry></vsys></entry></devices></config>"
)
KEPT = "-> kept: in the output it decides traffic. The target does not match its rules as the source did"


def test_rule_is_disabled_only_when_it_changes_nothing_as_the_target_matches(tmp_path: Path) -> None:
    """A rule that changes nothing where rules are matched after destination NAT may decide traffic where they are
    matched before it, and the other way round: what is disabled is proven on what is written as well."""
    out, report = tmp_path / "out", tmp_path / "report.txt"
    disable = ["-o", str(out), "--report", str(report), "-q", "--audit-action", "REDUNDANT_RULE=disable"]
    # iptables: the drop for the server's own address and port 80 adds nothing, the rule for its network drops that too.
    source = tmp_path / "in.rules"
    source.write_text(IPT_CROSS, encoding="utf-8")
    assert cli.main(["convert", str(source), "--to", "iptables"] + disable) == 0
    assert '# disabled by the audit: "FORWARD-2"' in out.read_text(encoding="utf-8") and KEPT not in report.read_text(encoding="utf-8")
    # On PAN-OS the same rule is the one that blocks the published address: the rule below it would allow that.
    assert cli.main(["convert", str(source), "--to", "panos"] + disable) == 0
    written, text = out.read_text(encoding="utf-8"), report.read_text(encoding="utf-8")
    assert "set rulebase security rules FORWARD-2 destination [ 10.20.0.11/32 203.0.113.11/32 ]" in written
    assert "FORWARD-2 disabled yes" not in written and "AUDIT_DISABLED" not in text
    assert "REDUNDANT_RULE: rule 'FORWARD-2' adds nothing" in text and KEPT in text
    # The other way round. PAN-OS: 'no-web' blocks the published address, as the rule for its network does further down.
    source = tmp_path / "in.xml"
    source.write_text(PAN_CROSS, encoding="utf-8")
    assert cli.main(["convert", str(source), "--to", "panos"] + disable) == 0
    assert "set rulebase security rules no-web disabled yes" in out.read_text(encoding="utf-8")
    # iptables sees the server's address there, and the rule that allows the server comes next.
    for target in ("fortios", "asa", "iptables"):
        assert cli.main(["convert", str(source), "--to", target] + disable) == 0, target
        text = report.read_text(encoding="utf-8")
        assert "AUDIT_DISABLED" not in text and KEPT in text, target
    assert '-A FORWARD -i untrust -o dmz -d 10.20.0.11/32 -m comment --comment "no-web" -j REJECT\n' in out.read_text(encoding="utf-8")


def test_proof_on_what_is_written_in_the_model() -> None:
    p = policy(Rule("block-web", destinations=["web"], action=Action.DROP), Rule("block-lan", destinations=["lan", "web"], action=Action.DROP))
    config = AuditConfig()
    config.set_action("REDUNDANT_RULE", "disable")

    def as_it_is(candidate: Policy) -> Tuple[Optional[Policy], List[str]]:
        return copy.deepcopy(candidate), []

    def with_a_rule_in_between(candidate: Policy) -> Tuple[Optional[Policy], List[str]]:
        written = copy.deepcopy(candidate)
        written.rules[1].destinations = ["lan"]  # as if the target had been given another address for it
        return written, []

    for trial, disabled in ((None, True), (as_it_is, True), (with_a_rule_in_between, False)):
        q = copy.deepcopy(p)
        result = audit.run(q, config)
        done = audit.apply(q, result, config, (), trial)
        assert (not q.rules[0].enabled) == disabled and bool(done) == disabled
        assert [f.done.split(":")[0].split(";")[0] for f in result.before if f.check == "REDUNDANT_RULE"] == ["disabled" if disabled else "kept"]
    # The net after the conversion looks at what was written too.
    q = copy.deepcopy(p)
    result = audit.run(q, config)
    audit.apply(q, result, config)
    audit.compare(result, audit.effective(q, []), config, [], with_a_rule_in_between(q)[0])
    assert [(f.check, f.name) for f in result.after or [] if "is needed again" in f.message] == [("EXPOSED_BY_CONVERSION", "block-web")]


def test_what_a_conversion_exposed_is_not_accepted_with_the_rule(tmp_path: Path) -> None:
    source, out, report = tmp_path / "in.xml", tmp_path / "out.cfg", tmp_path / "report.txt"
    source.write_text(PAN_LOST, encoding="utf-8")
    args = ["convert", str(source), "--to", "asa", "-o", str(out), "--report", str(report), "-q", "--audit-fail-on", "high",
            "--audit-action", "ANY_ANY_ANY=off"]  # fmt: skip
    # "Every finding about these rules is fine" was said about the source.
    assert cli.main(args + ["--audit-accept", "no-*"]) == 3
    text = report.read_text(encoding="utf-8")
    assert "[high] EXPOSED_BY_CONVERSION: rule 'no-out'" in text and "REDUNDANT_RULE: rule 'no-partner' (accepted on the command line)" in text
    # A rule that was accepted as dead and matches in the output is still named.
    assert "these never matched on the source and do in the output, because rules above them were not written: 'no-partner'" in text
    # By the name of the check it is accepted, and listed.
    assert cli.main(args + ["--audit-accept", "no-*", "--audit-accept", "no-out=EXPOSED_BY_CONVERSION"]) == 0
    text = report.read_text(encoding="utf-8")
    assert "nothing new: the converted policy has no finding the source had not (but see what was accepted)" in text
    assert "  EXPOSED_BY_CONVERSION: rule 'no-out' (accepted on the command line)" in text


def test_findings_of_a_rule_the_audit_disabled_do_not_fail_the_run() -> None:
    p = policy(Rule("open"), Rule("open-again"))
    config = AuditConfig()
    config.set_action("REDUNDANT_RULE", "disable")
    config.accept("open", ["ANY_ANY_ANY"])
    result = audit.run(p, config)
    assert result.fails(Level.HIGH)  # 'open-again' allows everything too
    audit.apply(p, result, config)
    assert not p.rules[1].enabled and not result.fails(Level.HIGH) and not result.fails(Level.LOW)
    # A rule that is disabled for what it allows no longer counts either; one that is kept does.
    q = policy(Rule("open"), Rule("telnet", sources=["lan"], destinations=["web"], services=["telnet"]))
    config = AuditConfig()
    config.set_action("ANY_ANY_ANY", "disable")
    result = audit.run(q, config)
    audit.apply(q, result, config)
    assert not result.fails(Level.HIGH) and result.fails(Level.MEDIUM)
    # (What was found on the source stays found: 'telnet' never matched there.)
    assert {f.check for f in result.reported()} == {"RISKY_SERVICE", "REDUNDANT_RULE", "UNUSED_OBJECT"}


@pytest.mark.parametrize("seed", range(30))
def test_patterns_have_two_wildcards_and_always_answer(seed: int) -> None:
    import re
    import time

    rng = random.Random(seed)
    for _ in range(300):
        pattern = "".join(rng.choice("ab*?[.") for _ in range(rng.randint(0, 6)))
        name = "".join(rng.choice("ab[.") for _ in range(rng.randint(0, 7)))
        expected = re.fullmatch("".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern), name, re.DOTALL)
        assert audit._like(pattern, name) == bool(expected), (pattern, name)
    start = time.perf_counter()
    assert not audit._like("*a" * 30 + "*b", "a" * 2000)
    assert audit._like("*a" * 30 + "*", "a" * 2000)
    assert time.perf_counter() - start < 2


def test_object_that_was_read_approximately_is_no_duplicate() -> None:
    p = policy(Rule("r", sources=["web", "web-2", "gw"]))
    p.addresses["web-2"] = Address("web-2", AddressKind.NETWORK, "10.20.0.10/32")
    p.addresses["gw"] = Address("gw", AddressKind.NETWORK, "10.20.0.10/32")
    assert "the same address under 3 names: 'web', 'web-2', 'gw'" in [f.message for f in audit.run(p).before if f.check == "DUPLICATE_OBJECT"]
    report = Report()
    report.add("address", "gw", audit_severity("approximated"), "GATEWAY_OBJECT", "only its main address is in the export")
    assert "the same address under 2 names: 'web', 'web-2'" in [f.message for f in audit.run(p, None, report).before if f.check == "DUPLICATE_OBJECT"]


@pytest.mark.parametrize("seed", range(60))
def test_rules_that_take_part_are_the_same_however_they_are_found(seed: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """In few pieces a rule is followed through the rules above it in their order; in many, cover by cover."""
    rng = random.Random(seed)
    p = small_model(rng, static=rng.random() < 0.7)
    config = AuditConfig()
    if seed % 2:
        config.set_action("OVERLAPPING_RULES", "report")

    def findings() -> List[Tuple[str, str, str, Tuple[str, ...]]]:
        return [(f.check, f.name, f.message, tuple(f.related)) for f in audit.run(copy.deepcopy(p), config).before]

    usual = findings()
    monkeypatch.setattr(audit, "_FEW_BOXES", -1)
    assert findings() == usual
