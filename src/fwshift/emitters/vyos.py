# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""VyOS emitter: neutral model -> ``set`` commands for VyOS 1.4 and later, to paste into a configuration session.

Design rules:

* The commands only add: groups, named chains, zones and NAT rules, the objects under a prefix of their own (``FWS-``).
  Nothing that is there is deleted. A configuration session applies all of them at ``commit`` or none.
* A policy with zones becomes the zone-based firewall (``firewall zone``): a zone of VyOS per zone of the model, and for
  each pair of zones a named chain with the rules of the model for that pair, in their order, ended by the default of
  the policy. VyOS drops what goes from one zone to another without a chain, and accepts traffic inside a zone unless
  ``intra-zone-filtering`` says otherwise: both are written where the policy needs them.
  Traffic from a zone to an interface in no zone is left to the forward filter by VyOS: the rules of the model for any
  destination are also written in a named chain jumped to from the forward filter for traffic out of an interface in
  no zone, ended by the default of the policy. Traffic from an interface in no zone into a zone VyOS drops.
* A policy without zones becomes one named chain per IP version, jumped to from the forward filter.
* A policy whose zones are interfaces (each zone holds one interface of its own name: a source that matches interfaces,
  as iptables, nftables, or VyOS 1.3 and EdgeOS rule-sets bound to interfaces) is written the same way, its rules
  matching the interfaces (``inbound-interface``, ``outbound-interface``): as the forward filter of the source, so that
  traffic of interfaces the policy does not name is decided as it was. This is what the migration of VyOS 1.3 to 1.4
  does with the rule-sets of interfaces.
* The model is connection-based: every chain starts by accepting established and related packets and dropping invalid
  ones, so that replies pass where VyOS has no ``global-options state-policy``.
* A rule of VyOS has one protocol (or tcp_udp), one address or group per side and IP version: a rule of the model becomes
  a rule per protocol and per kind of address where it needs more.
* The forward hook sees packets after destination NAT: rules are rewritten to the translated address, as for every
  platform that looks rules up after NAT. NAT is planned as for iptables and written as ``nat destination`` and
  ``nat source`` rules (IPv4).
"""

from __future__ import annotations

import copy
import ipaddress
import re
import shlex
from typing import AbstractSet, Callable, Dict, List, Optional, Sequence, Set, Tuple

from .. import transform
from ..model import ANY, L4_PROTOCOLS, Action, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..names import VYOS, clean
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, range_text
from ..options import Options
from ..report import Report, Severity
from . import iptables as _iptables

_STEP = 10
_FIRST_NUMBER = 10000  # the forward filter rule that jumps, and the first NAT rule, unless --policy-id-start says
_INTERFACE = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,14}")
Body = List[str]  # the statements of one rule, after "rule N"


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    probe = _Emitter(p, Report(), options, source_zones)
    # The forward hook sees the post-NAT destination. Rewrite only for translations that are really written.
    written = {
        nat.origin
        for nat in p.nat_rules
        if probe.plan(nat)[0] is None
        and (nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None)
    }
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, source_zones).run()


def _q(value: str) -> str:
    """A value as ``show configuration commands`` writes it: in single quotes."""
    return "'" + value + "'"


def _text(value: str, limit: int = 255) -> Tuple[str, bool]:
    """Free text VyOS takes in quotes, and whether characters had to be replaced (quotes, control characters, beyond
    ASCII)."""
    out = "".join(c if 32 <= ord(c) < 127 and c not in "'\\" else "_" for c in value)
    out = " ".join(out.split())[:limit].rstrip()
    return out, out != " ".join(value.split())


def _is_network(interval: Interval) -> bool:
    version, first, last = interval
    nets = list(ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)))
    return len(nets) == 1


def _network_text(interval: Interval) -> str:
    version, first, last = interval
    return str(next(ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))))


def _address_text(interval: Interval) -> str:
    """An address, a network or a range, as a rule of VyOS takes it."""
    version, first, last = interval
    if first == last:
        return str(int_to_ip(version, first))
    if _is_network(interval):
        return _network_text(interval)
    return range_text(interval)


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: AbstractSet[str]) -> None:
        self.p, self.report, self.options, self.source_zones = p, report, options, source_zones
        self.prefix = clean(options.object_prefix, VYOS) if options.object_prefix else "FWS-"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.leaves = {4: _iptables._Emitter(p, Report(), options, 4), 6: _iptables._Emitter(p, Report(), options, 6)}
        self.planner = self.leaves[4]
        self.families = [4, 6]
        if p.scope in ("IPv4", "IPv6"):
            self.families = [4 if p.scope == "IPv4" else 6]
        used = [z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        self.zones = transform.target_zones(p, options.zone_map, used, [])
        self.base = options.policy_id_start if options.policy_id_start > 0 else _FIRST_NUMBER
        self.names: Dict[str, Set[str]] = {}  # kind of name (groups of an IP version, chains, zones) -> names, lower case
        self.zone_names: Dict[str, str] = {}
        self.zone_interfaces: Dict[str, List[str]] = {}
        self.guessed: List[str] = []
        self.foreign: Dict[str, List[str]] = {}
        self.groups: Dict[Tuple[str, Tuple[str, ...]], str] = {}  # (kind, members) -> name
        self.group_lines: List[str] = []
        self.interface_groups: Dict[str, str] = {}
        self.changed: List[str] = []
        self.bodies: Dict[Tuple[str, int], Optional[List[Body]]] = {}
        self.reasons: Dict[str, List[transform.Reason]] = {}
        self.fqdn: Set[str] = set()
        self.tied: Set[str] = set()
        self.origdst = False
        self.backs: Dict[str, Dict[str, str]] = {}
        self.exclusions: Dict[Tuple[str, int], str] = {}
        self.exclusion_names: Dict[str, str] = {}
        self.exclusion_lines: List[str] = []
        self.chain_lines: List[str] = []
        self.zone_lines: List[str] = []
        self.flat_chain = ""
        self.by_interface = False
        self.other_chain = ""
        self.all_zones_group = ""

    # -- names ------------------------------------------------------------------------------

    def _name(self, label: str, space: str) -> str:
        """A name of its kind that is not taken: groups of each IP version, chains (the same for both) and zones each have
        names of their own."""
        base = clean(label, VYOS)
        if base != label and label not in self.changed:
            self.changed.append(label)
        taken = self.names.setdefault(space, set())
        candidate, counter = base, 2
        while candidate.lower() in taken:
            tail = f"-{counter}"
            candidate = base[: VYOS.max_len - len(tail)] + tail
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def _description(self, value: str) -> str:
        text, changed = _text(value)
        if changed and value not in self.changed:
            self.changed.append(value)
        return text

    def _zone(self, zone: str) -> str:
        """The name of the zone of VyOS for a zone of the model, and its interfaces, on first use."""
        if zone in self.zone_names:
            return self.zone_names[zone]
        name = self._name(zone, "zone")
        self.zone_names[zone] = name
        interfaces: List[str] = []
        for interface in transform.target_interfaces(self.p, self.options.zone_map, zone):
            mapped = self.options.interface_map.get(interface, interface)
            if _INTERFACE.fullmatch(mapped):
                interfaces.append(mapped)
            else:
                self.foreign.setdefault(zone, []).append(interface)
        if not interfaces:
            interfaces = [name]
            self.guessed.append(zone)
        self.zone_interfaces[zone] = list(dict.fromkeys(interfaces))
        return name

    # -- addresses ----------------------------------------------------------------------------

    def _group(self, family: int, intervals: List[Interval], label: str) -> Tuple[str, str]:
        """(kind, name) of a group of addresses of one IP version, made on first use: a network group where every part is
        a network, an address group (addresses and ranges) otherwise."""
        networks = all(_is_network(i) and i[1] != i[2] for i in intervals)
        kind = "network-group" if networks else "address-group"
        group_kind = kind if family == 4 else f"ipv6-{kind}"
        # An address group takes addresses and ranges, no networks: a network is written as its range.
        values = tuple(_network_text(i) if networks else str(int_to_ip(i[0], i[1])) if i[1] == i[2] else range_text(i) for i in intervals)
        key = (group_kind, values)
        if key in self.groups:
            return kind, self.groups[key]
        name = self._name(self.prefix + label, f"group{family}")
        self.groups[key] = name
        word = "network" if networks else "address"
        for value in values:
            self.group_lines.append(f"set firewall group {group_kind} {name} {word} {_q(value)}")
        return kind, name

    def _side(self, rule: Rule, source: bool, family: int, reasons: List[transform.Reason]) -> Optional[List[Body]]:
        """The ways a side of a rule is written for one IP version: [[]] for any address, None when it can match nothing
        of this IP version."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        word = "source" if source else "destination"
        intervals: List[Interval] = []
        hosts: List[str] = []
        for kind, value in [leaf for member in members for leaf in self.leaves[family]._leaves(member)]:
            if kind == "any":
                return None if negated else [[]]
            if kind == "fqdn":
                assert isinstance(value, str)
                hosts.append(self.p.addresses[value].value)
                continue
            assert isinstance(value, tuple)
            if value[0] != family:
                continue
            if value in (FULL_V4, FULL_V6):
                return None if negated else [[]]
            intervals.append(value)
        intervals = list(dict.fromkeys(intervals))
        hosts = list(dict.fromkeys(hosts))
        if not intervals and not hosts:
            return [[]] if negated else None
        bang = "!" if negated else ""
        if negated and hosts:
            reasons.append(("NEGATION_NOT_STATIC", f"the {word} is negated and holds a host name, which a rule of VyOS "
                            "cannot negate"))  # fmt: skip
            return [[]]
        out: List[Body] = []
        if intervals:
            if len(intervals) == 1:
                out.append([f"{word} address {_q(bang + _address_text(intervals[0]))}"])
            else:
                groups = [m for m in members if m in self.p.address_groups]
                label = groups[0] if len(members) == 1 and groups else f"{rule.name}-{'src' if source else 'dst'}"
                kind, name = self._group(family, intervals, label)
                out.append([f"{word} group {kind} {_q(bang + name)}"])
        if hosts:
            self.fqdn.update(hosts)
            if len(hosts) == 1:
                out.append([f"{word} fqdn {_q(hosts[0])}"])
            else:
                key = ("domain-group", tuple(hosts))
                if key not in self.groups:
                    name = self._name(f"{self.prefix}{rule.name}-{'src' if source else 'dst'}-dns", "domain")
                    self.groups[key] = name
                    for host in hosts:
                        self.group_lines.append(f"set firewall group domain-group {name} address {_q(host)}")
                out.append([f"{word} group domain-group {_q(self.groups[key])}"])
        return out

    # -- services -----------------------------------------------------------------------------

    def _entries(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[ServiceEntry]]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            return [entry for _, entries in lowered for entry in entries]
        if rule.services == [ANY]:
            return None
        entries: List[ServiceEntry] = []
        for service in rule.services:
            entries += transform.flatten_services(self.p, service) or []
        if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
            return None
        return entries

    def _services(self, entries: Optional[List[ServiceEntry]], negated: bool, family: int,
                  reasons: List[transform.Reason]) -> Optional[List[Body]]:  # fmt: skip
        """The ways the services of a rule are written for one IP version: [[]] for every protocol, None when they match
        nothing of this IP version."""
        if entries is None:
            return None if negated else [[]]
        mine = [e for e in entries if not (e.protocol == Protocol.ICMP and family == 6) and not (e.protocol == Protocol.ICMP6 and family == 4)
                and not (e.protocol == Protocol.IP and e.ip_protocol in ((1,) if family == 6 else (58,)))]  # fmt: skip
        if negated:
            if not mine:
                return [[]]
            plain = not any((e.protocol in L4_PROTOCOLS and (e.dst_ports or e.src_ports)) or e.icmp_type is not None
                            or e.icmp_code is not None for e in mine)  # fmt: skip
            numbers = {{Protocol.TCP: 6, Protocol.UDP: 17, Protocol.SCTP: 132, Protocol.ICMP: 1, Protocol.ICMP6: 58}.get(
                e.protocol, e.ip_protocol or 0) for e in mine}  # fmt: skip
            if plain and numbers == {6, 17}:
                return [["protocol '!tcp_udp'"]]
            if plain and len(numbers) == 1:
                return [[f"protocol {_q('!' + self._protocol(numbers.pop(), family))}"]]
            # Several protocols, or ports: a chain of its own returns on each of them and decides the rest.
            excluded = self._services(entries, False, family, reasons)
            if not excluded:
                return [[]]
            return [["\x00exclude"] + ["\x01" + "\x02".join(body) for body in excluded]]
        if not mine:
            return None
        out: List[Body] = []
        # Entries of one protocol with the same source ports share one list of ports; TCP and UDP with the same lists are
        # one rule of tcp_udp.
        merged: Dict[Tuple[str, str], List[str]] = {}
        for e in mine:
            if e.protocol in (Protocol.TCP, Protocol.UDP):
                ports = merged.setdefault((e.protocol.value, e.src_ports), [])
                ports += [port for port in (e.dst_ports.split(",") if e.dst_ports else [""]) if port not in ports]
        lists: Dict[Tuple[str, str], List[str]] = {}
        for (proto, src), ports in merged.items():
            dst = "" if "" in ports else ",".join(ports)
            lists.setdefault((dst, src), []).append(proto)
        for (dst, src), protocols in lists.items():
            names = sorted(set(protocols))
            for proto in (["tcp_udp"] if names == ["tcp", "udp"] else names):
                body = [f"protocol {_q(proto)}"]
                if dst:
                    body.append(f"destination port {_q(dst)}")
                if src:
                    body.append(f"source port {_q(src)}")
                out.append(body)
        for e in mine:
            if e.protocol in (Protocol.TCP, Protocol.UDP):
                continue
            if e.protocol == Protocol.SCTP:
                if e.dst_ports or e.src_ports:
                    reasons.append(("UNSUPPORTED_SERVICE", "SCTP ports: a rule of VyOS matches ports of TCP and UDP only"))
                    return [[]]
                out.append(["protocol 'sctp'"])
            elif e.protocol in (Protocol.ICMP, Protocol.ICMP6):
                word = "icmp" if family == 4 else "icmpv6"
                body = [f"protocol {_q('icmp' if family == 4 else 'ipv6-icmp')}"]
                if e.icmp_type is not None:
                    body.append(f"{word} type {_q(str(e.icmp_type))}")
                    if e.icmp_code is not None:
                        body.append(f"{word} code {_q(str(e.icmp_code))}")
                elif e.icmp_code is not None:
                    reasons.append(("UNSUPPORTED_SERVICE", "an ICMP code without a type"))
                    return [[]]
                out.append(body)
            elif e.ip_protocol:
                out.append([f"protocol {_q(self._protocol(e.ip_protocol, family))}"])
            else:
                reasons.append(("UNSUPPORTED_SERVICE", "IP protocol 0"))
                return [[]]
        unique: List[Body] = []
        for body in out:
            if body not in unique:
                unique.append(body)
        return unique

    @staticmethod
    def _protocol(number: int, family: int) -> str:
        names = {6: "tcp", 17: "udp", 1: "icmp", 58: "ipv6-icmp", 47: "gre", 50: "esp", 51: "ah", 132: "sctp", 89: "ospf"}
        return names.get(number, str(number))

    # -- rules --------------------------------------------------------------------------------

    def _bodies(self, rule: Rule, family: int) -> Optional[List[Body]]:
        """The rules of VyOS a rule of the model becomes in a chain of one IP version (without numbers); None when it
        can match nothing of that IP version. The reasons it cannot be written go into self.reasons."""
        key = (rule.origin, family)
        if key in self.bodies:
            return self.bodies[key]
        reasons = self.reasons.setdefault(rule.origin, [])
        entries = self._entries(rule, reasons)
        sources = self._side(rule, True, family, reasons)
        destinations = self._side(rule, False, family, reasons)
        services = self._services(entries, rule.negate_service, family, reasons)
        out: Optional[List[Body]] = None
        if sources is not None and destinations is not None and services is not None:
            out = [src + dst + svc for src in sources for dst in destinations for svc in services]
        self.bodies[key] = out
        return out

    def _verdict(self, rule: Rule) -> str:
        if rule.action == Action.ALLOW:
            return "accept"
        if rule.action in (Action.DROP, Action.DENY):
            return "drop"
        self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                        f"action {rule.action.value} becomes reject, which answers with an ICMP unreachable rather than a "
                        "TCP reset")  # fmt: skip
        return "reject"

    def _prepare(self) -> None:
        """Every rule's reasons not to be written, before any chain is written."""
        for rule in self.p.rules:
            transform.note_profiles(self.report, rule)
            reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
            if rule.users != [ANY]:
                reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
            if rule.url_categories != [ANY]:
                reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
            self.reasons[rule.origin] = reasons
            for family in self.families:
                self._bodies(rule, family)
            self.reasons[rule.origin] = list(dict.fromkeys(self.reasons[rule.origin]))
            if self.reasons[rule.origin]:
                transform.disable_rule(self.report, rule, self.reasons[rule.origin])
            elif not any(self.bodies.get((rule.origin, f)) for f in self.families):
                self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                                 "nothing in this rule can match a packet of the IP versions written", Severity.INFO)  # fmt: skip

    def _chain(self, family: int, name: str, rules: List[Rule], default: str, out: List[str],
               where: Optional[Callable[[Rule], List[Body]]] = None, tail: Sequence[Tuple[str, Body, str]] = ()) -> int:  # fmt: skip
        """A named chain: the replies, the rules, the default. Returns how many rules of the model it holds. ``where``
        gives the interfaces a rule is written for (a rule for each), ``tail`` rules (action, statements, description)
        that come after those of the model."""
        head = f"set firewall {'ipv4' if family == 4 else 'ipv6'} name {name}"
        out.append(f"{head} default-action {_q(default)}")
        out.append(f"{head} rule 1 action 'accept'")
        out.append(f"{head} rule 1 description 'fwshift: replies'")
        out.append(f"{head} rule 1 state 'established'")
        out.append(f"{head} rule 1 state 'related'")
        out.append(f"{head} rule 2 action 'drop'")
        out.append(f"{head} rule 2 description 'fwshift: invalid'")
        out.append(f"{head} rule 2 state 'invalid'")
        number = 0
        held = 0
        for rule in rules:
            item = self.report.item("rule", rule.origin)
            if item.skipped:
                continue
            if self.reasons.get(rule.origin):
                out.append(f"# FWSHIFT not written, see the report: {self._describe(rule)}")
                continue
            bodies = self.bodies.get((rule.origin, family))
            if not bodies:
                continue
            if where is not None:
                bodies = [side + body for side in where(rule) for body in bodies]
                if not bodies:
                    continue
            held += 1
            verdict = self._verdict(rule)
            description = self._description(rule.name)
            if not rule.enabled:
                by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
                out.append(f"# disabled {'by the audit' if by_audit else 'in the source'}: {self._describe(rule)}")
            for body in bodies:
                number += _STEP
                at = f"{head} rule {number}"
                if "\x00exclude" in body:
                    helper = self._exclusion(family, rule, body, verdict)
                    body = [s for s in body if not s.startswith(("\x00", "\x01"))] + [f"jump-target {_q(helper)}"]
                    out.append(f"{at} action 'jump'")
                else:
                    out.append(f"{at} action {_q(verdict)}")
                if description:
                    out.append(f"{at} description {_q(description)}")
                out += [f"{at} {statement}" for statement in body]
                if rule.log_start:
                    out.append(f"{at} log")
                if not rule.enabled:
                    out.append(f"{at} disable")
                label = f"{name} rule {number}" + (" (IPv6)" if family == 6 else "")
                if label not in item.emitted_as:
                    item.emitted_as.append(label)
        for action, body, description in tail:
            number += _STEP
            at = f"{head} rule {number}"
            out.append(f"{at} action {_q(action)}")
            out.append(f"{at} description {_q(description)}")
            out += [f"{at} {statement}" for statement in body]
        return held

    def _exclusion(self, family: int, rule: Rule, body: Body, verdict: str) -> str:
        """The chain of a rule with a negated service: a return for each service it excludes, then its action."""
        key = (rule.origin, family)
        if key in self.exclusions:
            return self.exclusions[key]
        name = self.exclusion_names.get(rule.origin) or self._name(f"{self.prefix}{rule.name}-not", "chain")
        self.exclusion_names[rule.origin] = name
        self.exclusions[key] = name
        head = f"set firewall {'ipv4' if family == 4 else 'ipv6'} name {name}"
        lines = [f"{head} default-action {_q(verdict)}"]
        if rule.log_start:
            lines.append(f"{head} default-log")
        number = 0
        for part in [s[1:] for s in body if s.startswith("\x01")]:
            number += _STEP
            lines.append(f"{head} rule {number} action 'return'")
            lines += [f"{head} rule {number} {statement}" for statement in part.split("\x02")]
        self.exclusion_lines += lines
        self.report.add("rule", rule.origin, Severity.INFO, "VYOS_NEGATED_SERVICE",
                        f"the negated service is written as chain {name}, which returns for each service the rule leaves "
                        "out and decides the rest")  # fmt: skip
        return name

    def _describe(self, rule: Rule) -> str:
        return _iptables._Emitter._describe(self.planner, rule)

    def _pairs(self, rule: Rule) -> List[Tuple[str, str]]:
        sources = self.zones if ANY in rule.src_zones else [z for z in rule.src_zones if z in self.zones]
        destinations = self.zones if ANY in rule.dst_zones else [z for z in rule.dst_zones if z in self.zones]
        if rule.scope == RuleScope.INTRAZONE:
            return [(a, a) for a in sources]  # (a rule inside a zone: its destination is the zone it comes from)
        pairs = [(a, b) for a in sources for b in destinations]
        if rule.scope == RuleScope.INTERZONE:
            pairs = [(a, b) for a, b in pairs if a != b]
        return pairs

    def _side_interface(self, zone: str, word: str, negated: bool = False) -> str:
        how, what = self._interface(zone)
        return f"{word}-interface {how} {_q(('!' if negated else '') + what)}"

    def _where(self, rule: Rule, inbound_only: bool = False) -> List[Body]:
        """The interfaces a rule is written for, a list of statements for each (``[[]]``: any interface). With
        ``inbound_only``, for traffic to an interface in no zone: the zones the traffic comes from."""
        sources: List[Optional[str]] = [None] if ANY in rule.src_zones else [z for z in rule.src_zones if z in self.zones]
        destinations: List[Optional[str]] = [None] if ANY in rule.dst_zones else [z for z in rule.dst_zones if z in self.zones]
        if rule.scope == RuleScope.INTRAZONE:
            if inbound_only:
                return []  # (traffic inside a zone does not leave by an interface in no zone)
            return [[self._side_interface(a, "inbound"), self._side_interface(a, "outbound")]
                    for a in (self.zones if sources == [None] else sources) if a is not None]  # fmt: skip
        if inbound_only:
            return [[self._side_interface(a, "inbound")] if a is not None else [] for a in sources]
        out: List[Body] = []
        if rule.scope == RuleScope.INTERZONE:
            if sources == [None] and destinations == [None]:
                # (from each zone to what is not that zone; from an interface in no zone to anywhere)
                return [[self._side_interface(a, "inbound"), self._side_interface(a, "outbound", True)] for a in self.zones] + [
                    [f"inbound-interface group {_q('!' + self._all_zones())}"]]  # fmt: skip
            for a in sources:
                for b in destinations:
                    if a is None and b is not None:
                        out.append([self._side_interface(b, "inbound", True), self._side_interface(b, "outbound")])
                    elif b is None and a is not None:
                        out.append([self._side_interface(a, "inbound"), self._side_interface(a, "outbound", True)])
                    elif a != b and a is not None and b is not None:
                        out.append([self._side_interface(a, "inbound"), self._side_interface(b, "outbound")])
            return out
        for a in sources:
            for b in destinations:
                body: Body = []
                if a is not None:
                    body.append(self._side_interface(a, "inbound"))
                if b is not None:
                    body.append(self._side_interface(b, "outbound"))
                out.append(body)
        return out

    def _all_zones(self) -> str:
        """The interface group of the interfaces of every zone, made on first use."""
        if not self.all_zones_group:
            self.all_zones_group = self._name(f"{self.prefix}ZONES", "interface")
            for zone in self.zones:
                self._zone(zone)
                for interface in self.zone_interfaces[zone]:
                    self.group_lines.append(f"set firewall group interface-group {self.all_zones_group} interface {_q(interface)}")
        return self.all_zones_group

    def _zones_are_interfaces(self) -> bool:
        """Each zone holds one interface of its own name: the source matched interfaces, not zones."""
        for zone in self.zones:
            if transform.target_interfaces(self.p, self.options.zone_map, zone) != [zone]:
                return False
            if not _INTERFACE.fullmatch(self.options.interface_map.get(zone, zone)):
                return False
        return True

    def _interfaced(self) -> None:
        """Zones that are interfaces: one chain per IP version jumped to from the forward filter, as without zones, its
        rules matching the interfaces."""
        between = self.p.default_interzone == Action.ALLOW
        inside = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.zones, self.report)
        tail: List[Tuple[str, Body, str]] = []
        for zone in self.zones:
            self._zone(zone)
            if inside[zone] != between:
                tail.append(("accept" if inside[zone] else "drop",
                             [self._side_interface(zone, "inbound"), self._side_interface(zone, "outbound")],
                             f"fwshift: inside {zone}"))  # fmt: skip
        self._flat(lambda rule: self._where(rule), tail)
        self.by_interface = True

    def _other(self, between: bool) -> List[str]:
        """Traffic from a zone to an interface in no zone, which VyOS leaves to the forward filter: the rules for any
        destination, in a chain jumped to for traffic out of an interface in no zone. Returns the lines of the jumps."""
        rules = [r for r in self.p.rules if ANY in r.dst_zones and r.scope != RuleScope.INTRAZONE]
        if not any(self.bodies.get((r.origin, f)) and not self.reasons.get(r.origin) for r in rules for f in self.families) and between:
            return []
        group = self._all_zones()
        chain = self._name(f"{self.prefix}NO-ZONE", "chain")
        self.other_chain = chain
        jumps: List[str] = []
        for family in self.families:
            self._chain(family, chain, rules, "accept" if between else "drop", self.chain_lines,
                        lambda rule: self._where(rule, inbound_only=True))  # fmt: skip
            head = f"set firewall {'ipv4' if family == 4 else 'ipv6'} forward filter rule {self.base}"
            jumps += [f"{head} action 'jump'", f"{head} description 'fwshift: traffic to interfaces in no zone'",
                      f"{head} jump-target {_q(chain)}", f"{head} outbound-interface group {_q('!' + group)}"]  # fmt: skip
        return jumps

    def _zoned(self) -> None:
        """The zone-based firewall: a chain per pair of zones and IP version that needs one."""
        between = self.p.default_interzone == Action.ALLOW
        inside = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.zones, self.report)
        pairs: Dict[Tuple[str, str], List[Rule]] = {(a, b): [] for a in self.zones for b in self.zones}
        for rule in self.p.rules:
            pairs_of = self._pairs(rule)
            for pair in pairs_of:
                pairs[pair].append(rule)
            if len(pairs_of) > 1:
                self.report.add("rule", rule.origin, Severity.INFO, "RULE_SPLIT",
                                f"written in the chains of {len(pairs_of)} pairs of zones")  # fmt: skip
            if (ANY in rule.src_zones or ANY in rule.dst_zones) and pairs_of:
                other = ("; it is also written for traffic to interfaces in no zone, which VyOS leaves to the forward "
                         "filter" if ANY in rule.dst_zones and rule.scope != RuleScope.INTRAZONE else "")
                self.report.add("rule", rule.origin, Severity.INFO, "ZONES_EXPANDED",
                                "a rule for every zone is written for each pair of the zones the policy knows ("
                                + ", ".join(self.zones) + f"){other}; traffic from an interface in no zone into a zone "
                                "VyOS drops")  # fmt: skip
        for zone in self.zones:
            self._zone(zone)

        def allows(pair: Tuple[str, str], family: int) -> bool:
            return any(r.action == Action.ALLOW and self.bodies.get((r.origin, family)) and not self.reasons.get(r.origin)
                       for r in pairs[pair])  # fmt: skip

        def holds(pair: Tuple[str, str], family: int) -> bool:
            return any(self.bodies.get((r.origin, family)) for r in pairs[pair])

        chains: List[str] = []
        zone_lines: List[str] = []
        for zone in self.zones:
            name = self.zone_names[zone]
            for interface in self.zone_interfaces[zone]:
                zone_lines.append(f"set firewall zone {name} interface {_q(interface)}")
        for (a, b), rules in pairs.items():
            src, dst = self.zone_names[a], self.zone_names[b]
            default_allow = inside[a] if a == b else between
            needed = {f: holds((a, b), f) or default_allow or allows((b, a), f) for f in self.families}
            if a == b:
                if not any(holds((a, b), f) for f in self.families):
                    if not default_allow:
                        zone_lines.append(f"set firewall zone {dst} intra-zone-filtering action 'drop'")
                    continue
                needed = {f: True for f in self.families}  # (one IP version without a chain would be accepted inside)
            if not any(needed.values()):
                continue
            chain = self._name(f"{self.prefix}{a}-{b}", "chain")
            for family in self.families:
                if not needed[family]:
                    continue
                self._chain(family, chain, rules, "accept" if default_allow else "drop", chains)
                word = "name" if family == 4 else "ipv6-name"
                if a == b:
                    zone_lines.append(f"set firewall zone {dst} intra-zone-filtering firewall {word} {_q(chain)}")
                else:
                    zone_lines.append(f"set firewall zone {dst} from {src} firewall {word} {_q(chain)}")
        self.chain_lines = chains
        self.zone_lines = self._other(between) + zone_lines

    def _flat(self, where: Optional[Callable[[Rule], List[Body]]] = None, tail: Sequence[Tuple[str, Body, str]] = ()) -> None:
        """No zones: one chain per IP version, jumped to from the forward filter."""
        default = "accept" if self.p.default_interzone == Action.ALLOW else "drop"
        chain = self._name(f"{self.prefix}FORWARD", "chain")
        chains: List[str] = []
        jumps: List[str] = []
        for family in self.families:
            self._chain(family, chain, self.p.rules, default, chains, where, tail)
            head = f"set firewall {'ipv4' if family == 4 else 'ipv6'} forward filter rule {self.base}"
            jumps += [f"{head} action 'jump'", f"{head} description 'fwshift: the converted policy'",
                      f"{head} jump-target {_q(chain)}"]  # fmt: skip
        self.chain_lines = chains
        self.zone_lines = jumps
        self.flat_chain = chain

    # -- NAT ----------------------------------------------------------------------------------

    def plan(self, nat: NatRule) -> _iptables.Plan:
        """What a NAT rule becomes (as iptables lines of the planner), or why it cannot be written."""
        tokens: Dict[str, str] = {}
        clone = copy.copy(nat)
        for attr in ("src_zones", "dst_zones"):
            names = []
            for zone in getattr(nat, attr):
                if zone == ANY:
                    names.append(zone)
                    continue
                tokens.setdefault(zone, f"fwsz{len(tokens)}")
                names.append(tokens[zone])
            setattr(clone, attr, names)
        problem, prerouting, postrouting, findings = self.planner.nat_plan(clone)
        back = {token: zone for zone, token in tokens.items()}

        def named(message: str) -> str:
            for token, zone in sorted(back.items(), key=lambda item: -len(item[0])):
                message = message.replace(token, zone)
            return message.replace("--to iptables", "--to vyos").replace("POSTROUTING", "nat source").replace(
                "PREROUTING", "nat destination")  # fmt: skip

        if problem is not None:
            code, message, severity = problem
            return (code, named(message), severity), [], [], []
        for line in prerouting + postrouting:
            if re.search(r"-p sctp .*--(d|s)ports? ", line):
                return ("NAT_SERVICE", "SCTP ports: a NAT rule of VyOS matches ports of TCP and UDP only", Severity.REVIEW), [], [], []
        self.backs[nat.origin] = back
        return None, prerouting, postrouting, [(s, c, named(m)) for s, c, m in findings]

    def _interface(self, zone: str) -> List[str]:
        """The statements that name the interfaces of a zone in a NAT rule."""
        self._zone(zone)
        interfaces = self.zone_interfaces[zone]
        if len(interfaces) == 1:
            return ["name", interfaces[0]]
        if zone not in self.interface_groups:
            name = self._name(f"{self.prefix}{zone}-interfaces", "interface")
            self.interface_groups[zone] = name
            for interface in interfaces:
                self.group_lines.append(f"set firewall group interface-group {name} interface {_q(interface)}")
        return ["group", self.interface_groups[zone]]

    def _nat_rule(self, line: str, kind: str, number: int, nat: NatRule) -> List[str]:
        """One iptables NAT line of the planner as the statements of a NAT rule of VyOS. The words are the closed set the
        planner writes."""
        back = self.backs.get(nat.origin, {})
        words = shlex.split(line)
        head = f"set nat {kind} rule {number}"
        out: List[str] = []
        description = self._description(nat.name)
        if description:
            out.append(f"{head} description {_q(description)}")
        i = 2
        while i < len(words):
            word = words[i]
            value = words[i + 1] if i + 1 < len(words) else ""
            if word in ("-i", "-o"):
                how, what = self._interface(back.get(value, value))
                side = "inbound-interface" if word == "-i" else "outbound-interface"
                out.append(f"{head} {side} {how} {_q(what)}")
            elif word in ("-s", "-d"):
                out.append(f"{head} {'source' if word == '-s' else 'destination'} address {_q(value[:-3] if value.endswith('/32') else value)}")
            elif word == "-p":
                out.append(f"{head} protocol {_q(value)}")
            elif word == "-m":
                if value == "iprange" and i + 3 < len(words):
                    out.append(f"{head} {'source' if words[i + 2] == '--src-range' else 'destination'} address {_q(words[i + 3])}")
                    i += 4
                    continue
                if value == "conntrack" and i + 3 < len(words) and words[i + 2] == "--ctorigdst":
                    self.origdst = True  # (a NAT rule of VyOS cannot match the destination before translation)
                    i += 4
                    continue
                if value == "comment" and i + 3 < len(words):
                    i += 4
                    continue
                if value in ("tcp", "udp", "sctp", "multiport"):
                    i += 2
                    continue
                raise ValueError(f"unexpected match module {value}")
            elif word in ("--dport", "--dports", "--sport", "--sports"):
                side = "destination" if word.startswith("--d") else "source"
                out.append(f"{head} {side} port {_q(value.replace(':', '-'))}")
            elif word == "-j":
                if value == "DNAT":
                    address, _, port = words[i + 3].partition(":")
                    out.append(f"{head} translation address {_q(address)}")
                    if port:
                        out.append(f"{head} translation port {_q(port)}")
                    i += 4
                    continue
                if value == "SNAT":
                    out.append(f"{head} translation address {_q(words[i + 3])}")
                    i += 4
                    continue
                if value == "MASQUERADE":
                    out.append(f"{head} translation address 'masquerade'")
                elif value == "ACCEPT":
                    out.append(f"{head} exclude")
                else:
                    raise ValueError(f"unexpected target {value}")
            else:
                raise ValueError(f"unexpected word {word}")
            i += 2
        if not nat.enabled:
            out.append(f"{head} disable")
        return out

    def _nat(self) -> List[str]:
        out: List[str] = []
        numbers = {"destination": self.base, "source": self.base}
        for nat in self.p.nat_rules:
            self.origdst = False
            problem, pre, post, findings = self.plan(nat)
            if problem is not None:
                self.report.skip("nat", nat.origin, *problem)
                continue
            item = self.report.item("nat", nat.origin)
            for severity, code, message in findings:
                self.report.add("nat", nat.origin, severity, code, message)
            written: List[str] = []
            for kind, lines in (("destination", pre), ("source", post)):
                for line in lines:
                    out += self._nat_rule(line, kind, numbers[kind], nat)
                    written.append(f"{kind} rule {numbers[kind]}")
                    numbers[kind] += _STEP
            if self.origdst:
                self.report.add("nat", nat.origin, Severity.APPROX, "NAT_AFTER_DNAT",
                                "the source translation of this rule is matched after its destination translation; a NAT "
                                "rule of VyOS cannot match the destination a connection had before it, so it also applies "
                                "to traffic from the same sources sent to the translated address directly")  # fmt: skip
            if not nat.enabled:
                self.report.add("nat", nat.origin, Severity.INFO, "NAT_DISABLED", "disabled in the source; written disabled")
            else:
                item.emitted_as += written
        return out

    # -- output -------------------------------------------------------------------------------

    def run(self) -> str:
        self._prepare()
        nat_lines = self._nat()
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction", tied=self.tied)
        if not self.zones:
            self._flat()
        elif self._zones_are_interfaces():
            self._interfaced()
        else:
            self._zoned()
        self._notes()
        out = [
            "# Generated by FWShift - review the conversion report before loading this.",
            "# Set commands for VyOS 1.4 or later: in configuration mode ('configure'), paste them, then 'compare',",
            "# 'commit-confirm 10' and 'confirm' (or 'commit'), and 'save'. They add; nothing is deleted.",
        ]
        out += self.group_lines + self.exclusion_lines + self.chain_lines + self.zone_lines + nat_lines
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        prefix = self.prefix
        rule_number = (f"Check that the forward filter has no rule {self.base} (show firewall ipv4 forward filter), or give "
                       f"another number with --policy-id-start; its rules with lower numbers come first, and those after rule "
                       f"{self.base} are no longer reached by what the chain decides, as it ends with the default of the policy")  # fmt: skip
        if self.zones and not self.by_interface:
            mode = ("The policy is written as the zone-based firewall: zones " + ", ".join(self.zone_names[z] for z in self.zones)
                    + f", and a chain {prefix}<from>-<to> for each pair of zones that needs one. Interfaces of the router in "
                    "no zone: VyOS drops their traffic into a zone and leaves traffic from a zone to them to the forward "
                    "filter")  # fmt: skip
            if self.other_chain:
                mode += (f"; that traffic is decided by chain {self.other_chain} (the rules for any destination and the "
                         f"default of the policy), jumped to from rule {self.base} of the forward filter for what leaves by "
                         f"an interface not in interface group {self.all_zones_group}. {rule_number}")  # fmt: skip
            mode += (". The forward filter of the router still applies before the zones (an accept there goes on to the "
                     "zones, a drop is final). A zone of the same name that exists gets these interfaces and chains in "
                     "addition to its own; a chain set for a pair that has one replaces it")  # fmt: skip
        elif self.by_interface:
            mode = (f"The zones of the policy are interfaces ({', '.join(self.zones)}): it is written as chain "
                    f"{self.flat_chain} for each IP version, its rules matching inbound-interface and outbound-interface, "
                    f"jumped to from rule {self.base} of the forward filter, as VyOS migrates rule-sets of interfaces. "
                    f"{rule_number}")  # fmt: skip
        else:
            mode = (f"The policy has no zones: it is written as chain {self.flat_chain} for each IP version, jumped to from rule "
                    f"{self.base} of the forward filter. {rule_number}")  # fmt: skip
        self.report.note(
            Severity.REVIEW, "VYOS_LOAD",
            "load the commands in configuration mode: 'configure', paste them, 'compare', then 'commit-confirm 10' (unless "
            "'confirm' follows within 10 minutes, VyOS goes back to the configuration before; older releases reboot to do "
            f"so) and 'save'. A commit applies all of them or none. {mode}. NAT rules are numbered from {self.base}: rules of the router with "
            "lower numbers come first. To take a conversion away: delete the groups, chains, zones and NAT rules the "
            f"commands name (all under {prefix}, and the NAT rules from {self.base} on). Assumed: names of up to 63 "
            "characters",
        )  # fmt: skip
        if self.guessed or self.foreign:
            listed = sorted(set(self.guessed) | set(self.foreign))
            detail = ""
            if self.foreign:
                detail = " (interfaces of the source that are no names of Linux interfaces: " + "; ".join(
                    f"{zone}: {', '.join(names[:4])}" for zone, names in sorted(self.foreign.items())) + ")"  # fmt: skip
            self.report.note(
                Severity.REVIEW, "INTERFACES_REQUIRED",
                "zones need the interfaces of the router: these were written with their own name as interface, which "
                "matches no traffic until it is replaced (--interface-map, or --zone-map with zones of the router's "
                "interfaces): " + ", ".join(self.zone_names.get(z, z) for z in listed) + detail,
            )  # fmt: skip
        named = [z for z in self.zones if z not in self.guessed and z not in self.foreign]
        if named and self.p.vendor != "vyos" and self.by_interface:
            self.report.note(
                Severity.REVIEW, "ZONES_REQUIRED",
                "the rules match these interfaces of the source: check that they are interfaces of the router (or map "
                "them with --interface-map): " + ", ".join(sorted({i for z in named for i in self.zone_interfaces[z]})),
            )  # fmt: skip
        elif named and self.p.vendor != "vyos":
            self.report.note(
                Severity.REVIEW, "ZONES_REQUIRED",
                "these zones are written with the interfaces of the source: check that they are interfaces of the router "
                "(or map them with --interface-map): " + ", ".join(f"{self.zone_names[z]}={','.join(self.zone_interfaces[z])}"
                                                                   for z in named),
            )  # fmt: skip
        if self.other_chain:
            self.report.note(
                Severity.REVIEW, "VYOS_NO_ZONE",
                f"traffic from a zone to an interface in no zone is decided by chain {self.other_chain}; its replies come in "
                "from an interface in no zone, which VyOS drops at the zones unless 'firewall global-options state-policy' "
                "accepts established and related packets (the commands do not set it, as it applies to the whole router)",
            )  # fmt: skip
        if len(self.families) == 1:
            other = 6 if self.families == [4] else 4
            self.report.note(
                Severity.REVIEW, "ONE_IP_VERSION",
                f"the source policy is for IPv{self.families[0]} only: the commands write IPv{self.families[0]} chains only, "
                f"and the router goes on deciding IPv{other} as its own configuration says",
            )  # fmt: skip
        if self.fqdn:
            self.report.note(
                Severity.INFO, "VYOS_FQDN",
                "host names are written as fqdn or domain-group, which the router resolves while it runs: "
                + ", ".join(sorted(self.fqdn)[:10]),
            )  # fmt: skip
        if any(r.log_start for r in self.p.rules):
            self.report.note(
                Severity.INFO, "VYOS_LOG",
                "rules that log the start of a connection have 'log': VyOS logs every packet the rule matches, which, "
                "after the replies are accepted at the top of each chain, is the first packet of each connection",
            )  # fmt: skip
        if self.changed:
            self.report.note(
                Severity.INFO, "VYOS_TEXT",
                "names and descriptions with characters VyOS does not take in them (or longer than it takes) were changed: "
                + ", ".join(self.changed[:10]),
            )  # fmt: skip

