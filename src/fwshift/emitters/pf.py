# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""pf emitter: neutral model -> a ruleset for an anchor of pf (``pfctl -a fwshift -f FILE``).

Design rules:

* The output is loaded into an anchor of its own, so nothing of the ruleset already loaded is replaced. The
  main ruleset has to call the anchor (``anchor "fwshift"``); the report says so. Tables, macros and tags
  have names that start with the prefix (``--target-prefix``, ``fws_`` when not given).
* A zone is an interface or an interface group: a macro per zone holds its name (the zone's name, or what
  ``--zone-map`` makes of it), so that one line changes it.
* pf decides about a forwarded packet when it comes in and again when it goes out; only then does it know
  both interfaces. So what arrives on a zone's interface is marked with a tag of that zone and let in
  (only what an allow rule or a destination NAT can match, and never the firewall's own addresses); the
  model's rules are decided when it leaves, in the model's order, with that tag as the source zone. Every
  rule is first match: a rule that blocks is ``quick``; a rule that allows sets another tag, which keeps the
  rules below it from matching, and the packet passes at the end of the ruleset, after source NAT.
* Destination NAT is a ``pass in quick ... rdr-to`` before the rest (first match); the rules see the
  translated destination, as on every platform that looks rules up after destination NAT. Source NAT is a
  ``match out ... nat-to`` on what the rules allowed, first match by its tag.
* A negated service list cannot be said in one rule of pf: the packets of the services left out get a tag of
  their own for the rule, and get their zone's tag back after it.
* A rule that cannot be enforced is written as a comment, so it is visible and not loaded.
"""

from __future__ import annotations

import copy
import re
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..model import ANY, ANY_V4, ANY_V6, L4_PROTOCOLS, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..model import SnatKind, SourceNat
from ..names import PF_TABLE, clean, unique
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, parse_literal, size
from ..options import Options
from ..report import Report, Severity

_INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
_ANCHOR = "fwshift"
# Words of pf.conf a macro or table may not be called.
_WORDS = frozenset(
    """all anchor antispoof any binat block code drop file flags for from group in inet inet6 keep label log match
    modulate nat no on out pass port proto queue quick rdr return scrub self set state synproxy table tag tagged
    to user""".split()
)  # fmt: skip

Frag = Tuple[int, str]  # (IP version the fragment needs, 0 for either; the words it adds to a rule)


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    emitter = _Emitter(p, report, options)
    # The rules are decided when the traffic leaves, after rdr-to: rewrite them for the translations that are written.
    written = {nat.origin for nat in p.nat_rules if emitter.nat_problem(nat) is None
               and (nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None)}  # fmt: skip
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


def valid_interface(name: str) -> bool:
    return bool(_INTERFACE.fullmatch(name))


def _label(text: str) -> str:
    """A label pf takes: no quotes, no $ (pf expands $nr, $srcaddr and others in labels), at most 63 bytes."""
    cleaned = " ".join(re.sub(r"[\"'$\\\x00-\x1f\x7f]", "_", text).split())
    while len(cleaned.encode("utf-8")) > 63:
        cleaned = cleaned[:-1]
    return f'label "{cleaned}"'


def _ports(text: str) -> str:
    items = [item.replace("-", ":") for item in text.split(",")]
    return items[0] if len(items) == 1 else "{ " + " ".join(items) + " }"


def service_fragments(entries: List[ServiceEntry]) -> Tuple[List[Frag], List[str]]:
    """(fragments of pf for protocol and port entries, problems). A fragment of "" matches every protocol."""
    problems: List[str] = []
    out: List[Frag] = []
    merged: Dict[Tuple[str, str], List[str]] = {}  # (protocol, source ports) -> destination ports ("" for all)
    for entry in entries:
        if entry.protocol in L4_PROTOCOLS:
            if entry.protocol == Protocol.SCTP and (entry.dst_ports or entry.src_ports):
                problems.append("ports of SCTP, which pf matches for TCP and UDP only")
                continue
            ports = merged.setdefault((entry.protocol.value, entry.src_ports), [])
            for port in entry.dst_ports.split(",") if entry.dst_ports else [""]:
                if port not in ports:
                    ports.append(port)
    by_ports: Dict[Tuple[str, str], List[str]] = {}  # (source ports, destination ports) -> protocols
    for (proto, src_ports), ports in merged.items():
        dst_ports = "" if "" in ports else ",".join(ports)
        by_ports.setdefault((src_ports, dst_ports), []).append(proto)
    for (src_ports, dst_ports), protos in by_ports.items():
        words = "proto " + (protos[0] if len(protos) == 1 else "{ " + " ".join(protos) + " }")
        out.append((0, words + (f"\x00{_ports(src_ports)}" if src_ports else "\x00") + (f"\x00{_ports(dst_ports)}" if dst_ports else "\x00")))
    numbers: List[str] = []
    icmp: Dict[Tuple[int, Optional[int]], List[str]] = {}
    for entry in entries:
        if entry.protocol in L4_PROTOCOLS:
            continue
        if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
            family = 4 if entry.protocol == Protocol.ICMP else 6
            if entry.icmp_type is None:
                icmp.setdefault((family, None), [])
            elif entry.icmp_code is not None:
                out.append((family, f"proto {'icmp' if family == 4 else 'icmp6'}\x00\x00\x00{'icmp' if family == 4 else 'icmp6'}-type "
                                    f"{entry.icmp_type} code {entry.icmp_code}"))  # fmt: skip
            else:
                icmp.setdefault((family, -1), []).append(str(entry.icmp_type))
        elif entry.ip_protocol:
            numbers.append(str(entry.ip_protocol))
        else:
            out.append((0, ""))
    for (family, kind), types in icmp.items():
        word = "icmp" if family == 4 else "icmp6"
        if kind is None:
            out.append((family, f"proto {word}\x00\x00\x00"))
        elif (family, None) not in icmp:
            types = transform.dedupe(types)
            out.append((family, f"proto {word}\x00\x00\x00{word}-type " + (types[0] if len(types) == 1 else "{ " + " ".join(types) + " }")))
    if numbers:
        numbers = transform.dedupe(numbers)
        out.append((0, "proto " + (numbers[0] if len(numbers) == 1 else "{ " + " ".join(numbers) + " }") + "\x00\x00\x00"))
    unique_out: List[Frag] = []
    for frag in out:
        if frag not in unique_out:
            unique_out.append(frag)
    return unique_out, problems


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.prefix = clean(options.object_prefix or "fws_", PF_TABLE)
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.tables: Dict[str, str] = {}  # table name -> its body
        self.table_of: Dict[Tuple[str, ...], str] = {}  # members -> table name
        self.taken: Set[str] = set(_WORDS)
        self.zones = self._zones()
        self.macro = {zone: unique(f"{self.prefix}if_{zone or 'all'}", self.taken, PF_TABLE) for zone in self.zones}
        self.tag = {zone: unique(f"{self.prefix}{zone or 'all'}", self.taken, PF_TABLE) for zone in self.zones}
        self.ok = {zone: unique(f"{self.prefix}ok_{zone or 'all'}", self.taken, PF_TABLE) for zone in self.zones}
        self.nat_tag = unique(f"{self.prefix}nat", self.taken, PF_TABLE)
        self.arrive: List[str] = []
        self.admit: List[str] = []
        self.decide: List[str] = []
        self.snat: List[str] = []
        self.skips = 0
        self.fqdn_rules = 0

    # -- zones ----------------------------------------------------------------------------------

    def _zones(self) -> List[str]:
        zones = [self.options.zone_map.get(name, name) for name in self.p.zones]
        zones += [z for rule in list(self.p.rules) + list(self.p.nat_rules) for z in rule.src_zones + rule.dst_zones]
        zones = transform.dedupe([z for z in zones if z != ANY])
        return zones or [""]  # no zones: one mark for everything that arrives

    def _on(self, zones: List[str]) -> str:
        """``on $macro`` or ``on { $a $b }``; "" for every interface."""
        if ANY in zones or zones == [""]:
            return ""
        names = [f"${self.macro[z]}" for z in zones]
        return "on " + (names[0] if len(names) == 1 else "{ " + " ".join(names) + " }")

    def _sources(self, zones: List[str]) -> List[str]:
        return list(self.zones) if ANY in zones else [z for z in zones if z in self.tag]

    # -- addresses ------------------------------------------------------------------------------

    def _leaves(self, member: str, seen: Tuple[str, ...] = ()) -> Optional[List[str]]:
        """What a member stands for, as entries pf takes in a table or a rule; None for every address."""
        if member == ANY:
            return None
        if member in self.p.addresses:
            address = self.p.addresses[member]
            if address.kind == AddressKind.FQDN:
                return [address.value]
            interval = parse_literal(address.value)
            return _entries(interval) if interval else []
        if member in self.p.address_groups:
            if member in seen:
                return []
            out: List[str] = []
            for inner in self.p.address_groups[member].members:
                found = self._leaves(inner, seen + (member,))
                if found is None:
                    return None
                out += found
            return transform.dedupe(out)
        interval = parse_literal(member)
        return _entries(interval) if interval else []

    def _families(self, members: List[str], negated: bool) -> Set[int]:
        if negated:
            return {4, 6}
        out: Set[int] = set()
        for member in members:
            out |= transform.families(self.p, member)
        return out

    def _address(self, members: List[str], negated: bool, family: int, side: str, rule: str) -> Optional[str]:
        """The words for one side of a rule (``any``, an address, ``<table>``, with ``!``); None when the side
        holds nothing of the IP version the fragment needs."""
        entries: List[str] = []
        for member in members:
            found = self._leaves(member)
            if found is None:
                return "! any" if negated else "any"
            entries += found
        entries = transform.dedupe(entries)
        if family:
            entries = [e for e in entries if _family(e) in (0, family)]
            if ("0.0.0.0/0" if family == 4 else "::/0") in entries:
                return None if negated else "any"
        elif "0.0.0.0/0" in entries and "::/0" in entries:
            return None if negated else "any"
        if not entries:
            return "any" if negated else None
        if len(entries) == 1:
            return ("! " if negated else "") + entries[0]
        key = tuple(entries)
        if key not in self.table_of:
            named = len(members) == 1 and (members[0] in self.p.address_groups or members[0] in self.p.addresses)
            name = unique(f"{self.prefix}{members[0] if named else rule + '_' + side}", self.taken, PF_TABLE)
            self.table_of[key] = name
            self.tables[name] = " ".join(entries)
        return ("! " if negated else "") + f"<{self.table_of[key]}>"

    # -- security rules -------------------------------------------------------------------------

    def _describe(self, rule: Rule) -> str:
        parts = [
            f"from {','.join(rule.src_zones)} to {','.join(rule.dst_zones)}",
            ("source not " if rule.negate_source else "source ") + ",".join(rule.sources),
            ("destination not " if rule.negate_destination else "destination ") + ",".join(rule.destinations),
            ("service not " if rule.negate_service else "service ") + ",".join(rule.services),
            "action " + rule.action.value,
        ]
        return " ".join((f'"{rule.name}" ' + "; ".join(parts)).split())

    def _entries(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[ServiceEntry]]:
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            return [entry for _, entries in lowered for entry in entries]
        if rule.services == [ANY]:
            return None
        entries: List[ServiceEntry] = []
        for service in rule.services:
            entries += transform.flatten_services(self.p, service) or []
        return entries

    def _pairs(self, rule: Rule) -> List[Tuple[List[str], List[str]]]:
        """(source zones, destination zones) of a rule, with "any" source zones as every zone of the output."""
        if rule.scope == RuleScope.INTRAZONE:
            return [([z], [z]) for z in self._sources(rule.src_zones)]
        if rule.scope == RuleScope.INTERZONE:
            out: List[Tuple[List[str], List[str]]] = []
            for zone in self._sources(rule.src_zones):
                targets = [z for z in (self.zones if ANY in rule.dst_zones else rule.dst_zones) if z != zone]
                if targets:
                    out.append(([zone], targets))
            return out
        return [(self._sources(rule.src_zones), rule.dst_zones)]

    def _rule(self, rule: Rule, number: int) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        entries = self._entries(rule, reasons)
        fragments: List[Frag] = [(0, "")]
        if entries is not None:
            fragments, problems = service_fragments(entries)
            reasons += [("SERVICE_NOT_WRITTEN", text) for text in problems]
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
            self.decide.append(f"# FWSHIFT disabled, see the report: {self._describe(rule)}")
            return
        if not rule.enabled:
            by_audit = any(f.code == "AUDIT_DISABLED" for f in item.findings)
            self.decide.append(f"# disabled {'by the audit' if by_audit else 'in the source'}: {self._describe(rule)}")
            return
        pairs = [pair for pair in self._pairs(rule) if pair[0] and pair[1]]
        if not pairs:
            self.report.skip("rule", rule.origin, "RULE_TYPE_EMPTY", "the rule's zones leave no pair of zones: it matches nothing", Severity.INFO)
            return
        fqdn = [m for m in rule.sources + rule.destinations if m in self.p.addresses and self.p.addresses[m].kind == AddressKind.FQDN]
        for name in transform.dedupe(fqdn):
            self.report.add("rule", rule.origin, Severity.APPROX, "FQDN_RESOLVED_ONCE",
                            f"'{name}' is a host name: pfctl resolves it once, when the rules are loaded, and keeps the addresses it got then")  # fmt: skip
        label = _label(rule.name)
        heads = self._heads(rule, fragments, number)
        if not heads:
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING", "nothing in this rule can match a packet of either IP version", Severity.INFO)
            return
        verdict = self._verdict(rule, fragments)
        log = " log" if rule.log_start else ""
        count = 0
        for src_zones, dst_zones in pairs:
            on = self._on(dst_zones)
            for zone in src_zones:
                tagged = f"tagged {self.tag[zone]}"
                for head, negated_services in heads:
                    if negated_services:
                        skip = unique(f"{self.prefix}x{number}_{zone or 'all'}", self.taken, PF_TABLE)
                        for words in negated_services:
                            self.decide.append(_join("match out", on, words, tagged, f"tag {skip}"))
                    if rule.action == Action.ALLOW:
                        self.decide.append(_join(f"match out{log}", on, head, tagged, f"tag {self.ok[zone]}", label))
                    else:
                        self.decide.append(_join(f"block {verdict} out{log} quick", on, head, tagged, label))
                    if negated_services:
                        self.decide.append(_join("match out", tagged.replace(self.tag[zone], skip), f"tag {self.tag[zone]}"))
                    count += 1
        item.emitted_as.append(f"{count} rule{'s' if count != 1 else ''}")
        if rule.action == Action.ALLOW:
            self._admit(rule, fragments, pairs, label)

    def _heads(self, rule: Rule, fragments: List[Frag], number: int) -> List[Tuple[str, List[str]]]:
        """(the words after the tag, the words of the services a negated list leaves out) for each fragment."""
        out: List[Tuple[str, List[str]]] = []
        families = self._rule_families(rule)
        if rule.negate_service:
            if fragments == [(0, "")]:
                return []  # not any service: nothing
            for family in families:
                words = [line for need, fragment in fragments if need in (0, family)
                         for line in [self._match(rule, fragment, family, number)] if line is not None]  # fmt: skip
                head = self._match(rule, "", family, number)
                if head is not None:
                    out.append((head, words))
            return out
        for need, fragment in fragments:
            for family in [need] if need else self._split(rule, families):
                if family and family not in families:
                    continue
                line = self._match(rule, fragment, family, number)
                if line is not None:
                    out.append((line, []))
        return out

    def _rule_families(self, rule: Rule) -> List[int]:
        return sorted(self._families(rule.sources, rule.negate_source) & self._families(rule.destinations, rule.negate_destination))

    @staticmethod
    def _split(rule: Rule, families: List[int]) -> List[int]:
        """The IP versions to write a rule for one by one: pfctl takes the version of a line from a single address in
        it, which a negated address must not decide, and 0.0.0.0/0 or ::/0 is one version only."""
        if rule.negate_source or rule.negate_destination or rule.negate_service:
            return families
        if any(m in (ANY_V4, ANY_V6) for m in rule.sources + rule.destinations):
            return families
        return [0]

    def _match(self, rule: Rule, fragment: str, family: int, number: int) -> Optional[str]:
        proto, src_port, dst_port, extra = _parts(fragment)
        src = self._address(rule.sources, rule.negate_source, family, "src", rule.name)
        dst = self._address(rule.destinations, rule.negate_destination, family, "dst", rule.name)
        if src is None or dst is None:
            return None
        if not family and 0 != _family(src.lstrip("! ")) != _family(dst.lstrip("! ")) != 0:
            return None  # an address of each IP version: no packet
        af = {4: "inet", 6: "inet6"}.get(family, "")
        return _join(af, proto, "from", src, f"port {src_port}" if src_port else "", "to", dst, f"port {dst_port}" if dst_port else "", extra)

    def _verdict(self, rule: Rule, fragments: List[Frag]) -> str:
        if rule.action in (Action.ALLOW, Action.DROP):
            return "drop"
        if rule.action == Action.DENY:
            return "return"
        tcp_only = not rule.negate_service and bool(fragments) and all(f.startswith("proto tcp\x00") for _, f in fragments)
        if tcp_only:
            return "return-rst"
        self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                        f"action {rule.action.value} becomes block return: a TCP reset can only answer TCP, pf answers the rest with ICMP")  # fmt: skip
        return "return"

    def _admit(self, rule: Rule, fragments: List[Frag], pairs: List[Tuple[List[str], List[str]]], label: str) -> None:
        """What arrives that the rule may allow is let in (when it leaves, the rules decide); never to the firewall itself."""
        zones = transform.dedupe([z for src_zones, _ in pairs for z in src_zones])
        on = self._on(zones)
        if rule.negate_service:
            fragments = [(0, "")]
        families = self._rule_families(rule)
        lines: List[str] = []
        for need, fragment in fragments:
            for family in [need] if need else self._split(rule, families):
                if family and family not in families:
                    continue
                proto, src_port, dst_port, extra = _parts(fragment)
                src = self._address(rule.sources, rule.negate_source, family, "src", rule.name)
                dst = self._address(rule.destinations, rule.negate_destination, family, "dst", rule.name)
                if src is None or dst is None:
                    continue
                if dst == "any":
                    dst = "! self"
                af = {4: "inet", 6: "inet6"}.get(family, "")
                lines.append(_join("pass in quick", on, af, proto, "from", src, f"port {src_port}" if src_port else "", "to", dst,
                                   f"port {dst_port}" if dst_port else "", extra, label))  # fmt: skip
        self.admit += [line for line in transform.dedupe(lines) if line not in self.admit]

    # -- NAT ------------------------------------------------------------------------------------

    def nat_problem(self, nat: NatRule) -> Optional[Tuple[str, str, Severity]]:
        """Why a NAT rule cannot be written; None when it can."""
        members = nat.sources + nat.destinations
        snat, dnat = nat.source_translation, nat.destination_translation
        members += (snat.addresses if snat else []) + ([dnat.address] if dnat else [])
        problems = list(nat.unsupported)
        problems += [f"references '{m}': {self.taint_a[m]}" for m in members if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        if problems:
            return "NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems), Severity.REVIEW
        if nat.service != ANY:
            entries = transform.flatten_services(self.p, nat.service)
            if not entries:
                return "NAT_SERVICE", f"service '{nat.service}' cannot be read", Severity.REVIEW
            fragments, problems = service_fragments(entries)
            if problems:
                return "NAT_SERVICE", f"service '{nat.service}': " + "; ".join(problems), Severity.REVIEW
            if dnat is not None and dnat.port and any(e.protocol not in (Protocol.TCP, Protocol.UDP) for e in entries):
                return "NAT_PORT", "a port translation needs a TCP or UDP service", Severity.REVIEW
        elif dnat is not None and dnat.port:
            return "NAT_PORT", "a port translation needs a TCP or UDP service on the rule", Severity.REVIEW
        if dnat is not None:
            mapped = transform.address_intervals(self.p, dnat.address)
            if not mapped or len(mapped) != 1 or mapped[0] in (FULL_V4, FULL_V6):
                return "NAT_DESTINATION", "the translated address must be one address or network", Severity.REVIEW
            if dnat.spread and size(mapped[0]) > 1 and len(_entries(mapped[0])) != 1:
                return "NAT_DESTINATION", "a translation to a range of addresses is not written", Severity.REVIEW
        if snat is not None and snat.kind != SnatKind.INTERFACE:
            for address in snat.addresses:
                resolved = transform.address_intervals(self.p, address)
                if not resolved:
                    return "NAT_POOL", f"translated address '{address}' is not a static address", Severity.REVIEW
            if snat.kind == SnatKind.STATIC and snat.bidirectional and transform.bidirectional_pair(self.p, nat) is None:
                return "NAT_BIDIRECTIONAL", "bi-directional static NAT of other than one address or network for one", Severity.REVIEW
        if snat is not None and snat.kind == SnatKind.INTERFACE and ANY in nat.dst_zones and not snat.interface and self.zones == [""]:
            return "NAT_INTERFACE", "NAT to the address of the outgoing interface needs a zone the traffic leaves by", Severity.REVIEW
        return None

    def _nat_match(self, nat: NatRule, destinations: List[str], service_ports: str = "") -> List[str]:
        """The words that match what a NAT rule translates, per IP version and protocol."""
        entries = transform.flatten_services(self.p, nat.service) if nat.service != ANY else None
        fragments: List[Frag] = [(0, "")] if entries is None else service_fragments(entries)[0]
        families = self._families(nat.sources, False) & self._families(destinations, False)
        out: List[str] = []
        for need, fragment in fragments:
            for family in [need] if need else sorted(families):
                if family not in families:
                    continue
                proto, src_port, dst_port, extra = _parts(fragment)
                if service_ports:
                    dst_port = _ports(service_ports)
                src = self._address(nat.sources, False, family, "src", nat.name)
                dst = self._address(destinations, False, family, "dst", nat.name)
                if src is None or dst is None:
                    continue
                af = "inet" if family == 4 else "inet6"
                out.append(_join(af, proto, "from", src, f"port {src_port}" if src_port else "", "to", dst, f"port {dst_port}" if dst_port else "", extra))
        return transform.dedupe(out)

    def _pool(self, address: str, static: bool) -> str:
        """The words after nat-to or rdr-to for one translated address or network."""
        intervals = transform.address_intervals(self.p, address) or []
        entries = [e for i in intervals for e in _entries(i)]
        if len(entries) == 1:
            single = size(intervals[0]) == 1
            return entries[0] + ("" if single else " bitmask" if static else "")
        key = tuple(entries)
        if key not in self.table_of:
            self.table_of[key] = unique(f"{self.prefix}pool_{address}", self.taken, PF_TABLE)
            self.tables[self.table_of[key]] = " ".join(entries)
        return f"<{self.table_of[key]}> round-robin"

    def _nat(self, nat: NatRule) -> None:
        problem = self.nat_problem(nat)
        if problem is not None:
            self.report.skip("nat", nat.origin, *problem)
            return
        item = self.report.item("nat", nat.origin)
        prefix = "" if nat.enabled else "# disabled in the source: "
        label = _label(nat.name)
        snat, dnat = nat.source_translation, nat.destination_translation
        zones_in = self._sources(nat.src_zones)
        admitted: List[str] = []
        decided: List[str] = []
        if dnat is not None:
            to = self._pool(dnat.address, True) + (f" port {dnat.port.replace('-', ':')}" if dnat.port else "")
            for words in self._nat_match(nat, nat.destinations):
                admitted.append(_join("pass in quick", self._on(zones_in), words, f"rdr-to {to}", label))
            if not nat.destinations or ANY in nat.destinations:
                self.report.add("nat", nat.origin, Severity.REVIEW, "NAT_ANY_DESTINATION",
                                "the rule translates traffic to every destination; the security rules were not adjusted to the translated address")  # fmt: skip
        pair = transform.bidirectional_pair(self.p, nat) if snat is not None and snat.bidirectional else None
        if pair is not None:
            inside, outside = pair
            static = " bitmask" if size(inside) > 1 else ""
            admitted.append(_join("pass in quick", self._on(self._sources([ANY])), "from any to", interval_text(outside),
                                  f"rdr-to {interval_text(inside)}{static}", _label(nat.name + " inbound")))  # fmt: skip
            self.report.add("nat", nat.origin, Severity.INFO, "NAT_BIDIRECTIONAL",
                            "bi-directional static NAT written as a nat-to for what leaves and an rdr-to for what arrives")  # fmt: skip
        if snat is not None or dnat is None:
            destinations = nat.destinations
            if dnat is not None:
                destinations = [dnat.address]
                self.report.add("nat", nat.origin, Severity.APPROX, "NAT_AFTER_DNAT",
                                "the source translation of this rule is matched when the traffic leaves, after its destination "
                                "translation; it also applies to traffic from the same sources that is sent to the translated address directly")  # fmt: skip
            ports = dnat.port if dnat is not None and dnat.port else ""
            out_zones = [ANY] if dnat is not None else nat.dst_zones
            for zone in zones_in:
                for words in self._nat_match(nat, destinations, ports):
                    for leaving in (self.zones if snat is not None and snat.kind == SnatKind.INTERFACE and ANY in out_zones
                                    and not snat.interface else out_zones):  # fmt: skip
                        target = ""
                        if snat is not None:
                            target = "nat-to " + self._snat_target(snat, leaving, nat)
                        decided.append(_join("match out", self._on([leaving]), words, f"tagged {self.ok[zone]}", target,
                                             f"tag {self.nat_tag}", label))  # fmt: skip
        self.admit += [prefix + line for line in admitted]
        self.snat += [prefix + line for line in decided]
        if not nat.enabled:
            self.report.add("nat", nat.origin, Severity.INFO, "NAT_DISABLED", "disabled in the source; written as a comment")
            return
        item.emitted_as += ([f"{len(admitted)} rdr-to"] if admitted else []) + ([f"{len(decided)} nat-to"] if decided else [])

    def _snat_target(self, snat: SourceNat, leaving: str, nat: NatRule) -> str:
        if snat.kind == SnatKind.INTERFACE:
            if leaving in self.macro and leaving:
                return f"(${self.macro[leaving]})"
            if snat.interface in self.macro:
                return f"(${self.macro[snat.interface]})"
            return f"({clean(snat.interface, PF_TABLE)})"
        if snat.kind == SnatKind.STATIC and snat.bidirectional:
            pair = transform.bidirectional_pair(self.p, nat)
            assert pair is not None
            return interval_text(pair[1]) + (" bitmask" if size(pair[1]) > 1 else " static-port")
        if len(snat.addresses) == 1:
            pool = self._pool(snat.addresses[0], snat.kind == SnatKind.STATIC)
            if snat.kind in (SnatKind.DYNAMIC, SnatKind.STATIC) and " " not in pool:
                pool += " static-port"
            return pool
        entries = [e for a in snat.addresses for i in (transform.address_intervals(self.p, a) or []) for e in _entries(i)]
        key = tuple(entries)
        if key not in self.table_of:
            self.table_of[key] = unique(f"{self.prefix}pool_{nat.name}", self.taken, PF_TABLE)
            self.tables[self.table_of[key]] = " ".join(entries)
        return f"<{self.table_of[key]}> round-robin" + (" static-port" if snat.kind == SnatKind.DYNAMIC else "")

    # -- output ---------------------------------------------------------------------------------

    def run(self) -> str:
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction")
        for number, rule in enumerate(self.p.rules, 1):
            self._rule(rule, number)
        self._defaults()
        self._notes()
        out = [
            "# Generated by FWShift - review the conversion report before loading this.",
            f'# A ruleset for the pf anchor "{_ANCHOR}" (OpenBSD; FreeBSD 15 and later). Check it with',
            f"# 'pfctl -vnf FILE -a {_ANCHOR}', load it with 'pfctl -a {_ANCHOR} -f FILE': nothing outside the anchor changes.",
            f'# The main ruleset decides where the anchor is evaluated: it needs a line \'anchor "{_ANCHOR}"\'.',
            "",
            "# The interface (or interface group) of each zone.",
        ]
        out += [f'{self.macro[zone]} = "{self._interface(zone)}"' for zone in self.zones if zone]
        if self.tables:
            out += ["", "# Tables."]
            out += [f"table <{name}> const {{ {body} }}" for name, body in self.tables.items()]
        out += ["", "# What arrives on the interface of a zone is marked with the zone."]
        for zone in self.zones:
            out.append(_join("match in", self._on([zone]) if zone else "all", f"tag {self.tag[zone]}"))
        out += ["", "# Destination NAT, first match, and what the rules may allow is let in: they decide when it leaves."]
        out += self.admit
        out += ["", "# The rules, first match, when the traffic leaves: the tag says the zone it came from."]
        out += self.decide
        out += ["", "# Source NAT, first match, of what the rules allowed."]
        out += self.snat
        out += ["", "# Pass what the rules allowed."]
        out += [f"pass out quick tagged {self.ok[zone]}" for zone in self.zones]
        out.append(f"pass out quick tagged {self.nat_tag}")
        return "\n".join(out) + "\n"

    def _interface(self, zone: str) -> str:
        if valid_interface(zone):
            return zone
        return clean(zone, PF_TABLE)[:15]

    def _defaults(self) -> None:
        """What no rule decides: the default of the source, inside a zone and between zones."""
        if Action.ALLOW in (self.p.default_intrazone, self.p.default_interzone):
            for zone in self.zones:
                self.admit.append(_join("pass in quick", self._on([zone]) if zone else "", "from any to ! self", _label("default")))
        lines = ["", "# What no rule decided: the default of the source."]
        for zone in self.zones:
            tagged = f"tagged {self.tag[zone]}"
            intra, inter = self.p.default_intrazone, self.p.default_interzone
            if intra != inter and zone:
                lines.append(self._default(intra, self._on([zone]), tagged, zone))
            lines.append(self._default(inter, "", tagged, zone))
        self.decide += lines

    def _default(self, action: Action, on: str, tagged: str, zone: str) -> str:
        if action == Action.ALLOW:
            return _join("match out", on, tagged, f"tag {self.ok[zone]}")
        return _join("block drop out quick", on, tagged)

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW,
            "PF_LOAD",
            f"the output is a ruleset for the anchor '{_ANCHOR}': check it with 'pfctl -vnf FILE -a {_ANCHOR}', load it with "
            f"'pfctl -a {_ANCHOR} -f FILE'. The main ruleset must call it ('anchor \"{_ANCHOR}\"'), before rules that pass or "
            "block forwarded traffic quick; rules after the anchor that are not quick can still change what it decides. It "
            "lets in what arrives on the interfaces of the zones that a rule may allow (never to the firewall's own addresses), "
            "decides when the traffic leaves, and needs OpenBSD pf or FreeBSD 15 or later (match rules with tag, nat-to, rdr-to)",
        )
        zones = [zone for zone in self.zones if zone]
        if zones and self.p.vendor != "pf":
            self.report.note(
                Severity.REVIEW,
                "INTERFACES_REQUIRED",
                "zones are written as interfaces or interface groups, a macro each at the top of the file: set each to the "
                "interface (or group) of the zone, or convert with --zone-map: " + ", ".join(zones),
            )
        bad = [zone for zone in zones if not valid_interface(zone)]
        if bad:
            self.report.note(Severity.REVIEW, "INTERFACE_NAME",
                             "these zone names are no interface names pf takes; their macros hold a cleaned name that matches "
                             "no interface until it is set: " + ", ".join(bad))  # fmt: skip
        if zones:
            self.report.note(Severity.INFO, "PF_ZONES_ONLY",
                             "the anchor decides about traffic that arrives on the interfaces of the zones (" + ", ".join(zones)
                             + "); what arrives on another interface is left to the main ruleset")  # fmt: skip
        transform.note_closed_zones(self.p, self.options.zone_map, self.report, list(self.options.zone_networks))
        open_zones = [zone.name for zone in self.p.zones.values() if zone.intrazone_allow]
        if open_zones and self.p.default_interzone != Action.ALLOW:
            self.report.note(Severity.REVIEW, "INTRAZONE_ALLOW",
                             "these zones allow traffic between their own interfaces on the source without a rule; no rule was "
                             "written for that: " + ", ".join(open_zones))  # fmt: skip
        if any(r.log_end and not r.log_start for r in self.p.rules):
            self.report.note(Severity.INFO, "LOGGING_AT_END",
                             "rules that log the end of a connection on the source are written without log: pf logs the "
                             "packet a rule matches; the rules that log the start of a connection have 'log'")  # fmt: skip


def _join(*parts: str) -> str:
    return " ".join(part for part in parts if part)


def _parts(fragment: str) -> Tuple[str, str, str, str]:
    """(protocol words, source ports, destination ports, ICMP words) of a fragment."""
    if not fragment:
        return "", "", "", ""
    parts = (fragment.split("\x00") + ["", "", "", ""])[:4]
    return parts[0], parts[1], parts[2], parts[3]


def _family(entry: str) -> int:
    interval = parse_literal(entry)
    return interval[0] if interval else 0


def _entries(interval: Interval) -> List[str]:
    """An interval as networks pf takes (a table holds no ranges)."""
    import ipaddress

    version, first, last = interval
    make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return [str(net) if net.num_addresses > 1 else str(net.network_address) for net in ipaddress.summarize_address_range(make(first), make(last))]
