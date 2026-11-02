# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Siemens SCALANCE emitter: neutral model -> CLI commands for a SCALANCE SC-600 or S615 (FIREWALL and FIREWALL NAT
configuration modes).

Design rules:

* The zones are the interfaces of the device: a zone ``vlan1`` (or ``vlan 1``, ``VLAN1``) is written ``vlan 1``; the
  VPN interfaces (``ipsecALL``, ``ipsec N``, ``sinemarcall``) and ``ppp 0`` / ``usb 0`` as the CLI names them. Any other
  zone name is written as it is, which the device refuses: map zones to interfaces with ``--zone-map``.
* A rule of the device names one interface each way, one source, one destination and at most one service. A rule of
  the model becomes one ``ipv4rule`` (and ``ipv6rule``) per pair of zones, address of each side and service; traffic
  inside one zone (one VLAN) does not pass the IP firewall and is not written. What a negation leaves is written as
  the ranges left. Services become IP services (``service name``, TCP or UDP, one port or range each way), ICMP
  services (``icmp name``, a type and a code: a type without a code becomes one service per code of that type in the
  IANA registry) and IP protocols (``proto name``; every ICMP is the protocol 1).
* Order: the device processes the rules by ascending priority (``prior``). The rules written get priorities from 1
  (``--policy-id-start``) up, one level per run of rules with the same action and logging, so the order within a level
  never decides a verdict. After them, the source's default for every pair of the zones written, so the converted rules
  decide all traffic between those zones; rules the device has with a lower priority still come first.
* There is no disabled rule and no comment in the CLI: a rule that cannot be written, or is disabled, is left out and
  listed in the report.
* Destination NAT is done before the firewall, whose rules name the translated address: the rules are written for it.
  Destination NAT becomes ``napt`` (one address and one port or range, of TCP or UDP) or ``netmap destination`` (a
  subnet onto a subnet of the same size), source NAT ``masquerading``, ``src-nat`` or ``netmap source``. IPv4 only.
* Add only: services, ICMP services and protocols with a prefix (``FWS_``), rules, NAT rules. Nothing is deleted,
  nothing is saved.
"""

from __future__ import annotations

import copy
import ipaddress
import itertools
import re
from dataclasses import dataclass, field
from typing import AbstractSet, Dict, List, Optional, Set, Tuple

from .. import names as name_rules
from .. import transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry, SnatKind
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, normalize, parse_literal, size, subtract
from ..options import Options
from ..report import Report, Severity

_PRIOR_MAX = 999  # (the SC-600 WBM manual: 0 ... 999; the S615 CLI manual of 2015: 0 ... 64)
_LINES_PER_RULE = 512
_OLD_RULE_LIMIT = 100  # (the S615 CLI manual of 2015 numbers rules 1 ... 100)
# The codes of the ICMP types FWShift writes a type without a code for (IANA registries of ICMP and ICMPv6 parameters).
_ICMP_CODES: Dict[int, Dict[int, List[int]]] = {
    4: {0: [0], 3: list(range(16)), 4: [0], 5: list(range(4)), 8: [0], 9: [0, 16], 10: [0], 11: [0, 1], 12: [0, 1, 2], 13: [0], 14: [0],
        15: [0], 16: [0], 17: [0], 18: [0]},
    6: {1: list(range(8)), 2: [0], 3: [0, 1], 4: list(range(4)), 128: [0], 129: [0], 130: [0], 131: [0], 132: [0], 133: [0], 134: [0],
        135: [0], 136: [0], 137: [0], 143: [0]},
}  # fmt: skip


def interface_words(zone: str) -> Optional[str]:
    """The interface a zone stands for, as a rule names it (``vlan 1``); None when the name is not an interface of a
    SCALANCE."""
    found = re.fullmatch(r"(?i)(vlan|ipsec|ppp|usb)[ _]?(\d+)", zone.strip())
    if found:
        return f"{found.group(1).lower()} {int(found.group(2))}"
    known = {"device": "device", "ipsecall": "ipsecALL", "sinemarcall": "sinemarcall"}
    return known.get(zone.strip().lower())


@dataclass
class _Written:
    rule: Rule
    lines: List[str]
    action: str
    log: str
    level: int = 0


@dataclass
class _Out:
    objects: List[str] = field(default_factory=list)
    rules: List[_Written] = field(default_factory=list)
    nat: List[str] = field(default_factory=list)


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    prefix = options.object_prefix or "FWS_"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,11}", prefix):
        raise FwshiftError("--target-prefix for SCALANCE: up to 12 letters, digits, periods, underscores and hyphens, starting with a letter")
    if not 0 <= options.policy_id_start <= _PRIOR_MAX:
        raise FwshiftError(f"--policy-id-start for SCALANCE: the priority of the first rules, 0 to {_PRIOR_MAX}")
    probe = _Emitter(p, Report(), options, source_zones)
    written = {nat.origin for nat in p.nat_rules if probe.nat_lines(nat)}
    translated = {nat.origin for nat in p.nat_rules if nat.origin in written
                  and (nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None)}  # fmt: skip
    transform.to_post_nat_lookup(p, report, translated)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, source_zones).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, source_zones: AbstractSet[str] = frozenset()) -> None:
        self.p, self.report, self.options = p, report, options
        self.source_zones = source_zones
        self.prefix = options.object_prefix or "FWS_"
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        used += [z for n in p.nat_rules for z in n.src_zones + n.dst_zones if z != ANY]
        self.zones = [z for z in transform.target_zones(p, options.zone_map, used, []) if interface_words(z) != "device"]
        self.out = _Out()
        self.taken: Set[str] = set()
        self.objects: Dict[str, str] = {}  # key -> name
        self.odd_zones: List[str] = []
        self.ipv6 = self._uses_ipv6()
        self.ipv4_only_rules: List[str] = []
        self.nat_cache: Dict[str, List[str]] = {}
        self.any_zone = False

    # -- names and zones -------------------------------------------------------------------------

    def _uses_ipv6(self) -> bool:
        for rule in self.p.rules:
            for member in rule.sources + rule.destinations:
                if member != ANY and 6 in transform.families(self.p, member):
                    return True
            for service in rule.services:
                if any(e.protocol == Protocol.ICMP6 for e in transform.flatten_services(self.p, service) or []):
                    return True
        return False

    def _interface(self, zone: str) -> str:
        words = interface_words(zone)
        if words is not None:
            return words
        cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", zone)[:50] or "zone"
        if zone not in self.odd_zones:
            self.odd_zones.append(zone)
        return cleaned

    def _name(self, label: str) -> str:
        return name_rules.unique(self.prefix + label, self.taken, name_rules.SCALANCE)

    # -- addresses ---------------------------------------------------------------------------------

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[Dict[int, List[str]]]:
        """The values of one side per IP version (``0.0.0.0/0``, an address, a subnet, a range); None if it cannot be
        written."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                found += [FULL_V4, FULL_V6]
                continue
            if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {member}: a rule of the device names addresses only"))
                return None
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows"))
                return None
            found += intervals
        merged = normalize(found)
        if negated:
            merged = subtract([FULL_V4, FULL_V6], merged)
        return {family: [interval_text(i) for i in merged if i[0] == family] for family in (4, 6)}

    # -- services ----------------------------------------------------------------------------------

    @staticmethod
    def _ports(ports: str) -> str:
        if not ports:
            return "all"
        first, _, last = ports.partition("-")
        return f"port {first}" if not last or first == last else f"range {first} - {last}"

    def _object(self, key: str, label: str, line: str) -> str:
        if key not in self.objects:
            name = self._name(label)
            self.objects[key] = name
            self.out.objects.append(line.format(name=name))
        return self.objects[key]

    def _refs(self, entry: ServiceEntry, reasons: List[transform.Reason], hint: str = "") -> Optional[List[Tuple[str, Set[int]]]]:
        """The service names (and the IP versions each is for) one entry becomes; ``hint`` is the name of the service of
        the source, which a new object is named after when the entry is all it holds."""
        both = {4, 6}
        if entry.protocol in (Protocol.TCP, Protocol.UDP):
            out: List[Tuple[str, Set[int]]] = []
            for dst in entry.dst_ports.split(",") if entry.dst_ports else [""]:
                for src in entry.src_ports.split(",") if entry.src_ports else [""]:
                    proto = entry.protocol.value
                    label = hint or f"{proto}_{dst or 'any'}" + (f"_from_{src}" if src else "")
                    line = f"service name {{name}} proto {proto} src {self._ports(src)} dst {self._ports(dst)}"
                    out.append((self._object(f"s:{proto}:{src}:{dst}", label, line), both))
            return out
        if entry.protocol == Protocol.SCTP:
            if entry.dst_ports or entry.src_ports:
                reasons.append(("SERVICE_SCTP", "SCTP ports: an IP service of the device is TCP or UDP"))
                return None
            return [(self._object("p:132", hint or "proto_132", "proto name {name} num 132"), both)]
        if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
            family = 4 if entry.protocol == Protocol.ICMP else 6
            number = 1 if family == 4 else 58
            if entry.icmp_type is None:
                if entry.icmp_code is not None:
                    reasons.append(("SERVICE_NOT_WRITTEN", "an ICMP code without a type"))
                    return None
                return [(self._object(f"p:{number}", hint or f"proto_{number}", f"proto name {{name}} num {number}"), {family})]
            codes = [entry.icmp_code] if entry.icmp_code is not None else _ICMP_CODES[family].get(entry.icmp_type)
            if codes is None:
                reasons.append(("SERVICE_NOT_WRITTEN", f"ICMP{'v6' if family == 6 else ''} type {entry.icmp_type} without a code: an "
                                "ICMP service of the device names a type and a code, and FWShift knows no codes of this type"))  # fmt: skip
                return None
            kind = "icmp" if family == 4 else "icmp6"
            return [(self._object(f"i:{family}:{entry.icmp_type}:{code}", hint if hint and len(codes) == 1 else f"{kind}_{entry.icmp_type}_{code}",
                                  f"icmp name {{name}} type {entry.icmp_type} code {code} ver ipv{family}"), {family}) for code in codes]  # fmt: skip
        if entry.ip_protocol is None:
            return [("", both)]
        if not 1 <= entry.ip_protocol <= 254:
            reasons.append(("SERVICE_NOT_WRITTEN", f"IP protocol {entry.ip_protocol}: a protocol of the device is 1 to 254"))
            return None
        number = entry.ip_protocol
        return [(self._object(f"p:{number}", hint or f"proto_{number}", f"proto name {{name}} num {number}"), both)]

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[Tuple[str, Set[int]]]]:
        """(service name or "" for every protocol, IP versions) of a rule."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        hinted: List[Tuple[ServiceEntry, str]] = []
        if lowered is not None:
            hinted = [(entry, app if len(found) == 1 else "") for app, found in lowered for entry in found]
            if not hinted:
                return None
        else:
            if rule.negate_service:
                reasons.append(("SERVICE_NEGATE", "every service but some: a rule of the device names one service"))
                return None
            if rule.services == [ANY]:
                return [("", {4, 6})]
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    if name not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                single = len(flat) == 1 and "," not in flat[0].dst_ports + flat[0].src_ports
                hinted += [(entry, name if single else "") for entry in flat]
        if any(e.protocol == Protocol.IP and e.ip_protocol is None for e, _ in hinted):
            return [("", {4, 6})]
        out: List[Tuple[str, Set[int]]] = []
        for entry, hint in hinted:
            refs = self._refs(entry, reasons, hint)
            if refs is None:
                return None
            out += refs
        merged: Dict[str, Set[int]] = {}
        for ref, families in out:
            merged.setdefault(ref, set()).update(families)
        return list(merged.items())

    # -- rules -------------------------------------------------------------------------------------

    def _pairs(self, rule: Rule) -> Tuple[List[Tuple[str, str]], bool]:
        """The (from, to) zones of the lines of a rule, and whether pairs inside one zone were left out."""
        if ANY in rule.src_zones + rule.dst_zones:
            self.any_zone = True
        sources = list(self.zones) if ANY in rule.src_zones else [z for z in rule.src_zones if z != ANY]
        destinations = list(self.zones) if ANY in rule.dst_zones else [z for z in rule.dst_zones if z != ANY]
        pairs = [(a, b) for a in transform.dedupe(sources) for b in transform.dedupe(destinations)]
        inside = any(a == b for a, b in pairs)
        return [(a, b) for a, b in pairs if a != b], inside

    def _rule(self, rule: Rule) -> None:
        if rule.scope == RuleScope.INTRAZONE:
            severity = Severity.INFO if rule.action == Action.ALLOW else Severity.REVIEW
            self.report.skip("rule", rule.origin, "SCALANCE_INTRAZONE", "a rule for traffic inside a zone: traffic inside one VLAN "
                             "does not pass the IP firewall of the device and is not filtered", severity)  # fmt: skip
            return
        if not rule.enabled:
            self.report.skip("rule", rule.origin, "DISABLED_NOT_WRITTEN", "disabled in the source; a rule of the device cannot be "
                             "disabled: not written", Severity.INFO)  # fmt: skip
            return
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        sources = self._side(rule, True, reasons)
        destinations = self._side(rule, False, reasons)
        services = self._services(rule, reasons)
        pairs, inside = self._pairs(rule)
        if not self.zones:
            reasons.append(("SCALANCE_NO_ZONES", "the policy names no zones: a rule of the device names its two interfaces"))
        lines: List[str] = []
        if not reasons and sources is not None and destinations is not None and services is not None:
            everything = sources == {4: ["0.0.0.0/0"], 6: ["::/0"]} and destinations == sources
            families = (4, 6) if self.ipv6 else (4,)
            if not self.ipv6 and (sources[6] or destinations[6]) and everything:
                self.ipv4_only_rules.append(rule.name)
            action = {Action.ALLOW: "acc", Action.DENY: "drop", Action.DROP: "drop"}.get(rule.action, "rej")
            log = "info" if rule.log_start or rule.log_end else "no"
            combos = ((a, b, f, s, d, ref) for a, b in pairs for f in families for s in sources[f] for d in destinations[f]
                      for ref, versions in services if f in versions)  # fmt: skip
            for src_zone, dst_zone, family, source, destination, ref in itertools.islice(combos, _LINES_PER_RULE + 1):
                lines.append(f"ipv{family}rule from {self._interface(src_zone)} to {self._interface(dst_zone)} srcip {source} "
                             f"dstip {destination} action {action}" + (f" service {ref}" if ref else "") + f" log {log}")  # fmt: skip
            if len(lines) > _LINES_PER_RULE:
                reasons.append(("SCALANCE_TOO_MANY", f"more than {_LINES_PER_RULE} rules of the device (pairs of zones, addresses and "
                                "services)"))  # fmt: skip
            elif not lines and pairs:
                reasons.append(("NOT_WRITTEN", "no rule of the device matches what it matches (ICMP of one IP version with "
                                "addresses of the other only, or IPv6 in a policy written for IPv4)"))  # fmt: skip
            elif not lines:
                severity = Severity.INFO if rule.action == Action.ALLOW else Severity.REVIEW
                self.report.skip("rule", rule.origin, "SCALANCE_INTRAZONE", "the rule matches traffic inside one zone only, which does "
                                 "not pass the IP firewall of the device", severity)  # fmt: skip
                return
            if not reasons:
                if inside:
                    self.report.add("rule", rule.origin, Severity.INFO if rule.action == Action.ALLOW else Severity.REVIEW, "SCALANCE_INTRAZONE",
                                    "traffic inside one zone does not pass the IP firewall of the device: there the rule filters nothing")  # fmt: skip
                if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
                    self.report.add("rule", rule.origin, Severity.INFO, "SCALANCE_REJECT", f"action {rule.action.value}: written as rej, "
                                    "which answers the sender (with what, the manuals do not say)")  # fmt: skip
                self.out.rules.append(_Written(rule, lines, action, log))
                return
        reasons = list(dict.fromkeys(reasons)) or [("NOT_WRITTEN", "the rule cannot be written")]
        transform.disable_rule(self.report, rule, reasons)
        self.report.item("rule", rule.origin).skipped = True

    def _levels(self) -> int:
        """Give each run of rules with the same action and logging one priority; return the next free one."""
        level = self.options.policy_id_start or 1
        previous: Optional[Tuple[str, str]] = None
        for index, written in enumerate(self.out.rules):
            if previous is not None and (written.action, written.log) != previous:
                level += 1
            previous = (written.action, written.log)
            written.level = level
        return level + 1 if self.out.rules else level

    def _defaults(self, level: int) -> List[_Written]:
        """The source's default for every pair of the zones written, after the rules."""
        zones = [z for z in self.zones if interface_words(z) != "device"]
        inter = self.p.default_interzone == Action.ALLOW
        action = "acc" if inter else "drop"
        if self.out.rules and self.out.rules[-1].action == action and self.out.rules[-1].log == "no":
            level -= 1  # (the same action as the last run: one level)
        lines = []
        for src_zone in zones:
            for dst_zone in zones:
                if src_zone == dst_zone:
                    continue
                for family in (4, 6) if self.ipv6 else (4,):
                    every = "0.0.0.0/0" if family == 4 else "::/0"
                    lines.append(f"ipv{family}rule from {self._interface(src_zone)} to {self._interface(dst_zone)} srcip {every} "
                                 f"dstip {every} action {action} log no prior {level}")  # fmt: skip
        if lines:
            self.report.note(Severity.INFO, "SCALANCE_DEFAULT_RULES",
                             f"after the converted rules, rules that {'accept' if inter else 'drop'} what no rule matches, as the source "
                             f"does, for every pair of the {len(zones)} zones written (priority {level}); traffic inside one zone does "
                             "not pass the IP firewall")  # fmt: skip
        if inter:
            self.report.note(Severity.REVIEW, "SCALANCE_DEFAULT_ACCEPT",
                             "the source accepts what no rule matches: the rules at the end accept everything between the zones "
                             "written, which the device would otherwise drop")  # fmt: skip
        inside = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, zones, self.report)
        blocked = [zone for zone in zones if not inside.get(zone, True)]
        if blocked:
            self.report.note(Severity.REVIEW, "SCALANCE_INTRAZONE_DEFAULT",
                             "the source blocks traffic inside a zone that no rule matches; inside one VLAN the device passes "
                             "everything: " + ", ".join(blocked[:12]) + (" ..." if len(blocked) > 12 else ""))  # fmt: skip
        return [_Written(Rule("defaults"), lines, action, "no", level)] if lines else []

    # -- NAT ---------------------------------------------------------------------------------------

    def nat_lines(self, nat: NatRule) -> List[str]:
        key = nat.origin + "\0" + nat.name
        if key not in self.nat_cache:
            self.nat_cache[key] = self._nat_lines(nat)
        return self.nat_cache[key]

    def _values(self, members: List[str]) -> Optional[List[str]]:
        """IPv4 values of a NAT rule's side (``0.0.0.0/0`` for any); None if it holds anything else."""
        if ANY in members:
            return ["0.0.0.0/0"]
        out: List[str] = []
        for member in members:
            intervals, known = transform.known_intervals(self.p, member)
            if not known or any(i[0] != 4 for i in intervals) or not intervals:
                return None
            out += [interval_text(i) for i in normalize(intervals)]
        return out

    @staticmethod
    def _cidr(text: str) -> Optional[ipaddress.IPv4Network]:
        try:
            return ipaddress.IPv4Network(text if "/" in text else text + "/32")
        except ValueError:
            return None

    def _zone_of(self, address: Interval) -> Optional[str]:
        """The zone whose networks hold an address, by the longest prefix (--zone-network, or what the source says)."""
        networks = dict(self.p.zone_networks)
        networks.update(self.options.zone_networks)
        best: Optional[Tuple[int, str]] = None
        for zone, values in networks.items():
            for value in values:
                found = parse_literal(value)
                if found is not None and found[0] == address[0] and found[1] <= address[1] and address[2] <= found[2]:
                    if best is None or size(found) < best[0]:
                        best = (size(found), zone)
        return best[1] if best else None

    def _nat_lines(self, nat: NatRule) -> List[str]:
        if not nat.enabled or nat.unsupported:
            return []
        pair = transform.bidirectional_pair(self.p, nat)
        if pair is not None:
            inside, outside = pair
            if len(nat.src_zones) != 1 or len(nat.dst_zones) != 1 or ANY in nat.src_zones + nat.dst_zones or nat.destinations != [ANY] \
                    or nat.service != ANY:
                return []
            inner, outer = interval_text(inside), interval_text(outside)
            if self._cidr(inner) is None or self._cidr(outer) is None:
                return []
            a, b = self._interface(nat.src_zones[0]), self._interface(nat.dst_zones[0])
            return [f"netmap source srcint {a} dstint {b} type ipv4 srcip {inner} dstip 0.0.0.0/0 transip {outer}",
                    f"netmap destination srcint {b} dstint {a} type ipv4 srcip 0.0.0.0/0 dstip {outer} transip {inner}"]  # fmt: skip
        dnat, snat = nat.destination_translation, nat.source_translation
        if dnat is not None and snat is not None:
            return []
        if dnat is not None:
            return self._dnat(nat)
        if snat is None:
            return []  # (an exemption: the device has none)
        if nat.service != ANY or len(nat.dst_zones) != 1 or ANY in nat.dst_zones:
            return []
        sources, destinations = self._values(nat.sources), self._values(nat.destinations)
        if sources is None or destinations is None:
            return []
        dst_if = self._interface(nat.dst_zones[0])
        src_zones = [z for z in (self.zones if ANY in nat.src_zones else nat.src_zones) if z != nat.dst_zones[0]]
        if snat.kind == SnatKind.INTERFACE:
            if nat.sources == [ANY] and nat.destinations == [ANY] and ANY in nat.src_zones:
                return [f"masquerading {dst_if}"]
            translated = "auto"
        elif snat.kind in (SnatKind.DYNAMIC, SnatKind.DYNAMIC_PORT):
            pool = self._values(snat.addresses) if snat.addresses else None
            if pool is None or len(pool) != 1 or "/" in pool[0] or "-" in pool[0]:
                return []
            translated = pool[0]
        elif snat.kind == SnatKind.STATIC and len(sources) == 1:
            pool = self._values(snat.addresses) if snat.addresses else None
            source_net = self._cidr(sources[0])
            target = self._cidr(pool[0]) if pool and len(pool) == 1 else None
            if source_net is None or target is None or source_net.num_addresses != target.num_addresses or snat.bidirectional:
                return []
            return [f"netmap source srcint {self._interface(z)} dstint {dst_if} type ipv4 srcip {sources[0]} dstip {d} transip {target}"
                    for z in src_zones for d in destinations]  # fmt: skip
        else:
            return []
        return [f"src-nat srcint {self._interface(z)} dstint {dst_if} type ipv4 srcip {s} dstip {d} transip {translated}"
                for z in src_zones for s in sources for d in destinations]  # fmt: skip

    def _dnat(self, nat: NatRule) -> List[str]:
        dnat = nat.destination_translation
        assert dnat is not None
        if dnat.spread or len(nat.destinations) != 1:
            return []
        outer, _ = transform.known_intervals(self.p, nat.destinations[0])
        inner, _ = transform.known_intervals(self.p, dnat.address) if dnat.address else ([], True)
        if len(outer) != 1 or len(inner) != 1 or outer[0][0] != 4 or inner[0][0] != 4:
            return []
        zones = [z for z in (self.zones if ANY in nat.src_zones else nat.src_zones) if z != ANY]
        if not zones:
            return []
        if nat.service != ANY:
            entries = transform.flatten_services(self.p, nat.service)
            if not entries or len(entries) != 1 or entries[0].protocol not in (Protocol.TCP, Protocol.UDP) or entries[0].src_ports \
                    or not re.fullmatch(r"\d+(-\d+)?", entries[0].dst_ports) or nat.sources != [ANY]:
                return []
            if outer[0][1] != outer[0][2] or inner[0][1] != inner[0][2]:
                return []
            first, _, last = entries[0].dst_ports.partition("-")
            ports = first if not last or last == first else f"{first} - {last}"
            if dnat.port and not dnat.port.isdigit():
                return []
            translated = dnat.port or ports
            return [f"napt srcint {self._interface(z)} proto {entries[0].protocol.value} type ipv4 dstip {interval_text(outer[0])} "
                    f"transip {interval_text(inner[0])} dstport {ports} transport {translated}" for z in zones]  # fmt: skip
        if dnat.port or size(outer[0]) != size(inner[0]):
            return []
        before, after = interval_text(outer[0]), interval_text(inner[0])
        if self._cidr(before) is None or self._cidr(after) is None:
            return []
        sources = self._values(nat.sources)
        target_zone = self._zone_of(inner[0])
        if sources is None or target_zone is None:
            return []
        return [f"netmap destination srcint {self._interface(z)} dstint {self._interface(target_zone)} type ipv4 srcip {s} dstip {before} "
                f"transip {after}" for z in zones if z != target_zone for s in sources]  # fmt: skip

    # -- output ------------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        level = self._levels()
        defaults = self._defaults(level)
        rules_written = self.out.rules + defaults
        too_high = [w for w in rules_written if w.level > _PRIOR_MAX]
        for written in too_high:
            if written.rule.origin:
                self.report.skip("rule", written.rule.origin, "SCALANCE_PRIORITY", f"the priority {written.level} it would need is above "
                                 f"{_PRIOR_MAX}, the highest the device takes")  # fmt: skip
        rules_written = [w for w in rules_written if w.level <= _PRIOR_MAX]
        lines: List[str] = []
        for written in rules_written:
            if written.rule.origin:
                lines += [f"{line} prior {written.level}" for line in written.lines]
                self.report.item("rule", written.rule.origin).emitted_as.append(f"{len(written.lines)} IP rules, priority {written.level}")
            else:
                lines += written.lines
        written_nat: Set[str] = set()
        for nat in self.p.nat_rules:
            found = self.nat_lines(nat)
            if not found:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                                 "not converted: the device writes destination NAT for one address and one TCP or UDP port or range "
                                 "(napt), or a subnet onto one of the same size (netmap), and source NAT to the interface, to one "
                                 "address or 1:1 (masquerading, src-nat, netmap); IPv4 only, no service in source NAT, no exemption")  # fmt: skip
                continue
            written_nat.add(nat.origin)
            self.out.nat += found
            self.report.item("nat", nat.origin).emitted_as.append(f"{len(found)} {found[0].split()[0]} rules")
        if written_nat:
            transform.note_nat_order(self.p, self.report, written_nat, "per-direction")
        out = ["configure terminal", "firewall"] + self.out.objects + lines + ["exit"]
        if self.out.nat:
            out += ["firewallnat"] + self.out.nat + ["exit"]
        out.append("end")
        self._notes(rules_written, len(lines))
        return "\n".join(out) + "\n"

    def _notes(self, rules_written: List[_Written], count: int) -> None:
        levels = [w.level for w in rules_written]
        where = f"priorities {min(levels)} to {max(levels)}" if levels else "no rules"
        self.report.note(Severity.REVIEW, "SCALANCE_LOAD",
                         f"the output is CLI commands for the FIREWALL and FIREWALL NAT modes (section 10): {count} IP rules with "
                         f"{where}. The device processes rules by ascending priority: rules it has with a lower priority come "
                         "first. Commands take effect as they are entered; nothing is deleted and nothing is saved")  # fmt: skip
        if self.odd_zones:
            self.report.note(Severity.REVIEW, "SCALANCE_ZONE_NAMES",
                             "zones that are not interfaces of the device (vlan N, ipsecALL, ipsec N, sinemarcall, ppp 0, usb 0) are "
                             "written as they are, and the device refuses those rules: map them with --zone-map ZONE=vlanN: "
                             + ", ".join(self.odd_zones[:12]) + (" ..." if len(self.odd_zones) > 12 else ""))  # fmt: skip
        if self.any_zone and self.zones:
            self.report.note(Severity.INFO, "SCALANCE_ANY_ZONE",
                             "a rule names one interface each way: a rule from or to any zone is written for every zone the policy "
                             "names (" + ", ".join(self.zones[:12]) + (" ..." if len(self.zones) > 12 else "") + "); traffic of other "
                             "interfaces of the device meets its own rules")  # fmt: skip
        if self.ipv4_only_rules:
            self.report.note(Severity.APPROX, "SCALANCE_IPV4_ONLY",
                             "the policy names no IPv6 address: rules that match any address were written for IPv4 only, and IPv6 "
                             "traffic meets the device's default: " + ", ".join(self.ipv4_only_rules[:12])
                             + (" ..." if len(self.ipv4_only_rules) > 12 else ""))  # fmt: skip
        if any(line.startswith("ipv6rule") for w in rules_written for line in w.lines) or any("ver ipv6" in line for line in self.out.objects):
            self.report.note(Severity.REVIEW, "SCALANCE_IPV6",
                             "ipv6rule and ICMP services of IPv6 are written in the form of the IPv4 commands; no Siemens manual "
                             "FWShift could read shows them: check them on the device")  # fmt: skip
        if count > _OLD_RULE_LIMIT:
            self.report.note(Severity.INFO, "SCALANCE_RULE_COUNT",
                             f"{count} IP rules: the S615 CLI manual of 2015 numbers rules 1 to {_OLD_RULE_LIMIT}; check how many the "
                             "firmware takes")  # fmt: skip
        if levels and max(levels) > 64:
            self.report.note(Severity.INFO, "SCALANCE_PRIORITY_RANGE",
                             f"priorities up to {max(levels)}: the SC-600 takes 0 to 999, the S615 CLI manual of 2015 0 to 64")
        if any(w.log == "info" for w in rules_written):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their rules log at the level info")
        if any(nat.destination_translation is not None for nat in self.p.nat_rules) and self.out.nat:
            self.report.note(Severity.INFO, "SCALANCE_NAT_WRITTEN",
                             "destination NAT is done before the firewall: the rules were written for the translated address")
