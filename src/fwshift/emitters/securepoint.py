# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Securepoint UTM emitter: neutral model -> commands of the UTM's CLI (``spcli``) that add network objects, services and
packet filter rules.

Design rules:

* The output only adds: ``node new``, ``node group new``, ``service new``, ``service group new``, one ``rule group new``
  (``fwshift``) and ``rule new`` in it. It never deletes or changes what is there, never creates zones or touches
  interfaces, and neither applies the rules (``system update rule``) nor saves the configuration (``system config save``):
  a person does both after reading the report (section 10 of the manual).
* A rule of the UTM has one source, one destination and one service, and its zones are those of its network objects.
  So every address is written as a network object in the zone it is used in (a model object used in two zones becomes
  two objects), a side of a rule with several members a network group, several services a service group, and a rule of
  the model one rule of the UTM per pair of a source and a destination zone. A side of ``any`` zone is written for every
  zone the policy knows, which is narrower where the UTM has other zones (reported). Zones must exist on the UTM under
  the names written (``--zone-map``).
* The UTM has no negation: a negated side is written as the networks that are left, a negated service is not written.
  An address range becomes the networks it is made of, a host name is not written (not confirmed that a network object
  takes one).
* The UTM has no rule that is switched off as far as its CLI is documented: a rule that is disabled, in the source or
  by the conversion, is written as a comment line (``#``), which is not loaded.
* After the converted rules come rules for what the policy does with traffic no rule matches, where it lets it through
  (the UTM drops what no rule matches).
* NAT is part of a rule on the UTM. A NAT rule of the model is written as a rule of its own with the action ``DROP`` after
  all others, carrying ``HIDENAT``, ``HIDENAT_EXCLUDE`` or ``DESTNAT``: the filter has decided all traffic before it,
  and its NAT applies to what it matches (netfilter applies NAT independently of the filter verdict; **assumed** for
  the UTM, section 12). The packet filter sees the destination after DESTNAT: rules are written for the translated
  address, as for iptables.
"""

from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..model import ANY, APP_DEFAULT, Action, AddressKind, NatRule, Policy, Protocol, Rule, ServiceEntry, SnatKind
from ..names import SECUREPOINT, SECUREPOINT_TEXT, clean, unique
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, normalize, parse_literal, size, subtract
from ..options import Options
from ..report import Report, Severity

GROUP = "fwshift"
_PROTOCOL_NAMES = {47: "gre", 50: "esp", 51: "ah", 2: "igmp", 4: "ipip", 89: "ospf", 112: "vrrp", 115: "l2tp", 103: "pim", 41: "ipv6",
                   108: "ipcomp"}  # fmt: skip
# Names a UTM comes with (its network objects, services and groups as Securepoint's documentation shows them): an object
# written must not take one of them.
RESERVED = {"any", "internet", "internal-network", "internal-interface", "external-interface", "dmz1-network", "dmz1-interface",
            "default-internet", "http", "https", "ssh", "ftp", "smtp", "smtps", "submission", "imap", "imap-ssl", "pop3", "pop3s",
            "domain-udp", "domain-tcp", "ntp-udp", "ntp-tcp", "ms-rdp", "icmp-echo-req", "securepoint-admin", "webcache",
            "openvpn-tcp", "openvpn-udp"}  # fmt: skip
_PER_RULE = 64  # more rules of the UTM than this for one rule of the model: not written
Leaf = Tuple[str, str]  # (preferred name, address in CIDR notation); a name alone ("", name) for an object the UTM has
Parts = List[Tuple[str, List[ServiceEntry]]]  # (preferred name, entries) of the services of a rule


def _q(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _cidrs(interval: Interval) -> List[str]:
    version, first, last = interval
    return [str(net) for net in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last))]


def _no_zero(ports: str) -> str:
    """A port or range without port 0, which no connection uses and a service of the UTM is not written with."""
    first, _, last = ports.partition("-")
    if first == "0":
        return "" if not last or last == "0" else f"1-{last}" if last != "1" else "1"
    return ports


def _preferred(member: str, cidr: str) -> str:
    """The name to give the network object of a member: its own, or for a literal net-<address>."""
    return f"net-{cidr}".replace("/", "_") if parse_literal(member) is not None else member


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    planner = _Emitter(p, Report(), options)
    written = {nat.origin for nat in p.nat_rules if nat.destination_translation is not None and planner.nat_plan(nat)[0] is None}
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    out = _Emitter(p, report, options)
    out.source_zones = source_zones
    return out.run()


@dataclass
class _NatPlan:
    flags: List[str]
    sources: List[Leaf]
    destinations: List[Leaf]
    src_zones: List[str]
    dst_zones: List[str]
    service: Parts
    any_service: bool
    nat_node: Optional[Tuple[str, str, str]] = None  # (preferred name, address, zone)
    nat_service: Optional[Parts] = None
    nat_any_service: bool = False
    findings: List[Tuple[Severity, str, str]] = field(default_factory=list)


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.source_zones: Set[str] = set()
        keep = {a.name for a in p.addresses.values() if a.builtin == "securepoint"} if p.vendor == "securepoint" else set()
        self.keep = keep
        self.taint_a = transform.tainted_addresses(p, keep=keep)
        self.taint_s = transform.tainted_services(p)
        self.prefix = options.object_prefix
        self.taken: Set[str] = set(RESERVED)
        self.objects: List[str] = []
        self.rules: List[str] = []
        self.nodes: Dict[Tuple[str, str], str] = {}
        self.preferred: Set[str] = set()
        self.node_groups: Dict[Tuple[str, ...], str] = {}
        self.services: Dict[Tuple[str, str, str], str] = {}
        self.service_groups: Dict[Tuple[str, ...], str] = {}
        self.renamed: List[str] = []
        self.interface_objects: List[str] = []
        self.zones_written: List[str] = []
        self.commented = 0
        used = [z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        self.zones = transform.target_zones(p, options.zone_map, used, list(options.zone_networks))

    # -- names and objects ----------------------------------------------------------------------------------------

    def _name(self, preferred: str) -> str:
        base = clean(self.prefix + preferred, SECUREPOINT)
        name = unique(base, self.taken, SECUREPOINT)
        if name != base and base.lower() in RESERVED:
            self.renamed.append(f"{base} -> {name}")
        return name

    def _zone_used(self, zone: str) -> None:
        if zone not in self.zones_written:
            self.zones_written.append(zone)

    def node(self, preferred: str, value: str, zone: str) -> str:
        key = (value, zone)
        if key not in self.nodes:
            if preferred in ("any-v4", "any-v6"):
                preferred = f"{preferred}-{zone}"
            name = self._name(preferred if preferred not in self.preferred else f"{preferred}-{zone}")
            self.preferred.add(preferred)
            self.nodes[key] = name
            self.objects.append(f"node new name {_q(name)} address {_q(value)} zone {_q(zone)}")
            self._zone_used(zone)
        return self.nodes[key]

    def side_object(self, leaves: List[Leaf], zone: str, preferred: str) -> str:
        """The object a side of a rule names in one zone: one network object, or a group of them."""
        names: List[str] = []
        for pref, value in leaves:
            names.append(value if not pref else self.node(pref, value, zone))
        names = list(dict.fromkeys(names))
        if len(names) == 1:
            return names[0]
        key = (zone,) + tuple(sorted(names))
        if key not in self.node_groups:
            name = self._name(preferred if preferred not in self.preferred else f"{preferred}-{zone}")
            self.preferred.add(preferred)
            self.node_groups[key] = name
            self.objects.append(f"node group new name {_q(name)} nodes [ {' '.join(_q(n) for n in names)} ]")
        return self.node_groups[key]

    def service_object(self, parts: Parts, any_service: bool, preferred: str) -> str:
        if any_service:
            return "any"
        names: List[str] = []
        for part, entries in parts:
            words_list = self._service_words(entries)
            for proto, words, key in words_list:
                if key not in self.services:
                    name = self._name(part if len(words_list) == 1 else f"{part}-{proto}-{key[1] or key[2]}")
                    self.services[key] = name
                    self.objects.append(f"service new name {_q(name)} proto {_q(proto)} {words}")
                names.append(self.services[key])
        names = list(dict.fromkeys(names))
        if len(names) == 1:
            return names[0]
        group_key = tuple(sorted(names))
        if group_key not in self.service_groups:
            name = self._name(preferred)
            self.service_groups[group_key] = name
            self.objects.append(f"service group new name {_q(name)} services [ {' '.join(_q(n) for n in names)} ]")
        return self.service_groups[group_key]

    @staticmethod
    def _service_words(entries: List[ServiceEntry]) -> List[Tuple[str, str, Tuple[str, str, str]]]:
        """(protocol, the rest of 'service new', a key) for each service of the UTM the entries need."""
        out: List[Tuple[str, str, Tuple[str, str, str]]] = []
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                dsts = [p for p in (_no_zero(x) for x in entry.dst_ports.split(",")) if p] if entry.dst_ports else ["1-65535"]
                srcs = [p for p in (_no_zero(x) for x in entry.src_ports.split(",")) if p] if entry.src_ports else [""]
                for dst in dsts:
                    for src in srcs:
                        words = f"dst-ports [ {_q(dst)} ] src-ports [ {_q(src) + ' ' if src else ''}]"
                        out.append((entry.protocol.value, words, (entry.protocol.value, dst, src)))
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                proto = "icmp" if entry.protocol == Protocol.ICMP else "icmpv6"
                kind = "any" if entry.icmp_type is None else str(entry.icmp_type)
                out.append((proto, f"icmp-types [ {_q(kind)} ]", (proto, kind, "")))
            else:
                assert entry.ip_protocol is not None
                proto = _PROTOCOL_NAMES[entry.ip_protocol]
                out.append((proto, "", (proto, "", "")))
        return list(dict.fromkeys(out))

    # -- what a rule can say ----------------------------------------------------------------------------------------

    def leaves(self, members: List[str], negated: bool, reasons: List[transform.Reason], what: str) -> Optional[List[Leaf]]:
        """The network objects a side needs, before zones; None when it matches no address."""
        if negated:
            intervals: List[Interval] = []
            for member in members:
                if member == ANY:
                    return None
                if self._fqdns(member):
                    reasons.append(("SECUREPOINT_FQDN", f"the {what} holds a host name and is negated; the UTM has no negation, and "
                                    "the addresses left cannot be worked out"))  # fmt: skip
                    return []
                intervals += transform.address_intervals(self.p, member) or []
            left = subtract([FULL_V4], normalize([i for i in intervals if i[0] == 4])) + subtract([FULL_V6], normalize([i for i in intervals if i[0] == 6]))
            return [(f"not-{c}", c) for interval in left for c in _cidrs(interval)] if left else None
        out: List[Leaf] = []
        for member in members:
            out += self._member_leaves(member, reasons, what, 0)
        return out

    def _fqdns(self, member: str, depth: int = 0) -> List[str]:
        if member in self.p.addresses:
            return [member] if self.p.addresses[member].kind == AddressKind.FQDN else []
        if member in self.p.address_groups and depth < 64:
            return [n for inner in self.p.address_groups[member].members for n in self._fqdns(inner, depth + 1)]
        return []

    def _member_leaves(self, member: str, reasons: List[transform.Reason], what: str, depth: int) -> List[Leaf]:
        if member == ANY:
            return [("any-v4", "0.0.0.0/0"), ("any-v6", "::/0")]
        if member in self.keep:
            return [("", member)]
        if member in self.p.addresses:
            address = self.p.addresses[member]
            if address.kind == AddressKind.FQDN:
                reasons.append(("SECUREPOINT_FQDN", f"the {what} holds host name '{address.value[:40]}'; that a network object of the "
                                "UTM takes a host name is not documented"))  # fmt: skip
                return []
            intervals = transform.address_intervals(self.p, member) or []
            cidrs = [c for interval in intervals for c in _cidrs(interval)]
            if len(cidrs) == 1:
                return [(member, cidrs[0])]
            return [(f"{member}-{n}", c) for n, c in enumerate(cidrs, 1)]
        if member in self.p.address_groups and depth < 64:
            return [leaf for inner in self.p.address_groups[member].members for leaf in self._member_leaves(inner, reasons, what, depth + 1)]
        interval = parse_literal(member)
        if interval is not None:
            return [(_preferred(member, c), c) for c in _cidrs(interval)]
        reasons.append(("SECUREPOINT_UNREAD_MEMBER", f"the {what} '{member[:40]}' cannot be written"))
        return []

    def _service_leaves(self, name: str, depth: int = 0) -> List[str]:
        if name in self.p.service_groups and depth < 64:
            return [leaf for inner in self.p.service_groups[name].members for leaf in self._service_leaves(inner, depth + 1)]
        return [name]

    def entries(self, rule: Rule, reasons: List[transform.Reason]) -> Tuple[Parts, bool]:
        """(the services, by the names to give them, whether the rule is for every service)."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        parts: Parts = []
        if lowered is not None:
            parts = [(app, found) for app, found in lowered]
        elif rule.services == [ANY]:
            return [], True
        else:
            for service in rule.services:
                for leaf in dict.fromkeys(self._service_leaves(service)):
                    parts.append((leaf, transform.flatten_services(self.p, leaf) or []))
        if rule.negate_service:
            reasons.append(("SECUREPOINT_NEGATED_SERVICE", "a negated service: a rule of the UTM cannot negate its service"))
            return [], False
        return self._parts_ok(parts, reasons)

    def _parts_ok(self, parts: Parts, reasons: List[transform.Reason]) -> Tuple[Parts, bool]:
        out: Parts = []
        for name, entries in parts:
            good, every = self._entries_ok(entries, reasons)
            if every:
                return [], True
            if good:
                out.append((name, good))
        return out, False

    @staticmethod
    def _entries_ok(entries: List[ServiceEntry], reasons: List[transform.Reason]) -> Tuple[List[ServiceEntry], bool]:
        out: List[ServiceEntry] = []
        for entry in entries:
            if entry.protocol == Protocol.IP and entry.ip_protocol is None:
                return [], True
            if entry.protocol in (Protocol.ICMP, Protocol.ICMP6) and entry.icmp_code == 0 and entry.icmp_type in (0, 8, 128, 129):
                entry = ServiceEntry(entry.protocol, icmp_type=entry.icmp_type)  # (echo request and reply have code 0 only)
            if entry.protocol in (Protocol.ICMP, Protocol.ICMP6) and entry.icmp_code is not None:
                reasons.append(("SECUREPOINT_ICMP_CODE", f"ICMP type {entry.icmp_type} code {entry.icmp_code}: a service of the UTM "
                                "names ICMP types, not codes"))  # fmt: skip
                continue
            if entry.protocol == Protocol.IP and entry.ip_protocol in (6, 17):
                out.append(ServiceEntry(Protocol.TCP if entry.ip_protocol == 6 else Protocol.UDP))
            elif entry.protocol == Protocol.IP and entry.ip_protocol in (1, 58):
                out.append(ServiceEntry(Protocol.ICMP if entry.ip_protocol == 1 else Protocol.ICMP6))
            elif entry.protocol == Protocol.SCTP:
                reasons.append(("SECUREPOINT_PROTOCOL", "SCTP: that a service of the UTM takes it is not documented"))
            elif entry.protocol == Protocol.IP and entry.ip_protocol not in _PROTOCOL_NAMES:
                reasons.append(("SECUREPOINT_PROTOCOL", f"IP protocol {entry.ip_protocol}: a service of the UTM is written with "
                                "protocols FWShift knows the names of (" + ", ".join(sorted(_PROTOCOL_NAMES.values())) + ")"))  # fmt: skip
            else:
                out.append(entry)
        return out, False

    def zones_of(self, zones: List[str]) -> List[str]:
        return list(self.zones) if ANY in zones else list(zones)

    # -- rules ----------------------------------------------------------------------------------------------------

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            reasons.append(("RULE_TYPE", f"{rule.scope.value} rule with 'any' zone: written for the zones the policy knows"))
            pairs = []
        shape: List[transform.Reason] = []
        src = self.leaves(rule.sources, rule.negate_source, shape, "source")
        dst = self.leaves(rule.destinations, rule.negate_destination, shape, "destination")
        entries, any_service = self.entries(rule, shape)
        reasons += shape
        if not shape and (src is None or dst is None or (not entries and not any_service)):
            self.report.skip("rule", rule.origin, "MATCHES_NOTHING", "nothing in this rule can match a packet", Severity.INFO)
            return
        combos: List[Tuple[str, str]] = []
        for src_zones, dst_zones in pairs:
            for sz in self.zones_of(src_zones):
                for dz in self.zones_of(dst_zones):
                    if (sz, dz) not in combos and not (rule.scope.value == "interzone" and sz == dz):
                        combos.append((sz, dz))
        if pairs and not combos:
            reasons.append(("SECUREPOINT_NO_ZONES", "the policy names no zone, and a network object of the UTM needs one: give the "
                            "rules zones, or map them with --zone-map"))  # fmt: skip
        if any(ANY in a or ANY in b for a, b in pairs) and self.zones:
            deny = rule.action != Action.ALLOW
            self.report.add("rule", rule.origin, Severity.REVIEW if deny else Severity.APPROX, "SECUREPOINT_ZONE_ANY",
                            "a side of 'any' zone is written for the zones the policy knows (" + ", ".join(self.zones[:8])
                            + "); traffic of other zones of the UTM is not matched" + (", and this blocking rule does not block it"
                                                                                       if deny else ""))  # fmt: skip
        if len(combos) > _PER_RULE:
            reasons.append(("SECUREPOINT_TOO_MANY", f"the rule would be {len(combos)} rules of the UTM (one per pair of zones); "
                            f"more than {_PER_RULE} are not written"))  # fmt: skip
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
            self.rules.append(f"# not written: {clean(rule.name, SECUREPOINT_TEXT)} (" + "; ".join(m for _, m in reasons)[:300]
                              .replace("\n", " ") + ")")  # fmt: skip
            self.commented += 1
            item.emitted_as.append("a comment line")
            return
        assert src is not None and dst is not None
        flags = [self._verdict(rule)] + (["LOG_ALL"] if rule.log_start or rule.log_end else [])
        single = len(rule.services) == 1 and rule.services[0] not in (ANY, APP_DEFAULT) and rule.applications == [ANY]
        service = self.service_object(entries, any_service, rule.services[0] if single else rule.name)
        comment = clean(rule.name, SECUREPOINT_TEXT)
        lines: List[str] = []
        for sz, dz in combos:
            source = self.side_object(src, sz, self._group_name(rule.sources, rule.negate_source, f"{rule.name}-src", sz))
            destination = self.side_object(dst, dz, self._group_name(rule.destinations, rule.negate_destination, f"{rule.name}-dst", dz))
            lines.append(f"rule new group {_q(GROUP)} src {_q(source)} dst {_q(destination)} service {_q(service)} comment {_q(comment)} "
                         f"flags [ {' '.join(_q(f) for f in flags)} ]")  # fmt: skip
        if not rule.enabled:
            lines = ["# " + line for line in lines]
            self.commented += 1
            self.report.add("rule", rule.origin, Severity.INFO, "SECUREPOINT_DISABLED",
                            "disabled in the source: written as comment lines, which are not loaded")  # fmt: skip
        self.rules += lines
        item.emitted_as.append(f"{len(lines)} rule{'s' if len(lines) != 1 else ''} of group {GROUP}")

    @staticmethod
    def _group_name(members: List[str], negated: bool, fallback: str, zone: str) -> str:
        if members == [ANY] and not negated:
            return f"any-{zone}"
        if len(members) == 1 and not negated and parse_literal(members[0]) is None:
            return members[0]
        return fallback

    def _verdict(self, rule: Rule) -> str:
        if rule.action == Action.ALLOW:
            return "ACCEPT"
        if rule.action in (Action.DROP, Action.DENY):
            return "DROP"
        self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                        f"action {rule.action.value} becomes REJECT, which answers the sender with an ICMP message, not a TCP reset")  # fmt: skip
        return "REJECT"

    def _defaults(self) -> None:
        """After the converted rules: what the policy lets through when no rule decides (the UTM drops it)."""
        if not self.zones:
            if self.p.default_interzone == Action.ALLOW or self.p.default_intrazone == Action.ALLOW:
                self.report.note(Severity.REVIEW, "SECUREPOINT_NO_ZONES",
                                 "the source lets through what no rule matches, and names no zones: no rule for it is written, and "
                                 "the UTM drops that traffic")  # fmt: skip
            return
        between = self.p.default_interzone == Action.ALLOW
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.zones, self.report)
        anything = [("any-v4", "0.0.0.0/0"), ("any-v6", "::/0")]
        written = 0
        for a in self.zones:
            for b in self.zones:
                if (decided[a] if a == b else between):
                    source = self.side_object(anything, a, f"any-{a}")
                    destination = self.side_object(anything, b, f"any-{b}")
                    self.rules.append(f"rule new group {_q(GROUP)} src {_q(source)} dst {_q(destination)} service {_q('any')} "
                                      f"comment {_q('fwshift-default')} flags [ {_q('ACCEPT')} ]")  # fmt: skip
                    written += 1
        if written:
            self.report.note(Severity.INFO, "SECUREPOINT_DEFAULT_WRITTEN",
                             f"the source lets through traffic no rule matches; {written} rules after the converted ones do the same "
                             "between the zones of the policy (the UTM drops it otherwise)")  # fmt: skip

    # -- NAT ------------------------------------------------------------------------------------------------------

    def _post_zone(self, target: str) -> List[str]:
        """The zones a translated destination lies in: by the networks of the zones, else by the rules that name it."""
        wanted = transform.address_intervals(self.p, target) or []
        if not wanted:
            return []
        networks: Dict[str, List[str]] = {}
        for zone, nets in self.p.zone_networks.items():
            networks.setdefault(self.options.zone_map.get(zone, zone), []).extend(nets)
        for zone, nets in self.options.zone_networks.items():
            networks[zone] = list(nets)
        found: List[Tuple[int, str]] = []
        for zone, nets in networks.items():
            for net in nets:
                interval = parse_literal(net)
                if interval is not None and interval[0] == wanted[0][0] and interval[1] <= wanted[0][1] and wanted[0][2] <= interval[2]:
                    found.append((size(interval), zone))
        best = [zone for count, zone in found if count == min(c for c, _ in found)] if found else []
        if best:
            return list(dict.fromkeys(best))
        zones: List[str] = []
        for rule in self.p.rules:
            if not rule.enabled or rule.action != Action.ALLOW or ANY in rule.dst_zones or rule.negate_destination:
                continue
            for member in rule.destinations:
                if member == ANY:
                    continue
                if any(i[0] == wanted[0][0] and i[1] <= wanted[0][1] and wanted[0][2] <= i[2] and size(i) <= size(wanted[0]) * 256
                       for i in transform.address_intervals(self.p, member) or []):  # fmt: skip
                    zones += rule.dst_zones
                    break
        return list(dict.fromkeys(zones))

    def _one_host(self, member: str) -> Optional[str]:
        intervals = transform.address_intervals(self.p, member) or []
        if len(intervals) != 1 or size(intervals[0]) != 1 or self._fqdns(member):
            return None
        return _cidrs(intervals[0])[0]

    def nat_plan(self, nat: NatRule) -> Tuple[Optional[Tuple[str, str]], Optional[_NatPlan]]:
        """What a NAT rule becomes, or why it is not written. No side effects."""
        problems = list(nat.unsupported)
        members = nat.sources + nat.destinations
        snat, dnat = nat.source_translation, nat.destination_translation
        members += (snat.addresses if snat else []) + ([dnat.address] if dnat else [])
        problems += [f"references '{m}': {self.taint_a[m]}" for m in members if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        if problems:
            return ("NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems)), None
        reasons: List[transform.Reason] = []
        sources = self.leaves(nat.sources, False, reasons, "source") or []
        destinations = self.leaves(nat.destinations, False, reasons, "destination") or []
        service, any_service = (([], True) if nat.service == ANY
                                else self._parts_ok([(leaf, transform.flatten_services(self.p, leaf) or []) for leaf in self._service_leaves(nat.service)], reasons))  # fmt: skip
        if reasons:
            return ("SECUREPOINT_NAT_FORM", "; ".join(m for _, m in reasons)), None
        if not self.zones:
            return ("SECUREPOINT_NAT_FORM", "the policy names no zone, and a network object of the UTM needs one"), None
        plan = _NatPlan([], sources, destinations, self.zones_of(nat.src_zones), self.zones_of(nat.dst_zones), service, any_service)
        if snat is None and dnat is None:
            plan.flags = ["DROP", "HIDENAT_EXCLUDE"]
            return None, plan
        if snat is not None and dnat is None and not snat.bidirectional:
            if snat.kind == SnatKind.INTERFACE and not snat.addresses:
                plan.flags = ["DROP", "HIDENAT"]
                return None, plan
            if snat.kind in (SnatKind.DYNAMIC_PORT, SnatKind.DYNAMIC) and len(snat.addresses) == 1:
                host = self._one_host(snat.addresses[0])
                if host is None:
                    return ("SECUREPOINT_NAT_FORM", "HIDENAT hides behind one address; the translated address is not one"), None
                plan.flags = ["DROP", "HIDENAT"]
                plan.nat_node = (_preferred(snat.addresses[0], host), host, "")
                if snat.kind == SnatKind.DYNAMIC:
                    plan.findings.append((Severity.APPROX, "SECUREPOINT_HIDENAT_PORTS", "HIDENAT translates the ports as well; the "
                                          "source kept them"))  # fmt: skip
                return None, plan
            return ("SECUREPOINT_NAT_FORM", "HIDENAT hides behind the address of an interface or of one network object; this "
                    "source translation is none of them"), None  # fmt: skip
        if dnat is not None and snat is None and not dnat.spread:
            target = self._one_host(dnat.address)
            if target is None:
                return ("SECUREPOINT_NAT_FORM", "DESTNAT takes traffic to one address; the translated address is not one"), None
            if len(nat.destinations) != 1 or self._one_host(nat.destinations[0]) is None:
                return ("SECUREPOINT_NAT_FORM", "DESTNAT names one address the traffic is sent to (its NAT network object)"), None
            if ANY in nat.dst_zones or len(nat.dst_zones) != 1:
                return ("SECUREPOINT_NAT_FORM", "DESTNAT needs the one zone the traffic is sent to (the zone of its NAT network object, "
                        "firewall-<zone>); the NAT rule names " + ("none" if ANY in nat.dst_zones else "several")), None  # fmt: skip
            post = self._post_zone(dnat.address)
            if not post:
                return ("SECUREPOINT_NAT_FORM", f"the zone of the translated address {dnat.address[:40]} is not known: give the networks "
                        "of the zones with --zone-network"), None  # fmt: skip
            translated = service
            if dnat.port:
                flat = [e for _, found in service for e in found]
                protocols = {e.protocol for e in flat}
                if any_service or not flat or not protocols <= {Protocol.TCP, Protocol.UDP} or not dnat.port.isdigit():
                    return ("SECUREPOINT_NAT_FORM", "a port translation of a service that is not TCP or UDP ports"), None
                translated = [(f"{nat.name}-port", [ServiceEntry(e.protocol, dnat.port, e.src_ports) for e in flat])]
            plan.flags = ["DROP", "DESTNAT"]
            plan.destinations = [(dnat.address, target)]
            plan.dst_zones = post
            plan.nat_node = ((_preferred(nat.destinations[0], destinations[0][1]), destinations[0][1], "firewall-" + nat.dst_zones[0])
                             if len(destinations) == 1 else None)  # fmt: skip
            if plan.nat_node is None:
                return ("SECUREPOINT_NAT_FORM", "DESTNAT names one address the traffic is sent to"), None
            plan.nat_service, plan.nat_any_service = service, any_service
            plan.service, plan.any_service = translated, any_service
            return None, plan
        return ("SECUREPOINT_NAT_FORM", "the UTM writes HIDENAT, HIDENAT_EXCLUDE and DESTNAT on a rule; a rule that translates "
                "source and destination, a static translation both ways or a pool is none of them"), None  # fmt: skip

    def _nat(self, nat: NatRule) -> None:
        problem, plan = self.nat_plan(nat)
        if problem is not None or plan is None:
            assert problem is not None
            self.report.skip("nat", nat.origin, *problem)
            return
        if not nat.enabled:
            self.report.skip("nat", nat.origin, "NAT_DISABLED", "disabled in the source; not written", Severity.INFO)
            return
        for severity, code, message in plan.findings:
            self.report.add("nat", nat.origin, severity, code, message)
        service = self.service_object(plan.service, plan.any_service, nat.name + "-service")
        tail = ""
        if plan.nat_service is not None:
            tail += f" nat_service {_q(self.service_object(plan.nat_service, plan.nat_any_service, nat.name + '-original'))}"
        lines: List[str] = []
        for sz in plan.src_zones:
            for dz in plan.dst_zones:
                nat_node = ""
                if "HIDENAT" in plan.flags:
                    if plan.nat_node is None:
                        nat_node = f"{dz}-interface"
                        if nat_node not in self.interface_objects:
                            self.interface_objects.append(nat_node)
                    else:
                        nat_node = self.node(plan.nat_node[0], plan.nat_node[1], "firewall-" + dz)
                elif plan.nat_node is not None:
                    nat_node = self.node(plan.nat_node[0], plan.nat_node[1], plan.nat_node[2])
                source = self.side_object(plan.sources, sz, self._group_name(nat.sources, False, f"{nat.name}-src", sz))
                destination = self.side_object(plan.destinations, dz, f"{nat.name}-dst" if "DESTNAT" in plan.flags else self._group_name(nat.destinations, False, f"{nat.name}-dst", dz))
                line = (f"rule new group {_q(GROUP)} src {_q(source)} dst {_q(destination)} service {_q(service)} "
                        f"comment {_q(clean(nat.name, SECUREPOINT_TEXT))} flags [ {' '.join(_q(f) for f in plan.flags)} ]")  # fmt: skip
                if nat_node:
                    line += f" nat_node {_q(nat_node)}"
                lines.append(line + tail)
        self.rules += lines
        self.report.item("nat", nat.origin).emitted_as.append(f"{len(lines)} rule{'s' if len(lines) != 1 else ''} with {plan.flags[1]}")

    # -- output ---------------------------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        nat_start = len(self.rules)
        for nat in self.p.nat_rules:
            self._nat(nat)
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction")
        self._notes(len(self.rules) > nat_start)
        header = ["# Securepoint UTM: commands of its CLI (spcli), written by FWShift. They add network objects, services and the",
                  f"# rule group '{GROUP}' with its rules, and delete nothing. Lines that start with '#' are not commands: leave them",
                  "# out when loading (grep -v '^#'). Nothing applies until 'system update rule', nothing is kept over a restart until",
                  "# 'system config save': run both yourself after reading the report (section 10 of the manual)."]  # fmt: skip
        return "\n".join(header + self.objects + [f"rule group new name {_q(GROUP)}"] + self.rules) + "\n"

    def _notes(self, nat_written: bool) -> None:
        self.report.note(Severity.REVIEW, "SECUREPOINT_LOAD",
                         f"the output is commands of the UTM's CLI (section 10): network objects, services and the rule group '{GROUP}' "
                         "with its rules, nothing deleted. A new rule group comes after the groups the UTM has, whose rules decide "
                         "first: move it in the web interface (Firewall > Packet filter) where it belongs. Apply with 'system update "
                         "rule' and keep with 'system config save' after checking")  # fmt: skip
        zones = [z for z in self.zones_written]
        if zones:
            self.report.note(Severity.REVIEW, "ZONES_REQUIRED",
                             "the network objects name these zones, which must exist on the UTM (Network > Zones, each bound to its "
                             "interface; the output creates none): " + ", ".join(zones) + ". Map other names with --zone-map")  # fmt: skip
        if self.interface_objects:
            self.report.note(Severity.REVIEW, "SECUREPOINT_INTERFACE_OBJECTS",
                             "HIDENAT behind the outgoing interface names the network object of that interface, written as "
                             "'<zone>-interface' (as the UTM names external-interface); these must exist on the UTM: "
                             + ", ".join(self.interface_objects))  # fmt: skip
        if nat_written:
            self.report.note(Severity.REVIEW, "SECUREPOINT_NAT_RULES",
                             "NAT rules are written as rules with the action DROP after all others, each carrying its HIDENAT, "
                             "HIDENAT_EXCLUDE or DESTNAT: the rules above have decided all traffic, and the NAT applies to what the rule "
                             "matches, as netfilter applies NAT independently of the filter verdict. That the UTM writes the NAT of a "
                             "DROP rule this way is not documented: check the NAT after 'system update rule'")  # fmt: skip
        if self.renamed:
            self.report.note(Severity.INFO, "SECUREPOINT_RESERVED_NAME",
                             "objects named like objects the UTM comes with were renamed: " + ", ".join(self.renamed[:12]))
        if self.commented:
            self.report.note(Severity.INFO, "SECUREPOINT_COMMENTED",
                             f"{self.commented} rules are written as comment lines (disabled in the source, or not convertible), which "
                             "are not loaded")  # fmt: skip
