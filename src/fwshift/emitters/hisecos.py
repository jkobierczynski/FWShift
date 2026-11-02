# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Belden/Hirschmann HiSecOS emitter: neutral model -> a CLI script for an EAGLE40, EAGLE20 or EAGLE30 (routed mode).

Design rules:

* The script only adds: rules of the packet filter (``packet-filter l3 addrule``) with new indexes from 1001
  (``--policy-id-start``), their assignments to interfaces (``addif``), and NAT rules with new indexes. It never
  deletes, never changes the default policy, interfaces, routing or management access, and holds no ``commit``: the
  device applies none of it until a person commits (``packet-filter l3 commit``, ``nat dnat commit``, ...), after
  reading what is pending.
* A rule of HiSecOS has one source, one destination, one protocol, and up to 15 ports per side (a range counts two),
  and IPv4 only. A rule of the model becomes one rule per combination; ranges become the networks they are made of; a
  negated destination, or a negated list, the networks that are left. IPv6 parts are not written.
* Every rule written is assigned for ``ingress`` on each interface of its source zones (every interface the policy
  knows, for ``any``) and, where its destination zone is not ``any``, for ``egress`` on each interface of those zones,
  with its index as its priority. With an ingress assignment on every rule, the order is the same whether the device
  keeps one order for all interfaces or one per interface (the MIB does not say), and the assignments of one rule mean
  "arriving on one of these AND leaving by one of those" (HM2-FW-MIB, hm2L3IfmDirection).
* After the converted rules come rules that do what the policy does with traffic no rule matches: inside each zone
  where that differs, then for everything that arrives on the interfaces written. The device's default policy and its
  own rules with lower priorities stay as they are; that is said in the report.
* Destination NAT is done before the filter (netfilter; assumed): rules are written for the translated address, as for
  iptables. Destination NAT (``nat dnat``), masquerading (``nat masq``) and 1:1 NAT (``nat 1to1nat``) are written
  where the model's rule has their form; other NAT rules are not.
* The keywords of the commands are FWShift's reading of the HM2-FW-MIB and HM2-NAT-MIB and of the command list of the
  CLI reference, **not confirmed** by its Format lines or on a device: validate the script on the device first
  (``script validate``), section 10 of the manual.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, ServiceEntry, SnatKind
from ..names import HISECOS_TEXT, clean
from ..netutil import FULL_V4, Interval, int_to_ip, normalize, size, subtract
from ..options import Options
from ..report import Report, Severity

FIRST_INDEX = 1001  # the first rule index of the packet filter, unless --policy-id-start says
MAX_INDEX = 2048  # hm2L3RuleIndex
FIRST_DNAT, MAX_DNAT = 201, 255  # hm2DnatRuleIndex, hm21to1RuleIndex: 1..255
FIRST_MASQ, MAX_MASQ = 101, 128  # hm2MasqRuleIndex: 1..128
_PORT_SLOTS = 15  # ports per field; a range takes two
_PER_RULE = 256  # more rules of HiSecOS than this for one rule of the model: not written
_INTERFACE = re.compile(r"^(\d+/\d+|vlan/\d+)$")
# hm2L3Proto: IP protocol numbers a rule names by name.
_PROTOCOL_NAMES = {2: "igmp", 4: "ipip", 6: "tcp", 17: "udp", 1: "icmp", 50: "esp", 51: "ah"}
Combination = Tuple[str, str, Tuple[str, ...]]  # source, destination, service words


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    emitter = _Emitter(p, Report(), options)
    # The filter sees the translated destination. Rewrite only for translations that are really written.
    written = {nat.origin for nat in p.nat_rules if emitter.nat_plan(nat, 1)[0] is None
               and (nat.destination_translation is not None or transform.bidirectional_pair(p, nat) is not None)}  # fmt: skip
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    out = _Emitter(p, report, options)
    out.source_zones = source_zones
    return out.run()


def _cidrs(interval: Interval) -> List[str]:
    """An IPv4 interval as the networks it is made of: a host as its address, a network in CIDR notation."""
    _, first, last = interval
    return [str(net.network_address) if net.prefixlen == 32 else str(net)
            for net in ipaddress.summarize_address_range(int_to_ip(4, first), int_to_ip(4, last))]  # fmt: skip


def _slots(ports: List[str]) -> int:
    return sum(2 if "-" in port else 1 for port in ports)


def _chunks(ports: List[str]) -> List[List[str]]:
    """Port lists of up to 15 slots each."""
    out: List[List[str]] = [[]]
    for port in ports:
        if _slots(out[-1] + [port]) > _PORT_SLOTS:
            out.append([])
        out[-1].append(port)
    return out


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.source_zones: Set[str] = set()
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        self.first = options.policy_id_start if options.policy_id_start > 0 else FIRST_INDEX
        self.next = self.first
        self.lines: List[str] = []
        self.nat_lines: List[str] = []
        self.guessed: List[str] = []
        self.interface_names: Dict[str, List[str]] = {}
        self.full = False  # the rule indexes ran out
        self.ipv6_left_out: List[str] = []

    # -- interfaces -----------------------------------------------------------------------------------------------

    def interfaces(self, zone: str) -> List[str]:
        """The interfaces of a zone on the device (after --interface-map); the zone's own name where it has none."""
        if zone in self.interface_names:
            return self.interface_names[zone]
        names = [self.options.interface_map.get(i, i) for i in transform.target_interfaces(self.p, self.options.zone_map, zone)]
        if not names:
            names = [self.options.interface_map.get(zone, zone)]
        out: List[str] = []
        for name in transform.dedupe(names):
            written = re.sub(r"[^A-Za-z0-9/._-]", "_", name)[:32] or "unnamed"
            if not _INTERFACE.match(written) and written not in self.guessed:
                self.guessed.append(written)
            out.append(written)
        self.interface_names[zone] = out
        return out

    def all_interfaces(self) -> List[str]:
        used = [z for r in list(self.p.rules) + list(self.p.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY]
        out: List[str] = []
        for zone in transform.target_zones(self.p, self.options.zone_map, used, []):
            out += self.interfaces(zone)
        return transform.dedupe(out)

    # -- addresses and services -------------------------------------------------------------------------------------

    def _intervals(self, members: List[str]) -> Tuple[Optional[List[Interval]], List[str], bool]:
        """(the IPv4 intervals of the members, or None for any; host names; whether IPv6 addresses were left out)."""
        out: List[Interval] = []
        names: List[str] = []
        six = False
        for member in members:
            if member == ANY:
                return None, [], False
            for name in self._fqdns(member):
                names.append(name)
            for interval in transform.address_intervals(self.p, member) or []:
                if interval[0] == 6:
                    six = True
                elif interval == FULL_V4:
                    return None, names, six
                else:
                    out.append(interval)
        return normalize(out), names, six

    def _fqdns(self, member: str, seen: Tuple[str, ...] = ()) -> List[str]:
        if member in self.p.addresses:
            address = self.p.addresses[member]
            return [member] if address.kind == AddressKind.FQDN else []
        if member in self.p.address_groups and member not in seen:
            return [n for inner in self.p.address_groups[member].members for n in self._fqdns(inner, seen + (member,))]
        return []

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[List[str]]:
        """The values a rule of HiSecOS takes for one side ("any", an address, a network, "!" and a network for the
        source); None when the side matches no IPv4 address."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        intervals, names, six = self._intervals(members)
        word = "source" if source else "destination"
        if names:
            reasons.append(("HISECOS_FQDN", f"the {word} holds host names ({', '.join(names[:3])}); a rule of HiSecOS takes "
                            "addresses only"))  # fmt: skip
        if six:
            self.ipv6_left_out.append(rule.origin)
        if intervals is None:
            return None if negated else ["any"]
        if negated:
            left = subtract([FULL_V4], intervals)
            if not left:
                return None
            if not intervals:
                return ["any"]
            if source and len(intervals) == 1 and len(_cidrs(intervals[0])) == 1:
                return ["!" + _cidrs(intervals[0])[0]]
            return [cidr for interval in left for cidr in _cidrs(interval)]
        if not intervals:
            return None
        return [cidr for interval in intervals for cidr in _cidrs(interval)]

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

    def _services(self, rule: Rule, entries: Optional[List[ServiceEntry]], reasons: List[transform.Reason]) -> List[Tuple[str, ...]]:
        """The service words of each rule of HiSecOS (protocol, ports, ICMP type); [] when nothing of IPv4 is left."""
        if entries is None:
            return [("proto", "any")]
        if rule.negate_service:
            reasons.append(("HISECOS_NEGATED_SERVICE", "a negated service: a rule of HiSecOS cannot negate its protocol or ports"))
            return []
        out: List[Tuple[str, ...]] = []
        merged: Dict[Tuple[str, str], List[str]] = {}
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                ports = merged.setdefault((entry.protocol.value, entry.src_ports), [])
                ports += [p for p in (entry.dst_ports.split(",") if entry.dst_ports else [""]) if p not in ports]
            elif entry.protocol == Protocol.SCTP:
                reasons.append(("HISECOS_PROTOCOL", "SCTP: a rule of HiSecOS names tcp, udp, icmp, igmp, ipip, esp, ah or any"))
            elif entry.protocol == Protocol.ICMP or (entry.protocol == Protocol.IP and entry.ip_protocol == 1):
                words: Tuple[str, ...] = ("proto", "icmp")
                if entry.icmp_type is not None:
                    param = f"type={entry.icmp_type}" + (f",code={entry.icmp_code}" if entry.icmp_code is not None else "")
                    words += ("param", param)
                out.append(words)
            elif entry.protocol == Protocol.ICMP6 or (entry.protocol == Protocol.IP and entry.ip_protocol == 58):
                self.ipv6_left_out.append(rule.origin)
            elif entry.protocol == Protocol.IP and entry.ip_protocol is None:
                return [("proto", "any")]
            elif entry.protocol == Protocol.IP and entry.ip_protocol in _PROTOCOL_NAMES:
                assert entry.ip_protocol is not None
                out.append(("proto", _PROTOCOL_NAMES[entry.ip_protocol]))
            else:
                reasons.append(("HISECOS_PROTOCOL", f"IP protocol {entry.ip_protocol}: a rule of HiSecOS names tcp, udp, icmp, igmp, "
                                "ipip, esp, ah or any"))  # fmt: skip
        for (proto, src_ports), ports in merged.items():
            dst_chunks = [[]] if "" in ports else _chunks(ports)
            src_chunks = _chunks(src_ports.split(",")) if src_ports else [[]]
            for dst_chunk in dst_chunks:
                for src_chunk in src_chunks:
                    words = ("proto", proto)
                    words += ("srcport", ",".join(src_chunk)) if src_chunk else ()
                    words += ("dstport", ",".join(dst_chunk)) if dst_chunk else ()
                    out.append(words)
        return list(dict.fromkeys(out))

    # -- security rules ---------------------------------------------------------------------------------------------

    def _index(self) -> Optional[int]:
        if self.next > MAX_INDEX:
            self.full = True
            return None
        index = self.next
        self.next += 1
        return index

    def _verdict(self, rule: Rule) -> str:
        if rule.action == Action.ALLOW:
            return "accept"
        if rule.action == Action.DROP:
            return "drop"
        if rule.action == Action.DENY:
            return "reject"
        self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                        f"action {rule.action.value} becomes reject, which answers the sender with an ICMP message, not a TCP reset")  # fmt: skip
        return "reject"

    def _write(self, words: List[str], description: str, enabled: bool, ingress: List[str], egress: List[str]) -> Optional[int]:
        index = self._index()
        if index is None:
            return None
        self.lines.append(" ".join(["packet-filter l3 addrule", str(index)] + words + ["description", description]))
        self.lines.append(f"packet-filter l3 {'enablerule' if enabled else 'disablerule'} {index}")
        for interface in ingress:
            self.lines.append(f"packet-filter l3 addif {interface} rule {index} direction ingress priority {index}")
        for interface in egress:
            self.lines.append(f"packet-filter l3 addif {interface} rule {index} direction egress priority {index}")
        return index

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        description = clean(rule.name, HISECOS_TEXT)
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            reasons.append(("RULE_TYPE", f"{rule.scope.value} rule with 'any' zone cannot be written as interface assignments"))
            pairs = []
        elif not pairs:
            self.report.skip("rule", rule.origin, "RULE_TYPE_EMPTY",
                             f"{rule.scope.value} rule whose zones leave no pair of different zones: it matches nothing", Severity.INFO)  # fmt: skip
            return
        shape: List[transform.Reason] = []
        src = self._side(rule, True, shape)
        dst = self._side(rule, False, shape)
        services = self._services(rule, self._entries(rule, reasons), shape)
        reasons += shape
        if src is None or dst is None or not services:
            if not shape and not reasons:
                self.report.skip("rule", rule.origin, "MATCHES_NOTHING",
                                 "nothing in this rule can match an IPv4 packet (HiSecOS filters IPv4 only)", Severity.INFO)  # fmt: skip
                return
        combinations: List[Combination] = []
        if not shape and src is not None and dst is not None:
            combinations = [(s, d, w) for s in src for d in dst for w in services]
        if len(combinations) > _PER_RULE:
            reasons.append(("HISECOS_TOO_MANY", f"the rule would be {len(combinations)} rules of HiSecOS (one source, destination "
                            f"and protocol each); more than {_PER_RULE} are not written"))  # fmt: skip
            combinations = []
        assignments: List[Tuple[List[str], List[str]]] = []
        known = self.all_interfaces()
        for src_zones, dst_zones in pairs:
            ingress = known if ANY in src_zones else transform.dedupe([i for z in src_zones for i in self.interfaces(z)])
            egress = [] if ANY in dst_zones else transform.dedupe([i for z in dst_zones for i in self.interfaces(z)])
            if not ingress:
                reasons.append(("HISECOS_NO_INTERFACES", "the policy names no zone, so there is no interface to assign the rule "
                                "to; give the rules zones, or map them with --zone-map"))  # fmt: skip
                break
            assignments.append((ingress, egress))
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        enabled = rule.enabled and not reasons
        verdict = self._verdict(rule)
        log = ["log", "enable" if rule.log_start else "disable", "trap", "disable"]
        if not combinations:
            # Not written as it is: a rule that keeps its place and its name in the rule table, disabled, matching nothing.
            index = self._write(["srcip", "0.0.0.0", "dstip", "0.0.0.0", "proto", "any", "action", verdict] + log, description,
                                False, [], [])  # fmt: skip
            if index is not None:
                item.emitted_as.append(f"rule {index} (a placeholder, disabled)")
            return
        if not assignments:
            assignments = [([], [])]  # (no interface to assign it to: written disabled, assigned to nothing)
        written: List[int] = []
        for ingress, egress in assignments:
            for source, destination, words in combinations:
                fields = ["srcip", source, "dstip", destination] + list(words) + ["action", verdict] + log
                index = self._write(fields, description, enabled, ingress, egress)
                if index is None:
                    break
                written.append(index)
        if self.full:
            self.report.add("rule", rule.origin, Severity.REVIEW, "HISECOS_TOO_MANY_RULES",
                            f"the rule indexes ran out (the packet filter takes rules 1 to {MAX_INDEX}): parts of this rule, and "
                            "the rules after it, are not written")  # fmt: skip
        if written:
            item.emitted_as.append(f"rule {written[0]}" if len(written) == 1 else f"rules {written[0]}-{written[-1]}")
        if not rule.enabled and not reasons:
            self.report.add("rule", rule.origin, Severity.INFO, "HISECOS_DISABLED", "disabled in the source; written with disablerule")

    def _defaults(self) -> None:
        """After the converted rules: what the policy does inside a zone and between zones when no rule decides."""
        used = [z for r in self.p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        zones = transform.target_zones(self.p, self.options.zone_map, used, [])
        if not zones:
            self.report.note(Severity.REVIEW, "HISECOS_NO_ZONES",
                             "the source names no zones: there is no interface to assign the rules to, and they are written "
                             "disabled. Give the rules zones, or map them with --zone-map and --interface-map")  # fmt: skip
            return
        between = self.p.default_interzone == Action.ALLOW
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, zones, self.report)
        verdict = "accept" if between else "drop"
        for zone in zones:
            if decided[zone] != between:
                names = self.interfaces(zone)
                self._write(["srcip", "any", "dstip", "any", "proto", "any", "action", "accept" if decided[zone] else "drop",
                             "log", "disable", "trap", "disable"], clean(f"fwshift-inside-{zone}", HISECOS_TEXT), True, names, names)  # fmt: skip
        last = self._write(["srcip", "any", "dstip", "any", "proto", "any", "action", verdict, "log", "disable", "trap", "disable"],
                           "fwshift-default", True, self.all_interfaces(), [])  # fmt: skip
        if last is None:
            self.report.note(Severity.REVIEW, "HISECOS_TOO_MANY_RULES",
                             "the rule indexes ran out before the rule for the policy's default; it is not written")

    # -- NAT --------------------------------------------------------------------------------------------------------

    def _one(self, members: List[str], what: str) -> Tuple[Optional[str], str]:
        """One IPv4 address or network, or "any", for a field of a NAT rule; (None, why) otherwise."""
        intervals, names, _ = self._intervals(members)
        if names:
            return None, f"the {what} holds a host name"
        if intervals is None:
            return "any", ""
        cidrs = [c for i in intervals for c in _cidrs(i)]
        if len(cidrs) != 1:
            return None, f"the {what} is not one IPv4 address or network"
        return cidrs[0], ""

    def nat_plan(self, nat: NatRule, index: int) -> Tuple[Optional[Tuple[str, str]], List[str], List[Tuple[Severity, str, str]]]:
        """What a NAT rule becomes (lines), or why it cannot be written. No side effects."""
        findings: List[Tuple[Severity, str, str]] = []
        problems = list(nat.unsupported)
        members = nat.sources + nat.destinations
        source, destination = nat.source_translation, nat.destination_translation
        members += (source.addresses if source else []) + ([destination.address] if destination else [])
        problems += [f"references '{m}': {self.taint_a[m]}" for m in members if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        if problems:
            return ("NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems)), [], []
        description = clean(nat.name, HISECOS_TEXT)
        src, why_src = self._one(nat.sources, "source")
        dst, why_dst = self._one(nat.destinations, "destination")
        proto, sports, dports = "any", "", ""
        if nat.service != ANY:
            entries = transform.flatten_services(self.p, nat.service) or []
            protos = {e.protocol for e in entries}
            if len(entries) != 1 or not protos <= {Protocol.TCP, Protocol.UDP}:
                return ("HISECOS_NAT_FORM", f"service '{nat.service}' is not one TCP or UDP entry, which a NAT rule of HiSecOS "
                        "needs"), [], []  # fmt: skip
            proto, sports, dports = entries[0].protocol.value, entries[0].src_ports, entries[0].dst_ports
            if _slots(sports.split(",") if sports else []) > _PORT_SLOTS or _slots(dports.split(",") if dports else []) > _PORT_SLOTS:
                return ("HISECOS_NAT_FORM", "more than 15 ports in a field of a NAT rule"), [], []
        if src is None or dst is None:
            return ("HISECOS_NAT_FORM", why_src or why_dst), [], []
        if destination is not None and source is None:
            mapped = transform.address_intervals(self.p, destination.address)
            if not mapped or len(mapped) != 1 or mapped[0][0] != 4 or size(mapped[0]) != 1:
                return ("HISECOS_NAT_FORM", "destination NAT of HiSecOS translates to one IPv4 address"), [], []
            if destination.port and "," in destination.port + dports:
                return ("HISECOS_NAT_FORM", "a port translation of a list of ports"), [], []
            interfaces = (self.all_interfaces() if ANY in nat.src_zones
                          else transform.dedupe([i for z in nat.src_zones for i in self.interfaces(z)]))  # fmt: skip
            if not interfaces:
                return ("HISECOS_NAT_FORM", "no interface to assign the destination NAT to"), [], []
            if nat.dst_zones != [ANY]:
                findings.append((Severity.APPROX, "HISECOS_NAT_EGRESS", "destination NAT of HiSecOS is assigned to the interface "
                                 "traffic arrives on; the zones it leaves by are not a condition"))  # fmt: skip
            new = str(int_to_ip(4, mapped[0][1]))
            words = ["nat dnat add", str(index), "srcip", src, "srcport", sports or "any", "dstip", dst, "dstport", dports or "any",
                     "proto", proto, "newdstip", new, "newdstport", destination.port or "any", "description", description]  # fmt: skip
            lines = [" ".join(words)]
            lines += [f"nat dnat if add {i} rule {index} direction ingress priority {index}" for i in interfaces]
            return None, lines, findings
        if source is not None and destination is None and source.kind == SnatKind.INTERFACE and not source.addresses:
            if dst != "any" or dports:
                return ("HISECOS_NAT_FORM", "masquerading of HiSecOS matches sources and source ports only, not destinations"), [], []
            if ANY in nat.dst_zones:
                return ("HISECOS_NAT_FORM", "masquerading needs the interface traffic leaves by: the rule names no destination zone"), [], []
            if nat.src_zones != [ANY]:
                findings.append((Severity.APPROX, "HISECOS_NAT_INGRESS", "masquerading of HiSecOS is assigned to the interface "
                                 "traffic leaves by; the zones it comes from are not a condition"))  # fmt: skip
            interfaces = transform.dedupe([i for z in nat.dst_zones for i in self.interfaces(z)])
            words = ["nat masq add", str(index), "srcip", src, "srcport", sports or "any", "proto", proto, "description", description]
            lines = [" ".join(words)]
            lines += [f"nat masq if add {i} rule {index} direction egress priority {index}" for i in interfaces]
            return None, lines, findings
        if source is not None and destination is None and source.kind == SnatKind.STATIC and source.bidirectional:
            pair = transform.bidirectional_pair(self.p, nat)
            if pair is None or nat.service != ANY or dst != "any":
                return ("HISECOS_NAT_FORM", "1:1 NAT of HiSecOS maps one network to another of the same size, for every service "
                        "and destination"), [], []  # fmt: skip
            inside, outside = pair
            inner, outer = _cidrs(inside), _cidrs(outside)
            if len(inner) != 1 or len(outer) != 1 or len(nat.src_zones) != 1 or len(nat.dst_zones) != 1 or ANY in nat.src_zones + nat.dst_zones:
                return ("HISECOS_NAT_FORM", "1:1 NAT of HiSecOS needs one network on each side and the zone of each side"), [], []
            egress, ingress = self.interfaces(nat.src_zones[0]), self.interfaces(nat.dst_zones[0])
            if len(egress) != 1 or len(ingress) != 1:
                return ("HISECOS_NAT_FORM", "1:1 NAT of HiSecOS names one ingress and one egress interface"), [], []
            words = ["nat 1to1nat add", str(index), "dstip", outer[0], "newdstip", inner[0], "ingress-if", ingress[0],
                     "egress-if", egress[0], "priority", str(index), "description", description]  # fmt: skip
            return None, [" ".join(words)], findings
        return ("HISECOS_NAT_FORM", "HiSecOS writes destination NAT to one address, masquerading behind the interface and 1:1 "
                "NAT of networks; this rule is none of them"), [], []  # fmt: skip

    def _nat(self) -> None:
        dnat, masq = FIRST_DNAT, FIRST_MASQ
        for nat in self.p.nat_rules:
            kind_masq = nat.source_translation is not None and nat.source_translation.kind == SnatKind.INTERFACE
            index = masq if kind_masq else dnat
            if index > (MAX_MASQ if kind_masq else MAX_DNAT):
                self.report.skip("nat", nat.origin, "HISECOS_TOO_MANY_RULES", "the NAT rule indexes ran out")
                continue
            problem, lines, findings = self.nat_plan(nat, index)
            if problem is not None:
                self.report.skip("nat", nat.origin, *problem)
                continue
            if kind_masq:
                masq += 1
            else:
                dnat += 1
            for severity, code, message in findings:
                self.report.add("nat", nat.origin, severity, code, message)
            if not nat.enabled:
                self.report.skip("nat", nat.origin, "NAT_DISABLED", "disabled in the source; not written", Severity.INFO)
                continue
            self.nat_lines += lines
            self.report.item("nat", nat.origin).emitted_as.append(" ".join(lines[0].split()[:4]))

    # -- output -----------------------------------------------------------------------------------------------------

    def run(self) -> str:
        self._nat()
        written = {nat.origin for nat in self.p.nat_rules if not self.report.item("nat", nat.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction")
        for rule in self.p.rules:
            if self.full:
                self.report.skip("rule", rule.origin, "HISECOS_TOO_MANY_RULES",
                                 f"the rule indexes ran out (the packet filter takes rules 1 to {MAX_INDEX})")  # fmt: skip
                continue
            self._rule(rule)
        self._defaults()
        self._notes()
        return "\n".join(self.lines + self.nat_lines) + "\n"

    def _notes(self) -> None:
        last = self.next - 1
        self.report.note(Severity.REVIEW, "HISECOS_LOAD",
                         "the output is a CLI script of HiSecOS (section 10): commands of the Global Config mode that add rules "
                         f"{self.first} to {last} of the packet filter (they must be free) with their interface assignments, "
                         "and NAT rules, and that delete nothing. The keywords are FWShift's reading of Belden's MIBs and command "
                         "list, not confirmed on a device: check the script with 'script validate' first. Nothing applies until "
                         "you commit: read 'show packet-filter l3 pending', then 'packet-filter l3 commit' (and 'nat dnat commit', "
                         "'nat masq commit', 'nat 1to1nat commit'). Rules of the device with lower priorities on the same interfaces "
                         "come first, and its default policy is not changed. To take the rules away again: "
                         f"'packet-filter l3 delif' for each assignment, then 'packet-filter l3 delrule N' for N from {self.first} "
                         f"to {last}")  # fmt: skip
        if self.guessed:
            self.report.note(Severity.REVIEW, "INTERFACES_REQUIRED",
                             "zones are written as the routing interfaces of the device (1/1, vlan/10): these names are not "
                             "such interfaces, and the device refuses the assignments that name them. Map the zones with "
                             "--zone-map, or their interfaces with --interface-map: " + ", ".join(self.guessed))  # fmt: skip
        if self.ipv6_left_out:
            names = transform.dedupe(self.ipv6_left_out)
            self.report.note(Severity.INFO, "HISECOS_IPV4_ONLY",
                             "HiSecOS filters IPv4: the IPv6 addresses and ICMPv6 of these rules are not written: "
                             + ", ".join(names[:12]) + (" ..." if len(names) > 12 else ""))  # fmt: skip
        if self.nat_lines:
            self.report.note(Severity.INFO, "HISECOS_NAT_WRITTEN",
                             "destination NAT and 1:1 NAT are done before the packet filter (assumed, as on netfilter): the rules "
                             "were written for the translated address")  # fmt: skip
