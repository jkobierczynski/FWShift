# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""F5 BIG-IP AFM emitter: neutral model -> a file for ``tmsh load sys config merge file``.

Design rules:

* The file holds address lists, port lists, one rule list with the rules of the model in their order, and one policy
  (``--target-policy``, default FWShift) whose single entry is that rule list. It is in the syntax of ``bigip.conf``,
  which ``load sys config merge`` takes and ``verify`` checks without changing anything. It enforces the policy in no
  context, changes no setting of the BIG-IP (``sys db``), and creates no VLAN, virtual server or route.
* The policy decides on its own, wherever it is attached: an allow rule is ``accept-decisively`` (an ``accept`` in the
  global or a route domain context would hand the packet on to the next context, whose rules and default would decide
  again), and the last rule of the list is the model's default. Wherever it is attached, the BIG-IP still lets
  through only traffic that a virtual server takes (a forwarding virtual server for routed traffic).
* Nothing is ever widened silently. A rule whose match cannot be written is written with ``status disabled`` and
  reported.
* A rule of AFM has one IP protocol: a rule of the model with several becomes one rule per protocol (and per set of
  source ports), one after the other, which together match what it matches.
* A zone of the model is a VLAN: the source zones of a rule are its source VLANs. AFM can name the VLAN a packet comes
  in on, not the one it leaves on: the destination zones of a rule are written as the networks behind them
  (``--zone-network``); without them an allow rule is written disabled, and a deny rule blocks in every zone.
* There is no negation in a rule: a negated address list is written as the addresses that are left; a negated service
  disables the rule.
* NAT is not written. On a BIG-IP it is part of the traffic objects (virtual servers with pools, SNAT pools and automap)
  or of CGNAT (``security nat`` policies), not of the firewall policy.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, Policy, Protocol, Rule, RuleScope, ServiceEntry
from ..names import F5AFM, F5AFM_RULE, clean
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, normalize, subtract
from ..options import Options
from ..parsers.f5afm import PROTOCOLS
from ..report import Report, Severity
from .asa import zone_spaces

_PLACEHOLDER: Interval = (4, int(ipaddress.ip_address("192.0.0.8")), int(ipaddress.ip_address("192.0.0.8")))
_VLAN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}){0,2}")
_PROTOCOL_NAMES = {number: name for name, number in reversed(list(PROTOCOLS.items()))}
_PROTOCOL_NAMES[58] = "ipv6-icmp"
_PROTOCOL_NAMES[4] = "ipip"
_MAX_ENTRIES = 10000


def emit(policy: Policy, report: Report, options: Options) -> str:
    zone_spaces(options.zone_networks, options.zone_excluded)  # refuses networks that contradict each other
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    for zone in [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]:
        if not _VLAN.fullmatch(zone):
            raise FwshiftError(f"zone '{zone[:40]}' cannot be the name of a VLAN of a BIG-IP: give it the name of one with --zone-map")
    transform.ensure_references(p, report)
    transform.sanitize_names(p, F5AFM, F5AFM_RULE, report, prefix=options.object_prefix)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


def _q(text: str) -> str:
    """A string in double quotes as tmsh writes it."""
    cleaned = " ".join(re.sub(r"[\x00-\x1f\x7f]", " ", text).split())
    return '"' + cleaned.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _cidrs(intervals: List[Interval]) -> List[str]:
    out: List[str] = []
    for version, first, last in normalize(intervals):
        for net in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)):
            out.append(str(net.network_address) if net.num_addresses == 1 else str(net))
    return out


def vlan_path(zone: str) -> str:
    """The VLAN a zone of the model stands for: in /Common unless the name holds its partition."""
    return "/" + zone if "/" in zone else "/Common/" + zone


@dataclass
class _Piece:
    """One rule of AFM: one protocol (or every protocol), its ports or ICMP types."""

    protocol: Optional[int] = None
    port_lists: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    source_ports: List[str] = field(default_factory=list)
    icmp: List[str] = field(default_factory=list)


@dataclass
class _Side:
    lists: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.native = p.vendor == "f5-afm"
        self.prefix = options.object_prefix
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s: Dict[str, str] = {}
        self.spaces = zone_spaces(options.zone_networks, options.zone_excluded)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.target_zones(p, options.zone_map, used, list(options.zone_networks))
        self.source_zones = transform.rule_zones(p)
        self.objects: List[str] = []
        self.port_lists: Dict[str, str] = {}  # service -> its port list
        self.single: Dict[str, Tuple[int, str]] = {}  # service -> (protocol, port list), for a service of one protocol
        self.rules: List[str] = []
        self.rule_names: Set[str] = set()
        self.object_names: Set[str] = set(p.addresses) | set(p.address_groups) | set(p.services) | set(p.service_groups)
        self.vlans: Set[str] = set()
        self.fqdn = False
        self.icmp = False
        name = clean(options.target_policy or "FWShift", F5AFM)
        self.policy_name = name
        self.list_name = clean(f"{name}_rules", F5AFM)
        self._origin = ""

    def run(self) -> str:
        self._addresses()
        self._services()
        for rule in self.p.rules:
            self._rule(rule)
        self._intrazone()
        self._default()
        for nat in self.p.nat_rules:
            self.report.skip("nat", nat.origin, "F5AFM_NAT_NOT_CONVERTED",
                             "not converted: NAT on a BIG-IP is done by the traffic objects (a virtual server with a pool, SNAT "
                             "automap or a SNAT pool) or by CGNAT (a security nat policy), not by the firewall policy. Set it up "
                             "there by hand")  # fmt: skip
        self._notes()
        return self._text()

    # -- output ---------------------------------------------------------------------------------------------------------

    def _text(self) -> str:
        policy, rules = f"/Common/{self.policy_name}", f"/Common/{self.list_name}"
        out = [
            "# Generated by FWShift: a network firewall policy for BIG-IP AFM. Read the report first: what is written",
            "# disabled or not converted is listed there. Copy the file to the BIG-IP, then:",
            "#",
            "#   tmsh load sys config merge file /var/tmp/THIS_FILE verify     checks it, changes nothing",
            "#   tmsh load sys config merge file /var/tmp/THIS_FILE            creates the objects and the policy",
            "#",
            f"# It creates address lists, port lists, the rule list {rules} and the policy {policy}, and",
            "# enforces the policy nowhere. Objects of the same name are changed by the merge: check that none exists.",
            "# Attach the policy to a context yourself, for example:",
            f"#   tmsh modify security firewall global-rules enforced-policy {policy}",
            f"#   tmsh modify net route-domain /Common/0 fw-enforced-policy {policy}",
            f"#   tmsh modify ltm virtual /Common/VS fw-enforced-policy {policy}",
            "# The BIG-IP lets through only traffic that a virtual server takes.",
        ]
        out += self.objects
        out.append(f"security firewall rule-list {rules} {{")
        out.append("    rules {")
        out += self.rules
        out.append("    }")
        out.append("}")
        out += [f"security firewall policy {policy} {{", "    rules {", f"        {self.list_name} {{",
                f"            rule-list {rules}", "        }", "    }", "}"]  # fmt: skip
        return "\n".join(out) + "\n"

    def _list(self, name: str, addresses: List[str], lists: List[str], fqdns: List[str], description: str) -> None:
        out = [f"security firewall address-list /Common/{name} {{"]
        if addresses:
            out.append("    addresses {")
            out += [f"        {a} {{ }}" for a in addresses]
            out.append("    }")
        if lists:
            out.append("    address-lists {")
            out += [f"        /Common/{member}" for member in lists]
            out.append("    }")
        if fqdns:
            out.append("    fqdns {")
            out += [f"        {f} {{ }}" for f in fqdns]
            out.append("    }")
        if description:
            out.append(f"    description {_q(description[:255])}")
        out.append("}")
        self.objects += out

    # -- objects --------------------------------------------------------------------------------------------------------

    def _addresses(self) -> None:
        for name, address in self.p.addresses.items():
            reason = self.taint_a.get(name, "")
            if not reason and address.kind == AddressKind.FQDN:
                self._list(name, [], [], [address.value.lower()], address.description)
                self.fqdn = True
                continue
            interval = None if reason else transform.address_intervals(self.p, name)
            if not interval:
                reason = reason or "an address that cannot be written"
                self.taint_a[name] = reason
                self._list(name, _cidrs([_PLACEHOLDER]), [], [], f"FWSHIFT PLACEHOLDER, matches nothing: {reason}")
                continue
            self._list(name, _cidrs(interval), [], [], address.description)
        for group in transform.topo_groups(self.p.address_groups):
            reason = self.taint_a.get(group.name, "")
            if reason or transform.is_placeholder_group(group):
                reason = reason or "an empty or dynamic group"
                self.taint_a[group.name] = reason
                self._list(group.name, _cidrs([_PLACEHOLDER]), [], [], f"FWSHIFT PLACEHOLDER, matches nothing: {reason}")
                continue
            literals: List[Interval] = []
            lists: List[str] = []
            for member in group.members:
                if member in self.p.addresses or member in self.p.address_groups:
                    lists.append(member)
                else:
                    found = transform.address_intervals(self.p, member)
                    literals += found or []
            self._list(group.name, _cidrs(literals), transform.dedupe(lists), [], group.description)
        self.taint_a = {**transform.tainted_addresses(self.p, keep=set(self.taint_a)), **self.taint_a}

    def _services(self) -> None:
        bad: Dict[str, str] = {}
        for name, service in self.p.services.items():
            if service.unsupported:
                bad[name] = service.unsupported
                continue
            entries = service.entries
            if not entries:
                bad[name] = "a service without content"
                continue
            problem = self._entries_problem(entries)
            if problem:
                bad[name] = problem
                self.report.add("service", name, Severity.REVIEW, "UNSUPPORTED_SERVICE",
                                f"{problem}: not written, and the rules that use it are written disabled")  # fmt: skip
                continue
            protocols = {e.protocol for e in entries}
            if len(protocols) == 1 and entries[0].protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP) and all(
                    e.dst_ports and not e.src_ports for e in entries):  # fmt: skip
                ports = _merge_ports(",".join(e.dst_ports for e in entries))
                out = [f"security firewall port-list /Common/{name} {{", "    ports {"]
                out += [f"        {port} {{ }}" for port in ports]
                out.append("    }")
                if service.description:
                    out.append(f"    description {_q(service.description[:255])}")
                out.append("}")
                self.objects += out
                self.single[name] = ({Protocol.TCP: 6, Protocol.UDP: 17, Protocol.SCTP: 132}[entries[0].protocol], name)
        for group in self.p.service_groups.values():
            flat = transform.flatten_services(self.p, group.name)
            if not flat:
                bad.setdefault(group.name, "a service group without content")
        self.taint_s = transform.tainted_services(self.p, bad)

    @staticmethod
    def _entries_problem(entries: List[ServiceEntry]) -> str:
        for entry in entries:
            if entry.protocol in (Protocol.ICMP, Protocol.ICMP6) and entry.icmp_type is None and entry.icmp_code is not None:
                return "an ICMP code without a type"
            if entry.src_ports and entry.protocol not in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
                return "source ports of a protocol without ports"
        return ""

    # -- rules ----------------------------------------------------------------------------------------------------------

    def _pieces(self, rule: Rule, reasons: List[transform.Reason]) -> List[_Piece]:
        """The rules of AFM one rule of the model needs for its services."""
        if any(s in self.taint_s for s in rule.services):
            return [_Piece()]  # written disabled, for the reason the service gives
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        named: List[str] = []
        if lowered is None:
            if ANY in rule.services:
                return [_Piece()]
            entries: List[ServiceEntry] = []
            for service in rule.services:
                if service in self.single:
                    named.append(service)
                else:
                    entries += transform.flatten_services(self.p, service) or []
        else:
            entries = [e for _, found in lowered for e in found]
            if not entries:
                return [_Piece()]
        if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
            return [_Piece()]
        # per protocol and source ports: every port, or the ports and port lists
        groups: Dict[Tuple[int, str], Tuple[List[bool], List[str], List[str]]] = {}
        for service in named:
            protocol, port_list = self.single[service]
            groups.setdefault((protocol, ""), ([False], [], []))[2].append(f"/Common/{port_list}")
        icmp: Dict[int, Optional[List[str]]] = {}
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
                protocol = {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.SCTP: 132}[entry.protocol]
                every, ranges, _ = groups.setdefault((protocol, entry.src_ports), ([False], [], []))
                if entry.dst_ports:
                    ranges.append(entry.dst_ports)
                else:
                    every[0] = True
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
                protocol = 1 if entry.protocol == Protocol.ICMP else 58
                self.icmp = True
                if entry.icmp_type is None:
                    icmp[protocol] = None
                elif icmp.setdefault(protocol, []) is not None:
                    text = str(entry.icmp_type) + ("" if entry.icmp_code is None else f":{entry.icmp_code}")
                    found = icmp[protocol]
                    assert found is not None
                    if text not in found:
                        found.append(text)
            else:
                assert entry.ip_protocol is not None
                groups.setdefault((entry.ip_protocol, ""), ([True], [], []))
        out: List[_Piece] = []
        for (protocol, source_ports), (every, ranges, lists) in groups.items():
            if every[0]:
                out.append(_Piece(protocol, source_ports=_merge_ports(source_ports)))
            else:
                out.append(_Piece(protocol, transform.dedupe(lists), _merge_ports(",".join(ranges)), _merge_ports(source_ports)))
        for protocol, types in icmp.items():
            out.append(_Piece(protocol, icmp=types or []))
        return out

    def _addresses_of(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[List[Interval]]:
        """Every address of a side, or None when it holds a host name."""
        found: List[Interval] = []
        for member in members:
            if member == ANY:
                found += [FULL_V4, FULL_V6]
                continue
            intervals = transform.address_intervals(self.p, member) if member not in self.taint_a else [_PLACEHOLDER]
            if intervals is None:
                return None
            found += intervals
        if negated:
            found = subtract([FULL_V4, FULL_V6], found)
            if members != [ANY]:
                self.report.add("rule", self._origin, Severity.INFO, "NEGATION_EXPANDED",
                                f"a rule of AFM has no negation: 'not {side} {', '.join(members)}' is written as the addresses that "
                                "are left")  # fmt: skip
        return normalize(found)

    def _side(self, members: List[str], negated: bool, side: str, reasons: List[transform.Reason]) -> Optional[_Side]:
        """The addresses of one side as AFM names them; None for every address."""
        if members == [ANY] and not negated:
            return None
        if not negated:
            out = _Side()
            for member in members:
                if member in self.p.addresses or member in self.p.address_groups:
                    out.lists.append(f"/Common/{member}")
                elif member == ANY:
                    return None
                else:
                    out.addresses += _cidrs(transform.address_intervals(self.p, member) or [_PLACEHOLDER])
            return out
        found = self._addresses_of(members, negated, side, reasons)
        if found is None:
            reasons.append(("UNCONVERTIBLE_OBJECT", f"the negated {side} holds a host name, which has no addresses to leave out"))
            return _Side(addresses=_cidrs([_PLACEHOLDER]))
        if not found:
            return _Side(addresses=_cidrs([_PLACEHOLDER]))  # matches nothing; see _rule
        return _Side(addresses=_cidrs(found))

    def _confine(self, rule: Rule, zones: List[str], side: Optional[_Side], reasons: List[transform.Reason]) -> Optional[_Side]:
        """The destination of a rule kept to its destination zones, as the networks behind them."""
        if ANY in zones or rule.egress_implied:
            return side
        allow = rule.action == Action.ALLOW
        members = rule.destinations
        found = self._addresses_of(members, rule.negate_destination, "destination", [])
        missing = [zone for zone in zones if zone not in self.spaces]
        if allow:
            if missing:
                reasons.append(("ZONE_NETWORK_MISSING",
                                f"the destination of the rule is in zone {', '.join(zones)}, and a rule of AFM cannot name the VLAN "
                                f"a packet leaves on: give the networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
                return side
            if found is None:
                reasons.append(("ZONE_NETWORK_MISSING", f"the destination of the rule in zone {', '.join(zones)} holds a host name, "
                                "which cannot be kept to the networks of the zone"))  # fmt: skip
                return side
            space = normalize([i for zone in zones for i in self.spaces[zone]])
            kept = intersect(found, space)
            if kept != normalize(found):
                placed = normalize([i for space_of in self.spaces.values() for i in space_of])
                nowhere = subtract(subtract(found, kept), placed)
                self.report.add("rule", rule.origin, Severity.APPROX if nowhere else Severity.INFO, "ZONE_BY_NETWORKS",
                                f"the destination in zone {', '.join(zones)} is written as the addresses of the networks given for "
                                "it with --zone-network" + (", without the addresses that lie in none of the networks given"
                                                            if nowhere else ""))  # fmt: skip
                return _Side(addresses=_cidrs(kept) or _cidrs([_PLACEHOLDER]))
            return side
        others = [zone for zone in self.universe if zone not in zones]
        if not others or any(zone not in self.spaces for zone in others) or found is None:
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                            f"the rule blocks traffic to zone {', '.join(zones)}; a rule of AFM cannot name the VLAN a packet "
                            "leaves on, and it blocks that traffic to every zone. Give the networks behind every zone with "
                            "--zone-network to keep it to its zones")  # fmt: skip
            return side
        away = normalize([i for zone in others for i in self.spaces[zone]])
        kept = subtract(found, away)
        if kept != normalize(found):
            self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                            f"the destination in zone {', '.join(zones)} is written without the networks given for the other zones "
                            "with --zone-network")  # fmt: skip
            return _Side(addresses=_cidrs(kept) or _cidrs([_PLACEHOLDER]))
        return side

    def _rule(self, rule: Rule) -> None:
        self._origin = rule.origin
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        transform.note_fqdn_families(self.p, rule, self.report, "AFM")
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "a negated service cannot be written: a rule of AFM has no negation"))
        pairs = transform.zone_pairs(rule)
        if pairs is None:
            reasons.append(("RULE_TYPE", f"{rule.scope.value} rule for every zone: a rule of AFM cannot compare the VLANs a packet "
                            "comes in and leaves on"))  # fmt: skip
            pairs = [(rule.src_zones, rule.dst_zones)]
        elif rule.scope != RuleScope.UNIVERSAL:
            self.report.add("rule", rule.origin, Severity.INFO, "RULE_TYPE",
                            f"{rule.scope.value} rule: written for each pair of its zones")  # fmt: skip
        pieces = self._pieces(rule, reasons)
        source = self._side(rule.sources, rule.negate_source, "source", reasons)
        plain_destination = self._side(rule.destinations, rule.negate_destination, "destination", reasons)
        written: List[Tuple[List[str], Optional[_Side], _Piece]] = []
        for src_zones, dst_zones in pairs:
            destination = self._confine(rule, dst_zones, plain_destination, reasons)
            for piece in pieces:
                written.append((src_zones, destination, piece))
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "RESET_ACTION",
                            f"action {rule.action.value} becomes reject, which answers the client only")  # fmt: skip
        if rule.log_start and not rule.log_end:
            self.report.add("rule", rule.origin, Severity.INFO, "F5AFM_LOG", "AFM logs a rule's matches, not the start or end of a "
                            "session: the rule is written with log yes")  # fmt: skip
        reasons = list(dict.fromkeys(reasons))
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        if len(written) > 1:
            self.report.add("rule", rule.origin, Severity.INFO, "RULE_SPLIT",
                            f"a rule of AFM has one IP protocol and one set of source VLANs: written as {len(written)} rules")  # fmt: skip
        action = {Action.ALLOW: "accept-decisively", Action.DROP: "drop", Action.DENY: "drop"}.get(rule.action, "reject")
        description = " ".join(rule.description.split())
        if reasons:
            description = f"FWSHIFT disabled, see the report. {description}".strip()
        for index, (src_zones, destination, piece) in enumerate(written):
            name = self._rule_name(rule.name if index == 0 else f"{rule.name}_{index + 1}")
            vlans = [vlan_path(z) for z in src_zones if z != ANY]
            self.vlans.update(z for z in src_zones if z != ANY)
            self.rules += self._rule_text(name, action, piece, source, destination, vlans, description,
                                          enabled=rule.enabled and not reasons, log=rule.log_end or rule.log_start)  # fmt: skip
            item.emitted_as.append(name)

    def _rule_name(self, label: str) -> str:
        base = clean(label, F5AFM_RULE)
        name, counter = base, 2
        while name in self.rule_names:
            tail = f"_{counter}"
            name = base[: F5AFM_RULE.max_len - len(tail)] + tail
            counter += 1
        self.rule_names.add(name)
        return name

    def _rule_text(self, name: str, action: str, piece: _Piece, source: Optional[_Side], destination: Optional[_Side],
                   vlans: List[str], description: str, enabled: bool, log: bool) -> List[str]:  # fmt: skip
        out = [f"        {name} {{", f"            action {action}"]
        if description:
            out.append(f"            description {_q(description[:255])}")
        if piece.icmp:
            out.append("            icmp {")
            out += [f"                {text} {{ }}" for text in piece.icmp]
            out.append("            }")
        if piece.protocol is not None:
            out.append(f"            ip-protocol {_PROTOCOL_NAMES.get(piece.protocol, str(piece.protocol))}")
        if log:
            out.append("            log yes")
        src = self._side_text(source, vlans, piece.source_ports, [])
        if src:
            out += ["            source {"] + src + ["            }"]
        dst = self._side_text(destination, [], piece.ports, piece.port_lists)
        if dst:
            out += ["            destination {"] + dst + ["            }"]
        if not enabled:
            out.append("            status disabled")
        out.append("        }")
        return out

    @staticmethod
    def _side_text(side: Optional[_Side], vlans: List[str], ports: List[str], port_lists: List[str]) -> List[str]:
        out: List[str] = []
        indent = " " * 16
        if side is not None and side.lists:
            out += [indent + "address-lists {"] + [indent + "    " + member for member in transform.dedupe(side.lists)] + [indent + "}"]
        if side is not None and side.addresses:
            if len(side.addresses) > _MAX_ENTRIES:
                raise FwshiftError(f"a rule would need more than {_MAX_ENTRIES} addresses")
            out += [indent + "addresses {"] + [indent + f"    {a} {{ }}" for a in transform.dedupe(side.addresses)] + [indent + "}"]
        if port_lists:
            out += [indent + "port-lists {"] + [indent + "    " + member for member in port_lists] + [indent + "}"]
        if ports:
            out += [indent + "ports {"] + [indent + f"    {port} {{ }}" for port in ports] + [indent + "}"]
        if vlans:
            out += [indent + "vlans {"] + [indent + "    " + vlan for vlan in transform.dedupe(vlans)] + [indent + "}"]
        return out

    # -- inside a zone, and the default ---------------------------------------------------------------------------------

    def _intrazone(self) -> None:
        """What no rule matches inside a zone, where the source decides it otherwise than between zones: a rule from the
        VLAN of each such zone to its networks, after the rules of the model and before its default."""
        inter = self.p.default_interzone == Action.ALLOW
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.universe, self.report)
        written: List[str] = []
        blocked: List[str] = []
        opened: List[str] = []
        for zone in self.universe:
            allow = decided[zone]
            if allow == inter:
                continue
            if zone not in self.spaces:
                (blocked if allow else opened).append(zone)
                continue
            name = self._rule_name(f"fwshift_intrazone_{zone}")
            self.rules += self._rule_text(name, "accept-decisively" if allow else "drop", _Piece(),
                                          None, _Side(addresses=_cidrs(self.spaces[zone])), [vlan_path(zone)],
                                          "FWSHIFT: traffic inside the zone that no rule matches", True, False)  # fmt: skip
            self.vlans.add(zone)
            written.append(zone)
        if written:
            self.report.note(Severity.INFO, "INTRAZONE_WRITTEN",
                             "the source decides traffic inside a zone that no rule matches otherwise than between zones; a rule of AFM "
                             "cannot name the VLAN a packet leaves on, so that was written as rules from the VLAN of each zone to its "
                             "networks (--zone-network), after the rules of the policy: " + ", ".join(written))  # fmt: skip
        if blocked:
            self.report.note(Severity.REVIEW, "INTRAZONE_DEFAULT",
                             "the source allows traffic inside these zones that no rule matches, and blocks it between zones; without "
                             "their networks (--zone-network) the converted policy blocks it: " + ", ".join(blocked))  # fmt: skip
        if opened:
            self.report.note(Severity.REVIEW, "INTRAZONE_DENY_NOT_WRITTEN",
                             "the source blocks traffic inside these zones that no rule matches, and allows it between zones; without "
                             "their networks (--zone-network) the converted policy ALLOWS it: give their networks, or a rule that "
                             "blocks it: " + ", ".join(opened))  # fmt: skip

    def _default(self) -> None:
        action = self.p.default_interzone
        word = {Action.ALLOW: "accept-decisively", Action.DROP: "drop", Action.DENY: "drop"}.get(action, "reject")
        name = self._rule_name("fwshift_default")
        self.rules += self._rule_text(name, word, _Piece(), None, None, [], "FWSHIFT: what no rule of the policy matches",
                                      True, False)  # fmt: skip
        if action == Action.ALLOW:
            self.report.note(Severity.INFO, "F5AFM_DEFAULT_ALLOW",
                             f"the source allows what no rule matches: the last rule of the list, {name}, accepts it decisively")  # fmt: skip

    def _notes(self) -> None:
        self.report.note(
            Severity.REVIEW, "F5AFM_LOAD",
            f"the output is a file for 'tmsh load sys config merge file' (section 10): address lists, port lists, the rule list "
            f"/Common/{self.list_name} and the policy /Common/{self.policy_name}. Load it with 'verify' first. The merge changes "
            "objects of the same name that exist: check that none does. The policy is enforced in no context: attach it to the "
            "global context, a route domain or a virtual server yourself. Allow rules are accept-decisively and the list ends with "
            "the default, so the policy decides alone wherever it is attached; the BIG-IP still lets through only traffic that a "
            "virtual server takes, which FWShift does not create",
        )  # fmt: skip
        if self.icmp:
            self.report.note(Severity.INFO, "F5AFM_ICMP_CONTEXT",
                             "the policy has ICMP rules: the BIG-IP ignores ICMP rules in the virtual server and self IP contexts, so "
                             "attach the policy to the global or a route domain context for them to apply")  # fmt: skip
        if self.fqdn:
            self.report.note(Severity.REVIEW, "F5AFM_FQDN_RESOLVER",
                             "address lists hold host names (fqdns): AFM resolves them only with a DNS resolver set as the global FQDN "
                             "resolver (security firewall global-fqdn-policy); without one they match nothing")  # fmt: skip
        if self.vlans:
            self.report.note(Severity.INFO if self.native else Severity.REVIEW, "F5AFM_VLANS_REQUIRED",
                             "the rules name these VLANs as the zones they come from, which must exist on the BIG-IP under these "
                             "names (--zone-map renames): " + ", ".join(vlan_path(v) for v in sorted(self.vlans)))  # fmt: skip


def _merge_ports(text: str) -> List[str]:
    ranges: List[Tuple[int, int]] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        first, _, last = part.partition("-")
        ranges.append((int(first), int(last or first)))
    out: List[Tuple[int, int]] = []
    for low, high in sorted(ranges):
        if out and low <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], high))
        else:
            out.append((low, high))
    return [str(low) if low == high else f"{low}-{high}" for low, high in out]

