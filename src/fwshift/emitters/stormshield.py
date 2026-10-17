# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Stormshield SNS emitter: neutral model -> a script of serverd commands for an SNS firewall (v4), to run with
``snscli --script``, ``nsrpc`` or the ``cli`` of the console.

Design rules:

* Objects first, with the prefix (``fws_`` or ``--target-prefix``) and ``update=1``: hosts and networks (ranges as
  the networks they are made of), groups, services (a port or a range, TCP or UDP), service groups and protocols.
* The filter rules go to one slot (``--target-policy N`` or ``N:NAME``, slot 9 by default), which the script empties
  first; it is not made the active one. Each rule of the model becomes one or more rules of the slot in its order:
  one per pair of interfaces it names, and one per kind of service (ports of TCP and UDP, each ICMP type, each other
  protocol), since a rule of SNS has one IP protocol. Together they match what the rule of the model matches.
* Filter rules name the addresses as they arrive, before NAT, as the model does.
* The zones of the model are the interfaces of the firewall by their names (``in``, ``out``, ``dmz1``): give them
  with ``--zone-map``. A rule for any zone names no interface.
* What the model allows where no rule matches becomes rules at the end; SNS blocks the rest.
* A rule the target cannot say is written with ``state=off`` and the reason in its comment.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import AbstractSet, Dict, List, Optional, Set, Tuple, Union

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, SnatKind
from ..netutil import Interval, int_to_ip, normalize
from ..options import Options
from ..report import Report, Severity

_DEFAULT_SLOT = 9
_MAX_RULES_PER_RULE = 256
_PROTOCOL_NAMES = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 47: "gre", 50: "vpn-esp", 51: "vpn-ah"}


def _value(text: str) -> str:
    """A value of a serverd command: quoted when it holds blanks; quotes and control characters taken out."""
    clean = "".join(c if c.isprintable() and c not in '"\\' else " " for c in text).strip()
    return f'"{clean}"' if not clean or re.search(r"[\s=<>#]", clean) else clean  # (< and > redirect in a script of snscli)


def _slot(options: Options) -> Tuple[int, str]:
    text = options.target_policy or "FWShift"
    found = re.fullmatch(r"(\d+)(?::(.*))?", text)
    if not found:
        return _DEFAULT_SLOT, text
    number = int(found.group(1))
    if not 1 <= number <= 10:
        raise FwshiftError("--target-policy for Stormshield: a filter slot from 1 to 10, as N or N:NAME")
    return number, (found.group(2) or "FWShift")


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    source_zones = transform.rule_zones(p)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    prefix = options.object_prefix or "fws_"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,15}", prefix) or prefix.lower().startswith(("firewall_", "network_")):
        raise FwshiftError("--target-prefix for Stormshield: up to 16 letters, digits, periods, underscores and hyphens, starting with a letter, "
                           "and not Firewall_ or Network_, which name the firewall's own objects")  # fmt: skip
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options, prefix, source_zones).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options, prefix: str, source_zones: AbstractSet[str] = frozenset()) -> None:
        self.p, self.report, self.options, self.prefix = p, report, options, prefix
        self.source_zones = source_zones  # zone names of the rules before --zone-map
        self.slot, self.slot_name = _slot(options)
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        used += [z for n in p.nat_rules for z in n.src_zones + n.dst_zones if z != ANY]
        self.zones = transform.target_zones(p, options.zone_map, used, [])
        self.names: Set[str] = set()
        self.objects: List[str] = []
        self.groups: List[str] = []
        self.address_objects: Dict[str, str] = {}  # key -> object name
        self.service_objects: Dict[str, str] = {}
        self.filter: List[str] = []
        self.nat: List[str] = []
        self.not_written: List[str] = []
        self.ipv6 = False
        self.renamed: Dict[str, str] = {}
        self.interface_names: Dict[str, str] = {}
        valid = [z for z in self.zones if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", z) and z.lower() != "any"]
        for zone in valid + [z for z in self.zones if z not in valid]:
            self._interface(zone)  # (the names that are valid first, so that they stay as they are)

    def _name(self, label: str) -> str:
        base = (self.prefix + re.sub(r"[^A-Za-z0-9_.-]", "_", label))[:64]
        name, counter = base, 2
        while name.lower() in self.names:
            name = f"{base[:59]}_{counter}"
            counter += 1
        self.names.add(name.lower())
        return name

    def _interface(self, zone: str) -> str:
        """The interface a zone stands for: its name, with what an interface name cannot hold replaced (and any, which
        stands for every interface)."""
        if zone in self.interface_names:
            return self.interface_names[zone]
        name = zone if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", zone) and zone.lower() != "any" else (re.sub(r"[^A-Za-z0-9_.-]", "_", zone)[:60] or "_")
        if name.lower() == "any":
            name = "zone_any"
        base, counter = name, 2
        while name.lower() in {n.lower() for n in self.interface_names.values()}:
            name = f"{base}_{counter}"
            counter += 1
        if name != zone:
            self.renamed[zone] = name
        self.interface_names[zone] = name
        return name

    # -- addresses -----------------------------------------------------------------------------

    @staticmethod
    def _cidrs(intervals: List[Interval]) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        out: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for interval in normalize(intervals):
            first, last = int_to_ip(interval[0], interval[1]), int_to_ip(interval[0], interval[2])
            out += list(ipaddress.summarize_address_range(first, last))
        return out

    def _object_of(self, key: str, label: str, intervals: List[Interval]) -> str:
        """An object for addresses: a host, a network, or a group of them."""
        if key in self.address_objects:
            return self.address_objects[key]
        nets = self._cidrs(intervals)
        lines: List[Tuple[str, str]] = []
        for net in nets:
            name = self._name(f"{label}_{len(lines) + 1}" if len(nets) > 1 else label)
            if net.version == 6:
                self.ipv6 = True
                if net.prefixlen == 128:
                    lines.append((name, f"CONFIG OBJECT HOST NEW name={name} ipv6={net.network_address} resolve=static update=1"))
                else:
                    lines.append((name, f"CONFIG OBJECT NETWORK NEW name={name} ipv6={net.network_address} prefixlenv6={net.prefixlen} update=1"))
            elif net.prefixlen == 32:
                lines.append((name, f"CONFIG OBJECT HOST NEW name={name} ip={net.network_address} resolve=static update=1"))
            else:
                lines.append((name, f"CONFIG OBJECT NETWORK NEW name={name} ip={net.network_address} mask={net.netmask} update=1"))
        self.objects += [line for _, line in lines]
        if len(lines) == 1:
            result = lines[0][0]
        else:
            result = self._name(label)
            self.groups.append(f"CONFIG OBJECT GROUP NEW name={result} update=1")
            self.groups += [f"CONFIG OBJECT GROUP ADDTO group={result} node={name}" for name, _ in lines]
        self.address_objects[key] = result
        return result

    def _side(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Optional[str]:
        """The value of srctarget or dsttarget: any, an object, or ! and an object."""
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        if ANY in members:
            if negated:
                reasons.append(("NEGATED_ANY", "every address but every address"))
                return None
            return "any"
        if self.p.vendor == "stormshield" and any(self._builtin(m) for m in members):
            # The firewall's own objects (Network_internals, Firewall_out ...) by their names, in a group with the others.
            if len(members) == 1:
                return ("!" if negated else "") + members[0]
            nodes: List[str] = []
            for member in members:
                if self._builtin(member):
                    nodes.append(member)
                    continue
                if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                    reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {member}: written with addresses only"))
                    return None
                intervals, known = transform.known_intervals(self.p, member)
                if not known or not intervals:
                    reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows, or nothing"))
                    return None
                nodes.append(self._object_of("|".join(f"{i[0]}-{i[1]}-{i[2]}" for i in normalize(intervals)), member, intervals))
            key = "g:" + ",".join(nodes)
            if key not in self.address_objects:
                group = self._name("-".join(members)[:40])
                self.groups.append(f"CONFIG OBJECT GROUP NEW name={group} update=1")
                self.groups += [f"CONFIG OBJECT GROUP ADDTO group={group} node={node}" for node in transform.dedupe(nodes)]
                self.address_objects[key] = group
            return ("!" if negated else "") + self.address_objects[key]
        found: List[Interval] = []
        for member in members:
            if member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN:
                reasons.append(("FQDN_NOT_SUPPORTED", f"host name object {member}: written with addresses only"))
                return None
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows"))
                return None
            found += intervals
        if not found:
            reasons.append(("NOT_WRITTEN", "addresses that hold nothing"))
            return None
        label = members[0] if len(members) == 1 else "-".join(members)[:40]
        key = "|".join(f"{i[0]}-{i[1]}-{i[2]}" for i in normalize(found))
        name = self._object_of(key, label, found)
        return ("!" if negated else "") + name

    def _builtin(self, name: str) -> bool:
        found = self.p.addresses.get(name) or self.p.address_groups.get(name)
        return found is not None and found.builtin == "stormshield"

    # -- services ------------------------------------------------------------------------------

    def _service_object(self, protocol: str, low: int, high: int) -> str:
        key = f"{protocol}:{low}-{high}"
        if key not in self.service_objects:
            name = self._name(f"{protocol}_{low}" if low == high else f"{protocol}_{low}-{high}")
            line = f"CONFIG OBJECT SERVICE NEW name={name} port={low}" + ("" if low == high else f" toport={high}") + f" proto={protocol} update=1"
            self.objects.append(line)
            self.service_objects[key] = name
        return self.service_objects[key]

    def _protocol_object(self, number: int) -> str:
        if number in _PROTOCOL_NAMES:
            return _PROTOCOL_NAMES[number]
        key = f"proto:{number}"
        if key not in self.service_objects:
            name = self._name(f"proto_{number}")
            self.objects.append(f"CONFIG OBJECT PROTOCOL NEW name={name} protonumber={number} update=1")
            self.service_objects[key] = name
        return self.service_objects[key]

    @staticmethod
    def _ranges(ports: str) -> List[Tuple[int, int]]:
        out = []
        for part in ports.split(","):
            low, _, high = part.partition("-")
            out.append((int(low), int(high or low)))
        return out

    def _pieces(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[str]]:
        """The service tokens of the rules a rule of the model becomes; [""] for any service."""
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "every service but some: the target writes it only for one service"))
            return None
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
        elif rule.services == [ANY]:
            return [""]
        else:
            entries = []
            for name in rule.services:
                flat = transform.flatten_services(self.p, name)
                if flat is None:
                    if name not in self.taint_s:
                        reasons.append(("SERVICE_UNKNOWN", f"service '{name}' cannot be read"))
                    return None
                entries += flat
        if any(e.protocol == Protocol.IP and e.ip_protocol is None for e in entries):
            return [""]
        ports: List[str] = []
        out: List[str] = []
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                every = [(0, 65535)]
                dst = [] if not entry.dst_ports or self._ranges(entry.dst_ports) == every else self._ranges(entry.dst_ports)
                src = [] if not entry.src_ports or self._ranges(entry.src_ports) == every else self._ranges(entry.src_ports)
                if not dst and not src:
                    out.append(f"ipproto={entry.protocol.value}")  # (every port, 0 too)
                    continue
                if not src:
                    ports += [self._service_object(entry.protocol.value, low, high) for low, high in dst]
                    continue
                for low, high in src:
                    source = self._service_object(entry.protocol.value, low, high)
                    out.append(f"ipproto={entry.protocol.value} srcport={source}"
                               + (" dstport=" + ",".join(self._service_object(entry.protocol.value, a, b) for a, b in dst) if dst else ""))
            elif entry.protocol == Protocol.ICMP:
                if entry.icmp_type is None and entry.icmp_code is not None:
                    reasons.append(("SERVICE_NOT_WRITTEN", "an ICMP code without a type"))
                    return None
                piece = "ipproto=icmp"
                if entry.icmp_type is not None:
                    piece += f" icmptype={entry.icmp_type}" + ("" if entry.icmp_code is None else f" icmpcode={entry.icmp_code}")
                out.append(piece)
            elif entry.protocol == Protocol.ICMP6:
                if entry.icmp_type is not None or entry.icmp_code is not None:
                    reasons.append(("SERVICE_NOT_WRITTEN", "an ICMPv6 type: the target writes ICMPv6 as a protocol only"))
                    return None
                out.append(f"ipproto={self._protocol_object(58)}")
            elif entry.protocol == Protocol.SCTP:
                if entry.dst_ports or entry.src_ports:
                    reasons.append(("SERVICE_NOT_WRITTEN", "SCTP with ports"))
                    return None
                out.append(f"ipproto={self._protocol_object(132)}")
            elif entry.ip_protocol == 0:
                reasons.append(("SERVICE_NOT_WRITTEN", "protocol 0, which may be read as every protocol"))
                return None
            else:
                assert entry.ip_protocol is not None
                out.append(f"ipproto={self._protocol_object(entry.ip_protocol)}")
        if ports:
            out.insert(0, "dstport=" + ",".join(transform.dedupe(ports)))
        return transform.dedupe(out)

    # -- rules ---------------------------------------------------------------------------------

    def _pairs(self, rule: Rule) -> List[Tuple[str, str]]:
        """(srcif, dstif) of the rules a rule of the model becomes; "" for any."""
        sources = [z for z in rule.src_zones if z != ANY] if ANY not in rule.src_zones else []
        destinations = [z for z in rule.dst_zones if z != ANY] if ANY not in rule.dst_zones else []
        if rule.scope == RuleScope.INTRAZONE:
            return [(z, z) for z in (sources or self.zones)]
        if rule.scope == RuleScope.INTERZONE:
            pairs = [(s, d) for s in (sources or self.zones) for d in (destinations or self.zones) if s != d]
            if not sources and not destinations and not self.zones:
                return [("", "")]
            return pairs
        return [(s, d) for s in (sources or [""]) for d in (destinations or [""])]

    def _rule(self, rule: Rule) -> None:
        transform.note_profiles(self.report, rule)
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.schedule:
            reasons.append(("SCHEDULE", f"schedule {rule.schedule} is not converted"))
        source = self._side(rule, True, reasons)
        destination = self._side(rule, False, reasons)
        pieces = self._pieces(rule, reasons)
        pairs = self._pairs(rule)
        if not pairs:
            reasons.append(("NOT_WRITTEN", "traffic between zones, and no zone is known"))
        reasons = list(dict.fromkeys(reasons))
        disabled = bool(reasons) or source is None or destination is None or pieces is None
        if pieces is not None and len(pieces) * max(len(pairs), 1) > _MAX_RULES_PER_RULE:
            reasons.append(("NOT_WRITTEN", f"more than {_MAX_RULES_PER_RULE} rules of the target"))
            disabled, pieces = True, None
        if disabled:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "the rule cannot be written")])
            self.not_written.append(f"{rule.name}: " + "; ".join(m for _, m in reasons)[:300])
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "STORMSHIELD_RESET", f"action {rule.action.value}: reset answers the client only")
        action = "pass" if rule.action == Action.ALLOW else "reset" if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH) else "block"
        comment = rule.description or rule.name
        if disabled:
            comment = f"{rule.name}: not converted ({'; '.join(m for _, m in reasons)[:160]})"
        written = 0
        for srcif, dstif in pairs or [("", "")]:
            for piece in pieces or [""]:
                tokens = [f"CONFIG FILTER RULE INSERT type=filter index={self.slot}", "state=" + ("off" if disabled or not rule.enabled else "on"),
                          f"action={action}"]  # fmt: skip
                if rule.log_start:
                    tokens.append("loglevel=log")
                if piece:
                    tokens.append(piece)
                tokens.append(f"srctarget={source or 'any'}")
                if srcif:
                    tokens.append(f"srcif={self._interface(srcif)}")
                tokens.append(f"dsttarget={destination or 'any'}")
                if dstif:
                    tokens.append(f"dstif={self._interface(dstif)}")
                tokens.append(f"comment={_value(comment[:200])}")
                self.filter.append(" ".join(tokens))
                written += 1
        self.report.item("rule", rule.origin).emitted_as.append(f"{written} rules of slot {self.slot}")

    def _defaults(self) -> None:
        inter = self.p.default_interzone == Action.ALLOW
        intra: List[str] = []
        blocked_inside: List[str] = []
        decided = transform.intrazone_decisions(self.p, self.options.zone_map, self.source_zones, self.zones, self.report)
        for zone in self.zones:
            allowed = decided[zone]
            if allowed and not inter:
                intra.append(zone)
            elif inter and not allowed:
                blocked_inside.append(zone)
        for zone in blocked_inside:
            self.filter.append(f"CONFIG FILTER RULE INSERT type=filter index={self.slot} state=on action=block srctarget=any "
                               f"srcif={self._interface(zone)} dsttarget=any dstif={self._interface(zone)} comment={_value('the source blocks inside ' + zone)}")  # fmt: skip
        for zone in intra:
            self.filter.append(f"CONFIG FILTER RULE INSERT type=filter index={self.slot} state=on action=pass srctarget=any "
                               f"srcif={self._interface(zone)} dsttarget=any dstif={self._interface(zone)} comment={_value('the source passes inside ' + zone)}")  # fmt: skip
        if intra or blocked_inside:
            self.report.note(Severity.INFO, "INTRAZONE_RULES_ADDED",
                             "rules for traffic inside a zone (in and out by the same interface) were added at the end, as the source "
                             "decides it when no rule does: " + ", ".join((intra + blocked_inside)[:12]))  # fmt: skip
        if inter:
            self.filter.append(f"CONFIG FILTER RULE INSERT type=filter index={self.slot} state=on action=pass srctarget=any dsttarget=any "
                               f"comment={_value('the source allows what no rule matches')}")  # fmt: skip
            self.report.note(Severity.REVIEW, "STORMSHIELD_DEFAULT_ALLOW",
                             "the source allows what no rule matches: the slot ends in a rule that passes everything")  # fmt: skip

    # -- NAT ------------------------------------------------------------------------------------

    def _nat_side(self, members: List[str]) -> Optional[str]:
        if ANY in members:
            return "any"
        found: List[Interval] = []
        for member in members:
            intervals, known = transform.known_intervals(self.p, member)
            if not known or (member in self.p.addresses and self.p.addresses[member].kind == AddressKind.FQDN):
                return None
            found += intervals
        if not found:
            return None
        key = "|".join(f"{i[0]}-{i[1]}-{i[2]}" for i in normalize(found))
        return self._object_of(key, members[0] if len(members) == 1 else "nat", found)

    def _nat(self, nat: NatRule) -> bool:
        if not nat.enabled or nat.unsupported:
            return False
        sources, destinations = self._nat_side(nat.sources), self._nat_side(nat.destinations)
        if sources is None or destinations is None or len([z for z in nat.src_zones if z != ANY]) > 1 or len([z for z in nat.dst_zones if z != ANY]) > 1:
            return False
        port = ""
        if nat.service != ANY:
            flat = transform.flatten_services(self.p, nat.service)
            if not flat or len(flat) != 1 or flat[0].protocol not in (Protocol.TCP, Protocol.UDP) or flat[0].src_ports or "," in flat[0].dst_ports \
                    or not flat[0].dst_ports:
                return False
            low, high = self._ranges(flat[0].dst_ports)[0]
            port = self._service_object(flat[0].protocol.value, low, high)
        base = [f"CONFIG FILTER RULE INSERT type=nat index={self.slot}", "state=on", "action=nat", f"srctarget={sources}"]
        if nat.src_zones != [ANY]:
            base.append(f"srcif={self._interface(nat.src_zones[0])}")
        base.append(f"dsttarget={destinations}")
        if nat.dst_zones != [ANY]:
            base.append(f"dstif={self._interface(nat.dst_zones[0])}")
        if port:
            base.append(f"dstport={port}")
        tokens: List[str] = []
        snat, dnat = nat.source_translation, nat.destination_translation
        if snat is None and dnat is None:
            return False  # (an exemption: how SNS says it is not published)
        if snat is not None:
            if snat.kind == SnatKind.INTERFACE:
                interface = snat.interface or (nat.dst_zones[0] if nat.dst_zones != [ANY] else "")
                if not interface:
                    return False
                tokens += [f"natsrctarget=Firewall_{self._interface(interface)}", "natsrcport=ephemeral_fw", "natsrcportlb=random"]
            elif snat.kind == SnatKind.DYNAMIC_PORT and snat.addresses:
                pool = self._nat_side(snat.addresses)
                if pool is None:
                    return False
                tokens += [f"natsrctarget={pool}", "natsrcport=ephemeral_fw", "natsrcportlb=random"]
            elif snat.kind == SnatKind.STATIC and snat.addresses and not snat.bidirectional:
                pool = self._nat_side(snat.addresses)
                if pool is None:
                    return False
                tokens += [f"natsrctarget={pool}", "natsrcarp=on"]
            elif snat.kind == SnatKind.STATIC and snat.bidirectional and dnat is None and nat.destinations == [ANY] and nat.service == ANY:
                pair = transform.bidirectional_pair(self.p, nat)
                if pair is None:
                    return False
                inside, outside = pair
                inner = self._object_of(f"{inside}", "inside", [inside])
                outer = self._object_of(f"{outside}", "outside", [outside])
                self.nat.append(" ".join(base + [f"natsrctarget={outer}", "natsrcarp=on", f"comment={_value(nat.name + ' (outbound)')}"]))
                inbound = [f"CONFIG FILTER RULE INSERT type=nat index={self.slot}", "state=on", "action=nat", "srctarget=any", f"dsttarget={outer}",
                           f"natdsttarget={inner}", "natdstarp=on", f"comment={_value(nat.name + ' (inbound)')}"]  # fmt: skip
                self.nat.append(" ".join(inbound))
                return True
            else:
                return False
        if dnat is not None:
            if dnat.spread:
                return False
            target = self._nat_side([dnat.address])
            if target is None:
                return False
            tokens += [f"natdsttarget={target}", "natdstarp=on"]
            if dnat.port:
                if not port or not dnat.port.isdigit():
                    return False
                tokens.append(f"natdstport={self._service_object(self._protocol_of(nat), int(dnat.port), int(dnat.port))}")
        self.nat.append(" ".join(base + tokens + [f"comment={_value(nat.name)}"]))
        return True

    def _protocol_of(self, nat: NatRule) -> str:
        flat = transform.flatten_services(self.p, nat.service) or []
        return flat[0].protocol.value if flat else "tcp"

    # -- output --------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        written = set()
        for nat in self.p.nat_rules:
            if self._nat(nat):
                written.add(nat.origin)
                self.report.item("nat", nat.origin).emitted_as.append(f"rules of the NAT of slot {self.slot}")
            else:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                                 "not converted: the target writes source NAT to an interface, a pool or a static address, a static "
                                 "translation both ways, and destination NAT of one address and port; exemptions are not written")  # fmt: skip
        if self.p.nat_rules:
            transform.note_nat_order(self.p, self.report, written, "first-match")
        self._notes()
        out = [
            "# Generated by FWShift: serverd commands for a Stormshield SNS firewall (v4). Read the report first: what is",
            "# not written is listed there. Run with: snscli --host FIREWALL --user admin --script this-file",
            f"# The script EMPTIES filter slot {self.slot} and writes the policy there; it does not make it the active slot.",
            f"# Check that slot {self.slot} is not the active one. Every object name starts with {self.prefix}; objects of those",
            "# names are changed (update=1), also where an active slot uses them. snscli goes on after a command that fails:",
            f"# read its output, and run CONFIG FILTER CHECK type=filter index={self.slot} before the slot is made active.",
            "MODIFY FORCE ON",
        ]
        out += self.objects + self.groups + ["CONFIG OBJECT ACTIVATE"]
        out += [f"CONFIG FILTER RULE REMOVE type=filter index={self.slot} position=all",
                f"CONFIG FILTER RULE REMOVE type=nat index={self.slot} position=all"]  # fmt: skip
        out += self.filter + self.nat
        out += ["CONFIG FILTER ACTIVATE",
                f"CONFIG SLOT UPDATE type=filter slot={self.slot} name={_value(self.slot_name)} comment={_value('written by FWShift')}",
                f"# CONFIG SLOT ACTIVATE type=filter slot={self.slot}     <- when the slot has been checked"]  # fmt: skip
        if self.not_written:
            out += ["# Written off (state=off):"] + [f"#   {line}" for line in self.not_written]
        return "\n".join("".join(c if c.isprintable() else " " for c in line) for line in out) + "\n"

    def _notes(self) -> None:
        self.report.note(Severity.REVIEW, "STORMSHIELD_LOAD",
                         f"the output is a script of serverd commands (section 10): it creates objects (and changes those of the same "
                         f"names, also where an active slot uses them), empties filter slot {self.slot} and writes the rules there; the "
                         "slot is not made active. snscli goes on after a command that fails: read its output, and check the slot "
                         "with CONFIG FILTER CHECK before it is made active")  # fmt: skip
        if any(line.find(" srcif=") > 0 or line.find(" dstif=") > 0 for line in self.filter + self.nat):
            self.report.note(Severity.REVIEW, "STORMSHIELD_INTERFACES",
                             "rules name interfaces by the zone names of the source: each must be the name of an interface of the "
                             "firewall (in, out, dmz1 ...); rename the zones with --zone-map ZONE=INTERFACE"
                             + ("; written with characters replaced: " + ", ".join(f"{k} as {v}" for k, v in list(self.renamed.items())[:12])
                                if self.renamed else ""))  # fmt: skip
        if self.ipv6:
            self.report.note(Severity.REVIEW, "STORMSHIELD_IPV6",
                             "IPv6 objects are written with ipv6= and prefixlenv6=, the names CONFIG OBJECT LIST answers with; that "
                             "the commands that create objects take them is not documented: check them")  # fmt: skip
        if self.nat:
            self.report.note(Severity.REVIEW, "STORMSHIELD_NAT_ARP",
                             "translated addresses are published by ARP (natsrcarp, natdstarp); leave that out where the address is "
                             "one of the firewall")  # fmt: skip
        if any(r.enabled and (r.log_start or r.log_end) for r in self.p.rules):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their rules have loglevel=log where the source "
                             "logs the start of a connection, and the standard connection log otherwise")  # fmt: skip
