# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco Meraki MX emitter: neutral model -> a shell script that puts the rule tables of one MX network through the
Dashboard API (v1), with curl.

Design rules:

* The outbound table (``l3FirewallRules``) decides traffic from the LAN (its VLANs) to other VLANs and to the internet;
  it names addresses, not zones. The zones inside (``--inside-zone``; from a Meraki source the VLANs) are the LAN; a
  rule for some of them is kept to their networks (``--zone-network``), as the AWS and Azure emitters do. Traffic
  inside one VLAN does not pass the MX and is not written.
* A rule of the MX has one protocol, one range of ports or a list of single ports, and IPv4 and IPv6 together only
  when a side is any: a rule of the model becomes as many rules as that takes, in its place. ICMP types and other
  protocols than TCP, UDP, ICMP and ICMPv6 have no field: such rules are not written.
* The table ends in the fixed default rule of the MX, which allows: where the model blocks what no rule matches, a rule
  that blocks everything is written last.
* From the internet only NAT lets traffic in: destination NAT becomes port forwarding (to the address of an uplink)
  or 1:many NAT, a static translation both ways 1:1 NAT, each with the sources of the rules of the model that allow
  all of it as its allowed remote addresses (kept to their zones outside, and only rules whose destination zones hold
  the translated address). Allowed remote addresses cannot say a rule that blocks: one that blocks some of it first
  ends the list, and a rule that cannot be written is left out, so the MX never lets in more than the model. Source
  NAT to the uplink is what the MX does anyway.
* The script backs up the tables it replaces, writes the bodies to files, and puts them only when ``DRY_RUN`` is not
  set; a table of NAT is put only when the model has rules for it (a put replaces the whole table).
"""

from __future__ import annotations

import copy
import ipaddress
import json
from typing import Dict, List, Optional, Set, Tuple, Union

from .. import transform
from ..errors import FwshiftError
from ..model import ANY, Action, AddressKind, NatRule, Policy, Protocol, Rule, RuleScope, ServiceEntry, SnatKind
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, intersect, normalize, overlaps, parse_literal, subtract
from ..options import Options
from ..report import Report, Severity
from .asa import zone_spaces

_MAX_PIECES = 256
_MAX_CIDRS = 64
Side = Optional[Tuple[Dict[int, List[Interval]], List[str], bool]]  # (addresses per IP version, host names, any)


def _cidrs(intervals: List[Interval]) -> List[str]:
    out: List[str] = []
    for interval in normalize(intervals):
        first, last = int_to_ip(interval[0], interval[1]), int_to_ip(interval[0], interval[2])
        networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = list(ipaddress.summarize_address_range(first, last))
        out += [str(net) for net in networks]
    return out


def emit(policy: Policy, report: Report, options: Options) -> str:
    p = copy.deepcopy(policy)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    if options.written is not None:
        options.written.append(p)
    return _Emitter(p, report, options).run()


class _Emitter:
    def __init__(self, p: Policy, report: Report, options: Options) -> None:
        self.p, self.report, self.options = p, report, options
        self.taint_a = transform.tainted_addresses(p)
        self.taint_s = transform.tainted_services(p)
        given = dict(options.zone_networks)
        if p.vendor == "meraki":
            for zone in p.zones:
                group = p.address_groups.get(f"zone {zone}")
                if zone not in given and group is not None and group.builtin == "meraki":
                    given[zone] = list(group.members)
        self.spaces = zone_spaces(given)
        used = [z for r in p.rules for z in r.src_zones + r.dst_zones if z != ANY]
        self.universe = transform.dedupe(list(p.zones) + used + list(options.zone_networks))
        if options.inside_zones:
            missing = [z for z in options.inside_zones if z not in self.universe]
            if missing:
                raise FwshiftError(f"--inside-zone {missing[0]}: no such zone in the policy")
            self.inside = list(options.inside_zones)
        elif p.vendor == "meraki":
            self.inside = [z for z in self.universe if z != "internet"]
        else:
            self.inside = list(self.universe)
            if self.universe:
                self.report.note(Severity.REVIEW, "MERAKI_INSIDE",
                                 "no --inside-zone: every zone was taken as a LAN of the MX; rules from a zone that is the "
                                 "internet are then written as outbound rules, which the MX never matches for traffic from the "
                                 "internet")  # fmt: skip
        self.outside = [z for z in self.universe if z not in self.inside]
        self.l3: List[Dict[str, object]] = []
        self.one_to_one: List[Dict[str, object]] = []
        self.one_to_many: Dict[str, List[Dict[str, object]]] = {}
        self.not_written: List[str] = []
        self.inbound_used: Set[str] = set()
        self.inbound: List[Rule] = []
        self.forwards: List[Dict[str, object]] = []
        self.uplinks: Dict[Interval, str] = {}  # address of an uplink -> its name (internet1 ...)
        self.inbound_why: Dict[str, str] = {}
        self.why = ""
        for nat in p.nat_rules:
            snat = nat.source_translation
            if snat is None or snat.kind != SnatKind.INTERFACE:
                continue
            for tag in nat.tags:
                name, _, address = tag[len("meraki wan "):].partition(" ") if tag.startswith("meraki wan ") else ("", "", "")
                found = parse_literal(address) if name.startswith("internet") else None
                if found is not None:
                    self.uplinks.setdefault(found, name)
            if snat.interface_address:
                found_all = transform.known_intervals(p, snat.interface_address)[0] if snat.interface_address in p.addresses else []
                for interval in found_all or [i for i in [parse_literal(snat.interface_address)] if i]:
                    self.uplinks.setdefault(interval, "internet1")

    # -- addresses -----------------------------------------------------------------------------------

    def _resolve(self, rule: Rule, source: bool, reasons: List[transform.Reason]) -> Side:
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        side = "source" if source else "destination"
        if ANY in members:
            if negated:
                reasons.append(("NEGATED_ANY", "every address but every address"))
                return None
            return {4: [FULL_V4], 6: [FULL_V6]}, [], True
        found: List[Interval] = []
        names: List[str] = []
        for member in members:
            address = self.p.addresses.get(member)
            if address is not None and address.kind == AddressKind.FQDN:
                if source or negated:
                    reasons.append(("FQDN_NOT_SUPPORTED", f"host name {address.value} as the {side}: the MX takes host names as destinations only"))
                    return None
                names.append(address.value)
                continue
            intervals, known = transform.known_intervals(self.p, member)
            if not known:
                if member not in self.taint_a:
                    reasons.append(("ZONE_DYNAMIC", f"'{member}' holds members only its platform knows"))
                return None
            found += intervals
        found = normalize(found)
        if negated:
            found = subtract([FULL_V4, FULL_V6], found)
        return {4: [i for i in found if i[0] == 4], 6: [i for i in found if i[0] == 6]}, names, False

    def _confine(self, rule: Rule, source: bool, cell: Side, reasons: List[transform.Reason]) -> Side:
        """The addresses of one side kept to the zones of the rule, where those are not all there is."""
        if cell is None:
            return None
        zones = rule.src_zones if source or rule.scope == RuleScope.INTRAZONE else rule.dst_zones
        if source:
            zones = self.inside if ANY in zones else [z for z in zones if z in self.inside]
            whole = set(zones) >= set(self.inside)
        else:
            whole = ANY in zones or set(zones) >= set(self.universe)
        if whole:
            return cell
        addresses, names, _ = cell
        side = "source" if source else "destination"
        missing = [z for z in zones if self._space(z) is None]
        if missing:
            if rule.action == Action.ALLOW:
                reasons.append(("ZONE_NETWORK_MISSING", f"the {side} of the rule is in zone {', '.join(zones)}, and the MX names no zone: give "
                                f"the networks behind {', '.join(missing)} with --zone-network"))  # fmt: skip
                return None
            self.report.add("rule", rule.origin, Severity.APPROX, "ZONE_WIDENED",
                            f"the rule blocks traffic whose {side} is in zone {', '.join(zones)}; the MX names no zone, and it blocks "
                            "that traffic from every zone. Give the networks behind the zones with --zone-network")  # fmt: skip
            return cell
        if names:
            reasons.append(("FQDN_NOT_SUPPORTED", "host names in a rule kept to zones: their addresses are not known"))
            return None
        space = normalize([i for zone in zones for i in self._space(zone) or []])
        kept = {family: intersect(addresses[family], space) for family in (4, 6)}
        self.report.add("rule", rule.origin, Severity.INFO, "ZONE_BY_NETWORKS",
                        f"the {side} in zone {', '.join(zones)} is written as the addresses of the networks given for it")  # fmt: skip
        return kept, [], False

    def _space(self, zone: str) -> Optional[List[Interval]]:
        """The addresses behind a zone: given, or for a zone outside everything the zones inside, and the other zones
        outside that have networks, do not hold (when it is the one zone without networks)."""
        if zone in self.spaces:
            return self.spaces[zone]
        if zone in self.outside and self.inside and all(z in self.spaces for z in self.inside) and \
                [z for z in self.outside if z not in self.spaces] == [zone]:
            taken = [i for z in self.universe if z != zone and z in self.spaces for i in self.spaces[z]]
            return subtract([FULL_V4, FULL_V6], taken)
        return None

    # -- services ---------------------------------------------------------------------------------------

    @staticmethod
    def _port_fields(ports: str) -> Optional[List[str]]:
        """The values of a port field for the ports of an entry: 'Any', one range each, singles together."""
        if not ports:
            return ["Any"]
        singles: List[str] = []
        ranges: List[str] = []
        for part in ports.split(","):
            low, _, high = part.partition("-")
            first, last = int(low), int(high or low)
            if (first, last) == (0, 65535):
                return ["Any"]
            if first == 0:
                return None  # (port 0: the MX takes ports from 1)
            if first == last:
                singles.append(str(first))
            else:
                ranges.append(f"{first}-{last}")
        return ([",".join(singles)] if singles else []) + ranges

    def _services(self, rule: Rule, reasons: List[transform.Reason]) -> Optional[List[Tuple[str, str, str]]]:
        """(protocol, srcPort, destPort) of the rules a rule of the model becomes."""
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "every service but some: the MX has no negation"))
            return None
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
            if not entries:
                return None
        elif rule.services == [ANY]:
            return [("any", "Any", "Any")]
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
            return [("any", "Any", "Any")]
        out: List[Tuple[str, str, str]] = []
        for entry in entries:
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                sources, destinations = self._port_fields(entry.src_ports), self._port_fields(entry.dst_ports)
                if sources is None or destinations is None:
                    reasons.append(("SERVICE_NOT_WRITTEN", "port 0, which the MX does not take"))
                    return None
                out += [(entry.protocol.value, s, d) for s in sources for d in destinations]
            elif entry.protocol in (Protocol.ICMP, Protocol.ICMP6) and entry.icmp_type is None and entry.icmp_code is None:
                out.append(("icmp" if entry.protocol == Protocol.ICMP else "icmp6", "Any", "Any"))
            else:
                reasons.append(("SERVICE_NOT_WRITTEN", "an ICMP type, or a protocol other than TCP, UDP, ICMP and ICMPv6: the MX has "
                                "no field for it"))  # fmt: skip
                return None
        return list(dict.fromkeys(out))

    # -- rules -----------------------------------------------------------------------------------------

    @staticmethod
    def _value(addresses: List[Interval], names: List[str], every: bool) -> Optional[str]:
        if every:
            return "Any"
        cidrs = _cidrs(addresses) + names
        if not cidrs or len(cidrs) > _MAX_CIDRS:
            return None
        return ",".join(cidrs)

    def _rule(self, rule: Rule) -> None:
        if rule.scope == RuleScope.INTRAZONE:
            severity = Severity.INFO if rule.action == Action.ALLOW else Severity.REVIEW
            self.report.skip("rule", rule.origin, "MERAKI_INTRAZONE", "a rule for traffic inside a zone: traffic inside one VLAN does not "
                             "pass the MX, and is not filtered", severity)  # fmt: skip
            return
        if not rule.enabled:
            self.report.skip("rule", rule.origin, "DISABLED_NOT_WRITTEN", "disabled in the source; a rule of the MX cannot be disabled", Severity.INFO)
            return
        src_zones = rule.src_zones
        inside = ANY in src_zones or any(z in self.inside for z in src_zones)
        outside = ANY in src_zones or any(z in self.outside for z in src_zones)
        if outside:
            self.inbound.append(rule)
        if not inside:
            return
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.schedule:
            reasons.append(("SCHEDULE", f"schedule {rule.schedule} is not converted"))
        source = self._confine(rule, True, self._resolve(rule, True, reasons), reasons)
        destination = self._confine(rule, False, self._resolve(rule, False, reasons), reasons)
        services = self._services(rule, reasons)
        pieces: List[Dict[str, object]] = []
        if not reasons and source is not None and destination is not None and services is not None:
            pieces = self._pieces(rule, source, destination, services, reasons)
        if not reasons and source is not None and destination is not None and services is not None and not pieces:
            reasons.append(("NOT_WRITTEN", "no rule of the MX matches what it matches: host names with IPv6 sources only, or ICMPv6 "
                            "with IPv4 addresses only (the MX takes host names for IPv4 only)"))  # fmt: skip
        if reasons or source is None or destination is None or services is None:
            transform.disable_rule(self.report, rule, reasons or [("NOT_WRITTEN", "the rule cannot be written")])
            self.not_written.append(f"{rule.name}: " + "; ".join(m for _, m in reasons)[:300])
            return
        same = [z for z in rule.src_zones if z != ANY and z in rule.dst_zones and z in self.inside]
        if same:
            self.report.add("rule", rule.origin, Severity.INFO if rule.action == Action.ALLOW else Severity.REVIEW, "MERAKI_INTRAZONE",
                            f"traffic inside zone {', '.join(same[:6])} does not pass the MX: there the rule filters nothing")  # fmt: skip
        self.l3 += pieces
        self.report.item("rule", rule.origin).emitted_as.append(f"{len(pieces)} rules of the outbound table")

    def _pieces(self, rule: Rule, source: Side, destination: Side, services: List[Tuple[str, str, str]],
                reasons: List[transform.Reason]) -> List[Dict[str, object]]:  # fmt: skip
        assert source is not None and destination is not None
        src, _, src_any = source
        dst, names, dst_any = destination
        families: List[Tuple[str, str]] = []
        if src_any and dst_any:
            families.append(("Any", "Any"))
        else:
            for family in (4, 6):
                s = self._value(src[family], [], src_any)
                d = self._value(dst[family], names if family == 4 else [], dst_any)
                if (src_any or src[family]) and (dst_any or dst[family] or (names and family == 4)):
                    if s is None or d is None:
                        reasons.append(("NOT_WRITTEN", f"more than {_MAX_CIDRS} networks on a side"))
                        return []
                    families.append((s, d))
            families = list(dict.fromkeys(families))
        out: List[Dict[str, object]] = []
        for s, d in families:
            for protocol, sport, dport in services:
                if protocol == "icmp6" and (s != "Any" and ":" not in s or d != "Any" and ":" not in d):
                    continue
                if protocol == "icmp" and (":" in s or ":" in d):
                    continue
                out.append({"comment": (rule.description or rule.name)[:127], "policy": "allow" if rule.action == Action.ALLOW else "deny",
                            "protocol": protocol, "srcPort": sport, "srcCidr": s, "destPort": dport, "destCidr": d,
                            "syslogEnabled": bool(rule.log_start or rule.log_end)})  # fmt: skip
        if len(out) > _MAX_PIECES:
            reasons.append(("NOT_WRITTEN", f"more than {_MAX_PIECES} rules of the MX"))
            return []
        if rule.action in (Action.RESET_CLIENT, Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add("rule", rule.origin, Severity.INFO, "REJECT_AS_DENY", f"action {rule.action.value}: written as deny")
        return out

    def _defaults(self) -> None:
        every = {"policy": "allow", "protocol": "any", "srcPort": "Any", "srcCidr": "Any", "destPort": "Any", "destCidr": "Any"}
        ended = False
        while self.l3 and all(self.l3[-1].get(k) == v for k, v in every.items()):
            self.l3.pop()  # (what the fixed default rule of the MX does)
            ended = True
        if self.p.default_interzone != Action.ALLOW and not ended:
            self.l3.append({"comment": "the source blocks what no rule matches", "policy": "deny", "protocol": "any", "srcPort": "Any",
                            "srcCidr": "Any", "destPort": "Any", "destCidr": "Any", "syslogEnabled": False})  # fmt: skip
            self.report.note(Severity.INFO, "MERAKI_DEFAULT_DENY", "the source blocks what no rule matches: the outbound table ends in a rule "
                             "that blocks everything, before the fixed default rule of the MX")  # fmt: skip
        blocked = [z for z in self.inside if not (self.p.zones[z].intrazone_allow if z in self.p.zones and self.p.zones[z].intrazone_allow is not None
                                                  else self.p.default_intrazone == Action.ALLOW)]  # fmt: skip
        if blocked:
            self.report.note(Severity.REVIEW, "MERAKI_INTRAZONE_DEFAULT",
                             "the source blocks traffic inside a zone that no rule matches; inside one VLAN the MX passes everything: "
                             + ", ".join(blocked[:12]))  # fmt: skip

    # -- NAT -------------------------------------------------------------------------------------------

    def _skip_inbound(self, rule: Rule, reasons: List[transform.Reason], text: str = "") -> None:
        self.inbound_why.setdefault(rule.origin, ("; ".join(m for _, m in reasons) or text)[:300])

    def _to_zone(self, rule: Rule, inner: Interval) -> Optional[bool]:
        """Whether the destination zones of a rule hold the translated address; None when that is not known."""
        if ANY in rule.dst_zones or set(rule.dst_zones) >= set(self.universe):
            return True
        zones = [z for z in self.inside if any(i[0] == inner[0] and i[1] <= inner[1] <= i[2] for i in self.spaces.get(z, []))]
        if not zones:
            return None
        held = [z in rule.dst_zones for z in zones]
        return True if all(held) else False if not any(held) else None

    def _service_match(self, rule: Rule, entries: Optional[List[ServiceEntry]]) -> Tuple[Optional[bool], bool]:
        """(whether the services of a rule can match those of the NAT rule (None: not known), whether they hold all of them)."""
        if rule.negate_service:
            return None, False  # (every service but some: what it matches of the NAT rule is not worked out)
        if rule.services == [ANY]:
            return True, True
        flat: List[ServiceEntry] = []
        for name in rule.services:
            found = transform.flatten_services(self.p, name)
            if found is None:
                return None, False
            flat += found
        if entries is None:
            return True, True  # (1:1 NAT lets in the services of each rule)
        meets = any(_meets(e, x) for e in flat for x in entries)
        whole = all(_holds(flat, x) for x in entries)
        return meets, whole

    def _from_outside(self, rule: Rule, source: Side, reasons: List[transform.Reason]) -> Optional[List[str]]:
        """The IPv4 sources of a rule from the internet, kept to its zones outside, as allowed remote addresses."""
        assert source is not None
        addresses, _, every = source
        zones = self.outside if ANY in rule.src_zones else [z for z in rule.src_zones if z in self.outside]
        found = list(addresses[4])
        if not set(zones) >= set(self.outside):
            spaces = [self._space(z) for z in zones]
            if any(space is None for space in spaces):
                reasons.append(("ZONE_NETWORK_MISSING", f"the source of the rule is in zone {', '.join(zones)}: give the networks behind it "
                                "with --zone-network"))  # fmt: skip
                return None
            found = intersect(found, normalize([i for space in spaces for i in space or []]))
            every = False
        if every or normalize(found) == [FULL_V4]:
            return ["any"]
        cidrs = _cidrs(found)
        if not cidrs:
            reasons.append(("NOT_WRITTEN", "no IPv4 source"))
            return None
        if len(cidrs) > _MAX_CIDRS:
            reasons.append(("NOT_WRITTEN", f"more than {_MAX_CIDRS} networks as allowed remote addresses"))
            return None
        return cidrs

    def _allowed(self, public: Interval, inner: Interval, entries: Optional[List[ServiceEntry]]) -> Optional[List[Tuple[Rule, List[str]]]]:
        """The rules from the internet that allow traffic to a public address (and all of the service), with their sources
        as allowed remote addresses. A rule that blocks some of it ends the list (None when it is first), as allowed
        remote addresses cannot say what comes after it; a rule that allows some of it and cannot be written is left out."""
        out: List[Tuple[Rule, List[str]]] = []
        for rule in self.inbound:
            deny = rule.action != Action.ALLOW
            reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
            for given, label in ((rule.users, "source users"), (rule.url_categories, "URL categories"), (rule.applications, "applications")):
                if given != [ANY]:
                    reasons.append(("NOT_WRITTEN", f"{label} {', '.join(given)[:80]} are not converted"))
            if rule.negate_service:
                reasons.append(("SERVICE_NEGATE", "every service but some: allowed remote addresses have no negation"))
            cell = self._resolve(rule, False, reasons)
            if cell is None:
                if deny:
                    self.why = f"rule {rule.name[:60]} blocks traffic to addresses that cannot be read"
                    return out or None
                self._skip_inbound(rule, reasons, "its destination cannot be read")
                continue
            if not any(i[1] <= public[1] <= i[2] for i in cell[0][public[0]]):
                if deny and cell[1]:
                    self.why = f"rule {rule.name[:60]} blocks traffic to host names"
                    return out or None
                continue
            to_zone = self._to_zone(rule, inner)
            if to_zone is False:
                continue
            meets, whole = self._service_match(rule, entries)
            if meets is False:
                continue
            if deny:
                self.why = f"rule {rule.name[:60]} blocks some of it first"
                return out or None
            if reasons or meets is None or not whole or to_zone is None:
                self._skip_inbound(rule, reasons, "its services cannot be read" if meets is None else
                                   "it allows some of the ports of the NAT rule only" if not whole else
                                   "the zone of the translated address is not known: give it with --zone-network")  # fmt: skip
                continue
            source = self._resolve(rule, True, reasons)
            sources = self._from_outside(rule, source, reasons) if source is not None and not reasons else None
            if sources is None:
                self._skip_inbound(rule, reasons, "its sources cannot be written")
                continue
            out.append((rule, sources))
        return out

    def _nat(self, nat: NatRule) -> bool:
        if not nat.enabled or nat.unsupported:
            return False
        pair = transform.bidirectional_pair(self.p, nat)
        if pair is not None:
            inside, outside = pair
            if inside[1] != inside[2] or nat.src_zones != [ANY] or nat.dst_zones != [ANY] or nat.destinations != [ANY] or nat.service != ANY:
                return False
            allowed = self._allowed(outside, inside, None)
            if allowed is None:
                return False
            inbound: List[Dict[str, object]] = []
            for rule, sources in allowed:
                entries = [e for name in rule.services for e in (transform.flatten_services(self.p, name) or [])] if rule.services != [ANY] \
                    else [ServiceEntry(Protocol.IP)]
                for entry in entries:
                    if entry.protocol == Protocol.IP and entry.ip_protocol is None:
                        inbound.append({"protocol": "any", "destinationPorts": ["any"], "allowedIps": sources})
                    elif entry.protocol in (Protocol.TCP, Protocol.UDP) and not entry.src_ports and _port_list(entry.dst_ports) is not None:
                        inbound.append({"protocol": entry.protocol.value, "allowedIps": sources, "destinationPorts": _port_list(entry.dst_ports)})
                    elif entry.protocol == Protocol.ICMP and entry.icmp_type in (None, 8) and entry.icmp_code in (None, 0):
                        inbound.append({"protocol": "icmp-ping", "destinationPorts": ["any"], "allowedIps": sources})
                        if entry.icmp_type is None:
                            self.report.add("rule", rule.origin, Severity.APPROX, "MERAKI_PING_ONLY", "of ICMP the MX lets in ping only")
                    else:
                        self.report.add("rule", rule.origin, Severity.APPROX, "MERAKI_INBOUND_SERVICE",
                                        "a service 1:1 NAT cannot let in (only TCP and UDP ports, ping and any): left out")  # fmt: skip
                self.inbound_used.add(rule.origin)
            self.one_to_one.append({"name": nat.name[:64], "publicIp": int_to_ip(4, outside[1]).compressed, "lanIp": int_to_ip(4, inside[1]).compressed,
                                    "uplink": "internet1", "allowedInbound": inbound})  # fmt: skip
            return True
        dnat = nat.destination_translation
        if dnat is None or nat.source_translation is not None or len(nat.destinations) != 1 or nat.sources != [ANY] or dnat.spread:
            return False
        outer = transform.known_intervals(self.p, nat.destinations[0])[0]
        inner = transform.known_intervals(self.p, dnat.address)[0] if dnat.address else []
        if len(outer) != 1 or len(inner) != 1 or outer[0][1] != outer[0][2] or inner[0][1] != inner[0][2] or outer[0][0] != 4:
            return False
        flat = transform.flatten_services(self.p, nat.service) if nat.service != ANY else None
        if not flat or len(flat) != 1 or flat[0].protocol not in (Protocol.TCP, Protocol.UDP) or flat[0].src_ports or "," in flat[0].dst_ports \
                or not flat[0].dst_ports:
            return False
        public = flat[0].dst_ports
        local = dnat.port or public
        given, translated = _span_of(public), _span_of(local)
        if given is None or translated is None:
            self.why = f"ports {public[:20]} to {local[:20]}: the MX takes one port or one range, from 1 to 65535"
            return False
        if given[1] - given[0] != translated[1] - translated[0]:
            return False
        allowed = self._allowed(outer[0], inner[0], flat)
        if not allowed:
            return False
        sources = sorted({s for _, found in allowed for s in found})
        self.inbound_used |= {rule.origin for rule, _ in allowed}
        uplink = self.uplinks.get(outer[0]) or next((t[len("meraki uplink "):] for t in nat.tags if t.startswith("meraki uplink internet")), None)
        if uplink is not None:
            self.forwards.append({"name": nat.name[:64], "lanIp": int_to_ip(4, inner[0][1]).compressed, "uplink": uplink,
                                  "protocol": flat[0].protocol.value, "publicPort": public, "localPort": local,
                                  "allowedIps": ["any"] if "any" in sources else sources})  # fmt: skip
            return True
        self.one_to_many.setdefault(int_to_ip(4, outer[0][1]).compressed, []).append(
            {"name": nat.name[:64], "protocol": flat[0].protocol.value, "publicPort": public, "localIp": int_to_ip(4, inner[0][1]).compressed,
             "localPort": local, "allowedIps": ["any"] if "any" in sources else sources})  # fmt: skip
        return True

    # -- output -----------------------------------------------------------------------------------------

    def run(self) -> str:
        for rule in self.p.rules:
            self._rule(rule)
        self._defaults()
        for nat in self.p.nat_rules:
            self.why = ""
            if nat.source_translation is not None and nat.source_translation.kind == SnatKind.INTERFACE and nat.destination_translation is None:
                self.report.item("nat", nat.origin).emitted_as.append("what the MX does by itself: the LAN goes out with the address of the uplink")
                continue
            if self._nat(nat):
                self.report.item("nat", nat.origin).emitted_as.append("a rule of 1:1 or 1:many NAT")
            else:
                self.report.skip("nat", nat.origin, "NAT_NOT_CONVERTED",
                                 "not converted: the MX writes destination NAT of one public address and port (1:many NAT) and a static "
                                 "translation both ways (1:1 NAT), with the rules that allow traffic to them as the allowed remote "
                                 "addresses, and none that blocks before them; source NAT is the uplink's"
                                 + (f". Here: {self.why}" if self.why else ""))  # fmt: skip
        for rule in self.inbound:
            if rule.origin in self.inbound_used:
                self.report.item("rule", rule.origin).emitted_as.append("the allowed remote addresses of a NAT rule")
            elif rule.action == Action.ALLOW and not self.report.item("rule", rule.origin).emitted_as:
                why = self.inbound_why.get(rule.origin)
                self.report.skip("rule", rule.origin, "MERAKI_INBOUND",
                                 "a rule from the internet: the MX lets traffic from the internet in only by its NAT rules, and "
                                 + (f"it cannot be written as their allowed remote addresses: {why}" if why else "no NAT rule of the model goes with it"))  # fmt: skip
            elif rule.action == Action.ALLOW:
                self.report.add("rule", rule.origin, Severity.REVIEW, "MERAKI_INBOUND",
                                "what it allows from the internet is not written: the MX lets that in only by its NAT rules")  # fmt: skip
        self._notes()
        return self._script()

    def _script(self) -> str:
        bodies: List[Tuple[str, str]] = [("l3FirewallRules", json.dumps({"rules": self.l3, "syslogDefaultRule": False}, indent=1))]
        if self.forwards:
            bodies.append(("portForwardingRules", json.dumps({"rules": self.forwards}, indent=1)))
        if self.one_to_one:
            bodies.append(("oneToOneNatRules", json.dumps({"rules": self.one_to_one}, indent=1)))
        if self.one_to_many:
            rules = [{"publicIp": ip, "uplink": "internet1", "portRules": port_rules} for ip, port_rules in self.one_to_many.items()]
            bodies.append(("oneToManyNatRules", json.dumps({"rules": rules}, indent=1)))
        out = [
            "#!/bin/sh",
            "# Generated by FWShift: the rule tables of one Cisco Meraki MX network, put through the Dashboard API (v1).",
            "# Read the report first: what is not written is listed there. Each put replaces the whole table.",
            "# Usage: MERAKI_API_KEY=... NETWORK_ID=N_... [MERAKI_BASE=https://api.meraki.com/api/v1] [DRY_RUN=1] sh this-file",
            "# DRY_RUN=1 only writes the bodies, and needs no key. The backups (before-*.json) end in the fixed default rule of the",
            "# MX: to put a backup back, remove that last rule (comment \"Default rule\") from its rules first.",
            "set -eu",
            'OUT="${OUT:-meraki-$(date +%Y%m%d%H%M%S)}"',
            'mkdir -p "$OUT"',
            "api() {  # api METHOD PATH [BODY-FILE]",
            "  tries=0",
            "  while :; do",
            '    if [ -n "${3:-}" ]; then',
            '      code=$(curl -sS -o "$OUT/last.json" -D "$OUT/last.hdr" -w \'%{http_code}\' -X "$1" -H "Authorization: Bearer $MERAKI_API_KEY" \\',
            '             -H \'Content-Type: application/json\' -H \'Accept: application/json\' --data-binary @"$3" "$MERAKI_BASE$2")',
            "    else",
            '      code=$(curl -sS -o "$OUT/last.json" -D "$OUT/last.hdr" -w \'%{http_code}\' -X "$1" -H "Authorization: Bearer $MERAKI_API_KEY" \\',
            '             -H \'Accept: application/json\' "$MERAKI_BASE$2")',
            "    fi",
            '    case "$code" in',
            '      2??) cat "$OUT/last.json"; return 0 ;;',
            '      429) tries=$((tries+1)); [ "$tries" -le 5 ] || { echo "rate limited: $2" >&2; return 1; }',
            '           wait=$(sed -n \'s/^[Rr]etry-[Aa]fter: *\\([0-9]*\\).*/\\1/p\' "$OUT/last.hdr"); sleep "${wait:-2}" ;;',
            '      *) echo "HTTP $code on $1 $2:" >&2; cat "$OUT/last.json" >&2; return 1 ;;',
            "    esac",
            "  done",
            "}",
        ]
        for name, body in bodies:
            out += [f"cat > \"$OUT/{name}.json\" <<'FWSHIFT_EOF'"] + body.split("\n") + ["FWSHIFT_EOF"]
        out += ['if [ "${DRY_RUN:-0}" = 1 ]; then echo "DRY_RUN: the bodies are in $OUT"; exit 0; fi',
                ': "${MERAKI_API_KEY:?set MERAKI_API_KEY}"', ': "${NETWORK_ID:?set NETWORK_ID}"',
                'MERAKI_BASE="${MERAKI_BASE:-https://api.meraki.com/api/v1}"']  # fmt: skip
        for name, _ in bodies:
            out.append(f'api GET "/networks/$NETWORK_ID/appliance/firewall/{name}" > "$OUT/before-{name}.json"')
        for name, _ in bodies:
            out += [f'api PUT "/networks/$NETWORK_ID/appliance/firewall/{name}" "$OUT/{name}.json" > "$OUT/after-{name}.json"', "sleep 0.2"]
        out.append('echo "done; the tables as they were are in $OUT/before-*.json"')
        if self.not_written:
            out += ["# Not written:"] + [f"#   {''.join(c if c.isprintable() else ' ' for c in line)}" for line in self.not_written]
        return "\n".join(out) + "\n"

    def _notes(self) -> None:
        self.report.note(Severity.REVIEW, "MERAKI_LOAD",
                         "the output is a shell script for the Dashboard API (section 10): it backs up and replaces the outbound "
                         "table" + (" and the tables of NAT it has rules for" if self.one_to_one or self.one_to_many or self.forwards else "")
                         + "; DRY_RUN=1 writes the bodies only. The fixed default rule of the MX (allow) stays at the end")  # fmt: skip
        if self.one_to_one or self.one_to_many or any(f.get("uplink") == "internet1" for f in self.forwards):
            self.report.note(Severity.REVIEW, "MERAKI_NAT_UPLINK",
                             "1:1 and 1:many NAT, and port forwarding to an address of an uplink whose name is not known, are "
                             "written for uplink internet1; a public address that is the MX's own WAN address needs port "
                             "forwarding instead")  # fmt: skip
        if len(self.l3) > 600:
            self.report.note(Severity.REVIEW, "MERAKI_MANY_RULES", f"{len(self.l3)} rules in the outbound table: puts of more than about "
                             "900 rules have been seen to time out")  # fmt: skip
        if any(bool(rule.get("syslogEnabled")) for rule in self.l3):
            self.report.note(Severity.INFO, "LOGGING_CONVERTED", "rules of the source log; their rules have syslogEnabled")


def _span_of(ports: str) -> Optional[Tuple[int, int]]:
    """One port or one range from 1 to 65535."""
    low, dash, high = ports.partition("-")
    if not low.isdigit() or (dash and not high.isdigit()) or not low.isascii() or not high.isascii():
        return None
    first, last = int(low), int(high or low)
    return (first, last) if 1 <= first <= last <= 65535 else None


def _port_list(ports: str) -> Optional[List[str]]:
    """The destination ports of an allowed inbound entry of 1:1 NAT; None for port 0, which the MX does not take."""
    if not ports or ports == "0-65535":
        return ["any"]
    parts = ports.split(",")
    if any(_span_of(part) is None for part in parts):
        return None
    return parts


def _ranges(ports: str) -> List[Interval]:
    if not ports:
        return [(0, 0, 65535)]
    return [(0, int(p.partition("-")[0]), int(p.partition("-")[2] or p.partition("-")[0])) for p in ports.split(",")]


def _holds(entries: List[ServiceEntry], wanted: ServiceEntry) -> bool:
    """Whether the entries together hold all of one TCP or UDP entry (with no source ports)."""
    if wanted.protocol not in (Protocol.TCP, Protocol.UDP) or wanted.src_ports:
        return False
    covered: List[Interval] = []
    for entry in entries:
        if entry.protocol == Protocol.IP and entry.ip_protocol is None:
            return True
        if entry.protocol == wanted.protocol and not entry.src_ports:
            covered += _ranges(entry.dst_ports)
    return not subtract(_ranges(wanted.dst_ports), covered)


def _meets(a: ServiceEntry, b: ServiceEntry) -> bool:
    """Whether two entries can match one packet (protocol and ports)."""
    if a.protocol == Protocol.IP and a.ip_protocol is None or b.protocol == Protocol.IP and b.ip_protocol is None:
        return True
    if a.protocol != b.protocol:
        return False
    if a.protocol not in (Protocol.TCP, Protocol.UDP):
        return True
    return overlaps(_ranges(a.dst_ports), _ranges(b.dst_ports))
