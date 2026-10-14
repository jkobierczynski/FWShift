# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco Meraki MX parser: the answers of the Dashboard API (v1) for one network -> neutral model.

What is read is one JSON object with the answers under the names of their endpoints: ``l3FirewallRules``, ``vlans``
(or ``singleLan``), ``staticRoutes``, ``portForwardingRules``, ``oneToOneNatRules``, ``oneToManyNatRules``,
``l7FirewallRules``, ``inboundFirewallRules``, ``policyObjects``, ``policyObjectsGroups``, ``uplinkStatuses``,
``uplinksNat``, ``applianceSettings`` and the rest (the fetch commands are in the manual). An ``l3FirewallRules``
answer alone is read too. How an MX decides, and how that is mapped onto the neutral model:

* Meraki has no zones: a zone per VLAN (``vlan10-office``, its subnet and the subnets routed behind it), ``lan`` for a
  network without VLANs, and ``internet`` for the rest.
* Traffic inside one VLAN does not pass the MX: a rule at the top allows it. The outbound table (``l3FirewallRules``)
  decides traffic from the VLANs, between them and to the internet: first match, and its fixed default rule allows
  what no rule matches. Layer 7 rules only block, after layer 3: those of ports and address ranges become rules that
  block before the table; the others (applications, categories, host names, countries) are not converted.
* From the internet only what port forwarding, 1:1 NAT and 1:many NAT allow passes (their allowed remote addresses),
  for the public address and port as they arrive; with NAT exceptions the inbound table decides instead. These become
  rules from the internet and NAT rules; the LAN to the internet is translated to the address of the uplink unless
  NAT is off on it.
* Policy objects (``OBJ(id)``), their groups (``GRP(id)``) and VLAN objects (``VLAN(10).*``, ``VLAN(10).5``) are
  resolved; host names (FQDN) are host name objects. What cannot be resolved makes its rule not converted.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import (
    ANY,
    Action,
    Address,
    AddressGroup,
    AddressKind,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    RuleScope,
    Service,
    ServiceEntry,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, normalize, parse_literal, subtract
from ..report import Report, Severity

KEYS = ("network", "applianceSettings", "vlansSettings", "vlans", "singleLan", "staticRoutes", "l3FirewallRules", "inboundFirewallRules",
        "cellularFirewallRules", "inboundCellularFirewallRules", "l7FirewallRules", "firewalledServices", "portForwardingRules",
        "oneToOneNatRules", "oneToManyNatRules", "policyObjects", "policyObjectsGroups", "groupPolicies", "uplinkStatuses", "uplinksNat",
        "vpnFirewallRules", "siteToSiteVpn", "fwshift")  # fmt: skip
_RULE_KEYS = {"comment", "policy", "protocol", "srcPort", "srcCidr", "destPort", "destCidr", "syslogEnabled"}
_FQDN = re.compile(r"(\*\.)?([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?")


def _table(value: Any) -> Optional[List[Any]]:
    """The rules of an answer of a rule table: ``{"rules": [...]}``, or the list itself."""
    if isinstance(value, dict) and isinstance(value.get("rules"), list):
        rules: List[Any] = value["rules"]
        return rules
    if isinstance(value, list):
        return value
    return None


def _is_rule(value: Any) -> bool:
    return isinstance(value, dict) and {"policy", "srcCidr", "destCidr"} <= set(value)


def looks_like_meraki(data: bytes) -> bool:
    """A bundle of Dashboard API answers, or an answer of a layer 3 rule table alone."""
    head = data[:4_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    if b'"fwshift": "meraki-mx"' in head or b'"fwshift":"meraki-mx"' in head:
        return True
    if b'"srcCidr"' in head and b'"destCidr"' in head and b'"policy"' in head:
        return True
    return b'"l3FirewallRules"' in head


def _bool(value: Any) -> bool:
    return value is True


def _text(value: Any) -> str:
    return "" if value is None else str(value)


class _Builder:
    def __init__(self, document: Dict[str, Any], report: Report) -> None:
        self.doc, self.report = document, report
        self.p = Policy(vendor="meraki", default_intrazone=Action.ALLOW, default_interzone=Action.DENY)
        self.notes: Dict[str, List[str]] = {}
        self.vlans: Dict[str, Tuple[List[Interval], List[Interval]]] = {}  # VLAN id -> (IPv4 subnets, IPv6 prefixes)
        self.lan_zones: List[str] = []
        self.zone_space: Dict[str, List[Interval]] = {}
        self.objects: Dict[str, str] = {}  # policy object id -> address name
        self.groups: Dict[str, str] = {}
        self.wan: Dict[str, List[Interval]] = {}  # uplink (internet1 ...) -> addresses
        self.names: Set[str] = set()
        self.counters: Dict[str, int] = {}
        self.fqdn_groups: Set[str] = set()
        self.vlan_zone: Dict[str, str] = {}
        self.nat_off: Set[str] = set()
        self.exceptions = False
        self.passthrough = False
        self.inbound_missing = False
        self.passthrough_denies = False

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    def _name(self, text: str) -> str:
        base = text.strip() or "rule"
        name = base
        counter = self.counters.get(base.lower(), 1)
        while name.lower() in self.names:
            counter += 1
            name = f"{base} ({counter})"
        self.counters[base.lower()] = counter
        self.names.add(name.lower())
        return name

    def build(self) -> Policy:
        if isinstance(self.doc.get("errors"), list):
            raise ParseError("an error answer of the Dashboard API: " + "; ".join(str(e) for e in self.doc["errors"])[:200])
        if self.doc.get("network", {}).get("isBoundToConfigTemplate") is True if isinstance(self.doc.get("network"), dict) else False:
            raise ParseError("the network is bound to a configuration template, whose firewall the per-network answers do not hold; "
                             "fetch the answers of the template")  # fmt: skip
        rules = _table(self.doc.get("l3FirewallRules"))
        if rules is None:
            raise ParseError("no l3FirewallRules: expected the answers of the Dashboard API for one network under the names of their "
                             "endpoints (the manual has the commands), or the answer of l3FirewallRules alone")  # fmt: skip
        mode = _text((self.doc.get("applianceSettings") or {}).get("deploymentMode")) if isinstance(self.doc.get("applianceSettings"), dict) else ""
        self.passthrough = mode == "passthrough"
        self._zones()
        self._policy_objects()
        self._uplinks()
        if self.lan_zones:
            self.p.rules.append(self._inside_vlan())
        self._l7()
        self._outbound(rules)
        self._inbound()
        self._nat()
        self._other()
        self._notes()
        return self.p

    # -- zones -------------------------------------------------------------------------------------

    def _zones(self) -> None:
        vlans = self.doc.get("vlans")
        single = self.doc.get("singleLan")
        enabled = (self.doc.get("vlansSettings") or {}).get("vlansEnabled") if isinstance(self.doc.get("vlansSettings"), dict) else None
        if isinstance(vlans, list) and enabled is not False:
            for vlan in vlans:
                if not isinstance(vlan, dict) or "id" not in vlan:
                    continue
                ident = _text(vlan["id"]).strip()
                label = re.sub(r"[^a-z0-9-]+", "-", _text(vlan.get("name")).lower()).strip("-")[:24]
                zone = f"vlan{ident}" + (f"-{label}" if label else "")
                v4 = [i for i in [parse_literal(_text(vlan.get("subnet")))] if i is not None and i[0] == 4]
                v6: List[Interval] = []
                ipv6 = vlan.get("ipv6")
                if isinstance(ipv6, dict) and ipv6.get("enabled") is True:
                    for assignment in ipv6.get("prefixAssignments") or []:
                        if isinstance(assignment, dict):
                            found = parse_literal(_text(assignment.get("staticPrefix")))
                            if found is not None and found[0] == 6:
                                v6.append(found)
                self.vlans[ident] = (v4, v6)
                self._zone(zone, v4 + v6, f"VLAN {ident}")
                self.vlan_zone[ident] = zone
        elif isinstance(single, dict):
            found = parse_literal(_text(single.get("subnet")))
            self._zone("lan", [found] if found is not None else [], "single LAN")
            self.vlan_zone["lan"] = "lan"
        else:
            self._say("MERAKI_NO_VLANS", "no vlans or singleLan answer")
        for route in self.doc.get("staticRoutes") or []:
            if not isinstance(route, dict) or route.get("enabled") is False:
                continue
            subnet = parse_literal(_text(route.get("subnet")))
            gateway = parse_literal(_text(route.get("gatewayIp")))
            if subnet is None:
                continue
            behind: Optional[str] = self.vlan_zone.get(_text(route.get("gatewayVlanId")))
            if behind is None and gateway is not None:
                behind = next((z for z, space in self.zone_space.items() if any(i[0] == gateway[0] and i[1] <= gateway[1] <= i[2] for i in space)), None)
            if behind is None:
                self._say("MERAKI_ROUTE", _text(route.get("name")) or interval_text(subnet))
                continue
            self.zone_space[behind] = normalize(self.zone_space[behind] + [subnet])
            self.p.address_groups[f"zone {behind}"].members.append(interval_text(subnet))
        self.p.zones["internet"] = Zone("internet", interfaces=["wan"])
        self.p.address_groups["zone internet"] = AddressGroup(
            "zone internet", [interval_text(i) for i in subtract([FULL_V4, FULL_V6], [i for s in self.zone_space.values() for i in s])],
            builtin="meraki", description="the addresses of no VLAN")  # fmt: skip

    def _zone(self, zone: str, space: List[Interval], label: str) -> None:
        self.p.zones[zone] = Zone(zone, interfaces=[label])
        self.lan_zones.append(zone)
        self.zone_space[zone] = normalize(space)
        self.p.address_groups[f"zone {zone}"] = AddressGroup(f"zone {zone}", [interval_text(i) for i in normalize(space)], builtin="meraki",
                                                             description=f"the networks of {label}")  # fmt: skip

    # -- objects ----------------------------------------------------------------------------------

    def _policy_objects(self) -> None:
        for item in self.doc.get("policyObjects") or []:
            if not isinstance(item, dict) or "id" not in item:
                continue
            ident, name = _text(item["id"]), self._object_name(_text(item.get("name")) or f"object {item['id']}")
            kind = _text(item.get("type"))
            text = _text(item.get("cidr")) if kind == "cidr" else f"{_text(item.get('ip'))}/{_text(item.get('mask'))}"
            cidr = parse_literal(text)
            if cidr is not None and parse_literal(text.split("/")[0]) != (cidr[0], cidr[1], cidr[1]):
                cidr = None  # (host bits)
            if kind in ("cidr", "ipAndMask") and cidr is not None:
                self.p.addresses[name] = Address(name, AddressKind.NETWORK, interval_text(cidr))
            elif kind == "fqdn" and _FQDN.fullmatch(_text(item.get("fqdn"))):
                self.p.addresses[name] = Address(name, AddressKind.FQDN, _text(item["fqdn"]))
            else:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, _text(item.get("cidr") or item.get("fqdn"))[:100],
                                                 raw=f"a policy object of type {kind[:30] or 'none'}")  # fmt: skip
            self.objects[ident] = name
        for item in self.doc.get("policyObjectsGroups") or []:
            if not isinstance(item, dict) or "id" not in item:
                continue
            ident, name = _text(item["id"]), self._object_name(_text(item.get("name")) or f"group {item['id']}")
            members = [_text(m) for m in item.get("objectIds") or []]
            group = AddressGroup(name, [self.objects.get(m, "") for m in members])
            if _text(item.get("category")) not in ("NetworkObjectGroup", ""):
                group.unsupported = f"a group of category {_text(item.get('category'))[:30]}"
            if any(m not in self.objects for m in members):
                group.unsupported = "a member is not in the policy objects of the input"
                group.members = [m for m in group.members if m]
            bad = [m for m in group.members if self.p.addresses[m].kind == AddressKind.UNSUPPORTED]
            if bad:
                group.unsupported = f"member {bad[0][:40]}: {self.p.addresses[bad[0]].raw}"
            if any(self.p.addresses[m].kind == AddressKind.FQDN for m in group.members):
                self.fqdn_groups.add(name)
            self.p.address_groups[name] = group
            self.groups[ident] = name

    def _object_name(self, text: str) -> str:
        base = text.strip() or "object"
        if base.lower() == ANY:
            base += " (object)"  # (any is every address in the model)
        name, counter = base, 2
        while name in self.p.addresses or name in self.p.address_groups:
            name = f"{base} ({counter})"
            counter += 1
        return name

    def _uplinks(self) -> None:
        for device in self.doc.get("uplinkStatuses") or []:
            if not isinstance(device, dict):
                continue
            for uplink in device.get("uplinks") or []:
                if not isinstance(uplink, dict):
                    continue
                found = parse_literal(_text(uplink.get("ip") or uplink.get("publicIp")))
                interface = _text(uplink.get("interface"))
                if found is not None and interface.startswith("wan"):
                    self.wan.setdefault("internet" + interface[3:], []).append(found)
        for network in self.doc.get("uplinksNat") or []:
            for uplink in (network.get("uplinks") or []) if isinstance(network, dict) else []:
                if isinstance(uplink, dict) and isinstance(uplink.get("nat"), dict) and uplink["nat"].get("enabled") is False:
                    self.nat_off.add(_text(uplink.get("interface")))

    # -- addresses, services --------------------------------------------------------------------------

    def _addresses(self, text: Any, destination: bool, problems: List[str]) -> List[str]:
        parts = [part.strip() for part in _text(text).split(",")]
        if any(not part for part in parts) or not parts:
            problems.append(f"an empty address in '{_text(text)[:60]}'")
            return [ANY]
        out: List[str] = []
        for part in parts:
            if part.lower() == "any":
                return [ANY]
            reference = re.fullmatch(r"(OBJ|GRP)[(\[](\d+)[)\]]", part)
            vlan = re.fullmatch(r"VLAN\((\d+)\)\.(\*|\d{1,3})", part)
            if reference:
                table = self.objects if reference.group(1) == "OBJ" else self.groups
                name = table.get(reference.group(2))
                if name is None:
                    problems.append(f"{part[:40]} is not in the policy objects of the input")
                    continue
                problems += self._why(name)
                found = self.p.addresses.get(name)
                if not destination and ((found is not None and found.kind == AddressKind.FQDN) or name in self.fqdn_groups):
                    problems.append(f"{part[:40]}: a host name as a source")
                out.append(name)
            elif vlan:
                name = self._vlan(vlan.group(1), vlan.group(2), problems)
                if name:
                    out.append(name)
            elif parse_literal(part) is not None and "-" not in part:
                interval = parse_literal(part)
                assert interval is not None
                address = part.split("/")[0]
                if parse_literal(address) not in (None, (interval[0], interval[1], interval[1])):
                    problems.append(f"'{part[:40]}': an address with host bits")
                    continue
                out.append(interval_text(interval))
            elif destination and _FQDN.fullmatch(part):
                name = f"fqdn {part.lower()}"
                self.p.addresses.setdefault(name, Address(name, AddressKind.FQDN, part.lower().rstrip(".")))
                out.append(name)
                self._say("MERAKI_FQDN", part[:60])
            else:
                problems.append(f"'{part[:40]}' cannot be read")
        return transform.dedupe(out) or [ANY]

    def _why(self, name: str) -> List[str]:
        found = self.p.addresses.get(name)
        if found is not None and found.kind == AddressKind.UNSUPPORTED:
            return [f"{name[:40]}: {found.raw}"]
        group = self.p.address_groups.get(name)
        return [f"{name[:40]}: {group.unsupported}"] if group is not None and group.unsupported else []

    def _vlan(self, ident: str, host: str, problems: List[str]) -> str:
        if ident not in self.vlans:
            problems.append(f"VLAN {ident} is not in the vlans of the input")
            return ""
        v4, v6 = self.vlans[ident]
        if not v4 and not v6:
            problems.append(f"VLAN {ident} has no subnet in the input")
            return ""
        if host == "*":
            name = f"VLAN({ident})"
            if name not in self.p.address_groups:
                self.p.address_groups[name] = AddressGroup(name, [interval_text(i) for i in v4 + v6], builtin="meraki")
            if v6:
                self._say("MERAKI_VLAN_IPV6", name)
            return name
        offset = int(host)
        if not v4 or not 1 <= offset <= 254 or v4[0][1] + offset > v4[0][2]:
            problems.append(f"VLAN({ident}).{host}: no such address in the subnet of the VLAN")
            return ""
        return interval_text((4, v4[0][1] + offset, v4[0][1] + offset))

    def _nat_ports(self, text: Any, problems: List[str], side: str) -> Optional[str]:
        """The ports of a NAT rule: one port or one range; any, or none, is not read."""
        value = _text(text).strip()
        if not value or value.lower() == "any":
            problems.append(f"{side} ports '{value[:20]}': a NAT rule names its ports")
            return None
        return self._ports(value, problems, side)

    @staticmethod
    def _ports(text: Any, problems: List[str], side: str) -> Optional[str]:
        """'' for any, else the ports as the model writes them; None if they cannot be read."""
        value = _text(text).strip()
        if not value or value.lower() == "any":
            return ""
        parts = [part.strip() for part in value.split(",")]
        if re.fullmatch(r"\d+-\d+", value):
            low, high = (int(x) for x in value.split("-"))
            if 1 <= low <= high <= 65535:
                return f"{low}-{high}" if low != high else str(low)
        elif all(p.isascii() and p.isdigit() and 1 <= int(p) <= 65535 for p in parts):
            return ",".join(str(int(p)) for p in parts)
        problems.append(f"{side} port '{value[:40]}' cannot be read (one range, or a list of single ports)")
        return None

    def _service(self, rule: Dict[str, Any], problems: List[str]) -> List[str]:
        protocol = _text(rule.get("protocol")).lower()
        source = self._ports(rule.get("srcPort"), problems, "source")
        destination = self._ports(rule.get("destPort"), problems, "destination")
        if source is None or destination is None:
            return [ANY]
        if protocol in ("tcp", "udp"):
            entry = ServiceEntry(Protocol(protocol), destination, source)
        elif protocol in ("icmp", "icmp6", "any"):
            if source or destination:
                problems.append(f"ports with protocol {protocol}")
                return [ANY]
            if protocol == "any":
                return [ANY]
            entry = ServiceEntry(Protocol.ICMP if protocol == "icmp" else Protocol.ICMP6)
        else:
            problems.append(f"protocol '{protocol[:20]}' cannot be read")
            return [ANY]
        return [self._inline(entry)]

    def _inline(self, entry: ServiceEntry) -> str:
        label = entry.protocol.value + (f"/{entry.dst_ports}" if entry.dst_ports else "") + (f" from {entry.src_ports}" if entry.src_ports else "")
        if entry.icmp_type is not None:
            label += f" type {entry.icmp_type}"
        if label not in self.p.services:
            self.p.services[label] = Service(label, [entry])
        return label

    # -- rules ----------------------------------------------------------------------------------

    def _inside_vlan(self) -> Rule:
        rule = Rule("inside a VLAN", src_zones=list(self.lan_zones), scope=RuleScope.INTRAZONE, action=Action.ALLOW, origin="inside a VLAN")
        self.names.add(rule.name.lower())
        rule.log_end = False
        rule.description = "traffic inside one VLAN does not pass the MX"
        return rule

    def _l7(self) -> None:
        for index, item in enumerate(_table(self.doc.get("l7FirewallRules")) or [], 1):
            if not isinstance(item, dict):
                continue
            kind, value = _text(item.get("type")), item.get("value")
            name = self._name(f"layer 7 rule {index}")
            if kind == "port" and _text(value).isdigit() and 1 <= int(_text(value)) <= 65535:
                services = [self._inline(ServiceEntry(Protocol.TCP, _text(value))), self._inline(ServiceEntry(Protocol.UDP, _text(value)))]
                destinations = [ANY]
            elif kind == "ipRange":
                found = parse_literal(_text(value)) if _text(value).count(":") > 1 else None  # (IPv6, with no port)
                address, port = _text(value), ""
                if found is None:
                    address, _, port = _text(value).partition(":")
                    found = parse_literal(address)
                if found is None or (port and not (port.isdigit() and 1 <= int(port) <= 65535)):
                    self.report.skip("rule", name, "MERAKI_L7", f"layer 7 rule of an address range '{_text(value)[:40]}' that cannot be read")
                    continue
                destinations = [interval_text(found)]
                services = [self._inline(ServiceEntry(Protocol.TCP, port)), self._inline(ServiceEntry(Protocol.UDP, port))] if port else [ANY]
            else:
                self.report.skip("rule", name, "MERAKI_L7", f"layer 7 rule of {kind[:30] or 'nothing'}: applications, categories, host names "
                                 "and countries have no ports or addresses; what it blocks after the layer 3 rules is not converted")  # fmt: skip
                continue
            rule = Rule(name, src_zones=list(self.lan_zones) or [ANY], destinations=destinations, services=services, action=Action.DENY, origin=name)
            rule.description = f"layer 7: {kind} {_text(value)[:60]}"
            rule.log_end = False
            self.report.add("rule", name, Severity.REVIEW, "MERAKI_L7_PORTS",
                            "a layer 7 rule of a port or an address range, read as blocking TCP and UDP to it before the layer 3 "
                            "rules (layer 7 only blocks, after layer 3)")  # fmt: skip
            self.p.rules.append(rule)

    def _outbound(self, rules: List[Any]) -> None:
        default: Optional[Dict[str, Any]] = None
        if rules and isinstance(rules[-1], dict) and _text(rules[-1].get("comment")).strip().lower() == "default rule":
            default = rules[-1]
            rules = rules[:-1]
        else:
            self._say("MERAKI_NO_DEFAULT_RULE", "l3FirewallRules")
        for index, item in enumerate(rules, 1):
            if not _is_rule(item):
                raise ParseError(f"rule {index} of l3FirewallRules is not a rule (policy, srcCidr and destCidr)")
            self._rule(item, index, list(self.lan_zones) or [ANY], [ANY], "outbound")
        if not self.lan_zones:
            self._say("MERAKI_NO_LAN", "no vlans or singleLan")
        rule = Rule(self._name("Default rule"), src_zones=list(self.lan_zones) or [ANY], action=Action.ALLOW)
        rule.origin = rule.name
        rule.description = "the fixed default rule of the outbound table"
        rule.log_end = bool(default and default.get("syslogEnabled") is True)
        if default is not None and _text(default.get("policy")).lower() not in ("allow", ""):
            rule.unsupported = [f"a default rule with policy {_text(default.get('policy'))[:20]}"]
        self.p.rules.append(rule)

    def _rule(self, item: Dict[str, Any], index: int, src_zones: List[str], dst_zones: List[str], table: str) -> Rule:
        problems: List[str] = []
        comment = _text(item.get("comment")).strip()
        name = self._name(comment[:80] or f"{table} rule {index}")
        rule = Rule(name, src_zones=src_zones, dst_zones=dst_zones)
        rule.origin = name
        rule.description = comment
        rule.source_ids = {"meraki.table": table, "meraki.rule": str(index)}
        policy = _text(item.get("policy")).lower()
        if policy not in ("allow", "deny"):
            problems.append(f"policy '{policy[:20]}' is not converted")
        rule.action = Action.ALLOW if policy == "allow" else Action.DENY
        rule.log_end = item.get("syslogEnabled") is True
        rule.sources = self._addresses(item.get("srcCidr"), False, problems)
        rule.destinations = self._addresses(item.get("destCidr"), True, problems)
        rule.services = self._service(item, problems)
        unknown = [k for k in item if k not in _RULE_KEYS]
        if unknown:
            problems.append(f"'{unknown[0][:30]}' is not converted")
        rule.unsupported = list(dict.fromkeys(problems))
        self.p.rules.append(rule)
        return rule

    # -- from the internet ---------------------------------------------------------------------------

    def _zone_of(self, address: Interval) -> List[str]:
        return [zone for zone, space in self.zone_space.items() if any(i[0] == address[0] and i[1] <= address[1] and address[2] <= i[2] for i in space)] or [ANY]

    def _wan_addresses(self, uplink: str) -> Optional[List[Interval]]:
        if uplink in ("both", "all"):
            found = [i for addresses in self.wan.values() for i in addresses]
            return found or None
        return self.wan.get(uplink) or None

    def _inbound(self) -> None:
        answer = self.doc.get("inboundFirewallRules")
        table = _table(answer) or []
        for index, item in enumerate(table, 1):
            if not _is_rule(item):
                raise ParseError(f"rule {index} of inboundFirewallRules is not a rule (policy, srcCidr and destCidr)")
        default = table[-1] if table and _text(table[-1].get("comment")).strip().lower() == "default rule" else None
        rules = table[:-1] if default is not None else table
        self.exceptions = bool(self.nat_off) or self.passthrough
        if rules and not self.exceptions:
            self._say("MERAKI_INBOUND_TABLE", f"{len(rules)} rules")
        if not self.exceptions:
            return
        if answer is None and self.nat_off:
            self.inbound_missing = True
        for index, item in enumerate(rules, 1):
            self._rule(item, index, ["internet"], list(self.lan_zones) or [ANY], "inbound")
        if default is not None and _text(default.get("policy")).lower() == "allow" and not self.passthrough:
            rule = Rule(self._name("Default rule of the inbound table"), src_zones=["internet"], dst_zones=list(self.lan_zones) or [ANY],
                        action=Action.ALLOW)  # fmt: skip
            rule.origin = rule.name
            self.p.rules.append(rule)
        if default is not None and _text(default.get("policy")).lower() == "deny" and self.passthrough:
            self.passthrough_denies = True

    def _allow(self, label: str, sources: Any, destination: List[str], services: List[str], zones: List[str], why: List[str]) -> None:
        problems = list(why)
        cidrs = [s for s in (sources if isinstance(sources, list) else [sources]) if s is not None]
        if not isinstance(sources, list) or any("," in _text(c) for c in cidrs):
            problems.append("allowed remote addresses that are not a list of addresses")
        members = self._addresses(",".join(_text(c) for c in cidrs), False, problems) if cidrs else [ANY]
        if not cidrs:
            problems.append("no allowed remote addresses")
        rule = Rule(self._name(label), src_zones=["internet"], dst_zones=zones, sources=members, destinations=destination, services=services,
                    action=Action.ALLOW)  # fmt: skip
        rule.origin = rule.name
        rule.log_end = False
        rule.description = "the allowed remote addresses of a NAT rule, for the public address as it arrives"
        rule.unsupported = list(dict.fromkeys(problems))
        if self.exceptions:
            rule.unsupported = ["NAT exceptions: the inbound table decides, and it is not in the input"] if self.inbound_missing else []
            rule.enabled = self.inbound_missing
            rule.description += "; not in force: the inbound table decides (NAT exceptions)"
        self.p.rules.append(rule)

    def _nat(self) -> None:
        nat_rules: List[NatRule] = []
        forwards = _table(self.doc.get("portForwardingRules")) or []
        for index, item in enumerate(forwards, 1):
            if not isinstance(item, dict):
                continue
            problems: List[str] = []
            label = _text(item.get("name")) or f"port forward {index}"
            protocol = _text(item.get("protocol")).lower()
            public, local = self._nat_ports(item.get("publicPort"), problems, "public"), self._nat_ports(item.get("localPort"), problems, "local")
            lan = parse_literal(_text(item.get("lanIp")))
            wan = self._wan_addresses(_text(item.get("uplink")))
            if protocol not in ("tcp", "udp"):
                problems.append(f"protocol '{protocol[:20]}'")
            if lan is None or lan[1] != lan[2]:
                problems.append(f"LAN address '{_text(item.get('lanIp'))[:40]}' cannot be read")
            if wan is None:
                problems.append(f"the address of uplink {_text(item.get('uplink'))[:20]} is not in uplinkStatuses")
            if public is not None and local is not None and ("," in public or "," in local or _span(public) != _span(local)):
                problems.append("public and local ports that are not one port or one range of the same length")
            service = self._inline(ServiceEntry(Protocol(protocol), public or "")) if protocol in ("tcp", "udp") and public is not None else ANY
            destinations = [interval_text(i) for i in wan or []] or [f"uplink {_text(item.get('uplink'))[:20]}"]
            nat = NatRule(self._name(f"NAT {label}"), src_zones=["internet"], destinations=destinations, service=service,
                          destination_translation=DestNat(interval_text(lan) if lan else "", (local or "") if local != public else ""))  # fmt: skip
            nat.origin, nat.unsupported, nat.combines = nat.name, list(problems), True
            nat.tags.append(f"meraki uplink {_text(item.get('uplink'))[:20]}")
            nat_rules.append(nat)
            self._allow(label, item.get("allowedIps"), destinations, [service], self._zone_of(lan) if lan else [ANY], problems)
        for index, item in enumerate(_table(self.doc.get("oneToOneNatRules")) or [], 1):
            if not isinstance(item, dict):
                continue
            problems = []
            label = _text(item.get("name")) or f"1:1 NAT {index}"
            public_ip, lan = parse_literal(_text(item.get("publicIp"))), parse_literal(_text(item.get("lanIp")))
            if public_ip is None or lan is None or public_ip[1] != public_ip[2] or lan[1] != lan[2]:
                problems.append("a public or LAN address that cannot be read")
            nat = NatRule(self._name(f"NAT {label}"), sources=[interval_text(lan)] if lan else [ANY],
                          source_translation=SourceNat(SnatKind.STATIC, [interval_text(public_ip)] if public_ip else [], bidirectional=True))  # fmt: skip
            nat.origin, nat.unsupported, nat.combines = nat.name, list(problems), True
            nat_rules.append(nat)
            for number, inbound in enumerate(item.get("allowedInbound") or [], 1):
                if not isinstance(inbound, dict):
                    continue
                why = list(problems)
                services = self._inbound_services(inbound, why)
                self._allow(f"{label} ({number})", inbound.get("allowedIps"), [interval_text(public_ip)] if public_ip else [ANY], services,
                            self._zone_of(lan) if lan else [ANY], why)  # fmt: skip
        for index, item in enumerate(_table(self.doc.get("oneToManyNatRules")) or [], 1):
            if not isinstance(item, dict):
                continue
            public_ip = parse_literal(_text(item.get("publicIp")))
            for number, port_rule in enumerate(item.get("portRules") or [], 1):
                if not isinstance(port_rule, dict):
                    continue
                problems = []
                label = _text(port_rule.get("name")) or f"1:many NAT {index}.{number}"
                protocol = _text(port_rule.get("protocol")).lower()
                public, local = self._nat_ports(port_rule.get("publicPort"), problems, "public"), self._nat_ports(port_rule.get("localPort"), problems, "local")
                lan = parse_literal(_text(port_rule.get("localIp")))
                if public_ip is None or lan is None or public_ip[1] != public_ip[2] or lan[1] != lan[2] or protocol not in ("tcp", "udp"):
                    problems.append("a public or local address, or a protocol, that cannot be read")
                if public is not None and local is not None and ("," in public or "," in local or _span(public) != _span(local)):
                    problems.append("public and local ports that are not one port or one range of the same length")
                service = self._inline(ServiceEntry(Protocol(protocol), public or "")) if protocol in ("tcp", "udp") and public is not None else ANY
                destinations = [interval_text(public_ip)] if public_ip else [ANY]
                nat = NatRule(self._name(f"NAT {label}"), src_zones=["internet"], destinations=destinations, service=service,
                              destination_translation=DestNat(interval_text(lan) if lan else "", (local or "") if local != public else ""))  # fmt: skip
                nat.origin, nat.unsupported, nat.combines = nat.name, list(problems), True
                nat_rules.append(nat)
                self._allow(label, port_rule.get("allowedIps"), destinations, [service], self._zone_of(lan) if lan else [ANY], problems)
        if not self.passthrough and self.lan_zones:
            uplinks = [u for u in ("wan1", "wan2", "wan3", "wan4") if ("internet" + u[3:]) in self.wan] or ["wan1"]
            on = [u for u in uplinks if u not in self.nat_off]
            if on:
                nat = NatRule(self._name("NAT to the uplink"), src_zones=list(self.lan_zones), dst_zones=["internet"],
                              source_translation=SourceNat(SnatKind.INTERFACE, interface="internet",
                                                           interface_address=interval_text(self.wan["internet" + on[0][3:]][0]) if ("internet" + on[0][3:]) in self.wan else ""))  # fmt: skip
                nat.origin, nat.combines = nat.name, True
                nat.tags += [f"meraki wan {name} {interval_text(address)}" for name, addresses in self.wan.items() for address in addresses]
                if len(on) != len(uplinks):
                    self._say("MERAKI_NAT_EXCEPTION", ", ".join(u for u in uplinks if u in self.nat_off))
                nat_rules.append(nat)
            else:
                self._say("MERAKI_NAT_EXCEPTION", ", ".join(uplinks))
        if self.passthrough:
            self._say("MERAKI_PASSTHROUGH", "passthrough")
            if nat_rules:
                self._say("MERAKI_PASSTHROUGH", "NAT rules in passthrough mode were read as they are")
        self.p.nat_rules = nat_rules
        if self.passthrough and not self.passthrough_denies:
            rule = Rule(self._name("from the internet (passthrough)"), src_zones=["internet"], dst_zones=list(self.lan_zones) or [ANY],
                        action=Action.ALLOW)  # fmt: skip
            rule.origin = rule.name
            rule.description = "in passthrough mode traffic from the internet passes unless the inbound table says otherwise"
            self.p.rules.append(rule)

    def _inbound_services(self, inbound: Dict[str, Any], problems: List[str]) -> List[str]:
        protocol = _text(inbound.get("protocol")).lower()
        given = inbound.get("destinationPorts")
        if not isinstance(given, list) or not given:
            problems.append("destination ports that are not a list of ports")
            return [ANY]
        ports = [_text(p).strip() for p in given]
        if protocol == "icmp-ping":
            return [self._inline(ServiceEntry(Protocol.ICMP, icmp_type=8))]
        if protocol == "any":
            if any(p.lower() != "any" for p in ports):
                problems.append("ports with protocol any")
            return [ANY]
        if protocol not in ("tcp", "udp"):
            problems.append(f"protocol '{protocol[:20]}'")
            return [ANY]
        if not ports or any(p.lower() == "any" for p in ports):
            return [self._inline(ServiceEntry(Protocol(protocol)))]
        out = []
        for port in ports:
            found = self._ports(port, problems, "destination")
            if found is None:
                return [ANY]
            out.append(self._inline(ServiceEntry(Protocol(protocol), found)))
        return out

    # -- the rest ------------------------------------------------------------------------------------

    def _other(self) -> None:
        for key, code in (("cellularFirewallRules", "MERAKI_CELLULAR"), ("inboundCellularFirewallRules", "MERAKI_CELLULAR"),
                          ("vpnFirewallRules", "MERAKI_VPN")):  # fmt: skip
            rules = [r for r in _table(self.doc.get(key)) or [] if _is_rule(r) and _text(r.get("comment")).strip().lower() != "default rule"]
            if rules:
                self._say(code, f"{key}: {len(rules)} rules")
        for policy in self.doc.get("groupPolicies") or []:
            if isinstance(policy, dict) and isinstance(policy.get("firewallAndTrafficShaping"), dict) \
                    and policy["firewallAndTrafficShaping"].get("settings") == "custom":
                self._say("MERAKI_GROUP_POLICY", _text(policy.get("name"))[:40] or _text(policy.get("groupPolicyId")))
        services = [s for s in self.doc.get("firewalledServices") or [] if isinstance(s, dict) and s.get("access") != "blocked"]
        if services:
            self._say("MERAKI_SERVICES", ", ".join(_text(s.get("service")) for s in services))
        unknown = [key for key in self.doc if key not in KEYS]
        if unknown:
            self._say("MERAKI_UNKNOWN_KEYS", ", ".join(unknown[:8]))

    def _notes(self) -> None:
        self.report.note(Severity.INFO, "MERAKI_SOURCE",
                         f"{len(self.lan_zones)} LAN zones ({', '.join(self.lan_zones[:8])}{' ...' if len(self.lan_zones) > 8 else ''}) and "
                         "internet; traffic inside one VLAN passes (it does not pass the MX); the outbound table, first match, ends "
                         "in its fixed default rule that allows the rest; from the internet only what NAT rules allow passes")  # fmt: skip
        texts = {
            "MERAKI_NO_VLANS": (Severity.REVIEW, "no VLANs: the LAN zones and VLAN objects are not known"),
            "MERAKI_ROUTE": (Severity.REVIEW, "static routes whose gateway is in no VLAN: their subnets are in no zone"),
            "MERAKI_FQDN": (Severity.INFO, "host names in destinations: the MX learns their addresses from the DNS answers it sees; a "
                            "domain without a subdomain stands for its subdomains too"),
            "MERAKI_VLAN_IPV6": (Severity.REVIEW, "VLAN objects read with the IPv6 prefixes of the VLAN as well"),
            "MERAKI_NO_DEFAULT_RULE": (Severity.REVIEW, "the outbound table does not end in the Default rule (an older export?): read "
                                       "as the fixed allow of the MX anyway"),
            "MERAKI_INBOUND_TABLE": (Severity.REVIEW, "inbound rules without NAT exceptions: they decide IPv6 from the internet only, "
                                     "and are not converted"),
            "MERAKI_NAT_EXCEPTION": (Severity.INFO, "uplinks with NAT off (NAT exceptions): the LAN is not translated there"),
            "MERAKI_PASSTHROUGH": (Severity.REVIEW, "an MX in passthrough mode: traffic from the internet passes unless the inbound table "
                                   "says otherwise"),
            "MERAKI_NO_LAN": (Severity.REVIEW, "no LAN zones: the rules apply to traffic from anywhere"),
            "MERAKI_CELLULAR": (Severity.REVIEW, "the rules of cellular failover act only on the cellular uplink, after the outbound "
                                "table: not converted"),
            "MERAKI_VPN": (Severity.REVIEW, "the site-to-site VPN rules of the organization decide traffic into the VPN: not converted"),
            "MERAKI_GROUP_POLICY": (Severity.REVIEW, "group policies with layer 3 rules of their own, for the clients and VLANs they are "
                                    "applied to: not converted, and the rules here may not be what those get"),
            "MERAKI_SERVICES": (Severity.INFO, "services of the MX itself that answer on the WAN (firewalledServices): not converted"),
            "MERAKI_UNKNOWN_KEYS": (Severity.INFO, "answers that are not read"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def _span(ports: str) -> int:
    low, _, high = ports.partition("-")
    return int(high or low) - int(low) if low else 0


def parse(data: bytes, report: Report) -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    if isinstance(document, list) and all(_is_rule(r) for r in document) and document:
        document = {"l3FirewallRules": {"rules": document}}
    if isinstance(document, dict) and "rules" in document and "syslogDefaultRule" in document:
        raise ParseError("a rule table with syslogDefaultRule alone: the answer of the inbound table, or a body to put, which is not "
                         "the outbound table as the Dashboard API answers it; give the bundle of the network")
    if isinstance(document, dict) and "rules" in document and "l3FirewallRules" not in document and \
            all(_is_rule(r) for r in document.get("rules") or [{}]):
        document = {"l3FirewallRules": document}
        report.note(Severity.REVIEW, "MERAKI_TABLE_ALONE", "the answer of one rule table, read as the outbound table: the VLANs, "
                    "objects and NAT rules are not known")  # fmt: skip
    if not isinstance(document, dict):
        raise ParseError("expected a JSON object with the answers of the Dashboard API under the names of their endpoints")
    try:
        return _Builder(document, report).build()
    except ParseError:
        raise
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None

