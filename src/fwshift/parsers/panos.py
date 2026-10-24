# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""PAN-OS parser: firewall or Panorama XML configuration -> neutral model."""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

from .. import xmlread, zonenets
from . import panos_set
from ..appmap import valid_ports
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
    ServiceGroup,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import Interval, is_network, is_range, parse_literal
from ..report import Report, Severity

# Services every PAN-OS release predefines.
_BUILTIN_SERVICES = {"service-http": ("tcp", "80,8080"), "service-https": ("tcp", "443")}

_ACTIONS = {
    "allow": Action.ALLOW,
    "deny": Action.DENY,
    "drop": Action.DROP,
    "reset-client": Action.RESET_CLIENT,
    "reset-server": Action.RESET_SERVER,
    "reset-both": Action.RESET_BOTH,
}

Layer = Tuple[str, ET.Element]


def _text(element: ET.Element, path: str, default: str = "") -> str:
    found = element.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip() or default


def _members(element: ET.Element, path: str) -> List[str]:
    return [m.text.strip() for m in element.findall(path + "/member") if m.text and m.text.strip()]


def _unique(name: str, taken: Set[str]) -> str:
    candidate, counter = name, 2
    while candidate in taken:
        candidate = f"{name}-{counter}"
        counter += 1
    taken.add(candidate)
    return candidate


def parse(data: bytes, report: Report, vsys: str = "", device_group: str = "") -> Policy:
    if not panos_set.is_xml(data):
        data = panos_set.to_xml(data, report)  # (set commands, as the firewall prints them or FWShift writes them)
    root = xmlread.fromstring(data, "PAN-OS exports")
    config = root if root.tag == "config" else root.find(".//config")
    if config is None:
        raise ParseError("no <config> element found; expected a PAN-OS or Panorama configuration export")

    layers, scope, panorama = _select_scope(config, vsys, device_group, report)
    policy = Policy(vendor="panos", scope=scope, default_intrazone=Action.ALLOW, default_interzone=Action.DENY)
    app_groups: Dict[str, List[str]] = {}
    app_filters: Set[str] = set()

    for _, layer in layers:
        for entry in layer.findall("address/entry"):
            address = _address(entry, report)
            policy.address_groups.pop(address.name, None)
            policy.addresses[address.name] = address
        for entry in layer.findall("address-group/entry"):
            group = _address_group(entry)
            policy.addresses.pop(group.name, None)
            policy.address_groups[group.name] = group
        for entry in layer.findall("service/entry"):
            service = _service(entry, report)
            policy.service_groups.pop(service.name, None)
            policy.services[service.name] = service
        for entry in layer.findall("service-group/entry"):
            name = entry.get("name", "")
            policy.services.pop(name, None)
            policy.service_groups[name] = ServiceGroup(name, _members(entry, "members"), tags=_members(entry, "tag"))
        for entry in layer.findall("application-group/entry"):
            app_groups[entry.get("name", "")] = _members(entry, "members")
        for entry in layer.findall("application-filter/entry"):
            app_filters.add(entry.get("name", ""))
        for entry in layer.findall("zone/entry"):
            name = entry.get("name", "")
            interfaces: List[str] = []
            for mode in ("layer3", "layer2", "virtual-wire", "tap", "tunnel"):
                interfaces += _members(entry, f"network/{mode}")
            policy.zones[name] = Zone(name, interfaces)
        for prefix in ("rulebase", "post-rulebase", "pre-rulebase"):
            for entry in layer.findall(f"{prefix}/default-security-rules/rules/entry"):
                action = _ACTIONS.get(_text(entry, "action"))
                if action is None:
                    continue
                if entry.get("name") == "intrazone-default":
                    policy.default_intrazone = action
                elif entry.get("name") == "interzone-default":
                    policy.default_interzone = action

    # Rule order: pre-rules top-down through the hierarchy, local rules, post-rules bottom-up.
    ordered: List[Tuple[str, str, ET.Element]] = []
    for label, layer in layers:
        ordered.append((label, "pre-rulebase", layer))
    for label, layer in layers:
        ordered.append((label, "rulebase", layer))
    for label, layer in reversed(layers):
        ordered.append((label, "post-rulebase", layer))

    taken_rules: Set[str] = set()
    taken_nat: Set[str] = set()
    for label, rulebase, layer in ordered:
        for entry in layer.findall(f"{rulebase}/security/rules/entry"):
            rule = _rule(entry, app_groups, app_filters)
            rule.source_ids["panos.name"] = rule.name
            if entry.get("uuid"):
                rule.source_ids["panos.uuid"] = entry.get("uuid", "")
            rule.name = rule.origin = _unique(rule.name, taken_rules)
            policy.rules.append(rule)
            targets = [d.get("name", "") for d in entry.findall("target/devices/entry")]
            if _text(entry, "target/negate") != "yes":
                rule.targets = [target for target in targets if target]  # (every device but these is not a list of devices)
            if targets or _text(entry, "target/negate") == "yes":
                report.add(
                    "rule",
                    rule.origin,
                    Severity.REVIEW,
                    "DEVICE_TARGET",
                    "the rule is pushed only to selected devices"
                    + (f" ({', '.join(targets)})" if targets else "")
                    + ("; negated target" if _text(entry, "target/negate") == "yes" else "")
                    + "; decide whether it belongs on the target firewall",
                )
        for entry in layer.findall(f"{rulebase}/nat/rules/entry"):
            nat = _nat_rule(entry)
            nat.name = nat.origin = _unique(nat.name, taken_nat)
            policy.nat_rules.append(nat)

    # Predefined services that are referenced but, being predefined, not in the file.
    referenced = {s for r in policy.rules for s in r.services} | {n.service for n in policy.nat_rules}
    referenced |= {m for g in policy.service_groups.values() for m in g.members}
    for name, (proto, ports) in _BUILTIN_SERVICES.items():
        if name in referenced and name not in policy.services and name not in policy.service_groups:
            policy.services[name] = Service(name, [ServiceEntry(Protocol(proto), dst_ports=ports)], builtin="panos")

    if not panorama:
        _zone_networks(config, policy, report)
        _interface_addresses(config, policy)
    if panorama:
        report.note(
            Severity.INFO,
            "PANORAMA_SOURCE",
            "read from Panorama: zones and interfaces live in templates and were not read; rules local to a "
            "firewall are not part of this policy",
        )
    return policy


def _interface_addresses(config: ET.Element, policy: Policy) -> None:
    """The address of the interface a source NAT hides behind (interface-address without an ip of its own): the first
    IPv4 address of that layer 3 interface or unit, as the configuration gives it. A target that cannot name the
    outgoing interface hides behind it (Check Point: the gateway object stands for its main address, not the outgoing
    interface's, which the FWShift lab found in 0.40.19)."""
    found: Dict[str, str] = {}
    for kind in ("ethernet", "aggregate-ethernet"):
        for interface in config.findall(f"devices/entry/network/interface/{kind}/entry"):
            holders = [(interface.get("name", ""), interface.find("layer3"))]
            holders += [(unit.get("name", ""), unit) for unit in interface.findall("layer3/units/entry")]
            for name, holder in holders:
                for address in holder.findall("ip/entry") if holder is not None else []:
                    text = address.get("name", "").split("/")[0]
                    try:
                        if ipaddress.ip_address(text).version == 4 and name not in found:
                            found[name] = text
                    except ValueError:
                        continue  # (an address object's name: not looked up here)
    for nat in policy.nat_rules:
        snat = nat.source_translation
        if snat is not None and snat.kind == SnatKind.INTERFACE and not snat.addresses and snat.interface in found:
            snat.interface_address = found[snat.interface]


def _zone_networks(config: ET.Element, policy: Policy, report: Report) -> None:
    """The networks behind the zones: the addresses of their interfaces (literal, or an address object of the policy),
    the static routes of the virtual routers and logical routers that leave by them (a next hop in the router's own
    interfaces), and the address pools of GlobalProtect behind their tunnel interface (zonenets). What lies behind an
    interface in no zone of this virtual system, a route that drops or goes to another router, is behind no zone."""
    network = config.find("devices/entry/network")
    if network is None:
        return

    def literal(text: str, host: bool = False) -> Optional[Interval]:
        found = parse_literal(text) if ("/" in text or "-" in text or host) else None
        if found is None and text in policy.addresses and policy.addresses[text].kind in (AddressKind.NETWORK, AddressKind.RANGE):
            found = parse_literal(policy.addresses[text].value)
        return found

    routers = network.findall("virtual-router/entry") + network.findall("logical-router/entry/vrf/entry")
    table_of: Dict[str, str] = {}
    for position, router in enumerate(routers):
        for member in _members(router, "interface"):
            table_of[member] = str(position)
    routes: List[zonenets.Route] = []
    unread: List[str] = []
    holders: List[Tuple[str, Optional[ET.Element]]] = []
    for kind in ("ethernet", "aggregate-ethernet"):
        for interface in network.findall(f"interface/{kind}/entry"):
            holders.append((interface.get("name", ""), interface.find("layer3")))
            holders += [(unit.get("name", ""), unit) for unit in interface.findall("layer3/units/entry")]
    for kind in ("vlan", "loopback", "tunnel"):  # (the interface itself, and its units vlan.10, loopback.1, tunnel.1)
        for interface in network.findall(f"interface/{kind}"):
            holders.append((kind, interface))
            holders += [(unit.get("name", ""), unit) for unit in interface.findall("units/entry")]
    for name, holder in holders:
        if holder is None:
            continue
        for address in holder.findall("ip/entry") + holder.findall("ipv6/address/entry"):
            found = literal(address.get("name", ""))
            if found is not None:
                routes.append(zonenets.Route(found, name, connected=True, table=table_of.get(name, "")))
        if holder.find("dhcp-client") is not None or holder.find("pppoe") is not None:
            unread.append(f"{name} takes its address from DHCP or PPPoE")
    for gateway in config.findall("devices/entry/vsys/entry/global-protect/global-protect-gateway/entry"):
        tunnel = _text(gateway, "remote-user-tunnel")
        for pool in gateway.findall(".//ip-pool/member"):
            found = literal((pool.text or "").strip())
            if found is not None:
                routes.append(zonenets.Route(found, tunnel, connected=True, table=table_of.get(tunnel, "")))
            else:
                unread.append(f"the GlobalProtect pool {(pool.text or '').strip()}")
    dynamic: Set[str] = set()
    for position, router in enumerate(routers):
        for version, table in ((4, "ip"), (6, "ipv6")):
            for route in router.findall(f"routing-table/{table}/static-route/entry"):
                name = route.get("name", "")
                destination = literal(_text(route, "destination"))
                if destination is None or destination[0] != version:
                    unread.append(f"static route {name}")
                    continue
                if route.find("route-table/no-install") is not None or route.find("route-table/multicast") is not None:
                    continue  # (not in the table that forwards)
                nexthop = route.find("nexthop")
                why = ""
                if nexthop is not None and nexthop.find("discard") is not None:
                    why = "a route that discards"
                elif nexthop is not None and (nexthop.find("next-vr") is not None or nexthop.find("next-lr") is not None):
                    why = "a route to another virtual router"
                hop = _text(route, "nexthop/ip-address") or _text(route, "nexthop/ipv6-address")
                gateway_address = literal(hop, host=True) if hop else None
                if hop and gateway_address is None and not why:
                    why = f"its next hop {hop} is not an address"
                metric = _text(route, "metric", "10")
                distance = _text(route, "admin-dist", "10")
                routes.append(zonenets.Route(destination, _text(route, "interface"), gateway_address,
                                             (int(distance) if distance.isdigit() else 10, int(metric) if metric.isdigit() else 10),
                                             nowhere=why, table=str(position)))  # fmt: skip
        for protocol in ("bgp", "ospf", "ospfv3", "rip"):
            if _text(router, f"protocol/{protocol}/enable") == "yes" or _text(router, f"{protocol}/enable") == "yes":
                dynamic.add(protocol)
    zone_of = {interface: zone.name for zone in policy.zones.values() for interface in zone.interfaces}
    # The routers of this virtual system: those that hold its interfaces (another's may hold the same networks).
    mine = {table_of[interface] for interface in zone_of if interface in table_of}
    if mine:
        routes = [route for route in routes if not route.table or route.table in mine]
    partial: List[str] = []
    if dynamic:
        partial.append(f"routing protocols are on ({', '.join(sorted(dynamic))})")
    layer2 = [entry.get("name", "") for entry in config.findall("devices/entry/vsys/entry/zone/entry")
              if entry.find("network/layer3") is None and entry.get("name", "") in policy.zones
              and any(entry.find(f"network/{mode}") is not None for mode in ("layer2", "virtual-wire", "tap", "tunnel", "external"))]  # fmt: skip
    if layer2:
        partial.append(f"zones without layer-3 interfaces ({', '.join(layer2[:6])}) pass traffic whose addresses are not known")
    placed = zonenets.place(routes, zone_of, report, unread=unread, partial="; ".join(partial))
    policy.zone_networks, policy.unzoned_networks = placed.zones, placed.unzoned


def _select_scope(
    config: ET.Element, vsys: str, device_group: str, report: Report
) -> Tuple[List[Layer], str, bool]:
    shared = config.find("shared")
    base: List[Layer] = [("shared", shared)] if shared is not None else []
    vsys_entries = {e.get("name", ""): e for e in config.findall("devices/entry/vsys/entry")}
    dg_entries = {e.get("name", ""): e for e in config.findall("devices/entry/device-group/entry")}

    if device_group or (dg_entries and not vsys_entries and not vsys):
        if not device_group:
            if len(dg_entries) != 1:
                raise ParseError(
                    "Panorama configuration with several device groups; choose one with --device-group: "
                    + ", ".join(sorted(dg_entries))
                )
            device_group = next(iter(dg_entries))
        if device_group not in dg_entries:
            raise ParseError(
                f"device group '{device_group}' not found; available: " + (", ".join(sorted(dg_entries)) or "none")
            )
        parents: Dict[str, str] = {}
        for entry in config.findall("readonly/devices/entry/device-group/entry"):
            parent = _text(entry, "parent-dg")
            if parent:
                parents[entry.get("name", "")] = parent
        chain = [device_group]
        while chain[-1] in parents and parents[chain[-1]] not in chain:
            chain.append(parents[chain[-1]])
        layers = base + [(name, dg_entries[name]) for name in reversed(chain) if name in dg_entries]
        if len(dg_entries) > 1 and config.find("readonly/devices/entry/device-group") is None:
            report.note(
                Severity.REVIEW,
                "NO_HIERARCHY",
                "the export has several device groups but no <readonly> section, which is where Panorama records "
                f"their hierarchy. Only '{device_group}' and 'shared' were read; rules and objects of parent "
                "device groups, if there are any, are missing",
            )
        return layers, f"device-group {device_group}", True

    if vsys_entries:
        if not vsys:
            if len(vsys_entries) != 1:
                raise ParseError(
                    "configuration with several virtual systems; choose one with --vsys: "
                    + ", ".join(sorted(vsys_entries))
                )
            vsys = next(iter(vsys_entries))
        if vsys not in vsys_entries:
            raise ParseError(f"virtual system '{vsys}' not found; available: " + ", ".join(sorted(vsys_entries)))
        return base + [(vsys, vsys_entries[vsys])], vsys, False

    if vsys:
        raise ParseError(f"virtual system '{vsys}' not found; the configuration has no virtual systems")
    if not base:
        raise ParseError("the configuration has no virtual system, device group or shared section")
    return base, "shared", bool(shared is not None and shared.find("pre-rulebase") is not None)


def _address(entry: ET.Element, report: Report) -> Address:
    name = entry.get("name", "")
    description, tags = _text(entry, "description"), _members(entry, "tag")
    for tag, kind in (("ip-netmask", AddressKind.NETWORK), ("ip-range", AddressKind.RANGE), ("fqdn", AddressKind.FQDN)):
        value = _text(entry, tag)
        if not value:
            continue
        valid = {AddressKind.NETWORK: is_network, AddressKind.RANGE: is_range}.get(kind)
        if valid is not None and not valid(value):
            report.add("address", name, Severity.REVIEW, "INVALID_ADDRESS", f"cannot interpret {tag} '{value}'")
            return Address(name, AddressKind.UNSUPPORTED, value, description, tags, raw=f"invalid {tag} '{value}'")
        return Address(name, kind, value, description, tags)
    wildcard = _text(entry, "ip-wildcard")
    raw = f"wildcard mask {wildcard}" if wildcard else "unknown address type"
    report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{raw} cannot be converted")
    return Address(name, AddressKind.UNSUPPORTED, wildcard, description, tags, raw=raw)


def _address_group(entry: ET.Element) -> AddressGroup:
    name = entry.get("name", "")
    group = AddressGroup(name, _members(entry, "static"), _text(entry, "description"), _members(entry, "tag"))
    if entry.find("dynamic") is not None:
        group.dynamic_filter = _text(entry, "dynamic/filter") or "(empty filter)"
    return group


def _service(entry: ET.Element, report: Report) -> Service:
    name = entry.get("name", "")
    service = Service(name, [], _text(entry, "description"), _members(entry, "tag"))
    for proto in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
        node = entry.find(f"protocol/{proto.value}")
        if node is not None:
            ports, source_ports = _text(node, "port"), _text(node, "source-port")
            if not ports:
                service.unsupported = f"{proto.value.upper()} service without a port"
            elif not valid_ports(ports) or (source_ports and not valid_ports(source_ports)):
                service.unsupported = f"port list '{ports}' / '{source_ports}' that could not be interpreted"
            service.entries.append(ServiceEntry(proto, ports, source_ports))
    if not service.entries:
        service.unsupported = "no TCP, UDP or SCTP definition"
    if service.unsupported:
        report.add("service", name, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{service.unsupported}: not converted")
    return service


def _expand_apps(
    names: List[str], groups: Dict[str, List[str]], seen: Tuple[str, ...] = (), memo: Optional[Dict[str, List[str]]] = None
) -> List[str]:
    """The applications behind names and application groups; a group that is reached twice is expanded once."""
    memo = {} if memo is None else memo
    out: Dict[str, None] = {}
    for name in names:
        if name in groups and name not in seen:
            if name not in memo:
                memo[name] = _expand_apps(groups[name], groups, seen + (name,), memo)
            expanded = memo[name]
        else:
            expanded = [name]
        out.update(dict.fromkeys(expanded))
    return list(out)


def _rule(entry: ET.Element, app_groups: Dict[str, List[str]], app_filters: Set[str]) -> Rule:
    rule = Rule(name=entry.get("name", ""))
    for tag in ("from", "to", "source", "destination", "application", "service"):
        if not _members(entry, tag):
            rule.unsupported.append(f"rule without <{tag}>")  # never read a missing match as "any"
    if not _text(entry, "action"):
        rule.unsupported.append("rule without <action>")
    rule.src_zones = _members(entry, "from") or [ANY]
    rule.dst_zones = _members(entry, "to") or [ANY]
    rule.sources = _members(entry, "source") or [ANY]
    rule.destinations = _members(entry, "destination") or [ANY]
    rule.services = _members(entry, "service") or [ANY]
    rule.applications = _expand_apps(_members(entry, "application") or [ANY], app_groups)
    rule.users = _members(entry, "source-user") or [ANY]
    rule.url_categories = _members(entry, "category") or [ANY]
    action_text = _text(entry, "action", "allow")
    if action_text in _ACTIONS:
        rule.action = _ACTIONS[action_text]
    else:
        rule.action = Action.DENY
        rule.unsupported.append(f"action '{action_text}'")
    rule.enabled = _text(entry, "disabled") != "yes"
    rule.negate_source = _text(entry, "negate-source") == "yes"
    rule.negate_destination = _text(entry, "negate-destination") == "yes"
    rule.log_start = _text(entry, "log-start") == "yes"
    rule.log_end = _text(entry, "log-end", "yes") == "yes"
    rule.description = _text(entry, "description")
    rule.tags = _members(entry, "tag")
    rule.schedule = _text(entry, "schedule")
    scope = _text(entry, "rule-type", "universal")
    rule.scope = RuleScope(scope) if scope in ("universal", "intrazone", "interzone") else RuleScope.UNIVERSAL

    for tag in ("hip-profiles", "source-hip", "destination-hip"):
        values = [v for v in _members(entry, tag) if v != ANY]
        if values:
            rule.unsupported.append(f"{tag} match {', '.join(values)}")
    filters = [a for a in rule.applications if a in app_filters]
    if filters:
        rule.unsupported.append(f"application filter {', '.join(filters)}")

    for tag in ("log-setting", "icmp-unreachable", "option/disable-server-response-inspection"):
        if _text(entry, tag) not in ("", "no"):
            rule.handling[tag] = _text(entry, tag)
    marking = entry.find("qos/marking")
    if marking is not None and len(marking):
        rule.handling["qos"] = " ".join(f"{child.tag} {(child.text or '').strip()}".strip() for child in marking.iter() if child is not marking)
    group_profile = _members(entry, "profile-setting/group")
    if group_profile:
        rule.profiles["group"] = ", ".join(group_profile)
    profiles = entry.find("profile-setting/profiles")
    if profiles is not None:
        for child in profiles:
            names = _members(profiles, child.tag)
            if names:
                rule.profiles[child.tag] = ", ".join(names)
    return rule


def _nat_rule(entry: ET.Element) -> NatRule:
    nat = NatRule(name=entry.get("name", ""))
    for tag in ("from", "to", "source", "destination"):
        if not _members(entry, tag):
            nat.unsupported.append(f"NAT rule without <{tag}>")
    nat.src_zones = _members(entry, "from") or [ANY]
    nat.dst_zones = _members(entry, "to") or [ANY]
    nat.sources = _members(entry, "source") or [ANY]
    nat.destinations = _members(entry, "destination") or [ANY]
    nat.service = _text(entry, "service", ANY)
    nat.enabled = _text(entry, "disabled") != "yes"
    nat.description = _text(entry, "description")
    nat.tags = _members(entry, "tag")

    nat_type = _text(entry, "nat-type", "ipv4")
    if nat_type != "ipv4":
        nat.unsupported.append(f"NAT type '{nat_type}'")
    if entry.find("dynamic-destination-translation") is not None:
        nat.unsupported.append("dynamic destination translation")

    source = entry.find("source-translation")
    if source is not None:
        dipp, dip, static = (source.find(t) for t in ("dynamic-ip-and-port", "dynamic-ip", "static-ip"))
        if dipp is not None:
            interface = dipp.find("interface-address")
            if interface is not None:
                ip = _text(interface, "ip") or _text(interface, "floating-ip")
                nat.source_translation = SourceNat(
                    SnatKind.INTERFACE, [ip] if ip else [], interface=_text(interface, "interface")
                )
            else:
                nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, _members(dipp, "translated-address"))
        elif dip is not None:
            nat.source_translation = SourceNat(SnatKind.DYNAMIC, _members(dip, "translated-address"))
            if dip.find("fallback") is not None:
                nat.unsupported.append("dynamic IP translation with fallback")
        elif static is not None:
            address = _text(static, "translated-address")
            nat.source_translation = SourceNat(
                SnatKind.STATIC, [address] if address else [], bidirectional=_text(static, "bi-directional") == "yes"
            )
        if nat.source_translation is None or (
            nat.source_translation.kind != SnatKind.INTERFACE and not nat.source_translation.addresses
        ):
            nat.unsupported.append("source translation that could not be interpreted")

    destination = entry.find("destination-translation")
    if destination is not None:
        address = _text(destination, "translated-address")
        if address:
            nat.destination_translation = DestNat(address, _text(destination, "translated-port"))
        else:
            nat.unsupported.append("destination translation without a translated address")
    return nat
