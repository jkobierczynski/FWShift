# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""FortiOS parser: FortiGate configuration backup -> neutral model.

How FortiOS behaviour is mapped onto the neutral model:

* ``all`` is IPv4-only (``0.0.0.0/0``); the IPv6 lists of a policy are separate.
* A policy without ``set action`` denies. A missing mandatory field, or an
  attribute this parser does not know, never makes a rule wider silently.
* FortiOS applies destination NAT (virtual IPs) before the policy lookup. A
  policy that names a VIP becomes a rule to the VIP's external address; a
  policy that names the mapped address gets the external address added.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..appmap import FORTIOS_DEFAULT_SERVICES, parse_spec, valid_ports
from ..errors import ParseError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    APP_DEFAULT,
    Action,
    Address,
    AddressGroup,
    AddressKind,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    Service,
    ServiceEntry,
    ServiceGroup,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import FULL_V4, Interval, is_network, is_number, is_range, netmask_to_cidr, overlaps, parse_literal
from ..netutil import range_text
from ..report import Report, Severity

# -- generic configuration tree -------------------------------------------


class Block:
    """One ``config`` table or one ``edit`` entry."""

    __slots__ = ("settings", "entries", "children")

    def __init__(self) -> None:
        self.settings: Dict[str, List[str]] = {}
        self.entries: Dict[str, Block] = {}
        self.children: Dict[str, Block] = {}

    def get(self, key: str, default: str = "") -> str:
        values = self.settings.get(key)
        return values[0] if values else default

    def list(self, key: str) -> List[str]:
        return list(self.settings.get(key, []))


def _quote_open(line: str, is_open: bool) -> bool:
    """Whether a double-quoted string is still open after ``line``."""
    index = 0
    while index < len(line):
        char = line[index]
        if is_open and char == "\\":
            index += 2
            continue
        if char == '"':
            is_open = not is_open
        index += 1
    return is_open


def split_line(line: str) -> List[str]:
    """Split a CLI line into words, honouring double quotes and backslash escapes."""
    out: List[str] = []
    current: List[str] = []
    quoted = started = False
    index = 0
    while index < len(line):
        char = line[index]
        if quoted:
            if char == "\\" and index + 1 < len(line):
                current.append(line[index + 1])
                index += 2
                continue
            if char == '"':
                quoted = False
            else:
                current.append(char)
        elif char == '"':
            quoted = started = True
        elif char.isspace():
            if current or started:
                out.append("".join(current))
            current, started = [], False
        else:
            current.append(char)
        index += 1
    if current or started:
        out.append("".join(current))
    return out


def parse_tree(text: str, warnings: Optional[List[str]] = None) -> Block:
    """Build the tree of ``config``/``edit`` blocks.

    A quoted value may span lines. An unescaped quote inside a value therefore
    swallows what follows it: when such a value runs over ``next`` or ``end``
    lines a warning is recorded, and a quote still open at the end is an error.
    """
    root = Block()
    stack: List[Tuple[str, Block]] = [("root", root)]
    pending: List[str] = []
    is_open = False
    opened_at = 0
    suspicious = False
    for number, physical in enumerate(text.splitlines(), 1):
        if is_open:
            if physical.strip() in ("next", "end"):
                suspicious = True
        else:
            opened_at = number
        is_open = _quote_open(physical, is_open)
        pending.append(physical)
        if is_open:
            continue  # a quoted value continues on the next line
        line = "\n".join(pending)
        if suspicious and warnings is not None:
            warnings.append(
                f"the quoted value starting on line {opened_at} runs over {len(pending)} lines, some of which "
                "look like configuration; an unescaped quote may have hidden entries from the converter"
            )
        pending, suspicious = [], False
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        words = split_line(stripped)
        if not words:
            continue
        verb, block = words[0], stack[-1][1]
        if verb == "config" and len(words) > 1:
            stack.append(("config", block.children.setdefault(" ".join(words[1:]), Block())))
        elif verb == "edit" and len(words) > 1:
            stack.append(("edit", block.entries.setdefault(words[1], Block())))
        elif verb == "set" and len(words) > 1:
            block.settings[words[1]] = words[2:]
        elif verb == "append" and len(words) > 1:
            block.settings.setdefault(words[1], []).extend(words[2:])
        elif verb == "unset" and len(words) > 1:
            block.settings.pop(words[1], None)
        elif verb == "next":
            if stack[-1][0] == "edit":
                stack.pop()
        elif verb == "end":
            if stack[-1][0] == "edit":
                stack.pop()
            if stack[-1][0] == "config":
                stack.pop()
    if is_open:
        raise ParseError(f"unterminated quoted string starting on line {opened_at}")
    return root


# -- tables ---------------------------------------------------------------

_PROFILE_KEYS = {
    "av-profile",
    "webfilter-profile",
    "dnsfilter-profile",
    "emailfilter-profile",
    "dlp-sensor",
    "dlp-profile",
    "ips-sensor",
    "application-list",
    "voip-profile",
    "waf-profile",
    "ssh-filter-profile",
    "file-filter-profile",
    "icap-profile",
    "videofilter-profile",
    "casb-profile",
    "virtual-patch-profile",
    "sctp-filter-profile",
    "profile-group",
    "ssl-ssh-profile",
}

# Attributes that narrow what a policy matches and have no neutral equivalent:
# a policy carrying one is converted disabled.
_RESTRICTING_KEYS = {
    "groups",
    "users",
    "fsso-groups",
    "fsso",
    "rsso",
    "ntlm",
    "devices",
    "application",
    "app-category",
    "app-group",
    "url-category",
    "src-vendor-mac",
    "vpntunnel",
    "geoip-match",
    "vlan-filter",
    "policy-expiry",
    "sgt-check",
    "sgt",
}
_RESTRICTING_PREFIXES = ("internet-service", "ztna-", "network-service", "tos", "reputation-")
# Restricting attributes that are on/off switches; every other one holds names or values.
_TOGGLE_KEYS = {
    "fsso",
    "rsso",
    "ntlm",
    "policy-expiry",
    "sgt-check",
    "internet-service",
    "internet-service-src",
    "internet-service-negate",
    "internet-service-src-negate",
    "internet-service6",
    "internet-service6-src",
    "internet-service6-negate",
    "internet-service6-src-negate",
    "ztna-status",
    "ztna-device-ownership",
    "ztna-policy-redirect",
    "tos-negate",
}
# Restricting attributes that are numbers, where zero means "not used".
_SWITCH_KEYS = {"tos", "tos-mask", "reputation-minimum", "sgt"}

# Attributes that are converted, or that do not change which traffic a policy matches.
_KNOWN_KEYS = {
    "name",
    "uuid",
    "srcintf",
    "dstintf",
    "srcaddr",
    "dstaddr",
    "srcaddr6",
    "dstaddr6",
    "action",
    "status",
    "schedule",
    "service",
    "logtraffic",
    "logtraffic-start",
    "comments",
    "nat",
    "ippool",
    "poolname",
    "srcaddr-negate",
    "dstaddr-negate",
    "srcaddr6-negate",
    "dstaddr6-negate",
    "service-negate",
    "match-vip",
    "utm-status",
    "profile-type",
    "profile-protocol-options",
    "inspection-mode",
    "global-label",
    "label",
    "auto-asic-offload",
    "np-acceleration",
    "capture-packet",
    "send-deny-packet",
    "session-ttl",
    "tcp-mss-sender",
    "tcp-mss-receiver",
    "traffic-shaper",
    "traffic-shaper-reverse",
    "per-ip-shaper",
    "diffserv-forward",
    "diffserv-reverse",
    "diffservcode-forward",
    "diffservcode-rev",
    "vlan-cos-fwd",
    "vlan-cos-rev",
    "timeout-send-rst",
    "block-notification",
    "replacemsg-override-group",
    "custom-log-fields",
    "logtraffic-app",
    "ssl-mirror",
    "ssl-mirror-intf",
    "wccp",
    "webcache",
    "wanopt",
    "delay-tcp-npu-session",
    "comment",
}
# What the model holds of a policy itself, or what only names it: everything else a policy sets is
# what it does with its traffic (Rule.handling).
_MODELLED_KEYS = {
    "name", "uuid", "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "action", "status", "schedule",
    "service", "logtraffic", "logtraffic-start", "comments", "comment", "global-label", "label", "srcaddr-negate",
    "dstaddr-negate", "srcaddr6-negate", "dstaddr6-negate", "service-negate",
}  # fmt: skip
# NAT details without an equivalent: mentioned, since they do not affect what is allowed.
_NOTED_KEYS = {"fixedport", "natip", "nat46", "nat64", "natinbound", "natoutbound", "port-preserve"}
_OFF_VALUES: Tuple[List[str], ...] = (["disable"], ["0"], ["0x00"], [""], [])

_UNCONVERTED_TABLES = (
    "firewall policy6",
    "firewall policy64",
    "firewall policy46",
    "firewall security-policy",
    "firewall proxy-policy",
    "firewall local-in-policy",
    "firewall local-in-policy6",
    "firewall multicast-policy",
    "firewall DoS-policy",
    "firewall interface-policy",
    "firewall vip6",
    "firewall vip46",
    "firewall vip64",
)

_RESERVED_NAMES = (ANY, APP_DEFAULT)  # words with a fixed meaning in the neutral model


@dataclass
class _Vip:
    name: str
    address: str  # name of the address object standing for the external IP
    mapped: str = ""
    extintf: str = ANY
    portforward: bool = False
    protocol: str = "tcp"
    extport: str = ""
    mappedport: str = ""
    src_filter: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)


@dataclass
class _PolicyInfo:
    policy_id: str
    block: Block
    rule: Rule
    dst_names: List[str]  # dstaddr as written, VIP names included
    nat: bool  # accept policy with per-policy source NAT


def _unique(name: str, taken: Set[str], suffix: str = "") -> str:
    """Return ``name``, or a variant of it that is not in ``taken`` yet, and record it."""
    candidate = name + suffix if name in taken else name
    counter = 2
    while candidate in taken:
        candidate = f"{name}{suffix}-{counter}"
        counter += 1
    taken.add(candidate)
    return candidate


def _collapse(members: List[str]) -> List[str]:
    out = transform.dedupe(members)
    if ANY_V4 in out and ANY_V6 in out:
        return [ANY]
    return out


def parse(data: bytes, report: Report, vdom: str = "") -> Policy:
    text = data.decode("utf-8-sig", errors="replace")
    warnings: List[str] = []
    tree = parse_tree(text, warnings)
    if not tree.children:
        raise ParseError("no 'config' sections found; expected a FortiOS configuration backup")
    for warning in warnings:
        report.note(Severity.REVIEW, "SUSPICIOUS_QUOTING", warning)
    scope, global_scope, name = _select_vdom(tree, vdom)
    return _Builder(scope, global_scope, report, name).build()


def _select_vdom(tree: Block, vdom: str) -> Tuple[Block, Block, str]:
    table = tree.children.get("vdom")
    vdoms = {name: block for name, block in table.entries.items() if block.children} if table else {}
    if not vdoms:
        if vdom:
            raise ParseError(f"VDOM '{vdom}' not found; the configuration has no VDOMs")
        return tree, tree, ""
    if not vdom:
        if len(vdoms) != 1:
            raise ParseError("configuration with several VDOMs; choose one with --vdom: " + ", ".join(sorted(vdoms)))
        vdom = next(iter(vdoms))
    if vdom not in vdoms:
        raise ParseError(f"VDOM '{vdom}' not found; available: " + ", ".join(sorted(vdoms)))
    return vdoms[vdom], tree.children.get("global", tree), vdom


class _Builder:
    def __init__(self, scope: Block, global_scope: Block, report: Report, vdom: str) -> None:
        self.scope = scope
        self.global_scope = global_scope
        self.report = report
        self.p = Policy(vendor="fortios", scope=vdom, default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.p.lookup_after_dnat = True
        self.names: Set[str] = set()  # address namespace of the neutral model
        self.address_names: Dict[str, str] = {}  # IPv4-table name -> neutral name, where they differ
        self.v6_names: Dict[str, str] = {}  # IPv6-table name -> neutral name
        self.service_names: Dict[str, str] = {}
        self.any_services: Set[str] = set()
        self.vips: Dict[str, _Vip] = {}
        self.vip_services: Dict[str, str] = {}
        self.pools: Dict[str, Tuple[str, SnatKind]] = {}
        self.interface_ip: Dict[str, str] = {}
        self.interface_net: Dict[str, Interval] = {}
        self.nat_seen: Dict[Tuple[object, ...], str] = {}
        self.family_memo: Dict[str, Set[int]] = {}  # address group -> IP versions; each group is walked once

    def section(self, path: str) -> Block:
        return self.scope.children.get(path) or Block()

    def build(self) -> Policy:
        self._interfaces()
        self._addresses()
        self._services()
        self._vips()
        self._pools()
        central = self.section("system settings").get("central-nat") == "enable"
        infos = self._policies(central)
        dnat = self._vip_rules()
        combined: List[NatRule] = []
        if central:
            snat = self._central_snat()
        else:
            combined, snat = self._policy_nat_rules(infos)
        # PAN-OS style first-match order: the most specific translations first.
        self.p.nat_rules = combined + dnat + snat
        for nat in self.p.nat_rules:
            nat.combines = True  # a virtual IP and a source NAT apply to the same session
        self._default_services()
        self.p.named_translations = True
        transform.rewrite_destinations(self.p, self.report, to_post_nat=False, report_deny=False, named_translations=True)
        self._deny_and_vips(infos)
        for table in _UNCONVERTED_TABLES:
            if self.section(table).entries:
                self.report.note(
                    Severity.REVIEW, "TABLE_NOT_CONVERTED", f"'config {table}' has entries and is not converted"
                )
        return self.p

    # -- interfaces and zones ---------------------------------------------

    def _interfaces(self) -> None:
        table = self.global_scope.children.get("system interface") or self.section("system interface")
        for name, block in table.entries.items():
            ip = block.list("ip")
            if len(ip) == 2 and ip[0] != "0.0.0.0":
                network = parse_literal(netmask_to_cidr(ip[0], ip[1]) or "")
                if network and parse_literal(ip[0]):
                    self.interface_ip[name] = ip[0]
                    self.interface_net[name] = network
        for name, block in self.section("system zone").entries.items():
            self.p.zones[name] = Zone(name, block.list("interface"), block.get("intrazone", "deny") == "allow")

    def _zone_of(self, interface: str) -> str:
        if interface == ANY:
            return ANY
        for zone in self.p.zones.values():
            if interface in zone.interfaces:
                return zone.name
        return interface

    def _egress(self, name: str) -> SourceNat:
        """Source NAT to the address of the interface a zone or interface name leaves through."""
        if name == ANY:
            return SourceNat(SnatKind.INTERFACE)
        interface = name
        if name in self.p.zones:
            members = self.p.zones[name].interfaces
            if len(members) != 1:
                return SourceNat(SnatKind.INTERFACE)  # ambiguous: several possible interfaces
            interface = members[0]
        return SourceNat(
            SnatKind.INTERFACE, interface=interface, interface_address=self.interface_ip.get(interface, "")
        )

    @staticmethod
    def _zones(names: List[str]) -> List[str]:
        out = transform.dedupe([ANY if n == "any" else n for n in names])
        return [ANY] if ANY in out or not out else out

    # -- addresses --------------------------------------------------------

    def _reserve(self, kind: str, name: str, taken: Set[str]) -> str:
        """A neutral name for an object whose own name is a reserved word of the model."""
        new = _unique(f"{name}-object", taken)
        self.report.add(
            kind, new, Severity.INFO, "RENAMED", f"named '{name}' in the source, a reserved word; renamed to '{new}'"
        )
        return new

    def _addresses(self) -> None:
        v4, v6 = self.section("firewall address"), self.section("firewall address6")
        g4, g6 = self.section("firewall addrgrp"), self.section("firewall addrgrp6")
        tables = (v4, g4, self.section("firewall vip"), self.section("firewall vipgrp"))
        self.names = {name for table in tables for name in table.entries if name not in _RESERVED_NAMES}
        for table in tables:
            for name in table.entries:
                if name in _RESERVED_NAMES and name not in self.address_names:
                    self.address_names[name] = self._reserve("address", name, self.names)
        for name in list(v6.entries) + list(g6.entries):
            if name != "all":
                base = f"{name}-object" if name in _RESERVED_NAMES else name
                self.v6_names[name] = _unique(base, self.names, "-v6")
        for name, block in v4.entries.items():
            if name != "all":
                neutral = self.address_names.get(name, name)
                self.p.addresses[neutral] = self._address(neutral, block, v6=False)
        for name, block in v6.entries.items():
            if name != "all":
                self.p.addresses[self.v6_names[name]] = self._address(self.v6_names[name], block, v6=True)
        for name, block in g4.entries.items():
            neutral = self.address_names.get(name, name)
            self.p.address_groups[neutral] = self._group(neutral, block, v6=False)
        for name, block in g6.entries.items():
            self.p.address_groups[self.v6_names[name]] = self._group(self.v6_names[name], block, v6=True)

    def _address(self, name: str, block: Block, v6: bool) -> Address:
        kind_text = block.get("type", "ipprefix" if v6 else "ipmask")
        comment = block.get("comment")
        value: Optional[str] = None
        kind = AddressKind.NETWORK
        if kind_text == "iprange":
            kind, value = AddressKind.RANGE, f"{block.get('start-ip')}-{block.get('end-ip')}"
        elif kind_text == "fqdn":
            return Address(name, AddressKind.FQDN, block.get("fqdn"), comment, fqdn_family=6 if v6 else 4)
        elif v6 and kind_text == "ipprefix":
            value = block.get("ip6", ANY_V6)
        elif not v6 and kind_text in ("ipmask", "interface-subnet"):
            subnet = block.list("subnet")
            if len(subnet) == 2:
                value = netmask_to_cidr(subnet[0], subnet[1])
            elif len(subnet) == 1:
                value = subnet[0]
            else:
                value = ANY_V4
        valid = value is not None and (is_range(value) if kind == AddressKind.RANGE else is_network(value))
        if value is None or not valid:
            raw = f"FortiOS address type '{kind_text}'" + (f" with value '{value}'" if value else "")
            self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{raw} cannot be converted")
            return Address(name, AddressKind.UNSUPPORTED, value or "", comment, raw=raw)
        return Address(name, kind, value, comment)

    def _group(self, name: str, block: Block, v6: bool) -> AddressGroup:
        group = AddressGroup(name, [self._ref(m, v6) for m in block.list("member")], block.get("comment"))
        if block.get("exclude") == "enable":
            group.unsupported = "address group with excluded members (" + ", ".join(block.list("exclude-member")) + ")"
            self.report.add("address-group", name, Severity.REVIEW, "GROUP_EXCLUDE", group.unsupported)
        return group

    def _ref(self, name: str, v6: bool) -> str:
        if name == "all":
            return ANY_V6 if v6 else ANY_V4
        if v6:
            return self.v6_names.get(name, name)
        if name in self.vips:
            return self.vips[name].address
        return self.address_names.get(name, name)

    # -- services ---------------------------------------------------------

    def _services(self) -> None:
        custom, groups = self.section("firewall service custom"), self.section("firewall service group")
        taken = {name for table in (custom, groups) for name in table.entries if name not in _RESERVED_NAMES}
        for table in (custom, groups):
            for name in table.entries:
                if name in _RESERVED_NAMES and name not in self.service_names:
                    self.service_names[name] = self._reserve("service", name, taken)
        for source_name, block in custom.entries.items():
            name = self.service_names.get(source_name, source_name)
            service = Service(name, [], block.get("comment"))
            protocol = block.get("protocol", "TCP/UDP/SCTP").upper()
            if protocol in ("TCP/UDP/SCTP", "TCP/UDP/UDP-LITE/SCTP"):
                merged: Dict[Tuple[Protocol, str], List[str]] = {}
                for key, proto in (
                    ("tcp-portrange", Protocol.TCP),
                    ("udp-portrange", Protocol.UDP),
                    ("sctp-portrange", Protocol.SCTP),
                ):
                    for token in block.list(key):
                        dst, _, src = token.partition(":")
                        if not valid_ports(dst) or (src and not valid_ports(src)):
                            service.unsupported = f"port range '{token}' that could not be interpreted"
                            continue
                        merged.setdefault((proto, src), []).append(dst)
                for (proto, src), ports in merged.items():
                    service.entries.append(ServiceEntry(proto, ",".join(ports), src))
            elif protocol in ("ICMP", "ICMP6"):
                icmp_type, icmp_code = block.get("icmptype"), block.get("icmpcode")
                if any(value and not (is_number(value) and int(value) < 256) for value in (icmp_type, icmp_code)):
                    # Set, but not a number: not the same as unset, which is every type.
                    service.unsupported = f"ICMP type or code '{icmp_type}/{icmp_code}' that could not be read"
                else:
                    service.entries.append(
                        ServiceEntry(
                            Protocol.ICMP if protocol == "ICMP" else Protocol.ICMP6,
                            icmp_type=int(icmp_type) if icmp_type else None,
                            icmp_code=int(icmp_code) if icmp_code else None,
                        )
                    )
            elif protocol == "IP":
                number = block.get("protocol-number", "0")
                if is_number(number) and 0 < int(number) < 256:
                    service.entries.append(ServiceEntry(Protocol.IP, ip_protocol=int(number)))
                elif number == "0":
                    service.entries.append(ServiceEntry(Protocol.IP))
                    self.any_services.add(source_name)
                else:
                    service.unsupported = f"protocol number '{number}' that could not be read"
            else:
                service.unsupported = f"service protocol '{protocol}'"
            if block.get("fqdn") or block.list("iprange") not in ([], ["0.0.0.0"]):
                service.unsupported = "service limited to a destination address or FQDN"
            if service.unsupported:
                self.report.add(
                    "service", name, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{service.unsupported}: not converted"
                )
            self.p.services[name] = service
        for source_name, block in groups.entries.items():
            name = self.service_names.get(source_name, source_name)
            members = [self.service_names.get(m, m) for m in block.list("member")]
            self.p.service_groups[name] = ServiceGroup(name, members, block.get("comment"))

    def _default_services(self) -> None:
        """Define factory-default services that are referenced but missing from the input."""
        referenced = {s for r in self.p.rules for s in r.services}
        referenced |= {m for g in self.p.service_groups.values() for m in g.members}
        for name in sorted(referenced):
            if name in self.p.services or name in self.p.service_groups or name not in FORTIOS_DEFAULT_SERVICES:
                continue
            entries = [parse_spec(spec) for spec in FORTIOS_DEFAULT_SERVICES[name]]
            self.p.services[name] = Service(name, entries, builtin="fortios")
            self.report.add(
                "service",
                name,
                Severity.INFO,
                "FACTORY_DEFAULT",
                "not defined in the input; the FortiOS factory-default definition was assumed",
            )

    # -- NAT objects ------------------------------------------------------

    def _vips(self) -> None:
        for source_name, block in self.section("firewall vip").entries.items():
            name = self.address_names.get(source_name, source_name)
            vip = _Vip(source_name, name)
            external, mapped = parse_literal(block.get("extip")), parse_literal(block.get("mappedip"))
            interface = block.get("extintf", "any")
            vip.extintf = ANY if interface == "any" else interface
            vip.portforward = block.get("portforward") == "enable"
            vip.protocol = block.get("protocol", "tcp")
            vip.extport = block.get("extport")
            vip.mappedport = block.get("mappedport") or vip.extport
            vip.src_filter = block.list("src-filter")
            vip_type = block.get("type", "static-nat")
            if vip_type != "static-nat":
                vip.problems.append(f"virtual IP of type '{vip_type}'")
            if external is None or mapped is None or external[0] != 4 or mapped[0] != 4:
                vip.problems.append("external or mapped address that could not be interpreted")
            if vip.portforward and vip.protocol not in ("tcp", "udp", "sctp"):
                vip.problems.append(f"port forwarding for protocol '{vip.protocol}'")
            if vip.portforward and not (valid_ports(vip.extport) and "," not in vip.extport):
                vip.problems.append(f"external port '{vip.extport}' that could not be interpreted")
            if any(parse_literal(source) is None for source in vip.src_filter):
                vip.problems.append("source filter that could not be interpreted")
            comment = block.get("comment")
            if vip.problems or external is None or mapped is None:
                raw = "; ".join(vip.problems)
                self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_VIP", f"{raw}: not converted")
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, block.get("extip"), comment, raw=raw)
            else:
                vip.mapped = range_text(mapped)
                single = external[1] == external[2]
                value = f"{range_text(external)}/32" if single else range_text(external)
                kind = AddressKind.NETWORK if single else AddressKind.RANGE
                self.p.addresses[name] = Address(name, kind, value, comment)
            self.vips[source_name] = vip
        for source_name, block in self.section("firewall vipgrp").entries.items():
            name = self.address_names.get(source_name, source_name)
            members = [self._ref(m, False) for m in block.list("member")]
            self.p.address_groups[name] = AddressGroup(name, members, block.get("comments"))

    def _pools(self) -> None:
        for name, block in self.section("firewall ippool").entries.items():
            first, last = block.get("startip"), block.get("endip") or block.get("startip")
            pool_type = block.get("type", "overload")
            address = _unique(f"{name}-object" if name in _RESERVED_NAMES else name, self.names, "-pool")
            interval = parse_literal(f"{first}-{last}")
            if interval is None or interval[0] != 4:
                self.p.addresses[address] = Address(
                    address, AddressKind.UNSUPPORTED, f"{first}-{last}", raw="IP pool with an unreadable range"
                )
            else:
                single = interval[1] == interval[2]
                self.p.addresses[address] = Address(
                    address,
                    AddressKind.NETWORK if single else AddressKind.RANGE,
                    f"{first}/32" if single else range_text(interval),
                    f"FortiOS IP pool {name}",
                )
            self.pools[name] = (address, SnatKind.DYNAMIC if pool_type == "one-to-one" else SnatKind.DYNAMIC_PORT)
            if pool_type not in ("overload", "one-to-one"):
                self.report.add(
                    "address",
                    address,
                    Severity.APPROX,
                    "POOL_TYPE",
                    f"IP pool type '{pool_type}' is converted as plain port address translation",
                )

    def _pool_translation(self, pool_names: List[str]) -> SourceNat:
        known = [self.pools[n] for n in pool_names if n in self.pools]
        kind = known[0][1] if known else SnatKind.DYNAMIC_PORT
        return SourceNat(kind, [address for address, _ in known] or pool_names)

    # -- policies ---------------------------------------------------------

    def _policies(self, central: bool) -> List[_PolicyInfo]:
        infos: List[_PolicyInfo] = []
        taken: Set[str] = set()
        for policy_id, block in self.section("firewall policy").entries.items():
            rule = Rule(name=_unique(block.get("name") or f"policy-{policy_id}", taken))
            rule.origin = rule.name
            rule.description = block.get("comments")
            uses_isdb = any(
                key.startswith("internet-service") and values not in _OFF_VALUES for key, values in block.settings.items()
            )
            for key in ("srcintf", "dstintf"):
                if not block.list(key):
                    rule.unsupported.append(f"policy without {key}")
            rule.src_zones = self._zones(block.list("srcintf"))
            rule.dst_zones = self._zones(block.list("dstintf"))

            src4, src6 = block.list("srcaddr"), block.list("srcaddr6")
            dst4, dst6 = block.list("dstaddr"), block.list("dstaddr6")
            if not uses_isdb:
                # FortiOS matches an IP version only when both sides name addresses of it.
                if bool(src6) != bool(dst6):
                    src6, dst6 = [], []
                    self._incomplete(rule, "IPv6")
                if bool(src4) != bool(dst4) and (src6 or dst6):
                    src4, dst4 = [], []
                    self._incomplete(rule, "IPv4")
            sources = [self._ref(m, False) for m in src4] + [self._ref(m, True) for m in src6]
            destinations = [self._ref(m, False) for m in dst4] + [self._ref(m, True) for m in dst6]
            if not sources and not uses_isdb:
                rule.unsupported.append("policy without a source address")
            if not destinations and not uses_isdb:
                rule.unsupported.append("policy without a destination address")
            rule.sources = _collapse(sources) or [ANY]
            rule.destinations = _collapse(destinations) or [ANY]
            rule.negate_source = self._negation(block, "srcaddr", src4, src6, rule)
            rule.negate_destination = self._negation(block, "dstaddr", dst4, dst6, rule)
            if rule.negate_source and rule.negate_destination and not (src4 and src6):
                # Negation covers both IP versions in the model; with both sides negated
                # nothing keeps a single-version policy to its version.
                rule.unsupported.append("source and destination both negated")
            self._simplify_any(rule)

            action = block.get("action", "deny")
            rule.action = Action.ALLOW if action == "accept" else Action.DROP
            if action not in ("accept", "deny"):
                rule.unsupported.append(f"policy action '{action}'")
            rule.enabled = block.get("status", "enable") != "disable"
            schedule = block.get("schedule", "always")
            rule.schedule = "" if schedule == "always" else schedule
            services = block.list("service")
            if not services and not uses_isdb:
                rule.unsupported.append("policy without a service")
            if not services or any(s in self.any_services or (s == "ALL" and s not in self.p.services) for s in services):
                rule.services = [ANY]
            else:
                rule.services = transform.dedupe([self.service_names.get(s, s) for s in services])
            rule.negate_service = block.get("service-negate") == "enable"
            rule.log_end = block.get("logtraffic", "utm" if action == "accept" else "disable") == "all"
            rule.log_start = block.get("logtraffic-start") == "enable"
            self._attributes(block, rule)

            for name in dst4:
                vip = self.vips.get(name)
                if vip and vip.portforward and vip.mappedport != vip.extport:
                    self.report.add(
                        "rule",
                        rule.origin,
                        Severity.REVIEW,
                        "NAT_PORT_TRANSLATION",
                        f"virtual IP '{name}' forwards port {vip.extport} to {vip.mappedport}; FortiOS policies "
                        "name the mapped port, the neutral model the original one. Check the service of this rule",
                    )
            self.p.rules.append(rule)
            nat = not central and action == "accept" and block.get("nat") == "enable"
            infos.append(_PolicyInfo(policy_id, block, rule, dst4, nat))
        return infos

    def _incomplete(self, rule: Rule, version: str) -> None:
        self.report.add(
            "rule",
            rule.origin,
            Severity.INFO,
            "INCOMPLETE_ADDRESS_PAIR",
            f"{version} addresses are set on one side of the policy only; it cannot match {version} and they were "
            "left out",
        )

    @staticmethod
    def _negation(block: Block, key: str, v4: List[str], v6: List[str], rule: Rule) -> bool:
        """The single negate flag of the model, from FortiOS's separate IPv4 and IPv6 flags."""
        negate4 = block.get(f"{key}-negate") == "enable"
        negate6 = block.get(f"{key}6-negate") == "enable"
        if v4 and v6:
            if negate4 != negate6:
                rule.unsupported.append(f"{key} negated for one IP version only")
            return negate4 and negate6
        return negate4 if v4 else negate6 if v6 else False

    def _attributes(self, block: Block, rule: Rule) -> None:
        noted: List[str] = []
        unknown: List[str] = []
        for key, values in block.settings.items():
            if key in _PROFILE_KEYS:
                if values and not (key == "ssl-ssh-profile" and values == ["no-inspection"]):
                    rule.profiles[key] = " ".join(values)
            elif key in _RESTRICTING_KEYS or key.startswith(_RESTRICTING_PREFIXES):
                # Only a number or an on/off switch can be "off"; a list of names always restricts.
                if key in _SWITCH_KEYS:
                    off = values in _OFF_VALUES
                elif key in _TOGGLE_KEYS:
                    off = values in ([], ["disable"])
                else:
                    off = not values
                if not off:
                    rule.unsupported.append(f"{key} {' '.join(values)}")
            elif key in _NOTED_KEYS:
                if values not in _OFF_VALUES:
                    noted.append(key)
            elif key not in _KNOWN_KEYS and values not in _OFF_VALUES:
                unknown.append(key)
            if key not in _MODELLED_KEYS and key not in _PROFILE_KEYS and values not in _OFF_VALUES:
                rule.handling[key] = " ".join(values)
        if noted:
            self.report.add(
                "rule",
                rule.origin,
                Severity.INFO,
                "ATTRIBUTES_IGNORED",
                "NAT attributes without an equivalent were ignored: " + ", ".join(sorted(noted)),
            )
        if unknown:
            self.report.add(
                "rule",
                rule.origin,
                Severity.REVIEW,
                "UNKNOWN_ATTRIBUTES",
                "policy attributes this converter does not know: "
                + ", ".join(sorted(unknown))
                + ". If one of them narrows what the policy matches, the converted rule is wider",
            )

    def _simplify_any(self, rule: Rule) -> None:
        """Use plain ``any`` where a single-family "all" cannot match the other IP version anyway.

        A side counts as able to match the other version when it holds such
        members, an FQDN (which other platforms resolve for both versions), or
        is negated (negation covers both versions in the model).
        """

        def capable(members: List[str], version: int, negated: bool) -> bool:
            return negated or any(version in self._model_families(m) for m in members)

        for literal, other in ((ANY_V4, 6), (ANY_V6, 4)):
            if rule.sources == [literal] and not rule.negate_source:
                if rule.destinations == [literal] and not rule.negate_destination:
                    rule.destinations = [ANY]  # the source side keeps the rule to one IP version
                elif not capable(rule.destinations, other, rule.negate_destination):
                    rule.sources = [ANY]
            elif rule.destinations == [literal] and not rule.negate_destination:
                if not capable(rule.sources, other, rule.negate_source):
                    rule.destinations = [ANY]

    def _model_families(self, member: str, _seen: Tuple[str, ...] = ()) -> Set[int]:
        """Like transform.families, but an FQDN counts for both IP versions."""
        address = self.p.addresses.get(member)
        if address is not None and address.kind == AddressKind.FQDN:
            return {4, 6}
        group = self.p.address_groups.get(member)
        if group is not None and member not in _seen:
            if member not in self.family_memo:
                out: Set[int] = set()
                for inner in group.members:
                    out |= self._model_families(inner, _seen + (member,))
                    if out == {4, 6}:
                        break
                self.family_memo[member] = out or {4}
            return self.family_memo[member]
        return transform.families(self.p, member)

    # -- NAT rules --------------------------------------------------------

    def _v4_members(self, members: List[str]) -> List[str]:
        out = [ANY if m in (ANY_V4, ANY) else m for m in members if 4 in transform.families(self.p, m)]
        return [ANY] if ANY in out else out

    def _policy_nat_rules(self, infos: List[_PolicyInfo]) -> Tuple[List[NatRule], List[NatRule]]:
        """Turn per-policy source NAT into an ordered NAT rulebase.

        NAT rules do not match on service, so a policy that passes overlapping
        traffic *without* NAT matters: an earlier one gets a no-NAT rule in
        front, where its addresses tell it apart; otherwise the overlap is reported.
        """
        combined: List[NatRule] = []
        snat: List[NatRule] = []
        exempted: Set[str] = set()
        plain = [i for i in infos if not i.nat and i.rule.action == Action.ALLOW and i.rule.enabled]
        for position, info in enumerate(infos):
            if not info.nat:
                continue
            new_combined, new_snat = self._policy_nat(info)
            combined += new_combined
            for nat in new_snat:
                for other in plain:
                    if not self._nat_overlap(other, nat):
                        continue
                    earlier = infos.index(other) < position
                    same = (
                        self._v4_members(other.rule.sources) == nat.sources
                        and self._plain_destinations(other) == nat.destinations
                    )
                    if earlier and not same:
                        if other.policy_id not in exempted:
                            exempted.add(other.policy_id)
                            snat.append(self._exemption(other))
                    elif earlier or info.rule.services != [ANY]:
                        self.report.add(
                            "nat",
                            self.nat_seen.get(self._nat_key(nat), nat.origin),
                            Severity.REVIEW,
                            "NAT_OVERLAP",
                            f"policy '{other.rule.name}' passes traffic between overlapping addresses without NAT, "
                            "for other services. NAT rules here do not match on service, so that traffic would be "
                            "translated too: add a no-NAT rule or narrow this one",
                        )
                key = self._nat_key(nat)
                if key in self.nat_seen:
                    self.report.add(
                        "nat",
                        self.nat_seen[key],
                        Severity.INFO,
                        "NAT_MERGED",
                        f"also covers the identical source NAT of policy {info.policy_id} ({info.rule.name})",
                    )
                    continue
                self.nat_seen[key] = nat.origin
                snat.append(nat)
        return combined, snat

    @staticmethod
    def _nat_key(nat: NatRule) -> Tuple[object, ...]:
        translation = nat.source_translation
        return (
            tuple(nat.src_zones),
            tuple(nat.dst_zones),
            tuple(nat.sources),
            tuple(nat.destinations),
            nat.service,
            translation.kind if translation else None,
            tuple(translation.addresses) if translation else (),
            translation.interface if translation else "",
            translation.interface_address if translation else "",
            nat.enabled,
            tuple(nat.unsupported),
        )

    def _plain_destinations(self, info: _PolicyInfo) -> List[str]:
        """IPv4 destinations of a policy that are not virtual IPs."""
        return self._v4_members([self._ref(n, False) for n in info.dst_names if n not in self.vips])

    def _nat_overlap(self, info: _PolicyInfo, nat: NatRule) -> bool:
        """Whether a policy without NAT passes traffic a derived NAT rule would translate."""

        def zones_meet(a: List[str], b: List[str]) -> bool:
            return ANY in a or ANY in b or bool(set(a) & set(b))

        def addresses_meet(a: List[str], b: List[str], negated: bool) -> bool:
            if negated:
                return True
            sets: List[List[Interval]] = []
            for members in (a, b):
                intervals: List[Interval] = []
                for member in members:
                    resolved = [FULL_V4] if member == ANY else transform.address_intervals(self.p, member)
                    if resolved is None:
                        return True  # FQDN and the like: assume it may overlap
                    intervals += resolved
                sets.append(intervals)
            return overlaps(sets[0], sets[1])

        rule = info.rule
        sources, destinations = self._v4_members(rule.sources), self._plain_destinations(info)
        if not sources or not destinations:
            return False
        return (
            zones_meet(rule.src_zones, nat.src_zones)
            and zones_meet(rule.dst_zones, nat.dst_zones)
            and addresses_meet(sources, nat.sources, rule.negate_source)
            and addresses_meet(destinations, nat.destinations, rule.negate_destination)
        )

    def _exemption(self, info: _PolicyInfo) -> NatRule:
        nat = NatRule(
            name=f"nonat-{info.policy_id}",
            src_zones=list(info.rule.src_zones),
            dst_zones=list(info.rule.dst_zones),
            sources=self._v4_members(info.rule.sources),
            destinations=self._plain_destinations(info),
            description=f"from FortiOS policy {info.policy_id} ({info.rule.name}), which does not translate",
        )
        nat.origin = nat.name
        if info.rule.negate_source or info.rule.negate_destination:
            nat.unsupported.append("no-NAT rule for a policy with a negated address match")
        self.report.add(
            "nat",
            nat.origin,
            Severity.APPROX,
            "NAT_EXEMPTION",
            f"no-NAT rule added for policy '{info.rule.name}', which passes this traffic untranslated although a "
            "later policy with NAT covers the same addresses; it applies to all services",
        )
        return nat

    def _policy_nat(self, info: _PolicyInfo) -> Tuple[List[NatRule], List[NatRule]]:
        """NAT rules of one policy with ``set nat enable``: (with destination NAT, source NAT only)."""
        rule, block = info.rule, info.block
        sources = self._v4_members(rule.sources)
        if not sources:
            return [], []
        use_pool = block.get("ippool") == "enable" and bool(block.list("poolname"))
        problems = []
        if rule.negate_source or rule.negate_destination:
            problems.append("source NAT of a policy with a negated address match")
        note = f"from FortiOS policy {info.policy_id} ({rule.name})"

        def finish(nat: NatRule) -> NatRule:
            nat.origin = nat.name
            nat.unsupported = list(problems)
            nat.enabled = rule.enabled
            nat.description = note
            return nat

        def translation_for(zone: str) -> SourceNat:
            return self._pool_translation(block.list("poolname")) if use_pool else self._egress(zone)

        combined: List[NatRule] = []
        for name in info.dst_names:
            vip = self.vips.get(name)
            if vip is None or vip.problems:
                continue
            service, port = self._vip_service(vip)
            combined.append(
                finish(
                    NatRule(
                        name=f"snat-{info.policy_id}-{name}",
                        src_zones=list(rule.src_zones),
                        dst_zones=[self._zone_of(vip.extintf)],
                        sources=list(sources),
                        destinations=[vip.address],
                        service=service,
                        source_translation=translation_for(rule.dst_zones[0] if len(rule.dst_zones) == 1 else ANY),
                        destination_translation=DestNat(vip.mapped, port),
                    )
                )
            )
        other = self._plain_destinations(info)
        if not other:
            return combined, []
        zone_sets = [list(rule.dst_zones)] if use_pool else [[zone] for zone in rule.dst_zones]
        snat = [
            finish(
                NatRule(
                    name=f"snat-{info.policy_id}" + (f"-{index + 1}" if len(zone_sets) > 1 else ""),
                    src_zones=list(rule.src_zones),
                    dst_zones=zones,
                    sources=list(sources),
                    destinations=list(other),
                    source_translation=translation_for(zones[0]),
                )
            )
            for index, zones in enumerate(zone_sets)
        ]
        return combined, snat

    def _vip_service(self, vip: _Vip) -> Tuple[str, str]:
        """(service matching the external port, translated port) of a port-forwarding VIP."""
        if not vip.portforward or not vip.extport:
            return ANY, ""
        if vip.name not in self.vip_services:
            name = _unique(f"{vip.address}-port", set(self.p.services) | set(self.p.service_groups))
            self.p.services[name] = Service(
                name, [ServiceEntry(Protocol(vip.protocol), dst_ports=vip.extport)], f"external port of VIP {vip.name}"
            )
            self.vip_services[vip.name] = name
        return self.vip_services[vip.name], ("" if vip.mappedport == vip.extport else vip.mappedport)

    def _vip_rules(self) -> List[NatRule]:
        out: List[NatRule] = []
        for vip in self.vips.values():
            if vip.problems:
                continue
            service, port = self._vip_service(vip)
            zone = self._zone_of(vip.extintf)  # a VIP applies to traffic arriving on its external interface
            nat = NatRule(
                name=vip.address,
                src_zones=[zone],
                dst_zones=[zone],
                sources=list(vip.src_filter) or [ANY],
                destinations=[vip.address],
                service=service,
                destination_translation=DestNat(vip.mapped, port),
            )
            nat.origin = nat.name
            if port and not is_number(port):
                nat.unsupported.append(f"translation of port range {vip.extport} to {vip.mappedport}")
            if not vip.portforward:
                self.report.add(
                    "nat",
                    nat.origin,
                    Severity.APPROX,
                    "VIP_REVERSE_NAT",
                    "FortiOS also source-translates sessions the mapped host opens (to the external IP) when the "
                    "outgoing policy has NAT enabled; that reverse direction is not converted",
                )
            out.append(nat)
        return out

    def _central_snat(self) -> List[NatRule]:
        out: List[NatRule] = []
        for entry_id, block in self.section("firewall central-snat-map").entries.items():
            nat = NatRule(name=f"central-snat-{entry_id}")
            nat.origin = nat.name
            nat.src_zones = self._zones(block.list("srcintf"))
            nat.dst_zones = self._zones(block.list("dstintf"))
            nat.sources = self._v4_members([self._ref(m, False) for m in block.list("orig-addr")]) or [ANY]
            nat.destinations = self._v4_members([self._ref(m, False) for m in block.list("dst-addr")]) or [ANY]
            nat.enabled = block.get("status", "enable") != "disable"
            nat.description = block.get("comments")
            if block.get("type", "ipv4") != "ipv4":
                nat.unsupported.append("IPv6 central SNAT entry")
            if block.get("protocol", "0") != "0":
                nat.unsupported.append("central SNAT entry limited to a protocol or port")
            if block.get("nat", "enable") == "enable":
                pools = block.list("nat-ippool")
                if pools:
                    nat.source_translation = self._pool_translation(pools)
                else:
                    nat.source_translation = self._egress(nat.dst_zones[0] if len(nat.dst_zones) == 1 else ANY)
            out.append(nat)
        return out

    def _deny_and_vips(self, infos: List[_PolicyInfo]) -> None:
        """Report deny policies that FortiOS does not apply to virtual-IP traffic.

        Without ``set match-vip enable`` (the default before FortiOS 7.2.3) a deny
        policy does not match traffic translated by a virtual IP unless it names
        the VIP; a converted deny rule covering the address always matches.
        """
        vips = [vip for vip in self.vips.values() if not vip.problems]
        for info in infos:
            rule = info.rule
            if rule.action == Action.ALLOW or info.block.get("match-vip") == "enable" or rule.negate_destination:
                continue
            affected: List[str] = []
            for vip in vips:
                if vip.name in info.dst_names:
                    continue
                zone = self._zone_of(vip.extintf)
                if zone != ANY and ANY not in rule.src_zones and zone not in rule.src_zones:
                    continue
                external = transform.address_intervals(self.p, vip.address) or []
                mapped = parse_literal(vip.mapped)
                covered: List[Interval] = []
                for member in rule.destinations:
                    covered += [FULL_V4] if member == ANY else transform.address_intervals(self.p, member) or []
                if overlaps(covered, external) or (mapped is not None and overlaps(covered, [mapped])):
                    affected.append(vip.name)
            if affected:
                self.report.add(
                    "rule",
                    rule.origin,
                    Severity.APPROX,
                    "DENY_AND_VIP",
                    "FortiOS applies a deny policy to virtual-IP traffic only with 'set match-vip enable' (the "
                    "default from 7.2.3 on); the converted rule always applies to traffic for "
                    + ", ".join(affected)
                    + " and may block what the source let through to a later policy",
                )
