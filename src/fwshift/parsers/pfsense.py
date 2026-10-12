# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""pfSense parser: ``config.xml`` (pfSense CE 2.6 and later, pfSense Plus of the same years) -> neutral model.

What an administrator has is the file of *Diagnostics > Backup & Restore*. It holds no ruleset:
pfSense writes the ruleset of pf from it at every change. This parser follows the code that does
that (``filter.inc``), and what pf does with the result. How that differs from the model:

* Rules are bound to the interface traffic arrives on; none names the interface it leaves by. An
  interface is a zone here, named by its description as the web interface shows it.
* The rules of an interface are first match ("quick"). Floating rules come before them, rules of
  interface groups in between. A floating rule that is not "quick" is last match: it decides only
  where no quick rule matched, and of several such rules the last one. It is put where it takes
  effect: behind the rules of the interfaces, the last one first.
* A floating rule for outgoing traffic is looked at when the packet leaves: after the rules of the
  arrival interface allowed it, and after outbound NAT. Blocking ones become rules for the
  destination zone at the top; passing ones decide nothing for forwarded traffic.
* A rule without ``ipprotocol`` is an IPv4 rule. With "Allow IPv6" switched off nothing of IPv6
  passes, whatever the rules say.
* pfSense does not load a rule it cannot resolve (an alias that is gone, an interface that is not
  enabled, an address of the firewall it does not have). Such a rule is reported and left out.
* Port forwards and 1:1 NAT are applied before the rules, which therefore name the translated
  destination; outbound NAT after them. The rules are rewritten to the original destination, as
  for every platform of that kind (``lookup_after_dnat``).
* What pfSense does without a rule is converted where it decides about forwarded traffic and can
  be known: "Block private networks" of an interface, a port forward that passes its own traffic,
  automatic outbound NAT. The rest is named in a note.
"""

from __future__ import annotations

import copy
import dataclasses
import html
import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from .. import transform, xmlread
from ..errors import FwshiftError, ParseError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
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
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import parse_literal
from ..report import Report, Severity

IPInterface = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]

KEY = re.compile(r"(wan|lan|opt[0-9]+)")
# Interfaces that are no assigned interface: what arrives through a tunnel or from a dial-in client.
SYSTEM_GROUPS = {"l2tp": "L2TP", "pppoe": "PPPoE", "enc0": "IPsec", "openvpn": "OpenVPN"}
# The protocols a rule can name besides TCP, UDP and ICMP, with their numbers.
PROTOCOLS = {
    "esp": 50, "ah": 51, "gre": 47, "etherip": 97, "ipv6": 41, "igmp": 2, "pim": 103, "ospf": 89, "carp": 112,
    "pfsync": 249,
}  # fmt: skip
PORT_PROTOCOLS = {"tcp": [Protocol.TCP], "udp": [Protocol.UDP], "tcp/udp": [Protocol.TCP, Protocol.UDP], "sctp": [Protocol.SCTP]}
# The names pf has for ICMP types (pfctl_parser.c), as far as pfSense offers them.
ICMP_TYPES = {
    "echorep": 0, "unreach": 3, "squench": 4, "redir": 5, "althost": 6, "echoreq": 8, "routeradv": 9, "routersol": 10,
    "timex": 11, "paramprob": 12, "timereq": 13, "timerep": 14, "inforeq": 15, "inforep": 16, "maskreq": 17,
    "maskrep": 18, "trace": 30, "dataconv": 31, "mobredir": 32, "ipv6-where": 33, "ipv6-here": 34, "mobregreq": 35,
    "mobregrep": 36, "skip": 39, "photuris": 40,
}  # fmt: skip
ICMP6_TYPES = {
    "unreach": 1, "toobig": 2, "timex": 3, "paramprob": 4, "echoreq": 128, "echorep": 129, "groupqry": 130,
    "listqry": 130, "grouprep": 131, "listenrep": 131, "groupterm": 132, "listendone": 132, "routersol": 133,
    "routeradv": 134, "neighbrsol": 135, "neighbradv": 136, "redir": 137, "routrrenum": 138, "wrureq": 139,
    "wrurep": 140, "fqdnreq": 139, "fqdnrep": 140, "niqry": 139, "nirep": 140, "mtraceresp": 200, "mtrace": 201,
}  # fmt: skip
# Service names pf takes for a port, as /etc/services of FreeBSD has them (the numbers of the IANA registry). A name
# that is not here is reported, not guessed.
SERVICE_PORTS = {
    "echo": 7, "discard": 9, "daytime": 13, "chargen": 19, "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
    "time": 37, "nameserver": 42, "whois": 43, "domain": 53, "tftp": 69, "gopher": 70, "finger": 79, "http": 80, "www": 80,
    "kerberos": 88, "pop3": 110, "sunrpc": 111, "auth": 113, "nntp": 119, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138,
    "netbios-ssn": 139, "imap": 143, "snmp": 161, "snmptrap": 162, "bgp": 179, "irc": 194, "ldap": 389, "https": 443,
    "microsoft-ds": 445, "kpasswd": 464, "smtps": 465, "submissions": 465, "isakmp": 500, "syslog": 514, "printer": 515,
    "submission": 587, "ldaps": 636, "rsync": 873, "ftps": 990, "imaps": 993, "pop3s": 995, "openvpn": 1194, "ms-sql-s": 1433,
    "radius": 1812, "radius-acct": 1813, "nfsd": 2049, "mysql": 3306, "ms-wbt-server": 3389, "svn": 3690, "ipsec-nat-t": 4500,
    "sip": 5060, "sip-tls": 5061, "xmpp-client": 5222, "postgresql": 5432, "http-alt": 8080,
}  # fmt: skip
# "Block private networks and loopback addresses" of an interface (filter.inc).
PRIVATE_NETWORKS = ["10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
_HOST_NAME = re.compile(r"(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])", re.I)
_DYNAMIC4 = ("dhcp", "pppoe", "pptp", "l2tp", "ppp")
_DYNAMIC6 = ("dhcp6", "slaac", "6rd", "6to4", "track6")
# What a rule can say that this parser reads; anything else that is set is reported.
_NARROWING = {
    "os": "operating system of the sender (os)",
    "tagged": "a mark set by another rule (tagged)",
    "dscp": "DiffServ code point (dscp)",
    "vlanprio": "VLAN priority (vlanprio)",
    "tcpflags1": "TCP flags of its own (tcpflags)",
    "tcpflags2": "TCP flags of its own (tcpflags)",
}
_HANDLING = (
    "gateway", "statetype", "statepolicy", "tag", "max", "max-src-nodes", "max-src-conn", "max-src-states",
    "statetimeout", "max-src-conn-rate", "max-src-conn-rates", "defaultqueue", "ackqueue", "dnpipe", "pdnpipe",
    "vlanprioset", "tcpflags_any", "allowopts", "disablereplyto",
)  # fmt: skip


class _Unreadable(Exception):
    """Something pfSense loads and FWShift cannot read: the rule is kept, and cannot be used."""


def looks_like_pfsense(data: bytes) -> bool:
    """XML whose first element is ``<pfsense>`` (or ``<opnsense>``, which gets an answer of its own)."""
    head = data[:8192].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    head = re.sub(rb"<\?.*?\?>|<!--.*?-->", b"", head, flags=re.S).lstrip()
    return head.startswith((b"<pfsense>", b"<pfsense ", b"<opnsense>", b"<opnsense "))


def parse(data: bytes, report: Report, interface_addresses: Sequence[str] = ()) -> Policy:
    root = xmlread.fromstring(data, "the configuration files of pfSense")
    for element in root.iter():
        if isinstance(element.tag, str):
            element.tag = element.tag.lower()  # as pfSense reads them
    if root.tag == "opnsense":
        raise ParseError(
            "this is the configuration of an OPNsense firewall. OPNsense keeps its aliases, its automatic rules and "
            "parts of its NAT in other places than pfSense does, and FWShift does not read it yet"
        )
    if root.tag != "pfsense":
        raise ParseError(f"not a pfSense configuration: the first element is <{str(root.tag)[:40]}>, not <pfsense>")
    return _Reader(root, report, interface_addresses).build()


def _children(node: Optional[ET.Element], name: str) -> List[ET.Element]:
    return [] if node is None else [child for child in node if child.tag == name]


def _child(node: Optional[ET.Element], name: str) -> Optional[ET.Element]:
    found = _children(node, name)
    if len(found) > 1:
        # pfSense stops reading at such a file ("cannot occur more than once"): nothing can be said about it.
        raise ParseError(
            f"<{name}> occurs {len(found)} times in one <{node.tag if node is not None else ''}>, where it can be there "
            "once: pfSense does not read such a file, and neither does FWShift"
        )
    return found[0] if found else None


def _clean(text: Optional[str]) -> str:
    # Text is entity-encoded a second time by pfSense, also inside CDATA.
    return html.unescape(text or "").strip()


def _text(node: Optional[ET.Element], name: str) -> str:
    child = _child(node, name)
    return "" if child is None else _clean(child.text)


def _has(node: Optional[ET.Element], name: str) -> bool:
    return _child(node, name) is not None


def _short(text: str, limit: int = 60) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


@dataclass
class _Interface:
    key: str
    zone: str  # the description, as the web interface shows it
    enabled: bool = True
    device: str = ""
    kind4: str = ""  # how the address is obtained when it is not in the file (dhcp, pppoe, ...)
    kind6: str = ""
    net4: Optional[IPInterface] = None
    net6: Optional[IPInterface] = None
    gateway: bool = False  # a WAN-type interface: pfSense translates what leaves by it, and adds no NAT reflection
    blockpriv: bool = False
    blockbogons: bool = False
    vips: List[Tuple[IPInterface, str]] = field(default_factory=list)  # (address with prefix length, mode)

    def net(self, family: int) -> Optional[IPInterface]:
        return self.net4 if family == 4 else self.net6

    def kind(self, family: int) -> str:
        return self.kind4 if family == 4 else self.kind6


@dataclass
class _Side:
    """The source or the destination of a rule, for one IP version."""

    members: List[str] = field(default_factory=list)
    negated: bool = False
    missing: str = ""  # why pfSense does not load a rule with this side
    problem: str = ""  # why it cannot be converted
    port: str = ""
    note: str = ""  # what the reader of the report should know about it


@dataclass
class _Half:
    """What a rule is for one IP version."""

    family: int
    sources: List[str] = field(default_factory=list)
    destinations: List[str] = field(default_factory=list)
    negate_source: bool = False
    negate_destination: bool = False
    services: List[str] = field(default_factory=list)
    missing: str = ""
    problems: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class _Read:
    """A rule of the file with what decides where it goes."""

    rules: List[Rule]
    zones: List[str]  # the interfaces it is for, "any" for all
    floating: bool = False
    quick: bool = True
    direction: str = "in"
    tier: str = ""  # for a rule of a group: the group; "" for a rule of an interface
    position: int = 0


class _Reader:
    def __init__(self, root: ET.Element, report: Report, interface_addresses: Sequence[str]) -> None:
        self.root, self.report = root, report
        self.p = Policy(vendor="pfsense", lookup_after_dnat=True)
        self.p.default_interzone = self.p.default_intrazone = Action.DENY
        try:
            self.version = float(_text(root, "version") or 0)
        except ValueError:
            self.version = 0.0
        self.system = _child(root, "system")
        self.ipv6 = _has(self.system, "ipv6allow")
        self.interfaces: Dict[str, _Interface] = {}
        self.groups: Dict[str, List[str]] = {}  # interface group -> keys of its members
        self.address_aliases: Dict[str, str] = {}  # name -> type
        self.port_aliases: Dict[str, Optional[List[str]]] = {}  # name -> entries, None when they cannot be read
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.service_alias_use: Dict[str, Tuple[object, ...]] = {}
        self.views: Dict[Tuple[str, int], Optional[str]] = {}
        self.not_loaded: List[str] = []
        self.ipv6_dropped = 0
        self.pass_rules: List[Rule] = []  # for port forwards that pass their own traffic
        self.out_blocks: Set[str] = set()  # origins of the rules that block traffic when it leaves
        self.given = self._given(interface_addresses)

    # -- what the caller says about addresses that are not in the file -------------------------

    @staticmethod
    def _given(values: Sequence[str]) -> Dict[str, List[IPInterface]]:
        out: Dict[str, List[IPInterface]] = {}
        for value in values:
            name, sep, text = value.partition("=")
            try:
                if not sep or not name.strip() or "/" not in text:
                    raise ValueError
                address = ipaddress.ip_interface(text.strip())
            except ValueError:
                raise FwshiftError(
                    f"--interface-address: '{_short(value, 60)}' is not INTERFACE=ADDRESS/BITS (for example "
                    "wan=198.51.100.2/24)"
                ) from None
            given = out.setdefault(name.strip().lower(), [])
            if any(other.version == address.version for other in given):
                raise FwshiftError(f"--interface-address: two IPv{address.version} addresses for '{_short(name.strip(), 30)}'")
            given.append(address)
        return out

    # -- reading -------------------------------------------------------------------------------

    def build(self) -> Policy:
        self._interfaces()
        self._aliases()
        nat = self._nat()
        rules = self._rules()
        self.p.nat_rules = nat
        # A port forward that passes its own traffic does so whatever the rules of the interface say; only what
        # blocks traffic when it leaves still applies to it.
        leaving = sum(1 for rule in rules if rule.origin in self.out_blocks)
        self.p.rules = rules[:leaving] + self.pass_rules + rules[leaving:]
        for interface in self.interfaces.values():
            if interface.enabled:
                self.p.zones.setdefault(interface.zone, Zone(interface.zone, [interface.key]))
        for zone in transform.dedupe(
            [z for r in list(self.p.rules) + list(self.p.nat_rules) + self.pass_rules for z in r.src_zones + r.dst_zones if z != ANY]
        ):
            self.p.zones.setdefault(zone, Zone(zone, []))
        # The rules see the translated destination of a port forward; the model matches the original one.
        transform.rewrite_destinations(self.p, self.report, to_post_nat=False)
        self._notes()
        return self.p

    def _unique(self, name: str, taken: Set[str]) -> str:
        name = " ".join(name.split()) or "unnamed"
        candidate, counter = name, 2
        while candidate in taken:
            candidate = f"{name} {counter}"
            counter += 1
        taken.add(candidate)
        return candidate

    # -- interfaces ----------------------------------------------------------------------------

    def _interfaces(self) -> None:
        zones: Set[str] = set()
        section = _child(self.root, "interfaces")
        for node in list(section) if section is not None else []:
            key = str(node.tag)
            if not KEY.fullmatch(key):
                continue
            descr = re.sub(r"[^A-Za-z0-9_]", "", _text(node, "descr")) or key.upper()
            if descr.lower() in zones:
                descr = key.upper()  # pfSense does not let two interfaces share a description
            while descr.lower() in zones:
                descr = f"{descr}_{key}"
            zones.add(descr.lower())
            interface = _Interface(key, descr, enabled=_has(node, "enable"))
            address, address6 = _text(node, "ipaddr"), _text(node, "ipaddrv6")
            interface.net4 = self._interface_address(address, _text(node, "subnet"), 4)
            interface.net6 = self._interface_address(address6, _text(node, "subnetv6"), 6)
            interface.kind4 = address.lower() if interface.net4 is None and address else ""
            interface.kind6 = address6.lower() if interface.net6 is None and address6 else ""
            device = interface.device = _text(node, "if")
            # interface_has_gateway(): a gateway set, an address by DHCP, PPP of any kind, a tunnel interface, or a
            # GIF or GRE tunnel with an address.
            interface.gateway = (
                bool(_text(node, "gateway")) or interface.kind4 in _DYNAMIC4 or device.startswith(("ovpn", "ipsec"))
                or (device.startswith(("gif", "gre")) and interface.net4 is not None)
            )  # fmt: skip
            interface.blockpriv, interface.blockbogons = _has(node, "blockpriv"), _has(node, "blockbogons")
            self.interfaces[key] = interface
        used: Set[str] = set()
        for interface in self.interfaces.values():
            for name in (interface.key, interface.zone.lower()):
                for given in self.given.get(name, []):
                    used.add(name)
                    if given.version == 4:
                        interface.net4, interface.kind4 = given, ""
                    else:
                        interface.net6, interface.kind6 = given, ""
        unknown = sorted(set(self.given) - used)
        if unknown:
            raise FwshiftError(
                "--interface-address: no interface '" + "', '".join(_short(name, 30) for name in unknown)
                + "' in the configuration; it has " + (", ".join(f"{i.key} ({i.zone})" for i in self.interfaces.values()) or "none")
            )
        vips = _children(_child(self.root, "virtualip"), "vip")
        parents = {f"_vip{_text(vip, 'uniqid')}": _text(vip, "interface") for vip in vips if _text(vip, "uniqid")}
        for vip in vips:
            # An IP alias on a CARP address names that address ("_vip<uniqid>") as its interface.
            owner = self.interfaces.get(parents.get(_text(vip, "interface"), _text(vip, "interface")))
            bits = _text(vip, "subnet_bits")
            try:
                host = ipaddress.ip_address(_text(vip, "subnet"))
                value = ipaddress.ip_interface(f"{host}/{bits or host.max_prefixlen}")
            except ValueError:
                continue
            if owner is not None:
                owner.vips.append((value, _text(vip, "mode").lower()))
        for entry in _children(_child(self.root, "ifgroups"), "ifgroupentry"):
            name = _text(entry, "ifname")
            if name:
                self.groups[name] = [key for key in _text(entry, "members").split() if key in self.interfaces]

    @staticmethod
    def _interface_address(address: str, bits: str, family: int) -> Optional[IPInterface]:
        try:
            value = ipaddress.ip_interface(f"{address}/{bits}" if bits else address)
        except ValueError:
            return None
        return value if value.version == family and bits else None

    def _zone(self, key: str) -> Optional[str]:
        """The zone of an interface a rule names, or None when pfSense has no such interface to put a rule on."""
        interface = self.interfaces.get(key)
        if interface is not None:
            return interface.zone if interface.enabled else None
        if key in SYSTEM_GROUPS and self._service_configured(key):
            return SYSTEM_GROUPS[key]
        return None

    def _service_configured(self, key: str) -> bool:
        if key == "enc0":
            return any(not _has(phase, "disabled") for phase in _children(_child(self.root, "ipsec"), "phase1"))
        if key == "openvpn":
            section = _child(self.root, "openvpn")
            return bool(_children(section, "openvpn-server") or _children(section, "openvpn-client"))
        if key == "l2tp":
            return _text(_child(self.root, "l2tp"), "mode") == "server"
        return any(_text(server, "mode") == "server" for server in _children(_child(self.root, "pppoes"), "pppoe"))

    def _zones_of(self, key: str) -> List[str]:
        """The zones a rule on an interface, a group or one of the tunnel interfaces is for."""
        if key in self.groups:
            return transform.dedupe([i.zone for i in map(self.interfaces.get, self.groups[key]) if i is not None and i.enabled])
        zone = self._zone(key)
        return [zone] if zone else []

    # -- aliases -------------------------------------------------------------------------------

    def _aliases(self) -> None:
        raw: Dict[str, Tuple[str, List[str], str]] = {}
        for alias in _children(_child(self.root, "aliases"), "alias"):
            name = _text(alias, "name")
            if name:
                raw[name] = (_text(alias, "type").lower(), _text(alias, "address").split(), _text(alias, "descr"))
        for name, (kind, entries, _) in raw.items():
            if kind in ("port", "url_ports"):
                self.port_aliases[name] = entries
            elif kind == "urltable_ports":
                self.port_aliases[name] = None
            else:
                self.address_aliases[name] = kind
        for name, (kind, entries, descr) in raw.items():
            if name not in self.address_aliases:
                continue
            group = AddressGroup(name, description=descr)
            self.p.address_groups[name] = group
            if kind == "urltable":
                group.unsupported = "a URL table: its addresses are in a file on the firewall, not in the configuration"
                continue
            if kind not in ("host", "network", "url"):
                group.unsupported = f"an alias of type '{_short(kind, 30)}', which FWShift does not know"
                continue
            for entry in entries:
                member, problem = self._alias_entry(entry)
                if problem and not group.unsupported:
                    group.unsupported = f"its entry '{_short(entry, 40)}' is {problem}"
                elif member and member not in group.members:
                    group.members.append(member)
        # What no walk can follow: too deep, or round in circles of many aliases (as transform.harden sees it).
        listed = {name: group.members for name, group in self.p.address_groups.items()}
        circular = transform._circular(listed)
        for name in transform._deep(listed) + (circular if len(circular) > transform.MAX_NESTING else []):
            group = self.p.address_groups[name]
            group.unsupported, group.members = f"aliases nested more than {transform.MAX_NESTING} deep, or in a circle", []

    def _alias_entry(self, entry: str) -> Tuple[str, str]:
        """(member, "") for an entry of a host or network alias, or ("", what is wrong with it)."""
        try:
            return str(ipaddress.ip_address(entry)), ""
        except ValueError:
            pass
        if "/" in entry:
            try:
                return str(ipaddress.ip_network(entry, strict=False)), ""
            except ValueError:
                return "", "not a network"
        if entry in self.address_aliases:
            return entry, ""
        if entry in self.port_aliases:
            return "", "an alias of ports"
        if parse_literal(entry) is not None or re.fullmatch(r"[0-9.:]+", entry):
            # The web interface writes a range out as addresses. One written by hand is taken for a host name.
            return "", "neither an address nor a host name pfSense could resolve"
        if not _HOST_NAME.fullmatch(entry):
            return "", "neither an address nor a host name"
        name = entry if entry not in self.p.address_groups and entry not in self.port_aliases else f"host {entry}"
        self.p.addresses.setdefault(name, Address(name, AddressKind.FQDN, entry.rstrip(".").lower()))
        return name, ""

    def _ports(self, text: str, _seen: Tuple[str, ...] = ()) -> Tuple[Optional[str], str]:
        """(ports in the syntax of the model, "") for a port, a range or an alias of ports; "" is every port.
        (None, why) when pfSense has no ports for it. Raises _Unreadable for ports pfSense has and FWShift cannot read."""
        text = text.strip()
        if not text:
            return "", ""
        if text in self.port_aliases:
            entries = self.port_aliases[text]
            if entries is None:
                raise _Unreadable(f"alias '{_short(text, 40)}' is a URL table of ports, which is not in the configuration")
            if text in _seen:
                return None, f"alias '{_short(text, 40)}' holds itself"
            if len(_seen) > transform.MAX_NESTING:
                raise _Unreadable(f"alias '{_short(text, 40)}' is nested more than {transform.MAX_NESTING} deep")
            found: List[str] = []
            for entry in entries:
                ports, why = self._ports(entry, _seen + (text,))
                if ports is None:
                    return None, why
                found += [port for port in (ports.split(",") if ports else ["1-65535"]) if port not in found]
            if not found:
                return None, f"alias '{_short(text, 40)}' is empty"
            return ",".join(found), ""
        if text in SERVICE_PORTS or re.fullmatch(r"[a-z][a-z0-9-]*", text):
            # A service name, which pf looks up in /etc/services.
            if text not in SERVICE_PORTS:
                raise _Unreadable(f"port '{_short(text, 40)}' is a service name FWShift has no number for")
            return str(SERVICE_PORTS[text]), ""
        first, _, last = text.replace(":", "-").partition("-")
        if first.isdigit() and (not last or last.isdigit()) and len(first) < 6 and len(last) < 6:
            low, high = int(first), int(last or first)
            if low > high:
                # The web interface turns such a range round; pf, given it as it is, matches no port.
                return None, f"port range '{_short(text, 20)}' runs backwards and matches no port"
            if 1 <= low and high <= 65535:
                if (low, high) == (1, 65535):
                    return "", ""
                return (str(low) if low == high else f"{low}-{high}"), ""
        return None, f"'{_short(text, 40)}' is neither a port nor an alias of ports"

    # -- objects for what the firewall itself is -----------------------------------------------

    def _suffix(self, family: int) -> str:
        return " IPv6" if family == 6 else ""

    def _address_object(self, key: str, family: int) -> Tuple[str, str]:
        """(object for the address of an interface, "") or ("", why there is none)."""
        interface = self.interfaces.get(key)
        if interface is None or not interface.enabled:
            return "", f"interface '{_short(key, 30)}' is not there or not enabled"
        name = f"{interface.zone} address{self._suffix(family)}"
        if name in self.p.addresses:
            return name, ""
        value = interface.net(family)
        if value is not None:
            self.p.addresses[name] = Address(
                name, AddressKind.NETWORK, f"{value.ip}/{value.max_prefixlen}",
                f"address of interface {interface.zone} in the configuration", raw=f"interface {interface.zone}",
                builtin="pfsense",
            )  # fmt: skip
        elif interface.kind(family):
            self.p.addresses[name] = Address(
                name, AddressKind.UNSUPPORTED, "", raw=f"the IPv{family} address of interface {interface.zone} is not in "
                f"the configuration ({interface.kind(family)}); give it with --interface-address", builtin="pfsense",
                fqdn_family=family,
            )  # fmt: skip
        else:
            return "", f"interface {interface.zone} has no IPv{family} address"
        return name, ""

    def _networks(self, interface: _Interface, family: int) -> List[str]:
        """The subnet of an interface and those of its virtual addresses that lie outside it."""
        found: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        value = interface.net(family)
        if value is not None:
            found.append(value.network)
        for vip, _ in interface.vips:
            if vip.version == family and not any(vip.ip in network for network in found):
                found.append(vip.network)
        return [str(network) for network in found]

    def _network_object(self, key: str, family: int) -> Tuple[str, str]:
        """(object for the networks of an interface or of the members of a group, "") or ("", why there is none)."""
        if key in self.groups:
            members = [m for m in (self._network_object(k, family)[0] for k in self.groups[key]) if m]
            if not members:
                return "", f"no interface of group '{_short(key, 30)}' has an IPv{family} network"
            name = f"{key} net{self._suffix(family)}"
            self.p.address_groups.setdefault(
                name, AddressGroup(name, members, f"networks of the interfaces of group {key}", builtin="pfsense")
            )
            return name, ""
        interface = self.interfaces.get(key)
        if interface is None or not interface.enabled:
            return "", f"interface '{_short(key, 30)}' is not there or not enabled"
        name = f"{interface.zone} net{self._suffix(family)}"
        if name in self.p.addresses or name in self.p.address_groups:
            return name, ""
        networks = self._networks(interface, family)
        described = f"network of interface {interface.zone} in the configuration"
        if interface.kind(family) and interface.net(family) is None:
            self.p.addresses[name] = Address(
                name, AddressKind.UNSUPPORTED, "", raw=f"the IPv{family} network of interface {interface.zone} is not in "
                f"the configuration ({interface.kind(family)}); give it with --interface-address", builtin="pfsense",
                fqdn_family=family,
            )  # fmt: skip
        elif not networks:
            return "", f"interface {interface.zone} has no IPv{family} network"
        elif len(networks) == 1:
            self.p.addresses[name] = Address(
                name, AddressKind.NETWORK, networks[0], described, raw=f"network {interface.zone}", builtin="pfsense",
            )  # fmt: skip
        else:
            self.p.address_groups[name] = AddressGroup(
                name, networks, described + ", with the networks of its virtual addresses", builtin="pfsense"
            )
        return name, ""

    def _self_object(self, family: int) -> str:
        """The addresses of the firewall itself: "This Firewall (self)"."""
        name = f"This Firewall{self._suffix(family)}"
        if name in self.p.address_groups:
            return name
        members: List[str] = []
        unknown: List[str] = []
        for interface in self.interfaces.values():
            if not interface.enabled:
                continue
            value = interface.net(family)
            if value is not None:
                members.append(str(value.ip))
            elif interface.kind(family):
                unknown.append(f"{interface.zone} ({interface.kind(family)})")
            members += [str(vip.ip) for vip, mode in interface.vips if vip.version == family and mode in ("carp", "ipalias")]
        group = AddressGroup(name, transform.dedupe(members), "the addresses of the firewall itself in the configuration", builtin="pfsense")
        if unknown:
            group.unsupported = (
                f"the IPv{family} address of " + ", ".join(unknown) + " is not in the configuration; give it with "
                "--interface-address"
            )
        elif not members:
            group.unsupported = f"the firewall has no IPv{family} address in the configuration"
        self.p.address_groups[name] = group
        return name

    # -- one side of a rule --------------------------------------------------------------------

    def _side(self, node: Optional[ET.Element], family: int) -> _Side:
        side = _Side(negated=_has(node, "not"), port=_text(node, "port"))
        every = ANY_V4 if family == 4 else ANY_V6
        if node is None:
            side.missing = "it has no address"
        elif _has(node, "any"):
            side.members = [every]
            if side.negated:
                side.problem = "'not any'"
        elif _text(node, "network"):
            self._network(side, _text(node, "network"), family)
        elif _text(node, "address"):
            self._address(side, _text(node, "address"), family)
        else:
            side.missing = "it has no address"
        return side

    def _network(self, side: _Side, word: str, family: int) -> None:
        name, why = "", ""
        if word == "(self)":
            name = self._self_object(family)
        elif word in ("pppoe", "l2tp", "pptp", "openvpn"):
            side.problem = f"the addresses of the {word} clients, which are not in the configuration"
            return
        elif word in self.groups or KEY.fullmatch(word):
            name, why = self._network_object(word, family)
            members = self.groups.get(word, [word])
            interfaces = [i for i in map(self.interfaces.get, members) if i is not None and i.enabled]
            other = any(self._networks(i, 10 - family) for i in interfaces)
            newer = self.version > 23.3 or not self.version
            if not name and other and newer:
                # After 2.7.2 pfSense names one table for both IP versions: it holds nothing of this one.
                if side.negated:
                    side.members, side.negated = [ANY_V4 if family == 4 else ANY_V6], False
                    return
                why = f"{why}; the rule matches nothing of IPv{family} there"
            old_list = self.version and (self.version <= 22.2 or (self.version <= 23.3 and family == 6 and word in ("wan", "lan")))
            if name and side.negated and old_list and word not in self.groups and len(self._networks(interfaces[0], family)) > 1:
                # Up to pfSense 2.7 the networks of an interface are a list here, and "not" of a list in pf is each
                # address left out on its own: every address passes one of them.
                side.members, side.negated = [ANY_V4 if family == 4 else ANY_V6], False
                side.note = (
                    f"'not {word}' names the network of the interface and those of its virtual addresses: pf reads 'not' "
                    "of such a list as every address, and so does the converted rule"
                )
                return
        elif word.endswith("ip") and KEY.fullmatch(word[:-2]):
            name, why = self._address_object(word[:-2], family)
        else:
            why = f"'{_short(word, 40)}' is no network pfSense knows"
        if name:
            side.members = [name]
        else:
            side.missing = why

    def _address(self, side: _Side, text: str, family: int) -> None:
        if text.startswith("::") and family == 6 and "/" not in text and text != "::1":
            side.problem = "an address that is completed with the prefix the provider delegates"
            return
        literal: Optional[str] = None
        try:
            literal = str(ipaddress.ip_address(text))
        except ValueError:
            if "/" in text:
                try:
                    literal = str(ipaddress.ip_network(text, strict=False))
                except ValueError:
                    pass
        if literal is not None:
            if (6 if ":" in literal else 4) != family:
                side.missing = f"'{literal}' is not an IPv{family} address"
            else:
                side.members = [literal]
        elif text in self.address_aliases:
            side.members = [text]
        else:
            side.missing = f"alias '{_short(text, 40)}' cannot be resolved"

    # -- services ------------------------------------------------------------------------------

    def _service_object(self, name: str, entries: List[ServiceEntry], description: str = "") -> str:
        key = [dataclasses.astuple(entry) for entry in entries]
        candidate, counter = name, 2
        while True:
            existing = self.p.services.get(candidate)
            if existing is None:
                self.p.services[candidate] = Service(candidate, list(entries), description, builtin="pfsense")
                return candidate
            if [dataclasses.astuple(entry) for entry in existing.entries] == key:
                return candidate
            candidate = f"{name}-{counter}"
            counter += 1

    def _service(self, node: ET.Element, family: int, source: _Side, destination: _Side) -> Tuple[str, str, str]:
        """(service, why pfSense does not load the rule, why it cannot be converted)."""
        protocol = _text(node, "protocol").lower()
        if not protocol and (source.port or destination.port):
            # filter.inc makes such a rule one for TCP, and writes its port only for a protocol that has ports.
            return self._service_object("tcp", [ServiceEntry(Protocol.TCP)]), "", ""
        if protocol in ("", "any"):
            return ANY, "", ""
        if protocol in PORT_PROTOCOLS:
            try:
                src, why = self._ports(source.port)
                if src is None:
                    return "", f"source port: {why}", ""
                dst, why = self._ports(destination.port)
                if dst is None:
                    return "", f"destination port: {why}", ""
            except _Unreadable as error:
                return "", "", str(error)
            label = protocol.replace("/", "-")
            entries = [ServiceEntry(p, dst, src) for p in PORT_PROTOCOLS[protocol]]
            if destination.port in self.port_aliases and not src:
                # The alias becomes the service, under its own name where it is used with one protocol.
                use = (protocol,)
                first = self.service_alias_use.setdefault(destination.port, use)
                name = destination.port if first == use else f"{destination.port}-{label}"
                return self._service_object(name, entries, f"ports of alias {destination.port}"), "", ""
            name = label + (f"-{dst.replace(',', '_')}" if dst else "") + (f"-from-{src.replace(',', '_')}" if src else "")
            return self._service_object(name, entries), "", ""
        if protocol == "icmp":
            table, kind, label = (ICMP_TYPES, Protocol.ICMP, "icmp") if family == 4 else (ICMP6_TYPES, Protocol.ICMP6, "icmp6")
            words = [word for word in _text(node, "icmptype").lower().split(",") if word.strip()]
            if not words or "any" in words:
                return self._service_object(label, [ServiceEntry(kind)]), "", ""
            unknown = [word for word in words if word not in table]
            if unknown:
                return "", "", f"ICMP type '{_short(unknown[0], 30)}', which pf does not have for IPv{family}"
            numbers = transform.dedupe([str(table[word]) for word in words])
            entries = [ServiceEntry(kind, icmp_type=int(number)) for number in numbers]
            return self._service_object(f"{label}-" + "-".join(transform.dedupe(words)), entries), "", ""
        if protocol in PROTOCOLS:
            return self._service_object(protocol, [ServiceEntry(Protocol.IP, ip_protocol=PROTOCOLS[protocol])]), "", ""
        return "", "", f"protocol '{_short(protocol, 30)}'"

    # -- rules ---------------------------------------------------------------------------------

    def _view(self, member: str, family: int) -> Optional[str]:
        """The part of a rule member that is of one IP version, as an object; None when it has none."""
        key = (member, family)
        if key in self.views:
            return self.views[key]
        self.views[key] = None  # for a group that holds itself
        out: Optional[str] = None
        suffix = f" IPv{family}"
        if member in self.p.address_groups:
            group = self.p.address_groups[member]
            members = [view for view in (self._view(m, family) for m in group.members) if view]
            if group.unsupported or members == group.members:
                out = member
            elif members:
                out = member + suffix
                self.p.address_groups[out] = AddressGroup(out, members, f"the IPv{family} addresses of {member}")
        elif member in self.p.addresses:
            address = self.p.addresses[member]
            if address.kind == AddressKind.FQDN and not address.fqdn_family:
                out = member + suffix
                self.p.addresses[out] = Address(out, AddressKind.FQDN, address.value, address.description, fqdn_family=family)
            elif self._families(member) == {family}:
                out = member
        elif member == ANY:
            out = ANY_V4 if family == 4 else ANY_V6
        elif self._families(member) == {family}:
            out = member
        self.views[key] = out
        return out

    def _families(self, member: str) -> Set[int]:
        address = self.p.addresses.get(member)
        if address is not None and address.kind == AddressKind.UNSUPPORTED and address.fqdn_family:
            return {address.fqdn_family}  # the address of an interface that is not in the file
        return transform.families(self.p, member)

    def _other_family(self, members: List[str], negated: bool, family: int) -> bool:
        """Whether a side of a rule for one IP version would match the other version in the model."""
        other = 10 - family
        return negated or any(other in self._families(member) for member in members)

    def _half(self, node: ET.Element, family: int) -> _Half:
        half = _Half(family)
        source = self._side(_child(node, "source"), family)
        destination = self._side(_child(node, "destination"), family)
        missing = [f"{what}: {side.missing}" for what, side in (("source", source), ("destination", destination)) if side.missing]
        half.problems = [f"{what}: {side.problem}" for what, side in (("source", source), ("destination", destination)) if side.problem]
        half.notes = [side.note for side in (source, destination) if side.note]
        service, absent, problem = self._service(node, family, source, destination)
        if absent:
            missing.append(absent)
        if problem:
            half.problems.append(problem)
        half.missing = "; ".join(missing)
        if half.missing:
            return half
        half.sources, half.negate_source = source.members, source.negated
        half.destinations, half.negate_destination = destination.members, destination.negated
        half.services = [service] if service else [ANY]
        return half

    def _unknown(self, half: _Half) -> bool:
        """Whether a half names something of the firewall itself whose addresses are not in the configuration."""
        for member in half.sources + half.destinations:
            address, group = self.p.addresses.get(member), self.p.address_groups.get(member)
            if (address is not None and address.kind == AddressKind.UNSUPPORTED) or (group is not None and group.builtin and group.unsupported):
                return True
        return False

    def _restrict(self, half: _Half) -> None:
        """Keep a rule for one IP version to that version, where both its sides could match the other one."""
        family = half.family
        if not (self._other_family(half.sources, half.negate_source, family)
                and self._other_family(half.destinations, half.negate_destination, family)):  # fmt: skip
            return
        for members, negated, what in (
            (half.sources, half.negate_source, "source"), (half.destinations, half.negate_destination, "destination")
        ):  # fmt: skip
            if negated:
                continue
            views = transform.dedupe([view for view in (self._view(member, family) for member in members) if view])
            if not views:
                half.missing = f"its {what} has no IPv{family} address"
            else:
                members[:] = views
            return
        # Both sides say "not": every address of the other IP version joins what the source is not.
        half.sources.append(ANY_V6 if family == 4 else ANY_V4)

    def _rule_node(self, node: ET.Element, label: str) -> List[Rule]:
        """The rules of the model for one rule of the file: one, or one per IP version where they differ."""
        descr = _text(node, "descr")
        name = self._unique(descr or label, self.rule_names)
        word = _text(node, "ipprotocol")  # as filter.inc compares it: in lower case, or it is IPv4
        families = {"inet46": [4, 6], "inet6": [6]}.get(word, [4])
        if not self.ipv6 and 6 in families:
            self.ipv6_dropped += 1
            families = [f for f in families if f == 4]
        halves = [self._half(node, family) for family in families]
        loaded = [half for half in halves if not half.missing]
        # Two halves that are both fine, or both not, are one rule for both IP versions, as in the file. Where one
        # of them names an address of the firewall that is not known, the other one stays usable as a rule of its own.
        together = len(loaded) == 2 and len(
            {(bool(half.problems), self._unknown(half), half.negate_source, half.negate_destination) for half in loaded}
        ) == 1
        if not together:
            for half in loaded:
                self._restrict(half)  # a rule for one IP version stays one in the model
            loaded = [half for half in loaded if not half.missing]
        if not loaded:
            self.rule_names.discard(name)
            if families:
                self.not_loaded.append(f"'{_short(name)}' ({'; '.join(transform.dedupe([h.missing for h in halves]))})")
            return []
        base = Rule(name=name, origin=name)
        kind = _text(node, "type")  # filter.inc takes anything but these words in lower case for "pass"
        base.action = {"block": Action.DROP, "reject": Action.RESET_CLIENT}.get(kind, Action.ALLOW)
        base.enabled = not _has(node, "disabled")
        base.log_start, base.log_end = _has(node, "log"), False
        base.schedule = _text(node, "sched")
        if not descr:
            base.description = "a pfSense rule without a description"
        for key, text in _NARROWING.items():
            value = _text(node, key)
            if value and (key != "vlanprio" or value != "none"):
                base.unsupported.append(f"it matches {text} '{_short(value, 30)}'")
        base.unsupported = transform.dedupe(base.unsupported)
        if _has(_child(node, "nat"), "enable"):
            base.unsupported.append("it translates IPv6 to IPv4 (NAT64)")
        for key in _HANDLING:
            child = _child(node, key)
            if child is not None and (_clean(child.text) or key in ("tcpflags_any", "allowopts", "disablereplyto")):
                if (key, _clean(child.text)) not in (("statetype", "keep state"), ("vlanprioset", "none")):
                    base.handling[key] = _clean(child.text) or "yes"
        out: List[Rule] = []
        if together:
            first, second = loaded
            merged = copy.deepcopy(base)
            merged.sources = self._both(first.sources + second.sources)
            merged.destinations = self._both(first.destinations + second.destinations)
            merged.negate_source, merged.negate_destination = first.negate_source, first.negate_destination
            merged.services = self._services(first.services + second.services)
            merged.unsupported = transform.dedupe(base.unsupported + first.problems + second.problems)
            out.append(merged)
        else:
            for half in loaded:
                rule = copy.deepcopy(base)
                if len(loaded) == 2 and half.family == 6:
                    rule.name = rule.origin = self._unique(f"{name} IPv6", self.rule_names)
                rule.sources, rule.destinations = list(half.sources), list(half.destinations)
                rule.negate_source, rule.negate_destination = half.negate_source, half.negate_destination
                rule.services = list(half.services)
                rule.unsupported = transform.dedupe(base.unsupported + half.problems)
                out.append(rule)
        for half in halves:
            if half.missing:
                self.report.add(
                    "rule", out[0].origin, Severity.INFO, "RULE_HALF_NOT_LOADED",
                    f"the rule is for IPv4 and IPv6, and there is no IPv{half.family} rule for it on pfSense ({half.missing}): "
                    "it is converted for the other IP version only",
                )  # fmt: skip
        for rule in out:
            self._rule_findings(node, rule)
            for text in transform.dedupe([text for half in loaded for text in half.notes]):
                self.report.add("rule", rule.origin, Severity.REVIEW, "NEGATED_LIST", text)
        return out

    @staticmethod
    def _both(members: List[str]) -> List[str]:
        members = transform.dedupe(members)
        if ANY_V4 in members and ANY_V6 in members:
            members = [ANY] + [member for member in members if member not in (ANY_V4, ANY_V6)]
        return members

    @staticmethod
    def _services(services: List[str]) -> List[str]:
        services = transform.dedupe(services)
        return [ANY] if ANY in services else services

    def _rule_findings(self, node: ET.Element, rule: Rule) -> None:
        if rule.handling.get("gateway"):
            self.report.add(
                "rule", rule.origin, Severity.INFO, "POLICY_ROUTING",
                f"the rule also sends what it passes to gateway '{_short(rule.handling['gateway'], 40)}' (policy routing), "
                "which is not converted",
            )  # fmt: skip
        if rule.handling.get("statetype") == "none" and rule.action == Action.ALLOW:
            self.report.add(
                "rule", rule.origin, Severity.APPROX, "STATELESS_RULE",
                "the rule passes packets without keeping a state: the answers need a rule of their own on pfSense. The "
                "model is about connections, and the converted rule allows the answers with it",
            )  # fmt: skip

    def _rules(self) -> List[Rule]:
        read: List[_Read] = []
        counters: Dict[str, int] = {}
        for position, node in enumerate(_children(_child(self.root, "filter"), "rule")):
            if _has(node, "separator"):
                continue
            floating = _has(node, "floating")
            interface = _text(node, "interface")
            item = _Read([], [], floating=floating, position=position)
            if floating:
                tab = "Floating"
                item.quick = _has(node, "quick")
                # Without a direction (or with "any") pf takes the rule for both directions.
                item.direction = (_text(node, "direction") or "any") if _text(node, "floating") == "yes" else "in"
                if item.direction not in ("in", "out", "any"):
                    if not _has(node, "disabled"):
                        self.not_loaded.append(f"'{_short(_text(node, 'descr') or 'floating rule')}' (direction '{_short(item.direction, 20)}', which pf does not have)")
                    continue
                if interface == "any" and 0 < self.version <= 22.2:
                    if not _has(node, "disabled"):
                        self.not_loaded.append(f"'{_short(_text(node, 'descr') or 'floating rule')}' (pfSense 2.6 loads no floating rule for interface 'any')")
                    continue
                if interface in ("", "any"):
                    item.zones = [ANY]
                else:
                    item.zones = transform.dedupe([z for key in interface.split(",") for z in self._zones_of(key.strip())])
            else:
                tab = SYSTEM_GROUPS.get(interface) or (self.interfaces[interface].zone if interface in self.interfaces else interface)
                item.zones = self._zones_of(interface)
                if interface in self.groups or interface in SYSTEM_GROUPS:
                    item.tier = interface
                    if interface == "openvpn":
                        # An assigned OpenVPN interface is also a member of the group pf keeps for them all.
                        section = _child(self.root, "interfaces")
                        item.zones += [
                            i.zone for i in self.interfaces.values()
                            if i.enabled and _text(_child(section, i.key), "if").startswith("ovpn") and i.zone not in item.zones
                        ]  # fmt: skip
            counters[tab] = counters.get(tab, 0) + 1
            label = f"{_short(tab, 30)} rule {counters[tab]}"
            kind = _text(node, "type")
            if kind == "match":
                self.report.note(
                    Severity.INFO, "MATCH_RULE_SKIPPED",
                    f"'{_short(_text(node, 'descr') or label)}' is a rule of type 'match': it marks or shapes traffic and "
                    "decides nothing. It is not converted",
                )  # fmt: skip
                continue
            if not item.zones:
                if not _has(node, "disabled"):
                    self.not_loaded.append(
                        f"'{_short(_text(node, 'descr') or label)}' (its interface '{_short(interface, 30)}' is not there or not enabled)"
                    )
                continue
            item.rules = self._rule_node(node, label)
            if item.rules:
                read.append(item)
        return self._ordered(read)

    def _ordered(self, read: List[_Read]) -> List[Rule]:
        """The rules in the order in which they decide: the model is first match."""
        incoming = [item for item in read if not item.floating or item.direction in ("in", "any")]
        quick = [item for item in incoming if item.floating and item.quick]
        late = [item for item in incoming if item.floating and not item.quick]
        grouped = self._group_tier([item for item in incoming if not item.floating and item.tier])
        plain = [item for item in incoming if not item.floating and not item.tier]
        out: List[Rule] = self._leaving([item for item in read if item.floating and item.direction in ("out", "any")])
        out += self._private()
        for item in quick + grouped + plain + list(reversed(late)):
            for rule in item.rules:
                rule.src_zones = list(item.zones)
                out.append(rule)
        if late:
            self.report.note(
                Severity.INFO, "FLOATING_LAST_MATCH",
                f"{len(late)} floating rule{'s are' if len(late) != 1 else ' is'} not 'quick': such a rule decides only "
                "where no rule of an interface matched, and of several the last one. In the converted policy "
                f"{'they stand' if len(late) != 1 else 'it stands'} behind the rules of the interfaces, the last one first: "
                + ", ".join(f"'{_short(rule.name, 40)}'" for item in reversed(late) for rule in item.rules[:1]),
            )  # fmt: skip
        return out

    def _group_tier(self, items: List[_Read]) -> List[_Read]:
        """Rules of interface groups and of the tunnel interfaces, between the floating rules and the others.

        Up to pfSense 2.7 they are read in the order of the file. Later versions take the groups in
        the order in which they are defined, then L2TP, PPPoE, IPsec and OpenVPN.
        """
        order = list(self.groups) + list(SYSTEM_GROUPS)
        sorted_items = sorted(items, key=lambda item: (order.index(item.tier), item.position))
        newer = self.version > 23.3 or not self.version
        if sorted_items != items:
            swapped = any(
                set(a.zones) & set(b.zones) and sorted_items.index(a) > sorted_items.index(b)
                for index, a in enumerate(items) for b in items[index + 1 :]
            )  # fmt: skip
            if swapped:
                self.report.note(
                    Severity.REVIEW, "RULE_ORDER_VERSION",
                    "rules of interface groups that share an interface are not in the file in the order of their "
                    "groups. pfSense up to 2.7 reads them in the order of the file, later versions group by group; "
                    f"the configuration says version {self.version or 'nothing'}, so they are read "
                    + ("group by group" if newer else "in the order of the file"),
                )  # fmt: skip
        return sorted_items if newer else items

    def _leaving(self, items: List[_Read]) -> List[Rule]:
        """Floating rules for traffic that leaves by an interface.

        pf looks at them when a forwarded packet goes out, after the rules of the arrival interface
        passed it. Without one of them everything goes out. A rule that blocks therefore blocks
        whatever the other rules say, and stands first; a rule that passes changes nothing, unless
        it keeps traffic away from a blocking rule behind it, which the model cannot say.
        """
        order = [item for item in items if item.quick] + list(reversed([item for item in items if not item.quick]))
        translated = self._translating_zones()
        out: List[Rule] = []
        passing: List[_Read] = []
        ignored: List[str] = []
        for item in order:
            for rule in item.rules:
                if rule.action == Action.ALLOW:
                    if item.direction == "out":
                        ignored.append(rule.name)
                    if rule.enabled and item not in passing:
                        passing.append(item)
                    continue
                block = rule
                if item.direction == "any":
                    block = copy.deepcopy(rule)
                    block.name = block.origin = self._unique(f"{rule.name} - leaving", self.rule_names)
                else:
                    item.rules = [r for r in item.rules if r is not rule]
                block.src_zones, block.dst_zones = [ANY], list(item.zones)
                before = [
                    other for other in passing
                    if other is not item and (ANY in other.zones or ANY in item.zones or set(other.zones) & set(item.zones))
                ]  # fmt: skip
                if before:
                    block.unsupported.append(
                        "it blocks traffic that leaves, except what a floating rule before it passes ("
                        + ", ".join(f"'{_short(r.name, 30)}'" for other in before for r in other.rules[:1]) + ")"
                    )
                named = block.negate_source or any(member not in (ANY, ANY_V4, ANY_V6) for member in block.sources)
                if named and translated and (ANY in item.zones or set(item.zones) & translated):
                    block.unsupported.append(
                        "it matches the source of traffic that leaves, which is the source after outbound NAT"
                    )
                self.out_blocks.add(block.origin)
                out.append(block)
        if ignored:
            self.report.note(
                Severity.INFO, "FLOATING_OUT_PASS",
                "floating rules that pass traffic leaving by an interface decide nothing for traffic the firewall "
                "forwards: it leaves when the rules of the interface it arrived on passed it. They are not converted: "
                + ", ".join(f"'{_short(name, 40)}'" for name in ignored),
            )  # fmt: skip
        return out

    def _translating_zones(self) -> Set[str]:
        """Zones by whose interface traffic leaves with a source that outbound NAT or 1:1 NAT may have changed."""
        nat = _child(self.root, "nat")
        outbound = _child(nat, "outbound")
        mode = _text(outbound, "mode") or "automatic"
        zones: Set[str] = set()
        if mode in ("automatic", "hybrid"):
            zones |= {i.zone for i in self.interfaces.values() if i.enabled and i.gateway}
        if mode in ("advanced", "hybrid"):
            zones |= {z for rule in _children(outbound, "rule") if not _has(rule, "disabled") for z in self._zones_of(_text(rule, "interface"))}
        for rule in _children(nat, "onetoone"):
            if not _has(rule, "disabled"):
                zones |= set(self._zones_of(_text(rule, "interface") or "wan"))
        return zones

    def _private(self) -> List[Rule]:
        """What "Block private networks and loopback addresses" of an interface does, as rules."""
        out: List[Rule] = []
        bridged = [_text(bridge, "members").lower() for bridge in _children(_child(self.root, "bridges"), "bridged")]
        for interface in self.interfaces.values():
            # filter.inc: stristr($members, $on), which also takes opt1 for a member where opt10 is one.
            if not (interface.enabled and interface.blockpriv) or any(interface.key in members for members in bridged):
                continue
            name = self._unique(f"Block private networks from {interface.zone}", self.rule_names)
            networks = [network for network in PRIVATE_NETWORKS if self.ipv6 or ":" not in network]
            rule = Rule(name=name, origin=name, src_zones=[interface.zone], sources=networks, action=Action.DROP)
            rule.log_start, rule.log_end = not _has(_child(self.root, "syslog"), "nologprivatenets"), False
            rule.description = "what 'Block private networks and loopback addresses' of the interface does on pfSense"
            self.report.add(
                "rule", name, Severity.INFO, "AUTOMATIC_RULE",
                f"interface {interface.zone} has 'Block private networks and loopback addresses' set: pfSense drops "
                "what arrives there from those networks before any rule is looked at. This rule stands for that",
            )  # fmt: skip
            out.append(rule)
        return out

    # -- NAT -----------------------------------------------------------------------------------

    def _nat(self) -> List[NatRule]:
        nat = _child(self.root, "nat")
        forwards = [rule for rule in (self._forward(node, n) for n, node in enumerate(_children(nat, "rule"), 1)) if rule]
        one_to_one = [rule for n, node in enumerate(_children(nat, "onetoone"), 1) for rule in self._one_to_one(node, n)]
        outbound = _child(nat, "outbound")
        mode = _text(outbound, "mode") or "automatic"
        manual: List[NatRule] = []
        if mode in ("advanced", "hybrid"):
            manual = [rule for rule in (self._outbound(node, n) for n, node in enumerate(_children(outbound, "rule"), 1)) if rule]
        automatic = self._automatic() if mode in ("automatic", "hybrid") else []
        count = len(_children(nat, "npt"))
        if count:
            self.report.note(
                Severity.REVIEW, "NPT_NOT_CONVERTED",
                f"{count} IPv6 prefix translation{'s' if count != 1 else ''} (NPt) of the configuration "
                f"{'are' if count != 1 else 'is'} not converted",
            )  # fmt: skip
        # A port forward goes before 1:1 NAT for what arrives, 1:1 NAT before outbound NAT for what leaves.
        return forwards + one_to_one + manual + automatic

    def _nat_rule(self, node: ET.Element, label: str) -> NatRule:
        name = self._unique(_text(node, "descr") or label, self.nat_names)
        nat = NatRule(name=name, origin=name, enabled=not _has(node, "disabled"))
        nat.combines = True  # a translation of the destination and one of the source apply to one connection
        return nat

    def _nat_zone(self, node: ET.Element, nat: NatRule, what: str) -> Optional[Tuple[List[str], Optional[_Interface]]]:
        """(zones a port forward or 1:1 rule is for, the assigned interface it is on, if it is one); None when pfSense
        has no such interface. A group or a tunnel interface is one too."""
        key = _text(node, "interface") or "wan"
        zones = self._zones_of(key)
        if not zones:
            if nat.enabled:
                self.not_loaded.append(f"{what} '{_short(nat.name)}' (its interface '{_short(key, 30)}' is not there or not enabled)")
            self.nat_names.discard(nat.name)
            return None
        return zones, self.interfaces.get(key)

    def _nat_side(self, nat: NatRule, node: Optional[ET.Element], what: str, family: int = 4) -> Optional[_Side]:
        """A side of a NAT rule; None when pfSense does not load the rule because of it."""
        side = self._side(node, family)
        if side.missing:
            if nat.enabled:
                self.not_loaded.append(f"NAT rule '{_short(nat.name)}' ({what}: {side.missing})")
            self.nat_names.discard(nat.name)
            return None
        if side.problem:
            nat.unsupported.append(f"{what}: {side.problem}")
        if side.negated:
            nat.unsupported.append(f"negated {what} in a NAT rule")
        return side

    def _nat_service(self, nat: NatRule, protocol: str, src: Optional[str], dst: Optional[str], alias: str = "") -> None:
        protocol = protocol.lower()
        if src is None or dst is None:
            nat.unsupported.append("ports that could not be read")
        elif protocol in ("", "any"):
            if src or dst:
                nat.service = self._service_object(
                    "tcp-udp" + (f"-{dst.replace(',', '_')}" if dst else "") + (f"-from-{src.replace(',', '_')}" if src else ""),
                    [ServiceEntry(p, dst, src) for p in (Protocol.TCP, Protocol.UDP)],
                )
        elif protocol in PORT_PROTOCOLS:
            label = protocol.replace("/", "-")
            entries = [ServiceEntry(p, dst, src) for p in PORT_PROTOCOLS[protocol]]
            if alias and not src:
                first = self.service_alias_use.setdefault(alias, (protocol,)) == (protocol,)
                nat.service = self._service_object(alias if first else f"{alias}-{label}", entries, f"ports of alias {alias}")
            else:
                name = label + (f"-{dst.replace(',', '_')}" if dst else "") + (f"-from-{src.replace(',', '_')}" if src else "")
                nat.service = self._service_object(name, entries)
        elif protocol == "icmp":
            nat.service = self._service_object("icmp", [ServiceEntry(Protocol.ICMP)])
            nat.unsupported.append("NAT limited to protocol icmp")
        elif protocol in PROTOCOLS:
            nat.service = self._service_object(protocol, [ServiceEntry(Protocol.IP, ip_protocol=PROTOCOLS[protocol])])
            nat.unsupported.append(f"NAT limited to protocol {protocol}")
        else:
            nat.unsupported.append(f"protocol '{_short(protocol, 30)}'")

    def _forward(self, node: ET.Element, number: int) -> Optional[NatRule]:
        nat = self._nat_rule(node, f"Port forward {number}")
        place = self._nat_zone(node, nat, "port forward")
        if place is None:
            return None
        zones, interface = place
        family = 6 if _text(node, "ipprotocol").lower() == "inet6" else 4
        source = self._nat_side(nat, _child(node, "source"), "source", family)
        destination = self._nat_side(nat, _child(node, "destination"), "destination", family) if source is not None else None
        if source is None or destination is None:
            return None
        nat.src_zones, nat.dst_zones = list(zones), list(zones)
        nat.sources, nat.destinations = source.members, destination.members
        if family == 6:
            nat.unsupported.append("IPv6 NAT")
        protocol = _text(node, "protocol").lower()
        ports = protocol in PORT_PROTOCOLS
        try:
            src, why_src = self._ports(source.port) if ports else ("", "")
            dst, why_dst = self._ports(destination.port) if ports else ("", "")
        except _Unreadable as error:
            nat.unsupported.append(str(error))
            src, dst, why_src, why_dst = "", "", "", ""
        if (src is None or dst is None) and nat.enabled:
            self.not_loaded.append(f"port forward '{_short(nat.name)}' ({why_src or why_dst})")
            self.nat_names.discard(nat.name)
            return None
        self._nat_service(nat, protocol, src, dst, destination.port if destination.port in self.port_aliases else "")
        if _has(node, "nordr"):
            # As for iptables: it ends the port forwards only, and outbound NAT still applies.
            nat.unsupported.append(
                "exception from port forwarding only ('no rdr'); the port forwards below it are converted without "
                "this exception"
            )
            return nat
        target, local = _text(node, "target"), _text(node, "local-port")
        address, spread = self._target(nat, target)
        if address is None:
            return None
        port = ""
        if ports and dst and local and local != destination.port:
            # As filter.inc works it out: a range written with a hyphen goes to a range as long; everything else
            # goes to the one port given (the first port of an alias).
            try:
                start, why = self._ports(local)
            except _Unreadable as error:
                start, why = None, str(error)
            if local in self.port_aliases and start:
                start = start.split(",")[0].split("-")[0]
            literal_range = destination.port not in self.port_aliases and "-" in destination.port
            if start is None or "-" in start or "," in start:
                nat.unsupported.append(f"the port it translates to ({why or 'not one port'})")
            elif literal_range and local not in self.port_aliases:
                low, _, high = dst.partition("-")
                if start != low:
                    nat.unsupported.append(
                        f"a range of ports translated to another range ({dst} to {start}-{int(start) + int(high) - int(low)}), "
                        "which the model cannot say"
                    )
            elif "," in dst or "-" in dst:
                nat.unsupported.append(f"several ports ({dst}) translated to the one port {start}")
            elif start != dst:
                port = start
        nat.destination_translation = DestNat(address, port, spread=spread)
        if interface is not None:
            self._reflection(node, nat, interface)
        if _text(node, "associated-rule-id") == "pass" and nat.enabled:
            self._pass_rule(nat, zones)
        return nat

    def _target(self, nat: NatRule, target: str) -> Tuple[Optional[str], bool]:
        """(address a port forward sends to, whether one of several is picked); None when pfSense does not load it."""
        try:
            address = ipaddress.ip_address(target)
            if address.version == 6 and "IPv6 NAT" not in nat.unsupported:
                nat.unsupported.append("IPv6 NAT")
            return str(address), False
        except ValueError:
            pass
        if target in self.address_aliases:
            found, complete = transform.known_intervals(self.p, target)
            hosts = sum(last - first + 1 for _, first, last in found)
            return target, hosts != 1 or not complete
        if target.endswith("ip") and KEY.fullmatch(target[:-2]):
            name, _ = self._address_object(target[:-2], 4)
            if name:
                return name, False
        if nat.enabled:
            self.not_loaded.append(f"port forward '{_short(nat.name)}' (its target '{_short(target, 40)}' cannot be resolved)")
        self.nat_names.discard(nat.name)
        return None, False

    def _reflection(self, node: ET.Element, nat: NatRule, interface: _Interface) -> None:
        """NAT reflection: the port forward also applies to what arrives on the interfaces without a gateway."""
        own = _text(node, "natreflection").lower()
        off = _has(self.system, "disablenatreflection")
        if own == "disable" or (not own and off):
            return
        pure = own == "purenat" or (not own and _has(self.system, "enablenatreflectionpurenat"))
        if not pure:
            self.report.add(
                "nat", nat.origin, Severity.REVIEW, "NAT_REFLECTION_PROXY",
                "the port forward has NAT reflection in proxy mode: clients on the inside that use the outside address "
                "are answered by a proxy on the firewall, which passes without a rule. That is not converted",
            )  # fmt: skip
            return
        inside = [i.zone for i in self.interfaces.values() if i.enabled and not i.gateway and i.key != interface.key]
        if inside:
            nat.src_zones = transform.dedupe(nat.src_zones + inside)
            self.report.add(
                "nat", nat.origin, Severity.INFO, "NAT_REFLECTION",
                "the port forward has NAT reflection: it also applies to what arrives on " + ", ".join(inside),
            )  # fmt: skip

    def _pass_rule(self, nat: NatRule, zones: List[str]) -> None:
        """The rule that stands for a port forward that passes its own traffic.

        It is written as pfSense writes the rule it links to a port forward: for the translated address
        and port. The model then gets the original address like every other rule.
        """
        assert nat.destination_translation is not None
        name = self._unique(f"{nat.name} - pass", self.rule_names)
        service = nat.service
        if nat.destination_translation.port and service in self.p.services:
            moved = [dataclasses.replace(entry, dst_ports=nat.destination_translation.port) for entry in self.p.services[service].entries]
            label = "-".join(transform.dedupe([entry.protocol.value for entry in moved]))
            service = self._service_object(f"{label}-{nat.destination_translation.port}", moved)
        rule = Rule(name=name, origin=name, src_zones=list(zones), sources=list(nat.sources),
                    destinations=[nat.destination_translation.address], services=[service])  # fmt: skip
        rule.log_end = False
        rule.unsupported = list(nat.unsupported)
        rule.description = "what the port forward passes by itself (filter rule association 'Pass')"
        self.report.add(
            "rule", name, Severity.APPROX, "AUTOMATIC_RULE",
            f"port forward '{_short(nat.name)}' passes what it forwards without a rule ('Pass' as its filter rule "
            "association): pfSense looks at no rule of the interface for it. This rule stands for that. Unlike the port "
            "forward it also passes what is sent to the translated address directly",
        )  # fmt: skip
        self.pass_rules.append(rule)

    def _one_to_one(self, node: ET.Element, number: int) -> List[NatRule]:
        """A 1:1 rule is two translations on one interface: of the destination of what arrives there for the
        outside address, and of the source of what leaves there from the inside one. The model has a rule that
        is both, but takes its first half for traffic from every zone; so the two are kept apart here."""
        nat = self._nat_rule(node, f"1to1 NAT {number}")
        place = self._nat_zone(node, nat, "1:1 NAT rule")
        if place is None:
            return []
        zones, interface = place
        external = _text(node, "external")
        family = 6 if _text(node, "ipprotocol").lower() == "inet6" or ":" in external else 4
        source = self._nat_side(nat, _child(node, "source"), "source", family)
        destination = self._nat_side(nat, _child(node, "destination"), "destination", family) if source is not None else None
        if source is None or destination is None:
            return []
        nat.dst_zones = list(zones)
        nat.sources, nat.destinations = source.members, destination.members
        if family == 6:
            nat.unsupported.append("IPv6 NAT")
            return [nat]
        if _has(node, "nobinat"):
            nat.unsupported.append(
                "exception from 1:1 NAT only ('no binat'); the 1:1 rules below it are converted without this exception"
            )
            return [nat]
        inside = transform.address_intervals(self.p, nat.sources[0]) if len(nat.sources) == 1 else None
        if nat.sources == [ANY_V4] or not inside or len(inside) != 1:
            nat.unsupported.append("1:1 NAT of something else than one address or network")
            return [nat]
        hosts = inside[0][2] - inside[0][1] + 1
        bits = 32 - (hosts.bit_length() - 1)
        if hosts & (hosts - 1) or inside[0][0] != 4:
            nat.unsupported.append("1:1 NAT of something else than one address or network")
            return [nat]
        try:
            outside = str(ipaddress.ip_address(external))
        except ValueError:
            name = self._address_object(external[:-2], 4)[0] if external.endswith("ip") and KEY.fullmatch(external[:-2]) else ""
            if not name:
                if nat.enabled:
                    self.not_loaded.append(f"1:1 NAT rule '{_short(nat.name)}' (its external address '{_short(external, 40)}' cannot be resolved)")
                self.nat_names.discard(nat.name)
                return []
            outside = name
        if hosts > 1 and outside not in self.p.addresses:
            try:
                outside = str(ipaddress.ip_network(f"{outside}/{bits}", strict=False))
            except ValueError:
                nat.unsupported.append("an external address of another IP version than the inside network")
        elif hosts > 1:
            nat.unsupported.append("1:1 NAT of a network to the address of an interface")
        self.nat_names.discard(nat.name)
        arriving = copy.deepcopy(nat)
        arriving.name = arriving.origin = self._unique(f"{nat.name} - inbound", self.nat_names)
        arriving.src_zones = list(zones)
        arriving.sources, arriving.destinations = list(nat.destinations), [outside]
        arriving.destination_translation = DestNat(nat.sources[0])
        leaving = nat
        leaving.name = leaving.origin = self._unique(f"{nat.name} - outbound", self.nat_names)
        leaving.source_translation = SourceNat(SnatKind.STATIC, [outside])
        for half in (arriving, leaving):
            half.description = "one half of a 1:1 NAT rule of pfSense"
        own = _text(node, "natreflection").lower()
        if interface is not None and (own == "enable" or (own != "disable" and _has(self.system, "enablebinatreflection"))):
            inside_zones = [i.zone for i in self.interfaces.values() if i.enabled and not i.gateway and i.key != interface.key]
            if inside_zones:
                arriving.src_zones = transform.dedupe(arriving.src_zones + inside_zones)
                self.report.add(
                    "nat", arriving.origin, Severity.INFO, "NAT_REFLECTION",
                    "the 1:1 rule has NAT reflection: its outside address also leads to the inside one for what arrives "
                    "on " + ", ".join(inside_zones),
                )  # fmt: skip
        return [arriving, leaving]

    def _outbound(self, node: ET.Element, number: int) -> Optional[NatRule]:
        nat = self._nat_rule(node, f"Outbound NAT {number}")
        key = _text(node, "interface")
        interface = self.interfaces.get(key)
        if interface is None or not interface.enabled:
            zones = self._zones_of(key)
            if not zones:
                if nat.enabled:
                    self.not_loaded.append(f"outbound NAT rule '{_short(nat.name)}' (its interface '{_short(key, 30)}' is not there or not enabled)")
                self.nat_names.discard(nat.name)
                return None
            nat.dst_zones = zones
        else:
            nat.dst_zones = [interface.zone]
        source = _text(_child(node, "source"), "network")
        target_node = _child(node, "destination")
        target_text = _text(target_node, "network") or _text(target_node, "address")
        for what, text, every in (("source", source, source == "any"), ("destination", target_text, _has(target_node, "any") or target_text == "any")):
            members = self._outbound_side(nat, what, text, every)
            if members is None:
                return None
            if what == "source":
                nat.sources = members
            else:
                nat.destinations = members
        if _has(target_node, "not"):
            nat.unsupported.append("negated destination in a NAT rule")
        family = _text(node, "ipprotocol").lower()
        if family == "inet6" or any(6 in transform.families(self.p, m) and 4 not in transform.families(self.p, m) for m in nat.sources + nat.destinations):
            nat.unsupported.append("IPv6 NAT")
        try:
            src, _ = self._ports(_text(node, "sourceport"))
            dst, _ = self._ports(_text(node, "dstport"))
        except _Unreadable as error:
            nat.unsupported.append(str(error))
            src = dst = ""
        self._nat_service(nat, _text(node, "protocol"), src, dst)
        if not family and nat.sources == [ANY_V4] and nat.destinations == [ANY_V4]:
            self.report.add(
                "nat", nat.origin, Severity.INFO, "NAT_IPV6_ALSO",
                "the rule names no IP version and no address: pfSense writes it for IPv4 and for IPv6. It is converted "
                "for IPv4",
            )  # fmt: skip
        if _has(node, "nonat"):
            return nat  # an exception from outbound NAT: the rule stops there, nothing is translated
        target = _text(node, "target")
        bits = _text(node, "target_subnet")
        if target == "other-subnet":  # up to pfSense 2.6
            target, bits = _text(node, "targetip"), _text(node, "targetip_subnet")
        static_port = _has(node, "staticnatport")
        pool = _text(node, "poolopts").lower()
        translated: Optional[str] = None
        if target in self.address_aliases:
            translated = target
        elif target and not (target.endswith("ip") and KEY.fullmatch(target[:-2])):
            try:
                value = ipaddress.ip_interface(f"{target}/{bits}" if bits and "/" not in target else target)
                translated = str(value.ip) if value.network.num_addresses == 1 else str(value.network)
                if value.version == 6 and "IPv6 NAT" not in nat.unsupported:
                    nat.unsupported.append("IPv6 NAT")
            except ValueError:
                nat.unsupported.append(f"a translated address that could not be read ('{_short(target, 40)}')")
                return nat
        if translated is None:
            # No target, or the address of an interface: pfSense takes the address of the interface of the rule.
            address = interface.net4 if interface is not None else None
            nat.source_translation = SourceNat(
                SnatKind.INTERFACE, interface=interface.key if interface is not None else key,
                interface_address=str(address.ip) if address is not None else "",
            )  # fmt: skip
            if static_port:
                self.report.add(
                    "nat", nat.origin, Severity.APPROX, "NAT_STATIC_PORT",
                    "the rule keeps the source port ('Static port'). It is converted as port address translation to the "
                    "address of the interface, which may change the port",
                )  # fmt: skip
        elif pool.startswith("bitmask"):
            nat.source_translation = SourceNat(SnatKind.STATIC, [translated])
        else:
            nat.source_translation = SourceNat(SnatKind.DYNAMIC if static_port else SnatKind.DYNAMIC_PORT, [translated])
        if _text(node, "natport"):
            self.report.add(
                "nat", nat.origin, Severity.INFO, "NAT_SOURCE_PORT",
                f"the rule translates the source port to {_short(_text(node, 'natport'), 30)}; the model has no place for "
                "the port a source translation picks",
            )  # fmt: skip
        return nat

    def _outbound_side(self, nat: NatRule, what: str, text: str, every: bool) -> Optional[List[str]]:
        if every or not text:
            if not every and what == "source":
                if nat.enabled:
                    self.not_loaded.append(f"outbound NAT rule '{_short(nat.name)}' (it has no source)")
                self.nat_names.discard(nat.name)
                return None
            return [ANY_V4]
        side = _Side()
        if text == "(self)" or text in self.groups or KEY.fullmatch(text):
            self._network(side, text, 4)
        else:
            self._address(side, text, 4)
            if side.missing and ":" in text:
                side.missing = ""
                self._address(side, text, 6)
        if side.missing:
            if nat.enabled:
                self.not_loaded.append(f"outbound NAT rule '{_short(nat.name)}' ({what}: {side.missing})")
            self.nat_names.discard(nat.name)
            return None
        if side.problem:
            nat.unsupported.append(f"{what}: {side.problem}")
        return side.members

    def _automatic(self) -> List[NatRule]:
        """The rules pfSense makes by itself in the outbound NAT modes "automatic" and "hybrid"."""
        inside: List[str] = []
        for interface in self.interfaces.values():
            if interface.enabled and not interface.gateway:
                inside += [network for network in self._networks(interface, 4) if network not in inside]
        gateways = {_text(g, "name"): _text(g, "interface") for g in _children(_child(self.root, "gateways"), "gateway_item")}
        for route in _children(_child(self.root, "staticroutes"), "route"):
            via = self.interfaces.get(gateways.get(_text(route, "gateway"), ""))
            interval = parse_literal(_text(route, "network"))
            private = [parse_literal(n) for n in ("10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16")]
            if _has(route, "disabled") or via is None or via.gateway or interval is None or interval[0] != 4:
                continue
            if any(p is not None and p[1] <= interval[1] and interval[2] <= p[2] for p in private):
                network = str(ipaddress.ip_network(_text(route, "network"), strict=False))
                if network not in inside:
                    inside.append(network)
        # The tunnel networks of OpenVPN and the pool of IPsec clients are translated too.
        section = _child(self.root, "openvpn")
        for kind in ("openvpn-server", "openvpn-client", "openvpn-csc"):
            for instance in _children(section, kind):
                interval = parse_literal(_text(instance, "tunnel_network"))
                if interval is not None and interval[0] == 4 and not _has(instance, "disable"):
                    network = str(ipaddress.ip_network(_text(instance, "tunnel_network"), strict=False))
                    inside += [network] if network not in inside else []
        client = _child(_child(self.root, "ipsec"), "client")
        pool = f"{_text(client, 'pool_address')}/{_text(client, 'pool_netbits')}"
        if _has(client, "enable") and parse_literal(pool) is not None and ":" not in pool:
            network = str(ipaddress.ip_network(pool, strict=False))
            inside += [network] if network not in inside else []
        vti = any(_text(phase, "mode") == "vti" for phase in _children(_child(self.root, "ipsec"), "phase2"))
        tunnels = [name for name, there in (("the PPPoE server", self._service_configured("pppoe")), ("IPsec VTI", vti)) if there]
        out: List[NatRule] = []
        for interface in self.interfaces.values():
            if not (interface.enabled and interface.gateway) or not inside or interface.device.startswith(("ovpn", "ipsec")):
                continue  # filter_nat_rules_outbound_automatic() leaves tunnel interfaces out
            name = self._unique(f"Automatic outbound NAT on {interface.zone}", self.nat_names)
            nat = NatRule(name=name, origin=name, dst_zones=[interface.zone], sources=list(inside), destinations=[ANY_V4])
            nat.combines = True
            nat.description = "the rule pfSense makes by itself for this interface (outbound NAT mode automatic or hybrid)"
            address = interface.net4
            nat.source_translation = SourceNat(
                SnatKind.INTERFACE, interface=interface.key, interface_address=str(address.ip) if address is not None else ""
            )
            self.report.add(
                "nat", name, Severity.INFO, "AUTOMATIC_RULE",
                "outbound NAT is automatic: pfSense translates what leaves by an interface with a gateway and comes "
                "from the networks of its other interfaces and of its static routes. This rule stands for that",
            )  # fmt: skip
            if tunnels:
                self.report.add(
                    "nat", name, Severity.APPROX, "NAT_AUTOMATIC_SOURCES",
                    "pfSense also translates what comes from the addresses of " + " and ".join(tunnels) + ", which this "
                    "rule does not hold",
                )  # fmt: skip
            out.append(nat)
        return out

    # -- notes ---------------------------------------------------------------------------------

    def _notes(self) -> None:
        if self.not_loaded:
            self.report.note(
                Severity.REVIEW, "RULE_NOT_LOADED",
                f"pfSense does not load {len(self.not_loaded)} rule{'s' if len(self.not_loaded) != 1 else ''} of the "
                "configuration, which it cannot resolve; they are not converted: " + "; ".join(self.not_loaded[:20])
                + (f"; and {len(self.not_loaded) - 20} more" if len(self.not_loaded) > 20 else ""),
            )  # fmt: skip
        if self.ipv6_dropped:
            self.report.note(
                Severity.INFO, "IPV6_NOT_ALLOWED",
                "'Allow IPv6' is switched off on this firewall (System > Advanced > Networking): it drops all IPv6 "
                f"traffic whatever the rules say. {self.ipv6_dropped} rule{'s' if self.ipv6_dropped != 1 else ''} for IPv6 "
                "or for both IP versions " + ("were" if self.ipv6_dropped != 1 else "was") + " read for IPv4 only",
            )  # fmt: skip
        if _has(self.system, "disablefilter"):
            self.report.note(
                Severity.REVIEW, "FILTER_DISABLED",
                "packet filtering is switched off on this firewall (System > Advanced > Firewall & NAT): it routes "
                "everything and translates nothing. The rules are converted as they stand in the configuration",
            )
        bogons = [i.zone for i in self.interfaces.values() if i.enabled and i.blockbogons]
        if bogons:
            self.report.note(
                Severity.REVIEW, "BOGONS_NOT_CONVERTED",
                "'Block bogon networks' is set on " + ", ".join(bogons) + ": pfSense drops what arrives there from "
                "addresses nobody has been given, by a list it downloads. That list is not in the configuration, and "
                "nothing is converted for it",
            )  # fmt: skip
        if _children(_child(self.root, "bridges"), "bridged"):
            self.report.note(
                Severity.REVIEW, "BRIDGE_NOT_CONVERTED",
                "the firewall bridges interfaces. On which of them a bridged packet is filtered is a setting of the "
                "system, and FWShift read the rules as those of routed interfaces",
            )
        section = _child(self.root, "captiveportal")
        portal = [zone for zone in (list(section) if section is not None else []) if _has(zone, "enable")]
        if portal:
            self.report.note(
                Severity.REVIEW, "CAPTIVE_PORTAL",
                "a captive portal is enabled: on its interfaces only clients that logged in get past the firewall, "
                "which no rule says and which is not converted",
            )
        self.report.note(
            Severity.INFO, "PFSENSE_AUTOMATIC_RULES",
            "pfSense has rules of its own before those of the configuration, which are not converted: it drops "
            "packets with a source that belongs to another interface (antispoof), packets from or to 169.254.0.0/16, "
            "and TCP and UDP from or to port 0; it passes the ICMPv6 messages IPv6 cannot do without; and it has "
            "rules for itself (anti-lockout, DHCP, IPsec). Rules for the firewall itself ('This Firewall', the "
            "address of an interface) are converted as rules for those addresses",
        )
