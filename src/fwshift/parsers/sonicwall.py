# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""SonicWall parser: the settings export of SonicOS 6.5 and 7 (``.exp``) -> neutral model.

What an administrator can produce is *Export Settings* (``.exp``): Base64 of ``key=value`` pairs
joined by ``&``, the values URL-encoded. Each table is a set of keys with the same index
(``addrObjId_3``, ``addrObjType_3``, ...). The file is read as it is, and so is its decoded text.
Nothing of this format is documented by SonicWall beyond how to decode it; the key names are those
that every published reader of the format agrees on (see DEVELOPMENT.md).

How SonicOS differs from the model, and what is done about it:

* Access rules are kept per pair of zones and are first match within their pair. A rule names one
  source, one destination and one service: an object, a group or "any". The rows of a pair are read
  in their order; where every row carries a priority, by the priority.
* An access rule matches the destination address before NAT and the zone the translated traffic
  goes to, as the model does. Nothing is rewritten.
* What no rule of a pair matches is decided by the default rule of that pair, which an export holds
  as a row. Where a pair has none, the default of SonicOS for the security types of the two zones
  is added as a rule and reported.
* NAT policies are one table, first match. A policy can translate source, destination and service
  at once, and matches the interface traffic arrives on and the one it leaves by: an interface
  becomes its zone. A "reflexive" policy has a mirror image, which is added as a policy of its own.
* Objects SonicOS has without their being in the export ("X1 IP", "LAN Subnets", "HTTPS") are
  worked out from the interfaces of the export, or taken from the defaults SonicOS ships with, and
  reported.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import unquote

from .. import transform
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
    ServiceGroup,
    SnatKind,
    SourceNat,
    Zone,
)
from ..netutil import is_number, netmask_to_cidr, normalize, parse_literal, size
from ..report import Report, Severity

IPInterface = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]
Getter = Callable[[str], str]

_KEY = re.compile(r"([A-Za-z][A-Za-z0-9_]*?)_([0-9]{1,7})")
_HEAD = re.compile(rb"(?:buildNum|shortProdName|addrObjId|svcObjId|policyAction|natPolicyOrigSrc|zoneObjId|iface_name|prefs\w*|\w+_[0-9]+)=")
_B64 = re.compile(rb"[A-Za-z0-9+/=\s]+")
_MAX = 256 * 1024 * 1024
# A row of a table is there when its sentinel key is: the name of the object, the action of the rule.
_ACTIONS = {"2": Action.ALLOW}
# Security types of the zones a firewall comes with; the value of zoneObjZoneType for others (as read by the
# published readers of the format: not confirmed).
_DEFAULT_ZONES = {"LAN": "trusted", "WAN": "untrusted", "DMZ": "public", "VPN": "encrypted", "SSLVPN": "sslvpn",
                  "MULTICAST": "untrusted", "WLAN": "wireless", "MGMT": "management"}  # fmt: skip
_ZONE_TYPES = {"0": "untrusted", "1": "trusted", "2": "public", "4": "wireless", "5": "encrypted", "6": "untrusted", "8": "sslvpn"}
# What SonicOS lets through between two zones without a rule of the pair, by security type (documented for
# these; nothing is assumed for the others, which are taken to deny).
_ALLOWED_PAIRS = {("trusted", "untrusted"), ("trusted", "public"), ("wireless", "untrusted"), ("wireless", "public"),
                  ("public", "untrusted")}  # fmt: skip
_DOCUMENTED = {"trusted", "untrusted", "public", "wireless"}
# Default services, as SonicOS ships them; used for a name a rule uses and the export does not define.
_DEFAULT_SERVICES: Dict[str, List[ServiceEntry]] = {
    "HTTP": [ServiceEntry(Protocol.TCP, "80")],
    "HTTPS": [ServiceEntry(Protocol.TCP, "443")],
    "SSH": [ServiceEntry(Protocol.TCP, "22")],
    "Telnet": [ServiceEntry(Protocol.TCP, "23")],
    "FTP": [ServiceEntry(Protocol.TCP, "21")],
    "SMTP (Send E-Mail)": [ServiceEntry(Protocol.TCP, "25")],
    "POP3 (Retrieve E-Mail)": [ServiceEntry(Protocol.TCP, "110")],
    "IMAP4": [ServiceEntry(Protocol.TCP, "143")],
    "DNS (Name Service)": [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")],
    "NTP": [ServiceEntry(Protocol.UDP, "123")],
    "SNMP": [ServiceEntry(Protocol.UDP, "161-162")],
    "Syslog": [ServiceEntry(Protocol.UDP, "514")],
    "IKE": [ServiceEntry(Protocol.UDP, "500")],
    "Terminal Services": [ServiceEntry(Protocol.TCP, "3389")],
    "Ping": [ServiceEntry(Protocol.ICMP, icmp_type=8)],
}
_INTERFACE = r"(X[0-9]+(?::V[0-9]+)?|U[0-9]+|W[0-9]+|MGMT)"


def looks_like_sonicwall(data: bytes) -> bool:
    """An .exp file, or its decoded text."""
    head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    if _HEAD.match(head) and (b"&" in head or b"\n" in head):
        return True
    if not head or not _B64.fullmatch(head):
        return False
    chunk = re.sub(rb"\s", b"", head)
    chunk = chunk[: len(chunk) // 4 * 4]
    try:
        decoded = base64.b64decode(chunk, validate=False)
    except (binascii.Error, ValueError):
        return False
    return bool(_HEAD.match(decoded.lstrip())) and b"=" in decoded


def decode(data: bytes) -> Dict[str, str]:
    """The keys and values of an .exp file or of its decoded text."""
    if len(data) > _MAX:
        raise ParseError("the settings file is larger than 256 MB; refusing to read it")
    text = data.lstrip(b"\xef\xbb\xbf \t\r\n").rstrip()
    if not text:
        raise ParseError("not a SonicWall settings export: the file is empty")
    if not _HEAD.match(text):
        compact = re.sub(rb"\s", b"", text).rstrip(b"&")
        try:
            text = base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
        except (binascii.Error, ValueError):
            raise ParseError("not a SonicWall settings export: the file is neither Base64 nor key=value pairs") from None
        if not _HEAD.match(text.lstrip()):
            raise ParseError("not a SonicWall settings export: the decoded file does not start with the keys of one")
    try:
        body = text.decode("utf-8")
    except UnicodeDecodeError:
        body = text.decode("latin-1")
    out: Dict[str, str] = {}
    for part in re.split(r"[&\r\n]", body):
        if not part:
            continue
        key, sep, value = part.partition("=")
        if not sep:
            raise ParseError(f"not a SonicWall settings export: '{_short(part, 40)}' is no key=value pair")
        value = unquote(value)
        if key in out and out[key] != value:
            raise ParseError(f"the settings export holds key '{_short(key, 40)}' twice, with two values")
        out[key] = value
    return out


def _short(text: str, limit: int = 60) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _unique(name: str, taken: Set[str]) -> str:
    candidate, counter = name, 2
    while candidate in taken:
        candidate = f"{name} ({counter})"
        counter += 1
    taken.add(candidate)
    return candidate


def _getter(row: Dict[str, str], prefix: str, tail: str) -> Getter:
    return lambda name: row[f"{prefix}{name}{tail}"]


def parse(data: bytes, report: Report, interface_addresses: Sequence[str] = ()) -> Policy:
    keys = decode(data)
    version = keys.get("buildNum", "")
    policy = Policy(vendor="sonicwall", scope=f"SonicOS {version}" if version else "")
    _Reader(policy, report, keys, interface_addresses).run()
    return policy


@dataclass
class _Interface:
    name: str
    number: str
    zone: str
    address: Optional[IPInterface] = None  # IPv4
    gateway: str = ""
    dynamic: str = ""  # why the address is not in the export


@dataclass
class _Table:
    """The rows of one table: index -> {field: value}, in the order of their indices."""

    rows: Dict[int, Dict[str, str]] = field(default_factory=dict)

    def ordered(self) -> List[Tuple[int, Dict[str, str]]]:
        return sorted(self.rows.items())


class _Reader:
    def __init__(self, policy: Policy, report: Report, keys: Dict[str, str], interface_addresses: Sequence[str]) -> None:
        self.p, self.report, self.keys = policy, report, keys
        self.tables: Dict[str, _Table] = {}
        for key, value in keys.items():
            match = _KEY.fullmatch(key)
            if match:
                prefix, index = match.group(1), int(match.group(2))
                self.tables.setdefault(prefix, _Table()).rows.setdefault(index, {})[prefix] = value
        self.interfaces: Dict[str, _Interface] = {}  # by name
        self.by_number: Dict[str, _Interface] = {}
        self.zone_types: Dict[str, str] = {}
        self.assumed_types: List[str] = []
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.defaults: List[str] = []
        self.six_rules: List[Rule] = []
        self.given = self._given(interface_addresses)

    # -- the table of a key ----------------------------------------------------------------------

    def column(self, prefix: str) -> Dict[int, str]:
        table = self.tables.get(prefix)
        return {index: row[prefix] for index, row in table.rows.items()} if table else {}

    def rows(self, sentinel: str, fields: Sequence[str]) -> List[Tuple[int, Dict[str, str]]]:
        """The rows of a table, by the indices its sentinel key has: {field: value} with '' for what is missing."""
        columns = {name: self.column(name) for name in fields}
        out: List[Tuple[int, Dict[str, str]]] = []
        for index in sorted(self.column(sentinel)):
            out.append((index, {name: columns[name].get(index, "") for name in fields}))
        return out

    def absent(self, index: int, fields: Sequence[str]) -> List[str]:
        """The fields of a row that the export does not have at all (an empty value is there)."""
        return [name for name in fields if f"{name}_{index}" not in self.keys]

    @staticmethod
    def _priority(value: str) -> Optional[int]:
        return int(value) if value.isdigit() and len(value) <= 9 else None

    @staticmethod
    def _given(values: Sequence[str]) -> Dict[str, IPInterface]:
        out: Dict[str, IPInterface] = {}
        for value in values:
            name, sep, text = value.partition("=")
            try:
                if not sep or not name.strip() or "/" not in text:
                    raise ValueError
                address = ipaddress.ip_interface(text.strip())
            except ValueError:
                raise FwshiftError(
                    f"--interface-address: '{_short(value, 60)}' is not INTERFACE=ADDRESS/BITS (for example X1=198.51.100.2/24)"
                ) from None
            if address.version != 4:
                raise FwshiftError(f"--interface-address: '{_short(value, 60)}': a SonicWall source takes IPv4 addresses here")
            key = name.strip().upper()
            if key in out:
                raise FwshiftError(f"--interface-address: two IPv4 addresses for '{_short(name.strip(), 30)}'")
            out[key] = address
        return out

    # -- top level -----------------------------------------------------------------------------

    def run(self) -> None:
        self._zones()
        self._interfaces()
        self._addresses()
        self._services()
        for six in (False, True):
            self._rules(six)
        self._default_rules()
        for six in (False, True):
            self._nat(six)
        self._builtins()
        for rule in self.six_rules:
            # What SonicOS has by itself is worked out from the IPv4 addresses of the interfaces; its IPv6 addresses
            # are not in the export.
            named = [m for m in rule.sources + rule.destinations if self._is_builtin(m)]
            if named:
                rule.unsupported.append("it names " + ", ".join(f"'{m}'" for m in named) + ", an object SonicOS has by "
                                        "itself, whose IPv6 addresses are not in the export")  # fmt: skip
        if not self.p.rules and not self.p.nat_rules:
            self.report.note(Severity.REVIEW, "NO_RULES", "the settings export holds no access rule and no NAT policy")
        if self.assumed_types:
            self.report.note(
                Severity.INFO, "ZONE_TYPE_ASSUMED",
                "the security type of these zones was read from a code of the export whose meaning is taken from the "
                "published readers of the format, not from SonicWall: " + ", ".join(self.assumed_types),
            )  # fmt: skip
        self.report.note(
            Severity.INFO, "SONICWALL_FORMAT",
            "the settings export is not documented by SonicWall beyond its encoding. The keys read are those every "
            "published reader of the format agrees on; what this parser does not know of a rule is not read",
        )  # fmt: skip

    # -- zones and interfaces ----------------------------------------------------------------------

    def _zones(self) -> None:
        for _, row in self.rows("zoneObjId", ("zoneObjId", "zoneObjZoneType", "zoneObjIntraZoneCom")):
            name = row["zoneObjId"]
            if not name:
                continue
            zone = self.p.zones.setdefault(name, Zone(name))
            if row["zoneObjIntraZoneCom"] in ("1", "0", "on", "off"):
                zone.intrazone_allow = row["zoneObjIntraZoneCom"] in ("1", "on")
            if name.upper() in _DEFAULT_ZONES:
                self.zone_types[name] = _DEFAULT_ZONES[name.upper()]
            elif row["zoneObjZoneType"] in _ZONE_TYPES:
                self.zone_types[name] = _ZONE_TYPES[row["zoneObjZoneType"]]
                self.assumed_types.append(f"{name} ({self.zone_types[name]})")

    def _zone(self, name: str) -> str:
        if name and name not in self.p.zones:
            self.p.zones[name] = Zone(name)
            if name.upper() in _DEFAULT_ZONES:
                self.zone_types[name] = _DEFAULT_ZONES[name.upper()]
        return name

    def _interfaces(self) -> None:
        fields = ("iface_name", "iface_ifnum", "interface_Zone", "iface_lan_ip", "iface_lan_mask", "iface_static_ip",
                  "iface_static_mask", "iface_static_gateway", "iface_lan_default_gw")  # fmt: skip
        for index, row in self.rows("iface_name", fields):
            name = row["iface_name"]
            if not name:
                continue
            zone = self._zone(row["interface_Zone"])
            interface = _Interface(name, row["iface_ifnum"] or str(index), zone)
            for ip_key, mask_key in (("iface_lan_ip", "iface_lan_mask"), ("iface_static_ip", "iface_static_mask")):
                ip, mask = row[ip_key], row[mask_key]
                if ip and ip != "0.0.0.0" and mask:
                    cidr = netmask_to_cidr(ip, mask)
                    if cidr:
                        interface.address = ipaddress.IPv4Interface(f"{ip}/{cidr.split('/')[1]}")
                        break
            gateway = row["iface_static_gateway"] or row["iface_lan_default_gw"]
            if gateway and gateway != "0.0.0.0" and parse_literal(gateway):
                interface.gateway = gateway
            given = self.given.pop(name.upper(), None)
            if given is not None:
                interface.address = given
            if interface.address is None:
                interface.dynamic = f"the address of interface {name} is not in the export (DHCP, PPPoE or not set)"
            self.interfaces[name] = interface
            self.by_number[interface.number] = interface
            if zone:
                listed = self.p.zones[zone].interfaces
                if name not in listed:
                    listed.append(name)
        if self.given:
            raise FwshiftError(
                "--interface-address: no interface '" + "', '".join(sorted(self.given)) + "' in the export; it has "
                + (", ".join(self.interfaces) or "none")
            )

    # -- objects --------------------------------------------------------------------------------

    def _addresses(self) -> None:
        fields = ("addrObjId", "addrObjType", "addrObjZone", "addrObjIp1", "addrObjIp2")
        groups: Set[str] = set()
        for _, row in self.rows("addrObjId", fields):
            name, kind = row["addrObjId"], row["addrObjType"]
            if not name:
                continue
            ip1, ip2 = row["addrObjIp1"], row["addrObjIp2"]
            if kind == "8":
                groups.add(name)
                self.p.address_groups[name] = AddressGroup(name, [])
                continue
            value, problem = "", ""
            if kind == "1":
                value = ip1 if parse_literal(ip1) and ":" not in ip1 else ""
            elif kind == "2":
                value = f"{ip1}-{ip2}" if parse_literal(f"{ip1}-{ip2}") else ""
            elif kind == "4":
                value = netmask_to_cidr(ip1, ip2) or ""
            else:
                problem = f"an address object of type {kind}, which this parser does not know"
            if not value and not problem:
                problem = f"an address object whose addresses could not be read ({_short(ip1, 30)}, {_short(ip2, 30)})"
            if problem:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=problem)
                continue
            self.p.addresses[name] = Address(name, AddressKind.RANGE if kind == "2" else AddressKind.NETWORK, value)
        for _, row in self.rows("addrObjFqdnId", ("addrObjFqdnId", "addrObjFqdn")):
            name = row["addrObjFqdnId"]
            if name:
                if row["addrObjFqdn"]:
                    self.p.addresses[name] = Address(name, AddressKind.FQDN, row["addrObjFqdn"])
                else:
                    self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw="an FQDN object without a host name")
        members = self.column("addro_atomToGrp")
        for index, group in sorted(self.column("addro_grpToGrp").items()):
            member = members.get(index, "")
            if group not in self.p.address_groups:
                self.p.address_groups[group] = AddressGroup(group, [], unsupported="a group that is not defined in the export")
            if member and member not in self.p.address_groups[group].members:
                self.p.address_groups[group].members.append(member)
        for held in self.p.address_groups.values():
            if not held.members and not held.unsupported:
                held.unsupported = "a group without members"
        for prefix in sorted(self.tables):
            if prefix.startswith(("addrObjV6", "addrObj6", "addrObjMac", "addrObjIpv6")) and prefix.endswith(("Id", "Name")):
                self.report.note(
                    Severity.REVIEW, "OBJECTS_NOT_READ",
                    f"the export has a table of address objects ({prefix}) that this parser does not read: rules that name "
                    "such an object are disabled",
                )  # fmt: skip

    def _services(self) -> None:
        fields = ("svcObjId", "svcObjType", "svcObjIpType", "svcObjPort1", "svcObjPort2")
        for index, row in self.rows("svcObjId", fields):
            name = row["svcObjId"]
            if not name:
                continue
            if row["svcObjType"] == "2":
                self.p.service_groups[name] = ServiceGroup(name, [])
                continue
            protocol, first, last = row["svcObjIpType"], row["svcObjPort1"], row["svcObjPort2"]
            service = Service(name)
            if protocol in ("6", "17") and self.absent(index, ("svcObjPort1", "svcObjPort2")):
                service.unsupported = "a TCP or UDP service whose ports the export does not hold"
            elif protocol in ("6", "17"):
                if not (is_number(first or "0") and is_number(last or first or "0")):
                    service.unsupported = f"ports '{_short(first, 10)}' to '{_short(last, 10)}' that could not be read"
                else:
                    low, high = int(first or 0), int(last or first or 0)
                    if low == 0 and high != 0:
                        low = high  # "Port1 0" is a single port: the one Port2 holds
                    if high < low or high > 65535:
                        service.unsupported = f"a port range {low}-{high} that is not one"
                    else:
                        ports = "" if (low, high) in ((0, 0), (0, 65535), (1, 65535)) else (str(low) if low == high else f"{max(low, 1)}-{high}")
                        service.entries = [ServiceEntry(Protocol.TCP if protocol == "6" else Protocol.UDP, ports)]
            elif protocol in ("1", "58"):
                service.unsupported = ("ICMP" if protocol == "1" else "ICMPv6") + (
                    " type and code of a service object: how the export stores them is not known" if (first or "0") != "0" or (last or "0") != "0"
                    else " of a service object without type: how the export stores 'every type' is not known")  # fmt: skip
            elif is_number(protocol) and 0 < int(protocol) <= 255:
                service.entries = [ServiceEntry(Protocol.IP, ip_protocol=int(protocol))]
            else:
                service.unsupported = f"a service of IP type '{_short(protocol, 10)}', which this parser does not know"
            self.p.services[name] = service
        members = self.column("so_atomToGrp")
        for index, group in sorted(self.column("so_grpToGrp").items()):
            member = members.get(index, "")
            self.p.service_groups.setdefault(group, ServiceGroup(group, []))
            if member and member not in self.p.service_groups[group].members:
                self.p.service_groups[group].members.append(member)

    # -- access rules -------------------------------------------------------------------------------

    def _rules(self, six: bool) -> None:
        tail = "V6" if six else ""
        names = ("Action", "SrcZone", "DstZone", "SrcNet", "DstNet", "SrcSvc", "DstSvc", "Enabled", "Comment", "Name",
                 "Whom", "Time", "Log", "Priority", "DefaultRule", "GeoIpBlock", "BotnetBlock")  # fmt: skip
        fields = tuple(f"policy{name}{tail}" for name in names)
        rows = self.rows(f"policyAction{tail}", fields)
        if not rows:
            return
        priorities = [self._priority(row[f"policyPriority{tail}"]) for _, row in rows]
        pairs: Dict[Tuple[str, str], List[Tuple[int, Dict[str, str]]]] = {}
        for index, row in rows:
            pairs.setdefault((row[f"policySrcZone{tail}"], row[f"policyDstZone{tail}"]), []).append((index, row))
        known = all(value is not None for value in priorities)

        def place(entry: Tuple[int, Dict[str, str]]) -> Tuple[int, int]:
            # The default rule of a pair is its last, whatever number it carries; the others by priority where every
            # row has one, otherwise in the order of the file.
            default = entry[1][f"policyDefaultRule{tail}"] == "1"
            return (1 if default else 0, (self._priority(entry[1][f"policyPriority{tail}"]) or 0) if known else entry[0])

        rows = [entry for listed in pairs.values() for entry in sorted(listed, key=place)]
        counters: Dict[Tuple[str, str], int] = {}
        for index, row in rows:
            get = _getter(row, "policy", tail)
            src_zone, dst_zone = self._zone(get("SrcZone")), self._zone(get("DstZone"))
            number = counters[(src_zone, dst_zone)] = counters.get((src_zone, dst_zone), 0) + 1
            label = get("Name") or f"{src_zone or 'any'} to {dst_zone or 'any'}{' IPv6' if six else ''} #{number}"
            name = _unique(label, self.rule_names)
            rule = Rule(name=name, origin=name, description=get("Comment"))
            rule.src_zones = [src_zone] if src_zone and src_zone.lower() != "any" else [ANY]
            rule.dst_zones = [dst_zone] if dst_zone and dst_zone.lower() != "any" else [ANY]
            missing = self.absent(index, [f"policy{key}{tail}" for key in ("SrcZone", "DstZone", "SrcNet", "DstNet", "DstSvc", "Enabled")])
            if missing:
                rule.unsupported.append("the export does not say " + ", ".join(m[len("policy"):].replace("V6", "") for m in missing))
            for key, zone_name in (("source", src_zone), ("destination", dst_zone)):
                if not zone_name and not missing:
                    rule.unsupported.append(f"an empty {key} zone")
            whole = ANY_V6 if six else ANY_V4
            rule.sources = [get("SrcNet")] if get("SrcNet") else [whole]
            rule.destinations = [get("DstNet")] if get("DstNet") else [whole]
            rule.services = [get("DstSvc")] if get("DstSvc") else [ANY]
            action = get("Action")
            rule.action = _ACTIONS.get(action, Action.DENY)
            if action not in ("0", "1", "2"):
                rule.unsupported.append(f"action code '{_short(action, 10)}', which this parser does not know")
            rule.enabled = get("Enabled") != "0"
            rule.log_end = get("Log") != "0"
            if get("SrcSvc"):
                rule.unsupported.append(f"source port service '{_short(get('SrcSvc'), 40)}'")
            if get("Whom") not in ("", "0", "All", "Everyone"):
                rule.users = [get("Whom")]
            if get("Time"):
                rule.schedule = get("Time")
            for key in ("GeoIpBlock", "BotnetBlock"):
                if get(key) not in ("", "0"):
                    rule.profiles[key] = get(key)
            if get("DefaultRule") == "1":
                rule.handling["default-rule"] = "yes"
            if six:
                self.six_rules.append(rule)
            self.p.rules.append(rule)

    def _default_rules(self) -> None:
        """The default rule of every pair of zones the export holds no default rule for, as SonicOS has it."""
        catch_all: Set[Tuple[str, str]] = set()
        for rule in self.p.rules:
            if (rule.enabled and not rule.unsupported and rule.services == [ANY] and rule.users == [ANY]
                    and not rule.schedule and rule.sources in ([ANY], [ANY_V4]) and rule.destinations in ([ANY], [ANY_V4])):  # fmt: skip
                catch_all |= {(src, dst) for src in rule.src_zones for dst in rule.dst_zones}
        zones = [name for name, zone in self.p.zones.items() if zone.interfaces or any(name in r.src_zones + r.dst_zones for r in self.p.rules)]
        added: List[str] = []
        unknown: Set[str] = set()
        for src in zones:
            for dst in zones:
                if src == dst or (src, dst) in catch_all or (ANY, dst) in catch_all or (src, ANY) in catch_all:
                    continue
                kinds = (self.zone_types.get(src, ""), self.zone_types.get(dst, ""))
                allowed = kinds in _ALLOWED_PAIRS
                if not (kinds[0] in _DOCUMENTED and kinds[1] in _DOCUMENTED):
                    unknown |= {zone for zone, kind in zip((src, dst), kinds) if kind not in _DOCUMENTED}
                if not allowed:
                    continue  # what the model does without a rule: it denies
                name = _unique(f"default {src} to {dst}", self.rule_names)
                rule = Rule(name=name, origin=name, src_zones=[src], dst_zones=[dst], log_end=False,
                            description=f"the default access rule of SonicOS from {src} to {dst}")  # fmt: skip
                self.p.rules.append(rule)
                added.append(f"{src} to {dst}")
                self.report.add("rule", name, Severity.APPROX, "DEFAULT_RULE_ASSUMED",
                                f"the export holds no rule for all traffic from {src} to {dst}; SonicOS allows it by default "
                                "for zones of these security types, and this rule stands for that")  # fmt: skip
        if unknown:
            self.report.note(
                Severity.REVIEW, "DEFAULT_RULES_UNKNOWN",
                "the export holds no default rule for some pairs of zones, and what SonicOS does by default for the "
                "security types of these zones is not documented: " + ", ".join(sorted(unknown))
                + ". Traffic between them that no rule matches is taken to be denied",
            )  # fmt: skip

    # -- NAT ----------------------------------------------------------------------------------------

    def _nat(self, six: bool) -> None:
        tail = "V6" if six else ""
        names = ("OrigSrc", "OrigDst", "OrigSvc", "TransSrc", "TransDst", "TransSvc", "SrcIface", "DstIface", "Enabled",
                 "Reflexive", "Comment", "Name", "Priority")  # fmt: skip
        fields = tuple(f"natPolicy{name}{tail}" for name in names)
        rows = self.rows(f"natPolicyOrigSrc{tail}", fields)
        if rows and all(self._priority(row[f"natPolicyPriority{tail}"]) is not None for _, row in rows):
            rows = sorted(rows, key=lambda entry: self._priority(entry[1][f"natPolicyPriority{tail}"]) or 0)
        for index, row in rows:
            get = _getter(row, "natPolicy", tail)
            label = get("Name") or get("Comment") or f"NAT policy {index}{' IPv6' if six else ''}"
            name = _unique(label, self.nat_names)
            nat = self._nat_policy(name, six, get)
            missing = self.absent(index, [f"natPolicy{key}{tail}" for key in ("OrigDst", "OrigSvc", "TransSrc", "TransDst", "TransSvc",
                                                                             "SrcIface", "DstIface", "Enabled")])  # fmt: skip
            if missing:
                nat.unsupported.append("the export does not say " + ", ".join(m[len("natPolicy"):].replace("V6", "") for m in missing))
            self.p.nat_rules.append(nat)
            if get("Reflexive") == "1":
                mirror = self._mirror(name, six, get)
                if mirror is not None:
                    self.p.nat_rules.append(mirror)

    def _interface_zone(self, number: str, nat: NatRule, inbound: bool) -> List[str]:
        if number in ("", "-1"):
            return [ANY]
        interface = self.by_number.get(number)
        direction = "arrives by" if inbound else "leaves by"
        if interface is None or not interface.zone:
            self.report.add("nat", nat.origin, Severity.REVIEW, "NAT_INTERFACE",
                            f"the policy is for traffic that {direction} interface number {number}, which the export does not "
                            "show with a zone: written without that condition")  # fmt: skip
            return [ANY]
        others = [name for name in self.p.zones[interface.zone].interfaces if name != interface.name]
        if others:
            self.report.add("nat", nat.origin, Severity.APPROX, "NAT_INTERFACE",
                            f"the policy is for traffic that {direction} {interface.name}; it is written for zone {interface.zone}, "
                            f"which also holds {', '.join(others[:6])}")  # fmt: skip
        return [interface.zone]

    def _nat_policy(self, name: str, six: bool, value: Getter) -> NatRule:
        nat = NatRule(name=name, origin=name, description=value("Comment"))
        nat.enabled = value("Enabled") != "0"
        whole = ANY_V6 if six else ANY_V4
        nat.sources = [value("OrigSrc")] if value("OrigSrc") else [whole]
        nat.destinations = [value("OrigDst")] if value("OrigDst") else [ANY]
        nat.service = value("OrigSvc") or ANY
        nat.src_zones = self._interface_zone(value("SrcIface"), nat, True)
        outbound = self._interface_zone(value("DstIface"), nat, False)
        nat.dst_zones = outbound
        self._translate(nat, value("TransSrc"), value("TransDst"), value("TransSvc"), value("DstIface"), outbound)
        return nat

    def _translate(self, nat: NatRule, source: str, destination: str, service: str, out_number: str, outbound: List[str]) -> None:
        if source:
            nat.source_translation = self._source_nat(nat, source, out_number)
        if destination:
            nat.destination_translation = DestNat(destination)
            targets = self._intervals(destination)
            original = self._intervals(nat.destinations[0]) if nat.destinations != [ANY] else None
            count = sum(size(i) for i in targets) if targets else 0
            same = original is not None and len(normalize(original)) == 1 and sum(size(i) for i in original) == count
            nat.destination_translation.spread = count > 1 and not same
            # The model wants the zone the original destination is reached in; the policy says where the translated
            # traffic leaves. Where the interfaces tell (the original address lies in the network of one), that zone.
            nat.dst_zones = self._reached_in(nat.destinations)
            if outbound != [ANY]:
                self.report.add(
                    "nat", nat.origin, Severity.APPROX, "NAT_OUTBOUND_INTERFACE",
                    f"the policy translates the destination and is limited to traffic that leaves by zone {', '.join(outbound)}: "
                    "that condition is not converted, and the rule applies whatever the interface the translated traffic "
                    "leaves by",
                )  # fmt: skip
        if service:
            port = self._translated_port(service)
            if destination and port is not None:
                assert nat.destination_translation is not None
                nat.destination_translation.port = port
            elif not destination:
                nat.unsupported.append(f"translated service '{_short(service, 40)}' without a translated destination")
            else:
                nat.unsupported.append(f"translated service '{_short(service, 40)}' that is not one TCP or UDP port")

    def _source_nat(self, nat: NatRule, source: str, out_number: str) -> SourceNat:
        match = re.fullmatch(_INTERFACE + r" IP", source)
        leaving = self.by_number.get(out_number)
        if match and leaving is not None and leaving.name == match.group(1):
            address = str(leaving.address.ip) if leaving.address is not None else ""
            return SourceNat(SnatKind.INTERFACE, interface=leaving.name, interface_address=address)
        targets = self._intervals(source)
        originals = [self._intervals(member) for member in nat.sources if member not in (ANY, ANY_V4, ANY_V6)]
        if targets and originals and all(originals):
            count = sum(size(i) for i in targets)
            merged = normalize([i for found in originals for i in found or []])
            if len(merged) == 1 and len(normalize(targets)) == 1 and size(merged[0]) == count and (count > 1 or size(merged[0]) == 1):
                return SourceNat(SnatKind.STATIC, [source])
        return SourceNat(SnatKind.DYNAMIC_PORT, [source])

    def _mirror(self, name: str, six: bool, value: Getter) -> Optional[NatRule]:
        """The policy SonicOS adds for a reflexive one: the same translation the other way round."""
        swap = {"SrcIface": value("DstIface"), "DstIface": value("SrcIface")}
        orig_src, orig_dst, orig_svc = value("OrigSrc"), value("OrigDst"), value("OrigSvc")
        trans_src, trans_dst, trans_svc = value("TransSrc"), value("TransDst"), value("TransSvc")
        fields = {
            "OrigSrc": trans_dst or orig_dst, "TransSrc": orig_dst if trans_dst else "",
            "OrigDst": trans_src or orig_src, "TransDst": orig_src if trans_src else "",
            "OrigSvc": trans_svc or orig_svc, "TransSvc": orig_svc if trans_svc else "",
            "Enabled": value("Enabled"), "Comment": "",
            **swap,
        }
        mirror_name = _unique(f"{name} (reflexive)", self.nat_names)
        nat = self._nat_policy(mirror_name, six, lambda key: fields.get(key, ""))
        nat.description = f"the reflexive policy of {name}"
        self.report.add("nat", mirror_name, Severity.APPROX, "NAT_REFLEXIVE",
                        f"policy '{name}' is reflexive: SonicOS adds its mirror image, which is converted as this rule. How "
                        "SonicOS builds the mirror is assumed (sources and destinations swapped with their translations)")  # fmt: skip
        return nat

    def _intervals(self, member: str) -> Optional[List[Tuple[int, int, int]]]:
        if member in (ANY, ""):
            return None
        self._builtin(member)
        return transform.address_intervals(self.p, member)

    def _reached_in(self, destinations: List[str]) -> List[str]:
        zones: List[str] = []
        for member in destinations:
            intervals = self._intervals(member)
            if not intervals:
                return [ANY]
            for interval in intervals:
                holding = [i.zone for i in self.interfaces.values() if i.address is not None and i.zone
                           and interval[0] == 4 and int(i.address.network.network_address) <= interval[1]
                           and interval[2] <= int(i.address.network.broadcast_address)]  # fmt: skip
                holding = list(dict.fromkeys(holding))
                if len(holding) != 1:
                    return [ANY]
                if holding[0] not in zones:
                    zones.append(holding[0])
        return zones or [ANY]

    def _translated_port(self, service: str) -> Optional[str]:
        self._default_service(service)
        entries = transform.flatten_services(self.p, service)
        if not entries:
            return None
        ports = {entry.dst_ports for entry in entries}
        if len(ports) != 1 or any(entry.protocol not in (Protocol.TCP, Protocol.UDP) or not is_number(entry.dst_ports) for entry in entries):
            return None
        return entries[0].dst_ports

    # -- what SonicOS has without its being in the export ----------------------------------------

    def _builtins(self) -> None:
        names = {m for r in self.p.rules for m in r.sources + r.destinations}
        names |= {m for n in self.p.nat_rules for m in n.sources + n.destinations}
        names |= {n.source_translation.addresses[0] for n in self.p.nat_rules if n.source_translation and n.source_translation.addresses}
        names |= {n.destination_translation.address for n in self.p.nat_rules if n.destination_translation}
        names |= {m for g in list(self.p.address_groups.values()) for m in g.members}
        for name in sorted(names):
            self._builtin(name)
        for name in sorted({s for r in self.p.rules for s in r.services} | {n.service for n in self.p.nat_rules}
                           | {m for g in list(self.p.service_groups.values()) for m in g.members}):  # fmt: skip
            self._default_service(name)

    def _is_builtin(self, name: str) -> bool:
        address, group = self.p.addresses.get(name), self.p.address_groups.get(name)
        return (address is not None and address.builtin == "sonicwall") or (group is not None and group.builtin == "sonicwall")

    def _default_service(self, name: str) -> None:
        if name in (ANY, "") or name in self.p.services or name in self.p.service_groups:
            return
        entries = _DEFAULT_SERVICES.get(name)
        if entries is None:
            return
        self.p.services[name] = Service(name, [ServiceEntry(e.protocol, e.dst_ports, e.src_ports, e.icmp_type, e.icmp_code) for e in entries],
                                        description="a default service of SonicOS", builtin="sonicwall")  # fmt: skip
        self.report.add("service", name, Severity.INFO, "DEFAULT_OBJECT",
                        "not defined in the export: the definition SonicOS ships with is assumed")  # fmt: skip

    def _builtin(self, name: str) -> None:
        """An address object SonicOS has by itself, from the interfaces of the export."""
        if name in (ANY, ANY_V4, ANY_V6, "") or name in self.p.addresses or name in self.p.address_groups or parse_literal(name):
            return
        interfaces = list(self.interfaces.values())

        def address(value: str, raw: str) -> None:
            self.p.addresses[name] = Address(name, AddressKind.NETWORK, value, raw=raw, builtin="sonicwall")

        def missing(why: str) -> None:
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=why + "; give it with --interface-address",
                                             builtin="sonicwall", fqdn_family=4)  # fmt: skip

        def group(members: List[str], raw: str) -> None:
            if not members:
                self.p.address_groups[name] = AddressGroup(name, [], unsupported=f"{raw}: none is in the export", builtin="sonicwall")
            else:
                self.p.address_groups[name] = AddressGroup(name, members, description=raw, builtin="sonicwall")

        def own(interface: _Interface, part: str) -> Optional[str]:
            if interface.address is None:
                return None
            if part == "IP":
                return str(interface.address.ip)
            if part == "Subnet":
                return str(interface.address.network)
            return interface.gateway or None

        match = re.fullmatch(_INTERFACE + r" (IP|Subnet|Default Gateway)", name)
        found = False
        if match and match.group(1) in self.interfaces:
            interface = self.interfaces[match.group(1)]
            value = own(interface, match.group(2))
            if value is None:
                missing(interface.dynamic or f"the default gateway of interface {interface.name} is not in the export")
            else:
                address(value, f"{match.group(2).lower()} of interface {interface.name}")
            found = True
        match = re.fullmatch(r"All " + _INTERFACE + r" Management IP", name)
        if not found and match and match.group(1) in self.interfaces:
            interface = self.interfaces[match.group(1)]
            value = own(interface, "IP")
            if value is None:
                missing(interface.dynamic)
            else:
                address(value, f"management address of interface {interface.name}")
            found = True
        match = re.fullmatch(r"(.+) Subnets", name)
        zone = next((z for z in self.p.zones if match and z.lower() == match.group(1).lower()), None)
        if not found and zone is not None:
            members = [own(i, "Subnet") for i in interfaces if i.zone == zone]
            if any(m is None for m in members):
                missing(f"an interface of zone {zone} has no address in the export")
            else:
                group([m for m in members if m], f"networks of the interfaces of zone {zone}")
            found = True
        if not found and name in ("Firewalled Subnets", "All Interface IP", "All WAN IP", "WAN Primary IP", "WAN Primary Subnet"):
            wan = [i for i in interfaces if self.zone_types.get(i.zone) == "untrusted"]
            if name == "Firewalled Subnets":
                chosen, part = [i for i in interfaces if i.zone and self.zone_types.get(i.zone) != "untrusted"], "Subnet"
            elif name == "All Interface IP":
                chosen, part = [i for i in interfaces if i.zone], "IP"
            elif name == "All WAN IP":
                chosen, part = wan, "IP"
            else:
                primary = [i for i in wan if i.name == "X1"] or wan[:1]
                chosen, part = primary, "IP" if name.endswith("IP") else "Subnet"
            values = [own(i, part) for i in chosen]
            if any(v is None for v in values):
                missing(f"an interface of '{name}' has no address in the export")
            elif name.startswith("WAN Primary") and values:
                address(str(values[0]), f"{name.lower()} (taken to be {chosen[0].name})")
            else:
                group([v for v in values if v], name.lower())
            found = True
        if found:
            kind = "address" if name in self.p.addresses else "address-group"
            self.report.add(kind, name, Severity.INFO, "DEFAULT_OBJECT",
                            "an object SonicOS has by itself, not defined in the export: worked out from the interfaces of the export")  # fmt: skip


__all__ = ["decode", "looks_like_sonicwall", "parse"]
