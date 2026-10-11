# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Sophos Firewall (SFOS 18 and later) parser: the Entities.xml of an export -> neutral model.

What an administrator can produce is the archive of *Backup & firmware > Import export*: a ``.tar``
that holds ``Entities.xml``. The archive is read as it is, and so are the XML file taken out of it
and the response of the XML API to a ``Get`` (the entities are the same elements there).

How Sophos Firewall differs from the model, and what is done about it:

* A firewall rule matches the destination address before destination NAT and the destination zone
  after it, as the model does. Nothing is rewritten.
* An element that is missing means "any" in this format (zones, networks, services): that is how
  Sophos writes it. An element that is there and empty, or that this parser does not know and that
  looks like a match criterion, makes the rule unsupported instead.
* *Exclusions* are one condition: a rule is skipped for traffic that matches **all** the kinds of
  exclusion it has (source zones and source networks and ...). The model has a negation per field.
  A rule with exclusions of N kinds becomes N rules, each with one field cut down, which together
  match what the rule matched.
* IPv4 and IPv6 rules are separate rulebases. "Any" in an IPv4 rule is ``0.0.0.0/0`` here.
* NAT rules match interfaces, not zones. An interface becomes its zone where the export says which
  zone that is.
* Rules of type HTTPBased (web server protection) are a reverse proxy on the firewall itself, not
  forwarding rules: they are reported and left out.
"""

from __future__ import annotations

import copy
import io
import tarfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

from .. import transform, xmlread
from ..appmap import SOPHOS_ICMP6_NAMES, SOPHOS_ICMP_NAMES, sophos_protocol_number, valid_ports
from ..errors import ParseError
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
from ..netutil import interval_text, is_number, netmask_to_cidr, normalize, parse_literal, size, subtract
from ..report import Report, Severity

_MAX_XML = 512 * 1024 * 1024  # of an Entities.xml inside an archive
_ACTIONS = {"accept": Action.ALLOW, "drop": Action.DROP, "reject": Action.RESET_CLIENT}
_ALWAYS = ("", "all the time")
_OFF = ("", "none", "disable", "disabled", "off", "no restriction", "-1", "0", "null")
KNOWN_USER = "known-user"  # "match known users" without a list: anybody who is signed in

# Elements of a firewall rule that this parser reads, or knows to say nothing about what is matched.
_RULE_ELEMENTS = {"Name", "Description", "IPFamily", "Status", "Position", "PolicyType", "After", "Before", "Section",
                  "NetworkPolicy", "UserPolicy", "HTTPBasedPolicy", "MoveTo"}  # fmt: skip
_MATCH_ELEMENTS = {"Action", "LogTraffic", "SkipLocalDestined", "SourceZones", "DestinationZones", "Schedule", "SourceNetworks",
                   "DestinationNetworks", "Services", "Exclusions", "MatchIdentity", "Identity", "ShowCaptivePortal",
                   "DataAccounting"}  # fmt: skip
# Inspection that a rule applies to what it allows: reported as profiles, as for every platform, under the
# name of the element. Both spellings of an element that documentation shows are listed.
PROFILE_ELEMENTS = ("WebFilter", "ApplicationControl", "IntrusionPrevention", "ScanVirus", "ZeroDayProtection", "Sandstorm",
                    "ProxyMode", "DecryptHTTPS", "ScanHTTP", "ScanHTTPS", "ScanFTP", "ScanSMTP", "ScanSMTPS", "ScanIMAP",
                    "ScanIMAPS", "ScanPOP3", "ScanPOP3S")  # fmt: skip
# Security Heartbeat: the rule is for endpoints that report a health status, of this colour or better. That
# says who the rule is for, as a host profile does elsewhere: a condition, which no target takes.
_HEARTBEAT_ELEMENTS = ("SourceSecurityHeartbeat", "MinimumSourceHBPermitted", "DestSecurityHeartbeat",
                       "MinimumDestHBPermitted", "MinimumDestinationHBPermitted")  # fmt: skip
# What a rule does with its traffic besides: kept for the audit ("do two rules handle traffic alike").
_HANDLING_ELEMENTS = {"BlockQuickQuic", "TrafficShappingPolicy", "TrafficShapingPolicy", "DSCPMarking", "WebCategoryBaseQoSPolicy",
                      "ApplicationBaseQoSPolicy", "ApplicationControlInternetScheme", "WebFilterInternetScheme", "PrimaryGateway", "BackupGateway",
                      "RewriteSourceAddress", "OutboundAddress", "ApplyNAT", "OverrideGatewayDefaultNATPolicy"}  # fmt: skip
# Of these, what says that the rule itself translates the source: how SFOS before version 18 wrote NAT.
_RULE_NAT_ELEMENTS = ("ApplyNAT", "RewriteSourceAddress")
_NAT_ELEMENTS = {"Name", "Description", "IPFamily", "Status", "Position", "After", "Before", "MoveTo", "LinkedFirewallrule",
                 "TranslatedDestination", "TranslatedService", "OriginalSourceNetworks", "TranslatedSource",
                 "OriginalDestinationNetworks", "OriginalServices", "InboundInterfaces", "OutboundInterfaces",
                 "OverrideInterfaceNATPolicy", "InterfaceNATPolicyList", "NATMethod", "HealthCheck", "ProbeMethod", "Port",
                 "ProbeInterval", "ResponseTimeOut", "DeactivateHostAfter", "monitorindex"}  # fmt: skip
# Words in the name of an element nobody told this parser about that make it a match criterion until proven otherwise.
_CRITERION_WORDS = ("zone", "network", "service", "source", "destination", "identity", "exclu", "interface", "user", "member",
                    "schedule", "host", "port", "protocol")  # fmt: skip
_EXCLUSIONS = ("SourceZones", "DestinationZones", "SourceNetworks", "DestinationNetworks", "Services")
# Entities whose names can stand in the networks of a rule and are no addresses.
_OTHER_HOSTS = {"MACHost": "MAC address host", "CountryGroup": "country group", "Country": "country"}


def looks_like_sophos(data: bytes) -> bool:
    """An export archive, or XML whose first element is one Sophos writes."""
    if _is_tar(data):
        return True
    head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    while head.startswith((b"<?", b"<!--")):
        end = head.find(b"?>" if head.startswith(b"<?") else b"-->")
        if end < 0:
            return False
        head = head[end + (2 if head.startswith(b"<?") else 3):].lstrip()
    return head.startswith((b"<Configuration", b"<Response", b"<Request", b"<Set"))


def _is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


def _unpack(data: bytes) -> bytes:
    """The Entities.xml of an export archive; anything else as it is."""
    if data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00":
        raise ParseError("the input is compressed; unpack it and give FWShift the .tar or the Entities.xml inside")
    if not _is_tar(data):
        return data
    found: List[bytes] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                if member.isfile() and member.name.replace("\\", "/").rsplit("/", 1)[-1] == "Entities.xml":
                    if member.size > _MAX_XML:
                        raise ParseError("the Entities.xml in the archive is larger than 512 MB; refusing to read it")
                    handle = archive.extractfile(member)
                    if handle is not None:
                        found.append(handle.read())
                    if len(found) > 1:
                        raise ParseError("the archive holds more than one Entities.xml; give FWShift the one that is meant")
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        raise ParseError(f"the archive could not be read: {exc}") from None
    if not found:
        raise ParseError("the archive holds no Entities.xml; expected the .tar of 'Backup & firmware > Import export'")
    return found[0]


def _text(element: Optional[ET.Element], path: str = "", default: str = "") -> str:
    if element is None:
        return default
    found = element.find(path) if path else element
    if found is None or found.text is None:
        return default
    return found.text.strip() or default


def _on(text: str) -> bool:
    return text.strip().lower() in ("enable", "enabled", "on", "yes", "1", "true")


def _unique(name: str, taken: Set[str]) -> str:
    candidate, counter = name, 2
    while candidate in taken:
        candidate = f"{name}-{counter}"
        counter += 1
    taken.add(candidate)
    return candidate


def _criterion_like(tag: str) -> bool:
    lowered = tag.lower()
    return any(word in lowered for word in _CRITERION_WORDS)


def parse(data: bytes, report: Report) -> Policy:
    root = xmlread.fromstring(_unpack(data), "exports of a Sophos Firewall")
    for element in root.iter():
        if isinstance(element.tag, str) and "}" in element.tag:
            element.tag = element.tag.rsplit("}", 1)[1]  # an export has no namespaces: an entity in one is read all the same
    containers = _containers(root)
    if not containers:
        raise ParseError("no <Configuration> element found; expected the Entities.xml of a Sophos Firewall export")
    for login in root.iter("Login"):
        status = _text(login, "status") or _text(login, "Status")
        if "fail" in status.lower():
            raise ParseError(f"the answer of the firewall says that the login failed ('{status[:60]}'): it holds no configuration")
    version = root.get("APIVersion", "") or containers[0].get("APIVersion", "")
    policy = Policy(vendor="sophos", scope=f"API version {version}" if version else "")
    entities = [child for container in containers for child in container if not _no_records(child)]
    _Reader(policy, report, entities).run()
    return policy


def _containers(root: ET.Element) -> List[ET.Element]:
    """The elements whose children are entities: the configuration itself, or what an API call wraps around it."""
    nested = [element for element in root.iter("Configuration") if element is not root]
    if root.tag in ("Configuration", "Response") and not nested:
        return [root]
    if root.tag == "Request" and not nested:
        return root.findall("Set") + root.findall("Configuration")
    if root.tag == "Set" and not nested:
        return [root]
    if len(nested) > 1 or (nested and root.tag in ("Configuration", "Response", "Request", "Set")):
        raise ParseError("the XML holds several <Configuration> elements, or one inside another; expected one export")
    return nested


def _no_records(entity: ET.Element) -> bool:
    """What the API answers for a kind of entity it has none of: a status and nothing else."""
    return len(entity) == 1 and entity[0].tag == "Status" and "record" in _text(entity[0]).lower()


class _Reader:
    def __init__(self, policy: Policy, report: Report, entities: List[ET.Element]) -> None:
        self.p, self.report, self.entities = policy, report, entities
        self.interface_zone: Dict[str, str] = {}
        self.local_zones: Set[str] = set()
        self.unknown: Dict[str, int] = {}  # element of a rule nobody told this parser about -> rules that have it
        self.by_rule: Dict[str, List[Rule]] = {}  # name of a firewall rule -> what it became
        self.rule_names: Set[str] = set()
        self.ambiguous: Set[str] = set()  # names that more than one firewall rule has
        self.interface_address: Dict[str, str] = {}
        self.zone_networks: Dict[str, List[Tuple[int, int, int]]] = {}  # zone -> the networks its interfaces are in

    def of(self, tag: str) -> List[ET.Element]:
        return [entity for entity in self.entities if entity.tag == tag]

    # -- top level --------------------------------------------------------

    def run(self) -> None:
        self._zones()
        self._hosts()
        self._services()
        rules = self._placed(self.of("FirewallRule"), "rule")
        self.rule_names = {_text(element, "Name") or "unnamed" for element in rules}  # a rule that is split takes none of these
        taken: Set[str] = set()
        for element in rules:
            name = _text(element, "Name") or "unnamed"
            if name in taken:
                self.ambiguous.add(name)
                name = _unique(name, self.rule_names)
            taken.add(name)
            made = self._rule(element, name)
            if made is None:
                continue
            self.by_rule[_text(element, "Name")] = made
            self.p.rules += made
        taken = set()
        for element in self._placed(self.of("NATRule"), "NAT rule"):
            nat = self._nat(element, _unique(_text(element, "Name") or "unnamed", taken))
            self.p.nat_rules.append(nat)
        self._forget_unused_system_hosts()
        if self.unknown:
            listed = ", ".join(f"<{tag}> ({count})" for tag, count in sorted(self.unknown.items()))
            self.report.note(
                Severity.INFO, "ELEMENTS_NOT_READ",
                f"elements of rules that this parser does not know and that do not look like a match criterion: {listed}. "
                "What they say is not converted",
            )  # fmt: skip
        if not rules and not self.p.nat_rules:
            self.report.note(Severity.REVIEW, "NO_RULES", "the input holds no <FirewallRule> and no <NATRule>: was it "
                             "exported without the firewall rules?")  # fmt: skip

    def _forget_unused_system_hosts(self) -> None:
        """A firewall has a system host for each of its ports and tunnels: only those the policy names are kept."""
        used: Set[str] = {member for group in self.p.address_groups.values() for member in group.members}
        for rule in self.p.rules:
            used |= set(rule.sources) | set(rule.destinations)
        for nat in self.p.nat_rules:
            used |= set(nat.sources) | set(nat.destinations)
            used |= set(nat.source_translation.addresses) if nat.source_translation else set()
            used |= {nat.destination_translation.address} if nat.destination_translation else set()
        for name in [name for name, address in self.p.addresses.items() if address.builtin == "sophos" and name not in used]:
            del self.p.addresses[name]
            self.report.discard("address", name)

    def _placed(self, elements: List[ET.Element], what: str) -> List[ET.Element]:
        """Rules in the order the firewall evaluates them.

        An export lists them in that order and says so again: each rule stands "After" the one
        before it. A file written for the API can say Top, Bottom, After or Before; it is read as
        the firewall would add the rules one by one.
        """
        lost: List[str] = []
        # Each IP version has a rulebase of its own: a rule is placed among the rules of its own.
        placed: Dict[bool, List[ET.Element]] = {False: [], True: []}
        names: Dict[bool, List[str]] = {False: [], True: []}
        for element in elements:
            six = _text(element, "IPFamily").lower() == "ipv6"
            out, listed, name = placed[six], names[six], _text(element, "Name")
            position = _text(element, "Position").lower()
            anchor = _text(element, "After/Name") if position == "after" else _text(element, "Before/Name") if position == "before" else ""
            if position == "top":
                index = 0
            elif position == "after" and listed and listed[-1] == anchor:
                index = len(out)  # what an export writes: each rule after the one before it
            elif anchor and anchor in listed:
                index = listed.index(anchor) + (1 if position == "after" else 0)
            else:
                index = len(out)
                if position != "bottom":
                    lost.append(name)  # no position, one this parser does not know, or a rule that is not there
            out.insert(index, element)
            listed.insert(index, name)
        if lost:
            self.report.note(
                Severity.REVIEW, "RULE_ORDER",
                f"{len(lost)} {what}(s) do not say where they stand, or stand after or before a rule that is not in the "
                f"input above them ({', '.join(lost[:5])}{' ...' if len(lost) > 5 else ''}): they were read in the order of "
                "the file. Check the order against the firewall",
            )  # fmt: skip
        return placed[False] + placed[True]

    # -- zones and interfaces ---------------------------------------------

    def _zones(self) -> None:
        for element in self.of("Zone"):
            name = _text(element, "Name")
            if not name:
                continue
            kind = _text(element, "Type").upper()
            if kind == "LOCAL" or (not kind and name == "LOCAL"):
                self.local_zones.add(name)  # the firewall itself: nothing is forwarded to it
                continue
            self.p.zones[name] = Zone(name)
        for element in self.entities:
            if element.tag in ("FirewallRule", "NATRule", "Zone") or len(element) == 0:
                continue
            zone = _text(element, "NetworkZone") or (_text(element, "Zone") if element.tag in ("VLAN", "LAG", "Bridge", "Alias") else "")
            name = _text(element, "Name") or _text(element, "Hardware")
            if zone and name and zone.lower() != "none" and zone not in self.local_zones:
                self.interface_zone[name] = zone
                for found in element.iter("IPAddress"):
                    interval = parse_literal(_text(found)) if "/" not in _text(found) and "-" not in _text(found) else None
                    if interval is not None and interval[0] == 4 and name not in self.interface_address:
                        self.interface_address[name] = _text(found)
                        masks = [_text(mask) for mask in element.iter("Netmask") if _text(mask)]
                        network = parse_literal(netmask_to_cidr(_text(found), masks[0]) or "") if masks else None
                        if network is not None and size(network) < 2**32:
                            self.zone_networks.setdefault(zone, []).append(network)
                if zone in self.p.zones and name not in self.p.zones[zone].interfaces:
                    self.p.zones[zone].interfaces.append(name)

    # -- hosts ------------------------------------------------------------

    def _define_address(self, name: str, kind: str) -> bool:
        if not name:
            return False
        if name in self.p.addresses or name in self.p.address_groups:
            self.report.add(kind, name, Severity.REVIEW, "DUPLICATE_NAME",
                            "the input defines this name more than once; the last definition was kept")  # fmt: skip
            self.p.addresses.pop(name, None)
            self.p.address_groups.pop(name, None)
        return True

    def _hosts(self) -> None:
        for element in self.of("IPHost"):
            name = _text(element, "Name")
            if self._define_address(name, "address"):
                self._ip_host(element, name)
        for element in self.of("FQDNHost"):
            name = _text(element, "Name")
            if self._define_address(name, "address"):
                fqdn = _text(element, "FQDN")
                if "*" in fqdn:
                    self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, fqdn, _text(element, "Description"),
                                                     raw=f"wildcard host name {fqdn}")  # fmt: skip
                    self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"wildcard host name '{fqdn}' cannot be converted")
                else:
                    self.p.addresses[name] = Address(name, AddressKind.FQDN, fqdn, _text(element, "Description"))
        for tag, what in _OTHER_HOSTS.items():
            for element in self.of(tag):
                name = _text(element, "Name")
                if self._define_address(name, "address"):
                    self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", _text(element, "Description"), raw=what)
                    self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{what} cannot be converted")
        groups = [(e, "HostList/Host") for e in self.of("IPHostGroup")] + [(e, "FQDNHostList/FQDNHost") for e in self.of("FQDNHostGroup")]
        for element, path in groups:
            name = _text(element, "Name")
            if self._define_address(name, "address-group"):
                members = [_text(member) for member in element.findall(path) if _text(member)]
                self.p.address_groups[name] = AddressGroup(name, members, _text(element, "Description"))
        # A host says which groups it is in; the group may not list it the other way round.
        for tag, path in (("FQDNHost", "FQDNHostGroupList/FQDNHostGroup"), ("IPHost", "HostGroupList/HostGroup")):
            for element in self.of(tag):
                for group in element.findall(path):
                    held = self.p.address_groups.get(_text(group))
                    if held is not None and _text(element, "Name") not in held.members:
                        held.members.append(_text(element, "Name"))

    def _ip_host(self, element: ET.Element, name: str) -> None:
        kind = _text(element, "HostType")
        description = _text(element, "Description")
        six = _text(element, "IPFamily").lower() == "ipv6"
        value: Optional[str] = None
        if kind == "IP":
            address = _text(element, "IPAddress")
            interval = parse_literal(address) if "/" not in address and "-" not in address else None
            value = address if interval is not None and size(interval) == 1 else None
            model_kind = AddressKind.NETWORK
        elif kind == "Network":
            address, subnet = _text(element, "IPAddress"), _text(element, "Subnet")
            if is_number(subnet) and "/" not in address:
                value = f"{address}/{subnet}" if parse_literal(f"{address}/{subnet}") is not None else None
            elif subnet and not six:
                value = netmask_to_cidr(address, subnet)
            if value is not None and value.endswith("/0"):
                value = None  # a network of every address: no firewall takes that for a host
            model_kind = AddressKind.NETWORK
        elif kind == "IPRange":
            value = f"{_text(element, 'StartIPAddress')}-{_text(element, 'EndIPAddress')}"
            value = value if parse_literal(value) is not None else None
            model_kind = AddressKind.RANGE
        elif kind == "IPList":
            listed = [part.strip() for part in _text(element, "ListOfIPAddresses").split(",") if part.strip()]
            family = 6 if six else 4
            if listed and all((parse_literal(part) or (0, 0, 0))[0] == family and "/" not in part and "-" not in part for part in listed):
                self.p.address_groups[name] = AddressGroup(name, listed, description)
                return
            model_kind = AddressKind.NETWORK
        else:
            # A system host stands for something of the firewall (the address of a port, the VPN clients):
            # another Sophos Firewall has it too, nobody else does.
            raw = f"system host of the firewall ('{name}')" if kind.lower() == "system host" else f"host of type '{kind or 'none'}'"
            system = kind.lower() == "system host"
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", description, raw=raw,
                                             builtin="sophos" if system else "", fqdn_family=(6 if six else 4) if system else 0)  # fmt: skip
            self.report.add("address", name, Severity.REVIEW, "UNSUPPORTED_ADDRESS", f"{raw} cannot be converted")
            return
        read = parse_literal(value) if value is not None else None
        if read is None or read[0] != (6 if six else 4):  # also an IPv4 address in a host that says it is IPv6
            raw = f"{kind} host whose address could not be read"
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", description, raw=raw)
            self.report.add("address", name, Severity.REVIEW, "INVALID_ADDRESS", raw)
            return
        assert value is not None
        self.p.addresses[name] = Address(name, model_kind, value, description)

    # -- services ---------------------------------------------------------

    def _services(self) -> None:
        for element in self.of("Services"):
            name = _text(element, "Name")
            if not name:
                continue
            service = Service(name, [], _text(element, "Description"))
            kind = _text(element, "Type")
            details = element.findall("ServiceDetails/ServiceDetail")
            problems = [problem for detail in details for problem in [self._detail(service, kind, detail)] if problem]
            if not details:
                problems.append("service without details")
            if problems:
                service.unsupported = problems[0]
                self.report.add("service", name, Severity.REVIEW, "UNSUPPORTED_SERVICE", f"{service.unsupported}: not converted")
            if name in self.p.services or name in self.p.service_groups:
                self.report.add("service", name, Severity.REVIEW, "DUPLICATE_NAME",
                                "the input defines this name more than once; the last definition was kept")  # fmt: skip
                self.p.service_groups.pop(name, None)
            self.p.services[name] = service
        for element in self.of("ServiceGroup"):
            name = _text(element, "Name")
            if not name:
                continue
            members = [_text(member) for member in element.findall("ServiceList/Service") if _text(member)]
            if name in self.p.services or name in self.p.service_groups:
                self.report.add("service-group", name, Severity.REVIEW, "DUPLICATE_NAME",
                                "the input defines this name more than once; the last definition was kept")  # fmt: skip
                self.p.services.pop(name, None)
            self.p.service_groups[name] = ServiceGroup(name, members, _text(element, "Description"))

    @staticmethod
    def _ports(text: str) -> Optional[str]:
        """``80``, ``8000:8080`` -> the model's ``80``, ``8000-8080``; every port is none at all. None: not ports."""
        text = text.strip().replace(":", "-")
        if not text or not valid_ports(text) or "," in text:
            return None
        first, _, last = text.partition("-")
        return "" if int(first) <= 1 and int(last or first) == 65535 else text

    def _detail(self, service: Service, kind: str, detail: ET.Element) -> str:
        """Add what one <ServiceDetail> says; return why it could not be read, if it could not."""
        expected = {"TCPorUDP": {"SourcePort", "DestinationPort", "Protocol"}, "IP": {"ProtocolName", "ProtocolNumber", "Protocol"},
                    "ICMP": {"ICMPType", "ICMPCode"}, "ICMPv6": {"ICMPv6Type", "ICMPv6Code"}}.get(kind)  # fmt: skip
        other = sorted({child.tag for child in detail} - (expected or set()))
        if expected is not None and other:
            return f"service of type {kind} with <{other[0]}>, which is no part of one"
        if kind == "TCPorUDP":
            protocol = {"tcp": Protocol.TCP, "udp": Protocol.UDP}.get(_text(detail, "Protocol").lower())
            dst = self._ports(_text(detail, "DestinationPort"))
            src = self._ports(_text(detail, "SourcePort", "1:65535"))
            if protocol is None or dst is None or src is None:
                return (f"protocol '{_text(detail, 'Protocol')}' with ports '{_text(detail, 'SourcePort')}' > "
                        f"'{_text(detail, 'DestinationPort')}' that could not be read")  # fmt: skip
            service.entries.append(ServiceEntry(protocol, dst, src))
            return ""
        if kind == "IP":
            named = _text(detail, "ProtocolName") or _text(detail, "ProtocolNumber") or _text(detail, "Protocol")
            number = sophos_protocol_number(named)
            if number is None:
                return f"IP protocol '{named}' that is not known"
            service.entries.append(ServiceEntry(Protocol.IP, ip_protocol=number))
            return ""
        if kind in ("ICMP", "ICMPv6"):
            six = kind == "ICMPv6"
            names = SOPHOS_ICMP6_NAMES if six else SOPHOS_ICMP_NAMES
            type_text = _text(detail, "ICMPv6Type" if six else "ICMPType")
            code_text = _text(detail, "ICMPv6Code" if six else "ICMPCode")
            icmp_type = _icmp_number(type_text, names, "any type")
            icmp_code = _icmp_number(code_text, {}, "any code")
            if icmp_type is False or icmp_code is False or (icmp_type is None and icmp_code is not None):
                return f"{kind} type '{type_text}' code '{code_text}' that could not be read"
            assert not isinstance(icmp_type, bool) and not isinstance(icmp_code, bool)
            service.entries.append(ServiceEntry(Protocol.ICMP6 if six else Protocol.ICMP, icmp_type=icmp_type, icmp_code=icmp_code))
            return ""
        return f"service of type '{kind or 'none'}'"

    # -- firewall rules ---------------------------------------------------

    def _members(self, block: Optional[ET.Element], path: str, child: str, what: str, problems: List[str]) -> List[str]:
        """The names in a list element; "any" when the element is not there, which is how Sophos writes any."""
        found = block.findall(path) if block is not None else []
        if not found:
            return [ANY]
        if len(found) > 1:
            problems.append(f"<{path}> given {len(found)} times")
            return [ANY]
        container = found[0]
        names = [_text(member) for member in container.findall(child) if _text(member)]
        if not names:
            problems.append(f"<{path}> without a <{child}>")  # never read an empty list as any
            return [ANY]
        if len(names) != len(container) or any(len(member) for member in container):
            problems.append(f"<{path}> holds something else than <{child}>")
        if (container.text or "").strip() or any((member.tail or "").strip() for member in container):
            problems.append(f"<{path}> holds text next to its <{child}> elements")
        return [ANY] if any(name.lower() == "any" for name in names) else list(dict.fromkeys(names))

    @staticmethod
    def _twice(element: ET.Element, problems: List[str]) -> None:
        """An element that is given twice says two things: neither is taken for the one that counts."""
        tags = [child.tag for child in element]
        for tag in sorted({tag for tag in tags if tags.count(tag) > 1}):
            problems.append(f"<{tag}> given {tags.count(tag)} times")

    @staticmethod
    def _enabled(element: ET.Element, problems: List[str]) -> bool:
        status = _text(element, "Status")
        if status.lower() in ("", "enable"):
            return True  # the API takes a rule without a status as an active one
        if status.lower() != "disable":
            problems.append(f"status '{status[:40]}', which is neither Enable nor Disable")
        return False

    def _unknown(self, element: ET.Element, known: Set[str], problems: List[str]) -> Dict[str, str]:
        """What a rule holds that this parser was not told about: a criterion until proven otherwise."""
        kept: Dict[str, str] = {}
        for child in element:
            if child.tag in known:
                continue
            content = " ".join("".join(child.itertext()).split())
            if _criterion_like(child.tag):
                if content.lower() not in _OFF and content.lower() not in ("any", "original"):
                    problems.append(f"element <{child.tag}> ('{content[:40]}') that this parser does not know")
            else:
                self.unknown[child.tag] = self.unknown.get(child.tag, 0) + 1
                if content.lower() not in _OFF:
                    kept[child.tag] = content[:80]
        return kept

    def _rule(self, element: ET.Element, name: str) -> Optional[List[Rule]]:
        kind = _text(element, "PolicyType")
        if kind.lower() == "httpbased" or (element.find("HTTPBasedPolicy") is not None and element.find("NetworkPolicy") is None):
            self.report.skip(
                "rule", name, "WAF_RULE",
                "web server protection rule: the firewall answers for the web server itself (a reverse proxy), which is "
                "not a forwarding rule and is not converted. Publish the server on the target in its own way",
            )  # fmt: skip
            return None
        if kind.lower() not in ("", "network", "user"):
            self.report.skip(
                "rule", name, "RULE_TYPE_NOT_READ",
                f"rule of type '{kind}', which this parser does not know (SFOS before version 18 published servers with "
                "rules of a type of their own): not converted",
            )  # fmt: skip
            return None
        problems: List[str] = []
        block = element.find("UserPolicy" if kind.lower() == "user" and element.find("UserPolicy") is not None else "NetworkPolicy")
        if block is None:
            block = element.find("UserPolicy")
        elif element.find("NetworkPolicy") is not None and element.find("UserPolicy") is not None:
            problems.append("a <NetworkPolicy> and a <UserPolicy> in one rule")
        rule = Rule(name=name, origin=name, description=_text(element, "Description"))
        rule.enabled = self._enabled(element, problems)
        self._twice(element, problems)
        rule.handling.update(self._unknown(element, _RULE_ELEMENTS, problems))
        if block is None:
            rule.unsupported += problems + ["rule without a <NetworkPolicy>"]
            rule.action = Action.DENY
            return [rule]
        self._twice(block, problems)
        known = _MATCH_ELEMENTS | set(PROFILE_ELEMENTS) | _HANDLING_ELEMENTS | set(_HEARTBEAT_ELEMENTS)
        rule.handling.update(self._unknown(block, known, problems))
        action = _text(block, "Action").lower()
        if action in _ACTIONS:
            rule.action = _ACTIONS[action]
        else:
            rule.action = Action.DENY
            problems.append(f"action '{_text(block, 'Action')}'" if action else "rule without <Action>")
        rule.log_end, rule.log_start = _on(_text(block, "LogTraffic")), False
        rule.src_zones = self._zone_list(block, "SourceZones", problems)
        rule.dst_zones = self._zone_list(block, "DestinationZones", problems)
        rule.sources = self._members(block, "SourceNetworks", "Network", "source", problems)
        rule.destinations = self._members(block, "DestinationNetworks", "Network", "destination", problems)
        rule.services = self._members(block, "Services", "Service", "service", problems)
        schedule = _text(block, "Schedule")
        if schedule.lower() not in _ALWAYS:
            rule.schedule = schedule
        if _on(_text(block, "MatchIdentity")):
            members = [_text(member) for member in block.findall("Identity/Member") if _text(member)]
            rule.users = list(dict.fromkeys(members)) or [KNOWN_USER]
            if _on(_text(block, "ShowCaptivePortal")):
                rule.handling["web-authentication"] = "unknown users are asked to sign in"
        elif block.find("Identity/Member") is not None and kind.lower() == "user":
            problems.append("user rule that does not say whether it matches known users")
        for tag in PROFILE_ELEMENTS:
            value = _text(block, tag)
            if value.lower() not in _OFF:
                rule.profiles[tag] = value
        for tag in sorted(_HANDLING_ELEMENTS):
            value = _text(block, tag)
            if value.lower() not in _OFF:
                rule.handling[tag] = value
        health = [f"{tag}={_text(block, tag)}" for tag in _HEARTBEAT_ELEMENTS if _text(block, tag).lower() not in _OFF]
        if health:
            problems.append(f"Security Heartbeat condition ({', '.join(health)}): the rule is for endpoints that report "
                            "their health only")  # fmt: skip
        if rule.handling:
            self.report.add(
                "rule", rule.origin, Severity.INFO, "HANDLING_NOT_CONVERTED",
                "what else the rule does with the traffic it matches is not converted: "
                + ", ".join(f"{tag}={value}" for tag, value in sorted(rule.handling.items())),
            )  # fmt: skip
        translating = [tag for tag in _RULE_NAT_ELEMENTS if tag in rule.handling]
        if translating:
            self.report.add(
                "rule", rule.origin, Severity.REVIEW, "RULE_NAT",
                f"the rule itself translates the source address (<{translating[0]}>, as SFOS before version 18 wrote NAT): "
                "that translation is not converted. Only the NAT rules of a configuration of version 18 or later are",
            )  # fmt: skip
        rule.unsupported += list(dict.fromkeys(problems))
        six = _text(element, "IPFamily").lower() == "ipv6"
        made = self._exclusions(rule, block.find("Exclusions"), six)
        if not made:
            self.report.skip("rule", name, "RULE_MATCHES_NOTHING",
                             "the exclusions of the rule take all of what it matches: it never applies, and is left out",
                             Severity.INFO)  # fmt: skip
            return None
        for one in made:
            self._pin(one, six)
        return made

    def _zone_list(self, block: ET.Element, path: str, problems: List[str]) -> List[str]:
        zones = self._members(block, path, "Zone", "zone", problems)
        # The zone of the firewall itself, by its type; by its name where the input does not define the zones.
        local = [zone for zone in zones if zone in self.local_zones or (zone == "LOCAL" and zone not in self.p.zones)]
        if local and zones != [ANY]:
            zones = [zone for zone in zones if zone not in local]
            if not zones:
                problems.append("rule for the firewall itself (zone LOCAL), which is not forwarded traffic")
                return [ANY]
        return zones

    def _exclusions(self, rule: Rule, element: Optional[ET.Element], six: bool) -> List[Rule]:
        """The rule without what its exclusions take out.

        Sophos skips a rule for traffic that matches every kind of exclusion the rule has. What
        the rule matches is therefore its match and (not kind 1 or not kind 2 ...): one rule per
        kind, each with that one field cut down. With one kind, which is the usual case, it stays
        one rule.
        """
        if element is None or len(element) == 0:
            return [rule]
        problems: List[str] = []
        kinds: List[Tuple[str, List[str]]] = []
        for child in element:
            if child.tag not in _EXCLUSIONS:
                problems.append(f"exclusion <{child.tag}> that this parser does not know")
                continue
            names = self._members(element, child.tag, "Zone" if child.tag.endswith("Zones") else "Service" if child.tag == "Services" else "Network",
                                  "exclusion", problems)  # fmt: skip
            if names == [ANY]:
                problems.append(f"exclusion of any in <{child.tag}>")
            else:
                kinds.append((child.tag, names))
        if problems:
            rule.unsupported += problems
            return [rule]
        made: List[Rule] = []
        for position, (kind, names) in enumerate(kinds):
            one = copy.deepcopy(rule)
            if position:
                one.name = one.origin = _unique(rule.name, self.rule_names)
            if self._exclude(one, kind, names, six):
                made.append(one)
        if not made:
            return []  # every kind of exclusion takes all of the rule: it matches nothing
        if len(kinds) > 1:
            self.report.add(
                "rule", made[0].origin, Severity.INFO, "RULE_SPLIT",
                f"the rule has exclusions of {len(kinds)} kinds, which Sophos Firewall applies together (the rule is skipped "
                f"only for traffic that matches all of them): written as {len(made)} rule(s), one per kind, that match the "
                "same traffic between them" + ("" if len(made) == 1 else ": " + ", ".join(f"'{one.name}'" for one in made[1:])),
            )  # fmt: skip
        return made

    def _exclude(self, rule: Rule, kind: str, names: List[str], six: bool) -> bool:
        """Cut one field of a rule down by an exclusion; False when nothing is left of the rule."""
        if kind.endswith("Zones"):
            source = kind == "SourceZones"
            zones = rule.src_zones if source else rule.dst_zones
            if zones == [ANY]:
                if not self.p.zones:
                    rule.unsupported.append(f"exclusion of zone {', '.join(names)} from any zone, with no zones in the input to say what is left")
                    return True
                zones = list(self.p.zones)
                blocking = rule.action != Action.ALLOW
                self.report.add(
                    "rule", rule.origin, Severity.REVIEW if blocking else Severity.APPROX, "EXCLUSION_ZONES",
                    f"any {'source' if source else 'destination'} zone except {', '.join(names)}: written as the other zones "
                    f"the input defines ({', '.join(zone for zone in zones if zone not in names) or 'none'}). A zone that is "
                    "not in the input, or is added to the firewall later, is not among them"
                    + (": this blocking rule does not block its traffic" if blocking else ""),
                )  # fmt: skip
            left = [zone for zone in zones if zone not in names]
            if source:
                rule.src_zones = left
            else:
                rule.dst_zones = left
            return bool(left)
        if kind == "Services":
            if rule.services == [ANY]:
                rule.services, rule.negate_service = names, True
            else:
                rule.unsupported.append(f"exclusion of service {', '.join(names)} from a list of services")
            return True
        source = kind == "SourceNetworks"
        members = rule.sources if source else rule.destinations
        side = "source" if source else "destination"
        if members == [ANY]:
            if source:
                rule.sources, rule.negate_source = names, True
            else:
                rule.destinations, rule.negate_destination = names, True
            return True
        held = self._intervals(members)
        taken = self._intervals(names)
        if held is None or taken is None:
            rule.unsupported.append(f"exclusion of {side} {', '.join(names)} from {', '.join(members)}, of which not every address is known")
            return True
        family = 6 if six else 4
        held = [interval for interval in held if interval[0] == family]
        rest = subtract(held, taken)
        if rest == normalize(held):
            return True  # the exclusion names nothing the rule is for
        if not rest:
            return False
        literals = [interval_text(interval) for interval in rest]
        if source:
            rule.sources = literals
        else:
            rule.destinations = literals
        self.report.add(
            "rule", rule.origin, Severity.INFO, "EXCLUSION_AS_ADDRESSES",
            f"{side} {', '.join(members)} without the excluded {', '.join(names)}: written as the addresses that are left "
            f"({', '.join(literals[:6])}{' ...' if len(literals) > 6 else ''})",
        )  # fmt: skip
        return True

    def _intervals(self, members: List[str]) -> Optional[List[Tuple[int, int, int]]]:
        out: List[Tuple[int, int, int]] = []
        for member in members:
            resolved = transform.address_intervals(self.p, member)
            if not resolved:
                return None
            out += resolved
        return normalize(out)

    def _pin(self, rule: Rule, six: bool) -> None:
        """Say in the rule itself which IP version it is for: in the model "any" is both."""
        literal, family = (ANY_V6, 6) if six else (ANY_V4, 4)
        if rule.sources == [ANY] and not rule.negate_source:
            rule.sources = [literal]
            return
        if rule.destinations == [ANY] and not rule.negate_destination:
            rule.destinations = [literal]
            return
        for members, negated in ((rule.sources, rule.negate_source), (rule.destinations, rule.negate_destination)):
            if not negated and all(self._families(member) == {family} for member in members):
                return
        self.report.add(
            "rule", rule.origin, Severity.APPROX, "IP_FAMILY",
            f"rule of the IPv{family} rulebase whose addresses do not say so (host names, or objects of the other IP "
            f"version): here it also matches IPv{4 if six else 6} traffic of the same names",
        )  # fmt: skip

    def _families(self, member: str) -> Set[int]:
        address = self.p.addresses.get(member)
        if address is not None and address.builtin == "sophos":
            return {address.fqdn_family or 4}  # a system host says which IP version it is of
        return transform.families(self.p, member)

    # -- NAT --------------------------------------------------------------

    def _nat_zones(self, element: ET.Element, path: str, nat: NatRule, inbound: bool, problems: List[str]) -> List[str]:
        interfaces = self._members(element, path, "Interface", "interface", problems)
        if interfaces == [ANY]:
            return [ANY]
        direction = "that enters by" if inbound else "that leaves by"
        # Where the interface was all that kept the rule to part of the traffic, the difference is not a detail.
        only = ANY in nat.destinations and (ANY in nat.sources or not inbound)
        zones: List[str] = []
        unknown = [name for name in interfaces if name not in self.interface_zone]
        if unknown:
            self.report.add(
                "nat", nat.origin, Severity.REVIEW if only else Severity.APPROX, "NAT_INTERFACE",
                f"the rule applied to traffic {direction} interface {', '.join(interfaces)} only; the input does not say which "
                f"zone {', '.join(unknown)} is in, so the rule is written without a zone and applies whatever the interface"
                + (". Nothing else limits it: export the zones and interfaces with the rules" if only else ""),
            )  # fmt: skip
            return [ANY]
        for name in interfaces:
            zone = self.interface_zone[name]
            if zone not in zones:
                zones.append(zone)
        others = sorted({name for name, zone in self.interface_zone.items() if zone in zones and name not in interfaces})
        if others:
            self.report.add(
                "nat", nat.origin, Severity.APPROX, "NAT_INTERFACE",
                f"the rule applied to traffic {direction} interface {', '.join(interfaces)} only; it is written for zone "
                f"{', '.join(zones)}, which also holds {', '.join(others[:6])}{' ...' if len(others) > 6 else ''}",
            )  # fmt: skip
        return zones

    def _nat(self, element: ET.Element, name: str) -> NatRule:
        nat = NatRule(name=name, origin=name, description=_text(element, "Description"))
        problems: List[str] = []
        nat.enabled = self._enabled(element, problems)
        self._twice(element, problems)
        self._unknown(element, _NAT_ELEMENTS, problems)
        six = _text(element, "IPFamily").lower() == "ipv6"
        linked = _text(element, "LinkedFirewallrule")
        if linked.lower() not in ("", "none"):
            self._linked(nat, linked, problems)
        else:
            nat.sources = self._members(element, "OriginalSourceNetworks", "Network", "source", problems)
            nat.destinations = self._members(element, "OriginalDestinationNetworks", "Network", "destination", problems)
            services = self._members(element, "OriginalServices", "Service", "service", problems)
            nat.service = self._one_service(nat, services)
            nat.src_zones = self._nat_zones(element, "InboundInterfaces", nat, True, problems)
            nat.dst_zones = self._nat_zones(element, "OutboundInterfaces", nat, False, problems)
        if six and nat.sources == [ANY]:
            nat.sources = [ANY_V6]
        source = _text(element, "TranslatedSource")
        if source.lower() == "masq":
            nat.source_translation = SourceNat(SnatKind.INTERFACE)
            # The address is that of the interface the traffic leaves by: named where the rule is for one.
            leaving = [name for name, zone in self.interface_zone.items() if zone in nat.dst_zones]
            listed = [_text(member) for member in element.findall("OutboundInterfaces/Interface") if _text(member)]
            if len(listed or leaving) == 1:
                nat.source_translation.interface = (listed or leaving)[0]
                nat.source_translation.interface_address = self.interface_address.get((listed or leaving)[0], "")
        elif source.lower() not in ("", "original"):
            # One host to one host keeps its address for address; anything else shares the translated addresses.
            one = all(self._one_address(member) for member in nat.sources + [source])
            nat.source_translation = SourceNat(SnatKind.STATIC if one and len(nat.sources) == 1 else SnatKind.DYNAMIC_PORT, [source])
        if _on(_text(element, "OverrideInterfaceNATPolicy")):
            self.report.add(
                "nat", nat.origin, Severity.REVIEW, "NAT_INTERFACE_OVERRIDE",
                "the rule translates the source to another address for some outgoing interfaces; only its general "
                "translation is converted",
            )  # fmt: skip
        destination = _text(element, "TranslatedDestination")
        port_service = _text(element, "TranslatedService")
        if destination.lower() not in ("", "original"):
            nat.destination_translation = DestNat(destination)
            targets = transform.address_intervals(self.p, destination)
            several = targets is None or sum(size(interval) for interval in targets) > 1
            method = _text(element, "NATMethod").lower().replace("-", "").replace("_", "").replace(" ", "")
            nat.destination_translation.spread = several and method not in ("onetoone", "1to1")
            if nat.destination_translation.spread and (method not in ("", "roundrobin") or _on(_text(element, "HealthCheck"))):
                self.report.add(
                    "nat", nat.origin, Severity.APPROX, "NAT_LOAD_BALANCING",
                    f"the rule spreads connections over several servers by method '{_text(element, 'NATMethod') or 'default'}'"
                    + (" with a health check" if _on(_text(element, "HealthCheck")) else "")
                    + ": converted as a translation that picks one of the addresses per connection, without the method "
                    "and without the check",
                )  # fmt: skip
            if port_service.lower() not in ("", "original"):
                port = self._translated_port(port_service)
                if port is None:
                    problems.append(f"translated service '{port_service}' that is not one TCP or UDP port")
                else:
                    nat.destination_translation.port = port
        elif port_service.lower() not in ("", "original"):
            problems.append(f"translated service '{port_service}' without a translated destination")
        if nat.destination_translation is not None and linked.lower() in ("", "none"):
            # The model wants the zone the original destination is reached in. The rule does not say: Sophos Firewall
            # asks for "any" as the outbound interface of a rule that publishes an address. Where the interfaces of
            # the export tell (the address lies in the network of one), that zone; otherwise none.
            outbound = nat.dst_zones
            nat.dst_zones = self._reached_in(nat.destinations)
            if outbound != [ANY]:
                self.report.add(
                    "nat", nat.origin, Severity.APPROX, "NAT_OUTBOUND_INTERFACE",
                    f"the rule translates the destination and is limited to traffic that leaves by {', '.join(outbound)} "
                    "(given here as the zone): that condition is not converted, and the rule applies whatever the "
                    "interface the translated traffic leaves by",
                )  # fmt: skip
        if nat.source_translation is None and nat.destination_translation is None and linked.lower() in ("", "none"):
            pass  # a rule that says "do not translate this": the model has it as a rule without translation
        nat.unsupported += list(dict.fromkeys(problems))
        return nat

    def _reached_in(self, destinations: List[str]) -> List[str]:
        """The zones in whose interface networks every one of these addresses lies; any zone when that cannot be told."""
        zones: List[str] = []
        for member in destinations:
            intervals = transform.address_intervals(self.p, member) if member != ANY else None
            if not intervals:
                return [ANY]
            for interval in intervals:
                holding = [zone for zone, networks in self.zone_networks.items()
                           if any(n[0] == interval[0] and n[1] <= interval[1] and interval[2] <= n[2] for n in networks)]  # fmt: skip
                if len(holding) != 1:
                    return [ANY]
                if holding[0] not in zones:
                    zones.append(holding[0])
        return zones or [ANY]

    def _one_address(self, member: str) -> bool:
        intervals = transform.address_intervals(self.p, member) if member != ANY else None
        return bool(intervals) and len(intervals or []) == 1 and size((intervals or [])[0]) == 1

    def _one_service(self, nat: NatRule, services: List[str]) -> str:
        if len(services) == 1:
            return services[0]
        name = f"{nat.name} services"
        counter = 2
        while name in self.p.services or name in self.p.service_groups:
            name = f"{nat.name} services {counter}"
            counter += 1
        self.p.service_groups[name] = ServiceGroup(name, list(services), f"the services of NAT rule {nat.name}")
        return name

    def _translated_port(self, service: str) -> Optional[str]:
        entries = transform.flatten_services(self.p, service)
        if not entries:
            return None
        ports = {entry.dst_ports for entry in entries}
        if len(ports) != 1 or len({entry.protocol for entry in entries}) != len(entries):
            return None
        if any(entry.protocol not in (Protocol.TCP, Protocol.UDP) or not is_number(entry.dst_ports) or entry.src_ports for entry in entries):
            return None
        return entries[0].dst_ports

    def _linked(self, nat: NatRule, linked: str, problems: List[str]) -> None:
        """A linked NAT rule has no match of its own: it translates the source of what its firewall rule matches."""
        rules = self.by_rule.get(linked)
        if linked in self.ambiguous:
            problems.append(f"linked to firewall rule '{linked}', a name that several rules of the input have")
            return
        if not rules:
            problems.append(f"linked to firewall rule '{linked}', which is not in the input or was not read")
            return
        rule = rules[0]
        if nat.enabled and (not rule.enabled or rule.action != Action.ALLOW):
            # It translates what its firewall rule lets through: of a rule that is off, or that blocks, nothing.
            nat.enabled = False
            self.report.add(
                "nat", nat.origin, Severity.INFO, "NAT_LINKED_INACTIVE",
                f"linked to firewall rule '{linked}', which is {'disabled' if not rule.enabled else 'a blocking rule'}: the "
                "NAT rule translated nothing, and is converted disabled",
            )  # fmt: skip
        inexact = []
        if len(rules) > 1 or rule.negate_source or rule.negate_destination or rule.negate_service:
            inexact.append("its exclusions")
        if rule.users != [ANY]:
            inexact.append("its users")
        if rule.schedule:
            inexact.append("its schedule")
        # It translates what its firewall rule decides. Traffic of the same kind that a rule above lets through is
        # not its business on the firewall, and is here.
        above = [other.name for other in self.p.rules[: self.p.rules.index(rule)]
                 if other.enabled and other.action == Action.ALLOW and self._zones_meet(other, rule)]  # fmt: skip
        if rule.unsupported:
            problems.append(f"linked to firewall rule '{linked}', which could not be read completely")
        nat.src_zones, nat.dst_zones = list(rule.src_zones), list(rule.dst_zones)
        # "Any" of an IPv4 rule is any again in an IPv4 NAT rule; an IPv6 rule keeps saying that it is one.
        nat.sources = [ANY] if rule.negate_source or rule.sources == [ANY_V4] else list(rule.sources)
        nat.destinations = [ANY] if rule.negate_destination or rule.destinations == [ANY_V4] else list(rule.destinations)
        nat.service = ANY if rule.negate_service else self._one_service(nat, list(rule.services))
        rule.handling["linked-nat"] = nat.name
        for other in rules[1:]:
            other.handling["linked-nat"] = nat.name
        self.report.add(
            "nat", nat.origin, Severity.APPROX if inexact else Severity.INFO, "NAT_LINKED",
            f"linked NAT rule of firewall rule '{linked}': it has no match of its own and is written with the zones, "
            "addresses and services of that rule" + (f", without {' and '.join(inexact)}: it applies to more traffic "
                                                      "than on the source" if inexact else ""),
        )  # fmt: skip
        if above:
            self.report.add(
                "nat", nat.origin, Severity.APPROX, "NAT_LINKED_ABOVE",
                f"on the firewall the rule translates only what firewall rule '{linked}' itself lets through. Here it also "
                f"applies to traffic of the same zones, addresses and services that a rule above it lets through "
                f"({', '.join(above[:4])}{' ...' if len(above) > 4 else ''}), if the two overlap",
            )  # fmt: skip

    @staticmethod
    def _zones_meet(a: Rule, b: Rule) -> bool:
        return all(ANY in first or ANY in second or bool(set(first) & set(second))
                   for first, second in ((a.src_zones, b.src_zones), (a.dst_zones, b.dst_zones)))  # fmt: skip


def _icmp_number(text: str, names: Dict[str, int], any_word: str) -> "Optional[int] | bool":
    """A type or code: a number, None for any, False for what could not be read."""
    lowered = text.strip().lower()
    if lowered in ("", "-1", any_word, "any"):
        return None
    if is_number(lowered) and len(lowered) <= 3 and int(lowered) <= 255:
        return int(lowered)
    if lowered in names:
        return names[lowered]
    return False


__all__ = ["KNOWN_USER", "PROFILE_ELEMENTS", "looks_like_sophos", "parse"]
