# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""LANCOM R&S Unified Firewall parser: the JSON of the REST API of LCOS FX -> neutral model.

The firewall (formerly Rohde & Schwarz Cybersecurity Unified Firewall, gateprotect) keeps its policy on the
*desktop*: desktop objects (hosts, networks, IP ranges, host and network groups, Internet objects, VPN and user
objects), and connections between two of them. A connection holds a list of services; each service of a connection
is a rule of its own, with a direction, NAT, a schedule, logging and DMZ (port forwarding) settings. LANCOM documents
no file a program can read: a backup (``.bak``, earlier ``.gp``) is encrypted with a password. What can be read is
what the REST API answers (LCOS FX 11.1 and later documents it on the firewall itself, *Help > REST API
Documentation*), saved to one file (section 3 of the manual). LANCOM publishes the field names of that API only by the
examples of its LMC add-ins; the rest is assumed, and the report says so (``LANCOM_UF_FORMAT``).

How the firewall differs from the model, and what is done about it:

* The policy only allows. A service on a connection lets connections through in its direction (``leftToRight``:
  from the first object ``obja`` to the second ``objb``; ``rightToLeft``; ``both``); what no connection allows is
  blocked. LANCOM documents no rule that blocks and no order: every rule of the model allows, the order is that of
  the input and does not matter. A rule whose ``action`` is none of the three directions is not used.
* The firewall is stateful: the replies of an allowed connection pass (the manual: TCP connections are tracked).
* Desktop objects are bound to an interface: a host, a network or an IP range names the interface it is connected
  through, and the firewall takes packets from its addresses on that interface only (an IP range may say ``any``).
  The interfaces are the zones of the model: a rule's source zone is the interface of its source object, its
  destination zone that of its destination object. An Internet object stands for every address behind the Internet
  connections it names, which are its zones. A group whose members are at several interfaces becomes one group per
  interface, and its rules one rule per interface.
* Rules between groups apply to their members too (the desktop shows them as inherited). The model's union of allow
  rules says the same, since an address of a member is an address of the group.
* NAT: masquerading (source NAT to the address of the outgoing interface) is set per service (``natactive``: ``left``
  for traffic from left to right, ``right``, ``both``) or on the connection. The per-service setting is read as a
  NAT rule of the model; the settings of the connection, a NAT source address and DMZ (port forwarding) are not, for
  their keys are not documented: the report says where.
* The desktop holds IPv4 objects (LCOS FX 11.1 documents IPv6 for connections, IPsec and a few services, not for
  desktop objects). An object with an attribute the parser does not know is not used.
* Services: TCP and UDP port ranges, ICMP (every type), and other IP protocols by name or number (GRE, ESP, AH, IGMP,
  OSPF, VRRP and protocols of the user). A schedule other than "always" is read as a schedule; a rule with no time
  range at all ("Always Off") as disabled (assumed).
* Rules for VPN and user objects are not converted; rules to and from the firewall itself are left out.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..errors import ParseError
from ..model import ANY, ANY_V4, Action, Address, AddressGroup, AddressKind, NatRule, Policy, Protocol, Rule, Service
from ..model import ServiceEntry, ServiceGroup, SnatKind, SourceNat, Zone
from ..netutil import interval_text, parse_literal
from ..report import Report, Severity
from .cisco import _documents

_MAX_OBJECTS = 200000
# The collections of the API (the names its URIs take, ``/model/<name>``), and what their items are.
_ENTITIES = {
    "hosts": "host", "networks": "network", "ipranges": "range", "ip-ranges": "range", "hostgroups": "group",
    "host-groups": "group", "networkgroups": "group", "internet": "internet", "internet-objects": "internet",
    "vpngroups": "vpn", "vpnhosts": "vpn", "vpn-hosts": "vpn", "vpnnetworks": "vpn", "vpn-networks": "vpn",
    "users": "user", "usergroups": "user", "user-groups": "user", "vpnusers": "user", "vpnusergroups": "user",
    "ltausergroups": "user", "firewall": "firewall", "predefined-services": "service", "userdefined-services": "service",
    "servicegroups": "service", "service-groups": "service", "protocols": "protocol", "predefined-protocols": "protocol",
    "userdefined-protocols": "protocol", "network-connections": "netconn", "desktop-connections": "connection",
}  # fmt: skip
_TYPES = {"host": "host", "network": "network", "iprange": "range", "ip-range": "range", "hostgroup": "group",
          "networkgroup": "group", "internet": "internet", "vpngroup": "vpn", "vpnhost": "vpn", "vpnnetwork": "vpn",
          "user": "user", "usergroup": "user", "vpnuser": "user", "vpnusergroup": "user", "firewall": "firewall"}  # fmt: skip
# Collections read for nothing: their items say nothing about what the desktop allows.
_IGNORED = {"interfaces", "fwshift", "tags", "desktop-tags", "dhcp-interfaces"}
# Keys of a desktop object that do not change what it matches.
_COSMETIC = {"id", "name", "type", "description", "tags", "color", "icon", "top", "left", "layer", "nologin", "exemptFromIdps",
             "exemptFromAv", "userdefined", "editable"}  # fmt: skip
_RANGE_KEYS = (("start", "end"), ("startIp", "endIp"), ("ipv4Start", "ipv4End"), ("rangeStart", "rangeEnd"), ("from", "to"))
_MEMBER_KEYS = ("hostgroupobjectitems", "items", "members")
# Keys of a rule (a service of a connection), and of a connection, that are read where they are or change nothing it matches.
_RULE_KEYS = {"uniqueId", "dmz", "natactive", "editable", "timeranges", "action", "trafficshaping", "trafficShaping",
              "useConnectionTrafficShaping", "log", "applicationfilter", "useConnection", "id", "description"}  # fmt: skip
_CONNECTION_KEYS = {"id", "obja", "objb", "rules", "description", "color", "points", "blockall", "webfiltersettings",
                    "applicationfilter", "appfilterRoutingProfiles", "trafficshaping", "trafficShaping", "name"}  # fmt: skip
_SERVICE_KEYS = {"id", "name", "services", "userdefined", "description", "tags", "editable", "type"}
_ENTRY_KEYS = {"protocol", "portfrom", "portto", "noproxy", "id"}
_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "gre": 47, "esp": 50, "ah": 51, "igmp": 2, "ospf": 89, "vrrp": 112,
              "sctp": 132, "icmpv6": 58, "ipv6-icmp": 58}  # fmt: skip
_DIRECTIONS = {"lefttoright": ("ab",), "righttoleft": ("ba",), "both": ("ab", "ba"), "bidirectional": ("ab", "ba")}
_NAT = {"left": {"ab"}, "lefttoright": {"ab"}, "right": {"ba"}, "righttoleft": {"ba"}, "both": {"ab", "ba"},
        "bidirectional": {"ab", "ba"}, "none": set(), "off": set(), "": set()}  # fmt: skip
_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def looks_like_lancomuf(data: bytes) -> bool:
    """JSON with the desktop connections of the REST API of a Unified Firewall."""
    head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    sample = data[:2_000_000]
    if re.search(rb'"fwshift"\s*:\s*"lancom-uf"', sample):
        return True
    if b'"desktop-connections"' in sample:
        return True
    return b'"obja"' in sample and b'"objb"' in sample and b'"uniqueId"' in sample


def _short(value: Any, limit: int = 40) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _empty(value: Any) -> bool:
    return bool(value in (None, "", [], {}, False))


@dataclass
class _Obj:
    kind: str
    ident: str
    name: str
    raw: Dict[str, Any]
    label: str = ""  # its name in the model
    problem: str = ""
    # Where it is and what it holds: (zones, model members) per interface; the zones are [ANY] for "any interface".
    parts: List[Tuple[List[str], List[str]]] = field(default_factory=list)
    done: bool = False


@dataclass
class _Reader:
    report: Report
    p: Policy
    objects: List[_Obj] = field(default_factory=list)
    by_id: Dict[str, _Obj] = field(default_factory=dict)
    by_name: Dict[str, _Obj] = field(default_factory=dict)
    services: List[Dict[str, Any]] = field(default_factory=list)
    service_names: Dict[str, str] = field(default_factory=dict)  # id or name -> model name
    service_problems: Dict[str, str] = field(default_factory=dict)  # model name -> why it cannot be used
    service_proxied: Set[str] = field(default_factory=set)
    protocols: Dict[str, int] = field(default_factory=dict)  # id or name (lower case) -> number
    netconns: Dict[str, str] = field(default_factory=dict)  # id -> name
    connections: List[Dict[str, Any]] = field(default_factory=list)
    unknown: List[str] = field(default_factory=list)
    missing: Set[str] = field(default_factory=set)
    taken: Set[str] = field(default_factory=set)  # model names of addresses and groups
    rule_names: Set[str] = field(default_factory=set)
    zones: Set[str] = field(default_factory=set)
    connection_keys: Set[str] = field(default_factory=set)
    connection_nat: List[str] = field(default_factory=list)
    resolving: Set[str] = field(default_factory=set)
    count: int = 0

    # -- the answers ------------------------------------------------------------------------------

    def take(self, document: Any) -> None:
        if isinstance(document, dict) and not ({"obja", "objb"} <= set(document) or "services" in document
                                               or self._kind_of(document)):  # fmt: skip
            for key, value in document.items():
                if key == "fwshift":
                    continue
                self._collection(str(key), value)
            return
        self._collection("", document)

    def _collection(self, entity: str, value: Any) -> None:
        lowered = entity.lower().strip("/").rsplit("/", 1)[-1]
        if lowered in _IGNORED:
            return
        if isinstance(value, dict):
            inner = [value[k] for k in ("data", "items", "results", lowered) if isinstance(value.get(k), list)]
            items: List[Any] = inner[0] if len(inner) == 1 else [value]
        elif isinstance(value, list):
            items = value
        else:
            self.unknown.append(entity or "a value that is no JSON object")
            return
        for item in items:
            self._item(lowered, item)

    def _kind_of(self, item: Dict[str, Any], entity: str = "") -> str:
        kind = _ENTITIES.get(entity, "")
        if kind:
            return kind
        if {"obja", "objb"} <= set(item):
            return "connection"
        typed = _TYPES.get(str(item.get("type", "")).lower().replace("_", ""), "")
        if typed:
            return typed
        if isinstance(item.get("services"), list):
            return "service"
        return ""

    def _item(self, entity: str, item: Any) -> None:
        if not isinstance(item, dict):
            self.unknown.append(entity or "a list item that is no JSON object")
            return
        self.count += 1
        if self.count > _MAX_OBJECTS:
            raise ParseError(f"the input holds more than {_MAX_OBJECTS} objects: refusing to read on")
        kind = self._kind_of(item, entity)
        if kind == "connection":
            self.connections.append(item)
        elif kind == "service":
            self.services.append(item)
        elif kind == "protocol":
            number = _number(item.get("number", item.get("protocol", item.get("protocolNumber"))))
            if number is not None:
                for key in ("id", "name"):
                    if isinstance(item.get(key), str) and item[key]:
                        self.protocols[item[key].lower()] = number
        elif kind == "netconn":
            if isinstance(item.get("id"), str) and isinstance(item.get("name"), str):
                self.netconns[item["id"]] = item["name"]
        elif kind:
            ident = item.get("id", item.get("uuid", ""))
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ParseError(f"a desktop object without a name ({_short(json.dumps(item), 60)})")
            obj = _Obj(kind, str(ident) if isinstance(ident, (str, int)) and not isinstance(ident, bool) else "", name, item)
            if obj.ident and obj.ident in self.by_id:
                raise ParseError(f"desktop object id '{_short(obj.ident)}' is in the input twice")
            self.objects.append(obj)
            if obj.ident:
                self.by_id[obj.ident] = obj
            self.by_name.setdefault(name, obj)
        else:
            self.unknown.append(entity or _short(item.get("name", "an object of no known kind")))

    # -- desktop objects --------------------------------------------------------------------------

    def _label(self, name: str, kind: str) -> str:
        candidate = name if name not in self.taken else f"{name} ({kind})"
        counter = 2
        while candidate in self.taken:
            candidate = f"{name} ({kind} {counter})"
            counter += 1
        self.taken.add(candidate)
        return candidate

    def _zone(self, raw: Dict[str, Any], kind: str) -> Tuple[List[str], str]:
        """The zone of an object from its interface; a problem where it names none."""
        interface = raw.get("interface")
        if isinstance(interface, dict):
            interface = interface.get("name")
        if not isinstance(interface, str) or not interface.strip():
            return [], f"a {kind} that names no interface"
        interface = interface.strip()
        if interface.lower() == "any":
            return [ANY], ""
        self.zones.add(interface)
        return [interface], ""

    def resolve(self, obj: _Obj) -> None:
        if obj.done:
            return
        if obj.ident in self.resolving or obj.name in self.resolving:
            obj.problem = "a group that holds itself"
            obj.done = True
            return
        key = obj.ident or obj.name
        self.resolving.add(key)
        try:
            self._resolve(obj)
        finally:
            self.resolving.discard(key)
        obj.done = True

    def _extra_keys(self, raw: Dict[str, Any], allowed: Set[str]) -> str:
        extra = [k for k, v in raw.items() if k not in _COSMETIC and k not in allowed and not _empty(v)]
        return f"attribute '{_short(extra[0], 30)}', which this parser does not read" if extra else ""

    def _resolve(self, obj: _Obj) -> None:
        raw, kind = obj.raw, obj.kind
        if kind in ("vpn", "user", "firewall"):
            return
        obj.label = self._label(obj.name, kind)
        description = str(raw.get("description") or "")
        if kind in ("host", "network"):
            obj.problem = self._extra_keys(raw, {"interface", "ipv4"})
            zones, problem = self._zone(raw, kind)
            interval = parse_literal(str(raw.get("ipv4") or "")) if isinstance(raw.get("ipv4"), str) else None
            if interval is None or interval[0] != 4:
                problem = problem or f"IPv4 address '{_short(raw.get('ipv4'))}' that could not be read"
            obj.problem = obj.problem or problem
            if obj.problem:
                self.p.addresses[obj.label] = Address(obj.label, AddressKind.UNSUPPORTED, "", description, raw=obj.problem)
                return
            assert interval is not None
            self.p.addresses[obj.label] = Address(obj.label, AddressKind.NETWORK, interval_text(interval), description)
            obj.parts = [(zones, [obj.label])]
            return
        if kind == "range":
            pair = next((p for p in _RANGE_KEYS if p[0] in raw or p[1] in raw), None)
            allowed = {"interface"} | set(pair or ())
            obj.problem = self._extra_keys(raw, allowed)
            zones, problem = self._zone(raw, "IP range")
            interval = None
            if pair is not None:
                interval = parse_literal(f"{raw.get(pair[0])}-{raw.get(pair[1])}")
            if interval is None or interval[0] != 4:
                problem = problem or "an IP range whose start and end could not be read"
            obj.problem = obj.problem or problem
            if obj.problem:
                self.p.addresses[obj.label] = Address(obj.label, AddressKind.UNSUPPORTED, "", description, raw=obj.problem)
                return
            assert interval is not None
            self.p.addresses[obj.label] = Address(obj.label, AddressKind.RANGE, interval_text(interval), description)
            obj.parts = [(zones, [obj.label])]
            return
        if kind == "internet":
            obj.problem = self._extra_keys(raw, {"connections"})
            connections = raw.get("connections")
            names: List[str] = []
            if isinstance(connections, list):
                for item in connections:
                    value = item.get("name", item.get("id")) if isinstance(item, dict) else item
                    if isinstance(value, str) and value:
                        names.append(self.netconns.get(value, value))
            if not names:
                obj.problem = obj.problem or "an Internet object that names no Internet connection"
            if obj.problem:
                self.p.addresses[obj.label] = Address(obj.label, AddressKind.UNSUPPORTED, "", description, raw=obj.problem)
                return
            self.zones.update(names)
            self.p.addresses[obj.label] = Address(obj.label, AddressKind.NETWORK, ANY_V4,
                                                  description or "every address behind the Internet connections "
                                                  + ", ".join(names))  # fmt: skip
            obj.parts = [(list(dict.fromkeys(names)), [obj.label])]
            return
        if kind == "group":
            self._group(obj, description)
            return

    def _group(self, obj: _Obj, description: str) -> None:
        raw = obj.raw
        key = next((k for k in _MEMBER_KEYS if k in raw), "")
        obj.problem = self._extra_keys(raw, {key} if key else set())
        members = raw.get(key) if key else None
        if not obj.problem and (not isinstance(members, list) or not members):
            obj.problem = "a group without members"
        by_zone: Dict[str, List[str]] = {}
        order: List[str] = []
        if not obj.problem:
            assert isinstance(members, list)
            for index, item in enumerate(members):
                reference = item if isinstance(item, str) else None
                if isinstance(item, dict):
                    for ref_key in ("reference", "object", "objectId", "uuid"):
                        if isinstance(item.get(ref_key), str) and item[ref_key]:
                            reference = item[ref_key]
                    if reference is None and set(item) <= {"id", "name"} and isinstance(item.get("id"), str) and \
                            item["id"] in self.by_id:  # fmt: skip
                        reference = item["id"]
                if reference is not None:
                    inner = self.by_id.get(reference) or self.by_name.get(reference)
                    if inner is None:
                        self.missing.add(reference)
                        obj.problem = f"it holds '{_short(reference)}', which is not in the input"
                        break
                    if inner.kind not in ("host", "network", "range", "group"):
                        obj.problem = f"it holds '{_short(inner.name)}', a {inner.kind} object"
                        break
                    self.resolve(inner)
                    if inner.problem:
                        obj.problem = f"it holds '{_short(inner.name)}', which cannot be read: {inner.problem}"
                        break
                    for zones, labels in inner.parts:
                        for zone in zones:
                            if zone not in by_zone:
                                order.append(zone)
                            by_zone.setdefault(zone, []).extend(labels)
                    continue
                if not isinstance(item, dict):
                    obj.problem = "a member that is neither an object nor a reference"
                    break
                extra = [k for k, v in item.items() if k not in ("id", "name", "interface", "ipv4", "nologin") and not _empty(v)]
                if extra:
                    obj.problem = f"a member with '{_short(extra[0], 30)}', which this parser does not read"
                    break
                zones, problem = self._zone(item, "member")
                interval = parse_literal(item["ipv4"]) if isinstance(item.get("ipv4"), str) else None
                if problem or interval is None or interval[0] != 4:
                    obj.problem = problem or f"a member whose IPv4 address '{_short(item.get('ipv4'))}' could not be read"
                    break
                for zone in zones:
                    if zone not in by_zone:
                        order.append(zone)
                    by_zone.setdefault(zone, []).append(interval_text(interval))
        if obj.problem:
            self.p.address_groups[obj.label] = AddressGroup(obj.label, [], description, unsupported=obj.problem)
            return
        if len(order) == 1:
            self.p.address_groups[obj.label] = AddressGroup(obj.label, list(dict.fromkeys(by_zone[order[0]])), description)
            obj.parts = [([order[0]], [obj.label])]
            return
        everything = [m for zone in order for m in by_zone[zone]]
        self.p.address_groups[obj.label] = AddressGroup(obj.label, list(dict.fromkeys(everything)), description)
        for zone in order:
            label = self._label(f"{obj.name} ({'any interface' if zone == ANY else zone})", "part")
            self.p.address_groups[label] = AddressGroup(label, list(dict.fromkeys(by_zone[zone])),
                                                        f"the members of '{obj.name}' at interface {zone}")  # fmt: skip
            obj.parts.append(([zone], [label]))

    # -- services ---------------------------------------------------------------------------------

    def build_services(self) -> None:
        raw_by_name: Dict[str, Dict[str, Any]] = {}
        for raw in self.services:
            name = raw.get("name")
            if not isinstance(name, str) or not name:
                raise ParseError("a service without a name")
            label = name
            counter = 2
            while label in raw_by_name:
                label = f"{name} ({counter})"
                counter += 1
            raw_by_name[label] = raw
            ident = raw.get("id")
            if isinstance(ident, str) and ident:
                if ident in self.service_names:
                    raise ParseError(f"service id '{_short(ident)}' is in the input twice")
                self.service_names[ident] = label
            self.service_names.setdefault(name, label)
        for label, raw in raw_by_name.items():
            self._service(label, raw)
        changed = True
        while changed:
            changed = False
            for group in self.p.service_groups.values():
                if group.name in self.service_problems:
                    continue
                bad = [m for m in group.members if m in self.service_problems]
                if bad:
                    self.service_problems[group.name] = f"it holds '{bad[0]}', which {self.service_problems[bad[0]]}"
                    changed = True

    def _service(self, label: str, raw: Dict[str, Any]) -> None:
        description = str(raw.get("description") or "")
        extra = [k for k, v in raw.items() if k not in _SERVICE_KEYS and not _empty(v)]
        entries_raw = raw.get("services")
        problem = f"attribute '{_short(extra[0], 30)}', which this parser does not read" if extra else ""
        if not problem and (not isinstance(entries_raw, list) or not entries_raw):
            problem = "a service without ports or protocols"
        entries: List[ServiceEntry] = []
        refs: List[str] = []
        if not problem:
            assert isinstance(entries_raw, list)
            for item in entries_raw:
                if isinstance(item, str):
                    target = self.service_names.get(item)
                    if target is None:
                        self.missing.add(item)
                        problem = f"it holds '{_short(item)}', which is not in the input"
                        break
                    refs.append(target)
                    continue
                if not isinstance(item, dict):
                    problem = "an entry that is not a JSON object"
                    break
                found, problem = self._entry(item)
                if problem:
                    break
                assert found is not None
                entries.append(found)
                if item.get("noproxy") is False and found.protocol == Protocol.TCP:
                    self.service_proxied.add(label)
        if problem:
            self.p.services[label] = Service(label, [], description, unsupported=problem)
            self.service_problems[label] = problem
        elif refs:
            members = list(refs)
            if entries:
                own = f"{label} (entries)"
                self.p.services[own] = Service(own, entries)
                members.append(own)
            self.p.service_groups[label] = ServiceGroup(label, list(dict.fromkeys(members)), description)
        else:
            self.p.services[label] = Service(label, entries, description)

    def _entry(self, item: Dict[str, Any]) -> Tuple[Optional[ServiceEntry], str]:
        extra = [k for k, v in item.items() if k not in _ENTRY_KEYS and not _empty(v)]
        if extra:
            return None, f"an entry with '{_short(extra[0], 30)}', which this parser does not read"
        protocol = item.get("protocol")
        number = _number(protocol)
        if number is None and isinstance(protocol, str):
            number = _PROTOCOLS.get(protocol.strip().lower(), self.protocols.get(protocol.strip().lower()))
        if number is None:
            return None, f"protocol '{_short(protocol, 20)}' that could not be read"
        if number in (6, 17):
            low, high = _port(item.get("portfrom")), item.get("portto")
            top = low if high in (None, "", 0) else _port(high)
            if low is None or top is None or top < low:
                return None, f"ports '{_short(item.get('portfrom'))}' to '{_short(high)}' that could not be read"
            ports = "" if (low, top) == (1, 65535) else str(low) if low == top else f"{low}-{top}"
            return ServiceEntry(Protocol.TCP if number == 6 else Protocol.UDP, ports), ""
        if any(not _empty(item.get(k)) and item.get(k) != 0 for k in ("portfrom", "portto")):
            return None, f"ports for IP protocol {number}"
        if number == 1:
            return ServiceEntry(Protocol.ICMP), ""
        if number == 58:
            return ServiceEntry(Protocol.ICMP6), ""
        if number == 132:
            return ServiceEntry(Protocol.SCTP), ""
        if number == 0:
            return None, "IP protocol 0"
        return ServiceEntry(Protocol.IP, ip_protocol=number), ""

    # -- connections ------------------------------------------------------------------------------

    def _endpoint(self, raw: Any, problems: List[str]) -> Optional[_Obj]:
        if isinstance(raw, dict):
            raw = raw.get("id", raw.get("name"))
        if not isinstance(raw, (str, int)) or isinstance(raw, bool) or raw == "":
            problems.append("a connection that does not name both of its objects")
            return None
        key = str(raw)
        obj = self.by_id.get(key) or self.by_name.get(key)
        if obj is None:
            self.missing.add(key)
            problems.append(f"desktop object '{_short(key)}' is not in the input")
            return None
        self.resolve(obj)
        return obj

    def build_rules(self) -> None:
        for index, conn in enumerate(self.connections):
            self._connection(index, conn)

    def _connection(self, index: int, conn: Dict[str, Any]) -> None:
        base: List[str] = []
        a = self._endpoint(conn.get("obja"), base)
        b = self._endpoint(conn.get("objb"), base)
        ident = str(conn.get("id") or f"#{index + 1}")
        handling: Dict[str, str] = {}
        for key, value in conn.items():
            if key not in _CONNECTION_KEYS and not _empty(value):
                self.connection_keys.add(key)
                handling[f"connection {key}"] = _short(json.dumps(value, sort_keys=True), 80)
        shaping = conn.get("trafficShaping")
        if isinstance(shaping, dict) and not _empty(shaping.get("trafficGroup")):
            handling["traffic shaping"] = str(shaping["trafficGroup"])
        profiles: Dict[str, str] = {}
        application = conn.get("applicationfilter")
        if isinstance(application, dict) and str(application.get("mode", "off")).lower() not in ("off", "") and \
                application.get("activeprofiles"):  # fmt: skip
            profiles["application"] = _short(json.dumps(application["activeprofiles"]), 60)
        if not _empty(conn.get("webfiltersettings")):
            profiles["url-filter"] = "the URL and content filter of the connection"
        rules = conn.get("rules")
        if rules in (None, []):
            return
        if not isinstance(rules, list):
            raise ParseError(f"the rules of desktop connection '{_short(ident)}' are not a list")
        if (a is not None and a.kind == "firewall") or (b is not None and b.kind == "firewall"):
            label = self._rule_label(f"{a.name if a else '?'} to {b.name if b else '?'} - traffic to the firewall")
            self.report.skip("rule", label, "FIREWALL_TRAFFIC",
                             "the connection is between a desktop object and the firewall itself: traffic to the firewall "
                             "(its services, its administration) is not forwarded traffic and is not converted", Severity.INFO)  # fmt: skip
            return
        for position, raw in enumerate(rules):
            if not isinstance(raw, dict):
                raise ParseError(f"a rule of desktop connection '{_short(ident)}' is not a JSON object")
            self._rule(ident, position, a, b, raw, list(base), dict(handling), dict(profiles))

    def _rule_label(self, label: str) -> str:
        candidate, counter = label, 2
        while candidate in self.rule_names:
            candidate = f"{label} ({counter})"
            counter += 1
        self.rule_names.add(candidate)
        return candidate

    def _rule(self, conn_id: str, position: int, a: Optional[_Obj], b: Optional[_Obj], raw: Dict[str, Any], problems: List[str],
              handling: Dict[str, str], profiles: Dict[str, str]) -> None:  # fmt: skip
        notes: List[Tuple[Severity, str, str]] = []
        for key, value in raw.items():
            if key not in _RULE_KEYS and not _empty(value):
                problems.append(f"attribute '{_short(key, 30)}', which this parser does not read")
        # The service.
        ident = raw.get("uniqueId")
        service = self.service_names.get(str(ident)) if isinstance(ident, (str, int)) and not isinstance(ident, bool) else None
        if service is None:
            if isinstance(ident, (str, int)) and not isinstance(ident, bool) and str(ident):
                self.missing.add(str(ident))
                problems.append(f"service '{_short(ident)}' is not in the input")
            else:
                problems.append("the rule names no service")
        elif service in self.service_problems:
            problems.append(f"service '{_short(service)}' cannot be read: {self.service_problems[service]}")
        if service in self.service_proxied:
            handling["proxy"] = "the service is handed to the proxy of the firewall"
        # The direction.
        action = raw.get("action")
        directions = _DIRECTIONS.get(str(action).lower()) if isinstance(action, str) else None
        if directions is None:
            problems.append(f"action '{_short(action, 20)}', which is not a direction (LANCOM documents no rule that blocks)")
            directions = ("ab",)
        # Logging.
        log = raw.get("log", False)
        if not isinstance(log, bool):
            problems.append("the input does not say plainly whether the rule logs")
            log = False
        # The schedule.
        enabled, schedule, why = _schedule(raw.get("timeranges"))
        if why:
            problems.append(why)
        if not enabled:
            notes.append((Severity.INFO, "RULE_ALWAYS_OFF", "the rule has no time range (Always Off): read as disabled"))
        # NAT and DMZ.
        nat_raw = raw.get("natactive")
        nat_text = "" if nat_raw in (None, False) else str(nat_raw).lower().replace("-", "").replace("_", "")
        nat = _NAT.get(nat_text)
        uses_connection = raw.get("useConnection") is True
        if uses_connection:
            self.connection_nat.append(conn_id)
            notes.append((Severity.REVIEW, "CONNECTION_NAT_NOT_READ",
                          "the rule takes the NAT settings of its connection, whose keys are not known: whether and how the "
                          "connection translates is not read. Look at the NAT tab of the connection"))  # fmt: skip
            nat = set()
        elif nat is None:
            notes.append((Severity.REVIEW, "NAT_NOT_READ", f"NAT setting '{_short(nat_raw, 20)}' that could not be read"))
            nat = set()
        dmz = raw.get("dmz")
        if not _empty(dmz):
            handling["dmz"] = _short(json.dumps(dmz, sort_keys=True), 80)
            notes.append((Severity.REVIEW, "DMZ_NOT_READ",
                          "DMZ / port forwarding is set for the service; its keys are not known and the translation is not read: "
                          "the rule allows the connections that reach the host by its own address, not those forwarded to it"))  # fmt: skip
        application = raw.get("applicationfilter")
        if isinstance(application, dict) and application.get("activeprofiles"):
            profiles["application"] = _short(json.dumps(application["activeprofiles"]), 60)
        elif isinstance(application, dict) and application.get("useconnection") is False:
            profiles.pop("application", None)
        shaping = raw.get("trafficShaping")
        if isinstance(shaping, dict) and not _empty(shaping.get("trafficGroup")):
            handling["traffic shaping"] = str(shaping["trafficGroup"])
        for side in (a, b):
            if side is not None and side.kind in ("vpn", "user"):
                problems.append(f"'{_short(side.name)}' is a {'VPN' if side.kind == 'vpn' else 'user'} object, which is not converted")
            elif side is not None and side.problem:
                problems.append(f"desktop object '{_short(side.name)}' cannot be read: {side.problem}")
        a_parts = a.parts if a is not None and a.parts else [([ANY], [ANY])]
        b_parts = b.parts if b is not None and b.parts else [([ANY], [ANY])]
        a_name = a.name if a is not None else "?"
        b_name = b.name if b is not None else "?"
        service_name = service or str(ident or "?")
        made: List[Rule] = []
        for direction in directions:
            src_parts, dst_parts = (a_parts, b_parts) if direction == "ab" else (b_parts, a_parts)
            src_name, dst_name = (a_name, b_name) if direction == "ab" else (b_name, a_name)
            pairs = [(s, d) for s in src_parts for d in dst_parts]
            for src, dst in pairs:
                label = f"{src_name} to {dst_name} - {service_name}"
                if len(pairs) > 1:
                    zones = f"{', '.join(src[0])} to {', '.join(dst[0])}".replace(ANY, "any interface")
                    label += f" ({zones})"
                label = self._rule_label(label)
                rule = Rule(name=label, origin=label, action=Action.ALLOW, enabled=enabled, schedule=schedule,
                            log_end=log, log_start=False)  # fmt: skip
                rule.src_zones, rule.sources = list(src[0]), list(src[1])
                rule.dst_zones, rule.destinations = list(dst[0]), list(dst[1])
                rule.services = [service] if service is not None else [ANY]
                rule.unsupported = list(dict.fromkeys(problems))
                rule.handling = dict(handling)
                rule.profiles = dict(profiles)
                rule.source_ids = {"lancom-uf.connection": conn_id, "lancom-uf.rule": str(position + 1),
                                   "lancom-uf.direction": "leftToRight" if direction == "ab" else "rightToLeft"}  # fmt: skip
                self.p.rules.append(rule)
                made.append(rule)
                if direction in nat and service is not None and not problems:
                    nat_rule = NatRule(name=f"{label} (NAT)", origin=f"{label} (NAT)")
                    nat_rule.src_zones, nat_rule.sources = list(src[0]), list(src[1])
                    nat_rule.dst_zones, nat_rule.destinations = list(dst[0]), list(dst[1])
                    nat_rule.service = service
                    nat_rule.enabled = enabled
                    nat_rule.source_translation = SourceNat(SnatKind.INTERFACE, interface="" if dst[0] == [ANY] or len(dst[0]) > 1
                                                            else dst[0][0])  # fmt: skip
                    nat_rule.description = "masquerading of the service, to the address of the outgoing interface"
                    self.p.nat_rules.append(nat_rule)
        for rule in made:
            for severity, code, message in notes:
                self.report.add("rule", rule.origin, severity, code, message)
            if len(directions) == 2:
                self.report.add("rule", rule.origin, Severity.INFO, "BIDIRECTIONAL_SPLIT",
                                f"the service is allowed in both directions between '{_short(a_name)}' and '{_short(b_name)}': "
                                "read as one rule per direction")  # fmt: skip
            if len(made) > len(directions):
                self.report.add("rule", rule.origin, Severity.INFO, "INTERFACE_SPLIT",
                                "an object of the connection has members at several interfaces: read as one rule per pair of "
                                "interfaces, the interfaces as zones")  # fmt: skip


def _number(raw: Any) -> Optional[int]:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if 0 <= raw <= 255 else None
    if isinstance(raw, str) and re.fullmatch(r"\s*\d{1,3}\s*", raw):
        value = int(raw)
        return value if value <= 255 else None
    return None


def _port(raw: Any) -> Optional[int]:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, str) and re.fullmatch(r"\s*\d{1,5}\s*", raw):
        raw = int(raw)
    if isinstance(raw, int) and 1 <= raw <= 65535:
        return raw
    return None


def _clock(text: Any) -> Optional[int]:
    """Minutes since midnight of "HH:MM" or "HH:MM:SS"; 23:59 counts as the end of the day."""
    if not isinstance(text, str):
        return None
    match = re.fullmatch(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", text.strip())
    if not match:
        return None
    hours, minutes = int(match.group(1)), int(match.group(2))
    if hours > 24 or minutes > 59:
        return None
    value = hours * 60 + minutes
    return 1440 if value >= 1439 else value


def _schedule(raw: Any) -> Tuple[bool, str, str]:
    """(enabled, schedule text, problem) of the time ranges of a rule: "" for always, disabled for none at all."""
    if raw is None:
        return True, "", "the rule has no time ranges in the input"
    if not isinstance(raw, list):
        return True, "", "time ranges that are not a list"
    if not raw:
        return False, "", ""
    covered: Dict[int, List[Tuple[int, int]]] = {}
    parts: List[str] = []
    for item in raw:
        if not isinstance(item, dict):
            return True, "", "a time range that is not a JSON object"
        extra = [k for k, v in item.items() if k not in ("repeattype", "starttime", "endtime", "startweekday", "endweekday", "id")
                 and not _empty(v)]  # fmt: skip
        if extra or str(item.get("repeattype", "weekly")).lower() != "weekly":
            return True, "", "a time range this parser does not read"
        start, end = _clock(item.get("starttime")), _clock(item.get("endtime"))
        first, last = item.get("startweekday"), item.get("endweekday")
        if start is None or end is None or not isinstance(first, int) or not isinstance(last, int) or \
                not (0 <= first <= 6 and 0 <= last <= 6) or isinstance(first, bool) or isinstance(last, bool):  # fmt: skip
            return True, "", "a time range this parser does not read"
        if first == last and start < end:
            covered.setdefault(first, []).append((start, end))
        parts.append(f"{_DAYS[first]} {item['starttime']} - {_DAYS[last]} {item['endtime']}")
    always = all(any(s == 0 and e == 1440 for s, e in covered.get(day, [])) for day in range(7))
    return True, ("" if always else "; ".join(parts)), ""


def parse(data: bytes, report: Report) -> Policy:
    documents = _documents(data)
    if not documents:
        raise ParseError("the input is empty")
    policy = Policy(vendor="lancom-uf", scope="desktop")
    policy.default_interzone = Action.DENY
    policy.default_intrazone = Action.DENY
    reader = _Reader(report, policy)
    for document in documents:
        reader.take(document)
    if not reader.connections and not reader.objects:
        raise ParseError("no desktop objects and no desktop connections of a Unified Firewall found; expected what its REST "
                         "API answers for /model/desktop-connections and the desktop objects and services they name")  # fmt: skip
    reader.build_services()
    for obj in reader.objects:
        reader.resolve(obj)
    reader.build_rules()
    for zone in sorted(reader.zones):
        policy.zones[zone] = Zone(zone, [zone])
    _notes(reader)
    return policy


def _listed(names: Any, limit: int = 10) -> str:
    items = sorted(names, key=str.lower)
    text = ", ".join(f"'{_short(n)}'" for n in items[:limit])
    return text + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _notes(reader: _Reader) -> None:
    report = reader.report
    report.note(
        Severity.INFO, "LANCOM_UF_FORMAT",
        f"read {len(reader.connections)} desktop connections, {len(reader.objects)} desktop objects and "
        f"{len(reader.services)} services from the answers of the REST API. LANCOM publishes the keys of that API only "
        "by the examples of its LMC add-ins (networks, desktop connections, user-defined services); the keys of hosts, IP "
        "ranges, groups, Internet objects and of a rule other than those are assumed, and an object, service or rule "
        "with a key the parser does not know is not used. The desktop only allows: what no connection allows is blocked",
    )  # fmt: skip
    if not reader.connections:
        report.note(Severity.REVIEW, "NO_RULES", "the input holds no desktop connection: save the answer of "
                    "/model/desktop-connections as well")  # fmt: skip
    if reader.unknown:
        report.note(Severity.REVIEW, "ANSWERS_NOT_READ",
                    "parts of the input that are no desktop objects, services or connections this parser knows were not read: "
                    + _listed(set(reader.unknown)))  # fmt: skip
    if reader.missing:
        report.note(Severity.REVIEW, "OBJECTS_MISSING",
                    "objects and services the connections name are not in the input, and the rules that name them are not "
                    "used: " + _listed(reader.missing) + ". Save the answers of every collection (section 3)")  # fmt: skip
    if reader.connection_keys:
        report.note(Severity.REVIEW, "CONNECTION_KEYS_NOT_READ",
                    "desktop connections hold keys the parser does not know: " + _listed(reader.connection_keys)
                    + ". They are kept with the rules as how they handle traffic, and not converted; if one of them "
                    "narrows what a connection lets through, the converted rules allow more")  # fmt: skip
    if any(obj.kind in ("vpn", "user") for obj in reader.objects):
        report.note(Severity.INFO, "VPN_USER_OBJECTS",
                    "VPN and user objects are not read: the rules of connections to and from them are not used")  # fmt: skip
    if reader.p.nat_rules:
        report.note(Severity.INFO, "MASQUERADING_READ",
                    "masquerading set on services was read as NAT rules to the address of the outgoing interface. A NAT "
                    "source address other than that, the NAT of a connection and DMZ (port forwarding) are not read")  # fmt: skip
