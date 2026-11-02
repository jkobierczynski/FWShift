# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cato Networks SASE Cloud parser: the WAN Firewall and the Internet Firewall, as the GraphQL API answers them -> neutral
model.

What is read is one JSON object: ``wanFirewall`` and ``internetFirewall`` (each the answer of ``policy { wanFirewall
{ policy { ... } } }``, the policy object in it, or the whole answer of one query that asked for both), with the entity
lookups that say what the rules name: ``sites`` (``entityLookup`` of type site), ``hosts`` (``site.staticHostList``
per site id), ``networkRanges`` (``site.networkRangeList`` per site id), ``networkInterfaces`` and ``siteRanges``
(``entityLookup`` of those types), ``globalIpRanges`` (``object.globalIpRangeList``) and ``groups``
(``groups.groupList`` with members). The fetch commands are in the manual (section 3). How Cato decides, and how that
is mapped onto the neutral model:

* Zones: a zone per site (its name, kept to letters, digits, "_" and "-"; the site's own name is the zone's
  interface), ``remote-users`` for users who connect with the Cato client (the connection
  origins ``REMOTE_*``), and ``internet``. The WAN Firewall decides traffic between sites and remote users (also
  between two ranges of one site, which goes through the PoP); the Internet Firewall traffic from them to the
  internet. The two see different traffic, so their rules are one list in the model: the WAN rules (destination zones:
  the sites and remote-users), then the Internet rules (destination zone: internet).
* Each policy is first match. The WAN Firewall ends in an implicit any-any block (the default of the model), the
  Internet Firewall in an implicit any-any allow: a rule at the end of the Internet rules allows the rest to the
  internet. A hidden rule above the Internet rules blocks what Cato deems illegal or malicious; it is not in the answer.
  Traffic inside one network range does not reach Cato: a rule at the top allows it.
* Within a column (source, destination, service) the objects are alternatives; the columns must all hold. A source of
  sites and addresses is "these sites, or these addresses": the rule becomes one rule of the model per part (sites;
  addresses per site they belong to), in its place, which together match the same.
* Direction ``BOTH`` matches connections from the destination to the source as well: a second set of rules, sides
  swapped, follows. The policies are read as stateful: a rule decides who may open a connection (Cato's own example,
  "site Alpha is allowed to connect to site Bravo, but site Bravo cannot connect with site Alpha").
* An exception makes the rule not apply to what the exception matches (evaluation goes on below). An exception of one
  column (source, destination, or a service where the rule has none) is cut out of the rule; any other is not converted.
* Users and user groups, applications and categories, domains, countries, device profiles, ASNs, containers, floating
  ranges and system groups narrow a rule in ways the model cannot hold: they go into ``Rule.unsupported``. Actions
  other than ALLOW and BLOCK (PROMPT, RBI, CAPTIVE_PORTAL) too.
* The API names IPv4 addresses only. Standard services are read by name from a small table of well-known ports, which
  Cato does not publish (``CATO_STANDARD_SERVICE``); custom services are protocol (TCP, UDP, TCP_UDP, ICMP, ANY) and
  ports.

Assumptions not confirmed on an account: the keys of ``helperFields`` (``siteId``, ``subnet``) that Cato's own CLI reads
for network interfaces, and the same for site ranges; that a custom service of TCP or UDP without ports is all ports;
that a disabled policy is read as its rules say.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import ANY, Action, Address, AddressGroup, AddressKind, Policy, Protocol, Rule, Service, ServiceEntry, Zone
from ..netutil import Interval, interval_text, normalize, parse_literal, subtract
from ..report import Report, Severity

INTERNET = "internet"
REMOTE = "remote-users"
KEYS = ("fwshift", "wanFirewall", "internetFirewall", "sites", "hosts", "networkRanges", "networkInterfaces", "siteRanges", "globalIpRanges",
        "groups", "data")  # fmt: skip
_REMOTE_ORIGINS = ("REMOTE_CLIENT", "REMOTE_EXTENSION", "REMOTE_BROWSER")
_FQDN = re.compile(r"([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,63}\.?")
# Standard services by name: Cato does not publish what each holds; these are the well-known ports of the protocol.
STANDARD: Dict[str, List[ServiceEntry]] = {
    "HTTP": [ServiceEntry(Protocol.TCP, "80")],
    "HTTPS": [ServiceEntry(Protocol.TCP, "443")],
    "SSH": [ServiceEntry(Protocol.TCP, "22")],
    "TELNET": [ServiceEntry(Protocol.TCP, "23")],
    "SMTP": [ServiceEntry(Protocol.TCP, "25")],
    "FTP": [ServiceEntry(Protocol.TCP, "21")],
    "DNS": [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")],
    "RDP": [ServiceEntry(Protocol.TCP, "3389")],
    "NTP": [ServiceEntry(Protocol.UDP, "123")],
    "SNMP": [ServiceEntry(Protocol.UDP, "161")],
    "SMB": [ServiceEntry(Protocol.TCP, "445")],
    "LDAP": [ServiceEntry(Protocol.TCP, "389")],
}
# Columns of a rule that narrow it and that the model has no place for.
_NARROWING = {"country": "source countries", "device": "device profiles", "deviceOS": "device operating systems"}
_SIDE_KEYS = {"site", "host", "ip", "subnet", "ipRange", "globalIpRange", "networkInterface", "siteNetworkSubnet", "floatingSubnet", "user",
              "usersGroup", "group", "systemGroup"}  # fmt: skip
_INTERNET_KEYS = {"application", "customApp", "appCategory", "customCategory", "sanctionedAppsCategory", "country", "domain", "fqdn", "ip",
                  "subnet", "ipRange", "globalIpRange", "remoteAsn", "containers", "group"}  # fmt: skip


def looks_like_cato(data: bytes) -> bool:
    """The bundle of section 3, or an answer of the GraphQL API with a WAN or Internet Firewall policy."""
    head = data[:4_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith(b"{"):
        return False
    if re.search(rb'"fwshift"\s*:\s*"cato"', head):
        return True
    return bool(re.search(rb'"(wanFirewall|internetFirewall)"\s*:\s*\{', head)) and b'"rules"' in head


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _nonempty(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_nonempty(v) for v in value.values())
    if isinstance(value, list):
        return bool(value)
    return value not in (None, "", False)


def _items(value: Any) -> List[Any]:
    """The items of an answer: a list, ``{"items": [...]}``, or a GraphQL answer that holds such a thing."""
    for _ in range(8):
        if isinstance(value, list):
            return value
        if not isinstance(value, dict):
            return []
        if isinstance(value.get("items"), list):
            return list(value["items"])
        if isinstance(value.get("data"), dict):
            value = value["data"]  # (a GraphQL answer, which may carry "extensions" next to it)
            continue
        inner = [v for v in value.values() if isinstance(v, (dict, list))]
        if len(inner) != 1:
            return []
        value = inner[0]
    return []


def _policy(value: Any, kind: str) -> Optional[Dict[str, Any]]:
    """The policy object (with ``rules``) of an answer, for ``wanFirewall`` or ``internetFirewall``."""
    for _ in range(8):
        if not isinstance(value, dict):
            return None
        if isinstance(value.get("rules"), list):
            return value
        for key in ("data", "policy", kind):
            if isinstance(value.get(key), dict):
                value = value[key]
                break
        else:
            return None
    return None


@dataclass
class _Piece:
    """One part of a column: zones, and the addresses in them (or every address), less what exceptions cut out."""

    zones: List[str]
    include: List[str] = field(default_factory=lambda: [ANY])
    exclude: List[str] = field(default_factory=list)


class _Builder:
    def __init__(self, doc: Dict[str, Any], report: Report) -> None:
        self.doc, self.report = doc, report
        self.p = Policy(vendor="cato", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.site_zone: Dict[str, str] = {}  # site id -> zone
        self.zone_ids: Dict[str, str] = {}  # zone -> site id
        self.hosts: Dict[str, Tuple[str, str]] = {}  # host id -> (address name, site id)
        self.interfaces: Dict[str, Tuple[str, str]] = {}  # network interface id -> (address name, site id)
        self.ranges: Dict[str, Tuple[str, str]] = {}  # site range id -> (address name, site id)
        self.global_ranges: Dict[str, str] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.names: Set[str] = set()
        self.notes: Dict[str, List[str]] = {}
        self.lookups: Set[str] = set()

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    def _name(self, text: str) -> str:
        base = text.strip() or "rule"
        name, counter = base, 1
        while name.lower() in self.names:
            counter += 1
            name = f"{base} ({counter})"
        self.names.add(name.lower())
        return name

    def _object_name(self, text: str) -> str:
        base = text.strip() or "object"
        if base.lower() == ANY:
            base += " (object)"
        name, counter = base, 2
        while name in self.p.addresses or name in self.p.address_groups:
            name = f"{base} ({counter})"
            counter += 1
        return name

    # -- the policies and the lookups --------------------------------------------------------------

    def build(self) -> Policy:
        if isinstance(self.doc.get("errors"), list) and self.doc["errors"]:
            raise ParseError("an error answer of the Cato API: " + "; ".join(_text(e.get("message") if isinstance(e, dict) else e)
                                                                            for e in self.doc["errors"])[:200])  # fmt: skip
        wan = _policy(self.doc.get("wanFirewall"), "wanFirewall") or _policy(self.doc, "wanFirewall")
        internet = _policy(self.doc.get("internetFirewall"), "internetFirewall") or _policy(self.doc, "internetFirewall")
        if wan is None and internet is None:
            raise ParseError("no WAN or Internet Firewall policy with rules: expected the bundle of section 3 of the manual (wanFirewall, "
                             "internetFirewall and the entity lookups), or an answer of the GraphQL query policy { wanFirewall | "
                             "internetFirewall { policy { rules ... } } }")  # fmt: skip
        self._lookups([wan, internet])
        self.p.zones[REMOTE] = Zone(REMOTE, interfaces=["Cato client (remote users)"])
        self.p.zones[INTERNET] = Zone(INTERNET, interfaces=["internet"])
        self._local()
        if wan is not None:
            self._rules(wan, "wanFirewall")
        else:
            self._say("CATO_POLICY_MISSING", "wanFirewall")
        if internet is not None:
            self._rules(internet, "internetFirewall")
            rule = Rule(self._name("Internet Firewall implicit allow"), src_zones=self._inside(), dst_zones=[INTERNET], action=Action.ALLOW)
            rule.origin, rule.log_end = rule.name, False
            rule.description = "the implicit any-any allow at the end of the Internet Firewall"
            self.p.rules.append(rule)
        else:
            self._say("CATO_POLICY_MISSING", "internetFirewall")
        self._other()
        self._notes(wan is not None, internet is not None)
        return self.p

    def _inside(self) -> List[str]:
        return [z for z in self.p.zones if z != INTERNET]

    def _zone(self, site_id: str, name: str) -> str:
        if site_id in self.site_zone:
            return self.site_zone[site_id]
        # A zone name every target takes (letters, digits, "_" and "-"); the site's own name is the zone's interface.
        base = re.sub(r"[^A-Za-z0-9_-]+", "-", name.strip()).strip("-")[:48] or f"site-{re.sub(r'[^A-Za-z0-9]+', '', site_id)[:20]}"
        if base.lower() in (INTERNET, REMOTE, ANY):
            base = "site-" + base
        zone, counter = base, 2
        while zone in self.p.zones or zone in (INTERNET, REMOTE):
            zone = f"{base}-{counter}"
            counter += 1
        self.site_zone[site_id] = zone
        self.zone_ids[zone] = site_id
        self.p.zones[zone] = Zone(zone, interfaces=[name.strip() or site_id])
        return zone

    def _refs(self, value: Any) -> List[Tuple[str, str]]:
        return [(_text(r.get("id")), _text(r.get("name"))) for r in value if isinstance(r, dict)] if isinstance(value, list) else []

    def _lookups(self, policies: List[Optional[Dict[str, Any]]]) -> None:
        for item in _items(self.doc.get("sites")):
            entity = item.get("entity") if isinstance(item, dict) and isinstance(item.get("entity"), dict) else item
            if isinstance(entity, dict) and entity.get("id") is not None:
                self._zone(_text(entity["id"]), _text(entity.get("name")))
        if "sites" in self.doc:
            self.lookups.add("sites")
        # Sites named by rules and groups, so that "every site" is known before the rules are read.
        stack: List[Any] = [p for p in policies if p is not None] + [self.doc.get("groups")]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "site" and isinstance(value, list):
                        for ident, name in self._refs(value):
                            self._zone(ident, name)
                    elif key == "type" and value == "SITE" and node.get("id") is not None:
                        self._zone(_text(node["id"]), _text(node.get("name")))
                    else:
                        stack.append(value)
            elif isinstance(node, list):
                stack.extend(node)
        ranges = self.doc.get("networkRanges")
        if isinstance(ranges, dict):
            self.lookups.add("networkRanges")
            for site_id, answer in ranges.items():
                zone = self.site_zone.get(_text(site_id))
                for item in _items(answer):
                    found = parse_literal(_text(item.get("subnet"))) if isinstance(item, dict) else None
                    if zone is not None and found is not None:
                        self.p.zone_networks.setdefault(zone, []).append(interval_text(found))
        hosts = self.doc.get("hosts")
        if isinstance(hosts, dict):
            self.lookups.add("hosts")
            for site_id, answer in hosts.items():
                for item in _items(answer):
                    if not isinstance(item, dict) or item.get("hostId", item.get("id")) is None:
                        continue
                    ident = _text(item.get("hostId", item.get("id")))
                    found = parse_literal(_text(item.get("ip")))
                    name = self._object_name(_text(item.get("name")) or f"host {ident}")
                    if found is not None and found[1] == found[2]:
                        self.p.addresses[name] = Address(name, AddressKind.NETWORK, interval_text(found), description="a host of a site")
                    else:
                        self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, _text(item.get("ip"))[:60], raw="a host without an address")
                    self.hosts[ident] = (name, _text(site_id))
        for key, table, label in (("networkInterfaces", self.interfaces, "network interface"), ("siteRanges", self.ranges, "site range")):
            if key not in self.doc:
                continue
            self.lookups.add(key)
            for item in _items(self.doc.get(key)):
                entity = item.get("entity") if isinstance(item, dict) else None
                helper: Dict[str, Any] = item["helperFields"] if isinstance(item, dict) and isinstance(item.get("helperFields"), dict) else {}
                if not isinstance(entity, dict) or entity.get("id") is None:
                    continue
                ident = _text(entity["id"])
                name = self._object_name(_text(entity.get("name")) or f"{label} {ident}")
                found = parse_literal(_text(helper.get("subnet")))
                site_id = _text(helper.get("siteId"))
                if found is not None:
                    self.p.addresses[name] = Address(name, AddressKind.NETWORK, interval_text(found), description=f"a {label} of a site")
                    zone = self.site_zone.get(site_id)
                    if zone is not None and interval_text(found) not in self.p.zone_networks.get(zone, []):
                        self.p.zone_networks.setdefault(zone, []).append(interval_text(found))
                else:
                    self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=f"a {label} whose subnet the lookup does not give")
                table[ident] = (name, site_id)
        if "globalIpRanges" in self.doc:
            self.lookups.add("globalIpRanges")
            for item in _items(self.doc.get("globalIpRanges")):
                if not isinstance(item, dict) or item.get("id") is None:
                    continue
                ident = _text(item["id"])
                name = self._object_name(_text(item.get("name")) or f"global range {ident}")
                text = _text(item.get("ipRange") or item.get("subnet"))
                parts = [parse_literal(part) for part in re.split(r"[,\s]+", text) if part]
                if parts and all(part is not None for part in parts):
                    members = [interval_text(part) for part in normalize([part for part in parts if part is not None])]
                    if len(members) == 1:
                        self.p.addresses[name] = Address(name, AddressKind.RANGE if "-" in members[0] else AddressKind.NETWORK, members[0],
                                                         description=_text(item.get("description"))[:200])  # fmt: skip
                    else:
                        self.p.address_groups[name] = AddressGroup(name, members, description=_text(item.get("description"))[:200])
                else:
                    self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, text[:60], raw="a global range that cannot be read")
                self.global_ranges[ident] = name
        if "groups" in self.doc:
            self.lookups.add("groups")
            for item in _items(self.doc.get("groups")):
                if isinstance(item, dict) and item.get("id") is not None:
                    self.groups[_text(item["id"])] = item

    def _local(self) -> None:
        """Traffic inside one network range does not reach Cato: a rule at the top allows it."""
        for zone, networks in self.p.zone_networks.items():
            for number, network in enumerate(networks, 1):
                name = self._name(f"inside {zone} range {number}")
                rule = Rule(name, src_zones=[zone], dst_zones=[zone], sources=[network], destinations=[network], action=Action.ALLOW, origin=name)
                rule.log_end = False
                rule.description = f"traffic inside {network} does not reach Cato"
                rule.source_ids = {"cato.local": "1"}
                self.p.rules.append(rule)

    # -- columns -------------------------------------------------------------------------------------

    def _group(self, ident: str, label: str, problems: List[str], codes: Set[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
        """(site zones, [(address member, site id)]) of a group."""
        group = self.groups.get(ident)
        if group is None:
            problems.append(f"group {label[:60]} is not in the groups of the input")
            codes.add("CATO_UNRESOLVED")
            return [], []
        members = group.get("members")
        items = _items(members)
        total = members.get("paging", {}).get("total") if isinstance(members, dict) and isinstance(members.get("paging"), dict) else None
        if isinstance(total, int) and total > len(items):
            problems.append(f"group {label[:60]}: the input holds {len(items)} of its {total} members")
            codes.add("CATO_UNRESOLVED")
            return [], []
        zones: List[str] = []
        out: List[Tuple[str, str]] = []
        for member in items:
            if not isinstance(member, dict):
                continue
            kind, mid, mname = _text(member.get("type")), _text(member.get("id")), _text(member.get("name"))
            if kind == "SITE":
                zones.append(self._zone(mid, mname))
            elif kind == "HOST":
                out.append(self._resolve(self.hosts, mid, mname, "host", problems, codes))
            elif kind == "NETWORK_INTERFACE":
                out.append(self._resolve(self.interfaces, mid, mname, "network interface", problems, codes))
            elif kind == "SITE_NETWORK_SUBNET":
                out.append(self._resolve(self.ranges, mid, mname, "site range", problems, codes))
            elif kind == "GLOBAL_IP_RANGE":
                out.append((self._global(mid, mname, problems, codes), ""))
            else:
                problems.append(f"group {label[:60]}: a member of type {kind[:30] or 'none'} ({mname[:40]})")
                codes.add("CATO_OBJECT")
        return zones, [(name, site) for name, site in out if name]

    def _resolve(self, table: Dict[str, Tuple[str, str]], ident: str, label: str, kind: str, problems: List[str], codes: Set[str]) -> Tuple[str, str]:
        if ident in table:
            name, site = table[ident]
            found = self.p.addresses.get(name)
            if found is not None and found.kind == AddressKind.UNSUPPORTED:
                codes.add("CATO_UNRESOLVED")
            return name, site
        name = self._object_name(f"{kind} {label or ident}")
        self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw=f"a {kind} that is not in the lookups of the input")
        table[ident] = (name, "")
        codes.add("CATO_UNRESOLVED")
        return name, ""

    def _global(self, ident: str, label: str, problems: List[str], codes: Set[str]) -> str:
        if ident in self.global_ranges:
            return self.global_ranges[ident]
        name = self._object_name(f"global range {label or ident}")
        self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", raw="a global range that is not in the lookups of the input")
        self.global_ranges[ident] = name
        codes.add("CATO_UNRESOLVED")
        return name

    def _literal(self, text: str, problems: List[str]) -> Optional[str]:
        found = parse_literal(text)
        if found is None or ("/" not in text and "-" not in text and found[1] != found[2]):
            problems.append(f"address '{text[:40]}' cannot be read")
            return None
        return interval_text(found)

    def _side(self, cell: Any, internet: bool, problems: List[str], codes: Set[str]) -> List[_Piece]:
        """The pieces of a source, or of the destination of a WAN rule (``internet``: of an Internet rule)."""
        if not isinstance(cell, dict) or not _nonempty(cell):
            return [_Piece([INTERNET] if internet else self._inside())]
        zones: List[str] = []
        by_site: Dict[str, List[str]] = {}  # site id ("" for none) -> members
        before = len(problems)
        allowed = _INTERNET_KEYS if internet else _SIDE_KEYS
        for key, value in cell.items():
            if not _nonempty(value):
                continue
            if key not in allowed:
                problems.append(f"'{key[:30]}' in a column is not read")
                continue
            if key == "site":
                zones += [self._zone(ident, name) for ident, name in self._refs(value)]
            elif key in ("ip", "subnet"):
                for text in value if isinstance(value, list) else [value]:
                    found = self._literal(_text(text), problems)
                    if found:
                        by_site.setdefault("", []).append(found)
            elif key == "ipRange":
                for item in value if isinstance(value, list) else []:
                    found = self._literal(f"{_text(item.get('from'))}-{_text(item.get('to'))}", problems) if isinstance(item, dict) else None
                    if found:
                        by_site.setdefault("", []).append(found)
            elif key == "host":
                for ident, name in self._refs(value):
                    member, site = self._resolve(self.hosts, ident, name, "host", problems, codes)
                    by_site.setdefault(site, []).append(member)
            elif key == "networkInterface":
                for ident, name in self._refs(value):
                    member, site = self._resolve(self.interfaces, ident, name, "network interface", problems, codes)
                    by_site.setdefault(site, []).append(member)
            elif key == "siteNetworkSubnet":
                for ident, name in self._refs(value):
                    member, site = self._resolve(self.ranges, ident, name, "site range", problems, codes)
                    by_site.setdefault(site, []).append(member)
            elif key == "globalIpRange":
                for ident, name in self._refs(value):
                    by_site.setdefault("", []).append(self._global(ident, name, problems, codes))
            elif key == "group":
                for ident, name in self._refs(value):
                    found_zones, in_group = self._group(ident, name, problems, codes)
                    if internet and found_zones:
                        problems.append(f"group {name[:40]} holds sites, as a destination on the internet")
                    zones += found_zones
                    for member, site in in_group:
                        by_site.setdefault(site, []).append(member)
            elif key == "fqdn":
                for text in value if isinstance(value, list) else [value]:
                    host = _text(text).strip().lower().rstrip(".")
                    if not _FQDN.fullmatch(host):
                        problems.append(f"host name '{host[:40]}' cannot be read")
                        continue
                    name = f"fqdn {host}"
                    self.p.addresses.setdefault(name, Address(name, AddressKind.FQDN, host))
                    by_site.setdefault("", []).append(name)
            elif key in ("user", "usersGroup"):
                problems.append(f"{'users' if key == 'user' else 'user groups'} " + ", ".join(n for _, n in self._refs(value))[:80])
                codes.add("CATO_USERS")
            elif key in ("floatingSubnet", "systemGroup"):
                problems.append(f"{'floating ranges' if key == 'floatingSubnet' else 'system groups'} " + ", ".join(n for _, n in self._refs(value))[:80])
                codes.add("CATO_OBJECT")
            else:
                label = {"domain": "domains", "remoteAsn": "ASNs", "containers": "containers", "country": "countries"}.get(key, key)
                listed = ", ".join(_text(v.get("name") if isinstance(v, dict) else v) for v in value) if isinstance(value, list) else ""
                problems.append(f"{label} {listed[:80]}".rstrip())
                codes.add("CATO_APPLICATION")
        pieces: List[_Piece] = []
        if zones:
            pieces.append(_Piece(transform.dedupe(zones)))
        for site, members in by_site.items():
            zone = self.site_zone.get(site)
            where = [INTERNET] if internet else [zone] if zone else self._inside()
            pieces.append(_Piece(where, transform.dedupe(members)))
        if not pieces and len(problems) > before:
            # Only what cannot be converted: the rule stays, as wide as the rest of it, with that in Rule.unsupported.
            return [_Piece([INTERNET] if internet else self._inside())]
        return pieces or [_Piece([], [])]

    # -- services -----------------------------------------------------------------------------------

    def _inline(self, entries: List[ServiceEntry], label: str) -> str:
        if label not in self.p.services:
            self.p.services[label] = Service(label, entries)
        return label

    def _ports(self, item: Dict[str, Any], problems: List[str]) -> Optional[str]:
        out: List[str] = []
        for port in item.get("port") or []:
            if not (isinstance(port, int) or _text(port).isdigit()) or not 1 <= int(port) <= 65535:
                problems.append(f"port '{_text(port)[:10]}' cannot be read")
                return None
            out.append(str(int(port)))
        span = item.get("portRange")
        if isinstance(span, dict):
            low, high = _text(span.get("from")), _text(span.get("to"))
            if not (low.isdigit() and high.isdigit() and 1 <= int(low) <= int(high) <= 65535):
                problems.append(f"port range '{low[:6]}-{high[:6]}' cannot be read")
                return None
            out.append(low if low == high else f"{int(low)}-{int(high)}")
        return ",".join(out)

    def _services(self, cell: Any, problems: List[str], codes: Set[str]) -> List[str]:
        if not isinstance(cell, dict) or not _nonempty(cell):
            return [ANY]
        out: List[str] = []
        for ident, name in self._refs(cell.get("standard")):
            label = (name or ident).strip()
            entries = STANDARD.get(label.upper())
            if entries is not None:
                out.append(self._inline(list(entries), label))
                codes.add("CATO_STANDARD_SERVICE")
            else:
                if label not in self.p.services:
                    self.p.services[label] = Service(label, [], unsupported="a standard service of Cato whose ports FWShift does not know")
                out.append(label)
        for item in cell.get("custom") or []:
            if not isinstance(item, dict):
                continue
            protocol = _text(item.get("protocol")).upper()
            ports = self._ports(item, problems)
            if ports is None:
                continue
            if protocol in ("TCP", "UDP", "TCP_UDP"):
                kinds = [Protocol.TCP, Protocol.UDP] if protocol == "TCP_UDP" else [Protocol(protocol.lower())]
                label = protocol.lower().replace("_", "-") + (f"/{ports}" if ports else "")
                out.append(self._inline([ServiceEntry(kind, ports) for kind in kinds], label))
            elif protocol == "ICMP" and not ports:
                out.append(self._inline([ServiceEntry(Protocol.ICMP)], "icmp"))
            elif protocol == "ANY" and not ports:
                return [ANY]
            else:
                problems.append(f"a service of protocol {protocol[:10] or 'none'}" + (f" with ports {ports[:30]}" if ports else ""))
        for key in cell:
            if key not in ("standard", "custom") and _nonempty(cell[key]):
                problems.append(f"'{key[:30]}' in the services is not read")
        return transform.dedupe(out) or [ANY]

    # -- rules ----------------------------------------------------------------------------------------

    def _rules(self, policy: Dict[str, Any], kind: str) -> None:
        if policy.get("enabled") is False:
            self._say("CATO_POLICY_DISABLED", kind)
        entries = [e for e in policy.get("rules") or [] if isinstance(e, dict)]
        if all(isinstance((e.get("rule") or {}).get("index"), int) for e in entries):
            entries.sort(key=lambda e: e["rule"]["index"])
        for entry in entries:
            self._rule(entry, kind)

    def _origins(self, rule: Dict[str, Any], problems: List[str], codes: Set[str]) -> Optional[List[str]]:
        """The source zones the connection origins allow, or None for all."""
        origins = [_text(o) for o in rule.get("connectionsOriginList") or []]
        if not origins:
            legacy = _text(rule.get("connectionOrigin")).upper()
            origins = ["SITE"] if legacy == "SITE" else list(_REMOTE_ORIGINS) if legacy == "REMOTE" else []
        if not origins:
            return None
        remote = [o for o in origins if o in _REMOTE_ORIGINS]
        unknown = [o for o in origins if o != "SITE" and o not in _REMOTE_ORIGINS]
        if unknown or (remote and len(set(remote)) != len(_REMOTE_ORIGINS)):
            problems.append("connection origins " + ", ".join(origins)[:80])
            codes.add("CATO_ORIGIN")
            return None
        zones = [z for z in self._inside() if z != REMOTE] if "SITE" in origins else []
        return zones + ([REMOTE] if remote else [])

    def _schedule(self, rule: Dict[str, Any]) -> str:
        out: List[str] = []
        schedule: Dict[str, Any] = rule["schedule"] if isinstance(rule.get("schedule"), dict) else {}
        active = _text(schedule.get("activeOn")).upper()
        if active == "WORKING_HOURS":
            out.append("working hours")
        elif active == "CUSTOM_TIMEFRAME":
            frame = schedule.get("customTimeframe") or {}
            out.append(f"from {_text(frame.get('from'))} to {_text(frame.get('to'))}" if isinstance(frame, dict) else "a custom timeframe")
        elif active == "CUSTOM_RECURRING":
            recur = schedule.get("customRecurring") or {}
            if isinstance(recur, dict):
                out.append(f"{','.join(_text(d) for d in recur.get('days') or [])} {_text(recur.get('from'))}-{_text(recur.get('to'))}")
        elif active not in ("", "ALWAYS"):
            out.append(active.lower())
        period: Dict[str, Any] = rule["activePeriod"] if isinstance(rule.get("activePeriod"), dict) else {}
        if period.get("useEffectiveFrom") is True:
            out.append(f"active from {_text(period.get('effectiveFrom'))}")
        if period.get("useExpiresAt") is True:
            out.append(f"expires {_text(period.get('expiresAt'))}")
        return "; ".join(out)[:200]

    def _rule(self, entry: Dict[str, Any], kind: str) -> None:
        data = entry.get("rule")
        if not isinstance(data, dict):
            raise ParseError(f"a rule of {kind} without its 'rule' object")
        properties = [_text(p) for p in entry.get("properties") or []]
        label = _text(data.get("name")).strip()[:120] or f"{kind} rule {_text(data.get('index'))}"
        if "REMOVED" in properties:
            self._say("CATO_REMOVED", label)
            return
        internet = kind == "internetFirewall"
        problems: List[str] = []
        codes: Set[str] = set()
        name = self._name(label)
        action_text = _text(data.get("action")).upper()
        action = Action.ALLOW if action_text in ("ALLOW", "PROMPT", "RBI") else Action.DENY
        if action_text not in ("ALLOW", "BLOCK"):
            problems.append(f"action {action_text[:20] or 'none'}" + {"PROMPT": ": the user is asked on a web page", "RBI": ": remote browser isolation",
                                                                       "CAPTIVE_PORTAL": ": a captive portal"}.get(action_text, ""))  # fmt: skip
            codes.add("CATO_ACTION")
        if _text(entry.get("ruleType")) == "SUB_POLICY_SCOPE" or entry.get("subPolicy"):
            problems.append("the scope of a sub-policy, whose rules are not in the input")
            codes.add("CATO_SUB_POLICY")
        sources = self._side(data.get("source"), False, problems, codes)
        destinations = self._side(data.get("destination"), internet, problems, codes)
        origins = self._origins(data, problems, codes)
        if origins is not None:
            for piece in sources:
                piece.zones = [z for z in piece.zones if z in origins]
        services = self._services(data.get("service"), problems, codes)
        if not internet and _nonempty(data.get("application")):
            problems.append("an application column (applications, categories, domains or addresses as applications)")
            codes.add("CATO_APPLICATION")
        for key, text in _NARROWING.items():
            if _nonempty(data.get(key)):
                problems.append(text)
                codes.add("CATO_DEVICE")
        if _nonempty(data.get("deviceAttributes")):
            problems.append("device attributes")
            codes.add("CATO_DEVICE")
        both = not internet and _text(data.get("direction")).upper() == "BOTH"
        negated_services: List[str] = []
        exceptions = [e for e in data.get("exceptions") or [] if isinstance(e, dict)]
        if exceptions and both:
            problems.append("exceptions on a rule of both directions: how an exception applies to the other direction is not documented")
            codes.add("CATO_EXCEPTION")
        elif exceptions:
            cut = self._exceptions(exceptions, internet, sources, destinations, services, negated_services, problems, codes)
            if cut:
                self.report.add("rule", name, Severity.INFO, "CATO_EXCEPTION_CUT",
                                f"{cut} exception(s) cut out of the rule: it does not match what they match, as on Cato")  # fmt: skip
        common = {"action": action, "log_end": (data.get("tracking") or {}).get("event", {}).get("enabled") is True
                  if isinstance(data.get("tracking"), dict) and isinstance(data["tracking"].get("event"), dict) else False,
                  "enabled": data.get("enabled") is not False, "description": _text(data.get("description"))[:500],
                  "schedule": self._schedule(data)}  # fmt: skip
        alert = (data.get("tracking") or {}).get("alert") if isinstance(data.get("tracking"), dict) else None
        handling = {"alert": _text(alert.get("frequency")).lower() or "on"} if isinstance(alert, dict) and alert.get("enabled") is True else {}
        source_ids = {"cato.policy": kind, "cato.rule_id": _text(data.get("id"))}
        section = data.get("section")
        if isinstance(section, dict) and _text(section.get("name")):
            source_ids["cato.section"] = _text(section.get("name"))
        if "SYSTEM" in properties:
            codes.add("CATO_SYSTEM_RULE")
        made: List[Rule] = []
        directions = [(sources, destinations)] + ([(destinations, sources)] if both else [])
        for number, (src, dst) in enumerate(directions):
            for sp in src:
                for dp in dst:
                    src_members, src_negated = self._members(sp, problems)
                    dst_members, dst_negated = self._members(dp, problems)
                    if not sp.zones or not dp.zones or not src_members or not dst_members:
                        continue  # (nothing is left of this part)
                    one = Rule(name if not made else self._name(label), action=action)
                    one.origin = one.name
                    one.src_zones, one.dst_zones = list(sp.zones), list(dp.zones)
                    one.sources, one.negate_source = src_members, src_negated
                    one.destinations, one.negate_destination = dst_members, dst_negated
                    one.services = list(negated_services) if negated_services else list(services)
                    one.negate_service = bool(negated_services)
                    one.log_end, one.enabled, one.description, one.schedule = (bool(common["log_end"]), bool(common["enabled"]),
                                                                               str(common["description"]), str(common["schedule"]))  # fmt: skip
                    one.handling = dict(handling)
                    one.source_ids = dict(source_ids, **({"cato.direction": "reverse"} if number else {}))
                    made.append(one)
        if not made:
            one = Rule(name, action=action, origin=name, enabled=False, src_zones=[REMOTE], dst_zones=[REMOTE])
            one.description = "matches nothing: " + ("its exceptions take all of it" if exceptions else "a column holds nothing that can be read")
            one.source_ids = dict(source_ids)
            made.append(one)
            self.report.add("rule", name, Severity.INFO if exceptions and not problems else Severity.REVIEW, "CATO_EMPTY",
                            "the rule matches nothing as read (" + one.description[len("matches nothing: "):] + "): kept disabled")  # fmt: skip
        problems = list(dict.fromkeys(problems))
        for one in made:
            one.unsupported = list(problems)
        first = made[0].origin
        texts = {
            "CATO_USERS": (Severity.REVIEW, "users or user groups narrow the rule; they are not converted"),
            "CATO_APPLICATION": (Severity.REVIEW, "applications, categories, domains, countries, ASNs or containers narrow the rule; they "
                                 "are not converted"),
            "CATO_DEVICE": (Severity.REVIEW, "source countries, device profiles, operating systems or device attributes narrow the rule; "
                            "they are not converted"),
            "CATO_ORIGIN": (Severity.REVIEW, "connection origins that are not all sites or all remote users: not converted"),
            "CATO_OBJECT": (Severity.REVIEW, "floating ranges, system groups or group members whose addresses are not known: not converted"),
            "CATO_UNRESOLVED": (Severity.REVIEW, "objects that are not in the lookups of the input: they match nothing until they are"),
            "CATO_ACTION": (Severity.REVIEW, f"action {action_text[:20]}: not converted (read as {action.value})"),
            "CATO_SUB_POLICY": (Severity.REVIEW, "the scope of a sub-policy: its rules are not in the input"),
            "CATO_EXCEPTION": (Severity.REVIEW, "exceptions that cannot be cut out of the rule: not converted"),
            "CATO_STANDARD_SERVICE": (Severity.APPROX, "standard services read by name as the well-known ports of their protocol; Cato does "
                                      "not publish what they hold"),
            "CATO_SYSTEM_RULE": (Severity.INFO, "a system rule of Cato, which cannot be changed or removed"),
        }
        for code in sorted(codes):
            severity, text = texts[code]
            self.report.add("rule", first, severity, code, text)
        if both:
            self.report.add("rule", first, Severity.INFO, "CATO_BOTH",
                            "direction BOTH: written as rules for each direction, the second set with source and destination "
                            "swapped: " + ", ".join(f"'{r.name}'" for r in made[1:])[:300])  # fmt: skip
        elif len(made) > 1:
            self.report.add("rule", first, Severity.INFO, "CATO_RULE_SPLIT",
                            "a column holds sites and addresses (or addresses of several sites), which Cato reads as alternatives: "
                            "written as one rule per part, which together match the same: " + ", ".join(f"'{r.name}'" for r in made[1:])[:300])  # fmt: skip
        self.p.rules += made

    def _members(self, piece: _Piece, problems: List[str]) -> Tuple[List[str], bool]:
        if not piece.exclude:
            return list(piece.include), False
        if piece.include == [ANY]:
            return transform.dedupe(piece.exclude), True
        keep = self._intervals(piece.include)
        drop = self._intervals(piece.exclude)
        if keep is None or drop is None:
            problems.append("an exception cuts addresses out of objects whose addresses are not known")
            return list(piece.include), False
        return [interval_text(i) for i in subtract(keep, drop)], False

    def _intervals(self, members: Iterable[str]) -> Optional[List[Interval]]:
        out: List[Interval] = []
        for member in members:
            found = transform.address_intervals(self.p, member)
            if found is None:
                return None
            out += found
        return normalize(out)

    def _exceptions(self, exceptions: List[Dict[str, Any]], internet: bool, sources: List[_Piece], destinations: List[_Piece],
                    services: List[str], negated: List[str], problems: List[str], codes: Set[str]) -> int:  # fmt: skip
        cut = 0
        for exception in exceptions:
            columns = [key for key, value in exception.items() if key not in ("name", "direction", "connectionOrigin") and _nonempty(value)]
            if _text(exception.get("connectionOrigin")).upper() not in ("", "ANY"):
                columns.append("connectionOrigin")
            label = _text(exception.get("name"))[:40] or "an exception"
            if len(columns) != 1 or columns[0] not in ("source", "destination", "service"):
                problems.append(f"exception {label}: " + (", ".join(columns)[:80] if columns else "no criteria") + " (only an exception of one "
                                "column of addresses or services is cut out)")  # fmt: skip
                codes.add("CATO_EXCEPTION")
                continue
            column = columns[0]
            mine: List[str] = []
            if column == "service":
                if services != [ANY] or negated:
                    problems.append(f"exception {label}: services cut out of a rule that names services")
                    codes.add("CATO_EXCEPTION")
                    continue
                found = self._services(exception["service"], mine, codes)
                if mine or found == [ANY]:
                    problems += [f"exception {label}: {m}" for m in mine] or [f"exception {label}: every service"]
                    codes.add("CATO_EXCEPTION")
                    continue
                negated += found
                cut += 1
                continue
            pieces = self._side(exception[column], internet and column == "destination", mine, codes)
            if mine:
                problems += [f"exception {label}: {m}" for m in mine]
                codes.add("CATO_EXCEPTION")
                continue
            target = sources if column == "source" else destinations
            for piece in pieces:
                if piece.include == [ANY]:
                    for own in target:
                        own.zones = [z for z in own.zones if z not in piece.zones]
                    continue
                for own in target:  # (an address is where it is: the zone of a site's object need not be checked)
                    own.exclude += [m for m in piece.include if m not in own.exclude]
            cut += 1
        return cut

    # -- the rest -------------------------------------------------------------------------------------

    def _other(self) -> None:
        unknown = [key for key in self.doc if key not in KEYS]
        if unknown:
            self._say("CATO_UNKNOWN_KEYS", ", ".join(unknown[:8]))
        missing = [key for key in ("sites", "hosts", "networkRanges", "networkInterfaces", "siteRanges", "globalIpRanges", "groups")
                   if key not in self.lookups]  # fmt: skip
        if missing:
            self._say("CATO_NO_LOOKUPS", ", ".join(missing))

    def _notes(self, wan: bool, internet: bool) -> None:
        sites = [z for z in self.p.zones if z not in (INTERNET, REMOTE)]
        self.report.note(Severity.INFO, "CATO_SOURCE",
                         f"{len(sites)} sites as zones ({', '.join(sites[:8])}{' ...' if len(sites) > 8 else ''}), remote-users and internet; "
                         "the WAN Firewall (first match, implicit block) decides between sites and remote users, the Internet Firewall "
                         "(first match, implicit allow, written as a last rule) from them to the internet; traffic inside one network "
                         "range does not reach Cato and is allowed")  # fmt: skip
        if internet:
            self.report.note(Severity.INFO, "CATO_INTERNET_TOP", "a hidden rule of Cato above the Internet Firewall blocks connections Cato "
                             "deems illegal or malicious; it is not in the answer and not converted")  # fmt: skip
        self.report.note(Severity.INFO, "CATO_INBOUND", "traffic from the internet to the sites is decided by Remote Port Forwarding, which is "
                         "not read: in the model nothing from the internet is allowed")  # fmt: skip
        texts = {
            "CATO_NO_LOOKUPS": (Severity.REVIEW, "entity lookups missing from the input: sites no rule names are not zones, and hosts, "
                                "ranges and groups the rules name match nothing"),
            "CATO_POLICY_MISSING": (Severity.REVIEW, "a policy is not in the input; the model says nothing of the traffic it decides"),
            "CATO_POLICY_DISABLED": (Severity.REVIEW, "a policy that is switched off: its rules are read as they are"),
            "CATO_REMOVED": (Severity.INFO, "rules marked removed in the revision read: left out"),
            "CATO_UNKNOWN_KEYS": (Severity.INFO, "keys in the bundle that are not read"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def parse(data: bytes, report: Report) -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    if not isinstance(document, dict):
        raise ParseError("expected a JSON object: the bundle of section 3 of the manual, or an answer of the GraphQL API")
    try:
        return _Builder(document, report).build()
    except ParseError:
        raise
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None
