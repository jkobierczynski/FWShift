# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Zscaler Internet Access (ZIA) Cloud Firewall parser: the answers of the ZIA API -> neutral model.

What is read is JSON: one object with the answers under the names of their endpoints (``firewallFilteringRules``,
``ipSourceGroups``, ``ipv6SourceGroups``, ``ipDestinationGroups``, ``ipv6DestinationGroups``, ``networkServices``,
``networkServiceGroups``, ``networkApplicationGroups``, ``locations``, ``locationGroups``, ``timeWindows``; the manual
has the commands), or the answers themselves, concatenated or in an array, each told by the shape of its entries. The
answer of ``/firewallFilteringRules`` alone is read too. How ZIA decides, and how that is mapped onto the model:

* ZIA filters what leaves a location (a site whose traffic comes through a GRE or IPsec tunnel, or a Zscaler
  Client Connector) for the internet. A location is a zone; ``road-warrior`` is the zone of Client Connector traffic
  from outside any location (ZIA calls it Road Warrior); ``internet`` is the zone every rule goes to. Traffic between
  locations, inside one, and from the internet never passes the Cloud Firewall: no rule of the model allows it, and the
  model blocks it (what no rule matches), which ZSCALER_OUTBOUND_ONLY says. ZIA does not let in a connection that comes
  from the internet; a reply to a connection a rule allowed comes back (the firewall is stateful, as the model is).
* Rules are evaluated in ascending ``order``, first match; a disabled rule keeps its place and is skipped. The admin
  rank (``rank``, 0 to 7) keeps the rules of a higher rank above the others when admin ranking is on; the order is read
  as it is, and a rank out of that order is reported. Predefined rules share order numbers with others (the API
  answers so): those keep the order of the answer. The default rule (``defaultRule``, order -1) is last and matches
  everything.
* A rule without locations or location groups applies to every location and to Client Connector traffic. Location
  groups are read as their locations, from the ``locationGroups`` answer. Source IP addresses and groups, destination
  IP addresses and IP groups, network services and their groups are read; a missing criterion matches all.
* Users, groups, departments, devices, device trust levels, workload groups, source and destination countries, IP
  categories, network applications and their groups, application services, FQDNs and wildcard domains, and
  destination groups of FQDNs, domains or categories narrow a match and are not modelled: the rule is not converted
  (``Rule.unsupported``), with a finding. A time window is the rule's schedule. ``EVAL_NWAPP`` hands the decision to
  the network application, which is not modelled either.
* ``BLOCK_DROP`` drops, ``BLOCK_RESET`` answers TCP with a reset, ``BLOCK_ICMP`` answers with an ICMP unreachable
  (read as deny).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import ANY, Action, AddressGroup, Policy, Protocol, Rule, Service, ServiceEntry, ServiceGroup, Zone
from ..netutil import interval_text, parse_literal
from ..report import Report, Severity

INTERNET = "internet"
ROAMING = "road-warrior"
KEYS = ("firewallFilteringRules", "ipSourceGroups", "ipv6SourceGroups", "ipDestinationGroups", "ipv6DestinationGroups",
        "networkServices", "networkServiceGroups", "networkApplicationGroups", "networkApplications", "locations",
        "subLocations", "locationGroups", "timeWindows", "fwshift")  # fmt: skip
_ALIASES = {"locations/groups": "locationGroups", "sublocations": "subLocations", "ipSourceGroups/ipv6SourceGroups": "ipv6SourceGroups",
            "ipDestinationGroups/ipv6DestinationGroups": "ipv6DestinationGroups"}  # fmt: skip
_ACTIONS = {"ALLOW": Action.ALLOW, "BLOCK_DROP": Action.DROP, "BLOCK_RESET": Action.RESET_CLIENT, "BLOCK_ICMP": Action.DENY}
# Keys of a rule that say nothing about what it matches, or that hold what is read below.
_RULE_KEYS = {"accessControl", "id", "name", "order", "rank", "action", "state", "description", "lastModifiedTime", "lastModifiedBy",
              "enableFullLogging", "capturePCAP", "defaultRule", "predefined", "isEunEnabled", "eunTemplateId", "labels",
              "excludeContextShieldEndPoint", "locations", "locationGroups", "srcIps", "srcIpGroups", "srcIpv6Groups", "destAddresses",
              "destIpGroups", "destIpv6Groups", "nwServices", "nwServiceGroups", "timeWindows", "excludeSrcCountries"}  # fmt: skip
# Keys that narrow a match and are not modelled: (finding code, what they are).
_NOT_MODELLED = {
    "users": ("ZSCALER_IDENTITY", "users"), "groups": ("ZSCALER_IDENTITY", "groups"), "departments": ("ZSCALER_IDENTITY", "departments"),
    "devices": ("ZSCALER_IDENTITY", "devices"), "deviceGroups": ("ZSCALER_IDENTITY", "device groups"),
    "workloadGroups": ("ZSCALER_IDENTITY", "workload groups"), "zpaAppSegments": ("ZSCALER_IDENTITY", "ZPA application segments"),
    "sourceCountries": ("ZSCALER_COUNTRY", "source countries"), "destCountries": ("ZSCALER_COUNTRY", "destination countries"),
    "destIpCategories": ("ZSCALER_CATEGORY", "destination IP categories"), "resCategories": ("ZSCALER_CATEGORY", "resolved categories"),
    "nwApplications": ("ZSCALER_APPLICATION", "network applications"),
    "nwApplicationGroups": ("ZSCALER_APPLICATION", "network application groups"),
    "appServices": ("ZSCALER_APPLICATION", "application services"), "appServiceGroups": ("ZSCALER_APPLICATION", "application service groups"),
    "endPointApplications": ("ZSCALER_APPLICATION", "endpoint applications"),
    "endPointApplicationGroups": ("ZSCALER_APPLICATION", "endpoint application groups"),
}  # fmt: skip
_TRUST_LEVELS = {"UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"}
# Standard services without ports: what they stand for (by name or tag).
_STANDARD = {"ICMP_ANY": ServiceEntry(Protocol.ICMP), "GRE_PROTOCOL": ServiceEntry(Protocol.IP, ip_protocol=47),
             "ESP_PROTOCOL": ServiceEntry(Protocol.IP, ip_protocol=50)}  # fmt: skip
_PORT_KEYS = ("srcTcpPorts", "destTcpPorts", "srcUdpPorts", "destUdpPorts")
_FQDN = re.compile(r"(\*?\.)?([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,63}\.?")


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _documents(text: str) -> List[Any]:
    """The JSON documents of a text, one after the other (as answers saved with ``curl ... >> file``)."""
    decoder, out, position = json.JSONDecoder(), [], 0
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        value, position = decoder.raw_decode(text, position)
        out.append(value)
    return out


def _kind(item: Any) -> str:
    """Which answer an entry belongs to, by its keys; "" when that cannot be told."""
    if not isinstance(item, dict):
        return ""
    if "action" in item and ("order" in item or "defaultRule" in item or "rank" in item):
        return "firewallFilteringRules"
    if "groupType" in item or "dynamicLocationGroupCriteria" in item:
        return "locationGroups"
    if "parentId" in item or "tz" in item or "vpnCredentials" in item:
        return "locations"
    if _text(item.get("type")).startswith("DSTN_"):
        return "ipDestinationGroups"
    if isinstance(item.get("services"), list):
        return "networkServiceGroups"
    if isinstance(item.get("networkApplications"), list):
        return "networkApplicationGroups"
    if any(k in item for k in _PORT_KEYS) or _text(item.get("type")) in ("STANDARD", "PREDEFINED", "CUSTOM"):
        return "networkServices"
    if "startTime" in item and "endTime" in item:
        return "timeWindows"
    if "ipAddresses" in item and "id" in item:
        return "ipSourceGroups"
    return ""


def _is_rule(item: Any) -> bool:
    return _kind(item) == "firewallFilteringRules"


def looks_like_zscaler(data: bytes) -> bool:
    """Answers of the ZIA API: firewall filtering rules (order, rank, an action of ZIA) or a bundle that names them."""
    head = data[:4_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    if b'"firewallFilteringRules"' in head:
        return True
    actions = (b'"BLOCK_DROP"', b'"BLOCK_RESET"', b'"BLOCK_ICMP"', b'"EVAL_NWAPP"')
    return b'"order"' in head and b'"rank"' in head and b'"action"' in head and any(a in head for a in actions + (b'"ALLOW"',)) \
        and (b'"defaultRule"' in head or any(a in head for a in actions))


class _Builder:
    def __init__(self, answers: Dict[str, List[Any]], report: Report, alone: bool) -> None:
        self.answers, self.report, self.alone = answers, report, alone
        self.p = Policy(vendor="zscaler", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.notes: Dict[str, List[str]] = {}
        self.names: Set[str] = set()
        self.object_names: Set[str] = set()
        self.src_groups: Dict[str, str] = {}  # id -> address group name
        self.dst_groups: Dict[str, str] = {}
        self.dst_why: Dict[str, str] = {}  # id of a destination group -> why it is not modelled
        self.services: Dict[str, str] = {}  # id -> service name
        self.service_groups: Dict[str, str] = {}
        self.locations: Dict[str, str] = {}  # id -> zone
        self.children: Dict[str, List[str]] = {}  # zone of a location -> zones of its sub-locations
        self.location_groups: Dict[str, List[str]] = {}  # id -> zones
        self.windows: Dict[str, str] = {}  # id -> name

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    def _unique(self, text: str, taken: Set[str], fallback: str) -> str:
        base = " ".join(text.split()) or fallback
        name, counter = base, 2
        if base.lower() == ANY:
            name = base = base + " (object)"
        while name.lower() in taken:
            name = f"{base} ({counter})"
            counter += 1
        taken.add(name.lower())
        return name

    def build(self) -> Policy:
        self._locations()
        self._groups()
        self._services()
        for item in self.answers.get("timeWindows", []):
            if isinstance(item, dict) and "id" in item:
                self.windows[_text(item["id"])] = _text(item.get("name")) or f"time window {item['id']}"
        rules = [r for r in self.answers.get("firewallFilteringRules", []) if isinstance(r, dict)]
        if not rules:
            raise ParseError("no firewall filtering rules: expected the answers of the ZIA API (firewallFilteringRules and the "
                             "groups, services and locations it names; the manual has the commands)")  # fmt: skip
        defaults = [r for r in rules if r.get("defaultRule") is True]
        ordinary = [r for r in rules if r.get("defaultRule") is not True]
        for item in ordinary:
            if not isinstance(item.get("order"), int) or isinstance(item.get("order"), bool):
                raise ParseError(f"rule '{_text(item.get('name'))[:60]}' has no order")
        ordinary.sort(key=lambda r: int(r["order"]))  # (stable: rules of one order number keep the order of the answer)
        self._ranks(ordinary)
        for item in ordinary:
            self._rule(item)
        if len(defaults) > 1:
            raise ParseError("more than one default rule: the answers of several tenants or policies?")
        if defaults:
            self._rule(defaults[0], default=True)
        else:
            self._say("ZSCALER_NO_DEFAULT_RULE", "firewallFilteringRules")
        self._notes()
        return self.p

    # -- zones -------------------------------------------------------------------------------------

    def _zone(self, ident: str, label: str) -> str:
        if ident in self.locations:
            return self.locations[ident]
        name = self._unique(label or f"location {ident}", {z.lower() for z in self.p.zones}, "location")
        if name.lower() in (INTERNET, ROAMING.lower()):
            name = self._unique(f"location {name}", {z.lower() for z in self.p.zones}, "location")
        self.p.zones[name] = Zone(name, interfaces=[f"ZIA location {ident}"])
        self.locations[ident] = name
        return name

    def _locations(self) -> None:
        found = [x for x in self.answers.get("locations", []) + self.answers.get("subLocations", []) if isinstance(x, dict) and "id" in x]
        for item in found:
            ident = _text(item["id"])
            if ident == "-3":
                continue  # (Road Warrior, from /locations/lite)
            zone = self._zone(ident, _text(item.get("name")))
            if item.get("ofwEnabled") is False:
                self._say("ZSCALER_FIREWALL_OFF", zone)
        for item in found:
            parent = _text(item.get("parentId"))
            if parent and parent != "0" and _text(item["id"]) in self.locations:
                zone = self.locations[_text(item["id"])]
                if parent in self.locations:
                    self.children.setdefault(self.locations[parent], []).append(zone)
                networks = [parse_literal(_text(a)) for a in item.get("ipAddresses") or []]
                if networks and all(n is not None for n in networks):
                    self.p.zone_networks[zone] = [interval_text(n) for n in networks if n is not None]
        for item in self.answers.get("locationGroups", []):
            if not isinstance(item, dict) or "id" not in item:
                continue
            members = item.get("locations")
            if isinstance(members, list):
                self.location_groups[_text(item["id"])] = [self._zone(_text(m.get("id")), _text(m.get("name")))
                                                           for m in members if isinstance(m, dict) and "id" in m]  # fmt: skip
        for rule in self.answers.get("firewallFilteringRules", []):
            for ident, label in self._refs(rule.get("locations") if isinstance(rule, dict) else None):
                if ident != "-3":
                    self._zone(ident, label)
        self.p.zones[ROAMING] = Zone(ROAMING, interfaces=["Zscaler Client Connector outside a location"])
        self.p.zones[INTERNET] = Zone(INTERNET, interfaces=["internet"])
        self.locations["-3"] = ROAMING

    # -- objects ----------------------------------------------------------------------------------

    def _addresses(self, values: Any, label: str) -> Tuple[List[str], List[str]]:
        """(literals, what cannot be read) of a list of addresses."""
        out, bad = [], []
        for value in values if isinstance(values, list) else []:
            text = _text(value).strip()
            found = parse_literal(text)
            if found is not None and ("/" not in text or parse_literal(text.split("/")[0]) == (found[0], found[1], found[1])):
                out.append(interval_text(found))
            else:
                bad.append(text[:60])
        if not isinstance(values, list) and values is not None:
            bad.append(f"{label} that are not a list")
        return out, bad

    def _groups(self) -> None:
        for key in ("ipSourceGroups", "ipv6SourceGroups"):
            for item in self.answers.get(key, []):
                if not isinstance(item, dict) or "id" not in item:
                    continue
                name = self._unique(_text(item.get("name")), self.object_names, f"source group {item['id']}")
                members, bad = self._addresses(item.get("ipAddresses"), "addresses")
                group = AddressGroup(name, members, description=_text(item.get("description")))
                if bad:
                    group.unsupported = f"addresses that cannot be read: {', '.join(bad[:3])}"
                self.p.address_groups[name] = group
                self.src_groups[_text(item["id"])] = name
        for key in ("ipDestinationGroups", "ipv6DestinationGroups"):
            for item in self.answers.get(key, []):
                if not isinstance(item, dict) or "id" not in item:
                    continue
                ident = _text(item["id"])
                name = self._unique(_text(item.get("name")), self.object_names, f"destination group {item['id']}")
                kind = _text(item.get("type")) or "DSTN_IP"
                group = AddressGroup(name, description=_text(item.get("description")))
                if kind == "DSTN_IP":
                    group.members, bad = self._addresses(item.get("addresses"), "addresses")
                    if bad:
                        group.unsupported = f"addresses that cannot be read: {', '.join(bad[:3])}"
                    if item.get("countries") or item.get("ipCategories") or item.get("urlCategories"):
                        group.unsupported = "countries or categories in a group of addresses"
                else:
                    what = {"DSTN_FQDN": "FQDNs", "DSTN_DOMAIN": "domains", "DSTN_OTHER": "countries and categories"}.get(kind, kind[:30])
                    group.unsupported = f"a destination group of {what} ({kind[:30]}), which the model does not hold"
                    self.dst_why[ident] = "ZSCALER_FQDN" if kind in ("DSTN_FQDN", "DSTN_DOMAIN") else "ZSCALER_CATEGORY"
                self.p.address_groups[name] = group
                self.dst_groups[ident] = name

    @staticmethod
    def _ports(ranges: Any, problems: List[str]) -> Optional[str]:
        """The ports of a list of {start, end}: "" for none, None when they cannot be read."""
        if ranges is None:
            return ""
        if not isinstance(ranges, list):
            problems.append("ports that are not a list")
            return None
        out: List[str] = []
        for item in ranges:
            if not isinstance(item, dict) or not isinstance(item.get("start"), int):
                problems.append("a port range without a start")
                return None
            start: int = item["start"]
            end: int = item["end"] if isinstance(item.get("end"), int) else start
            if not 1 <= start <= end <= 65535:
                problems.append(f"ports {start}-{end}")
                return None
            out.append(str(start) if start == end else f"{start}-{end}")
        return ",".join(out)

    def _services(self) -> None:
        for item in self.answers.get("networkServices", []):
            if not isinstance(item, dict) or "id" not in item:
                continue
            label = _text(item.get("name")) or _text(item.get("tag"))
            name = self._unique(label, {s.lower() for s in self.p.services}, f"service {item['id']}")
            kind = _text(item.get("type"))
            service = Service(name, description=_text(item.get("description")), builtin="zscaler" if kind in ("STANDARD", "PREDEFINED") else "")
            problems: List[str] = []
            for protocol, src_key, dst_key in ((Protocol.TCP, "srcTcpPorts", "destTcpPorts"), (Protocol.UDP, "srcUdpPorts", "destUdpPorts")):
                src, dst = self._ports(item.get(src_key), problems), self._ports(item.get(dst_key), problems)
                if src is None or dst is None:
                    continue
                every = _text(item.get("tag") or label).upper() == f"{protocol.value.upper()}_ANY"
                if src or dst or every:
                    service.entries.append(ServiceEntry(protocol, dst, src))
            standard = _STANDARD.get(_text(item.get("tag") or label).upper())
            if standard is not None and not service.entries:
                service.entries.append(ServiceEntry(standard.protocol, ip_protocol=standard.ip_protocol))
            if problems:
                service.unsupported = "; ".join(problems)
            elif not service.entries:
                service.unsupported = f"a service of type {kind[:20] or 'none'} without ports ({label[:40]}): what it matches is not known"
            self.p.services[name] = service
            self.services[_text(item["id"])] = name
        for item in self.answers.get("networkServiceGroups", []):
            if not isinstance(item, dict) or "id" not in item:
                continue
            name = self._unique(_text(item.get("name")), {s.lower() for s in list(self.p.services) + list(self.p.service_groups)},
                                f"service group {item['id']}")  # fmt: skip
            members = []
            for member in item.get("services") or []:
                ident = _text(member.get("id")) if isinstance(member, dict) else ""
                members.append(self.services.get(ident) or self._missing_service(member))
            self.p.service_groups[name] = ServiceGroup(name, members, description=_text(item.get("description")))
            self.service_groups[_text(item["id"])] = name

    def _missing_service(self, reference: Any) -> str:
        label = _text(reference.get("name")) if isinstance(reference, dict) else ""
        ident = _text(reference.get("id")) if isinstance(reference, dict) else ""
        name = f"{label or 'service'} (id {ident})"
        if name not in self.p.services:
            self.p.services[name] = Service(name, unsupported="a network service that is not in the networkServices of the input")
            self._say("ZSCALER_REFERENCE", name)
        return name

    # -- rules ----------------------------------------------------------------------------------

    def _ranks(self, rules: List[Dict[str, Any]]) -> None:
        lowest = -1
        for item in rules:
            rank = item.get("rank")
            if isinstance(rank, int) and not isinstance(rank, bool):
                if rank < lowest:
                    self._say("ZSCALER_RANK", f"{_text(item.get('name'))[:40]} (rank {rank} below rank {lowest})")
                lowest = max(lowest, rank)

    @staticmethod
    def _refs(value: Any) -> List[Tuple[str, str]]:
        """(id, name) of a list of references."""
        if not isinstance(value, list):
            return []
        return [(_text(v.get("id")), _text(v.get("name"))) for v in value if isinstance(v, dict)]

    def _rule(self, item: Dict[str, Any], default: bool = False) -> None:
        name = self._unique(_text(item.get("name")), self.names, "rule")
        rule = Rule(name, origin=name)
        rule.description = _text(item.get("description"))
        rule.source_ids = {"zscaler.id": _text(item.get("id")), "zscaler.order": _text(item.get("order")), "zscaler.rank": _text(item.get("rank"))}
        if default:
            rule.source_ids["zscaler.default"] = "true"
        if item.get("predefined") is True:
            rule.source_ids["zscaler.predefined"] = "true"
        rule.tags = [_text(label.get("name")) for label in item.get("labels") or [] if isinstance(label, dict) and label.get("name")]
        rule.enabled = _text(item.get("state")) != "DISABLED"
        if _text(item.get("state")) not in ("ENABLED", "DISABLED"):
            rule.unsupported.append(f"state '{_text(item.get('state'))[:20]}'")
        action = _text(item.get("action"))
        rule.action = _ACTIONS.get(action, Action.DROP)
        if action == "EVAL_NWAPP":
            rule.unsupported.append("action EVAL_NWAPP: the decision waits for the network application, which is not modelled")
            self.report.add("rule", name, Severity.REVIEW, "ZSCALER_EVAL_NWAPP",
                            "action EVAL_NWAPP hands the decision to the network application of the traffic: not converted")  # fmt: skip
        elif action not in _ACTIONS:
            rule.unsupported.append(f"action '{action[:30]}'")
        elif action == "BLOCK_ICMP":
            self.report.add("rule", name, Severity.INFO, "ZSCALER_BLOCK_ICMP", "BLOCK_ICMP drops and answers with an ICMP unreachable: read as deny")
        rule.log_end = True
        self._zones_of(rule, item)
        rule.dst_zones = [INTERNET]
        self._sides(rule, item)
        rule.services = self._rule_services(rule, item)
        windows = [self.windows.get(i) or n or f"time window {i}" for i, n in self._refs(item.get("timeWindows"))]
        rule.schedule = ", ".join(windows)
        self._not_modelled(rule, item)
        rule.unsupported = list(dict.fromkeys(rule.unsupported))
        self.p.rules.append(rule)

    def _zones_of(self, rule: Rule, item: Dict[str, Any]) -> None:
        locations = self._refs(item.get("locations"))
        groups = self._refs(item.get("locationGroups"))
        if locations and groups:
            rule.unsupported.append("both locations and location groups: how ZIA combines them is not known")
            self.report.add("rule", rule.name, Severity.REVIEW, "ZSCALER_LOCATION_GROUP",
                            "the rule names locations and location groups: whether ZIA takes either or both is not documented")  # fmt: skip
        zones: List[str] = []
        for ident, label in locations:
            zone = self._zone(ident, label)
            zones.append(zone)
            if self.children.get(zone):
                self.report.add("rule", rule.name, Severity.REVIEW, "ZSCALER_SUBLOCATION",
                                f"location {zone[:40]} has sub-locations ({', '.join(self.children[zone][:4])}): read as the "
                                "location without them, which may be narrower than ZIA")  # fmt: skip
        for ident, label in groups:
            if ident not in self.location_groups:
                rule.unsupported.append(f"location group {label[:40] or ident}: its locations are not in the input")
                self.report.add("rule", rule.name, Severity.REVIEW, "ZSCALER_LOCATION_GROUP",
                                f"location group {label[:40] or ident} is not in the locationGroups of the input")  # fmt: skip
                continue
            zones += self.location_groups[ident]
        if locations or groups:
            rule.src_zones = list(dict.fromkeys(zones)) or [ANY]
        elif self.answers.get("locations"):
            rule.src_zones = [z for z in self.p.zones if z != INTERNET]
        else:
            rule.src_zones = [ANY]

    def _sides(self, rule: Rule, item: Dict[str, Any]) -> None:
        sources, bad = self._addresses(item.get("srcIps"), "source addresses")
        for text in bad:
            rule.unsupported.append(f"source address '{text}' cannot be read")
        for ident, label in self._refs(item.get("srcIpGroups")) + self._refs(item.get("srcIpv6Groups")):
            if ident in self.src_groups:
                sources.append(self.src_groups[ident])
            else:
                rule.unsupported.append(f"source group {label[:40] or ident} is not in the input")
                self._say("ZSCALER_REFERENCE", label[:40] or ident)
        destinations: List[str] = []
        for value in item.get("destAddresses") or []:
            text = _text(value).strip()
            found = parse_literal(text)
            if found is not None:
                destinations.append(interval_text(found))
            elif _FQDN.fullmatch(text):
                rule.unsupported.append(f"destination FQDN {text[:60]}")
                self.report.add("rule", rule.name, Severity.REVIEW, "ZSCALER_FQDN",
                                f"destination {text[:60]}: ZIA matches a domain by the names it sees in the traffic; not modelled")  # fmt: skip
            else:
                rule.unsupported.append(f"destination address '{text[:60]}' cannot be read")
        for ident, label in self._refs(item.get("destIpGroups")) + self._refs(item.get("destIpv6Groups")):
            if ident not in self.dst_groups:
                rule.unsupported.append(f"destination group {label[:40] or ident} is not in the input")
                self._say("ZSCALER_REFERENCE", label[:40] or ident)
                continue
            group = self.dst_groups[ident]
            destinations.append(group)
            if ident in self.dst_why:
                rule.unsupported.append(f"destination group {group[:40]}: {self.p.address_groups[group].unsupported}")
                self.report.add("rule", rule.name, Severity.REVIEW, self.dst_why[ident],
                                f"destination group {group[:40]}: {self.p.address_groups[group].unsupported}")  # fmt: skip
        rule.sources = transform.dedupe(sources) or [ANY]
        rule.destinations = transform.dedupe(destinations) or [ANY]

    def _rule_services(self, rule: Rule, item: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        for ident, label in self._refs(item.get("nwServices")):
            out.append(self.services.get(ident) or self._missing_service({"id": ident, "name": label}))
        for ident, label in self._refs(item.get("nwServiceGroups")):
            if ident in self.service_groups:
                out.append(self.service_groups[ident])
            else:
                rule.unsupported.append(f"service group {label[:40] or ident} is not in the input")
                self._say("ZSCALER_REFERENCE", label[:40] or ident)
        return transform.dedupe(out) or [ANY]

    def _not_modelled(self, rule: Rule, item: Dict[str, Any]) -> None:
        for key, (code, what) in _NOT_MODELLED.items():
            value = item.get(key)
            if not value:
                continue
            listed = [_text(v.get("name") or v.get("id")) if isinstance(v, dict) else _text(v) for v in (value if isinstance(value, list) else [value])]
            text = f"{what} {', '.join(listed[:4])[:80]}" + (" (excluded)" if key == "sourceCountries" and item.get("excludeSrcCountries") else "")
            rule.unsupported.append(text)
            self.report.add("rule", rule.name, Severity.REVIEW, code, f"{text}: narrows the match and is not modelled")
        levels = item.get("deviceTrustLevels")
        if isinstance(levels, list) and levels and set(map(_text, levels)) != _TRUST_LEVELS:
            rule.unsupported.append(f"device trust levels {', '.join(map(_text, levels))[:60]}")
            self.report.add("rule", rule.name, Severity.REVIEW, "ZSCALER_IDENTITY", "device trust levels narrow the match and are not modelled")
        unknown = [k for k, v in item.items() if k not in _RULE_KEYS and k not in _NOT_MODELLED and k != "deviceTrustLevels" and v not in (None, False, [], {}, "")]
        for key in unknown:
            rule.unsupported.append(f"'{key[:30]}' is not read")
            self.report.add("rule", rule.name, Severity.REVIEW, "ZSCALER_UNKNOWN_FIELD", f"'{key[:30]}' is not read; the rule is not converted")

    def _notes(self) -> None:
        zones = [z for z in self.p.zones if z not in (INTERNET, ROAMING)]
        self.report.note(Severity.INFO, "ZSCALER_SOURCE",
                         f"{len(zones)} locations ({', '.join(zones[:8])}{' ...' if len(zones) > 8 else ''}), road-warrior (Client "
                         "Connector outside a location) and internet; the rules decide traffic from the locations to the internet, "
                         "first match in ascending order, and the default rule decides the rest")  # fmt: skip
        self.report.note(Severity.REVIEW, "ZSCALER_OUTBOUND_ONLY",
                         "ZIA filters traffic to the internet only: traffic between locations, inside one and from the internet "
                         "does not pass it, and the model blocks it (no rule allows it). A target that sees such traffic needs "
                         "rules for it")  # fmt: skip
        if not self.answers.get("locations"):
            self._say("ZSCALER_NO_LOCATIONS", "no locations answer")
        if self.alone:
            self._say("ZSCALER_RULES_ALONE", "the answer of firewallFilteringRules alone")
        texts = {
            "ZSCALER_NO_LOCATIONS": (Severity.REVIEW, "the locations are not known: rules without locations are read as applying to "
                                     "traffic from every zone"),
            "ZSCALER_RULES_ALONE": (Severity.REVIEW, "only the rules: the groups, services and locations they name are not known, and "
                                    "rules that name them are not converted"),
            "ZSCALER_NO_DEFAULT_RULE": (Severity.REVIEW, "no default rule in the input: the model blocks what no rule matches, which may "
                                        "not be what the tenant does"),
            "ZSCALER_RANK": (Severity.REVIEW, "admin ranks out of the rule order: read in the rule order"),
            "ZSCALER_FIREWALL_OFF": (Severity.REVIEW, "locations whose firewall is off (ofwEnabled false): the rules do not decide their "
                                     "traffic on ZIA, the model applies them anyway"),
            "ZSCALER_REFERENCE": (Severity.REVIEW, "objects named by rules or groups that are not in the input"),
            "ZSCALER_UNKNOWN_KEYS": (Severity.INFO, "answers that are not read"),
            "ZSCALER_UNCLASSIFIED": (Severity.REVIEW, "answers whose entries could not be told apart, not read"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def _answers(document: Any, report: Report) -> Tuple[Dict[str, List[Any]], bool, List[str], List[str]]:
    """The answers by endpoint, whether the rules came alone, unknown keys, and lists that could not be told."""
    answers: Dict[str, List[Any]] = {}
    unknown: List[str] = []
    unclassified: List[str] = []
    if isinstance(document, dict) and not _is_rule(document):
        for key, value in document.items():
            name = _ALIASES.get(key.strip("/"), key.strip("/"))
            if name not in KEYS:
                unknown.append(key[:40])
                continue
            if name == "fwshift":
                continue
            answers.setdefault(name, []).extend(value if isinstance(value, list) else [value])
        return answers, False, unknown, unclassified
    documents = document if isinstance(document, list) else [document]
    if documents and all(_is_rule(d) for d in documents):
        return {"firewallFilteringRules": list(documents)}, True, [], []
    for index, answer in enumerate(documents, 1):
        items = answer if isinstance(answer, list) else [answer]
        kinds = {_kind(item) for item in items if isinstance(item, dict)}
        if not items:
            continue
        if len(kinds) != 1 or "" in kinds:
            unclassified.append(f"answer {index}")
            continue
        answers.setdefault(kinds.pop(), []).extend(items)
    alone = set(answers) == {"firewallFilteringRules"}
    return answers, alone, unknown, unclassified


def parse(data: bytes, report: Report) -> Policy:
    try:
        documents = _documents(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    if not documents:
        raise ParseError("no JSON in the input")
    document: Any = documents[0] if len(documents) == 1 else documents
    if isinstance(document, dict) and isinstance(document.get("message"), str) and isinstance(document.get("code"), str):
        raise ParseError(f"an error answer of the ZIA API: {document['code'][:40]}: {document['message'][:160]}")
    try:
        answers, alone, unknown, unclassified = _answers(document, report)
        builder = _Builder(answers, report, alone)
        for key in unknown:
            builder._say("ZSCALER_UNKNOWN_KEYS", key)
        for key in unclassified:
            builder._say("ZSCALER_UNCLASSIFIED", key)
        return builder.build()
    except ParseError:
        raise
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None
