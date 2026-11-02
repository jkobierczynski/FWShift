# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Netskope Cloud Firewall parser: the firewall rules of the Real-time Protection policies of Netskope One -> model.

Netskope One is a SASE platform; its Cloud Firewall decides the traffic that users (Netskope Client) and sites (IPsec
and GRE tunnels) send through Netskope to the internet. Its rules are the Real-time Protection policies of the type
firewall. FWShift only reads them: Netskope documents no API and no Terraform resource that creates them (see below).

What is read is JSON: the Real-time Protection policies as a list of rules (the JSON of *Policies > Real-time
Protection > Export*, or the answer of the tenant's rules endpoint, ``{"data": [...]}``), or an object that holds that
list under ``rules`` together with what the rules name: ``service_objects``, ``destination_profiles``,
``firewall_apps`` (the definitions of custom firewall apps) and ``default_action`` (``block`` or ``allow``). Each rule
is ``rule_name``, ``enabled`` (``"1"`` or ``"0"``) and ``rule_data``; ``rule_data`` holds ``policy_type``,
``access_method``, ``users``, ``user_groups``, ``organization_units``, ``net_location_obj``, ``src_countries``,
``schedule`` and ``match_criteria_action`` (``action_name``) as the rules API of Netskope Private Access names them
(the registry documentation of ``netskope_npa_rules``), and ``src_ips``/``b_negate_src_ips``, ``any_traffic``,
``firewall_apps``, ``cloud_apps``, ``destination_profiles`` and ``service_objects`` for the criteria of a firewall rule.
**Netskope publishes neither the shape of the export nor that of the rules endpoint**: these names are FWShift's
reading (not confirmed on a tenant). Any other key of a rule makes the rule not converted, so a file of another shape
is reported rule by rule and never read wrongly; the keys are in ``_RULE_DATA`` below and in the manual. A service
object has the documented shape of ``netskope_service_object`` (``name``, ``protocols`` with ``tcp``, ``udp``,
``tcp_udp`` port lists and ``icmp``), a destination profile that of ``netskope_destination_profile`` (``name``,
``type``, ``values``); a custom firewall app is ``name``, ``destinations`` (IP addresses, ranges, CIDR, host names, as
the definition page takes them) and ``protocols`` as a service object.

How the Cloud Firewall decides, from Netskope's documentation, and how it is mapped onto the neutral model:

* "a top-to-bottom, first-match approach": the rules in the order of the list (the order of the export is taken to
  be the order of the policy page; not confirmed). Policies of other types (web, cloud app, DLP, threat protection,
  DNS) are skipped for firewall traffic and are not read. A disabled rule stays in place, disabled.
* The **Default Action** of the firewall policy applies to traffic no rule matches; it is Block unless changed. It
  becomes a last rule, ``Default Action``. It is a property of the tenant, not of a rule: give it as
  ``default_action``, or Block is assumed and said.
* Zones: the access method is where traffic comes from (``client``, ``ipsec``, ``gre``: the access methods a firewall
  rule can name), ``internet`` is where it goes; a rule without access methods applies to all three. Traffic between
  users or sites does not pass the Cloud Firewall, and the model says nothing about it.
* Source IP (Matches / Does Not Match) is the source of the packet: a rule's sources, negated for Does Not Match.
  Destination profiles hold addresses, service objects ports: a rule with both matches the product. A custom firewall
  app is its destinations with its ports (empty destinations: any); a rule of several custom apps is one rule per app,
  in place, which is exact (same action, one after the other). *Any Traffic* is any destination and any service.
* What narrows a match and has no place in the model makes the rule not converted (``Rule.unsupported``, with a
  finding): users, user groups and OUs; predefined (DPI) firewall apps and cloud apps; host names, in custom apps and
  destination profiles (Netskope evaluates them only for the Netskope Client); network locations (Source IP (Egress)),
  source countries, device classification, schedules.
* Flows are tracked: a rule decides the first packet of a connection (TCP SYN, the first UDP packet), which is the
  model's reading. Every flow is logged (network events, and alerts for blocks): the rules log at the end.
* Web traffic (HTTP and HTTPS through the proxy) that no firewall rule matches is decided by the web and cloud app
  policies and their defaults, which are not converted: the model applies the Default Action to it.

Netskope Private Access rules (``policy_type`` ``private-app``) are refused: they grant users access to private apps
through publishers, with no network path the model could express, and every rule is about users.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import ANY, Action, AddressGroup, Policy, Protocol, Rule, Service, ServiceEntry, Zone
from ..netutil import interval_text, parse_literal
from ..report import Report, Severity

ZONES = {"client": "Client", "ipsec": "IPSec", "gre": "GRE"}  # zone -> access method as Netskope writes it
INTERNET = "internet"
BUNDLE_KEYS = ("rules", "service_objects", "destination_profiles", "firewall_apps", "default_action", "fwshift")
# The keys of a rule outside rule_data: what it is called, whether it is on, where it is kept. None of them matches.
_RULE_KEYS = {"rule_id", "id", "rule_name", "enabled", "description", "rule_data", "group_id", "group_name", "rule_order", "modify_time",
              "modify_by", "modify_type"}  # fmt: skip
# The keys of rule_data: what each is, and the finding when it narrows the rule in a way the model cannot express.
# "read" keys are converted; "meta" keys match nothing.
_RULE_DATA: Dict[str, Tuple[str, str]] = {
    "policy_type": ("meta", ""),
    "json_version": ("meta", ""),
    "description": ("meta", ""),
    "user_type": ("meta", ""),
    "match_criteria_action": ("read", ""),
    "access_method": ("read", ""),
    "src_ips": ("read", ""),
    "b_negate_src_ips": ("read", ""),
    "any_traffic": ("read", ""),
    "firewall_apps": ("read", ""),
    "destination_profiles": ("read", ""),
    "service_objects": ("read", ""),
    "users": ("NETSKOPE_USERS", "users"),
    "user_groups": ("NETSKOPE_USERS", "user groups"),
    "organization_units": ("NETSKOPE_USERS", "organization units"),
    "cloud_apps": ("NETSKOPE_APPLICATION", "cloud apps"),
    "net_location_obj": ("NETSKOPE_NOT_CONVERTED", "network locations (Source IP (Egress))"),
    "b_negate_net_location": ("flag", ""),
    "src_countries": ("NETSKOPE_NOT_CONVERTED", "source countries"),
    "b_negate_src_countries": ("flag", ""),
    "device_classification_id": ("NETSKOPE_NOT_CONVERTED", "device classification"),
    "classification": ("NETSKOPE_NOT_CONVERTED", "device classification"),
    "os": ("NETSKOPE_NOT_CONVERTED", "operating systems"),
    "user_confidence": ("NETSKOPE_NOT_CONVERTED", "user confidence index"),
    "schedule": ("NETSKOPE_NOT_CONVERTED", "a schedule"),
}
_ACTION_KEYS = {"action_name", "emit_alert", "template"}
_FQDN = re.compile(r"(\*\.)?([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}\.?")
_PORTS = re.compile(r"\d{1,5}(-\d{1,5})?")

Problem = Tuple[str, str]  # (finding code, text)


def looks_like_netskope(data: bytes) -> bool:
    """JSON with rules of the Netskope policy engine: ``rule_data`` with a ``match_criteria_action``."""
    head = data[:4_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    return b'"rule_data"' in head and b'"match_criteria_action"' in head


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _empty(value: Any) -> bool:
    """Not used in the rule: Netskope reads a criterion that is not used as Any."""
    if value is None or value is False or value == "":
        return True
    if isinstance(value, list):
        return all(_empty(v) for v in value)
    if isinstance(value, dict):
        return all(_empty(v) for v in value.values())
    return False


def _items(value: Any) -> Optional[List[Any]]:
    """A list as the export writes it, or as an API answer wraps it (``{"data": [...]}``); None if it is neither."""
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        items: List[Any] = value["data"]
        return items
    if isinstance(value, list):
        return value
    return None


def _strings(value: Any) -> Optional[List[str]]:
    """A list of names or values (one comma-separated text is taken too); None if it is something else."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list) and all(isinstance(v, (str, int)) and not isinstance(v, bool) for v in value):
        return [str(v).strip() for v in value if str(v).strip()]
    return None


class _Builder:
    def __init__(self, rules: List[Any], bundle: Dict[str, Any], report: Report) -> None:
        self.rules, self.bundle, self.report = rules, bundle, report
        self.p = Policy(vendor="netskope", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.names: Set[str] = set()
        self.object_names: Set[str] = set()
        self.services: Dict[str, str] = {}  # service object name -> service of the model
        self.profiles: Dict[str, str] = {}  # destination profile name -> address group
        self.apps: Dict[str, Tuple[List[str], List[str], List[Problem]]] = {}  # custom app -> (destinations, services, problems)
        self.icmp: List[str] = []
        self.other_types: Dict[str, int] = {}
        self.firewall_rules = 0

    # -- names -------------------------------------------------------------------------------------

    def _name(self, text: str) -> str:
        base = text.strip() or "rule"
        name, counter = base, 2
        while name.lower() in self.names:
            name = f"{base} ({counter})"
            counter += 1
        self.names.add(name.lower())
        return name

    def _object_name(self, text: str) -> str:
        base = text.strip() or "object"
        if base.lower() == ANY:
            base += " (object)"  # (any is every address in the model)
        name, counter = base, 2
        while name.lower() in self.object_names:
            name = f"{base} ({counter})"
            counter += 1
        self.object_names.add(name.lower())
        return name

    # -- objects -----------------------------------------------------------------------------------

    def _entries(self, protocols: Any, label: str) -> Tuple[List[ServiceEntry], str]:
        """The entries of a ``protocols`` block (service object, custom app); a reason when it cannot be read."""
        if not isinstance(protocols, dict):
            return [], f"{label}: no protocols"
        unknown = [k for k in protocols if k not in ("tcp", "udp", "tcp_udp", "icmp")]
        if unknown:
            return [], f"{label}: protocol '{_text(unknown[0])[:20]}' is not read"
        ports: Dict[str, List[str]] = {"tcp": [], "udp": []}
        for key in ("tcp", "udp", "tcp_udp"):
            given = _strings(protocols.get(key))
            if given is None:
                return [], f"{label}: {key} ports that are not a list"
            for part in (p.strip() for item in given for p in item.split(",")):
                compact = part.replace(" ", "")
                low, _, high = compact.partition("-")
                if not _PORTS.fullmatch(compact) or not 1 <= int(low) <= int(high or low) <= 65535:
                    return [], f"{label}: {key} port '{part[:20]}' cannot be read"
                text = str(int(low)) if int(high or low) == int(low) else f"{int(low)}-{int(high)}"
                for protocol in (("tcp", "udp") if key == "tcp_udp" else (key,)):
                    if text not in ports[protocol]:
                        ports[protocol].append(text)
        entries = [ServiceEntry(Protocol(proto), ",".join(found)) for proto, found in ports.items() if found]
        icmp = protocols.get("icmp")
        if icmp not in (None, True, False):
            return [], f"{label}: icmp '{_text(icmp)[:10]}' cannot be read"
        if icmp is True:
            entries.append(ServiceEntry(Protocol.ICMP))
            self.icmp.append(label)
        if not entries:
            return [], f"{label}: no protocol and no port"
        return entries, ""

    def _service_objects(self) -> None:
        for item in _items(self.bundle.get("service_objects")) or []:
            if not isinstance(item, dict) or not _text(item.get("name")).strip():
                continue
            source = _text(item["name"]).strip()
            name = source
            counter = 2
            while name in self.p.services:
                name = f"{source} ({counter})"
                counter += 1
            entries, why = self._entries(item.get("protocols"), f"service object {source[:40]}")
            service = Service(name, entries, description=_text(item.get("description"))[:200])
            if _text(item.get("type")).upper() == "PREDEFINED":
                service.builtin = "netskope"
            if why:
                service.unsupported = why
            self.p.services[name] = service
            self.services.setdefault(source, name)

    def _addresses(self, values: List[str], label: str) -> Tuple[List[str], List[Problem]]:
        """Literals of the model for addresses as Netskope takes them; host names and the rest are problems."""
        out: List[str] = []
        problems: List[Problem] = []
        for value in values:
            interval = parse_literal(value)
            if interval is not None:
                address = value.split("/")[0].strip()
                if "/" in value and parse_literal(address) != (interval[0], interval[1], interval[1]):
                    problems.append(("NETSKOPE_NOT_CONVERTED", f"{label}: '{value[:40]}' has host bits"))
                    continue
                out.append(interval_text(interval))
            elif _FQDN.fullmatch(value) and not value.replace(".", "").isdigit():
                problems.append(("NETSKOPE_FQDN", f"{label}: host name '{value[:60]}'"))
            else:
                problems.append(("NETSKOPE_NOT_CONVERTED", f"{label}: '{value[:40]}' cannot be read"))
        return list(dict.fromkeys(out)), problems

    def _destination_profiles(self) -> None:
        for item in _items(self.bundle.get("destination_profiles")) or []:
            if not isinstance(item, dict) or not _text(item.get("name")).strip():
                continue
            source = _text(item["name"]).strip()
            name = self._object_name(source)
            group = AddressGroup(name, description=_text(item.get("description"))[:200])
            values = _strings(item.get("values"))
            kind = _text(item.get("type")).lower()
            if values is None or not values:
                group.unsupported = "a destination profile without values"
            elif kind == "regex":
                group.unsupported = "a destination profile of regular expressions"
            else:
                members, problems = self._addresses(values, f"destination profile {source[:40]}")
                group.members = members
                if problems:
                    group.unsupported = problems[0][1]
            self.p.address_groups[name] = group
            self.profiles.setdefault(source, name)

    def _firewall_apps(self) -> None:
        for item in _items(self.bundle.get("firewall_apps")) or []:
            if not isinstance(item, dict) or not _text(item.get("name")).strip():
                continue
            source = _text(item["name"]).strip()
            label = f"firewall app {source[:40]}"
            problems: List[Problem] = []
            values = _strings(item.get("destinations"))
            destinations = [ANY]
            if values is None:
                problems.append(("NETSKOPE_NOT_CONVERTED", f"{label}: destinations that are not a list"))
            elif values:  # (empty: Netskope sets the destination to any)
                members, problems = self._addresses(values, label)
                if members and not problems:
                    name = self._object_name(source)
                    self.p.address_groups[name] = AddressGroup(name, members, description="the destinations of a custom firewall app")
                    destinations = [name]
            entries, why = self._entries(item.get("protocols"), label)
            services = [ANY]
            if why:
                problems.append(("NETSKOPE_NOT_CONVERTED", why))
            else:
                name = source
                counter = 2
                while name in self.p.services:
                    name = f"{source} ({counter})"
                    counter += 1
                self.p.services[name] = Service(name, entries, description="the protocols of a custom firewall app")
                services = [name]
            self.apps[source] = (destinations, services, problems)

    # -- rules -------------------------------------------------------------------------------------

    def build(self) -> Policy:
        for zone, method in ZONES.items():
            self.p.zones[zone] = Zone(zone, interfaces=[method])
        self.p.zones[INTERNET] = Zone(INTERNET, interfaces=["egress"])
        self._service_objects()
        self._destination_profiles()
        self._firewall_apps()
        for index, item in enumerate(self.rules, 1):
            if not isinstance(item, dict):
                raise ParseError(f"rule {index} of the list is not an object")
            data = item.get("rule_data")
            policy_type = _text(data.get("policy_type")).strip().lower() if isinstance(data, dict) else ""
            if policy_type == "private-app":
                raise ParseError("Netskope Private Access rules (policy_type private-app): FWShift reads the Cloud Firewall rules of "
                                 "the Real-time Protection policies; private access by users to private apps has no network path to convert")  # fmt: skip
            if policy_type and policy_type != "firewall":
                self.other_types[policy_type[:30]] = self.other_types.get(policy_type[:30], 0) + 1
                continue
            self._rule(item, index)
        self._default()
        self._notes()
        return self.p

    def _rule(self, item: Dict[str, Any], index: int) -> None:
        name = self._name(_text(item.get("rule_name"))[:100] or f"rule {index}")
        problems: List[Problem] = []
        rule = Rule(name, src_zones=list(ZONES), dst_zones=[INTERNET], origin=name)
        rule.log_end = True
        rule.description = (_text(item.get("description")) or _text((item.get("rule_data") or {}).get("description")
                            if isinstance(item.get("rule_data"), dict) else ""))[:200]  # fmt: skip
        ident = item.get("rule_id", item.get("id"))
        if ident is not None:
            rule.source_ids["netskope.rule_id"] = _text(ident)[:40]
        enabled = item.get("enabled")
        if enabled in ("0", 0, False):
            rule.enabled = False
        elif enabled not in ("1", 1, True):
            rule.enabled = False
            problems.append(("NETSKOPE_NOT_CONVERTED", f"enabled '{_text(enabled)[:10]}' cannot be read"))
        unknown = [k for k in item if k not in _RULE_KEYS]
        if unknown:
            problems.append(("NETSKOPE_NOT_CONVERTED", f"key '{_text(unknown[0])[:30]}' of the rule is not read"))
        data = item.get("rule_data")
        if not isinstance(data, dict):
            problems.append(("NETSKOPE_NOT_CONVERTED", "no rule_data"))
            self._finish(rule, problems)
            return
        self.firewall_rules += 1
        if not _text(data.get("policy_type")).strip():
            problems.append(("NETSKOPE_NOT_CONVERTED", "no policy_type: whether it is a firewall rule is not known"))
        for key, value in data.items():
            kind, text = _RULE_DATA.get(key, ("unknown", ""))
            if kind == "unknown":
                problems.append(("NETSKOPE_NOT_CONVERTED", f"key '{_text(key)[:30]}' of rule_data is not read"))
            elif kind == "flag":
                if value not in (None, True, False):
                    problems.append(("NETSKOPE_NOT_CONVERTED", f"{key} '{_text(value)[:10]}' cannot be read"))
            elif kind.startswith("NETSKOPE_") and not _empty(value):
                shown = ", ".join(_strings(value) or [])[:80]
                problems.append((kind, f"{text}{': ' + shown if shown else ''}"))
        if data.get("b_negate_net_location") is True and _empty(data.get("net_location_obj")):
            problems.append(("NETSKOPE_NOT_CONVERTED", "Does Not Match of no network location"))
        if data.get("b_negate_src_countries") is True and _empty(data.get("src_countries")):
            problems.append(("NETSKOPE_NOT_CONVERTED", "Does Not Match of no source country"))
        rule.action = self._action(data.get("match_criteria_action"), problems)
        rule.src_zones = self._zones(data.get("access_method"), problems)
        self._sources(rule, data, problems)
        parts = self._destinations(data, problems)
        if len(parts) <= 1:
            if parts:
                rule.destinations, rule.services = parts[0][1], parts[0][2]
            self._finish(rule, problems)
            return
        # One rule per custom app, in place: the same action one after the other is the union of what they match.
        base = rule
        self.names.discard(base.name.lower())
        for label, destinations, services in parts:
            part = Rule(self._name(f"{base.name} [{label}]"), src_zones=list(base.src_zones), dst_zones=[INTERNET], sources=list(base.sources),
                        destinations=destinations, services=services, action=base.action, enabled=base.enabled,
                        negate_source=base.negate_source, description=base.description)  # fmt: skip
            part.origin, part.log_end, part.source_ids = part.name, True, dict(base.source_ids)
            part.source_ids["netskope.rule_name"] = base.name
            self.report.add("rule", part.origin, Severity.INFO, "NETSKOPE_APPS_SPLIT",
                            f"rule {base.name[:60]} names {len(parts)} custom firewall apps: one rule per app, in place (exact)")
            self._finish(part, list(problems))

    def _finish(self, rule: Rule, problems: List[Problem]) -> None:
        problems = list(dict.fromkeys(problems))
        rule.unsupported = list(dict.fromkeys(text for _, text in problems))
        for code, text in problems:
            self.report.add("rule", rule.origin, Severity.REVIEW, code, f"{text}; the rule is not converted")
        self.p.rules.append(rule)

    def _action(self, value: Any, problems: List[Problem]) -> Action:
        if not isinstance(value, dict):
            problems.append(("NETSKOPE_NOT_CONVERTED", "no match_criteria_action"))
            return Action.DENY
        unknown = [k for k in value if k not in _ACTION_KEYS]
        if unknown:
            problems.append(("NETSKOPE_NOT_CONVERTED", f"key '{_text(unknown[0])[:30]}' of the action is not read"))
        action = _text(value.get("action_name")).strip().lower()
        if action == "allow":
            return Action.ALLOW
        if action != "block":
            problems.append(("NETSKOPE_NOT_CONVERTED", f"action '{action[:20]}': a firewall rule allows or blocks"))
        return Action.DENY

    def _zones(self, value: Any, problems: List[Problem]) -> List[str]:
        methods = _strings(value)
        if methods is None:
            problems.append(("NETSKOPE_NOT_CONVERTED", "access methods that are not a list"))
            return list(ZONES)
        zones: List[str] = []
        for method in methods:
            zone = method.lower().replace(" ", "")
            if zone in ZONES:
                zones.append(zone)
            else:
                problems.append(("NETSKOPE_NOT_CONVERTED", f"access method '{method[:30]}' (a firewall rule takes Client, IPSec and GRE)"))
        return list(dict.fromkeys(zones)) or list(ZONES)

    def _sources(self, rule: Rule, data: Dict[str, Any], problems: List[Problem]) -> None:
        values = _strings(data.get("src_ips"))
        negate = data.get("b_negate_src_ips")
        if negate not in (None, True, False):
            problems.append(("NETSKOPE_NOT_CONVERTED", f"b_negate_src_ips '{_text(negate)[:10]}' cannot be read"))
        if values is None:
            problems.append(("NETSKOPE_NOT_CONVERTED", "source IP addresses that are not a list"))
            return
        if not values:
            if negate is True:
                problems.append(("NETSKOPE_NOT_CONVERTED", "Does Not Match of no source IP address"))
            return
        members, found = self._addresses(values, "source IP")
        problems += found
        if members:
            rule.sources = members
            rule.negate_source = negate is True

    def _destinations(self, data: Dict[str, Any], problems: List[Problem]) -> List[Tuple[str, List[str], List[str]]]:
        """(label, destinations, services) per part of the rule: one, or one per custom firewall app; none when it cannot be read."""
        apps, profiles, services = (_strings(data.get(key)) for key in ("firewall_apps", "destination_profiles", "service_objects"))
        any_traffic = data.get("any_traffic")
        if apps is None or profiles is None or services is None or any_traffic not in (None, True, False):
            problems.append(("NETSKOPE_NOT_CONVERTED", "a destination that cannot be read"))
            return []
        if any_traffic is True:
            if apps or profiles or services:
                problems.append(("NETSKOPE_NOT_CONVERTED", "Any Traffic together with other destinations"))
                return []
            return [("any", [ANY], [ANY])]
        if apps:
            if profiles or services:
                problems.append(("NETSKOPE_NOT_CONVERTED", "firewall apps together with destination profiles or service objects"))
                return []
            parts: List[Tuple[str, List[str], List[str]]] = []
            for app in apps:
                if app not in self.apps:
                    problems.append(("NETSKOPE_APPLICATION", f"firewall app {app[:40]}: a predefined (DPI) application, or a custom app "
                                     "that is not in firewall_apps"))  # fmt: skip
                    continue
                targets, ports, why = self.apps[app]
                problems += why
                parts.append((app, targets, ports))
            return parts if len(parts) == len(apps) else []
        if not profiles and not services:
            problems.append(("NETSKOPE_NOT_CONVERTED", "no destination (no Any Traffic, firewall app, destination profile or service object)"))
            return []
        destinations: List[str] = []
        for profile in profiles:
            name = self.profiles.get(profile)
            if name is None:
                problems.append(("NETSKOPE_NOT_CONVERTED", f"destination profile {profile[:40]} is not in destination_profiles"))
                continue
            group = self.p.address_groups[name]
            if group.unsupported:
                code = "NETSKOPE_FQDN" if "host name" in group.unsupported else "NETSKOPE_NOT_CONVERTED"
                problems.append((code, group.unsupported))
            destinations.append(name)
        members: List[str] = []
        for service in services:
            name = self.services.get(service)
            if name is None:
                problems.append(("NETSKOPE_NOT_CONVERTED", f"service object {service[:40]} is not in service_objects"))
                continue
            if self.p.services[name].unsupported:
                problems.append(("NETSKOPE_NOT_CONVERTED", self.p.services[name].unsupported))
            members.append(name)
        return [("", transform.dedupe(destinations) or [ANY], transform.dedupe(members) or [ANY])]

    def _default(self) -> None:
        given = self.bundle.get("default_action")
        action = _text(given).strip().lower()
        if given is None:
            action = "block"
            self.report.note(Severity.REVIEW, "NETSKOPE_DEFAULT_ASSUMED", "the input does not say the Default Action of the firewall policy: "
                             "read as Block, Netskope's default; give it as default_action if it was changed")  # fmt: skip
        elif action not in ("block", "allow"):
            raise ParseError(f"default_action '{action[:20]}': block or allow")
        rule = Rule(self._name("Default Action"), src_zones=list(ZONES), dst_zones=[INTERNET],
                    action=Action.ALLOW if action == "allow" else Action.DENY)  # fmt: skip
        rule.origin, rule.log_end = rule.name, True
        rule.description = "the Default Action of the firewall policy: what no rule matches"
        self.p.rules.append(rule)

    def _notes(self) -> None:
        self.report.note(Severity.INFO, "NETSKOPE_SOURCE",
                         f"{self.firewall_rules} firewall rules of the Real-time Protection policies, first match, from the access methods "
                         "(zones client, ipsec, gre) to the zone internet, then the Default Action; only traffic steered to Netskope "
                         "is decided by them, and traffic between users or sites is not in the model")  # fmt: skip
        self.report.note(Severity.REVIEW, "NETSKOPE_WEB_TRAFFIC",
                         "web traffic (HTTP and HTTPS through the proxy) that no firewall rule matches is decided by the web and cloud app "
                         "policies and their defaults, which are not converted: the model applies the Default Action to it")  # fmt: skip
        if self.other_types:
            self.report.note(Severity.INFO, "NETSKOPE_OTHER_POLICIES",
                             "policies of other types, which firewall traffic skips, not read: "
                             + ", ".join(f"{count} {kind}" for kind, count in sorted(self.other_types.items())))  # fmt: skip
        if not self.firewall_rules and self.other_types:
            self.report.note(Severity.REVIEW, "NETSKOPE_NO_FIREWALL_RULES",
                             "no rule of policy_type firewall: only the Default Action is in the model (types found: "
                             + ", ".join(sorted(self.other_types)) + ")")  # fmt: skip
        if self.icmp:
            self.report.note(Severity.REVIEW, "NETSKOPE_ICMP",
                             "ICMP read as ICMP for IPv4; whether it also matches ICMPv6 is not documented: "
                             + ", ".join(dict.fromkeys(self.icmp[:12])))  # fmt: skip
        unknown = [k for k in self.bundle if k not in BUNDLE_KEYS]
        if unknown:
            self.report.note(Severity.INFO, "NETSKOPE_UNKNOWN_KEYS", "keys that are not read: " + ", ".join(_text(k)[:30] for k in unknown[:8]))


def parse(data: bytes, report: Report) -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    bundle: Dict[str, Any] = {}
    rules = _items(document)
    if isinstance(document, dict) and "rules" in document:
        bundle, rules = document, _items(document["rules"])
    if rules is None:
        raise ParseError("expected the Real-time Protection policies as a list of rules (the JSON export, or {\"data\": [...]}), or an "
                         "object with that list under rules and the service objects, destination profiles and firewall apps they name")  # fmt: skip
    try:
        return _Builder(rules, bundle, report).build()
    except ParseError:
        raise
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None
