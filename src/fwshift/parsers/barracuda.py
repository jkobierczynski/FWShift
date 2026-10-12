# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Barracuda parser: the JSON of the REST API of a CloudGen Firewall (8.0 and later) -> neutral model.

A CloudGen Firewall has no export of its forwarding rules that another program can read: its
configuration backup (a PAR file) is in a format of its own that Barracuda does not document. What
can be read is what the REST API of the firewall answers, saved to a file: the forwarding rules
(``GET /rest/config/v1/forwarding-firewall/rules?expand=true``) and the network and service objects
they name, one answer after the other (section 3 of the manual). Barracuda documents that API by
examples only; the keys read are those its examples and the published tools that use it show, and
the report says so.

How the firewall differs from the model, and what is done about it:

* A rule has no zones. The firewall picks the way out by its routes and the connection object of
  the rule. An entry of a network object can name the interface traffic comes in by, and does so
  when the object is the source of a rule: interfaces are the zones here, and a rule whose source
  holds entries of several interfaces becomes one rule per interface.
* A network object can exclude addresses. They are subtracted.
* Rules are first match. IPv4 and IPv6 rules are told apart by the version of each rule. What no
  rule matches is blocked.
* A rule may be bi-directional: it then matches traffic the other way round as well, and becomes
  two rules.
* Destination NAT and source NAT are parts of a rule (the action Dst NAT, Map, and the connection
  object). How the API spells them is not known: such rules are not read, and the report says so.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..errors import ParseError
from ..model import ANY, ANY_V4, ANY_V6, Action, Address, AddressGroup, AddressKind, Policy, Protocol, Rule, Service
from ..model import ServiceEntry, ServiceGroup, Zone
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, parse_literal, subtract
from ..report import Report, Severity
from .cisco import _documents

_MAX_NESTING = 64
_MAX_LEAVES = 200000
# Keys of a rule that do not narrow or widen what it matches, or that are read where they are.
_RULE_KEYS = {"name", "comment", "deactivated", "dynamic", "bidirectional", "ipVersion", "source", "destination", "service",
              "action", "policies", "position", "color", "expiresIn", "expireAction", "id"}  # fmt: skip
_ENTRY_KEYS = {"protocol", "ports", "portRange", "clientPortUsed", "sessionTimeout", "balancedTimeout", "comment", "plugin",
               "serviceLabel", "maxPingSize", "minDelay", "tcp", "udp", "icmp", "other"}  # fmt: skip
_NO_TRANSLATION = {"original source ip", "originalsourceip", "no snat", "nosnat", "no snat (bridging)", "client (no translation)",
                   "client", "none", ""}  # fmt: skip
_SUBOBJECTS = ("tcp", "udp", "icmp", "other")
_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "icmp6": 58, "ipv6-icmp": 58, "gre": 47, "esp": 50, "ah": 51,
              "sctp": 132}  # fmt: skip
_HOST = re.compile(r"(?=.{1,253}$)(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+")


def looks_like_barracuda(data: bytes) -> bool:
    """JSON with the keys of the REST API of a CloudGen Firewall."""
    head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    sample = data[:2_000_000]
    rules = all(sign in sample for sign in (b'"references"', b'"deactivated"', b'"ipVersion"'))
    objects = b'"included"' in sample and b'"entry"' in sample
    return rules or objects


@dataclass
class _Leaf:
    """One address of a network object: an interval or a host name, with the interface of its entry."""

    interval: Optional[Interval]
    host: str
    interface: str


@dataclass
class _Net:
    name: str
    raw: Dict[str, Any]
    problem: str = ""
    leaves: Optional[List[_Leaf]] = None


@dataclass
class _Reader:
    report: Report
    p: Policy
    nets: Dict[str, _Net] = field(default_factory=dict)
    services: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    rules: List[Dict[str, Any]] = field(default_factory=list)
    listed: Set[str] = field(default_factory=set)
    answers: int = 0
    rule_answers: int = 0
    missing: Set[str] = field(default_factory=set)
    connections: List[str] = field(default_factory=list)
    icmp_limits: List[str] = field(default_factory=list)
    leaves_read: int = 0
    resolving: Set[str] = field(default_factory=set)
    zones: Set[str] = field(default_factory=set)
    empty: str = ""
    dst_interfaces: bool = False
    taken: Set[str] = field(default_factory=set)
    derived: Dict[Tuple[str, str, int], str] = field(default_factory=dict)
    bad_services: Dict[str, str] = field(default_factory=dict)
    checked: Set[str] = field(default_factory=set)
    limited: Set[str] = field(default_factory=set)
    limited_rules: List[str] = field(default_factory=list)

    # -- the answers ------------------------------------------------------------------------------

    def take(self, value: Any, depth: int = 0) -> bool:
        """File one answer of the API; False when it is nothing this parser knows."""
        if depth > 4:
            return False
        if isinstance(value, list):
            taken = [self.take(item, depth + 1) for item in value]
            return bool(taken) and all(taken)
        if not isinstance(value, dict):
            return False
        if isinstance(value.get("rules"), list):
            self.rule_answers += 1
            for rule in value["rules"]:
                if not isinstance(rule, dict):
                    raise ParseError("an item of a list of rules is not a rule (not a JSON object)")
                self.rules.append(rule)
            return True
        if isinstance(value.get("objects"), list):
            known = True
            for item in value["objects"]:
                if isinstance(item, str):
                    self.listed.add(item)
                else:
                    known = self.take(item, depth + 1) and known
            return known
        name = value.get("name")
        if not isinstance(name, str) or not name:
            return False
        if "entries" in value:
            if name in self.services:
                raise ParseError(f"service object '{_short(name)}' is in the input twice")
            self.services[name] = value
            return True
        if "included" in value or "excluded" in value:
            if name in self.nets:
                raise ParseError(f"network object '{_short(name)}' is in the input twice")
            self.nets[name] = _Net(name, value)
            return True
        if "action" in value and ("source" in value or "destination" in value):
            self.rules.append(value)
            return True
        return False

    # -- network objects --------------------------------------------------------------------------

    def leaves(self, name: str, depth: int = 0) -> Optional[List[_Leaf]]:
        """The addresses of a network object, references followed and exclusions subtracted; None when unusable."""
        net = self.nets.get(name)
        if net is None:
            self.missing.add(name)
            return None
        if net.leaves is not None or net.problem:
            return net.leaves
        if depth > _MAX_NESTING or name in self.resolving:
            net.problem = "network objects that refer to each other in a circle, or nested more than 64 deep"
            return None
        self.resolving.add(name)
        try:
            out, problem = self._read_net(net, depth)
        finally:
            self.resolving.discard(name)
        if problem:
            net.problem = problem
            return None
        self.leaves_read += len(out)
        if self.leaves_read > _MAX_LEAVES:
            raise ParseError(f"the network objects of the input hold more than {_MAX_LEAVES} addresses in all: refusing to read on")
        net.leaves = out
        return out

    def _read_net(self, net: _Net, depth: int) -> Tuple[List[_Leaf], str]:
        raw = net.raw
        kind = str(raw.get("type", "")).lower()
        if any(word in kind for word in ("geo", "wildcard", "external", "pool", "dynamic", "mac")):
            return [], f"a network object of type '{_short(str(raw.get('type')), 30)}', which is not read"
        out: List[_Leaf] = []
        included = raw.get("included", [])
        excluded = raw.get("excluded", [])
        if not isinstance(included, list) or not isinstance(excluded, list):
            return [], "its included or excluded entries are not a list"
        for item in included:
            if not isinstance(item, dict):
                return [], "an included entry that is not a JSON object"
            if "references" in item:
                target = item["references"]
                if not isinstance(target, str) or not target:
                    return [], "a reference that names no object"
                if target == "Any" and target not in self.nets:
                    out.append(_Leaf(FULL_V4, "", ""))
                    out.append(_Leaf(FULL_V6, "", ""))
                    continue
                inner = self.leaves(target, depth + 1)
                if inner is None:
                    if target not in self.nets:
                        return [], f"it refers to '{_short(target)}', which is not in the input"
                    return [], f"it refers to '{_short(target)}', which cannot be read"
                out += inner
                continue
            entry = item.get("entry")
            if not isinstance(entry, dict):
                return [], "an included entry with neither an address nor a reference"
            leaf, problem = self._entry(entry)
            if problem:
                return [], problem
            assert leaf is not None
            out.append(leaf)
        removed: List[Interval] = []
        for item in excluded:
            entry = item.get("entry") if isinstance(item, dict) else None
            if not isinstance(entry, dict):
                return [], "an excluded entry that is not an address (an exclusion cannot refer to an object)"
            leaf, problem = self._entry(entry)
            if problem or leaf is None or leaf.interval is None:
                return [], problem or "an excluded entry that is not an address"
            removed.append(leaf.interval)
        if removed:
            if any(leaf.interval is None for leaf in out):
                return [], "it excludes addresses from a host name, whose addresses are not known"
            kept: List[_Leaf] = []
            for leaf in out:
                assert leaf.interval is not None
                kept += [_Leaf(left, "", leaf.interface) for left in subtract([leaf.interval], removed)]
            out = kept
        if not out:
            return [], "a network object without addresses" if not removed else "its exclusions leave no address"
        return out, ""

    def _entry(self, entry: Dict[str, Any]) -> Tuple[Optional[_Leaf], str]:
        for key, value in entry.items():
            if key in ("ip", "interface", "comment"):
                continue
            if key == "mac" and value in (None, "", "00:00:00:00:00:00"):
                continue
            if value in (None, "", [], {}, False):
                continue
            return None, f"an entry with '{_short(key, 20)}', which this parser does not read"
        ip = entry.get("ip")
        if not isinstance(ip, str) or not ip.strip():
            return None, "an entry without an address"
        interface = entry.get("interface", "")
        if interface is None:
            interface = ""
        if not isinstance(interface, str):
            return None, "an entry whose interface is not a name"
        if interface.lower() in ("any", "*"):
            interface = ""
        interval = parse_literal(ip)
        if interval is not None:
            return _Leaf(interval, "", interface), ""
        if _HOST.fullmatch(ip.strip()) and re.search(r"[A-Za-z]", ip):
            return _Leaf(None, ip.strip(), interface), ""
        return None, f"address '{_short(ip, 40)}' that could not be read"

    def build_objects(self) -> None:
        """Network objects as the model has them: addresses and host names, without the interfaces of entries."""
        for name in sorted(self.nets, key=str.lower):
            found = self.leaves(name)
            net = self.nets[name]
            comment = str(net.raw.get("comment") or "")
            if found is None:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, "", description=comment, raw=net.problem)
                continue
            members = self._members(found)
            if len(members) == 1 and members[0] not in self.p.addresses:
                interval = parse_literal(members[0])
                assert interval is not None
                kind = AddressKind.NETWORK if interval_text(interval) == members[0] and "-" not in members[0] else AddressKind.RANGE
                self.p.addresses[name] = Address(name, kind, members[0], description=comment)
            else:
                self.p.address_groups[name] = AddressGroup(name, members, description=comment)

    def _members(self, found: List[_Leaf], family: int = 0) -> List[str]:
        out: List[str] = []
        for leaf in found:
            if leaf.interval is not None:
                if family and leaf.interval[0] != family:
                    continue
                out.append(interval_text(leaf.interval))
            else:
                label = f"{leaf.host} (IPv{family})" if family else leaf.host
                if label not in self.p.addresses:
                    self.p.addresses[label] = Address(label, AddressKind.FQDN, leaf.host, fqdn_family=family)
                out.append(label)
        return list(dict.fromkeys(out))

    # -- services ---------------------------------------------------------------------------------

    def build_services(self) -> None:
        for name in sorted(self.services, key=str.lower):
            raw = self.services[name]
            comment = str(raw.get("comment") or "")
            entries_raw = raw.get("entries")
            if not isinstance(entries_raw, list) or not entries_raw:
                self.p.services[name] = Service(name, [], description=comment, unsupported="a service object without entries")
                continue
            refs: List[str] = []
            entries: List[ServiceEntry] = []
            problem = ""
            for item in entries_raw:
                if isinstance(item, dict) and "references" in item:
                    target = item["references"]
                    if not isinstance(target, str) or not target:
                        problem = "a reference that names no service object"
                        break
                    refs.append(target)
                    continue
                entry = item.get("entry", item) if isinstance(item, dict) else None
                if not isinstance(entry, dict):
                    problem = "an entry that is not a JSON object"
                    break
                found, problem = self._service_entry(name, entry)
                if problem:
                    break
                entries.append(found)  # type: ignore[arg-type]
            if problem:
                self.p.services[name] = Service(name, [], description=comment, unsupported=problem)
            elif refs:
                members = list(refs)
                if entries:
                    own = f"{name} entries"
                    self.p.services[own] = Service(own, entries)
                    members.append(own)
                self.p.service_groups[name] = ServiceGroup(name, members, description=comment)
            else:
                self.p.services[name] = Service(name, entries, description=comment)
        for name in self.services:
            self._service_state(name, set())

    def _service_state(self, name: str, seen: Set[str]) -> None:
        """Whether a service object refers to one that is not in the input, and whether it limits ICMP."""
        if name in seen or name in self.checked:
            return
        self.checked.add(name)
        group = self.p.service_groups.get(name)
        if group is None:
            if name in self.icmp_limits:
                self.limited.add(name)
            return
        for member in group.members:
            if member not in self.services and member not in self.p.services:
                self.missing.add(member)
                self.bad_services[name] = f"refers to '{_short(member)}', which is not in the input"
                continue
            self._service_state(member, seen | {name})
            if member in self.bad_services:
                self.bad_services.setdefault(name, f"refers to '{_short(member)}', which {self.bad_services[member]}")
            if member in self.limited:
                self.limited.add(name)

    def _service_entry(self, owner: str, entry: Dict[str, Any]) -> Tuple[Optional[ServiceEntry], str]:
        for key, value in entry.items():
            if key not in _ENTRY_KEYS and value not in (None, "", [], {}, False, 0):
                return None, f"an entry with '{_short(key, 20)}', which this parser does not read"
        number = _protocol(entry.get("protocol"))
        if number is None:
            return None, f"protocol '{_short(str(entry.get('protocol')), 20)}' that could not be read"
        name = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}.get(number, "other")
        for other in _SUBOBJECTS:
            if other != name and entry.get(other) not in (None, {}, "", False):
                return None, f"settings of '{other}' in an entry of protocol {number}"
        inner = entry.get(name, {})
        if inner in (None, "", False):
            inner = {}
        if not isinstance(inner, dict):
            return None, f"settings of '{name}' that are not a JSON object"
        merged: Dict[str, Any] = {}
        for key, value in inner.items():
            if key not in _ENTRY_KEYS or key in _SUBOBJECTS:
                if value not in (None, "", [], {}, False, 0):
                    return None, f"an entry with '{_short(key, 20)}' in its settings, which this parser does not read"
                continue
            merged[key] = value
        for key, value in entry.items():
            if key in _SUBOBJECTS:
                continue
            if key in merged and value is None:
                continue
            if key in merged and merged[key] is not None and merged[key] != value:
                return None, f"two values of '{_short(key, 20)}' in one entry"
            merged[key] = value
        entry = merged
        if number in (6, 17):
            ports_raw = entry.get("ports", entry.get("portRange"))
            ports = _ports(ports_raw)
            if ports is None:
                return None, f"ports '{_short(json.dumps(ports_raw), 40)}' that could not be read"
            client_raw = entry.get("clientPortUsed")
            client = _client_ports(client_raw)
            if client is None:
                return None, f"client ports '{_short(json.dumps(client_raw), 40)}' that could not be read"
            return ServiceEntry(Protocol.TCP if number == 6 else Protocol.UDP, ports, client), ""
        if number in (1, 58):
            limits = [key for key in ("maxPingSize", "minDelay") if entry.get(key) not in (None, 0, "0", "")]
            if limits and owner not in self.icmp_limits:
                self.icmp_limits.append(owner)
            return ServiceEntry(Protocol.ICMP if number == 1 else Protocol.ICMP6), ""
        if number == 0:
            return None, "IP protocol 0"
        return ServiceEntry(Protocol.IP, ip_protocol=number), ""

    # -- rules ------------------------------------------------------------------------------------

    def build_rules(self) -> None:
        names: List[str] = []
        for raw in self.rules:
            name = raw.get("name")
            if not isinstance(name, str) or not name:
                raise ParseError("a rule without a name")
            if name in self.taken:
                raise ParseError(f"rule '{_short(name)}' is in the input twice")
            self.taken.add(name)
            names.append(name)
        for name, raw in zip(names, self.rules):
            self._rule(name, raw)

    def _rule(self, name: str, raw: Dict[str, Any]) -> None:
        problems: List[str] = []
        for key, value in raw.items():
            if key not in _RULE_KEYS and value not in (None, "", [], {}, False):
                problems.append(f"attribute '{_short(key, 30)}', which this parser does not read")
        state = raw.get("deactivated")
        if isinstance(state, str) and state.lower() in ("true", "false"):
            state = state.lower() == "true"
        if not isinstance(state, bool):
            problems.append("the input does not say whether the rule is active")
            state = False
        enabled = not state
        family = {"ipv4": 4, "ipv6": 6}.get(str(raw.get("ipVersion", "")).lower())
        if family is None:
            problems.append(f"IP version '{_short(str(raw.get('ipVersion')), 20)}', which this parser does not know")
        action, why = _action(raw.get("action"), self, name)
        if why:
            problems.append(why)
        services = self._refs(raw, "service", problems)
        self.empty = ""
        self.dst_interfaces = False
        sources = self._side(raw, "source", family or 0, problems, with_interfaces=True)
        destinations = self._side(raw, "destination", family or 0, problems, with_interfaces=False)
        both = raw.get("bidirectional", False)
        if isinstance(both, str) and both.lower() in ("true", "false"):
            both = both.lower() == "true"
        if not isinstance(both, bool):
            problems.append("the input does not say plainly whether the rule is bi-directional")
            both = False
        bidirectional = both
        if self.empty and not problems:
            self.report.skip("rule", name, "RULE_MATCHES_NOTHING", f"{self.empty}: the rule matches nothing and is left out",
                             Severity.INFO)  # fmt: skip
            return
        groups = sources if sources else [(ANY, [ANY_V4 if family == 4 else ANY_V6 if family == 6 else ANY])]
        if bidirectional and (len(groups) > 1 or groups[0][0] != ANY or self.dst_interfaces):
            problems.append("a bi-directional rule whose source or destination names interfaces: what the firewall does the "
                            "other way round is not known")  # fmt: skip
            groups = [(ANY, groups[0][1])]
        expires = raw.get("expiresIn")
        if expires not in (None, "", 0, False):
            if action == Action.ALLOW:
                problems.append("an allowing rule that expires: converted, it would allow for good")
            else:
                self.report.add("rule", name, Severity.APPROX, "RULE_EXPIRES",
                                "a rule that expires: converted, it blocks for good")  # fmt: skip
        dst = destinations[0][1] if destinations else [ANY_V4 if family == 4 else ANY_V6 if family == 6 else ANY]
        comment = str(raw.get("comment") or "")
        policies = raw.get("policies")
        profiles: Dict[str, str] = {}
        schedule = ""
        users: List[str] = [ANY]
        if isinstance(policies, dict):
            schedule, users = self._policies(policies, profiles, problems)
        elif policies not in (None, {}, ""):
            problems.append("its policies are not a JSON object")
        made: List[Rule] = []
        for zone, members in groups:
            label = name if len(groups) == 1 else self._label(f"{name} ({zone if zone != ANY else 'any interface'})")
            made.append(self._make(label, action, enabled, [zone], members, dst, services, comment, problems, profiles, schedule, users))
            if zone != ANY:
                self.zones.add(zone)
        if len(groups) > 1:
            for rule in made:
                self.report.add("rule", rule.origin, Severity.INFO, "INTERFACE_SPLIT",
                                f"the source of rule '{name}' holds entries of {len(groups)} interfaces: it is read as one rule "
                                "per interface")  # fmt: skip
        if bidirectional:
            back = self._make(self._label(f"{name} (back)"), action, enabled, [ANY], dst, groups[0][1], services, comment, problems, profiles,
                              schedule, users)  # fmt: skip
            for rule in (made[0], back):
                self.report.add("rule", rule.origin, Severity.INFO, "BIDIRECTIONAL_SPLIT",
                                f"rule '{name}' is bi-directional: it is read as two rules, the second one with source and "
                                "destination swapped")  # fmt: skip
        if raw.get("dynamic") not in (None, False):
            for rule in made:
                self.report.add("rule", rule.origin, Severity.APPROX if action == Action.ALLOW and enabled else Severity.INFO,
                                "DYNAMIC_RULE", "a dynamic rule, which the firewall switches on and off at run time: read as it "
                                "stood when the input was saved")  # fmt: skip
        for rule in made + ([back] if bidirectional else []):
            for service in self.limited_rules:
                self.report.add("rule", rule.origin, Severity.APPROX, "ICMP_LIMITS",
                                f"service '{service}' limits the size or rate of ICMP echo requests; the limits are not "
                                "converted")  # fmt: skip
        self.limited_rules = []

    def _label(self, label: str) -> str:
        """A name for a rule FWShift makes, unique against the names of the input and those made before."""
        candidate, counter = label, 2
        while candidate in self.taken:
            candidate = f"{label} {counter}"
            counter += 1
        self.taken.add(candidate)
        return candidate

    def _make(self, label: str, action: Action, enabled: bool, zones: List[str], sources: List[str], destinations: List[str],
              services: List[str], comment: str, problems: List[str], profiles: Dict[str, str], schedule: str,
              users: List[str]) -> Rule:  # fmt: skip
        rule = Rule(name=label, origin=label, action=action, enabled=enabled, description=comment)
        rule.src_zones, rule.sources, rule.destinations, rule.services = list(zones), list(sources), list(destinations), list(services)
        rule.unsupported = list(dict.fromkeys(problems))
        rule.profiles = dict(profiles)
        rule.schedule = schedule
        rule.users = list(users)
        self.p.rules.append(rule)
        return rule

    def _policies(self, policies: Dict[str, Any], profiles: Dict[str, str], problems: List[str]) -> Tuple[str, List[str]]:
        schedule, users = "", [ANY]
        for key, value in policies.items():
            if key == "application":
                if isinstance(value, dict):
                    on = sorted(k for k, v in value.items() if v is True)
                    if on:
                        profiles["application"] = ", ".join(on)
                elif value not in (None, "", {}):
                    problems.append("an application policy this parser does not read")
            elif key == "ips":
                if isinstance(value, str) and value and value.lower() != "none":
                    profiles["ips"] = value
            elif key in ("qos", "trafficShaping", "shaping"):
                continue
            elif key == "schedule":
                kind = value.get("type") if isinstance(value, dict) else value
                if kind not in (None, "", "always", "Always"):
                    schedule = _short(json.dumps(value) if not isinstance(value, str) else value, 60)
            elif key in ("user", "users"):
                if value in (None, "", [], {}):
                    continue
                found = value.get("references") if isinstance(value, dict) and set(value) == {"references"} else value
                found = found if isinstance(found, list) else [found]
                if not all(isinstance(item, str) and item for item in found):
                    problems.append("a user condition this parser does not read")
                    continue
                named = [item for item in found if item != "Any"]
                if named:
                    users = named
            elif value not in (None, "", [], {}, False):
                problems.append(f"policy '{_short(key, 30)}', which this parser does not read")
        return schedule, users

    def _refs(self, raw: Dict[str, Any], key: str, problems: List[str]) -> List[str]:
        """The names a field of a rule refers to; ["any"] for the object Any."""
        side = raw.get(key)
        if not isinstance(side, dict) or "references" not in side:
            problems.append(f"its {key} is not a reference to an object (explicit entries are not read)" if isinstance(side, dict)
                            else f"the rule names no {key}")  # fmt: skip
            return [ANY]
        others = [k for k, v in side.items() if k != "references" and v not in (None, "", [], {}, False)]
        if others:
            problems.append(f"its {key} holds '{_short(others[0], 30)}', which this parser does not read")
        found = side["references"]
        names = found if isinstance(found, list) else [found]
        if not names or not all(isinstance(item, str) and item for item in names):
            problems.append(f"its {key} refers to no object")
            return [ANY]
        out: List[str] = []
        for item in names:
            if item == "Any" and item not in (self.services if key == "service" else self.nets):
                return [ANY]
            if key == "service":
                if item not in self.services:
                    self.missing.add(item)
                    problems.append(f"service object '{_short(item)}' is not in the input")
                    continue
                if item in self.bad_services:
                    problems.append(f"service object '{_short(item)}' {self.bad_services[item]}")
                if item in self.limited and item not in self.limited_rules:
                    self.limited_rules.append(item)
            out.append(item)
        return out or [ANY]

    def _side(self, raw: Dict[str, Any], key: str, family: int, problems: List[str],
              with_interfaces: bool) -> List[Tuple[str, List[str]]]:  # fmt: skip
        """The members of a source or destination, by interface: [(zone, members)]."""
        anyway = [ANY_V4] if family == 4 else [ANY_V6] if family == 6 else [ANY]
        names = self._refs(raw, key, problems)
        if names == [ANY]:
            return [(ANY, anyway)]
        by_interface: Dict[str, List[str]] = {}
        failed = False
        for name in names:
            found = self.leaves(name)
            if found is None:
                problems.append(f"network object '{_short(name)}' " + (f"cannot be read: {self.nets[name].problem}" if name in self.nets
                                                                         else "is not in the input"))  # fmt: skip
                failed = True
                continue
            interfaces = list(dict.fromkeys(leaf.interface for leaf in found))
            if not with_interfaces:
                self.dst_interfaces = self.dst_interfaces or any(interfaces)
                interfaces = [""]
            for interface in interfaces:
                mine = [leaf for leaf in found if not with_interfaces or leaf.interface == interface]
                filtered = bool(family) and any(leaf.interval is None or leaf.interval[0] != family for leaf in mine)
                if interfaces == [""] and not filtered:
                    by_interface.setdefault("", []).append(name)
                    continue
                whole = not with_interfaces or interfaces == [""]
                member = self._derived(name, None if whole else interface, family if filtered else 0, mine)
                if member:
                    by_interface.setdefault(interface, []).append(member)
        if not by_interface:
            if not failed:
                self.empty = f"its {key} holds no address of IPv{family}, the version of the rule"
            return [(ANY, anyway)]
        return [(interface or ANY, list(dict.fromkeys(members))) for interface, members in by_interface.items()]

    def _derived(self, name: str, interface: Optional[str], family: int, leaves: List[_Leaf]) -> str:
        """A group of the addresses of a network object at one interface (None: at any), or of one IP version: made once,
        used by name."""
        key = (name, "*" if interface is None else interface, family)
        if key in self.derived:
            return self.derived[key]
        members = self._members(leaves, family)
        if not members:
            self.derived[key] = ""
            return ""
        where = "" if interface is None else interface or "no interface"
        label = f"{name} ({', '.join(part for part in (where, f'IPv{family}' if family else '') if part)})"
        candidate, counter = label, 2
        while candidate in self.nets or candidate in self.p.addresses or candidate in self.p.address_groups:
            candidate = f"{label} {counter}"
            counter += 1
        what = ("" if interface is None else f"at interface {interface}" if interface else "in entries without an interface")
        what += (" and " if what and family else "") + (f"of IPv{family}" if family else "")
        self.p.address_groups[candidate] = AddressGroup(candidate, members, description=f"the addresses of '{name}' {what}")
        self.derived[key] = candidate
        return candidate


def _action(raw: Any, reader: _Reader, rule: str) -> Tuple[Action, str]:
    if not isinstance(raw, dict) or not isinstance(raw.get("type"), str):
        return Action.DROP, "the rule has no action this parser can read"
    kind = re.sub(r"[^a-z]", "", raw["type"].lower())
    others = {k: v for k, v in raw.items() if k not in ("type", "connection") and v not in (None, "", [], {}, False)}
    connection = raw.get("connection")
    if connection not in (None, "", {}):
        target = connection.get("references") if isinstance(connection, dict) else connection
        if not isinstance(target, str) or target.lower() not in _NO_TRANSLATION:
            reader.connections.append(rule)
    if kind == "pass":
        return Action.ALLOW, f"action setting '{_short(next(iter(others)), 30)}', which this parser does not read" if others else ""
    if kind == "block":
        return Action.DROP, ""
    if kind == "deny":
        return Action.RESET_CLIENT, ""
    if kind in ("dnat", "dstnat", "destinationnat"):
        return Action.ALLOW, "action Dst NAT: how the API spells its target list is not known, so the translation is not read"
    if kind == "map":
        return Action.ALLOW, "action Map: how the API spells its redirection is not known, so the translation is not read"
    if kind in ("appredirect", "redirect", "localredirect"):
        return Action.ALLOW, "action App Redirect: the traffic is handed to a service of the firewall itself"
    if kind in ("broadmulticast", "broadcast", "multicast"):
        return Action.ALLOW, "action Broad-Multicast, which forwards broadcasts between bridged networks"
    if kind in ("cascade", "cascadeback"):
        return Action.DROP, ("action Cascade: the rules of the rule list it hands traffic to are not read, and they decide "
                             "that traffic" if kind == "cascade" else "action Cascade Back")  # fmt: skip
    return Action.DROP, f"action '{_short(raw['type'], 20)}', which this parser does not know"


def _protocol(raw: Any) -> Optional[int]:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if 0 <= raw <= 255 else None
    if not isinstance(raw, str):
        return None
    text = raw.strip().lower()
    match = re.match(r"0*(\d{1,3})(\s|$)", text)
    if match:
        number = int(match.group(1))
        return number if number <= 255 else None
    return _PROTOCOLS.get(text)


def _ports(raw: Any) -> Optional[str]:
    """Destination ports as the model writes them ("" for every port); None when they cannot be read."""
    if isinstance(raw, int) and not isinstance(raw, bool):
        raw = [raw]
    if isinstance(raw, str):
        raw = raw.replace(",", " ").split()
    if not isinstance(raw, list) or not raw:
        return None
    parts: List[Tuple[int, int]] = []
    for item in raw:
        text = str(item).strip() if isinstance(item, (str, int)) and not isinstance(item, bool) else ""
        if text in ("*", "any", "0-65535", "1-65535"):
            return ""
        match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", text)
        if not match:
            return None
        low, high = int(match.group(1)), int(match.group(2) or match.group(1))
        if low > high or high > 65535 or low == 0:
            return None
        parts.append((low, high))
    return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in sorted(set(parts)))


def _client_ports(raw: Any) -> Optional[str]:
    """Source ports ("" for any); None when they cannot be read."""
    if raw in (None, "", {}, [], False, "*", "any", "Any", "0-65535", "1-65535"):
        return ""
    if isinstance(raw, dict):
        if str(raw.get("type", "")).lower() in ("any", "all"):
            return ""
        low, high = raw.get("from"), raw.get("to")
        if isinstance(low, int) and isinstance(high, int) and 0 <= low <= high <= 65535:
            return "" if (low, high) in ((0, 65535), (1, 65535)) else (str(low) if low == high else f"{low}-{high}")
        return None
    return _ports(raw)


def _short(text: str, limit: int = 40) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def parse(data: bytes, report: Report) -> Policy:
    documents = _documents(data)
    if not documents:
        raise ParseError("the input is empty")
    policy = Policy(vendor="barracuda", scope="forwarding firewall")
    policy.default_interzone = Action.DENY
    policy.default_intrazone = Action.DENY
    reader = _Reader(report, policy)
    unknown = 0
    for document in documents:
        if reader.take(document):
            reader.answers += 1
        else:
            unknown += 1
    if not reader.rules and not reader.nets and not reader.services:
        raise ParseError("no rules and no objects of a CloudGen Firewall found; expected what its REST API answers to "
                         "GET /rest/config/v1/forwarding-firewall/rules?expand=true and to the objects it names")  # fmt: skip
    reader.build_services()
    reader.build_objects()
    reader.build_rules()
    for zone in sorted(reader.zones):
        policy.zones[zone] = Zone(zone, [zone])
    _notes(reader, unknown)
    return policy


def _notes(reader: _Reader, unknown: int) -> None:
    report = reader.report
    report.note(
        Severity.INFO, "BARRACUDA_FORMAT",
        f"read {len(reader.rules)} forwarding rules, {len(reader.nets)} network objects and {len(reader.services)} service objects "
        f"from {reader.answers} answers of the REST API. Barracuda documents that API by examples only: the keys read are "
        "those its examples and published tools show, and a key of a rule, an object or an entry this parser does not know "
        "makes it unusable",
    )  # fmt: skip
    if reader.rule_answers > 1:
        report.note(Severity.INFO, "RULES_JOINED",
                    f"the input holds {reader.rule_answers} lists of rules; they were read one after the other, in the order "
                    "of the input, as pages of one list")  # fmt: skip
    if not reader.rules:
        report.note(Severity.REVIEW, "NO_RULES", "the input holds no forwarding rule: save the answer of "
                    "GET /rest/config/v1/forwarding-firewall/rules?expand=true as well")  # fmt: skip
    if unknown:
        report.note(Severity.REVIEW, "ANSWERS_NOT_READ",
                    f"{unknown} of the JSON documents of the input are no rules and no objects this parser knows, and were "
                    "not read")  # fmt: skip
    if reader.missing:
        names = sorted(reader.missing, key=str.lower)
        report.note(Severity.REVIEW, "OBJECTS_MISSING",
                    "objects the rules name are not in the input, and the rules that name them are not used: "
                    + ", ".join(f"'{_short(n)}'" for n in names[:10]) + (f" and {len(names) - 10} more" if len(names) > 10 else "")
                    + ". Fetch each one (GET .../forwarding-firewall/objects/networks/<name>, .../objects/services/<name>) "
                    "and add the answers to the input")  # fmt: skip
    if reader.connections:
        report.note(Severity.REVIEW, "CONNECTION_NOT_READ",
                    "rules whose connection object translates the source address: "
                    + ", ".join(f"'{_short(n)}'" for n in reader.connections[:10])
                    + (f" and {len(reader.connections) - 10} more" if len(reader.connections) > 10 else "")
                    + ". Source NAT is not read; the rules are, as they match")  # fmt: skip
    if reader.icmp_limits:
        report.note(Severity.INFO, "ICMP_LIMITS",
                    "service objects that limit the size or rate of ICMP echo requests: "
                    + ", ".join(f"'{_short(n)}'" for n in reader.icmp_limits[:10])
                    + ". The limits are not converted: the rules allow ICMP of any size and rate")  # fmt: skip
