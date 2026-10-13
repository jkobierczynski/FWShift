# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""VMware NSX distributed firewall parser: Policy API JSON -> neutral model.

What is read: the answers of the NSX Policy API, in either form or mixed in one file: the hierarchical answer of
``GET /policy/api/v1/infra`` (``Infra`` with ``ChildDomain``, ``ChildGroup``, ``ChildSecurityPolicy``,
``ChildRule``, ``ChildService`` ...), and the list answers (``{"results": [...]}``) of
``/infra/domains/default/security-policies``, ``.../rules``, ``/groups``, ``/infra/services`` and
``/infra/segments``, alone or together in one JSON array. Objects are found by their ``resource_type`` wherever
they are, and joined by their paths.

How NSX behaviour is mapped onto the neutral model:

* The distributed firewall has no zones: every rule is from any zone to any zone. Where a rule is enforced
  (applied-to, ``scope``) is not where its traffic goes; an allow rule enforced at fewer workloads than its
  sources or destinations is not converted, a blocking one is converted for all and says so.
* Categories in their order (Emergency, Infrastructure, Environment, Application, then policies without one),
  policies by their sequence numbers, rules by theirs: one first-match list. The Ethernet category (layer 2) is
  reported, not converted.
* The default layer-3 rule at the end is the default action of the model.
* Groups of addresses (``IPAddressExpression``, groups by path, addresses written in a rule) are address groups;
  membership by tags, names or virtual machines needs the inventory of NSX and is kept as a dynamic group, which
  only an NSX target can write again. A segment stands for its subnet, which also holds addresses that are not
  members (the gateway): said in the report.
* A rule for one direction only (``IN`` or ``OUT``) is checked at one end of the connection; NSX checks the other
  end against the rules below it. An allow rule for one direction is not converted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    APP_DEFAULT,
    Action,
    AddressGroup,
    Policy,
    Protocol,
    Rule,
    Service,
    ServiceEntry,
    ServiceGroup,
)
from ..netutil import interval_text, parse_literal
from ..report import Report, Severity

CATEGORIES = ("Ethernet", "Emergency", "Infrastructure", "Environment", "Application", "")
_ACTIONS = {"ALLOW": Action.ALLOW, "DROP": Action.DROP, "REJECT": Action.DENY}
_ALG_PROTOCOLS = {"FTP": "tcp", "TFTP": "udp", "MS_RPC_TCP": "tcp", "MS_RPC_UDP": "udp", "ORACLE_TNS": "tcp",
                  "SUN_RPC_TCP": "tcp", "SUN_RPC_UDP": "udp", "NBNS_BROADCAST": "udp", "NBDG_BROADCAST": "udp"}  # fmt: skip
_SEP = "\x1f"  # between the names of the groups a rule is applied to
_OBJECT_TYPES = {"SecurityPolicy", "CommunicationMap", "Rule", "CommunicationEntry", "Group", "Service", "Segment",
                 "GatewayPolicy"}  # fmt: skip


@dataclass
class _Found:
    """The objects of an export, by their paths."""

    policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    rules: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)  # policy path -> its rules
    groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    services: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    segments: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    gateway_policies: int = 0
    gateway_rules: int = 0
    order: Dict[str, int] = field(default_factory=dict)  # path -> the order it was found in


def looks_like_nsx(data: bytes) -> bool:
    """JSON of the NSX Policy API: objects with a resource_type NSX gives."""
    head = data[:2_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    for marker in (b'"ChildSecurityPolicy"', b'"ChildDomain"', b'"SecurityPolicy"', b'"CommunicationMap"',
                   b'"IPAddressExpression"', b'"L4PortSetServiceEntry"'):  # fmt: skip
        if marker in head and b'"resource_type"' in head:
            return True
    return False


class _Collector:
    def __init__(self) -> None:
        self.found = _Found()
        self.counter = 0

    def note(self, path: str) -> None:
        if path not in self.found.order:
            self.found.order[path] = self.counter
            self.counter += 1

    def walk(self, node: Any, domain: str, policy: str) -> None:
        if isinstance(node, list):
            for item in node:
                self.walk(item, domain, policy)
            return
        if not isinstance(node, dict):
            return
        if node.get("marked_for_delete") is True:
            return
        kind = node.get("resource_type")
        if isinstance(kind, str) and kind.startswith("Child") and kind != "ChildResourceReference":
            inner = node.get(kind[5:])
            if inner is None and kind == "ChildServiceEntry":
                inner = node.get("Service")
            self.walk(inner, domain, policy)
            return
        if kind == "ChildResourceReference":
            if node.get("target_type") == "Domain":
                domain = str(node.get("id", domain))
            self.walk(node.get("children", []), domain, policy)
            return
        if kind == "Domain":
            self.walk(node.get("children", []), str(node.get("id", domain)), policy)
            return
        if kind in ("SecurityPolicy", "CommunicationMap"):
            path = str(node.get("path") or f"/infra/domains/{domain}/security-policies/{node.get('id', '')}")
            self.found.policies[path] = node
            self.note(path)
            self.found.rules.setdefault(path, [])
            for key in ("rules", "communication_entries"):
                items = node.get(key) or []
                for item in items if isinstance(items, list) else [items]:
                    if isinstance(item, dict) and "resource_type" not in item:
                        item = dict(item, resource_type="Rule")  # a rule by where it stands
                    self.walk(item, domain, path)
            self.walk(node.get("children", []), domain, path)
            return
        if kind in ("Rule", "CommunicationEntry"):
            parent = str(node.get("parent_path") or policy)
            if "/gateway-policies/" in parent:
                self.found.gateway_rules += 1  # (a rule of a gateway policy)
                return
            path = str(node.get("path") or f"{parent}/rules/{node.get('id', '')}")
            listed = self.found.rules.setdefault(parent, [])
            ident = node.get("path") or node.get("id")
            if ident is None or all((r.get("path") or r.get("id")) != ident for r in listed):
                listed.append(node)
            self.note(path)
            return
        if kind == "Group":
            path = str(node.get("path") or f"/infra/domains/{domain}/groups/{node.get('id', '')}")
            self.found.groups[path] = node
            self.note(path)
            return
        if kind == "Service":
            path = str(node.get("path") or f"/infra/services/{node.get('id', '')}")
            known = self.found.services.setdefault(path, dict(node))
            entries = list(known.get("service_entries") or [])
            for child in node.get("children", []) or []:
                if isinstance(child, dict) and isinstance(child.get("ServiceEntry") or child.get("Service"), dict):
                    if child.get("marked_for_delete") is not True:
                        entries.append(child.get("ServiceEntry") or child.get("Service"))
            known["service_entries"] = entries
            self.note(path)
            return
        if kind == "Segment":
            path = str(node.get("path") or f"/infra/segments/{node.get('id', '')}")
            self.found.segments[path] = node
            return
        if kind == "GatewayPolicy":
            self.found.gateway_policies += 1
            return
        for value in node.values():
            if isinstance(value, (dict, list)):
                self.walk(value, domain, policy)


def _list(value: Any) -> List[Any]:
    """A list as the API gives it; a single value where a list belongs is one element."""
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _sequence(node: Dict[str, Any]) -> int:
    """The number that orders a policy or a rule (``precedence`` in the communication maps of NSX-T 2.4)."""
    return _int(node.get("sequence_number", node.get("precedence")))


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _ports(values: Any) -> Optional[str]:
    """``["80", "1000-2000", "22, 33-70"]`` -> ``80,1000-2000,22,33-70``; "" for all; None if not readable."""
    if not values:
        return ""
    parts: List[str] = []
    for value in values if isinstance(values, list) else [values]:
        for part in str(value).replace(" ", "").split(","):
            if not part:
                continue
            first, _, last = part.partition("-")
            if not first.isdigit() or (last and not last.isdigit()):
                return None
            if int(first) > 65535 or int(last or first) > 65535 or int(last or first) < int(first):
                return None
            parts.append(part)
    return ",".join(parts)


def parse(data: bytes, report: Report) -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    try:
        collector = _Collector()
        collector.walk(document, "default", "")
        found = collector.found
        if not found.policies and not any(found.rules.values()):
            raise ParseError(
                "no security policies found; expected the answers of the NSX Policy API "
                "(GET /policy/api/v1/infra with a filter, or /infra/domains/default/security-policies with their rules)"
            )
        return _Builder(found, report).build()
    except RecursionError:
        raise ParseError("groups, services or JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None


class _Builder:
    def __init__(self, found: _Found, report: Report) -> None:
        self.found, self.report = found, report
        self.p = Policy(vendor="nsx")
        self.group_names: Dict[str, str] = {}  # path -> name
        self.service_names: Dict[str, str] = {}
        self.builtin_names: Dict[str, str] = {}  # path of a service of NSX itself -> its id
        self.taken: Set[str] = set()  # names of address objects and groups
        self.taken_services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.segment_groups: Set[str] = set()
        self.stateless: List[str] = []
        self.one_direction: List[str] = []
        self.one_end: List[Tuple[str, str]] = []
        self.equal_rules: List[str] = []
        self.jumped = ""  # a conditional jump to the application rules: what the environment rules below it say
        self.jumped_all = False

    # -- names --------------------------------------------------------------------

    @staticmethod
    def _unique(name: str, taken: Set[str]) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate)
        return candidate

    def _object_name(self, kind: str, label: str, taken: Set[str]) -> str:
        """A name for an object that cannot be mistaken for a word of the model ("any") or for an address."""
        if label.lower() in (ANY, APP_DEFAULT):
            new = self._unique(f"{label}-object", taken)
        elif kind == "address-group" and parse_literal(label) is not None:
            new = self._unique(f"{label} (object)", taken)
        else:
            return self._unique(label, taken)
        self.report.add(kind, new, Severity.INFO, "RENAMED", f"named '{label}' in the source, which the model reads as a word "
                        f"or an address of its own; renamed to '{new}'")  # fmt: skip
        return new

    # -- groups -------------------------------------------------------------------

    def group(self, path: str, stack: Tuple[str, ...] = ()) -> str:
        """The name of the address group a group path stands for (made on first use)."""
        if path in stack:
            self.p.address_groups[self.group_names[stack[-1]]].unsupported = "the group contains itself"
        if path in self.group_names:
            return self.group_names[path]
        node = self.found.groups.get(path)
        label = str((node or {}).get("display_name") or (node or {}).get("id") or path.rsplit("/", 1)[-1])
        name = self._object_name("address-group", label, self.taken)
        self.group_names[path] = name
        group = AddressGroup(name, description=str((node or {}).get("description", "")))
        self.p.address_groups[name] = group
        if node is None:
            group.unsupported = f"group {path} is not in the export"
            return name
        self.members(group, path, node, stack + (path,))
        return name

    def members(self, group: AddressGroup, path: str, node: Dict[str, Any], stack: Tuple[str, ...]) -> None:
        expressions = node.get("expression") or []
        if not isinstance(expressions, list):
            group.unsupported = "an expression that cannot be read"
            return
        dynamic: List[str] = []
        conjunctions = set()
        for expression in expressions:
            if not isinstance(expression, dict):
                group.unsupported = "an expression that cannot be read"
                return
            kind = expression.get("resource_type")
            if kind == "ConjunctionOperator":
                conjunctions.add(str(expression.get("conjunction_operator", "OR")).upper())
            elif kind == "IPAddressExpression":
                addresses = expression.get("ip_addresses") or []
                for text in addresses if isinstance(addresses, list) else [addresses]:
                    interval = parse_literal(str(text))
                    if interval is None:
                        group.unsupported = f"address '{str(text)[:60]}' cannot be read"
                        return
                    group.members.append(interval_text(interval))
            elif kind == "PathExpression":
                for member in _list(expression.get("paths")):
                    member = str(member)
                    if "/groups/" in member:
                        group.members.append(self.group(member, stack))
                    elif member in self.found.segments or "/segments/" in member:
                        networks = self.segment_networks(member)
                        if networks is None:
                            dynamic.append(f"segment {member}")
                        else:
                            group.members += networks
                            self.segment_groups.add(group.name)
                    else:
                        dynamic.append(f"member {member}")
            elif kind == "MACAddressExpression":
                dynamic.append("MAC addresses")
            elif kind in ("Condition", "NestedExpression", "ExternalIDExpression", "IdentityGroupExpression"):
                dynamic.append(_describe(expression))
            else:
                dynamic.append(f"expression {kind}")
        if node.get("extended_expression"):
            group.unsupported = "a match on identity groups (identity firewall), which the model has no place for"
            return
        if "AND" in conjunctions:
            if dynamic:
                group.dynamic_filter = "nsx:" + json.dumps(self._native(expressions), sort_keys=True)
                group.members = []
            else:
                group.unsupported = "address lists joined by AND, which the model has no place for"
            return
        if dynamic:
            # The members are known to NSX only (its inventory): what the group holds is not known here.
            group.dynamic_filter = "nsx:" + json.dumps(self._native(expressions), sort_keys=True)
            group.description = (group.description + " " if group.description else "") + "NSX membership: " + "; ".join(dynamic)[:300]
        group.members = transform.dedupe(group.members)

    def _native(self, expressions: List[Any]) -> List[Any]:
        """The expression as NSX has it, with the paths of other groups replaced by the names of their address groups
        here (``fwshift-group:NAME``): an NSX target writes those groups under the ids it gives them."""
        out: List[Any] = []
        for expression in expressions:
            if isinstance(expression, dict) and expression.get("resource_type") == "PathExpression":
                expression = dict(expression, paths=[f"fwshift-group:{self.group_names.get(str(p), str(p))}" if "/groups/" in str(p)
                                                     else p for p in expression.get("paths") or []])  # fmt: skip
            out.append(expression)
        return out

    def segment_networks(self, path: str) -> Optional[List[str]]:
        segment = self.found.segments.get(path)
        if segment is None:
            return None
        out: List[str] = []
        for subnet in segment.get("subnets") or []:
            if not isinstance(subnet, dict):
                return None
            text = str(subnet.get("network") or subnet.get("gateway_address") or "")
            interval = parse_literal(text)
            if interval is None:
                return None
            out.append(interval_text(interval))
        return out or None

    # -- services -----------------------------------------------------------------

    def service(self, path: str, stack: Tuple[str, ...] = ()) -> str:
        if path in self.service_names:
            return self.service_names[path]
        node = self.found.services.get(path)
        builtin = bool(node and (node.get("_system_owned") or node.get("is_default")))
        if builtin:
            name = self.builtin_names[path]  # (reserved under its id, by which a rule refers to it)
        else:
            label = path.rsplit("/", 1)[-1] if node is None else str(node.get("display_name") or node.get("id") or path.rsplit("/", 1)[-1])
            name = self._object_name("service", label, self.taken_services)
        self.service_names[path] = name
        if node is None:
            self.p.services[name] = Service(name, unsupported=f"service {path} is not in the export")
            return name
        nested: List[str] = []
        entries: List[ServiceEntry] = []
        problems: List[str] = []
        algs: List[str] = []
        for entry in node.get("service_entries") or []:
            if not isinstance(entry, dict):
                problems.append("an entry that cannot be read")
                continue
            kind = entry.get("resource_type")
            if kind == "NestedServiceServiceEntry":
                inner = str(entry.get("nested_service_path", ""))
                if inner in stack or inner == path:
                    problems.append("a service that contains itself")
                else:
                    nested.append(self.service(inner, stack + (path,)))
                continue
            converted = _entry(entry, problems, algs)
            if converted is not None:
                entries.append(converted)
        description = str(node.get("description", ""))
        if nested:
            group_members = list(nested)
            if entries or problems:
                own = self._unique(f"{name}.entries", self.taken_services)
                self.p.services[own] = Service(own, entries, unsupported="; ".join(problems))
                group_members.insert(0, own)
            self.p.service_groups[name] = ServiceGroup(name, group_members, description=description,
                                                       builtin="nsx" if builtin else "")  # fmt: skip
        else:
            if not entries and not problems:
                problems.append("a service without entries")
            self.p.services[name] = Service(name, entries, description=description, builtin="nsx" if builtin else "",
                                            unsupported="; ".join(problems))  # fmt: skip
        for alg in algs:
            self.report.add("service", name, Severity.APPROX, "ALG_SERVICE",
                            f"application level gateway {alg}: converted as its port. NSX also lets through the connections the "
                            "protocol opens (an FTP data connection, RPC ports); a target without such a helper does not")  # fmt: skip
        return name

    def inline_service(self, rule_name: str, entries_in: List[Any]) -> str:
        problems: List[str] = []
        algs: List[str] = []
        entries = []
        for entry in entries_in:
            converted = _entry(entry, problems, algs) if isinstance(entry, dict) else None
            if not isinstance(entry, dict):
                problems.append("an entry that cannot be read")
            elif entry.get("resource_type") == "NestedServiceServiceEntry":
                problems.append("a nested service in a rule")
            if converted is not None:
                entries.append(converted)
        name = self._unique(f"{rule_name}.services", self.taken_services)
        self.p.services[name] = Service(name, entries, unsupported="; ".join(problems))
        for alg in algs:
            self.report.add("service", name, Severity.APPROX, "ALG_SERVICE",
                            f"application level gateway {alg}: converted as its port; NSX also lets through the connections "
                            "the protocol opens")  # fmt: skip
        return name

    # -- the policy ---------------------------------------------------------------

    def build(self) -> Policy:
        for path, node in self.found.services.items():
            if node.get("_system_owned") or node.get("is_default"):
                # A service of NSX itself keeps its id: no service of the export takes it first.
                self.builtin_names[path] = self._unique(path.rsplit("/", 1)[-1], self.taken_services)
        ordered = sorted(
            self.found.policies.items(),
            # The default policy is at the end of its category whatever its number.
            key=lambda item: (self.category(item[1]), bool(item[1].get("is_default")), _sequence(item[1]),
                              self.found.order.get(item[0], 0)),
        )
        orphans = [path for path in self.found.rules if path not in self.found.policies and self.found.rules[path]]
        default_action: Optional[Action] = None
        defaults: List[Tuple[str, str, Action]] = []
        layer2 = [0, 0]  # rules, blocking rules
        seen_sequence: Dict[Tuple[int, int], List[str]] = {}
        for path, node in ordered:
            category = self.category(node)
            name = str(node.get("display_name") or node.get("id") or path)
            if CATEGORIES[category] == "Ethernet":
                rules = self.found.rules.get(path, [])
                layer2[0] += len(rules)
                layer2[1] += sum(1 for r in rules if str(r.get("action", "ALLOW")).upper() != "ALLOW" and not r.get("disabled"))
                continue
            if not node.get("is_default"):
                seen_sequence.setdefault((category, _sequence(node)), []).append(name)
            found_default = self.policy(path, node)
            if found_default is not None:
                defaults.append((path, name, found_default))
        if defaults:
            # The global default rule is in default-layer3-section; others (of a project or a VPC) apply to their own.
            chosen = next((d for d in defaults if d[0].endswith("/default-layer3-section")), defaults[0])
            default_action = chosen[2]
            if len(defaults) > 1:
                self.report.note(Severity.REVIEW, "DEFAULT_RULES",
                                 f"default rules in {len(defaults)} policies (" + ", ".join(d[1] for d in defaults) + f"); the one of "
                                 f"'{chosen[1]}' is the default action of the model, the others were not converted")  # fmt: skip
        for path in orphans:
            self.report.note(Severity.REVIEW, "RULES_WITHOUT_POLICY",  # (rules of gateway policies are counted apart)
                             f"{len(self.found.rules[path])} rules name the policy {path}, which is not in the export: not converted")  # fmt: skip
        self.p.default_interzone = self.p.default_intrazone = default_action or Action.DENY
        self.versions()
        self.applied_to()
        self.notes(default_action, layer2, seen_sequence)
        return self.p

    def category(self, node: Dict[str, Any]) -> int:
        value = str(node.get("category") or "")
        if value in CATEGORIES:
            return CATEGORIES.index(value)
        return len(CATEGORIES) - 1

    def policy(self, path: str, node: Dict[str, Any]) -> Optional[Action]:
        """Convert the rules of one policy; the action of the default layer-3 rule where this policy holds it."""
        label = str(node.get("display_name") or node.get("id") or path)
        rules = sorted(self.found.rules.get(path, []),
                       key=lambda r: (_sequence(r), self.found.order.get(str(r.get("path", "")), 0)))  # fmt: skip
        numbers = [_sequence(r) for r in rules]
        if len(set(numbers)) != len(numbers):
            self.equal_rules.append(label)
        scope = [str(s) for s in _list(node.get("scope")) if str(s).upper() != "ANY"]
        if node.get("stateful") is False:
            self.stateless.append(label)
        environment = str(node.get("category") or "") == "Environment"
        if environment and self.jumped_all:
            return None  # every packet left the environment category before this policy
        uncategorised = str(node.get("category") or "") not in CATEGORIES[:-1]
        default: Optional[Action] = None
        for index, raw in enumerate(rules):
            is_default = bool(node.get("is_default")) and (bool(raw.get("is_default")) or index == len(rules) - 1)
            if is_default and _any_any(raw) and str(raw.get("action", "ALLOW")).upper() in _ACTIONS:
                default = _ACTIONS[str(raw.get("action", "ALLOW")).upper()]
                continue
            rule = self.rule(raw, label, scope, node)
            if rule is None:
                continue
            if environment and self.jumped:
                rule.unsupported.append(self.jumped)
            if uncategorised and rule.action == Action.ALLOW:
                rule.unsupported.append("a policy without a category: whether NSX reaches it before its default rule is not "
                                        "documented")  # fmt: skip
            if str(raw.get("action", "")).upper() == "JUMP_TO_APPLICATION":
                if not environment:
                    rule.unsupported.append("jump to the application rules outside the environment category")
                    rule.action = Action.DROP
                    self.p.rules.append(rule)
                    continue
                unscoped = not scope and not [x for x in _list(raw.get("scope")) if str(x).upper() != "ANY"]
                if _any_any(raw) and unscoped and not raw.get("disabled") and not self.jumped:
                    self.jumped_all = True
                    break  # every packet jumps: the rest of the environment rules, in every policy, is never reached
                if not raw.get("disabled"):
                    self.jumped = self.jumped or (f"follows a conditional jump to the application rules (rule '{rule.name}'), "
                                                  "which cannot be expressed")  # fmt: skip
                continue
            self.p.rules.append(rule)
        preference = str(node.get("connectivity_preference") or node.get("connectivity_strategy") or "").upper()
        if preference.startswith(("ALLOWLIST", "WHITELIST", "DENYLIST", "BLACKLIST")) and scope:
            drop = preference.startswith(("ALLOWLIST", "WHITELIST"))
            for side in ("source", "destination"):
                rule = Rule(name=self._unique(f"{label}-default-{side}", self.rule_names))
                rule.origin = rule.name
                rule.description = f"the rule NSX adds at the end of policy '{label}' ({preference.lower()}), for traffic whose {side} is in its applied-to"
                members = [self.group(s) for s in scope]
                if side == "source":
                    rule.sources = members
                else:
                    rule.destinations = members
                rule.action = Action.DROP if drop else Action.ALLOW
                rule.log_end = "LOGGING" in preference
                if not drop:
                    rule.unsupported.append("the allow rule NSX adds at the end of a deny-list policy, for its applied-to only")
                self.p.rules.append(rule)
        return default

    def rule(self, raw: Dict[str, Any], policy: str, policy_scope: List[str], node: Dict[str, Any]) -> Optional[Rule]:
        label = str(raw.get("display_name") or raw.get("id") or "rule")
        rule = Rule(name=self._unique(label, self.rule_names))
        rule.origin = rule.name
        rule.description = str(raw.get("description") or raw.get("notes") or "")
        rule.source_ids = {k: str(v) for k, v in (("nsx.rule_id", raw.get("rule_id")), ("nsx.path", raw.get("path")),
                                                  ("nsx.policy", policy)) if v not in (None, "")}  # fmt: skip
        if raw.get("tag"):
            rule.source_ids["nsx.tag"] = str(raw.get("tag"))
        rule.enabled = not bool(raw.get("disabled"))
        rule.log_start = rule.log_end = bool(raw.get("logged"))
        action = str(raw.get("action") or "").upper()
        rule.action = _ACTIONS.get(action, Action.DROP)
        if action not in _ACTIONS and action != "JUMP_TO_APPLICATION":
            rule.unsupported.append(f"action {action}" if action else "no action in the export")
        for key in ("source_groups", "destination_groups"):
            if key not in raw:
                rule.unsupported.append(f"no {key} in the export (an export with included_fields?)")
        if "services" not in raw and "service_entries" not in raw:
            rule.unsupported.append("no services in the export (an export with included_fields?)")
        rule.sources, rule.negate_source = self.side(raw.get("source_groups"), rule.unsupported), bool(raw.get("sources_excluded"))
        rule.destinations = self.side(raw.get("destination_groups"), rule.unsupported)
        rule.negate_destination = bool(raw.get("destinations_excluded"))
        if rule.negate_source and rule.sources == [ANY]:
            rule.unsupported.append("excluded sources that are any")
        if rule.negate_destination and rule.destinations == [ANY]:
            rule.unsupported.append("excluded destinations that are any")
        services: List[str] = []
        listed = [str(s) for s in _list(raw.get("services"))]
        if any(s.upper() == "ANY" for s in listed):
            services = [ANY]
        else:
            services = [self.service(s) for s in listed]
            if raw.get("service_entries"):
                services.append(self.inline_service(rule.name, list(raw.get("service_entries") or [])))
        rule.services = services or [ANY]
        profiles = [str(p) for p in _list(raw.get("profiles")) if str(p).upper() != "ANY"]
        if profiles:
            rule.unsupported.append("context profile " + ", ".join(p.rsplit("/", 1)[-1] for p in profiles)
                                    + " (layer 7: applications, domain names), which the model has no place for")  # fmt: skip
        direction = str(raw.get("direction") or "IN_OUT").upper()
        if direction in ("IN", "OUT"):
            if rule.action == Action.ALLOW:
                rule.unsupported.append(f"direction {direction} only: NSX checks the other end of the connection against the "
                                        "rules below it, which one rule cannot say")  # fmt: skip
            else:
                self.one_direction.append(rule.origin)
        elif direction != "IN_OUT":
            rule.unsupported.append(f"direction {direction}")
        family = str(raw.get("ip_protocol") or "IPV4_IPV6").upper()
        if family in ("IPV4", "IPV6"):
            rule.handling["nsx.ip_protocol"] = family
        scope = policy_scope or [str(s) for s in _list(raw.get("scope")) if str(s).upper() != "ANY"]
        if scope:
            names = [self.group(s) for s in scope]
            rule.handling["nsx.applied_to"] = _SEP.join(names)
        if node.get("scheduler_path"):
            rule.schedule = str(node.get("scheduler_path")).rsplit("/", 1)[-1]
        return rule

    def side(self, values: Any, problems: List[str]) -> List[str]:
        items = [str(v) for v in _list(values)]
        if not items or any(v.upper() == "ANY" for v in items):
            return [ANY]
        out: List[str] = []
        for item in items:
            if item.startswith("/"):
                out.append(self.group(item))
                continue
            interval = parse_literal(item)
            if interval is None:
                problems.append(f"address '{item[:60]}' cannot be read")
                continue
            out.append(interval_text(interval))
        return out or [ANY]

    # -- after the rules ------------------------------------------------------------

    def versions(self) -> None:
        """A rule for one IP version: an "any" on one side keeps it to that version, or the members of both versions
        are written as their addresses of this one."""
        nothing: List[str] = []
        for rule in list(self.p.rules):
            family = rule.handling.get("nsx.ip_protocol", "")
            if not family:
                continue
            version = 4 if family == "IPV4" else 6
            any_version = ANY_V4 if version == 4 else ANY_V6
            members_all = [m for m in rule.sources + rule.destinations if m != ANY]
            if any(not transform.known_intervals(self.p, m)[1] for m in members_all):
                # A group NSX fills itself: its rules reach no other target; an NSX target writes the version back.
                continue
            rule.handling.pop("nsx.ip_protocol")
            if rule.sources == [ANY] and not rule.negate_source:
                rule.sources = [any_version]
                continue
            if rule.destinations == [ANY] and not rule.negate_destination:
                rule.destinations = [any_version]
                continue
            pinned = False  # a side of addresses of this version only keeps the rule to it
            for side in ("sources", "destinations"):
                members: List[str] = getattr(rule, side)
                negated = rule.negate_source if side == "sources" else rule.negate_destination
                if ANY in members:
                    continue
                if all(transform.families(self.p, m) <= {version} for m in members):
                    pinned = pinned or not negated
                    continue
                literals: List[str] = []
                known = True
                for member in members:
                    if transform.families(self.p, member) <= {version}:
                        literals.append(member)
                        continue
                    intervals, member_known = transform.known_intervals(self.p, member)
                    known = known and member_known
                    literals += [interval_text(i) for i in intervals if i[0] == version]
                if not known:
                    continue  # (an unknown member makes the rule unsupported anyway)
                if not literals and not negated:
                    nothing.append(rule.name)
                    break
                setattr(rule, side, literals or [any_version])
                if not literals:
                    setattr(rule, "negate_source" if side == "sources" else "negate_destination", False)
                    # "not any address of the other version": every address of this one
                pinned = pinned or not negated or not literals
            else:
                if not pinned:
                    rule.unsupported.append(f"a rule for {family} only, with excluded addresses on both sides")
                continue
            self.p.rules.remove(rule)
        if nothing:
            self.report.note(Severity.INFO, "RULE_WITHOUT_EFFECT",
                             f"rules for one IP version whose sources or destinations hold no address of it match nothing and "
                             f"were left out: {', '.join(nothing)}")  # fmt: skip

    def applied_to(self) -> None:
        """A rule enforced at fewer workloads than its traffic: where the source or the destination lies within the
        applied-to, nothing is lost."""
        for rule in self.p.rules:
            names = rule.handling.get("nsx.applied_to", "")
            if not names:
                continue
            listed = names.replace(_SEP, ", ")
            scope, complete = [], True
            for name in names.split(_SEP):
                intervals, known = transform.known_intervals(self.p, name)
                scope += intervals
                complete = complete and known
            covered: List[str] = []
            for side, members, negated in (("sources", rule.sources, rule.negate_source),
                                           ("destinations", rule.destinations, rule.negate_destination)):  # fmt: skip
                if negated or ANY in members:
                    continue
                inside, known = [], True
                for member in members:
                    intervals, member_known = transform.known_intervals(self.p, member)
                    inside += intervals
                    known = known and member_known
                if complete and known and inside and all(any(s[0] == i[0] and s[1] <= i[1] and i[2] <= s[2] for s in scope) for i in inside):
                    covered.append(side)
            if rule.action != Action.ALLOW:
                if len(covered) < 2:
                    self.report.add("rule", rule.origin, Severity.APPROX, "APPLIED_TO",
                                    f"applied to {listed} only on NSX: the converted rule blocks this traffic wherever it is, "
                                    "which is more")  # fmt: skip
            elif not covered:
                rule.unsupported.append(f"applied to {listed} only: enforced at fewer workloads than its sources and its destinations")
            elif len(covered) == 1:
                other = "destinations" if covered == ["sources"] else "sources"
                self.one_end.append((rule.origin, f"applied to {listed}, which holds its {covered[0]} and not its {other}: "
                                     f"where its {other} are workloads of NSX, NSX checks that end against the rules below this one, "
                                     "and may drop what this rule allows. The converted rule allows it at both ends"))  # fmt: skip

    def notes(self, default: Optional[Action], layer2: List[int], sequence: Dict[Tuple[int, int], List[str]]) -> None:
        if default is None:
            self.report.note(
                Severity.REVIEW,
                "DEFAULT_RULE_MISSING",
                "the export holds no default layer-3 rule (policy default-layer3-section). The NSX default allows what no "
                "rule matches unless it was changed; the converted policy denies it. Export the default policy with the "
                "others to know",
            )
        elif default == Action.ALLOW:
            self.report.note(
                Severity.REVIEW,
                "DEFAULT_ALLOW",
                "the default layer-3 rule allows what no rule matches (the NSX default); the model records that as its "
                "default action",
            )
        if layer2[0]:
            self.report.note(
                Severity.REVIEW if layer2[1] else Severity.INFO,
                "LAYER2_NOT_CONVERTED",
                f"{layer2[0]} rules of the Ethernet category (layer 2, before every layer-3 rule) are not converted"
                + (f"; {layer2[1]} of them block traffic, by MAC address or ether type" if layer2[1] else ""),
            )
        for (category, number), names in sorted(sequence.items()):
            if len(names) > 1:
                self.report.note(
                    Severity.REVIEW,
                    "EQUAL_SEQUENCE",
                    f"policies {', '.join(names)} of category {CATEGORIES[category] or '(none)'} have the same sequence "
                    f"number {number}: NSX runs them in an order it does not define. They were read in the order of the export",
                )
        if self.stateless:
            self.report.note(
                Severity.REVIEW,
                "STATELESS_POLICY",
                "stateless policies (" + ", ".join(self.stateless) + ") check every packet on its own. The converted rules "
                "are connection-based: an allow rule also admits the replies",
            )
        for origin, message in self.one_end:
            self.report.add("rule", origin, Severity.REVIEW, "APPLIED_TO_ONE_END", message)
        if self.equal_rules:
            self.report.note(Severity.REVIEW, "EQUAL_SEQUENCE",
                             "rules of the same policy with the same sequence number run in an order NSX does not define; they "
                             "were read in the order of the export: " + ", ".join(self.equal_rules))  # fmt: skip
        if self.found.gateway_rules and not self.found.gateway_policies:
            self.report.note(Severity.REVIEW, "GATEWAY_POLICY_NOT_CONVERTED",
                             f"{self.found.gateway_rules} rules of gateway firewall policies are not converted; only the "
                             "distributed firewall is")  # fmt: skip
        for origin in self.one_direction:
            self.report.add("rule", origin, Severity.APPROX, "DIRECTION",
                            "the rule blocks traffic in one direction only (IN or OUT) on NSX; the converted rule blocks the "
                            "connection whichever end checks it, which is more")  # fmt: skip
        for name in sorted(self.segment_groups):
            self.report.add("address-group", name, Severity.REVIEW, "SEGMENT_AS_SUBNET",
                            "a segment in the group stands for its subnet here. NSX means the workloads attached to it: the subnet "
                            "also holds the gateway and other addresses that are not members")  # fmt: skip
        if self.found.gateway_policies:
            self.report.note(Severity.REVIEW, "GATEWAY_POLICY_NOT_CONVERTED",
                             f"{self.found.gateway_policies} gateway firewall policies (Tier-0 and Tier-1 gateways) are not "
                             "converted; only the distributed firewall is")  # fmt: skip
        if any(group.dynamic_filter for group in self.p.address_groups.values()):
            self.report.note(
                Severity.REVIEW,
                "DYNAMIC_MEMBERSHIP",
                "groups whose members NSX finds itself (tags, names, virtual machines, segment ports) are kept as dynamic "
                "groups: only an NSX target writes them again; other targets write their rules disabled. Export the members "
                "(GET .../groups/ID/members/ip-addresses) and make them address groups to convert those rules",
            )


def _entry(entry: Dict[str, Any], problems: List[str], algs: List[str]) -> Optional[ServiceEntry]:
    kind = entry.get("resource_type")
    if kind == "L4PortSetServiceEntry":
        proto = str(entry.get("l4_protocol", "")).lower()
        dst, src = _ports(entry.get("destination_ports")), _ports(entry.get("source_ports"))
        if proto not in ("tcp", "udp") or dst is None or src is None:
            problems.append(f"port entry '{entry.get('display_name') or entry.get('id') or ''}' cannot be read")
            return None
        return ServiceEntry(Protocol(proto), dst, src)
    if kind == "ICMPTypeServiceEntry":
        protocol = str(entry.get("protocol", "ICMPv4")).upper()
        if protocol not in ("ICMPV4", "ICMPV6"):
            problems.append(f"ICMP entry for {protocol}")
            return None
        kind_value = entry.get("icmp_type")
        code = entry.get("icmp_code")
        if code is not None and kind_value is None:
            problems.append("ICMP code without a type")
            return None
        if any(v is not None and _int(v, -1) not in range(256) for v in (kind_value, code)):
            problems.append(f"ICMP type or code '{kind_value}/{code}' cannot be read")
            return None
        return ServiceEntry(Protocol.ICMP if protocol == "ICMPV4" else Protocol.ICMP6,
                            icmp_type=None if kind_value is None else _int(kind_value),
                            icmp_code=None if code is None else _int(code))  # fmt: skip
    if kind == "IPProtocolServiceEntry":
        number = _int(entry.get("protocol_number"), -1)
        if not 0 < number < 256:
            problems.append("IP protocol entry without a number")
            return None
        if number in (6, 17, 132):
            return ServiceEntry(Protocol({6: "tcp", 17: "udp", 132: "sctp"}[number]))
        if number in (1, 58):
            return ServiceEntry(Protocol.ICMP if number == 1 else Protocol.ICMP6)
        return ServiceEntry(Protocol.IP, ip_protocol=number)
    if kind == "IGMPTypeServiceEntry":
        return ServiceEntry(Protocol.IP, ip_protocol=2)
    if kind == "ALGTypeServiceEntry":
        alg = str(entry.get("alg", "")).upper()
        alg_proto = _ALG_PROTOCOLS.get(alg)
        dst, src = _ports(entry.get("destination_ports")), _ports(entry.get("source_ports"))
        if alg_proto is None or not dst or src is None:
            problems.append(f"application level gateway {alg or '?'} that cannot be read")
            return None
        algs.append(alg)
        return ServiceEntry(Protocol(alg_proto), dst, src)
    if kind == "EtherTypeServiceEntry":
        problems.append("an ether type (layer 2)")
        return None
    problems.append(f"entry type {kind}")
    return None


def _any_any(raw: Dict[str, Any]) -> bool:
    def anything(values: Any) -> bool:
        items = [str(v).upper() for v in values or []]
        return not items or items == ["ANY"]

    return (anything(raw.get("source_groups")) and anything(raw.get("destination_groups")) and anything(raw.get("services"))
            and not raw.get("service_entries") and not raw.get("sources_excluded") and not raw.get("destinations_excluded")
            and anything(raw.get("profiles")) and str(raw.get("direction") or "IN_OUT").upper() == "IN_OUT"
            and str(raw.get("ip_protocol") or "IPV4_IPV6").upper() == "IPV4_IPV6")  # fmt: skip


def _describe(expression: Dict[str, Any]) -> str:
    kind = expression.get("resource_type")
    if kind == "Condition":
        return " ".join(str(expression.get(k, "")) for k in ("member_type", "key", "operator", "value")).strip()
    if kind == "ExternalIDExpression":
        return f"{expression.get('member_type', '')} by external id"
    if kind == "IdentityGroupExpression":
        return "identity groups"
    if kind == "NestedExpression":
        return "(" + " and ".join(_describe(e) for e in expression.get("expressions") or [] if isinstance(e, dict)
                                  and e.get("resource_type") == "Condition") + ")"  # fmt: skip
    return str(kind)
