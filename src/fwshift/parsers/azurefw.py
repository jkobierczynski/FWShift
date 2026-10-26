# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Azure Firewall parser: a firewall policy with its rule collection groups, or the classic rules of a firewall -> model.

What is read, alone or together in one JSON array or object: ``az network firewall policy show`` and ``az network
firewall policy rule-collection-group list`` (properties flattened), the REST answers (``properties``, ``{"value": [...]}``
lists), an exported ARM template (``Microsoft.Network/firewallPolicies`` and ``.../ruleCollectionGroups``, top level or
nested, names as expressions), ``az network firewall show`` for the classic rules (``networkRuleCollections``,
``natRuleCollections``, ``applicationRuleCollections``) or for the policy a firewall uses, ``az network ip-group list``
(the addresses of IP groups) and ``az network list-service-tags``.

How Azure Firewall decides, and how that is mapped onto the neutral model (Microsoft's documentation of rule processing
and of Firewall Policy rule sets):

* One list without zones. The firewall goes through the rules three times: DNAT rules, then network rules, then
  application rules, each time by the priority of the rule collection group (100 first, 65000 last) and inside it by the
  priority of the rule collection; the rule collection groups of a parent (base) policy before those of the child,
  whatever their priorities. Rules are terminating; what no rule allows is denied. Classic rules: NAT, network and
  application collections, each kind by priority.
* A rule collection has one action; its rules have no order among themselves. A rule of the model per rule of Azure,
  in the order above, is exact.
* A DNAT rule translates and allows what it matches: no network rule sees that traffic. The model gets the NAT rule
  and, ahead of every other rule, an allow rule for what it matches before translation (``AZFW_DNAT_ALLOWS``).
* A network rule: protocols TCP, UDP, ICMP and ``Any``; ``Any`` with every port is every IP protocol (so documented
  since November 2020), ``Any`` with ports TCP and UDP on them; ports are destination ports. Addresses, CIDRs and ranges;
  IP groups (their addresses where the export has them, else dynamic groups); service tags (dynamic groups unless the
  service tags are in the export); FQDNs, resolved by the firewall (host name objects, IPv4).
* An application rule matches HTTP, HTTPS and MSSQL by the name the client asks for (Host header, TLS SNI), by URL, by
  web category or by FQDN tag. None of that is an address: the rule is kept, in its place after the network rules,
  with what it matches by name as not converted. ``*`` as the target is every name (``AZFW_APP_ANY_NAME``).
* Azure Firewall filters IPv4 only: ``*`` is ``0.0.0.0/0``; an IPv6 address in a rule is not converted.
* Not policy rules, reported for the whole policy: threat intelligence (before the rules), IDPS (after them), the
  built-in infrastructure rule collection (after the application rules), source NAT to the firewall's addresses.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import (ANY, ANY_V4, APP_DEFAULT, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy,
                     Protocol, Rule, Service, ServiceEntry)  # fmt: skip
from ..netutil import interval_text, parse_literal
from ..report import Report, Severity
from .azure import _is_expression, _Template

_POLICY = "microsoft.network/firewallpolicies"
_GROUP = "microsoft.network/firewallpolicies/rulecollectiongroups"
_FIREWALL = "microsoft.network/azurefirewalls"
_IP_GROUP = "microsoft.network/ipgroups"
_NAT_COLLECTION = "firewallpolicynatrulecollection"
_FILTER_COLLECTION = "firewallpolicyfilterrulecollection"
_KINDS = ("nat", "network", "application")
_APP_PORTS = {"http": 80, "https": 443, "mssql": 1433}
_TAG = re.compile(r"[A-Za-z][A-Za-z0-9._-]*")
_TYPED = re.compile(rb'"type"\s*:\s*"microsoft\.network/(firewallpolicies|azurefirewalls)')
_HOST = re.compile(r"(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?")


def looks_like_azurefw(data: bytes) -> bool:
    """JSON of Azure with a firewall policy, its rule collection groups or the classic rules of a firewall in it."""
    head = data[:2_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    lowered = head.lower()
    if _TYPED.search(lowered):
        return True
    return any(key in lowered for key in (b'"rulecollectiontype"', b'"networkrulecollections"', b'"natrulecollections"',
                                          b'"applicationrulecollections"'))  # fmt: skip


def has_nsg(data: bytes) -> bool:
    """Whether the JSON holds network security groups too (an export of a resource group can hold both)."""
    return re.search(rb'"type"\s*:\s*"microsoft\.network/networksecuritygroups"', data[:2_000_000].lower()) is not None


def _flat(node: Dict[str, Any]) -> Dict[str, Any]:
    """The object with its ``properties`` merged in, as the CLI prints it."""
    inner = node.get("properties")
    if isinstance(inner, dict):
        out = {k: v for k, v in node.items() if k != "properties"}
        for key, value in inner.items():
            out.setdefault(key, value)
        return out
    return node


def _list(value: Any) -> List[Any]:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _dicts(value: Any) -> List[Dict[str, Any]]:
    return [_flat(item) for item in _list(value) if isinstance(item, dict)]


def _kind(node: Dict[str, Any]) -> str:
    return str(node.get("type") or "").lower()


def _last(identifier: str) -> str:
    return str(identifier).rstrip("/").rsplit("/", 1)[-1]


def _owner(identifier: str) -> str:
    """The name of the policy in the id of one of its rule collection groups ('' when the id does not say)."""
    found = re.search(r"/firewallpolicies/([^/]+)/rulecollectiongroups/", str(identifier), re.IGNORECASE)
    return found.group(1) if found else ""


def _number(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


@dataclass
class _Policy:
    name: str
    ident: str
    node: Dict[str, Any]
    groups: List[Dict[str, Any]] = field(default_factory=list)
    listed: List[str] = field(default_factory=list)  # the ids of the groups the policy names
    order: int = 0
    unsure: bool = False


@dataclass
class _Firewall:
    name: str
    node: Dict[str, Any]
    policy: str  # the id of the policy it uses, or ""


@dataclass
class _Found:
    policies: List[_Policy] = field(default_factory=list)
    firewalls: List[_Firewall] = field(default_factory=list)
    orphans: List[Tuple[str, Dict[str, Any], bool]] = field(default_factory=list)  # (owner, group, unsure) before their policy
    ip_groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # id (lower case) -> group
    tags: Dict[str, List[str]] = field(default_factory=dict)
    tag_names: Dict[str, str] = field(default_factory=dict)
    tags_version: str = ""
    truncated: bool = False
    conditional: List[str] = field(default_factory=list)


class _Collector:
    def __init__(self) -> None:
        self.found = _Found()
        self.by_key: Dict[str, _Policy] = {}

    def walk(self, node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                self.walk(item)
            return
        if not isinstance(node, dict):
            return
        schema = str(node.get("$schema") or "")
        if "deploymentTemplate" in schema and isinstance(node.get("resources"), (list, dict)):
            if isinstance(node["resources"], dict):
                raise ParseError("a template with symbolic resource names (languageVersion 2.0) is not read; export the policy with "
                                 "az network firewall policy show and rule-collection-group list instead")  # fmt: skip
            self.template(node["resources"], _Template(node), "", {})
            return
        if isinstance(node.get("template"), dict):
            self.walk(node["template"])
            return
        if isinstance(node.get("value"), list) and not node.get("type"):  # a REST list
            if node.get("nextLink"):
                self.found.truncated = True
            self.walk(node["value"])
            return
        if isinstance(node.get("values"), list) and node.get("changeNumber") is not None:  # service tags
            self.found.tags_version = str(node.get("changeNumber"))
            for item in _dicts(node["values"]):
                name = str(item.get("name") or item.get("id") or "")
                self.found.tags[name.lower()] = [str(p) for p in _list(item.get("addressPrefixes"))]
                self.found.tag_names[name.lower()] = name
            return
        flat = _flat(node)
        kind = _kind(flat)
        if kind == _POLICY:
            self.policy(flat)
        elif kind == _GROUP or (not kind and "ruleCollections" in flat):
            self.group(flat, "")
        elif kind == _FIREWALL:
            self.firewall(flat)
        elif kind == _IP_GROUP or (not kind and "ipAddresses" in flat and "/ipgroups/" in str(flat.get("id", "")).lower()):
            self.found.ip_groups[str(flat.get("id") or flat.get("name") or "").lower()] = flat
        elif not kind:
            # Answers kept under keys of one object: {"policy": {...}, "groups": [...]}.
            for value in node.values():
                if isinstance(value, (dict, list)):
                    self.walk(value)

    def template(self, resources: List[Any], reader: _Template, parent: str, context: Dict[str, int], unsure_parent: bool = False) -> None:
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            for instance, unsure in reader.instances(resource, context):
                unsure = unsure or unsure_parent
                kind = _kind(instance)
                children = instance.get("resources") if isinstance(instance.get("resources"), list) else None
                body = _flat({k: v for k, v in instance.items() if k not in ("resources", "_context")})
                if kind == _POLICY:
                    name = self.policy(body, unsure)
                    if children:
                        self.template(children, reader, name, instance.get("_context", {}), unsure)
                elif kind in (_GROUP, "rulecollectiongroups"):
                    self.group(body, parent, unsure)
                elif kind == _FIREWALL:
                    self.firewall(body)
                elif kind == _IP_GROUP:
                    name = str(body.get("name") or "")
                    self.found.ip_groups[("/microsoft.network/ipgroups/" + name).lower()] = body
                elif kind == "microsoft.resources/deployments" and _POLICY in json.dumps(body, default=str).lower():
                    raise ParseError("a nested deployment with a firewall policy in it is not read; export the policy with az network "
                                     "firewall policy show and rule-collection-group list instead")  # fmt: skip

    def policy(self, node: Dict[str, Any], unsure: bool = False) -> str:
        name = str(node.get("name") or "") or _last(str(node.get("id", "policy")))
        if _is_expression(name):
            raise ParseError(f"the name of a firewall policy is a template expression that is not worked out: {name[:80]}")
        ident = str(node.get("id") or "") or f"/firewallPolicies/{name}"
        key = name.lower()
        if key in self.by_key or ident.lower() in self.by_key:
            return name  # (the same policy twice: the first one counts)
        found = _Policy(name, ident, node, order=len(self.found.policies), unsure=unsure)
        found.listed = [str(g.get("id", "")) for g in _list(node.get("ruleCollectionGroups")) if isinstance(g, dict) and g.get("id")]
        self.by_key[key] = found
        self.by_key[ident.lower()] = found
        self.found.policies.append(found)
        if unsure:
            self.found.conditional.append(f"policy {name}")
        for owner, group, maybe in [o for o in self.found.orphans if o[0].lower() == key]:
            found.groups.append(dict(group, _unsure=maybe))
        self.found.orphans = [o for o in self.found.orphans if o[0].lower() != key]
        return name

    def group(self, node: Dict[str, Any], parent: str, unsure: bool = False) -> None:
        full = str(node.get("name") or "")
        if _is_expression(full):
            raise ParseError(f"the name of a rule collection group is a template expression that is not worked out: {full[:80]}")
        owner = _owner(str(node.get("id", "")))
        if "/" in full:
            owner, _, full = full.rpartition("/")
        owner = owner or parent
        if isinstance(node.get("ruleCollections"), str):
            raise ParseError(f"the rule collections of group {full} are a template expression that is not worked out")
        group = dict(node, name=full or _last(str(node.get("id", "group"))))
        if unsure:
            self.found.conditional.append(f"rule collection group {group['name']}")
        policy = self.by_key.get(owner.lower())
        if policy is None:
            self.found.orphans.append((owner, group, unsure))
        else:
            same = [g for g in policy.groups if str(g.get("name", "")).lower() == str(group["name"]).lower()]
            if not same:
                policy.groups.append(dict(group, _unsure=unsure))

    def firewall(self, node: Dict[str, Any]) -> None:
        name = str(node.get("name") or "") or _last(str(node.get("id", "firewall")))
        reference = node.get("firewallPolicy")
        policy = str(reference.get("id") or "") if isinstance(reference, dict) else ""
        self.found.firewalls.append(_Firewall(name, node, policy))


def parse(data: bytes, report: Report, policy: str = "") -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    try:
        collector = _Collector()
        collector.walk(document)
        found = collector.found
        for owner, group, unsure in found.orphans:
            # A group whose policy is not in the input: the policy is known by its name only.
            name = owner or "policy"
            holder = collector.by_key.get(name.lower())
            if holder is None:
                holder = _Policy(name, f"/firewallPolicies/{name}", {}, order=len(found.policies))
                collector.by_key[name.lower()] = holder
                found.policies.append(holder)
            holder.groups.append(dict(group, _unsure=unsure))
        found.orphans = []
        if not found.policies and not found.firewalls:
            raise ParseError("no firewall policy, rule collection group or Azure Firewall found; expected the JSON of 'az network firewall "
                             "policy show' and 'az network firewall policy rule-collection-group list', of 'az network firewall show', or "
                             "an exported template")  # fmt: skip
        return _Builder(found, collector.by_key, report).build(policy)
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None


@dataclass
class _Entry:
    """One rule of Azure in the order the firewall takes it."""

    kind: str  # nat, network, application
    raw: Dict[str, Any]
    action: str  # allow, deny, dnat, or the unreadable value
    policy: str
    group: str
    collection: str
    problems: List[str]


class _Builder:
    def __init__(self, found: _Found, by_key: Dict[str, _Policy], report: Report) -> None:
        self.found, self.by_key, self.report = found, by_key, report
        self.p = Policy(vendor="azure-firewall", default_intrazone=Action.DENY, default_interzone=Action.DENY)
        self.taken: Set[str] = {ANY, APP_DEFAULT}
        self.taken_services: Set[str] = {ANY, APP_DEFAULT}
        self.rule_names: Set[str] = set()
        self.nat_names: Set[str] = set()
        self.groups: Dict[str, str] = {}  # tag or ip group key -> address group
        self.services: Dict[str, Tuple[List[str], str]] = {}
        self.fqdns: Dict[str, str] = {}
        self.dynamic: List[str] = []
        self.equal: List[str] = []
        self.mixed: List[str] = []
        self.uses_any = False
        self.uses_icmp = False
        self.uses_fqdn = False
        self.settings: Dict[str, Any] = {}
        self.classic = False
        self.chain: List[_Policy] = []
        self.missing_base = ""
        self.missing_groups: List[str] = []
        self.dnat_allows: List[Rule] = []

    @staticmethod
    def _unique(name: str, taken: Set[str]) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate.lower() in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate.lower())
        return candidate

    # -- what is read ---------------------------------------------------------------------------

    def _select(self, wanted: str) -> Tuple[Optional[_Policy], Optional[_Firewall]]:
        policies, firewalls = self.found.policies, self.found.firewalls
        if wanted:
            key = wanted.lower()
            for firewall in firewalls:
                if firewall.name.lower() == key:
                    return self._of_firewall(firewall)
            chosen = self.by_key.get(key)
            if chosen is None:
                names = [p.name for p in policies] + [f.name for f in firewalls]
                raise ParseError(f"--policy: no firewall policy or firewall '{wanted}' in the input (it holds: {', '.join(names[:12]) or 'none'})")
            return chosen, None
        if len(firewalls) == 1:
            return self._of_firewall(firewalls[0])
        bases = {str((p.node.get("basePolicy") or {}).get("id") or "").lower() for p in policies if isinstance(p.node.get("basePolicy"), dict)}
        bases |= {_last(b) for b in bases}
        leaves = [p for p in policies if p.ident.lower() not in bases and p.name.lower() not in bases]
        if len(leaves) == 1 and not firewalls:
            return leaves[0], None
        names = [p.name for p in leaves] + [f.name for f in firewalls]
        raise ParseError(f"the input holds several firewall policies or firewalls ({', '.join(names[:12])}): give --policy with the name of one")

    def _of_firewall(self, firewall: _Firewall) -> Tuple[Optional[_Policy], Optional[_Firewall]]:
        node = firewall.node
        classic = any(_list(node.get(k)) for k in ("networkRuleCollections", "natRuleCollections", "applicationRuleCollections"))
        if firewall.policy and not classic:
            chosen = self.by_key.get(firewall.policy.lower()) or self.by_key.get(_last(firewall.policy).lower())
            if chosen is None:
                raise ParseError(f"firewall {firewall.name} uses firewall policy {_last(firewall.policy)}, which is not in the input; add "
                                 "az network firewall policy show and rule-collection-group list for it")  # fmt: skip
            return chosen, None
        return None, firewall

    def _chain(self, leaf: _Policy) -> List[_Policy]:
        chain = [leaf]
        while True:
            base = chain[0].node.get("basePolicy")
            ident = str(base.get("id") or "") if isinstance(base, dict) else ""
            if not ident:
                return chain
            parent = self.by_key.get(ident.lower()) or self.by_key.get(_last(ident).lower())
            if parent is None:
                self.missing_base = _last(ident)
                return chain
            if parent in chain:
                raise ParseError(f"firewall policy {parent.name} is its own base policy (through {chain[0].name})")
            chain.insert(0, parent)

    def _entries(self, chosen: Optional[_Policy], firewall: Optional[_Firewall]) -> List[_Entry]:
        out: Dict[str, List[_Entry]] = {kind: [] for kind in _KINDS}
        if firewall is not None:
            self.classic = True
            self.settings = firewall.node
            for key, kind in (("natRuleCollections", "nat"), ("networkRuleCollections", "network"), ("applicationRuleCollections", "application")):
                collections = self._sorted(_dicts(firewall.node.get(key)), f"firewall {firewall.name}, {kind} rule collections")
                for collection in collections:
                    action, found = self._action(collection, kind)
                    for rule in _dicts(collection.get("rules")):
                        out[kind].append(_Entry(kind, rule, action, firewall.name, "", str(collection.get("name") or "collection"),
                                                list(found)))  # fmt: skip
            return out["nat"] + out["network"] + out["application"]
        assert chosen is not None
        self.chain = self._chain(chosen)
        self.settings = chosen.node
        for holder in self.chain:
            listed = {_last(i).lower() for i in holder.listed}
            have = {str(g.get("name", "")).lower() for g in holder.groups}
            self.missing_groups += [f"{holder.name}/{name}" for name in sorted(listed - have)]
            for group in self._sorted(holder.groups, f"policy {holder.name}, rule collection groups"):
                group_name = str(group.get("name") or "group")
                collections = self._sorted(_dicts(group.get("ruleCollections")), f"group {group_name}, rule collections")
                for collection in collections:
                    ctype = str(collection.get("ruleCollectionType") or "").lower()
                    rules = _dicts(collection.get("rules"))
                    kinds = {self._rule_kind(r) for r in rules}
                    if ctype == _FILTER_COLLECTION and len(kinds - {""}) > 1:
                        self.mixed.append(f"{group_name}/{collection.get('name')}")
                    for rule in rules:
                        kind = self._rule_kind(rule)
                        problems: List[str] = []
                        if ctype == _NAT_COLLECTION and kind != "nat" or ctype == _FILTER_COLLECTION and kind == "nat":
                            problems.append(f"a rule of type {rule.get('ruleType')} in a collection of type {collection.get('ruleCollectionType')}")
                        elif ctype not in (_NAT_COLLECTION, _FILTER_COLLECTION):
                            problems.append(f"rule collection type '{str(collection.get('ruleCollectionType'))[:40]}' cannot be read")
                        if not kind:
                            problems.append(f"rule type '{str(rule.get('ruleType'))[:40]}' cannot be read")
                            kind = "nat" if ctype == _NAT_COLLECTION else "network"
                        action, more = self._action(collection, kind)
                        if group.get("_unsure"):
                            problems.append("the template deploys its rule collection group only under a condition that is not worked out here")
                        out[kind].append(_Entry(kind, rule, action, holder.name, group_name, str(collection.get("name") or "collection"),
                                                problems + more))  # fmt: skip
        return out["nat"] + out["network"] + out["application"]

    @staticmethod
    def _rule_kind(rule: Dict[str, Any]) -> str:
        return {"natrule": "nat", "networkrule": "network", "applicationrule": "application"}.get(str(rule.get("ruleType") or "").lower(), "")

    def _sorted(self, items: List[Dict[str, Any]], where: str) -> List[Dict[str, Any]]:
        """Items by priority (100 first), in the order of the input where two have the same; one without a priority last."""
        numbered = [(_number(item.get("priority")), index, item) for index, item in enumerate(items)]
        seen: Dict[int, str] = {}
        for number, _, item in numbered:
            if number is None:
                continue
            if number in seen:
                self.equal.append(f"{where}: {seen[number]} and {item.get('name')} ({number})")
            seen[number] = str(item.get("name"))
        numbered.sort(key=lambda t: (t[0] if t[0] is not None else 1 << 30, t[1]))
        out = []
        for number, _, item in numbered:
            if number is None or not 100 <= number <= 65000:
                item = dict(item, _badpriority=str(item.get("priority"))[:30])
            out.append(item)
        return out

    @staticmethod
    def _action(collection: Dict[str, Any], kind: str) -> Tuple[str, List[str]]:
        action = collection.get("action")
        value = str((action.get("type") if isinstance(action, dict) else action) or "").lower()
        problems: List[str] = []
        if collection.get("_badpriority") is not None:
            problems.append(f"the priority of rule collection {collection.get('name')} ('{collection['_badpriority']}') is not one Azure "
                            "allows (100 to 65000)")  # fmt: skip
        if kind == "nat":
            if value != "dnat":
                problems.append(f"NAT action '{value[:20]}', which is not converted (only DNAT is documented)")
            return value, problems
        if value not in ("allow", "deny"):
            problems.append(f"action '{value[:20]}' cannot be read")
        return value, problems

    # -- members -----------------------------------------------------------------------------

    def _addresses(self, values: Any, problems: List[str], side: str) -> List[str]:
        out: List[str] = []
        for value in _list(values):
            text = str(value).strip()
            if not text:
                continue
            if text in ("*", "Any", "any"):
                out.append(ANY_V4)
                continue
            interval = parse_literal(text)
            if interval is not None and re.search(r"[.:]", text):
                if interval[0] == 6:
                    problems.append(f"IPv6 {side} address '{text[:60]}', which Azure Firewall does not take")
                out.append(interval_text(interval))
                continue
            if _is_expression(text):
                problems.append(f"{side} address '{text[:60]}' is a template expression that is not worked out")
            elif _TAG.fullmatch(text):
                out.append(self._tag(text))
            else:
                problems.append(f"{side} address '{text[:60]}' cannot be read")
        return out

    def _tag(self, name: str) -> str:
        key = "tag:" + name.lower()
        if key in self.groups:
            return self.groups[key]
        group_name = self._unique(self.found.tag_names.get(name.lower(), name), self.taken)
        group = AddressGroup(group_name, description=f"service tag {name}", builtin="azure-firewall")
        prefixes = self.found.tags.get(name.lower())
        good = [interval_text(i) for i in (parse_literal(p) for p in prefixes or []) if i is not None and i[0] == 4]
        if good:
            group.members = good
            group.description += f" (its IPv4 addresses, of the service tags of change {self.found.tags_version or '?'})"
        else:
            group.dynamic_filter = "azure-tag:" + name
            self.dynamic.append(f"service tag {name}")
        self.p.address_groups[group_name] = group
        self.groups[key] = group_name
        return group_name

    def _ip_groups(self, values: Any, problems: List[str]) -> List[str]:
        out: List[str] = []
        for value in _list(values):
            ident = str(value.get("id") if isinstance(value, dict) else value).strip()
            if _is_expression(ident):
                problems.append(f"IP group '{ident[:60]}' is a template expression that is not worked out")
                continue
            if ident:
                out.append(self._ip_group(ident, problems))
        return out

    def _ip_group(self, ident: str, problems: List[str]) -> str:
        key = "ipg:" + ident.lower()
        if key in self.groups:
            return self.groups[key]
        node = self.found.ip_groups.get(ident.lower())
        if node is None:
            same = [g for k, g in self.found.ip_groups.items() if _last(k) == _last(ident).lower()]
            node = same[0] if len(same) == 1 else None
        name = self._unique(_last(ident) or "ipgroup", self.taken)
        group = AddressGroup(name, description=f"IP group {ident}", builtin="azure-firewall")
        if node is None:
            group.dynamic_filter = "azure-ipgroup:" + ident
            self.dynamic.append(f"IP group {_last(ident)}")
        else:
            bad: List[str] = []
            for value in _list(node.get("ipAddresses")):
                interval = parse_literal(str(value).strip())
                if interval is None or interval[0] != 4:
                    bad.append(str(value)[:40])
                    continue
                group.members.append(interval_text(interval))
            if bad:
                group.unsupported = f"entries that are not IPv4 addresses, networks or ranges: {', '.join(bad[:4])}"
            elif not group.members:
                group.unsupported = "an IP group without addresses"
        self.p.address_groups[name] = group
        self.groups[key] = name
        return name

    def _fqdn(self, value: str, problems: List[str], wildcards: bool) -> Optional[str]:
        text = value.strip().rstrip(".").lower()
        if not _HOST.fullmatch(text) or ("*" in text and not wildcards):
            problems.append(f"FQDN '{value[:60]}' cannot be read" + ("" if wildcards else " (network rules take no wildcards)"))
            return None
        if text in self.fqdns:
            return self.fqdns[text]
        name = self._unique(text, self.taken)
        self.p.addresses[name] = Address(name, AddressKind.FQDN, text, fqdn_family=4)
        self.fqdns[text] = name
        return name

    # -- services ------------------------------------------------------------------------------

    def _ports(self, values: Any, problems: List[str]) -> Optional[str]:
        parts: List[str] = []
        for value in _list(values):
            for text in str(value).replace(" ", "").split(","):
                if text in ("*", ""):
                    if text == "*":
                        return ""
                    continue
                first, _, last = text.partition("-")
                if not first.isdigit() or not (last or first).isdigit() or not 0 < int(first) <= int(last or first) <= 65535:
                    problems.append(f"port '{text[:20]}' cannot be read")
                    return None
                parts.append(text)
        if not parts:
            problems.append("no destination port")
            return None
        return ",".join(transform.dedupe(parts))

    def _service(self, protocols: List[str], ports: Optional[str], problems: List[str]) -> List[str]:
        names = sorted({str(p).upper() for p in protocols})
        if not names:
            problems.append("no protocol")
            return [ANY]
        if ports is None:
            return [ANY]
        unknown = [n for n in names if n not in ("TCP", "UDP", "ICMP", "ANY")]
        if unknown:
            problems.append(f"protocol '{unknown[0][:20]}' cannot be read")
            return [ANY]
        if "ANY" in names:
            self.uses_any = True
            if not ports:
                return [ANY]  # every IP protocol
            names = sorted(set(names) - {"ANY"} | {"TCP", "UDP"})
        key = json.dumps([names, ports])
        if key in self.services:
            return self.services[key][0]
        entries: List[ServiceEntry] = []
        for name in names:
            if name in ("TCP", "UDP"):
                entries.append(ServiceEntry(Protocol(name.lower()), dst_ports=ports))
            else:
                self.uses_icmp = True
                entries.append(ServiceEntry(Protocol.ICMP))
        label = "-".join(n.lower() for n in names if n != "ICMP")
        if label:
            label += "-" + (ports or "all")
        if "ICMP" in names:
            label = (label + "-icmp") if label else "icmp"
        name = self._unique(label, self.taken_services)
        self.p.services[name] = Service(name, entries)
        self.services[key] = ([name], name)
        return [name]

    # -- rules -----------------------------------------------------------------------------

    @staticmethod
    def _label(entry: _Entry) -> str:
        """The name of a rule: its collection and its own name (the group and the policy are in its source ids)."""
        return f"{entry.collection}/{entry.raw.get('name') or 'rule'}"

    @staticmethod
    def _path(entry: _Entry) -> str:
        return "/".join(p for p in (entry.policy, entry.group, entry.collection, str(entry.raw.get("name") or "rule")) if p)

    def _ids(self, entry: _Entry) -> Dict[str, str]:
        out = {"azurefw.policy" if not self.classic else "azurefw.firewall": entry.policy, "azurefw.collection": entry.collection,
               "azurefw.rule": str(entry.raw.get("name") or ""), "azurefw.type": entry.kind}  # fmt: skip
        if entry.group:
            out["azurefw.group"] = entry.group
        return out

    def _sides(self, entry: _Entry, problems: List[str]) -> Tuple[List[str], List[str]]:
        raw = entry.raw
        sources = self._addresses(raw.get("sourceAddresses"), problems, "source") + self._ip_groups(raw.get("sourceIpGroups"), problems)
        if not _list(raw.get("sourceAddresses")) and not _list(raw.get("sourceIpGroups")):
            problems.append("no source")
        destinations = self._addresses(raw.get("destinationAddresses"), problems, "destination")
        destinations += self._ip_groups(raw.get("destinationIpGroups"), problems)
        if entry.kind == "network":
            for value in _list(raw.get("destinationFqdns")):
                name = self._fqdn(str(value), problems, wildcards=False)
                if name:
                    self.uses_fqdn = True
                    destinations.append(name)
        return transform.dedupe(sources), transform.dedupe(destinations)

    def _rule(self, entry: _Entry) -> None:
        raw, problems = entry.raw, list(entry.problems)
        sources, destinations = self._sides(entry, problems)
        name = self._unique(self._label(entry), self.rule_names)
        rule = Rule(name, sources=sources or [ANY], destinations=destinations, action=Action.ALLOW if entry.action == "allow" else Action.DENY)
        rule.origin, rule.log_end, rule.description = name, False, str(raw.get("description") or "")
        rule.source_ids = self._ids(entry)
        if entry.kind == "network":
            if not destinations and not any(_list(raw.get(k)) for k in ("destinationAddresses", "destinationIpGroups", "destinationFqdns")):
                problems.append("no destination")
            protocols = _list(raw.get("ipProtocols")) or _list(raw.get("protocols"))
            rule.services = self._service([str(p) for p in protocols], self._ports(raw.get("destinationPorts"), problems), problems)
        else:
            self._application(rule, raw, problems)
        rule.destinations = rule.destinations or [ANY]
        rule.unsupported = list(dict.fromkeys(problems))
        self.p.rules.append(rule)

    def _application(self, rule: Rule, raw: Dict[str, Any], problems: List[str]) -> None:
        entries: List[ServiceEntry] = []
        for protocol in _dicts(raw.get("protocols")):
            kind = str(protocol.get("protocolType") or "").lower()
            port = _number(protocol.get("port"))
            if kind not in _APP_PORTS:
                problems.append(f"application protocol '{str(protocol.get('protocolType'))[:20]}' cannot be read")
                continue
            if port is None:
                port = _APP_PORTS[kind]
            if not 0 < port < 65536:
                problems.append(f"port '{protocol.get('port')}' cannot be read")
                continue
            entries.append(ServiceEntry(Protocol.TCP, dst_ports=str(port)))
        if not _dicts(raw.get("protocols")):
            problems.append("no protocol")
        if entries:
            rule.services = self._service(["TCP"], ",".join(transform.dedupe([e.dst_ports for e in entries])), problems)
        targets = [str(t).strip() for t in _list(raw.get("targetFqdns")) if str(t).strip()]
        named: List[str] = []
        if "*" in targets:
            targets = []
            self.report.add("rule", rule.origin, Severity.REVIEW, "AZFW_APP_ANY_NAME",
                            "an application rule for every name ('*'): it matches HTTP, HTTPS or MSSQL traffic whatever the name the "
                            "client asks for, and is read as its TCP ports. Traffic on those ports that is not of the protocol (no "
                            "Host header, no SNI) is not matched by Azure Firewall, and is matched by the converted rule")  # fmt: skip
        elif targets:
            names = [self._fqdn(t, problems, wildcards=True) for t in targets]
            rule.destinations = transform.dedupe(rule.destinations + [n for n in names if n])
            named.append("target FQDNs " + ", ".join(targets[:6]) + (" ..." if len(targets) > 6 else ""))
        for key, label in (("targetUrls", "target URLs"), ("webCategories", "web categories"), ("fqdnTags", "FQDN tags")):
            values = [str(v) for v in _list(raw.get(key)) if str(v).strip()]
            if values:
                named.append(f"{label} " + ", ".join(values[:6]) + (" ..." if len(values) > 6 else ""))
        if named:
            problems.append("an application rule matches by the name the client asks for (HTTP Host header, TLS SNI), not by address: "
                            + "; ".join(named))  # fmt: skip
        elif not targets and "*" not in [str(t).strip() for t in _list(raw.get("targetFqdns"))]:
            problems.append("an application rule without targets")
        if raw.get("terminateTLS"):
            rule.profiles["tls-inspection"] = "terminateTLS"
        headers = _dicts(raw.get("httpHeadersToInsert"))
        if headers:
            rule.handling["http-headers"] = ", ".join(str(h.get("headerName")) for h in headers)

    def _nat(self, entry: _Entry) -> None:
        raw, problems = entry.raw, list(entry.problems)
        sources, destinations = self._sides(entry, problems)
        label = self._label(entry)
        name = self._unique(label, self.nat_names)
        protocols = [str(p).upper() for p in _list(raw.get("ipProtocols")) or _list(raw.get("protocols"))]
        if any(p not in ("TCP", "UDP") for p in protocols):
            problems.append(f"DNAT of protocol {', '.join(p for p in protocols if p not in ('TCP', 'UDP'))[:30]}, which is not documented "
                            "(TCP and UDP are)")  # fmt: skip
        ports = self._ports(raw.get("destinationPorts"), problems)
        service = self._service([p for p in protocols if p in ("TCP", "UDP")], ports, problems)
        if ANY_V4 in destinations:
            problems.append("DNAT to every destination address ('*'), which Azure does not take (the firewall's address is wanted)")
        target = str(raw.get("translatedAddress") or "").strip()
        fqdn = str(raw.get("translatedFqdn") or "").strip()
        translated: Optional[str] = None
        if target:
            interval = parse_literal(target)
            if interval is None or interval[0] != 4 or interval[1] != interval[2]:
                problems.append(f"translated address '{target[:60]}' is not one IPv4 address")
            else:
                translated = interval_text(interval)
        elif fqdn:
            translated = self._fqdn(fqdn, problems, wildcards=False)
        else:
            problems.append("no translated address")
        port = str(raw.get("translatedPort") or "").strip()
        if port and not port.isdigit():
            problems.append(f"translated port '{port[:20]}' is not one port")
            port = ""
        nat = NatRule(name, sources=sources or [ANY], destinations=destinations or [ANY], service=service[0] if len(service) == 1 else ANY)
        nat.origin, nat.description = name, str(raw.get("description") or "")
        if ports and port and ports == port:
            port = ""
        if ports is not None and port and ("," in (ports or "") or "-" in (ports or "")):
            self.report.add("nat", name, Severity.REVIEW, "AZFW_DNAT_PORTS",
                            f"a DNAT rule of several ports ({ports}) to one translated port ({port}): Microsoft does not document how "
                            "they are translated; read as every one of them to that port")  # fmt: skip
        if translated is not None:
            nat.destination_translation = DestNat(translated, port)
        nat.unsupported = list(dict.fromkeys(problems))
        if fqdn and translated:
            self.report.add("nat", name, Severity.INFO, "AZFW_DNAT_FQDN",
                            f"translated to the first address {fqdn} resolves to; when it does not resolve, the rule matches nothing")  # fmt: skip
        self.p.nat_rules.append(nat)
        if entry.action != "dnat":
            return
        # What the DNAT rule translates, Azure Firewall allows, before any network rule.
        allow = Rule(self._unique(f"{label} (DNAT)", self.rule_names), sources=nat.sources, destinations=nat.destinations, services=service)
        allow.origin, allow.log_end, allow.description = allow.name, False, nat.description
        allow.source_ids = dict(self._ids(entry), **{"azurefw.dnat": nat.origin})
        allow.unsupported = list(nat.unsupported)
        self.report.add("rule", allow.origin, Severity.INFO, "AZFW_DNAT_ALLOWS",
                        f"Azure Firewall allows what DNAT rule {self._path(entry)} translates, before any network rule sees it: this rule "
                        "says so, for the addresses before translation")  # fmt: skip
        self.dnat_allows.append(allow)

    # -- the whole -------------------------------------------------------------------------

    def build(self, wanted: str) -> Policy:
        chosen, firewall = self._select(wanted)
        self.p.scope = (chosen.name if chosen is not None else firewall.name if firewall is not None else "")
        entries = self._entries(chosen, firewall)
        for entry in entries:
            if entry.kind == "nat":
                self._nat(entry)
            else:
                self._rule(entry)
        self.p.rules = self.dnat_allows + self.p.rules
        self._notes(chosen, firewall)
        return self.p

    def _setting(self, *path: str) -> Any:
        value: Any = self.settings
        for key in path:
            if not isinstance(value, dict):
                return None
            value = next((v for k, v in value.items() if str(k).lower() == key.lower()), None)
        return value

    def _notes(self, chosen: Optional[_Policy], firewall: Optional[_Firewall]) -> None:
        order = ("classic rules of firewall " + firewall.name + ": NAT rule collections, then network, then application ones, each by "
                 "priority") if firewall is not None else (
            "firewall policy " + " > ".join(p.name for p in self.chain) + ": DNAT rules, then network rules, then application rules, "
            "each by the priority of the rule collection group and of the rule collection" +
            (", the groups of the base policy before those of the child" if len(self.chain) > 1 else ""))  # fmt: skip
        self.report.note(Severity.INFO, "AZFW_ORDER", "read in the order Azure Firewall takes the rules: " + order +
                         ". What no rule allows is denied; rules of one collection have one action and no order among themselves")  # fmt: skip
        self.report.note(Severity.INFO, "AZFW_IPV4_ONLY",
                         "Azure Firewall filters IPv4 only: '*' is read as 0.0.0.0/0, and the converted policy says nothing for IPv6")
        self.report.note(Severity.INFO, "AZFW_UNFILTERED",
                         "the firewall decides only what is routed through it (user-defined routes, a secured hub); traffic inside a "
                         "virtual network that is not routed to it, and network security groups on the way, are not in this export")  # fmt: skip
        if self.missing_base:
            self.report.note(Severity.REVIEW, "AZFW_BASE_POLICY_MISSING",
                             f"the policy inherits from base policy {self.missing_base}, which is not in the input: its rule collection "
                             "groups come first in Azure, and are missing here. Add it (az network firewall policy show and "
                             "rule-collection-group list for it)")  # fmt: skip
        if chosen is not None and not any(p.groups for p in self.chain):
            self.report.note(Severity.REVIEW, "AZFW_NO_GROUPS",
                             "the input holds no rule collection group of the policy: add the answer of az network firewall policy "
                             "rule-collection-group list")  # fmt: skip
        if self.missing_groups or self.found.truncated:
            self.report.note(Severity.REVIEW, "AZFW_INCOMPLETE_EXPORT",
                             "the input is not complete: " + ("an answer says there is more (nextLink)" if self.found.truncated else "") +
                             ("; " if self.found.truncated and self.missing_groups else "") +
                             ("the policy names rule collection groups that are not in it: " + ", ".join(self.missing_groups[:8])
                              if self.missing_groups else ""))  # fmt: skip
        if self.equal:
            self.report.note(Severity.REVIEW, "AZFW_EQUAL_PRIORITY",
                             "items with the same priority; read in the order of the input: " + "; ".join(self.equal[:8]))
        if self.mixed:
            self.report.note(Severity.REVIEW, "AZFW_MIXED_COLLECTION",
                             "rule collections that hold network and application rules, which Azure does not allow; each rule was "
                             "read in the pass of its type: " + ", ".join(self.mixed[:8]))  # fmt: skip
        if self.dynamic:
            self.report.note(Severity.REVIEW, "AZFW_DYNAMIC",
                             "addresses only Azure knows: " + ", ".join(sorted(set(self.dynamic))[:12]) + ". They are dynamic groups, which "
                             "only an Azure Firewall target writes again; add the IP groups (az network ip-group list) and the service "
                             "tags (az network list-service-tags) to the export to convert them for other targets")  # fmt: skip
        if self.found.conditional:
            self.report.note(Severity.REVIEW, "AZFW_TEMPLATE_CONDITION",
                             "the template deploys these only under a condition that is not worked out here; the rules of such a "
                             "group are not converted: " + ", ".join(self.found.conditional[:8]))  # fmt: skip
        if self.uses_any:
            self.report.note(Severity.INFO, "AZFW_ANY_PROTOCOL",
                             "protocol Any with every port is every IP protocol, as Microsoft documents it since November 2020 (before, "
                             "it meant TCP, UDP and ICMP); with ports it is TCP and UDP on them")  # fmt: skip
        if self.uses_icmp:
            self.report.note(Severity.INFO, "AZFW_ICMP_INTERNET",
                             "rules for ICMP do not apply to traffic to the internet, which the firewall cannot translate for it "
                             "(a known issue Microsoft documents); between networks of Azure they do")  # fmt: skip
        if self.uses_fqdn:
            proxy = self._setting("dnsSettings", "enableProxy")
            if proxy is None and self.classic:
                extra = self._setting("additionalProperties")
                if isinstance(extra, dict):
                    proxy = next((v for k, v in extra.items() if str(k).lower() == "network.dns.enableproxy"), None)
            enabled = str(proxy).lower() == "true"
            if not enabled:
                self.report.note(Severity.REVIEW, "AZFW_FQDN_DNS_PROXY",
                                 "network rules name FQDNs, which Azure Firewall resolves only with DNS proxy enabled; " +
                                 ("the policy does not enable it (a child policy does not inherit it from its base)" if proxy is not None or
                                  self.settings else "the input does not hold the policy's settings") +
                                 ". The rules are read as the firewall would resolve the names")  # fmt: skip
        threat = str(self._setting("threatIntelMode") or "").lower()
        if threat in ("deny", "alert", "off"):
            self.report.note(Severity.REVIEW if threat == "deny" else Severity.INFO, "AZFW_THREAT_INTEL",
                             f"threat intelligence mode {threat.capitalize()}: it is applied before the rules" +
                             (" and blocks traffic of known malicious addresses and names, which the converted policy does not"
                              if threat == "deny" else "; it does not block") + ". It is not a rule and is not converted")  # fmt: skip
        idps = str(self._setting("intrusionDetection", "mode") or "").lower()
        if idps in ("deny", "alert"):
            self.report.note(Severity.REVIEW if idps == "deny" else Severity.INFO, "AZFW_IDPS",
                             f"IDPS in mode {idps.capitalize()}" + (": after the rules, it blocks what its signatures match, which the "
                             "converted policy does not" if idps == "deny" else ": it alerts and does not block") + "; not converted")  # fmt: skip
        others = [label for key, label in (("transportSecurity", "TLS inspection"), ("explicitProxy", "an explicit proxy"),
                                           ("sql", "SQL redirect settings")) if self._setting(key)]  # fmt: skip
        if others:
            self.report.note(Severity.INFO, "AZFW_SETTINGS", "settings of the policy that are not rules are not converted: " + ", ".join(others))
        snat = self._setting("snat", "privateRanges")
        if snat is None and self.classic:
            extra = self._setting("additionalProperties")
            if isinstance(extra, dict):
                snat = next((v for k, v in extra.items() if str(k).lower() == "network.snat.privateranges"), None)
        ranges = ", ".join(str(s) for s in _list(snat)) if snat else "the defaults: the ranges of RFC 1918 and RFC 6598"
        self.report.note(Severity.INFO, "AZFW_SNAT",
                         "Azure Firewall translates the source of what a network rule allows to its public address unless the "
                         f"destination is in its private ranges ({ranges}); of what an application rule allows always (to one of its "
                         "private addresses); and, community sources say, of what a DNAT rule translates. None of that is a rule of "
                         "the policy: no source NAT rule is in the model")  # fmt: skip
        if any(r.source_ids.get("azurefw.type") == "application" for r in self.p.rules):
            self.report.note(Severity.INFO, "AZFW_INFRASTRUCTURE",
                             "after the application rules Azure Firewall allows the FQDNs of its built-in infrastructure rule collection "
                             "(platform image repository, managed disk status, diagnostics), unless an application rule denies all; "
                             "the model does not hold them")  # fmt: skip
        if self.classic:
            self.report.note(Severity.INFO, "AZFW_CLASSIC", "the classic rules of the firewall were read (it uses no firewall policy)")
