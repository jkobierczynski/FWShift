# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Azure network security groups parser: the JSON of the Azure CLI, the REST API, a template or Resource Graph -> model.

What is read: network security groups in any of the forms Azure gives them, alone or together in one JSON array:
``az network nsg show`` and ``az network nsg list`` (properties flattened), the REST answers (``properties``, a
``{"value": [...]}`` list), an exported ARM template (rules inline or as child resources, names as expressions), and
the rows of ``az graph query``. With them, if given: network interfaces (``az network nic list``: the members of
application security groups), virtual networks and subnets (the addresses behind each group), and the service tags
(``az network list-service-tags``).

How Azure behaviour is mapped onto the neutral model:

* Each network security group is a zone; everything else is the zone ``outside``. An inbound rule is a rule from
  ``outside`` into the group's zone, an outbound rule one from the zone to ``outside``; each list in the order of its
  priorities, ending in the default rules (added when the export leaves them out).
* A connection between two resources behind groups passes the outbound rules of the one and the inbound rules of the
  other. That is one first-match list too: each outbound rule that denies, and for each that allows, the inbound
  rules cut to it.
* ``VirtualNetwork`` on the side of the group's own resources is any of them; ``Internet`` there is none. On the other
  side, and for the other service tags and the application security groups, the addresses are known to Azure only:
  they are dynamic groups, unless the export gives them (service tags, interfaces). ``AzureLoadBalancer`` is
  168.63.129.16.
* Protocol ``*`` is TCP, UDP and ICMP, as Microsoft documents it; ``Esp`` and ``Ah`` are IP protocols 50 and 51.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import regions, transform
from ..errors import ParseError
from ..model import ANY, APP_DEFAULT, Action, AddressGroup, Policy, Protocol, Rule, Service, ServiceEntry, Zone
from ..netutil import Interval, intersect, interval_text, normalize, parse_literal
from ..report import Report, Severity

_NSG = "microsoft.network/networksecuritygroups"
_NIC = "microsoft.network/networkinterfaces"
_ASG = "microsoft.network/applicationsecuritygroups"
_VNET = "microsoft.network/virtualnetworks"
_SUBNET = "microsoft.network/virtualnetworks/subnets"
_LOAD_BALANCER = "168.63.129.16"
_MAX_COMPOSED = 5000  # rules for one pair of groups
# The six rules every group ends in (the API's names).
_DEFAULTS = [
    ("AllowVnetInBound", "Inbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow"),
    ("AllowAzureLoadBalancerInBound", "Inbound", 65001, "AzureLoadBalancer", "*", "Allow"),
    ("DenyAllInBound", "Inbound", 65500, "*", "*", "Deny"),
    ("AllowVnetOutBound", "Outbound", 65000, "VirtualNetwork", "VirtualNetwork", "Allow"),
    ("AllowInternetOutBound", "Outbound", 65001, "*", "Internet", "Allow"),
    ("DenyAllOutBound", "Outbound", 65500, "*", "*", "Deny"),
]


def looks_like_azure(data: bytes) -> bool:
    """JSON of Azure with network security groups in it."""
    head = data[:2_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    lowered = head.lower()
    return b"microsoft.network/networksecuritygroups" in lowered or (b'"securityrules"' in lowered and b'"priority"' in lowered)


def _flat(node: Dict[str, Any]) -> Dict[str, Any]:
    """The object with its ``properties`` merged in, as the CLI prints it."""
    inner = node.get("properties")
    if isinstance(inner, dict):
        out = dict(node)
        del out["properties"]
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
    return identifier.rstrip("/").rsplit("/", 1)[-1]


@dataclass
class _Nsg:
    name: str
    ident: str
    rules: List[Dict[str, Any]] = field(default_factory=list)
    defaults: List[Dict[str, Any]] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    order: int = 0


@dataclass
class _Found:
    nsgs: List[_Nsg] = field(default_factory=list)
    interfaces: List[Dict[str, Any]] = field(default_factory=list)
    interfaces_given: bool = False
    asgs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    subnets: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # id (lower case) -> subnet
    tags: Dict[str, List[str]] = field(default_factory=dict)  # service tag (lower case) -> prefixes
    tag_names: Dict[str, str] = field(default_factory=dict)
    tags_version: str = ""
    templates: int = 0
    truncated: bool = False
    conditional: List[str] = field(default_factory=list)  # groups of a template deployed only under a condition left open
    vnets: Dict[str, List[str]] = field(default_factory=dict)  # virtual network id (lower case) -> the ids it is peered with


class _Unknown(Exception):
    """A template expression that is not worked out here."""


_TOKEN = re.compile(r"\s*(?:('(?:[^']|'')*')|(-?\d+)|([A-Za-z_][A-Za-z0-9_]*)|(\S))")
_MAX_COPIES = 5000
_RULE_TYPES = {_NSG + "/securityrules", "securityrules"}


class _Template:
    """The template expressions a group's export or a Bicep build uses: parameters and variables (their default values),
    concat, format, resourceId, copyIndex, if, equals and a few more, with [index] and .property. Anything else is not
    worked out: a name then makes the template unreadable, any other field is left as written (and cannot be read)."""

    def __init__(self, template: Dict[str, Any]) -> None:
        self.parameters = {str(k).lower(): v for k, v in (template.get("parameters") or {}).items()} if isinstance(template.get("parameters"), dict) else {}
        self.variables = {str(k).lower(): v for k, v in (template.get("variables") or {}).items()} if isinstance(template.get("variables"), dict) else {}
        self.depth = 0

    # -- resources ----------------------------------------------------------------------------

    def instances(self, resource: Dict[str, Any], outer: Dict[str, int]) -> List[Tuple[Dict[str, Any], bool]]:
        """The resources one entry deploys, worked out: (resource, deployed only under a condition left open). A copy loop
        gives one per copy; a condition that is false gives none."""
        loop = resource.get("copy")
        contexts: List[Dict[str, int]] = [dict(outer)]
        if loop is not None:
            if not isinstance(loop, dict):
                raise ParseError("a copy loop of a template resource cannot be read")
            count = self._count(loop.get("count"), outer)
            contexts = [dict(outer, **{"": i, str(loop.get("name") or "").lower(): i}) for i in range(count)]
        out: List[Tuple[Dict[str, Any], bool]] = []
        for context in contexts:
            condition: Any = True
            if "condition" in resource:
                try:
                    condition = self.evaluate(resource["condition"], context)
                except _Unknown:
                    condition = None
            if condition is not None and not condition:
                continue  # (not deployed)
            body = {k: v for k, v in resource.items() if k not in ("copy", "condition", "resources")}
            evaluated = self.deep(body, context)
            if isinstance(resource.get("resources"), list):
                evaluated["resources"] = resource["resources"]
                evaluated["_context"] = context
            out.append((evaluated, condition is None))
        return out

    def _count(self, value: Any, context: Dict[str, int]) -> int:
        try:
            count = self.evaluate(value, context)
        except _Unknown:
            count = None
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= _MAX_COPIES:
            raise ParseError(f"the count of a template copy loop is not worked out ({str(value)[:60]}); export the deployed groups "
                             "with az network nsg list instead")  # fmt: skip
        return int(count)

    def deep(self, value: Any, context: Dict[str, int], key: str = "") -> Any:
        """A value with its expressions worked out where they can be; property copy loops written out."""
        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            for name, item in value.items():
                if name == "copy" and isinstance(item, list):
                    for loop in item:
                        if not isinstance(loop, dict) or "input" not in loop:
                            raise ParseError("a property copy loop of a template cannot be read")
                        count = self._count(loop.get("count"), context)
                        label = str(loop.get("name") or "")
                        out[label] = [self.deep(loop["input"], dict(context, **{label.lower(): i})) for i in range(count)]
                    continue
                out[name] = self.deep(item, context, name)
            return out
        if isinstance(value, list):
            return [self.deep(item, context, key) for item in value]
        if isinstance(value, str) and value.startswith("[[") :
            return value[1:]
        if _is_expression(value):
            try:
                return self.evaluate(value, context, names=key in ("name", "id"))
            except _Unknown:
                return value
        return value

    # -- expressions --------------------------------------------------------------------------

    def evaluate(self, value: Any, context: Dict[str, int], names: bool = False) -> Any:
        if not _is_expression(value):
            return value[1:] if isinstance(value, str) and value.startswith("[[") else value
        self.depth += 1
        try:
            if self.depth > 40:
                raise _Unknown()
            tokens = [t for t in _TOKEN.findall(value[1:-1]) if any(t)]
            reader = _Reader(self, tokens, context, names)
            result = reader.expression()
            if reader.position != len(tokens):
                raise _Unknown()
            return result
        finally:
            self.depth -= 1

    def call(self, function: str, arguments: List[Any], context: Dict[str, int], names: bool) -> Any:
        function = function.lower()
        if function == "parameters" and len(arguments) == 1:
            parameter = self.parameters.get(str(arguments[0]).lower())
            if isinstance(parameter, dict) and "defaultValue" in parameter:
                try:
                    return self.deep_strict(parameter["defaultValue"], context)
                except _Unknown:
                    pass
            if names:
                # (An export names a parameter after the resource: networkSecurityGroups_nsg_web_name is nsg_web.)
                text = str(arguments[0])
                return re.sub(r"_(name|externalid)$", "", re.sub(r"^[a-z][A-Za-z]+s_", "", text)) or text
            raise _Unknown()
        if function == "variables" and len(arguments) == 1:
            key = str(arguments[0]).lower()
            if key not in self.variables:
                raise _Unknown()
            return self.deep_strict(self.variables[key], context)
        if function == "copyindex":
            loop, offset = "", 0
            for argument in arguments:
                if isinstance(argument, str):
                    loop = argument.lower()
                elif isinstance(argument, int) and not isinstance(argument, bool):
                    offset = argument
            if loop not in context:
                raise _Unknown()
            return context[loop] + offset
        if function == "concat":
            if arguments and all(isinstance(a, list) for a in arguments):
                return [item for a in arguments for item in a]
            return "".join(_text(a) for a in arguments)
        if function == "format" and arguments:
            def place(found: "re.Match[str]") -> str:
                index = int(found.group(1)) + 1
                if index >= len(arguments):
                    raise _Unknown()
                return _text(arguments[index])
            return re.sub(r"\{(\d+)(?::[^}]*)?\}", place, str(arguments[0]))
        if function in ("resourceid", "subscriptionresourceid") and arguments:
            return "/" + "/".join(_text(a) for a in arguments)
        if function in ("tolower", "toupper", "string", "trim") and len(arguments) == 1:
            text = _text(arguments[0])
            return text.lower() if function == "tolower" else text.upper() if function == "toupper" else text.strip() if function == "trim" else text
        if function == "int" and len(arguments) == 1 and str(arguments[0]).strip().lstrip("-").isdigit():
            return int(str(arguments[0]).strip())
        if function == "bool" and len(arguments) == 1:
            if isinstance(arguments[0], bool):
                return arguments[0]
            if str(arguments[0]).lower() in ("true", "false"):
                return str(arguments[0]).lower() == "true"
        if function == "equals" and len(arguments) == 2:
            return arguments[0] == arguments[1]
        if function == "not" and len(arguments) == 1 and isinstance(arguments[0], bool):
            return not arguments[0]
        if function in ("and", "or") and arguments and all(isinstance(a, bool) for a in arguments):
            return all(arguments) if function == "and" else any(arguments)
        if function == "if" and len(arguments) == 3 and isinstance(arguments[0], bool):
            return arguments[1] if arguments[0] else arguments[2]
        if function in ("add", "sub", "mul") and len(arguments) == 2 and all(isinstance(a, int) and not isinstance(a, bool) for a in arguments):
            a, b = arguments
            return a + b if function == "add" else a - b if function == "sub" else a * b
        if function == "length" and len(arguments) == 1 and isinstance(arguments[0], (list, str, dict)):
            return len(arguments[0])
        if function == "empty" and len(arguments) == 1 and isinstance(arguments[0], (list, str, dict)):
            return not arguments[0]
        if function == "createarray":
            return list(arguments)
        raise _Unknown()

    def deep_strict(self, value: Any, context: Dict[str, int]) -> Any:
        """A default value or variable, all of it worked out (or _Unknown)."""
        if isinstance(value, dict):
            return {k: self.deep_strict(v, context) for k, v in value.items()}
        if isinstance(value, list):
            return [self.deep_strict(v, context) for v in value]
        return self.evaluate(value, context)


class _Reader:
    """Reads one expression: a literal or a function call, then [index] and .property."""

    def __init__(self, template: _Template, tokens: List[Tuple[str, str, str, str]], context: Dict[str, int], names: bool) -> None:
        self.template, self.tokens, self.context, self.names = template, tokens, context, names
        self.position = 0

    def _peek(self) -> str:
        return self.tokens[self.position][3] if self.position < len(self.tokens) else ""

    def _take(self, symbol: str) -> None:
        if self._peek() != symbol:
            raise _Unknown()
        self.position += 1

    def expression(self) -> Any:
        if self.position >= len(self.tokens):
            raise _Unknown()
        string, number, word, _ = self.tokens[self.position]
        self.position += 1
        if string:
            value: Any = string[1:-1].replace("''", "'")
        elif number:
            value = int(number)
        elif word and self._peek() == "(":
            self.position += 1
            arguments: List[Any] = []
            if self._peek() == ")":
                self.position += 1
            else:
                while True:
                    arguments.append(self.expression())
                    if self._peek() == ",":
                        self.position += 1
                        continue
                    self._take(")")
                    break
            value = self.template.call(word, arguments, self.context, self.names)
        elif word.lower() in ("true", "false"):
            value = word.lower() == "true"
        else:
            raise _Unknown()
        while self._peek() in ("[", "."):
            if self._peek() == "[":
                self.position += 1
                index = self.expression()
                self._take("]")
                value = _index(value, index)
            else:
                self.position += 1
                if self.position >= len(self.tokens) or not self.tokens[self.position][2]:
                    raise _Unknown()
                value = _index(value, self.tokens[self.position][2])
                self.position += 1
        return value


def _index(value: Any, index: Any) -> Any:
    if isinstance(value, list) and isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(value):
        return value[index]
    if isinstance(value, dict) and isinstance(index, str):
        for key, item in value.items():
            if str(key).lower() == index.lower():
                return item
    raise _Unknown()


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (str, int)):
        return str(value)
    raise _Unknown()


def _is_expression(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("[") and value.endswith("]") and not value.startswith("[[")


class _Collector:
    def __init__(self) -> None:
        self.found = _Found()
        self.counter = 0
        self.by_id: Dict[str, _Nsg] = {}

    def walk(self, node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                self.walk(item)
            return
        if not isinstance(node, dict):
            return
        schema = str(node.get("$schema") or "")
        if "deploymentTemplate" in schema and isinstance(node.get("resources"), (list, dict)):
            self.found.templates += 1
            if isinstance(node["resources"], dict):
                raise ParseError("a template with symbolic resource names (languageVersion 2.0) is not read; export the deployed "
                                 "groups with az network nsg list instead")  # fmt: skip
            children: List[Tuple[Dict[str, Any], bool, str]] = []
            self.template(node["resources"], _Template(node), "", {}, children)
            for child, unsure, parent in children:
                self.child_rule(_flat(child), parent, unsure)
            return
        if isinstance(node.get("template"), dict):
            self.walk(node["template"])
            return
        data = node.get("data")
        if isinstance(data, dict) and "rows" in data and "columns" in data:
            raise ParseError("a Resource Graph answer in the table format; ask for objects (az graph query does, the REST API "
                             "with resultFormat objectArray)")  # fmt: skip
        if isinstance(data, list) and any(k in node for k in ("count", "totalRecords", "total_records")):  # Resource Graph
            total = node.get("total_records", node.get("totalRecords"))
            count = node.get("count", len(data))
            more = isinstance(total, int) and isinstance(count, int) and not isinstance(total, bool) and total > count
            if more or node.get("skip_token") or node.get("$skipToken") or node.get("skipToken") or \
                    str(node.get("resultTruncated", "")).lower() == "true":  # fmt: skip
                self.found.truncated = True
            self.walk(data)
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
        if kind == _NSG or (not kind and "securityRules" in flat and "priority" not in flat):
            self.nsg(flat)
        elif kind == _NIC or (not kind and "ipConfigurations" in flat):
            self.found.interfaces_given = True
            self.found.interfaces.append(flat)
        elif kind == _ASG:
            self.found.asgs[str(flat.get("id", "")).lower()] = flat
        elif kind == _VNET or (not kind and "addressSpace" in flat):
            peers = []
            for peering in _dicts(flat.get("virtualNetworkPeerings")):
                remote = peering.get("remoteVirtualNetwork")
                state = str(peering.get("peeringState") or "connected").lower()
                if isinstance(remote, dict) and remote.get("id") and state == "connected":
                    peers.append(str(remote["id"]).lower())
            if flat.get("id"):
                self.found.vnets[str(flat["id"]).lower()] = peers
            for subnet in _dicts(flat.get("subnets")):
                self.found.subnets[str(subnet.get("id", "")).lower()] = subnet
        elif kind == _SUBNET or (not kind and "/subnets/" in str(flat.get("id", "")) and ("addressPrefix" in flat or "addressPrefixes" in flat)):
            self.found.subnets[str(flat.get("id", "")).lower()] = flat
        elif kind == "microsoft.resources/deployments" and _NSG in json.dumps(flat, default=str).lower():
            raise ParseError("a nested deployment with network security groups in it is not read; export the deployed groups "
                             "with az network nsg list instead")  # fmt: skip

    def template(self, resources: List[Any], reader: _Template, parent: str, context: Dict[str, int],
                 children: List[Tuple[Dict[str, Any], bool, str]]) -> None:  # fmt: skip
        """The resources of a template, worked out: groups now, their child rules (top level or nested) once every
        group is known."""
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            for instance, unsure in reader.instances(resource, context):
                kind = _kind(instance)
                if kind in _RULE_TYPES:
                    children.append((instance, unsure, parent))
                elif kind == _NSG:
                    name = self.nsg(_flat(instance), unsure)
                    if isinstance(instance.get("resources"), list):
                        self.template(instance["resources"], reader, name, instance.get("_context", {}), children)
                else:
                    self.walk({k: v for k, v in instance.items() if k not in ("resources", "_context")})

    def nsg(self, node: Dict[str, Any], unsure: bool = False) -> str:
        name = str(node.get("name") or "") or _last(str(node.get("id", "nsg")))
        if _is_expression(name):
            raise ParseError(f"the name of a network security group is a template expression that is not worked out: {name[:80]}")
        ident = str(node.get("id") or "") or f"/networkSecurityGroups/{name}"
        group = _Nsg(name, ident, order=self.counter)
        self.counter += 1
        if isinstance(node.get("securityRules"), str):
            raise ParseError(f"the rules of group {name} are a template expression that is not worked out: "
                             f"{str(node['securityRules'])[:80]}")  # fmt: skip
        for rule in _dicts(node.get("securityRules")):
            if _is_expression(rule.get("name")):
                raise ParseError(f"the name of a rule of group {name} is a template expression that is not worked out")
            group.rules.append(rule)
        group.defaults = _dicts(node.get("defaultSecurityRules"))
        group.subnets = [str(s.get("id", "")) for s in _dicts(node.get("subnets"))]
        group.interfaces = [str(s.get("id", "")) for s in _dicts(node.get("networkInterfaces"))]
        key = (ident or name).lower()
        if key in self.by_id:
            return self.by_id[key].name  # (the same group twice: the first one counts)
        if unsure:
            self.found.conditional.append(name)
        self.by_id[key] = group
        self.by_id.setdefault(name.lower(), group)
        self.found.nsgs.append(group)
        return name

    def child_rule(self, rule: Dict[str, Any], parent: str, unsure: bool) -> None:
        full = str(rule.get("name") or "")
        if _is_expression(full):
            raise ParseError(f"the name of a rule of a template is an expression that is not worked out: {full[:80]}")
        if parent and "/" not in full:
            full = f"{parent}/{full}"
        owner, _, name = full.rpartition("/")
        group = self.by_id.get(owner.lower())
        if group is None:
            group = _Nsg(owner or "nsg", f"/networkSecurityGroups/{owner}", order=self.counter)
            self.counter += 1
            self.by_id[owner.lower()] = group
            self.found.nsgs.append(group)
        same = [r for r in group.rules if str(r.get("name", "")).lower() == name.lower()]
        rule = dict(rule, name=name)
        if unsure:
            rule["_conditional"] = True
        if not same:
            group.rules.append(rule)
        elif any(_rule_key(r) != _rule_key(rule) for r in same):
            group.rules.append(dict(rule, _conflict=True))


def _rule_key(rule: Dict[str, Any]) -> str:
    keys = ("protocol", "access", "direction", "priority", "sourceAddressPrefix", "sourceAddressPrefixes", "destinationAddressPrefix",
            "destinationAddressPrefixes", "sourcePortRange", "sourcePortRanges", "destinationPortRange", "destinationPortRanges")  # fmt: skip
    return json.dumps({k: rule.get(k) for k in keys if rule.get(k) not in (None, [], "")}, sort_keys=True, default=str).lower()


def parse(data: bytes, report: Report) -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    try:
        collector = _Collector()
        collector.walk(document)
        if not collector.found.nsgs:
            raise ParseError("no network security groups found; expected the JSON of 'az network nsg list' (or show, a template "
                             "export, or the REST API), alone or in a JSON array with the other answers")  # fmt: skip
        return _Builder(collector.found, report).build()
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None


# A side of a rule: ANY, None (nothing), a list of intervals (known), or the name of an address group whose addresses
# only Azure knows.
Side = Any
_NOTHING = "\0nothing"


@dataclass
class _AzRule:
    nsg: str
    zone: str
    name: str
    direction: str
    priority: int
    allow: bool
    sources: List[str]  # the members as the model has them (ANY, literals, group names)
    destinations: List[str]
    services: List[str]
    service_set: Optional[regions.Services]
    problems: List[str]
    default: bool
    ident: str
    description: str
    order: int


class _Builder:
    def __init__(self, found: _Found, report: Report) -> None:
        self.found, self.report = found, report
        self.p = Policy(vendor="azure")
        self.taken: Set[str] = set()
        self.taken_services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.zones: Dict[str, str] = {}  # nsg key -> zone
        self.outside = "outside"
        self.groups: Dict[str, str] = {}  # tag or asg key -> address group
        self.services: Dict[str, Tuple[List[str], Optional[regions.Services], str]] = {}
        self.asg_members: Dict[str, List[str]] = {}
        self.dynamic: Set[str] = set()
        self.added_defaults: List[str] = []
        self.equal: List[str] = []
        self.composed = 0
        self.capped: List[str] = []
        self.wider: List[str] = []
        self.asg_found: Set[str] = set()  # application security groups whose members are the interfaces of the export
        self.asg_deny: Set[str] = set()  # ... named by a deny rule
        self.any_before: List[str] = []  # an allow rule for ESP or AH after a deny rule '*'
        self.unpeered: List[str] = []
        self.peering_unknown: List[str] = []

    @staticmethod
    def _unique(name: str, taken: Set[str]) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate.lower() in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def build(self) -> Policy:
        self._associate()
        self._members()
        names: Set[str] = {ANY, APP_DEFAULT}
        for nsg in self.found.nsgs:
            zone = self._unique(nsg.name, names)
            self.zones[nsg.ident.lower()] = zone
            self.p.zones[zone] = Zone(zone)
        self.outside = self._unique("outside", names)
        self.p.zones[self.outside] = Zone(self.outside)
        lists: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for nsg in self.found.nsgs:
            lists[nsg.ident.lower()] = self._lists(nsg)
        for nsg in self.found.nsgs:
            zone, own = self.zones[nsg.ident.lower()], lists[nsg.ident.lower()]
            for raw in own["Inbound"]:
                self._plain(nsg, zone, raw, inbound=True)
            for raw in own["Outbound"]:
                self._plain(nsg, zone, raw, inbound=False)
        for sender in self.found.nsgs:
            for receiver in self.found.nsgs:
                if not self._routed(sender, receiver):
                    continue
                self._compose(sender, receiver, lists[sender.ident.lower()]["Outbound"], lists[receiver.ident.lower()]["Inbound"])
        self._notes()
        return self.p

    # -- members of application security groups, and the networks of each group ----------------

    def _associate(self) -> None:
        """The subnets and interfaces of each group, also where only the subnet or the interface names it."""
        exact = {nsg.ident.lower(): nsg for nsg in self.found.nsgs}
        names: Dict[str, List[_Nsg]] = {}
        for nsg in self.found.nsgs:
            names.setdefault(nsg.name.lower(), []).append(nsg)

        def owner(reference: Any) -> Optional[_Nsg]:
            if not isinstance(reference, dict) or not reference.get("id"):
                return None
            ident = str(reference["id"]).lower()
            if ident in exact:
                return exact[ident]
            same = names.get(_last(ident), [])
            # (a group of a template has no full id: its name is enough when only one group has it)
            return same[0] if len(same) == 1 and not same[0].ident.lower().startswith("/subscriptions/") else None

        for ident, subnet in self.found.subnets.items():
            group = owner(subnet.get("networkSecurityGroup"))
            if group is not None and ident not in {i.lower() for i in group.subnets}:
                group.subnets.append(str(subnet.get("id", "")))
        for interface in self.found.interfaces:
            group = owner(interface.get("networkSecurityGroup"))
            ident = str(interface.get("id", ""))
            if group is not None and ident and ident.lower() not in {i.lower() for i in group.interfaces}:
                group.interfaces.append(ident)

    def _vnets(self, nsg: _Nsg) -> Set[str]:
        """The virtual networks of the resources behind a group (by the ids of their subnets)."""
        subnets = [i.lower() for i in nsg.subnets]
        wanted = {i.lower() for i in nsg.interfaces}
        for interface in self.found.interfaces:
            if str(interface.get("id", "")).lower() in wanted:
                for config in _dicts(interface.get("ipConfigurations")):
                    if isinstance(config.get("subnet"), dict):
                        subnets.append(str(config["subnet"].get("id", "")).lower())
        return {found.group(1) for found in (re.match(r"(.*/virtualnetworks/[^/]+)/subnets/", i) for i in subnets) if found}

    def _routed(self, sender: _Nsg, receiver: _Nsg) -> bool:
        """Whether resources behind two groups reach each other on their private addresses: in one virtual network, or
        in two that are peered. When the export says neither, nothing passes between them that the rules of the two decide
        together (traffic through public addresses is from outside)."""
        if sender is receiver:
            return True
        mine, theirs = self._vnets(sender), self._vnets(receiver)
        if not mine or not theirs or mine & theirs:
            return True
        label = f"{sender.name} to {receiver.name}"
        if any(b in self.found.vnets.get(a, []) or a in self.found.vnets.get(b, []) for a in mine for b in theirs):
            return True
        if all(v in self.found.vnets for v in mine | theirs):
            self.unpeered.append(label)
            return False
        self.peering_unknown.append(label)
        return True

    def _members(self) -> None:
        for interface in self.found.interfaces:
            for config in _dicts(interface.get("ipConfigurations")):
                address = str(config.get("privateIPAddress") or "")
                length = config.get("privateIPAddressPrefixLength")
                text = f"{address}/{length}" if address and length not in (None, "") and "/" not in address else address
                if parse_literal(text) is None:
                    continue
                for asg in _dicts(config.get("applicationSecurityGroups")):
                    self.asg_members.setdefault(str(asg.get("id", "")).lower(), []).append(text)
        for ident, members in self.asg_members.items():
            self.asg_members[ident] = [interval_text(i) for i in normalize([i for i in (parse_literal(m) for m in members) if i is not None])]

    def _networks(self, nsg: _Nsg) -> List[str]:
        out: List[str] = []
        for ident in nsg.subnets:
            subnet = self.found.subnets.get(ident.lower())
            if subnet:
                out += [str(p) for p in _list(subnet.get("addressPrefix")) + _list(subnet.get("addressPrefixes"))]
        for interface in self.found.interfaces:
            if str(interface.get("id", "")).lower() in {i.lower() for i in nsg.interfaces}:
                out += [str(c.get("privateIPAddress")) for c in _dicts(interface.get("ipConfigurations")) if c.get("privateIPAddress")]
        return transform.dedupe(out)

    # -- the lists of a group -----------------------------------------------------------------

    def _lists(self, nsg: _Nsg) -> Dict[str, List[Dict[str, Any]]]:
        rules = list(nsg.rules)
        defaults = nsg.defaults
        if not defaults:
            defaults = [{"name": n, "direction": d, "priority": p, "sourceAddressPrefix": s, "destinationAddressPrefix": t, "access": a,
                         "protocol": "*", "sourcePortRange": "*", "destinationPortRange": "*", "_added": True}
                        for n, d, p, s, t, a in _DEFAULTS]  # fmt: skip
            self.added_defaults.append(nsg.name)
        out: Dict[str, List[Dict[str, Any]]] = {"Inbound": [], "Outbound": []}
        for index, raw in enumerate(rules):
            raw = dict(raw, _order=index)
            direction = str(raw.get("direction", "")).capitalize()
            if direction not in out:
                raw["_problem"] = f"direction '{str(raw.get('direction'))[:20]}' cannot be read"
                direction = "Inbound"  # (written as a rule that is not converted, in the inbound list)
            out[direction].append(raw)
        for direction, items in out.items():
            items.sort(key=lambda r: (_priority(r), r["_order"]))
            deny_any = ""
            for raw in items:
                protocol, access = str(raw.get("protocol") or "").lower(), str(raw.get("access") or "").lower()
                if access == "deny" and protocol in ("*", "any") and not deny_any:
                    deny_any = str(raw.get("name"))
                elif deny_any and access == "allow" and protocol in ("esp", "ah"):
                    self.any_before.append(f"{nsg.name}: {raw.get('name')} after {deny_any} ({direction.lower()})")
            seen: Dict[int, str] = {}
            for raw in items:
                number = _priority(raw)
                if number in seen:
                    self.equal.append(f"{nsg.name}: {seen[number]} and {raw.get('name')} ({direction.lower()}, {number})")
                seen[number] = str(raw.get("name"))
            items += [dict(d, _default=True) for d in defaults if str(d.get("direction", "")).capitalize() == direction]
            items.sort(key=lambda r: (bool(r.get("_default")), _priority(r), r.get("_order", 0)))
        return out

    # -- sides and services -------------------------------------------------------------------

    def _side(self, raw: Dict[str, Any], prefix: str, own: bool, problems: List[str]) -> List[str]:
        """The members of one side of a rule. ``own``: the side of the group's own resources."""
        single = raw.get(f"{prefix}AddressPrefix")
        several = [p for p in _list(raw.get(f"{prefix}AddressPrefixes")) if p not in (None, "")]
        asgs = _dicts(raw.get(f"{prefix}ApplicationSecurityGroups"))
        given = [kind for kind, value in (("prefix", single not in (None, "")), ("prefixes", bool(several)), ("asg", bool(asgs))) if value]
        if not given:
            problems.append(f"no {prefix} address")
            return [ANY]
        if len(given) > 1:
            problems.append(f"the {prefix} side holds {' and '.join(given)} together")
            return [ANY]
        out: List[str] = []
        for value in ([single] if single not in (None, "") else several):
            text = str(value).strip()
            member = self._value(text, own, problems, prefix)
            if member == ANY:
                return [ANY]
            if member != _NOTHING:
                out.append(member)
        for asg in asgs:
            out.append(self._asg(str(asg.get("id", ""))))
        return out or [_NOTHING]

    def _value(self, text: str, own: bool, problems: List[str], prefix: str) -> str:
        lowered = text.lower()
        if lowered in ("*", "any"):
            return ANY
        interval = parse_literal(text)
        if interval is not None and (re.search(r"[.:]", text)):
            return interval_text(interval)
        tag = re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*", text) is not None
        if tag and own:
            # Every resource behind a group is in its virtual network; none is the internet, an Azure service or the host
            # that sends the load balancer's probes.
            return ANY if lowered == "virtualnetwork" else _NOTHING
        if lowered == "azureloadbalancer":
            return self._tag("AzureLoadBalancer", [_LOAD_BALANCER])
        if tag:
            known = self.found.tags.get(lowered)
            return self._tag(self.found.tag_names.get(lowered, text), known)
        problems.append(f"{prefix} address '{text[:60]}' cannot be read")
        return ANY

    def _tag(self, name: str, prefixes: Optional[List[str]]) -> str:
        key = "tag:" + name.lower()
        if key in self.groups:
            return self.groups[key]
        group_name = self._unique(name, self.taken)
        group = AddressGroup(group_name, description=f"service tag {name}", builtin="azure")
        good = [interval_text(i) for i in (parse_literal(p) for p in prefixes or []) if i is not None] if prefixes is not None else []
        if prefixes is not None and good:
            group.members = good
            if name != "AzureLoadBalancer":
                group.description += f" (the addresses of the service tags of change {self.found.tags_version or '?'})"
        else:
            group.dynamic_filter = "azure-tag:" + name
            self.dynamic.add(name)
        self.p.address_groups[group_name] = group
        self.groups[key] = group_name
        return group_name

    def _asg(self, ident: str) -> str:
        key = "asg:" + ident.lower()
        if key in self.groups:
            return self.groups[key]
        name = self._unique(_last(ident) or "asg", self.taken)
        group = AddressGroup(name, description=f"application security group {ident}")
        members = self.asg_members.get(ident.lower())
        if members:
            group.members = list(members)
            self.asg_found.add(name)
        elif self.found.interfaces_given:
            group.members = []
            group.unsupported = "no network interface of the export is a member"
        else:
            group.dynamic_filter = "azure-asg:" + ident
            self.dynamic.add(name)
        self.p.address_groups[name] = group
        self.groups[key] = name
        return name

    def _service(self, raw: Dict[str, Any], problems: List[str]) -> Tuple[List[str], Optional[regions.Services]]:
        protocol = str(raw.get("protocol") or "").strip()
        lowered = protocol.lower()
        destination = self._ports(raw, "destination", problems)
        source = self._ports(raw, "source", problems)
        if destination is None or source is None:
            return [ANY], None
        deny = str(raw.get("access") or "").lower() == "deny"
        key = json.dumps([lowered, destination, source, deny and lowered in ("*", "any")])
        if key in self.services:
            names, found, problem = self.services[key]
            if problem:
                problems.append(problem)
            return names, found
        entries: List[ServiceEntry] = []
        problem = ""
        if lowered in ("tcp", "udp"):
            entries = [ServiceEntry(Protocol(lowered), dst_ports=destination, src_ports=source)]
            label = f"{lowered}-{destination or 'all'}" + (f"-from-{source}" if source else "")
        elif lowered in ("icmp", "esp", "ah"):
            if destination or source:
                problem = f"ports with protocol {protocol}, which mean nothing documented"
            entries = [ServiceEntry(Protocol.ICMP)] if lowered == "icmp" else [ServiceEntry(Protocol.IP, ip_protocol=50 if lowered == "esp" else 51)]
            label = lowered
        elif lowered in ("*", "any"):
            # Microsoft documents "*" as TCP, UDP and ICMP. With ports it says nothing of ICMP: an allow rule allows TCP and
            # UDP on them, a deny rule blocks ICMP as well.
            entries = [ServiceEntry(Protocol.TCP, dst_ports=destination, src_ports=source),
                       ServiceEntry(Protocol.UDP, dst_ports=destination, src_ports=source)]  # fmt: skip
            if (not destination and not source) or deny:
                entries.append(ServiceEntry(Protocol.ICMP))
            label = "tcp-udp-icmp" if not destination and not source else f"tcp-udp-{destination or 'all'}" + (f"-from-{source}" if source else "")
            if (destination or source) and deny:
                label += "-icmp"
        else:
            problem = f"protocol '{protocol[:20]}' cannot be read"
            label = ""
        if problem:
            problems.append(problem)
            self.services[key] = ([ANY], None, problem)
            return [ANY], None
        name = self._unique(label, self.taken_services)
        self.p.services[name] = Service(name, entries)
        found = regions.service_set(entries)
        self.services[key] = ([name], found, "")
        return [name], found

    @staticmethod
    def _ports(raw: Dict[str, Any], side: str, problems: List[str]) -> Optional[str]:
        single = raw.get(f"{side}PortRange")
        several = [p for p in _list(raw.get(f"{side}PortRanges")) if p not in (None, "")]
        values = [single] if single not in (None, "") else several
        if single not in (None, "") and several:
            problems.append(f"{side} ports given twice")
            return None
        if not values:
            return ""  # (no ports: the schema does not require them; Azure fills in '*')
        parts: List[str] = []
        for value in values:
            for text in str(value).replace(" ", "").split(","):
                if text in ("*", "any", "Any"):
                    return ""
                first, _, last = text.partition("-")
                if not first.isdigit() or not (last or first).isdigit() or int(first) > int(last or first) or int(last or first) > 65535:
                    problems.append(f"{side} port '{text[:20]}' cannot be read")
                    return None
                parts.append(text)
        return ",".join(transform.dedupe(parts))

    # -- rules ----------------------------------------------------------------------------

    def _read(self, nsg: _Nsg, zone: str, raw: Dict[str, Any], inbound: bool, both_own: bool = False) -> _AzRule:
        problems: List[str] = [str(raw["_problem"])] if raw.get("_problem") else []
        if raw.get("_conflict"):
            problems.append("the template holds this rule twice, and the two differ")
        access = str(raw.get("access") or "").lower()
        if access not in ("allow", "deny"):
            problems.append(f"access '{str(raw.get('access'))[:20]}' cannot be read")
        if not raw.get("_default"):
            number = _priority_value(raw.get("priority"))
            if raw.get("priority") is None:
                problems.append("a rule without a priority")
            elif number is None:
                problems.append(f"priority '{str(raw.get('priority'))[:40]}' cannot be read")
            elif not 100 <= number <= 4096:
                problems.append(f"priority {number} is not one Azure allows (100 to 4096)")
        if raw.get("_conditional"):
            problems.append("the template deploys this rule only under a condition that is not worked out here")
        sources = self._side(raw, "source", not inbound or both_own, problems)
        destinations = self._side(raw, "destination", inbound or both_own, problems)
        services, found = self._service(raw, problems)
        if access == "deny":
            self.asg_deny.update(m for m in sources + destinations if m in self.asg_found)
        return _AzRule(nsg.name, zone, str(raw.get("name") or "rule"), "Inbound" if inbound else "Outbound", _priority(raw),
                       access == "allow", sources, destinations, services, found, problems, bool(raw.get("_default")),
                       str(raw.get("id") or ""), str(raw.get("description") or ""), int(raw.get("_order", 0)))  # fmt: skip

    def _emit(self, base: str, rule: _AzRule, src_zone: str, dst_zone: str, sources: List[str], destinations: List[str],
              services: List[str], allow: bool, problems: List[str]) -> Rule:  # fmt: skip
        out = Rule(self._unique(base, self.rule_names), src_zones=[src_zone], dst_zones=[dst_zone], sources=sources,
                   destinations=destinations, services=services, action=Action.ALLOW if allow else Action.DENY)  # fmt: skip
        out.origin = out.name
        out.log_end = False
        out.description = rule.description
        out.unsupported = list(dict.fromkeys(problems))
        out.source_ids = {"azure.nsg": rule.nsg, "azure.name": rule.name, "azure.direction": rule.direction,
                          "azure.priority": str(rule.priority) if rule.priority < 1 << 30 else "?"}  # fmt: skip
        if rule.ident:
            out.source_ids["azure.id"] = rule.ident
        self.p.rules.append(out)
        return out

    def _plain(self, nsg: _Nsg, zone: str, raw: Dict[str, Any], inbound: bool) -> None:
        rule = self._read(nsg, zone, raw, inbound)
        if _NOTHING in rule.sources or _NOTHING in rule.destinations:
            return  # (Internet on the group's own side: no resource behind it)
        base = f"{nsg.name}:{rule.name}"
        self._emit(base, rule, self.outside if inbound else zone, zone if inbound else self.outside, rule.sources, rule.destinations,
                   rule.services, rule.allow, rule.problems)  # fmt: skip

    def _compose(self, sender: _Nsg, receiver: _Nsg, outbound: List[Dict[str, Any]], inbound: List[Dict[str, Any]]) -> None:
        """Traffic from the resources behind one group to those behind another (or the same): its outbound rules, and for
        each that allows, the inbound rules of the other cut to it."""
        src_zone, dst_zone = self.zones[sender.ident.lower()], self.zones[receiver.ident.lower()]
        outs = [self._read(sender, src_zone, raw, False, both_own=True) for raw in outbound]
        ins = [self._read(receiver, dst_zone, raw, True, both_own=True) for raw in inbound]
        count = 0
        label = f"{sender.name} to {receiver.name}"
        for out_rule in outs:
            if _NOTHING in out_rule.sources or _NOTHING in out_rule.destinations:
                continue
            if not out_rule.allow:
                self._emit(f"{sender.name}:{out_rule.name} to {receiver.name}", out_rule, src_zone, dst_zone, out_rule.sources,
                           out_rule.destinations, out_rule.services, False, out_rule.problems)  # fmt: skip
                count += 1
                continue
            for in_rule in ins:
                if _NOTHING in in_rule.sources or _NOTHING in in_rule.destinations:
                    continue
                if count >= _MAX_COMPOSED:
                    self.capped.append(label)
                    blocker = Rule(self._unique(f"{label}: the rest", self.rule_names), src_zones=[src_zone], dst_zones=[dst_zone],
                                   action=Action.DENY)  # fmt: skip
                    blocker.origin = blocker.name
                    blocker.description = "more combinations of outbound and inbound rules than are converted: the rest is blocked"
                    self.p.rules.append(blocker)
                    self.composed += count
                    return
                combined = self._both(out_rule, in_rule)
                if combined is None:
                    continue
                sources, destinations, services, problems, wider = combined
                rule = self._emit(f"{sender.name}:{out_rule.name}+{receiver.name}:{in_rule.name}", in_rule, src_zone, dst_zone, sources,
                                  destinations, services, in_rule.allow, problems)  # fmt: skip
                rule.source_ids["azure.outbound"] = f"{sender.name}:{out_rule.name}"
                if wider:
                    self.wider.append(rule.name)
                    self.report.add("rule", rule.origin, Severity.APPROX, "AZURE_COMPOSED_WIDER",
                                    f"a deny rule of {receiver.name} cut to an allow rule of {sender.name}: the cut cannot be worked out "
                                    "(a service tag or an application security group on both), so the converted rule blocks all "
                                    "the deny rule blocks, which is more")  # fmt: skip
                count += 1
        self.composed += count

    def _both(self, out_rule: _AzRule, in_rule: _AzRule) -> Optional[Tuple[List[str], List[str], List[str], List[str], bool]]:
        """The connections both rules match: (sources, destinations, services, problems, made wider); None if none."""
        problems = out_rule.problems + in_rule.problems
        wider = False
        cells: List[List[str]] = []
        for a, b in ((out_rule.sources, in_rule.sources), (out_rule.destinations, in_rule.destinations)):
            cell = self._cut(a, b)
            if cell is None:  # (the cut cannot be read)
                if in_rule.allow:
                    problems = problems + [f"its cut with outbound rule {out_rule.name} cannot be worked out (service tags or "
                                           "application security groups on both)"]  # fmt: skip
                    cell = b
                else:
                    cell, wider = b, True
            if cell == [_NOTHING]:
                return None
            cells.append(cell)
        if out_rule.service_set is None or in_rule.service_set is None:
            services = in_rule.services if out_rule.services == [ANY] else out_rule.services if in_rule.services == [ANY] else in_rule.services
        elif out_rule.services == [ANY] or _same(out_rule.service_set, regions.ALL_SERVICES):
            services = in_rule.services
        else:
            both = out_rule.service_set.and_(in_rule.service_set)
            if both.empty():
                return None
            if _same(both, in_rule.service_set):
                services = in_rule.services
            elif _same(both, out_rule.service_set):
                services = out_rule.services
            else:
                entries = [e for v in (4, 6) for e in (regions.entries_of(both, v) or ([], False))[0]]
                unique: List[ServiceEntry] = []
                for entry in entries:
                    if entry not in unique:
                        unique.append(entry)
                name = self._unique("svc-" + "-".join(e.protocol.value + (e.dst_ports or "") for e in unique[:3]), self.taken_services)
                self.p.services[name] = Service(name, unique)
                services = [name]
        return cells[0], cells[1], services, problems, wider

    def _cut(self, a: List[str], b: List[str]) -> Optional[List[str]]:
        """The addresses on one side of both rules; None when that cannot be worked out here."""
        if a == [ANY]:
            return b
        if b == [ANY]:
            return a
        if _NOTHING in a or _NOTHING in b:
            return [_NOTHING]
        if a == b:
            return a
        left, right = self._intervals(a), self._intervals(b)
        if left is None or right is None:
            return None
        both = intersect(left, right)
        return [interval_text(i) for i in both] if both else [_NOTHING]

    def _intervals(self, members: List[str]) -> Optional[List[Interval]]:
        out: List[Interval] = []
        for member in members:
            found = transform.address_intervals(self.p, member)
            if found is None:
                return None
            out += found
        return normalize(out)

    # -- notes ----------------------------------------------------------------------------

    def _notes(self) -> None:
        self.report.note(Severity.REVIEW if self.any_before else Severity.INFO, "AZURE_ANY_PROTOCOL",
                         "protocol '*' is read as Microsoft documents it: TCP, UDP and ICMP; with ports, an allow rule allows TCP and "
                         "UDP on them and a deny rule blocks ICMP as well. If Azure also matches other protocols with it, a deny rule "
                         "'*' blocks more there than the converted rule" +
                         ("; these allow rules for ESP or AH come after a deny rule '*', and what that rule blocks of them is "
                          "not blocked in the converted policy: " + "; ".join(self.any_before[:8]) if self.any_before else ""))  # fmt: skip
        self.report.note(Severity.INFO, "AZURE_UNFILTERED",
                         "network security groups do not filter the platform's own traffic (168.63.129.16 and 169.254.169.254: "
                         "DHCP, DNS, the instance metadata service, health probes); and the security admin rules of Azure "
                         "Virtual Network Manager, which come first, are not in this export")  # fmt: skip
        zones = []
        for nsg in self.found.nsgs:
            networks = self._networks(nsg)
            if networks:
                zones.append(f"{self.zones[nsg.ident.lower()]}={','.join(networks)}")
        self.report.note(Severity.INFO, "AZURE_ZONES",
                         "each network security group is a zone, and everything else the zone " + self.outside + ". " +
                         (("The networks behind them, for --zone-network: " + " ".join(f"--zone-network {z}" for z in zones))
                          if zones else "The export does not say which networks lie behind them (add the virtual networks and the "
                          "network interfaces); targets that need them want --zone-network"))  # fmt: skip
        if self.composed:
            self.report.note(Severity.INFO, "AZURE_COMPOSED",
                             f"traffic between resources behind the groups passes the outbound rules of one and the inbound rules of "
                             f"the other: {self.composed} rules say what both allow, in the order of the two")  # fmt: skip
        if self.capped:
            self.report.note(Severity.REVIEW, "AZURE_COMPOSED_LEFT_OUT",
                             "for these pairs of groups not every combination of outbound and inbound rules was converted; the "
                             "rest is blocked: " + ", ".join(transform.dedupe(self.capped)))  # fmt: skip
        if self.added_defaults:
            self.report.note(Severity.INFO, "AZURE_DEFAULT_RULES_ADDED",
                             "the export does not list the default rules of these groups (a template never does); the six rules "
                             "every group has were added: " + ", ".join(self.added_defaults))  # fmt: skip
        if self.equal:
            self.report.note(Severity.REVIEW, "AZURE_EQUAL_PRIORITY",
                             "rules of one direction with the same priority, which Azure does not allow; they were read in the order "
                             "of the export: " + "; ".join(self.equal[:8]))  # fmt: skip
        if self.dynamic:
            self.report.note(Severity.REVIEW, "AZURE_DYNAMIC",
                             "service tags and application security groups whose addresses only Azure knows: " +
                             ", ".join(sorted(self.dynamic)) + ". They are dynamic groups, which only an Azure target writes again; "
                             "add the service tags (az network list-service-tags) and the network interfaces to the export to "
                             "convert them for other targets")  # fmt: skip
        if self.found.conditional:
            self.report.note(Severity.REVIEW, "AZURE_TEMPLATE_CONDITION",
                             "the template deploys these groups only under a condition that is not worked out here; they were read "
                             "as deployed: " + ", ".join(self.found.conditional[:8]))  # fmt: skip
        if self.asg_found:
            self.report.note(Severity.REVIEW if self.asg_deny else Severity.INFO, "AZURE_ASG_MEMBERS",
                             "the members of these application security groups are the network interfaces in the export: " +
                             ", ".join(sorted(self.asg_found)) + ". A member whose interface is not in it (another resource group, "
                             "another subscription) is not in the group" +
                             ("; deny rules name " + ", ".join(sorted(self.asg_deny)) + ", which then block less than in Azure"
                              if self.asg_deny else ""))  # fmt: skip
        if self.unpeered:
            self.report.note(Severity.INFO, "AZURE_NOT_PEERED",
                             "the resources behind these groups are in virtual networks that are not peered, so they do not reach "
                             "each other on private addresses and nothing is converted for them (a VPN gateway between the "
                             "networks is not looked at): " + ", ".join(self.unpeered[:8]))  # fmt: skip
        if self.peering_unknown:
            self.report.note(Severity.REVIEW, "AZURE_PEERING_UNKNOWN",
                             "the resources behind these groups are in different virtual networks, and the export does not say "
                             "whether they are peered (add the virtual networks): VirtualNetwork was read as reaching each other: " +
                             ", ".join(self.peering_unknown[:8]))  # fmt: skip
        if self.found.truncated:
            self.report.note(Severity.REVIEW, "AZURE_INCOMPLETE_EXPORT",
                             "an answer says there is more (nextLink, a skip token, more records than it holds): groups that were "
                             "left out are missing")  # fmt: skip
        chained = self._chains()
        if chained:
            self.report.note(Severity.REVIEW, "AZURE_NSG_CHAIN",
                             "these network interfaces have a group of their own and one on their subnet; Azure checks both, the "
                             "converted policy each on its own: " + ", ".join(chained[:8]))  # fmt: skip

    def _chains(self) -> List[str]:
        out: List[str] = []
        subnet_groups = {i.lower() for nsg in self.found.nsgs for i in nsg.subnets}
        for interface in self.found.interfaces:
            own = interface.get("networkSecurityGroup")
            if not isinstance(own, dict) or not own.get("id"):
                continue
            for config in _dicts(interface.get("ipConfigurations")):
                subnet: Dict[str, Any] = config["subnet"] if isinstance(config.get("subnet"), dict) else {}
                if str(subnet.get("id", "")).lower() in subnet_groups:
                    out.append(str(interface.get("name") or _last(str(interface.get("id", "")))))
                    break
        return out


def _priority_value(value: Any) -> Optional[int]:
    """A priority as a number; None when it is not one (an expression, text, a fraction, true)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _priority(raw: Dict[str, Any]) -> int:
    """The place of a rule in its list; a rule whose priority cannot be read comes last (it is not converted)."""
    number = _priority_value(raw.get("priority"))
    return number if number is not None else 1 << 30


def _same(a: regions.Services, b: regions.Services) -> bool:
    return a.minus(b).empty() and b.minus(a).empty()

