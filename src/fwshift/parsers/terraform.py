# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Terraform parser: the resources of a Terraform state or plan -> neutral model, for the AWS and the Azure provider.

What is read: the JSON of ``terraform show -json`` (of the state, or of a saved plan) and the raw state of
``terraform state pull`` (``terraform.tfstate``, version 4). Of the resources of the provider asked for:

* AWS (hashicorp/aws): ``aws_security_group`` and ``aws_default_security_group`` with their inline rules,
  ``aws_security_group_rule``, ``aws_vpc_security_group_ingress_rule`` and ``_egress_rule``, ``aws_network_acl``,
  ``aws_default_network_acl``, ``aws_network_acl_rule`` and ``_association``, ``aws_network_interface``,
  ``aws_network_interface_sg_attachment``, ``aws_instance``, ``aws_subnet``, ``aws_vpc`` and the managed prefix lists.
* Azure (hashicorp/azurerm): ``azurerm_network_security_group`` with its inline rules, ``azurerm_network_security_rule``,
  the associations of a group with subnets and network interfaces, application security groups and their associations,
  ``azurerm_network_interface``, ``azurerm_subnet``, ``azurerm_virtual_network`` (with inline subnets) and its peerings.

The resources are turned into the answers the cloud's own CLI gives for the same things (``describe-security-groups``
and the others for AWS, ``az network nsg list`` and the others for Azure), and those are read by the parser of that
cloud: what the AWS and the Azure parsers say about how the cloud decides holds here as well.

What Terraform adds:

* A group's inline rules are filled from everything the cloud reports after a refresh, so they repeat the rules of the
  separate rule resources (and a network ACL's ``subnet_ids`` its associations). Every rule is taken once.
* A group Terraform created has no outbound rule unless one is declared: Terraform takes away the one AWS adds. The
  state says so (the group has no outbound rule), and so does the model.
* A plan does not know what is not created yet: an id that is not known is the address of the resource, from the
  references of the configuration; what cannot be worked out that way is not read, and said.
* The members of a security group are the interfaces and instances of this state; others are not known.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import Policy
from ..report import Report, Severity
from . import aws as parse_aws
from . import azure as parse_azure

_AWS_GROUPS = ("aws_security_group", "aws_default_security_group")
_AWS_RULES = ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule")
_AWS_ACLS = ("aws_network_acl", "aws_default_network_acl")
# Resource types that filter traffic and are not read: said, so that nobody takes the conversion for all of it.
_NOT_READ = re.compile(r"^(aws_networkfirewall_|aws_wafv2?_|aws_shield|aws_lb_listener_rule|azurerm_firewall|azurerm_web_application_firewall"
                       r"|azurerm_network_manager_|aws_vpc_security_group_vpc_association|aws_route53_resolver_firewall_)")  # fmt: skip
_PROTOCOL_NAMES = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmpv6", "icmp6": "icmpv6", "-1": "-1", "all": "-1",
                   "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "esp": "50", "ah": "51", "gre": "47", "sctp": "132"}  # fmt: skip
_ACL_PROTOCOLS = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58", "icmp6": "58", "all": "-1", "-1": "-1", "esp": "50", "ah": "51",
                  "gre": "47", "sctp": "132"}  # fmt: skip
_MAX_DEPTH = 64  # modules in modules
_MAX_RESOURCES = 200000


def looks_like_terraform(data: bytes) -> bool:
    """The JSON of terraform show -json (a state or a plan), or a raw state."""
    head = data[:262144].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith(b"{"):
        return False
    if re.match(rb'\{\s*"format_version"\s*:', head):
        return True  # (how Terraform writes it; an empty state is no more than that)
    if b'"format_version"' in head and (b'"root_module"' in head or b'"planned_values"' in head or b'"values"' in head):
        return True
    return b'"lineage"' in head and b'"resources"' in head and re.search(rb'"version"\s*:\s*4\b', head) is not None


def providers_of(data: bytes) -> Set[str]:
    """Which of the providers FWShift reads the input holds firewall resources of: "aws", "azure"."""
    out: Set[str] = set()
    managed = rb'"mode"\s*:\s*"managed"\s*,\s*"type"\s*:\s*"'  # (a resource, not a data source: Terraform writes the mode first)
    if re.search(managed + rb'(aws_security_group|aws_default_security_group|aws_network_acl|aws_default_network_acl'
                 rb'|aws_security_group_rule|aws_vpc_security_group_(?:ingress|egress)_rule)"', data):  # fmt: skip
        out.add("aws")
    if re.search(managed + rb'(azurerm_network_security_group|azurerm_network_security_rule)"', data):
        out.add("azure")
    return out


@dataclass
class _Instance:
    type: str
    address: str  # with the index of count or for_each
    base: str  # without it: the address the configuration refers to
    module: str
    values: Dict[str, Any]
    unknown: Set[str] = field(default_factory=set)  # top-level attributes a plan does not know yet


class _State:
    """The managed resources of the input, and for a plan what its configuration refers to."""

    def __init__(self, document: Dict[str, Any]) -> None:
        self.instances: List[_Instance] = []
        self.plan = False
        self.kind = ""
        self.references: Dict[Tuple[str, str], List[str]] = {}  # (base address, attribute) -> addresses referred to
        self.blocks: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}  # (base address, block) -> the expressions of each block
        self.skipped_deposed = 0
        self.actions: Dict[str, List[str]] = {}  # address -> what a plan does with it (create, update, ...)
        self.after_unknown: Dict[str, Dict[str, Any]] = {}  # address -> what a plan does not know of it yet
        self.deleted: List[Tuple[str, Dict[str, Any]]] = []  # (type, the values before) of what a plan deletes or replaces
        self.incomplete = False
        self.version = str(document.get("terraform_version") or "")
        if "format_version" in document:
            major = str(document.get("format_version") or "").split(".")[0]
            if major != "1":
                raise ParseError(f"terraform show -json of format version {str(document.get('format_version'))[:20]}: FWShift reads version 1")
            if "planned_values" in document or "resource_changes" in document:
                self.plan, self.kind = True, "plan"
                if document.get("errored") is True:
                    raise ParseError("the plan failed (errored): what it would do is not complete; fix the configuration and plan again")
                self.incomplete = document.get("complete") is False
                for change in document.get("resource_changes") or []:
                    if not isinstance(change, dict) or not isinstance(change.get("change"), dict) or change.get("mode", "managed") != "managed":
                        continue
                    address, body = str(change.get("address") or ""), change["change"]
                    actions = [str(a) for a in body.get("actions") or [] if isinstance(a, str)]
                    if change.get("deposed"):
                        continue  # (a deposed object: left out, as in a state)
                    self.actions[address] = actions
                    if isinstance(body.get("after_unknown"), dict):
                        self.after_unknown[address] = body["after_unknown"]
                    if "delete" in actions and isinstance(body.get("before"), dict):
                        self.deleted.append((str(change.get("type") or ""), body["before"]))
                values = document.get("planned_values")
                self._module(values.get("root_module") if isinstance(values, dict) else None, 0)
                self._configuration(document.get("configuration"))
            else:
                self.kind = "state"
                values = document.get("values")
                self._module(values.get("root_module") if isinstance(values, dict) else None, 0)
        elif document.get("version") == 4 and isinstance(document.get("resources"), list):
            self.kind = "raw state"
            self._raw(document["resources"])
        else:
            raise ParseError("not the JSON of terraform show -json, nor a raw state of version 4")
        if len(self.instances) > _MAX_RESOURCES:
            raise ParseError(f"more than {_MAX_RESOURCES} resources")

    def _module(self, module: Any, depth: int) -> None:
        if not isinstance(module, dict):
            return
        if depth > _MAX_DEPTH:
            raise ParseError("modules nested too deeply")
        prefix = str(module.get("address") or "")
        for resource in module.get("resources") or []:
            if not isinstance(resource, dict) or resource.get("mode") != "managed":
                continue
            if resource.get("deposed_key"):
                self.skipped_deposed += 1
                continue  # (the object being replaced; the current one is listed too)
            address = str(resource.get("address") or "")
            kind = str(resource.get("type") or "")
            name = str(resource.get("name") or "")
            values: Dict[str, Any] = resource["values"] if isinstance(resource.get("values"), dict) else {}
            base = (prefix + "." if prefix else "") + f"{kind}.{name}"
            instance = _Instance(kind, address or base, base, prefix, dict(values))
            if self.plan:
                unknown = self.after_unknown.get(instance.address, {})
                instance.unknown = {key for key in _KNOWN_ATTRIBUTES.get(kind, ()) if key not in values}
                instance.unknown |= {key for key, value in unknown.items() if _has_true(value)}
            self.instances.append(instance)
        for child in module.get("child_modules") or []:
            self._module(child, depth + 1)

    def _raw(self, resources: List[Any]) -> None:
        for resource in resources:
            if not isinstance(resource, dict) or resource.get("mode") != "managed":
                continue
            module = str(resource.get("module") or "")
            kind, name = str(resource.get("type") or ""), str(resource.get("name") or "")
            base = (module + "." if module else "") + f"{kind}.{name}"
            for instance in resource.get("instances") or []:
                if not isinstance(instance, dict):
                    continue
                if instance.get("deposed"):
                    self.skipped_deposed += 1
                    continue
                key = instance.get("index_key")
                address = base + ("" if key is None else f"[{json.dumps(key)}]")
                attributes: Dict[str, Any] = instance["attributes"] if isinstance(instance.get("attributes"), dict) else {}
                self.instances.append(_Instance(kind, address, base, module, dict(attributes)))

    def _configuration(self, configuration: Any) -> None:
        if isinstance(configuration, dict):
            self._config_module(configuration.get("root_module"), "", 0)

    def _config_module(self, module: Any, prefix: str, depth: int) -> None:
        if not isinstance(module, dict) or depth > _MAX_DEPTH:
            return
        for resource in module.get("resources") or []:
            if not isinstance(resource, dict) or resource.get("mode", "managed") != "managed":
                continue
            base = (prefix + "." if prefix else "") + str(resource.get("address") or "")
            for attribute, expression in (resource.get("expressions") or {}).items():
                if isinstance(expression, dict):
                    self.references[(base, attribute)] = [self._absolute(prefix, r) for r in expression.get("references") or [] if isinstance(r, str)]
                elif isinstance(expression, list):
                    self.blocks[(base, attribute)] = [self._block(prefix, e) for e in expression if isinstance(e, dict)]
        for name, call in (module.get("module_calls") or {}).items():
            if isinstance(call, dict):
                self._config_module(call.get("module"), (prefix + "." if prefix else "") + f"module.{name}", depth + 1)

    def _block(self, prefix: str, expressions: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for attribute, expression in expressions.items():
            if isinstance(expression, dict) and "constant_value" in expression:
                out[attribute] = expression["constant_value"]
            elif isinstance(expression, dict):
                out[attribute] = _Refs(self._absolute(prefix, r) for r in expression.get("references") or [] if isinstance(r, str))
            elif isinstance(expression, list):
                out[attribute] = _Refs()  # (a block in a block: not read)
        return out

    def expressions(self, instance: "_Instance", key: str) -> Tuple[Optional[List[str]], Optional[List[Dict[str, Any]]]]:
        """The references and the blocks the configuration writes for an attribute of an instance (a module with count or
        for_each is one configuration for all its instances)."""
        bases = [instance.base, re.sub(r"\[[^\]]*\]", "", instance.module) + instance.base[len(instance.module):]]
        for base in bases:
            if (base, key) in self.references or (base, key) in self.blocks:
                return self.references.get((base, key)), self.blocks.get((base, key))
        return None, None

    @staticmethod
    def _absolute(prefix: str, reference: str) -> str:
        if reference.startswith(("var.", "local.", "each.", "count.", "path.", "terraform.", "data.", "module.")) or not prefix:
            return reference
        return f"{prefix}.{reference}"


# The attributes of each type that refer to other resources, or hold rules: in a plan, one of them missing is not known yet.
_KNOWN_ATTRIBUTES: Dict[str, Tuple[str, ...]] = {
    "aws_security_group": ("id", "vpc_id", "ingress", "egress"), "aws_default_security_group": ("id", "vpc_id", "ingress", "egress"),
    "aws_security_group_rule": ("security_group_id", "source_security_group_id", "cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids", "type",
                                "protocol", "from_port", "to_port", "self"),
    "aws_vpc_security_group_ingress_rule": ("security_group_id", "referenced_security_group_id", "cidr_ipv4", "cidr_ipv6", "prefix_list_id",
                                            "ip_protocol", "from_port", "to_port"),
    "aws_vpc_security_group_egress_rule": ("security_group_id", "referenced_security_group_id", "cidr_ipv4", "cidr_ipv6", "prefix_list_id",
                                           "ip_protocol", "from_port", "to_port"),
    "aws_network_acl": ("id", "vpc_id", "subnet_ids", "ingress", "egress"), "aws_default_network_acl": ("id", "subnet_ids", "ingress", "egress"),
    "aws_network_acl_rule": ("network_acl_id", "cidr_block", "ipv6_cidr_block", "rule_number", "egress", "protocol", "rule_action", "from_port",
                             "to_port", "icmp_type", "icmp_code"), "aws_network_acl_association": ("network_acl_id", "subnet_id"),
    "aws_network_interface": ("id", "subnet_id", "security_groups", "private_ip", "private_ips"),
    "aws_network_interface_sg_attachment": ("security_group_id", "network_interface_id"),
    "aws_instance": ("subnet_id", "vpc_security_group_ids", "private_ip"), "aws_subnet": ("id", "vpc_id", "cidr_block"),
    "aws_vpc": ("id", "cidr_block"), "aws_ec2_managed_prefix_list": ("id",), "aws_ec2_managed_prefix_list_entry": ("prefix_list_id",),
    "azurerm_network_security_group": ("id", "name", "resource_group_name", "security_rule"), "azurerm_application_security_group": ("id",),
    "azurerm_network_security_rule": ("source_application_security_group_ids", "destination_application_security_group_ids", "name", "priority",
                                      "direction", "access", "protocol", "source_port_range", "source_port_ranges", "destination_port_range",
                                      "destination_port_ranges", "source_address_prefix", "source_address_prefixes", "destination_address_prefix",
                                      "destination_address_prefixes", "network_security_group_name", "resource_group_name"),
    "azurerm_subnet_network_security_group_association": ("subnet_id", "network_security_group_id"),
    "azurerm_network_interface_security_group_association": ("network_interface_id", "network_security_group_id"),
    "azurerm_network_interface_application_security_group_association": ("network_interface_id", "application_security_group_id"),
    "azurerm_network_interface": ("id", "ip_configuration"), "azurerm_subnet": ("id", "address_prefixes"),
    "azurerm_virtual_network": ("id", "subnet"), "azurerm_virtual_network_peering": ("remote_virtual_network_id",),
}  # fmt: skip


def parse(data: bytes, report: Report, provider: str = "", vpc: str = "") -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    if not isinstance(document, dict):
        raise ParseError("not the JSON of terraform show -json, nor a raw state: the top is not an object")
    try:
        state = _State(document)
        found = {i.type for i in state.instances}
        if not provider:
            held = ({"aws"} if found & set(_AWS_GROUPS + _AWS_RULES + _AWS_ACLS) else set()) | \
                ({"azure"} if found & {"azurerm_network_security_group", "azurerm_network_security_rule"} else set())  # fmt: skip
            if len(held) != 1:
                raise ParseError(f"the {state.kind} holds resources of AWS and of Azure: read it with --from terraform-aws or --from "
                                 "terraform-azure" if held else f"the {state.kind} holds no security groups (AWS) or network security groups (Azure)")  # fmt: skip
            provider = held.pop()
        wanted = {"aws": set(_AWS_GROUPS + _AWS_RULES), "azure": {"azurerm_network_security_group", "azurerm_network_security_rule"}}
        if not found & wanted.get(provider, set()):
            raise ParseError(f"the {state.kind} holds no " + ("security groups or security group rules of AWS" if provider == "aws" else
                             "network security groups or rules of Azure"))  # fmt: skip
        reader = _Reader(state, report, vpc)
        answers = reader.aws() if provider == "aws" else reader.azure()
        body = json.dumps(answers).encode("utf-8")
        policy = parse_aws.parse(body, report) if provider == "aws" else parse_azure.parse(body, report)
        reader.notes(provider)
        return policy
    except ParseError:
        raise
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"a resource of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None


def _has_true(value: Any) -> bool:
    """Whether an after_unknown value marks anything not known."""
    if value is True:
        return True
    if isinstance(value, list):
        return any(_has_true(v) for v in value)
    if isinstance(value, dict):
        return any(_has_true(v) for v in value.values())
    return False


def _list(value: Any) -> List[Any]:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _text(value: Any) -> str:
    """A text value, or "" for one that is not text or not known."""
    return value.strip() if isinstance(value, str) and not isinstance(value, _Unknown) else ""


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and float(value).is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value.strip())
    return None


class _Refs(list):  # type: ignore[type-arg]
    """The references of an expression of the configuration that is not a constant."""


# Attributes that hold a list: what the references of the configuration stand for is a list.
_PLURAL = {"security_groups", "vpc_security_group_ids", "cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids", "subnet_ids",
           "source_application_security_group_ids", "destination_application_security_group_ids", "address_prefixes",
           "private_ips", "address_space", "secondary_private_ips", "ipv6_addresses", "source_address_prefixes",
           "destination_address_prefixes", "source_port_ranges", "destination_port_ranges"}  # fmt: skip
# The attributes of the blocks a plan may know only in part: one of them missing from a block is not known yet.
_SG_BLOCK = ("protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids", "security_groups", "self")
_ACL_BLOCK = ("rule_no", "action", "protocol", "from_port", "to_port", "cidr_block", "ipv6_cidr_block", "icmp_type", "icmp_code")
_BLOCK_KEYS: Dict[Tuple[str, str], Tuple[str, ...]] = {
    ("aws_security_group", "ingress"): _SG_BLOCK, ("aws_security_group", "egress"): _SG_BLOCK,
    ("aws_default_security_group", "ingress"): _SG_BLOCK, ("aws_default_security_group", "egress"): _SG_BLOCK,
    ("aws_network_acl", "ingress"): _ACL_BLOCK, ("aws_network_acl", "egress"): _ACL_BLOCK,
    ("aws_default_network_acl", "ingress"): _ACL_BLOCK, ("aws_default_network_acl", "egress"): _ACL_BLOCK,
    ("azurerm_network_security_group", "security_rule"): (
        "name", "priority", "direction", "access", "protocol", "source_port_range", "source_port_ranges", "destination_port_range",
        "destination_port_ranges", "source_address_prefix", "source_address_prefixes", "destination_address_prefix",
        "destination_address_prefixes", "source_application_security_group_ids", "destination_application_security_group_ids"),
    ("azurerm_network_interface", "ip_configuration"): ("subnet_id",),
    ("azurerm_virtual_network", "subnet"): ("name", "address_prefixes"),
}  # fmt: skip
_ATTRIBUTE = re.compile(r"^(?P<head>.+)\.(?P<attr>[a-z_][a-z0-9_]*)$")


class _Reader:
    def __init__(self, state: _State, report: Report, vpc: str) -> None:
        self.state, self.report, self.wanted_vpc = state, report, vpc
        self.by_base: Dict[str, List[_Instance]] = {}
        self.by_address: Dict[str, _Instance] = {}
        self.ident: Dict[str, str] = {}  # address -> the id (or, not known yet, the address)
        for instance in state.instances:
            self.by_base.setdefault(instance.base, []).append(instance)
            self.by_address[instance.address] = instance
            self.ident[instance.address] = _text(instance.values.get("id")) or instance.address
        self.unresolved: List[str] = []  # values a plan does not know, and the configuration does not tell
        self.guessed: List[str] = []  # ... that the references of the configuration tell
        self.conflicts: List[str] = []  # inline rules that say otherwise than the separate resource of the same rule
        self.counter = 0
        self.read: Dict[str, int] = {}
        self.gone: Dict[str, List[_Instance]] = {}  # type -> what a plan deletes, as it was
        for kind, before in state.deleted:
            self.gone.setdefault(kind, []).append(_Instance(kind, "(deleted)", "(deleted)", "", dict(before)))

    # -- values, with what a plan does not know yet ---------------------------------------------

    def _instance_at(self, address: str) -> Optional[_Instance]:
        if address in self.by_address:
            return self.by_address[address]
        found = self.by_base.get(address, [])
        return found[0] if len(found) == 1 else None

    def _target(self, reference: str) -> Optional[str]:
        """The id of the resource a reference names ('aws_vpc.main', or its id): for --policy."""
        instance = self._instance_at(reference) or self._instance_at(re.sub(r"\.id$", "", reference))
        return self.ident[instance.address] if instance is not None else None

    @staticmethod
    def _local(reference: str, module: str) -> str:
        """A reference of the configuration of a module with count or for_each, in the instance of the module it is read for."""
        plain = re.sub(r"\[[^\]]*\]", "", module)
        if module != plain and reference.startswith(plain + "."):
            return module + reference[len(plain):]
        return reference

    def _resolve(self, references: List[str], module: str) -> Optional[List[Any]]:
        """What the references of an expression stand for, when each is an attribute of a resource of the state that is
        known (an id not known yet is the address of the resource); None when one is not."""
        references = [self._local(r, module) for r in references]
        if not references:
            return None
        # Terraform lists 'aws_vpc.main.id' and 'aws_vpc.main' (and 'aws_vpc.main[0]' and 'aws_vpc.main'): the longest counts.
        leaves = [r for r in references if not any(o != r and o.startswith((r + ".", r + "[")) for o in references)]
        out: List[Any] = []
        for reference in leaves:
            found = _ATTRIBUTE.match(reference)
            target = self._instance_at(found.group("head")) if found else None
            if found is None or target is None:
                return None
            attribute = found.group("attr")
            if attribute == "id":
                value: Any = self.ident[target.address]
            elif attribute in target.values and attribute not in target.unknown:
                value = target.values[attribute]
            else:
                return None
            out += value if isinstance(value, list) else [value]
        return out if all(isinstance(v, str) and v for v in out) else None

    def _partial(self, value: Any) -> bool:
        """A list of a plan with an element that is not known yet (null)."""
        return self.state.plan and isinstance(value, list) and any(item is None for item in value)

    def value(self, instance: _Instance, key: str) -> Any:
        """An attribute; for one a plan does not know, what the configuration refers to (an id, or an address); _UNKNOWN for
        what neither tells."""
        value = instance.values.get(key)
        if key not in instance.unknown and not self._partial(value):
            return value
        references, _ = self.state.expressions(instance, key)
        return self._from_references(references or [], key, f"{instance.address}.{key}", instance.module)

    def computed(self, instance: _Instance, key: str) -> bool:
        """An attribute a plan does not know and the configuration does not write: Terraform or the cloud fills it in."""
        references, blocks = self.state.expressions(instance, key)
        return (key in instance.unknown or self._partial(instance.values.get(key))) and references is None and blocks is None

    def _from_references(self, references: List[str], key: str, label: str, module: str) -> Any:
        found = self._resolve(references, module)
        if found is None or (key not in _PLURAL and len(found) != 1):
            self.unresolved.append(label)
            return _UNKNOWN
        self.guessed.append(label)
        return transform.dedupe(found) if key in _PLURAL else found[0]

    def blocks(self, instance: _Instance, key: str, separate: bool = False) -> Optional[List[Dict[str, Any]]]:
        """Nested blocks (inline rules); in a plan that does not know them, as the configuration writes them. None: not known.

        ``separate``: separate resources of the state hold rules of the same resource, so that a list Terraform fills in
        itself (not in the configuration) is theirs."""
        raw = _list(instance.values.get(key))
        items = [b for b in raw if isinstance(b, dict)]
        wanted = _BLOCK_KEYS.get((instance.type, key), ())
        partial = self.state.plan and (len(items) != len(raw) or any(
            any(k not in b for k in wanted) or any(self._partial(v) for v in b.values()) for b in items))  # fmt: skip
        if key not in instance.unknown and not partial:
            return items
        _, written = self.state.expressions(instance, key)
        if written is None:
            if separate and not partial:
                return []  # (computed: the rules of the separate resources, read there)
            # A dynamic block, or a list of a resource that is changed: not known. (The configuration of a plan does not show
            # dynamic blocks.)
            self.unresolved.append(f"{instance.address}.{key}")
            return None
        out = []
        for block in written:
            item: Dict[str, Any] = {}
            for attribute, value in block.items():
                if isinstance(value, _Refs):
                    item[attribute] = self._from_references(list(value), attribute, f"{instance.address}.{key}.{attribute}", instance.module)
                else:
                    item[attribute] = value
            for attribute in wanted:
                if attribute not in item and attribute in ("protocol", "priority", "direction", "access", "rule_no", "action", "name"):
                    item[attribute] = _UNKNOWN  # (a block that does not say what it does: not read)
                    self.unresolved.append(f"{instance.address}.{key}.{attribute}")
            out.append(item)
        return out

    def resolved(self, instance: _Instance, keys: Sequence[str]) -> Dict[str, Any]:
        """The values of a resource, with what a plan does not know worked out or _UNKNOWN."""
        out = dict(instance.values)
        for key in keys:
            if key in instance.unknown or self._partial(out.get(key)):
                out[key] = self.value(instance, key)
        return out

    def of(self, *kinds: str) -> List[_Instance]:
        out = [i for i in self.state.instances if i.type in kinds]
        for instance in out:
            self.read[instance.type] = self.read.get(instance.type, 0) + 1
        return out

    # -- AWS -----------------------------------------------------------------------------------

    def aws(self) -> List[Dict[str, Any]]:
        groups: Dict[str, Dict[str, Any]] = {}
        rules: Dict[str, Dict[Tuple[Any, ...], Dict[str, Any]]] = {}
        separate: Dict[str, Dict[Tuple[Any, ...], Dict[str, Any]]] = {}
        for instance in self.of(*_AWS_RULES):
            group, items = self._separate_rule(instance, self.resolved(instance, _KNOWN_ATTRIBUTES[instance.type]))
            if not group:
                continue  # (said: TERRAFORM_UNKNOWN)
            for item in items:
                separate.setdefault(group, {}).setdefault(self._rule_key(item), item)
        # What a plan deletes is still in the inline rules of its group, which repeat it: not read there.
        gone = {(group, self._rule_key(item)) for kind in _AWS_RULES for instance in self.gone.get(kind, [])
                for group, items in [self._separate_rule(instance, instance.values)] for item in items}  # fmt: skip
        for instance in self.of(*_AWS_GROUPS):
            ident = self.ident[instance.address]
            groups[ident] = {"GroupId": ident, "GroupName": _text(instance.values.get("name")) or instance.address,
                             "Description": _text(instance.values.get("description")), "VpcId": _text(self.value(instance, "vpc_id")),
                             "IpPermissions": [], "IpPermissionsEgress": [], "Tags": self._tags(instance)}  # fmt: skip
            rules[ident] = {}
            for key, egress in (("ingress", False), ("egress", True)):
                found = self.blocks(instance, key, separate=ident in separate)
                if found is None:  # (not known: a rule that cannot be read, so that it is not converted, and said)
                    rules[ident][(egress, "unknown")] = self._item(egress, _UNKNOWN, None, None, "", ReferencedGroupInfo={"GroupId": "unknown-" + ident})
                for block in found or []:
                    for item in self._inline_rule(ident, egress, block):
                        key_of = self._rule_key(item)
                        if (ident, key_of) not in gone or key_of in separate.get(ident, {}):
                            rules[ident].setdefault(key_of, item)
        for group, found_rules in separate.items():
            if group not in groups:
                groups[group] = {"GroupId": group, "GroupName": group, "Description": "", "VpcId": "", "IpPermissions": [],
                                 "IpPermissionsEgress": []}  # fmt: skip
                self.report.note(Severity.REVIEW, "TERRAFORM_GROUP_NOT_IN_STATE",
                                 f"rules of the {self.state.kind} belong to security group {group}, which it does not hold: the group is "
                                 "read with those rules only, and without the rules the cloud holds for it otherwise")  # fmt: skip
            for key_of, item in found_rules.items():
                rules.setdefault(group, {}).setdefault(key_of, item)
        vpcs = sorted({g["VpcId"] for g in groups.values() if g["VpcId"]})
        if self.wanted_vpc:
            wanted = self._target(self.wanted_vpc) or self.wanted_vpc
            if wanted not in vpcs:
                raise ParseError(f"--policy: no security group of VPC '{self.wanted_vpc[:60]}' in the {self.state.kind}; it holds groups of "
                                 + (", ".join(vpcs) or "no VPC it names"))  # fmt: skip
            groups = {k: g for k, g in groups.items() if g["VpcId"] in (wanted, "")}
            vpcs = [wanted]
        elif len(vpcs) > 1:
            raise ParseError(f"the {self.state.kind} holds security groups of several VPCs ({', '.join(vpcs[:5])}): name the one to read with "
                             "--policy (its id, or the address of its aws_vpc)")  # fmt: skip
        vpc = vpcs[0] if vpcs else ""
        # describe-security-group-rules, one peer per rule as Terraform has most of them. A group without rules is not named
        # there, and the AWS parser reads its permissions, which are empty: the same.
        answers: List[Dict[str, Any]] = [
            {"SecurityGroups": list(groups.values())},
            {"SecurityGroupRules": [dict(item, GroupId=ident) for ident in groups for item in rules.get(ident, {}).values()]},
        ]
        subnets = self._aws_subnets()
        interfaces = self._aws_interfaces(subnets)
        if interfaces is not None:
            answers.append({"NetworkInterfaces": [i for i in interfaces if not vpc or i.get("VpcId") in (vpc, "")]})
        if subnets:
            answers.append({"Subnets": list(subnets.values())})
        vpc_answers = []
        for instance in self.of("aws_vpc"):
            ident = self.ident[instance.address]
            blocks = [b for b in (_text(instance.values.get("cidr_block")),) if b]
            six = [b for b in (_text(instance.values.get("ipv6_cidr_block")),) if b]
            vpc_answers.append({"VpcId": ident, "CidrBlock": blocks[0] if blocks else "", "CidrBlockAssociationSet": [{"CidrBlock": b} for b in blocks],
                                "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": b} for b in six], "Tags": self._tags(instance)})  # fmt: skip
        if vpc_answers:
            answers.append({"Vpcs": vpc_answers})
        acls = self._aws_acls(vpc)
        if acls is not None:
            answers.append({"NetworkAcls": acls})
        answers += self._aws_prefix_lists()
        return answers

    @staticmethod
    def _tags(instance: _Instance) -> List[Dict[str, str]]:
        tags = instance.values.get("tags")
        return [{"Key": str(k), "Value": str(v)} for k, v in tags.items()] if isinstance(tags, dict) else []

    @staticmethod
    def _rule_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
        peer = item.get("CidrIpv4") or item.get("CidrIpv6") or item.get("PrefixListId") or \
            json.dumps(item.get("ReferencedGroupInfo"), sort_keys=True)  # fmt: skip
        return (item["IsEgress"], item["IpProtocol"], item.get("FromPort"), item.get("ToPort"), str(peer).lower())

    @staticmethod
    def _protocol(value: Any) -> str:
        if value is _UNKNOWN:
            return "(not known)"
        text = str(value if value is not None else "").strip().lower()
        if text in _PROTOCOL_NAMES:
            return _PROTOCOL_NAMES[text]
        if text.isdigit():
            return str(int(text))
        return text or "?"

    def _item(self, egress: bool, value: Any, low: Any, high: Any, description: Any, **peer: Any) -> Dict[str, Any]:
        """A rule as describe-security-group-rules gives it: -1 for the ports where AWS has none. A protocol or a port that is
        not known makes a protocol that cannot be read."""
        protocol = self._protocol(value)
        item: Dict[str, Any] = {"IsEgress": egress, "IpProtocol": protocol, "Description": _text(description)}
        if any(v is _UNKNOWN for v in (value, low, high)):
            item["IpProtocol"] = "(not known)"
        if protocol in ("tcp", "udp", "icmp", "icmpv6"):
            item["FromPort"], item["ToPort"] = _int(low), _int(high)  # (None where not given: the AWS parser decides)
            if protocol in ("icmp", "icmpv6") and item["FromPort"] is not None and item["ToPort"] is None:
                item["ToPort"] = -1
        else:
            item["FromPort"], item["ToPort"] = -1, -1
        return dict(item, **peer)

    def _peer(self, item: Dict[str, Any], kind: str, value: Any, own: str) -> Optional[Dict[str, Any]]:
        if value is _UNKNOWN:
            return dict(item, ReferencedGroupInfo={"GroupId": "unknown-" + own})
        if value is not None and not isinstance(value, str):
            return dict(item, CidrIpv4=json.dumps(value)[:60])  # (not an address: read as nothing, and said)
        text = _text(value)
        if not text:
            return None
        if kind == "group":
            user, _, group = text.rpartition("/")
            info = {"GroupId": group}
            if user:
                info["UserId"] = user
            return dict(item, ReferencedGroupInfo=info)
        if kind == "prefix":
            return dict(item, PrefixListId=text)
        return dict(item, **{"CidrIpv6" if ":" in text else "CidrIpv4": text})

    def _peers(self, base: Dict[str, Any], kinds: Sequence[Tuple[str, Any]], own: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for kind, values in kinds:
            for value in [_UNKNOWN] if values is _UNKNOWN else _list(values):
                found = self._peer(base, kind, value, own)
                if found is not None:
                    out.append(found)
        return out

    def _inline_rule(self, group: str, egress: bool, block: Dict[str, Any]) -> List[Dict[str, Any]]:
        base = self._item(egress, block.get("protocol"), block.get("from_port"), block.get("to_port"), block.get("description"))
        out = self._peers(base, [("cidr", block.get("cidr_blocks")), ("cidr", block.get("ipv6_cidr_blocks")),
                                 ("prefix", block.get("prefix_list_ids")), ("group", block.get("security_groups"))], group)  # fmt: skip
        if block.get("self") is True:
            out.append(dict(base, ReferencedGroupInfo={"GroupId": group}))
        elif block.get("self") is _UNKNOWN:
            out.append(dict(base, ReferencedGroupInfo={"GroupId": "unknown-" + group}))
        return out

    def _separate_rule(self, instance: _Instance, values: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
        """The group of a separate rule resource, and its rules."""
        group = _text(values.get("security_group_id"))
        if instance.type == "aws_security_group_rule":
            kind = values.get("type")
            base = self._item(_text(kind) == "egress", values.get("protocol") if kind is not _UNKNOWN else _UNKNOWN, values.get("from_port"),
                              values.get("to_port"), values.get("description"))  # fmt: skip
            out = self._peers(base, [("cidr", values.get("cidr_blocks")), ("cidr", values.get("ipv6_cidr_blocks")),
                                     ("prefix", values.get("prefix_list_ids"))], group)  # fmt: skip
            source = values.get("source_security_group_id")
            if source is _UNKNOWN or _text(source):
                out += self._peers(base, [("group", source)], group)
            if values.get("self") is True:
                out.append(dict(base, ReferencedGroupInfo={"GroupId": group}))
            elif values.get("self") is _UNKNOWN:
                out.append(dict(base, ReferencedGroupInfo={"GroupId": "unknown-" + group}))
            return group, out
        base = self._item(instance.type.endswith("egress_rule"), values.get("ip_protocol"), values.get("from_port"), values.get("to_port"),
                          values.get("description"))  # fmt: skip
        for kind, key in (("cidr", "cidr_ipv4"), ("cidr", "cidr_ipv6"), ("prefix", "prefix_list_id"), ("group", "referenced_security_group_id")):
            value = values.get(key)
            if value is _UNKNOWN or _text(value) or (value is not None and not isinstance(value, str)):
                found = self._peer(base, kind, value, group)
                return group, [found] if found is not None else []
        return group, [dict(base, CidrIpv4="")]  # (no peer: read as nothing, and said)

    def _aws_subnets(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for instance in self.of("aws_subnet"):
            ident = self.ident[instance.address]
            six = _text(instance.values.get("ipv6_cidr_block"))
            vpc = self.value(instance, "vpc_id")
            out[ident] = {"SubnetId": ident, "VpcId": _text(vpc), "CidrBlock": _text(instance.values.get("cidr_block")),
                          "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": six}] if six else [], "Tags": self._tags(instance)}  # fmt: skip
        return out

    def _aws_interfaces(self, subnets: Dict[str, Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        interfaces = self.of("aws_network_interface")
        instances = self.of("aws_instance")
        if not interfaces and not instances:
            return None
        by_id: Dict[str, Dict[str, Any]] = {}
        for instance in interfaces:
            ident = self.ident[instance.address]
            subnet = self.value(instance, "subnet_id")
            groups = self.value(instance, "security_groups")
            private = [str(a) for a in transform.dedupe([_text(instance.values.get("private_ip"))] + [_text(a) for a in _list(instance.values.get("private_ips"))]) if a]
            by_id[ident] = {"NetworkInterfaceId": ident, "SubnetId": _text(subnet), "VpcId": subnets.get(_text(subnet), {}).get("VpcId", ""),
                            "Groups": [{"GroupId": _text(g)} for g in _list(groups) if _text(g)],
                            "PrivateIpAddress": private[0] if private else "", "PrivateIpAddresses": [{"PrivateIpAddress": a} for a in private],
                            "Ipv6Addresses": [{"Ipv6Address": str(a)} for a in _list(instance.values.get("ipv6_addresses")) if a],
                            "InterfaceType": _text(instance.values.get("interface_type")) or "interface",
                            "SourceDestCheck": instance.values.get("source_dest_check", True) is not False}  # fmt: skip
            if groups is _UNKNOWN:
                by_id[ident]["Groups"] = [{"GroupId": "unknown-groups"}]
            if not private:
                self.unresolved.append(f"{instance.address}.private_ip")
        for attachment in self.gone.get("aws_network_interface_sg_attachment", []):
            interface, group = _text(attachment.values.get("network_interface_id")), _text(attachment.values.get("security_group_id"))
            if interface in by_id and {"GroupId": group} in by_id[interface]["Groups"]:
                by_id[interface]["Groups"].remove({"GroupId": group})  # (deleted by the plan; added again below if another attachment has it)
        for attachment in self.of("aws_network_interface_sg_attachment"):
            interface, group = self.value(attachment, "network_interface_id"), self.value(attachment, "security_group_id")
            interface, group = _text(interface), _text(group)
            if interface and group and interface in by_id:
                if {"GroupId": group} not in by_id[interface]["Groups"]:
                    by_id[interface]["Groups"].append({"GroupId": group})
        of_instance: Dict[str, str] = {}  # instance id -> its interface
        for instance in instances:
            primary = _text(instance.values.get("primary_network_interface_id"))
            public = _text(instance.values.get("public_ip"))
            of_instance[self.ident[instance.address]] = primary or "eni-of-" + instance.address
            if primary and primary in by_id:
                target = by_id[primary]  # (an interface of the state: its groups are its own)
                if public and target["PrivateIpAddresses"]:
                    target["PrivateIpAddresses"][0]["Association"] = {"PublicIp": public}
                continue
            subnet = self.value(instance, "subnet_id")
            groups = self.value(instance, "vpc_security_group_ids")
            private = transform.dedupe([a for a in [_text(instance.values.get("private_ip"))] + [_text(s) for s in _list(instance.values.get("secondary_private_ips"))] if a])
            addresses: List[Dict[str, Any]] = [{"PrivateIpAddress": a} for a in private]
            if public and addresses:
                addresses[0]["Association"] = {"PublicIp": public}
            ident = primary or "eni-of-" + instance.address
            by_id[ident] = {"NetworkInterfaceId": ident, "SubnetId": _text(subnet), "VpcId": subnets.get(_text(subnet), {}).get("VpcId", ""),
                            "Groups": [{"GroupId": _text(g)} for g in _list(groups) if _text(g)] if groups is not _UNKNOWN else [{"GroupId": "unknown-groups"}],
                            "PrivateIpAddress": private[0] if private else "", "PrivateIpAddresses": addresses,
                            "Ipv6Addresses": [{"Ipv6Address": str(a)} for a in _list(instance.values.get("ipv6_addresses")) if a],
                            "InterfaceType": "interface", "SourceDestCheck": instance.values.get("source_dest_check", True) is not False}  # fmt: skip
            if not private:
                self.unresolved.append(f"{instance.address}.private_ip")
                del by_id[ident]
        # Elastic IP addresses: a static NAT of a private address of an interface, as the AWS CLI shows them.
        for eip in self.of("aws_eip", "aws_eip_association"):
            values = eip.values
            association = eip.type == "aws_eip_association"
            interface = _text(values.get("network_interface_id" if association else "network_interface"))
            owner = _text(values.get("instance_id" if association else "instance"))
            found = by_id.get(interface) or by_id.get(of_instance.get(owner, ""))
            public = _text(values.get("public_ip"))
            if found is None or not public or not found["PrivateIpAddresses"]:
                continue
            wanted = _text(values.get("private_ip_address" if association else "associate_with_private_ip")) or \
                (_text(values.get("private_ip")) if not association else "")  # fmt: skip
            item = next((a for a in found["PrivateIpAddresses"] if a["PrivateIpAddress"] == wanted), found["PrivateIpAddresses"][0])
            item["Association"] = {"PublicIp": public}
        return list(by_id.values())

    def _acl_entry(self, egress: bool, number: Any, action: Any, protocol: Any, cidr: Any, six: Any, low: Any, high: Any,
                   icmp_type: Any, icmp_code: Any) -> Dict[str, Any]:  # fmt: skip
        text = str(protocol if protocol is not None else "").strip().lower()
        number_text = _ACL_PROTOCOLS.get(text, str(int(text)) if text.isdigit() else text)
        entry: Dict[str, Any] = {"RuleNumber": _int(number), "Egress": egress, "RuleAction": _text(action).lower(), "Protocol": number_text}
        if any(v is _UNKNOWN for v in (number, action, protocol, cidr, six, low, high, icmp_type, icmp_code)) or entry["RuleNumber"] is None:
            entry["CidrBlock"] = ""  # (not known, or no number: an entry that cannot be read; the ACL is not converted, and said)
            return entry
        if _text(cidr):
            entry["CidrBlock"] = _text(cidr)
        elif _text(six):
            entry["Ipv6CidrBlock"] = _text(six)
        if number_text in ("6", "17"):
            entry["PortRange"] = {"From": _int(low), "To": _int(high)}
        if number_text in ("1", "58"):
            first, code = _int(icmp_type), _int(icmp_code)
            entry["IcmpTypeCode"] = {"Type": first if first is not None else -1, "Code": code if code is not None else -1}
        return entry

    def _separate_entries(self, values: Dict[str, Any]) -> List[Dict[str, Any]]:
        egress = values.get("egress")
        if egress is _UNKNOWN:  # (which way is not known: an entry that cannot be read, each way)
            return [{"RuleNumber": _int(values.get("rule_number")), "Egress": e, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": ""}
                    for e in (False, True)]  # fmt: skip
        return [self._acl_entry(egress is True, values.get("rule_number"), values.get("rule_action"), values.get("protocol"),
                                values.get("cidr_block"), values.get("ipv6_cidr_block"), values.get("from_port"), values.get("to_port"),
                                values.get("icmp_type"), values.get("icmp_code"))]  # fmt: skip

    @staticmethod
    def _entry_key(entry: Dict[str, Any]) -> Tuple[bool, Any]:
        return (bool(entry["Egress"]), entry["RuleNumber"] if entry["RuleNumber"] is not None else f"unknown-{id(entry)}")

    def _aws_acls(self, vpc: str) -> Optional[List[Dict[str, Any]]]:
        acls = self.of(*_AWS_ACLS)
        separate = self.of("aws_network_acl_rule")
        associations = self.of("aws_network_acl_association")
        if not acls and not separate:
            return None
        out: Dict[str, Dict[str, Any]] = {}
        entries: Dict[str, Dict[Tuple[bool, Any], Dict[str, Any]]] = {}
        # The separate entries first: the inline entries of their ACL repeat them, as of the last refresh.
        own: Dict[str, Dict[Tuple[bool, Any], Dict[str, Any]]] = {}
        for instance in separate:
            values = self.resolved(instance, _KNOWN_ATTRIBUTES["aws_network_acl_rule"])
            acl = _text(values.get("network_acl_id"))
            if acl:
                for entry in self._separate_entries(values):
                    own.setdefault(acl, {}).setdefault(self._entry_key(entry), entry)
        gone = {(_text(i.values.get("network_acl_id")), self._entry_key(e)) for i in self.gone.get("aws_network_acl_rule", [])
                for e in self._separate_entries(i.values)}  # fmt: skip
        # A subnet has one ACL: an association resource of the plan or the state says which, whatever the subnet_ids of another
        # ACL repeat from the last refresh.
        associated: Dict[str, str] = {}
        for instance in associations:
            acl, subnet = _text(self.value(instance, "network_acl_id")), _text(self.value(instance, "subnet_id"))
            if acl and subnet:
                associated[subnet] = acl
        gone_associations = {(_text(i.values.get("network_acl_id")), _text(i.values.get("subnet_id")))
                             for i in self.gone.get("aws_network_acl_association", [])}  # fmt: skip
        for instance in acls:
            ident = self.ident[instance.address]
            subnets = [] if self.computed(instance, "subnet_ids") else self.value(instance, "subnet_ids")
            listed = [_text(s) for s in _list(subnets) if _text(s)]
            listed = [s for s in listed if associated.get(s, ident) == ident and (ident, s) not in gone_associations]
            out[ident] = {"NetworkAclId": ident, "VpcId": _text(self.value(instance, "vpc_id")) or vpc,
                          "IsDefault": instance.type == "aws_default_network_acl", "Associations": [{"SubnetId": s} for s in listed],
                          "Tags": self._tags(instance)}  # fmt: skip
            if subnets is _UNKNOWN:  # (which subnets it is for is not known: not converted, and said)
                out[ident]["Associations"] = []
                self.unresolved.append(f"{instance.address}.subnet_ids")
            entries[ident] = dict(own.get(ident, {}))
            for key, egress in (("ingress", False), ("egress", True)):
                found = self.blocks(instance, key, separate=ident in own)
                if found is None:  # (not known: an entry that cannot be read, so that the ACL is not converted, and said)
                    entries[ident][(egress, "unknown")] = {"RuleNumber": 0, "Egress": egress, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": ""}
                for block in found or []:
                    entry = self._acl_entry(egress, block.get("rule_no"), block.get("action"), block.get("protocol"), block.get("cidr_block"),
                                            block.get("ipv6_cidr_block"), block.get("from_port"), block.get("to_port"),
                                            block.get("icmp_type"), block.get("icmp_code"))  # fmt: skip
                    key_of = self._entry_key(entry)
                    if (ident, key_of) in gone and key_of not in own.get(ident, {}):
                        continue  # (deleted by the plan)
                    if key_of in entries[ident] and entries[ident][key_of] != entry:
                        if key_of in own.get(ident, {}):
                            self.conflicts.append(f"network ACL {ident} entry {key_of[1]} ({'outbound' if egress else 'inbound'})")
                        continue
                    entries[ident].setdefault(key_of, entry)
        for acl, mine in own.items():
            if acl not in out:
                out[acl] = {"NetworkAclId": acl, "IsDefault": False, "Associations": []}  # (no VpcId: of the VPC read)
                entries[acl] = dict(mine)
                self.report.note(Severity.REVIEW, "TERRAFORM_ACL_NOT_IN_STATE",
                                 f"entries of the {self.state.kind} belong to network ACL {acl}, which it does not hold: the ACL is read "
                                 "with those entries only, for the subnets associated with it here. Entries it has otherwise may deny "
                                 "what the converted policy allows, or allow what it denies")  # fmt: skip
        for subnet, acl in associated.items():
            if acl in out and (acl, subnet) not in gone_associations and {"SubnetId": subnet} not in out[acl]["Associations"]:
                out[acl]["Associations"].append({"SubnetId": subnet})
        for ident, found_acl in out.items():
            found_acl["Entries"] = list(entries[ident].values())
        return list(out.values())

    def _aws_prefix_lists(self) -> List[Dict[str, Any]]:
        lists = self.of("aws_ec2_managed_prefix_list")
        extra = self.of("aws_ec2_managed_prefix_list_entry")
        if not lists and not extra:
            return []
        entries: Dict[str, List[str]] = {}
        names: List[Dict[str, Any]] = []
        for instance in lists:
            ident = self.ident[instance.address]
            names.append({"PrefixListId": ident, "PrefixListName": _text(instance.values.get("name")) or ident,
                          "AddressFamily": _text(instance.values.get("address_family"))})  # fmt: skip
            entries[ident] = [_text(e.get("cidr")) for e in _list(instance.values.get("entry")) if isinstance(e, dict)]
        for instance in extra:
            ident = _text(self.value(instance, "prefix_list_id"))
            if ident:
                entries.setdefault(ident, []).append(_text(instance.values.get("cidr")))
        out: List[Dict[str, Any]] = [{"PrefixLists": names}] if names else []
        for ident, cidrs in entries.items():
            out.append({"PrefixListId": ident, "Entries": [{"Cidr": c} for c in transform.dedupe(cidrs) if c]})
        return out

    # -- Azure ---------------------------------------------------------------------------------

    def azure(self) -> List[Dict[str, Any]]:
        nsgs: Dict[str, Dict[str, Any]] = {}  # id (lower case) -> group
        # The separate rules first: the inline rules of their group repeat them, as of the last refresh.
        own: Dict[Tuple[str, str], Dict[str, Dict[str, Any]]] = {}  # (resource group, group name), lower case -> name -> rule
        names: Dict[Tuple[str, str], str] = {}
        for instance in self.of("azurerm_network_security_rule"):
            values = self.resolved(instance, _KNOWN_ATTRIBUTES["azurerm_network_security_rule"])
            owner = (_text(values.get("resource_group_name")).lower(), _text(values.get("network_security_group_name")).lower())
            if not owner[1]:
                continue  # (said: TERRAFORM_UNKNOWN)
            names.setdefault(owner, _text(values.get("network_security_group_name")))
            rule = self._azure_rule(values)
            own.setdefault(owner, {}).setdefault(rule["name"].lower(), rule)
        gone = {(_text(i.values.get("resource_group_name")).lower(), _text(i.values.get("network_security_group_name")).lower(),
                 _text(i.values.get("name")).lower()) for i in self.gone.get("azurerm_network_security_rule", [])}  # fmt: skip
        for instance in self.of("azurerm_network_security_group"):
            ident = self.ident[instance.address]
            name = _text(instance.values.get("name")) or instance.address
            owner = (_text(instance.values.get("resource_group_name")).lower(), name.lower())
            group: Dict[str, Any] = {"id": ident, "name": name, "type": "Microsoft.Network/networkSecurityGroups", "securityRules": [],
                                     "subnets": [], "networkInterfaces": []}  # fmt: skip
            nsgs[ident.lower()] = group
            mine = own.pop(owner, {})
            rules = dict(mine)
            found = self.blocks(instance, "security_rule", separate=bool(mine))
            if found is None:  # (not known: a rule that cannot be read, so that it is not converted, and said)
                rules["(not known)"] = {"name": "(not known)", "priority": 100, "direction": "Inbound", "access": "Deny", "protocol": "?"}
            for block in found or []:
                rule = self._azure_rule(block)
                key = rule["name"].lower()
                if (owner[0], owner[1], key) in gone and key not in mine:
                    continue  # (deleted by the plan)
                if key in rules:
                    if key in mine and self._same_rule(rules[key], rule) is False:
                        self.conflicts.append(f"network security group {name} rule {rule['name']}")
                    continue
                rules[key] = rule
            group["securityRules"] = list(rules.values())
        for owner, mine in own.items():
            name = names[owner]
            ident = f"/resourceGroups/{owner[0]}/providers/Microsoft.Network/networkSecurityGroups/{name}"
            nsgs[ident.lower()] = {"id": ident, "name": name, "type": "Microsoft.Network/networkSecurityGroups", "securityRules": list(mine.values()),
                                   "subnets": [], "networkInterfaces": []}  # fmt: skip
            self.report.note(Severity.REVIEW, "TERRAFORM_GROUP_NOT_IN_STATE",
                             f"rules of the {self.state.kind} belong to network security group {name}, which it does not hold: the group "
                             "is read with those rules and the default rules of Azure only. Rules it has otherwise may deny what the "
                             "converted policy allows, or allow what it denies")  # fmt: skip
        subnets: Dict[str, Dict[str, Any]] = {}
        vnets: Dict[str, Dict[str, Any]] = {}
        for instance in self.of("azurerm_virtual_network"):
            ident = self.ident[instance.address]
            vnets[ident.lower()] = {"id": ident, "name": _text(instance.values.get("name")), "type": "Microsoft.Network/virtualNetworks",
                                    "addressSpace": {"addressPrefixes": [str(p) for p in _list(instance.values.get("address_space"))]},
                                    "subnets": [], "virtualNetworkPeerings": []}  # fmt: skip
            for block in self.blocks(instance, "subnet") or []:
                sub_id = _text(block.get("id")) or f"{ident}/subnets/{_text(block.get('name'))}"
                subnet: Dict[str, Any] = {"id": sub_id, "name": _text(block.get("name")), "addressPrefixes": [str(p) for p in _list(block.get("address_prefixes"))]}
                if _text(block.get("security_group")):
                    subnet["networkSecurityGroup"] = {"id": _text(block.get("security_group"))}
                subnets[sub_id.lower()] = subnet
        for instance in self.of("azurerm_subnet"):
            ident = self.ident[instance.address]
            subnets[ident.lower()] = {"id": ident, "name": _text(instance.values.get("name")), "type": "Microsoft.Network/virtualNetworks/subnets",
                                      "addressPrefixes": [str(p) for p in _list(instance.values.get("address_prefixes"))]}  # fmt: skip
        for instance in self.of("azurerm_subnet_network_security_group_association"):
            subnet, group = self.value(instance, "subnet_id"), self.value(instance, "network_security_group_id")
            subnet_id, group_id = _text(subnet), _text(group)
            if subnet_id and group_id:
                if subnet_id.lower() in subnets:
                    subnets[subnet_id.lower()]["networkSecurityGroup"] = {"id": group_id}
                if group_id.lower() in nsgs and {"id": subnet_id} not in nsgs[group_id.lower()]["subnets"]:
                    nsgs[group_id.lower()]["subnets"].append({"id": subnet_id})
        for instance in self.of("azurerm_virtual_network_peering"):
            remote = self.value(instance, "remote_virtual_network_id")
            name = _text(instance.values.get("virtual_network_name")).lower()
            for vnet in vnets.values():
                if vnet["name"].lower() == name and _text(remote):
                    vnet["virtualNetworkPeerings"].append({"remoteVirtualNetwork": {"id": remote}, "peeringState": "Connected"})
        for subnet in subnets.values():
            parent = re.match(r"(.*/virtualnetworks/[^/]+)/subnets/", subnet["id"], re.I)
            if parent and parent.group(1).lower() in vnets:
                listed = vnets[parent.group(1).lower()]["subnets"]
                if all(s["id"].lower() != subnet["id"].lower() for s in listed):
                    listed.append(subnet)
        nics: Dict[str, Dict[str, Any]] = {}
        for instance in self.of("azurerm_network_interface"):
            ident = self.ident[instance.address]
            configs = []
            for block in self.blocks(instance, "ip_configuration") or []:
                config: Dict[str, Any] = {"name": _text(block.get("name")), "privateIPAddress": _text(block.get("private_ip_address")),
                                          "applicationSecurityGroups": []}  # fmt: skip
                if _text(block.get("subnet_id")):
                    config["subnet"] = {"id": _text(block.get("subnet_id"))}
                if self.state.plan and not config["privateIPAddress"]:
                    self.unresolved.append(f"{instance.address}.ip_configuration.private_ip_address")
                configs.append(config)
            nics[ident.lower()] = {"id": ident, "name": _text(instance.values.get("name")), "type": "Microsoft.Network/networkInterfaces",
                                   "ipConfigurations": configs}  # fmt: skip
        for instance in self.of("azurerm_network_interface_application_security_group_association"):
            nic, asg = self.value(instance, "network_interface_id"), self.value(instance, "application_security_group_id")
            nic, asg = _text(nic), _text(asg)
            if nic and asg and nic.lower() in nics:
                for config in nics[nic.lower()]["ipConfigurations"]:
                    config["applicationSecurityGroups"].append({"id": asg})
        for instance in self.of("azurerm_network_interface_security_group_association"):
            nic, group = self.value(instance, "network_interface_id"), self.value(instance, "network_security_group_id")
            nic_id, group_id = _text(nic), _text(group)
            if nic_id and group_id:
                if nic_id.lower() in nics:
                    nics[nic_id.lower()]["networkSecurityGroup"] = {"id": group_id}
                if group_id.lower() in nsgs and {"id": nic_id} not in nsgs[group_id.lower()]["networkInterfaces"]:
                    nsgs[group_id.lower()]["networkInterfaces"].append({"id": nic_id})
        asgs = [{"id": self.ident[i.address], "name": _text(i.values.get("name")), "type": "Microsoft.Network/applicationSecurityGroups"}
                for i in self.of("azurerm_application_security_group")]  # fmt: skip
        answers: List[Any] = list(nsgs.values())
        answers += list(nics.values()) + asgs + list(vnets.values())
        answers += [s for s in subnets.values() if not any(s in v["subnets"] for v in vnets.values())]
        return answers

    def _azure_rule(self, block: Dict[str, Any]) -> Dict[str, Any]:
        """A security rule as the Azure CLI prints it. One with a value that is not known has a protocol that cannot be read
        (and a name of its own when its name is not known), so that it is not converted."""
        name = _text(block.get("name"))
        unknown = [key for key, value in block.items() if value is _UNKNOWN]
        if not name:
            self.counter += 1
            name = f"(not known {self.counter})"
        rule: Dict[str, Any] = {"name": name, "priority": _int(block.get("priority")), "direction": _text(block.get("direction")),
                                "access": _text(block.get("access")), "protocol": "?" if unknown else _text(block.get("protocol"))}  # fmt: skip
        if _text(block.get("description")):
            rule["description"] = _text(block.get("description"))
        for side in ("source", "destination"):
            single, several = _text(block.get(f"{side}_port_range")), [str(p) for p in _list(block.get(f"{side}_port_ranges")) if str(p)]
            if single:
                rule[f"{side}PortRange"] = single
            if several:
                rule[f"{side}PortRanges"] = several
            single, several = _text(block.get(f"{side}_address_prefix")), [str(p) for p in _list(block.get(f"{side}_address_prefixes")) if str(p)]
            if single:
                rule[f"{side}AddressPrefix"] = single
            if several:
                rule[f"{side}AddressPrefixes"] = several
            asgs = block.get(f"{side}_application_security_group_ids")
            if asgs is _UNKNOWN:
                rule[f"{side}ApplicationSecurityGroups"] = [{"id": "unknown-application-security-group"}]
            elif _list(asgs):
                rule[f"{side}ApplicationSecurityGroups"] = [{"id": str(a)} for a in _list(asgs) if str(a)]
        return rule

    @staticmethod
    def _same_rule(one: Dict[str, Any], other: Dict[str, Any]) -> bool:
        def plain(rule: Dict[str, Any]) -> str:
            return json.dumps({k: v for k, v in rule.items() if k != "description"}, sort_keys=True).lower()

        return plain(one) == plain(other)

    # -- notes ---------------------------------------------------------------------------------

    def notes(self, provider: str) -> None:
        kind = self.state.kind
        read = ", ".join(f"{count} {name}" for name, count in sorted(self.read.items()))
        self.report.note(Severity.INFO, "TERRAFORM_SOURCE",
                         f"read from a Terraform {kind}" + (f" (Terraform {self.state.version})" if self.state.version else "")
                         + f", as the answers of the {'AWS' if provider == 'aws' else 'Azure'} CLI for the same resources: {read or 'nothing'}. "
                         f"Resources outside this {kind} (made by hand, or by another state) are not in it")  # fmt: skip
        if self.state.plan:
            self.report.note(Severity.REVIEW, "TERRAFORM_PLAN",
                             "a plan: what it creates or changes is read as it will be after the apply. Ids not known yet stand for "
                             "the resources the configuration refers to; what the plan deletes is not read")  # fmt: skip
        if self.state.incomplete:
            self.report.note(Severity.REVIEW, "TERRAFORM_INCOMPLETE",
                             "the plan says it is not complete (complete: false): resources that depend on what is not planned yet "
                             "are missing, and the converted policy may allow more or less than the apply will. Plan again after the "
                             "first apply")  # fmt: skip
        if self.guessed:
            self.report.note(Severity.REVIEW, "TERRAFORM_REFERENCES",
                             "values the plan does not know yet were taken from the resources the configuration refers to: "
                             + ", ".join(transform.dedupe(self.guessed)[:12]) + (" ..." if len(set(self.guessed)) > 12 else "")
                             + ". Anything else the expression adds (a constant, a function) is not in the plan, nor here")  # fmt: skip
        if self.unresolved:
            what = ("values the plan does not know, and the configuration does not refer to a resource for (a variable, a data "
                    "source, a dynamic block, an expression)" if self.state.plan else "values the state does not hold")
            self.report.note(Severity.REVIEW, "TERRAFORM_UNKNOWN",
                             f"{what}: " + ", ".join(transform.dedupe(self.unresolved)[:12]) + (" ..." if len(set(self.unresolved)) > 12 else "")
                             + ". A rule or entry that holds one is not converted, and a network ACL with one is not converted; an "
                             "interface without an address is no member, and a rule whose group is not known is missing from it")  # fmt: skip
        if self.conflicts:
            self.report.note(Severity.REVIEW, "TERRAFORM_CONFLICT",
                             "inline rules repeat rules of separate resources with other contents (the state was not refreshed since "
                             "one of them changed): " + ", ".join(self.conflicts[:12]) + (" ..." if len(self.conflicts) > 12 else "")
                             + ". The separate resources were read. Refresh the state (terraform apply -refresh-only) and convert it again")  # fmt: skip
        if provider == "aws" and (self.read.get("aws_network_interface") or self.read.get("aws_instance")):
            self.report.note(Severity.REVIEW, "TERRAFORM_MEMBERS",
                             f"the members of the security groups are the network interfaces and instances of this {kind}: a group "
                             "attached to interfaces elsewhere (another state, a load balancer, made by hand) has those members "
                             "as well, and the converted policy does not know them")  # fmt: skip
        if provider == "aws" and not (self.read.get("aws_network_interface") or self.read.get("aws_instance")):
            self.report.retract("note", {"AWS_NO_INTERFACES"})
            self.report.note(Severity.REVIEW, "TERRAFORM_NO_MEMBERS",
                             f"the {kind} holds no network interfaces or instances: which addresses a security group stands for is not "
                             "known, and its rules cannot be written for any target. Convert the state that holds the instances or "
                             "interfaces as well")  # fmt: skip
        if provider == "aws" and not (self.read.get("aws_network_acl") or self.read.get("aws_default_network_acl") or self.read.get("aws_network_acl_rule")):
            self.report.retract("note", {"AWS_NACL_NOT_EXPORTED"})
            self.report.note(Severity.INFO, "TERRAFORM_NO_ACLS",
                             f"the {kind} holds no network ACLs: the default network ACL of the VPC, or one made elsewhere, may deny "
                             "what the converted policy allows")  # fmt: skip
        if self.state.skipped_deposed:
            self.report.note(Severity.INFO, "TERRAFORM_DEPOSED",
                             f"{self.state.skipped_deposed} deposed object(s), which a replacement leaves until it is done, were left out")
        other = sorted({i.type for i in self.state.instances if _NOT_READ.match(i.type)})
        if other:
            self.report.note(Severity.REVIEW, "TERRAFORM_NOT_READ",
                             f"the {kind} holds resources that filter traffic and are not read: " + ", ".join(other[:12])
                             + ". The converted policy does not hold what they do")  # fmt: skip


class _Unknown(str):
    """A value a plan does not know and the configuration does not tell."""


_UNKNOWN = _Unknown("(not known)")


