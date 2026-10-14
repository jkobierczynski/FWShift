# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Terraform: the parser of states and plans, the HCL emitters, and packet-level equivalence with judges of their own.

The judges of test_aws and test_azure decide the CLI answers random VPCs and groups are made of. Here the same answers
are written as Terraform writes them (inline and separate rules, the echoes a refresh leaves, modules, count, the raw
state, plans with ids that are not known yet), and the parser must decide as the judge does. The HCL the emitters write
is read by a small HCL reader of this module, which shares no code with the emitters, and turned into what the judges
of the script and the template read.
"""

from __future__ import annotations

import copy
import json
import random
import re
from typing import Any, Dict, List, Optional, Tuple

import pytest
import test_aws as A
import test_azure as Z
from helpers import DATA, load
from test_iptables import Packet, model_allows, random_model
from test_nsx import ZONES_AT

from fwshift import cli
from fwshift.emitters import terraform as emit_terraform
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import Action, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry
from fwshift.options import Options
from fwshift.parsers import azure as parse_azure
from fwshift.parsers import terraform as parse_terraform
from fwshift.report import Report, Severity

AWS = "registry.terraform.io/hashicorp/aws"
AZURERM = "registry.terraform.io/hashicorp/azurerm"


def codes(report: Report) -> set:
    return {n.code for n in report.notes} | {f.code for item in report.items.values() for f in item.findings}


# -- a reader of HCL ------------------------------------------------------------------------------


class Ref:
    """A reference: var.vpc_id, aws_security_group.g1.id."""

    def __init__(self, path: List[Any]) -> None:
        self.path = path

    def __repr__(self) -> str:
        return ".".join(str(p) for p in self.path)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Ref) and other.path == self.path


class Call:
    def __init__(self, name: str, arguments: List[Any]) -> None:
        self.name, self.arguments = name, arguments


class Block:
    def __init__(self, kind: str, labels: List[str]) -> None:
        self.kind, self.labels = kind, labels
        self.attributes: Dict[str, Any] = {}
        self.blocks: List[Block] = []

    def all(self, kind: str) -> List["Block"]:
        return [b for b in self.blocks if b.kind == kind]


_TOKEN = re.compile(r'(?P<space>[ \t\r]+)|(?P<newline>\n)|(?P<comment>(?:#|//)[^\n]*)|(?P<string>"(?:[^"\\\n]|\\.)*")'
                    r'|(?P<number>-?\d+)|(?P<ident>[A-Za-z_][A-Za-z0-9_-]*)|(?P<punct>[{}\[\]()=,.:])')  # fmt: skip


def hcl_string(raw: str) -> str:
    """The value of a quoted string; an interpolation or a directive in it fails the test."""
    out, index, body = [], 0, raw[1:-1]
    escapes = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
    while index < len(body):
        char = body[index]
        if char == "\\":
            follower = body[index + 1]
            if follower == "u":
                out.append(chr(int(body[index + 2:index + 6], 16)))
                index += 6
                continue
            assert follower in escapes, raw
            out.append(escapes[follower])
            index += 2
            continue
        if body.startswith("$${", index) or body.startswith("%%{", index):
            out.append(body[index + 1:index + 3])
            index += 3
            continue
        assert not body.startswith(("${", "%{"), index), f"an expression in a string: {raw}"
        out.append(char)
        index += 1
    return "".join(out)


class Hcl:
    def __init__(self, text: str) -> None:
        self.tokens: List[Tuple[str, str]] = []
        position = 0
        while position < len(text):
            found = _TOKEN.match(text, position)
            assert found is not None, f"cannot read HCL at {text[position:position + 40]!r}"
            kind = found.lastgroup or ""
            if kind not in ("space", "comment"):
                self.tokens.append((kind, found.group()))
            position = found.end()
        self.tokens.append(("end", ""))
        self.at = 0
        self.root = Block("root", [])
        self.body(self.root, "end")

    def peek(self) -> Tuple[str, str]:
        return self.tokens[self.at]

    def take(self, value: Optional[str] = None) -> Tuple[str, str]:
        token = self.tokens[self.at]
        assert value is None or token[1] == value, (token, value, self.tokens[self.at - 5:self.at + 5])
        self.at += 1
        return token

    def lines(self) -> None:
        while self.peek()[0] == "newline":
            self.at += 1

    def body(self, block: Block, end: str) -> None:
        while True:
            self.lines()
            kind, text = self.peek()
            if (end == "end" and kind == "end") or text == end:
                self.take()
                return
            assert kind == "ident", (kind, text)
            self.take()
            if self.peek()[1] == "=":
                self.take("=")
                assert text not in block.attributes, f"{text} twice"
                block.attributes[text] = self.expression()
                assert self.peek()[0] in ("newline", "end") or self.peek()[1] == "}", self.peek()
                continue
            labels = []
            while self.peek()[1] != "{":
                label_kind, label = self.take()
                assert label_kind in ("string", "ident"), label
                labels.append(hcl_string(label) if label_kind == "string" else label)
            self.take("{")
            child = Block(text, labels)
            self.body(child, "}")
            block.blocks.append(child)

    def expression(self) -> Any:
        kind, text = self.take()
        if kind == "string":
            return hcl_string(text)
        if kind == "number":
            return int(text)
        if text == "[":
            items = []
            while True:
                self.lines()
                if self.peek()[1] == "]":
                    self.take()
                    return items
                items.append(self.expression())
                self.lines()
                if self.peek()[1] == ",":
                    self.take()
        if text == "{":
            out: Dict[str, Any] = {}
            while True:
                self.lines()
                if self.peek()[1] == "}":
                    self.take()
                    return out
                key_kind, key = self.take()
                key = hcl_string(key) if key_kind == "string" else key
                self.take("=")
                out[key] = self.expression()
                if self.peek()[1] == ",":
                    self.take()
        assert kind == "ident", (kind, text)
        if text in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[text]
        if self.peek()[1] == "(":
            self.take("(")
            arguments = []
            while self.peek()[1] != ")":
                arguments.append(self.expression())
                if self.peek()[1] == ",":
                    self.take()
            self.take(")")
            return Call(text, arguments)
        path: List[Any] = [text]
        while self.peek()[1] in (".", "["):
            if self.take()[1] == ".":
                path.append(self.take()[1])
            else:
                path.append(self.expression())
                self.take("]")
        return Ref(path)


def resources(hcl: Hcl, kind: str) -> Dict[str, Block]:
    return {b.labels[1]: b for b in hcl.root.all("resource") if b.labels[0] == kind}


def output(hcl: Hcl, name: str) -> Any:
    return next(b for b in hcl.root.all("output") if b.labels == [name]).attributes["value"]


def aws_script(text: str) -> str:
    """The emitted HCL as the script test_aws's ScriptJudge reads: the groups, what they are attached to, their rules."""
    hcl = Hcl(text)
    terraform = hcl.root.all("terraform")[0]
    assert terraform.all("required_providers")[0].attributes["aws"]["source"] == "hashicorp/aws"
    assert [b.labels for b in hcl.root.all("variable")] == [["vpc_id"]]
    groups = resources(hcl, "aws_security_group")
    attach = output(hcl, "fwshift_attach")
    variables: Dict[str, str] = {}
    lines: List[str] = []
    for name, entry in attach.items():
        resource = entry["id"].path[1]
        assert entry["id"] == Ref(["aws_security_group", resource, "id"]) and groups[resource].attributes["name"] == name
        assert groups[resource].attributes["vpc_id"] == Ref(["var", "vpc_id"])
        variables[resource] = f"G{len(variables) + 1}"
        lines += [f"# attach {name}: {' '.join(entry['addresses'])}", f"{variables[resource]}=$(group '{name}' 'x') || exit 1"]
    assert set(variables) == set(groups)
    for word in ("ingress", "egress"):
        for rule in resources(hcl, f"aws_vpc_security_group_{word}_rule").values():
            values = rule.attributes
            group = values["security_group_id"].path
            assert group[0] == "aws_security_group" and group[2] == "id"
            permission: Dict[str, Any] = {"IpProtocol": values["ip_protocol"]}
            if "from_port" in values:
                permission["FromPort"], permission["ToPort"] = values["from_port"], values["to_port"]
            if "cidr_ipv4" in values:
                permission["IpRanges"] = [{"CidrIp": values["cidr_ipv4"]}]
            else:
                permission["Ipv6Ranges"] = [{"CidrIpv6": values["cidr_ipv6"]}]
            assert sum(k in values for k in ("cidr_ipv4", "cidr_ipv6", "referenced_security_group_id", "prefix_list_id")) == 1
            lines += [f"{word} \"${variables[group[1]]}\" <<'FWSHIFT_JSON'", json.dumps([permission]), "FWSHIFT_JSON"]
    return "\n".join(lines) + "\n"


_CAMEL = {"source_port_range": "sourcePortRange", "source_port_ranges": "sourcePortRanges", "destination_port_range": "destinationPortRange",
          "destination_port_ranges": "destinationPortRanges", "source_address_prefix": "sourceAddressPrefix",
          "source_address_prefixes": "sourceAddressPrefixes", "destination_address_prefix": "destinationAddressPrefix",
          "destination_address_prefixes": "destinationAddressPrefixes"}  # fmt: skip


def azure_template(text: str) -> str:
    """The emitted HCL as the template test_azure's TemplateJudge reads."""
    hcl = Hcl(text)
    assert hcl.root.all("terraform")[0].all("required_providers")[0].attributes["azurerm"]["source"] == "hashicorp/azurerm"
    assert [b.labels for b in hcl.root.all("provider")] == [["azurerm"]]
    networks = {name: entry["networks"] for name, entry in output(hcl, "fwshift_networks").items() if entry["networks"]}
    out = []
    for block in resources(hcl, "azurerm_network_security_group").values():
        assert block.attributes["resource_group_name"] == Ref(["var", "resource_group_name"])
        assert isinstance(block.attributes["location"], Call) and block.attributes["location"].name == "coalesce"
        rules = []
        for rule in block.all("security_rule"):
            values = rule.attributes
            body: Dict[str, Any] = {key: values[key] for key in ("priority", "direction", "access", "protocol") if key in values}
            for snake, camel in _CAMEL.items():
                if snake in values:
                    body[camel] = values[snake]
            for side in ("source", "destination"):
                if f"{side}_application_security_group_ids" in values:
                    body[f"{side}ApplicationSecurityGroups"] = [{"id": repr(i)} for i in values[f"{side}_application_security_group_ids"]]
            if "description" in values:
                body["description"] = values["description"]
            rules.append({"name": values["name"], "properties": body})
        out.append({"type": "Microsoft.Network/networkSecurityGroups", "name": block.attributes["name"], "properties": {"securityRules": rules}})
    template = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "metadata": {"networks": networks}, "resources": out}  # fmt: skip
    return json.dumps(template)


# -- states, as Terraform writes them -----------------------------------------------------------


class StateWriter:
    """Resources of a show -json state, in a root module and a child module, under made-up names."""

    def __init__(self, rng: random.Random, provider: str, modules: bool = True) -> None:
        self.rng, self.provider, self.modules = rng, provider, modules
        self.items: List[Dict[str, Any]] = []
        self.counter = 0

    def add(self, kind: str, values: Dict[str, Any]) -> str:
        self.counter += 1
        module = "module.m1" if self.modules and self.rng.random() < 0.25 else ""
        name = f"r{self.counter}"
        index: Any = None
        if self.rng.random() < 0.2:
            index = self.rng.choice([0, 1, "a", "b-c"])
        address = (module + "." if module else "") + f"{kind}.{name}" + ("" if index is None else f"[{json.dumps(index)}]")
        item: Dict[str, Any] = {"address": address, "mode": "managed", "type": kind, "name": name, "provider_name": self.provider,
                                "schema_version": 0, "values": values, "sensitive_values": {}}  # fmt: skip
        if index is not None:
            item["index"] = index
        item["_module"] = module
        self.items.append(item)
        return address

    def show(self) -> Dict[str, Any]:
        root = [self._clean(i) for i in self.items if not i["_module"]]
        child = [self._clean(i) for i in self.items if i["_module"]]
        module: Dict[str, Any] = {"resources": root}
        if child:
            module["child_modules"] = [{"address": "module.m1", "resources": child}]
        return {"format_version": "1.0", "terraform_version": "1.13.4", "values": {"root_module": module}}

    def raw(self) -> Dict[str, Any]:
        grouped: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for item in self.items:
            key = (item["_module"], item["type"], item["name"])
            entry = grouped.setdefault(key, {"mode": "managed", "type": item["type"], "name": item["name"],
                                             "provider": f'provider["{self.provider}"]', "instances": []})  # fmt: skip
            if item["_module"]:
                entry["module"] = item["_module"]
            instance: Dict[str, Any] = {"schema_version": 0, "attributes": item["values"], "sensitive_attributes": []}
            if "index" in item:
                instance["index_key"] = item["index"]
            entry["instances"].append(instance)
        return {"version": 4, "terraform_version": "1.13.4", "serial": 7, "lineage": "00000000-1111-2222-3333-444444444444",
                "outputs": {}, "resources": list(grouped.values()), "check_results": None}  # fmt: skip

    @staticmethod
    def _clean(item: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in item.items() if not k.startswith("_")}


def peers(permission: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """(kind, value, account) of each source or destination of a permission of describe-security-groups."""
    out = [("cidr4", r["CidrIp"], "") for r in permission.get("IpRanges", [])]
    out += [("cidr6", r["CidrIpv6"], "") for r in permission.get("Ipv6Ranges", [])]
    out += [("prefix", r["PrefixListId"], "") for r in permission.get("PrefixListIds", [])]
    out += [("group", r["GroupId"], r.get("UserId", "")) for r in permission.get("UserIdGroupPairs", [])]
    return out


OWN_ACCOUNT = "111122223333"


def group_text(value: str, account: str) -> str:
    return value if account in ("", OWN_ACCOUNT) else f"{account}/{value}"


def ports(permission: Dict[str, Any], single: bool) -> Tuple[Any, Any]:
    protocol = str(permission["IpProtocol"])
    if protocol in ("tcp", "6", "udp", "17", "icmp", "icmpv6"):
        return permission.get("FromPort", -1), permission.get("ToPort", -1)
    return (None, None) if single else (0, 0)


def spelling(rng: random.Random, protocol: str, legacy: bool) -> str:
    choices = {"6": ["tcp", "6"], "tcp": ["tcp", "6"], "-1": ["-1", "all"] if legacy else ["-1"], "udp": ["udp", "17"],
               "icmp": ["icmp", "1"], "icmpv6": ["icmpv6", "58"]}  # fmt: skip
    return rng.choice(choices.get(protocol, [protocol]))


def inline_block(permission: Dict[str, Any], chosen: List[Tuple[str, str, str]], protocol: str, own: str) -> Dict[str, Any]:
    low, high = ports(permission, False)
    return {"description": "", "from_port": low, "to_port": high, "protocol": protocol,
            "cidr_blocks": [v for k, v, _ in chosen if k == "cidr4"], "ipv6_cidr_blocks": [v for k, v, _ in chosen if k == "cidr6"],
            "prefix_list_ids": [v for k, v, _ in chosen if k == "prefix"],
            "security_groups": [group_text(v, a) for k, v, a in chosen if k == "group" and v != own],
            "self": any(k == "group" and v == own for k, v, _ in chosen)}  # fmt: skip


def aws_state(rng: random.Random, document: List[Dict[str, Any]], modules: bool = True) -> StateWriter:
    """The CLI answers of a random VPC (test_aws.random_aws) as a Terraform state."""
    writer = StateWriter(rng, AWS, modules)
    answers: Dict[str, Any] = {}
    for answer in document:
        for key, value in answer.items():
            if key == "PrefixListId":
                answers.setdefault("prefix", []).append(answer)
            elif key != "Entries":
                answers[key] = value
    for vpc in answers.get("Vpcs", []):
        writer.add("aws_vpc", {"id": vpc["VpcId"], "cidr_block": vpc["CidrBlock"],
                               "ipv6_cidr_block": vpc["Ipv6CidrBlockAssociationSet"][0]["Ipv6CidrBlock"], "tags": {}})  # fmt: skip
    for subnet in answers.get("Subnets", []):
        writer.add("aws_subnet", {"id": subnet["SubnetId"], "vpc_id": subnet["VpcId"], "cidr_block": subnet["CidrBlock"],
                                  "ipv6_cidr_block": subnet["Ipv6CidrBlockAssociationSet"][0]["Ipv6CidrBlock"]})  # fmt: skip
    for answer in answers.get("prefix", []):
        entries = [e["Cidr"] for e in answer["Entries"]]
        split = rng.randint(0, len(entries))
        writer.add("aws_ec2_managed_prefix_list", {"id": answer["PrefixListId"], "name": "corp", "address_family": "IPv4",
                                                   "entry": [{"cidr": c, "description": ""} for c in entries[:split]]})  # fmt: skip
        for cidr in entries[split:]:
            writer.add("aws_ec2_managed_prefix_list_entry", {"id": f"{answer['PrefixListId']},{cidr}", "prefix_list_id": answer["PrefixListId"],
                                                             "cidr": cidr, "description": ""})  # fmt: skip
    for group in answers["SecurityGroups"]:
        own = group["GroupId"]
        values: Dict[str, Any] = {"id": own, "name": group["GroupName"], "description": group["Description"], "vpc_id": group["VpcId"],
                                  "tags": {}, "ingress": [], "egress": []}  # fmt: skip
        separate: List[Tuple[str, Dict[str, Any]]] = []
        for egress, key in ((False, "IpPermissions"), (True, "IpPermissionsEgress")):
            word = "egress" if egress else "ingress"
            for permission in group[key]:
                every = peers(permission)
                protocol = str(permission["IpProtocol"])
                roll = rng.random()
                if roll < 0.4 or not every:
                    values[word].append(inline_block(permission, every, spelling(rng, protocol, False), own))
                    continue
                echo = rng.random() < 0.7
                if echo:  # (what a refresh puts inline: the same rules, one block per resource or together)
                    values[word].append(inline_block(permission, every, spelling(rng, protocol, False), own))
                if roll < 0.7:
                    cidrs = [p for p in every if p[0] != "group"]
                    groups = [p for p in every if p[0] == "group"]
                    low, high = ports(permission, False)
                    for chosen in ([cidrs] if cidrs else []) + [[g] for g in groups]:
                        body = {"id": f"sgrule-{rng.randrange(10 ** 9)}", "type": word, "security_group_id": own,
                                "protocol": spelling(rng, protocol, True), "from_port": low, "to_port": high,
                                "cidr_blocks": [v for k, v, _ in chosen if k == "cidr4"], "ipv6_cidr_blocks": [v for k, v, _ in chosen if k == "cidr6"],
                                "prefix_list_ids": [v for k, v, _ in chosen if k == "prefix"], "self": False,
                                "source_security_group_id": None, "description": ""}  # fmt: skip
                        if chosen[0][0] == "group":
                            if chosen[0][1] == own and rng.random() < 0.5:
                                body["self"] = True
                            else:
                                body["source_security_group_id"] = group_text(chosen[0][1], chosen[0][2])
                        separate.append(("aws_security_group_rule", body))
                else:
                    low, high = ports(permission, True)
                    for kind, value, account in every:
                        body = {"id": f"sgr-{rng.randrange(10 ** 9):017x}", "security_group_id": own, "ip_protocol": spelling(rng, protocol, False),
                                "from_port": low, "to_port": high, "cidr_ipv4": value if kind == "cidr4" else None,
                                "cidr_ipv6": value if kind == "cidr6" else None, "prefix_list_id": value if kind == "prefix" else None,
                                "referenced_security_group_id": group_text(value, account) if kind == "group" else None,
                                "description": None, "tags": None}  # fmt: skip
                        separate.append((f"aws_vpc_security_group_{word}_rule", body))
        writer.add(rng.choice(["aws_security_group", "aws_security_group", "aws_default_security_group"]), values)
        for kind, body in separate:
            writer.add(kind, body)
    by_subnet = {s["SubnetId"]: s for s in answers.get("Subnets", [])}
    instance_ids: Dict[str, str] = {}
    for interface in answers.get("NetworkInterfaces", []):
        private = [a["PrivateIpAddress"] for a in interface["PrivateIpAddresses"]]
        public = [(a["PrivateIpAddress"], a["Association"]["PublicIp"]) for a in interface["PrivateIpAddresses"] if "Association" in a]
        six = [a["Ipv6Address"] for a in interface["Ipv6Addresses"]]
        groups = [g["GroupId"] for g in interface["Groups"]]
        assert interface["SubnetId"] in by_subnet
        if rng.random() < 0.5:
            ident = f"i-{rng.randrange(16 ** 17):017x}"
            primary = interface["NetworkInterfaceId"] if rng.random() < 0.5 else ""
            values = {"id": ident, "subnet_id": interface["SubnetId"], "private_ip": private[0], "secondary_private_ips": private[1:],
                      "ipv6_addresses": six, "vpc_security_group_ids": groups, "security_groups": [], "public_ip": "",
                      "primary_network_interface_id": primary, "source_dest_check": True}  # fmt: skip
            instance_ids[interface["NetworkInterfaceId"]] = ident
            eip = None
            if public:
                if rng.random() < 0.5:
                    values["public_ip"] = public[0][1]
                else:
                    eip = {"id": f"eipalloc-{rng.randrange(10 ** 9)}", "instance": ident, "network_interface": primary,
                           "public_ip": public[0][1], "private_ip": public[0][0], "associate_with_private_ip": None}  # fmt: skip
            writer.add("aws_instance", values)
            if eip:
                writer.add("aws_eip", eip)
        else:
            attached = [g for g in groups if rng.random() < 0.3]
            values = {"id": interface["NetworkInterfaceId"], "subnet_id": interface["SubnetId"], "private_ips": private,
                      "private_ip": private[0] if rng.random() < 0.5 else "", "ipv6_addresses": six,
                      "security_groups": [g for g in groups if g not in attached or rng.random() < 0.5],
                      "interface_type": "interface", "source_dest_check": True}  # fmt: skip
            writer.add("aws_network_interface", values)
            for group in attached:
                writer.add("aws_network_interface_sg_attachment", {"id": f"sg-attach-{rng.randrange(10 ** 6)}", "security_group_id": group,
                                                                   "network_interface_id": interface["NetworkInterfaceId"]})  # fmt: skip
            for address, outside in public:
                if rng.random() < 0.5:
                    writer.add("aws_eip", {"id": f"eipalloc-{rng.randrange(10 ** 9)}", "network_interface": interface["NetworkInterfaceId"],
                                           "public_ip": outside, "private_ip": address, "associate_with_private_ip": address, "instance": ""})  # fmt: skip
                else:
                    writer.add("aws_eip_association", {"id": f"eipassoc-{rng.randrange(10 ** 9)}", "network_interface_id": interface["NetworkInterfaceId"],
                                                       "public_ip": outside, "private_ip_address": address, "instance_id": ""})  # fmt: skip
    for acl in answers.get("NetworkAcls", []):
        subnets = [a["SubnetId"] for a in acl["Associations"]]
        inline_subnets = [s for s in subnets if rng.random() < 0.6]
        values = {"id": acl["NetworkAclId"], "vpc_id": acl["VpcId"], "subnet_ids": list(inline_subnets), "ingress": [], "egress": [], "tags": {}}
        if acl["IsDefault"]:
            values["default_network_acl_id"] = acl["NetworkAclId"]
            del values["vpc_id"]
        separate_entries = []
        for entry in acl["Entries"]:
            cidr, six = entry.get("CidrBlock", ""), entry.get("Ipv6CidrBlock", "")
            low = entry.get("PortRange", {}).get("From", 0)
            high = entry.get("PortRange", {}).get("To", 0)
            icmp = entry.get("IcmpTypeCode", {"Type": 0, "Code": 0})
            if rng.random() < 0.6 or acl["IsDefault"]:
                values["egress" if entry["Egress"] else "ingress"].append({
                    "rule_no": entry["RuleNumber"], "action": entry["RuleAction"], "protocol": entry["Protocol"], "cidr_block": cidr,
                    "ipv6_cidr_block": six, "from_port": low, "to_port": high, "icmp_type": icmp["Type"], "icmp_code": icmp["Code"]})  # fmt: skip
            else:
                names = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "-1": "all"}
                protocol = rng.choice([entry["Protocol"], names.get(entry["Protocol"], entry["Protocol"])])
                separate_entries.append({"id": f"nacl-{rng.randrange(10 ** 9)}", "network_acl_id": acl["NetworkAclId"], "rule_number": entry["RuleNumber"],
                                         "egress": entry["Egress"], "protocol": protocol, "rule_action": entry["RuleAction"],
                                         "cidr_block": cidr or None, "ipv6_cidr_block": six or None, "from_port": low, "to_port": high,
                                         "icmp_type": icmp["Type"] if "IcmpTypeCode" in entry else None,
                                         "icmp_code": icmp["Code"] if "IcmpTypeCode" in entry else None})  # fmt: skip
        writer.add("aws_default_network_acl" if acl["IsDefault"] else "aws_network_acl", values)
        for body in separate_entries:
            writer.add("aws_network_acl_rule", body)
        for subnet in subnets:
            if subnet not in inline_subnets or rng.random() < 0.3:
                writer.add("aws_network_acl_association", {"id": f"aclassoc-{rng.randrange(10 ** 6)}", "network_acl_id": acl["NetworkAclId"],
                                                           "subnet_id": subnet})  # fmt: skip
    rng.shuffle(writer.items)
    return writer


def aws_judged(document: List[Dict[str, Any]], model: Policy, rng: random.Random, seed: int, label: str, packets: int = 300) -> int:
    judge = A.AwsJudge(document)
    pool = A.addresses_of(document)
    compared = 0
    for _ in range(packets):
        pkt = A.aws_packet(rng, pool)
        if pkt is None:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        compared += 1
        assert model_allows(model, pkt) == verdict, (label, seed, pkt)
    return compared


@pytest.mark.parametrize("raw", [False, True])
def test_aws_state_decides_like_the_judge(raw: bool) -> None:
    """A random VPC, written as Terraform writes it: the parsed state decides every packet as the VPC does."""
    compared = 0
    for seed in range(100):
        rng = random.Random(seed + (500 if raw else 0))
        document = A.random_aws(rng)
        writer = aws_state(rng, document)
        state = writer.raw() if raw else writer.show()
        report = Report()
        model = parse_terraform.parse(json.dumps(state).encode(), report)
        assert "TERRAFORM_SOURCE" in codes(report)
        compared += aws_judged(document, model, rng, seed, "raw" if raw else "show")
    assert compared > 8000


def test_aws_state_without_acls_and_interfaces() -> None:
    """Without network ACLs: what the groups allow, and said; without members: groups whose rules nothing can write."""
    for seed in range(20):
        rng = random.Random(9000 + seed)
        document = A.random_aws(rng, acls=False)
        state = aws_state(rng, document).show()
        report = Report()
        model = parse_terraform.parse(json.dumps(state).encode(), report)
        assert "TERRAFORM_NO_ACLS" in codes(report) and "AWS_NACL_NOT_EXPORTED" not in codes(report)
        aws_judged(document, model, rng, seed, "no acls")
    document = A.random_aws(random.Random(5), acls=False)
    bare = [a for a in document if "NetworkInterfaces" not in a]
    state = aws_state(random.Random(5), bare).show()
    report = Report()
    model = parse_terraform.parse(json.dumps(state).encode(), report)
    assert "TERRAFORM_NO_MEMBERS" in codes(report) and "AWS_NO_INTERFACES" not in codes(report)
    assert all(g.dynamic_filter or g.unsupported or g.builtin for g in model.address_groups.values() if "security group" in g.description)


# -- plans ----------------------------------------------------------------------------------------

GROUP_TYPES = ("aws_security_group", "aws_default_security_group")


def references(address: str, attribute: str = "id") -> List[str]:
    out = [f"{address}.{attribute}", address]
    if address.endswith("]"):
        out.append(address[:address.rindex("[")])
    return out


def constant(value: Any) -> Dict[str, Any]:
    return {"constant_value": value}


def aws_plan(rng: random.Random, writer: StateWriter, share: float = 0.5) -> Dict[str, Any]:
    """The state as a plan that creates some of its groups: their ids are not known; what refers to them refers to them in
    the configuration, as Terraform writes it (unknown attributes left out, unknown elements of lists null)."""
    groups = {i["values"]["id"]: i["address"] for i in writer.items if i["type"] in GROUP_TYPES}
    new = {ident for ident in groups if rng.random() < share}
    planned: List[Dict[str, Any]] = []
    configuration: List[Dict[str, Any]] = []
    changes: List[Dict[str, Any]] = []
    for item in writer.items:
        values = copy.deepcopy(item["values"])
        expressions: Dict[str, Any] = {}
        created = item["type"] in GROUP_TYPES and values["id"] in new
        if created:
            del values["id"]
        for key in ("security_group_id", "referenced_security_group_id", "source_security_group_id"):
            if values.get(key) in new:
                expressions[key] = {"references": references(groups[values.pop(key)])}
        for key in ("vpc_security_group_ids", "security_groups"):
            if isinstance(values.get(key), list) and any(isinstance(v, str) and v in new for v in values[key]):
                expressions[key] = {"references": [r for v in values[key] for r in references(groups[v])]}
                values[key] = [None if v in new else v for v in values[key]]
        for key in ("ingress", "egress"):
            blocks = values.get(key)
            if item["type"] not in GROUP_TYPES or not any(v in new for b in blocks for v in b["security_groups"]):
                continue
            written = []
            for block in blocks:
                local = [v for v in block["security_groups"] if v in groups]
                rest = dict(block, security_groups=[v for v in block["security_groups"] if v not in groups])
                written.append({k: constant(v) for k, v in rest.items()})
                if local:
                    referred = {k: constant(v) for k, v in block.items() if k not in ("security_groups", "self")}
                    referred.update(cidr_blocks=constant([]), ipv6_cidr_blocks=constant([]), prefix_list_ids=constant([]), self=constant(False))
                    referred["security_groups"] = {"references": [r for v in local for r in references(groups[v])]}
                    written.append(referred)
            expressions[key] = written
            values[key] = [dict(b, security_groups=[None if v in new else v for v in b["security_groups"]]) for b in blocks]
        planned.append(dict(StateWriter._clean(item), values=values))
        base = item["address"][:item["address"].rindex("[")] if item["address"].endswith("]") else item["address"]
        if expressions:
            configuration.append({"address": base, "mode": "managed", "type": item["type"], "name": item["name"], "expressions": expressions})
        changes.append({"address": item["address"], "type": item["type"], "change": {"actions": ["create"] if created else ["no-op"]}})
    return {"format_version": "1.2", "terraform_version": "1.13.4", "planned_values": {"root_module": {"resources": planned}},
            "resource_changes": changes, "configuration": {"root_module": {"resources": configuration}}}  # fmt: skip


def test_aws_plan_decides_like_the_judge() -> None:
    """Groups that a plan creates have no id yet: the address stands for it, and what refers to them still does."""
    compared = 0
    for seed in range(80):
        rng = random.Random(7000 + seed)
        document = A.random_aws(rng)
        plan = aws_plan(rng, aws_state(rng, document, modules=False))
        report = Report()
        model = parse_terraform.parse(json.dumps(plan).encode(), report)
        found = codes(report)
        assert "TERRAFORM_PLAN" in found and "TERRAFORM_UNKNOWN" not in found, report.to_text()
        compared += aws_judged(document, model, rng, seed, "plan")
    assert compared > 6000


# -- Azure ----------------------------------------------------------------------------------------


def unused(rng: random.Random, plural: bool) -> Any:
    """What a state holds for a field a rule does not use: "" and [] mostly, null at times."""
    return rng.choice([[], [], None] if plural else ["", "", None])


def azurerm_rule(rng: random.Random, rule: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"name": rule["name"], "description": rng.choice(["", "made up"]), "priority": rule["priority"],
                           "direction": rule["direction"], "access": rule["access"], "protocol": rule["protocol"]}  # fmt: skip
    for side in ("source", "destination"):
        for camel, snake in ((f"{side}PortRange", f"{side}_port_range"), (f"{side}AddressPrefix", f"{side}_address_prefix")):
            out[snake] = rule[camel] if rule.get(camel) else unused(rng, False)
            out[snake + "es" if "prefix" in snake else snake + "s"] = list(rule[camel + ("es" if "Prefix" in camel else "s")]) \
                if rule.get(camel + ("es" if "Prefix" in camel else "s")) else unused(rng, True)  # fmt: skip
        asgs = [a["id"] for a in rule.get(f"{side}ApplicationSecurityGroups", [])]
        out[f"{side}_application_security_group_ids"] = asgs if asgs else unused(rng, True)
    return out


def azure_state(rng: random.Random, groups: List[Dict[str, Any]]) -> StateWriter:
    writer = StateWriter(rng, AZURERM)
    writer.add("azurerm_application_security_group", {"id": Z.ASG_IDS["asg-x"], "name": "asg-x", "resource_group_name": "rg"})
    for group in groups:
        inline, separate = [], []
        for rule in group["securityRules"]:
            body = azurerm_rule(rng, rule)
            roll = rng.random()
            if roll < 0.5:
                inline.append(body)
            else:
                separate.append(body)
                if rng.random() < 0.7:
                    inline.append(dict(body))  # (the echo of a refresh)
        writer.add("azurerm_network_security_group", {"id": group["id"], "name": group["name"], "resource_group_name": "rg",
                                                      "location": "westeurope", "security_rule": inline, "tags": {}})  # fmt: skip
        for body in separate:
            writer.add("azurerm_network_security_rule", dict(body, id=f"{group['id']}/securityRules/{body['name']}", resource_group_name="rg",
                                                             network_security_group_name=group["name"]))  # fmt: skip
    for interface in Z.interfaces():
        config = interface["ipConfigurations"][0]
        writer.add("azurerm_network_interface", {"id": interface["id"], "name": interface["name"], "resource_group_name": "rg",
                                                 "ip_configuration": [{"name": "ipconfig1", "private_ip_address": config["privateIPAddress"],
                                                                       "subnet_id": "", "private_ip_address_allocation": "Static"}]})  # fmt: skip
        writer.add("azurerm_network_interface_application_security_group_association", {
            "id": f"{interface['id']}|{Z.ASG_IDS['asg-x']}", "network_interface_id": interface["id"],
            "application_security_group_id": Z.ASG_IDS["asg-x"]})  # fmt: skip
    rng.shuffle(writer.items)
    return writer


@pytest.mark.parametrize("loose", [False, True])
def test_azure_state_decides_like_the_judge(loose: bool) -> None:
    compared = 0
    for seed in range(100):
        rng = random.Random(seed + (1000 if loose else 0))
        groups = Z.random_azure(rng, loose)
        writer = azure_state(rng, groups)
        state = writer.raw() if seed % 3 == 0 else writer.show()
        report = Report()
        model = parse_terraform.parse(json.dumps(state).encode(), report)
        judge = Z.AzureJudge(groups, Z.NETWORKS, {Z.ASG_IDS["asg-x"].lower(): Z.ASG_MEMBERS["asg-x"]})
        for _ in range(300):
            pkt = Z.azure_packet(rng)
            if pkt is None:
                continue
            verdict = judge.allows(pkt)
            if verdict is None:
                continue
            compared += 1
            got = model_allows(model, pkt)
            assert got <= verdict if loose else got == verdict, (seed, pkt)
    assert compared > 10000


# -- the HCL the emitters write ---------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(30))
def test_emitted_aws_configuration_decides_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = A.without_source_ports(random_model(rng))
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    text = emit_terraform.emit_terraform_aws(model, report, Options(zone_networks=ZONES_AT))
    assert A.compare(model, report, aws_script(text), rng, False, seed) == 500
    assert {"TERRAFORM_LOAD", "TERRAFORM_ATTACH"} <= codes(report) and not {"AWS_LOAD", "AWS_ATTACH"} & codes(report)


@pytest.mark.parametrize("seed", range(15))
def test_emitted_aws_configuration_never_allows_more(seed: int) -> None:
    rng = random.Random(2000 + seed)
    model = random_model(rng)
    report = Report()
    networks = {zone: nets for zone, nets in ZONES_AT.items() if rng.random() < 0.8}
    text = emit_terraform.emit_terraform_aws(model, report, Options(zone_networks=networks))
    A.compare(model, report, aws_script(text), rng, False, seed)


@pytest.mark.parametrize("seed", range(30))
def test_emitted_azure_configuration_decides_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = random_model(rng)
    report = Report()
    text = emit_terraform.emit_terraform_azure(model, report, Options(zone_networks=ZONES_AT))
    assert Z.compare(model, report, azure_template(text), rng, False, seed) == 500
    assert "TERRAFORM_LOAD" in codes(report) and "AZURE_LOAD" not in codes(report)


@pytest.mark.parametrize("seed", range(15))
def test_emitted_azure_configuration_with_an_inside_decides_like_the_model(seed: int) -> None:
    rng = random.Random(3000 + seed)
    model = random_model(rng)
    report = Report()
    inside = rng.sample(sorted(ZONES_AT), rng.randint(1, 2))
    text = emit_terraform.emit_terraform_azure(model, report, Options(zone_networks=ZONES_AT, inside_zones=inside))
    assert Z.compare(model, report, azure_template(text), rng, True, seed) > 100


def test_the_hcl_is_the_aws_script_and_the_template_rewritten() -> None:
    """The same groups and rules as the AWS script and the ARM template, for the same policy."""
    for seed in range(10):
        model = random_model(random.Random(seed))
        script = cli.convert(copy.deepcopy(model), "aws", Report(), Options(zone_networks=ZONES_AT))
        hcl = cli.convert(copy.deepcopy(model), "terraform-aws", Report(), Options(zone_networks=ZONES_AT))
        mine, theirs = A.ScriptJudge(aws_script(hcl)), A.ScriptJudge(script)
        assert mine.attach == theirs.attach
        flat = {key: sorted(json.dumps(dict(p, **{k: [r] for k in ("IpRanges", "Ipv6Ranges") for r in p.get(k, [])}), sort_keys=True)
                            for p in perms) for key, perms in mine.rules.items()}  # fmt: skip
        split = {}
        for key, perms in theirs.rules.items():
            items = []
            for permission in perms:
                for k in ("IpRanges", "Ipv6Ranges"):
                    for r in permission.get(k, []):
                        one = {x: y for x, y in permission.items() if x not in ("IpRanges", "Ipv6Ranges")}
                        one[k] = [{kk: vv for kk, vv in r.items() if kk != "Description"}]
                        items.append(json.dumps(dict(one, **{k: [one[k][0]]}), sort_keys=True))
            split[key] = sorted(items)
        assert flat == split
        template = json.loads(cli.convert(copy.deepcopy(model), "azure", Report(), Options(zone_networks=ZONES_AT)))
        written = json.loads(azure_template(cli.convert(copy.deepcopy(model), "terraform-azure", Report(), Options(zone_networks=ZONES_AT))))
        assert written["metadata"]["networks"] == {k: v for k, v in template["metadata"]["networks"].items() if v}
        for ours, arm in zip(written["resources"], template["resources"]):
            assert ours["name"] == arm["name"]
            assert [(r["name"], r["properties"]) for r in ours["properties"]["securityRules"]] == \
                [(r["name"], r["properties"]) for r in arm["properties"]["securityRules"]]  # fmt: skip


# -- what is read, and what is not ----------------------------------------------------------------


def show(*items: Dict[str, Any], children: Optional[List[Dict[str, Any]]] = None) -> bytes:
    module: Dict[str, Any] = {"resources": list(items)}
    if children:
        module["child_modules"] = children
    return json.dumps({"format_version": "1.0", "terraform_version": "1.13.4", "values": {"root_module": module}}).encode()


def item(kind: str, name: str, values: Dict[str, Any], module: str = "", provider: str = AWS, **more: Any) -> Dict[str, Any]:
    address = (module + "." if module else "") + f"{kind}.{name}"
    return dict({"address": address, "mode": "managed", "type": kind, "name": name, "provider_name": provider, "values": values}, **more)


def sg(name: str, ident: str, ingress: List[Dict[str, Any]] = (), egress: List[Dict[str, Any]] = (), vpc: str = "vpc-1") -> Dict[str, Any]:
    return item("aws_security_group", name, {"id": ident, "name": name, "description": "", "vpc_id": vpc, "ingress": list(ingress),
                                             "egress": list(egress)})  # fmt: skip


def tcp(port: int, *cidrs: str, groups: List[str] = ()) -> Dict[str, Any]:
    return {"from_port": port, "to_port": port, "protocol": "tcp", "cidr_blocks": list(cidrs), "ipv6_cidr_blocks": [], "prefix_list_ids": [],
            "security_groups": list(groups), "self": False, "description": ""}  # fmt: skip


def eni(name: str, ident: str, address: str, groups: List[str], subnet: str = "subnet-1") -> Dict[str, Any]:
    return item("aws_network_interface", name, {"id": ident, "subnet_id": subnet, "private_ip": address, "private_ips": [address],
                                                "security_groups": groups})  # fmt: skip


def single_values(protocol: str, port: Optional[int], **peer: Any) -> Dict[str, Any]:
    """The planned values of an aws_vpc_security_group_ingress_rule: every attribute, null where not set (a plan leaves out
    only what it does not know)."""
    out: Dict[str, Any] = {"ip_protocol": protocol, "from_port": port, "to_port": port, "cidr_ipv4": None, "cidr_ipv6": None,
                           "prefix_list_id": None, "referenced_security_group_id": None, "description": None}  # fmt: skip
    out.update(peer)
    return out


def parse(data: bytes, **kwargs: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_terraform.parse(data, report, **kwargs), report


def test_detection_and_what_is_refused() -> None:
    aws_sample, azure_sample = (DATA / "terraform_aws_sample.json").read_bytes(), (DATA / "terraform_azure_sample.json").read_bytes()
    assert cli.detect_format(aws_sample) == "terraform-aws" and cli.detect_format(azure_sample) == "terraform-azure"
    raw = {"version": 4, "terraform_version": "1.9.0", "serial": 1, "lineage": "x", "outputs": {},
           "resources": [{"mode": "managed", "type": "aws_security_group", "name": "a", "instances": [{"attributes": {"id": "sg-1", "vpc_id": "v"}}]}]}
    assert cli.detect_format(json.dumps(raw).encode()) == "terraform-aws"
    assert cli.detect_format((DATA / "aws_sample.json").read_bytes()) == "aws"
    assert cli.detect_format((DATA / "azure_sample.json").read_bytes()) == "azure"
    both = json.loads(aws_sample)
    both["values"]["root_module"]["resources"] += json.loads(azure_sample)["values"]["root_module"]["resources"]
    mixed = json.dumps(both).encode()
    with pytest.raises(FwshiftError, match="--from terraform-aws or --from terraform-azure"):
        cli.detect_format(mixed)
    with pytest.raises(ParseError, match="AWS and of Azure"):
        parse(mixed)
    assert parse(mixed, provider="azure")[0].vendor == "azure" and parse(mixed, provider="aws")[0].vendor == "aws"
    with pytest.raises(FwshiftError, match="without the firewall resources"):
        cli.detect_format(show(item("aws_s3_bucket", "b", {"id": "b"})))
    with pytest.raises(ParseError, match="no security groups or security group rules of AWS"):
        parse(azure_sample, provider="aws")
    with pytest.raises(ParseError, match="no network security groups"):
        parse(aws_sample, provider="azure")
    for document, message in (({"format_version": "2.0", "values": {}}, "format version 2.0"), ([1], "not an object"),
                              ({"version": 3, "modules": []}, "nor a raw state"), ({"format_version": "1.0"}, "holds no security groups")):  # fmt: skip
        with pytest.raises(ParseError, match=re.escape(message)):
            parse(json.dumps(document).encode())
    with pytest.raises(ParseError, match="cannot be read"):
        parse(b"{not json")
    model, _ = parse(show(sg("a", "sg-1", ingress=[dict(tcp(22, "10.0.0.0/8"), cidr_blocks=[5])]), eni("e", "eni-1", "10.0.0.5", ["sg-1"])))
    assert [r.unsupported for r in model.rules if r.name == "a-in-1"] == [["'5' is not a CIDR block"]]  # (never any address)
    with pytest.raises(ParseError, match="unexpected shape"):
        parse(json.dumps({"format_version": "1.0", "values": {"root_module": {"resources": 5}}}).encode())


def test_vpcs_and_policy() -> None:
    data = show(sg("a", "sg-1", [tcp(22, "10.0.0.0/8")], vpc="vpc-1"), sg("b", "sg-2", [tcp(80, "10.0.0.0/8")], vpc="vpc-2"),
                item("aws_vpc", "two", {"id": "vpc-2", "cidr_block": "10.2.0.0/16"}), eni("e", "eni-1", "10.2.0.5", ["sg-2"]))  # fmt: skip
    with pytest.raises(ParseError, match="several VPCs"):
        parse(data)
    for wanted in ("vpc-2", "aws_vpc.two"):
        model, report = parse(data, vpc=wanted)
        assert model.scope == "vpc-2" and "b" in model.address_groups and "a" not in model.address_groups
    with pytest.raises(ParseError, match="no security group of VPC 'vpc-9'"):
        parse(data, vpc="vpc-9")
    model = cli.load(data, "terraform-aws", Report(), policy="vpc-1")
    assert model.scope == "vpc-1"


def test_echoes_are_read_once_and_what_is_left_out_is_said() -> None:
    model, report = load("terraform_aws_sample.json")
    found = codes(report)
    assert {"TERRAFORM_SOURCE", "TERRAFORM_DEPOSED", "TERRAFORM_NOT_READ", "TERRAFORM_MEMBERS", "AWS_REMOTE_GROUP"} <= found
    assert "TERRAFORM_PLAN" not in found and "TERRAFORM_UNKNOWN" not in found and "TERRAFORM_NO_ACLS" not in found
    assert "shop-web-old" not in json.dumps(model.to_json())  # (the deposed object)
    assert "aws_networkfirewall_firewall" in next(n.message for n in report.notes if n.code == "TERRAFORM_NOT_READ")
    # Every rule of the app group once, though the state has each twice (inline and as a resource).
    app = [r for r in model.rules if "shop-app" in r.name and r.action == Action.ALLOW]
    assert len(app) == len({json.dumps([r.sources, r.destinations, r.services]) for r in app})
    model, report = load("terraform_azure_sample.json")
    assert [r.name for r in model.rules if r.name.startswith("nsg-db:")][:2] == ["nsg-db:postgres-from-app", "nsg-db:deny-web"]  # (once each)
    assert "TERRAFORM_NOT_READ" in codes(report) and "azurerm_firewall" in next(n.message for n in report.notes if n.code == "TERRAFORM_NOT_READ")


def test_the_samples_decide_as_the_cli_answers_they_stand_for() -> None:
    """The AWS sample, written as the answers of the AWS CLI by hand: both decide every packet the same."""
    state = json.loads((DATA / "terraform_aws_sample.json").read_text(encoding="utf-8"))
    model, _ = load("terraform_aws_sample.json")
    resources = state["values"]["root_module"]["resources"] + state["values"]["root_module"]["child_modules"][0]["resources"]
    value = {r["address"]: r["values"] for r in resources if "deposed_key" not in r}
    group = {v["id"]: v for a, v in value.items() if a.split(".")[-2] == "aws_security_group"}
    pairs = {"IpPermissions": "ingress", "IpPermissionsEgress": "egress"}
    groups = []
    for ident, values in group.items():
        answer: Dict[str, Any] = {"GroupId": ident, "GroupName": values["name"], "VpcId": values["vpc_id"], "Description": ""}
        for key, word in pairs.items():
            answer[key] = []
            for block in values[word]:
                protocol = block["protocol"]
                permission: Dict[str, Any] = {"IpProtocol": protocol, "FromPort": block["from_port"], "ToPort": block["to_port"],
                                              "IpRanges": [{"CidrIp": c} for c in block["cidr_blocks"]],
                                              "Ipv6Ranges": [{"CidrIpv6": c} for c in block["ipv6_cidr_blocks"]],
                                              "PrefixListIds": [{"PrefixListId": p} for p in block["prefix_list_ids"]],
                                              "UserIdGroupPairs": [{"GroupId": g} for g in block["security_groups"]] + ([{"GroupId": ident}] if block["self"] else [])}  # fmt: skip
                answer[key].append(permission)
        groups.append(answer)
    interfaces = []
    for address, values in value.items():
        if ".aws_instance." in "." + address or ".aws_network_interface." in "." + address:
            private = values.get("private_ip") or values["private_ips"][0]
            entry: Dict[str, Any] = {"PrivateIpAddress": private}
            if values.get("public_ip"):
                entry["Association"] = {"PublicIp": values["public_ip"]}
            interfaces.append({"NetworkInterfaceId": address, "SubnetId": values["subnet_id"], "Groups": [{"GroupId": g} for g in values.get("vpc_security_group_ids", values.get("security_groups", []))],
                               "PrivateIpAddresses": [entry] + [{"PrivateIpAddress": a} for a in values.get("secondary_private_ips", [])],
                               "Ipv6Addresses": [{"Ipv6Address": a} for a in values.get("ipv6_addresses", [])]})  # fmt: skip
    subnets = [{"SubnetId": v["id"], "CidrBlock": v["cidr_block"], "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": v["ipv6_cidr_block"]}] if v["ipv6_cidr_block"] else []}
               for a, v in value.items() if ".aws_subnet." in "." + a]  # fmt: skip
    acl = value["aws_network_acl.db"]
    entries = [{"RuleNumber": e["rule_no"], "Egress": word == "egress", "RuleAction": e["action"], "Protocol": e["protocol"], "CidrBlock": e["cidr_block"],
                "PortRange": {"From": e["from_port"], "To": e["to_port"]}, "IcmpTypeCode": {"Type": e["icmp_type"], "Code": e["icmp_code"]}}
               for word in ("ingress", "egress") for e in acl[word]]  # fmt: skip
    document = [{"SecurityGroups": groups}, {"NetworkInterfaces": interfaces}, {"Subnets": subnets},
                {"Vpcs": [{"CidrBlockAssociationSet": [{"CidrBlock": "10.30.0.0/16"}], "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": "2001:db8:30::/56"}]}]},
                {"NetworkAcls": [{"IsDefault": False, "Associations": [{"SubnetId": "subnet-0a1b2c3d4e5f63013"}], "Entries": entries}]},
                {"PrefixListId": "pl-0a1b2c3d4e5f63061", "Entries": [{"Cidr": "198.51.100.0/25"}, {"Cidr": "203.0.113.64/26"}]}]  # fmt: skip
    rng = random.Random(3)
    pool = A.addresses_of(document) + ["10.30.1.99", "10.30.2.99", "198.51.100.20", "203.0.113.70"]
    assert aws_judged_pool(document, model, rng, pool) > 1500


def aws_judged_pool(document: List[Dict[str, Any]], model: Policy, rng: random.Random, pool: List[str]) -> int:
    judge = A.AwsJudge(document)
    count = 0
    for _ in range(6000):
        pkt = A.aws_packet(rng, pool)
        if pkt is None:
            continue
        verdict = judge.allows(pkt)
        if verdict is None:
            continue
        count += 1
        assert model_allows(model, pkt) == verdict, pkt
    return count


def plan(planned: List[Dict[str, Any]], configuration: List[Dict[str, Any]], changes: Dict[str, str] = None,
         modules: Optional[Dict[str, Any]] = None) -> bytes:  # fmt: skip
    root: Dict[str, Any] = {"resources": configuration}
    if modules:
        root["module_calls"] = modules
    return json.dumps({"format_version": "1.2", "planned_values": {"root_module": {"resources": planned}},
                       "resource_changes": [{"address": a, "change": {"actions": [v]}} for a, v in (changes or {}).items()],
                       "configuration": {"root_module": root}}).encode()  # fmt: skip


def test_what_a_plan_does_not_know_is_not_read() -> None:
    """An id from a variable or a data source, an address of a dynamic interface, inline rules written by a dynamic
    block: never read as any address, and said."""
    group = item("aws_security_group", "a", {"name": "a", "vpc_id": "vpc-1", "ingress": [], "egress": []})
    rule = item("aws_vpc_security_group_ingress_rule", "r", single_values("tcp", 22, cidr_ipv4="10.0.0.0/8"))
    model, report = parse(plan([group, rule, eni("e", "eni-1", "10.0.0.5", [])],
                               [{"address": "aws_vpc_security_group_ingress_rule.r", "expressions": {"security_group_id": {"references": ["var.group"]}}}],
                               {"aws_security_group.a": "create"}))  # fmt: skip
    found = codes(report)
    assert {"TERRAFORM_PLAN", "TERRAFORM_UNKNOWN"} <= found and "aws_vpc_security_group_ingress_rule.r.security_group_id" in report.to_text()
    assert not [r for r in model.rules if r.action == Action.ALLOW and "22" in json.dumps(r.services)]
    # The reference to a resource of the state stands for it, however Terraform lists it.
    for references in (["aws_security_group.a.id", "aws_security_group.a"], ["aws_security_group.a.id"]):
        model, report = parse(plan([group, rule, eni("e", "eni-1", "10.0.0.5", [None])],
                                   [{"address": "aws_vpc_security_group_ingress_rule.r", "expressions": {"security_group_id": {"references": references}}},
                                    {"address": "aws_network_interface.e", "expressions": {"security_groups": {"references": references}}}],
                                   {"aws_security_group.a": "create"}))  # fmt: skip
        assert "TERRAFORM_REFERENCES" in codes(report) and "TERRAFORM_UNKNOWN" not in codes(report)
        assert model.address_groups["a"].members == ["10.0.0.5"]
        assert [r.sources for r in model.rules if r.name == "a-in-1"] == [["10.0.0.0/8"]]
    # A conditional between two groups: one of them, not known which.
    other = item("aws_security_group", "b", {"name": "b", "vpc_id": "vpc-1", "ingress": [], "egress": []})
    model, report = parse(plan([group, other, rule], [{"address": "aws_vpc_security_group_ingress_rule.r", "expressions": {
        "security_group_id": {"references": ["aws_security_group.a.id", "aws_security_group.a", "aws_security_group.b.id", "aws_security_group.b"]}}}]))  # fmt: skip
    assert "TERRAFORM_UNKNOWN" in codes(report) and not [r for r in model.rules if "22" in json.dumps(r.services)]
    # An expression that names a variable as well: not known.
    model, report = parse(plan([group, rule], [{"address": "aws_vpc_security_group_ingress_rule.r",
                                                "expressions": {"security_group_id": {"references": ["aws_security_group.a.id", "var.x"]}}}]))  # fmt: skip
    assert "TERRAFORM_UNKNOWN" in codes(report)
    # Inline entries of a network ACL a plan changes and the configuration does not write: the ACL is not converted.
    acl = item("aws_network_acl", "n", {"id": "acl-1", "vpc_id": "vpc-1", "subnet_ids": ["subnet-1"]})
    subnet = item("aws_subnet", "s", {"id": "subnet-1", "vpc_id": "vpc-1", "cidr_block": "10.0.0.0/24"})
    known = sg("b", "sg-2", [tcp(22, "0.0.0.0/0")])
    _, report = parse(plan([known, acl, subnet, eni("e", "eni-1", "10.0.0.5", ["sg-2"])], [], {"aws_network_acl.n": "update"}))
    assert {"TERRAFORM_UNKNOWN", "AWS_NACL_NOT_CONVERTED"} <= codes(report)
    _, report = parse(plan([known, acl, subnet, eni("e", "eni-1", "10.0.0.5", ["sg-2"])], [], {"aws_network_acl.n": "create"}))
    assert {"TERRAFORM_UNKNOWN", "AWS_NACL_NOT_CONVERTED"} <= codes(report)  # (a dynamic block, which a plan does not show)
    entry = item("aws_network_acl_rule", "e", {"network_acl_id": "acl-1", "rule_number": 100, "egress": False, "protocol": "-1", "rule_action": "allow",
                                               "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": None, "from_port": None, "to_port": None,
                                               "icmp_type": None, "icmp_code": None})  # fmt: skip
    _, report = parse(plan([known, acl, entry, subnet, eni("e", "eni-1", "10.0.0.5", ["sg-2"])], [], {"aws_network_acl.n": "create"}))
    assert not {"TERRAFORM_UNKNOWN", "AWS_NACL_NOT_CONVERTED"} & codes(report)  # (the list Terraform fills in: the separate entries)
    # Azure: an interface whose address is given when it is created.
    nsg = item("azurerm_network_security_group", "g", {"id": "/x/networkSecurityGroups/g", "name": "g", "security_rule": []}, provider=AZURERM)
    nic = item("azurerm_network_interface", "n", {"id": "/x/networkInterfaces/n", "name": "n", "ip_configuration": [{"name": "c", "subnet_id": "/s"}]},
               provider=AZURERM)  # fmt: skip
    _, report = parse(plan([nsg, nic], [], {"azurerm_network_interface.n": "create"}))
    assert "azurerm_network_interface.n.ip_configuration.private_ip_address" in report.to_text()


def test_references_inside_modules() -> None:
    """The configuration of a module refers to its own resources without the module's address."""
    group = item("aws_security_group", "a", {"name": "a", "vpc_id": "vpc-1", "ingress": [], "egress": []}, module="module.net")
    rule = item("aws_vpc_security_group_ingress_rule", "r", single_values("tcp", 443, cidr_ipv4="192.0.2.0/24"), module="module.net")
    interface = eni("e", "eni-1", "10.0.0.5", ["module.net.aws_security_group.a"])
    calls = {"net": {"module": {"resources": [{"address": "aws_vpc_security_group_ingress_rule.r",
                                               "expressions": {"security_group_id": {"references": ["aws_security_group.a.id", "aws_security_group.a"]}}}]}}}  # fmt: skip
    data = json.dumps({"format_version": "1.2", "planned_values": {"root_module": {"resources": [interface], "child_modules": [
        {"address": "module.net", "resources": [group, rule]}]}}, "configuration": {"root_module": {"module_calls": calls}}}).encode()
    model, report = parse(data)
    assert "TERRAFORM_UNKNOWN" not in codes(report)
    assert [r.sources for r in model.rules if r.name == "a-in-1"] == [["192.0.2.0/24"]]


def test_hostile_text_stays_text_in_hcl() -> None:
    """Quotes, backslashes, line breaks, control characters and template sequences: read back as the same text."""
    nasty = 'x" ${file("/etc/passwd")} %{ if true }\\n\\\\ \x01\t  $${ end'
    p = Policy(vendor="test")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "443")])
    rule = Rule("r1", src_zones=["outside"], dst_zones=["inside"], services=["web"], description=nasty)
    rule.origin = "r1"
    p.rules.append(rule)
    networks = {"inside": ["10.1.0.0/24"], "outside": ["0.0.0.0/0", "::/0"]}
    hcl = Hcl(cli.convert(copy.deepcopy(p), "terraform-azure", Report(), Options(zone_networks=networks)))
    template = json.loads(cli.convert(copy.deepcopy(p), "azure", Report(), Options(zone_networks=networks)))
    ours = [r.attributes["description"] for b in resources(hcl, "azurerm_network_security_group").values() for r in b.all("security_rule")]
    arm = [r["properties"]["description"] for res in template["resources"] for r in res["properties"]["securityRules"]]
    assert ours == arm and any(nasty[:40] in text for text in ours)
    for text in ("plain", nasty, "${", "%{", "$${", "\\", '"', "\u0085", "\x7f"):
        assert hcl_string(emit_terraform.string(text)) == text
    taken: set = set()
    assert [emit_terraform.identifier(t, taken, "g") for t in ("1web", "web", "Web", "w e/b", "")] == ["g_1web", "web", "Web_2", "w_e_b", "g"]
    assert emit_terraform.comment("a\nb\rc") == "# a b c"


def test_application_security_groups_of_a_template_become_data_sources() -> None:
    rule = Z.cli_rule("Allow-Web", "Inbound", 100, destinationApplicationSecurityGroups=[
        {"id": "[resourceId('Microsoft.Network/applicationSecurityGroups', parameters('asg_name'))]"}])
    del rule["destinationAddressPrefix"]
    document = {"$schema": Z.SCHEMA, "parameters": {"asg_name": {"type": "String", "defaultValue": "asg-o'web"}},
                "resources": [{"type": "Microsoft.Network/networkSecurityGroups", "name": "nsg_web",
                               "properties": {"securityRules": [{"name": "Allow-Web", "properties": Z.properties(rule)}]}}]}  # fmt: skip
    p = parse_azure.parse(json.dumps(document).encode(), Report())
    text = cli.convert(p, "terraform-azure", Report(), Options(zone_networks={"nsg_web": ["10.30.1.0/24"], "outside": ["0.0.0.0/0", "::/0"]}))
    hcl = Hcl(text)
    data = [b for b in hcl.root.all("data") if b.labels[0] == "azurerm_application_security_group"]
    assert len(data) == 1 and data[0].attributes["name"] == "asg-o'web"
    used = [r.attributes.get("destination_application_security_group_ids") for b in resources(hcl, "azurerm_network_security_group").values()
            for r in b.all("security_rule") if "destination_application_security_group_ids" in r.attributes]  # fmt: skip
    assert used and all(i == [Ref(["data", "azurerm_application_security_group", data[0].labels[1], "id"])] for i in used)


def test_the_command_line(tmp_path: Any) -> None:
    out = tmp_path / "aws.tf"
    assert cli.main(["convert", str(DATA / "terraform_aws_sample.json"), "--to", "terraform-aws", "-o", str(out), "-q"]) == 0
    Hcl(out.read_text(encoding="utf-8"))
    out = tmp_path / "azure.tf"
    assert cli.main(["convert", str(DATA / "terraform_azure_sample.json"), "--to", "terraform-azure", "-o", str(out), "-q"]) == 0
    Hcl(out.read_text(encoding="utf-8"))
    assert cli.main(["convert", str(DATA / "terraform_azure_sample.json"), "--from", "terraform-aws", "--to", "json", "-q"]) != 0


# -- review round 34 -----------------------------------------------------------------------------


def changes_plan(planned: List[Dict[str, Any]], changes: List[Dict[str, Any]], configuration: List[Dict[str, Any]] = (), **top: Any) -> bytes:
    return json.dumps(dict({"format_version": "1.2", "planned_values": {"root_module": {"resources": planned}}, "resource_changes": changes,
                            "configuration": {"root_module": {"resources": list(configuration)}}}, **top)).encode()  # fmt: skip


def legacy(group: str, port: int, cidr: str) -> Dict[str, Any]:
    return {"id": f"sgrule-{port}", "type": "ingress", "security_group_id": group, "protocol": "tcp", "from_port": port, "to_port": port,
            "cidr_blocks": [cidr], "ipv6_cidr_blocks": [], "prefix_list_ids": [], "self": False, "source_security_group_id": None,
            "description": ""}  # fmt: skip


def allowed_ports(model: Policy) -> List[str]:
    return sorted(s for r in model.rules if r.action == Action.ALLOW and r.enabled and not r.unsupported for s in r.services)


def test_r34_what_a_plan_deletes_or_replaces_is_not_read_from_the_echo() -> None:
    web = sg("web", "sg-1", [tcp(22, "0.0.0.0/0"), tcp(443, "10.0.0.0/8")])
    member = eni("e", "eni-1", "10.0.0.5", ["sg-1"])
    deleted = {"address": "aws_security_group_rule.ssh", "type": "aws_security_group_rule",
               "change": {"actions": ["delete"], "before": legacy("sg-1", 22, "0.0.0.0/0"), "after": None}}  # fmt: skip
    model, report = parse(changes_plan([web, member], [deleted]))
    assert allowed_ports(model) == ["tcp-443"]
    # Replaced: the old CIDR goes, the new one is read from the planned resource.
    new = item("aws_security_group_rule", "ssh", legacy("sg-1", 22, "192.0.2.0/24"))
    replaced = dict(deleted, change={"actions": ["delete", "create"], "before": legacy("sg-1", 22, "0.0.0.0/0"), "after": legacy("sg-1", 22, "192.0.2.0/24")})
    model, _ = parse(changes_plan([web, member, new], [replaced]))
    assert [r.sources for r in model.rules if "tcp-22" in r.services] == [["192.0.2.0/24"]]
    # An attachment the plan deletes: the interface's groups repeat it.
    attached = eni("e", "eni-1", "10.0.0.5", ["sg-1", "sg-2"])
    other = sg("other", "sg-2", [tcp(3389, "0.0.0.0/0")])
    gone = {"address": "aws_network_interface_sg_attachment.a", "type": "aws_network_interface_sg_attachment",
            "change": {"actions": ["delete"], "before": {"security_group_id": "sg-2", "network_interface_id": "eni-1"}}}  # fmt: skip
    model, _ = parse(changes_plan([web, other, attached], [gone]))
    assert "tcp-3389" not in allowed_ports(model)
    # Azure: a separate rule the plan deletes, still in the inline rules of its group.
    nsg = item("azurerm_network_security_group", "g", {"id": "/x/networkSecurityGroups/g", "name": "g", "resource_group_name": "rg",
                                                       "security_rule": [azurerm_rule(random.Random(1), Z.cli_rule("ssh", "Inbound", 100, destinationPortRange="22"))]},
               provider=AZURERM)  # fmt: skip
    before = dict(nsg["values"]["security_rule"][0], resource_group_name="rg", network_security_group_name="g")
    model, _ = parse(changes_plan([nsg], [{"address": "azurerm_network_security_rule.ssh", "type": "azurerm_network_security_rule",
                                           "change": {"actions": ["delete"], "before": before}}]))  # fmt: skip
    assert not [r for r in model.rules if r.name == "g:ssh"]


def test_r34_inline_rules_that_say_otherwise_than_their_resource() -> None:
    rng = random.Random(2)
    stale = azurerm_rule(rng, Z.cli_rule("ssh", "Inbound", 100, protocol="Tcp", destinationPortRange="*"))
    fresh = azurerm_rule(rng, Z.cli_rule("ssh", "Inbound", 100, protocol="Tcp", source="10.0.0.0/8", destinationPortRange="22"))
    nsg = item("azurerm_network_security_group", "g", {"id": "/x/networkSecurityGroups/g", "name": "g", "resource_group_name": "rg",
                                                       "security_rule": [stale]}, provider=AZURERM)  # fmt: skip
    rule = item("azurerm_network_security_rule", "ssh", dict(fresh, resource_group_name="rg", network_security_group_name="g"), provider=AZURERM)
    model, report = parse(show(nsg, rule))
    assert "TERRAFORM_CONFLICT" in codes(report)
    assert [(r.sources, r.services) for r in model.rules if r.name == "g:ssh"] == [(["10.0.0.0/8"], ["tcp-22"])]
    # A network ACL: inline entry 100 allows, the separate entry 100 denies.
    acl = item("aws_network_acl", "n", {"id": "acl-1", "vpc_id": "vpc-1", "subnet_ids": ["subnet-1"], "egress": [],
                                        "ingress": [{"rule_no": 100, "action": "allow", "protocol": "-1", "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": "",
                                                     "from_port": 0, "to_port": 0, "icmp_type": 0, "icmp_code": 0}]})  # fmt: skip
    deny = item("aws_network_acl_rule", "d", {"network_acl_id": "acl-1", "rule_number": 100, "egress": False, "protocol": "-1", "rule_action": "deny",
                                              "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": None, "from_port": 0, "to_port": 0,
                                              "icmp_type": None, "icmp_code": None})  # fmt: skip
    subnet = item("aws_subnet", "s", {"id": "subnet-1", "vpc_id": "vpc-1", "cidr_block": "10.0.0.0/24"})
    model, report = parse(show(sg("b", "sg-2", [tcp(443, "0.0.0.0/0")]), acl, deny, subnet, eni("e", "eni-1", "10.0.0.5", ["sg-2"])))
    assert "TERRAFORM_CONFLICT" in codes(report)
    pkt = Packet("", "", "198.51.100.7", "10.0.0.5", "tcp", 40000, 443)
    assert model_allows(model, pkt) is False


def test_r34_rule_lists_and_values_a_plan_does_not_know() -> None:
    nsg = {"id": "/x/networkSecurityGroups/g", "name": "g", "resource_group_name": "rg"}
    # A rule that is not known yet (null), and a list of a group the plan creates that nothing else fills in.
    for values, action in ((dict(nsg, security_rule=[None]), "update"), (dict(nsg), "create")):
        model, report = parse(changes_plan([item("azurerm_network_security_group", "g", values, provider=AZURERM)],
                                           [{"address": "azurerm_network_security_group.g", "change": {"actions": [action]}}]))  # fmt: skip
        assert "TERRAFORM_UNKNOWN" in codes(report)
        assert [r.unsupported for r in model.rules if r.name == "g:(not known)"], [r.name for r in model.rules]
    # A port that is not known: the rule is not converted.
    values = azurerm_rule(random.Random(3), Z.cli_rule("app", "Inbound", 100, source="10.0.0.0/8", destinationPortRange="443"))
    del values["destination_port_range"]
    rule = item("azurerm_network_security_rule", "app", dict(values, resource_group_name="rg", network_security_group_name="g"), provider=AZURERM)
    model, report = parse(changes_plan([item("azurerm_network_security_group", "g", dict(nsg, security_rule=[]), provider=AZURERM), rule],
                                       [{"address": "azurerm_network_security_rule.app", "change": {"actions": ["create"],
                                                                                                     "after_unknown": {"destination_port_range": True}}}]))  # fmt: skip
    assert "TERRAFORM_UNKNOWN" in codes(report) and [r.unsupported for r in model.rules if r.name == "g:app"][0]
    # ICMP without a known type; a network ACL entry without a known number.
    icmp = item("aws_vpc_security_group_ingress_rule", "i", dict(single_values("icmp", None, cidr_ipv4="10.0.0.0/8"), security_group_id="sg-1"))
    del icmp["values"]["from_port"]
    model, _ = parse(changes_plan([sg("a", "sg-1"), icmp, eni("e", "eni-1", "10.0.0.5", ["sg-1"])], []))
    assert [r.unsupported for r in model.rules if r.name == "a-in-1"][0]
    entry = item("aws_network_acl_rule", "e", {"network_acl_id": "acl-1", "egress": False, "protocol": "6", "rule_action": "allow",
                                               "cidr_block": "198.51.100.0/24", "ipv6_cidr_block": None, "from_port": 443, "to_port": 443,
                                               "icmp_type": None, "icmp_code": None})  # fmt: skip
    acl = item("aws_network_acl", "n", {"id": "acl-1", "vpc_id": "vpc-1", "subnet_ids": ["subnet-1"], "ingress": [], "egress": []})
    subnet = item("aws_subnet", "s", {"id": "subnet-1", "vpc_id": "vpc-1", "cidr_block": "10.0.0.0/24"})
    _, report = parse(changes_plan([sg("b", "sg-2", [tcp(443, "0.0.0.0/0")]), acl, entry, subnet, eni("e", "eni-1", "10.0.0.5", ["sg-2"])], []))
    assert "AWS_NACL_NOT_CONVERTED" in codes(report)
    # Rule names from a variable: each rule its own, none dropped as a repeat, none converted.
    written = [{"name": {"references": ["var.prefix"]}, "priority": {"constant_value": p}, "direction": {"constant_value": "Inbound"},
                "access": {"constant_value": a}, "protocol": {"constant_value": "*"}, "source_port_range": {"constant_value": "*"},
                "destination_port_range": {"constant_value": "*"}, "source_address_prefix": {"constant_value": "*"},
                "destination_address_prefix": {"constant_value": "*"}} for p, a in ((100, "Deny"), (200, "Allow"))]  # fmt: skip
    model, report = parse(changes_plan([item("azurerm_network_security_group", "g", dict(nsg, security_rule=[None, None]), provider=AZURERM)], [],
                                       [{"address": "azurerm_network_security_group.g", "expressions": {"security_rule": written}}]))  # fmt: skip
    mine = [r for r in model.rules if r.name.startswith("g:(not known")]
    assert len(mine) == 2 and all(r.unsupported for r in mine)


def test_r34_entries_of_an_acl_not_in_the_state_apply() -> None:
    deny = item("aws_network_acl_rule", "d", {"network_acl_id": "acl-2", "rule_number": 100, "egress": False, "protocol": "-1", "rule_action": "deny",
                                              "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": None, "from_port": 0, "to_port": 0,
                                              "icmp_type": None, "icmp_code": None})  # fmt: skip
    association = item("aws_network_acl_association", "a", {"network_acl_id": "acl-2", "subnet_id": "subnet-1"})
    default = item("aws_default_network_acl", "d", {"id": "acl-1", "default_network_acl_id": "acl-1", "subnet_ids": [], "egress": [],
                                                    "ingress": [{"rule_no": 100, "action": "allow", "protocol": "-1", "cidr_block": "0.0.0.0/0",
                                                                 "ipv6_cidr_block": "", "from_port": 0, "to_port": 0, "icmp_type": 0, "icmp_code": 0}]})  # fmt: skip
    subnet = item("aws_subnet", "s", {"id": "subnet-1", "vpc_id": "vpc-1", "cidr_block": "10.0.0.0/24"})
    model, report = parse(show(sg("b", "sg-2", [tcp(443, "0.0.0.0/0")]), deny, association, default, subnet, eni("e", "eni-1", "10.0.0.5", ["sg-2"])))
    assert "TERRAFORM_ACL_NOT_IN_STATE" in codes(report) and "may deny" in report.to_text()
    assert [r for r in model.rules if r.action == Action.DROP and "acl-2" in r.description]


def test_r34_errored_and_incomplete_plans() -> None:
    with pytest.raises(ParseError, match="errored"):
        parse(changes_plan([sg("a", "sg-1")], [], errored=True))
    _, report = parse(changes_plan([sg("a", "sg-1")], [], complete=False))
    assert "TERRAFORM_INCOMPLETE" in codes(report)


def test_r34_odd_text_and_detection(tmp_path: Any) -> None:
    source = tmp_path / "s.json"
    rule = azurerm_rule(random.Random(4), Z.cli_rule("r\ud800x", "Inbound", 100))
    source.write_text(json.dumps({"format_version": "1.0", "values": {"root_module": {"resources": [
        item("azurerm_network_security_group", "g", {"id": "/x/g", "name": "g", "security_rule": [rule]}, provider=AZURERM)]}}}), encoding="utf-8")
    assert cli.main(["convert", str(source), "--to", "terraform-azure", "-o", str(tmp_path / "o.tf"), "-q"]) == 0
    # A data source of another provider does not make a state of two.
    state = json.loads((DATA / "terraform_azure_sample.json").read_text(encoding="utf-8"))
    state["values"]["root_module"]["resources"].append({"address": "data.aws_security_group.x", "mode": "data", "type": "aws_security_group",
                                                        "name": "x", "provider_name": AWS, "values": {"id": "sg-9"}})  # fmt: skip
    assert cli.detect_format(json.dumps(state, indent=2).encode()) == "terraform-azure"
    with pytest.raises(FwshiftError, match="without the firewall resources"):
        cli.detect_format(b'{"format_version":"1.0"}')
    with pytest.raises(FwshiftError, match="--policy is for"):
        cli.load((DATA / "terraform_azure_sample.json").read_bytes(), "terraform-azure", Report(), policy="vpc-1")
    # In a state, a value that is missing is said as missing, not as unknown to a plan.
    _, report = parse(show(sg("a", "sg-1"), item("aws_network_interface", "e", {"id": "eni-1", "subnet_id": "s", "security_groups": ["sg-1"]})))
    assert "values the state does not hold: aws_network_interface.e.private_ip" in report.to_text()


def test_r34_a_plan_that_creates_an_acl_associated_by_resources_and_modules_with_count() -> None:
    acl = item("aws_network_acl", "n", {"vpc_id": "vpc-1", "ingress": [], "egress": []})
    association = item("aws_network_acl_association", "a", {"subnet_id": "subnet-1"})
    data = changes_plan([sg("b", "sg-2", [tcp(443, "0.0.0.0/0")]), acl, association], [{"address": "aws_network_acl.n", "change": {"actions": ["create"]}}],
                        [{"address": "aws_network_acl_association.a", "expressions": {"network_acl_id": {"references": ["aws_network_acl.n.id", "aws_network_acl.n"]}}},
                         {"address": "aws_network_acl.n", "expressions": {"ingress": [], "egress": []}}])  # fmt: skip
    _, report = parse(data)
    assert "TERRAFORM_UNKNOWN" not in codes(report), report.to_text()
    # A module with count: its configuration is one, its resources are in module.m[0].
    group = item("aws_security_group", "a", {"name": "a", "vpc_id": "vpc-1", "ingress": [], "egress": []}, module="module.m[0]")
    rule = item("aws_vpc_security_group_ingress_rule", "r", single_values("tcp", 443, cidr_ipv4="192.0.2.0/24"), module="module.m[0]")
    calls = {"m": {"module": {"resources": [{"address": "aws_vpc_security_group_ingress_rule.r",
                                             "expressions": {"security_group_id": {"references": ["aws_security_group.a.id", "aws_security_group.a"]}}}]}}}  # fmt: skip
    data = json.dumps({"format_version": "1.2", "planned_values": {"root_module": {"resources": [eni("e", "eni-1", "10.0.0.5", ["module.m[0].aws_security_group.a"])],
                                                                                   "child_modules": [{"address": "module.m[0]", "resources": [group, rule]}]}},
                       "configuration": {"root_module": {"module_calls": calls}}}).encode()  # fmt: skip
    model, report = parse(data)
    assert "TERRAFORM_UNKNOWN" not in codes(report) and [r.sources for r in model.rules if r.name == "a-in-1"] == [["192.0.2.0/24"]]


def test_data_sources_deposed_objects_and_what_a_plan_marks_unknown() -> None:
    """A data source is not a resource of the state; a deposed object of a raw state is left out; what after_unknown
    marks is not known, whatever the planned values hold."""
    data = {"address": "data.aws_security_group.x", "mode": "data", "type": "aws_security_group", "name": "x", "provider_name": AWS,
            "values": {"id": "sg-9", "name": "x", "vpc_id": "vpc-1", "ingress": [tcp(3389, "0.0.0.0/0")], "egress": []}}  # fmt: skip
    model, _ = parse(show(sg("a", "sg-1", [tcp(22, "10.0.0.0/8")]), data, eni("e", "eni-1", "10.0.0.5", ["sg-1", "sg-9"])))
    assert "tcp-3389" not in allowed_ports(model) and "x" not in model.address_groups
    raw = {"version": 4, "terraform_version": "1.9.0", "serial": 1, "lineage": "x", "outputs": {}, "resources": [
        {"mode": "managed", "type": "aws_security_group", "name": "a", "instances": [
            {"attributes": {"id": "sg-1", "name": "a", "vpc_id": "vpc-1", "ingress": [tcp(22, "10.0.0.0/8")], "egress": []}},
            {"deposed": "00000001", "attributes": {"id": "sg-0", "name": "old", "vpc_id": "vpc-1", "ingress": [tcp(3389, "0.0.0.0/0")], "egress": []}}]},
        {"mode": "managed", "type": "aws_network_interface", "name": "e", "instances": [
            {"attributes": {"id": "eni-1", "subnet_id": "s", "private_ip": "10.0.0.5", "private_ips": ["10.0.0.5"], "security_groups": ["sg-1", "sg-0"]}}]}]}  # fmt: skip
    model, report = parse(json.dumps(raw).encode())
    assert "tcp-3389" not in allowed_ports(model) and "TERRAFORM_DEPOSED" in codes(report)
    nsg = item("azurerm_network_security_group", "g", {"id": "/x/networkSecurityGroups/g", "name": "g", "resource_group_name": "rg",
                                                       "security_rule": [azurerm_rule(random.Random(5), Z.cli_rule("ok", "Inbound", 100))]},
               provider=AZURERM)  # fmt: skip
    model, report = parse(changes_plan([nsg], [{"address": "azurerm_network_security_group.g", "change": {"actions": ["update"],
                                                                                                          "after_unknown": {"security_rule": True}}}]))  # fmt: skip
    assert "TERRAFORM_UNKNOWN" in codes(report) and [r.unsupported for r in model.rules if r.name == "g:(not known)"][0]


def test_inline_rules_of_a_group_a_plan_does_not_know_and_groups_of_other_accounts() -> None:
    web = item("aws_security_group", "web", {"id": "sg-1", "name": "web", "vpc_id": "vpc-1", "ingress": [None], "egress": []})
    model, report = parse(changes_plan([web, eni("e", "eni-1", "10.0.0.5", ["sg-1"])], [{"address": "aws_security_group.web", "change": {"actions": ["update"]}}]))
    assert "aws_security_group.web.ingress" in report.to_text()
    assert [r for r in model.rules if r.unsupported and "web" in r.destinations]
    model, _ = load("terraform_aws_sample.json")
    audit = [g for g in model.address_groups.values() if "sg-0f9e8d7c6b5a43001" in g.description]
    assert audit and '"UserId": "444455556666"' in audit[0].dynamic_filter


def test_icmpv6_of_an_unknown_type_and_an_association_that_moves_a_subnet() -> None:
    icmp = item("aws_vpc_security_group_ingress_rule", "i", dict(single_values("icmpv6", None, cidr_ipv6="2001:db8::/32"), security_group_id="sg-1"))
    del icmp["values"]["from_port"]
    member = eni("e", "eni-1", "10.0.0.5", ["sg-1"])
    member["values"]["ipv6_addresses"] = ["2001:db8::5"]
    model, report = parse(changes_plan([sg("a", "sg-1"), icmp, member], []))
    assert "TERRAFORM_UNKNOWN" in codes(report) and [r.unsupported for r in model.rules if r.name == "a-in-1"][0]
    # The subnet_ids of ACL A still name the subnet that an association of the plan moves to ACL B.
    def acl(name: str, ident: str, action: str, subnets: List[str]) -> Dict[str, Any]:
        return item("aws_network_acl", name, {"id": ident, "vpc_id": "vpc-1", "subnet_ids": subnets, "egress": [], "ingress": [
            {"rule_no": 100, "action": action, "protocol": "-1", "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": "", "from_port": 0, "to_port": 0,
             "icmp_type": 0, "icmp_code": 0}]})  # fmt: skip
    moved = item("aws_network_acl_association", "m", {"id": "aclassoc-9", "network_acl_id": "acl-b", "subnet_id": "subnet-1"})
    subnet = item("aws_subnet", "s", {"id": "subnet-1", "vpc_id": "vpc-1", "cidr_block": "10.0.0.0/24"})
    model, _ = parse(show(sg("b", "sg-2", [tcp(443, "0.0.0.0/0")]), acl("b", "acl-b", "deny", []), acl("a", "acl-a", "allow", ["subnet-1"]), moved,
                          subnet, eni("e", "eni-1", "10.0.0.5", ["sg-2"])))  # fmt: skip
    assert model_allows(model, Packet("", "", "198.51.100.7", "10.0.0.5", "tcp", 40000, 443)) is False


def test_elastic_ip_of_a_second_address_acl_entries_of_a_plan_and_a_group_not_in_the_state() -> None:
    interface = item("aws_network_interface", "e", {"id": "eni-1", "subnet_id": "subnet-1", "private_ip": "10.0.0.5", "private_ips": ["10.0.0.5", "10.0.0.6"],
                                                    "security_groups": ["sg-1"]})  # fmt: skip
    eip = item("aws_eip", "p", {"id": "eipalloc-1", "network_interface": "eni-1", "associate_with_private_ip": "10.0.0.6", "private_ip": "10.0.0.6",
                                "public_ip": "192.0.2.6", "instance": ""})  # fmt: skip
    model, _ = parse(show(sg("a", "sg-1", [tcp(22, "0.0.0.0/0")]), interface, eip))
    assert [(n.sources, n.source_translation.addresses) for n in model.nat_rules if n.source_translation] == [(["10.0.0.6"], ["192.0.2.6"])]
    # An ICMP entry whose type the plan does not know; an entry the plan deletes, still in the inline list.
    acl = item("aws_network_acl", "n", {"id": "acl-1", "vpc_id": "vpc-1", "subnet_ids": ["subnet-1"], "egress": [], "ingress": [
        {"rule_no": 50, "action": "deny", "protocol": "6", "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": "", "from_port": 443, "to_port": 443,
         "icmp_type": 0, "icmp_code": 0},
        {"rule_no": 100, "action": "allow", "protocol": "-1", "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": "", "from_port": 0, "to_port": 0,
         "icmp_type": 0, "icmp_code": 0}]})  # fmt: skip
    subnet = item("aws_subnet", "s", {"id": "subnet-1", "vpc_id": "vpc-1", "cidr_block": "10.0.0.0/24"})
    before = {"network_acl_id": "acl-1", "rule_number": 50, "egress": False, "protocol": "6", "rule_action": "deny", "cidr_block": "0.0.0.0/0",
              "ipv6_cidr_block": None, "from_port": 443, "to_port": 443, "icmp_type": None, "icmp_code": None}  # fmt: skip
    members = [sg("b", "sg-2", [tcp(443, "0.0.0.0/0")]), acl, subnet, eni("e", "eni-1", "10.0.0.5", ["sg-2"])]
    model, _ = parse(changes_plan(members, [{"address": "aws_network_acl_rule.d", "type": "aws_network_acl_rule",
                                             "change": {"actions": ["delete"], "before": before}}]))  # fmt: skip
    assert model_allows(model, Packet("", "", "198.51.100.7", "10.0.0.5", "tcp", 40000, 443)) is True
    icmp = item("aws_network_acl_rule", "i", {"network_acl_id": "acl-1", "rule_number": 40, "egress": False, "protocol": "1", "rule_action": "allow",
                                              "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": None, "from_port": None, "to_port": None, "icmp_code": -1})  # fmt: skip
    _, report = parse(changes_plan(members + [icmp], []))
    assert {"TERRAFORM_UNKNOWN", "AWS_NACL_NOT_CONVERTED"} <= codes(report)
    # Rules of a network security group the state does not hold.
    rule = item("azurerm_network_security_rule", "r", dict(azurerm_rule(random.Random(6), Z.cli_rule("ok", "Inbound", 100)), resource_group_name="rg",
                                                            network_security_group_name="elsewhere"), provider=AZURERM)  # fmt: skip
    _, report = parse(show(item("azurerm_network_security_group", "g", {"id": "/x/g", "name": "g", "security_rule": []}, provider=AZURERM), rule))
    assert [n.severity for n in report.notes if n.code == "TERRAFORM_GROUP_NOT_IN_STATE"] == [Severity.REVIEW]
