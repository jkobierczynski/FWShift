# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AWS Network Firewall both ways.

``NfwJudge`` decides connections as the firewall does, from the JSON of the CLI, packet by packet: the stateless rules
for every packet, the stateful engine for what they forward (rules in strict or action order, flow keywords, the
direction of the header, IP-only rules on the first packet of each direction, the default actions). It shares no code
with the parser: the parser works out sets of connections for the moments a flow can be decided, the judge walks the
packets of one connection. Both are written from the same reading of AWS's documentation; they find where the code
disagrees with that reading, not where the reading is wrong.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import random
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load
from test_iptables import Packet, model_allows, random_model, random_packet
from test_nsx import ZONES_AT, zone_of

from fwshift import cli
from fwshift.emitters import awsnfw as emit_awsnfw
from fwshift.errors import ParseError
from fwshift.model import ANY, Action, Address, AddressGroup, AddressKind, Policy, Protocol, Rule, RuleScope, Service, ServiceEntry
from fwshift.options import Options
from fwshift.parsers import awsnfw as parse_awsnfw
from fwshift.report import Report, Severity

REPLY = {1: {8: 0, 13: 14, 15: 16, 17: 18}, 58: {128: 129}}
PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}


# -- the judge --------------------------------------------------------------------------------------------------------


def _ip(text: str) -> Any:
    return ipaddress.ip_address(text)


def _split(text: str) -> List[str]:
    parts, depth, current = [], 0, ""
    for char in text:
        depth += char == "["
        depth -= char == "]"
        if char == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += char
    parts.append(current.strip())
    return parts


def _type_matches(expression: str, value: int) -> bool:
    """itype as Suricata compares it: N, <N, >N, N<>M (strict)."""
    if "<>" in expression:
        low, high = expression.split("<>")
        return int(low) < value < int(high)
    if expression.startswith("<"):
        return value < int(expression[1:])
    if expression.startswith(">"):
        return value > int(expression[1:])
    return value == int(expression)


class _Packet:
    """One packet of a connection."""

    def __init__(self, src: Any, dst: Any, proto: int, sport: int, dport: int, itype: Optional[int], to_server: bool,
                 established: bool, first: bool) -> None:  # fmt: skip
        self.src, self.dst, self.proto, self.sport, self.dport, self.itype = src, dst, proto, sport, dport, itype
        self.to_server, self.established, self.first = to_server, established, first


class _Suricata:
    """A rule as the judge reads it."""

    def __init__(self, text: str, scope: "_Scope", disabled: bool = False) -> None:
        self.scope, self.disabled = scope, disabled
        head, _, options = text.partition("(")
        words = re.findall(r"\[[^\]]*\]|\S+", head)
        # (brackets with spaces inside are kept together by the regular expression above, one level deep, which the tests use)
        self.action, self.proto, self.src, self.sport, self.dir, self.dst, self.dport = [w.lower() if i < 2 else w for i, w in enumerate(words)]
        self.flow: List[str] = []
        self.ip_proto: Optional[int] = None
        self.ip_not: List[int] = []
        self.itype: Optional[str] = None
        for option in options.rstrip().rstrip(")").split(";"):
            key, _, value = option.strip().partition(":")
            if key == "flow":
                self.flow = [w.strip() for w in value.split(",")]
            elif key == "ip_proto" and value.startswith("!"):
                self.ip_not.append(int(value[1:]))
            elif key == "ip_proto":
                self.ip_proto = int(value)
            elif key == "itype":
                self.itype = value.replace(" ", "")

    def address(self, expression: str, address: Any) -> bool:
        expression = expression.strip()
        if expression.lower() == "any":
            return True
        if expression.startswith("!"):
            return not self.address(expression[1:], address)
        if expression.startswith("["):
            parts = _split(expression[1:-1])
            positives = [p for p in parts if not p.startswith("!")]
            negatives = [p[1:] for p in parts if p.startswith("!")]
            inside = any(self.address(p, address) for p in positives) if positives else True
            return inside and not any(self.address(p, address) for p in negatives)
        if expression.startswith("$"):
            return self.scope.variable(expression[1:], address)
        if expression.startswith("@"):
            return any(address in ipaddress.ip_network(c) for c in self.scope.references[expression[1:]])
        network = ipaddress.ip_network(expression, strict=False)
        return address.version == network.version and address in network

    def port(self, expression: str, port: int) -> bool:
        expression = expression.strip()
        if expression.lower() == "any":
            return True
        if expression.startswith("!"):
            return not self.port(expression[1:], port)
        if expression.startswith("["):
            parts = _split(expression[1:-1])
            positives = [p for p in parts if not p.startswith("!")]
            negatives = [p[1:] for p in parts if p.startswith("!")]
            inside = any(self.port(p, port) for p in positives) if positives else True
            return inside and not any(self.port(p, port) for p in negatives)
        if expression.startswith("$"):
            definitions = self.scope.ports[expression[1:]]
            return self.port("[" + ",".join(definitions) + "]", port)
        low, colon, high = expression.partition(":")
        return int(low or 0) <= port <= (int(high or 65535) if colon else int(low))

    def matches(self, pkt: _Packet) -> bool:
        if self.proto == "tcp" and pkt.proto != 6 or self.proto == "udp" and pkt.proto != 17:
            return False
        if self.proto == "icmp" and pkt.proto not in (1, 58):
            return False
        if self.ip_proto is not None and pkt.proto != self.ip_proto or pkt.proto in self.ip_not:
            return False
        if self.itype is not None and (pkt.proto not in (1, 58) or pkt.itype is None or not _type_matches(self.itype, pkt.itype)):
            return False
        if not self.flow and not pkt.first:
            return False  # (an IP-only rule is evaluated on the first packet of each direction)
        if "to_server" in self.flow and not pkt.to_server or "to_client" in self.flow and pkt.to_server:
            return False
        if "established" in self.flow and not pkt.established or "not_established" in self.flow and pkt.established:
            return False
        ported = pkt.proto in (6, 17)
        forward = (self.address(self.src, pkt.src) and self.address(self.dst, pkt.dst)
                   and (not ported or (self.port(self.sport, pkt.sport) and self.port(self.dport, pkt.dport))))  # fmt: skip
        if forward:
            return True
        return self.dir == "<>" and (self.address(self.src, pkt.dst) and self.address(self.dst, pkt.src)
                                     and (not ported or (self.port(self.sport, pkt.dport) and self.port(self.dport, pkt.sport))))  # fmt: skip


class _Scope:
    """The variables of a rule group."""

    def __init__(self, body: Dict[str, Any], policy_home: List[str], references: Dict[str, List[str]]) -> None:
        variables = body.get("RuleVariables", {})
        self.sets = {k: v["Definition"] for k, v in variables.get("IPSets", {}).items()}
        self.ports = {k: v["Definition"] for k, v in variables.get("PortSets", {}).items()}
        self.policy_home = policy_home
        self.references: Dict[str, List[str]] = {}
        for name, item in body.get("ReferenceSets", {}).get("IPSetReferences", {}).items():
            ident = item["ReferenceArn"].rsplit("/", 1)[-1]
            if ident in references:  # (a rule that names one without its entries cannot be judged, and is not)
                self.references[name] = references[ident]

    def variable(self, name: str, address: Any) -> bool:
        if name in self.sets:
            return any(address in ipaddress.ip_network(c, strict=False) for c in self.sets[name])
        if name == "HOME_NET":
            return any(address in ipaddress.ip_network(c) for c in self.policy_home)
        if name == "EXTERNAL_NET":  # (the policy's, whatever the group's HOME_NET is)
            return not any(address in ipaddress.ip_network(c) for c in self.policy_home)
        raise KeyError(name)


class NfwJudge:
    def __init__(self, documents: List[Dict[str, Any]]) -> None:
        policy = next(d for d in documents if "FirewallPolicy" in d)["FirewallPolicy"]
        groups = {d["RuleGroupResponse"]["RuleGroupArn"]: d["RuleGroup"] for d in documents if "RuleGroup" in d}
        references = {d["PrefixListId"]: [e["Cidr"] for e in d["Entries"]] for d in documents if "PrefixListId" in d and "Entries" in d}
        home: List[str] = []
        for document in documents:
            for vpc in document.get("Vpcs", []):
                home += [b["CidrBlock"] for b in vpc.get("CidrBlockAssociationSet", [])]
                home += [b["Ipv6CidrBlock"] for b in vpc.get("Ipv6CidrBlockAssociationSet", [])]
        variables = policy.get("PolicyVariables", {}).get("RuleVariables", {})
        if "HOME_NET" in variables:
            home = variables["HOME_NET"]["Definition"]
        self.stateless: List[Tuple[Dict[str, Any], str]] = []
        for reference in sorted(policy.get("StatelessRuleGroupReferences", []), key=lambda r: r["Priority"]):
            body = groups[reference["ResourceArn"]]
            for rule in sorted(body["RulesSource"]["StatelessRulesAndCustomActions"]["StatelessRules"], key=lambda r: r["Priority"]):
                action = next(a for a in rule["RuleDefinition"]["Actions"] if a.startswith("aws:"))
                self.stateless.append((rule["RuleDefinition"]["MatchAttributes"], action))
        self.default = next(a for a in policy["StatelessDefaultActions"] if a.startswith("aws:"))
        self.strict = policy.get("StatefulEngineOptions", {}).get("RuleOrder") == "STRICT_ORDER"
        defaults = policy.get("StatefulDefaultActions", []) if self.strict else []
        self.drop = "strict" if "aws:drop_strict" in defaults else ("established" if any(d.startswith("aws:drop_") for d in defaults) else "")
        self.rules: List[_Suricata] = []
        for reference in sorted(policy.get("StatefulRuleGroupReferences", []), key=lambda r: r["Priority"]):
            body = groups[reference["ResourceArn"]]
            scope = _Scope(body, home, references)
            source = body["RulesSource"]
            if "RulesString" in source:
                for line in source["RulesString"].splitlines():
                    if line.strip() and not line.strip().startswith("#"):
                        self.rules.append(_Suricata(line, scope))
            for item in source.get("StatefulRules", []):
                header = item["Header"]
                options = " ".join(f"{o['Keyword']}:{','.join(o.get('Settings', []))};" for o in item.get("RuleOptions", []))
                text = (f"{item['Action']} {header['Protocol']} {header['Source']} {header['SourcePort']} "
                        f"{'<>' if header['Direction'] == 'ANY' else '->'} {header['Destination']} {header['DestinationPort']} ({options})")
                self.rules.append(_Suricata(text, scope))
        if not self.strict:
            order = {"pass": 0, "drop": 1, "reject": 2, "alert": 3}
            self.rules.sort(key=lambda r: order[r.action])

    def _stateless(self, pkt: _Packet) -> str:
        for match, action in self.stateless:
            if match.get("Sources") and not any(pkt.src in ipaddress.ip_network(a["AddressDefinition"]) for a in match["Sources"]
                                                if ipaddress.ip_network(a["AddressDefinition"]).version == pkt.src.version):  # fmt: skip
                continue
            if match.get("Destinations") and not any(pkt.dst in ipaddress.ip_network(a["AddressDefinition"]) for a in match["Destinations"]
                                                     if ipaddress.ip_network(a["AddressDefinition"]).version == pkt.dst.version):  # fmt: skip
                continue
            if match.get("Protocols") and pkt.proto not in match["Protocols"]:
                continue
            if pkt.proto in (6, 17):
                if match.get("SourcePorts") and not any(r["FromPort"] <= pkt.sport <= r["ToPort"] for r in match["SourcePorts"]):
                    continue
                if match.get("DestinationPorts") and not any(r["FromPort"] <= pkt.dport <= r["ToPort"] for r in match["DestinationPorts"]):
                    continue
            return action
        return self.default

    def allows(self, pkt: Packet) -> Optional[bool]:
        """Whether the connection works; None where the firewall's stateful engine would see half a flow."""
        proto = PROTO.get(pkt.proto) or int(pkt.proto)
        src, dst = _ip(pkt.src), _ip(pkt.dst)
        if src.version != dst.version:
            return None
        packets = [_Packet(src, dst, proto, pkt.sport, pkt.dport, pkt.icmp_type if proto in (1, 58) else None, True, False, True)]
        reply_type = REPLY.get(proto, {}).get(pkt.icmp_type) if proto in (1, 58) else None
        if proto not in (1, 58) or reply_type is not None:
            packets.append(_Packet(dst, src, proto, pkt.dport, pkt.sport, reply_type, False, False, True))
        if proto == 6:
            packets.append(_Packet(src, dst, proto, pkt.sport, pkt.dport, None, True, True, False))
            packets.append(_Packet(dst, src, proto, pkt.dport, pkt.sport, None, False, True, False))
        verdicts = [self._stateless(p) for p in packets]
        if "aws:drop" in verdicts:
            return False
        if "aws:pass" in verdicts and "aws:forward_to_sfe" in verdicts:
            return None
        if "aws:forward_to_sfe" not in verdicts:
            return True
        if self.strict and self.drop == "strict":
            # Strict order with aws:drop_strict: every packet on its own (AWS: "Drop all - Drops all packets"; a pass rule
            # passes the packet it matches). The FWShift lab, 0.41.7: pass rules with flow:to_server and nothing for the
            # replies blocked every connection.
            for p in packets:
                verdict = next((rule.action for rule in self.rules if rule.action != "alert" and rule.matches(p)), "")
                if verdict != "pass":
                    return False
            return True
        decided = ""
        for p in packets:
            if decided == "pass":
                return True
            for rule in self.rules:
                if rule.action == "alert" or not rule.matches(p):
                    continue
                decided = "pass" if rule.action == "pass" else "drop"
                break
            if decided == "drop":
                return False
            if decided:
                continue
            if self.drop == "strict":
                return False
            if self.drop == "established" and (proto != 6 or p.established):
                return False
        return True


# -- documents ---------------------------------------------------------------------------------------------------------

ARN = "arn:aws:network-firewall:eu-west-1:111122223333"


def policy_answer(body: Dict[str, Any], name: str = "pol") -> Dict[str, Any]:
    return {"UpdateToken": "t", "FirewallPolicyResponse": {"FirewallPolicyName": name, "FirewallPolicyArn": f"{ARN}:firewall-policy/{name}"},
            "FirewallPolicy": body}  # fmt: skip


def group_answer(name: str, body: Dict[str, Any], stateless: bool = False) -> Dict[str, Any]:
    kind = "stateless-rulegroup" if stateless else "stateful-rulegroup"
    return {"UpdateToken": "t", "RuleGroup": body,
            "RuleGroupResponse": {"RuleGroupArn": f"{ARN}:{kind}/{name}", "RuleGroupName": name, "Type": "STATELESS" if stateless else "STATEFUL"}}  # fmt: skip


def vpc_answer(*blocks: str) -> Dict[str, Any]:
    four = [{"CidrBlock": b, "CidrBlockState": {"State": "associated"}} for b in blocks if ":" not in b]
    six = [{"Ipv6CidrBlock": b, "Ipv6CidrBlockState": {"State": "associated"}} for b in blocks if ":" in b]
    return {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": four[0]["CidrBlock"] if four else "", "CidrBlockAssociationSet": four,
                      "Ipv6CidrBlockAssociationSet": six}]}  # fmt: skip


def suricata_policy(rules: str, defaults: Optional[List[str]] = None, order: str = "STRICT_ORDER", stateless: Optional[List[Dict[str, Any]]] = None,
                    stateless_default: str = "aws:forward_to_sfe", variables: Optional[Dict[str, Any]] = None,
                    home: Tuple[str, ...] = ("10.0.0.0/22", "2001:db8::/47")) -> List[Dict[str, Any]]:  # fmt: skip
    body: Dict[str, Any] = {"StatelessDefaultActions": [stateless_default], "StatelessFragmentDefaultActions": [stateless_default],
                            "StatefulRuleGroupReferences": [{"ResourceArn": f"{ARN}:stateful-rulegroup/g", "Priority": 1}],
                            "StatefulEngineOptions": {"RuleOrder": order}}  # fmt: skip
    if defaults is not None:
        body["StatefulDefaultActions"] = defaults
    documents = [policy_answer(body)]
    if stateless:
        body["StatelessRuleGroupReferences"] = [{"ResourceArn": f"{ARN}:stateless-rulegroup/s", "Priority": 1}]
        documents.append(group_answer("s", {"RulesSource": {"StatelessRulesAndCustomActions": {"StatelessRules": stateless}}}, True))
    group: Dict[str, Any] = {"RulesSource": {"RulesString": rules}, "StatefulRuleOptions": {"RuleOrder": order}}
    if variables:
        group["RuleVariables"] = variables
    documents.append(group_answer("g", group))
    if home:
        documents.append(vpc_answer(*home))
    return documents


def parse_documents(documents: List[Dict[str, Any]], report: Optional[Report] = None) -> Policy:
    return parse_awsnfw.parse(json.dumps(documents).encode(), report or Report())


def stateless_rule(priority: int, action: str, **match: Any) -> Dict[str, Any]:
    attributes: Dict[str, Any] = {}
    for key, value in match.items():
        if key in ("Sources", "Destinations"):
            attributes[key] = [{"AddressDefinition": cidr} for cidr in value]
        elif key in ("SourcePorts", "DestinationPorts"):
            attributes[key] = [{"FromPort": low, "ToPort": high} for low, high in value]
        else:
            attributes[key] = value
    return {"Priority": priority, "RuleDefinition": {"MatchAttributes": attributes, "Actions": [action]}}


# -- random firewalls -------------------------------------------------------------------------------------------------

CIDRS = ["10.0.0.0/24", "10.0.1.0/24", "10.0.1.128/25", "10.0.2.0/23", "10.0.3.17/32", "10.0.4.0/22", "10.0.0.0/16",
         "2001:db8::/48", "2001:db8:1::/48", "2001:db8:2::/64", "2001:db8:3::2/128", "2001:db8::/32"]  # fmt: skip


def _address(rng: random.Random, simple: bool = False) -> str:
    cidr = rng.choice(CIDRS)
    if simple:
        return rng.choice(["any", cidr, cidr, "$HOME_NET", "$EXTERNAL_NET"])
    return rng.choice(["any", "any", cidr, cidr, "$HOME_NET", "$EXTERNAL_NET", "$NETS", f"[{cidr},{rng.choice(CIDRS)}]",
                       f"[{cidr},!{rng.choice(CIDRS)}]", f"!{cidr}", "!$HOME_NET", f"[$NETS,{cidr}]", "@LIST"])  # fmt: skip


def _ports(rng: random.Random, simple: bool = False) -> str:
    if simple:
        return rng.choice(["any", "any", "80", "8000:8010", "1024:65535"])
    return rng.choice(["any", "any", "any", "80", "443", "8000:8010", "[22,443]", "!80", "[1024:65535,!40000]", "$WEB", "[53,8005]"])


def random_rule(rng: random.Random, sid: int, simple: bool = False) -> str:
    action = rng.choice(["pass", "pass", "pass", "drop", "drop", "reject", "alert"])
    proto = rng.choice(["tcp", "tcp", "udp", "icmp", "ip", "ip"])
    sport, dport = ("any", "any") if proto in ("icmp", "ip") else (_ports(rng, simple), _ports(rng, simple))
    options = []
    flows = ["", "", "to_server", "to_client", "not_established"] + (["established,to_server", "established", "established,to_client"] if proto == "tcp" else [])
    flow = rng.choice(flows)
    if flow:
        options.append(f"flow:{flow};")
    if proto == "icmp" and rng.random() < 0.5:
        options.append(f"itype:{rng.choice([0, 8, 13, 128])};")
    if proto == "ip" and rng.random() < 0.4:
        options.append(f"ip_proto:{rng.choice([47, 6, 17, 1])};")
    direction = "<>" if rng.random() < 0.2 else "->"
    return f"{action} {proto} {_address(rng, simple)} {sport} {direction} {_address(rng, simple)} {dport} ({' '.join(options)} sid:{sid};)"


def random_nfw(rng: random.Random) -> List[Dict[str, Any]]:
    strict = rng.random() < 0.7
    order = "STRICT_ORDER" if strict else "DEFAULT_ACTION_ORDER"
    defaults = rng.choice([[], ["aws:drop_strict"], ["aws:drop_established"], ["aws:drop_established", "aws:alert_established"],
                           ["aws:drop_established_app_layer"]]) if strict else []  # fmt: skip
    body: Dict[str, Any] = {"StatelessDefaultActions": [rng.choice(["aws:forward_to_sfe"] * 8 + ["aws:pass", "aws:drop"])],
                            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"], "StatefulEngineOptions": {"RuleOrder": order},
                            "StatefulDefaultActions": defaults, "StatefulRuleGroupReferences": []}  # fmt: skip
    documents: List[Dict[str, Any]] = [policy_answer(body)]
    if rng.random() < 0.4:
        rules = []
        for priority in range(1, rng.randint(1, 4)):
            match: Dict[str, Any] = {}
            if rng.random() < 0.6:
                match["Sources"] = rng.sample(CIDRS, rng.randint(1, 2))
            if rng.random() < 0.6:
                match["Destinations"] = rng.sample(CIDRS, rng.randint(1, 2))
            protocols = rng.choice([[], [6], [17], [1], [6, 17], [47], [58]])
            if protocols:
                match["Protocols"] = protocols
            if protocols and set(protocols) <= {6, 17}:
                if rng.random() < 0.5:
                    match["DestinationPorts"] = rng.choice([[(80, 80)], [(8000, 8010)], [(22, 22), (443, 443)]])
                if rng.random() < 0.3:
                    match["SourcePorts"] = rng.choice([[(1024, 65535)], [(80, 80)]])
            rules.append(stateless_rule(priority * 10, rng.choice(["aws:pass", "aws:drop", "aws:forward_to_sfe"]), **match))
        body["StatelessRuleGroupReferences"] = [{"ResourceArn": f"{ARN}:stateless-rulegroup/edge", "Priority": 1}]
        documents.append(group_answer("edge", {"RulesSource": {"StatelessRulesAndCustomActions": {"StatelessRules": rules}}}, True))
    sid = 1
    for index in range(rng.randint(1, 2)):
        name = f"g{index}"
        body["StatefulRuleGroupReferences"].append({"ResourceArn": f"{ARN}:stateful-rulegroup/{name}", "Priority": 10 * (index + 1)})
        group: Dict[str, Any] = {"StatefulRuleOptions": {"RuleOrder": order},
                                 "RuleVariables": {"IPSets": {"NETS": {"Definition": ["10.0.1.0/24", "2001:db8:2::/64"]}},
                                                   "PortSets": {"WEB": {"Definition": ["80", "443", "8000:8010"]}}},
                                 "ReferenceSets": {"IPSetReferences": {"LIST": {"ReferenceArn": "arn:aws:ec2:eu-west-1:111122223333:prefix-list/pl-1"}}}}  # fmt: skip
        if rng.random() < 0.2:
            group["RuleVariables"]["IPSets"]["HOME_NET"] = {"Definition": ["10.0.4.0/22"]}  # (EXTERNAL_NET stays the policy's)
        if rng.random() < 0.5:
            lines = []
            for _ in range(rng.randint(2, 9)):
                lines.append(random_rule(rng, sid))
                sid += 1
            group["RulesSource"] = {"RulesString": "\n".join(lines) + "\n"}
        else:
            rules = []
            for _ in range(rng.randint(2, 9)):
                text = random_rule(rng, sid, simple=True)
                sid += 1
                found = re.match(r"(\w+) (\w+) (\S+) (\S+) (\S+) (\S+) (\S+) \((.*)\)$", text)
                assert found
                action, proto, src, sport, direction, dst, dport, options = found.groups()
                header = {"Protocol": proto.upper(), "Source": src.upper() if src == "any" else src, "SourcePort": sport.upper(),
                          "Direction": "ANY" if direction == "<>" else "FORWARD", "Destination": dst.upper() if dst == "any" else dst,
                          "DestinationPort": dport.upper()}  # fmt: skip
                rule_options = []
                for option in options.split(";"):
                    key, _, value = option.strip().partition(":")
                    if key:
                        rule_options.append({"Keyword": key, "Settings": [value]} if value else {"Keyword": key})
                rules.append({"Action": action.upper(), "Header": header, "RuleOptions": rule_options})
            group["RulesSource"] = {"StatefulRules": rules}
        documents.append(group_answer(name, group))
    if rng.random() < 0.3:
        body["PolicyVariables"] = {"RuleVariables": {"HOME_NET": {"Definition": ["10.0.0.0/23", "2001:db8:1::/48"]}}}
    documents.append(vpc_answer("10.0.0.0/22", "2001:db8::/47"))
    documents.append({"PrefixListId": "pl-1", "Entries": [{"Cidr": "10.0.2.0/24"}, {"Cidr": "10.0.4.0/24"}]})
    return documents


def nfw_packet(rng: random.Random) -> Packet:
    pkt = random_packet(rng, rng.choice([4, 6]))
    if rng.random() < 0.3:
        pkt.sport, pkt.dport = rng.choice([80, 443, 8005, 22]), rng.choice([1024, 40000, 80])
    if rng.random() < 0.2:
        pkt.dst = rng.choice(["10.0.2.9", "10.0.4.1", "198.51.100.7", "2001:db8:4::1"] if ":" not in pkt.src else ["2001:db8:4::1", "2001:db8:2::9"])
    return pkt


@pytest.mark.parametrize("block", range(4))
def test_parsed_policy_decides_like_the_judge(block: int) -> None:
    """Random policies, stateless and stateful, in both orders and with every default: the model the parser makes gives
    the judge's verdict for every connection the judge can decide."""
    compared = 0
    for seed in range(block * 60, block * 60 + 60):
        rng = random.Random(seed)
        documents = random_nfw(rng)
        report = Report()
        model = parse_documents(documents, report)
        flagged = [r.name for r in model.rules if r.unsupported and r.enabled]
        assert not flagged, (seed, flagged)
        judge = NfwJudge(documents)
        for _ in range(250):
            pkt = nfw_packet(rng)
            verdict = judge.allows(pkt)
            if verdict is None:
                continue
            compared += 1
            assert model_allows(model, pkt) == verdict, (seed, pkt, json.dumps(documents, indent=1))
    assert compared > 10000


# -- the judge of a script --------------------------------------------------------------------------------------------


def script_documents(text: str) -> List[Dict[str, Any]]:
    """The policy and the rule groups an emitted script creates, as describe answers (the ARNs made up)."""
    groups: Dict[int, Dict[str, Any]] = {}
    names: Dict[int, str] = {}
    lines = text.splitlines()
    policy: Optional[Dict[str, Any]] = None
    for index, line in enumerate(lines):
        found = re.match(r"cat > \"\$TMP/group(\d+)\.json\" <<'FWSHIFT_JSON'$", line)
        if found:
            end = lines.index("FWSHIFT_JSON", index)
            groups[int(found.group(1))] = json.loads("\n".join(lines[index + 1:end]))
        found = re.match(r"G(\d+)=\$\(group (\S+) (\d+) \"\$TMP/group\d+\.json\"\) \|\| exit 1$", line)
        if found:
            names[int(found.group(1))] = found.group(2)
            assert int(found.group(3)) >= 2 * len([r for r in groups[int(found.group(1))]["RulesSource"]["RulesString"].splitlines() if r])
        if line == 'cat > "$TMP/policy.json" <<FWSHIFT_JSON':
            body = lines[index + 1]
            for number in groups:
                body = body.replace("${G%d}" % number, f"{ARN}:stateful-rulegroup/{names[number]}")
            assert "$" not in body
            policy = json.loads(body)
    assert policy is not None and set(groups) == set(names)
    out = [policy_answer(policy, "fwshift")]
    for number, body in groups.items():
        assert set(body) <= {"RuleVariables", "RulesSource", "StatefulRuleOptions"}
        for name in body.get("RuleVariables", {}).get("IPSets", {}):
            assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", name) and name.upper() not in ("HOME_NET", "EXTERNAL_NET")
        rules = body["RulesSource"]["RulesString"]
        assert len(rules) <= 2_000_000
        sids = [re.search(r"sid:(\d+);", line).group(1) for line in rules.splitlines() if line]  # type: ignore[union-attr]
        assert len(sids) == len(set(sids))
        for line in rules.splitlines():
            for variable in re.findall(r"\$([A-Za-z0-9_]+)", line):
                assert variable in body.get("RuleVariables", {}).get("IPSets", {}), (variable, line)
            assert "flow:to_server;" in line or line.startswith('pass ip any any -> any any (msg:"fwshift-replies"; flow:to_client;'), line
        out.append(group_answer(names[number], body))
    return out


def compare_script(model: Policy, report: Report, text: str, rng: random.Random, seed: int, packets: int = 400) -> int:
    judge = NfwJudge(script_documents(text))
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    count = 0
    for _ in range(packets):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        verdict = judge.allows(pkt)
        assert verdict is not None
        count += 1
        assert verdict == model_allows(compared, pkt), (seed, pkt, text)
    return count


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    """Zones become their networks, objects variables, negations '!' and what a negated service leaves; every rule for the
    first packet. Rules the emitter does not write are left out of the model's side (the report says so)."""
    rng = random.Random(seed)
    model = random_model(rng)
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL  # (a rule type is written approximately: blocks more)
    report = Report()
    text = emit_awsnfw.emit(model, report, Options(zone_networks=ZONES_AT))
    assert compare_script(model, report, text, rng, seed) == 400


@pytest.mark.parametrize("seed", range(20))
def test_the_defaults_inside_and_between_zones_as_the_source_decides(seed: int) -> None:
    from test_gcp import model_decides, with_random_defaults

    rng = random.Random(5000 + seed)
    model = with_random_defaults(rng, random_model(rng))
    for rule in model.rules:
        rule.scope = RuleScope.UNIVERSAL
    report = Report()
    text = emit_awsnfw.emit(model, report, Options(zone_networks=ZONES_AT))
    judge = NfwJudge(script_documents(text))
    compared = copy.deepcopy(model)
    for rule in compared.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    for _ in range(300):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        assert judge.allows(pkt) == model_decides(compared, pkt), (seed, pkt, text)


@pytest.mark.parametrize("seed", range(30))
def test_roundtrip_of_random_firewalls(seed: int) -> None:
    """A random firewall, read, written and read back: the written policy decides every connection as the first did, and
    the parser reads the written one back to the same verdicts."""
    rng = random.Random(9000 + seed)
    documents = random_nfw(rng)
    source = parse_documents(documents)
    text = cli.convert(source, "aws-network-firewall", Report())
    written = script_documents(text)
    first, second = NfwJudge(documents), NfwJudge(written)
    again = parse_documents(written)
    for _ in range(300):
        pkt = nfw_packet(rng)
        verdict = first.allows(pkt)
        if verdict is None:
            continue
        assert second.allows(pkt) == verdict, (seed, pkt, text)
        assert model_allows(again, pkt) == verdict, (seed, pkt)


# -- the sample -------------------------------------------------------------------------------------------------------


def test_awsnfw_sample_rules() -> None:
    p, report = load("awsnfw_sample.json")
    assert p.vendor == "aws-network-firewall" and p.scope == "pol-inspection" and not p.zones and not p.nat_rules
    assert p.default_interzone == Action.DROP
    rules = {r.name: r for r in p.rules}
    names = [r.name for r in p.rules]
    # The stateless rules come first: what their replies meet, then the rules for the first packet.
    assert names[:3] == ["sl-edge-1-replies", "sl-edge-20-replies", "sl-edge-20-replies-2"]
    assert rules["sl-edge-1-replies"].services == ["tcp-all-from-22"] and rules["sl-edge-1-replies"].destinations == ["198.51.100.0/24"]
    assert rules["sl-edge-20-replies"].negate_service and rules["sl-edge-20-replies-2"].services == ["icmp6-128"]
    assert rules["sl-edge-5"].action == Action.ALLOW and rules["sl-edge-6"].services == ["tcp-all-from-873"]
    assert "sl-edge-8" not in rules and "sl-edge-10" not in rules  # (passed one way, forwarded the other; forwarded)
    assert rules["sl-edge-12"].unsupported and rules["sl-edge-20"].sources == ["2001:db8:bad::/48"]
    # The AWS managed group that is not in the input.
    assert rules["ThreatSignaturesMalwareStrictOrder-1"].unsupported
    # The first packet: 5-tuple and Suricata rules in strict order, then aws:drop_established for what is not TCP.
    first = names.index("sf-baseline-100")
    kill = names.index("stateful-default-not-tcp")
    assert names[first:kill] == ["sf-baseline-100", "sf-baseline-101", "sf-baseline-102", "sf-baseline-102-rev", "sf-baseline-103",
                                 "sf-baseline-105", "sf-baseline-106", "sf-baseline-107", "sf-app-1000", "sf-app-1003", "sf-app-1004",
                                 "sf-app-1005", "sf-app-1005-rev", "sf-app-1007", "sf-app-1008", "sf-app-1011", "sf-app-1012", "sf-app-1013"]
    assert rules["stateful-default-not-tcp"].negate_service and rules["stateful-default-not-tcp"].services == ["tcp-all"]
    # The first reply: the rules without flow:to_server, mirrored; then established TCP.
    # (A rule for both directions needs no reading of its replies: the other direction holds them, on the first packet.)
    assert names[kill + 1:kill + 7] == ["sf-baseline-100-reply", "sf-baseline-103-reply", "sf-app-1003-reply", "sf-app-1009-reply",
                                        "sf-app-1001", "sf-app-1002"]
    assert rules["sf-baseline-100-reply"].sources == [ANY] and rules["sf-baseline-100-reply"].destinations == ["HOME_NET"]
    assert rules["sf-baseline-100-reply"].services == ["tcp-all-from-443"]
    assert rules["sf-baseline-103"].action == Action.RESET_CLIENT and rules["sf-baseline-103-reply"].action == Action.RESET_SERVER
    assert rules["sf-baseline-105"].services == ["icmp-8+icmp6-8"]
    assert rules["sf-app-1002"].applications == ["ssl"] and rules["sf-app-1002"].negate_destination
    assert rules["sf-app-1003"].applications == ["dns"] and rules["sf-app-1003"].services == [ANY]
    assert rules["sf-app-1004"].sources == ["partners"] and p.services[rules["sf-app-1004"].services[0]].entries[0].dst_ports == "1-21,23-1023"
    assert p.address_groups["partners"].members == ["198.51.100.128/25", "203.0.113.0/26"]
    assert p.address_groups["branches"].unsupported
    assert rules["sf-app-1005"].destinations == ["10.20.0.0-10.20.4.255", "10.20.6.0-10.20.255.255"]
    assert rules["sf-app-1006"].unsupported and not rules["sf-app-1008"].enabled
    assert rules["sf-app-1011"].action == Action.DROP
    assert rules["sf-app-1013"].sources == ["HOME_NET"] and rules["sf-app-1013"].negate_source
    assert not rules["sf-app-1010"].enabled  # (established, to the client: with drop_established it never decides)
    assert rules["dl-egress-1"].unsupported and not rules["dl-egress-2"].unsupported and rules["dl-egress-2"].action == Action.DROP
    assert rules["dl-block-1"].unsupported
    assert p.address_groups["HOME_NET"].members == ["10.20.0.0/16", "2001:db8:20::/56"]
    assert p.address_groups["WEB_SERVERS"].members == ["10.20.1.0/24", "2001:db8:20:1::/64"]
    notes = {n.code for n in report.notes}
    assert {"AWSNFW_ASYMMETRIC", "AWSNFW_STATELESS_FORWARD", "AWSNFW_STATELESS_NOT_WORKED_OUT", "AWSNFW_ALERT_RULES",
            "AWSNFW_CUSTOM_ACTIONS", "AWSNFW_GROUP_MISSING", "AWSNFW_HOME_NET", "AWSNFW_NO_ZONES", "AWSNFW_FRAGMENTS"} <= notes
    codes = {(name, f.code) for (_, name), item in report.items.items() for f in item.findings}
    assert ("sf-app-1003", "AWSNFW_APP_TIMING") in codes and ("sf-app-1011", "AWSNFW_REJECT_NOT_TCP") in codes
    assert ("sf-app-1010", "AWSNFW_NEVER_MATCHES") in codes and ("sl-edge-1-replies", "AWSNFW_REPLY_DROPPED") in codes


def test_awsnfw_sample_decides_like_the_judge() -> None:
    documents = json.loads((DATA / "awsnfw_sample.json").read_text(encoding="utf-8"))
    for document in documents:  # (the judge does not read domain lists, payload keywords or the missing group)
        if "FirewallPolicy" in document:
            document["FirewallPolicy"]["StatefulRuleGroupReferences"] = [
                r for r in document["FirewallPolicy"]["StatefulRuleGroupReferences"] if r["Priority"] in (100, 200)]
            document["FirewallPolicy"]["StatelessRuleGroupReferences"] = []
        if document.get("RuleGroupResponse", {}).get("RuleGroupName") == "sf-app":
            lines = document["RuleGroup"]["RulesSource"]["RulesString"].splitlines()
            document["RuleGroup"]["RulesSource"]["RulesString"] = "\n".join(
                line for line in lines if not re.search(r"BRANCHES|content|\btls\b|\bdns\b", line)) + "\n"  # fmt: skip
    model = parse_documents(documents)
    judge = NfwJudge(documents)
    rng = random.Random(3)
    pool4 = ["10.20.1.5", "10.20.5.9", "10.20.6.10", "10.20.7.3", "10.20.2.4", "10.20.3.8", "10.20.4.2", "10.30.10.7", "10.30.99.1",
             "10.30.5.5", "203.0.113.9", "198.51.100.200", "192.0.2.1"]  # fmt: skip
    pool6 = ["2001:db8:20::5", "2001:db8:20:1::7", "2001:db8:ff::53", "2001:db8:99::1"]
    compared = 0
    for _ in range(4000):
        pool = pool4 if rng.random() < 0.8 else pool6
        pkt = Packet("x", "x", rng.choice(pool), rng.choice(pool), rng.choice(["tcp", "tcp", "udp", "icmp" if pool is pool4 else "icmp6", "47"]),
                     rng.choice([22, 443, 1024, 3389, 40000]), rng.choice([22, 80, 443, 53, 161, 3389, 5432, 8443, 1024, 40000]),
                     rng.choice([0, 8, 13, 128]))  # fmt: skip
        verdict = judge.allows(pkt)
        if verdict is None or pkt.src == pkt.dst:
            continue
        compared += 1
        assert model_allows(model, pkt) == verdict, pkt
    assert compared > 3000


# -- the traps, one by one -------------------------------------------------------------------------------------------


# With aws:drop_strict every packet is decided on its own (the FWShift lab, 0.41.7): a test about something else lets the
# replies through with this rule, as FWShift's own output does.
REPLIES = "pass ip any any -> any any (flow:to_client; sid:999;)\n"


def decide(documents: List[Dict[str, Any]], src: str, dst: str, proto: str = "tcp", sport: int = 40000, dport: int = 443,
           icmp_type: int = 8) -> Tuple[bool, Optional[bool]]:  # fmt: skip
    """(the model's verdict, the judge's)."""
    model = parse_documents(documents)
    pkt = Packet("x", "x", src, dst, proto, sport, dport, icmp_type)
    return model_allows(model, pkt), NfwJudge(documents).allows(pkt)


def test_a_pass_rule_without_flow_lets_connections_in_under_drop_established() -> None:
    rules = "pass tcp $HOME_NET any -> any 443 (sid:1;)\n"
    out = decide(suricata_policy(rules, ["aws:drop_established"]), "198.51.100.7", "10.0.0.5", sport=443, dport=40000)
    assert out == (True, True)  # (the reply from inside matches the rule)
    assert decide(suricata_policy(rules, ["aws:drop_strict"]), "198.51.100.7", "10.0.0.5", sport=443, dport=40000) == (False, False)
    with_flow = "pass tcp $HOME_NET any -> any 443 (flow:to_server; sid:1;)\n"
    assert decide(suricata_policy(with_flow, ["aws:drop_established"]), "198.51.100.7", "10.0.0.5", sport=443, dport=40000) == (False, False)
    assert decide(suricata_policy(with_flow, ["aws:drop_established"]), "10.0.0.5", "198.51.100.7") == (True, True)


def test_established_and_application_rules_need_drop_established() -> None:
    rules = "pass tcp $HOME_NET any -> any 443 (flow:established,to_server; sid:1;)\n"
    assert decide(suricata_policy(rules, ["aws:drop_strict"]), "10.0.0.5", "198.51.100.7") == (False, False)
    assert decide(suricata_policy(rules, ["aws:drop_established"]), "10.0.0.5", "198.51.100.7") == (True, True)
    report = Report()
    model = parse_documents(suricata_policy("pass tls $HOME_NET any -> any any (flow:to_server; sid:1;)\n", ["aws:drop_strict"]), report)
    assert not model.rules[0].enabled and any(f.code == "AWSNFW_NEVER_MATCHES" for f in report.item("rule", model.rules[0].origin).findings)
    model = parse_documents(suricata_policy("pass tls $HOME_NET any -> any any (flow:to_server; sid:1;)\n", ["aws:drop_established"]))
    assert model.rules[-1].applications == ["ssl"] and model.rules[-1].enabled


def test_drop_established_drops_other_protocols_on_the_first_packet() -> None:
    rules = "pass udp any any -> any 53 (flow:to_client; sid:1;)\npass tcp any any -> any any (flow:to_client; sid:2;)\n"
    documents = suricata_policy(rules, ["aws:drop_established"])
    assert decide(documents, "10.0.0.5", "198.51.100.7", "udp", 53, 40000) == (False, False)
    assert decide(documents, "10.0.0.5", "198.51.100.7", "tcp", 40000, 22) == (True, True)  # (the SYN-ACK matches rule 2)
    model = parse_documents(documents)
    assert [(r.name, r.enabled) for r in model.rules] == [("stateful-default-not-tcp", True), ("g-2-reply", True), ("g-1", False)]


def test_action_order_puts_every_pass_before_every_drop() -> None:
    rules = "drop tcp any any -> any 22 (flow:to_server; sid:1;)\npass tcp 10.0.0.0/24 any -> any any (flow:to_server; sid:2;)\n"
    assert decide(suricata_policy(rules, None, "DEFAULT_ACTION_ORDER"), "10.0.0.5", "198.51.100.7", dport=22) == (True, True)
    assert decide(suricata_policy(rules, [], "STRICT_ORDER"), "10.0.0.5", "198.51.100.7", dport=22) == (False, False)
    report = Report()
    parse_documents(suricata_policy(rules, ["aws:drop_strict"], "DEFAULT_ACTION_ORDER"), report)
    assert any(n.code == "AWSNFW_DEFAULTS_IGNORED" for n in report.notes)


def test_both_directions_and_the_external_net_pitfall() -> None:
    rules = "drop ip 10.0.1.0/24 any <> 10.0.2.0/24 any (flow:to_server; sid:1;)\n"
    documents = suricata_policy(rules, [])
    assert decide(documents, "10.0.2.9", "10.0.1.9") == (False, False) and decide(documents, "10.0.1.9", "10.0.2.9") == (False, False)
    # A group's own HOME_NET does not change EXTERNAL_NET, which stays the negation of the policy's.
    documents = suricata_policy("pass tcp $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; sid:1;)\n" + REPLIES, ["aws:drop_strict"],
                                variables={"IPSets": {"HOME_NET": {"Definition": ["10.0.4.0/22"]}}})  # fmt: skip
    assert decide(documents, "10.0.4.1", "198.51.100.7") == (True, True)
    assert decide(documents, "10.0.4.1", "10.0.1.1") == (False, False)  # (10.0.1.1 is in the policy's HOME_NET)


def test_home_net_unknown_is_never_any() -> None:
    report = Report()
    model = parse_documents(suricata_policy("pass tcp $HOME_NET any -> any 443 (flow:to_server; sid:1;)\n", ["aws:drop_strict"], home=()), report)
    assert model.address_groups["HOME_NET"].unsupported and any(n.code == "AWSNFW_HOME_NET_UNKNOWN" for n in report.notes)
    text = cli.convert(model, "aws-network-firewall", report)
    assert "pass tcp" not in text and report.item("rule", "g-1").disabled
    # The policy's variable wins over the VPC.
    documents = suricata_policy("pass tcp $HOME_NET any -> any 443 (flow:to_server; sid:1;)\n", ["aws:drop_strict"])
    documents[0]["FirewallPolicy"]["PolicyVariables"] = {"RuleVariables": {"HOME_NET": {"Definition": ["10.9.0.0/16"]}}}
    assert parse_documents(documents).address_groups["HOME_NET"].members == ["10.9.0.0/16"]


def test_stateless_rules_see_packets_and_both_directions_need_a_rule() -> None:
    forward = [stateless_rule(1, "aws:pass", Sources=["10.0.0.0/24"], Destinations=["10.0.4.0/24"], Protocols=[6], DestinationPorts=[(22, 22)])]
    back = forward + [stateless_rule(2, "aws:pass", Sources=["10.0.4.0/24"], Destinations=["10.0.0.0/24"], Protocols=[6], SourcePorts=[(22, 22)])]
    for rules, default, wanted in ((forward, "aws:drop", False), (back, "aws:drop", True), (forward, "aws:pass", True)):
        documents = suricata_policy("", [], stateless=rules, stateless_default=default)
        assert decide(documents, "10.0.0.5", "10.0.4.5", dport=22) == (wanted, wanted), (default, len(rules))
    report = Report()
    parse_documents(suricata_policy("", [], stateless=forward, stateless_default="aws:drop"), report)
    assert any(f.code == "AWSNFW_STATELESS_REPLY" for f in report.item("rule", "s-1").findings)
    # Passed one way, forwarded the other: the stateful engine sees half a flow.
    report = Report()
    parse_documents(suricata_policy("pass tcp any any -> any any (flow:to_server; sid:1;)\n", [], stateless=forward), report)
    assert any(n.code == "AWSNFW_ASYMMETRIC" for n in report.notes)
    # A stateless drop also drops the replies of connections opened the other way.
    drop = [stateless_rule(1, "aws:drop", Sources=["10.0.4.0/24"], Protocols=[6])]
    documents = suricata_policy("pass tcp any any -> any any (flow:to_server; sid:1;)\n", [], stateless=drop)
    assert decide(documents, "10.0.0.5", "10.0.4.5") == (False, False)
    # The stateless default passes: nothing reaches the stateful engine.
    report = Report()
    model = parse_documents(suricata_policy("drop tcp any any -> any any (flow:to_server; sid:1;)\n", [], stateless_default="aws:pass"), report)
    assert any(n.code == "AWSNFW_STATEFUL_UNREACHABLE" for n in report.notes) and not model.rules[-1].enabled


def test_stateless_rules_that_cannot_be_read() -> None:
    flags = [stateless_rule(1, "aws:drop", Protocols=[6], TCPFlags=[{"Flags": ["SYN"], "Masks": ["SYN", "ACK"]}]),
             stateless_rule(2, "aws:drop", DestinationPorts=[(22, 22)]),
             {"Priority": 3, "RuleDefinition": {"MatchAttributes": {}, "Actions": ["aws:pass", "aws:drop"]}}]  # fmt: skip
    report = Report()
    model = parse_documents(suricata_policy("", [], stateless=flags), report)
    assert [bool(r.unsupported) for r in model.rules[:3]] == [True, True, True]
    assert any(n.code == "AWSNFW_STATELESS_NOT_WORKED_OUT" for n in report.notes)


def test_what_cannot_be_read_is_never_read_as_any() -> None:
    rules = ("pass tcp $NOPE any -> any any (flow:to_server; sid:1;)\n"
             "pass tcp any any -> any $NOPORTS (flow:to_server; sid:2;)\n"
             "pass tcp any any -> any any (flow:to_server; content:\"x\"; sid:3;)\n"
             "pass sctp any any -> any any (sid:4;)\n"
             "pass tcp any any => any any (sid:5;)\n"
             "pass tcp any any -> any any sid:6;\n"
             "rejectboth tcp any any -> any any (sid:7;)\n"
             "pass tcp 10.0.0.300 any -> any any (sid:8;)\n"
             "pass icmp any 80 -> any any (sid:9;)\n"
             "pass tcp [10.0.0.0/8,!10.0.0.0/8] any -> any any (sid:10;)\n"
             "pass tcp any any -> any any (flow:only_stream; sid:11;)\n"
             "pass tcp any any -> any any (flow:to_server,to_client; sid:12;)\n"
             "pass foo any any -> any any (sid:13;)\n")  # fmt: skip
    report = Report()
    model = parse_documents(suricata_policy(rules, []), report)
    by_name = {r.name: r for r in model.rules}
    for number in range(1, 14):
        if number in (10, 12):  # (a list that leaves no address, and two directions at once, match nothing: disabled)
            assert not by_name[f"g-{number}"].enabled
            assert any(f.code == "AWSNFW_MATCHES_NOTHING" for f in report.item("rule", f"g-{number}").findings)
        else:
            assert by_name[f"g-{number}"].unsupported, number
    assert by_name["g-5"].source_ids["awsnfw.sid"] == "5"  # (a header that cannot be read keeps its sid)


def test_ip_set_references_variables_and_lists() -> None:
    documents = suricata_policy("pass tcp @PL any -> [$NETS,!10.0.1.5] $PORTS (flow:to_server; sid:1;)\n" + REPLIES, ["aws:drop_strict"],
                                variables={"IPSets": {"NETS": {"Definition": ["10.0.1.0/24"]}},
                                           "PortSets": {"PORTS": {"Definition": ["80", "8000:8010"]}}})  # fmt: skip
    documents[-2]["RuleGroup"]["ReferenceSets"] = {"IPSetReferences": {"PL": {"ReferenceArn": "arn:aws:ec2:eu-west-1:111122223333:prefix-list/pl-9"}}}
    report = Report()
    model = parse_documents(documents, report)
    assert model.address_groups["PL"].unsupported  # (its entries are not there)
    documents.append({"PrefixListId": "pl-9", "Entries": [{"Cidr": "192.0.2.0/28"}]})
    model = parse_documents(documents)
    rule = model.rules[0]
    assert rule.sources == ["PL"] and rule.destinations == ["10.0.1.0-10.0.1.4", "10.0.1.6-10.0.1.255"]
    assert model.services[rule.services[0]].entries[0].dst_ports == "80,8000-8010"
    assert decide(documents, "192.0.2.3", "10.0.1.9", dport=8005) == (True, True)
    assert decide(documents, "192.0.2.3", "10.0.1.5", dport=8005) == (False, False)
    resource = copy.deepcopy(documents)
    resource[-3]["RuleGroup"]["ReferenceSets"]["IPSetReferences"]["PL"]["ReferenceArn"] = "arn:aws:resource-groups:eu-west-1:1:group/web"
    assert "resource group" in parse_documents(resource).address_groups["PL"].unsupported


def test_domain_lists() -> None:
    body = {"RulesSource": {"RulesSourceList": {"Targets": [".example.com"], "TargetTypes": ["TLS_SNI"], "GeneratedRulesType": "ALLOWLIST"}},
            "StatefulRuleOptions": {"RuleOrder": "STRICT_ORDER"}}  # fmt: skip
    documents = suricata_policy("", ["aws:drop_established"])
    documents[-2] = group_answer("g", body)
    model = parse_documents(documents)
    allow, rest = model.rules[-2], model.rules[-1]
    assert allow.action == Action.ALLOW and allow.unsupported and allow.applications == ["ssl"]
    assert rest.action == Action.DROP and not rest.unsupported and rest.negate_destination
    body["RulesSource"]["RulesSourceList"]["GeneratedRulesType"] = "ALERTLIST"
    report = Report()
    parse_documents(documents, report)
    assert any(n.code == "AWSNFW_ALERT_RULES" for n in report.notes)


def test_override_to_alert_and_missing_groups() -> None:
    documents = suricata_policy("drop tcp any any -> any 22 (flow:to_server; sid:1;)\npass tcp any any -> any any (flow:to_server; sid:2;)\n", [])
    documents[0]["FirewallPolicy"]["StatefulRuleGroupReferences"][0]["Override"] = {"Action": "DROP_TO_ALERT"}
    assert decide(documents, "10.0.0.5", "198.51.100.7", dport=22)[0] is True
    documents[0]["FirewallPolicy"]["StatefulRuleGroupReferences"].append({"ResourceArn": f"{ARN}:stateful-rulegroup/gone", "Priority": 0})
    report = Report()
    model = parse_documents(documents, report)
    assert model.rules[0].name == "gone-1" and model.rules[0].unsupported
    assert any(n.code == "AWSNFW_GROUP_MISSING" for n in report.notes)


def test_commented_rules_are_disabled_and_comments_are_comments() -> None:
    rules = "# a comment\n#drop tcp any any -> any 22 (sid:1;)\n  \n# pass is a word (not a rule\npass tcp any any \\\n -> any 80 (flow:to_server; sid:2;)\n"
    model = parse_documents(suricata_policy(rules, []))
    assert [(r.name, r.enabled) for r in model.rules] == [("g-1", False), ("g-2", True), ("g-1-reply", False)]


def test_input_forms_and_errors() -> None:
    documents = suricata_policy("pass tcp any any -> any 80 (flow:to_server; sid:1;)\n", [])
    stream = "\n".join(json.dumps(d, indent=1) for d in documents).encode()
    assert [r.name for r in parse_awsnfw.parse(stream, Report()).rules] == ["g-1"]
    wrapped = json.dumps({"FirewallPolicy": documents[0], "RuleGroups": documents[1:2], "Vpcs": documents[2]["Vpcs"]}).encode()
    assert [r.name for r in parse_awsnfw.parse(wrapped, Report()).rules] == ["g-1"]
    with pytest.raises(ParseError, match="no firewall policy"):
        parse_awsnfw.parse(json.dumps(documents[1:]).encode(), Report())
    with pytest.raises(ParseError, match="JSON"):
        parse_awsnfw.parse(b'{"FirewallPolicy": {', Report())
    two = documents + [policy_answer(documents[0]["FirewallPolicy"], "other")]
    with pytest.raises(ParseError, match="--policy"):
        parse_awsnfw.parse(json.dumps(two).encode(), Report())
    assert parse_awsnfw.parse(json.dumps(two).encode(), Report(), policy="other").scope == "other"
    with pytest.raises(ParseError, match="no firewall policy named"):
        parse_awsnfw.parse(json.dumps(two).encode(), Report(), policy="third")


def test_detection() -> None:
    text = (DATA / "awsnfw_sample.json").read_bytes()
    assert parse_awsnfw.looks_like_awsnfw(text) and cli.detect_format(text) == "aws-network-firewall"
    for path in sorted(DATA.iterdir()):
        if path.is_file() and path.name != "awsnfw_sample.json":
            assert not parse_awsnfw.looks_like_awsnfw(path.read_bytes()), path.name
    stream = b"\n".join(json.dumps(d).encode() for d in suricata_policy("", []))
    assert cli.detect_format(stream) == "aws-network-firewall"


# -- the emitter ------------------------------------------------------------------------------------------------------


def small_policy() -> Policy:
    p = Policy(vendor="panos")
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.1.0.10/32")
    p.addresses["guests"] = Address("guests", AddressKind.NETWORK, "10.2.0.0/24")
    p.address_groups["HOME_NET"] = AddressGroup("HOME_NET", ["guests", "web"])
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    deny = Rule("no-guests", sources=["guests"], destinations=["web"], action=Action.DROP)
    allow = Rule("to-web", destinations=["web"], services=["https"])
    home = Rule("from-home", sources=["HOME_NET"], services=["https"], action=Action.RESET_BOTH)
    for rule in (deny, allow, home):
        rule.origin = rule.name
        p.rules.append(rule)
    return p


def test_emitted_rules_variables_and_policy() -> None:
    report = Report()
    text = emit_awsnfw.emit(small_policy(), report, Options())
    documents = script_documents(text)
    group = documents[1]["RuleGroup"]
    assert group["RuleVariables"]["IPSets"] == {"guests": {"Definition": ["10.2.0.0/24"]}, "web": {"Definition": ["10.1.0.10/32"]},
                                                "FWS_HOME_NET": {"Definition": ["10.1.0.10/32", "10.2.0.0/24"]}}
    lines = group["RulesSource"]["RulesString"].splitlines()
    # (the first rule passes the replies: with aws:drop_strict every packet is decided on its own, the FWShift lab, 0.41.7)
    assert lines[0].startswith('pass ip any any -> any any (msg:"fwshift-replies"; flow:to_client; sid:')
    assert lines[1] == 'drop ip $guests any -> $web any (msg:"no-guests"; flow:to_server; sid:1; rev:1;)'
    assert lines[2] == 'pass tcp any any -> $web 443 (msg:"to-web"; flow:to_server; sid:2; rev:1;)'
    assert lines[3].startswith("reject tcp $FWS_HOME_NET any -> any 443")
    policy = documents[0]["FirewallPolicy"]
    assert policy["StatefulDefaultActions"] == ["aws:drop_strict"] and policy["StatelessDefaultActions"] == ["aws:forward_to_sfe"]
    assert policy["StatefulEngineOptions"] == {"RuleOrder": "STRICT_ORDER"}
    assert any(f.code == "RESET_ACTION" for f in report.item("rule", "from-home").findings)
    assert {"AWSNFW_LOAD", "AWSNFW_ORDER"} <= {n.code for n in report.notes}


def test_what_the_emitter_cannot_write() -> None:
    p = small_policy()
    p.addresses["site"] = Address("site", AddressKind.FQDN, "www.example.com")
    p.services["sctp-ports"] = Service("sctp-ports", [ServiceEntry(Protocol.SCTP, "2905")])
    p.services["many-icmp"] = Service("many-icmp", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    rules = [Rule("fqdn", destinations=["site"]), Rule("sctp", services=["sctp-ports"]), Rule("users", users=["alice"]),
             Rule("not-icmp", services=["many-icmp"], negate_service=True),
             Rule("not-icmp-deny", services=["many-icmp"], negate_service=True, action=Action.DROP),
             Rule("zoned", src_zones=["inside"], services=["https"]), Rule("off", enabled=False)]  # fmt: skip
    for rule in rules:
        rule.origin = rule.name
        p.rules.append(rule)
    report = Report()
    text = emit_awsnfw.emit(p, report, Options())
    for name, code in (("fqdn", "FQDN_NOT_SUPPORTED"), ("sctp", "SERVICE_SCTP"), ("users", "USER_MATCH"), ("zoned", "ZONE_NETWORK_MISSING")):
        assert report.item("rule", name).disabled and any(f.code == code for f in report.item("rule", name).findings), name
    assert "#   off: disabled in the source" in text
    # A negated service: what it leaves, a rule per protocol and the rest with ip_proto:!N.
    lines = script_documents(text)[1]["RuleGroup"]["RulesSource"]["RulesString"].splitlines()
    left = [line for line in lines if '"not-icmp-deny"' in line]
    assert any("ip_proto:!1;" in line for line in left) and any("itype:<8;" in line for line in left)
    assert any("itype:>8;" in line for line in left) and not report.item("rule", "not-icmp").disabled
    # Zones with networks: the rule is written for them.
    report = Report()
    text = emit_awsnfw.emit(p, report, Options(zone_networks={"inside": ["10.0.0.0/8"]}))
    assert 'pass tcp 10.0.0.0/8 any -> any 443 (msg:"zoned"' in script_documents(text)[1]["RuleGroup"]["RulesSource"]["RulesString"]


def test_names_variables_and_long_lists() -> None:
    p = Policy(vendor="panos")
    p.addresses["1 strange name!"] = Address("1 strange name!", AddressKind.NETWORK, "10.0.0.1")
    p.addresses["external_net"] = Address("external_net", AddressKind.NETWORK, "10.0.0.2")
    rules = [Rule("r", sources=["1 strange name!", "external_net"], destinations=[f"10.{n}.0.1" for n in range(60)]),
             Rule("zoned", destinations=[f"10.{n}.0.1" for n in range(70)], dst_zones=["a"]),
             Rule("same", destinations=[f"10.{n}.0.1" for n in range(60)], action=Action.DROP)]
    for rule in rules:
        rule.origin = rule.name
        p.rules.append(rule)
    text = emit_awsnfw.emit(p, Report(), Options(zone_networks={"a": ["10.0.0.0/10"]}))
    group = script_documents(text)[1]["RuleGroup"]
    sets = group["RuleVariables"]["IPSets"]
    assert sets["x1_strange_name_"]["Definition"] == ["10.0.0.1/32"] and sets["FWS_external_net"]["Definition"] == ["10.0.0.2/32"]
    assert len(sets["r_DST"]["Definition"]) == 60 and len(sets["zoned_DST"]["Definition"]) == 64
    assert "same_DST" not in sets and '-> $r_DST any (msg:"same"' in group["RulesSource"]["RulesString"]  # (one list, one variable)
    assert all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", name) for name in sets)


def test_script_runs_in_every_mode(tmp_path: Any) -> None:
    text = emit_awsnfw.emit(small_policy(), Report(), Options(object_prefix="lab-"))
    script = tmp_path / "nfw.sh"
    script.write_text(text, encoding="utf-8")
    printed = subprocess.run(["sh", str(script)], env=dict(os.environ, DRY_RUN="1"), capture_output=True, text=True)
    assert printed.returncode == 0, printed.stderr
    assert "aws network-firewall create-rule-group --rule-group-name lab-fwshift-rules --type STATEFUL --capacity 100" in printed.stderr
    assert "aws network-firewall create-firewall-policy --firewall-policy-name lab-fwshift" in printed.stderr
    log = tmp_path / "calls.log"
    stub = tmp_path / "bin" / "aws"
    stub.parent.mkdir()
    stub.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$LOG"
for a in "$@"; do case "$a" in file://*) cat "${a#file://}" >> "$LOG.files" ;; esac; done
case "$2" in
  describe-rule-group|describe-firewall-policy) [ -n "${EXISTS:-}" ] && exit 0; echo "ResourceNotFoundException" >&2; exit 254 ;;
  create-rule-group) echo "arn:aws:network-firewall:eu-west-1:111122223333:stateful-rulegroup/new" ;;
esac
exit 0
""", encoding="utf-8")
    stub.chmod(0o755)
    env = dict(os.environ, PATH=f"{stub.parent}:{os.environ['PATH']}", LOG=str(log))
    checked = subprocess.run(["sh", str(script)], env=dict(env, CHECK="1"), capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    calls = log.read_text().splitlines()
    assert all("--dry-run" in c for c in calls if c.split()[1].startswith("create"))
    assert "StatefulRuleGroupReferences" not in (tmp_path / "calls.log.files").read_text().split("RulesString")[-1]
    log.write_text("")
    (tmp_path / "calls.log.files").write_text("")
    done = subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    calls = log.read_text().splitlines()
    assert not any("--dry-run" in c for c in calls)
    assert any(c.startswith("network-firewall create-firewall-policy --firewall-policy-name lab-fwshift") for c in calls)
    files = (tmp_path / "calls.log.files").read_text()
    assert '"ResourceArn":"arn:aws:network-firewall:eu-west-1:111122223333:stateful-rulegroup/new"' in files
    log.write_text("")
    stopped = subprocess.run(["sh", str(script)], env=dict(env, EXISTS="1"), capture_output=True, text=True)
    assert stopped.returncode != 0 and "exists already" in stopped.stderr
    assert not any("create-" in c for c in log.read_text().splitlines())


def test_nat_is_not_written_and_rules_see_private_addresses() -> None:
    p, _ = load("aws_sample.json")
    report = Report()
    text = cli.convert(p, "aws-network-firewall", report)
    assert all(item.skipped for (kind, _), item in report.items.items() if kind == "nat")
    assert "203.0.113" not in "\n".join(line for line in text.splitlines() if line.startswith(("pass", "drop")))


def test_large_policies_are_split_into_groups() -> None:
    p = Policy(vendor="panos")
    for index in range(10_050):
        rule = Rule(f"r{index}", sources=[f"10.{index // 250}.{index % 250}.0/24"], action=Action.DROP)
        rule.origin = rule.name
        p.rules.append(rule)
    report = Report()
    text = emit_awsnfw.emit(p, report, Options())
    documents = script_documents(text)
    assert len(documents) == 3 and any(n.code == "AWSNFW_SPLIT" for n in report.notes)
    references = documents[0]["FirewallPolicy"]["StatefulRuleGroupReferences"]
    assert [r["Priority"] for r in references] == [100, 200]


def test_emitted_findings_have_severities_the_manual_names() -> None:
    report = Report()
    emit_awsnfw.emit(small_policy(), report, Options())
    assert all(n.severity in (Severity.INFO, Severity.APPROX, Severity.REVIEW) for n in report.notes)


def test_icmp_types_ip_proto_negation_and_both_directions() -> None:
    rules = ("pass icmp any any -> 10.0.4.0/22 any (flow:to_server; ip_proto:!58; itype:>8; sid:1;)\n"
             "pass ip any any -> 10.0.4.0/22 any (flow:to_server; ip_proto:!6; ip_proto:!17; ip_proto:!1; sid:2;)\n"
             "drop icmp 10.0.0.0/24 any <> 10.0.1.0/24 any (itype:0; sid:3;)\n")  # fmt: skip
    documents = suricata_policy(rules, [])
    model = parse_documents(documents)
    first = next(r for r in model.rules if r.name == "g-1")
    assert [e.icmp_type for e in model.services[first.services[0]].entries] == list(range(9, 256))
    second = next(r for r in model.rules if r.name == "g-2")
    assert second.negate_service and {e.protocol for e in model.services[second.services[0]].entries} == {Protocol.TCP, Protocol.UDP, Protocol.ICMP}
    # (A typed ICMP rule for both directions has replies of its own: an echo request, whose reply is the type 0 it names.)
    assert "g-3-reply" in [r.name for r in model.rules] and "g-3-rev-reply" in [r.name for r in model.rules]
    for src, dst, proto, kind, wanted in (("10.0.1.5", "10.0.0.5", "icmp", 8, False), ("10.0.0.5", "10.0.1.5", "icmp", 8, False),
                                          ("10.0.0.5", "10.0.1.5", "icmp", 13, True), ("10.0.1.5", "10.0.0.5", "icmp", 0, False)):  # fmt: skip
        assert decide(documents, src, dst, proto, 1024, 53, kind) == (wanted, wanted), (src, dst, proto, kind)
    strict = suricata_policy(rules + REPLIES, ["aws:drop_strict"])
    for src, dst, proto, kind, wanted in (("10.0.0.5", "10.0.4.1", "icmp", 13, True), ("10.0.0.5", "10.0.4.1", "icmp", 8, False),
                                          ("10.0.0.5", "10.0.4.1", "47", 0, True), ("10.0.0.5", "10.0.4.1", "udp", 0, False)):  # fmt: skip
        assert decide(strict, src, dst, proto, 1024, 53, kind) == (wanted, wanted), (src, dst, proto, kind)


def test_a_group_of_the_wrong_kind_is_not_converted() -> None:
    documents = suricata_policy("pass tcp any any -> any any (flow:to_server; sid:1;)\n", [])
    stateless = group_answer("g", {"RulesSource": {"StatelessRulesAndCustomActions": {"StatelessRules": [stateless_rule(1, "aws:pass")]}}}, True)
    documents[1] = stateless
    documents[1]["RuleGroupResponse"]["RuleGroupArn"] = f"{ARN}:stateful-rulegroup/g"
    report = Report()
    model = parse_documents(documents, report)
    assert any(n.code == "AWSNFW_GROUP_TYPE" for n in report.notes) and model.rules[0].unsupported
