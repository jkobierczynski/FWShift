# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/awsnfw_sample.json: a made-up AWS Network Firewall policy, as the AWS CLI prints it, the answers in
one JSON array:

    aws network-firewall describe-firewall-policy --firewall-policy-name pol-inspection --output json
    aws network-firewall describe-rule-group --rule-group-arn ARN --output json      (one per rule group but one)
    aws ec2 describe-vpcs --vpc-ids vpc-0a1b2c3d4e5f60789 --output json                (HOME_NET)
    aws ec2 describe-managed-prefix-lists --output json
    aws ec2 get-managed-prefix-list-entries --prefix-list-id pl-...                    (wrapped with its PrefixListId)

It holds the traps of the platform: stateless rules with and without a rule for the replies, a forward with a custom
action, TCP flags, IPv6; 5-tuple rules with and without flow keywords, both directions, reject, alert, ICMP types, port
ranges; Suricata rules with variables, an IP set reference with and without its entries, application protocols, lists
with negation, a payload keyword, a commented-out rule, rules for the replies only and for established packets only;
an allow list and a deny list of domain names; an AWS managed rule group whose answer is not there. Every address is a
documentation or private address, every id and account number is made up.

    python3 tests/tools/make_awsnfw_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

REGION, ACCOUNT = "eu-west-1", "111122223333"
PREFIX = f"arn:aws:network-firewall:{REGION}:{ACCOUNT}"


def arn(kind: str, name: str) -> str:
    return f"{PREFIX}:{kind}/{name}"


def group(name: str, kind: str, body: Dict[str, Any], capacity: int = 100) -> Dict[str, Any]:
    return {
        "UpdateToken": "0a1b2c3d-1111-2222-3333-444455556666",
        "RuleGroup": body,
        "RuleGroupResponse": {
            "RuleGroupArn": arn("stateless-rulegroup" if kind == "STATELESS" else "stateful-rulegroup", name),
            "RuleGroupName": name, "RuleGroupId": "0f1e2d3c-4b5a-6978-8091-a2b3c4d5e6f7", "Type": kind, "Capacity": capacity,
            "RuleGroupStatus": "ACTIVE", "NumberOfAssociations": 1, "ConsumedCapacity": 20,
        },
    }  # fmt: skip


def stateless(priority: int, actions: List[str], **match: Any) -> Dict[str, Any]:
    attributes: Dict[str, Any] = {}
    for key, value in match.items():
        if key in ("Sources", "Destinations"):
            attributes[key] = [{"AddressDefinition": cidr} for cidr in value]
        elif key in ("SourcePorts", "DestinationPorts"):
            attributes[key] = [{"FromPort": low, "ToPort": high} for low, high in value]
        else:
            attributes[key] = value
    return {"RuleDefinition": {"MatchAttributes": attributes, "Actions": actions}, "Priority": priority}


def five(action: str, protocol: str, source: str, sport: str, direction: str, destination: str, dport: str, **options: str) -> Dict[str, Any]:
    return {"Action": action, "Header": {"Protocol": protocol, "Source": source, "SourcePort": sport, "Direction": direction,
                                         "Destination": destination, "DestinationPort": dport},
            "RuleOptions": [{"Keyword": key, "Settings": [value]} if value else {"Keyword": key} for key, value in options.items()]}  # fmt: skip


SURICATA = r"""# Rules of the application tier. A commented-out rule is a disabled rule.
pass tcp any any -> $WEB_SERVERS $WEB_PORTS (msg:"web servers from anywhere"; flow:to_server; sid:1000; rev:2;)
pass tcp $ADMIN_NETS any -> $WEB_SERVERS 22 (msg:"admin ssh"; flow:established,to_server; sid:1001;)
pass tls $HOME_NET any -> $EXTERNAL_NET any (msg:"tls out"; flow:to_server; sid:1002;)
pass dns $HOME_NET any -> any any (msg:"dns, no flow keyword"; sid:1003;)
drop tcp @PARTNERS any -> $HOME_NET [1:1023,!22] (msg:"partners: no low ports but ssh"; flow:to_server; sid:1004;)
pass ip @BRANCHES any <> [10.20.0.0/16,!10.20.5.0/24] any (msg:"branches both ways"; sid:1005;)
drop http $HOME_NET any -> any any (msg:"admin paths"; flow:to_server,established; http.uri; content:"/admin"; sid:1006;)
pass ip 10.20.7.0/24 any -> any any (msg:"gre tunnels"; ip_proto:47; flow:to_server; sid:1007;)
# drop udp any any -> any 69 (msg:"old tftp rule"; sid:1008;)
pass tcp $HOME_NET any -> any any (msg:"replies only"; flow:to_client; sid:1009;)
pass tcp any any -> $HOME_NET any (msg:"established to clients"; flow:established,to_client; sid:1010;)
reject udp any any -> 10.20.2.0/24 161 (msg:"no snmp"; flow:to_server; sid:1011;)
pass tcp [10.30.0.0/16,!10.30.99.0/24] any -> 10.20.3.0/24 $HIGH (msg:"spokes to high ports"; flow:to_server; priority:2; sid:1012;)
drop ip $EXTERNAL_NET any -> $HOME_NET any (msg:"the rest inbound"; flow:to_server; sid:1013;)
"""


def build() -> List[Dict[str, Any]]:
    policy = {
        "UpdateToken": "9a8b7c6d-1111-2222-3333-444455556666",
        "FirewallPolicyResponse": {
            "FirewallPolicyName": "pol-inspection", "FirewallPolicyArn": arn("firewall-policy", "pol-inspection"),
            "FirewallPolicyId": "1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809", "Description": "egress and east-west inspection",
            "FirewallPolicyStatus": "ACTIVE", "NumberOfAssociations": 1,
        },
        "FirewallPolicy": {
            "StatelessRuleGroupReferences": [{"ResourceArn": arn("stateless-rulegroup", "sl-edge"), "Priority": 10}],
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:drop"],
            "StatelessCustomActions": [{"ActionName": "CountDefault", "ActionDefinition": {
                "PublishMetricAction": {"Dimensions": [{"Value": "default"}]}}}],
            "StatefulRuleGroupReferences": [
                {"ResourceArn": f"arn:aws:network-firewall:{REGION}:aws-managed:stateful-rulegroup/ThreatSignaturesMalwareStrictOrder",
                 "Priority": 50},
                {"ResourceArn": arn("stateful-rulegroup", "sf-baseline"), "Priority": 100},
                {"ResourceArn": arn("stateful-rulegroup", "sf-app"), "Priority": 200},
                {"ResourceArn": arn("stateful-rulegroup", "dl-block"), "Priority": 250},
                {"ResourceArn": arn("stateful-rulegroup", "dl-egress"), "Priority": 300},
            ],
            "StatefulDefaultActions": ["aws:drop_established", "aws:alert_established"],
            "StatefulEngineOptions": {"RuleOrder": "STRICT_ORDER", "StreamExceptionPolicy": "DROP"},
        },
    }  # fmt: skip
    edge = group("sl-edge", "STATELESS", {"RulesSource": {"StatelessRulesAndCustomActions": {
        "StatelessRules": [
            stateless(1, ["aws:drop"], Sources=["198.51.100.0/24"], Protocols=[6], DestinationPorts=[(22, 22)]),
            stateless(5, ["aws:pass"], Sources=["10.20.8.0/24"], Destinations=["10.40.0.0/24"], Protocols=[6], DestinationPorts=[(873, 873)]),
            stateless(6, ["aws:pass"], Sources=["10.40.0.0/24"], Destinations=["10.20.8.0/24"], Protocols=[6], SourcePorts=[(873, 873)]),
            stateless(8, ["aws:pass"], Sources=["10.20.9.0/24"], Destinations=["203.0.113.10/32"], Protocols=[17], DestinationPorts=[(514, 514)]),
            stateless(10, ["aws:forward_to_sfe", "CountIcmp"], Sources=["10.20.0.0/16"], Protocols=[1]),
            stateless(12, ["aws:drop"], Sources=["192.0.2.0/24"], Protocols=[6],
                      TCPFlags=[{"Flags": ["SYN"], "Masks": ["SYN", "ACK"]}]),
            stateless(20, ["aws:drop"], Sources=["2001:db8:bad::/48"]),
        ],
        "CustomActions": [{"ActionName": "CountIcmp", "ActionDefinition": {"PublishMetricAction": {"Dimensions": [{"Value": "icmp"}]}}}],
    }}}, capacity=200)  # fmt: skip
    baseline = group("sf-baseline", "STATEFUL", {
        "RulesSource": {"StatefulRules": [
            five("PASS", "TCP", "$HOME_NET", "ANY", "FORWARD", "ANY", "443", sid="100"),
            five("PASS", "TCP", "$HOME_NET", "ANY", "FORWARD", "ANY", "80", flow="to_server", sid="101"),
            five("DROP", "TCP", "ANY", "ANY", "ANY", "10.20.5.0/24", "22", sid="102"),
            five("REJECT", "TCP", "ANY", "ANY", "FORWARD", "10.20.6.10/32", "3389", sid="103"),
            five("ALERT", "IP", "ANY", "ANY", "FORWARD", "ANY", "ANY", msg='"everything"', sid="104"),
            five("PASS", "ICMP", "$HOME_NET", "ANY", "FORWARD", "ANY", "ANY", itype="8", sid="105"),
            five("PASS", "UDP", "2001:db8:20::/56", "ANY", "FORWARD", "2001:db8:ff::53/128", "53", flow="to_server", sid="106"),
            five("PASS", "TCP", "10.30.0.0/16", "1024:65535", "FORWARD", "10.20.4.0/24", "[5432,6432]", flow="to_server", sid="107"),
        ]},
        "StatefulRuleOptions": {"RuleOrder": "STRICT_ORDER"},
    })  # fmt: skip
    app = group("sf-app", "STATEFUL", {
        "RuleVariables": {
            "IPSets": {"WEB_SERVERS": {"Definition": ["10.20.1.0/24", "2001:db8:20:1::/64"]},
                       "ADMIN_NETS": {"Definition": ["10.30.10.0/24"]}},
            "PortSets": {"WEB_PORTS": {"Definition": ["80", "443", "8443"]}, "HIGH": {"Definition": ["1024:65535"]}},
        },
        "ReferenceSets": {"IPSetReferences": {
            "PARTNERS": {"ReferenceArn": f"arn:aws:ec2:{REGION}:{ACCOUNT}:prefix-list/pl-0a1b2c3d4e5f60789"},
            "BRANCHES": {"ReferenceArn": f"arn:aws:ec2:{REGION}:{ACCOUNT}:prefix-list/pl-0f9e8d7c6b5a40321"},
        }},
        "RulesSource": {"RulesString": SURICATA},
        "StatefulRuleOptions": {"RuleOrder": "STRICT_ORDER"},
    })  # fmt: skip
    block = group("dl-block", "STATEFUL", {
        "RulesSource": {"RulesSourceList": {"Targets": ["bad.example.org"], "TargetTypes": ["TLS_SNI"], "GeneratedRulesType": "DENYLIST"}},
        "StatefulRuleOptions": {"RuleOrder": "STRICT_ORDER"},
    })  # fmt: skip
    egress = group("dl-egress", "STATEFUL", {
        "RulesSource": {"RulesSourceList": {"Targets": [".example.com", "updates.example.net"], "TargetTypes": ["TLS_SNI", "HTTP_HOST"],
                                            "GeneratedRulesType": "ALLOWLIST"}},
        "StatefulRuleOptions": {"RuleOrder": "STRICT_ORDER"},
    })  # fmt: skip
    vpcs = {"Vpcs": [{
        "VpcId": "vpc-0a1b2c3d4e5f60789", "OwnerId": ACCOUNT, "State": "available", "CidrBlock": "10.20.0.0/16",
        "CidrBlockAssociationSet": [{"AssociationId": "vpc-cidr-assoc-0a1b2c3d", "CidrBlock": "10.20.0.0/16",
                                     "CidrBlockState": {"State": "associated"}}],
        "Ipv6CidrBlockAssociationSet": [{"AssociationId": "vpc-cidr-assoc-0e1f2a3b", "Ipv6CidrBlock": "2001:db8:20::/56",
                                         "Ipv6CidrBlockState": {"State": "associated"}, "NetworkBorderGroup": REGION}],
        "Tags": [{"Key": "Name", "Value": "inspection"}],
    }]}  # fmt: skip
    lists = {"PrefixLists": [
        {"PrefixListId": "pl-0a1b2c3d4e5f60789", "AddressFamily": "IPv4", "State": "create-complete", "PrefixListName": "partners",
         "MaxEntries": 10, "Version": 3, "OwnerId": ACCOUNT},
        {"PrefixListId": "pl-0f9e8d7c6b5a40321", "AddressFamily": "IPv4", "State": "create-complete", "PrefixListName": "branches",
         "MaxEntries": 20, "Version": 1, "OwnerId": ACCOUNT},
    ]}  # fmt: skip
    entries = {"PrefixListId": "pl-0a1b2c3d4e5f60789", "Entries": [
        {"Cidr": "203.0.113.0/26", "Description": "partner a"}, {"Cidr": "198.51.100.128/25", "Description": "partner b"}]}
    return [policy, edge, baseline, app, block, egress, vpcs, lists, entries]


def main() -> None:
    target = Path(__file__).resolve().parents[1] / "data" / "awsnfw_sample.json"
    target.write_text(json.dumps(build(), indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {target}")


if __name__ == "__main__":
    main()
