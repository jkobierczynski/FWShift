# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AWS EC2 security groups (and VPC network ACLs) parser: the JSON of the AWS CLI -> neutral model.

What is read: the answers of ``aws ec2 describe-security-groups`` (required), and of ``describe-network-interfaces``,
``describe-vpcs``, ``describe-subnets``, ``describe-network-acls``, ``describe-managed-prefix-lists``,
``get-managed-prefix-list-entries`` (wrapped as ``{"PrefixListId": ..., "Entries": [...]}``) and
``describe-security-group-rules``, alone or together in one JSON array. Each answer is told by its top-level key.
One VPC at a time.

How AWS behaviour is mapped onto the neutral model:

* A security group allows only, and the rules of all the groups of a network interface are one set, without order:
  every rule of the model allows, and what no rule allows is denied. There are no zones: a group stands for the
  private addresses of the network interfaces it is attached to (from ``describe-network-interfaces``); without
  them its members are not known, and it is a dynamic group whose rules no target can write.
* An inbound rule allows its sources to reach the members of its group. An outbound rule allows the members to reach
  its destinations; inside the VPC the destination's inbound rules must allow the connection as well, so an
  outbound rule is read for the addresses outside the VPC only. Where the outbound rules of a member's groups do not
  allow everything inside the VPC, what that member may reach inside is worked out rule by rule (an outbound rule of
  its groups and an inbound rule of the destination's, together), and the rest is denied.
* A public or Elastic IP address of an interface is a static NAT of its private address, which the groups see.
* A network ACL is checked where traffic enters or leaves a subnet, in the order of its rule numbers, and does not
  remember connections. What it denies on the way in and out of a subnet with members is a blocking rule at the
  top; that the replies of a connection need rules of their own is checked and said, not converted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .. import regions, transform
from ..errors import ParseError
from ..model import (
    ANY,
    APP_DEFAULT,
    Action,
    AddressGroup,
    NatRule,
    Policy,
    Protocol,
    Rule,
    Service,
    ServiceEntry,
    SnatKind,
    SourceNat,
)
from ..netutil import Interval, intersect, interval_text, normalize, overlaps, parse_literal, subtract, within
from ..report import Report, Severity

_ANSWER_KEYS = ("SecurityGroups", "SecurityGroupRules", "NetworkInterfaces", "Vpcs", "Subnets", "NetworkAcls", "PrefixLists",
                "Entries")  # fmt: skip
_PROTOCOLS = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58", "all": "-1"}
_MAX_PAIRS = 4000
_MIDDLEBOXES = {"nat_gateway", "gateway_load_balancer", "gateway_load_balancer_endpoint", "transit_gateway", "network_load_balancer",
                "load_balancer"}  # fmt: skip  # rules worked out for the members whose outbound rules do not allow everything inside the VPC


def looks_like_aws(data: bytes) -> bool:
    """JSON of the AWS CLI with security groups in it."""
    head = data[:2_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    return b'"SecurityGroups"' in head or b'"SecurityGroupRules"' in head or (b'"IpPermissions"' in head and b'"GroupId"' in head)


@dataclass
class _Found:
    groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # id -> the group, in the order of the export
    group_rules: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)  # describe-security-group-rules, by group
    interfaces: List[Dict[str, Any]] = field(default_factory=list)
    interfaces_given: bool = False
    vpcs: List[Dict[str, Any]] = field(default_factory=list)
    subnets: List[Dict[str, Any]] = field(default_factory=list)
    nacls: List[Dict[str, Any]] = field(default_factory=list)
    nacls_given: bool = False
    prefix_lists: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    prefix_entries: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    incomplete: List[str] = field(default_factory=list)  # answers that say there is more (NextToken)


@dataclass
class _Element:
    """One source (inbound) or destination (outbound) of a rule of a group: AWS counts each as a rule."""

    group: str
    egress: bool
    protocol: Any
    from_port: Any
    to_port: Any
    kind: str  # "cidr", "prefix-list", "group"
    value: str
    description: str = ""
    rule_id: str = ""
    vpc: str = ""
    user: str = ""
    peering: str = ""
    named_only: bool = False  # a group given by its name alone


def _list(value: Any) -> List[Any]:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _dicts(value: Any) -> List[Dict[str, Any]]:
    return [item for item in _list(value) if isinstance(item, dict)]


def _tag(node: Dict[str, Any], key: str = "Name") -> str:
    for tag in _dicts(node.get("Tags", node.get("TagSet"))):
        if tag.get("Key") == key:
            return str(tag.get("Value", ""))
    return ""


class _Collector:
    def __init__(self) -> None:
        self.found = _Found()

    def walk(self, document: Any) -> None:
        for answer in _list(document) if isinstance(document, list) else [document]:
            if not isinstance(answer, dict):
                continue
            if "GroupId" in answer and ("IpPermissions" in answer or "IpPermissionsEgress" in answer):
                self.group(answer)  # a group on its own (--query 'SecurityGroups[]')
                continue
            if not any(key in answer for key in _ANSWER_KEYS):
                continue
            if answer.get("NextToken"):
                self.found.incomplete.append(next(key for key in _ANSWER_KEYS if key in answer))
            for group in _dicts(answer.get("SecurityGroups")):
                self.group(group)
            for item in _dicts(answer.get("SecurityGroupRules")):
                self.found.group_rules.setdefault(str(item.get("GroupId", "")), []).append(item)
            if "NetworkInterfaces" in answer:
                self.found.interfaces_given = True
                self.found.interfaces += _dicts(answer.get("NetworkInterfaces"))
            self.found.vpcs += _dicts(answer.get("Vpcs"))
            self.found.subnets += _dicts(answer.get("Subnets"))
            if "NetworkAcls" in answer:
                self.found.nacls_given = True
                self.found.nacls += _dicts(answer.get("NetworkAcls"))
            for item in _dicts(answer.get("PrefixLists")):
                self.found.prefix_lists[str(item.get("PrefixListId", ""))] = item
            if "Entries" in answer and answer.get("PrefixListId"):
                self.found.prefix_entries.setdefault(str(answer["PrefixListId"]), []).extend(_dicts(answer.get("Entries")))

    def group(self, group: Dict[str, Any]) -> None:
        ident = str(group.get("GroupId", ""))
        if ident and ident not in self.found.groups:
            self.found.groups[ident] = group


def parse(data: bytes, report: Report) -> Policy:
    try:
        document = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
    try:
        collector = _Collector()
        collector.walk(document)
        if not collector.found.groups:
            raise ParseError("no security groups found; expected the answer of 'aws ec2 describe-security-groups --output json', "
                             "alone or in a JSON array with the other answers")  # fmt: skip
        return _Builder(collector.found, report).build()
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None


@dataclass
class _Service:
    name: str  # ANY for every protocol
    entries: List[ServiceEntry]
    problem: str = ""
    ignored_ports: bool = False


class _Builder:
    def __init__(self, found: _Found, report: Report) -> None:
        self.found, self.report = found, report
        self.p = Policy(vendor="aws")
        self.taken: Set[str] = set()
        self.taken_services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.group_names: Dict[str, str] = {}  # group id -> address group
        self.prefix_names: Dict[str, str] = {}
        self.services: Dict[Tuple[str, str, str], _Service] = {}
        self.vpc = ""
        self.known = found.interfaces_given  # the members of the groups are known
        self.members: Dict[str, List[Interval]] = {}  # group id -> the addresses of its interfaces
        self.host_groups: Dict[Interval, Set[str]] = {}  # address -> the groups of its interface
        self.host_subnet: Dict[Interval, str] = {}
        self.public: List[Tuple[Interval, Interval, str]] = []  # private, public, interface
        self.bad_groups: Dict[str, str] = {}  # group id -> why its members are not known
        self.inside: Optional[List[Interval]] = None
        self.inside_from = ""
        self.inside_group = ""
        self.elements: Dict[str, List[_Element]] = {}  # group id -> its rules, inbound then outbound
        self.missing_groups: Set[str] = set()  # attached to interfaces, not in the export
        self.remote: Set[str] = set()
        self.unused: List[str] = []

    # -- names --------------------------------------------------------------------

    @staticmethod
    def _unique(name: str, taken: Set[str]) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate.lower() in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def _object_name(self, label: str) -> str:
        if label.lower() in (ANY, APP_DEFAULT):
            new = self._unique(f"{label}-object", self.taken)
        elif parse_literal(label) is not None:
            new = self._unique(f"{label} (object)", self.taken)
        else:
            return self._unique(label, self.taken)
        self.report.add("address-group", new, Severity.INFO, "RENAMED", f"named '{label}' in the source, which the model reads "
                        f"as a word or an address of its own; renamed to '{new}'")  # fmt: skip
        return new

    def _rule_name(self, base: str) -> str:
        return self._unique(base, self.rule_names)

    # -- reading ------------------------------------------------------------------

    def build(self) -> Policy:
        self._vpc()
        self._elements()
        self._membership()
        self._inside()
        self._groups()
        if self.found.nacls_given and self.known:
            self._nacls()
        self._pairs()
        self._inbound()
        self._outbound()
        self._nat()
        self._notes()
        return self.p

    def _vpc(self) -> None:
        vpcs = transform.dedupe([str(g.get("VpcId", "")) for g in self.found.groups.values() if g.get("VpcId")])
        if len(vpcs) > 1:
            raise ParseError(f"the export holds security groups of several VPCs ({', '.join(vpcs[:5])}): convert one VPC at a time "
                             "(aws ec2 describe-security-groups --filters Name=vpc-id,Values=vpc-...)")  # fmt: skip
        self.vpc = vpcs[0] if vpcs else ""
        self.p.scope = self.vpc

    def _elements(self) -> None:
        for ident, group in self.found.groups.items():
            out: List[_Element] = []
            if ident in self.found.group_rules:
                for item in self.found.group_rules[ident]:
                    element = self._from_group_rule(ident, item)
                    if element is not None:
                        out.append(element)
            else:
                for egress, key in ((False, "IpPermissions"), (True, "IpPermissionsEgress")):
                    for permission in _dicts(group.get(key)):
                        out += self._from_permission(ident, egress, permission)
            out.sort(key=lambda e: e.egress)  # inbound first; the order within each says nothing
            self.elements[ident] = out

    @staticmethod
    def _from_permission(group: str, egress: bool, permission: Dict[str, Any]) -> List[_Element]:
        base: Dict[str, Any] = dict(group=group, egress=egress, protocol=permission.get("IpProtocol"), from_port=permission.get("FromPort"),
                    to_port=permission.get("ToPort"))  # fmt: skip
        out: List[_Element] = []
        for key in ("IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs"):
            if any(not isinstance(item, dict) for item in _list(permission.get(key))):
                out.append(_Element(kind="cidr", value="", **base))  # (read as nothing, and said)
        for item in _dicts(permission.get("IpRanges")):
            out.append(_Element(kind="cidr", value=str(item.get("CidrIp", "")), description=str(item.get("Description", "")), **base))
        for item in _dicts(permission.get("Ipv6Ranges")):
            out.append(_Element(kind="cidr", value=str(item.get("CidrIpv6", "")), description=str(item.get("Description", "")), **base))
        for item in _dicts(permission.get("PrefixListIds")):
            out.append(_Element(kind="prefix-list", value=str(item.get("PrefixListId", "")), description=str(item.get("Description", "")),
                                **base))  # fmt: skip
        for item in _dicts(permission.get("UserIdGroupPairs")):
            ident = str(item.get("GroupId") or "")
            out.append(_Element(kind="group", value=ident or str(item.get("GroupName", "")), named_only=not ident,
                                description=str(item.get("Description", "")), vpc=str(item.get("VpcId") or ""),
                                user=str(item.get("UserId") or ""), peering=str(item.get("PeeringStatus") or ""), **base))  # fmt: skip
        return out

    @staticmethod
    def _from_group_rule(group: str, item: Dict[str, Any]) -> Optional[_Element]:
        base: Dict[str, Any] = dict(group=group, egress=bool(item.get("IsEgress")), protocol=item.get("IpProtocol"), from_port=item.get("FromPort"),
                    to_port=item.get("ToPort"), description=str(item.get("Description", "")),
                    rule_id=str(item.get("SecurityGroupRuleId", "")))  # fmt: skip
        if item.get("CidrIpv4"):
            return _Element(kind="cidr", value=str(item["CidrIpv4"]), **base)
        if item.get("CidrIpv6"):
            return _Element(kind="cidr", value=str(item["CidrIpv6"]), **base)
        if item.get("PrefixListId"):
            return _Element(kind="prefix-list", value=str(item["PrefixListId"]), **base)
        referenced = item.get("ReferencedGroupInfo")
        if isinstance(referenced, dict):
            return _Element(kind="group", value=str(referenced.get("GroupId", "")), vpc=str(referenced.get("VpcId") or ""),
                            user=str(referenced.get("UserId") or ""), peering=str(referenced.get("PeeringStatus") or ""),
                            **base)  # fmt: skip
        return _Element(kind="cidr", value="", **base)  # (no source: read as nothing, below)

    def _membership(self) -> None:
        if not self.known:
            return
        elsewhere: List[str] = []
        for interface in self.found.interfaces:
            name = str(interface.get("NetworkInterfaceId", "?"))
            groups = [str(g.get("GroupId", "")) for g in _dicts(interface.get("Groups")) if g.get("GroupId")]
            if self.vpc and interface.get("VpcId") and interface.get("VpcId") != self.vpc:
                elsewhere.append(name)
                for group in groups:
                    if group in self.found.groups:
                        self.bad_groups[group] = f"attached to network interface {name} of another VPC, which is not in the export"
                continue
            addresses: List[str] = [str(interface.get("PrivateIpAddress") or "")]
            # A public address is a static NAT of the private one for an instance's interface; a NAT gateway's or a load
            # balancer's is not (nothing from outside is let in to it that way).
            published = bool(groups) and str(interface.get("InterfaceType") or "interface") in ("interface", "efa", "trunk", "branch")
            for item in _dicts(interface.get("PrivateIpAddresses")):
                addresses.append(str(item.get("PrivateIpAddress") or ""))
                public = (item.get("Association") or {}).get("PublicIp") if isinstance(item.get("Association"), dict) else None
                if public and published:
                    self._public(str(item.get("PrivateIpAddress") or ""), str(public), name)
            association = interface.get("Association")
            if published and isinstance(association, dict) and association.get("PublicIp") and not _dicts(interface.get("PrivateIpAddresses")):
                self._public(str(interface.get("PrivateIpAddress") or ""), str(association["PublicIp"]), name)
            for item in _dicts(interface.get("Ipv6Addresses")):
                addresses.append(str(item.get("Ipv6Address") or ""))
            if _list(interface.get("Ipv4Prefixes")) or _list(interface.get("Ipv6Prefixes")):
                for group in groups:
                    self.bad_groups[group] = (f"network interface {name} has delegated prefixes; whether a reference to the group "
                                              "covers their addresses is not documented")  # fmt: skip
            for text in transform.dedupe([a for a in addresses if a]):
                interval = parse_literal(text)
                if interval is None or interval[1] != interval[2]:
                    raise ParseError(f"network interface {name}: '{text[:60]}' is not an address")
                self.host_groups.setdefault(interval, set()).update(groups)
                self.host_subnet[interval] = str(interface.get("SubnetId") or "")
                for group in groups:
                    self.members.setdefault(group, []).append(interval)
                    if group not in self.found.groups:
                        self.missing_groups.add(group)
        routed = [str(i.get("NetworkInterfaceId", "?")) for i in self.found.interfaces
                  if str(i.get("InterfaceType", "")) in _MIDDLEBOXES or i.get("SourceDestCheck") is False]  # fmt: skip
        if routed:
            self.report.note(Severity.REVIEW, "AWS_ROUTED_THROUGH",
                             "traffic is routed through these interfaces (NAT gateways, endpoints, appliances): " + ", ".join(routed[:8])
                             + (" ..." if len(routed) > 8 else "") + ". The network ACLs of their subnets and what they do "
                             "themselves apply to that traffic too, and are not converted")  # fmt: skip
        if elsewhere:
            self.report.note(Severity.INFO, "AWS_OTHER_VPC_INTERFACES",
                             f"network interfaces of other VPCs were left out: {', '.join(elsewhere[:8])}"
                             + (" ..." if len(elsewhere) > 8 else ""))  # fmt: skip

    def _public(self, private: str, public: str, interface: str) -> None:
        inner, outer = parse_literal(private), parse_literal(public)
        if inner is not None and outer is not None and inner[1] == inner[2] and outer[1] == outer[2]:
            if (inner, outer, interface) not in self.public:
                self.public.append((inner, outer, interface))

    def _inside(self) -> None:
        """The addresses of the VPC: from its CIDR blocks, else its subnets, else the interfaces."""
        found: List[Interval] = []
        for vpc in self.found.vpcs:
            if self.vpc and vpc.get("VpcId") != self.vpc:
                continue
            blocks = [str(b.get("CidrBlock", "")) for b in _dicts(vpc.get("CidrBlockAssociationSet")) if _associated(b, "CidrBlockState")]
            blocks += [str(b.get("Ipv6CidrBlock", "")) for b in _dicts(vpc.get("Ipv6CidrBlockAssociationSet"))
                       if _associated(b, "Ipv6CidrBlockState")]  # fmt: skip
            if not blocks and vpc.get("CidrBlock"):
                blocks.append(str(vpc["CidrBlock"]))
            found += [i for i in map(parse_literal, blocks) if i is not None]
        if found:
            self.inside, self.inside_from = normalize(found), "its CIDR blocks"
            return
        for subnet in self.found.subnets:
            if self.vpc and subnet.get("VpcId") not in (None, self.vpc):
                continue
            found += [i for i in map(parse_literal, self._subnet_blocks(subnet)) if i is not None]
        if found:
            self.inside, self.inside_from = normalize(found), "its subnets"
        elif self.known and self.host_groups:
            self.inside, self.inside_from = normalize(list(self.host_groups)), "the addresses of its network interfaces"

    @staticmethod
    def _subnet_blocks(subnet: Dict[str, Any]) -> List[str]:
        blocks = [str(subnet["CidrBlock"])] if subnet.get("CidrBlock") else []
        blocks += [str(b.get("Ipv6CidrBlock", "")) for b in _dicts(subnet.get("Ipv6CidrBlockAssociationSet"))
                   if _associated(b, "Ipv6CidrBlockState")]  # fmt: skip
        return blocks

    # -- objects ------------------------------------------------------------------

    def _groups(self) -> None:
        for ident, group in self.found.groups.items():
            name = self._object_name(str(group.get("GroupName") or ident))
            self.group_names[ident] = name
            description = str(group.get("Description") or "")
            node = AddressGroup(name, description=(description + " " if description else "") + f"(security group {ident})")
            if ident in self.bad_groups:
                node.unsupported = self.bad_groups[ident]
            elif not self.known:
                node.dynamic_filter = "aws:" + json.dumps({"GroupId": ident, "VpcId": self.vpc}, sort_keys=True)
            else:
                node.members = [interval_text(i) for i in normalize(self.members.get(ident, []))]
            self.p.address_groups[name] = node
        if self.inside is not None and self.known:
            label = next((_tag(v) for v in self.found.vpcs if v.get("VpcId") == self.vpc and _tag(v)), "") or self.vpc or "vpc"
            self.inside_group = self._object_name(label)
            self.p.address_groups[self.inside_group] = AddressGroup(
                self.inside_group, [interval_text(i) for i in self.inside], f"the addresses of VPC {self.vpc or '?'} ({self.inside_from})",
                builtin="aws",  # (an AWS target takes it for the inside of the VPC)
            )

    def _group_ref(self, element: _Element) -> str:
        """The address group a reference to a group stands for."""
        ident = element.value
        if ident in self.group_names:
            return self.group_names[ident]
        name = self._object_name(ident or "unnamed-group")
        self.group_names[ident] = name
        node = AddressGroup(name, description=f"security group {ident}" + (f" of account {element.user}" if element.user else "")
                            + (f" in {element.vpc}" if element.vpc else ""))  # fmt: skip
        if element.named_only:
            node.unsupported = "a group given by its name alone (the default VPC); its id is not in the export"
        else:
            node.dynamic_filter = "aws:" + json.dumps({"GroupId": ident, "VpcId": element.vpc or self.vpc, "UserId": element.user},
                                                      sort_keys=True)  # fmt: skip
        self.remote.add(ident)
        self.p.address_groups[name] = node
        return name

    def _prefix_ref(self, ident: str) -> str:
        if ident in self.prefix_names:
            return self.prefix_names[ident]
        info = self.found.prefix_lists.get(ident, {})
        name = self._object_name(str(info.get("PrefixListName") or ident))
        self.prefix_names[ident] = name
        node = AddressGroup(name, description=f"prefix list {ident}")
        if ident not in self.found.prefix_entries:
            node.unsupported = (f"the entries of prefix list {ident} are not in the export (add the answer of aws ec2 "
                                "get-managed-prefix-list-entries)")  # fmt: skip
        else:
            entries = [str(e.get("Cidr", "")) for e in self.found.prefix_entries[ident]]
            bad = [text for text in entries if parse_literal(text) is None]
            if bad:
                node.unsupported = f"entry '{bad[0][:60]}' of prefix list {ident} cannot be read"
            else:
                node.members = [interval_text(i) for i in normalize([i for i in map(parse_literal, entries) if i])]
                if not node.members:
                    node.unsupported = f"prefix list {ident} has no entries"
        self.p.address_groups[name] = node
        return name

    def _member(self, element: _Element) -> Tuple[str, str]:
        """(the rule member an element stands for, why it cannot be read)."""
        if element.kind == "cidr":
            interval = parse_literal(element.value)
            if interval is None or "/" not in element.value:
                return "", f"'{element.value[:60]}' is not a CIDR block"
            return interval_text(interval), ""
        if element.kind == "prefix-list":
            return self._prefix_ref(element.value), ""
        if element.value in self.found.groups:
            return self.group_names[element.value], ""
        return self._group_ref(element), ""

    def _intervals(self, element: _Element) -> Optional[List[Interval]]:
        """The addresses an element stands for; None when they are not known here."""
        if element.kind == "cidr":
            interval = parse_literal(element.value)
            return [interval] if interval is not None and "/" in element.value else None
        name = self._prefix_ref(element.value) if element.kind == "prefix-list" else (
            self.group_names[element.value] if element.value in self.found.groups else self._group_ref(element))
        return transform.address_intervals(self.p, name)

    def _service(self, element: _Element) -> _Service:
        protocol = str(element.protocol if element.protocol is not None else "").strip().lower()
        number = _PROTOCOLS.get(protocol, protocol)
        key = (number, str(element.from_port), str(element.to_port))
        if number not in ("6", "17", "1", "58"):
            key = (number, "", "")
        if key in self.services:
            return self.services[key]
        found = self._read_service(number, element.from_port, element.to_port)
        if found.name != ANY and not found.problem:
            found.name = self._unique(found.name, self.taken_services)
            self.p.services[found.name] = Service(found.name, list(found.entries))
        self.services[key] = found
        return found

    @staticmethod
    def _read_service(number: str, low: Any, high: Any) -> _Service:
        def port(value: Any) -> Optional[int]:
            if isinstance(value, bool):
                return None
            try:
                return int(value)
            except (TypeError, ValueError, OverflowError):
                return None

        first, last = port(low), port(high)
        if number == "-1":
            return _Service(ANY, [])
        if number in ("6", "17"):
            name = "tcp" if number == "6" else "udp"
            if first is None or last is None or first == -1 or last == -1:
                return _Service("", [], f"the ports {low}-{high} cannot be read (TCP and UDP rules have a port range)")
            if not 0 <= first <= last <= 65535:
                return _Service("", [], f"the ports {low}-{high} cannot be read")
            ports = "" if (first, last) == (0, 65535) else (str(first) if first == last else f"{first}-{last}")
            return _Service(f"{name}-{ports or 'all'}", [ServiceEntry(Protocol(name), dst_ports=ports)])
        if number in ("1", "58"):
            kind = Protocol.ICMP if number == "1" else Protocol.ICMP6
            label = "icmp" if number == "1" else "icmpv6"
            if first is None and low is not None:
                return _Service("", [], f"ICMP type {low} cannot be read")
            if first is None and number == "1":
                return _Service("", [], "an ICMP rule without a type (ICMP rules have one, or -1)")
            if first is None or first == -1:
                if last not in (None, -1):
                    return _Service("", [], f"an ICMP code ({high}) without a type")
                return _Service(f"{label}-all", [ServiceEntry(kind)])
            if not 0 <= first <= 255 or (last is not None and not -1 <= last <= 255):
                return _Service("", [], f"ICMP type or code {low}/{high} cannot be read")
            if last is None or last == -1:
                return _Service(f"{label}-{first}", [ServiceEntry(kind, icmp_type=first)])
            return _Service(f"{label}-{first}-{last}", [ServiceEntry(kind, icmp_type=first, icmp_code=last)])
        if not number.isdigit() or not 0 <= int(number) <= 255:
            return _Service("", [], f"protocol '{number[:20]}' cannot be read")
        ignored = first not in (None, -1) or last not in (None, -1)
        if number == "132":
            return _Service("sctp-all", [ServiceEntry(Protocol.SCTP)], ignored_ports=ignored)
        return _Service(f"ip-{number}", [ServiceEntry(Protocol.IP, ip_protocol=int(number))], ignored_ports=ignored)

    def _service_set(self, service: _Service) -> Optional[regions.Services]:
        if service.problem:
            return None
        return regions.ALL_SERVICES if service.name == ANY else regions.service_set(service.entries)

    def _problems(self, element: _Element, service: _Service) -> List[str]:
        problems = [f"{service.problem}"] if service.problem else []
        if element.kind == "cidr":
            interval = parse_literal(element.value)
            if interval is not None and service.entries:
                kind = service.entries[0].protocol
                if (kind == Protocol.ICMP and interval[0] == 6) or (kind == Protocol.ICMP6 and interval[0] == 4):
                    problems.append(f"{'ICMP' if kind == Protocol.ICMP else 'ICMPv6'} with an address of the other IP version "
                                    f"({element.value}), which matches no packet")  # fmt: skip
        return problems

    # -- rules --------------------------------------------------------------------

    def _rule(self, base: str, element: Optional[_Element], **values: Any) -> Rule:
        rule = Rule(self._rule_name(base), **values)
        rule.origin = rule.name
        rule.log_end = False
        if element is not None:
            rule.description = element.description
            rule.source_ids["aws.group_id"] = element.group
            if element.rule_id:
                rule.source_ids["aws.rule_id"] = element.rule_id
        self.p.rules.append(rule)
        return rule

    def _inbound(self) -> None:
        for ident in self.found.groups:
            name = self.group_names[ident]
            if self.known and ident not in self.bad_groups and not self.members.get(ident):
                if any(not e.egress for e in self.elements[ident]):
                    self.unused.append(name)
                continue
            number = 0
            for element in self.elements[ident]:
                if element.egress:
                    continue
                number += 1
                if element.kind == "group" and element.value in self.found.groups and self.known and \
                        element.value not in self.bad_groups and not self.members.get(element.value):
                    continue  # from a group no interface carries: nothing
                if self._other_version(ident, element):
                    continue
                service = self._service(element)
                member, problem = self._member(element)
                rule = self._rule(f"{name}-in-{number}", element, sources=[member or ANY], destinations=[name],
                                  services=[service.name] if service.name and not service.problem else [ANY])  # fmt: skip
                self._finish(rule, element, service, [problem] if problem else [])

    def _outbound(self) -> None:
        for ident in self.found.groups:
            name = self.group_names[ident]
            if self.known and ident not in self.bad_groups and not self.members.get(ident):
                continue
            number = 0
            for element in self.elements[ident]:
                if not element.egress:
                    continue
                number += 1
                if element.kind == "group" and element.value in self.found.groups:
                    continue  # inside the VPC: the inbound rules of the destination decide (and the pairs, above)
                if self._other_version(ident, element):
                    continue
                service = self._service(element)
                member, problem = self._member(element)
                destinations = [member or ANY]
                if member and self.inside is not None:
                    intervals = self._intervals(element)
                    # Inside the VPC the inbound rules of the destination decide too. (Its public addresses are outside:
                    # what is sent there leaves through the internet gateway, see AWS_HAIRPIN.)
                    if intervals is not None and overlaps(intervals, self.inside):
                        rest = subtract(intervals, self.inside)
                        if not rest:
                            continue  # inside the VPC only: as above
                        destinations = [interval_text(i) for i in rest]
                rule = self._rule(f"{name}-out-{number}", element, sources=[name], destinations=destinations,
                                  services=[service.name] if service.name and not service.problem else [ANY])  # fmt: skip
                if destinations != [member] and member:
                    rule.description = (rule.description + " | " if rule.description else "") + \
                        f"{member} without the addresses of the VPC"
                self._finish(rule, element, service, [problem] if problem else [])

    def _other_version(self, group: str, element: _Element) -> bool:
        """Whether an address block of a rule is of an IP version no member of its group has: then it matches nothing."""
        if not self.known or group in self.bad_groups or element.kind != "cidr":
            return False
        interval = parse_literal(element.value)
        return interval is not None and all(member[0] != interval[0] for member in self.members.get(group, []))

    def _finish(self, rule: Rule, element: _Element, service: _Service, problems: List[str]) -> None:
        problems = problems + self._problems(element, service)
        if not element.value:
            problems.append("a rule without a source or destination")
        rule.unsupported += problems
        if service.ignored_ports:
            self.report.add("rule", rule.origin, Severity.INFO, "AWS_PORTS_IGNORED",
                            f"ports {element.from_port}-{element.to_port} with protocol {element.protocol}: AWS ignores them, and "
                            "so does the converted rule")  # fmt: skip
        if element.kind == "group" and element.value not in self.found.groups and element.peering and element.peering != "active":
            self.report.add("rule", rule.origin, Severity.REVIEW, "AWS_STALE_REFERENCE",
                            f"the rule names group {element.value} through a peering connection in state {element.peering}")

    # -- what members may reach inside the VPC ------------------------------------------

    def _pairs(self) -> None:
        """Rules for the members whose outbound rules do not allow everything inside the VPC."""
        if not self.known:
            restricted = [self.group_names[g] for g in self.found.groups if not self._open(g)]
            if restricted:
                self.report.note(Severity.REVIEW, "AWS_EGRESS_UNKNOWN",
                                 "the outbound rules of these groups do not allow everything, and without the network interfaces "
                                 "(describe-network-interfaces) it is not known which addresses are their members: inside the "
                                 "VPC, the converted inbound rules do not check what the source may send: " + ", ".join(restricted))  # fmt: skip
            return
        hosts = normalize(list(self.host_groups))
        profiles: Dict[FrozenSet[str], List[Interval]] = {}
        for host, groups in self.host_groups.items():
            if groups:  # (an interface without groups, a NAT gateway's, sends what it is given: no outbound rules)
                profiles.setdefault(frozenset(groups), []).append(host)
        written, capped = 0, []
        for profile in sorted(profiles, key=lambda p: sorted(self.group_names.get(g, g) for g in p)):
            versions = {host[0] for host in profiles[profile]}  # (a member without an IPv6 address sends no IPv6)
            if self._covers(profile, [host for host in hosts if host[0] in versions]):
                continue
            label = "+".join(sorted(self.group_names.get(g, g) for g in profile))
            members = normalize(profiles[profile])
            count, complete = self._pair_rules(profile, label, members)
            written += count
            if not complete:
                capped.append(label)
            holder = self._unique(f"{label} members", self.taken)
            self.p.address_groups[holder] = AddressGroup(holder, [interval_text(i) for i in members],
                                                         f"the addresses whose groups are exactly {label}")  # fmt: skip
            rule = self._rule(f"{label}-outbound-rest", None, sources=[holder], destinations=[self.inside_group], action=Action.DROP)
            rule.description = f"what the outbound rules of {label} do not allow inside the VPC"
        if written or capped:
            self.report.note(Severity.INFO, "AWS_EGRESS_PAIRS",
                             f"inside the VPC a connection needs an outbound rule of the source's groups and an inbound rule of the "
                             f"destination's. Where the outbound rules do not allow everything, {written} rule{' allows' if written == 1 else 's allow'} what both "
                             "allow, and a rule after them blocks the rest of what those members send inside the VPC")  # fmt: skip
        if capped:
            self.report.note(Severity.REVIEW, "AWS_EGRESS_PAIRS_LEFT_OUT",
                             "for the members of these groups not every connection inside the VPC could be worked out (too many, or "
                             "a prefix list without its entries); the converted policy blocks what was left out: " + ", ".join(capped))  # fmt: skip

    def _open(self, group: str) -> bool:
        """Whether the outbound rules of a group allow every protocol to every address."""
        found: List[Interval] = []
        for element in self.elements.get(group, []):
            if element.egress and self._service(element).name == ANY and not self._service(element).problem:
                found += self._intervals(element) or []
        need = self.inside if self.inside is not None else [regions.full(4), regions.full(6)]
        return within(need, found)

    def _covers(self, profile: FrozenSet[str], hosts: List[Interval]) -> bool:
        if profile & self.missing_groups:
            return False
        found: List[Interval] = []
        for group in profile:
            for element in self.elements.get(group, []):
                service = self._service(element)
                if element.egress and service.name == ANY and not service.problem:
                    found += self._intervals(element) or []
        return within(hosts, found)

    def _pair_rules(self, profile: FrozenSet[str], label: str, members: List[Interval]) -> Tuple[int, bool]:
        count, complete = 0, not (profile & set(self.bad_groups))
        outbound = [e for g in sorted(profile) if g in self.found.groups and g not in self.bad_groups for e in self.elements[g] if e.egress]
        for egress in outbound:
            reach = self._intervals(egress)
            out_service = self._service(egress)
            out_set = self._service_set(out_service)
            if reach is None or out_set is None or self._problems(egress, out_service):
                if not (egress.kind == "group" and egress.value not in self.found.groups):
                    complete = False  # (a group of another VPC is outside: no pair)
                continue
            for target in self.found.groups:
                if target in self.bad_groups or not self.members.get(target):
                    continue
                destinations = intersect(self.members[target], reach)
                if not destinations:
                    continue
                for ingress in (e for e in self.elements[target] if not e.egress):
                    sources = self._intervals(ingress)
                    in_service = self._service(ingress)
                    in_set = self._service_set(in_service)
                    if sources is None or in_set is None or self._problems(ingress, in_service):
                        if ingress.kind == "prefix-list" or in_set is None:
                            complete = False
                        continue
                    allowed = intersect(members, sources)
                    both = out_set.and_(in_set)
                    if not allowed or both.empty():
                        continue
                    for version in (4, 6):
                        src, dst = regions.addresses(allowed, version), regions.addresses(destinations, version)
                        if not src or not dst:
                            continue
                        services = self._pair_service(both, version, out_service, out_set, in_service, in_set)
                        if services is None:
                            complete = False
                            continue
                        if count >= _MAX_PAIRS:
                            return count, False
                        names, negated = services
                        rule = self._rule(f"{label}-to-{self.group_names[target]}", None, sources=[interval_text(i) for i in src],
                                          destinations=[interval_text(i) for i in dst], services=names)  # fmt: skip
                        rule.negate_service = negated
                        rule.description = (f"outbound rule of {self.group_names[egress.group]} and inbound rule of "
                                            f"{self.group_names[target]}")  # fmt: skip
                        rule.source_ids["aws.group_id"] = egress.group
                        count += 1
        return count, complete

    def _pair_service(self, both: regions.Services, version: int, out_service: _Service, out_set: regions.Services,
                      in_service: _Service, in_set: regions.Services) -> Optional[Tuple[List[str], bool]]:  # fmt: skip
        for service, whole in ((in_service, in_set), (out_service, out_set)):
            if _same(both, whole):
                return [service.name], False
        found = regions.entries_of(both, version)
        if found is None:
            return None
        entries, negated = found
        if not entries:
            return ([ANY], False) if negated else None
        name = self._unique("svc-" + "-".join(e.protocol.value + (e.dst_ports or str(e.icmp_type or "")) for e in entries[:3]),
                            self.taken_services)  # fmt: skip
        self.p.services[name] = Service(name, entries)
        return [name], negated

    # -- network ACLs ---------------------------------------------------------------

    def _nacls(self) -> None:
        subnets = {str(s.get("SubnetId", "")): s for s in self.found.subnets}
        used = transform.dedupe([self.host_subnet[h] for h in sorted(self.host_groups) if self.host_subnet.get(h)])
        by_subnet: Dict[str, Dict[str, Any]] = {}
        default: Optional[Dict[str, Any]] = None
        for acl in self.found.nacls:
            if self.vpc and acl.get("VpcId") not in (None, self.vpc):
                continue
            if acl.get("IsDefault"):
                default = acl
            for association in _dicts(acl.get("Associations")):
                by_subnet[str(association.get("SubnetId", ""))] = acl
        unknown: List[str] = []
        for subnet in used:
            chosen = by_subnet.get(subnet, default)
            if chosen is None:
                unknown.append(subnet)
                continue
            if subnet not in subnets:
                self.report.note(Severity.REVIEW, "AWS_NACL_NO_SUBNET",
                                 f"network ACL {chosen.get('NetworkAclId', '?')} of subnet {subnet} is not converted: the subnet "
                                 "(describe-subnets) is not in the export, and without its addresses it is not known where the "
                                 "ACL applies. The converted policy allows what the ACL may deny")  # fmt: skip
                continue
            blocks = [i for i in map(parse_literal, self._subnet_blocks(subnets[subnet])) if i is not None]
            for version in (4, 6):
                if not regions.addresses(blocks, version):  # (no block of that version listed: its members, at least)
                    blocks += [h for h in self.host_groups if h[0] == version and self.host_subnet.get(h) == subnet]
            self._nacl(chosen, subnet, normalize(blocks), _tag(subnets[subnet]) or subnet)
        if unknown:
            self.report.note(Severity.REVIEW, "AWS_NACL_MISSING",
                             "the network ACLs of these subnets are not in the export; the converted policy allows what they may "
                             "deny: " + ", ".join(unknown))  # fmt: skip

    def _nacl(self, acl: Dict[str, Any], subnet: str, blocks: List[Interval], place: str) -> None:
        ident = str(acl.get("NetworkAclId", "acl"))
        label = _tag(acl) or ident
        denied: Dict[bool, List[regions.Box]] = {}
        for egress in (False, True):
            entries = sorted((e for e in _dicts(acl.get("Entries")) if bool(e.get("Egress")) == egress),
                             key=lambda e: _number(e.get("RuleNumber")))  # fmt: skip
            found = self._acl_denies(entries, ident)
            if found is None:
                self.report.note(Severity.REVIEW, "AWS_NACL_NOT_CONVERTED",
                                 f"network ACL {ident} ({'outbound' if egress else 'inbound'}) of subnet {subnet} is not converted: "
                                 "an entry cannot be read, or what it denies is too complex. The converted policy allows what it "
                                 "may deny")  # fmt: skip
                continue
            denied[egress] = found
            merged: Dict[Tuple[int, str, bool], Tuple[List[Interval], List[ServiceEntry]]] = {}
            for box in found:
                version = box[0]
                own = regions.addresses(blocks, version)
                if not own:
                    continue
                peers = subtract(box[1], own)  # (traffic inside the subnet passes no ACL)
                if not peers:
                    continue
                services = regions.entries_of(box[3], version)
                if services is None:
                    self.report.note(Severity.REVIEW, "AWS_NACL_NOT_CONVERTED",
                                     f"part of what network ACL {ident} denies at subnet {subnet} has too many ICMP types and codes "
                                     "to be written; the converted policy allows it")  # fmt: skip
                    continue
                entries_found, negated = services
                if not entries_found and not negated:
                    continue
                key = (version, repr(entries_found), negated)
                merged.setdefault(key, ([], entries_found))[0].extend(peers)
            for (version, _, negated), (peers, entries_found) in merged.items():
                peers = normalize(peers)
                own = regions.addresses(blocks, version)
                names = [ANY]
                if entries_found:
                    names = [self._acl_service(f"{label}-{'out' if egress else 'in'}", entries_found, ident)]
                side_peers, side_own = [interval_text(i) for i in peers], [interval_text(i) for i in own]
                rule = self._rule(f"{label}-{'out' if egress else 'in'}-{place}", None,
                                  sources=side_own if egress else side_peers, destinations=side_peers if egress else side_own,
                                  services=names, action=Action.DROP)  # fmt: skip
                rule.negate_service = bool(entries_found) and negated
                rule.description = f"denied by network ACL {ident} where traffic {'leaves' if egress else 'enters'} subnet {subnet}"
                rule.source_ids["aws.network_acl_id"] = ident
        self._returns(denied, ident, subnet)

    def _acl_service(self, base: str, entries: List[ServiceEntry], acl: str) -> str:
        for name, service in self.p.services.items():
            if service.entries == entries and service.description == f"network ACL {acl}":
                return name
        number = 1
        while f"{base}-{number}".lower() in self.taken_services:
            number += 1
        name = f"{base}-{number}"
        self.taken_services.add(name.lower())
        self.p.services[name] = Service(name, entries, description=f"network ACL {acl}")
        return name

    def _acl_denies(self, entries: List[Dict[str, Any]], acl: str) -> Optional[List[regions.Box]]:
        """What an ordered list of ACL entries denies, as boxes of (peer addresses, services); the destination side of
        each box is every address (it is the subnet's, put in by the caller)."""
        remaining: List[regions.Box] = [(v, [regions.full(v)], [regions.full(v)], regions.ALL_SERVICES) for v in (4, 6)]
        denied: List[regions.Box] = []
        for entry in entries:
            box = self._acl_box(entry)
            if box is None:
                return None
            if regions.empty(box):
                continue
            if str(entry.get("RuleAction", "")).lower() == "deny":
                denied += [piece for piece in (regions.box_and(r, box) for r in remaining) if piece is not None]
            elif str(entry.get("RuleAction", "")).lower() != "allow":
                return None
            cut = regions.minus_all(remaining, [box], limit=2000)
            if cut is None:
                return None
            remaining = cut
        return denied + remaining  # (what no entry allows is denied by the last rule, '*')

    @staticmethod
    def _acl_box(entry: Dict[str, Any]) -> Optional[regions.Box]:
        text = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
        interval = parse_literal(str(text or ""))
        if interval is None:
            return None
        protocol = str(entry.get("Protocol", "")).strip().lower()
        protocol = _PROTOCOLS.get(protocol, protocol)
        version = interval[0]
        nothing: regions.Box = (version, [], [], regions.ALL_SERVICES)
        if protocol == "-1":
            svc = regions.ALL_SERVICES
        elif protocol in ("6", "17"):
            if not isinstance(entry.get("PortRange"), dict):
                return None  # (a TCP or UDP entry has a port range)
            ports: Dict[str, Any] = entry["PortRange"]
            low, high = _number(ports.get("From"), -1), _number(ports.get("To"), -1)
            if not 0 <= low <= high <= 65535:
                return None
            kind = Protocol.TCP if protocol == "6" else Protocol.UDP
            found = regions.service_set([ServiceEntry(kind, dst_ports="" if (low, high) == (0, 65535) else f"{low}-{high}")])
            if found is None:
                return None
            svc = found
        elif protocol in ("1", "58"):
            if (protocol == "1") != (version == 4):
                if protocol == "58" and version == 4:
                    return nothing  # ICMPv6 with an IPv4 block: no packet
                return nothing
            if not isinstance(entry.get("IcmpTypeCode"), dict):
                return None  # (an ICMP entry has a type and a code, -1 for all)
            codes: Dict[str, Any] = entry["IcmpTypeCode"]
            kind_value, code_value = _number(codes.get("Type"), -2), _number(codes.get("Code"), -2)
            if not -1 <= kind_value <= 255 or not -1 <= code_value <= 255:
                return None
            found = regions.service_set([ServiceEntry(Protocol.ICMP if protocol == "1" else Protocol.ICMP6,
                                                      icmp_type=None if kind_value < 0 else kind_value,
                                                      icmp_code=None if code_value < 0 or kind_value < 0 else code_value)])  # fmt: skip
            if found is None:
                return None
            svc = found
        elif protocol.isdigit() and 0 <= int(protocol) <= 255:
            found = regions.service_set([ServiceEntry(Protocol.IP, ip_protocol=int(protocol))])
            if found is None:
                return None
            svc = found
        else:
            return None
        return (version, [interval], [regions.full(version)], svc)

    def _returns(self, denied: Dict[bool, List[regions.Box]], acl: str, subnet: str) -> None:
        """Whether the ACL lets the replies of connections through: TCP and UDP to the ports clients use, ICMP echo replies,
        and every other protocol."""
        clients = (0, 65535, 1024, 65535)
        replies = regions.Services({6: [clients], 17: [clients], 1: [(0, 0, 0, 65535)], 58: [(129, 129, 0, 65535)]}, True)
        for egress, boxes in denied.items():
            wanted = [(v, [regions.full(v)], [regions.full(v)], replies) for v in (4, 6)]
            if any(regions.box_and(w, b) is not None for w in wanted for b in boxes):
                self.report.note(Severity.REVIEW, "AWS_NACL_RETURN",
                                 f"network ACL {acl} of subnet {subnet} denies some {'outbound' if egress else 'inbound'} TCP or UDP "
                                 "to ports 1024-65535, ICMP echo replies or other protocols. It does not remember connections: the "
                                 f"replies of connections {'into' if egress else 'out of'} the subnet need them, and where it denies "
                                 "them a connection the converted policy allows fails")  # fmt: skip

    # -- NAT and notes --------------------------------------------------------------

    def _nat(self) -> None:
        for private, public, interface in self.public:
            name = self._unique(f"public-{interval_text(public)}", {n.name.lower() for n in self.p.nat_rules})
            nat = NatRule(name, sources=[interval_text(private)], description=f"public address of {interface}")
            nat.source_translation = SourceNat(SnatKind.STATIC, [interval_text(public)], bidirectional=True)
            nat.origin = name
            self.p.nat_rules.append(nat)
        if self.public:
            self.p.lookup_after_dnat = True
            # (A blocking rule of a network ACL sees the public address on the way out, as the model does: nothing to say.)
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False, report_deny=False)
            # From outside the groups see the private address: a rule for it is meant for the public one as well. Traffic from
            # inside to a public address is another matter (AWS_HAIRPIN), which the findings of the rewriting cannot tell.
            self.report.retract("rule", {"NAT_DESTINATION_REWRITTEN", "NAT_ADDRESS_EXPOSED"})
            self.report.note(Severity.INFO, "AWS_PUBLIC_ADDRESSES",
                             "the public and Elastic IP addresses of the network interfaces are static NAT of their private "
                             "addresses: the internet gateway translates what comes from outside, and the groups see the private "
                             "address. The rules that name a private address name its public address as well, as the model has "
                             "rules before NAT")  # fmt: skip
            self.report.note(Severity.REVIEW, "AWS_HAIRPIN",
                             "connections from inside the VPC to its own public addresses are not converted as AWS decides them: "
                             "they leave through the internet gateway, the source's outbound rules see the public address and the "
                             "destination's inbound rules see the source's public address (or that of its NAT gateway). The "
                             "converted policy treats them as connections to the private address, which may allow more")  # fmt: skip

    def _notes(self) -> None:
        self.report.note(Severity.INFO, "AWS_UNFILTERED",
                         "security groups never filter traffic to the Amazon DNS server, DHCP, the instance metadata service, "
                         "the Time Sync Service and Windows license activation; neither does the converted policy say anything "
                         "about it")  # fmt: skip
        if self.found.incomplete:
            self.report.note(Severity.REVIEW, "AWS_INCOMPLETE_EXPORT",
                             "these answers say there is more to fetch (NextToken): " + ", ".join(transform.dedupe(self.found.incomplete))
                             + ". Export without --max-items; groups or interfaces left out make the converted policy differ")  # fmt: skip
        if not self.known:
            self.report.note(Severity.REVIEW, "AWS_NO_INTERFACES",
                             "the network interfaces (describe-network-interfaces) are not in the export: which addresses a group "
                             "stands for is not known, and its rules cannot be written for any target. Add that answer")  # fmt: skip
        if self.remote:
            self.report.note(Severity.REVIEW, "AWS_REMOTE_GROUP",
                             "rules name groups that are not in the export (another VPC, another account, or left out): "
                             + ", ".join(sorted(self.remote)) + ". Their members are not known; those rules are not converted")  # fmt: skip
        if self.missing_groups:
            self.report.note(Severity.REVIEW, "AWS_GROUP_MISSING",
                             "network interfaces carry groups that are not in the export: " + ", ".join(sorted(self.missing_groups))
                             + ". What those groups allow is missing from the converted policy")  # fmt: skip
        if self.unused:
            self.report.note(Severity.INFO, "AWS_GROUP_UNUSED",
                             "no network interface of the export carries these groups, so their inbound rules allow nothing and "
                             "were left out: " + ", ".join(self.unused))  # fmt: skip
        if self.found.nacls_given and not self.known:
            self.report.note(Severity.REVIEW, "AWS_NACL_NOT_CONVERTED",
                             "the network ACLs are not converted: without the network interfaces it is not known which subnets "
                             "hold members")  # fmt: skip
        elif not self.found.nacls_given and self.known:
            self.report.note(Severity.INFO, "AWS_NACL_NOT_EXPORTED",
                             "the network ACLs (describe-network-acls) are not in the export: the converted policy is what the "
                             "security groups allow, and an ACL may deny more")  # fmt: skip


def _associated(block: Dict[str, Any], key: str) -> bool:
    state = block.get(key)
    return not isinstance(state, dict) or str(state.get("State", "associated")) == "associated"


def _number(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _same(a: regions.Services, b: regions.Services) -> bool:
    return a.minus(b).empty() and b.minus(a).empty()
