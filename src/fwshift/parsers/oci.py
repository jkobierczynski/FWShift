# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Oracle Cloud Infrastructure (OCI) security lists and network security groups parser: the JSON of the OCI CLI -> model.

What is read, for one VCN: the answers of ``oci network vcn get``, ``subnet list``, ``security-list list``, ``nsg list``,
``nsg rules list`` (one per NSG, wrapped with the NSG it is for: ``--query "{nsgId: '<ocid>', data: data}"``, since a
rule does not name its NSG), ``private-ip list`` and ``vnic get``; optionally Oracle's ``public_ip_ranges.json`` with
``oci iam region list``, for the addresses of service CIDR labels. The answers one after the other, as a shell
concatenates them, or in a JSON array. Keys as the CLI prints them (``is-stateless``) or as the API and the SDKs do
(``isStateless``). Each object is told by its OCID (``ocid1.securitylist.``, ...) or, without one, by its keys.

How OCI behaviour is mapped onto the neutral model:

* Security rules only allow, and the rules of the security lists of a VNIC's subnet and of every NSG the VNIC is in are
  one set, without order: every rule of the model allows, and what no rule allows is denied. There are no zones: a
  security list stands for the addresses of the subnets it is associated with, an NSG for the addresses of its VNICs
  (from ``vnic get`` and ``private-ip list``); without the VNICs an NSG's members are not known, and it is a dynamic
  group whose rules no target can write.
* The rules are enforced at each VNIC, whether the peer is in the VCN or not, so inside the VCN a connection needs the
  sender's egress rules and the receiver's ingress rules. As for AWS: an ingress rule allows its sources to reach the
  members; an egress rule is read for the addresses outside the VCN only; where the egress rules of an address do not
  allow everything inside the VCN, what it may reach there is worked out rule by rule (an egress rule of its lists and
  NSGs together with an ingress rule of the destination's), and the rest is denied.
* A stateless rule does not track the connection, and when a stateless and a stateful rule match the same traffic in
  one direction the stateless one decides: the reply then needs a rule in the other direction (an egress rule of the
  same VNIC for a stateless ingress rule). What a VNIC lets in or out statelessly and whose replies it does not let
  through is blocked at the top. An ICMP message other than a request has no reply; a request (echo, timestamp,
  information, address mask) needs its reply type, code 0.
* A public IP address of a VNIC is a static NAT of its primary private address at the internet gateway; the rules see
  the private address.
* Traffic to and from 169.254.0.0/16 (metadata, iSCSI, DNS, NTP) is never filtered; the model says nothing about it.

From Oracle's documentation of security rules, security lists, network security groups, the API reference and the CLI
reference; not confirmed in a tenancy. That a CIDR rule also matches traffic from a VNIC of the same subnet, and the
reply types of ICMP requests, are FWShift's reading.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .. import regions, transform
from ..errors import ParseError
from ..model import ANY, APP_DEFAULT, Action, AddressGroup, NatRule, Policy, Protocol, Rule, Service, ServiceEntry, SnatKind, SourceNat
from ..netutil import Interval, intersect, interval_text, normalize, overlaps, parse_literal, subtract, within
from ..report import Report, Severity

_MAX_PAIRS = 4000
_REPLY_TYPE = {1: {8: 0, 13: 14, 15: 16, 17: 18}, 58: {128: 129}}  # an ICMP request and the type of its reply
_GONE = ("TERMINATED", "TERMINATING")
Profile = Tuple[str, FrozenSet[str]]  # (subnet, NSGs) of an address


def looks_like_oci(data: bytes) -> bool:
    """JSON of the OCI CLI (or API) with security lists or network security groups in it."""
    head = data[:2_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith((b"{", b"[")):
        return False
    if b'"ocid1.securitylist.' in head or b'"ocid1.networksecuritygroup.' in head:
        return True
    return any(key in head for key in (b'"ingress-security-rules"', b'"egress-security-rules"', b'"ingressSecurityRules"',
                                       b'"egressSecurityRules"'))  # fmt: skip


def _key(text: str) -> str:
    return text.replace("-", "").replace("_", "").lower()


def _norm(value: Any, depth: int = 0) -> Any:
    """Keys as one spelling: kebab-case (the CLI) and camelCase (the API) both become lower case without separators."""
    if depth > 40:
        raise ParseError("JSON nested deeper than can be followed")
    if isinstance(value, dict):
        return {_key(str(k)): _norm(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_norm(v, depth + 1) for v in value]
    return value


def _documents(data: bytes) -> List[Any]:
    """One JSON value, or several one after the other (the answers of several CLI calls in one file)."""
    text = data.decode("utf-8-sig", errors="replace")
    decoder = json.JSONDecoder()
    out: List[Any] = []
    position = 0
    while True:
        while position < len(text) and text[position] in " \t\r\n":
            position += 1
        if position >= len(text):
            break
        try:
            value, position = decoder.raw_decode(text, position)
        except ValueError as error:
            raise ParseError(f"the JSON cannot be read: {str(error)[:200]}") from None
        out.append(value)
        if len(out) > 100000:
            raise ParseError("more than 100000 JSON documents in one file")
    if not out:
        raise ParseError("the input is empty")
    return out


def _list(value: Any) -> List[Any]:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def _dicts(value: Any) -> List[Dict[str, Any]]:
    return [item for item in _list(value) if isinstance(item, dict)]


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _kind(item: Dict[str, Any]) -> str:
    ident = _text(item.get("id"))
    if ident.startswith("ocid1."):
        return ident.split(".")[1]
    if "direction" in item and "protocol" in item:
        return "rule"
    if "ingresssecurityrules" in item or "egresssecurityrules" in item:
        return "securitylist"
    if "securitylistids" in item:
        return "subnet"
    if "defaultsecuritylistid" in item or "cidrblocks" in item:
        return "vcn"
    if "nsgids" in item or "macaddress" in item:
        return "vnic"
    if "ipaddress" in item and "vnicid" in item:
        return "ipv6" if ":" in _text(item.get("ipaddress")) else "privateip"
    if set(item) <= {"key", "name"} and "key" in item and "name" in item:
        return "region"
    return ""


@dataclass
class _Found:
    vcns: List[Dict[str, Any]] = field(default_factory=list)
    subnets: List[Dict[str, Any]] = field(default_factory=list)
    lists: List[Dict[str, Any]] = field(default_factory=list)
    nsgs: List[Dict[str, Any]] = field(default_factory=list)
    rules: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)  # NSG -> its rules (nsg rules list)
    vnics: List[Dict[str, Any]] = field(default_factory=list)
    private_ips: List[Dict[str, Any]] = field(default_factory=list)
    regions: Dict[str, str] = field(default_factory=dict)  # region key (IAD) -> name (us-ashburn-1)
    ranges: Dict[str, List[Tuple[str, List[str]]]] = field(default_factory=dict)  # region -> (cidr, tags)
    ranges_stamp: str = ""
    orphans: int = 0  # NSG rules not wrapped with their NSG
    incomplete: List[str] = field(default_factory=list)
    gone: List[str] = field(default_factory=list)


class _Collector:
    def __init__(self) -> None:
        self.found = _Found()

    def walk(self, document: Any, depth: int = 0) -> None:
        for answer in document if isinstance(document, list) else [document]:
            if isinstance(answer, list) and depth < 3:
                self.walk(answer, depth + 1)  # (answers in a JSON array, or items on their own)
                continue
            if not isinstance(answer, dict):
                continue
            if isinstance(answer.get("regions"), list) and "lastupdatedtimestamp" in answer:
                self.ranges(answer)
                continue
            if "data" not in answer:
                self.item(answer, _text(answer.get("nsgid")))
                continue
            nsg = _text(answer.get("nsgid"))
            if answer.get("opcnextpage"):
                self.found.incomplete.append(nsg or "a list")
            if nsg:
                self.found.rules.setdefault(nsg, [])
            for item in _dicts(answer.get("data")):
                self.item(item, nsg)

    def item(self, item: Dict[str, Any], nsg: str) -> None:
        kind = _kind(item)
        if kind == "rule":
            if nsg:
                self.found.rules.setdefault(nsg, []).append(item)
            else:
                self.found.orphans += 1
            return
        if _text(item.get("lifecyclestate")).upper() in _GONE:
            self.found.gone.append(_text(item.get("displayname")) or _text(item.get("id")))
            return
        if kind == "region":
            self.found.regions[_text(item.get("key")).lower()] = _text(item.get("name"))
            return
        target = {"vcn": self.found.vcns, "subnet": self.found.subnets, "securitylist": self.found.lists,
                  "networksecuritygroup": self.found.nsgs, "vnic": self.found.vnics, "privateip": self.found.private_ips,
                  "ipv6": self.found.private_ips}.get(kind)  # fmt: skip
        if target is not None and not any(_text(o.get("id")) == _text(item.get("id")) and o.get("id") for o in target):
            target.append(item)

    def ranges(self, answer: Dict[str, Any]) -> None:
        self.found.ranges_stamp = _text(answer.get("lastupdatedtimestamp"))
        for region in _dicts(answer.get("regions")):
            entries = self.found.ranges.setdefault(_text(region.get("region")), [])
            for cidr in _dicts(region.get("cidrs")):
                entries.append((_text(cidr.get("cidr")), [_text(t) for t in _list(cidr.get("tags"))]))


def parse(data: bytes, report: Report, vcn: str = "") -> Policy:
    try:
        documents = _norm(_documents(data))
        collector = _Collector()
        collector.walk(documents)
        found = collector.found
        if not found.lists and not found.nsgs:
            raise ParseError("no security lists or network security groups found; expected the answers of 'oci network "
                             "security-list list' and 'oci network nsg list' (with 'oci network nsg rules list' for each NSG), "
                             "one after the other or in a JSON array")  # fmt: skip
        return _Builder(found, report, vcn).build()
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        if isinstance(error, ParseError):
            raise
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None


@dataclass
class _Element:
    """One security rule of a security list or an NSG."""

    holder: str  # "sl:<ocid>" or "nsg:<ocid>"
    egress: bool
    stateless: bool
    protocol: str
    kind: str  # "cidr", "service", "nsg"
    value: str
    options: Dict[str, Any]
    number: int
    description: str = ""
    rule_id: str = ""
    invalid: bool = False
    problem: str = ""


@dataclass
class _Holder:
    key: str
    ident: str
    kind: str  # "security list", "NSG"
    label: str
    name: str = ""  # its address group
    elements: List[_Element] = field(default_factory=list)


@dataclass
class _Service:
    name: str  # ANY for every protocol
    entries: List[ServiceEntry]
    problem: str = ""


class _Builder:
    def __init__(self, found: _Found, report: Report, vcn: str) -> None:
        self.found, self.report, self.wanted = found, report, vcn
        self.p = Policy(vendor="oci")
        self.taken: Set[str] = set()
        self.taken_services: Set[str] = set()
        self.rule_names: Set[str] = set()
        self.vcn = ""
        self.holders: Dict[str, _Holder] = {}
        self.subnets: Dict[str, Dict[str, Any]] = {}
        self.subnet_blocks: Dict[str, List[Interval]] = {}
        self.subnet_names: Dict[str, str] = {}
        self.known = bool(found.vnics) or not found.nsgs  # NSG membership is known
        self.host_nsgs: Dict[Interval, FrozenSet[str]] = {}
        self.host_subnet: Dict[Interval, str] = {}
        self.nsg_members: Dict[str, List[Interval]] = {}
        self.public: List[Tuple[Interval, Interval, str]] = []
        self.profiles: Dict[Profile, List[Interval]] = {}
        self.inside: Optional[List[Interval]] = None
        self.inside_from = ""
        self.inside_group = ""
        self.refs: Dict[str, str] = {}  # NSG OCID or service label -> address group
        self.services: Dict[str, _Service] = {}
        self.missing_lists: Set[str] = set()
        self.missing_nsgs: Set[str] = set()
        self.missing_subnets: Set[str] = set()
        self.remote: Set[str] = set()
        self.labels: Set[str] = set()
        self.unused: List[str] = []
        self.element_rules: List[Tuple[_Element, Rule, List[Profile]]] = []
        self.unreplied: Dict[Profile, List[regions.Box]] = {}
        self.foreign: Set[str] = set()  # subnets of other VCNs

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

    # -- reading ------------------------------------------------------------------

    def build(self) -> Policy:
        self._scope()
        self._subnets()
        self._holders()
        self._membership()
        self._inside()
        self._profiles()
        self._groups()
        self._stateless()
        self._pairs()
        self._rules(egress=False)
        self._rules(egress=True)
        self._nat()
        self._notes()
        return self.p

    def _scope(self) -> None:
        """One VCN: the one --policy names, or the only one in the input."""
        found = self.found
        vcns = transform.dedupe([_text(o.get("vcnid")) for o in found.subnets + found.lists + found.nsgs if o.get("vcnid")]
                                + [_text(v.get("id")) for v in found.vcns if v.get("id")])  # fmt: skip
        if self.wanted:
            chosen = [_text(v.get("id")) for v in found.vcns if self.wanted in (_text(v.get("id")), _text(v.get("displayname")))]
            if not chosen and self.wanted in vcns:
                chosen = [self.wanted]
            if not chosen:
                raise ParseError(f"--policy {self.wanted}: no VCN of that OCID or name in the input (it holds {', '.join(vcns[:5]) or 'none'})")
            self.vcn = chosen[0]
        elif len(vcns) > 1:
            raise ParseError(f"the input holds several VCNs ({', '.join(vcns[:5])}): convert one at a time (--policy with the OCID or "
                             "the name of the VCN, or list with --vcn-id)")  # fmt: skip
        else:
            self.vcn = vcns[0] if vcns else ""
        self.p.scope = self.vcn
        if self.vcn:
            self.foreign = {_text(o.get("id")) for o in found.subnets if _text(o.get("vcnid")) not in ("", self.vcn)}
            dropped = 0
            for key in ("subnets", "lists", "nsgs", "vcns"):
                kept = [o for o in getattr(found, key) if _text(o.get("vcnid" if key != "vcns" else "id")) in ("", self.vcn)]
                dropped += len(getattr(found, key)) - len(kept)
                setattr(found, key, kept)
            if dropped:
                self.report.note(Severity.INFO, "OCI_OTHER_VCN", f"{dropped} subnets, security lists and NSGs of other VCNs were left out")

    def _subnets(self) -> None:
        for subnet in self.found.subnets:
            ident = _text(subnet.get("id"))
            blocks = [_text(subnet.get("cidrblock"))] if subnet.get("cidrblock") else []
            blocks += [_text(b) for b in _list(subnet.get("ipv6cidrblocks"))]
            if subnet.get("ipv6cidrblock") and _text(subnet.get("ipv6cidrblock")) not in blocks:
                blocks.append(_text(subnet["ipv6cidrblock"]))
            intervals: List[Interval] = []
            for text in blocks:
                interval = parse_literal(text)
                if interval is None or "/" not in text:
                    raise ParseError(f"subnet {ident}: '{text[:60]}' is not a CIDR block")
                intervals.append(interval)
            self.subnets[ident] = subnet
            self.subnet_blocks[ident] = normalize(intervals)

    def _holders(self) -> None:
        for sl in self.found.lists:
            ident = _text(sl.get("id"))
            holder = _Holder(f"sl:{ident}", ident, "security list", _text(sl.get("displayname")) or ident)
            for egress, key in ((False, "ingresssecurityrules"), (True, "egresssecurityrules")):
                for number, item in enumerate(_list(sl.get(key)), 1):
                    holder.elements.append(self._element(holder.key, egress, number, item))
            self.holders[holder.key] = holder
        for nsg in self.found.nsgs:
            ident = _text(nsg.get("id"))
            holder = _Holder(f"nsg:{ident}", ident, "NSG", _text(nsg.get("displayname")) or ident)
            counts = {False: 0, True: 0}
            for item in self.found.rules.get(ident, []):
                egress = _text(item.get("direction")).upper() == "EGRESS"
                counts[egress] += 1
                holder.elements.append(self._element(holder.key, egress, counts[egress], item))
            self.holders[holder.key] = holder

    @staticmethod
    def _element(holder: str, egress: bool, number: int, item: Any) -> _Element:
        if not isinstance(item, dict):
            return _Element(holder, egress, False, "", "cidr", "", {}, number, problem="a rule that is not an object")
        side = "destination" if egress else "source"
        value = _text(item.get(side))
        kind = {"CIDR_BLOCK": "cidr", "SERVICE_CIDR_BLOCK": "service", "NETWORK_SECURITY_GROUP": "nsg", "": ""}.get(
            _text(item.get(side + "type")).upper(), "?")
        problem = ""
        if kind == "":
            kind = "nsg" if value.startswith("ocid1.networksecuritygroup.") else "cidr"  # (a security list's default: CIDR_BLOCK)
        elif kind == "?":
            kind, problem = "cidr", f"{side} type '{_text(item.get(side + 'type'))[:40]}' is not known"
        direction = _text(item.get("direction")).upper()
        if direction and direction not in ("INGRESS", "EGRESS"):
            problem = problem or f"direction '{direction[:20]}' is not known"
        stateless = item.get("isstateless")
        if stateless not in (None, True, False):
            problem = problem or f"is-stateless '{str(stateless)[:20]}' cannot be read"
        options = {k: item.get(k) for k in ("tcpoptions", "udpoptions", "icmpoptions") if item.get(k) is not None}
        return _Element(holder, egress, stateless is True, _text(item.get("protocol")).strip().lower(), kind, value, options, number,
                        _text(item.get("description")), _text(item.get("id")), item.get("isvalid") is False, problem)  # fmt: skip

    def _membership(self) -> None:
        """The addresses of the VNICs, and the NSGs each is in."""
        found = self.found
        extra: Dict[str, List[str]] = {}
        for item in found.private_ips:
            if item.get("vnicid") and item.get("ipaddress") and _text(item.get("subnetid")) not in self.foreign:
                extra.setdefault(_text(item["vnicid"]), []).append(_text(item["ipaddress"]))
        seen: Set[str] = set()
        routed: List[str] = []
        zpr: List[str] = []
        vlans: List[str] = []
        for vnic in found.vnics:
            ident = _text(vnic.get("id"))
            seen.add(ident)
            subnet = _text(vnic.get("subnetid"))
            if subnet in self.foreign:
                continue  # (a VNIC of another VCN)
            if vnic.get("vlanid") and not subnet:
                vlans.append(ident)
                continue
            if self.vcn and self.subnets and subnet not in self.subnets and found.subnets:
                if not any(_text(s.get("id")) == subnet for s in found.subnets):
                    self.missing_subnets.add(subnet)
            nsgs = frozenset(_text(n) for n in _list(vnic.get("nsgids")) if n)
            if vnic.get("skipsourcedestcheck") is True:
                routed.append(_text(vnic.get("displayname")) or ident)
            if vnic.get("securityattributes"):
                zpr.append(_text(vnic.get("displayname")) or ident)
            addresses = [_text(vnic.get("privateip"))] + extra.get(ident, []) + [_text(a) for a in _list(vnic.get("ipv6addresses"))]
            if vnic.get("publicip") and vnic.get("privateip"):
                self._public(_text(vnic["privateip"]), _text(vnic["publicip"]), _text(vnic.get("displayname")) or ident)
            for text in transform.dedupe([a for a in addresses if a]):
                interval = parse_literal(text)
                if interval is None or interval[1] != interval[2]:
                    raise ParseError(f"VNIC {ident}: '{text[:60]}' is not an address")
                self.host_nsgs[interval] = self.host_nsgs.get(interval, frozenset()) | nsgs
                self.host_subnet[interval] = subnet
                for nsg in nsgs:
                    self.nsg_members.setdefault(nsg, []).append(interval)
                    if f"nsg:{nsg}" not in self.holders:
                        self.missing_nsgs.add(nsg)
        lost = sorted({vnic for vnic in extra if vnic not in seen})
        if lost and found.nsgs:
            self.report.note(Severity.REVIEW, "OCI_VNIC_MISSING",
                             "private IPs belong to VNICs whose answer of 'oci network vnic get' is not in the input: "
                             + ", ".join(lost[:8]) + (" ..." if len(lost) > 8 else "") + ". Which NSGs they are in is not known; "
                             "they are read with the security lists of their subnet only")  # fmt: skip
            for other in lost:
                for text in extra[other]:
                    interval = parse_literal(text)
                    if interval is not None and interval[1] == interval[2] and interval not in self.host_nsgs:
                        self.host_nsgs[interval] = frozenset()
                        self.host_subnet[interval] = next((_text(i.get("subnetid")) for i in found.private_ips
                                                           if _text(i.get("vnicid")) == other and i.get("subnetid")), "")  # fmt: skip
        if routed:
            self.report.note(Severity.REVIEW, "OCI_ROUTED_THROUGH",
                             "these VNICs forward traffic for others (skip source/destination check): " + ", ".join(routed[:8])
                             + (" ..." if len(routed) > 8 else "") + ". The rules of their lists and NSGs, and what the "
                             "appliance does, apply to that traffic too, and are not converted")  # fmt: skip
        if zpr:
            self.report.note(Severity.REVIEW, "OCI_ZPR",
                             "these VNICs have Zero Trust Packet Routing security attributes: " + ", ".join(zpr[:8])
                             + ". Traffic to them must satisfy the ZPR policies as well, which are not read; the converted "
                             "policy may allow more")  # fmt: skip
        if vlans:
            self.report.note(Severity.REVIEW, "OCI_VLAN",
                             "VNICs in VLANs (Oracle Cloud VMware Solution) were left out: their NSGs are those of the VLAN, "
                             "which are not read: " + ", ".join(vlans[:8]))  # fmt: skip

    def _public(self, private: str, public: str, vnic: str) -> None:
        inner, outer = parse_literal(private), parse_literal(public)
        if inner is not None and outer is not None and inner[1] == inner[2] and outer[1] == outer[2]:
            if (inner, outer, vnic) not in self.public:
                self.public.append((inner, outer, vnic))

    def _inside(self) -> None:
        """The addresses of the VCN: from its CIDR blocks, else its subnets, else the VNICs."""
        found: List[Interval] = []
        for vcn in self.found.vcns:
            blocks = [_text(b) for b in _list(vcn.get("cidrblocks"))]
            if not blocks and vcn.get("cidrblock"):
                blocks.append(_text(vcn["cidrblock"]))
            blocks += [_text(b) for b in _list(vcn.get("ipv6cidrblocks")) + _list(vcn.get("ipv6privatecidrblocks"))]
            blocks += [_text(b.get("ipv6cidrblock")) for b in _dicts(vcn.get("byoipv6cidrdetails"))]
            found += [i for i in map(parse_literal, blocks) if i is not None]
        if found:
            self.inside, self.inside_from = normalize(found), "its CIDR blocks"
            return
        for intervals in self.subnet_blocks.values():
            found += intervals
        found += list(self.host_subnet)
        if found:
            self.inside, self.inside_from = normalize(found), "its subnets" if self.subnet_blocks else "the addresses of its VNICs"

    def _profiles(self) -> None:
        """Each address of the VCN where a VNIC may be: the lists of its subnet and the NSGs of its VNIC."""
        with_nsgs: Dict[str, List[Interval]] = {}
        for host, nsgs in self.host_nsgs.items():
            subnet = self.host_subnet.get(host, "")
            if nsgs or subnet not in self.subnet_blocks:
                self.profiles.setdefault((subnet, nsgs), []).append(host)
            if nsgs:
                with_nsgs.setdefault(subnet, []).append(host)
            if subnet and subnet not in self.subnet_blocks:
                self.missing_subnets.add(subnet)
        for subnet, blocks in self.subnet_blocks.items():
            rest = subtract(blocks, normalize(with_nsgs.get(subnet, [])))
            if rest:
                self.profiles.setdefault((subnet, frozenset()), []).extend(rest)
        self.profiles = {key: normalize(value) for key, value in self.profiles.items()}

    def _holders_of(self, profile: Profile) -> List[_Holder]:
        subnet, nsgs = profile
        out: List[_Holder] = []
        for ident in _list(self.subnets.get(subnet, {}).get("securitylistids")):
            key = f"sl:{_text(ident)}"
            if key in self.holders:
                out.append(self.holders[key])
            else:
                self.missing_lists.add(_text(ident))
        for nsg in sorted(nsgs):
            if f"nsg:{nsg}" in self.holders:
                out.append(self.holders[f"nsg:{nsg}"])
        return out

    def _profile_label(self, profile: Profile) -> str:
        subnet, nsgs = profile
        names = [self.subnet_names.get(subnet, subnet or "no-subnet")]
        names += sorted(self.holders[f"nsg:{n}"].label if f"nsg:{n}" in self.holders else n for n in nsgs)
        return "+".join(names)

    # -- objects ------------------------------------------------------------------

    def _groups(self) -> None:
        for ident, subnet in self.subnets.items():
            name = self._object_name(_text(subnet.get("displayname")) or ident)
            self.subnet_names[ident] = name
            self.p.address_groups[name] = AddressGroup(name, [interval_text(i) for i in self.subnet_blocks[ident]],
                                                       f"subnet {ident}")  # fmt: skip
        for holder in self.holders.values():
            holder.name = self._object_name(holder.label)
            if holder.kind == "security list":
                users = [self.subnet_names[s] for s, node in self.subnets.items()
                         if holder.ident in [_text(x) for x in _list(node.get("securitylistids"))]]  # fmt: skip
                node = AddressGroup(holder.name, users, f"security list {holder.ident}: the subnets it is associated with")
            else:
                node = AddressGroup(holder.name, description=f"network security group {holder.ident}")
                if self.known:
                    node.members = [interval_text(i) for i in normalize(self.nsg_members.get(holder.ident, []))]
                else:
                    node.dynamic_filter = "oci:" + json.dumps({"nsgId": holder.ident, "vcnId": self.vcn}, sort_keys=True)
            self.p.address_groups[holder.name] = node
        if self.inside is not None:
            label = next((_text(v.get("displayname")) for v in self.found.vcns if _text(v.get("displayname"))), "") or self.vcn or "vcn"
            self.inside_group = self._object_name(label)
            self.p.address_groups[self.inside_group] = AddressGroup(
                self.inside_group, [interval_text(i) for i in self.inside], f"the addresses of VCN {self.vcn or '?'} ({self.inside_from})",
                builtin="oci",  # (an OCI target takes it for the inside of the VCN)
            )

    def _members(self, holder: _Holder) -> Optional[List[Interval]]:
        """The addresses a list or an NSG applies to; None when not known."""
        if holder.kind == "security list":
            return normalize([i for s, node in self.subnets.items() if holder.ident in [_text(x) for x in _list(node.get("securitylistids"))]
                              for i in self.subnet_blocks[s]])  # fmt: skip
        return normalize(self.nsg_members.get(holder.ident, [])) if self.known else None

    def _nsg_ref(self, ident: str) -> str:
        if f"nsg:{ident}" in self.holders:
            return self.holders[f"nsg:{ident}"].name
        if ident in self.refs:
            return self.refs[ident]
        name = self._object_name(ident or "unnamed-nsg")
        self.refs[ident] = name
        node = AddressGroup(name, description=f"network security group {ident}, not in the input")
        if self.known:
            # An NSG names NSGs of its own VCN only, and the VNICs of the VCN are in the input: its members are those that
            # are in it (none, maybe).
            node.members = [interval_text(i) for i in normalize(self.nsg_members.get(ident, []))]
            if not node.members:
                self.remote.add(ident)
        else:
            node.dynamic_filter = "oci:" + json.dumps({"nsgId": ident, "vcnId": self.vcn}, sort_keys=True)
            self.remote.add(ident)
        self.p.address_groups[name] = node
        return name

    def _label_ref(self, label: str) -> str:
        if label in self.refs:
            return self.refs[label]
        name = self._object_name(label or "unnamed-service")
        self.refs[label] = name
        node = AddressGroup(name, description=f"service CIDR label {label}")
        cidrs = self._label_ranges(label)
        if cidrs is None:
            node.unsupported = (f"the addresses of the Oracle services of {label} are not in the input (add Oracle's "
                                "public_ip_ranges.json and the answer of 'oci iam region list')")  # fmt: skip
            self.labels.add(label)
        else:
            node.members = cidrs
            node.description += f" (Oracle's public_ip_ranges.json of {self.found.ranges_stamp or '?'})"
        self.p.address_groups[name] = node
        return name

    def _label_ranges(self, label: str) -> Optional[List[str]]:
        """The published ranges of a service CIDR label: tag OSN for all services, OBJECT_STORAGE for Object Storage."""
        found = re.fullmatch(r"all-([a-z0-9]+)-services-in-oracle-services-network", label.lower())
        tag = "OSN"
        if found is None:
            found, tag = re.fullmatch(r"oci-([a-z0-9]+)-objectstorage", label.lower()), "OBJECT_STORAGE"
        if found is None or not self.found.ranges:
            return None
        region = self.found.regions.get(found.group(1), "")
        if region not in self.found.ranges:
            return None
        cidrs = [c for c, tags in self.found.ranges[region] if tag in tags]
        intervals = [parse_literal(c) for c in cidrs]
        if not cidrs or any(i is None for i in intervals):
            return None
        return [interval_text(i) for i in normalize([i for i in intervals if i is not None])]

    def _member(self, element: _Element) -> str:
        if element.kind == "nsg":
            return self._nsg_ref(element.value)
        if element.kind == "service":
            return self._label_ref(element.value)
        interval = parse_literal(element.value)
        return interval_text(interval) if interval is not None and "/" in element.value else ""

    def _intervals(self, element: _Element) -> Optional[List[Interval]]:
        """The addresses an element stands for; None when they are not known here."""
        if element.kind == "cidr":
            interval = parse_literal(element.value)
            return [interval] if interval is not None and "/" in element.value else None
        return transform.address_intervals(self.p, self._member(element))

    def _service(self, element: _Element) -> _Service:
        key = json.dumps([element.protocol, element.options], sort_keys=True, default=str)
        if key in self.services:
            return self.services[key]
        found = self._read_service(element.protocol, element.options)
        if found.name != ANY and not found.problem:
            same = next((name for name, service in self.p.services.items() if service.entries == found.entries), "")
            found.name = same or self._unique(found.name, self.taken_services)
            if not same:
                self.p.services[found.name] = Service(found.name, list(found.entries))
        self.services[key] = found
        return found

    @staticmethod
    def _read_service(protocol: str, options: Dict[str, Any]) -> _Service:
        def ports(node: Any, side: str) -> Optional[Tuple[int, int]]:
            if node is None:
                return (0, 65535)
            if not isinstance(node, dict) or isinstance(node.get("min"), bool) or isinstance(node.get("max"), bool):
                return None
            try:
                low, high = int(str(node.get("min"))), int(str(node.get("max")))
            except (TypeError, ValueError, OverflowError):
                return None
            return (low, high) if 0 <= low <= high <= 65535 else None

        def text(pair: Tuple[int, int]) -> str:
            return "" if pair == (0, 65535) else (str(pair[0]) if pair[0] == pair[1] else f"{pair[0]}-{pair[1]}")

        if protocol == "all":
            if options:
                return _Service("", [], "options with protocol 'all'")
            return _Service(ANY, [])
        if protocol in ("6", "17"):
            own, other = ("tcpoptions", "udpoptions") if protocol == "6" else ("udpoptions", "tcpoptions")
            if other in options or "icmpoptions" in options:
                return _Service("", [], f"options of another protocol with protocol {protocol}")
            node = options.get(own) or {}
            if not isinstance(node, dict):
                return _Service("", [], "the port options cannot be read")
            dst, src = ports(node.get("destinationportrange"), "destination"), ports(node.get("sourceportrange"), "source")
            if dst is None or src is None:
                return _Service("", [], "a port range cannot be read")
            label = "tcp" if protocol == "6" else "udp"
            name = f"{label}-{text(dst) or 'all'}" + (f"-from-{text(src)}" if text(src) else "")
            return _Service(name, [ServiceEntry(Protocol(label), dst_ports=text(dst), src_ports=text(src))])
        if protocol in ("1", "58"):
            kind, label = (Protocol.ICMP, "icmp") if protocol == "1" else (Protocol.ICMP6, "icmpv6")
            if "tcpoptions" in options or "udpoptions" in options:
                return _Service("", [], f"port options with protocol {protocol}")
            node = options.get("icmpoptions")
            if node is None:
                return _Service(f"{label}-all", [ServiceEntry(kind)])
            if not isinstance(node, dict):
                return _Service("", [], "the ICMP options cannot be read")
            values: List[Optional[int]] = []
            for key in ("type", "code"):
                value = node.get(key)
                if value is None:
                    values.append(None)
                    continue
                if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit() or not 0 <= int(value) <= 255:
                    return _Service("", [], f"ICMP {key} '{str(value)[:20]}' cannot be read")
                values.append(int(value))
            kind_value, code = values
            if kind_value is None:
                return _Service("", [], "ICMP options without a type (the type is required)")
            if code is None:
                return _Service(f"{label}-{kind_value}", [ServiceEntry(kind, icmp_type=kind_value)])
            return _Service(f"{label}-{kind_value}-{code}", [ServiceEntry(kind, icmp_type=kind_value, icmp_code=code)])
        if not protocol.isascii() or not protocol.isdigit() or not 0 <= int(protocol) <= 255:
            return _Service("", [], f"protocol '{protocol[:20]}' cannot be read")
        if options:
            return _Service("", [], f"options with protocol {protocol}, which has none")
        if protocol == "132":
            return _Service("sctp-all", [ServiceEntry(Protocol.SCTP)])
        return _Service(f"ip-{int(protocol)}", [ServiceEntry(Protocol.IP, ip_protocol=int(protocol))])

    def _service_set(self, element: _Element) -> Optional[regions.Services]:
        service = self._service(element)
        if service.problem:
            return None
        return regions.ALL_SERVICES if service.name == ANY else regions.service_set(service.entries)

    def _problems(self, element: _Element) -> List[str]:
        service = self._service(element)
        problems = [p for p in (element.problem, service.problem) if p]
        if element.kind == "cidr":
            interval = parse_literal(element.value)
            if interval is None or "/" not in element.value:
                problems.append(f"'{element.value[:60]}' is not a CIDR block" if element.value else "a rule without a source or destination")
            elif service.entries:
                kind = service.entries[0].protocol
                if (kind == Protocol.ICMP and interval[0] == 6) or (kind == Protocol.ICMP6 and interval[0] == 4):
                    problems.append(f"{'ICMP' if kind == Protocol.ICMP else 'ICMPv6'} with an address of the other IP version "
                                    f"({element.value}), which matches no packet")  # fmt: skip
        elif not element.value:
            problems.append("a rule without a source or destination")
        return problems

    def _usable(self, element: _Element) -> bool:
        return not element.invalid and not self._problems(element)

    def _boxes(self, element: _Element, members: List[Interval]) -> Optional[List[regions.Box]]:
        """What an element allows at the given members, as boxes; None when its addresses or services are not known."""
        if not self._usable(element):
            return []
        peers = self._intervals(element)
        services = self._service_set(element)
        if peers is None or services is None:
            return None
        out: List[regions.Box] = []
        for version in (4, 6):
            own, other = regions.addresses(members, version), regions.addresses(peers, version)
            if own and other:
                out.append((version, own, other, services) if element.egress else (version, other, own, services))
        return out

    # -- rules --------------------------------------------------------------------

    def _rule(self, base: str, element: Optional[_Element], **values: Any) -> Rule:
        rule = Rule(self._unique(base, self.rule_names), **values)
        rule.origin = rule.name
        rule.log_end = False
        if element is not None:
            rule.description = element.description
            holder = self.holders[element.holder]
            rule.source_ids["oci.security_list_id" if holder.kind == "security list" else "oci.nsg_id"] = holder.ident
            if element.rule_id:
                rule.source_ids["oci.rule_id"] = element.rule_id
            else:
                rule.source_ids["oci.rule"] = f"{'egress' if element.egress else 'ingress'} {element.number}"
        self.p.rules.append(rule)
        return rule

    def _box_rule(self, base: str, box: regions.Box, action: Action, description: str) -> bool:
        """A rule for what a box holds; False when its services cannot be written as entries."""
        version, src, dst, svc = box
        found = regions.entries_of(svc, version)
        if found is None:
            return False
        entries, negated = found
        if not entries and not negated:
            return True  # (matches nothing: not written)
        names = [ANY]
        if entries:
            names = [self._entries_service(entries)]
        rule = self._rule(base, None, sources=[interval_text(i) for i in src], destinations=[interval_text(i) for i in dst],
                          services=names, action=action)  # fmt: skip
        rule.negate_service = bool(entries) and negated
        rule.description = description
        return True

    def _entries_service(self, entries: List[ServiceEntry]) -> str:
        for name, service in self.p.services.items():
            if service.entries == entries:
                return name
        name = self._unique("svc-" + "-".join(e.protocol.value + (e.dst_ports or str(e.icmp_type if e.icmp_type is not None else ""))
                                              for e in entries[:3]), self.taken_services)  # fmt: skip
        self.p.services[name] = Service(name, entries)
        return name

    def _rules(self, egress: bool) -> None:
        for holder in self.holders.values():
            members = self._members(holder)
            if members is not None and not members:
                if not egress and holder.elements:
                    self.unused.append(holder.name)
                continue
            versions = {m[0] for m in members} if members is not None else {4, 6}
            for element in holder.elements:
                if element.egress != egress:
                    continue
                if element.invalid:
                    self.report.note(Severity.INFO, "OCI_RULE_INVALID",
                                     f"{'egress' if egress else 'ingress'} rule {element.number} of {holder.kind} {holder.name} names "
                                     f"NSG {element.value}, which was deleted (is-valid false): OCI ignores the rule, and so does the "
                                     "converted policy")  # fmt: skip
                    continue
                if element.kind == "cidr":
                    interval = parse_literal(element.value)
                    if interval is not None and "/" in element.value and interval[0] not in versions:
                        continue  # an address of an IP version no member has: matches nothing
                if element.kind == "nsg" and self.known and not self.nsg_members.get(element.value):
                    self._member(element)
                    continue  # an NSG no VNIC is in: nothing
                self._element_rule(holder, element, members)

    def _element_rule(self, holder: _Holder, element: _Element, members: Optional[List[Interval]]) -> None:
        service = self._service(element)
        member = self._member(element)
        services = [service.name] if service.name and not service.problem else [ANY]
        word = "out" if element.egress else "in"
        if not element.egress:
            rule = self._rule(f"{holder.name}-{word}-{element.number}", element, sources=[member or ANY], destinations=[holder.name],
                              services=services)  # fmt: skip
        else:
            destinations = [member or ANY]
            if member and self.inside is not None:
                intervals = self._intervals(element)
                # Inside the VCN the ingress rules of the destination decide too (the pairs, above).
                if intervals is not None and overlaps(intervals, self.inside):
                    rest = subtract(intervals, self.inside)
                    if not rest:
                        return
                    destinations = [interval_text(i) for i in rest]
            rule = self._rule(f"{holder.name}-{word}-{element.number}", element, sources=[holder.name], destinations=destinations,
                              services=services)  # fmt: skip
            if member and destinations != [member]:
                rule.description = (rule.description + " | " if rule.description else "") + f"{member} without the addresses of the VCN"
        rule.unsupported += self._problems(element)
        if element.kind == "service" and element.value not in self.labels:
            self.report.add("rule", rule.origin, Severity.APPROX, "OCI_SERVICE_RANGES",
                            f"service CIDR label {element.value} is read as the ranges Oracle publishes for it; on OCI the rule "
                            "matches that traffic only through a service gateway, and the published ranges change")  # fmt: skip
        if element.stateless:
            rule.description = (rule.description + " | " if rule.description else "") + "stateless"
        profiles = [p for p in self.profiles if holder in self._holders_of(p)]
        self.element_rules.append((element, rule, profiles))

    # -- stateless rules ------------------------------------------------------------

    def _stateless(self) -> None:
        """Block, first, what a VNIC lets through statelessly and whose replies it does not let through."""
        if not any(e.stateless for h in self.holders.values() for e in h.elements):
            return
        unknown: List[str] = []
        failed: List[str] = []
        for profile in sorted(self.profiles, key=self._profile_label):
            members = self.profiles[profile]
            holders = self._holders_of(profile)
            if not any(e.stateless for h in holders for e in h.elements):
                continue
            boxes: Dict[Tuple[bool, bool], List[regions.Box]] = {(e, s): [] for e in (False, True) for s in (False, True)}
            incomplete = False
            for holder in holders:
                for element in holder.elements:
                    found = self._boxes(element, members)
                    if found is None:
                        incomplete = True
                        continue
                    boxes[(element.egress, False)] += found
                    if element.stateless:
                        boxes[(element.egress, True)] += found
            label = self._profile_label(profile)
            if incomplete:
                unknown.append(label)
            blocked: List[regions.Box] = []
            for egress in (False, True):
                stateless = boxes[(egress, True)]
                if not stateless:
                    continue
                replies = [m for m in (_mirror(b) for b in boxes[(not egress, False)]) if m is not None] + _no_reply()
                left = regions.minus_all(stateless, replies, limit=2000)
                if left is None:
                    failed.append(label)
                    continue
                for box in left:
                    if _meets_nothing(box):
                        continue
                    blocked.append(box)
                    word = "out" if egress else "in"
                    if not self._box_rule(f"{label}-stateless-{word}", box, Action.DROP,
                                          f"let {word} by a stateless rule of {label}, and the replies are not let through"):
                        failed.append(label)
            self.unreplied[profile] = blocked
        if any(self.unreplied.values()):
            self.report.note(Severity.INFO, "OCI_STATELESS_REPLY",
                             "stateless rules let traffic through without tracking the connection, and some of their replies are "
                             "not allowed in the other direction (a stateless rule decides over a stateful one that matches the "
                             "same traffic). Those connections fail on OCI and are blocked first in the converted policy "
                             "('...-stateless-in', '...-stateless-out')")  # fmt: skip
        if unknown:
            self.report.note(Severity.REVIEW, "OCI_STATELESS_UNKNOWN",
                             "for these addresses some rules name addresses that are not known (an NSG without its VNICs, a "
                             "service CIDR label without Oracle's ranges): whether the replies of their stateless rules are let "
                             "through is worked out without them, and the converted policy may block connections OCI allows: "
                             + ", ".join(unknown))  # fmt: skip
        if failed:
            self.report.note(Severity.REVIEW, "OCI_STATELESS_NOT_WORKED_OUT",
                             "for these addresses what their stateless rules let through without its replies is too complex to "
                             "work out; the converted policy allows it, which may be more than OCI does: " + ", ".join(sorted(set(failed))))  # fmt: skip

    # -- what members may reach inside the VCN ----------------------------------------

    def _pairs(self) -> None:
        """Rules for the addresses whose egress rules do not allow everything inside the VCN."""
        hosts = normalize([i for v in self.profiles.values() for i in v])
        written, capped = 0, []
        for profile in sorted(self.profiles, key=self._profile_label):
            members = self.profiles[profile]
            versions = {m[0] for m in members}
            if self._covers(profile, [h for h in hosts if h[0] in versions]):
                continue
            label = self._profile_label(profile)
            count, complete = self._pair_rules(profile, label, members)
            written += count
            if not complete:
                capped.append(label)
            holder = self._unique(f"{label} members", self.taken)
            self.p.address_groups[holder] = AddressGroup(holder, [interval_text(i) for i in members],
                                                         f"the addresses whose lists and NSGs are exactly {label}")  # fmt: skip
            rule = self._rule(f"{label}-egress-rest", None, sources=[holder], destinations=[self.inside_group or ANY], action=Action.DROP)
            rule.description = f"what the egress rules of {label} do not allow inside the VCN"
        if written or capped:
            self.report.note(Severity.INFO, "OCI_EGRESS_PAIRS",
                             "inside the VCN a connection needs an egress rule of the sender's lists and NSGs and an ingress rule "
                             f"of the receiver's. Where the egress rules do not allow everything, {written} rule"
                             f"{' allows' if written == 1 else 's allow'} what both allow, and a rule after them blocks the rest "
                             "of what those addresses send inside the VCN")  # fmt: skip
        if capped:
            self.report.note(Severity.REVIEW, "OCI_EGRESS_PAIRS_LEFT_OUT",
                             "for these addresses not every connection inside the VCN could be worked out (too many, an NSG "
                             "without its rules, or addresses that are not known); the converted policy blocks what was left out: "
                             + ", ".join(capped))  # fmt: skip

    def _covers(self, profile: Profile, hosts: List[Interval]) -> bool:
        if (profile[1] & self.missing_nsgs) or any(n not in self.found.rules for n in profile[1] if f"nsg:{n}" in self.holders):
            return False
        if profile[0] in self.missing_subnets:
            return False
        found: List[Interval] = []
        for holder in self._holders_of(profile):
            for element in holder.elements:
                if element.egress and self._usable(element) and self._service(element).name == ANY:
                    found += self._intervals(element) or []
        return within(hosts, found)

    def _pair_rules(self, profile: Profile, label: str, members: List[Interval]) -> Tuple[int, bool]:
        complete = not (profile[1] & self.missing_nsgs) and profile[0] not in self.missing_subnets
        count = 0
        outbound = [e for h in self._holders_of(profile) for e in h.elements if e.egress]
        for egress in outbound:
            if not self._usable(egress) or egress.kind == "service":
                continue  # (an Oracle service is outside the VCN: no pair)
            reach = self._intervals(egress)
            out_service = self._service(egress)
            out_set = self._service_set(egress)
            if reach is None or out_set is None:
                complete = False
                continue
            for holder in self.holders.values():
                targets = self._members(holder)
                if not targets:
                    if targets is None:
                        complete = False
                    continue
                destinations = intersect(targets, reach)
                if not destinations:
                    continue
                for ingress in (e for e in holder.elements if not e.egress):
                    if not self._usable(ingress) or ingress.kind == "service":
                        continue
                    sources = self._intervals(ingress)
                    in_service = self._service(ingress)
                    in_set = self._service_set(ingress)
                    if sources is None or in_set is None:
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
                        rule = self._rule(f"{label}-to-{holder.name}", None, sources=[interval_text(i) for i in src],
                                          destinations=[interval_text(i) for i in dst], services=names)  # fmt: skip
                        rule.negate_service = negated
                        source_holder = self.holders[egress.holder]
                        rule.description = (f"egress rule {egress.number} of {source_holder.name} and ingress rule {ingress.number} of "
                                            f"{holder.name}")  # fmt: skip
                        rule.source_ids["oci.security_list_id" if source_holder.kind == "security list" else "oci.nsg_id"] = source_holder.ident
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
        return [self._entries_service(entries)], negated

    # -- NAT and notes --------------------------------------------------------------

    def _nat(self) -> None:
        for private, public, vnic in self.public:
            name = self._unique(f"public-{interval_text(public)}", {n.name.lower() for n in self.p.nat_rules})
            nat = NatRule(name, sources=[interval_text(private)], description=f"public IP address of VNIC {vnic}")
            nat.source_translation = SourceNat(SnatKind.STATIC, [interval_text(public)], bidirectional=True)
            nat.origin = name
            self.p.nat_rules.append(nat)
        if self.public:
            self.p.lookup_after_dnat = True
            transform.rewrite_destinations(self.p, self.report, to_post_nat=False, report_deny=False)
            self.report.retract("rule", {"NAT_DESTINATION_REWRITTEN", "NAT_ADDRESS_EXPOSED"})
            self.report.note(Severity.INFO, "OCI_PUBLIC_ADDRESSES",
                             "the public IP addresses of the VNICs are static NAT of their primary private addresses: the internet "
                             "gateway translates what comes from outside, and the rules see the private address. The rules that "
                             "name a private address name its public address as well, as the model has rules before NAT")  # fmt: skip
            self.report.note(Severity.REVIEW, "OCI_HAIRPIN",
                             "connections from inside the VCN to its own public addresses are not converted as OCI decides them: "
                             "they go through the internet gateway, and the rules see public addresses at both ends (a rule that "
                             "names an NSG does not match them). The converted policy treats them as connections to the private "
                             "address, which may allow more")  # fmt: skip

    def _notes(self) -> None:
        found = self.found
        self.report.note(Severity.INFO, "OCI_UNFILTERED",
                         "security rules are never enforced for traffic to or from 169.254.0.0/16 (instance metadata, iSCSI boot "
                         "volumes, the VCN's DNS and NTP); neither does the converted policy say anything about it")  # fmt: skip
        if found.incomplete:
            self.report.note(Severity.REVIEW, "OCI_INCOMPLETE_EXPORT",
                             "answers say there is another page (opc-next-page): " + ", ".join(transform.dedupe(found.incomplete))[:300]
                             + ". List with --all; lists, NSGs or VNICs left out make the converted policy differ")  # fmt: skip
        if found.orphans:
            self.report.note(Severity.REVIEW, "OCI_NSG_RULES_UNWRAPPED",
                             f"{found.orphans} NSG security rules are not wrapped with the NSG they belong to (an NSG rule does not "
                             "name its NSG); they were left out. List them with --query \"{nsgId: '<ocid>', data: data}\"")  # fmt: skip
        if found.nsgs and not found.vnics:
            self.report.note(Severity.REVIEW, "OCI_NO_VNICS",
                             "the VNICs ('oci network vnic get') are not in the input: which addresses an NSG stands for is not "
                             "known, its rules cannot be written for any target, and what NSGs allow the addresses of a subnet is "
                             "left out where the converted policy works out connections inside the VCN. Add those answers")  # fmt: skip
        if found.lists and not found.subnets:
            self.report.note(Severity.REVIEW, "OCI_SUBNETS_MISSING",
                             "the subnets ('oci network subnet list') are not in the input: where the security lists apply is not "
                             "known, and their rules are not converted. Add that answer")  # fmt: skip
        if self.missing_subnets:
            self.report.note(Severity.REVIEW, "OCI_SUBNET_MISSING",
                             "VNICs are in subnets that are not in the input: " + ", ".join(sorted(self.missing_subnets)[:8])
                             + ". The security lists of those subnets are missing from the converted policy")  # fmt: skip
        if self.missing_lists:
            self.report.note(Severity.REVIEW, "OCI_LIST_MISSING",
                             "subnets are associated with security lists that are not in the input: " + ", ".join(sorted(self.missing_lists)[:8])
                             + ". What those lists allow is missing from the converted policy")  # fmt: skip
        if self.missing_nsgs:
            self.report.note(Severity.REVIEW, "OCI_NSG_MISSING",
                             "VNICs are in NSGs that are not in the input: " + ", ".join(sorted(self.missing_nsgs)[:8])
                             + ". What those NSGs allow is missing from the converted policy")  # fmt: skip
        without = [h.name for h in self.holders.values() if h.kind == "NSG" and h.ident not in found.rules]
        if without:
            self.report.note(Severity.REVIEW, "OCI_NSG_RULES_MISSING",
                             "the rules of these NSGs ('oci network nsg rules list') are not in the input, and they are read as "
                             "allowing nothing (the CLI may print nothing for an NSG without rules; if they have rules, add them): "
                             + ", ".join(without))  # fmt: skip
        if self.remote:
            self.report.note(Severity.REVIEW, "OCI_REMOTE_NSG",
                             "rules name NSGs that are not in the input: " + ", ".join(sorted(self.remote)) + (
                                 ". No VNIC of the input is in them, so those rules allow nothing (an NSG names NSGs of its own "
                                 "VCN; if VNICs are missing from the input, add them)" if self.known else
                                 ". Their VNICs are not known; those rules are not converted"))  # fmt: skip
        if self.labels:
            self.report.note(Severity.REVIEW, "OCI_SERVICE_LABEL",
                             "rules name service CIDR labels whose addresses are not in the input: " + ", ".join(sorted(self.labels))
                             + ". Those rules are not converted; add Oracle's public_ip_ranges.json and 'oci iam region list'")  # fmt: skip
        if self.unused:
            self.report.note(Severity.INFO, "OCI_UNUSED",
                             "these security lists are associated with no subnet, or no VNIC is in these NSGs, so their rules "
                             "allow nothing and were left out: " + ", ".join(self.unused))  # fmt: skip
        defaults = {_text(v.get("defaultsecuritylistid")) for v in found.vcns if v.get("defaultsecuritylistid")}
        using = [self.subnet_names[s] for s, node in self.subnets.items() if defaults & {_text(x) for x in _list(node.get("securitylistids"))}]
        if using:
            self.report.note(Severity.INFO, "OCI_DEFAULT_SECURITY_LIST",
                             "these subnets use the default security list of the VCN, whose rules (as created: SSH from anywhere, "
                             "ICMP type 3, every egress) are converted as they are now: " + ", ".join(using))  # fmt: skip
        if any(self._service(e).entries and self._service(e).entries[0].protocol == Protocol.UDP
               and (self._service(e).entries[0].dst_ports or self._service(e).entries[0].src_ports)
               for h in self.holders.values() for e in h.elements if not self._service(e).problem):  # fmt: skip
            self.report.note(Severity.INFO, "OCI_UDP_FRAGMENTS",
                             "rules allow UDP to or from certain ports: OCI drops the fragments after the first of a fragmented "
                             "UDP packet that such a rule allows (they carry no ports). The model has no fragments")  # fmt: skip
        if found.gone:
            self.report.note(Severity.INFO, "OCI_TERMINATED", f"{len(found.gone)} objects that are terminated or being terminated were left out")
        affected: Set[str] = set()
        for element, rule, profiles in self.element_rules:
            for profile in profiles:
                for box in self.unreplied.get(profile, []):
                    mine = self._boxes(element, self.profiles[profile])
                    if mine and any(regions.box_and(box, b) is not None for b in mine) and rule.origin not in affected:
                        affected.add(rule.origin)
                        self.report.add("rule", rule.origin, Severity.INFO, "OCI_STATELESS_REPLY",
                                        "part of what the rule allows is let through statelessly, and the replies are not let "
                                        "through in the other direction: those connections are blocked, first, as on OCI")  # fmt: skip


def _mirror(box: regions.Box) -> Optional[regions.Box]:
    """The connections whose replies are in ``box``: sources and destinations exchanged, ports too, an ICMP request for
    its reply (which has code 0). None when there are none."""
    version, src, dst, svc = box
    numbers = set(svc.protocols) | ({6, 17, 132, 1, 58} if svc.rest else set())
    out: Dict[int, List[Tuple[int, int, int, int]]] = {}
    for number in numbers:
        rects = svc.of(number)
        if number in (6, 17, 132):
            out[number] = [(r[2], r[3], r[0], r[1]) for r in rects]
        elif number in (1, 58):
            out[number] = [(request, request, 0, 65535) for rect in rects for request, reply in _REPLY_TYPE[number].items()
                           if rect[0] <= reply <= rect[1] and rect[2] <= 0 <= rect[3]]  # fmt: skip
        else:
            out[number] = list(rects)
    mirrored = regions.Services(out, svc.rest)
    if mirrored.empty():
        return None
    return (version, list(dst), list(src), mirrored)


def _no_reply() -> List[regions.Box]:
    """ICMP messages that are no request: they have no reply to let through."""
    out: List[regions.Box] = []
    for version in (4, 6):
        rects: Dict[int, List[Tuple[int, int, int, int]]] = {}
        for number, requests in _REPLY_TYPE.items():
            low, found = 0, []
            for request in sorted(requests):
                if low < request:
                    found.append((low, request - 1, 0, 65535))
                low = request + 1
            found.append((low, 65535, 0, 65535))
            rects[number] = found
        out.append((version, [regions.full(version)], [regions.full(version)], regions.Services(rects, False)))
    return out


def _meets_nothing(box: regions.Box) -> bool:
    """Whether a box holds no connection: no address, or only the ICMP of the other IP version."""
    if regions.empty(box):
        return True
    foreign = 58 if box[0] == 4 else 1
    svc = box[3]
    return not svc.rest and all(number == foreign or not rects for number, rects in svc.protocols.items())


def _same(a: regions.Services, b: regions.Services) -> bool:
    return a.minus(b).empty() and b.minus(a).empty()
