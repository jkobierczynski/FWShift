# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco Secure Firewall: the JSON of a Management Center and of a Device Manager, read and written.

Nothing here has been near a device. What is tested is that both directions agree with a reader
that is not fwshift's own (helpers.CiscoConfig), with a made-up device that decides about packets
the way the documentation says one does, and with a made-up Management Center that the loader
script is run against.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import pytest
from helpers import DATA, CiscoConfig
from test_iptables import ZONES, Packet, _in, model_verdict, random_model
from test_sophos import model_expects, model_translation, packets, random_nat_model

from fwshift import cli, transform
from fwshift.errors import ParseError
from fwshift.model import ANY, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, RuleScope
from fwshift.model import Service, ServiceEntry, ServiceGroup, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import cisco as parse_cisco
from fwshift.report import Report

TARGETS = ["fmc", "fdm"]


def codes(report: Report, kind: str, name: str) -> List[str]:
    return [finding.code for finding in report.item(kind, name).findings]


def notes(report: Report) -> List[str]:
    return [note.code for note in report.notes]


def convert(policy: Policy, target: str = "fmc", options: Optional[Options] = None, **kwargs: Any) -> Tuple[CiscoConfig, Report, str]:
    report = Report()
    text = cli.convert(policy, target, report, options)
    return CiscoConfig(text, **kwargs), report, text


def lost_rules(report: Report) -> List[str]:
    """Rules that are not in force on the target: written disabled, or left out."""
    return [item.name for item in report.items.values() if item.kind == "rule" and (item.disabled or item.skipped)]


# -- model -> manager: the output decides like the model --------------------------------------


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("seed", range(50))
def test_emitted_rules_decide_like_the_model(target: str, seed: int) -> None:
    """Lists, negations, rule types, source ports, both IP versions: the verdict of the model."""
    rng = random.Random(seed)
    model = random_model(rng)
    model.zones = {zone: Zone(zone) for zone in ZONES}
    if seed % 3 == 1:
        model.zones[ZONES[0]].intrazone_allow = True
    for rule in model.rules:
        if rng.random() < 0.3:
            rule.negate_source = rule.sources != [ANY]
            rule.negate_destination = rule.destinations != [ANY]
        if rng.random() < 0.15:
            rule.scope = rng.choice([RuleScope.INTRAZONE, RuleScope.INTERZONE])  # also with zone "any"
    config, report, text = convert(model, target, zones=tuple(ZONES))
    lost = lost_rules(report)
    for name in lost:
        rule = next(rule for rule in model.rules if rule.name == name)
        found = set(codes(report, "rule", name))
        # Only a rule type with zone "any", a negated service and (Device Manager) a rule that is off have no way to be written.
        assert found & {"RULE_TYPE", "NEGATION", "NO_MATCH", "RULE_TYPE_EMPTY"} or (target == "fdm" and not rule.enabled), (seed, name, found)
    expected = Policy(vendor="panos", zones=model.zones, addresses=model.addresses, address_groups=model.address_groups,
                      services=model.services, service_groups=model.service_groups,
                      rules=[rule for rule in model.rules if rule.name not in lost
                             or set(codes(report, "rule", rule.name)) & {"NO_MATCH", "RULE_TYPE_EMPTY"}])  # fmt: skip
    allowed = 0
    for pkt in packets(rng, 500, ZONES + ["eth8"]):
        allowed += config.allows(pkt)
        assert config.allows(pkt) == model_expects(expected, pkt), (seed, pkt, config.deciding(pkt))
    ALLOWED[target] = ALLOWED.get(target, 0) + allowed
    LOST[target] = LOST.get(target, 0) + len(lost)


ALLOWED: Dict[str, int] = {}
LOST: Dict[str, int] = {}


def test_the_random_policies_let_traffic_through_and_lose_few_rules() -> None:
    """The comparison above is of policies that allow a good part of the packets, and of rules that are written."""
    assert ALLOWED and all(count > 2000 for count in ALLOWED.values()), ALLOWED
    assert LOST["fmc"] < 90 and LOST["fdm"] < 130, LOST  # of some 400 rules: rule types with zone "any", negated services, rules that are off


def _span(intervals: Sequence[Tuple[int, int, int]]) -> str:
    version, first, last = intervals[0][0], min(i[1] for i in intervals), max(i[2] for i in intervals)
    make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return str(make(first)) if first == last else f"{make(first)}-{make(last)}"


def file_translation(config: CiscoConfig, pkt: Packet) -> Tuple[str, str, str, str]:
    """(model rule, translated source, translated destination, translated port) of the NAT rule that applies."""
    rule = config.translating(pkt)
    if rule is None:
        return "", "Original", "Original", "Original"
    source = destination = port = "Original"
    if rule["to_interface"]:
        source = "MASQ"
    elif rule["pool"] is not None:
        source = _span(config.span_of(rule["pool"]))
    elif rule["tsrc"] is not None and (not rule["static"] or rule["tsrc"] != rule["osrc"]):
        source = _span(config.span_of(rule["tsrc"]))
    if rule["tdst"] is not None and rule["tdst"] != rule["odst"]:
        destination = _span(config.span_of(rule["tdst"]))
    if rule["tdp"] is not None and rule["tdp"] != rule["odp"]:
        port = str(config.ports[rule["tdp"]]["low"])
    return rule["description"].split()[0], source, destination, port


def cisco_nat_model(rng: random.Random) -> Policy:
    """NAT rules of the shapes a manual NAT rule has, and a few that it does not have."""
    p = random_model(rng)
    p.rules = []
    p.services["one"] = Service("one", [ServiceEntry(Protocol.TCP, "8080")])
    p.services["both"] = Service("both", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")])
    four = ["net0", "net1", "net2", "net3", "net4", "half", "span", "host", "10.0.3.0/24", "10.0.0.34"]
    for index in range(rng.randint(5, 10)):
        nat = NatRule(f"n{index}", origin=f"n{index}")
        nat.src_zones = [ANY] if rng.random() < 0.3 else rng.sample(ZONES, rng.randint(1, 2))
        nat.sources = [ANY] if rng.random() < 0.4 else rng.sample(four, rng.randint(1, 2))
        nat.destinations = [ANY] if rng.random() < 0.5 else rng.sample(four, rng.randint(1, 2))
        nat.service = rng.choice([ANY, ANY, ANY, "web", "one", "both", "dns", "one", "ranges", "mix", "many"])
        shape = rng.choice(["masq", "pool", "host", "static", "dnat", "dnat", "dnat-port", "none", "both"])
        nat.dst_zones = rng.sample(ZONES, rng.randint(1, 2)) if shape == "masq" or rng.random() < 0.7 else [ANY]
        if shape == "masq":
            nat.source_translation = SourceNat(SnatKind.INTERFACE)
        elif shape == "pool":
            members = rng.choice([["192.0.2.1", "192.0.2.2"], ["192.0.2.8/30"], ["192.0.2.1", "192.0.2.9"], ["half"], ["grp"]])
            nat.source_translation = SourceNat(rng.choice([SnatKind.DYNAMIC_PORT, SnatKind.DYNAMIC]), members)
        elif shape in ("host", "both"):
            nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, [rng.choice(["host", "192.0.2.77"])])
        elif shape == "static":
            nat.sources = [rng.choice(["half", "net1", "host"])]
            mapped = {"half": "192.0.2.128/25", "net1": "198.51.100.0/24", "host": "192.0.2.17"}[nat.sources[0]]
            nat.source_translation = SourceNat(SnatKind.STATIC, [mapped], bidirectional=rng.random() < 0.5)
        if shape in ("dnat", "dnat-port", "both"):
            nat.dst_zones = [ANY]
            nat.destinations = [rng.choice(four)] if rng.random() < 0.85 else nat.destinations
            if shape == "dnat-port":
                nat.service = rng.choice(["one", "one", "both", "web", ANY])
            nat.destination_translation = DestNat(rng.choice(["host", "10.0.4.9"]), "8443" if shape == "dnat-port" else "")
        nat.enabled = rng.random() > 0.1
        p.nat_rules.append(nat)
    return p


def aim(rng: random.Random, model: Policy, pkt: Packet, rule: Any) -> None:
    """Turn a packet into one that a rule (of either kind) is likely to match: an address of its lists, a port of its service."""

    def inside(members: List[str], current: str) -> str:
        found = [i for member in members if member != ANY for i in transform.address_intervals(model, member) or [] if i[0] == 4]
        if not found:
            return current
        version, first, last = rng.choice(found)
        return str(ipaddress.IPv4Address(rng.choice([first, last, (first + last) // 2])))

    if ANY not in rule.src_zones:
        pkt.in_if = rng.choice(rule.src_zones)
    if ANY not in rule.dst_zones:
        pkt.out_if = rng.choice(rule.dst_zones)
    pkt.src, pkt.dst = inside(rule.sources, pkt.src), inside(rule.destinations, pkt.dst)
    services = [rule.service] if hasattr(rule, "service") else rule.services
    entries = [entry for name in services if name != ANY for entry in transform.flatten_services(model, name) or []]
    ported = [entry for entry in entries if entry.protocol in (Protocol.TCP, Protocol.UDP) and entry.dst_ports]
    if ported:
        entry = rng.choice(ported)
        pkt.proto, pkt.dport = entry.protocol.value, int(rng.choice(entry.dst_ports.split(",")).split("-")[0])


TRANSLATED: Dict[str, int] = {}


def file_translation_plain(config: CiscoConfig, pkt: Packet) -> Tuple[str, str, str]:
    """What the NAT rule that applies does, without which rule of a model it came from."""
    return file_translation(config, pkt)[1:]


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("seed", range(50))
def test_emitted_nat_rules_translate_like_the_model(target: str, seed: int) -> None:
    """Manual NAT in the order of the rules: the first rule that matches a packet translates it as the model says."""
    rng = random.Random(seed)
    model = random_nat_model(rng) if seed >= 40 else cisco_nat_model(rng)
    options = Options(interface_map={zone: zone for zone in ZONES})
    config, report, text = convert(model, target, options, zones=tuple(ZONES), interfaces=tuple(ZONES))
    skipped = [item.name for item in report.items.values() if item.kind == "nat" and item.skipped]
    for name in skipped:
        nat = next(rule for rule in model.nat_rules if rule.origin == name)
        message = report.item("nat", name).findings[0].message
        translation, destination = nat.source_translation, nat.destination_translation
        reasons = {
            "the outgoing interface": translation is not None and translation.kind == SnatKind.INTERFACE and
            (ANY in nat.dst_zones or destination is not None),
            "IPv4 and IPv6": (translation is not None and translation.addresses == ["grp"]) or "grp" in nat.sources + nat.destinations,
            "is not a TCP or UDP service": nat.service in ("mix", "ranges"),
            "one static address object on each side": destination is not None and (len(nat.destinations) > 1 or ANY in nat.destinations),
            "port range cannot be translated": destination is not None and bool(destination.port),
            "ports or ranges": nat.service == "many",
            "range of ports": target == "fdm" and nat.service in ("many", "ranges"),
            "port translation needs a TCP or UDP service": destination is not None and nat.service == ANY,
        }
        assert any(text_ in message and holds for text_, holds in reasons.items()), (seed, name, message, nat)
    translated = 0
    for pkt in packets(rng, 400):
        if ":" in pkt.src:
            continue
        if rng.random() < 0.6:
            aim(rng, model, pkt, rng.choice(model.nat_rules))
        found = file_translation(config, pkt)
        translated += found[0] != ""
        expected = model_translation(model, pkt, skipped)
        if expected[2] == pkt.dst:
            expected = expected[:2] + ("Original",) + expected[3:]  # translated to the address it has
        assert found == expected, (seed, pkt, config.translating(pkt))
    TRANSLATED[target] = TRANSLATED.get(target, 0) + translated


def test_the_random_nat_rules_translate_a_good_part_of_the_packets() -> None:
    assert all(count > 6000 for count in TRANSLATED.values()) and len(TRANSLATED) == 2, TRANSLATED


# -- a made-up manager: the JSON a Management Center or a Device Manager gives -----------------

BASE = "https://fmc.example.net/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f"
FDM_BASE = "https://ftd.example.net/api/fdm/v6"
Ref = Dict[str, Any]


class Manager:
    """Builds what the REST API of a Management Center returns, or what a Device Manager exports.

    The shapes are those of the API documentation and of the definitions Cisco publishes with its
    Terraform and Ansible tooling; nothing here came from a device.
    """

    def __init__(self, fdm: bool = False, policy: str = "Main", tag: str = "a") -> None:
        self.fdm = fdm
        self.tag = tag  # what tells the ids of two managers apart
        self.count = 0
        self.objects: Dict[str, List[Ref]] = {}  # collection -> objects, in the order they were made
        self.policy = self._new("accesspolicy" if fdm else "AccessPolicy", "NGFW-Access-Policy" if fdm else policy)
        self.policy["defaultAction"] = ({"action": "DENY", "eventLogAction": "LOG_NONE", "type": "accessdefaultaction"} if fdm else
                                        {"type": "AccessPolicyDefaultAction", "id": self._id("default"), "action": "BLOCK"})  # fmt: skip
        self.policies: List[Ref] = [self.policy]
        self.parents: Dict[str, Tuple[str, Ref]] = {}  # child policy -> (where it says so, the policy it inherits from)
        self.rules: Dict[str, List[Ref]] = {self.policy["id"]: []}
        self.prefilter: Optional[Ref] = None
        self.prefilter_rules: List[Ref] = []
        self.nat_policy = self._new("FTDNatPolicy", "NAT") if not fdm else {}
        self.manual: List[Ref] = []
        self.auto: List[Ref] = []
        self.containers = {False: self._new("manualnatrulecontainer", "NGFW-Before-Auto-NAT-Policy", afterAuto=False),
                           True: self._new("manualnatrulecontainer", "NGFW-After-Auto-NAT-Policy", afterAuto=True),
                           None: self._new("objectnatrulecontainer", "NGFW-Object-NAT-Policy")} if fdm else {}  # fmt: skip
        self.metadata = {"hardwareModel": "Cisco Firepower Threat Defense for VMware", "type": "metadata", "configType": "FULL_CONFIG",
                         "apiVersion": "latest", "generatedOn": "Mon Jan 05 10:00:00 UTC 2026", "exportType": "FULL_EXPORT",
                         "softwareVersion": "7.2.5-208"}  # fmt: skip

    # -- objects ----------------------------------------------------------

    def _id(self, kind: str) -> str:
        self.count += 1
        return f"{self.count:08x}-{kind.lower()[:4]:x<4}-11ee-a5a7-6f90451d6ef{self.tag}"

    def _new(self, kind: str, name: str, **fields: Any) -> Ref:
        out: Ref = {"type": kind, "id": self._id(kind), "name": name}
        if self.fdm:
            out["version"] = f"v{self.count}"
        out.update(fields)
        return out

    def _add(self, collection: str, kind: str, name: str, **fields: Any) -> Ref:
        obj = self._new(kind, name, **fields)
        self.objects.setdefault(collection, []).append(obj)
        return obj

    @staticmethod
    def ref(obj: Ref) -> Ref:
        return {key: obj[key] for key in ("type", "id", "name", "version") if key in obj}

    def host(self, name: str, value: str, **fields: Any) -> Ref:
        if self.fdm:
            return self._add("object/networks", "networkobject", name, subType="HOST", value=value, **{"isSystemDefined": False, **fields})
        return self._add("object/hosts", "Host", name, value=value, **{"overridable": False, **fields})

    def network(self, name: str, value: str, **fields: Any) -> Ref:
        if self.fdm:
            return self._add("object/networks", "networkobject", name, subType="NETWORK", value=value, **{"isSystemDefined": False, **fields})
        return self._add("object/networks", "Network", name, value=value, **{"overridable": False, **fields})

    def range(self, name: str, value: str, **fields: Any) -> Ref:
        if self.fdm:
            return self._add("object/networks", "networkobject", name, subType="RANGE", value=value, **{"isSystemDefined": False, **fields})
        return self._add("object/ranges", "Range", name, value=value, **{"overridable": False, **fields})

    def fqdn(self, name: str, value: str, resolution: str = "IPV4_AND_IPV6", **fields: Any) -> Ref:
        if self.fdm:
            return self._add("object/networks", "networkobject", name, subType="FQDN", value=value, dnsResolution=resolution, **fields)
        return self._add("object/fqdns", "FQDN", name, value=value, dnsResolution=resolution, **fields)

    def group(self, name: str, members: Sequence[Ref], literals: Sequence[str] = (), **fields: Any) -> Ref:
        refs = [self.ref(member) for member in members]
        if self.fdm:
            assert not literals, "a network group of a Device Manager holds objects"
            return self._add("object/networkgroups", "networkobjectgroup", name, objects=refs, **fields)
        return self._add("object/networkgroups", "NetworkGroup", name, objects=refs, literals=[self.literal(v) for v in literals], **fields)

    @staticmethod
    def literal(value: str) -> Ref:
        kind = "Range" if "-" in value else "Network" if "/" in value else "Host"
        return {"type": kind, "value": value}

    def tcp(self, name: str, port: str, protocol: str = "TCP", **fields: Any) -> Ref:
        if self.fdm:
            return self._add("object/tcpports" if protocol == "TCP" else "object/udpports", f"{protocol.lower()}portobject", name,
                             port=port, **{"isSystemDefined": False, **fields})  # fmt: skip
        if port:
            fields["port"] = port
        return self._add("object/protocolportobjects", "ProtocolPortObject", name, protocol=protocol, **fields)

    def udp(self, name: str, port: str, **fields: Any) -> Ref:
        return self.tcp(name, port, "UDP", **fields)

    def protocol(self, name: str, protocol: str, **fields: Any) -> Ref:
        if self.fdm:
            return self._add("object/protocols", "protocolobject", name, protocol=protocol, **fields)
        return self._add("object/protocolportobjects", "ProtocolPortObject", name, protocol=protocol, **fields)

    def icmp(self, name: str, kind: Any = None, code: Any = None, six: bool = False, **fields: Any) -> Ref:
        if self.fdm:
            prefix = "icmpv6" if six else "icmpv4"
            fields[f"{prefix}Type"] = kind if kind is not None else "ANY"
            fields[f"{prefix}Code"] = code
            return self._add(f"object/{prefix}ports", f"{prefix}portobject", name, **fields)
        if kind is not None:
            fields["icmpType"] = str(kind)
        if code is not None:
            fields["code"] = str(code)
        return self._add("object/icmpv6objects" if six else "object/icmpv4objects", "ICMPV6Object" if six else "ICMPV4Object", name,
                         **{"overridable": False, **fields})  # fmt: skip

    def port_group(self, name: str, members: Sequence[Ref], **fields: Any) -> Ref:
        kind, collection = ("portobjectgroup", "object/portgroups") if self.fdm else ("PortObjectGroup", "object/portobjectgroups")
        return self._add(collection, kind, name, objects=[self.ref(member) for member in members], **fields)

    def zone(self, name: str, interfaces: Sequence[Ref] = (), **fields: Any) -> Ref:
        if self.fdm:
            refs = [{**self.ref(i), "hardwareName": i["hardwareName"]} for i in interfaces]
            return self._add("object/securityzones", "securityzone", name, mode="ROUTED", interfaces=refs, **fields)
        zone = self._add("object/securityzones", "SecurityZone", name, interfaceMode="ROUTED", **fields)
        for interface in interfaces:
            interface["securityZone"] = {"id": zone["id"], "type": "SecurityZone"}
        zone["interfaces"] = [self.ref(interface) for interface in interfaces]
        return zone

    def interface(self, name: str, hardware: str, address: str = "", mask: str = "255.255.255.0", six: str = "", **fields: Any) -> Ref:
        if self.fdm:
            fields["ipv4"] = {"ipType": "STATIC", "ipAddress": {"ipAddress": address, "netmask": mask, "type": "ipv4address"} if address else None,
                              "type": "interfaceipv4"}  # fmt: skip
            fields["ipv6"] = {"enabled": bool(six), "ipAddresses": [{"ipAddress": six, "type": "ipv6address"}] if six else [], "type": "interfaceipv6"}
            return self._add("devices/default/interfaces", "physicalinterface", name, hardwareName=hardware, enabled=True, mode="ROUTED", **fields)
        if address:
            fields["ipv4"] = {"static": {"address": address, "netmask": mask}}
        if six:
            fields["ipv6"] = {"enableIPV6": True, "addresses": [{"address": six.split("/")[0], "prefix": six.split("/")[1], "enforceEUI64": False}]}
        return self._add("devices/devicerecords/dev1/physicalinterfaces", "PhysicalInterface", hardware, ifname=name, enabled=True, mode="NONE", **fields)

    # -- rules ------------------------------------------------------------

    def _networks(self, members: Optional[Sequence[Any]]) -> Any:
        members = members or []
        refs = [self.ref(member) for member in members if isinstance(member, dict)]
        literals = [self.literal(member) for member in members if isinstance(member, str)]
        if self.fdm:
            assert not literals, "a rule of a Device Manager names objects"
            return refs
        out: Ref = {}
        if refs:
            out["objects"] = refs
        if literals:
            out["literals"] = literals
        return out

    def _ports(self, members: Optional[Sequence[Any]]) -> Any:
        members = members or []
        refs = [self.ref(member) for member in members if "id" in member]
        literals = [member for member in members if "id" not in member]
        if self.fdm:
            assert not literals
            return refs
        out: Ref = {}
        if refs:
            out["objects"] = refs
        if literals:
            out["literals"] = literals
        return out

    def rule(self, name: str, action: str = "ALLOW", policy: Optional[Ref] = None, section: str = "Mandatory", enabled: bool = True,
             src_zones: Optional[Sequence[Ref]] = None, dst_zones: Optional[Sequence[Ref]] = None,
             sources: Optional[Sequence[Any]] = None, destinations: Optional[Sequence[Any]] = None,
             src_ports: Optional[Sequence[Ref]] = None, dst_ports: Optional[Sequence[Ref]] = None, log: str = "end",
             **fields: Any) -> Ref:  # fmt: skip
        policy = policy or self.policy
        held = self.rules.setdefault(policy["id"], [])
        if self.fdm:
            rule = self._new("accessrule", name, ruleId=268435456 + self.count, ruleAction={"ALLOW": "PERMIT", "BLOCK": "DENY"}.get(action, action),
                             eventLogAction={"end": "LOG_FLOW_END", "both": "LOG_BOTH", "none": "LOG_NONE"}[log],
                             sourceZones=[self.ref(z) for z in src_zones or []], destinationZones=[self.ref(z) for z in dst_zones or []],
                             sourceNetworks=self._networks(sources), destinationNetworks=self._networks(destinations),
                             sourcePorts=self._ports(src_ports), destinationPorts=self._ports(dst_ports), identitySources=[], users=[],
                             embeddedAppFilter=None, urlFilter=None, intrusionPolicy=None, filePolicy=None, logFiles=False,
                             syslogServer=None, destinationDynamicObjects=[], sourceDynamicObjects=[], timeRangeObjects=[])  # fmt: skip
            rule["links"] = {"self": f"{FDM_BASE}/policy/accesspolicies/{policy['id']}/accessrules/{rule['id']}"}
        else:
            rule = self._new("AccessRule", name, action=action, enabled=enabled, sendEventsToFMC=log != "none", logFiles=False,
                             logBegin=log == "both", logEnd=log in ("end", "both"), variableSet={"name": "Default-Set", "id": "vs", "type": "VariableSet"},
                             vlanTags={}, enableSyslog=False)  # fmt: skip
            rule["metadata"] = {"ruleIndex": len(held) + 1, "section": section, "category": "--Undefined--",
                                "accessPolicy": {"type": "AccessPolicy", "name": policy["name"], "id": policy["id"]},
                                "timestamp": 1700000000000, "domain": {"name": "Global", "id": "e276abec", "type": "Domain"}}  # fmt: skip
            rule["links"] = {"self": f"{BASE}/policy/accesspolicies/{policy['id']}/accessrules/{rule['id']}"}
            for key, zones in (("sourceZones", src_zones), ("destinationZones", dst_zones)):
                if zones:
                    rule[key] = {"objects": [self.ref(zone) for zone in zones]}
            for key, members in (("sourceNetworks", sources), ("destinationNetworks", destinations)):
                if members:
                    rule[key] = self._networks(members)
            for key, ports in (("sourcePorts", src_ports), ("destinationPorts", dst_ports)):
                if ports:
                    rule[key] = self._ports(ports)
        rule.update(fields)
        held.append(rule)
        return rule

    def child_policy(self, name: str, default: str = "INHERIT_FROM_PARENT", said: str = "policy") -> Ref:
        """An access control policy that inherits from the first one.

        Where that is said: in the ``policy`` itself, in its inheritance ``settings``, or ``nowhere``.
        """
        child = self._new("AccessPolicy", name, defaultAction={"type": "AccessPolicyDefaultAction", "id": self._id("default"), "action": default})
        if said == "policy":
            child["metadata"] = {"inherit": True, "parentPolicy": {"type": "AccessPolicy", "name": self.policy["name"], "id": self.policy["id"]}}
        self.parents[child["id"]] = (said, self.policy)
        self.policies.append(child)
        self.rules[child["id"]] = []
        return child

    def inheritance(self, policy: Ref) -> Ref:
        """The answer to GET policy/accesspolicies/{id}/inheritancesettings."""
        said, parent = self.parents.get(policy["id"], ("settings", None))
        setting: Ref = {"type": "AccessPolicyInheritanceSetting", "id": policy["id"],
                        "links": {"self": f"{BASE}/policy/accesspolicies/{policy['id']}/inheritancesettings/{policy['id']}"}}  # fmt: skip
        if parent is not None and said == "settings":
            setting["basePolicy"] = {"type": "AccessPolicy", "name": parent["name"], "id": parent["id"]}
        return {"links": {"self": f"{BASE}/policy/accesspolicies/{policy['id']}/inheritancesettings?offset=0&limit=25"}, "items": [setting],
                "paging": {"offset": 0, "limit": 25, "count": 1, "pages": 1}}  # fmt: skip

    def use_prefilter(self, name: str = "Edge prefilter", default: str = "ANALYZE_TUNNELS", policy: Optional[Ref] = None) -> Ref:
        self.prefilter = self._new("PrefilterPolicy", name, defaultAction={"type": "PrefilterPolicyDefaultAction", "action": default})
        (policy or self.policy)["prefilterPolicySetting"] = self.ref(self.prefilter)
        return self.prefilter

    def prefilter_rule(self, name: str, action: str = "FASTPATH", kind: str = "PREFILTER", enabled: bool = True,
                       src_zones: Optional[Sequence[Ref]] = None, dst_zones: Optional[Sequence[Ref]] = None,
                       sources: Optional[Sequence[Any]] = None, destinations: Optional[Sequence[Any]] = None,
                       src_ports: Optional[Sequence[Ref]] = None, dst_ports: Optional[Sequence[Ref]] = None, **fields: Any) -> Ref:  # fmt: skip
        assert self.prefilter is not None and not self.fdm
        rule = self._new("PrefilterRule", name, ruleType=kind, action=action, enabled=enabled, logBegin=False, logEnd=False,
                         sendEventsToFMC=False)  # fmt: skip
        rule["metadata"] = {"ruleIndex": len(self.prefilter_rules) + 1}
        rule["links"] = {"self": f"{BASE}/policy/prefilterpolicies/{self.prefilter['id']}/prefilterrules/{rule['id']}"}
        for key, zones in (("sourceInterfaces", src_zones), ("destinationInterfaces", dst_zones)):
            if zones:
                rule[key] = {"objects": [self.ref(zone) for zone in zones]}
        for key, members in (("sourceNetworks", sources), ("destinationNetworks", destinations)):
            if members:
                rule[key] = self._networks(members)
        for key, ports in (("sourcePorts", src_ports), ("destinationPorts", dst_ports)):
            if ports:
                rule[key] = self._ports(ports)
        rule.update(fields)
        self.prefilter_rules.append(rule)
        return rule

    # -- NAT --------------------------------------------------------------

    def manual_nat(self, kind: str = "STATIC", after_auto: bool = False, name: str = "", **fields: Any) -> Ref:
        """A manual NAT rule. References (objects, zones, interfaces) are given as objects and written as references."""
        for key, value in list(fields.items()):
            if isinstance(value, dict) and "id" in value and key != "patOptions":
                fields[key] = self.ref(value)
        if self.fdm:
            rule = self._new("manualnatrule", name or f"nat{len(self.manual) + 1}", natType=kind, **{"enabled": True, **fields})
            holder = self.containers[after_auto]
            rule["links"] = {"self": f"{FDM_BASE}/policy/manualnatpolicies/{holder['id']}/manualnatrules/{rule['id']}"}
            rule["_parent"] = holder["name"]
        else:
            rule = {"type": "FTDManualNatRule", "id": self._id("nat"), "natType": kind, "enabled": True, **fields}
            section = "AFTER_AUTO" if after_auto else "BEFORE_AUTO"
            rule["metadata"] = {"section": section, "index": sum(1 for other in self.manual if other["metadata"]["section"] == section) + 1}
            rule["links"] = {"self": f"{BASE}/policy/ftdnatpolicies/{self.nat_policy['id']}/manualnatrules/{rule['id']}"}
        self.manual.append(rule)
        return rule

    def auto_nat(self, kind: str = "STATIC", name: str = "", **fields: Any) -> Ref:
        for key, value in list(fields.items()):
            if isinstance(value, dict) and "id" in value:
                fields[key] = self.ref(value)
        if self.fdm:
            rule = self._new("objectnatrule", name or f"auto{len(self.auto) + 1}", natType=kind, **{"enabled": True, **fields})
            holder = self.containers[None]
            rule["links"] = {"self": f"{FDM_BASE}/policy/objectnatpolicies/{holder['id']}/objectnatrules/{rule['id']}"}
            rule["_parent"] = holder["name"]
        else:
            rule = {"type": "FTDAutoNatRule", "id": self._id("auto"), "natType": kind, **fields}
            rule["links"] = {"self": f"{BASE}/policy/ftdnatpolicies/{self.nat_policy['id']}/autonatrules/{rule['id']}"}
        self.auto.append(rule)
        return rule

    # -- what comes out ---------------------------------------------------

    def answers(self, policies: bool = True) -> List[Any]:
        """The answers of the REST API: a list per collection, with paging, and the policies themselves."""
        base = FDM_BASE if self.fdm else BASE

        def listed(path: str, items: List[Ref]) -> Ref:
            return {"links": {"self": f"{base}/{path}?offset=0&limit=1000&expanded=true"}, "items": items,
                    "paging": {"offset": 0, "limit": 1000, "count": len(items), "pages": 1}}  # fmt: skip

        out: List[Any] = [listed(path, items) for path, items in self.objects.items()]
        for policy in self.policies if policies else []:
            out.append(policy)
            if not self.fdm and self.parents.get(policy["id"], ("settings", None))[0] == "settings":
                out.append(self.inheritance(policy))
        for ident, rules in self.rules.items():
            if rules or len(self.rules) == 1:
                out.append(listed(f"policy/accesspolicies/{ident}/accessrules", rules))
        if self.prefilter is not None:
            out += [self.prefilter, listed(f"policy/prefilterpolicies/{self.prefilter['id']}/prefilterrules", self.prefilter_rules)]
        strip = [{key: value for key, value in rule.items() if key != "_parent"} for rule in self.manual + self.auto]
        if self.fdm:
            out += list(self.containers.values()) if strip else []
            for holder, kind in ((self.containers.get(False), "manualnatrule"), (self.containers.get(None), "objectnatrule")):
                rules = [rule for rule in strip if rule["type"] == kind]
                if rules and holder is not None:
                    out.append(listed(f"policy/{kind[:-4]}policies/{holder['id']}/{kind}s", rules))
        elif strip:
            out.append(listed(f"policy/ftdnatpolicies/{self.nat_policy['id']}/manualnatrules", [r for r in strip if "Manual" in r["type"]]))
            out.append(listed(f"policy/ftdnatpolicies/{self.nat_policy['id']}/autonatrules", [r for r in strip if "Auto" in r["type"]]))
        return out

    def api(self, **kwargs: Any) -> bytes:
        """The answers one after the other, as a file of them is."""
        return "\n".join(json.dumps(answer) for answer in self.answers(**kwargs)).encode("utf-8")

    def export(self) -> bytes:
        """The text file of a configuration export of a Device Manager."""
        assert self.fdm
        entries: List[Ref] = [self.metadata]
        for items in self.objects.values():
            entries += [{"type": "identitywrapper", "data": {k: v for k, v in item.items() if k != "links"}, "action": "CREATE"} for item in items]
        entries.append({"type": "identitywrapper", "data": self.policy, "action": "CREATE"})
        for index, rule in enumerate(self.rules[self.policy["id"]]):
            entries.append({"type": "identitywrapper", "data": {k: v for k, v in rule.items() if k != "links"}, "action": "CREATE",
                            "parentName": self.policy["name"], "index": index})  # fmt: skip
        if self.manual or self.auto:
            entries += [{"type": "identitywrapper", "data": holder, "action": "CREATE"} for holder in self.containers.values()]
        for rules in ([r for r in self.manual if r["_parent"].startswith("NGFW-Before")], [r for r in self.manual if r["_parent"].startswith("NGFW-After")],
                      self.auto):  # fmt: skip
            for index, rule in enumerate(rules):
                data = {k: v for k, v in rule.items() if k not in ("links", "_parent")}
                entries.append({"type": "identitywrapper", "data": data, "action": "CREATE", "parentName": rule["_parent"], "index": index})
        return ("[\n" + ",\n".join(json.dumps(entry) for entry in entries) + "\n]\n").encode("utf-8")


def read(data: bytes, dialect: str = "", **kwargs: Any) -> Tuple[Policy, Report]:
    report = Report()
    source = dialect or cli.detect_format(data)
    return cli.load(data, source, report, **kwargs), report


def plit(protocol: int, port: str = "") -> Ref:
    """A port literal of a rule of a Management Center."""
    out: Ref = {"type": "PortLiteral", "protocol": str(protocol)}
    if port:
        out["port"] = port
    return out


# -- a made-up device: what it does with a packet, and the JSON of its manager -----------------

NAMEIFS = ["outside", "inside", "dmz", "guest"]
Match = Callable[[Packet], bool]


@dataclass
class Lab:
    """A device made up at random: the JSON of its manager, and what it does with a packet."""

    manager: Manager
    prefilter: List[Tuple[str, Match]] = field(default_factory=list)  # (fastpath, block or analyze; what it matches)
    access: List[Tuple[bool, Match]] = field(default_factory=list)  # in the order of evaluation
    default: bool = False
    block_tunnels: bool = False

    def allows(self, pkt: Packet) -> bool:
        for action, match in self.prefilter:
            if match(pkt):
                if action != "analyze":
                    return action == "fastpath"
                break  # the first prefilter rule that matches handles the packet: this one hands it on
        else:
            if self.block_tunnels and (pkt.proto in ("47", "4", "41") or (pkt.proto == "udp" and pkt.dport == 3544)):
                return False
        for allow, match in self.access:
            if match(pkt):
                return allow
        return self.default


def lab_packet(rng: random.Random) -> Packet:
    if rng.random() < 0.75:
        src, dst = (f"10.0.{rng.randrange(5)}.{rng.randrange(0, 256, 17)}" for _ in range(2))
    else:
        src, dst = (f"2001:db8:{rng.randrange(4)}::{rng.randrange(1, 4)}" for _ in range(2))
    proto = rng.choice(["tcp", "tcp", "tcp", "udp", "icmp" if "." in src else "icmp6", "47", "50"])
    return Packet(rng.choice(NAMEIFS), rng.choice(NAMEIFS), src, dst, proto, rng.choice([53, 1024, 40000]),
                  rng.choice([22, 53, 80, 443, 8000, 8005, 8080, 9000, 3544]), rng.choice([0, 3, 8, 128, 129]))  # fmt: skip


def random_lab(rng: random.Random, fdm: bool, nat: bool = False, prefilter: bool = False, inherit: bool = False) -> Lab:
    m = Manager(fdm)
    lab = Lab(m)
    zones = {name: m.zone(name) for name in NAMEIFS}
    net1, net2 = m.network("NET1", "10.0.1.0/24"), m.network("NET2", "10.0.2.0/24")
    host, span, six = m.host("HOST", "10.0.3.17"), m.range("SPAN", "10.0.3.100-10.0.4.50"), m.network("SIX", "2001:db8:2::/48")
    name = m.fqdn("FQ", "www.example.com")
    if fdm:
        app, one6, half = m.host("APP", "10.0.2.34"), m.network("ONE6", "2001:db8:1::/48"), m.network("HALF", "10.0.4.0/25")
        grp = m.group("GRP", [net1, app, one6, half])
        nest = m.group("NEST", [net1, app, one6, half, span])  # as an export holds a group: its objects
    else:
        grp = m.group("GRP", [net1], ["10.0.2.34", "2001:db8:1::/48", "10.0.4.0/25"])
        nest = m.group("NEST", [grp, span])
    http, https, high = m.tcp("HTTP", "80"), m.tcp("HTTPS", "443"), m.tcp("HIGH", "8000-8010")
    ssh, dns_u, dns_t, any_udp = m.tcp("SSH", "22"), m.udp("DNS_UDP", "53"), m.tcp("DNS_TCP", "53"), m.udp("ALLUDP", "" if not fdm else "1-65535")
    ping = m.icmp("PING", "ECHO_REQUEST" if fdm else 8)
    icmp_any, ping6 = m.icmp("ICMP"), m.icmp("PING6", "ECHO_REQUEST" if fdm else 128, six=True)
    unreach = m.icmp("UNREACH", "DESTINATION_UNREACHABLE" if fdm else 3, "PORT_UNREACHABLE" if fdm else 3)
    gre, esp = m.protocol("GRE", "GRE"), m.protocol("ESP", "ESP" if fdm else "50")
    web, mix = m.port_group("WEB", [http, https, high]), m.port_group("MIX", [dns_u, ping, ping6, gre, ssh])

    def members(*literals: str) -> Callable[[str], bool]:
        return lambda address: any(_in(address, literal) for literal in literals)

    grp_of = ("10.0.1.0/24", "10.0.2.34", "2001:db8:1::/48", "10.0.4.0/25")
    addresses: List[Tuple[Any, Callable[[str], bool]]] = [
        (net1, members("10.0.1.0/24")), (net2, members("10.0.2.0/24")), (host, members("10.0.3.17")),
        (span, members("10.0.3.100-10.0.4.50")), (six, members("2001:db8:2::/48")), (grp, members(*grp_of)),
        (nest, members(*grp_of, "10.0.3.100-10.0.4.50")), (name, lambda a: False),
    ]  # fmt: skip
    if not fdm:
        addresses += [("10.0.0.17", members("10.0.0.17")), ("10.0.2.0/23", members("10.0.2.0/23")),
                      ("2001:db8:3::/48", members("2001:db8:3::/48")), ("10.0.0.34-10.0.0.200", members("10.0.0.34-10.0.0.200"))]  # fmt: skip

    def port(protocol: str, low: int, high_: int) -> Callable[[Packet, bool], bool]:
        return lambda p, source: p.proto == protocol and low <= (p.sport if source else p.dport) <= high_

    # (what a rule names, the one protocol it is of when it can be a source port, what it matches)
    ports: List[Tuple[Any, str, Callable[[Packet, bool], bool]]] = [
        (http, "tcp", port("tcp", 80, 80)), (https, "tcp", port("tcp", 443, 443)), (high, "tcp", port("tcp", 8000, 8010)),
        (ssh, "tcp", port("tcp", 22, 22)), (dns_u, "udp", port("udp", 53, 53)), (dns_t, "tcp", port("tcp", 53, 53)),
        (any_udp, "udp", lambda p, source: p.proto == "udp"),
        (web, "tcp", lambda p, source: p.proto == "tcp" and (p.sport if source else p.dport) in (80, 443, *range(8000, 8011))),
        (ping, "", lambda p, source: p.proto == "icmp" and p.icmp_type == 8), (icmp_any, "", lambda p, source: p.proto == "icmp"),
        (ping6, "", lambda p, source: p.proto == "icmp6" and p.icmp_type == 128),
        (unreach, "", lambda p, source: p.proto == "icmp" and p.icmp_type == 3),
        (gre, "", lambda p, source: p.proto == "47"), (esp, "", lambda p, source: p.proto == "50"),
        (mix, "", lambda p, source: (p.proto == "udp" and p.dport == 53) or (p.proto == "icmp" and p.icmp_type == 8)
         or (p.proto == "icmp6" and p.icmp_type == 128) or p.proto == "47" or (p.proto == "tcp" and p.dport == 22)),
    ]  # fmt: skip
    if not fdm:
        ports += [(plit(6, "9000"), "tcp", port("tcp", 9000, 9000)), (plit(17, "1024-65535"), "udp", port("udp", 1024, 65535)),
                  (plit(50), "", lambda p, source: p.proto == "50"),
                  ({"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": "0"}, "", lambda p, source: p.proto == "icmp" and p.icmp_type == 0),
                  ({"type": "ICMPv6PortLiteral", "protocol": "58", "icmpType": "129", "code": "0"}, "",
                   lambda p, source: p.proto == "icmp6" and p.icmp_type == 129)]  # fmt: skip

    def conditions() -> Tuple[Dict[str, Any], Match]:
        fields: Dict[str, Any] = {}
        checks: List[Match] = []
        for key, attribute in (("src_zones", "in_if"), ("dst_zones", "out_if")):
            if rng.random() < 0.5:
                picked = rng.sample(NAMEIFS, rng.randint(1, 2))
                fields[key] = [zones[zone] for zone in picked]
                checks.append(lambda p, picked=picked, attribute=attribute: getattr(p, attribute) in picked)
        for key, attribute in (("sources", "src"), ("destinations", "dst")):
            if rng.random() < 0.6:
                chosen = rng.sample(addresses, rng.randint(1, 2))
                fields[key] = [member for member, _ in chosen]
                checks.append(lambda p, chosen=chosen, attribute=attribute: any(match(getattr(p, attribute)) for _, match in chosen))
        kind = rng.random()
        if kind < 0.2:  # source ports, alone or with destination ports of the same protocol
            protocol = rng.choice(["tcp", "udp"])
            usable = [entry for entry in ports if entry[1] == protocol]
            origin = rng.sample(usable, 1)
            fields["src_ports"] = [member for member, _, _ in origin]
            checks.append(lambda p, origin=origin: any(match(p, True) for _, _, match in origin))
            if rng.random() < 0.6:
                target = rng.sample(usable, rng.randint(1, 2))
                fields["dst_ports"] = [member for member, _, _ in target]
                checks.append(lambda p, target=target: any(match(p, False) for _, _, match in target))
        elif kind < 0.8:
            target = rng.sample(ports, rng.randint(1, 3))
            fields["dst_ports"] = [member for member, _, _ in target]
            checks.append(lambda p, target=target: any(match(p, False) for _, _, match in target))
        return fields, lambda p: all(check(p) for check in checks)

    def access_rules(prefix: str, count: int, policy: Optional[Ref] = None, section: str = "Mandatory") -> List[Tuple[bool, Match]]:
        out: List[Tuple[bool, Match]] = []
        for index in range(count):
            fields, match = conditions()
            action = rng.choice(["ALLOW", "ALLOW", "ALLOW", "TRUST", "BLOCK", "BLOCK"] + ([] if fdm else ["BLOCK_RESET", "MONITOR", "BLOCK_INTERACTIVE"]))
            enabled = fdm or rng.random() > 0.1
            m.rule(f"{prefix}{index}", action, policy=policy, section=section, enabled=enabled, log=rng.choice(["end", "both", "none"]), **fields)
            if enabled and action != "MONITOR":
                out.append((action in ("ALLOW", "TRUST"), match))
        return out

    lab.default = rng.random() < 0.25
    m.policy["defaultAction"]["action"] = ("PERMIT" if lab.default else "DENY") if fdm else ("PERMIT" if lab.default else "BLOCK")
    if inherit:
        child = m.child_policy("Branch", rng.choice(["INHERIT_FROM_PARENT", "BLOCK"]))
        if child["defaultAction"]["action"] == "BLOCK":
            lab.default = False
        top, own = access_rules("top", rng.randint(1, 4)), access_rules("own", rng.randint(1, 4), child)
        own_default = access_rules("own-default", rng.randint(0, 3), child, "Default")
        lab.access = top + own + own_default + access_rules("top-default", rng.randint(0, 3), None, "Default")
    else:
        lab.access = access_rules("r", rng.randint(3, 10))
        if not fdm:
            lab.access += access_rules("d", rng.randint(0, 3), None, "Default")
    if prefilter:
        lab.block_tunnels = rng.random() < 0.5
        m.use_prefilter(default="BLOCK_TUNNELS" if lab.block_tunnels else "ANALYZE_TUNNELS", policy=m.policies[-1])
        for index in range(rng.randint(1, 4)):
            fields, match = conditions()
            action = rng.choice(["FASTPATH", "FASTPATH", "BLOCK", "ANALYZE"])
            enabled = rng.random() > 0.1
            m.prefilter_rule(f"pre{index}", action, enabled=enabled, **fields)
            if enabled:
                lab.prefilter.append((action.lower(), match))
    if nat:
        # Access rules name real addresses: NAT changes nothing about what they let through.
        pub, gateway = m.host("PUB", "198.51.110.1"), m.host("SIX-GW", "10.0.2.99")
        mapped2, mapped_host = m.network("NET2-PUB", "198.51.100.0/24"), m.host("HOST-PUB", "198.51.101.17")
        any4 = m.network("any-ipv4", "0.0.0.0/0", **({"isSystemDefined": True} if fdm else {"metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}}}))
        outside, inside, dmz, guest = (m.interface(n, f"GigabitEthernet0/{i}") for i, n in enumerate(NAMEIFS)) if fdm else (zones[n] for n in NAMEIFS)
        m.auto_nat("STATIC", originalNetwork=net2, translatedNetwork=mapped2, sourceInterface=dmz, destinationInterface=outside)
        m.auto_nat("STATIC", originalNetwork=host, translatedNetwork=mapped_host, sourceInterface=guest, destinationInterface=outside)
        m.manual_nat("DYNAMIC", originalSource=net1, interfaceInTranslatedSource=True, sourceInterface=inside, destinationInterface=outside)
        m.manual_nat("STATIC", originalSource=any4, translatedSource=any4, originalDestination=pub, translatedDestination=gateway,
                     sourceInterface=outside, destinationInterface=dmz)  # fmt: skip
        if fdm:
            for zone, interface in zip(NAMEIFS, (outside, inside, dmz, guest)):
                zones[zone]["interfaces"] = [{**m.ref(interface), "hardwareName": interface["hardwareName"]}]
    return lab


def model_allows(p: Policy, pkt: Packet) -> bool:
    verdict = model_verdict(p, pkt)
    return p.default_interzone == Action.ALLOW if verdict is None else verdict


LAB_ALLOWED: List[int] = []


@pytest.mark.parametrize("fdm,nat,prefilter,inherit", [
    (False, False, False, False), (False, True, False, False), (False, False, False, True), (False, False, True, False),
    (False, True, True, True), (True, False, False, False), (True, True, False, False),
])  # fmt: skip
def test_parsed_policy_decides_like_the_device(fdm: bool, nat: bool, prefilter: bool, inherit: bool) -> None:
    """Zones, objects, literals, source ports, sections, inheritance, prefilter, default action: every packet as the device."""
    allowed = exact = 0
    for seed in range(100):
        rng = random.Random(seed)
        lab = random_lab(rng, fdm, nat, prefilter, inherit)
        data = lab.manager.export() if fdm and seed % 2 else lab.manager.api()
        kwargs = {"policy": "Branch"} if inherit and seed % 2 else {}
        p, report = read(data, **kwargs)
        assert p.vendor == ("fdm" if fdm else "fmc"), seed
        # An Analyze rule in front of other prefilter rules is the one thing that is not read exactly, and it is said.
        inexact = {item.name for item in report.items.values() if item.kind == "rule" and "PREFILTER_ANALYZE" in [f.code for f in item.findings]
                   and not item.skipped}  # fmt: skip
        unusable = [rule.name for rule in p.rules if rule.unsupported]
        assert set(unusable) <= {rule.name for rule in p.rules if rule.name.startswith("pre")} and (prefilter or not unusable), (seed, unusable)
        assert (p.default_interzone == Action.ALLOW) == lab.default, seed
        for _ in range(300):
            pkt = lab_packet(rng)
            expected = lab.allows(pkt)
            allowed += expected
            if not inexact and not unusable:
                exact += 1
                assert model_allows(p, pkt) == expected, (seed, pkt)
            else:
                assert expected or not model_allows(p, pkt), (seed, pkt)  # never wider than the device
    LAB_ALLOWED.append(allowed)
    assert allowed > 5000 and exact > (5000 if prefilter else 29000), (allowed, exact)


@pytest.mark.parametrize("fdm", [False, True])
@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("nat", [False, True])
def test_converted_policy_decides_like_the_device(fdm: bool, target: str, nat: bool) -> None:
    """From one manager to the same one or the other: what is written does what the device did.

    With NAT the rules go to the original address and back to the real one: nothing may be left
    behind, and what a rule did not name before it does not name after.
    """
    compared = same = 0
    for seed in range(60):
        rng = random.Random(900 + seed)
        lab = random_lab(rng, fdm, nat, prefilter=not fdm and seed % 3 == 0, inherit=not fdm and seed % 4 == 1)
        p, read_report = read(lab.manager.api())
        report = Report()
        native = target == p.vendor
        text = cli.convert(p, target, report)
        config = CiscoConfig(text, zones=tuple(NAMEIFS), native=native, resolved={"FQ": []})
        lost = lost_rules(report)
        for name in lost:
            rule = next(rule for rule in p.rules if rule.origin == name)
            found = set(codes(report, "rule", name))
            # What a Device Manager has no name for, a rule that is off, and what the prefilter could not say.
            assert found & {"UNCONVERTIBLE_OBJECT", "DISABLED_RULE", "UNSUPPORTED_MATCH"} or not rule.enabled, (seed, name, found)
            assert "UNCONVERTIBLE_OBJECT" not in found or target == "fdm", (seed, name, report.to_text())
        effective = Policy(vendor=p.vendor, zones=p.zones, addresses=p.addresses, address_groups=p.address_groups, services=p.services,
                           service_groups=p.service_groups, rules=[rule for rule in p.rules if rule.origin not in lost])  # fmt: skip
        exact = not any(rule.unsupported for rule in p.rules) and not any(
            "PREFILTER_ANALYZE" in codes(read_report, "rule", rule.origin) for rule in p.rules) and not [
            name for name in lost if next(rule for rule in p.rules if rule.origin == name).enabled]  # fmt: skip
        for _ in range(200):
            pkt = lab_packet(rng)
            decided = model_verdict(effective, pkt)
            compared += 1
            assert config.allows(pkt) == bool(decided), (seed, pkt, config.deciding(pkt))
            if exact and (decided is not None or not lab.default):
                same += 1
                assert config.allows(pkt) == lab.allows(pkt), (seed, pkt)
    assert compared == 12000 and same > (3000 if fdm != (target == "fdm") else 6000), (compared, same)


# -- a made-up Management Center, for the script that loads a policy --------------------------


class FakeFmc:
    """Enough of the REST API of a Management Center to run the loader against, strict about what it is sent.

    It keeps what is created, hands out ids, refuses a name that exists (whatever its case) and a
    reference to something it does not have, and answers a listing page by page. It can be told to
    refuse a call, to say it is asked too often, or to let the token run out.
    """

    DOMAIN = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
    FAMILIES = {"object/hosts": "network", "object/networks": "network", "object/ranges": "network", "object/fqdns": "network",
                "object/networkgroups": "network", "object/protocolportobjects": "port", "object/icmpv4objects": "port",
                "object/icmpv6objects": "port", "object/portobjectgroups": "port", "object/securityzones": "zone",
                "object/interfacegroups": "zone", "policy/accesspolicies": "access", "policy/ftdnatpolicies": "nat"}  # fmt: skip
    TYPES = {"object/hosts": "Host", "object/networks": "Network", "object/ranges": "Range", "object/fqdns": "FQDN",
             "object/networkgroups": "NetworkGroup", "object/protocolportobjects": "ProtocolPortObject",
             "object/icmpv4objects": "ICMPV4Object", "object/icmpv6objects": "ICMPV6Object", "object/portobjectgroups": "PortObjectGroup",
             "object/securityzones": "SecurityZone", "object/interfacegroups": "InterfaceGroup", "policy/accesspolicies": "AccessPolicy",
             "policy/ftdnatpolicies": "FTDNatPolicy"}  # fmt: skip

    def __init__(self, user: str = "api", password: str = "secret") -> None:
        self.user, self.password = user, password
        self.store: Dict[str, List[Dict[str, Any]]] = {path: [] for path in self.FAMILIES}
        self.rules: Dict[str, List[Dict[str, Any]]] = {}  # access policy id -> rules
        self.nat: Dict[str, List[Dict[str, Any]]] = {}
        self.calls: List[Tuple[str, str]] = []
        self.logins = 0
        self.count = 0
        self.tokens: List[str] = []
        self.refuse: Optional[Callable[[str, str, Any], str]] = None  # (method, path, body) -> why not
        self.throttle: List[int] = []  # numbers of the calls that are answered with 429
        self.expire: List[int] = []  # numbers of the calls at which the token has run out
        self.page_limit = 1000
        # Ways to misbehave, for the tests of what the loader does then.
        self.after: Optional[Callable[[str, str, int, bytes], Optional[Tuple[int, bytes]]]] = None  # the answer, once the call is carried out
        self.hidden: List[str] = []  # names a listing leaves out until something was created
        self.skip_existing = False  # a bulk call passes over names that exist, and says nothing
        self.keep_rule: Optional[Callable[[Dict[str, Any]], bool]] = None  # rules a bulk call quietly leaves out
        self.reverse_rules = False  # a bulk call stores its rules last first
        self.posted = False
        for name, value in (("any-ipv4", "0.0.0.0/0"), ("any-ipv6", "::/0"), ("IPv4-Private-10.0.0.0-8", "10.0.0.0/8")):
            self._create("object/networks", {"type": "Network", "name": name, "value": value}, system=True)
        for name, protocol, port in (("HTTP", "TCP", "80"), ("HTTPS", "TCP", "443"), ("SSH", "TCP", "22")):
            self._create("object/protocolportobjects", {"type": "ProtocolPortObject", "name": name, "protocol": protocol, "port": port}, system=True)

    def _create(self, path: str, body: Dict[str, Any], system: bool = False) -> Dict[str, Any]:
        self.count += 1
        obj = dict(body)
        obj["id"] = f"{self.count:08x}-0000-11ee-a5a7-6f90451d6efd"
        obj["links"] = {"self": f"{BASE}/{path}/{obj['id']}"}
        obj["metadata"] = {"readOnly": {"state": True, "reason": "SYSTEM"}} if system else {"timestamp": 1700000000000 + self.count}
        self.store[path].append(obj)
        return obj

    def _all(self) -> Dict[str, Dict[str, Any]]:
        return {obj["id"]: obj for objects in self.store.values() for obj in objects}

    def _check(self, path: str, body: Any, known: Dict[str, Dict[str, Any]]) -> str:
        """Why an object, a rule or a NAT rule is not taken; empty when it is."""
        if not isinstance(body, dict) or not isinstance(body.get("type"), str):
            return "not an object"
        if "@ref" in json.dumps(body):
            return "a reference without an id"
        name, kind = body.get("name"), body["type"]
        spaces = kind in ("AccessRule", "AccessPolicy", "FTDNatPolicy")
        if kind != "FTDManualNatRule" and (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]*" if spaces else r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
                                           or len(name) > (50 if spaces else 64)):  # fmt: skip
            return f"Invalid name {name!r}"
        try:
            if kind == "Host":
                ipaddress.ip_address(body["value"])
            elif kind == "Network":
                ipaddress.ip_network(body["value"], strict=True)
            elif kind == "Range":
                low, high = (ipaddress.ip_address(part) for part in body["value"].split("-"))
                if low.version != high.version or int(low) >= int(high):
                    return "Invalid range"
            elif kind == "ProtocolPortObject" and not (body["protocol"] in ("TCP", "UDP") and all(1 <= int(p) <= 65535 for p in body.get("port", "1").split("-"))):
                return "Invalid port"
            elif kind in ("NetworkGroup", "PortObjectGroup") and not body.get("objects"):
                return "A group needs members"
            elif kind == "NetworkGroup" and any(member.get("type") == "FQDN" for member in body["objects"]):
                return "A network group holds no FQDN object"
            elif kind == "PortObjectGroup" and any(member.get("type") == "PortObjectGroup" for member in body["objects"]):
                return "A port group holds no port group"
            elif kind == "AccessRule" and (body.get("action") not in ("ALLOW", "TRUST", "BLOCK", "BLOCK_RESET") or (body["action"].startswith("BLOCK") and body.get("logEnd"))):
                return "Invalid action or logging"
        except (KeyError, ValueError, TypeError, AttributeError):
            return f"Invalid value in {kind} {name}"

        def references(value: Any, top: bool = True) -> List[Dict[str, Any]]:
            if isinstance(value, list):
                return [found for item in value for found in references(item, False)]
            if not isinstance(value, dict):
                return []
            if not top and "id" in value and "type" in value:
                return [value]
            return [found for inner in value.values() for found in references(inner, False)]

        for ref in references(body):
            held = known.get(ref["id"])
            if held is None or held["type"] != ref["type"] or held["name"] != ref.get("name"):
                return f"Invalid reference {ref.get('type')} {ref.get('name')}"
        return ""

    def send(self, method: str, path: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, str], bytes]:
        headers = {key.lower(): value for key, value in headers.items()}  # the names of headers are not case sensitive
        if path == "/api/fmc_platform/v1/auth/generatetoken":
            import base64

            expected = "Basic " + base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
            if method != "POST" or headers.get("authorization") != expected:
                return 401, {}, b'{"error":{"messages":[{"description":"Invalid username or password"}]}}'
            self.logins += 1
            self.tokens = [f"token-{self.logins}"]
            return 204, {"x-auth-access-token": self.tokens[0], "x-auth-refresh-token": "refresh", "domain_uuid": self.DOMAIN,
                         "domains": json.dumps([{"name": "Global", "uuid": self.DOMAIN}, {"name": "Global/Lab", "uuid": "lab-uuid"}])}, b""  # fmt: skip
        number = len(self.calls) + 1
        self.calls.append((method, path))
        if number in self.expire:
            self.tokens = []
        if headers.get("x-auth-access-token") not in self.tokens:
            return 401, {}, b'{"error":{"messages":[{"description":"Invalid access token"}]}}'
        if number in self.throttle:
            return 429, {"retry-after": "1"}, b'{"error":{"messages":[{"description":"Too many requests"}]}}'
        prefix = f"/api/fmc_config/v1/domain/{self.DOMAIN}/"
        if not path.startswith(prefix):
            return 404, {}, b'{"error":{"messages":[{"description":"no such domain"}]}}'
        rest, _, query = path[len(prefix):].partition("?")
        options = dict(pair.split("=", 1) for pair in query.split("&") if "=" in pair)
        payload = json.loads(body.decode("utf-8")) if body else None
        try:
            status, answer = self._handle(method, rest, options, payload)
        except KeyError as error:
            status, answer = 404, {"error": {"messages": [{"description": f"not found: {error}"}]}}
        raw = json.dumps(answer).encode("utf-8")
        changed = self.after(method, rest, status, raw) if self.after is not None else None
        if changed is not None:
            status, raw = changed
        return status, {"content-type": "application/json"}, raw

    @staticmethod
    def _error(text: str, status: int = 400) -> Tuple[int, Dict[str, Any]]:
        return status, {"error": {"category": "FRAMEWORK", "messages": [{"description": text}], "severity": "ERROR"}}

    def _handle(self, method: str, rest: str, options: Dict[str, str], payload: Any) -> Tuple[int, Dict[str, Any]]:
        if self.refuse is not None:
            why = self.refuse(method, rest, payload)
            if why:
                return self._error(why, 422)
        parts = rest.split("/")
        collection = "/".join(parts[:2])
        if collection not in self.store:
            return self._error(f"no such resource {collection}", 404)
        if len(parts) == 4 and parts[3] == "inheritancesettings" and method == "GET":
            setting = {"type": "AccessPolicyInheritanceSetting", "id": parts[2], "links": {"self": f"{BASE}/{rest}/{parts[2]}"}}
            return 200, {"links": {"self": f"{BASE}/{rest}"}, "items": [setting], "paging": {"offset": 0, "limit": 25, "count": 1, "pages": 1}}
        if len(parts) == 4:  # the rules of a policy
            holder = {"accessrules": self.rules, "manualnatrules": self.nat}[parts[3]]
            rules = holder[parts[2]]
            if method == "GET":
                return 200, self._page(rules, options, f"{rest}")
            if method != "POST" or options.get("bulk") != "true" or not isinstance(payload, list):
                return self._error("rules are created in bulk")
            if (parts[3] == "accessrules") != (options.get("section") == "mandatory") or (parts[3] == "manualnatrules") != (options.get("section") == "before_auto"):
                return self._error("section")
            if len(payload) > 1000 or len(json.dumps(payload)) > 2_048_000:
                return self._error("too much for one call", 413)
            known = self._all()
            created = []
            if self.keep_rule is not None:
                payload = [body for body in payload if self.keep_rule(body)]
            if self.reverse_rules:
                payload = payload[::-1]
            for body in payload:
                why = self._check(rest, body, known)
                if not why and parts[3] == "accessrules" and body.get("name", "").lower() in {rule["name"].lower() for rule in rules + created}:
                    why = f"a rule named {body.get('name')} exists"
                if why:
                    return self._error(why)  # all or nothing
                self.count += 1
                rule = dict(body)
                rule["id"] = f"{self.count:08x}-0000-11ee-a5a7-6f90451d6efd"
                rule["links"] = {"self": f"{BASE}/{rest}/{rule['id']}"}
                created.append(rule)
            for rule in created:
                rules.append(rule)
                if parts[3] == "accessrules":
                    policy = next(p for p in self.store[collection] if p["id"] == parts[2])
                    rule["metadata"] = {"ruleIndex": len(rules), "section": "Mandatory",
                                        "accessPolicy": {"type": "AccessPolicy", "id": policy["id"], "name": policy["name"]}}  # fmt: skip
                    if "newComments" in rule:
                        rule["commentHistoryList"] = [{"comment": text, "user": {"name": "api"}} for text in rule.pop("newComments")]
                else:
                    rule["metadata"] = {"section": "BEFORE_AUTO", "index": len(rules)}
            return 201, {"items": created}
        if len(parts) == 3:
            held = next((obj for obj in self.store[collection] if obj["id"] == parts[2]), None)
            if held is None:
                return self._error("not found", 404)
            if method == "GET":
                return 200, held
            if method != "DELETE":
                return self._error("method")
            if held["metadata"].get("readOnly"):
                return self._error("a system object cannot be deleted")
            used = json.dumps([obj for objects in self.store.values() for obj in objects if obj is not held]
                              + [rule for rules in list(self.rules.values()) + list(self.nat.values()) for rule in rules])  # fmt: skip
            if f'"id": "{held["id"]}"' in used and collection.startswith("object/"):
                return self._error(f"{held['name']} is in use")
            self.store[collection].remove(held)
            self.rules.pop(held["id"], None)
            self.nat.pop(held["id"], None)
            return 200, held
        if method == "GET":
            shown = [obj for obj in self.store[collection] if obj["name"] not in self.hidden or self.posted]
            return 200, self._page(shown, options, collection)
        if method != "POST":
            return self._error("method")
        self.posted = True
        bulk = options.get("bulk") == "true"
        if bulk != isinstance(payload, list):
            return self._error("a list is sent with bulk=true, and only then")
        bodies = payload if bulk else [payload]
        if len(bodies) > 1000 or len(json.dumps(bodies)) > 2_048_000:
            return self._error("too much for one call", 413)
        family = self.FAMILIES[collection]
        taken = {obj["name"].lower() for path, objects in self.store.items() if self.FAMILIES[path] == family for obj in objects}
        known = self._all()
        if self.skip_existing and bulk:
            bodies = [body for body in bodies if str(body.get("name")).lower() not in taken]
        for body in bodies:
            why = self._check(collection, body, known)
            if not why and body.get("type") != self.TYPES[collection]:
                why = f"a {body.get('type')} is not created here"
            if not why and (not isinstance(body.get("name"), str) or body["name"].lower() in taken):
                why = f"The object name {body.get('name')} already exists"
            if why:
                return self._error(why)
            taken.add(body["name"].lower())
        created = [self._create(collection, body) for body in bodies]
        for obj in created:
            if collection == "policy/accesspolicies":
                self.rules[obj["id"]] = []
                obj["defaultAction"] = {"type": "AccessPolicyDefaultAction", "id": obj["id"] + "-default", **obj["defaultAction"]}
                obj["prefilterPolicySetting"] = {"type": "PrefilterPolicy", "id": "prefilter-default", "name": "Default Prefilter Policy"}
            elif collection == "policy/ftdnatpolicies":
                self.nat[obj["id"]] = []
        return 201, {"items": created} if bulk else created[0]

    def _page(self, items: List[Dict[str, Any]], options: Dict[str, str], path: str) -> Dict[str, Any]:
        limit, offset = min(int(options.get("limit", "25")), self.page_limit), int(options.get("offset", "0"))
        shown = items[offset:offset + limit]
        if options.get("expanded") != "true":
            shown = [{key: item[key] for key in ("type", "id", "name", "links") if key in item} for item in shown]
        return {"links": {"self": f"{BASE}/{path}?offset={offset}&limit={limit}"}, "items": shown,
                "paging": {"offset": offset, "limit": limit, "count": len(items), "pages": max(1, -(-len(items) // limit))}}  # fmt: skip

    def created(self) -> Dict[str, List[str]]:
        """Names per collection of what is not there from the start."""
        return {path: [obj["name"] for obj in objects if not obj["metadata"].get("readOnly")] for path, objects in self.store.items()
                if any(not obj["metadata"].get("readOnly") for obj in objects)}  # fmt: skip

    def dump(self) -> bytes:
        """What the REST API returns for everything, as someone would fetch it to convert it."""
        token = {"X-auth-access-token": "dump"}
        self.tokens.append("dump")
        out: List[str] = []
        prefix = f"/api/fmc_config/v1/domain/{self.DOMAIN}/"
        paths = list(self.store) + [f"policy/accesspolicies/{ident}/accessrules" for ident in self.rules]
        paths += [f"policy/accesspolicies/{ident}/inheritancesettings" for ident in self.rules]
        paths += [f"policy/ftdnatpolicies/{ident}/manualnatrules" for ident in self.nat]
        for path in paths:
            out.append(self.send("GET", f"{prefix}{path}?expanded=true&limit=1000", token, None)[2].decode("utf-8"))
        for policy in self.store["policy/accesspolicies"]:
            out.append(json.dumps(policy))
        return "\n".join(out).encode("utf-8")


def load_script(text: str, fmc: FakeFmc, tmp_path: Any, *arguments: str, password: str = "secret") -> Tuple[int, List[str]]:
    """Run the loader of a script against a made-up Management Center; (exit status, what it said)."""
    import os

    from fwshift.emitters import fmc_loader

    said: List[str] = []
    plan = CiscoConfig(text).plan
    previous = os.environ.get("FMC_PASSWORD")
    os.environ["FMC_PASSWORD"] = password
    try:
        argv = ["--host", "fmc.example.net", "--user", "api", "--journal", str(tmp_path / "journal.json"), *arguments]
        status = fmc_loader.main(argv, transport=fmc, say=said.append, plan=plan)
    finally:
        if previous is None:
            del os.environ["FMC_PASSWORD"]
        else:
            os.environ["FMC_PASSWORD"] = previous
    return status, said


@pytest.mark.parametrize("seed", range(12))
def test_the_script_loads_what_the_model_says(seed: int, tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """Model -> script -> a Management Center -> its REST API -> parser: the policy that comes back decides the same."""
    rng = random.Random(300 + seed)
    model = random_model(rng)
    model.zones = {zone: Zone(zone) for zone in ZONES}
    if seed % 2:
        # With NAT rules the access rules are written for the real addresses: what is compared then is the NAT rules.
        model.nat_rules = cisco_nat_model(random.Random(seed)).nat_rules
        for name, service in cisco_nat_model(random.Random(seed)).services.items():
            model.services.setdefault(name, service)
    report = Report()
    text = cli.convert(model, "fmc", report)
    config = CiscoConfig(text, zones=tuple(ZONES))
    fmc = FakeFmc()
    status, said = load_script(text, fmc, tmp_path)
    assert status == 0, (said, capsys.readouterr().err)
    assert "assigned to no device" in said[-1]
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))["created"]
    made = fmc.created()
    assert sorted(entry["name"] for entry in journal) == sorted(name for names in made.values() for name in names)
    assert made["policy/accesspolicies"] == ["FWShift"] and made["object/securityzones"] == config.plan["zones"]
    policy = fmc.store["policy/accesspolicies"][0]
    assert [rule["name"] for rule in fmc.rules[policy["id"]]] == [rule["name"] for rule in config.rules]
    back, back_report = read(fmc.dump(), "fmc")
    assert back.scope == "FWShift" and len(back.rules) == len(config.rules) and not [rule.name for rule in back.rules if rule.unsupported]
    lost = lost_rules(report)
    expected = Policy(vendor="panos", zones=model.zones, addresses=model.addresses, address_groups=model.address_groups,
                      services=model.services, service_groups=model.service_groups,
                      rules=[rule for rule in model.rules if rule.name not in lost])  # fmt: skip
    for pkt in packets(rng, 300 if not model.nat_rules else 0):
        if rng.random() < 0.5:
            aim(rng, model, pkt, rng.choice(model.rules))
        assert bool(model_verdict(back, pkt)) == bool(model_verdict(expected, pkt)) == config.allows(pkt), (seed, pkt)
    # The NAT rules come back as they were written: one per rule of the script, in its order.
    assert len(back.nat_rules) == len(config.nat) and not [nat.name for nat in back.nat_rules if nat.unsupported], back_report.to_text()
    assert bool(config.nat) == bool(seed % 2) and ("policy/ftdnatpolicies" in made) == bool(config.nat)
    again = Report()
    # (A port that an object of the manager already says is that object.)
    twice = CiscoConfig(cli.convert(back, "fmc", again), zones=tuple(ZONES), native=True, existing_ports=ports_there(back))
    for pkt in packets(rng, 200):
        if ":" not in pkt.src:
            aim(rng, model, pkt, rng.choice(model.nat_rules or model.rules))
            assert file_translation_plain(twice, pkt) == file_translation_plain(config, pkt), (seed, pkt)


def small_model() -> Policy:
    """A policy with a little of everything a script creates."""
    p = Policy(vendor="panos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.zones = {"inside": Zone("inside"), "outside": Zone("outside"), "dmz": Zone("dmz")}
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.0.1.0/24", "The LAN")
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.0.2.10/32")
    p.addresses["web-pub"] = Address("web-pub", AddressKind.NETWORK, "203.0.113.10/32")
    p.addresses["pool"] = Address("pool", AddressKind.RANGE, "203.0.113.100-203.0.113.110")
    p.addresses["updates"] = Address("updates", AddressKind.FQDN, "updates.example.com", fqdn_family=4)
    p.address_groups["servers"] = AddressGroup("servers", ["web", "10.0.2.11"])
    p.address_groups["all"] = AddressGroup("all", ["servers", "lan"])
    p.services["web-ports"] = Service("web-ports", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["alt"] = Service("alt", [ServiceEntry(Protocol.TCP, "8080")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.service_groups["both"] = ServiceGroup("both", ["web-ports", "ping"])

    def rule(name: str, **fields: Any) -> Rule:
        made = Rule(name=name, origin=name, **fields)
        p.rules.append(made)
        return made

    rule("out", src_zones=["inside"], dst_zones=["outside"], sources=["lan"], services=["web-ports"])
    rule("updates", src_zones=["inside"], dst_zones=["outside"], destinations=["updates"], services=["both"])
    rule("in", src_zones=["outside"], dst_zones=["dmz"], destinations=["web-pub"], services=["alt"])
    rule("mgmt", sources=["all"], services=["ping"], action=Action.DROP, log_end=False)
    p.nat_rules.append(NatRule("publish", origin="publish", src_zones=["outside"], destinations=["web-pub"], service="alt",
                               destination_translation=DestNat("web")))  # fmt: skip
    p.nat_rules.append(NatRule("hide", origin="hide", src_zones=["inside"], dst_zones=["outside"], sources=["lan"],
                               source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pool"])))  # fmt: skip
    return p


def test_the_script_looks_before_it_creates(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """--show needs no Management Center, --dry-run creates nothing, and a name that is taken stops the run before it starts."""
    from fwshift.emitters import fmc_loader

    text = cli.convert(small_model(), "fmc", Report())
    plan = CiscoConfig(text).plan
    said: List[str] = []
    assert fmc_loader.main(["--show"], say=said.append, plan=plan) == 0
    assert said[0] == "Access control policy 'FWShift': 4 rules, default action BLOCK" and "NAT policy 'FWShift': 2 rules" in said
    assert "security zones (used if they exist, created empty if not): outside, inside, dmz" in said and "2 network groups" not in said
    assert "1 network groups" in said and "1 network groups that hold groups (level 2)" in said
    assert "objects that must exist already: any-ipv4" in said
    assert fmc_loader.main([], say=said.append, plan=plan) == 1 and "--host and --user are needed" in capsys.readouterr().err

    fmc = FakeFmc()
    status, said = load_script(text, fmc, tmp_path, "--dry-run")
    assert status == 0 and "Nothing was created (--dry-run)." in said[-1] and not fmc.created() and not (tmp_path / "journal.json").exists()
    assert {method for method, _ in fmc.calls} == {"GET"}

    # A wrong password, and a domain the user does not have.
    assert load_script(text, fmc, tmp_path, password="guess")[0] == 1 and "refused the login (HTTP 401): Invalid username" in capsys.readouterr().err
    assert load_script(text, fmc, tmp_path, "--domain", "Global/Nowhere")[0] == 1
    assert "domain 'Global/Nowhere' is not one this user can use (there are: Global, Global/Lab)" in capsys.readouterr().err

    # An object of the same name, whatever its case and whatever kind of network object it is.
    fmc._create("object/ranges", {"type": "Range", "name": "LAN", "value": "10.9.0.1-10.9.0.9"})
    status, said = load_script(text, fmc, tmp_path)
    error = capsys.readouterr().err
    assert status == 1 and "1 object(s) this policy would create exist already: network object 'LAN'. Nothing was created." in error
    assert "--target-prefix" in error and fmc.created() == {"object/ranges": ["LAN"]} and not (tmp_path / "journal.json").exists()
    # With a prefix every object has a name of its own; the zones and the predefined object are used as they are.
    options = Options(object_prefix="mig-")
    text = cli.convert(small_model(), "fmc", Report(), options)
    assert load_script(text, fmc, tmp_path)[0] == 0
    assert "mig-lan" in fmc.created()["object/networks"] and fmc.created()["object/securityzones"] == ["outside", "inside", "dmz"]

    # A policy of that name exists now: nothing more is created, and the journal of the first run is not touched.
    (tmp_path / "journal.json").rename(tmp_path / "first.json")
    before = fmc.created()
    text = cli.convert(small_model(), "fmc", Report(), Options(object_prefix="again-"))
    assert load_script(text, fmc, tmp_path)[0] == 1 and "access control policy 'FWShift' exists already. Nothing was created" in capsys.readouterr().err
    assert fmc.created() == before
    assert load_script(text, fmc, tmp_path, "--name", "Second")[0] == 0 and fmc.created()["policy/accesspolicies"] == ["FWShift", "Second"]
    # A journal that is there is the trace of a run: it is not written over.
    assert load_script(text, fmc, tmp_path, "--name", "Third")[0] == 1 and "lists what an earlier run created" in capsys.readouterr().err


def test_the_script_counts_on_objects_that_must_be_there(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    text = cli.convert(small_model(), "fmc", Report())
    fmc = FakeFmc()
    fmc.store["object/networks"] = [obj for obj in fmc.store["object/networks"] if obj["name"] != "any-ipv4"]
    assert load_script(text, fmc, tmp_path)[0] == 1
    assert "counts on objects the Management Center does not have: Network 'any-ipv4'. Nothing was created" in capsys.readouterr().err
    assert not fmc.created()


def test_a_run_that_stops_leaves_a_journal_and_undo_takes_it_all_back(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    text = cli.convert(small_model(), "fmc", Report())
    fmc = FakeFmc()
    before = json.dumps(fmc.store, sort_keys=True)
    fmc.refuse = lambda method, path, body: "Invalid port" if method == "POST" and path == "object/portobjectgroups" else ""
    status, said = load_script(text, fmc, tmp_path)
    error = capsys.readouterr().err
    assert status == 1 and "POST object/portobjectgroups was refused (HTTP 422): Invalid port" in error
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))["created"]
    assert f"Stopped. {len(journal)} object(s) exist that this run created; they are listed in" in error and "--undo" in error
    made = fmc.created()
    assert sorted(entry["name"] for entry in journal) == sorted(name for names in made.values() for name in names) and len(journal) > 10
    assert "policy/accesspolicies" not in made  # the policy comes last: none was made of a part of its objects
    # Undo: the groups before what they hold, and nothing of what was there before.
    fmc.refuse = None
    status, said = load_script(text, fmc, tmp_path, "--undo")
    assert status == 0 and f"Of the {len(journal)} the run created, {len(journal)} were deleted" in said[-1], said
    assert json.dumps(fmc.store, sort_keys=True) == before and (tmp_path / "journal.json.undone").exists()
    # After a full run undo deletes the policies with their rules, and the zones it created.
    assert load_script(text, fmc, tmp_path)[0] == 0 and len(fmc.rules) == 1 and len(fmc.nat) == 1
    assert load_script(text, fmc, tmp_path, "--undo")[0] == 0
    assert json.dumps(fmc.store, sort_keys=True) == before and not fmc.rules and not fmc.nat
    # What is in use by something the run did not create stays, and is said.
    assert load_script(text, fmc, tmp_path)[0] == 0
    web = next(obj for obj in fmc.store["object/hosts"] if obj["name"] == "web")
    fmc._create("object/networkgroups", {"type": "NetworkGroup", "name": "by-hand", "objects": [{"type": "Host", "id": web["id"], "name": "web"}]})
    status, said = load_script(text, fmc, tmp_path, "--undo")
    assert status == 1 and any("NOT deleted: hosts 'web'" in line and "in use" in line for line in said) and "The journal is kept" in said[-1]
    assert fmc.created()["object/hosts"] == ["web"] and (tmp_path / "journal.json").exists()
    # Undo a second time: what is gone is said to be gone, not deleted again.
    fmc.store["object/networkgroups"] = [obj for obj in fmc.store["object/networkgroups"] if obj["name"] != "by-hand"]
    status, said = load_script(text, fmc, tmp_path, "--undo")
    assert status == 0 and "1 were deleted and" in said[-1] and "were not there any more" in said[-1] and not fmc.created()
    assert sum(1 for line in said if line.startswith("  was not there any more:")) == len(said) - 2
    # A journal says where its run was: it is not carried out against another Management Center or domain.
    assert load_script(text, fmc, tmp_path)[0] == 0
    data = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert (data["domain"], data["host"]) == (FakeFmc.DOMAIN, "")
    for key, value in (("domain", "another-domain"), ("host", "https://other.example.net")):
        (tmp_path / "journal.json").write_text(json.dumps({**data, key: value}), encoding="utf-8")
        before_undo = fmc.created()
        assert load_script(text, fmc, tmp_path, "--undo")[0] == 1 and "Nothing was deleted" in capsys.readouterr().err
        assert fmc.created() == before_undo
    # And a file that is no journal of this loader deletes nothing.
    for content in ('{"created": null}', '{"created": {}}', '{"created": [{"path": "policy/devicerecords", "id": "x", "name": "ftd1"}]}',
                    '{"created": [{"path": "object/hosts", "id": 5, "name": "web"}]}', "[]", "not json"):  # fmt: skip
        (tmp_path / "journal.json").write_text(content, encoding="utf-8")
        calls = len(fmc.calls)
        assert load_script(text, fmc, tmp_path, "--undo")[0] == 1 and fmc.created() == before_undo
        assert all(method != "DELETE" for method, _ in fmc.calls[calls:]) and "Traceback" not in capsys.readouterr().err


def sloppy(tmp_path: Any, **settings: Any) -> Tuple["FakeFmc", str, Any]:
    fmc = FakeFmc()
    for key, value in settings.items():
        setattr(fmc, key, value)
    return fmc, cli.convert(small_model(), "fmc", Report()), tmp_path / "journal.json"


def journaled(path: Any) -> List[str]:
    return sorted(entry["name"] for entry in json.loads(path.read_text(encoding="utf-8"))["created"])


def everything(fmc: "FakeFmc") -> List[str]:
    return sorted(name for names in fmc.created().values() for name in names)


def test_the_journal_is_true_whatever_the_answers_are(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """A call that was carried out and answered badly created what it created: the journal says so, and undo deletes it."""
    cases: List[Tuple[str, Callable[[str, str, int, bytes], Optional[Tuple[int, bytes]]], str]] = [
        ("an error after the networks were created", lambda m, path, status, raw: (500, b"Internal error") if m == "POST" and path == "object/networks" else None,
         "POST object/networks was refused (HTTP 500)"),
        ("a page of HTML for the hosts", lambda m, path, status, raw: (201, b"<html>proxy</html>") if m == "POST" and path == "object/hosts" else None,
         "the answer (HTTP 201) is not JSON"),
        ("half an answer for the policy", lambda m, path, status, raw: (201, raw[: len(raw) // 2]) if m == "POST" and path == "policy/accesspolicies" else None,
         "the answer (HTTP 201) is not JSON"),
        ("an answer without ids for the ranges", lambda m, path, status, raw: (201, b'{"items": [{"name": "pool"}]}') if m == "POST" and path == "object/ranges" else None,
         ""),
        ("an empty answer for a zone", lambda m, path, status, raw: (201, b"") if m == "POST" and path == "object/securityzones" else None, ""),
    ]  # fmt: skip
    for index, (label, after, message) in enumerate(cases):
        fmc, text, _ = sloppy(tmp_path, after=after)
        journal = tmp_path / f"journal{index}.json"
        status, said = load_script(text, fmc, tmp_path, "--journal", str(journal))
        error = capsys.readouterr().err
        assert (status == 1 and message in error) if message else status == 0, (label, error)
        # Whatever happened: what is on the Management Center and was not there before is what the journal lists.
        assert journaled(journal) == everything(fmc) and everything(fmc), label
        fmc.after = None
        assert load_script(text, fmc, tmp_path, "--journal", str(journal), "--undo")[0] == 0 and not fmc.created(), label


def test_the_script_takes_as_its_own_only_what_it_made(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    # A host of that name is there, the list did not show it, and the bulk call passed over it without a word.
    fmc, text, journal = sloppy(tmp_path, hidden=["web"], skip_existing=True)
    old = fmc._create("object/hosts", {"type": "Host", "name": "web", "value": "192.0.2.99"})
    status, said = load_script(text, fmc, tmp_path)
    error = capsys.readouterr().err
    assert status == 1 and "1 Host object(s) exist under names of this policy and are not what it sent" in error and "left alone: web" in error
    assert "web" not in journaled(journal) and old in fmc.store["object/hosts"] and "policy/accesspolicies" not in fmc.created()
    assert load_script(text, fmc, tmp_path, "--undo")[0] == 0 and fmc.created() == {"object/hosts": ["web"]} and old["value"] == "192.0.2.99"
    # An answer that names objects nobody sent gives the run nothing to delete later.
    fmc, text, journal = sloppy(tmp_path)
    other = fmc._create("object/hosts", {"type": "Host", "name": "someone-elses", "value": "192.0.2.50"})
    extra = json.dumps({"items": [{"name": "someone-elses", "id": other["id"], "type": "Host"}]}).encode()
    fmc.after = lambda m, path, status, raw: (201, raw[:-2] + b", " + extra[11:]) if m == "POST" and path == "object/hosts" else None
    assert load_script(text, fmc, tmp_path)[0] == 0 and "someone-elses" not in journaled(journal)
    assert load_script(text, fmc, tmp_path, "--undo")[0] == 0 and fmc.created() == {"object/hosts": ["someone-elses"]}


def test_the_script_checks_the_rules_it_made(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    # The Management Center took the rules that allow and left the others out, and said "created".
    fmc, text, journal = sloppy(tmp_path, keep_rule=lambda rule: rule.get("action") != "BLOCK")
    status, said = load_script(text, fmc, tmp_path)
    error = capsys.readouterr().err
    assert status == 1 and "the access control policy 'FWShift' holds 3 rules and 4 were sent: it is not the policy that was converted" in error
    assert "FWShift" in journaled(journal) and "--undo" in error and not any(line.startswith("Done") for line in said)
    # It stored them in another order.
    fmc, text, _ = sloppy(tmp_path, reverse_rules=True)
    status, said = load_script(text, fmc, tmp_path, "--journal", str(tmp_path / "second.json"))
    error = capsys.readouterr().err
    assert status == 1 and "lists its rules in another order than they were sent (rule 1 is 'mgmt', not 'out')" in error
    # NAT rules have no names: their number is what can be checked.
    fmc, text, _ = sloppy(tmp_path, keep_rule=lambda rule: rule.get("type") != "FTDManualNatRule" or rule.get("natType") == "STATIC")
    status, said = load_script(text, fmc, tmp_path, "--journal", str(tmp_path / "third.json"))
    assert status == 1 and "the NAT policy 'FWShift' holds 1 rules and 2 were sent" in capsys.readouterr().err


def test_the_journal_is_there_before_anything_is_created(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    from fwshift.emitters import fmc_loader

    fmc, text, _ = sloppy(tmp_path)
    for arguments, message in (
        (["--journal", str(tmp_path / "no-such-directory" / "journal.json")], "could not be written"),
        (["--journal", str(tmp_path)], "exists"),
        (["--name", "n" * 300], "is not a name for a policy"),
        (["--name", "semi;colon"], "is not a name for a policy"),
        (["--name", " padded "], "is not a name for a policy"),
    ):  # fmt: skip
        status, said = load_script(text, fmc, tmp_path, *arguments)
        error = capsys.readouterr().err
        assert status == 1 and message in error and "Traceback" not in error and not fmc.created(), (arguments, error)
        assert all(method == "GET" for method, _ in fmc.calls)
    # A run that was refused its first object leaves no journal behind: there is nothing to undo.
    fmc.refuse = lambda method, path, body: "no" if method == "POST" else ""
    status, said = load_script(text, fmc, tmp_path)
    assert status == 1 and "Stopped. Nothing was created." in capsys.readouterr().err and not (tmp_path / "journal.json").exists()
    # The journal cannot be written any more half way: said, with what is not in it.
    fmc, text, journal = sloppy(tmp_path)
    plan = CiscoConfig(text).plan
    saves: List[int] = []
    real = fmc_loader.Run.save

    def failing(self: Any) -> None:
        saves.append(len(self.made))
        if len(saves) > 3:
            raise fmc_loader.Stop("the journal could not be written (disk full)")
        real(self)

    fmc_loader.Run.save = failing  # type: ignore[method-assign]
    try:
        os.environ["FMC_PASSWORD"] = "secret"
        status = fmc_loader.main(["--host", "fmc.example.net", "--user", "api", "--journal", str(journal)], transport=fmc, say=lambda line: None, plan=plan)
    finally:
        fmc_loader.Run.save = real  # type: ignore[method-assign]
        del os.environ["FMC_PASSWORD"]
    error = capsys.readouterr().err
    assert status == 1 and "Created and NOT in the journal, which could not be written: " in error
    missing = sorted(set(everything(fmc)) - set(journaled(journal)))
    assert missing and all(f"'{name}'" in error for name in missing)
    # The journal is replaced in one step: no half-written file under its name, and nothing left next to it.
    assert json.loads(journal.read_text(encoding="utf-8"))["format"] == 1 and not (tmp_path / "journal.json.tmp").exists()


def test_zones_that_exist_under_another_spelling_or_as_something_else(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    fmc, text, journal = sloppy(tmp_path)
    there = fmc._create("object/securityzones", {"type": "SecurityZone", "name": "DMZ", "interfaceMode": "ROUTED"})
    status, said = load_script(text, fmc, tmp_path)
    assert status == 0 and "  security zone 'dmz' exists as 'DMZ': that one is used" in said, capsys.readouterr().err
    assert sorted(fmc.created()["object/securityzones"]) == ["DMZ", "inside", "outside"] and "dmz" not in journaled(journal)
    policy = fmc.store["policy/accesspolicies"][0]
    assert fmc.rules[policy["id"]][2]["destinationZones"]["objects"] == [{"type": "SecurityZone", "name": "DMZ", "id": there["id"]}]
    # An interface group has the name: no zone can, and that is known before anything is created.
    fmc, text, journal = sloppy(tmp_path)
    fmc._create("object/interfacegroups", {"type": "InterfaceGroup", "name": "Inside", "interfaceMode": "ROUTED"})
    status, said = load_script(text, fmc, tmp_path, "--journal", str(tmp_path / "second.json"))
    error = capsys.readouterr().err
    assert status == 1 and "'Inside' is an interface group, and the policy names a security zone 'inside'" in error and "Nothing was created" in error
    assert fmc.created() == {"object/interfacegroups": ["Inside"]}


def test_a_policy_that_was_changed_by_hand_is_not_run_half_way(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    from fwshift.emitters import fmc_loader

    plan = CiscoConfig(cli.convert(small_model(), "fmc", Report())).plan
    changes: List[Callable[[Dict[str, Any]], Any]] = [
        lambda p: p["steps"][0]["items"].append("text"), lambda p: p["steps"][0].update(items=None), lambda p: p["steps"][0].update(items={}),
        lambda p: p.update(rules=5), lambda p: p.update(zones=5), lambda p: p.update(zones=None), lambda p: p.update(zones=[5]),
        lambda p: p.update(existing=["any-ipv4"]), lambda p: p.update(existing=None), lambda p: p.update(existing={}), lambda p: p.update(nat="x"),
        lambda p: p["rules"][0].pop("name"), lambda p: p["steps"][0]["items"][0].pop("name"), lambda p: p.update(policy=5), lambda p: p.update(format=2),
        # A step that would post somewhere else than to the collection of its objects.
        lambda p: p["steps"][0].update(path="devices/devicerecords"), lambda p: p["steps"][0].update(path="../../fmc_platform/v1/auth/revokeaccess"),
        lambda p: p["steps"][0].update(type="AccessPolicy", path="policy/accesspolicies"), lambda p: p["steps"].append("x"),
    ]  # fmt: skip
    for index, change in enumerate(changes):
        mine = json.loads(json.dumps(plan))
        change(mine)
        fmc = FakeFmc()
        os.environ["FMC_PASSWORD"] = "secret"
        try:
            for arguments in (["--show"], ["--host", "fmc.example.net", "--user", "api", "--journal", str(tmp_path / f"j{index}.json")]):
                assert fmc_loader.main(arguments, transport=fmc, say=lambda line: None, plan=mine) == 1, index
                assert "is not in the form this loader reads" in capsys.readouterr().err
        finally:
            del os.environ["FMC_PASSWORD"]
        assert not fmc.calls and fmc.logins == 0


def test_the_script_waits_logs_in_again_and_keeps_the_order(tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from fwshift.emitters import fmc_loader

    waited: List[float] = []
    monkeypatch.setattr(fmc_loader.time, "sleep", waited.append)
    model = small_model()
    for index in range(40):
        model.addresses[f"h{index}"] = Address(f"h{index}", AddressKind.NETWORK, f"10.7.0.{index}/32")
        model.rules.append(Rule(name=f"rule {index}", origin=f"rule {index}", sources=[f"h{index}"], action=Action.DROP if index % 3 else Action.ALLOW))
    text = cli.convert(model, "fmc", Report())
    fmc = FakeFmc()
    fmc.page_limit = 5  # it gives less per page than it is asked for
    fmc.throttle, fmc.expire = [3, 4, 30], [10, 40]
    monkeypatch.setattr(fmc_loader, "BULK_ITEMS", 7)
    status, said = load_script(text, fmc, tmp_path)
    assert status == 0, capsys.readouterr().err
    assert waited == [1.0, 1.0, 1.0] and fmc.logins == 3
    policy = fmc.store["policy/accesspolicies"][0]
    assert [rule["name"] for rule in fmc.rules[policy["id"]]] == [rule["name"] for rule in CiscoConfig(text).rules]
    assert [rule["metadata"]["ruleIndex"] for rule in fmc.rules[policy["id"]]] == list(range(1, 45))
    posts = [path for method, path in fmc.calls if method == "POST" and "accessrules" in path]
    assert len(posts) >= 7  # seven rules a call, and the calls that had to be made again
    assert len(fmc.store["object/hosts"]) == 43 and sum(1 for method, path in fmc.calls if method == "POST" and "object/hosts" in path) >= 7
    # Asked too often without end: the run gives up, and says what it had made.
    fmc2 = FakeFmc()
    fmc2.throttle = list(range(20, 200))
    status, said = load_script(text, fmc2, tmp_path, "--journal", str(tmp_path / "second.json"))
    assert status == 1 and "kept answering that it is asked too often" in capsys.readouterr().err


def test_the_script_is_a_program_and_its_policy_is_data(tmp_path: Any) -> None:
    """Whatever a name or a description holds, it stays inside the comment lines the policy is in."""
    import subprocess
    import sys

    model = small_model()
    model.rules[0].description = "quote ''' and \"\"\" and \\ and\n#: {\"format\": 2}\nimport os; os.system('true') next"
    model.addresses["lan"].description = "line\rbreak é中"
    text = cli.convert(model, "fmc", Report())
    compile(text, "script.py", "exec")
    lines = text.split("\n")
    start = lines.index("# The policy, as data. Do not change it here: convert again.")
    assert all(line.startswith("#") for line in lines[start:] if line) and text.isascii() and "\r" not in text
    config = CiscoConfig(text)
    assert "import os; os.system('true')" in config.rules[0]["comment"] and config.plan["format"] == 1
    script = tmp_path / "load-policy.py"
    script.write_text(text, encoding="utf-8")
    shown = subprocess.run([sys.executable, str(script), "--show"], capture_output=True, text=True, timeout=60)
    assert shown.returncode == 0 and shown.stdout.startswith("Access control policy 'FWShift': 4 rules"), shown.stderr
    plan = subprocess.run([sys.executable, str(script), "--plan"], capture_output=True, text=True, timeout=60)
    assert json.loads(plan.stdout) == config.plan
    # Read through a pager that is closed after the first line: an end, not a traceback.
    from fwshift.emitters import fmc_loader

    def closed(line: str) -> None:
        raise BrokenPipeError(32, "Broken pipe")

    assert fmc_loader.main(["--show"], say=closed, plan=config.plan) == 1
    nowhere = subprocess.run([sys.executable, str(script), "--host", "http://192.0.2.1", "--user", "api"], capture_output=True, text=True,
                             timeout=60, env={**os.environ, "FMC_PASSWORD": "x"})  # fmt: skip
    assert nowhere.returncode == 1 and "only https is used" in nowhere.stderr
    # The loader without a policy says so.
    from fwshift.emitters import cisco as emit_cisco

    bare = tmp_path / "bare.py"
    bare.write_text(emit_cisco.loader_source(), encoding="utf-8")
    alone = subprocess.run([sys.executable, str(bare), "--show"], capture_output=True, text=True, timeout=60)
    assert alone.returncode == 1 and "holds no policy" in alone.stderr


def test_the_script_talks_http_to_a_management_center(tmp_path: Any) -> None:
    """The same run through sockets: the script as a file, the made-up Management Center behind a web server."""
    import http.server
    import subprocess
    import sys
    import threading

    fmc = FakeFmc()

    class Handler(http.server.BaseHTTPRequestHandler):
        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            headers = {key: value for key, value in self.headers.items()}
            status, answered, raw = fmc.send(self.command, self.path, headers, body)
            self.send_response(status)
            for key, value in answered.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = do_POST = do_DELETE = _serve

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        script = tmp_path / "load-policy.py"
        script.write_text(cli.convert(small_model(), "fmc", Report()), encoding="utf-8")
        command = [sys.executable, str(script), "--host", f"http://127.0.0.1:{server.server_address[1]}", "--user", "api"]
        run = subprocess.run(command, capture_output=True, text=True, timeout=120, cwd=tmp_path, env={**os.environ, "FMC_PASSWORD": "secret"})
        assert run.returncode == 0 and "Done. What was created is listed in fwshift-fmc-FWShift.journal.json" in run.stdout, run.stderr
        assert fmc.created()["policy/accesspolicies"] == ["FWShift"] and len(fmc.rules) == 1
        back, _ = read(fmc.dump(), "fmc")
        assert [rule.name for rule in back.rules] == ["out", "updates", "in", "mgmt"] and len(back.nat_rules) == 2
        undo = subprocess.run(command + ["--undo"], capture_output=True, text=True, timeout=120, cwd=tmp_path, env={**os.environ, "FMC_PASSWORD": "secret"})
        assert undo.returncode == 0 and not fmc.created(), undo.stdout + undo.stderr
    finally:
        server.shutdown()
        server.server_close()


# -- what is read, case by case ----------------------------------------------------------------


def one_rule(m: Manager, p: Policy, name: str) -> Rule:
    found = [rule for rule in p.rules if rule.name == name]
    assert len(found) == 1, (name, [rule.name for rule in p.rules])
    return found[0]


@pytest.mark.parametrize("fdm", [False, True])
def test_objects_as_they_are_read(fdm: bool) -> None:
    m = Manager(fdm)
    host, net = m.host("srv", "10.1.2.3", description="A server"), m.network("lan", "10.1.0.0/16")
    span, six = m.range("pool", "10.2.0.10-10.2.0.20"), m.network("six", "2001:db8:5::/64")
    names = [m.fqdn("both", "www.example.com"), m.fqdn("four", "v4.example.com", "IPV4_ONLY"), m.fqdn("sixonly", "v6.example.com", "IPV6_ONLY")]
    system = {"isSystemDefined": True} if fdm else {"metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}}}
    every, reserved = m.network("any-ipv4", "0.0.0.0/0", **system), m.host("any", "10.9.9.9")
    inner = m.group("inner", [host, span])
    outer = m.group("outer", [inner, net, six]) if fdm else m.group("outer", [inner, net], ["2001:db8:5::/64", "10.3.0.1", "10.4.0.1-10.4.0.9"])
    bad = [m.host("masked", "10.1.2.3/24"), m.network("bare", "10.5.0.0"), m.range("backwards", "10.2.0.20-10.2.0.10"),
           m.fqdn("address", "10.1.1.1"), m.host("nothing", "")]  # fmt: skip
    m.rule("all", sources=[host, net, span, six, every, reserved, outer] + names, destinations=bad)
    p, report = read(m.api())
    assert (p.addresses["srv"].value, p.addresses["srv"].description, p.addresses["srv"].kind) == ("10.1.2.3/32", "A server", AddressKind.NETWORK)
    assert p.addresses["lan"].value == "10.1.0.0/16" and p.addresses["six"].value == "2001:db8:5::/64"
    assert (p.addresses["pool"].kind, p.addresses["pool"].value) == (AddressKind.RANGE, "10.2.0.10-10.2.0.20")
    assert [(p.addresses[n].kind, p.addresses[n].value, p.addresses[n].fqdn_family) for n in ("both", "four", "sixonly")] == [
        (AddressKind.FQDN, "www.example.com", 0), (AddressKind.FQDN, "v4.example.com", 4), (AddressKind.FQDN, "v6.example.com", 6)]
    assert p.addresses["any-ipv4"].builtin == p.vendor and p.addresses["srv"].builtin == ""
    # A name that means every address in the model is not kept for an object.
    assert "any" not in p.addresses and p.addresses["any-object"].value == "10.9.9.9/32" and "RENAMED" in codes(report, "address", "any-object")
    assert p.address_groups["inner"].members == ["srv", "pool"]
    assert p.address_groups["outer"].members == (["inner", "lan", "six"] if fdm else ["inner", "lan", "2001:db8:5::/64", "10.3.0.1", "10.4.0.1-10.4.0.9"])
    for name in ("masked", "bare", "backwards", "address", "nothing"):
        assert p.addresses[name].kind == AddressKind.UNSUPPORTED and codes(report, "address", name) == ["UNSUPPORTED_ADDRESS"], name
    rule = one_rule(m, p, "all")
    assert rule.sources == ["srv", "lan", "pool", "six", "any-ipv4", "any-object", "outer", "both", "four", "sixonly"] and not rule.unsupported
    # The rule that names what could not be read is not converted, on any target.
    for target in ("panos", "fmc", "fdm"):
        out = Report()
        cli.convert(p, target, out)
        assert "UNCONVERTIBLE_OBJECT" in codes(out, "rule", "all") and (out.item("rule", "all").disabled or out.item("rule", "all").skipped)


def test_objects_that_are_not_in_the_input_or_are_no_addresses() -> None:
    m = Manager()
    known = m.host("known", "10.1.1.1")
    missing = {"type": "Network", "id": "0000-missing", "name": "elsewhere"}
    country = {"type": "Country", "id": "76", "name": "Belgium"}
    group = m.group("mixed", [known, missing])
    m.rule("gone", sources=[missing], action="BLOCK")
    m.rule("geo", destinations=[country, known])
    m.rule("through-group", sources=[group])
    m.rule("no-name", sources=[{"type": "Host"}])
    m.rule("fine", sources=[known], dst_ports=[{"type": "ProtocolPortObject", "id": "0000-port", "name": "lost-port"}])
    p, report = read(m.api())
    assert p.addresses["elsewhere"].kind == AddressKind.UNSUPPORTED and "not in the input in full" in p.addresses["elsewhere"].raw
    assert "of type 'Country', which has no addresses to read" in p.addresses["Belgium"].raw
    assert p.address_groups["mixed"].members == ["known", "elsewhere"]
    assert one_rule(m, p, "no-name").unsupported == ["a reference without a name"] and one_rule(m, p, "no-name").sources == [ANY]
    assert p.services["lost-port"].unsupported.startswith("port object 'lost-port', which is not in the input in full")
    out = Report()
    config = CiscoConfig(cli.convert(p, "fmc", out))
    # Nothing that is missing is read as "any": every one of these rules is written disabled.
    assert [rule["name"] for rule in config.rules if not rule["enabled"]] == ["gone", "geo", "through-group", "no-name", "fine"]
    assert all(rule["comment"].startswith("FWSHIFT: disabled by the converter") for rule in config.rules)
    assert "This deny rule is NOT enforced" in out.item("rule", "gone").findings[0].message


@pytest.mark.parametrize("fdm", [False, True])
def test_ports_as_they_are_read(fdm: bool) -> None:
    m = Manager(fdm)
    made = {
        "one": m.tcp("one", "443"), "span": m.udp("span", "5000-5010"), "ping": m.icmp("ping", "ECHO_REQUEST" if fdm else 8),
        "every-icmp": m.icmp("every-icmp"), "coded": m.icmp("coded", "DESTINATION_UNREACHABLE" if fdm else "3", "PORT_UNREACHABLE" if fdm else "3"),
        "ping6": m.icmp("ping6", "ECHO_REQUEST" if fdm else 128, six=True), "tunnel": m.protocol("tunnel", "GRE"),
        "ospf": m.protocol("ospf", "OSPFIGP"), "sctp": m.protocol("sctp", "SCTP"),
    }  # fmt: skip
    group = m.port_group("several", [made["one"], made["ping"], made["tunnel"]])
    m.rule("r", dst_ports=list(made.values()) + [group])
    p, report = read(m.api())
    entry = {name: p.services[name].entries[0] for name in made}
    assert (entry["one"].protocol, entry["one"].dst_ports, entry["one"].src_ports) == (Protocol.TCP, "443", "")
    assert (entry["span"].protocol, entry["span"].dst_ports) == (Protocol.UDP, "5000-5010")
    assert (entry["ping"].protocol, entry["ping"].icmp_type, entry["ping"].icmp_code) == (Protocol.ICMP, 8, None)
    assert (entry["every-icmp"].protocol, entry["every-icmp"].icmp_type) == (Protocol.ICMP, None)
    assert (entry["coded"].icmp_type, entry["coded"].icmp_code) == (3, 3)
    assert (entry["ping6"].protocol, entry["ping6"].icmp_type) == (Protocol.ICMP6, 128)
    assert (entry["tunnel"].protocol, entry["tunnel"].ip_protocol) == (Protocol.IP, 47) and entry["ospf"].ip_protocol == 89
    assert entry["sctp"].protocol == Protocol.SCTP and not entry["sctp"].dst_ports
    assert p.service_groups["several"].members == ["one", "ping", "tunnel"]
    assert one_rule(m, p, "r").services == list(made) + ["several"] and not report.needs_review


def test_ports_of_a_management_center_in_other_spellings() -> None:
    m = Manager()
    made = [m.tcp("all-tcp", ""), m.protocol("by-number", "17", port="53"), m.protocol("named-icmp", "ICMP"),
            m.protocol("six-icmp", "IPv6-ICMP"), m.protocol("esp", "50"), m.protocol("numbers", 6, port=8080)]  # fmt: skip
    literals = [plit(6, "22"), plit(17), plit(47), {"type": "PortLiteral", "protocol": "1", "icmpType": "Any"},
                {"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": "3", "code": "1"}, {"type": "PortLiteral", "protocol": "TCP", "port": "80"}]  # fmt: skip
    m.rule("r", dst_ports=made + literals)
    p, report = read(m.api())
    rule = one_rule(m, p, "r")
    assert rule.services == ["all-tcp", "by-number", "named-icmp", "six-icmp", "esp", "numbers", "tcp-22", "udp-all", "gre", "icmp-all",
                             "icmp-3-1", "tcp-80"] and not rule.unsupported  # fmt: skip
    entries = {name: p.services[name].entries[0] for name in rule.services}
    assert (entries["all-tcp"].protocol, entries["all-tcp"].dst_ports) == (Protocol.TCP, "")
    assert (entries["by-number"].protocol, entries["by-number"].dst_ports) == (Protocol.UDP, "53")
    assert entries["named-icmp"].protocol == Protocol.ICMP and entries["six-icmp"].protocol == Protocol.ICMP6
    assert entries["esp"].ip_protocol == 50 and entries["numbers"].dst_ports == "8080" and entries["icmp-3-1"].icmp_code == 1


@pytest.mark.parametrize("fields,why", [
    ({"protocol": "IP"}, "protocol 'IP'"), ({"protocol": "0"}, "protocol '0'"), ({"protocol": "TCP", "port": "80,443"}, "port '80,443'"),
    ({"protocol": "TCP", "port": "http"}, "port 'http'"), ({"protocol": "TCP", "port": "70000"}, "port '70000'"),
    ({"protocol": "GRE", "port": "5"}, "a port (5) for IP protocol 47"), ({"protocol": "SCTP", "port": "2905"}, "a port (2905) for IP protocol 132"),
    ({"protocol": "Banyan"}, "protocol 'Banyan'"), ({"protocol": "300"}, "protocol '300'"), ({"protocol": ["TCP"], "port": "80"}, "protocol ''"),
])  # fmt: skip
def test_port_objects_that_are_not_understood_make_their_rules_unusable(fields: Dict[str, Any], why: str) -> None:
    m = Manager()
    odd = m._add("object/protocolportobjects", "ProtocolPortObject", "odd", **fields)
    m.rule("uses-it", dst_ports=[odd])
    m.rule("literal", dst_ports=[{"type": "PortLiteral", **fields}])
    p, report = read(m.api())
    assert p.services["odd"].unsupported.startswith(why) and not p.services["odd"].entries, p.services["odd"]
    assert one_rule(m, p, "uses-it").unsupported == [] and one_rule(m, p, "literal").unsupported[0].startswith(why)
    out = Report()
    cli.convert(p, "panos", out)
    assert out.item("rule", "uses-it").disabled and out.item("rule", "literal").disabled


def test_names_of_a_device_manager_that_are_not_known() -> None:
    m = Manager(fdm=True)
    bad = [m.icmp("new-type", "EXTENDED_ECHO_REQUEST"), m.icmp("wrong-code", "ECHO_REQUEST", "PORT_UNREACHABLE"),
           m.icmp("code-of-any", None, "NET_UNREACHABLE"), m.protocol("divert", "DIVERT"), m.protocol("lower", "gre"),
           m.icmp("exp6", "PRIVATE_EXPERIMENTATION", six=True), m.tcp("list", "80,443"), m.tcp("empty", ""), m.tcp("null", "1"),
           m.tcp("word", "any"), m.tcp("false", "1")]  # fmt: skip
    bad[8]["port"], bad[10]["port"] = None, False
    fine = [m.icmp("any-code", "ECHO_REQUEST", "ANY_IPV4"), m.icmp("any6", "ANY", "ANY_IPV6", six=True)]
    m.rule("bad", dst_ports=bad)
    m.rule("fine", dst_ports=fine)
    p, report = read(m.export())
    assert [bool(p.services[obj["name"]].unsupported) for obj in bad] == [True] * 11
    assert "is not a type FWShift knows the number of" in p.services["new-type"].unsupported
    assert "is not a code of type ECHO_REQUEST" in p.services["wrong-code"].unsupported
    assert p.services["any-code"].entries[0].icmp_type == 8 and p.services["any6"].entries[0].protocol == Protocol.ICMP6
    # A port object of a Device Manager says its port, also when that is every port (1-65535): one without is not read as that.
    assert p.services["empty"].unsupported == p.services["null"].unsupported == "port object without a port"
    every = Manager(fdm=True)
    every.rule("r", dst_ports=[every.tcp("all", "1-65535")])
    assert read(every.export())[0].services["all"].entries[0].dst_ports == "1-65535"
    # The names stand for the numbers of the IANA registries.
    from fwshift.appmap import FDM_ICMP6_TYPES, FDM_ICMP_CODES, FDM_ICMP_TYPES, FDM_PROTOCOLS

    assert (FDM_ICMP_TYPES["ECHO_REQUEST"], FDM_ICMP_TYPES["ECHO_REPLY"], FDM_ICMP_TYPES["TIME_EXCEEDED"], FDM_ICMP_TYPES["TRACEROUTE"]) == (8, 0, 11, 30)
    assert (FDM_ICMP6_TYPES["ECHO_REQUEST"], FDM_ICMP6_TYPES["NEIGHBOUR_SOLICITATION"], FDM_ICMP6_TYPES["PACKET_TOO_BIG"]) == (128, 135, 2)
    assert FDM_ICMP_CODES["PORT_UNREACHABLE"] == (3, 3) and FDM_ICMP_CODES["FRAG_ASSEMBLY"] == (11, 1)
    assert [FDM_PROTOCOLS[n] for n in ("IGMP", "TCP", "UDP", "GRE", "ESP", "AH", "EIGRP", "OSPFIGP", "PIM", "VRRP", "L2TP", "SCTP", "IPIP")] == [
        2, 6, 17, 47, 50, 51, 88, 89, 103, 112, 115, 132, 94]
    assert len(set(FDM_PROTOCOLS.values())) == len(FDM_PROTOCOLS) and all(0 < number < 255 for number in FDM_PROTOCOLS.values())


def test_source_and_destination_ports_must_both_match() -> None:
    m = Manager()
    web, dns, any_udp, ping = m.tcp("web", "80"), m.udp("dns", "53"), m.udp("udp", ""), m.icmp("ping", 8)
    group = m.port_group("two", [web, m.tcp("tls", "443")])
    m.rule("from-dns", src_ports=[dns])
    m.rule("dns-to-high", src_ports=[dns], dst_ports=[plit(17, "1024-65535"), any_udp])
    m.rule("high-to-web", src_ports=[plit(6, "1024-65535")], dst_ports=[group])
    m.rule("two-protocols", src_ports=[dns], dst_ports=[web])
    m.rule("mixed", src_ports=[dns, plit(6, "53")], dst_ports=[web, dns])
    m.rule("icmp-source", src_ports=[ping], dst_ports=[web])
    p, report = read(m.api())

    def entries(name: str) -> List[Tuple[str, str, str]]:
        rule = one_rule(m, p, name)
        assert len(rule.services) == 1 and not rule.unsupported, rule
        return [(e.protocol.value, e.src_ports, e.dst_ports) for e in p.services[rule.services[0]].entries]

    assert entries("from-dns") == [("udp", "53", "")]
    assert entries("dns-to-high") == [("udp", "53", ""), ("udp", "53", "1024-65535")]  # the objects of a condition, then what it spells out
    assert entries("high-to-web") == [("tcp", "1024-65535", "80"), ("tcp", "1024-65535", "443")]
    # A source port of one protocol and a destination port of another are never both there.
    assert entries("mixed") == [("udp", "53", "53"), ("tcp", "53", "80")]
    assert one_rule(m, p, "two-protocols").unsupported == ["source ports and destination ports that share no protocol"]
    assert one_rule(m, p, "icmp-source").unsupported == ["source port 'ping', which is not a TCP or UDP port"]


CONDITIONS = [
    ({"applications": {"applications": [{"type": "Application", "id": "1", "name": "HTTP"}]}}, "an application condition"),
    ({"applications": {"inlineApplicationFilters": [{"risks": [{"id": "5", "name": "Very High"}]}]}}, "an application condition"),
    ({"urls": {"urlCategoriesWithReputation": [{"type": "UrlCategoryAndReputation", "category": {"name": "Gambling"}}]}}, "a URL condition"),
    ({"urls": {"literals": [{"type": "Url", "url": "example.com"}]}}, "a URL condition"),
    ({"vlanTags": {"literals": [{"type": "VlanTagLiteral", "startTag": 10, "endTag": 20}]}}, "a VLAN tag condition"),
    ({"sourceSecurityGroupTags": {"objects": [{"type": "SecurityGroupTag", "name": "Staff", "id": "s"}]}}, "a security group tag as source"),
    ({"destinationSecurityGroupTags": {"objects": [{"type": "SecurityGroupTag", "name": "Srv", "id": "s"}]}}, "a security group tag as destination"),
    ({"sourceDynamicObjects": {"objects": [{"type": "DynamicObject", "name": "dyn", "id": "d"}]}}, "a dynamic object as source"),
    ({"destinationDynamicObjects": {"objects": [{"type": "DynamicObject", "name": "dyn", "id": "d"}]}}, "a dynamic object as destination"),
    ({"originalSourceNetworks": {"literals": [{"type": "Host", "value": "10.1.1.1"}]}}, "a condition on the original client address"),
    ({"endPointDeviceTypes": [{"type": "EndPointDeviceType", "name": "Android", "id": "e"}]}, "an endpoint device type condition"),
    ({"somethingNew": {"objects": [{"name": "x"}]}}, "field 'somethingNew', which FWShift does not know"),
    ({"newSwitch": True}, "field 'newSwitch', which FWShift does not know"),
    ({"sourceNetworks": {"objects": [], "geoLocations": [{"name": "BE"}]}}, "'geoLocations' in the source networks"),
    ({"sourceNetworks": "10.1.1.1"}, "source networks that could not be read"),
    ({"sourceNetworks": {"literals": [{"type": "Host", "value": "ten.one.one.one"}]}}, "address 'ten.one.one.one'"),
    ({"sourceZones": {"objects": [{"type": "TunnelTag", "name": "gre-tunnels", "id": "t"}]}}, "tunnel zone 'gre-tunnels': the rule is for connections inside a tunnel"),
    ({"sourceZones": {"objects": [{"type": "InterfaceGroup", "name": "grp", "id": "g"}]}}, "'grp' of type 'interfacegroup' where a security zone is expected"),
    ({"sourceZones": {"literals": [{"value": "inside"}]}}, "source zones given as something else than zones"),
    ({"enabled": "yes"}, "rule that does not say whether it is enabled"),
    ({"action": "ALLOW_WITH_WARNING"}, "action 'ALLOW_WITH_WARNING', which FWShift does not know"),
    ({"destinationPorts": {"literals": [{"type": "EtherTypeLiteral", "value": "0x0806"}]}}, "port of type 'ethertypeliteral'"),
]  # fmt: skip


@pytest.mark.parametrize("fields,why", CONDITIONS)
def test_what_is_not_understood_makes_the_rule_unusable(fields: Dict[str, Any], why: str) -> None:
    """A condition FWShift does not convert, or does not know, never turns into "any"."""
    m = Manager()
    m.rule("odd", sources=["10.1.0.0/16"]).update(fields)
    m.rule("below", "BLOCK")
    p, report = read(m.api())
    rule = one_rule(m, p, "odd")
    assert rule.unsupported == [why], rule.unsupported
    assert rule.action == (Action.DENY if "action" in fields else Action.ALLOW)
    for target in ("fmc", "fdm", "asa"):
        out = Report()
        text = cli.convert(p, target, out)
        assert out.item("rule", "odd").disabled or out.item("rule", "odd").skipped, target
        if target != "asa":
            assert [rule["name"] for rule in CiscoConfig(text).rules if rule["enabled"]] == ["below"]


def test_conditions_that_are_there_and_say_nothing() -> None:
    m = Manager()
    empty: Dict[str, Any] = {"applications": {}, "urls": {"objects": [], "literals": []}, "vlanTags": None, "users": {"objects": []},
                             "sourceNetworks": {"objects": [], "literals": []}, "destinationPorts": {}, "timeRangeObjects": [],
                             "sourceDynamicObjects": {"type": "x", "links": {"self": "y"}}, "newSwitch": False, "somethingNew": []}  # fmt: skip
    m.rule("plain", **empty)
    fdm = Manager(fdm=True)
    fdm.rule("plain", embeddedAppFilter={"applications": [], "applicationFilters": [], "conditions": [], "type": "embeddedappfilter"},
             urlFilter={"urlObjects": [], "urlCategories": [], "type": "embeddedurlfilter"})  # fmt: skip
    for data in (m.api(), fdm.api(), fdm.export()):
        p, report = read(data)
        rule = p.rules[0]
        assert not rule.unsupported and rule.sources == rule.destinations == rule.services == rule.src_zones == [ANY] and rule.users == [ANY]


def test_users_time_ranges_logging_and_what_else_a_rule_says() -> None:
    m = Manager()
    web = m.tcp("web", "80")
    m.rule("staff", users={"objects": [{"type": "RealmUserGroup", "name": "CORP\\staff", "id": "u1"}, {"type": "RealmUser", "name": "CORP\\ann", "id": "u2"}]})
    m.rule("hours", timeRangeObjects=[{"type": "TimeRange", "name": "office-hours", "id": "t1"}], dst_ports=[web])
    m.rule("inspected", log="both", description="Web out", ipsPolicy={"type": "IntrusionPolicy", "name": "Balanced", "id": "i"},
           filePolicy={"type": "FilePolicy", "name": "Malware", "id": "f"}, metadata={"ruleIndex": 3, "section": "Mandatory", "category": "Web"})  # fmt: skip
    m.rule("commented", log="none", commentHistoryList=[{"comment": "first", "user": {"name": "a"}}, {"comment": "second"}])
    m.rule("trusted", "TRUST")
    m.rule("reset", "BLOCK_RESET")
    m.rule("page", "BLOCK_RESET_INTERACTIVE")
    m.rule("off", enabled=False)
    p, report = read(m.api())
    assert one_rule(m, p, "staff").users == ["CORP\\staff", "CORP\\ann"] and one_rule(m, p, "hours").schedule == "office-hours"
    inspected = one_rule(m, p, "inspected")
    assert (inspected.log_start, inspected.log_end, inspected.description, inspected.tags) == (True, True, "Web out", ["Web"])
    assert inspected.profiles == {"intrusion": "Balanced", "file": "Malware"}
    commented = one_rule(m, p, "commented")
    assert (commented.log_start, commented.log_end, commented.description, commented.tags) == (False, False, "first; second", [])
    assert one_rule(m, p, "trusted").handling == {"inspection": "none (trust)"} and one_rule(m, p, "trusted").action == Action.ALLOW
    assert one_rule(m, p, "reset").action == Action.RESET_BOTH and one_rule(m, p, "page").action == Action.RESET_BOTH
    assert codes(report, "rule", "page") == ["INTERACTIVE_BLOCK"] and not one_rule(m, p, "off").enabled
    # Users and a time range are conditions too: on a target that does not take them the rule is not in force.
    out = Report()
    config = CiscoConfig(cli.convert(p, "fmc", out), native=True)
    assert codes(out, "rule", "staff") == ["USER_MATCH"] and codes(out, "rule", "hours") == ["SCHEDULE"]
    assert [rule["name"] for rule in config.rules if not rule["enabled"]] == ["staff", "hours", "off"]
    assert {rule["name"]: rule["action"] for rule in config.rules}["trusted"] == "trust"
    assert "PROFILES_NOT_CONVERTED" in codes(out, "rule", "inspected")

    fdm = Manager(fdm=True)
    fdm.rule("both", log="both")
    fdm.rule("none", "TRUST", log="none", users=[{"name": "ann", "type": "trafficentry", "identitySource": {"name": "Realm"}}],
             timeRangeObjects=[{"name": "nights", "id": "t", "type": "timerangeobject"}], intrusionPolicy={"name": "Max", "type": "intrusionpolicy", "id": "i"})  # fmt: skip
    fdm.rule("start", eventLogAction="LOG_FLOW_START")
    p, report = read(fdm.export())
    assert [(rule.log_start, rule.log_end) for rule in p.rules] == [(True, True), (False, False), (True, False)]
    assert (p.rules[1].users, p.rules[1].schedule, p.rules[1].profiles, p.rules[1].handling) == (["ann"], "nights", {"intrusion": "Max"}, {"inspection": "none (trust)"})


def test_rules_that_are_listed_without_their_content_are_not_rules_for_everything() -> None:
    m = Manager()
    lan = m.network("lan", "10.1.0.0/16")
    m.rule("first", "BLOCK", sources=[lan])
    m.rule("second", sources=[lan])
    answers = m.answers()
    listing = next(answer for answer in answers if "accessrules" in answer.get("links", {}).get("self", ""))
    listing["items"] = [{key: rule[key] for key in ("type", "id", "name", "links")} for rule in listing["items"]]
    p, report = read(json.dumps(answers).encode())
    assert [(rule.name, rule.action, rule.sources) for rule in p.rules] == [("first", Action.DENY, [ANY]), ("second", Action.DENY, [ANY])]
    assert all(rule.unsupported == ["rule that is in the input by name only (fetch the rules with expanded=true)"] for rule in p.rules)
    assert "RULES_NOT_EXPANDED" in notes(report) and report.needs_review
    out = Report()
    assert not [rule for rule in CiscoConfig(cli.convert(p, "fmc", out)).rules if rule["enabled"]]


def test_rule_order_sections_and_pages() -> None:
    m = Manager()
    for index in range(1, 7):
        m.rule(f"m{index}", sources=[f"10.0.0.{index}"])
    m.rule("d1", section="Default")
    m.rule("d2", section="Default")
    rules = m.rules[m.policy["id"]]
    # Pages in the wrong order, the rules inside a page shuffled: the index of each rule says where it goes.
    pages = [rules[5:], rules[:2][::-1], rules[2:5]]
    answers = [m.policy] + [{"links": {"self": f"{BASE}/policy/accesspolicies/{m.policy['id']}/accessrules?offset={3 * i}&limit=3"},
                             "items": page, "paging": {"offset": 3 * i, "limit": 3, "count": 8, "pages": 3}} for i, page in enumerate(pages)]  # fmt: skip
    p, report = read(json.dumps(answers).encode())
    assert [rule.name for rule in p.rules] == ["m1", "m2", "m3", "m4", "m5", "m6", "d1", "d2"] and "EXPORT_INCOMPLETE" not in notes(report)
    # A page that is missing is said: the rules that are there decide traffic the missing ones decided.
    p, report = read(json.dumps(answers[:3]).encode())
    assert [rule.name for rule in p.rules] == ["m1", "m2", "m6", "d1", "d2"]
    text = next(note.message for note in report.notes if note.code == "EXPORT_INCOMPLETE")
    assert text.startswith("the manager has 8 access rules in 'Main', the input holds 5") and report.needs_review
    # Without an index the order of the input is the order.
    for rule in rules:
        del rule["metadata"]["ruleIndex"]
    p, report = read(json.dumps([m.policy, {"items": rules[::-1], "paging": {"count": 8}}]).encode())
    assert [rule.name for rule in p.rules] == ["m6", "m5", "m4", "m3", "m2", "m1", "d2", "d1"]


def test_inherited_policies() -> None:
    m = Manager(policy="Corporate")
    m.rule("top-mandatory", "BLOCK", sources=["10.66.0.0/16"])
    m.rule("top-default", section="Default", sources=["10.1.0.0/16"])
    child = m.child_policy("Branch")
    m.rule("own-mandatory", policy=child, sources=["10.2.0.0/16"])
    m.rule("own-default", policy=child, section="Default", sources=["10.3.0.0/16"])
    data = m.api()
    with pytest.raises(ParseError, match="'Corporate' is not in the input|x") as error:
        read(data, policy="x")
    assert "access control policy 'x' is not in the input (found: Branch, Corporate)" in str(error.value)
    # Without a choice, the policy nothing inherits from is the one that is meant.
    for kwargs in ({}, {"policy": "Branch"}):
        p, report = read(data, **kwargs)
        assert p.scope == "Branch" and [rule.name for rule in p.rules] == ["top-mandatory", "own-mandatory", "own-default", "top-default"]
        assert p.default_interzone == Action.DENY and not report.notes
    p, report = read(data, policy="Corporate")
    assert [rule.name for rule in p.rules] == ["top-mandatory", "top-default"]
    # Its own default action, where it has one.
    m.policy["defaultAction"]["action"] = "PERMIT"
    assert read(m.api())[0].default_interzone == Action.ALLOW
    child["defaultAction"]["action"] = "BLOCK"
    assert read(m.api())[0].default_interzone == Action.DENY
    # The rules of the policy it inherits from are not there: said, because they come first.
    answers = [answer for answer in m.answers() if m.policy["id"] not in json.dumps(answer.get("links", {})) and answer is not m.policy]
    p, report = read(json.dumps(answers).encode())
    assert [rule.name for rule in p.rules] == ["own-mandatory", "own-default"]
    assert "PARENT_POLICY_MISSING" in notes(report) and "'Branch' inherits from 'Corporate'" in report.notes[0].message
    # Two policies that have nothing to do with each other: one has to be chosen.
    other = Manager(policy="Other", tag="b")
    other.rule("x")
    with pytest.raises(ParseError, match=r"several access control policies \(Branch, Other\): choose one with --policy"):
        read(m.api() + b"\n" + other.api())
    assert read(m.api() + b"\n" + other.api(), policy="Other")[0].scope == "Other"
    # Two with one name (a manager has domains): the id tells them apart, and the error gives the ids.
    twin = Manager(policy="Other", tag="c")
    twin.rule("y")
    both = other.api() + b"\n" + twin.api()
    with pytest.raises(ParseError, match=r"several access control policies \(Other \(id [0-9a-f-]+b\), Other \(id [0-9a-f-]+c\)\): choose one"):
        read(both)
    with pytest.raises(ParseError, match=r"2 access control policies are named 'Other': give --policy the id of one \(Other \(id "):
        read(both, policy="Other")
    assert [rule.name for rule in read(both, policy=twin.policy["id"])[0].rules] == ["y"]


def test_default_action() -> None:
    for action, allows in (("BLOCK", False), ("PERMIT", True), ("TRUST", True), ("NETWORK_DISCOVERY", True)):
        m = Manager()
        m.rule("r")
        m.policy["defaultAction"]["action"] = action
        p, report = read(m.api())
        assert (p.default_interzone == Action.ALLOW) == (p.default_intrazone == Action.ALLOW) == allows and not report.notes, action
    m.policy["defaultAction"]["action"] = "QUARANTINE"
    p, report = read(m.api())
    assert p.default_interzone == Action.DENY and "'QUARANTINE', which FWShift does not know: it was taken to block" in report.notes[0].message
    # The policy itself is not in the input: its default action is not known, and that is said.
    p, report = read(m.api(policies=False))
    assert p.default_interzone == Action.DENY and notes(report) == ["INHERITANCE_UNKNOWN", "DEFAULT_ACTION_UNKNOWN"] and report.needs_review
    assert p.scope == "Main"
    # The default action as an answer of its own.
    m.policy["defaultAction"] = {"id": "da-1", "type": "AccessPolicyDefaultAction", "links": {"self": f"{BASE}/policy/accesspolicies/{m.policy['id']}/defaultactions/da-1"}}
    extra = {"items": [{"id": "da-1", "type": "AccessPolicyDefaultAction", "action": "PERMIT"}], "paging": {"count": 1}}
    assert read(m.api() + json.dumps(extra).encode())[0].default_interzone == Action.ALLOW
    for action, allows in (("DENY", False), ("PERMIT", True), ("TRUST", True)):
        fdm = Manager(fdm=True)
        fdm.rule("r")
        fdm.policy["defaultAction"]["action"] = action
        assert (read(fdm.export())[0].default_interzone == Action.ALLOW) == allows


def test_prefilter_rules_come_first() -> None:
    m = Manager()
    inside, outside = m.zone("inside"), m.zone("outside")
    lan, srv = m.network("lan", "10.1.0.0/16"), m.host("srv", "10.2.0.5")
    m.use_prefilter("Fast")
    m.prefilter_rule("fast", "FASTPATH", src_zones=[inside], sources=[lan], destinations=[srv], dst_ports=[plit(6, "10000")])
    m.prefilter_rule("drop", "BLOCK", src_zones=[outside], sources=["10.0.0.0/8"], logBegin=True)
    m.prefilter_rule("off", "FASTPATH", enabled=False)
    m.rule("acp", "BLOCK", src_zones=[inside])
    p, report = read(m.api())
    assert [(rule.name, rule.action, rule.enabled) for rule in p.rules] == [
        ("fast", Action.ALLOW, True), ("drop", Action.DROP, True), ("off", Action.ALLOW, False), ("acp", Action.DROP, True)]
    fast = p.rules[0]
    assert (fast.src_zones, fast.sources, fast.destinations, fast.services) == (["inside"], ["lan"], ["srv"], ["tcp-10000"])
    assert fast.handling == {"inspection": "none (fastpath)"} and p.rules[1].log_start and not report.notes
    # The place of a prefilter rule is its index, not where the answer lists it.
    answers = m.answers()
    for answer in answers:
        if "prefilterrules" in json.dumps(answer.get("links", "")):
            answer["items"].reverse()
    assert [rule.name for rule in read(json.dumps(answers).encode())[0].rules] == ["fast", "drop", "off", "acp"]
    # Written for a Management Center again, a Fastpath rule is an access rule that trusts, in the same place.
    out = Report()
    config = CiscoConfig(cli.convert(p, "fmc", out), native=True)
    assert [(rule["name"], rule["action"]) for rule in config.rules] == [("fast", "trust"), ("drop", "block"), ("off", "trust"), ("acp", "block")]
    assert codes(out, "rule", "fast") == ["PREFILTER_AS_TRUST"]


def test_an_analyze_rule_ends_the_prefilter_for_its_traffic() -> None:
    m = Manager()
    inside, outside = m.zone("inside"), m.zone("outside")
    m.use_prefilter("Mixed")
    m.prefilter_rule("inspect-admins", "ANALYZE", src_zones=[inside], sources=["10.1.0.0/24"])
    m.prefilter_rule("fast-lan", "FASTPATH", src_zones=[inside], sources=["10.1.0.0/16"])
    m.prefilter_rule("fast-elsewhere", "FASTPATH", src_zones=[inside], sources=["10.2.0.0/16"])
    m.prefilter_rule("fast-outside", "FASTPATH", src_zones=[outside], sources=["10.1.0.0/24"])
    m.prefilter_rule("drop-lan", "BLOCK", sources=["10.1.0.0/16"], dst_ports=[plit(6, "23")])
    m.prefilter_rule("analyze-off", "ANALYZE", enabled=False)
    m.prefilter_rule("fast-after-off", "FASTPATH", src_zones=[outside], sources=["10.3.0.0/16"])
    m.rule("acp", "BLOCK")
    p, report = read(m.api())
    assert [rule.name for rule in p.rules] == ["fast-lan", "fast-elsewhere", "fast-outside", "drop-lan", "fast-after-off", "acp"]
    assert report.item("rule", "inspect-admins").skipped and codes(report, "rule", "inspect-admins") == ["PREFILTER_ANALYZE"]
    # It overlaps the Analyze rule above it: what it fastpaths of 10.1.0.0/24 the device hands to the access rules.
    assert "prefilter rule 'inspect-admins' above it hands part of the traffic" in one_rule(m, p, "fast-lan").unsupported[0]
    # Other addresses, or another zone: nothing in common with it.
    assert not one_rule(m, p, "fast-elsewhere").unsupported and not one_rule(m, p, "fast-outside").unsupported
    assert not one_rule(m, p, "fast-after-off").unsupported
    # A rule that blocks stays: it blocks more than it did, and that is said.
    drop = one_rule(m, p, "drop-lan")
    assert not drop.unsupported and codes(report, "rule", "drop-lan") == ["PREFILTER_ANALYZE"] and report.item("rule", "drop-lan").status == "needs-review"
    # The policy as converted never lets through what the device handed to its access rules.
    for src, expected in (("10.1.0.5", False), ("10.1.9.5", False), ("10.2.0.5", True)):
        assert bool(model_verdict(p, Packet("inside", "outside", src, "192.0.2.1", "tcp", 1024, 443))) == expected, src


def test_tunnel_rules_and_the_default_of_the_prefilter() -> None:
    m = Manager()
    outside, dmz = m.zone("outside"), m.zone("dmz")
    peer, hub = m.host("peer", "198.51.100.7"), m.host("hub", "10.2.0.1")
    m.use_prefilter("Tunnels", "BLOCK_TUNNELS")
    m.prefilter_rule("gre-in", "FASTPATH", kind="TUNNEL", src_zones=[outside], dst_zones=[dmz], sources=[peer], destinations=[hub],
                     encapsulationPorts=["GRE", "IP_IN_IP"])  # fmt: skip
    m.prefilter_rule("teredo", "BLOCK", kind="TUNNEL", encapsulationPorts=["TEREDO"], bidirectional=True)
    m.prefilter_rule("no-encapsulation", "FASTPATH", kind="TUNNEL")
    m.prefilter_rule("with-ports", "FASTPATH", kind="TUNNEL", encapsulationPorts=["GRE"], dst_ports=[plit(6, "80")])
    m.prefilter_rule("zone-on-fastpath", "FASTPATH", kind="TUNNEL", encapsulationPorts=["GRE"], tunnelZone={"objects": [{"type": "TunnelTag", "name": "z", "id": "z"}]})
    m.prefilter_rule("odd-type", "FASTPATH", kind="ENCRYPTED")
    m.prefilter_rule("plain-with-encapsulation", "FASTPATH", encapsulationPorts=["GRE"])
    m.prefilter_rule("six-in-four", "ANALYZE", kind="TUNNEL", sources=[peer], encapsulationPorts=["IPV6_IN_IP"],
                     tunnelZone={"objects": [{"type": "TunnelTag", "name": "v6-tunnels", "id": "tz"}]})  # fmt: skip
    m.rule("acp")
    p, report = read(m.api())
    names = [rule.name for rule in p.rules]
    assert names == ["gre-in", "teredo", "teredo-reverse", "no-encapsulation", "with-ports", "zone-on-fastpath", "odd-type",
                     "plain-with-encapsulation", "prefilter-default-block-tunnels", "acp"]  # fmt: skip
    gre = one_rule(m, p, "gre-in")
    assert gre.services == ["gre", "ipinip"] and (gre.src_zones, gre.dst_zones, gre.sources, gre.destinations) == (["outside"], ["dmz"], ["peer"], ["hub"])
    assert codes(report, "rule", "gre-in") == ["TUNNEL_RULE"] and report.item("rule", "gre-in").status == "approximated"
    teredo, back = one_rule(m, p, "teredo"), one_rule(m, p, "teredo-reverse")
    assert [(e.protocol, e.dst_ports, e.src_ports) for e in p.services[teredo.services[0]].entries] == [(Protocol.UDP, "3544", "")]
    assert [(e.protocol, e.dst_ports, e.src_ports) for e in p.services[back.services[0]].entries] == [(Protocol.UDP, "", "3544")]
    assert back.action == Action.DROP
    assert report.item("rule", "six-in-four").skipped
    assert one_rule(m, p, "no-encapsulation").unsupported == ["tunnel rule without an encapsulation"]
    assert one_rule(m, p, "with-ports").unsupported == ["ports on a tunnel rule"]
    assert one_rule(m, p, "zone-on-fastpath").unsupported == ["a tunnel zone on a rule that does not hand the tunnel to the access rules"]
    assert one_rule(m, p, "odd-type").unsupported == ["prefilter rule of type 'ENCRYPTED'"]
    assert one_rule(m, p, "plain-with-encapsulation").unsupported == ["'encapsulationPorts' on a rule that is not a tunnel rule"]
    last = one_rule(m, p, "prefilter-default-block-tunnels")
    assert last.action == Action.DROP and last.services == ["gre", "ipinip", "proto-41", "udp-3544"]
    # The Analyze rule for IPv6 in IP exempts tunnels from the default: one list cannot say that, and the default blocks them too.
    assert codes(report, "rule", last.name) == ["PREFILTER_ANALYZE"]
    for proto, src, expected in (("47", "198.51.100.7", True), ("4", "198.51.100.7", True), ("47", "198.51.100.8", False), ("41", "198.51.100.7", False)):
        assert bool(model_verdict(p, Packet("outside", "dmz", src, "10.2.0.1", proto))) == expected, (proto, src)


def test_which_prefilter_policy_and_what_is_missing_of_it() -> None:
    m = Manager()
    m.rule("acp")
    # The policy names a prefilter policy that is not in the input.
    m.policy["prefilterPolicySetting"] = {"type": "PrefilterPolicy", "id": "pf-9", "name": "Custom prefilter"}
    p, report = read(m.api())
    assert notes(report) == ["PREFILTER_MISSING", "PREFILTER_DEFAULT_UNKNOWN"] and report.needs_review
    # The default prefilter policy has no rules: only its default action is not known.
    m.policy["prefilterPolicySetting"]["name"] = "Default Prefilter Policy"
    assert notes(read(m.api())[1]) == ["PREFILTER_DEFAULT_UNKNOWN"]
    # The policy with its rules listed, and none there: nothing is missing.
    m.use_prefilter("Empty")
    assert notes(read(m.api())[1]) == []
    # Prefilter rules without the access control policy that says whose they are.
    m.prefilter_rule("fast", "FASTPATH", sources=["10.1.0.0/16"])
    p, report = read(m.api(policies=False))
    assert [rule.name for rule in p.rules] == ["fast", "acp"]
    assert notes(report) == ["PREFILTER_ASSUMED", "INHERITANCE_UNKNOWN", "DEFAULT_ACTION_UNKNOWN"]
    other = Manager(tag="b")
    other.use_prefilter("Second")
    other.prefilter_rule("other-fast", "BLOCK")
    answers = m.answers(policies=False) + [answer for answer in other.answers(policies=False) if "prefilterrules" in json.dumps(answer.get("links", ""))]
    p, report = read(json.dumps(answers).encode())
    assert [rule.name for rule in p.rules] == ["acp"] and "PREFILTER_NOT_READ" in notes(report)
    # The interfaces of a prefilter rule: zones, or an interface group that is whole zones.
    m = Manager()
    one, two, three = (m.interface(name, f"GigabitEthernet0/{index}") for index, name in enumerate(("a", "b", "c")))
    left, right = m.zone("left", [one, two]), m.zone("right", [three])
    whole = m._add("object/interfacegroups", "InterfaceGroup", "whole", interfaceMode="ROUTED", interfaces=[m.ref(one), m.ref(two), m.ref(three)])
    part = m._add("object/interfacegroups", "InterfaceGroup", "part", interfaceMode="ROUTED", interfaces=[m.ref(one)])
    m.use_prefilter("Groups")
    m.prefilter_rule("by-zones", "FASTPATH", src_zones=[left], dst_zones=[right])
    m.prefilter_rule("by-group", "FASTPATH", src_zones=[whole])
    m.prefilter_rule("by-part", "FASTPATH", src_zones=[part])
    m.rule("acp")
    p, report = read(m.api())
    assert one_rule(m, p, "by-zones").src_zones == ["left"] and one_rule(m, p, "by-group").src_zones == ["left", "right"]
    assert one_rule(m, p, "by-part").unsupported == ["interface group 'part', which is not the interfaces of whole security zones"]
    assert p.zones["left"].interfaces == ["a", "b"] and p.zones["right"].interfaces == ["c"]


# -- NAT, as it is read ---------------------------------------------------------------------------


def nat_setup(fdm: bool) -> Tuple[Manager, Dict[str, Ref]]:
    """A manager with the objects, zones and interfaces the NAT cases use."""
    m = Manager(fdm)
    o: Dict[str, Ref] = {}
    out_if = m.interface("outside", "GigabitEthernet0/0", "203.0.113.2", "255.255.255.0")
    in_if = m.interface("inside", "GigabitEthernet0/1", "10.1.0.1", "255.255.0.0")
    dmz_if = m.interface("dmz", "GigabitEthernet0/2", "10.2.0.1", "255.255.255.0")
    zones = [m.zone("outside", [out_if]), m.zone("inside", [in_if]), m.zone("dmz", [dmz_if])]
    for name, value in zip(("outside", "inside", "dmz"), (out_if, in_if, dmz_if) if fdm else zones):
        o[name] = value  # what a NAT rule names: the interface on a Device Manager, the zone on a Management Center
    system = {"isSystemDefined": True} if fdm else {"metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}}}
    o["any4"] = m.network("any-ipv4", "0.0.0.0/0", **system)
    o["lan"], o["srv"], o["pub"] = m.network("lan", "10.1.0.0/16"), m.host("srv", "10.2.0.10"), m.host("srv-pub", "203.0.113.10")
    o["pool"], o["one"] = m.range("pool", "203.0.113.100-203.0.113.110"), m.host("one", "203.0.113.50")
    o["dmz-net"], o["dmz-pub"] = m.network("dmz-net", "10.2.0.0/24"), m.network("dmz-pub", "198.51.100.0/24")
    o["partner"], o["six"], o["six-pub"] = m.network("partner", "192.0.2.0/24"), m.host("six", "2001:db8:2::10"), m.host("six-pub", "2001:db8:ffff::10")
    o["web"], o["alt"], o["dns"], o["web-range"] = m.tcp("p-web", "443"), m.tcp("p-alt", "8443"), m.udp("p-dns", "53"), m.tcp("p-range", "8000-8010")
    o["name"] = m.fqdn("host-name", "srv.example.com")
    m.rule("to-srv", destinations=[o["srv"]], dst_ports=[o["alt"]])
    return m, o


def nats(m: Manager, **kwargs: Any) -> Tuple[Dict[str, NatRule], Policy, Report]:
    p, report = read(m.export() if m.fdm else m.api(), **kwargs)
    return {nat.name: nat for nat in p.nat_rules}, p, report


@pytest.mark.parametrize("fdm", [False, True])
def test_manual_nat_as_it_is_read(fdm: bool) -> None:
    m, o = nat_setup(fdm)
    # 1: no translation between two networks, as a rule for both directions.
    m.manual_nat("STATIC", originalSource=o["lan"], translatedSource=o["lan"], originalDestination=o["partner"], translatedDestination=o["partner"],
                 sourceInterface=o["inside"], destinationInterface=o["outside"], noProxyArp=True, routeLookup=True, description="exempt")  # fmt: skip
    # 2: a destination translation with a port, from any source.
    m.manual_nat("STATIC", originalSource=o["any4"], translatedSource=o["any4"], originalDestination=o["pub"], translatedDestination=o["srv"],
                 originalDestinationPort=o["web"], translatedDestinationPort=o["alt"], sourceInterface=o["outside"], destinationInterface=o["dmz"],
                 unidirectional=True)  # fmt: skip
    # 3: a pool with port translation; 4: one address; 5: the interface; 6: a range handed out address by address.
    pat = {"patPoolAddress": m.ref(o["pool"]), "interfacePat": False, "roundRobin": True, ("extended" if fdm else "extendedPat"): True}
    m.manual_nat("DYNAMIC", originalSource=o["lan"], patOptions=pat, sourceInterface=o["inside"], destinationInterface=o["outside"])
    m.manual_nat("DYNAMIC", originalSource=o["lan"], translatedSource=o["one"], sourceInterface=o["inside"], destinationInterface=o["outside"])
    m.manual_nat("DYNAMIC", originalSource=o["lan"], interfaceInTranslatedSource=True, sourceInterface=o["inside"], destinationInterface=o["outside"])
    m.manual_nat("DYNAMIC", originalSource=o["lan"], translatedSource=o["pool"], sourceInterface=o["inside"], destinationInterface=o["outside"])
    # 7: static, both ways; 8: one way; 9: with a destination, which makes it the rule of those connections.
    m.manual_nat("STATIC", originalSource=o["dmz-net"], translatedSource=o["dmz-pub"], sourceInterface=o["dmz"], destinationInterface=o["outside"])
    m.manual_nat("STATIC", originalSource=o["dmz-net"], translatedSource=o["dmz-pub"], sourceInterface=o["dmz"], destinationInterface=o["outside"],
                 unidirectional=True, enabled=False)  # fmt: skip
    m.manual_nat("STATIC", originalSource=o["srv"], translatedSource=o["pub"], originalDestination=o["partner"], translatedDestination=o["partner"],
                 sourceInterface=o["dmz"], destinationInterface=o["outside"])  # fmt: skip
    # 10: a port of a server published on the address of the interface; 11: on an address of its own.
    m.manual_nat("STATIC", originalSource=o["srv"], interfaceInTranslatedSource=True, originalSourcePort=o["alt"], translatedSourcePort=o["web"],
                 sourceInterface=o["dmz"], destinationInterface=o["outside"])  # fmt: skip
    m.manual_nat("STATIC", after_auto=True, originalSource=o["srv"], translatedSource=o["pub"], originalSourcePort=o["dns"], translatedSourcePort=o["dns"],
                 sourceInterface=o["dmz"], destinationInterface=o["outside"])  # fmt: skip
    # 12: the address of the interface the traffic arrives on, as destination.
    m.manual_nat("STATIC", originalSource=o["any4"], translatedSource=o["any4"], interfaceInOriginalDestination=True, translatedDestination=o["srv"],
                 originalDestinationPort=o["web"], translatedDestinationPort=o["web"], sourceInterface=o["outside"], destinationInterface=o["dmz"])  # fmt: skip
    found, p, report = nats(m)
    assert len(found) == 12 and not [nat.unsupported for nat in found.values() if nat.unsupported]
    # The rule "after auto" is the last of the list, wherever it stands in the input.
    r = dict(zip(range(1, 13), p.nat_rules[:10] + [p.nat_rules[11], p.nat_rules[10]]))
    assert (r[1].src_zones, r[1].dst_zones, r[1].sources, r[1].destinations, r[1].source_translation, r[1].destination_translation,
            r[1].description, r[1].combines) == (["inside"], ["outside"], ["lan"], ["partner"], None, None, "exempt", False)  # fmt: skip
    assert (r[2].src_zones, r[2].dst_zones, r[2].sources, r[2].destinations, r[2].service) == (["outside"], ["outside"], ["any-ipv4"], ["srv-pub"], "p-web")
    assert (r[2].destination_translation, r[2].source_translation, r[2].combines) == (DestNat("srv", "8443"), None, False)
    assert (r[3].source_translation, r[3].sources, r[3].destinations) == (SourceNat(SnatKind.DYNAMIC_PORT, ["pool"]), ["lan"], [ANY])
    assert codes(report, "nat", r[3].name) == ["ATTRIBUTES_IGNORED"] and "round robin, extended PAT" in report.item("nat", r[3].name).findings[0].message
    assert r[4].source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["one"])
    assert r[5].source_translation == SourceNat(SnatKind.INTERFACE, interface="outside", interface_address="203.0.113.2")
    assert r[6].source_translation == SourceNat(SnatKind.DYNAMIC, ["pool"])
    assert r[7].source_translation == SourceNat(SnatKind.STATIC, ["dmz-pub"], bidirectional=True) and r[7].combines and r[7].enabled
    assert r[8].source_translation == SourceNat(SnatKind.STATIC, ["dmz-pub"], bidirectional=False) and not r[8].enabled
    assert r[9].source_translation == SourceNat(SnatKind.STATIC, ["srv-pub"], bidirectional=False) and r[9].destinations == ["partner"]
    assert codes(report, "nat", r[9].name) == ["NAT_REVERSE_DIRECTION"] and not r[9].combines
    # (The port a rule matches is the port object it names: no second service for the same port.)
    # A published port is a destination translation for what comes in on the mapped interface.
    assert (r[10].src_zones, r[10].dst_zones, r[10].sources, r[10].destinations, r[10].service) == (["outside"], ["outside"], [ANY], ["outside-interface"], "p-web")
    assert (r[10].destination_translation, r[10].combines) == (DestNat("srv", "8443"), True)
    assert p.addresses["outside-interface"].value == "203.0.113.2/32" and p.addresses["outside-interface"].raw == "interface outside"
    assert "NAT_INTERFACE_ADDRESS" in codes(report, "nat", r[10].name)
    assert (r[11].destinations, r[11].service, r[11].destination_translation) == (["srv-pub"], "p-dns", DestNat("srv", ""))
    assert (r[12].destinations, r[12].destination_translation, r[12].service, r[12].dst_zones) == (["outside-interface"], DestNat("srv", ""), "p-web", ["outside"])
    # The rule that names the real address and port of the server is brought to the address and port a client uses.
    to_srv = p.rules[0]
    # (198.51.100.10 is what rule 7 makes of the server, as one address of the network it maps.)
    assert to_srv.destinations == ["srv", "srv-pub", "198.51.100.10", "outside-interface"]
    assert sorted(to_srv.nat_added) == ["198.51.100.10", "outside-interface", "srv-pub"]
    assert "NAT_PORT_TRANSLATION" in codes(report, "rule", "to-srv")


@pytest.mark.parametrize("fdm", [False, True])
def test_automatic_nat_as_it_is_read(fdm: bool) -> None:
    m, o = nat_setup(fdm)
    port = (lambda number, protocol="tcp": m.tcp(f"n{number}", str(number)) if protocol == "tcp" else m.udp(f"u{number}", str(number)))
    m.auto_nat("DYNAMIC", name="hide-lan", originalNetwork=o["lan"], interfaceInTranslatedNetwork=True, sourceInterface=o["inside"],
               destinationInterface=o["outside"])  # fmt: skip
    m.auto_nat("STATIC", name="map-dmz", originalNetwork=o["dmz-net"], translatedNetwork=o["dmz-pub"], sourceInterface=o["dmz"],
               destinationInterface=o["outside"], dns=True)  # fmt: skip
    ports = {"originalPort": port(8443), "translatedPort": port(443)} if fdm else {"originalPort": 8443, "translatedPort": 443, "serviceProtocol": "TCP"}
    m.auto_nat("STATIC", name="publish", originalNetwork=o["srv"], translatedNetwork=o["pub"], sourceInterface=o["dmz"],
               destinationInterface=o["outside"], **ports)  # fmt: skip
    same = {"originalPort": port(53, "udp"), "translatedPort": port(53, "udp")} if fdm else {"originalPort": 53, "translatedPort": 53, "serviceProtocol": "UDP"}
    m.auto_nat("STATIC", name="on-interface", originalNetwork=o["six"], translatedNetwork=None, interfaceInTranslatedNetwork=True,
               sourceInterface=o["dmz"], destinationInterface=o["outside"], **same)  # fmt: skip
    m.auto_nat("DYNAMIC", name="pool", originalNetwork=o["partner"], translatedNetwork=o["pool"], sourceInterface=o["inside"],
               destinationInterface=o["outside"], **({} if fdm else {"fallThrough": True}))  # fmt: skip
    found, p, report = nats(m)
    order = [nat.name for nat in p.nat_rules]
    by = {(name if fdm else {"hide-lan": "nat-lan", "map-dmz": "nat-dmz-net", "publish": "nat-srv", "on-interface": "nat-six", "pool": "nat-partner"}[name]): name
          for name in ("hide-lan", "map-dmz", "publish", "on-interface", "pool")}  # fmt: skip
    # The device sorts them: static before dynamic, then the fewest addresses first.
    assert [by[name] for name in order] == ["publish", "on-interface", "map-dmz", "pool", "hide-lan"]
    r = {by[nat.name]: nat for nat in p.nat_rules}
    assert [by[nat.name] for nat in p.nat_rules if nat.unsupported] == ["on-interface"]
    assert r["hide-lan"].source_translation == SourceNat(SnatKind.INTERFACE, interface="outside", interface_address="203.0.113.2")
    assert (r["hide-lan"].src_zones, r["hide-lan"].dst_zones, r["hide-lan"].sources) == (["inside"], ["outside"], ["lan"])
    assert r["map-dmz"].source_translation == SourceNat(SnatKind.STATIC, ["dmz-pub"], bidirectional=True) and r["map-dmz"].combines
    assert "translate DNS replies" in report.item("nat", r["map-dmz"].name).findings[0].message
    assert (r["publish"].src_zones, r["publish"].sources, r["publish"].destinations, r["publish"].service) == (["outside"], [ANY], ["srv-pub"], "n443" if fdm else "tcp-443")
    assert r["publish"].destination_translation == DestNat("srv", "8443") and r["publish"].combines
    # The address of an IPv4 interface for an IPv6 server: nothing that can be.
    assert r["on-interface"].unsupported == ["translation between IPv4 and IPv6"]
    assert r["pool"].source_translation == SourceNat(SnatKind.DYNAMIC, ["pool"])
    if not fdm:
        assert "interface (as fallback)" in report.item("nat", r["pool"].name).findings[0].message


NAT_PROBLEMS = [
    ({"natType": "TWICE"}, "NAT type 'TWICE'"),
    ({"translatedSource": None}, "static NAT without a translated address"),
    ({"interfaceInTranslatedSource": True}, "a translated address and the address of the interface at once"),
    ({"translatedSource": None, "interfaceInTranslatedSource": True}, "static NAT to the interface address without a port"),
    ({"translatedDestination": "srv"}, "a translated destination without an original one"),
    ({"originalDestination": "pub", "interfaceInOriginalDestination": True, "translatedDestination": "srv"},
     "an original destination and the address of the interface at once"),
    ({"interfaceInOriginalDestination": True}, "the address of the interface as destination without a translated destination"),
    ({"originalDestinationPort": "web"}, "a destination port on one side of the translation only"),
    ({"originalSourcePort": "web", "translatedSourcePort": "dns"}, "port translation between two protocols"),
    ({"originalSourcePort": "web", "translatedSourcePort": "alt", "originalDestinationPort": "web", "translatedDestinationPort": "web"},
     "port translation of source and destination ports at once"),
    ({"originalSourcePort": "web", "translatedSourcePort": "alt", "unidirectional": True}, "translation of a source port"),
    ({"originalSourcePort": "web", "translatedSourcePort": "alt", "originalDestination": "pub", "translatedDestination": "srv"},
     "port forwarding with a destination translation as well"),
    ({"originalDestinationPort": "web", "translatedDestinationPort": "alt"}, "port translation without a destination address"),
    ({"patOptions": {"patPoolAddress": "pool"}}, "a PAT pool on a static NAT rule"),
    ({"translatedSource": "six-pub"}, "translation between IPv4 and IPv6"),
    ({"translatedSource": "name"}, None),  # a host name is no address to translate to: the object cannot be converted
    ({"originalSource": {"type": "Network", "id": "gone", "name": "gone"}}, None),
    ({"enabled": None}, "NAT rule that does not say whether it is enabled"),
    ({"somethingNew": {"a": 1}}, "field 'somethingNew', which FWShift does not know"),
    ({"natType": "DYNAMIC", "translatedSource": None}, "dynamic NAT without a translated address"),
    ({"natType": "DYNAMIC", "translatedSource": None, "interfaceInTranslatedSource": True, "destinationInterface": None},
     "port address translation to the interface address without a destination interface"),
    ({"natType": "DYNAMIC", "translatedSource": None, "interfaceInTranslatedSource": True, "interfaceIpv6": True},
     "port address translation to the IPv6 address of the interface"),
    ({"originalSourcePort": "web-range", "translatedSourcePort": "alt"}, "translation of a range of ports"),
    ({"originalDestination": "pub", "translatedDestination": "srv", "originalDestinationPort": "web", "translatedDestinationPort": "web-range"},
     "translation of a range of ports"),
    ({"sourceInterface": {"type": "Device", "id": "d", "name": "ftd1"}}, "interface object 'ftd1' of type 'device'"),
]  # fmt: skip


@pytest.mark.parametrize("fields,why", NAT_PROBLEMS)
def test_nat_that_is_not_understood_is_not_converted(fields: Dict[str, Any], why: Optional[str]) -> None:
    m, o = nat_setup(False)
    base: Dict[str, Any] = {"originalSource": o["lan"], "translatedSource": o["one"], "sourceInterface": o["inside"], "destinationInterface": o["outside"]}
    kind = fields.get("natType", "STATIC")
    for key, value in fields.items():
        if key == "patOptions":
            value = {"patPoolAddress": m.ref(o["pool"])}
        base[key] = o[value] if isinstance(value, str) and value in o else value
    base.pop("natType", None)
    m.manual_nat(kind, **{key: value for key, value in base.items() if value is not None or key == "enabled"})
    found, p, report = nats(m)
    nat = p.nat_rules[0]
    if why is None:
        out = Report()
        cli.convert(p, "fmc", out)
        assert out.item("nat", nat.origin).skipped, (nat, out.to_text())
        return
    assert why in nat.unsupported, nat.unsupported
    for target in ("fmc", "fdm", "panos"):
        out = Report()
        text = cli.convert(p, target, out)
        assert out.item("nat", nat.origin).skipped and "NAT_NOT_CONVERTED" in codes(out, "nat", nat.origin)
        if target != "panos":
            assert not CiscoConfig(text, native=target == "fmc").nat


def test_nat_policies_interface_groups_and_zones_without_interfaces() -> None:
    m, o = nat_setup(False)
    m.manual_nat("DYNAMIC", originalSource=o["lan"], interfaceInTranslatedSource=True, sourceInterface=o["inside"], destinationInterface=o["outside"])
    other = Manager(tag="b")
    net = other.network("branch", "10.9.0.0/16")
    other.nat_policy["name"] = "Branch NAT"
    other.manual_nat("DYNAMIC", originalSource=net, interfaceInTranslatedSource=True, destinationInterface=other.zone("wan"))
    both = m.api() + b"\n" + json.dumps(other.nat_policy).encode() + b"\n" + json.dumps(m.nat_policy).encode() + b"\n" + other.api(policies=False)
    with pytest.raises(ParseError, match=r"several NAT policies \(Branch NAT, NAT\): choose one with --nat-policy"):
        read(both)
    assert [nat.sources for nat in read(both, nat_policy="Branch NAT")[0].nat_rules] == [["branch"]]
    assert [nat.sources for nat in read(both, nat_policy="NAT")[0].nat_rules] == [["lan"]]
    with pytest.raises(ParseError, match="NAT policy 'Nowhere' is not in the input"):
        read(both, nat_policy="Nowhere")
    # A zone whose interface the input does not show: the interface is named by its zone, its address is not known.
    p, report = read(other.api(policies=False))
    nat = p.nat_rules[0]
    assert nat.source_translation == SourceNat(SnatKind.INTERFACE) and nat.dst_zones == ["wan"] and not nat.unsupported
    # An interface group: the zones of its interfaces, said when that is more than the group.
    m, o = nat_setup(False)
    extra = m.interface("inside2", "GigabitEthernet0/5", "10.5.0.1")
    m.objects["object/securityzones"][1]["interfaces"].append(m.ref(extra))
    in_if = next(i for i in m.objects["devices/devicerecords/dev1/physicalinterfaces"] if i["ifname"] == "inside")
    part = m._add("object/interfacegroups", "InterfaceGroup", "one-of-two", interfaces=[m.ref(in_if)])
    whole = m._add("object/interfacegroups", "InterfaceGroup", "both", interfaces=[m.ref(in_if), m.ref(extra)])
    unknown = {"type": "InterfaceGroup", "id": "nowhere", "name": "not-there"}
    for group in (part, whole, unknown):
        m.manual_nat("DYNAMIC", originalSource=o["lan"], translatedSource=o["one"], sourceInterface=group, destinationInterface=o["outside"])
    p, report = read(m.api())
    assert [nat.src_zones for nat in p.nat_rules] == [["inside"], ["inside"], [ANY]]
    assert [codes(report, "nat", nat.name) for nat in p.nat_rules] == [["NAT_INTERFACE"], [], ["NAT_INTERFACE"]]
    assert [report.item("nat", nat.name).status for nat in p.nat_rules] == ["approximated", "exact", "needs-review"]
    # The address of an interface of a zone that has two: which one is not said.
    m.manual_nat("STATIC", originalSource=o["srv"], interfaceInTranslatedSource=True, originalSourcePort=o["alt"], translatedSourcePort=o["web"],
                 sourceInterface=o["dmz"], destinationInterface=o["inside"])  # fmt: skip
    p, report = read(m.api())
    assert p.nat_rules[-1].unsupported == ["the address of the interface of zone 'inside', which the input does not tell"]


def test_interfaces_and_zones_of_a_device_manager() -> None:
    m, o = nat_setup(True)
    lone = m.interface("lab", "GigabitEthernet0/7", "10.7.0.1")
    m.manual_nat("DYNAMIC", name="lab-out", originalSource=o["lan"], interfaceInTranslatedSource=True, sourceInterface=lone, destinationInterface=o["outside"])
    shared = m.interface("inside-b", "GigabitEthernet0/8", "10.8.0.1")
    m.objects["object/securityzones"][1]["interfaces"].append({**m.ref(shared), "hardwareName": "GigabitEthernet0/8"})
    m.manual_nat("DYNAMIC", name="one-of-two", originalSource=o["lan"], translatedSource=o["one"], sourceInterface=o["inside"], destinationInterface=o["outside"])
    m.manual_nat("DYNAMIC", after_auto=True, name="late", originalSource=o["lan"], translatedSource=o["one"])
    m.auto_nat("STATIC", name="auto", originalNetwork=o["srv"], translatedNetwork=o["pub"], sourceInterface=o["dmz"], destinationInterface=o["outside"])
    for data in (m.export(), m.api()):
        p, report = read(data)
        assert [nat.name for nat in p.nat_rules] == ["lab-out", "one-of-two", "auto", "late"], [nat.name for nat in p.nat_rules]
        # An interface in no zone is a zone of its own: no access rule names it, and a rule for any zone covers it.
        assert p.nat_rules[0].src_zones == ["lab"] and p.zones["lab"].interfaces == ["lab"] and p.zones["inside"].interfaces == ["inside", "inside-b"]
        assert p.nat_rules[1].src_zones == ["inside"] and codes(report, "nat", "one-of-two") == ["NAT_INTERFACE"]
        assert "also holds inside-b" in report.item("nat", "one-of-two").findings[0].message
        assert p.nat_rules[3].src_zones == p.nat_rules[3].dst_zones == [ANY]
        assert p.scope == ("FTD 7.2.5-208 on Cisco Firepower Threat Defense for VMware" if data.startswith(b"[") else "")


# -- the file: what it is, and what is wrong with it ------------------------------------------------


def zipped(files: Dict[str, bytes], encrypted: bool = False) -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    data = buffer.getvalue()
    if encrypted:  # the bit that says so, in the header of the file and in the directory of the archive
        local, central = data.index(b"PK\x03\x04"), data.index(b"PK\x01\x02")
        data = data[:local + 6] + b"\x01" + data[local + 7:central + 8] + b"\x01" + data[central + 9:]
    return data


def test_the_export_of_a_device_manager_is_read_by_its_wrappers() -> None:
    m = Manager(True)
    lan = m.network("lan", "10.1.0.0/16")
    for name in ("first", "second", "third"):
        m.rule(name, sources=[lan])
    p, report = read(m.export())
    assert p.vendor == "fdm" and p.scope == "FTD 7.2.5-208 on Cisco Firepower Threat Defense for VMware"
    assert [rule.name for rule in p.rules] == ["first", "second", "third"] and not report.notes
    entries = json.loads(m.export())
    rules = [entry for entry in entries if entry.get("data", {}).get("type") == "accessrule"]
    others = [entry for entry in entries if entry not in rules]

    def names(listed: List[Any]) -> List[str]:
        return [rule.name for rule in read(json.dumps(listed).encode(), "fdm")[0].rules]

    # The place of a rule is its index in the policy, not where it stands in the file.
    assert names(others + rules[::-1]) == ["first", "second", "third"]
    # Without an index, or with one index twice, the file is all there is to go by.
    rules[2]["index"] = 0
    assert names(others + rules[::-1]) == ["third", "second", "first"]
    for rule in rules:
        del rule["index"]
    assert names(others + rules[::-1]) == ["third", "second", "first"]
    # What the file says is to be deleted is not part of the configuration.
    rules[1]["action"] = "DELETE"
    assert names(others + rules) == ["first", "third"]
    # Without the first entry, the software the file is from is not known: no scope, and the rules all the same.
    p, report = read(json.dumps(others[1:] + rules).encode(), "fdm")
    assert p.scope == "" and [rule.name for rule in p.rules] == ["first", "third"]


def test_the_zip_of_a_device_manager() -> None:
    m = Manager(True)
    m.rule("r", sources=[m.network("lan", "10.1.0.0/16")])
    export = m.export()
    data = zipped({"full_config.txt": export})
    assert cli.detect_format(data) == "fdm"
    assert [rule.name for rule in read(data)[0].rules] == ["r"]
    assert [rule.name for rule in read(zipped({"export/config.JSON": export, "export/": b""}))[0].rules] == ["r"]
    for broken, message in (
        (zipped({"full_config.txt": export}, encrypted=True), "the zip is encrypted. Export the configuration with doNotEncrypt"),
        (zipped({"a.txt": export, "b.txt": export}), "the zip holds 2 text files"),
        (zipped({"image.bin": b"\x00" * 20}), "the zip holds 0 text files"),
        (data[: len(data) // 2], "the zip could not be read"),
        (zipped({"full_config.txt": b"not json"}), "not valid JSON"),
    ):  # fmt: skip
        with pytest.raises(ParseError, match=message):
            read(broken, "fdm")
    # A zip is nothing a Management Center gives, and a zip of something else is not a format FWShift knows.
    with pytest.raises(ParseError, match="the input is a zip; unpack it"):
        read(data, "fmc")
    # Without --from: the zip is looked into, and what is wrong with it is said.
    empty = zipped({})
    assert empty[:4] == b"PK\x05\x06"
    for other, why in ((zipped({"a.txt": b"hello"}), "the file in it is not a configuration of a Device Manager"),
                       (zipped({"full_config.txt": export}, encrypted=True), "the zip is encrypted. Export the configuration with doNotEncrypt"),
                       (zipped({"a.txt": export, "b.txt": export}), "the zip holds 2 text files"),
                       (data[: len(data) // 2], "the zip could not be read"), (empty, "the zip holds 0 text files")):  # fmt: skip
        with pytest.raises(cli.FwshiftError, match=r"the input is compressed \(a zip\), and not the configuration export of a Firewall Device Manager") as caught:
            cli.detect_format(other)
        assert why in str(caught.value) and "Unpack it and give FWShift the file inside" in str(caught.value)
    # More than a configuration can be: not unpacked into memory.
    monkey = parse_cisco._MAX_UNZIPPED
    try:
        parse_cisco._MAX_UNZIPPED = 1000
        with pytest.raises(ParseError, match="too large to be a configuration export"):
            read(zipped({"full_config.txt": export + b" " * 2000}), "fdm")
    finally:
        parse_cisco._MAX_UNZIPPED = monkey


def test_the_format_is_told_by_what_is_in_the_json() -> None:
    fmc, fdm = Manager(), Manager(True)
    for m in (fmc, fdm):
        m.rule("r", sources=[m.network("lan", "10.1.0.0/16")], dst_ports=[m.tcp("web", "443")])
    assert cli.detect_format(fmc.api()) == "fmc" and cli.detect_format(fdm.export()) == "fdm" and cli.detect_format(fdm.api()) == "fdm"
    assert cli.detect_format((DATA / "fmc_sample.json").read_bytes()) == "fmc" and cli.detect_format((DATA / "fdm_sample.txt").read_bytes()) == "fdm"
    assert cli.detect_format((DATA / "checkpoint_sample.json").read_bytes()) == "checkpoint"
    # JSON that is neither is left to the reader of the Check Point API, which says what it misses.
    assert cli.detect_format(b'{"objects": [{"type": "host", "name": "h"}, {"type": "access-rule"}]}') == "checkpoint"
    assert cli.detect_format(b"[]") == "checkpoint"
    # One answer of each kind is enough, and so is the address it was fetched from.
    assert cli.detect_format(json.dumps({"items": [{"type": "Host", "name": "h", "value": "10.1.1.1"}]}).encode()) == "fmc"
    assert cli.detect_format(json.dumps({"items": [{"type": "networkobject", "name": "h"}]}).encode()) == "fdm"
    assert cli.detect_format(b'{"links": {"self": "https://x.example.net/api/fmc_config/v1/domain/d/object/hosts"}, "items": []}') == "fmc"
    assert cli.detect_format(b'{"links": {"self": "https://x.example.net/api/fdm/v6/object/networks"}, "items": []}') == "fdm"
    # Saved by a tool that writes UTF-16, or with a byte order mark.
    for encoded in (fmc.api().decode().encode("utf-16"), b"\xef\xbb\xbf" + fmc.api(), "﻿".encode("utf-16-be") + fmc.api().decode().encode("utf-16-be")):
        assert cli.detect_format(encoded) == "fmc" and [rule.name for rule in read(encoded)[0].rules] == ["r"]
    # Several answers in one file: one after the other, in one list, or one inside the other.
    answers = fmc.answers()
    for data in (fmc.api(), json.dumps(answers).encode(), json.dumps({"saved": {"at": "2026-01-05", "answers": [answers]}}).encode(),
                 b"\r\n\r\n".join(json.dumps(answer, indent=2).encode() for answer in answers)):  # fmt: skip
        p, report = read(data)
        assert [rule.name for rule in p.rules] == ["r"] and sorted(p.addresses) == ["lan"] and not report.notes


def test_input_of_the_other_manager_or_of_none() -> None:
    fmc, fdm = Manager(), Manager(True)
    for m in (fmc, fdm):
        m.rule("r", sources=[m.network("lan", "10.1.0.0/16")])
    with pytest.raises(ParseError, match="the input is the JSON of a Firewall Management Center; read it with --from fmc"):
        read(fmc.api(), "fdm")
    with pytest.raises(ParseError, match="the input is the JSON of a Firewall Device Manager; read it with --from fdm"):
        read(fdm.export(), "fmc")
    with pytest.raises(ParseError, match="of a Firewall Management Center and of a Firewall Device Manager; convert them apart"):
        read(fmc.api() + b"\n" + fdm.export(), "fmc")
    for data, message in (
        (b"", "the input is empty"), (b" \r\n\t ", "the input is empty"),
        (b"[]", "no Cisco Secure Firewall configuration found; expected what the REST API of a Firewall Management Center returns"),
        (b'{"error": {"category": "FRAMEWORK", "messages": [{"description": "Access token invalid."}], "severity": "ERROR"}}',
         "no Cisco Secure Firewall configuration found"),
        (b"null", "no Cisco Secure Firewall configuration found"), (b'"text"', "no Cisco Secure Firewall configuration found"),
        (b'{"items": [', "not valid JSON"), (b"<html><body>401 Unauthorized</body></html>", "not valid JSON"),
        (fmc.api() + b"\n{oops", r"not valid JSON \(after \d+ complete documents\)"),
        (b"\xff\xfe\x00\xd8", "not valid JSON"), (b'{"type": "Host", "name": "\xc3\x28"}', "the text is not UTF-8"),
        (b"[" * 200_000, "nested too deeply"), (b'{"a":' * 200_000, "nested too deeply"),
        # Types of a manager, and nothing of a policy in them.
        (b'{"type": "AccessPolicy"}', "no rules and no objects found in the input"),
        (b'{"items": [{"type": "Domain", "name": "Global", "id": "x"}]}', "no Cisco Secure Firewall configuration found"),
    ):  # fmt: skip
        with pytest.raises(ParseError, match=message):
            read(data, "fmc")
    with pytest.raises(ParseError, match="expected the configuration export of a Firewall Device Manager, or what its REST API returns"):
        read(b"{}", "fdm")


def _mangle(value: Any, rng: random.Random, chance: float) -> Any:
    """The same JSON with some of its values replaced by what no manager writes there."""
    odd: List[Any] = [None, 5, -1, 1.5, True, False, "", "x", "any", "0.0.0.0/0", [], {}, [None], [[]], [5, "x"], {"type": 5}, {"id": []},
                      {"name": {}}, {"objects": 5}, {"objects": [5, None, [], {}]}, {"literals": [{"type": "x"}, {"value": []}, 7]},
                      {"type": "nothing", "id": {}, "name": []}, "9" * 400, "\x00😀‮", 10**30]  # fmt: skip
    if rng.random() < chance:
        return rng.choice(odd)
    if isinstance(value, dict):
        out = {key: _mangle(inner, rng, chance) for key, inner in value.items() if rng.random() > chance / 2}
        if rng.random() < chance:
            out[rng.choice(["type", "id", "name", "objects", "literals", "value", "metadata", "action", "port", "protocol", "new"])] = rng.choice(odd)
        return out
    if isinstance(value, list):
        return [_mangle(inner, rng, chance) for inner in value]
    return value


@pytest.mark.parametrize("sample", ["fmc_sample.json", "fdm_sample.txt"])
def test_json_that_is_not_what_a_manager_writes_never_crashes(sample: str) -> None:
    """Whatever stands where a value is expected: a policy that says what it could not read, or an error that says why."""
    data = (DATA / sample).read_bytes()
    dialect = cli.detect_format(data)
    documents = json.loads(data)
    whole = len(read(data)[0].rules)
    read_fine = errors = 0
    for seed in range(250):
        rng = random.Random(seed)
        mangled = json.dumps(_mangle(documents, rng, rng.choice([0.002, 0.01, 0.05, 0.2]))).encode()
        try:
            p, report = read(mangled, dialect)
        except ParseError:
            errors += 1
            continue
        read_fine += 1
        # What is left is a policy the emitters can write. (That nothing unreadable is read as "any" is tested below.)
        for target in ("fmc", "fdm", "panos", "asa"):
            cli.convert(p, target, Report())
    assert read_fine > 150 and errors < 100 and whole > 5, (read_fine, errors)


ODD: List[Any] = [5, -1, 1.5, True, False, "", "x", "any", "0.0.0.0/0", [None], [[]], [5, "x"], ["any"], {"objects": 5}, {"objects": [5, None, [], {}]},
                  {"literals": [{"type": "x"}, {"value": []}, 7]}, {"objects": "any"},
                  [{"type": "nothing", "id": {}, "name": []}], {"objects": [{"type": "Network", "name": "any"}]}, "9" * 400, 10**30,
                  {"objects": [{"name": "any-ipv4"}]}, [{"name": "any"}], {"any": True}]  # fmt: skip
NOTHING: List[Any] = [None, [], {}, {"type": "x"}, {"objects": []}, {"objects": [], "literals": []}, {"objects": None}]


@pytest.mark.parametrize("fdm", [False, True])
@pytest.mark.parametrize("field", ["sourceZones", "destinationZones", "sourceNetworks", "destinationNetworks", "sourcePorts", "destinationPorts"])
def test_a_condition_that_cannot_be_read_is_never_no_condition(fdm: bool, field: str) -> None:
    def setup() -> Tuple[Manager, Ref]:
        m = Manager(fdm)
        rule = m.rule("narrow", src_zones=[m.zone("inside")], dst_zones=[m.zone("outside")], sources=[m.network("lan", "10.1.0.0/16")],
                      destinations=[m.host("srv", "192.0.2.10")], src_ports=[m.tcp("high", "1024-65535")], dst_ports=[m.tcp("web", "443")])  # fmt: skip
        return m, rule

    hit = Packet("inside", "outside", "10.1.2.3", "192.0.2.10", "tcp", 2000, 443)
    m, rule = setup()
    p, report = read(m.export() if fdm else m.api())
    assert model_verdict(p, hit) and not one_rule(m, p, "narrow").unsupported
    refused = 0
    for value in ODD:
        m, rule = setup()
        rule[field] = value
        try:
            p, report = read(m.export() if fdm else m.api())
        except ParseError:  # a type of the other manager in it: the file is not read at all
            refused += 1
            continue
        found = one_rule(m, p, "narrow")
        for target in ("panos", "fmc", "fdm"):
            out = Report()
            cli.convert(p, target, out)
            item = out.item("rule", "narrow")
            assert item.disabled or item.skipped, (field, value, found, target)
    assert refused <= 1
    # A condition that is there and holds nothing is a rule without that condition, as the manager shows it.
    for value in NOTHING:
        m, rule = setup()
        rule[field] = value
        p, report = read(m.export() if fdm else m.api())
        found = one_rule(m, p, "narrow")
        assert not found.unsupported and model_verdict(p, hit), (field, value)
        wide = {"sourceZones": found.src_zones, "destinationZones": found.dst_zones, "sourceNetworks": found.sources,
                "destinationNetworks": found.destinations}  # fmt: skip
        assert wide.get(field, [ANY]) == [ANY]


@pytest.mark.parametrize("fdm", [False, True])
@pytest.mark.parametrize("field", ["originalSource", "translatedSource", "originalDestination", "translatedDestination", "sourceInterface",
                                   "destinationInterface", "originalDestinationPort", "translatedDestinationPort", "natType", "patOptions"])  # fmt: skip
def test_a_field_of_a_nat_rule_that_cannot_be_read_stops_the_rule(fdm: bool, field: str) -> None:
    refused = 0
    for value in ODD:
        m, o = nat_setup(fdm)
        nat = m.manual_nat("STATIC", originalSource=o["any4"], translatedSource=o["any4"], originalDestination=o["pub"], translatedDestination=o["srv"],
                           originalDestinationPort=o["web"], translatedDestinationPort=o["alt"], sourceInterface=o["outside"], destinationInterface=o["dmz"])  # fmt: skip
        nat[field] = value
        try:
            found, p, report = nats(m)
        except ParseError:
            refused += 1
            continue
        rule = p.nat_rules[0]
        out = Report()
        cli.convert(p, "panos", out)
        assert rule.unsupported or out.item("nat", rule.origin).skipped, (field, value, rule)
    assert refused <= 1


@pytest.mark.parametrize("fdm,field", [(False, "action"), (False, "enabled"), (True, "ruleAction")])
def test_an_action_or_a_switch_that_cannot_be_read_allows_nothing(fdm: bool, field: str) -> None:
    hit = Packet("inside", "outside", "10.1.2.3", "192.0.2.10", "tcp", 2000, 443)
    for value in ODD + ["allow ", "PERMIT_ALL", ["ALLOW"], {"action": "ALLOW"}, "yes", 1, "true", None]:
        if field == "enabled" and isinstance(value, bool):
            continue
        m = Manager(fdm)
        rule = m.rule("r", sources=[m.network("lan", "10.1.0.0/16")])
        rule[field] = value
        try:
            p, report = read(m.export() if fdm else m.api())
        except ParseError as error:
            assert "convert them apart" in str(error)
            continue
        assert not model_verdict(p, hit) or p.rules[0].unsupported
        for target in ("panos", "fmc", "fdm"):
            out = Report()
            cli.convert(p, target, out)
            assert out.item("rule", "r").disabled or out.item("rule", "r").skipped, (value, target, p.rules)


@pytest.mark.parametrize("fdm", [False, True])
@pytest.mark.parametrize("kind", ["network", "port"])
def test_a_group_that_cannot_be_read_is_not_an_empty_group(fdm: bool, kind: str) -> None:
    for key in ("objects", "literals"):
        for value in ODD:
            if kind == "port" and key == "literals" and value in (False, ""):
                continue  # a field a port group does not have, and nothing in it
            m = Manager(fdm)
            group = m.group("g", [m.host("h", "10.1.1.1")]) if kind == "network" else m.port_group("g", [m.tcp("web", "443")])
            group[key] = value
            m.rule("r", **({"sources": [group]} if kind == "network" else {"dst_ports": [group]}))
            try:
                p, report = read(m.export() if fdm else m.api())
            except ParseError as error:
                assert "convert them apart" in str(error)
                continue
            for target in ("panos", "fmc", "fdm"):
                out = Report()
                cli.convert(p, target, out)
                assert out.item("rule", "r").disabled or out.item("rule", "r").skipped, (key, value, target, p.address_groups, p.service_groups)


# -- what is written, case by case ------------------------------------------------------------------


def model(*rules: Rule, vendor: str = "panos") -> Policy:
    p = Policy(vendor=vendor, default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.addresses = {
        "net-a": Address("net-a", AddressKind.NETWORK, "10.0.0.0/24", "Network A"),
        "host-a": Address("host-a", AddressKind.NETWORK, "10.0.0.17/32"),
        "span": Address("span", AddressKind.RANGE, "10.0.2.100-10.0.3.50"),
        "aligned": Address("aligned", AddressKind.RANGE, "10.0.4.0-10.0.4.255"),
        "six": Address("six", AddressKind.NETWORK, "2001:db8:1::/48"),
        "name": Address("name", AddressKind.FQDN, "www.example.com"),
        "name4": Address("name4", AddressKind.FQDN, "v4.example.com", fqdn_family=4),
        "all4": Address("all4", AddressKind.NETWORK, "0.0.0.0/0"),
        "all6": Address("all6", AddressKind.NETWORK, "::/0"),
        "broken": Address("broken", AddressKind.UNSUPPORTED, "", raw="geo region"),
    }
    p.address_groups = {
        "inner": AddressGroup("inner", ["host-a", "span"]),
        "outer": AddressGroup("outer", ["inner", "net-a", "192.0.2.7", "192.0.2.64/26", "198.51.100.1-198.51.100.9"]),
        "with-name": AddressGroup("with-name", ["net-a", "name"]),
        "names-only": AddressGroup("names-only", ["name", "name4"]),
        "over-names": AddressGroup("over-names", ["with-name", "six"]),
        "empty": AddressGroup("empty", []),
        "bad-group": AddressGroup("bad-group", ["net-a", "broken"]),
    }
    p.services = {
        "web": Service("web", [ServiceEntry(Protocol.TCP, "80,443")], "Web"),
        "one": Service("one", [ServiceEntry(Protocol.TCP, "8080")]),
        "dns-both": Service("dns-both", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")]),
        "echo": Service("echo", [ServiceEntry(Protocol.ICMP, icmp_type=8)]),
        "echo6": Service("echo6", [ServiceEntry(Protocol.ICMP6, icmp_type=128)]),
        "coded": Service("coded", [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)]),
        "gre": Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)]),
        "odd-proto": Service("odd-proto", [ServiceEntry(Protocol.IP, ip_protocol=253)]),
        "sctp": Service("sctp", [ServiceEntry(Protocol.SCTP)]),
        "sctp-port": Service("sctp-port", [ServiceEntry(Protocol.SCTP, "2905")]),
        "from-high": Service("from-high", [ServiceEntry(Protocol.TCP, "22", "1024-65535")]),
        "from-dns": Service("from-dns", [ServiceEntry(Protocol.UDP, "", "53")]),
        "mixed-src": Service("mixed-src", [ServiceEntry(Protocol.TCP, "22", "1024-65535"), ServiceEntry(Protocol.TCP, "23"),
                                           ServiceEntry(Protocol.UDP, "161", "161")]),  # fmt: skip
        "all-tcp": Service("all-tcp", [ServiceEntry(Protocol.TCP, "1-65535")]),
        "zero": Service("zero", [ServiceEntry(Protocol.TCP, "0-1023")]),
        "only-zero": Service("only-zero", [ServiceEntry(Protocol.TCP, "0")]),
        "everything": Service("everything", [ServiceEntry(Protocol.IP)]),
        "tcp-proto": Service("tcp-proto", [ServiceEntry(Protocol.IP, ip_protocol=6)]),
        "icmp-proto": Service("icmp-proto", [ServiceEntry(Protocol.IP, ip_protocol=1)]),
        "code-only": Service("code-only", [ServiceEntry(Protocol.ICMP, icmp_code=3)]),
        "odd-icmp": Service("odd-icmp", [ServiceEntry(Protocol.ICMP, icmp_type=200)]),
        "nothing": Service("nothing", []),
    }
    p.service_groups = {
        "plain-group": ServiceGroup("plain-group", ["web", "echo"]),
        "nested": ServiceGroup("nested", ["plain-group", "one"]),
        "with-gre": ServiceGroup("with-gre", ["one", "gre"]),
        "with-src": ServiceGroup("with-src", ["one", "from-high"]),
        "with-all": ServiceGroup("with-all", ["one", "everything"]),
        "bad-services": ServiceGroup("bad-services", ["one", "sctp-port"]),
    }
    for rule in rules:
        rule.origin = rule.origin or rule.name
        p.rules.append(rule)
    return p


def written(config: CiscoConfig, name: str) -> Dict[str, Any]:
    found = [rule for rule in config.rules if rule["name"] == name]
    assert len(found) == 1, (name, [rule["name"] for rule in config.rules])
    return found[0]


def steps(config: CiscoConfig) -> List[Tuple[str, List[str]]]:
    return [(step["type"], [item["name"] for item in step["items"]]) for step in config.plan["steps"]]


def entries(config: CiscoConfig, kind: str = "") -> List[Dict[str, Any]]:
    """The objects of an import file of a Device Manager, in the order of the file."""
    listed = [entry["data"] for entry in json.loads(config.text)[1:]]
    return [data for data in listed if not kind or data["type"] == kind]


@pytest.mark.parametrize("target", TARGETS)
def test_address_objects_and_groups_as_they_are_written(target: str) -> None:
    p = model(
        Rule("groups", sources=["outer"], destinations=["with-name", "names-only", "over-names"]),
        Rule("literals", sources=["192.0.2.7", "192.0.2.64/26", "198.51.100.1-198.51.100.9", "10.0.4.0-10.0.4.255"], destinations=["aligned", "span"]),
        Rule("full", sources=["all4"], destinations=["all6", "::/0"]),
        Rule("both-full", sources=["all4", "all6"], destinations=["0.0.0.0/0"]),
        Rule("names", sources=["name", "name4", "six"]),
        Rule("bad", sources=["broken"], action=Action.DENY), Rule("bad-in-group", sources=["bad-group"]), Rule("no-members", sources=["empty"]),
    )  # fmt: skip
    config, report, text = convert(p, target)
    kinds = {name: held["kind"] for name, held in config.networks.items()}
    # A host, a network and a range are three kinds of object; a range stays one even where it is a whole network.
    assert [kinds[name] for name in ("host-a", "net-a", "span", "aligned", "six", "name")] == ["host", "network", "range", "range", "network", "fqdn"]
    assert config.networks["name4"]["resolution"] == "IPV4_ONLY" and config.networks["name"]["resolution"] == "IPV4_AND_IPV6"
    # What a rule or a group spells out gets an object, one per value.
    assert (kinds["h-192.0.2.7"], kinds["n-192.0.2.64_26"], kinds["r-198.51.100.1-198.51.100.9"]) == ("host", "network", "range")
    assert written(config, "literals")["sources"] == ["h-192.0.2.7", "n-192.0.2.64_26", "r-198.51.100.1-198.51.100.9", "aligned"]
    # A group of a Management Center holds groups; a Device Manager is given the objects.
    assert config.networks["outer"]["members"] == (["inner"] if target == "fmc" else ["host-a", "span"]) + [
        "net-a", "h-192.0.2.7", "n-192.0.2.64_26", "r-198.51.100.1-198.51.100.9"]  # fmt: skip
    # No group holds a host name: the group is written without it and the rules name it.
    assert config.networks["with-name"]["members"] == ["net-a"] and "names-only" not in config.networks
    assert config.networks["over-names"]["members"] == (["with-name", "six"] if target == "fmc" else ["net-a", "six"])
    assert written(config, "groups")["destinations"] == ["with-name", "name", "name4", "over-names"]
    assert codes(report, "address-group", "with-name") == codes(report, "address-group", "names-only") == ["GROUP_SPLIT"]
    assert report.item("address-group", "names-only").emitted_as == ["name", "name4"] and "FQDN_DNS" in notes(report)
    # Every address of an IP version is an object the manager has; both together is no condition.
    assert "all4" not in config.networks and codes(report, "address", "all4") == ["PREDEFINED_OBJECT"]
    assert (written(config, "full")["sources"], written(config, "full")["destinations"]) == (["any-ipv4"], ["any-ipv6"])
    assert (written(config, "both-full")["sources"], written(config, "both-full")["destinations"]) == (None, ["any-ipv4"])
    assert config.used_existing == ["any-ipv4", "any-ipv6"]
    # What could not be converted allows nothing: the rule is there and switched off, or it is not there.
    lost = ["bad", "bad-in-group", "no-members"]
    assert all(codes(report, "rule", name) == ["UNCONVERTIBLE_OBJECT"] for name in lost)
    assert "This deny rule is NOT enforced" in report.item("rule", "bad").findings[0].message
    if target == "fmc":
        assert [written(config, name)["enabled"] for name in lost] == [False] * 3 and all(report.item("rule", name).disabled for name in lost)
        assert written(config, "bad")["comment"] == "FWSHIFT: disabled by the converter, see the report."
        # The objects those rules name keep their names and are one address nothing has.
        assert [config.networks[name]["intervals"] for name in ("broken", "bad-group", "empty")] == [[(4, 3221225480, 3221225480)]] * 3
        assert "FWSHIFT PLACEHOLDER, matches nothing: geo region" in text
        # One call per kind of object, in the order they can be created; groups level by level.
        made = steps(config)
        assert [kind for kind, _ in made] == ["Host", "Network", "Range", "FQDN", "NetworkGroup", "NetworkGroup", "ProtocolPortObject",
                                              "ICMPV4Object", "ICMPV6Object", "PortObjectGroup"]  # fmt: skip
        assert made[4][1] == ["inner", "with-name"] and made[5][1] == ["outer", "over-names"]
    else:
        assert all(report.item("rule", name).skipped for name in lost) and not set(lost) & {rule["name"] for rule in config.rules}
        assert not {"broken", "bad-group", "empty"} & set(config.networks)
        # One file, the objects before the rules (the reader of the test checks that nothing is named before it is there).
        kinds_in_order = [data["type"] for data in entries(config)]
        assert kinds_in_order[-1] == "accessrule" and "manualnatrule" not in kinds_in_order


@pytest.mark.parametrize("target", TARGETS)
def test_services_as_they_are_written(target: str) -> None:
    services, groups = model().services, model().service_groups
    rules = [Rule(f"r-{name}", services=[name]) for name in services] + [Rule(f"g-{name}", services=[name]) for name in groups]
    rules += [Rule("several", services=["web", "gre", "echo", "from-high"]), Rule("any-and", services=["one", "everything"]),
              Rule("from-all", services=["from-dns", "all-tcp"])]  # fmt: skip
    config, report, text = convert(model(*rules), target)
    fmc = target == "fmc"

    def ports(name: str) -> Tuple[Optional[List[Any]], Optional[List[Any]]]:
        return written(config, name)["src_ports"], written(config, name)["dst_ports"]

    # A port object is one port or range of one protocol: more is a group of them, under the name of the service.
    assert config.ports["web"] == {"kind": "group", "members": ["tcp-80", "tcp-443"], **({"fmc": "PortObjectGroup"} if fmc else {"fdm": "portobjectgroup"})}
    assert config.ports["dns-both"]["members"] == ["tcp-53", "udp-53"] and codes(report, "service", "web") == ["SERVICE_SPLIT"]
    assert (config.ports["one"]["low"], config.ports["one"]["high"], config.ports["one"]["protocol"]) == (8080, 8080, "tcp")
    assert ports("r-web") == (None, ["web"]) and ports("r-one") == (None, ["one"])
    # No port group holds a port group.
    assert config.ports["plain-group"]["members"] == ["tcp-80", "tcp-443", "echo"] and config.ports["nested"]["members"] == ["tcp-80", "tcp-443", "echo", "one"]
    assert (config.ports["echo"]["kind"], config.ports["echo"]["type"], config.ports["echo6"]["kind"], config.ports["coded"]["type"]) == ("icmp4", 8, "icmp6", 3)
    assert (config.ports["coded"]["code"], config.ports["echo"]["code"]) == (4, None)
    # Ping written with its code, as several platforms do: a Device Manager has no codes for that type, and the type says it.
    pinged = model(Rule("r", services=["ping0", "unreach0"]))
    pinged.services["ping0"] = Service("ping0", [ServiceEntry(Protocol.ICMP, icmp_type=8, icmp_code=0)])
    pinged.services["unreach0"] = Service("unreach0", [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=0)])
    with_codes, told, _ = convert(pinged, target)
    assert (with_codes.ports["ping0"]["type"], with_codes.ports["ping0"]["code"]) == (8, 0 if fmc else None)
    assert (with_codes.ports["unreach0"]["type"], with_codes.ports["unreach0"]["code"]) == (3, 0)  # a type that has codes keeps its own
    assert codes(told, "service", "ping0") == ([] if fmc else ["ICMP_CODE"]) and not codes(told, "service", "unreach0")
    # Another protocol: a number in the rule on a Management Center, an object with its name on a Device Manager.
    assert ports("r-gre") == (None, [47] if fmc else ["gre"]) and ports("r-sctp") == (None, [132] if fmc else ["sctp"])
    assert ports("g-with-gre") == (None, ["one", 47] if fmc else ["with-gre"])
    assert ("gre" in config.ports, "with-gre" in config.ports) == (not fmc, not fmc)
    # TCP, UDP and ICMP said as protocols are the objects for them.
    assert (config.ports["tcp-proto"]["low"], config.ports["tcp-proto"]["high"]) == ((0, 65535) if fmc else (1, 65535))
    assert config.ports["icmp-proto"]["kind"] == "icmp4" and config.ports["icmp-proto"]["type"] is None
    assert config.ports["zero"]["low"] == 1 and codes(report, "service", "zero") == ["PORT_ZERO"]
    # Every protocol is a rule without ports, also where it stands next to others.
    assert ports("r-everything") == ports("g-with-all") == ports("any-and") == (None, None)
    # Source ports are a condition of their own: a rule per set of them, each with the destination ports that go with it.
    assert ports("r-from-high") == (["tcp-1024-65535"], ["tcp-22"]) and ports("r-from-dns") == (["udp-53"], None)
    assert [ports(name) for name in ("r-mixed-src", "r-mixed-src-2", "r-mixed-src-3")] == [
        (None, ["tcp-23"]), (["tcp-1024-65535"], ["tcp-22"]), (["udp-161"], ["udp-161"])]
    assert codes(report, "rule", "r-mixed-src") == ["RULE_SPLIT"] and report.item("rule", "r-mixed-src").emitted_as == ["r-mixed-src", "r-mixed-src-2", "r-mixed-src-3"]
    assert [ports(name) for name in ("g-with-src", "g-with-src-2")] == [(None, ["one"]), (["tcp-1024-65535"], ["tcp-22"])]
    assert [ports(name) for name in ("several", "several-2")] == [(None, ["web", "echo", 47] if fmc else ["web", "gre", "echo"]), (["tcp-1024-65535"], ["tcp-22"])]
    assert [ports(name) for name in ("from-all", "from-all-2")] == [(None, ["all-tcp"]), (["udp-53"], None)]
    # A port that has an object under a name of the source is that object, also in a group that is made for another service.
    p = model(Rule("r", services=["late-group"]))
    p.services["late-group"] = Service("late-group", [ServiceEntry(Protocol.TCP, "8080,9090"), ServiceEntry(Protocol.UDP, "53")])
    p.services["udp-53"] = Service("udp-53", [ServiceEntry(Protocol.UDP, "53")])
    again, said, _ = convert(p, target)
    assert again.ports["late-group"]["members"] == ["one", "tcp-9090", "udp-53"] and "udp-53_2" not in again.ports
    # What a port object cannot say is not written as something else.
    lost = ["r-sctp-port", "r-only-zero", "r-code-only", "r-nothing", "g-bad-services"] + ([] if fmc else ["r-odd-proto", "r-odd-icmp"])
    for name in lost:
        assert codes(report, "rule", name) == ["UNCONVERTIBLE_OBJECT"], name
        assert report.item("rule", name).disabled if fmc else report.item("rule", name).skipped
    assert [codes(report, "service", name) for name in ("sctp-port", "only-zero", "code-only")] == [["UNSUPPORTED_SERVICE"]] * 3
    assert "SCTP ports, which a port object cannot name" in report.item("service", "sctp-port").findings[0].message
    if fmc:
        assert ports("r-odd-proto") == (None, [253]) and config.ports["odd-icmp"]["type"] == 200
        assert "FWSHIFT PLACEHOLDER for a service that was not converted (TCP port 1 stands in): SCTP ports" in text
        assert not written(config, "r-sctp-port")["enabled"] and ports("r-sctp-port") == (None, ["sctp-port"])
    else:
        assert "IP protocol 253, which a Device Manager has no name for" in report.item("service", "odd-proto").findings[0].message
        assert "ICMP type 200, which a Device Manager has no name for" in report.item("service", "odd-icmp").findings[0].message
        by_name = {data["name"]: data for data in entries(config)}
        assert by_name["gre"] == {"type": "protocolobject", "name": "gre", "protocol": "GRE"}
        assert by_name["sctp"]["protocol"] == "SCTP" and by_name["all-tcp"]["port"] == "1-65535"
        assert (by_name["echo"]["icmpv4Type"], by_name["echo6"]["icmpv6Type"], by_name["icmp-proto"]["icmpv4Type"]) == ("ECHO_REQUEST", "ECHO_REQUEST", "ANY")
        assert (by_name["coded"]["icmpv4Type"], by_name["coded"]["icmpv4Code"]) == ("DESTINATION_UNREACHABLE", "FRAGMENTATION_NEEDED")
        assert "icmpv4Code" not in by_name["echo"] and not {"sctp-port", "only-zero", "nothing", "bad-services"} & set(by_name)


@pytest.mark.parametrize("target", TARGETS)
def test_names_the_manager_takes(target: str) -> None:
    p = model(Rule("Rule with spaces & signs!", sources=["Obj With Space", "ANY-ipv4", "Net-A", "net-a"], services=["HTTP", "http", "Tcp/8080"]),
              Rule("x" * 200), Rule("x" * 199 + "y"), Rule("dup"), Rule("DUP"), Rule("ünïcödé"), Rule(" "))  # fmt: skip
    p.addresses["Obj With Space"] = Address("Obj With Space", AddressKind.NETWORK, "10.9.0.0/24")
    p.addresses["ANY-ipv4"] = Address("ANY-ipv4", AddressKind.NETWORK, "10.9.1.0/24")
    p.addresses["Net-A"] = Address("Net-A", AddressKind.NETWORK, "10.9.2.0/24")
    p.addresses["y" * 100] = Address("y" * 100, AddressKind.NETWORK, "10.9.3.0/24")
    p.services["HTTP"] = Service("HTTP", [ServiceEntry(Protocol.TCP, "80")])
    p.services["http"] = Service("http", [ServiceEntry(Protocol.TCP, "8000")])
    p.services["Tcp/8080"] = Service("Tcp/8080", [ServiceEntry(Protocol.TCP, "8080")])
    p.rules[0].src_zones = ["Zone One", "trust"]
    config, report, text = convert(p, target)  # the reader of the test refuses a name the manager would refuse, or has already
    first = config.rules[0]
    # Two names that differ by case only are one name to a manager; a name the manager has for an object of its own is taken.
    assert first["sources"] == ["Obj_With_Space", "ANY-ipv4_2", "Net-A_2", "net-a"] and first["dst_ports"] == ["HTTP_2", "http_3", "Tcp_8080"]
    assert all(codes(report, "address", name) == ["RENAMED"] for name in ("Obj With Space", "ANY-ipv4", "Net-A", "y" * 100))
    assert "y" * 64 in config.networks and "y" * 65 not in config.networks
    assert (config.ports["HTTP_2"]["low"], config.ports["http_3"]["low"]) == (80, 8000)
    limit = 50 if target == "fmc" else 128
    names = [rule["name"] for rule in config.rules]
    assert names[0] == ("Rule with spaces _ signs_" if target == "fmc" else "Rule_with_spaces___signs_")
    assert names[1:3] == ["x" * limit, "x" * (limit - 2) + "_2"] and names[3:6] == ["dup", "DUP_2", "x_n_c_d_"]
    assert report.item("rule", "DUP").emitted_as == ["DUP_2"]
    assert first["src_zones"] == ["Zone_One", "trust"] and "'Zone One' to 'Zone_One'" in report.notes[0].message
    # A prefix gives every object that is created a name of its own; rules, zones and what the manager has keep theirs.
    config, report, text = convert(p, target, Options(object_prefix="mig-", target_policy="Migrated policy"))
    assert all(name.startswith("mig-") or name in ("any-ipv4", "any-ipv6") for name in config.networks)
    assert all(name.startswith("mig-") for name in config.ports)
    assert config.rules[0]["sources"] == ["mig-Obj_With_Space", "mig-ANY-ipv4", "mig-Net-A_2", "mig-net-a"] and config.rules[0]["dst_ports"][0] == "mig-HTTP"
    assert config.rules[0]["src_zones"] == ["Zone_One", "trust"] and config.rules[3]["name"] == "dup"
    if target == "fmc":
        assert config.plan["policy"] == "Migrated policy" and config.plan["zones"] == ["Zone_One", "trust"]
        assert "a new access control policy 'Migrated policy'" in report.notes[1].message
    for options, message in ((Options(object_prefix="bad prefix"), "--target-prefix takes up to 20 letters"),
                             (Options(object_prefix="p" * 21), "--target-prefix takes up to 20 letters")):  # fmt: skip
        with pytest.raises(cli.FwshiftError, match=message):
            cli.convert(p, target, Report(), options)
    with pytest.raises(cli.FwshiftError, match="--target-policy: control characters are not allowed"):
        cli.convert(p, target, Report(), Options(target_policy="line\nbreak"))
    for name in ("", "x" * 51, "semi;colon"):
        if target == "fmc":
            with pytest.raises(cli.FwshiftError, match="is not a name a Management Center takes for a policy"):
                cli.convert(p, target, Report(), Options(target_policy=name))
        else:
            cli.convert(p, target, Report(), Options(target_policy=name))  # a Device Manager has one policy: the option says nothing


@pytest.mark.parametrize("target", TARGETS)
def test_rules_as_they_are_written(target: str) -> None:
    z: Dict[str, Any] = {"src_zones": ["inside"], "dst_zones": ["outside"]}
    p = model(
        Rule("not-src", sources=["net-a"], negate_source=True, **z),
        Rule("not-dst", destinations=["host-a", "span"], negate_destination=True, action=Action.DENY, **z),
        Rule("not-name", sources=["name"], negate_source=True, action=Action.DENY),
        Rule("not-any", sources=[ANY], negate_source=True), Rule("not-all", sources=["all4", "all6"], negate_source=True),
        Rule("not-v4", sources=["all4"], negate_source=True),
        Rule("not-svc", services=["web"], negate_service=True), Rule("not-any-svc", services=[ANY], negate_service=True),
        Rule("intra", src_zones=["inside", "dmz"], dst_zones=["inside", "dmz"], scope=RuleScope.INTRAZONE),
        Rule("inter", src_zones=["inside", "dmz"], dst_zones=["inside", "dmz"], scope=RuleScope.INTERZONE),
        Rule("inter-one", src_zones=["inside"], dst_zones=["inside"], scope=RuleScope.INTERZONE),
        Rule("intra-any", scope=RuleScope.INTRAZONE),
        Rule("off", enabled=False, **z),
        Rule("deny", action=Action.DENY, log_end=False, **z), Rule("drop", action=Action.DROP, log_start=True, log_end=True),
        Rule("reset-c", action=Action.RESET_CLIENT), Rule("reset-s", action=Action.RESET_SERVER), Rule("reset-b", action=Action.RESET_BOTH),
        Rule("quiet", log_end=False), Rule("both-logs", log_start=True), Rule("start-only", log_start=True, log_end=False),
        Rule("user", users=["alice"]), Rule("url", url_categories=["gambling"], action=Action.DENY),
        Rule("app", applications=["ssl", "web-browsing"], services=["application-default"]),
        Rule("app-unknown", applications=["made-up-app"], services=["application-default"]),
        Rule("timed", schedule="office-hours"), Rule("profile", profiles={"virus": "strict"}),
        Rule("unsup", unsupported=["something the source said"]),
        Rule("described", description="A rule\nwith two lines and a tab\there " + "x" * 600),
    )  # fmt: skip
    config, report, text = convert(p, target)
    fmc = target == "fmc"
    there = {rule["name"] for rule in config.rules}
    # No rule negates: the addresses that are left are written, for IPv4 and IPv6.
    assert written(config, "not-src")["sources"] == ["r-0.0.0.0-9.255.255.255", "r-10.0.1.0-255.255.255.255", "any-ipv6"]
    assert written(config, "not-dst")["destinations"] == ["r-0.0.0.0-10.0.0.16", "r-10.0.0.18-10.0.2.99", "r-10.0.3.51-255.255.255.255", "any-ipv6"]
    assert written(config, "not-v4")["sources"] == ["any-ipv6"] and codes(report, "rule", "not-src") == ["NEGATION_AS_ADDRESSES"]
    for src, dst, expected in (("10.0.0.5", "192.0.2.1", False), ("10.0.1.5", "192.0.2.1", True), ("2001:db8::1", "2001:db8::2", True)):
        assert config.allows(Packet("inside", "outside", src, dst, "tcp", 1024, 80)) == expected, src
    # The host that "not-dst" excepts is not decided by it: a later rule is asked.
    assert config.deciding(Packet("inside", "outside", "10.0.0.5", "10.0.0.17", "tcp", 1024, 80))["name"] == "deny"  # type: ignore[index]
    assert config.deciding(Packet("inside", "outside", "10.0.0.5", "10.0.0.18", "tcp", 1024, 80))["name"] == "not-dst"  # type: ignore[index]
    # Not every address is no address; not a host name is not known here: neither is written as a rule for everything.
    assert codes(report, "rule", "not-any") == codes(report, "rule", "not-all") == codes(report, "rule", "not-any-svc") == ["NO_MATCH"]
    assert codes(report, "rule", "not-name") == ["NEGATION"] and report.item("rule", "not-name").skipped
    assert "This deny rule is NOT enforced" in report.item("rule", "not-name").findings[0].message
    assert not {"not-any", "not-all", "not-any-svc", "not-name"} & there
    assert codes(report, "rule", "not-svc") == ["NEGATION"]
    # A rule for the traffic inside zones, or between them, is a rule per pair of zones.
    assert [(written(config, name)["src_zones"], written(config, name)["dst_zones"]) for name in ("intra", "intra-2", "inter", "inter-2")] == [
        (["inside"], ["inside"]), (["dmz"], ["dmz"]), (["inside"], ["dmz"]), (["dmz"], ["inside"])]
    assert codes(report, "rule", "intra") == ["RULE_SPLIT"] and codes(report, "rule", "inter-one") == ["RULE_TYPE_EMPTY"] and "inter-one" not in there
    assert codes(report, "rule", "intra-any") == ["RULE_TYPE"]
    # Actions and logging.
    assert [written(config, name)["action"] for name in ("deny", "drop", "reset-c", "reset-s", "reset-b")] == (
        ["block", "block", "reset", "reset", "reset"] if fmc else ["block"] * 5)
    assert [codes(report, "rule", name) for name in ("reset-c", "reset-s", "reset-b")] == [["RESET_ACTION"], ["RESET_ACTION"], [] if fmc else ["RESET_ACTION"]]
    assert [written(config, name)["log"] for name in ("deny", "drop", "quiet", "both-logs", "start-only")] == [False, True, False, True, True]
    lost = ["not-svc", "intra-any", "user", "url", "app-unknown", "timed", "unsup"]
    wanted = [["NEGATION"], ["RULE_TYPE"], ["USER_MATCH"], ["URL_CATEGORY"], ["APP_UNKNOWN"], ["SCHEDULE"], ["UNSUPPORTED_MATCH"]]
    assert [codes(report, "rule", name) for name in lost] == wanted
    assert written(config, "app")["dst_ports"] == ["tcp-443", "tcp-80"] and codes(report, "rule", "app") == ["APP_TO_PORTS"]
    assert codes(report, "rule", "profile") == ["PROFILES_NOT_CONVERTED"] and written(config, "profile")["enabled"]
    if fmc:
        raw = {rule["name"]: rule for rule in config.plan["rules"]}
        # A rule that blocks has no end of a connection to log.
        assert [(raw[n]["logBegin"], raw[n]["logEnd"]) for n in ("deny", "drop", "quiet", "both-logs", "start-only", "reset-b")] == [
            (False, False), (True, False), (False, False), (True, True), (True, False), (True, False)]
        assert all(not written(config, name)["enabled"] and report.item("rule", name).disabled for name in lost)
        assert not written(config, "off")["enabled"] and not report.item("rule", "off").findings and written(config, "off")["comment"] == ""
        assert written(config, "not-svc")["dst_ports"] == ["web"]  # as it stands it says the opposite: it is there to be finished by hand
        comment = written(config, "described")["comment"]
        assert comment.startswith("A rule with two lines and a tab here xxx") and len(comment) == 500
        assert raw["user"]["newComments"] == ["FWSHIFT: disabled by the converter, see the report."] and "newComments" not in raw["deny"]
        assert notes(report) == ["FMC_LOAD", "ZONES_REQUIRED", "FQDN_DNS"] and config.plan["zones"] == ["inside", "outside", "dmz"]
    else:
        raw = {data["name"]: data for data in entries(config, "accessrule")}
        assert [raw[n]["eventLogAction"] for n in ("deny", "drop", "quiet", "both-logs", "start-only")] == [
            "LOG_NONE", "LOG_BOTH", "LOG_NONE", "LOG_BOTH", "LOG_BOTH"] and raw["described"]["eventLogAction"] == "LOG_FLOW_END"
        # No rule of a Device Manager is switched off: what is, or would have to be, is not in the file.
        assert not set(lost + ["off"]) & there and all(report.item("rule", name).skipped for name in lost + ["off"])
        assert codes(report, "rule", "off") == ["DISABLED_RULE"] and report.item("rule", "off").status == "skipped"
        assert "a Device Manager has no rules that are switched off" in report.item("rule", "user").findings[0].message
        assert "This deny rule is NOT enforced" in report.item("rule", "url").findings[0].message
        assert notes(report) == ["FDM_LOAD", "EXISTING_OBJECTS", "ZONES_REQUIRED", "FQDN_DNS"]
        assert "inside, outside, dmz. Zones are not written" in report.notes[2].message and not entries(config, "securityzone")


# -- NAT, as it is written --------------------------------------------------------------------------


def nat_model(*rules: NatRule, vendor: str = "panos") -> Policy:
    p = model(vendor=vendor)
    p.zones = {"inside": Zone("inside", ["eth1"]), "outside": Zone("outside", ["eth0"]), "dmz": Zone("dmz", ["eth2", "eth3"])}
    p.addresses.update({
        "srv": Address("srv", AddressKind.NETWORK, "10.0.9.10/32"), "srv-pub": Address("srv-pub", AddressKind.NETWORK, "203.0.113.10/32"),
        "pool": Address("pool", AddressKind.RANGE, "203.0.113.100-203.0.113.110"),
        "pool-net": Address("pool-net", AddressKind.NETWORK, "203.0.113.128/28"),
        "one-pub": Address("one-pub", AddressKind.NETWORK, "203.0.113.50/32"), "net-pub": Address("net-pub", AddressKind.NETWORK, "198.51.100.0/24"),
        "six-pub": Address("six-pub", AddressKind.NETWORK, "2001:db8:ffff::/48"), "partner": Address("partner", AddressKind.NETWORK, "192.0.2.0/24"),
    })  # fmt: skip
    for rule in rules:
        rule.origin = rule.origin or rule.name
        p.nat_rules.append(rule)
    return p


IO: Dict[str, Any] = {"src_zones": ["inside"], "dst_zones": ["outside"]}
HIDE = SourceNat(SnatKind.DYNAMIC_PORT, ["one-pub"])
INTERFACES = {"eth0": "outside", "eth1": "inside", "eth2": "dmz", "eth3": "dmz2"}


def nat_cases() -> List[NatRule]:
    return [
        NatRule("exempt", sources=["net-a"], destinations=["partner"], **IO),
        NatRule("hide-if", sources=["net-a"], source_translation=SourceNat(SnatKind.INTERFACE), **IO),
        NatRule("hide-one", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["one-pub"]), **IO),
        NatRule("hide-pool", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pool"]), **IO),
        NatRule("hide-net", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pool-net"]), **IO),
        NatRule("dyn-pool", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC, ["pool"]), **IO),
        NatRule("dyn-one", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC, ["one-pub"]), **IO),
        NatRule("static", sources=["net-a"], source_translation=SourceNat(SnatKind.STATIC, ["net-pub"], bidirectional=True), **IO),
        NatRule("static-oneway", sources=["net-a"], source_translation=SourceNat(SnatKind.STATIC, ["net-pub"]), **IO),
        NatRule("static-size", sources=["net-a"], source_translation=SourceNat(SnatKind.STATIC, ["one-pub"], bidirectional=True), **IO),
        NatRule("dnat", src_zones=["outside"], destinations=["srv-pub"], destination_translation=DestNat("srv")),
        NatRule("dnat-port", src_zones=["outside"], destinations=["srv-pub"], service="one", destination_translation=DestNat("srv", "80")),
        NatRule("dnat-web", src_zones=["outside"], destinations=["srv-pub"], service="web", destination_translation=DestNat("srv")),
        NatRule("dnat-src", src_zones=["outside"], sources=["partner"], destinations=["srv-pub"], service="one", destination_translation=DestNat("srv", "80")),
        NatRule("both", src_zones=["inside"], sources=["net-a"], destinations=["srv-pub"], source_translation=copy_of(HIDE),
                destination_translation=DestNat("srv")),
        NatRule("two-zones", sources=["net-a"], source_translation=copy_of(HIDE), src_zones=["inside", "dmz"], dst_zones=["outside"]),
        NatRule("off", sources=["net-a"], source_translation=copy_of(HIDE), enabled=False, description="Old rule", **IO),
    ]  # fmt: skip


def copy_of(translation: SourceNat) -> SourceNat:
    return SourceNat(translation.kind, list(translation.addresses), translation.interface, translation.interface_address, translation.bidirectional)


def short(rule: Dict[str, Any]) -> Dict[str, Any]:
    """A NAT rule as the reader of the test has it, without what it does not say."""
    return {key: value for key, value in rule.items() if value not in (None, False, "") and key not in ("name", "enabled", "description")}


@pytest.mark.parametrize("target,mapped", [("fmc", False), ("fdm", False), ("fdm", True)])
def test_nat_rules_as_they_are_written(target: str, mapped: bool) -> None:
    p = nat_model(*nat_cases())
    config, report, text = convert(p, target, Options(interface_map=dict(INTERFACES)) if mapped else None)
    fmc = target == "fmc"
    by: Dict[str, List[Dict[str, Any]]] = {}
    for rule in config.nat:  # a rule from another platform carries its name in its description
        by.setdefault(rule["description"].split(" ")[0], []).append(rule)
    named = fmc or mapped  # the rules say where the traffic comes in and goes out
    io = {"src_if": "inside", "dst_if": "outside"} if named else {}
    everyone = {"osrc": "any-ipv4", "tsrc": "any-ipv4"} if fmc else {}  # a Device Manager says "any" by saying nothing
    outside = {"src_if": "outside"} if named else {}

    def one(name: str) -> Dict[str, Any]:
        assert len(by[name]) == 1, (name, by.get(name))
        return short(by[name][0])

    # No translation between two networks: the device's rule for it, with the route deciding the interface.
    assert one("exempt") == {"static": True, "osrc": "net-a", "tsrc": "net-a", "odst": "partner", "tdst": "partner", **io}
    assert one("hide-one") == {"osrc": "net-a", "tsrc": "one-pub", **io}
    # Port address translation to more than one address is a PAT pool; a pool holds hosts and ranges, no subnet.
    assert one("hide-pool") == {"osrc": "net-a", "pool": "pool", **io}
    assert one("hide-net") == {"osrc": "net-a", "pool": "r-203.0.113.128-203.0.113.143", **io}
    assert one("dyn-pool") == {"osrc": "net-a", "tsrc": "pool", **io} and one("dyn-one") == {"osrc": "net-a", "tsrc": "one-pub", **io}
    assert "NAT_DYNAMIC_ONE_ADDRESS" in codes(report, "nat", "dyn-one")
    assert one("static") == {"static": True, "osrc": "net-a", "tsrc": "net-pub", **io}
    assert one("static-oneway") == {"static": True, "unidirectional": True, "osrc": "net-a", "tsrc": "net-pub", **io}
    assert "NAT_STATIC_SIZE" in codes(report, "nat", "static-size") and "256 addresses to 1" in report.item("nat", "static-size").findings[0].message
    # A destination translation decides where the packet goes: the rule names where it comes in, and works one way.
    dnat = {"static": True, "unidirectional": True, "odst": "srv-pub", "tdst": "srv", **outside}
    assert one("dnat") == {**dnat, **everyone}
    assert one("dnat-port") == {**dnat, **everyone, "odp": "one", "tdp": "tcp-80"}
    assert [short(rule) for rule in by["dnat-web"]] == [{**dnat, **everyone, "odp": "tcp-80", "tdp": "tcp-80"}, {**dnat, **everyone, "odp": "tcp-443", "tdp": "tcp-443"}]
    assert report.item("nat", "dnat-web").emitted_as == ["2 NAT rules"]
    assert one("dnat-src") == {**dnat, "osrc": "partner", "tsrc": "partner", "odp": "one", "tdp": "tcp-80"}
    assert one("both") == {"osrc": "net-a", "tsrc": "one-pub", "odst": "srv-pub", "tdst": "srv", **({"src_if": "inside"} if named else {})}
    assert not by["off"][0]["enabled"] and by["off"][0]["description"] == "off Old rule"
    if fmc:
        assert one("hide-if") == {"to_interface": True, "osrc": "net-a", **io}
        assert [(rule["src_if"], rule["dst_if"]) for rule in by["two-zones"]] == [("inside", "outside"), ("dmz", "outside")]
        assert [rule["name"] for rule in config.nat] == [f"nat-{index}" for index in range(1, len(config.nat) + 1)]
        raw = config.plan["nat"]
        assert raw[0]["noProxyArp"] and raw[0]["routeLookup"] and not raw[2]["noProxyArp"]
        assert raw[3]["patOptions"]["patPoolAddress"] == {"@ref": "Range", "name": "pool"} and "translatedSource" not in raw[3]
        assert config.plan["zones"] == ["inside", "outside", "dmz"] and "INTERFACES_REQUIRED" not in notes(report)
    elif mapped:
        # A NAT rule of a Device Manager names interfaces: a rule for each interface of the zone.
        assert one("hide-if") == {"to_interface": True, "osrc": "net-a", **io}
        assert [(rule["name"], rule["src_if"], rule["dst_if"]) for rule in by["two-zones"]] == [
            ("two-zones", "inside", "outside"), ("two-zones-2", "dmz", "outside"), ("two-zones-3", "dmz2", "outside")]
        assert "INTERFACES_REQUIRED" in notes(report) and "inside, outside, dmz, dmz2" in report.notes[notes(report).index("INTERFACES_REQUIRED")].message
        raw_rule = next(data for data in entries(config, "manualnatrule") if data["name"] == "hide-if")
        assert raw_rule["sourceInterface"] == {"type": "physicalinterface", "name": "inside"}
        assert all(not codes(report, "nat", rule.name) or codes(report, "nat", rule.name)[0] != "NAT_ZONES" for rule in p.nat_rules)
    else:
        # Which interfaces a zone has on the target is not known: the rule is written for any interface, and that is said.
        assert codes(report, "nat", "exempt") == ["NAT_ZONES"] and report.item("nat", "exempt").status == "approximated"
        assert "Name them with --interface-map" in report.item("nat", "exempt").findings[0].message
        assert len(by["two-zones"]) == 1 and codes(report, "nat", "two-zones")[:2] == ["NAT_ZONES", "NAT_ZONES"]
        # The address of an interface that is not known cannot be written at all.
        assert "hide-if" not in by and codes(report, "nat", "hide-if") == ["NAT_NOT_CONVERTED"] and "--interface-map" in report.item("nat", "hide-if").findings[0].message
        assert "INTERFACES_REQUIRED" not in notes(report)
    if not fmc:
        holders = {entry["parentName"] for entry in json.loads(text)[1:] if entry["data"]["type"] == "manualnatrule"}
        assert holders == {"NGFW-Before-Auto-NAT-Policy"}


NOT_WRITTEN = [
    (NatRule("v6", sources=["net-a"], source_translation=SourceNat(SnatKind.STATIC, ["six-pub"]), **IO), "NAT_ADDRESSES", "translation between IPv4 and IPv6"),
    (NatRule("mixed", sources=["net-a", "six"], source_translation=copy_of(HIDE), **IO), "NAT_ADDRESSES", "no group with IPv4 and IPv6 addresses"),
    (NatRule("fqdn-src", sources=["name"], source_translation=copy_of(HIDE), **IO), "NAT_ADDRESSES", "static addresses as source"),
    (NatRule("fqdn-dst", sources=["net-a"], destinations=["name"], source_translation=copy_of(HIDE), **IO), "NAT_ADDRESSES", "static addresses as destination"),
    (NatRule("fqdn-pool", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["name"]), **IO), "NAT_POOL", "not static addresses"),
    (NatRule("dnat-two", src_zones=["outside"], destinations=["srv-pub", "one-pub"], destination_translation=DestNat("srv")), "NAT_DESTINATION", "one static address object on each side"),
    (NatRule("dnat-any", src_zones=["outside"], destination_translation=DestNat("srv")), "NAT_DESTINATION", "one static address object on each side"),
    (NatRule("svc-icmp", sources=["net-a"], service="echo", source_translation=copy_of(HIDE), **IO), "NAT_SERVICE", "not a TCP or UDP service"),
    (NatRule("svc-all", sources=["net-a"], service="all-tcp", source_translation=copy_of(HIDE), **IO), "NAT_SERVICE", "every port of a protocol"),
    (NatRule("svc-src", sources=["net-a"], service="from-high", source_translation=copy_of(HIDE), **IO), "NAT_SERVICE", "without source ports"),
    (NatRule("port-no-svc", src_zones=["outside"], destinations=["srv-pub"], destination_translation=DestNat("srv", "80")), "NAT_PORT", "needs a TCP or UDP service"),
    (NatRule("range-to-port", src_zones=["outside"], destinations=["srv-pub"], service="zero", destination_translation=DestNat("srv", "80")), "NAT_PORT", "a port range cannot be translated to one port"),
    (NatRule("bad-ref", sources=["broken"], source_translation=copy_of(HIDE), **IO), "NAT_NOT_CONVERTED", "references 'broken': geo region"),
    (NatRule("unsup", sources=["net-a"], unsupported=["a thing"], **IO), "NAT_NOT_CONVERTED", "not converted: a thing"),
    (NatRule("hide-if-any", sources=["net-a"], source_translation=SourceNat(SnatKind.INTERFACE), src_zones=["inside"]), "NAT_NOT_CONVERTED", "--target-nat-zone"),
]  # fmt: skip


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("rule,code,why", NOT_WRITTEN, ids=[case[0].name for case in NOT_WRITTEN])
def test_nat_that_cannot_be_written_is_left_out_and_said(target: str, rule: NatRule, code: str, why: str) -> None:
    import copy

    after = NatRule("after", sources=["net-a"], source_translation=copy_of(HIDE), **IO)
    p = nat_model(copy.deepcopy(rule), after)
    p.rules.append(Rule("to-srv", origin="to-srv", destinations=["srv-pub"], services=["one"]))
    config, report, text = convert(p, target, Options(interface_map=dict(INTERFACES)))
    item = report.item("nat", rule.name)
    if rule.name == "range-to-port" and target == "fdm":
        code, why = "NAT_SERVICE", "a NAT rule of a Device Manager names one port"  # it does not get as far as the translation
    assert item.skipped and codes(report, "nat", rule.name) == [code] and why in item.findings[0].message, item.findings
    assert [nat["description"].split(" ")[0] for nat in config.nat] == ["after"]
    # The rule below it now gets traffic the lost rule took first: said, where the two overlap.
    # (A source that is not known may be any source.)
    overlap = rule.name not in ("dnat-two", "dnat-any", "port-no-svc", "range-to-port")
    assert ("NAT_ORDER" in codes(report, "nat", "after")) == overlap, codes(report, "nat", "after")
    # A destination translation that is not written is not undone in the access rules either.
    assert written(config, "to-srv")["destinations"] == ["srv-pub"]
    if rule.name == "hide-if-any":
        config, report, text = convert(p, target, Options(interface_map=dict(INTERFACES), nat_zone="outside"))
        assert short(config.nat[0]) == {"to_interface": True, "osrc": "net-a", "src_if": "inside", "dst_if": "outside"}


@pytest.mark.parametrize("fdm", [False, True])
def test_the_address_of_an_interface_goes_round_as_the_interface(fdm: bool) -> None:
    m, o = nat_setup(fdm)
    m.manual_nat("DYNAMIC", originalSource=o["lan"], interfaceInTranslatedSource=True, sourceInterface=o["inside"], destinationInterface=o["outside"])
    m.manual_nat("STATIC", originalSource=o["srv"], interfaceInTranslatedSource=True, originalSourcePort=o["alt"], translatedSourcePort=o["web"],
                 sourceInterface=o["dmz"], destinationInterface=o["outside"])  # fmt: skip
    m.manual_nat("STATIC", originalSource=o["any4"], translatedSource=o["any4"], interfaceInOriginalDestination=True, translatedDestination=o["srv"],
                 originalDestinationPort=o["dns"], translatedDestinationPort=o["dns"], sourceInterface=o["outside"], destinationInterface=o["dmz"])  # fmt: skip
    m.manual_nat("STATIC", originalSource=o["srv"], translatedSource=o["pub"], originalSourcePort=o["alt"], translatedSourcePort=o["web"],
                 sourceInterface=o["dmz"], destinationInterface=o["outside"])  # fmt: skip
    m.auto_nat("STATIC", name="auto", originalNetwork=o["dmz-net"], translatedNetwork=o["dmz-pub"], sourceInterface=o["dmz"], destinationInterface=o["outside"])
    found, p, report = nats(m)
    first = p.nat_rules[1].name
    assert "NAT_INTERFACE_ADDRESS" in codes(report, "nat", first) and "outside-interface" in p.addresses
    for target in TARGETS:
        native = target == p.vendor
        out = Report()
        for item in report.items.values():  # what the reader said stays said, unless the writer takes it back
            for finding in item.findings:
                out.add(item.kind, item.name, finding.severity, finding.code, finding.message)
        text = cli.convert(p, target, out, Options(interface_map={"inside": "inside", "outside": "outside", "dmz": "dmz"}))
        config = CiscoConfig(text, native=native)
        rules = [short(rule) for rule in config.nat]
        every = {"osrc": "any-ipv4", "tsrc": "any-ipv4"}
        assert rules == [
            {"to_interface": True, "src_if": "inside", "dst_if": "outside", "osrc": "lan"},
            # A published port, the way the device writes it: from the side of the server, so that other rules still apply.
            {"static": True, "to_interface": True, "dst_if": "outside", "osrc": "srv", "osp": "p-alt", "tsp": "p-web"},
            {"static": True, "unidirectional": True, "from_interface": True, "src_if": "outside", **every, "tdst": "srv", "odp": "p-dns", "tdp": "p-dns"},
            {"static": True, "dst_if": "outside", "osrc": "srv", "tsrc": "srv-pub", "osp": "p-alt", "tsp": "p-web"},
            # An automatic rule becomes a manual one: the script and the import file create rules, not objects that carry them.
            {"static": True, "src_if": "dmz", "dst_if": "outside", "osrc": "dmz-net", "tsrc": "dmz-pub"},
        ], (target, rules)
        # The object that stood for the address is not needed and not written; the rule follows the interface again.
        assert "outside-interface" not in config.networks and "NAT_INTERFACE_ADDRESS" not in codes(out, "nat", first)
        assert all(out.item("nat", nat.origin).status == "exact" for nat in p.nat_rules), out.to_text()
        # The access rule for the server names its real address again, as it did.
        assert written(config, "to-srv")["destinations"] == ["srv"]
    # An ASA says it with the same word.
    text = cli.convert(p, "asa", Report())
    assert "nat (any,outside) source static srv interface service tcp-src-8443 tcp-src-443" in text
    assert "destination static interface srv service p-dns p-dns unidirectional" in text and "object network outside-interface" not in text
    # Another platform has no such word: the address the interface had is what is written.
    out = Report()
    assert "203.0.113.2" in cli.convert(p, "panos", out)


# -- what the manager has already, and what the output says about itself ----------------------------

PORTS_THERE = {"HTTPS": {"kind": "port", "protocol": "tcp", "low": 443, "high": 443, "fdm": "tcpportobject", "fmc": "ProtocolPortObject"},
               "GRE": {"kind": "protocol", "number": 47, "fdm": "protocolobject", "fmc": "ProtocolPortObject"}}  # fmt: skip


@pytest.mark.parametrize("fdm", [False, True])
def test_objects_the_manager_comes_with_are_named_not_created(fdm: bool) -> None:
    m = Manager(fdm)
    system: Dict[str, Any] = {"isSystemDefined": True} if fdm else {"metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}}}
    any4 = m.network("any-ipv4", "0.0.0.0/0", **system)
    private = m.group("IPv4-Private-All-RFC1918", [m.network("IPv4-Private-10.0.0.0-8", "10.0.0.0/8", **system)], **system)
    https, gre, own = m.tcp("HTTPS", "443", **system), m.protocol("GRE", "GRE", **system), m.network("own", "10.1.0.0/16")
    m.rule("r1", src_zones=[m.zone("inside")], dst_zones=[m.zone("outside")], sources=[private, own], destinations=[any4], dst_ports=[https, gre])
    m.rule("trusted", "TRUST", sources=[own])
    m.rule("answers", src_ports=[https], sources=[own])
    m.policy["defaultAction"]["action"] = "PERMIT"
    p, report = read(m.export() if fdm else m.api())
    assert p.addresses["any-ipv4"].builtin == p.vendor and p.services["GRE"].builtin == p.vendor and p.rules[1].handling == {"inspection": "none (trust)"}
    same, other = ("fdm", "fmc") if fdm else ("fmc", "fdm")
    there = {"IPv4-Private-All-RFC1918": ["10.0.0.0/8"]}
    # For a manager of the same kind: its own objects, by their names.
    out = Report()
    config = CiscoConfig(cli.convert(p, same, out), native=True, existing=there, existing_ports=PORTS_THERE)
    assert sorted(config.networks) == ["IPv4-Private-All-RFC1918", "any-ipv4", "own"] and sorted(config.ports) == ["GRE", "HTTPS"]
    first = written(config, "r1")
    assert (first["sources"], first["destinations"], first["dst_ports"]) == (["IPv4-Private-All-RFC1918", "own"], ["any-ipv4"], ["HTTPS", "GRE"])
    for kind, name in (("address", "any-ipv4"), ("address", "IPv4-Private-10.0.0.0-8"), ("address-group", "IPv4-Private-All-RFC1918"),
                       ("service", "HTTPS"), ("service", "GRE")):  # fmt: skip
        assert codes(out, kind, name) == ["EXISTING_OBJECT"], name
    assert written(config, "trusted")["action"] == "trust" and not out.item("rule", "trusted").findings
    assert written(config, "answers")["src_ports"] == ["HTTPS"]  # the port has an object: no second one is made for the source port
    if not fdm:
        # The script asks for them before it creates anything. (A protocol without ports is a port object like the others.)
        assert config.plan["existing"] == [
            {"type": "Network", "name": "any-ipv4"}, {"type": "Network", "name": "IPv4-Private-10.0.0.0-8"},
            {"type": "NetworkGroup", "name": "IPv4-Private-All-RFC1918"}, {"type": "ProtocolPortObject", "name": "HTTPS"},
            {"type": "ProtocolPortObject", "name": "GRE"}, {"type": "Network", "name": "any-ipv6"}]  # fmt: skip
    # The source lets through what no rule matches; neither output does, and both say so. One default action for
    # everything: there is nothing to say about traffic inside a zone.
    assert notes(out)[-1] == "INTERZONE_DEFAULT" and "INTRAZONE_DEFAULT" not in notes(out) and "INTRAZONE_ALLOW_ADDED" not in notes(out)
    assert "the default action of the source allows what no rule matches" in out.notes[-1].message
    assert ("the default action of the device is not changed by an import" if fdm else "the new access control policy blocks it by default") in out.notes[-1].message
    assert config.rules[-1]["name"] == "answers"
    # For the other manager: objects of its own, under names that are free there.
    out = Report()
    config = CiscoConfig(cli.convert(p, other, out), existing=there, existing_ports=PORTS_THERE)
    first = written(config, "r1")
    assert first["sources"] == ["IPv4-Private-All-RFC1918_2", "own"] and first["destinations"] == ["any-ipv4"]
    assert first["dst_ports"] == (["HTTPS_2", 47] if fdm else ["HTTPS_2", "GRE"])
    assert config.networks["IPv4-Private-All-RFC1918_2"]["members"] == ["IPv4-Private-10.0.0.0-8_2"]
    assert codes(out, "address", "any-ipv4") == ["PREDEFINED_OBJECT"] and out.item("address", "any-ipv4").emitted_as == ["any-ipv4"]
    assert codes(out, "service", "HTTPS") == ["RENAMED"] and written(config, "trusted")["action"] == "trust"


def test_what_each_output_says_about_itself() -> None:
    p = model(Rule("r", src_zones=["trust"], dst_zones=["untrust"], sources=["net-a"]))
    # A Device Manager wants to know what the file is for: said by an export of it, and not known otherwise.
    config, report, text = convert(p, "fdm")
    assert config.metadata == {"type": "metadata", "hardwareModel": "REPLACE WITH THE VALUE FROM AN EXPORT OF THE TARGET",
                               "softwareVersion": "REPLACE WITH THE VALUE FROM AN EXPORT OF THE TARGET", "apiVersion": "latest",
                               "configType": "DELTA_CONFIG", "exportType": "PARTIAL_EXPORT"}  # fmt: skip
    load = report.notes[0]
    assert load.code == "FDM_LOAD" and load.severity.name == "REVIEW" and "copy both from the first object of an export of the target device" in load.message
    assert "its access rules stay above the rules of this file" in load.message and "Nothing is in force until the changes are deployed" in load.message
    assert notes(report) == ["FDM_LOAD", "EXISTING_OBJECTS", "ZONES_REQUIRED", "FQDN_DNS"] and "trust, untrust" in report.notes[2].message
    m = Manager(True)
    m.rule("r", sources=[m.network("lan", "10.1.0.0/16")])
    native, _ = read(m.export())
    config, report, text = convert(native, "fdm", native=True)
    assert (config.metadata["hardwareModel"], config.metadata["softwareVersion"]) == ("Cisco Firepower Threat Defense for VMware", "7.2.5-208")
    assert "they are those of the export that was read" in report.notes[0].message and notes(report) == ["FDM_LOAD", "EXISTING_OBJECTS"]
    # What its API answered says neither.
    native, _ = read(m.api())
    assert convert(native, "fdm", native=True)[0].metadata["hardwareModel"].startswith("REPLACE WITH")
    # A scope that only looks like one is not taken apart into a model and a version.
    native.scope = 'FTD 7.2"},{" on a "model"'
    assert convert(native, "fdm", native=True)[0].metadata["softwareVersion"] == '7.2"},{"'  # a value, whatever is in it
    # The script for a Management Center.
    config, report, text = convert(p, "fmc")
    load = report.notes[0]
    assert load.code == "FMC_LOAD" and load.severity.name == "REVIEW" and "assigns them to no device" in load.message
    assert "stops before it creates anything when a name is taken" in load.message and "Run it with --show and with --dry-run first" in load.message
    assert notes(report) == ["FMC_LOAD", "ZONES_REQUIRED", "FQDN_DNS"] and "one that does not is created empty" in report.notes[1].message
    assert config.plan["generator"].startswith("FWShift ") and config.plan["policy"] == "FWShift" and config.plan["description"]
    # A source that passes traffic inside a zone, and between zones: a rule for the first where it can be told, a note for both.
    p = model(Rule("r", src_zones=["trust"], dst_zones=["untrust"], sources=["net-a"]), Rule("block", action=Action.DENY, src_zones=["dmz"], dst_zones=["dmz"]))
    p.default_intrazone = p.default_interzone = Action.ALLOW
    for target in TARGETS:
        config, report, text = convert(p, target)
        assert [code for code in notes(report) if "ZONE_DEFAULT" in code] == ["INTRAZONE_DEFAULT", "INTERZONE_DEFAULT"]
        assert "the source allows traffic between zones that no rule matches" in report.notes[notes(report).index("INTERZONE_DEFAULT")].message
        assert [rule["name"] for rule in config.rules] == ["r", "block"]
    # A source whose zones each say whether they pass their own traffic (an ASA with same-security-traffic, a zone of a PAN-OS).
    p = model(Rule("r", src_zones=["trust"], dst_zones=["untrust"], sources=["net-a"]))
    p.zones = {"trust": Zone("trust", intrazone_allow=True), "untrust": Zone("untrust", intrazone_allow=False), "dmz": Zone("dmz")}
    for target in TARGETS:
        config, report, text = convert(p, target)
        last = config.rules[-1]
        assert [rule["name"] for rule in config.rules] == ["r", "fwshift-intrazone-trust"] and "INTRAZONE_ALLOW_ADDED" in notes(report)
        assert (last["src_zones"], last["dst_zones"], last["action"], last["log"]) == (["trust"], ["trust"], "allow", False)


# -- the samples, the command line, and the rest of the program -------------------------------------


def test_the_samples_are_read_in_full() -> None:
    p, report = read((DATA / "fmc_sample.json").read_bytes())
    assert (p.vendor, p.scope, len(p.rules), len(p.nat_rules), len(p.addresses), len(p.services)) == ("fmc", "Edge", 21, 7, 16, 24)
    assert list(p.zones) == ["outside", "inside", "dmz"] and p.default_interzone == Action.DENY and not p.rules[0].unsupported
    assert notes(report) == ["OBJECT_OVERRIDES"] and not [rule.name for rule in p.rules if rule.unsupported and rule.name not in ("Staff social media",)]
    # The prefilter rules come first, then the mandatory rules, then the default ones.
    assert [rule.name for rule in p.rules[:7]] == ["pre-backup", "pre-spoofed", "pre-partner-gre", "pre-partner-gre-reverse",
                                                   "prefilter-default-block-tunnels", "Block OT outbound", "LAN web"]  # fmt: skip
    assert report.item("rule", "Watch DMZ").skipped and codes(report, "rule", "Uncategorised web") == ["INTERACTIVE_BLOCK"]
    p, report = read((DATA / "fdm_sample.txt").read_bytes())
    assert (p.vendor, p.scope, len(p.rules), len(p.nat_rules)) == ("fdm", "FTD 7.2.5-208 on Cisco Firepower 1010 Threat Defense", 8, 4)
    assert list(p.zones) == ["outside_zone", "inside_zone", "iot"] and not report.notes


def nets_there(p: Policy) -> Dict[str, List[str]]:
    """The network objects a manager comes with, as the policy that was read from it holds them."""
    out = {name: [address.value] for name, address in p.addresses.items() if address.builtin == p.vendor and address.kind != AddressKind.UNSUPPORTED}
    for name, group in p.address_groups.items():
        if group.builtin:
            out[name] = [value for member in group.members for value in out.get(member, [member])]
    return out


def ports_there(p: Policy) -> Dict[str, Dict[str, Any]]:
    """The port objects a manager comes with, as the policy that was read from it holds them: for the reader of the test."""
    out: Dict[str, Dict[str, Any]] = {}
    for name, service in p.services.items():
        if not service.builtin or len(service.entries) != 1:
            continue
        entry = service.entries[0]
        if entry.protocol in (Protocol.TCP, Protocol.UDP):
            low, _, high = entry.dst_ports.partition("-")
            out[name] = {"kind": "port", "protocol": entry.protocol.value, "low": int(low or 0), "high": int(high or low or 65535),
                         "fdm": f"{entry.protocol.value}portobject", "fmc": "ProtocolPortObject"}  # fmt: skip
        elif entry.protocol == Protocol.IP and entry.ip_protocol is not None:
            out[name] = {"kind": "protocol", "number": entry.ip_protocol, "fdm": "protocolobject", "fmc": "ProtocolPortObject"}
    return out


@pytest.mark.parametrize("sample", ["fmc_sample.json", "fdm_sample.txt"])
@pytest.mark.parametrize("target", TARGETS)
def test_a_sample_converted_twice_is_the_same_policy(sample: str, target: str) -> None:
    """What was written for a manager is read back as what was written, for both of them."""
    first, _ = read((DATA / sample).read_bytes())
    out = Report()
    text = cli.convert(first, target, out, Options(interface_map={"outside": "outside", "inside": "inside", "dmz": "dmz", "iot": "iot"}))
    native = first.vendor == target
    config = CiscoConfig(text, native=native, existing=nets_there(first) if native else None, existing_ports=ports_there(first) if native else None)
    if target == "fmc":
        return  # the script is not read back: it is run against a made-up Management Center above
    again, report = read(text.encode(), "fdm")
    assert [rule.name for rule in again.rules] == [rule["name"] for rule in config.rules]
    # An import file holds what is added, not the policy it is added to: that its default action is not known is all there is to say.
    assert len(again.nat_rules) == len(config.nat) and notes(report) == ["DEFAULT_ACTION_UNKNOWN"]
    if native:  # the port objects of the device are named and not in the file: what uses them cannot be read back from it
        return
    assert not [rule.name for rule in again.rules if rule.unsupported]
    # The same traffic, decided the same way, by the file and by what is read from it.
    zones = [zone for zone in config.zones] or ["inside_zone"]
    rng = random.Random(7)
    spans = {name: again.addresses[name].value for name in again.addresses if again.addresses[name].kind == AddressKind.NETWORK}
    hosts = sorted({value.split("/")[0] for value in spans.values()}) + ["198.51.100.77", "2001:db8::77"]
    for _ in range(600):
        pkt = Packet(rng.choice(zones), rng.choice(zones), rng.choice(hosts), rng.choice(hosts),
                     rng.choice(["tcp", "udp", "icmp"]), rng.choice([53, 1024, 40000]), rng.choice([22, 53, 80, 443, 5001, 8443, 3389]))  # fmt: skip
        if ":" in pkt.src != ":" in pkt.dst:
            continue
        assert config.allows(pkt) == bool(model_verdict(again, pkt)), pkt


def test_the_command_line(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    fmc, fdm = str(DATA / "fmc_sample.json"), str(DATA / "fdm_sample.txt")
    out, report = tmp_path / "load_policy.py", tmp_path / "report.json"
    assert cli.main(["convert", fmc, "--to", "fmc", "-o", str(out), "--report-json", str(report), "-q", "--target-policy", "Edge v2",
                     "--target-prefix", "m-", "--zone-map", "dmz=servers"]) == 0  # fmt: skip
    sample = read((DATA / "fmc_sample.json").read_bytes())[0]
    config = CiscoConfig(out.read_text(encoding="utf-8"), native=True, existing=nets_there(sample), existing_ports=ports_there(sample))
    assert config.plan["policy"] == "Edge v2" and config.plan["zones"] == ["inside", "outside", "servers"]
    assert "m-lan-net" in config.networks and "any-ipv4" in config.networks and "m-any-ipv4" not in config.networks
    said = json.loads(report.read_text(encoding="utf-8"))
    assert said["summary"]["rule"]["total"] == 22 and {note["code"] for note in said["notes"]} >= {"FMC_LOAD", "ZONES_REQUIRED", "OBJECT_OVERRIDES"}
    assert capsys.readouterr().err == ""
    # Which policy to read is said by name.
    assert cli.main(["inspect", fmc, "--policy", "Edge", "--nat-policy", "Edge NAT"]) == 0
    assert "security rules:  21 (1 disabled)" in capsys.readouterr().out
    assert cli.main(["inspect", fmc, "--policy", "Core"]) == 1
    assert "access control policy 'Core' is not in the input (found: Edge)" in capsys.readouterr().err
    assert cli.main(["convert", fmc, "--to", "panos", "--nat-policy", "Other", "-q"]) == 1
    assert "NAT policy 'Other' is not in the input (found: Edge NAT)" in capsys.readouterr().err
    # A Device Manager: the file for an import, and the same from its zip.
    assert cli.main(["convert", fdm, "--to", "fdm", "-q"]) == 0
    text = capsys.readouterr().out
    sample = read((DATA / "fdm_sample.txt").read_bytes())[0]
    assert CiscoConfig(text, native=True, existing=nets_there(sample), existing_ports=ports_there(sample)).metadata["softwareVersion"] == "7.2.5-208"
    packed = tmp_path / "export.zip"
    packed.write_bytes(zipped({"full_config.txt": (DATA / "fdm_sample.txt").read_bytes()}))
    assert cli.main(["convert", str(packed), "--to", "fdm", "-q"]) == 0 and capsys.readouterr().out == text
    assert cli.main(["inspect", str(packed)]) == 0 and "format:          fdm" in capsys.readouterr().out
    # What is wrong with the input, or with an option, is one line.
    bad = tmp_path / "bad.json"
    bad.write_text('{"items": [{"type": "AccessRule", "name": "r", ', encoding="utf-8")
    for args, message in (
        (["inspect", str(bad)], "not valid JSON"),
        (["convert", fmc, "--from", "fdm", "--to", "panos"], "is the JSON of a Firewall Management Center; read it with --from fmc"),
        (["convert", fdm, "--from", "fmc", "--to", "panos"], "is the JSON of a Firewall Device Manager; read it with --from fdm"),
        (["convert", str(DATA / "checkpoint_sample.json"), "--from", "fmc", "--to", "panos"], "no Cisco Secure Firewall configuration found"),
        (["convert", str(DATA / "panos_sample.xml"), "--from", "fmc", "--to", "panos"], "not valid JSON"),
        (["convert", fmc, "--to", "fmc", "--target-policy", "a/b"], "is not a name a Management Center takes for a policy"),
        (["convert", fmc, "--to", "fmc", "--target-prefix", "has space"], "--target-prefix takes up to 20 letters"),
        (["convert", str(packed), "--from", "fmc", "--to", "panos"], "the input is a zip; unpack it"),
    ):  # fmt: skip
        assert cli.main(args) == 1, args
        err = capsys.readouterr().err
        assert message in err and "Traceback" not in err and len(err.strip().splitlines()) == 1, (args, err)
    # --strict: both samples hold something to look at.
    assert cli.main(["convert", fmc, "--to", "fdm", "-q", "--strict"]) == 2 and capsys.readouterr().out.startswith("[\n")


def test_audit_and_matrix_read_both_managers(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    sample = read((DATA / "fmc_sample.json").read_bytes())[0]
    assert cli.main(["audit", str(DATA / "fmc_sample.json")]) == 0
    shown = capsys.readouterr().out
    assert "source: fmc (Edge)" in shown and "ANY_TO_ANY: rule 'Ping out'" in shown
    # A rule of these managers says whether it logs and which inspection it gets: both can be missed.
    assert "NO_LOG: rule 'LAN DNS and NTP'" in shown and "NO_PROFILE: rule 'LAN DNS and NTP'" in shown and "NO_PROFILE: rule 'LAN web'" not in shown
    # A Fastpath rule is traffic nothing looks into.
    assert "NO_PROFILE: rule 'pre-backup'" in shown
    assert cli.main(["audit", str(DATA / "fdm_sample.txt")]) == 0
    shown = capsys.readouterr().out
    assert "source: fdm (FTD 7.2.5-208 on Cisco Firepower 1010 Threat Defense)" in shown and "NO_LOG" in shown
    assert cli.main(["matrix", str(DATA / "fdm_sample.txt")]) == 0
    shown = capsys.readouterr().out
    assert "outside_zone -> inside_zone" in shown and "rule 'NAS_from_Internet': any -> nas: tcp/5001" in shown
    assert cli.main(["matrix", str(DATA / "fmc_sample.json")]) == 0
    shown = capsys.readouterr().out
    assert "inside -> outside" in shown and "rule 'LAN web'" in shown
    # The audit after a conversion: what the target is left with.
    for target in TARGETS:
        report = tmp_path / "report.txt"
        assert cli.main(["convert", str(DATA / "fmc_sample.json"), "--to", target, "-q", "--audit", "-o", os.devnull, "--report", str(report)]) == 0
        text = report.read_text(encoding="utf-8")
        assert "\nAudit\n" in text and "After the conversion" in text and "ANY_TO_ANY: rule 'Ping out'" in text
    # A rule the audit switches off is switched off in the script, and left out of the file for a Device Manager.
    out = tmp_path / "out"
    for target in TARGETS:
        args = ["convert", str(DATA / "fmc_sample.json"), "--to", target, "-q", "-o", str(out), "--audit-action", "ANY_TO_ANY=disable"]
        assert cli.main(args) == 0
        config = CiscoConfig(out.read_text(encoding="utf-8"), native=target == "fmc", existing=nets_there(sample), existing_ports=ports_there(sample))
        found = [rule for rule in config.rules if rule["name"].replace("_", " ") == "Ping out"]
        assert [rule["enabled"] for rule in found] == ([False] if target == "fmc" else [])


def test_large_and_deep_input_takes_no_time_to_speak_of() -> None:
    import time

    m = Manager()
    zones = [m.zone(f"z{index}") for index in range(6)]
    nets = [m.network(f"net{index}", f"10.{index // 250}.{index % 250}.0/24") for index in range(1500)]
    groups = [m.group("g0", nets[:40])]
    for index in range(1, 60):  # each group holds the one before it
        groups.append(m.group(f"g{index}", [groups[-1], nets[index]]))
    ports = [m.tcp(f"p{index}", str(1000 + index)) for index in range(400)]
    for index in range(3000):
        m.rule(f"rule {index}", "ALLOW" if index % 3 else "BLOCK", src_zones=[zones[index % 6]], dst_zones=[zones[(index + 1) % 6]],
               sources=[nets[index % 1500], groups[index % 60]], destinations=[nets[(index * 7) % 1500]], dst_ports=[ports[index % 400]])  # fmt: skip
    m.rules[m.policy["id"]][-1]["metadata"]["ruleIndex"] = 3000
    data = m.api()
    started = time.monotonic()
    p, report = read(data)
    assert len(p.rules) == 3000 and len(p.addresses) == 1500 and not report.needs_review
    for target in TARGETS:
        out = Report()
        config = CiscoConfig(cli.convert(p, target, out), native=target == "fmc")
        assert len(config.rules) == 3000 and len(config.networks) == 1560
        if target == "fmc":
            # Groups in groups are created a level at a time: a call cannot name what the same call creates.
            assert [kind for kind, _ in steps(config)].count("NetworkGroup") == 60
        else:
            assert len(config.networks["g59"]["members"]) == 60  # the objects themselves, each once
    assert time.monotonic() - started < 60
    # A reference that leads back to itself, and a group that holds itself: no group, and no endless loop.
    m = Manager()
    a = m.group("a", [m.host("h", "10.1.1.1")])
    b = m.group("b", [a])
    a["objects"].append(m.ref(b))
    m.rule("r", sources=[a])
    p, report = read(m.api())
    out = Report()
    cli.convert(p, "fmc", out)
    assert out.item("rule", "r").disabled and "UNSUPPORTED_GROUP" in codes(out, "address-group", "a") + codes(report, "address-group", "a")


@pytest.mark.parametrize("fdm", [False, True])
def test_the_objects_for_every_address_are_known_without_being_in_the_input(fdm: bool) -> None:
    """A partial export, or a file for an import, names them and leaves them out; nobody can give them another value."""
    m = Manager(fdm)
    kind = "networkobject" if fdm else "Network"
    four, six = {"type": kind, "id": "sys-4", "name": "any-ipv4"}, {"type": kind, "name": "any-ipv6"}
    other = {"type": kind, "id": "sys-9", "name": "IPv4-Private-All-RFC1918"}
    m.rule("v4", sources=[four], destinations=[m.host("srv", "192.0.2.10")])
    m.rule("v6", sources=[six])
    m.rule("unknown", sources=[other])
    p, report = read(m.export() if fdm else m.api())
    assert (p.addresses["any-ipv4"].value, p.addresses["any-ipv6"].value, p.addresses["any-ipv4"].builtin) == ("0.0.0.0/0", "::/0", p.vendor)
    assert codes(report, "address", "any-ipv4") == ["PREDEFINED_OBJECT"] and report.item("address", "any-ipv4").status == "exact"
    assert not one_rule(m, p, "v4").unsupported and model_verdict(p, Packet("a", "b", "198.51.100.1", "192.0.2.10", "tcp", 1024, 80))
    assert transform.address_intervals(p, "any-ipv4") == [(4, 0, 2**32 - 1)] and transform.address_intervals(p, "any-ipv6") == [(6, 0, 2**128 - 1)]
    # Any other object of the manager that is not in the input has a value nobody told: what uses it is not converted.
    assert p.addresses["IPv4-Private-All-RFC1918"].kind == AddressKind.UNSUPPORTED
    out = Report()
    cli.convert(p, "panos", out)
    assert out.item("rule", "unknown").disabled and not out.item("rule", "v4").disabled and not out.item("rule", "v6").disabled


@pytest.mark.parametrize("fdm", [False, True])
def test_a_range_of_ports_in_a_nat_rule(fdm: bool) -> None:
    m, o = nat_setup(fdm)
    # The same range before and after is a condition: the ports stay what they are.
    m.manual_nat("STATIC", originalSource=o["any4"], translatedSource=o["any4"], originalDestination=o["pub"], translatedDestination=o["srv"],
                 originalDestinationPort=o["web-range"], translatedDestinationPort=o["web-range"], sourceInterface=o["outside"], destinationInterface=o["dmz"])  # fmt: skip
    found, p, report = nats(m)
    nat = p.nat_rules[0]
    assert not nat.unsupported and (nat.service, nat.destination_translation) == ("p-range", DestNat("srv", ""))
    # A Management Center takes it as it is; a NAT rule of a Device Manager names one port.
    out = Report()
    config = CiscoConfig(cli.convert(p, "fmc", out), native=not fdm)
    assert (config.nat[0]["odp"], config.nat[0]["tdp"]) == ("p-range", "p-range") and out.item("nat", nat.origin).status == "exact"
    out = Report()
    config = CiscoConfig(cli.convert(p, "fdm", out, Options(interface_map={"outside": "outside", "dmz": "dmz"})), native=fdm)
    assert not config.nat and codes(out, "nat", nat.origin) == ["NAT_SERVICE"]
    assert "a NAT rule of a Device Manager names one port" in out.item("nat", nat.origin).findings[0].message


# -- the script and what is on the other end of the line (review round 15) -------------------------


def test_the_script_follows_no_redirect_and_ends_cleanly_on_a_bad_line(tmp_path: Any) -> None:
    """The password and the token go to the Management Center that was named: a redirect is an error, not a new address."""
    import http.server
    import socket
    import subprocess
    import sys
    import threading

    seen: List[Tuple[str, str, Dict[str, str]]] = []
    mode = {"answer": "redirect"}

    class Witness(http.server.BaseHTTPRequestHandler):
        def _serve(self) -> None:
            seen.append(("witness", self.path, dict(self.headers.items())))
            self.send_response(204)
            self.send_header("X-auth-access-token", "stolen")
            self.send_header("DOMAIN_UUID", "d")
            self.end_headers()

        do_GET = do_POST = _serve

        def log_message(self, *args: Any) -> None:
            pass

    witness = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Witness)

    class Front(http.server.BaseHTTPRequestHandler):
        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            seen.append(("front", self.path, dict(self.headers.items())))
            if mode["answer"] == "garbage":
                self.wfile.write(b"SSH-2.0-OpenSSH_9.6\r\n")
                return
            if mode["answer"] == "token-then-redirect" and "generatetoken" in self.path:
                self.send_response(204)
                self.send_header("X-auth-access-token", "real-token")
                self.send_header("DOMAIN_UUID", "d")
                self.end_headers()
                return
            self.send_response(int(mode.get("status", "302")))
            self.send_header("Location", f"http://127.0.0.1:{witness.server_address[1]}{self.path}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_POST = _serve

        def log_message(self, *args: Any) -> None:
            pass

    front = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Front)
    for server in (witness, front):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    script = tmp_path / "load-policy.py"
    script.write_text(cli.convert(small_model(), "fmc", Report()), encoding="utf-8")
    env = {**os.environ, "FMC_PASSWORD": "s3cret-Pa55"}

    def run(*arguments: str, environment: Optional[Dict[str, str]] = None) -> Any:
        return subprocess.run([sys.executable, str(script), *arguments], capture_output=True, text=True, timeout=120, cwd=tmp_path,
                              env=env if environment is None else environment, stdin=subprocess.DEVNULL)  # fmt: skip

    try:
        host = f"http://127.0.0.1:{front.server_address[1]}"
        for status in ("301", "302", "303", "307", "308"):
            mode.update(answer="redirect", status=status)
            done = run("--host", host, "--user", "api")
            assert done.returncode == 1 and "answered with a redirect" in done.stderr and "It is not followed" in done.stderr, done.stderr
        # Logged in, and then sent elsewhere: the token stays here as well.
        mode["answer"] = "token-then-redirect"
        done = run("--host", host, "--user", "api", "--dry-run")
        assert done.returncode == 1 and "answered with a redirect" in done.stderr
        assert not [entry for entry in seen if entry[0] == "witness"], "a redirect was followed"
        assert all("s3cret" not in done.stdout + done.stderr for _ in (0,)) and not list(tmp_path.glob("*.journal.json"))
        # What answers is no web server; nothing answers; no password and nobody to ask.
        mode["answer"] = "garbage"
        done = run("--host", host, "--user", "api")
        assert done.returncode == 1 and "no usable answer from" in done.stderr and "Traceback" not in done.stderr
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        done = run("--host", f"http://127.0.0.1:{port}", "--user", "api")
        assert done.returncode == 1 and "no usable answer from" in done.stderr and "Traceback" not in done.stderr
        done = run("--host", host, "--user", "api", environment={key: value for key, value in os.environ.items() if key != "FMC_PASSWORD"})
        assert done.returncode == 1 and "no password: set the environment variable FMC_PASSWORD" in done.stderr and "Traceback" not in done.stderr
        # A host that is no host, and a file that is no certificate.
        for value, message in (("fmc example net", "without spaces"), ("fmc\nexample", "without spaces"), ("http://[::1", "is not a name or an address"),
                               ("https://fmc.example.net/api", "and nothing after it"), ("https://user:pw@fmc.example.net", "and nothing after it"),
                               ("http://fmc.example.net", "only https is used"), ("http://127.0.0.1@fmc.example.net", "and nothing after it"),
                               ("https://fmc.example.net:port", "is not a name or an address")):  # fmt: skip
            done = run("--host", value, "--user", "api")
            assert done.returncode == 1 and message in done.stderr and "Traceback" not in done.stderr, (value, done.stderr)
        (tmp_path / "not-a-certificate.pem").write_text("hello\n", encoding="utf-8")
        for value in ("no-such-file.pem", "not-a-certificate.pem"):
            done = run("--host", "fmc.example.net", "--user", "api", "--cafile", value)
            assert done.returncode == 1 and "no certificates could be read from it" in done.stderr and "Traceback" not in done.stderr, done.stderr
    finally:
        for server in (witness, front):
            server.shutdown()
            server.server_close()


def test_the_password_is_asked_only_of_a_console(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """On Windows NUL passes isatty(), and getpass reads the console anyway: only a handle with a console mode is asked."""
    import ctypes
    import sys
    import types

    from fwshift.emitters import fmc_loader

    class Stream:
        def __init__(self, tty: bool) -> None:
            self.tty = tty

        def isatty(self) -> bool:
            return self.tty

        def fileno(self) -> int:
            return 0

    monkeypatch.setattr(fmc_loader.sys, "stdin", None)
    assert not fmc_loader.someone_to_ask()
    monkeypatch.setattr(fmc_loader.sys, "stdin", Stream(False))
    assert not fmc_loader.someone_to_ask()
    monkeypatch.setattr(fmc_loader.sys, "stdin", Stream(True))
    monkeypatch.setattr(fmc_loader.sys, "platform", "linux")
    assert fmc_loader.someone_to_ask()
    # Windows: NUL is a terminal to isatty() and has no console mode; a console has one.
    monkeypatch.setattr(fmc_loader.sys, "platform", "win32")
    console = {"mode": False}
    kernel32 = types.SimpleNamespace(GetConsoleMode=lambda handle, mode: int(console["mode"]))
    monkeypatch.setattr(ctypes, "windll", types.SimpleNamespace(kernel32=kernel32), raising=False)
    monkeypatch.setitem(sys.modules, "msvcrt", types.SimpleNamespace(get_osfhandle=lambda fd: 4))
    assert not fmc_loader.someone_to_ask()
    console["mode"] = True
    assert fmc_loader.someone_to_ask()
    # Whatever cannot be asked about counts as nobody there.
    monkeypatch.setitem(sys.modules, "msvcrt", None)
    assert not fmc_loader.someone_to_ask()
    # Nobody there: the run stops with the way out, and getpass is never reached.
    plan = CiscoConfig(cli.convert(small_model(), "fmc", Report())).plan
    monkeypatch.setattr(fmc_loader, "someone_to_ask", lambda: False)
    monkeypatch.delenv("FMC_PASSWORD", raising=False)
    monkeypatch.setattr(fmc_loader.getpass, "getpass", lambda prompt: pytest.fail("getpass was called"))
    assert fmc_loader.main(["--host", "fmc.example.net", "--user", "api"], transport=object(), say=lambda line: None, plan=plan) == 1
    assert "no password: set the environment variable FMC_PASSWORD" in capsys.readouterr().err


def test_a_list_that_never_ends_is_not_followed_for_ever(tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from fwshift.emitters import fmc_loader

    monkeypatch.setattr(fmc_loader, "MAX_PAGES", 30)
    fmc, text, _ = sloppy(tmp_path, page_limit=1)
    real = fmc._page

    def lying(items: List[Dict[str, Any]], options: Dict[str, str], path: str) -> Dict[str, Any]:
        page = real(items, {**options, "offset": "0"}, path)
        page["paging"]["count"] = 10**12
        return page

    fmc._page = lying  # type: ignore[method-assign]
    status, said = load_script(text, fmc, tmp_path)
    assert status == 1 and "the list does not end after 30 pages" in capsys.readouterr().err and len(fmc.calls) == 31 and not fmc.created()


# -- what the input does not say (review round 15) -------------------------------------------------


def test_whether_a_policy_inherits_is_said_or_asked_about() -> None:
    def build(said: str) -> Tuple[Manager, Ref]:
        m = Manager(policy="Base")
        m.rule("base-block", "BLOCK", sources=["198.51.100.0/24"])
        m.rule("base-default", section="Default", sources=["10.9.0.0/16"])
        child = m.child_policy("Edge", default="BLOCK", said=said)
        m.rule("edge-allow", policy=child, dst_ports=[plit(6, "443")])
        return m, child

    order = ["base-block", "edge-allow", "base-default"]
    # Said in the policy, or in its inheritance settings (a call of its own): the rules of both, in the order of the device.
    for said in ("policy", "settings"):
        m, child = build(said)
        p, report = read(m.api())
        assert (p.scope, [rule.name for rule in p.rules], notes(report)) == ("Edge", order, []), said
    # Said nowhere. Two policies that may have nothing to do with each other: one is asked for, and read with the warning
    # that its parent, if it has one, is not in what was read.
    m, child = build("nowhere")
    with pytest.raises(ParseError, match=r"several access control policies \(Base, Edge\): choose one with --policy"):
        read(m.api())
    p, report = read(m.api(), policy="Edge")
    assert [rule.name for rule in p.rules] == ["edge-allow"] and notes(report) == ["INHERITANCE_UNKNOWN"] and report.needs_review
    message = report.notes[0].message
    assert "does not say whether access control policy 'Edge' inherits" in message and "(it holds other policies)" in message
    assert f"policy/accesspolicies/{child['id']}/inheritancesettings" in message
    # The same for a policy that is alone in the input: its parent may simply not have been fetched.
    alone = Manager(policy="Solo")
    alone.rule("r")
    answers = [answer for answer in alone.answers() if "inheritancesettings" not in json.dumps(answer.get("links", ""))]
    p, report = read(json.dumps(answers).encode())
    assert notes(report) == ["INHERITANCE_UNKNOWN"] and "(it holds other policies)" not in report.notes[0].message
    # A policy that says it does not inherit, either way, is believed.
    alone.policy["metadata"] = {"inherit": False}
    assert notes(read(json.dumps(answers).encode())[1]) == []
    # The manager lists the rules a policy inherits with its own: rules in the list of Edge that say they are rules of
    # Base tell that Edge inherits from Base, and none of them is dropped.
    m, child = build("nowhere")
    answers = m.answers()
    mine = next(a for a in answers if f"/accesspolicies/{child['id']}/accessrules" in json.dumps(a.get("links", "")))
    theirs = next(a for a in answers if f"/accesspolicies/{m.policy['id']}/accessrules" in json.dumps(a.get("links", "")))
    mine["items"] = [theirs["items"][0]] + mine["items"] + [theirs["items"][1]]
    mine["paging"]["count"] = 3
    for data in (answers, [a for a in answers if a is not theirs]):
        p, report = read(json.dumps(data).encode(), policy="Edge")
        assert [rule.name for rule in p.rules] == order and notes(report) == [], notes(report)
    p, report = read(json.dumps([a for a in answers if a is not theirs and a is not m.policy]).encode())
    assert [rule.name for rule in p.rules] == order and p.scope == "Edge"


def test_answers_that_are_missing_or_are_errors_are_said() -> None:
    m = Manager(policy="Edge")
    m.rule("block-first", "BLOCK", sources=["198.51.100.0/24"])
    m.rule("allow-all")
    m.host("h", "10.1.1.1")
    answers = m.answers()
    rules = next(a for a in answers if "accessrules" in json.dumps(a.get("links", "")))
    rest = [a for a in answers if a is not rules]

    def said(listed: List[Any]) -> Tuple[List[str], List[str], Report]:
        p, report = read(json.dumps(listed).encode(), "fmc")
        return [rule.name for rule in p.rules], notes(report), report

    assert said(answers)[:2] == (["block-first", "allow-all"], [])
    # The policy, and no list of its rules.
    names, codes_, report = said(rest)
    assert names == [] and codes_ == ["EXPORT_INCOMPLETE"] and "no list of its rules" in report.notes[0].message and report.needs_review
    # What the manager answers when the token has run out, saved as if it were the list.
    error = {"error": {"category": "FRAMEWORK", "messages": [{"description": "Access token invalid."}], "severity": "ERROR"}}
    names, codes_, report = said(rest + [error])
    assert codes_ == ["EXPORT_INCOMPLETE", "EXPORT_INCOMPLETE"]
    assert "1 of the answers in the input are errors of the manager (Access token invalid.)" in report.notes[1].message
    assert said(answers + [error])[1] == ["EXPORT_INCOMPLETE"]
    # A list that says it has rules and holds none it could give.
    for items in ({}, None, "x", 5):
        names, codes_, report = said(rest + [{**rules, "items": items}])
        assert names == [] and codes_ == ["EXPORT_INCOMPLETE"] and "the manager has 2 access rules in 'Edge', the input holds 0" in report.notes[0].message
    names, codes_, report = said(rest + [{key: value for key, value in rules.items() if key != "items"}])
    assert codes_ == ["EXPORT_INCOMPLETE"]
    # An item in the list of rules that is no rule FWShift knows: the rule below it would decide its traffic.
    for kind in (None, 5, "AccessRuleV2", "missing"):
        broken = json.loads(json.dumps(rules))
        if kind == "missing":
            del broken["items"][0]["type"]
        else:
            broken["items"][0]["type"] = kind
        names, codes_, report = said(rest + [broken])
        assert names == ["allow-all"] and codes_ == ["EXPORT_INCOMPLETE"], kind
        assert "the manager has 2 access rules in 'Edge', the input holds 1 that could be read" in report.notes[0].message
    # A list that does not say how many there are is taken to hold what it lists.
    plain = json.loads(json.dumps(rules))
    del plain["paging"]["count"]
    assert said(rest + [plain])[:2] == (["block-first", "allow-all"], [])
    # The same for a Device Manager.
    fdm = Manager(True)
    fdm.rule("r")
    p, report = read(fdm.api() + b"\n" + json.dumps({"error": {"severity": "ERROR", "key": "Unauthorized", "messages": [{"description": "Token expired"}]}}).encode())
    assert notes(report) == ["EXPORT_INCOMPLETE"] and "Token expired" in report.notes[0].message


def test_an_interface_that_is_only_named_is_in_no_known_zone() -> None:
    """A partial listing of a Device Manager, or a file FWShift wrote for one, names interfaces and does not hold them."""
    m, o = nat_setup(True)
    m.manual_nat("DYNAMIC", name="hide", originalSource=o["lan"], translatedSource=o["one"], sourceInterface=o["inside"], destinationInterface=o["outside"])
    m.manual_nat("STATIC", name="publish", originalSource=o["srv"], translatedSource=o["pub"], originalSourcePort=o["alt"], translatedSourcePort=o["web"],
                 sourceInterface=o["dmz"], destinationInterface=o["outside"])  # fmt: skip
    whole, _ = read(m.export())
    assert [(nat.src_zones, nat.dst_zones) for nat in whole.nat_rules] == [(["inside"], ["outside"]), (["outside"], ["outside"])]
    entries = [entry for entry in json.loads(m.export()) if entry.get("data", {}).get("type") not in ("physicalinterface", "securityzone")]
    p, report = read(json.dumps(entries).encode(), "fdm")
    assert [(nat.src_zones, nat.dst_zones) for nat in p.nat_rules] == [([ANY], [ANY]), ([ANY], [ANY])]
    assert codes(report, "nat", "hide") == ["NAT_INTERFACE", "NAT_INTERFACE"] and report.item("nat", "hide").status == "needs-review"
    assert "does not say which security zone that interface is in" in report.item("nat", "hide").findings[0].message
    assert not [zone for zone in p.zones if zone in ("inside-2", "outside-2")]
    # The interfaces are there and no zone holds any: the same.
    entries = [entry for entry in json.loads(m.export()) if entry.get("data", {}).get("type") != "securityzone"]
    for entry in entries:
        for key in ("sourceZones", "destinationZones"):
            if key in entry.get("data", {}):
                entry["data"][key] = []
    p, report = read(json.dumps(entries).encode(), "fdm")
    assert [nat.src_zones for nat in p.nat_rules] == [[ANY], [ANY]] and "NAT_INTERFACE" in codes(report, "nat", "hide")
    # The file FWShift writes for an import is such an input: read back, its NAT rules say so.
    text = cli.convert(whole, "fdm", Report(), Options(interface_map={"inside": "inside", "outside": "outside", "dmz": "dmz"}))
    again, report = read(text.encode(), "fdm")
    assert all("NAT_INTERFACE" in codes(report, "nat", nat.name) for nat in again.nat_rules) and all(nat.src_zones == [ANY] for nat in again.nat_rules)


@pytest.mark.parametrize("fdm", [False, True])
def test_names_fwshift_makes_up_are_names_a_manager_takes_also_for_its_own_policy(fdm: bool) -> None:
    """From a manager to a manager of the same kind the names of the source are kept; the names that are added are not from it."""
    m = Manager(fdm)
    upper = m.host("H-10.20.0.7", "192.0.2.1")
    port = m.tcp("TCP-22", "2222")
    six, span = m.host("six", "2001:db8::1"), m.range("six-span", "2001:db8::5-2001:db8::9")
    if fdm:
        lower, ssh = m.host("lit", "10.20.0.7"), m.tcp("p22", "22")
        m.rule("r", sources=[upper, lower, six, span], dst_ports=[port, ssh])
        m.manual_nat("DYNAMIC", name="n", originalSource=six, translatedSource=m.network("pool6", "2001:db8:ffff::/124"))
    else:
        m.rule("r", sources=[upper, "10.20.0.7", "2001:db8::1", "2001:db8:1::/64", "2001:db8::5-2001:db8::9"], dst_ports=[port, plit(6, "22")],
               src_ports=[plit(6, "1024-65535")])  # fmt: skip
    p, _ = read(m.export() if fdm else m.api())
    out = Report()
    text = cli.convert(p, "fdm" if fdm else "fmc", out)
    config = CiscoConfig(text, native=True)
    names = list(config.networks) + list(config.ports)
    made = [name for name in names if name not in ("H-10.20.0.7", "TCP-22", "six", "six-span", "lit", "p22", "pool6")]
    assert made and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name) for name in made), made
    assert len({name.lower() for name in names}) == len(names), names
    if not fdm:
        # (A literal that an object of the source already says is that object: 2001:db8::1 is "six".)
        assert written(config, "r")["sources"] == ["H-10.20.0.7", "h-10.20.0.7_2", "six", "n-2001_db8_1___64", "six-span"]
        assert written(config, "r")["dst_ports"] == ["TCP-22", "tcp-22_2"]
    else:
        assert config.nat[0]["pool"] is None and config.nat[0]["tsrc"].startswith("r-2001_db8_ffff__-2001_db8_ffff__f")


@pytest.mark.parametrize("kind", ["network", "port"])
@pytest.mark.parametrize("shape", ["deep", "ring"])
def test_groups_nested_without_end_are_not_followed(kind: str, shape: str) -> None:
    """A thousand groups, each in the next, or in a ring: no platform has that, and no pass gets lost in it."""
    m = Manager()
    leaf = m.host("h", "10.1.1.1") if kind == "network" else m.tcp("web", "443")
    make = (lambda name, members: m.group(name, members)) if kind == "network" else (lambda name, members: m.port_group(name, members))
    groups = [make("g0", [leaf])]
    for index in range(1, 1500):
        groups.append(make(f"g{index}", [groups[-1]]))
    if shape == "ring":
        groups[0]["objects"].append(m.ref(groups[-1]))
    shallow = make("shallow", [make("inner", [leaf])])
    key = "sources" if kind == "network" else "dst_ports"
    m.rule("far", **{key: [groups[-1]]})
    m.rule("near", **{key: [groups[10]]})
    m.rule("fine", **{key: [shallow]})
    p, report = read(m.api())
    first: Optional[Report] = None
    for target in ("panos", "fortios", "checkpoint", "asa", "fmc", "fdm", "sophos", "iptables"):
        out = Report()
        cli.convert(p, target, out)  # no RecursionError
        first = first or out
        assert out.item("rule", "far").disabled or out.item("rule", "far").skipped, target
        assert not (out.item("rule", "fine").disabled or out.item("rule", "fine").skipped), target
        if shape == "deep":  # ten levels are levels a platform has
            assert not (out.item("rule", "near").disabled or out.item("rule", "near").skipped), target
        else:
            assert out.item("rule", "near").disabled or out.item("rule", "near").skipped, target
    item = "address-group" if kind == "network" else "service-group"
    assert first is not None
    message = first.item(item, "g1499").findings[0].message
    assert ("nested more than 64 deep" if shape == "deep" else "holds itself") in message


def test_words_of_the_other_manager_and_holders_of_one_thing() -> None:
    hit = Packet("a", "b", "10.1.2.3", "192.0.2.10", "tcp", 2000, 443)
    # Each manager has its own words for what a rule does: the word of the other one is not a word it knows.
    for fdm, action in ((False, "PERMIT"), (False, "DENY"), (True, "ALLOW"), (True, "BLOCK"), (True, "BLOCK_RESET"), (True, "MONITOR"), (False, "FASTPATH")):
        m = Manager(fdm)
        m.rule("r")["ruleAction" if fdm else "action"] = action
        p, report = read(m.export() if fdm else m.api())
        assert p.rules[0].unsupported == [f"action '{action}', which FWShift does not know"] and p.rules[0].action == Action.DENY, (fdm, action)
    # A condition that holds one thing FWShift does not know is a condition, however little that thing says.
    for value in ({"geo": {"type": "Country"}}, {"objects": [{"type": "Country"}]}, {"x": {"y": {"type": "z"}}}):
        m = Manager()
        m.rule("r", sourceNetworks=value)
        p, report = read(m.api())
        assert p.rules[0].unsupported, value
    for value in ({"type": "x"}, {"objects": [], "type": "y", "links": {"self": "https://fmc.example.net/x"}}):
        m = Manager()
        m.rule("r", sourceNetworks=value)
        p, report = read(m.api())
        assert not p.rules[0].unsupported and model_verdict(p, hit), value
    # A section that is neither of the two a policy has.
    m = Manager()
    m.rule("first")
    m.rule("second", section="Emergency")
    p, report = read(m.api())
    assert notes(report) == ["RULE_SECTIONS_UNKNOWN"] and "(emergency)" in report.notes[0].message and [rule.name for rule in p.rules] == ["first", "second"]
