# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Sophos Firewall: parser, emitter, and packet-level equivalence in both directions.

What a Sophos Firewall would do with an Entities.xml is worked out by ``helpers.SophosConfig``,
which shares no code with fwshift's parser: exclusions that apply together, a rulebase per IP
version, first match, the position of each rule.
"""

from __future__ import annotations

import io
import ipaddress
import random
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from xml.sax.saxutils import escape

import pytest
from helpers import DATA, SophosConfig, load, run
from test_iptables import ZONES, Packet, model_allows, model_verdict, random_model, random_packet

from fwshift import cli, transform
from fwshift.emitters import sophos as emit_sophos
from fwshift.errors import ParseError
from fwshift.model import ANY, ANY_V4, ANY_V6, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy, Protocol
from fwshift.model import Rule, RuleScope, Service, ServiceEntry, ServiceGroup, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import sophos as parse_sophos
from fwshift.report import Report, Severity

# -- writing an export by hand ---------------------------------------------------------------


class Entities:
    """An Entities.xml put together piece by piece, as an export lists it: each rule after the one before it."""

    def __init__(self, version: str = "2000.1", root: str = "Configuration") -> None:
        self.version, self.root = version, root
        self.parts: List[str] = []
        self.last: Dict[Tuple[str, int], str] = {}

    @staticmethod
    def _listed(tag: str, child: str, names: Optional[Sequence[str]]) -> str:
        if names is None:
            return ""
        return f"<{tag}>" + "".join(f"<{child}>{escape(name)}</{child}>" for name in names) + f"</{tag}>"

    def add(self, xml: str) -> "Entities":
        self.parts.append(xml)
        return self

    def zone(self, name: str, kind: str = "LAN") -> "Entities":
        return self.add(f'<Zone transactionid=""><Name>{escape(name)}</Name><Type>{kind}</Type></Zone>')

    def interface(self, name: str, zone: str) -> "Entities":
        return self.add(f'<Interface transactionid=""><Name>{name}</Name><Hardware>{name}</Hardware>'
                        f"<NetworkZone>{zone}</NetworkZone></Interface>")  # fmt: skip

    def host(self, name: str, value: str) -> "Entities":
        """``10.0.0.1``, ``10.0.0.0/24`` or ``10.0.0.1-10.0.0.9``, of either IP version."""
        family = "IPv6" if ":" in value else "IPv4"
        if "-" in value:
            first, last = value.split("-")
            body = f"<HostType>IPRange</HostType><StartIPAddress>{first}</StartIPAddress><EndIPAddress>{last}</EndIPAddress>"
        elif "/" in value:
            network = ipaddress.ip_network(value)
            subnet = network.netmask if network.version == 4 else network.prefixlen
            body = f"<HostType>Network</HostType><IPAddress>{network.network_address}</IPAddress><Subnet>{subnet}</Subnet>"
        else:
            body = f"<HostType>IP</HostType><IPAddress>{value}</IPAddress>"
        return self.add(f'<IPHost transactionid=""><Name>{escape(name)}</Name><IPFamily>{family}</IPFamily>{body}</IPHost>')

    def group(self, name: str, members: Sequence[str], family: int = 4) -> "Entities":
        return self.add(f'<IPHostGroup transactionid=""><Name>{escape(name)}</Name><IPFamily>IPv{family}</IPFamily>'
                        f"<Description></Description>{self._listed('HostList', 'Host', members)}</IPHostGroup>")  # fmt: skip

    def fqdn(self, name: str, fqdn: str, groups: Sequence[str] = ()) -> "Entities":
        listed = self._listed("FQDNHostGroupList", "FQDNHostGroup", groups) if groups else ""
        return self.add(f'<FQDNHost transactionid=""><Name>{escape(name)}</Name><FQDN>{fqdn}</FQDN>{listed}</FQDNHost>')

    def fqdn_group(self, name: str, members: Sequence[str]) -> "Entities":
        return self.add(f'<FQDNHostGroup transactionid=""><Name>{escape(name)}</Name>'
                        f"{self._listed('FQDNHostList', 'FQDNHost', members)}</FQDNHostGroup>")  # fmt: skip

    def service(self, name: str, *details: str) -> "Entities":
        """``tcp/80``, ``tcp/8000:8010`` with ``@1024:2000`` for source ports, ``ip/GRE``, ``icmp/8``, ``icmp6/128``."""
        kinds = {"tcp": "TCPorUDP", "udp": "TCPorUDP", "ip": "IP", "icmp": "ICMP", "icmp6": "ICMPv6"}
        kind = kinds[details[0].split("/")[0]]
        body = ""
        for detail in details:
            proto, _, value = detail.partition("/")
            assert kinds[proto] == kind, details
            if kind == "TCPorUDP":
                ports, _, source = value.partition("@")
                body += (f"<ServiceDetail><SourcePort>{source or '1:65535'}</SourcePort><DestinationPort>{ports}"
                         f"</DestinationPort><Protocol>{proto.upper()}</Protocol></ServiceDetail>")  # fmt: skip
            elif kind == "IP":
                body += f"<ServiceDetail><ProtocolName>{value}</ProtocolName></ServiceDetail>"
            else:
                icmp_type, _, code = value.partition(",")
                body += (f"<ServiceDetail><{kind}Type>{icmp_type}</{kind}Type><{kind}Code>{code or '-1'}</{kind}Code>"
                         "</ServiceDetail>")  # fmt: skip
        return self.add(f'<Services transactionid=""><Name>{escape(name)}</Name><Type>{kind}</Type>'
                        f"<ServiceDetails>{body}</ServiceDetails></Services>")  # fmt: skip

    def service_group(self, name: str, members: Sequence[str]) -> "Entities":
        return self.add(f'<ServiceGroup transactionid=""><Name>{escape(name)}</Name><Description></Description>'
                        f"{self._listed('ServiceList', 'Service', members)}</ServiceGroup>")  # fmt: skip

    def _position(self, kind: str, name: str, family: int, position: str) -> str:
        before = self.last.get((kind, family))
        if not position:
            position = f"After:{before}" if before else "Top"
        if position in ("Top", "Bottom") or position.startswith("After"):
            self.last[(kind, family)] = name
        word, _, anchor = position.partition(":")
        return f"<Position>{word}</Position>" + (f"<{word}><Name>{escape(anchor)}</Name></{word}>" if anchor else "")

    def rule(self, name: str, action: str = "Accept", family: int = 4, src_zones: Optional[Sequence[str]] = None,
             dst_zones: Optional[Sequence[str]] = None, sources: Optional[Sequence[str]] = None,
             destinations: Optional[Sequence[str]] = None, services: Optional[Sequence[str]] = None,
             exclusions: Optional[Dict[str, Sequence[str]]] = None, status: str = "Enable", position: str = "",
             extra: str = "", head: str = "", kind: str = "Network", log: str = "Enable") -> "Entities":  # fmt: skip
        excluded = ""
        for key, names in (exclusions or {}).items():
            child = "Zone" if key.endswith("Zones") else "Service" if key == "Services" else "Network"
            excluded += self._listed(key, child, names)
        placed, anchor = (self._position("rule", name, family, position) + "\n").split("</Position>", 1)
        return self.add(
            f'<FirewallRule transactionid=""><Name>{escape(name)}</Name><Description></Description>'
            f"<IPFamily>IPv{family}</IPFamily><Status>{status}</Status>{placed}</Position>"
            f"<PolicyType>{kind}</PolicyType>{anchor.strip()}{head}<NetworkPolicy><Action>{action}</Action><LogTraffic>{log}</LogTraffic>"
            f"<SkipLocalDestined>Disable</SkipLocalDestined>{self._listed('SourceZones', 'Zone', src_zones)}"
            f"{self._listed('DestinationZones', 'Zone', dst_zones)}<Schedule>All The Time</Schedule>"
            f"{self._listed('SourceNetworks', 'Network', sources)}{self._listed('DestinationNetworks', 'Network', destinations)}"
            f"{self._listed('Services', 'Service', services)}"
            + (f"<Exclusions>{excluded}</Exclusions>" if exclusions is not None else "")
            + f"{extra}</NetworkPolicy></FirewallRule>"
        )  # fmt: skip

    def nat(self, name: str, family: int = 4, sources: Optional[Sequence[str]] = None,
            destinations: Optional[Sequence[str]] = None, services: Optional[Sequence[str]] = None,
            inbound: Optional[Sequence[str]] = None, outbound: Optional[Sequence[str]] = None, source: str = "Original",
            destination: str = "Original", service: str = "Original", linked: str = "None", status: str = "Enable",
            position: str = "", extra: str = "") -> "Entities":  # fmt: skip
        return self.add(
            f'<NATRule transactionid=""><Name>{escape(name)}</Name><Description></Description><IPFamily>IPv{family}</IPFamily>'
            f"<Status>{status}</Status>{self._position('nat', name, family, position)}"
            f"<LinkedFirewallrule>{escape(linked)}</LinkedFirewallrule><TranslatedDestination>{escape(destination)}"
            f"</TranslatedDestination><TranslatedService>{escape(service)}</TranslatedService>"
            f"{self._listed('OriginalSourceNetworks', 'Network', sources)}"
            f"{self._listed('OriginalDestinationNetworks', 'Network', destinations)}"
            f"{self._listed('OriginalServices', 'Service', services)}{self._listed('InboundInterfaces', 'Interface', inbound)}"
            f"{self._listed('OutboundInterfaces', 'Interface', outbound)}"
            f"<OverrideInterfaceNATPolicy>Disable</OverrideInterfaceNATPolicy><TranslatedSource>{escape(source)}"
            f"</TranslatedSource>{extra}</NATRule>"
        )  # fmt: skip

    def xml(self) -> str:
        attributes = f' APIVersion="{self.version}" IPS_CAT_VER="1"' if self.root == "Configuration" else ""
        return (f'<?xml version="1.0" encoding="UTF-8"?>\n<{self.root}{attributes}>\n' + "\n".join(self.parts)
                + f"\n</{self.root}>\n")  # fmt: skip

    def parse(self) -> Tuple[Policy, Report]:
        report = Report()
        return parse_sophos.parse(self.xml().encode(), report), report

    def config(self) -> SophosConfig:
        return SophosConfig(self.xml())


def codes(report: Report, kind: str, name: str) -> List[str]:
    return [finding.code for finding in report.item(kind, name).findings]


def notes(report: Report) -> List[str]:
    return [note.code for note in report.notes]


def convert(policy: Policy, options: Optional[Options] = None, **kwargs: Any) -> Tuple[SophosConfig, Report, str]:
    report = Report()
    text = cli.convert(policy, "sophos", report, options)
    return SophosConfig(text, **kwargs), report, text


def model_expects(p: Policy, pkt: Packet) -> bool:
    """The model's verdict, with what a Sophos Firewall does with traffic no rule matches."""
    verdict = model_verdict(p, pkt)
    if verdict is not None:
        return verdict
    return pkt.in_if == pkt.out_if and pkt.in_if in p.zones and bool(p.zones[pkt.in_if].intrazone_allow)


def packets(rng: random.Random, count: int, zones: Sequence[str] = ZONES) -> List[Packet]:
    out: List[Packet] = []
    for index in range(count):
        pkt = random_packet(rng, 6 if index % 4 == 0 else 4)
        pkt.in_if, pkt.out_if = rng.choice(list(zones)), rng.choice(list(zones))
        out.append(pkt)
    return out


# -- model -> Entities.xml: the file decides like the model -----------------------------------


@pytest.mark.parametrize("seed", range(60))
def test_emitted_rules_decide_like_the_model(seed: int) -> None:
    """Lists, negations of one or several fields, rule types, both IP versions: the verdict of the model."""
    rng = random.Random(seed)
    model = random_model(rng)
    model.zones = {zone: Zone(zone) for zone in ZONES}
    if seed % 3 == 1:
        model.zones[ZONES[0]].intrazone_allow = True
    for rule in model.rules:
        if rng.random() < 0.3:  # more rules with several negated fields than the generator makes by itself
            rule.negate_source = rule.sources != [ANY]
            rule.negate_destination = rule.destinations != [ANY]
        if rng.random() < 0.15:
            rule.scope = rng.choice([RuleScope.INTRAZONE, RuleScope.INTERZONE])  # also with zone "any"
    config, report, text = convert(model, zones=tuple(ZONES))
    lost = {item.name for item in report.items.values() if item.kind == "rule" and item.disabled}
    expected_model = Policy(vendor="panos", zones=model.zones, addresses=model.addresses, address_groups=model.address_groups,
                            services=model.services, service_groups=model.service_groups,
                            rules=[rule for rule in model.rules if rule.name not in lost])  # fmt: skip
    # Only a rule type with zone "any" has no way to be written: everything else is.
    for name in lost:
        assert "RULE_TYPE" in codes(report, "rule", name), (seed, name, codes(report, "rule", name))
    # "eth8" is a zone no rule names: it reaches the rules that name no zone.
    for pkt in packets(rng, 600, ZONES + ["eth8"]):
        assert config.allows(pkt) == model_expects(expected_model, pkt), (seed, pkt, text)


def test_rule_types_and_zone_defaults() -> None:
    p = Policy(vendor="panos", default_intrazone=Action.ALLOW)
    p.zones = {name: Zone(name) for name in ("a", "b", "c")}
    p.rules = [
        Rule("intra", src_zones=["a", "b"], scope=RuleScope.INTRAZONE, action=Action.DENY, origin="intra"),
        Rule("inter", src_zones=["a", "b"], dst_zones=["b", "c"], scope=RuleScope.INTERZONE, origin="inter"),
        Rule("wide", scope=RuleScope.INTERZONE, origin="wide"),
        Rule("empty", src_zones=["a"], dst_zones=["a"], scope=RuleScope.INTERZONE, origin="empty"),
    ]
    config, report, _ = convert(p)
    by_name = {rule["name"]: rule for rule in config.rules[4]}
    assert (by_name["intra"]["src_zones"], by_name["intra"]["dst_zones"]) == (["a"], ["a"])
    assert (by_name["intra_2"]["src_zones"], by_name["intra_2"]["dst_zones"]) == (["b"], ["b"])
    assert (by_name["inter"]["dst_zones"], by_name["inter_2"]["dst_zones"]) == (["b", "c"], ["c"])
    assert not by_name["wide"]["enabled"] and "RULE_TYPE" in codes(report, "rule", "wide")
    assert report.item("rule", "empty").skipped and "empty" not in by_name
    # The source lets traffic inside a zone through; a Sophos Firewall does not, and the report says so.
    assert "INTRAZONE_DEFAULT" in notes(report) and "ZONES_REQUIRED" in notes(report)
    p.default_intrazone, p.default_interzone = Action.DENY, Action.ALLOW
    p.zones["b"].intrazone_allow = True
    config, report, _ = convert(p)
    added = [rule for rule in config.rules[4] + config.rules[6] if rule["name"].startswith("fwshift-intrazone-b")]
    assert [(rule["src_zones"], rule["dst_zones"], rule["action"]) for rule in added] == [(["b"], ["b"], "Accept")] * 2
    assert config.rules[4][-1] in added and config.rules[6][-1] in added  # below every other rule
    assert "INTRAZONE_ALLOW_ADDED" in notes(report) and "INTERZONE_DEFAULT" in notes(report)
    assert "INTRAZONE_DEFAULT" not in notes(report)


def _policy(*rules: Rule, vendor: str = "panos") -> Policy:
    p = Policy(vendor=vendor)
    p.addresses = {
        "net-a": Address("net-a", AddressKind.NETWORK, "10.0.0.0/24"),
        "net-b": Address("net-b", AddressKind.NETWORK, "10.0.1.0/24"),
        "host-a": Address("host-a", AddressKind.NETWORK, "10.0.0.17/32"),
        "span": Address("span", AddressKind.RANGE, "10.0.2.100-10.0.3.50"),
        "six": Address("six", AddressKind.NETWORK, "2001:db8:1::/48"),
        "name": Address("name", AddressKind.FQDN, "www.example.com"),
    }
    p.services = {
        "web": Service("web", [ServiceEntry(Protocol.TCP, "80,443")]),
        "dns-both": Service("dns-both", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")]),
        "echo": Service("echo", [ServiceEntry(Protocol.ICMP, icmp_type=8)]),
        "echo6": Service("echo6", [ServiceEntry(Protocol.ICMP6, icmp_type=128)]),
    }
    for rule in rules:
        rule.origin = rule.origin or rule.name
        p.rules.append(rule)
    return p


def test_one_negated_field_is_an_exclusion_and_two_are_not() -> None:
    """Exclusions apply together: 'not A and not B' written as two exclusions would be 'not (A and B)'."""
    p = _policy(
        Rule("one", sources=["net-a"], negate_source=True, destinations=["net-b"]),
        Rule("two", sources=["net-a"], negate_source=True, destinations=["net-b"], negate_destination=True),
        Rule("three", sources=["net-a"], negate_source=True, destinations=["net-b"], negate_destination=True,
             services=["web"], negate_service=True),
        Rule("name", sources=["name"], negate_source=True, destinations=["net-b"], negate_destination=True),
        Rule("all", sources=[ANY_V4, "six"], negate_source=True, action=Action.DENY),
    )  # fmt: skip
    config, report, text = convert(p)
    rules = {rule["name"]: rule for rule in config.rules[4] + config.rules[6]}
    assert rules["one"]["exclusions"] == {"SourceNetworks": ["net-a"]} and rules["one"]["sources"] is None
    # One field stays an exclusion; the other is written as the addresses that are left.
    assert rules["two"]["exclusions"] == {"SourceNetworks": ["net-a"]}
    assert [config.span(name) for name in rules["two"]["destinations"]] == ["0.0.0.0-10.0.0.255", "10.0.2.0-255.255.255.255"]
    assert "NEGATION_AS_ADDRESSES" in codes(report, "rule", "two") and report.item("rule", "two").status == "exact"
    # With a negated service, both address fields are turned round.
    assert rules["three"]["exclusions"] == {"Services": ["web"]} and rules["three"]["services"] is None
    assert len(rules["three"]["sources"]) == 2 and len(rules["three"]["destinations"]) == 2
    # A host name cannot be turned round: it is the exclusion, the list of addresses is written out.
    assert rules["name"]["exclusions"] == {"SourceNetworks": ["name"]} and report.item("rule", "name").status == "exact"
    assert len(rules["name"]["destinations"]) == 2
    assert rules["name_v6"]["destinations"] is None and rules["name_v6"]["exclusions"] == {"SourceNetworks": ["name"]}
    # Two fields that cannot be turned round: the rule is not written as if it could.
    p.rules[3].destinations = ["name"]
    config, report, _ = convert(p)
    assert "NEGATION" in codes(report, "rule", "name") and report.item("rule", "name").disabled
    assert not {rule["name"]: rule for rule in config.rules[4]}["name"]["enabled"]
    # "Not any IPv4 address, not this IPv6 network" is an IPv6 rule with one exclusion.
    assert "all" not in {rule["name"] for rule in config.rules[4]}
    assert {rule["name"]: rule for rule in config.rules[6]}["all"]["exclusions"] == {"SourceNetworks": ["six"]}
    # In packets: a rule with two negated fields is not the rule with two exclusions.
    for src, dst, expected in (("10.0.0.5", "10.0.1.5", False), ("10.0.0.5", "10.9.9.9", False),
                               ("10.9.9.9", "10.0.1.5", False), ("10.9.9.9", "10.8.8.8", True)):  # fmt: skip
        only = _policy(Rule("two", sources=["net-a"], negate_source=True, destinations=["net-b"], negate_destination=True))
        pkt = Packet("x", "y", src, dst, "tcp", 40000, 80)
        assert convert(only)[0].allows(pkt) == model_allows(only, pkt) == expected, (src, dst)


def test_a_rulebase_per_ip_version() -> None:
    p = _policy(
        Rule("both", services=["web"]),
        Rule("four", sources=["net-a"]),
        Rule("six", sources=["six", "net-a"], destinations=["six"]),
        Rule("mixed", sources=["net-a"], destinations=["six"]),
        Rule("ping", services=["echo"]),
        Rule("pings", services=["echo", "echo6"], action=Action.DROP),
        Rule("names", sources=["name"], destinations=["name"]),
        Rule("pinned", sources=[ANY_V6], services=["web"]),
    )
    config, report, _ = convert(p)
    four, six = [rule["name"] for rule in config.rules[4]], [rule["name"] for rule in config.rules[6]]
    assert four == ["both", "four", "ping", "pings", "names"]
    assert six == ["both_v6", "six", "pings_v6", "names_v6", "pinned"]  # ICMP is of one IP version
    assert report.item("rule", "mixed").skipped and codes(report, "rule", "mixed") == ["NO_COMMON_FAMILY"]
    assert report.item("rule", "both").emitted_as == ["both", "both_v6"] and report.item("rule", "both").status == "exact"
    assert "IP_VERSION_SPLIT" in notes(report)
    # Each rule stands after the one before it of its own IP version, the first at the bottom of what is there.
    assert "<Position>Bottom</Position>" in config.text and config.text.count("<Position>Bottom</Position>") == 2
    by_name = {rule["name"]: rule for rule in config.rules[6]}
    assert by_name["six"]["sources"] == ["six"] and by_name["six"]["destinations"] == ["six"]


def test_groups_are_flat_and_of_one_kind() -> None:
    p = _policy(Rule("r", sources=["all"], destinations=["names"]), Rule("s", sources=["inner"], destinations=["wide"]))
    p.addresses["name4"] = Address("name4", AddressKind.FQDN, "four.example.com", fqdn_family=4)
    p.address_groups = {
        "inner": AddressGroup("inner", ["net-a", "10.0.9.0/24"]),
        "all": AddressGroup("all", ["inner", "six", "name", "host-a", "2001:db8:9::1"], "Everything"),
        "names": AddressGroup("names", ["name", "name4"]),
        "wide": AddressGroup("wide", ["net-b", ANY_V4]),
    }
    config, report, text = convert(p)
    hosts = config.hosts
    assert hosts["inner"] == {"kind": "group", "version": 4, "members": ["net-a", "n-10.0.9.0_24"]}
    assert hosts["all"]["members"] == ["net-a", "n-10.0.9.0_24", "host-a"] and hosts["all_v6"]["members"] == ["six", "h-2001_db8_9__1"]
    assert hosts["all_fqdn"] == {"kind": "fqdngroup", "members": ["name"]}
    assert report.item("address-group", "all").emitted_as == ["all", "all_v6", "all_fqdn"]
    assert codes(report, "address-group", "all") == ["GROUP_SPLIT"] and report.item("address-group", "all").status == "exact"
    # A name that is resolved for IPv4 only is not in the group an IPv6 rule gets.
    assert hosts["names"]["members"] == ["name", "name4"] and hosts["names_fqdn6"]["members"] == ["name"]
    rules = {rule["name"]: rule for rule in config.rules[4] + config.rules[6]}
    assert rules["r"]["sources"] == ["all", "all_fqdn"] and rules["r"]["destinations"] == ["names"]
    assert rules["r_v6"]["sources"] == ["all_v6", "all_fqdn"] and rules["r_v6"]["destinations"] == ["names_fqdn6"]
    # A group that holds every IPv4 address is "any" in an IPv4 rule, and no object.
    assert rules["s"]["destinations"] is None and "wide" not in hosts and "s_v6" not in rules
    assert "<Description>Everything</Description>" in text


def test_objects_that_are_every_address_are_not_defined() -> None:
    p = _policy(Rule("r", sources=["everything"], destinations=["net-a"]), Rule("n", sources=["everything"], negate_source=True))
    p.addresses["everything"] = Address("everything", AddressKind.NETWORK, "0.0.0.0/0")
    config, report, _ = convert(p)
    assert "everything" not in config.hosts and config.rules[4][0]["sources"] is None
    # "Not every IPv4 address" leaves IPv6: the rule is written for that.
    assert [rule["name"] for rule in config.rules[4]] == ["r"] and [rule["name"] for rule in config.rules[6]] == ["n"]


def test_services() -> None:
    p = _policy(Rule("r", services=["mixed", "grp", "sctp", "odd", "rare", "every", "high"]))
    p.services.update({
        "mixed": Service("mixed", [ServiceEntry(Protocol.TCP, "80,8000-8010", "1024-2000,3000"), ServiceEntry(Protocol.UDP, "53"),
                                   ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=1), ServiceEntry(Protocol.IP, ip_protocol=47),
                                   ServiceEntry(Protocol.ICMP6), ServiceEntry(Protocol.SCTP)]),
        "sctp": Service("sctp", [ServiceEntry(Protocol.SCTP, "2905")]),
        "odd": Service("odd", [ServiceEntry(Protocol.ICMP, icmp_type=42)]),
        "rare": Service("rare", [ServiceEntry(Protocol.IP, ip_protocol=89), ServiceEntry(Protocol.IP, ip_protocol=200)]),
        "every": Service("every", [ServiceEntry(Protocol.IP)]),
        "high": Service("high", [ServiceEntry(Protocol.IP, ip_protocol=61)]),
    })  # fmt: skip
    p.service_groups = {"inner": ServiceGroup("inner", ["web", "mixed"]), "grp": ServiceGroup("grp", ["inner", "dns-both"])}
    p.rules.append(Rule("clean", services=["grp", "rare"], origin="clean"))
    p.rules.append(Rule("any", services=["web", "every"], origin="any"))
    p.rules.append(Rule("none", services=["every"], negate_service=True, origin="none"))
    config, report, text = convert(p)
    services = config.services
    # A Sophos service holds one kind of protocol: the others become services of their own, and a group.
    assert services["mixed"] == {"kind": "group", "members": ["mixed-tcpudp", "mixed-ip", "mixed-icmp", "mixed-icmpv6"]}
    tcp = services["mixed-tcpudp"]["details"]
    assert {"protocol": "tcp", "src": (1024, 2000), "dst": (8000, 8010)} in tcp and len(tcp) == 5
    assert {"protocol": "udp", "src": (1, 65535), "dst": (53, 53)} in tcp
    assert services["mixed-ip"]["details"] == [{"number": 47}, {"number": 132}]
    assert services["mixed-icmp"]["details"] == [{"icmp": "icmp", "type": 3, "code": 1}]
    assert services["mixed-icmpv6"]["details"] == [{"icmp": "icmp6", "type": -1, "code": -1}]
    assert codes(report, "service", "mixed") == ["SERVICE_SPLIT"] and report.item("service", "mixed").status == "exact"
    # Groups hold services only: a group in a group is written out.
    assert services["grp"]["members"] == ["web", "mixed-tcpudp", "mixed-ip", "mixed-icmp", "mixed-icmpv6", "dns-both"]
    # What a Sophos service cannot say is never written as something wider.
    for name, word in (("sctp", "SCTP ports"), ("odd", "ICMP type 42"), ("high", "IP protocol 61")):
        assert word in report.item("service", name).findings[0].message and report.item("service", name).status == "needs-review"
        assert services[name]["details"] == [{"protocol": "tcp", "src": (1, 65535), "dst": (1, 1)}]
    assert report.item("rule", "r").disabled and not config.rules[4][0]["enabled"]
    assert not report.item("rule", "clean").disabled
    # A protocol name that the documentation does not show is written, and said.
    assert services["rare"]["details"] == [{"number": 89}, {"number": 200}] and "OSPFIGP" in text and "IPProto200" in text
    assert codes(report, "service", "rare") == ["PROTOCOL_NAME"] and "OSPFIGP" in report.item("service", "rare").findings[0].message
    # A service that is every protocol is "any service", not an object; negated, it leaves nothing.
    assert "every" not in services and not report.item("service", "every").findings
    assert {rule["name"]: rule for rule in config.rules[4]}["any"]["services"] is None
    assert report.item("rule", "none").skipped


def test_names() -> None:
    long = "L" * 70
    p = _policy(Rule("r", sources=["Web", "web", "any", "Any", long, "weird,name<&>"], services=["HTTP", "http", "Any", "tcp 80"]),
                Rule("R" * 70), Rule("R"), Rule("x:y"))  # fmt: skip
    for name in ("Web", "web", "any", "Any", long, "weird,name<&>"):
        p.addresses[name] = Address(name, AddressKind.NETWORK, f"10.1.{len(p.addresses)}.0/24")
    for name in ("HTTP", "http", "Any", "tcp 80"):
        p.services[name] = Service(name, [ServiceEntry(Protocol.TCP, str(8000 + len(p.services)))])
    config, report, text = convert(p)
    # Names that differ in case only would be one object after an import; the words of the format are no names.
    assert report.item("address", "web").emitted_as == ["web_2"] and "Web" in config.hosts
    assert report.item("address", "any").emitted_as == ["any_2"] and report.item("address", "Any").emitted_as == ["Any_3"]
    assert report.item("address", long).emitted_as == ["L" * 50] and report.item("address", "weird,name<&>").emitted_as == ["weird_name___"]
    # A service of another platform that carries the name of one a Sophos Firewall comes with would replace it.
    assert report.item("service", "HTTP").emitted_as == ["HTTP_2"] and report.item("service", "http").emitted_as == ["http_3"]
    assert report.item("service", "Any").emitted_as == ["Any_2"] and "tcp 80" in config.services
    assert [rule["name"] for rule in config.rules[4]] == ["r", "R" * 60, "R_2", "x_y"]
    rule = config.rules[4][0]
    assert rule["sources"] == ["Web", "web_2", "any_2", "Any_3", "L" * 50, "weird_name___"]
    assert rule["services"] == ["HTTP_2", "http_3", "Any_2", "tcp 80"]
    # With a prefix every object gets a name of its own, also where its name was fine.
    config, report, _ = convert(p, Options(object_prefix="m-"))
    assert "m-net-a" in config.hosts and "m-web" in config.services and "m-HTTP" in config.services and "HTTP_2" not in config.services
    assert report.item("address", "net-a").emitted_as == ["m-net-a"] and not report.item("address", "net-a").findings


def test_text_from_the_input_stays_text() -> None:
    """Nothing a name or a description holds can become markup, whatever platform it comes from."""
    evil = "</Name></IPHost><IPHost><Name>injected"
    for vendor in ("panos", "sophos"):
        p = _policy(Rule(evil, sources=[evil], services=[evil], description="a <b> & ]]> \x01\x0b￾ c"), vendor=vendor)
        p.addresses[evil] = Address(evil, AddressKind.NETWORK, "10.5.0.0/24")
        p.addresses["desc"] = Address("desc", AddressKind.FQDN, "www.example.org", description="<Zone>x</Zone>\n&amp;")
        p.services[evil] = Service(evil, [ServiceEntry(Protocol.TCP, "81")])
        p.nat_rules = [NatRule(evil, sources=[evil], source_translation=SourceNat(SnatKind.INTERFACE), origin="n",
                               description="<x>")]  # fmt: skip
        transform.harden(p, Report())
        config, report, text = convert(p)
        assert "injected" not in config.hosts and len(config.rules[4]) == 1 and len(config.nat[4]) == 1
        assert len([name for name, host in config.hosts.items() if host["kind"] == "ip"]) == len(p.addresses) - 2
        assert config.rules[4][0]["description"] == "a <b> & ]]> _ _ c"
    # Read back by fwshift itself, a name of a Sophos Firewall is the name it was.
    again = parse_sophos.parse(text.encode(), Report())
    assert evil in again.addresses and again.rules[0].name == evil and again.rules[0].sources == [evil]


def test_what_cannot_be_converted_is_written_disabled() -> None:
    p = _policy(
        Rule("user", users=["alice"]),
        Rule("url", url_categories=["gambling"]),
        Rule("time", schedule="office-hours"),
        Rule("region", sources=["region"], action=Action.DENY),
        Rule("missing", destinations=["nowhere"], services=["nothing"]),
        Rule("flagged", unsupported=["something the parser could not read"]),
        Rule("empty", sources=["nobody"]),
        Rule("app", applications=["web-browsing", "no-such-app"], services=["application-default"]),
        Rule("off", enabled=False),
        Rule("ok", sources=["net-a"], log_end=False, action=Action.RESET_BOTH),
    )
    p.addresses["region"] = Address("region", AddressKind.UNSUPPORTED, "", raw="a region")
    p.address_groups["nobody"] = AddressGroup("nobody", [])
    config, report, text = convert(p)
    rules = {rule["name"]: rule for rule in config.rules[4]}
    for name, code in (("user", "USER_MATCH"), ("url", "URL_CATEGORY"), ("time", "SCHEDULE"), ("region", "UNCONVERTIBLE_OBJECT"),
                       ("missing", "UNCONVERTIBLE_OBJECT"), ("flagged", "UNSUPPORTED_MATCH"), ("empty", "UNCONVERTIBLE_OBJECT"),
                       ("app", "APP_UNKNOWN")):  # fmt: skip
        assert code in codes(report, "rule", name) and report.item("rule", name).disabled, name
        assert not rules[name]["enabled"] and rules[name]["description"].startswith("FWSHIFT: disabled by the converter"), name
    assert "NOT enforced" in report.item("rule", "region").findings[0].message
    # What stands in for an object that could not be converted matches nothing: a host name that does not exist.
    for name in ("region", "nowhere", "nobody"):
        assert config.hosts[name]["kind"] == "fqdn" and config.hosts[name]["fqdn"].endswith(".fwshift.invalid"), name
    assert len({config.hosts[name]["fqdn"] for name in ("region", "nowhere", "nobody")}) == 3
    assert "FWSHIFT PLACEHOLDER, matches nothing: a region" in text
    assert not rules["off"]["enabled"] and not report.item("rule", "off").disabled
    assert rules["ok"]["enabled"] and rules["ok"]["action"] == "Reject" and not rules["ok"]["log"]
    assert codes(report, "rule", "ok") == ["RESET_ACTION"] and rules["region"]["action"] == "Drop"
    # Applications become their ports where the table has them.
    p.rules[7].applications = ["web-browsing", "dns"]
    config, report, _ = convert(p)
    app = {rule["name"]: rule for rule in config.rules[4]}["app"]
    assert app["enabled"] and app["services"] == ["app-web-browsing", "app-dns"] and "APP_TO_PORTS" in codes(report, "rule", "app")
    assert config.services["app-dns"]["details"] == [{"protocol": "tcp", "src": (1, 65535), "dst": (53, 53)},
                                                     {"protocol": "udp", "src": (1, 65535), "dst": (53, 53)}]  # fmt: skip


# -- Entities.xml -> model: the model decides like the firewall would ------------------------

HOSTS4 = {"net0": "10.0.0.0/24", "net1": "10.0.1.0/24", "net2": "10.0.2.0/24", "net3": "10.0.3.0/24", "net4": "10.0.4.0/24",
          "half": "10.0.1.128/25", "span": "10.0.2.100-10.0.3.50", "host": "10.0.0.17"}  # fmt: skip
HOSTS6 = {"six": "2001:db8:1::/48", "six2": "2001:db8:2::/64", "host6": "2001:db8:3::1"}
SERVICES = ["web", "dns2", "ranges", "echo", "stamp", "echo6", "gre", "mix"]


def base_entities() -> Entities:
    e = Entities()
    for zone in ZONES:
        e.zone(zone).interface(zone, zone)  # an interface per zone, of the same name
    for name, value in {**HOSTS4, **HOSTS6}.items():
        e.host(name, value)
    e.group("grp4", ["net0", "span"]).group("grp6", ["six", "host6"], 6)
    e.service("web", "tcp/80", "tcp/443").service("dns2", "tcp/53", "udp/53")
    e.service("ranges", "tcp/8000:8010@1024:2000", "tcp/9000").service("echo", "icmp/8").service("stamp", "icmp/13")
    e.service("echo6", "icmp6/128").service("gre", "ip/GRE").service_group("mix", ["web", "echo", "gre"])
    return e


def random_entities(rng: random.Random) -> Entities:
    e = base_entities()
    pools = {4: list(HOSTS4) + ["grp4"], 6: list(HOSTS6) + ["grp6"]}
    names: Dict[int, List[str]] = {4: [], 6: []}

    def some(pool: List[str], chance: float = 0.3, most: int = 3) -> Optional[List[str]]:
        return None if rng.random() < chance else rng.sample(pool, rng.randint(1, most))

    for index in range(rng.randint(5, 12)):
        family = 6 if rng.random() < 0.25 else 4
        services = some(SERVICES, 0.4)
        exclusions: Optional[Dict[str, Sequence[str]]] = None
        if rng.random() < 0.5:
            kinds = ["SourceZones", "DestinationZones", "SourceNetworks", "DestinationNetworks"]
            kinds += ["Services"] if services is None or rng.random() < 0.15 else []
            exclusions = {}
            for kind in rng.sample(kinds, rng.choice([1, 1, 2, 2, 3])):
                pool = ZONES if kind.endswith("Zones") else SERVICES if kind == "Services" else pools[family]
                exclusions[kind] = rng.sample(pool, rng.randint(1, 2))
        position = ""
        if names[family] and rng.random() < 0.15:
            position = rng.choice(["Top", "Bottom", f"Before:{rng.choice(names[family])}", f"After:{rng.choice(names[family])}"])
        name = f"r{index}"
        e.rule(name, rng.choice(["Accept", "Accept", "Drop", "Reject"]), family, some(ZONES, 0.3, 2), some(ZONES, 0.3, 2),
               some(pools[family]), some(pools[family]), services, exclusions,
               "Disable" if rng.random() < 0.1 else "Enable", position)  # fmt: skip
        names[family].append(name)
    return e


def test_parsed_rules_decide_like_the_firewall_would() -> None:
    """Exclusions of several kinds, both rulebases, positions, lists and "any": the model gives the verdict of the file.

    A file with a rule the parser flags (an exclusion it cannot express: such a rule is converted disabled)
    is set aside; most generated files have none.
    """
    compared = 0
    for seed in range(120):
        rng = random.Random(seed)
        entities = random_entities(rng)
        config = entities.config()
        model, report = entities.parse()
        assert {rule.origin.split("-")[0] for rule in model.rules} | {i.name for i in report.items.values() if i.skipped} \
            == {rule["name"] for rule in config.rules[4] + config.rules[6]}, seed
        if any(rule.unsupported for rule in model.rules):
            assert all("exclusion of service" in text for rule in model.rules for text in rule.unsupported), seed
            continue
        compared += 1
        for pkt in packets(rng, 400):
            assert model_allows(model, pkt) == config.allows(pkt), (seed, pkt, config.deciding(pkt), entities.xml())
    assert compared >= 90, compared


def test_roundtrip_of_a_random_export_keeps_every_decision() -> None:
    """Entities.xml -> model -> Entities.xml: the second file decides like the first."""
    compared = 0
    for seed in range(60):
        rng = random.Random(5000 + seed)
        entities = random_entities(rng)
        first = entities.config()
        model, report = entities.parse()
        if any(rule.unsupported for rule in model.rules):
            continue
        compared += 1
        text = cli.convert(model, "sophos", report)
        second = SophosConfig(text, zones=tuple(ZONES))
        # Nothing needs a second look but a rule that matched nothing on the source either (ICMP in the IPv6
        # rulebase), and a blocking rule for "any zone except": the zones of the file stand for "any" there.
        review = [(item.name, [f.code for f in item.findings if f.severity == Severity.REVIEW] or [item.findings[-1].code])
                  for item in report.items.values() if item.status in ("needs-review", "skipped")]  # fmt: skip
        allowed = {"NO_COMMON_FAMILY", "RULE_MATCHES_NOTHING", "EXCLUSION_ZONES"}
        assert second.api_version == "2000.1" and all(set(found) <= allowed for _, found in review), (seed, review)
        for pkt in packets(rng, 300):
            assert second.allows(pkt) == first.allows(pkt), (seed, pkt, entities.xml(), text)
    assert compared >= 40, compared


def test_exclusions_apply_together() -> None:
    """The rule is skipped only for traffic that matches every kind of exclusion it has."""
    e = base_entities()
    e.rule("r", src_zones=["eth0", "eth1"], sources=["net0", "net1"], services=["web"],
           exclusions={"SourceZones": ["eth1"], "SourceNetworks": ["half", "host"], "DestinationNetworks": ["net4"]})  # fmt: skip
    model, report = e.parse()
    config = e.config()
    assert [rule.name for rule in model.rules] == ["r", "r-2", "r-3"] and codes(report, "rule", "r") == ["RULE_SPLIT"]
    first, second, third = model.rules
    assert first.src_zones == ["eth0"] and first.sources == ["net0", "net1"] and first.destinations == [ANY_V4]
    assert second.src_zones == ["eth0", "eth1"] and second.sources == ["10.0.0.0-10.0.0.16", "10.0.0.18-10.0.1.127"]
    assert third.destinations == ["net4"] and third.negate_destination and not third.negate_source
    assert codes(report, "rule", "r-2") == ["EXCLUSION_AS_ADDRESSES"] and report.item("rule", "r-2").status == "exact"
    for zone, src, dst, expected in (("eth1", "10.0.0.17", "10.0.4.9", False),  # all three hold: skipped
                                     ("eth0", "10.0.0.17", "10.0.4.9", True), ("eth1", "10.0.0.18", "10.0.4.9", True),
                                     ("eth1", "10.0.0.17", "10.0.3.9", True), ("eth2", "10.0.0.18", "10.0.3.9", False)):  # fmt: skip
        pkt = Packet(zone, "eth2", src, dst, "tcp", 40000, 443)
        assert config.allows(pkt) == model_allows(model, pkt) == expected, pkt
    # One kind of exclusion is one rule; a zone is taken out of the zones, an address out of "any" is a negation.
    e = base_entities()
    e.rule("zone", src_zones=["eth0", "eth1"], exclusions={"SourceZones": ["eth1", "eth2"]})
    e.rule("anyzone", exclusions={"DestinationZones": ["eth2"]})
    e.rule("net", exclusions={"SourceNetworks": ["net0"]})
    e.rule("svc", exclusions={"Services": ["web"]})
    e.rule("svc-of-list", services=["mix"], exclusions={"Services": ["web"]})
    e.rule("beside", sources=["net3"], exclusions={"SourceNetworks": ["net0"]})
    e.rule("nothing", sources=["half"], exclusions={"SourceNetworks": ["net1"]})
    e.rule("gone", src_zones=["eth0"], exclusions={"SourceZones": ["eth0"]}, action="Drop")
    model, report = e.parse()
    rules = {rule.name: rule for rule in model.rules}
    assert rules["zone"].src_zones == ["eth0"]
    assert rules["anyzone"].dst_zones == ["eth0", "eth1"] and codes(report, "rule", "anyzone") == ["EXCLUSION_ZONES"]
    assert report.item("rule", "anyzone").status == "approximated"
    assert rules["net"].sources == ["net0"] and rules["net"].negate_source and rules["net"].destinations == [ANY_V4]
    assert rules["svc"].services == ["web"] and rules["svc"].negate_service
    assert rules["svc-of-list"].unsupported == ["exclusion of service web from a list of services"]
    assert rules["beside"].sources == ["net3"] and not rules["beside"].negate_source
    for name in ("nothing", "gone"):  # the exclusion takes everything: the rule never applies
        assert name not in rules and report.item("rule", name).skipped and codes(report, "rule", name) == ["RULE_MATCHES_NOTHING"]
        assert report.item("rule", name).findings[0].severity == Severity.INFO
    assert not report.needs_review or [i.name for i in report.items.values() if i.status == "needs-review"] == []


def test_what_is_missing_is_any_and_what_is_empty_is_not() -> None:
    """A list that is not there is "any": that is how the format writes it. Nothing else is read as any."""
    e = base_entities()
    e.rule("absent")
    e.rule("empty", sources=[])
    e.rule("blank", extra="", services=[" "])
    e.rule("stray", extra="<SourceUsers><User>x</User></SourceUsers>")
    e.rule("stray-off", extra="<DestinationCountries></DestinationCountries><NewInspection>Enable</NewInspection>")
    e.rule("wrong-child", destinations=None, extra="<DestinationNetworks><Host>net0</Host></DestinationNetworks>")
    e.rule("empty-exclusion", exclusions={"SourceNetworks": []})
    e.rule("odd-exclusion", exclusions={}, extra="")
    e.add(e.parts.pop().replace("<Exclusions></Exclusions>", "<Exclusions><Users><User>x</User></Users></Exclusions>"))
    e.rule("any-exclusion", exclusions={"SourceNetworks": ["Any"]})
    e.rule("action", action="Tarpit")
    e.rule("word", sources=["Any"], destinations=["any", "net0"])
    e.rule("undefined", sources=["no-such-host"], services=["no-such-service"])
    e.add('<FirewallRule transactionid=""><Name>bare</Name><IPFamily>IPv4</IPFamily><Status>Enable</Status>'
          "<Position>Bottom</Position><PolicyType>Network</PolicyType></FirewallRule>")  # fmt: skip
    model, report = e.parse()
    rules = {rule.name: rule for rule in model.rules}
    absent = rules["absent"]
    assert (absent.src_zones, absent.dst_zones, absent.sources, absent.destinations, absent.services) == \
        ([ANY], [ANY], [ANY_V4], [ANY], [ANY]) and not absent.unsupported
    assert rules["empty"].unsupported == ["<SourceNetworks> without a <Network>"]
    assert rules["blank"].unsupported == ["<Services> without a <Service>"]
    assert "element <SourceUsers> ('x')" in rules["stray"].unsupported[0]
    # An element nobody knows that says nothing, or that does not look like a criterion, leaves the rule alone.
    assert not rules["stray-off"].unsupported and rules["stray-off"].handling == {"NewInspection": "Enable"}
    assert "ELEMENTS_NOT_READ" in notes(report) and "<NewInspection> (1)" in report.notes[0].message
    assert rules["wrong-child"].unsupported == ["<DestinationNetworks> without a <Network>"]
    assert rules["empty-exclusion"].unsupported and rules["odd-exclusion"].unsupported == ["exclusion <Users> that this parser does not know"]
    assert rules["any-exclusion"].unsupported == ["exclusion of any in <SourceNetworks>"]
    assert rules["action"].unsupported == ["action 'Tarpit'"] and rules["action"].action == Action.DENY
    assert rules["word"].sources == [ANY_V4] and rules["word"].destinations == [ANY]
    assert rules["bare"].unsupported == ["rule without a <NetworkPolicy>"] and rules["bare"].action == Action.DENY
    # A name nothing defines stays a name: every emitter gives it a placeholder and disables the rule.
    assert rules["undefined"].sources == ["no-such-host"] and not rules["undefined"].unsupported
    report = Report()
    text = cli.convert(model, "sophos", report)
    config = SophosConfig(text)
    written = {rule["name"]: rule for rule in config.rules[4]}
    for name, rule in rules.items():
        assert written[name]["enabled"] == (not rule.unsupported and name != "undefined"), name
    assert "UNDEFINED_REFERENCE" in codes(report, "address", "no-such-host")


def test_objects_as_they_are_read() -> None:
    e = Entities()
    e.host("h", "10.1.1.1").host("n", "10.1.2.0/24").host("r", "10.1.3.1-10.1.3.9").host("n6", "2001:db8:5::/64")
    e.add('<IPHost transactionid=""><Name>prefix</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType>'
          "<IPAddress>10.1.4.0</IPAddress><Subnet>24</Subnet></IPHost>")  # fmt: skip
    e.add('<IPHost transactionid=""><Name>list</Name><IPFamily>IPv4</IPFamily><HostType>IPList</HostType>'
          "<ListOfIPAddresses>10.1.5.1, 10.1.5.9</ListOfIPAddresses></IPHost>")  # fmt: skip
    e.add('<IPHost transactionid=""><Name>#Port1</Name><IPFamily>IPv4</IPFamily><HostType>System Host</HostType></IPHost>')
    e.add('<IPHost transactionid=""><Name>##ALL_RW6</Name><IPFamily>IPv6</IPFamily><HostType>System Host</HostType></IPHost>')
    e.add('<IPHost transactionid=""><Name>#Port9</Name><IPFamily>IPv4</IPFamily><HostType>System Host</HostType></IPHost>')
    e.group("ports", ["#Port1", "h"]).rule("vpn6", family=6, sources=["##ALL_RW6"])
    for name, body in (("badmask", "<HostType>Network</HostType><IPAddress>10.1.6.0</IPAddress><Subnet>255.0.255.0</Subnet>"),
                       ("badip", "<HostType>IP</HostType><IPAddress>10.1.6.300</IPAddress>"),
                       ("slash", "<HostType>IP</HostType><IPAddress>10.1.6.0/24</IPAddress>"),
                       ("badrange", "<HostType>IPRange</HostType><StartIPAddress>10.1.6.9</StartIPAddress>"
                                    "<EndIPAddress>10.1.6.1</EndIPAddress>"),
                       ("badlist", "<HostType>IPList</HostType><ListOfIPAddresses>10.1.7.1,x</ListOfIPAddresses>"),
                       ("mac", "<HostType>MAC</HostType>")):  # fmt: skip
        e.add(f'<IPHost transactionid=""><Name>{name}</Name><IPFamily>IPv4</IPFamily>{body}</IPHost>')
    e.fqdn("www", "www.example.com", groups=["sites"]).fqdn("wild", "*.example.com").fqdn("other", "other.example.com")
    e.fqdn_group("sites", ["other"]).group("servers", ["h", "r"])
    e.add('<MACHost transactionid=""><Name>printer</Name><Type>MACAddress</Type><MACAddress>00:00:5e:00:53:01</MACAddress></MACHost>')
    e.add('<CountryGroup transactionid=""><Name>Region</Name></CountryGroup>')
    e.service("svc", "tcp/80", "udp/1000:2000@53").service("icmp-names", "icmp/Echo Request,Any Code", "icmp/Any Type")
    e.service("icmp6-names", "icmp6/Echo Request", "icmp6/135,0").service("protos", "ip/ESP", "ip/IPProto200", "ip/89", "ip/ospfigp")
    e.service("bad-proto", "ip/NOPE").service("bad-port", "tcp/80,81").service("bad-icmp", "icmp/Chatter").service("all", "tcp/1:65535")
    e.add('<Services transactionid=""><Name>empty</Name><Type>TCPorUDP</Type><ServiceDetails></ServiceDetails></Services>')
    e.add('<Services transactionid=""><Name>odd</Name><Type>Quic</Type><ServiceDetails><ServiceDetail/></ServiceDetails></Services>')
    e.service_group("both", ["svc", "protos"])
    e.host("h", "10.9.9.9").service("svc", "tcp/81")  # defined twice: the last one is kept, and the report says so
    model, report = e.parse()
    a, g, s = model.addresses, model.address_groups, model.services
    assert (a["h"].value, a["n"].value, a["r"].value, a["n6"].value, a["prefix"].value) == \
        ("10.9.9.9", "10.1.2.0/24", "10.1.3.1-10.1.3.9", "2001:db8:5::/64", "10.1.4.0/24")
    assert a["r"].kind == AddressKind.RANGE and g["list"].members == ["10.1.5.1", "10.1.5.9"]
    assert a["#Port1"].builtin == "sophos" and a["#Port1"].kind == AddressKind.UNSUPPORTED and a["##ALL_RW6"].fqdn_family == 6
    # A firewall has a system host per port: one that nothing names is not carried along, nor reported.
    assert "#Port9" not in a and ("address", "#Port9") not in report.items and codes(report, "address", "#Port1")
    assert not codes(report, "rule", "vpn6")  # an IPv6 system host says that the rule is an IPv6 rule
    for name in ("badmask", "badip", "slash", "badrange", "badlist"):
        assert a[name].kind == AddressKind.UNSUPPORTED and codes(report, "address", name) == ["INVALID_ADDRESS"], name
    assert a["mac"].kind == a["printer"].kind == a["Region"].kind == a["wild"].kind == AddressKind.UNSUPPORTED
    assert a["wild"].value == "*.example.com" and a["www"].kind == AddressKind.FQDN
    assert g["sites"].members == ["other", "www"] and g["servers"].members == ["h", "r"]  # a host says which groups hold it
    assert [(x.protocol.value, x.dst_ports, x.src_ports) for x in s["svc"].entries] == [("tcp", "81", "")]
    assert codes(report, "address", "h") == ["DUPLICATE_NAME"] and codes(report, "service", "svc") == ["DUPLICATE_NAME"]
    assert [(x.icmp_type, x.icmp_code) for x in s["icmp-names"].entries] == [(8, None), (None, None)]
    assert [(x.protocol, x.icmp_type, x.icmp_code) for x in s["icmp6-names"].entries] == [(Protocol.ICMP6, 128, None), (Protocol.ICMP6, 135, 0)]
    assert [x.ip_protocol for x in s["protos"].entries] == [50, 200, 89, 89]
    for name in ("bad-proto", "bad-port", "bad-icmp", "empty", "odd"):
        assert s[name].unsupported and codes(report, "service", name) == ["UNSUPPORTED_SERVICE"], name
    assert s["all"].entries[0].dst_ports == "" and model.service_groups["both"].members == ["svc", "protos"]


def test_rule_order_is_the_order_of_evaluation() -> None:
    e = base_entities()
    e.rule("b", position="Bottom").rule("a", position="Top").rule("c", position="After:a").rule("d", position="Before:b")
    e.rule("six", family=6, position="Bottom").rule("e", position="After:b").rule("six-top", family=6, position="Top")
    model, report = e.parse()
    assert [rule.name for rule in model.rules] == ["a", "c", "d", "b", "e", "six-top", "six"] and not report.notes
    assert [rule["name"] for rule in e.config().rules[4]] == ["a", "c", "d", "b", "e"]
    # A rule that stands after a rule the file does not hold: read where it is, and said.
    e.rule("lost", position="After:not-there").rule("cross", position="After:six")
    model, report = e.parse()
    assert [rule.name for rule in model.rules][:7] == ["a", "c", "d", "b", "e", "lost", "cross"]
    assert notes(report) == ["RULE_ORDER"] and "lost, cross" in report.notes[0].message
    assert report.notes[0].severity == Severity.REVIEW


def test_rules_that_are_no_forwarding_rules() -> None:
    e = base_entities().zone("LOCAL", "LOCAL")
    e.rule("waf", kind="HTTPBased").rule("old-dnat", kind="PublicNonHTTPBased")
    e.rule("to-firewall", dst_zones=["LOCAL"]).rule("partly", dst_zones=["LOCAL", "eth1"])
    e.rule("users", kind="User", extra="<MatchIdentity>Enable</MatchIdentity><Identity><Member>Finance</Member>"
           "<Member>Sales</Member></Identity><ShowCaptivePortal>Enable</ShowCaptivePortal>")  # fmt: skip
    e.rule("known", extra="<MatchIdentity>Enable</MatchIdentity>")
    e.rule("not-matched", extra="<MatchIdentity>Disable</MatchIdentity><Identity><Member>x</Member></Identity>")
    e.rule("timed", extra="").add(e.parts.pop().replace("All The Time", "Work hours"))
    e.rule("v17", extra="<ApplyNAT>CustomNatPolicy</ApplyNAT><OutboundAddress>MASQ</OutboundAddress>")
    e.rule("profiles", extra="<WebFilter>Default Policy</WebFilter><IntrusionPrevention>None</IntrusionPrevention>"
           "<ScanVirus>Disable</ScanVirus><DSCPMarking>-1</DSCPMarking><TrafficShappingPolicy>Gold</TrafficShappingPolicy>", log="Disable")  # fmt: skip
    model, report = e.parse()
    rules = {rule.name: rule for rule in model.rules}
    assert report.item("rule", "waf").skipped and codes(report, "rule", "waf") == ["WAF_RULE"]
    assert report.item("rule", "old-dnat").skipped and codes(report, "rule", "old-dnat") == ["RULE_TYPE_NOT_READ"]
    assert "LOCAL" not in model.zones and "firewall itself" in rules["to-firewall"].unsupported[0]
    assert rules["partly"].dst_zones == ["eth1"] and not rules["partly"].unsupported
    assert rules["users"].users == ["Finance", "Sales"] and "web-authentication" in rules["users"].handling
    assert rules["known"].users == [parse_sophos.KNOWN_USER] and rules["not-matched"].users == [ANY]
    assert rules["timed"].schedule == "Work hours"
    assert codes(report, "rule", "v17") == ["HANDLING_NOT_CONVERTED", "RULE_NAT"] and rules["v17"].handling["ApplyNAT"] == "CustomNatPolicy"
    assert rules["profiles"].profiles == {"WebFilter": "Default Policy"} and rules["profiles"].handling == {"TrafficShappingPolicy": "Gold"}
    assert not rules["profiles"].log_end and rules["users"].log_end and not rules["users"].log_start


def test_ip_version_of_a_rule() -> None:
    e = base_entities().fqdn("www", "www.example.com")
    e.rule("four").rule("six", family=6).rule("names", sources=["www"], destinations=["www"])
    e.rule("named-one-side", sources=["www"], destinations=["net0"]).rule("six-any-src", family=6, destinations=["six"])
    e.rule("excluded", family=6, exclusions={"SourceNetworks": ["six"], "DestinationNetworks": ["six2"]})
    model, report = e.parse()
    rules = {rule.name: rule for rule in model.rules}
    assert rules["four"].sources == [ANY_V4] and rules["six"].sources == [ANY_V6] and rules["six-any-src"].sources == [ANY_V6]
    # Only host names on both sides: in the model the rule is for both IP versions, and the report says so.
    assert codes(report, "rule", "names") == ["IP_FAMILY"] and report.item("rule", "names").status == "approximated"
    assert not codes(report, "rule", "named-one-side")
    # A negated list is of no IP version: the other side says which rulebase the rule was in.
    assert rules["excluded"].negate_source and rules["excluded"].destinations == [ANY_V6]
    assert rules["excluded-2"].negate_destination and rules["excluded-2"].sources == [ANY_V6]
    for pkt in packets(random.Random(3), 300):
        assert model_allows(model, pkt) == e.config().allows(pkt), pkt


# -- NAT ------------------------------------------------------------------------------------


def model_translation(p: Policy, pkt: Packet, skipped: Sequence[str] = ()) -> Tuple[str, str, str, str]:
    """(rule, translated source, translated destination, translated port) of the first NAT rule that matches.

    The zone of a rule that translates the destination is where its original address is reached, which
    is nothing a packet of these tests has: it is not compared.
    """
    from test_iptables import _entry_matches, _member_matches

    for nat in p.nat_rules:
        if not nat.enabled or nat.unsupported or nat.origin in skipped:
            continue
        if ANY not in nat.src_zones and pkt.in_if not in nat.src_zones:
            continue
        if nat.destination_translation is None and ANY not in nat.dst_zones and pkt.out_if not in nat.dst_zones:
            continue
        if not any(_member_matches(p, member, pkt.src) for member in nat.sources):
            continue
        if not any(_member_matches(p, member, pkt.dst) for member in nat.destinations):
            continue
        if nat.service != ANY and not any(_entry_matches(entry, pkt) for entry in transform.flatten_services(p, nat.service) or []):
            continue
        source, destination, port = "Original", "Original", "Original"
        if nat.source_translation is not None:
            intervals = [i for member in nat.source_translation.addresses for i in transform.address_intervals(p, member) or []]
            source = "MASQ" if not intervals else _span(intervals)
        if nat.destination_translation is not None:
            destination = _span(transform.address_intervals(p, nat.destination_translation.address) or [])
            port = nat.destination_translation.port or "Original"
        return nat.origin, source, destination, port
    return "", "Original", "Original", "Original"


def _span(intervals: List[Tuple[int, int, int]]) -> str:
    version, first, last = intervals[0][0], min(i[1] for i in intervals), max(i[2] for i in intervals)
    make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return str(make(first)) if first == last else f"{make(first)}-{make(last)}"


def file_translation(config: SophosConfig, pkt: Packet) -> Tuple[str, str, str, str]:
    rule = config.translating(pkt)
    if rule is None:
        return "", "Original", "Original", "Original"
    source = rule["source"] if rule["source"] in ("Original", "MASQ") else config.span(rule["source"])
    destination = rule["destination"] if rule["destination"] == "Original" else config.span(rule["destination"])
    port = rule["service"]
    if port != "Original":
        ports = {detail["dst"] for detail in config.services[port]["details"]}
        assert len(ports) == 1 and ports == {(min(ports)[0], min(ports)[0])}, ports
        port = str(min(ports)[0])
        if all(detail["dst"][0] == pkt.dport for detail in config.services[rule["services"][0]]["details"]) and str(pkt.dport) == port:
            port = "Original"
    return rule["name"], source, destination, port


def random_nat_model(rng: random.Random) -> Policy:
    p = random_model(rng)
    p.rules = []
    p.services["one"] = Service("one", [ServiceEntry(Protocol.TCP, "8080")])
    p.services["both"] = Service("both", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")])
    four = ["net0", "net1", "net2", "net3", "net4", "half", "span", "host", "10.0.3.0/24", "10.0.0.34"]
    for index in range(rng.randint(4, 9)):
        nat = NatRule(f"n{index}", origin=f"n{index}")
        nat.src_zones = [ANY] if rng.random() < 0.4 else rng.sample(ZONES, rng.randint(1, 2))
        nat.sources = [ANY] if rng.random() < 0.4 else rng.sample(four, rng.randint(1, 2))
        nat.destinations = [ANY] if rng.random() < 0.4 else rng.sample(four, rng.randint(1, 2))
        nat.service = rng.choice([ANY, ANY, "web", "one", "both", "dns", "ranges", "mix"])
        shape = rng.choice(["masq", "pool", "host", "dnat", "dnat-port", "none", "both"])
        if shape in ("masq", "pool", "host", "none", "both"):
            nat.dst_zones = [ANY] if rng.random() < 0.3 else rng.sample(ZONES, rng.randint(1, 2))
        if shape == "masq":
            nat.source_translation = SourceNat(SnatKind.INTERFACE)
        elif shape == "pool":
            members = rng.choice([["192.0.2.1", "192.0.2.2"], ["192.0.2.8/30"], ["192.0.2.1", "192.0.2.9"], ["half"], ["grp"]])
            nat.source_translation = SourceNat(rng.choice([SnatKind.DYNAMIC_PORT, SnatKind.DYNAMIC]), members)
        elif shape in ("host", "both"):
            nat.source_translation = SourceNat(SnatKind.DYNAMIC_PORT, [rng.choice(["host", "192.0.2.77"])])
        if shape in ("dnat", "dnat-port", "both"):
            nat.dst_zones = [ANY]
            nat.destination_translation = DestNat(rng.choice(["host", "10.0.4.9"]), "8443" if shape == "dnat-port" else "")
        nat.enabled = rng.random() > 0.1
        p.nat_rules.append(nat)
    return p


@pytest.mark.parametrize("seed", range(40))
def test_emitted_nat_rules_translate_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = random_nat_model(rng)
    options = Options(interface_map={zone: zone for zone in ZONES})
    config, report, text = convert(model, options, interfaces=tuple(ZONES))
    skipped = [item.name for item in report.items.values() if item.kind == "nat" and item.skipped]
    for name in skipped:
        nat = next(rule for rule in model.nat_rules if rule.origin == name)
        message = report.item("nat", name).findings[0].message
        # Left out for a reason the rule shows: a pool that is not one range, a port translation without one port.
        pool = nat.source_translation is not None and nat.source_translation.addresses in (["192.0.2.1", "192.0.2.9"], ["grp"])
        port = nat.destination_translation is not None and nat.destination_translation.port and nat.service != "one"
        assert ("translated source" in message and pool) or ("translation to port" in message and port), (seed, name, message)
    assert len(config.nat[4]) == len(model.nat_rules) - len(skipped) and not config.nat[6]
    for pkt in packets(rng, 400):
        if ":" in pkt.src:
            continue
        assert file_translation(config, pkt) == model_translation(model, pkt, skipped), (seed, pkt, text)


def random_nat_entities(rng: random.Random) -> Entities:
    e = base_entities()
    e.host("pub1", "192.0.2.10").host("pub2", "192.0.2.20").host("pool", "192.0.2.100-192.0.2.110").service("one", "tcp/8080")
    e.service("alt", "tcp/8443").service("both", "tcp/5353", "udp/5353")
    four = list(HOSTS4) + ["grp4"]

    def some(pool: List[str], chance: float = 0.4) -> Optional[List[str]]:
        return None if rng.random() < chance else rng.sample(pool, rng.randint(1, 2))

    for index in range(rng.randint(4, 9)):
        shape = rng.choice(["masq", "host", "pool", "dnat", "pat", "pat2", "none", "both"])
        fields: Dict[str, Any] = {"sources": some(four), "destinations": some(four), "inbound": some(ZONES),
                                  "status": "Disable" if rng.random() < 0.1 else "Enable"}  # fmt: skip
        fields["services"] = some(["web", "one", "dns2", "ranges", "mix"], 0.5)
        if shape in ("masq", "host", "pool", "none"):
            fields["outbound"] = some(ZONES)
        if shape in ("masq", "host", "pool", "both"):
            fields["source"] = {"masq": "MASQ", "host": "pub1", "pool": "pool", "both": "pub2"}[shape]
        if shape in ("dnat", "pat", "pat2", "both"):
            fields["destination"] = rng.choice(["host", "pub2"])
        if shape == "pat":
            fields["services"], fields["service"] = ["one"], "alt"
        if shape == "pat2":
            fields["services"], fields["service"] = ["dns2"], "both"
        e.nat(f"n{index}", **fields)
    return e


def test_parsed_nat_rules_translate_like_the_firewall_would() -> None:
    for seed in range(60):
        rng = random.Random(seed)
        entities = random_nat_entities(rng)
        config = entities.config()
        model, report = entities.parse()
        assert not any(nat.unsupported for nat in model.nat_rules), (seed, [nat.unsupported for nat in model.nat_rules])
        assert not report.needs_review, (seed, report.to_text())
        for pkt in packets(rng, 300):
            if ":" in pkt.src:
                continue
            assert model_translation(model, pkt) == file_translation(config, pkt), (seed, pkt, entities.xml())
        # And back: the file written from the model translates like the file that was read.
        text = cli.convert(model, "sophos", report)
        second = SophosConfig(text, interfaces=tuple(ZONES))
        for pkt in packets(rng, 200):
            if ":" not in pkt.src:
                assert file_translation(second, pkt) == file_translation(config, pkt), (seed, pkt, entities.xml(), text)


def test_nat_rules_as_they_are_read() -> None:
    e = base_entities().zone("WAN", "WAN").interface("eth0b", "eth0")
    e.add('<Interface transactionid=""><Name>wan</Name><Hardware>Port2</Hardware><NetworkZone>WAN</NetworkZone>'
          "<IPv4Configuration>Enable</IPv4Configuration><IPAddress>198.51.100.1</IPAddress><Netmask>255.255.255.0</Netmask>"
          "</Interface>")  # fmt: skip
    e.host("pub", "198.51.100.10").host("pool", "198.51.100.20-198.51.100.29").host("pub6", "2001:db8:f::1")
    e.service("alt", "tcp/8443").service("both", "tcp/5353", "udp/5353").service("two", "tcp/1", "tcp/2")
    e.rule("out", src_zones=["eth0"], dst_zones=["WAN"], sources=["net0"], services=["web", "dns2"])
    e.rule("earlier", src_zones=["eth0"], services=["web"]).rule("linked-here", src_zones=["eth0"], dst_zones=["WAN"])
    e.rule("six", family=6, sources=["six"]).rule("cut", sources=["net1"], exclusions={"DestinationNetworks": ["net2"]})
    e.nat("dnat", destinations=["pub"], services=["web"], inbound=["wan"], destination="host")
    e.nat("pat", destinations=["pub"], services=["dns2"], inbound=["eth0"], destination="host", service="both")
    e.nat("pat-bad", destinations=["pub"], services=["web"], destination="host", service="two")
    e.nat("pat-alone", services=["web"], service="alt")
    e.nat("out-if", destinations=["pub"], outbound=["eth1"], destination="host")
    e.nat("masq", sources=["net0"], outbound=["wan"], source="MASQ")
    e.nat("masq-zone", outbound=["eth0"], source="MASQ")
    e.nat("static", sources=["host"], source="pub").nat("shared", sources=["net0"], source="pub").nat("pool", sources=["host"], source="pool")
    e.nat("none", sources=["net0"], destinations=["net4"])
    e.nat("lb", destinations=["pub"], destination="pool", extra="<NATMethod>Round-robin</NATMethod>")
    e.nat("one-to-one", destinations=["pool"], destination="pool", extra="<NATMethod>OnetoOne</NATMethod>")
    e.nat("unknown-if", inbound=["Port99"], source="MASQ").nat("part-of-zone", inbound=["eth0b"], source="MASQ")
    e.nat("linked", linked="out", source="MASQ").nat("linked-2", linked="linked-here", source="pub")
    e.nat("linked-six", family=6, linked="six", source="pub6").nat("linked-cut", linked="cut", source="MASQ")
    e.nat("linked-lost", linked="no such rule", source="MASQ")
    e.nat("override", source="MASQ", extra="").add(e.parts.pop().replace(">Disable</Override", ">Enable</Override"))
    e.nat("stray", source="MASQ", extra="<OriginalDestinationPorts>80</OriginalDestinationPorts><Colour>blue</Colour>")
    e.nat("six", family=6, source="MASQ").nat("off", status="Disable", source="MASQ")
    model, report = e.parse()
    nat = {rule.name: rule for rule in model.nat_rules}
    assert list(nat)[:4] == ["dnat", "pat", "pat-bad", "pat-alone"]
    # A rule that translates the destination: the zone of the model is where the published address is reached.
    dnat = nat["dnat"]
    assert (dnat.src_zones, dnat.dst_zones, dnat.destinations, dnat.service) == (["WAN"], ["WAN"], ["pub"], "web")
    assert dnat.destination_translation == DestNat("host") and not codes(report, "nat", "dnat")
    assert nat["pat"].destination_translation == DestNat("host", "5353")  # one port, for TCP and for UDP
    assert nat["pat-bad"].unsupported == ["translated service 'two' that is not one TCP or UDP port"]
    assert nat["pat-alone"].unsupported == ["translated service 'alt' without a translated destination"]
    assert codes(report, "nat", "out-if") == ["NAT_OUTBOUND_INTERFACE"] and nat["out-if"].dst_zones == ["WAN"]
    # Masquerading: the interface is named where the rule is for one interface, with the address it has.
    masq = nat["masq"].source_translation
    assert masq == SourceNat(SnatKind.INTERFACE, interface="wan", interface_address="198.51.100.1") and nat["masq"].dst_zones == ["WAN"]
    assert nat["masq-zone"].source_translation == SourceNat(SnatKind.INTERFACE, interface="eth0") and nat["masq-zone"].dst_zones == ["eth0"]
    # An interface becomes its zone. Where the zone holds more interfaces, the rule is for more than it was.
    assert codes(report, "nat", "masq-zone") == ["NAT_INTERFACE"] and codes(report, "nat", "part-of-zone") == ["NAT_INTERFACE"]
    assert "also holds eth0" in report.item("nat", "part-of-zone").findings[0].message and nat["part-of-zone"].src_zones == ["eth0"]
    assert codes(report, "nat", "unknown-if") == ["NAT_INTERFACE"] and nat["unknown-if"].src_zones == [ANY]
    # One host to one host is address for address; a network behind one address is not.
    assert nat["static"].source_translation == SourceNat(SnatKind.STATIC, ["pub"])
    assert nat["shared"].source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["pub"])
    assert nat["pool"].source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["pool"])
    assert nat["none"].source_translation is None and nat["none"].destination_translation is None and not nat["none"].unsupported
    assert nat["lb"].destination_translation == DestNat("pool", spread=True)
    assert nat["one-to-one"].destination_translation == DestNat("pool", spread=False)
    # A linked rule has no match of its own: that of its firewall rule, as far as a NAT rule can say it.
    linked = nat["linked"]
    assert (linked.src_zones, linked.dst_zones, linked.sources, linked.destinations) == (["eth0"], ["WAN"], ["net0"], [ANY])
    assert model.service_groups[linked.service].members == ["web", "dns2"] and codes(report, "nat", "linked") == ["NAT_LINKED"]
    assert linked.source_translation is not None and linked.source_translation.interface == "wan"
    assert report.item("nat", "linked").status == "exact" and model.rules[0].handling["linked-nat"] == "linked"
    # Above 'linked-here' a rule lets through what it also matches: there the linked rule did not apply.
    assert codes(report, "nat", "linked-2") == ["NAT_LINKED", "NAT_LINKED_ABOVE"] and "out, earlier" in report.item("nat", "linked-2").findings[1].message
    assert nat["linked-six"].sources == ["six"] and nat["linked-six"].destinations == [ANY_V6]
    assert nat["linked-cut"].destinations == [ANY] and report.item("nat", "linked-cut").findings[0].severity == Severity.APPROX
    assert nat["linked-lost"].unsupported == ["linked to firewall rule 'no such rule', which is not in the input or was not read"]
    assert codes(report, "nat", "override") == ["NAT_INTERFACE_OVERRIDE"]
    assert "<OriginalDestinationPorts>" in nat["stray"].unsupported[0] and len(nat["stray"].unsupported) == 1
    assert nat["six"].sources == [ANY_V6] and not nat["off"].enabled
    # Written again, what could not be read is left out and said; nothing of it is guessed.
    text = cli.convert(model, "sophos", report)
    config = SophosConfig(text)
    written = [rule["name"] for rule in config.nat[4] + config.nat[6]]
    for name in ("pat-bad", "pat-alone", "linked-lost", "stray"):
        assert name not in written and report.item("nat", name).skipped, name
    assert {rule["name"]: rule for rule in config.nat[4]}["masq"]["outbound"] == ["wan"]
    assert {rule["name"]: rule for rule in config.nat[4]}["dnat"]["inbound"] == ["wan"]
    assert {rule["name"]: rule for rule in config.nat[4]}["part-of-zone"]["inbound"] == ["eth0", "eth0b"]
    assert {rule["name"]: rule for rule in config.nat[6]}["six"]["source"] == "MASQ"
    assert {rule["name"]: rule for rule in config.nat[4]}["lb"]["method"] == "Round-robin"
    assert {rule["name"]: rule for rule in config.nat[4]}["one-to-one"]["method"] == "OnetoOne"
    assert {rule["name"]: rule for rule in config.nat[4]}["pat"]["service"] == "both"  # the service the policy has


def _nat(name: str, **fields: Any) -> NatRule:
    nat = NatRule(name, origin=name)
    for key, value in fields.items():
        setattr(nat, key, value)
    return nat


def test_nat_rules_as_they_are_written() -> None:
    p = _policy()
    p.zones = {"in": Zone("in", ["ethernet1/1", "ethernet1/2"]), "out": Zone("out", ["ethernet1/3"]), "dmz": Zone("dmz")}
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "198.51.100.10/32")
    p.addresses["pubs"] = Address("pubs", AddressKind.RANGE, "198.51.100.20-198.51.100.29")
    p.addresses["servers"] = Address("servers", AddressKind.RANGE, "10.0.5.20-10.0.5.29")
    p.address_groups["two"] = AddressGroup("two", ["198.51.100.1", "198.51.100.2"])
    p.services["tcp8080"] = Service("tcp8080", [ServiceEntry(Protocol.TCP, "8080")])
    p.nat_rules = [
        _nat("masq", src_zones=["in"], dst_zones=["out"], sources=["net-a"], source_translation=SourceNat(SnatKind.INTERFACE)),
        _nat("masq-ip", dst_zones=["out"], source_translation=SourceNat(SnatKind.INTERFACE, ["198.51.100.1/24"], "ethernet1/3")),
        _nat("pool", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["two"])),
        _nat("dynamic", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC, ["pubs"])),
        _nat("static", src_zones=["dmz"], dst_zones=["out"], sources=["host-a"],
             source_translation=SourceNat(SnatKind.STATIC, ["pub"], bidirectional=True)),
        _nat("static-range", sources=["servers"], source_translation=SourceNat(SnatKind.STATIC, ["pubs"], bidirectional=True)),
        _nat("dnat", src_zones=["out"], dst_zones=["out"], destinations=["pub"], service="tcp8080",
             destination_translation=DestNat("host-a", "443")),
        _nat("dnat-same-port", destinations=["pub"], service="tcp8080", destination_translation=DestNat("host-a", "8080")),
        _nat("dnat-range", destinations=["pubs"], destination_translation=DestNat("servers")),
        _nat("dnat-spread", destinations=["pub"], destination_translation=DestNat("servers", spread=True)),
        _nat("dnat-uneven", destinations=["pub", "net-b"], destination_translation=DestNat("servers")),
        _nat("dnat-name", destinations=["pub"], destination_translation=DestNat("name")),
        _nat("dnat-port-any", destinations=["pub"], destination_translation=DestNat("host-a", "443")),
        _nat("both", destinations=["pub"], source_translation=SourceNat(SnatKind.INTERFACE), destination_translation=DestNat("host-a")),
        _nat("no-nat", sources=["net-a"], destinations=["net-b"]),
        _nat("six", sources=["six"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["2001:db8:f::1"])),
        _nat("mixed", sources=["net-a", "six"], source_translation=SourceNat(SnatKind.INTERFACE)),
        _nat("apart", sources=["net-a"], destinations=["six"], source_translation=SourceNat(SnatKind.INTERFACE)),
        _nat("wide", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["net-b", "span"])),
        _nat("flagged", unsupported=["something"], source_translation=SourceNat(SnatKind.INTERFACE)),
        _nat("off", enabled=False, source_translation=SourceNat(SnatKind.INTERFACE)),
    ]
    options = Options(interface_map={"ethernet1/1": "Port1", "ethernet1/3": "Port2"})
    config, report, text = convert(p, options)
    nat = {rule["name"]: rule for rule in config.nat[4] + config.nat[6]}
    # A NAT rule matches interfaces. Where the interfaces of a zone are not all known, the rule is for any, and said.
    assert nat["masq"]["inbound"] is None and nat["masq"]["outbound"] == ["Port2"] and nat["masq"]["source"] == "MASQ"
    assert codes(report, "nat", "masq") == ["NAT_ZONES"] and "from in only" in report.item("nat", "masq").findings[0].message
    assert report.item("nat", "masq").status == "approximated"
    assert config.span(nat["masq-ip"]["source"]) == "198.51.100.1" and not codes(report, "nat", "masq-ip")
    assert config.span(nat["pool"]["source"]) == "198.51.100.1-198.51.100.2" and nat["pool"]["source"] == "r-198.51.100.1-198.51.100.2"
    assert nat["dynamic"]["source"] == "pubs" and codes(report, "nat", "dynamic") == ["NAT_DYNAMIC_IP"]
    # Static NAT for both directions is two rules on a Sophos Firewall.
    assert nat["static"]["source"] == "pub" and nat["static"]["outbound"] == ["Port2"]
    back = nat["static-in"]
    assert (back["destinations"], back["destination"], back["inbound"], back["source"]) == (["pub"], "host-a", None, "Original")
    assert report.item("nat", "static").emitted_as == ["static", "static-in"]
    assert codes(report, "nat", "static") == ["NAT_ZONES", "NAT_BIDIRECTIONAL"]
    assert report.item("nat", "static").findings[0].severity == Severity.APPROX  # the rule names its source: not every packet
    assert codes(report, "nat", "static-range") == ["NAT_STATIC_RANGE", "NAT_BIDIRECTIONAL"]
    assert nat["static-range-in"]["method"] == "OnetoOne" and nat["static-range-in"]["destination"] == "servers"
    assert [rule["name"] for rule in config.nat[4]].index("static-in") == [rule["name"] for rule in config.nat[4]].index("static") + 1
    # A port translation is a service of its own; the outbound interface of a destination NAT rule is "any".
    assert nat["dnat"]["service"] == "tcp-443" and nat["dnat"]["inbound"] == ["Port2"] and nat["dnat"]["outbound"] is None
    assert config.services["tcp-443"]["details"] == [{"protocol": "tcp", "src": (1, 65535), "dst": (443, 443)}]
    assert nat["dnat-same-port"]["service"] == "Original"
    assert nat["dnat-range"]["method"] == "OnetoOne" and nat["dnat-spread"]["method"] == "Round-robin"
    assert nat["dnat-name"]["destination"] == "name" and nat["dnat-name"]["method"] == ""
    for name, word in (("dnat-uneven", "not an address for address translation"), ("dnat-port-any", "needs a service of the rule"),
                       ("apart", "share no IP version"), ("wide", "is not one IPv4 address or range"),
                       ("flagged", "something")):  # fmt: skip
        assert name not in nat and report.item("nat", name).skipped and word in report.item("nat", name).findings[0].message, name
    assert nat["both"]["source"] == "MASQ" and nat["both"]["destination"] == "host-a" and nat["both"]["outbound"] is None
    assert (nat["no-nat"]["source"], nat["no-nat"]["destination"]) == ("Original", "Original")
    assert nat["six"]["version"] == 6 and config.span(nat["six"]["source"]) == "2001:db8:f::1"
    assert nat["mixed"]["version"] == 4 and nat["mixed"]["sources"] == ["net-a"] and codes(report, "nat", "mixed")[0] == "NAT_IP_VERSION"
    assert not nat["off"]["enabled"]
    # A rule that only its zone kept apart from all other traffic now translates everything: that needs a look.
    p.nat_rules = [_nat("all-out", src_zones=["dmz"], dst_zones=["dmz"], source_translation=SourceNat(SnatKind.INTERFACE))]
    config, report, _ = convert(p, options)
    assert [f.severity for f in report.item("nat", "all-out").findings] == [Severity.REVIEW, Severity.REVIEW]
    assert config.nat[4][0]["inbound"] is None and config.nat[4][0]["outbound"] is None
    # With a zone that the zone map makes of an interface, as for an iptables source.
    p.nat_rules = [_nat("eth", src_zones=["eth1"], dst_zones=["eth0"], source_translation=SourceNat(SnatKind.INTERFACE))]
    options = Options(zone_map={"eth0": "WAN", "eth1": "LAN"}, interface_map={"eth0": "Port2", "eth1": "Port1"})
    config, report, _ = convert(p, options)
    assert (config.nat[4][0]["inbound"], config.nat[4][0]["outbound"]) == (["Port1"], ["Port2"]) and not codes(report, "nat", "eth")


def test_first_match_nat_order_is_reported() -> None:
    p = _policy()
    p.nat_rules = [
        _nat("in", src_zones=["wan"], dst_zones=["wan"], destinations=["host-a"], destination_translation=DestNat("10.0.5.5"),
             combines=True),
        _nat("out", dst_zones=["lan"], source_translation=SourceNat(SnatKind.INTERFACE), combines=True),
    ]
    _, report, _ = convert(p)
    assert "NAT_ORDER" in notes(report) + codes(report, "nat", "in") + codes(report, "nat", "out")


# -- the sample -------------------------------------------------------------------------------


def test_sample_is_read_as_exported() -> None:
    policy, report = load("sophos_sample.xml")
    assert policy.vendor == "sophos" and policy.scope == "API version 2000.1"
    assert (policy.default_intrazone, policy.default_interzone, policy.lookup_after_dnat) == (Action.DENY, Action.DENY, False)
    assert list(policy.zones) == ["LAN", "WAN", "DMZ", "OT", "VPN"] and policy.zones["LAN"].interfaces == ["Port1", "Port3"]
    names = [rule.name for rule in policy.rules]
    assert names[:3] == ["Block countries", "LAN to Internet web", "LAN web again"] and names[-1] == "LAN6 to Internet"
    assert "Web shop" not in names and report.item("rule", "Web shop").skipped
    rules = {rule.name: rule for rule in policy.rules}
    web = rules["LAN to Internet web"]
    assert (web.src_zones, web.dst_zones, web.sources, web.destinations) == (["LAN"], ["WAN"], ["lan-net"], [ANY_V4])
    assert web.services == ["Web Access", "DNS"] and web.log_end and web.action == Action.ALLOW
    assert web.profiles == {"WebFilter": "Default Policy", "IntrusionPrevention": "generalpolicy", "ScanVirus": "Enable"}
    assert rules["LAN to DMZ web not mail"].negate_destination and rules["LAN to DMZ web not mail"].destinations == ["mail-1"]
    assert rules["LAN SSH out"].dst_zones == ["OT"] and rules["LAN SSH out-2"].dst_zones == ["DMZ", "OT"]
    assert rules["LAN SSH out-2"].sources == ["10.10.0.0-10.10.5.9", "10.10.5.21-10.11.255.255"]
    assert rules["Finance to app"].users == ["Finance"] and rules["DNS in office hours"].schedule == "Work hours (5 Day week)"
    assert not rules["Old test rule"].enabled and rules["Reject the rest from LAN"].action == Action.RESET_CLIENT
    assert rules["LAN6 to Internet"].destinations == [ANY_V6]
    assert policy.address_groups["dns-servers"].members == ["10.10.0.53", "10.11.0.53"]
    assert policy.address_groups["update-sites"].members == ["mirror.example.net", "updates.example.com"]
    assert policy.addresses["lan6-net"].value == "2001:db8:10::/48" and "#Port2" not in policy.addresses
    assert policy.services["TIMESTAMP"].entries[0].icmp_type == 13 and policy.services["GRE"].entries[0].ip_protocol == 47
    assert policy.services["syslog-from-high"].entries[0].src_ports == "1024-65535"
    assert not any(rule.unsupported for rule in policy.rules) and not any(nat.unsupported for nat in policy.nat_rules)


def test_sample_nat() -> None:
    policy, report = load("sophos_sample.xml")
    nat = {rule.name: rule for rule in policy.nat_rules}
    assert list(nat) == ["Publish web", "Publish mail", "Mail server out", "No NAT to partner", "NAT of LAN to Internet web",
                         "Default SNAT IPv4"]  # fmt: skip
    assert nat["Publish web"].src_zones == nat["Publish web"].dst_zones == ["WAN"]
    assert nat["Publish mail"].destination_translation == DestNat("mail-1", "25") and nat["Publish mail"].service == "smtp-alt"
    assert nat["Mail server out"].source_translation == SourceNat(SnatKind.STATIC, ["mail-public"])
    assert nat["No NAT to partner"].source_translation is None and nat["No NAT to partner"].destination_translation is None
    linked = nat["NAT of LAN to Internet web"]
    assert (linked.src_zones, linked.dst_zones, linked.sources) == (["LAN"], ["WAN"], ["lan-net"])
    assert linked.source_translation == SourceNat(SnatKind.INTERFACE, interface="Port2", interface_address="198.51.100.1")
    assert report.item("nat", linked.name).status == "exact"


@pytest.mark.parametrize("sample", ["sophos_sample.xml", "panos_sample.xml", "fortios_sample.conf", "checkpoint_sample.json",
                                    "asa_sample.cfg", "iptables_sample.rules"])  # fmt: skip
def test_every_sample_converts_to_a_file_an_import_would_take(sample: str) -> None:
    """Every name defined before it is used, one IP version per rule and object, only documented values."""
    source, _ = load(sample)
    text, report = run(sample, "sophos")
    config = SophosConfig(text)
    enabled = [rule for rule in config.rules[4] + config.rules[6] if rule["enabled"]]
    assert enabled and config.nat[4] and not config.defined_zones
    lost = {item.name for item in report.items.values() if item.kind == "rule" and (item.disabled or item.skipped)}
    assert lost and all(any(f.severity >= Severity.APPROX or f.code == "RULE_TYPE_EMPTY" for f in report.item("rule", name).findings)
                        for name in lost)  # fmt: skip
    assert "SOPHOS_LOAD" in notes(report) and "EXISTING_OBJECTS" in notes(report)


def test_sample_roundtrip_keeps_every_decision() -> None:
    """Sample -> model -> Entities.xml: the file, and the model read from it again, decide and translate alike."""
    source, _ = load("sophos_sample.xml")
    text, report = run("sophos_sample.xml", "sophos")
    again = parse_sophos.parse(text.encode(), Report())
    config = SophosConfig(text, zones=tuple(source.zones), interfaces=("Port1", "Port2", "Port3", "Port4", "Port5"))
    lost = {item.name for item in report.items.values() if item.kind == "rule" and item.disabled}
    assert lost == {"Block countries", "Finance to app", "DNS in office hours"}
    assert [rule.name for rule in again.rules] == [rule.name for rule in source.rules]
    assert [nat.name for nat in again.nat_rules] == [nat.name for nat in source.nat_rules]
    # The file names interfaces and does not say which zone they are in: read on its own, its NAT rules are for any zone.
    assert all(nat.src_zones == nat.dst_zones == [ANY] for nat in again.nat_rules)
    for rule in source.rules:
        rule.enabled = rule.enabled and rule.name not in lost  # as the output has them
    rng = random.Random(11)
    zones = ["LAN", "WAN", "DMZ", "OT", "VPN"]
    behind = {"LAN": ["10.10.5.15", "10.10.200.9", "10.11.7.15", "10.10.7.15", "10.10.0.53", "2001:db8:10::5"],
              "WAN": ["198.51.100.66", "192.0.2.80", "10.99.1.1", "198.51.100.10", "198.51.100.25", "2001:db8:99::1"],
              "DMZ": ["10.20.0.10", "10.20.0.25", "198.51.100.10", "198.51.100.25"], "OT": ["10.30.1.7"], "VPN": ["10.99.1.1"]}  # fmt: skip
    everywhere = sorted({address for listed in behind.values() for address in listed})
    decided = translated = 0
    for _ in range(6000):
        in_zone, out_zone = rng.choice(zones), rng.choice(zones)
        if rng.random() < 0.75:  # mostly where the rules of the sample are
            in_zone, out_zone = rng.choice([("LAN", "WAN"), ("LAN", "DMZ"), ("LAN", "OT"), ("WAN", "DMZ"), ("OT", "LAN"), ("DMZ", "WAN")])
        src = rng.choice(behind[in_zone] if rng.random() < 0.8 else everywhere)
        dst = rng.choice([d for d in (behind[out_zone] if rng.random() < 0.8 else everywhere) if (":" in d) == (":" in src)] or [src])
        pkt = Packet(in_zone, out_zone, src, dst, rng.choice(["tcp", "tcp", "udp", "icmp", "icmp6", "47"]),
                     rng.choice([900, 40000]), rng.choice([22, 25, 53, 80, 443, 502, 514, 2525, 8443, 9005]), rng.choice([0, 8, 13, 128]))  # fmt: skip
        verdicts = (model_allows(source, pkt), model_allows(again, pkt), config.allows(pkt))
        assert len(set(verdicts)) == 1, (pkt, verdicts)
        decided += verdicts[0]
        if ":" in src:
            continue
        # A NAT rule of the file matches interfaces: the packet on an interface of its zones.
        wire = Packet(rng.choice(source.zones[pkt.in_if].interfaces or ["none"]), rng.choice(source.zones[pkt.out_if].interfaces or ["none"]),
                      pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport, pkt.icmp_type)  # fmt: skip
        first = model_translation(source, pkt)
        assert first == file_translation(config, wire), (pkt, wire)
        translated += first[0] != ""
    assert decided > 120 and translated > 1500, (decided, translated)


# -- files, the command line and input that is not what it should be --------------------------


def _tar(members: Dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_an_export_is_an_archive(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    xml = (DATA / "sophos_sample.xml").read_bytes()
    expected = parse_sophos.parse(xml, Report()).to_dict()
    for members in ({"Entities.xml": xml}, {"readme.txt": b"hello", "export/Entities.xml": xml, "cert.pem": b"x" * 2000}):
        data = _tar(members)
        assert cli.detect_format(data) == "sophos" and parse_sophos.parse(data, Report()).to_dict() == expected
    with pytest.raises(ParseError, match="holds no Entities.xml"):
        parse_sophos.parse(_tar({"other.xml": xml}), Report())
    with pytest.raises(ParseError, match="archive could not be read|holds no Entities.xml"):
        parse_sophos.parse(_tar({"Entities.xml": xml})[:700], Report())
    with pytest.raises(ParseError, match="not well-formed"):
        parse_sophos.parse(_tar({"Entities.xml": b"<Configuration>"}), Report())
    # The command line reads an archive and writes one: Entities.xml in a tar is what an import takes.
    source, out, plain = tmp_path / "export.tar", tmp_path / "import.TAR", tmp_path / "import.xml"
    source.write_bytes(_tar({"Entities.xml": xml}))
    assert cli.main(["convert", str(source), "--to", "sophos", "-o", str(out), "-q"]) == 0
    assert cli.main(["convert", str(source), "--to", "sophos", "-o", str(plain), "-q"]) == 0
    with tarfile.open(out) as archive:
        assert archive.getnames() == ["Entities.xml"]
        member = archive.extractfile("Entities.xml")
        assert member is not None and member.read() == plain.read_bytes()
    assert plain.read_text(encoding="utf-8").startswith('<?xml version="1.0" encoding="UTF-8"?>\n<Configuration APIVersion="2000.1"')
    assert emit_sophos.archive(plain.read_text(encoding="utf-8")) == out.read_bytes()
    assert cli.main(["inspect", str(out)]) == 0
    shown = capsys.readouterr().out
    assert "format:          sophos" in shown and "security rules:  16 (4 disabled)" in shown and "NAT rules:       6" in shown
    # Another target does not get an archive, whatever the name of the output.
    assert cli.main(["convert", str(source), "--to", "panos", "-o", str(out), "-q"]) == 0 and out.read_bytes().startswith(b"set ")


def test_format_is_detected_and_api_answers_are_read() -> None:
    e = base_entities().rule("r", sources=["net0"]).nat("n", source="MASQ")
    xml = e.xml()
    assert cli.detect_format(xml.encode()) == "sophos"
    assert cli.detect_format(b"\xef\xbb\xbf<?xml version='1.0'?>\n<!-- exported -->\n<Configuration APIVersion='1905.1'/>") == "sophos"
    assert cli.detect_format(b'<Response APIVersion="2000.1"><Login><status>ok</status></Login></Response>') == "sophos"
    assert cli.detect_format(b"<config version='10.1.0'><devices/></config>") == "panos"
    assert cli.detect_format(b"<?xml version='1.0'?><!-- unfinished") == "panos"
    inner = "\n".join(e.parts)
    # What the XML API answers to a Get, and what is sent to it with a Set, hold the same entities.
    for wrapped in (f'<Response APIVersion="2000.1" IPS_CAT_VER="1"><Login><status>Authentication Successful</status></Login>'
                    f"{inner}</Response>",
                    f'<Request><Login><Username>admin</Username><Password>x</Password></Login><Set operation="add">{inner}'
                    "</Set></Request>",
                    f"<Set operation=\"add\">{inner}</Set>", f"<Export><Configuration APIVersion=\"1800.1\">{inner}</Configuration></Export>"):  # fmt: skip
        policy = parse_sophos.parse(wrapped.encode(), Report())
        assert [rule.name for rule in policy.rules] == ["r"] and [nat.name for nat in policy.nat_rules] == ["n"], wrapped[:40]
    assert parse_sophos.parse(xml.encode(), Report()).scope == "API version 2000.1"
    # Converted for another Sophos Firewall, the file says the version it was read from; from another platform, 18.0.
    assert 'APIVersion="2000.1"' in cli.convert(e.parse()[0], "sophos", Report())
    assert 'APIVersion="1800.1"' in cli.convert(_policy(Rule("r")), "sophos", Report())
    odd = Entities(version='9"><x y="1').rule("r")
    assert 'APIVersion="1800.1"' in cli.convert(parse_sophos.parse(odd.xml().replace('9"><x y="1', "9&quot;&gt;&lt;x").encode(), Report()), "sophos", Report())


def test_malformed_input_is_a_clean_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for data, message in ((b"<Configuration", "not well-formed"), (b"<Configuration><IPHost></Configuration>", "not well-formed"),
                          (b"<Other><Thing/></Other>", "no <Configuration> element"), (b"", "not well-formed"),
                          (b'<?xml version="1.0" encoding="no-such-encoding"?><Configuration/>', "not well-formed"),
                          (b'<!DOCTYPE c [<!ENTITY a "aaaa">]><Configuration>&a;</Configuration>', "DOCTYPE"),
                          (b"\x00\x01\x02 garbage", "not well-formed")):  # fmt: skip
        with pytest.raises(ParseError, match=message):
            parse_sophos.parse(data, Report())
    report = Report()
    assert not parse_sophos.parse(b"<Configuration/>", report).rules and notes(report) == ["NO_RULES"]
    # Entities that are not what they should be: nothing crashes, nothing is guessed.
    junk = ('<Configuration APIVersion="x"><FirewallRule/><FirewallRule><Name/><NetworkPolicy><Action/><SourceZones/>'
            "<Exclusions><SourceNetworks/></Exclusions></NetworkPolicy></FirewallRule><NATRule/><NATRule><Name>n</Name>"
            "<TranslatedSource><x/></TranslatedSource><OriginalServices><Service/></OriginalServices></NATRule><IPHost/>"
            "<IPHost><Name>h</Name></IPHost><IPHostGroup><Name>g</Name></IPHostGroup><Services><Name>s</Name></Services>"
            "<ServiceGroup><Name>sg</Name><ServiceList><Service>s</Service><Other/></ServiceList></ServiceGroup>"
            "<Zone/><Zone><Name>z</Name></Zone><Interface><Name>i</Name><NetworkZone>z</NetworkZone></Interface>"
            "<FQDNHost><Name>f</Name></FQDNHost><FQDNHostGroup/>text<Unknown><Name>u</Name><Zone>z</Zone></Unknown></Configuration>")  # fmt: skip
    report = Report()
    policy = parse_sophos.parse(junk.encode(), report)
    assert [rule.name for rule in policy.rules] == ["unnamed", "unnamed-2"] and all(rule.unsupported for rule in policy.rules)
    assert all(rule.action == Action.DENY for rule in policy.rules)
    assert [nat.name for nat in policy.nat_rules] == ["unnamed", "n"] and policy.nat_rules[1].unsupported
    assert policy.addresses["h"].kind == AddressKind.UNSUPPORTED and policy.services["s"].unsupported
    text = cli.convert(policy, "sophos", report)
    config = SophosConfig(text)
    assert all(not rule["enabled"] for rule in config.rules[4]) and len(config.nat[4]) == 1  # the rule that says nothing
    for target in ("panos", "fortios", "checkpoint", "asa", "iptables"):
        cli.convert(parse_sophos.parse(junk.encode(), Report()), target, Report())
    bad = tmp_path / "bad.xml"
    bad.write_bytes(b"<Configuration><broken")
    assert cli.main(["inspect", str(bad)]) == 1 and "not well-formed XML" in capsys.readouterr().err
    assert cli.main(["convert", str(DATA / "panos_sample.xml"), "--from", "sophos", "--to", "panos"]) == 1
    assert "no <Configuration> element" in capsys.readouterr().err


def test_deeply_nested_and_repeated_objects_are_no_trouble() -> None:
    e = base_entities()
    e.add('<IPHostGroup transactionid=""><Name>self</Name><IPFamily>IPv4</IPFamily><HostList><Host>self</Host><Host>net0</Host>'
          "</HostList></IPHostGroup>")  # fmt: skip
    e.service_group("loop", ["loop", "web"])
    e.rule("r", sources=["self"], services=["loop"])
    for index in range(300):
        e.rule(f"bulk{index}", sources=["net0"], exclusions={"SourceNetworks": ["host"], "DestinationNetworks": ["net1"]})
    model, report = e.parse()
    assert len(model.rules) == 601
    text = cli.convert(model, "sophos", report)
    config = SophosConfig(text)
    assert not config.rules[4][0]["enabled"] and report.item("rule", "r").disabled  # a group that holds itself is no group
    assert len(config.rules[4]) == 601


def test_cli_options(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["convert", str(DATA / "panos_sample.xml"), "--to", "sophos", "-q", "--zone-map", "trust=LAN", "--zone-map", "untrust=WAN",
            "--zone-map", "dmz=DMZ", "--interface-map", "ethernet1/1=Port2", "--interface-map", "ethernet1/2=Port1",
            "--interface-map", "ethernet1/3=Port3", "--target-prefix", "pa-"]  # fmt: skip
    assert cli.main(args) == 0
    captured = capsys.readouterr()
    config = SophosConfig(captured.out)
    assert captured.err == "" and "pa-lan-net" in config.hosts and all(name.startswith("pa-") for name in config.services)
    zones = {zone for rule in config.rules[4] for zone in (rule["src_zones"] or []) + (rule["dst_zones"] or [])}
    assert zones == {"LAN", "WAN", "DMZ", "ot"}
    # With the interfaces of the zones named, a NAT rule is for those interfaces.
    nat = {rule["name"]: rule for rule in config.nat[4]}
    assert nat["Outbound-PAT"]["outbound"] == ["Port2"] and nat["Outbound-PAT"]["inbound"] == ["Port1"]
    assert nat["Inbound-Web-DNAT"]["inbound"] == ["Port2"] and nat["Inbound-Web-DNAT"]["outbound"] is None
    assert cli.main(["convert", str(DATA / "sophos_sample.xml"), "--to", "sophos", "--zone-map", "LAN=bad\nzone"]) == 1
    assert "control characters" in capsys.readouterr().err


def test_audit_reads_and_writes_a_sophos_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sample = str(DATA / "sophos_sample.xml")
    assert cli.main(["audit", sample]) == 0
    shown = capsys.readouterr().out
    assert "REDUNDANT_RULE: rule 'LAN web again' never matches" in shown
    assert "NO_LOG: rule 'OT to SCADA'" in shown and "NO_PROFILE: rule 'OT to SCADA'" in shown  # a Sophos rule says both
    assert "NO_PROFILE: rule 'LAN to Internet web'" not in shown
    # The audit disables what it proved to decide nothing, on the model the emitter writes from as well.
    out, report = tmp_path / "out.xml", tmp_path / "report.txt"
    args = ["convert", sample, "--to", "sophos", "-o", str(out), "--report", str(report), "-q", "--audit-action", "REDUNDANT_RULE=disable"]
    assert cli.main(args) == 0
    config = SophosConfig(out.read_text(encoding="utf-8"))
    rules = {rule["name"]: rule for rule in config.rules[4]}
    assert not rules["LAN web again"]["enabled"] and rules["LAN to Internet web"]["enabled"]
    assert "AUDIT_DISABLED: disabled by the audit (REDUNDANT_RULE)" in report.read_text(encoding="utf-8")
    kept: List[Policy] = []
    policy, first = load("sophos_sample.xml")
    cli.convert(policy, "sophos", first, Options(written=kept))
    assert len(kept) == 1 and kept[0] is not policy and [rule.name for rule in kept[0].rules] == [rule.name for rule in policy.rules]
    assert cli.main(["matrix", sample, "--summary"]) == 0
    shown = capsys.readouterr().out
    assert "WAN  -                 -                 tcp/443 tcp/2525" in shown and "'Web shop'" in shown


# -- found in review (round 14) ---------------------------------------------------------------


def test_zone_of_a_rule_that_translates_the_destination() -> None:
    """A Sophos NAT rule does not say where its original destination lies. Nothing is made up about it."""
    e = base_entities().zone("WAN", "WAN").zone("LAN").host("pub", "198.51.100.10").host("far", "203.0.113.5").host("resolver", "10.0.4.53")
    e.add('<Interface transactionid=""><Name>Port2</Name><NetworkZone>WAN</NetworkZone><IPAddress>198.51.100.1</IPAddress>'
          "<Netmask>255.255.255.0</Netmask></Interface>")  # fmt: skip
    e.add('<Interface transactionid=""><Name>Port1</Name><NetworkZone>LAN</NetworkZone><IPAddress>10.0.0.1</IPAddress>'
          "<Netmask>255.255.255.0</Netmask></Interface>")  # fmt: skip
    e.nat("published", destinations=["pub"], inbound=["Port2"], destination="host")
    e.nat("hairpin", destinations=["pub"], inbound=["Port1"], destination="host")
    e.nat("elsewhere", destinations=["far"], inbound=["Port2"], destination="host")
    e.nat("force-dns", services=["dns2"], inbound=["Port1"], destination="resolver")
    model, report = e.parse()
    nat = {rule.name: rule for rule in model.nat_rules}
    # The address lies in the network of an interface: that zone, whichever interface the traffic arrives on.
    assert nat["published"].dst_zones == ["WAN"] and nat["hairpin"].dst_zones == ["WAN"] and nat["hairpin"].src_zones == ["LAN"]
    assert nat["elsewhere"].dst_zones == [ANY] and nat["force-dns"].dst_zones == [ANY] and nat["force-dns"].src_zones == ["LAN"]
    # PAN-OS needs the zone: it is asked for, not guessed. ("From LAN to LAN" would redirect nothing that leaves.)
    text = cli.convert(model, "panos", report)
    assert report.item("nat", "force-dns").skipped and "--target-nat-zone" in report.item("nat", "force-dns").findings[-1].message
    assert 'nat rules force-dns' not in text and "nat rules published to WAN" in text
    # The other way round: a rule that was for traffic towards one zone is for all of it on a Sophos Firewall.
    p = _policy()
    p.nat_rules = [
        _nat("redirect", src_zones=["trust"], dst_zones=["untrust"], service="dns-both", destination_translation=DestNat("host-a")),
        _nat("wide", src_zones=["trust"], dst_zones=["untrust"], destinations=["10.0.0.0/8"], destination_translation=DestNat("host-a")),
        _nat("published", src_zones=["untrust"], dst_zones=["untrust"], destinations=["span"], destination_translation=DestNat("host-a")),
    ]
    _, report, _ = convert(p, Options(interface_map={"trust": "Port1", "untrust": "Port2"}))
    assert [f.severity for f in report.item("nat", "redirect").findings if f.code == "NAT_DESTINATION_ZONE"] == [Severity.REVIEW]
    assert [f.severity for f in report.item("nat", "wide").findings if f.code == "NAT_DESTINATION_ZONE"] == [Severity.APPROX]
    assert "NAT_DESTINATION_ZONE" not in codes(report, "nat", "published")


def test_words_of_the_format_are_no_names_for_zones_or_interfaces(capsys: pytest.CaptureFixture[str]) -> None:
    from fwshift.errors import FwshiftError

    for zone in ("Any", "ANY", "None"):
        with pytest.raises(FwshiftError, match="word of the Sophos format"):
            cli.convert(_policy(Rule("r", src_zones=[zone])), "sophos", Report())
        with pytest.raises(FwshiftError, match="--zone-map"):
            cli.convert(_policy(Rule("r", src_zones=["trust"])), "sophos", Report(), Options(zone_map={"trust": zone}))
        with pytest.raises(FwshiftError, match="--interface-map"):
            cli.convert(_policy(Rule("r")), "sophos", Report(), Options(interface_map={"ethernet1/1": zone}))
        p = _policy()
        p.nat_rules = [_nat("n", src_zones=[zone], source_translation=SourceNat(SnatKind.INTERFACE))]
        with pytest.raises(FwshiftError, match="word of the Sophos format"):
            cli.convert(p, "sophos", Report())
    # Renamed, the rule is a rule for that zone.
    config, _, _ = convert(_policy(Rule("r", src_zones=["Any"])), Options(zone_map={"Any": "Guests"}))
    assert config.rules[4][0]["src_zones"] == ["Guests"]
    assert cli.main(["convert", str(DATA / "panos_sample.xml"), "--to", "sophos", "--zone-map", "trust=Any"]) == 1
    assert "cannot be the name of a zone" in capsys.readouterr().err


def test_linked_nat_rule_of_a_rule_that_lets_nothing_through() -> None:
    e = base_entities()
    e.rule("off", status="Disable", src_zones=["eth0"]).rule("drop", action="Drop", src_zones=["eth0"]).rule("on", src_zones=["eth0"])
    e.rule("twice", sources=["net0"]).rule("twice", sources=["net1"])
    e.nat("n-off", linked="off", source="MASQ").nat("n-drop", linked="drop", source="MASQ").nat("n-on", linked="on", source="MASQ")
    e.nat("n-twice", linked="twice", source="MASQ")
    model, report = e.parse()
    nat = {rule.name: rule for rule in model.nat_rules}
    assert not nat["n-off"].enabled and not nat["n-drop"].enabled and nat["n-on"].enabled
    assert "NAT_LINKED_INACTIVE" in codes(report, "nat", "n-off") and "NAT_LINKED_INACTIVE" in codes(report, "nat", "n-drop")
    assert "NAT_LINKED_INACTIVE" not in codes(report, "nat", "n-on")
    assert [rule.name for rule in model.rules][-2:] == ["twice", "twice-2"]
    assert nat["n-twice"].unsupported == ["linked to firewall rule 'twice', a name that several rules of the input have"]
    config = SophosConfig(cli.convert(model, "sophos", report))
    assert {rule["name"]: rule["enabled"] for rule in config.nat[4]} == {"n-off": False, "n-drop": False, "n-on": True}


def test_port_zero_is_no_port_of_a_sophos_service() -> None:
    p = _policy(Rule("r", services=["low", "all", "from-low", "zero"]), Rule("ok", services=["low"]))
    p.services.update({
        "low": Service("low", [ServiceEntry(Protocol.TCP, "0-1023,8080")]),
        "all": Service("all", [ServiceEntry(Protocol.UDP, "0-65535")]),
        "from-low": Service("from-low", [ServiceEntry(Protocol.TCP, "80", "0-1023")]),
        "zero": Service("zero", [ServiceEntry(Protocol.TCP, "0")]),
    })
    config, report, _ = convert(p)
    services = config.services
    assert services["low"]["details"] == [{"protocol": "tcp", "src": (1, 65535), "dst": (1, 1023)},
                                          {"protocol": "tcp", "src": (1, 65535), "dst": (8080, 8080)}]  # fmt: skip
    assert services["all"]["details"] == [{"protocol": "udp", "src": (1, 65535), "dst": (1, 65535)}]
    assert services["from-low"]["details"] == [{"protocol": "tcp", "src": (1, 1023), "dst": (80, 80)}]
    for name in ("low", "all", "from-low"):
        assert codes(report, "service", name) == ["PORT_ZERO"] and report.item("service", name).status == "exact"
    assert codes(report, "service", "zero") == ["UNSUPPORTED_SERVICE"] and report.item("rule", "r").disabled
    assert not report.item("rule", "ok").disabled


def test_security_heartbeat_is_a_condition() -> None:
    e = base_entities()
    e.rule("healthy", extra="<SourceSecurityHeartbeat>Enable</SourceSecurityHeartbeat><MinimumSourceHBPermitted>Green"
           "</MinimumSourceHBPermitted>")  # fmt: skip
    e.rule("dest", extra="<MinimumDestinationHBPermitted>Yellow</MinimumDestinationHBPermitted>")
    e.rule("unrestricted", extra="<SourceSecurityHeartbeat>Disable</SourceSecurityHeartbeat><MinimumSourceHBPermitted>"
           "No Restriction</MinimumSourceHBPermitted><DestSecurityHeartbeat>Disable</DestSecurityHeartbeat>")  # fmt: skip
    model, report = e.parse()
    rules = {rule.name: rule for rule in model.rules}
    assert "Security Heartbeat condition (SourceSecurityHeartbeat=Enable, MinimumSourceHBPermitted=Green)" in rules["healthy"].unsupported[0]
    assert rules["dest"].unsupported and not rules["unrestricted"].unsupported and not rules["unrestricted"].profiles
    for target in ("sophos", "panos", "fortios"):
        again = Report()
        cli.convert(e.parse()[0], target, again)
        assert again.item("rule", "healthy").disabled and not again.item("rule", "unrestricted").disabled, target


def test_what_a_rule_says_twice_or_oddly_is_not_guessed() -> None:
    e = base_entities()
    for status in ("Disabled", "Off", "0", "enable ", "DISABLE"):
        e.rule(f"status-{status.strip()}", status=status)
    e.rule("no-status", extra="").add(e.parts.pop().replace("<Status>Enable</Status>", ""))
    e.rule("two-lists", src_zones=["eth0"], extra="<SourceZones><Zone>eth1</Zone></SourceZones>")
    e.rule("two-actions", action="Drop", extra="<Action>Accept</Action>")
    e.rule("two-statuses", head="<Status>Disable</Status>")
    e.rule("mixed", src_zones=["eth0"]).add(e.parts.pop().replace("<SourceZones><Zone>eth0</Zone>", "<SourceZones>eth1<Zone>eth0</Zone>"))
    e.rule("nested", sources=["net0"]).add(e.parts.pop().replace("<Network>net0</Network>", "<Network>net0<Network>net1</Network></Network>"))
    e.rule("both-policies", head="<UserPolicy><Action>Accept</Action></UserPolicy>")
    e.rule("middle", position="Middle").rule("nowhere").add(e.parts.pop().replace("<Position>After</Position>", ""))
    model, report = e.parse()
    rules = {rule.name: rule for rule in model.rules}
    for name in ("status-Disabled", "status-Off", "status-0"):
        assert not rules[name].enabled and "which is neither Enable nor Disable" in rules[name].unsupported[0], name
    assert rules["status-enable"].enabled and not rules["status-DISABLE"].enabled and not rules["status-DISABLE"].unsupported
    assert rules["no-status"].enabled and not rules["no-status"].unsupported
    assert rules["two-lists"].unsupported == ["<SourceZones> given 2 times"]
    assert rules["two-actions"].unsupported == ["<Action> given 2 times"]
    assert rules["two-statuses"].unsupported == ["<Status> given 2 times"]
    assert rules["mixed"].unsupported == ["<SourceZones> holds text next to its <Zone> elements"]
    assert rules["nested"].unsupported == ["<SourceNetworks> holds something else than <Network>"]
    assert rules["both-policies"].unsupported == ["a <NetworkPolicy> and a <UserPolicy> in one rule"]
    assert notes(report) == ["RULE_ORDER"] and "middle, nowhere" in report.notes[0].message
    # The same for a NAT rule.
    e = base_entities().nat("odd", status="Maybe", source="MASQ").nat("twice", source="MASQ", extra="<TranslatedSource>Original</TranslatedSource>")
    nat = {rule.name: rule for rule in e.parse()[0].nat_rules}
    assert not nat["odd"].enabled and nat["odd"].unsupported and nat["twice"].unsupported == ["<TranslatedSource> given 2 times"]


def test_severity_follows_what_is_lost() -> None:
    e = base_entities()
    e.rule("allow-but", exclusions={"SourceZones": ["eth0"]}).rule("block-but", action="Drop", exclusions={"SourceZones": ["eth0"]})
    e.nat("only-if", outbound=["Port9"], source="MASQ").nat("named", sources=["net0"], destinations=["net1"], outbound=["Port9"], source="MASQ")
    e.nat("in-only", inbound=["Port9"], source="MASQ").nat("in-src", sources=["net0"], inbound=["Port9"], source="MASQ")
    e.rule("shaped", extra="<TrafficShappingPolicy>Gold</TrafficShappingPolicy><DSCPMarking>46</DSCPMarking><PrimaryGateway>ISP2</PrimaryGateway>")
    model, report = e.parse()
    # "Any zone except" on a blocking rule: a zone the file does not hold is no longer blocked.
    assert report.item("rule", "allow-but").findings[0].severity == Severity.APPROX
    assert report.item("rule", "block-but").findings[0].severity == Severity.REVIEW
    assert "does not block" in report.item("rule", "block-but").findings[0].message
    # An interface that was all that limited a NAT rule.
    severities = {name: report.item("nat", name).findings[0].severity for name in ("only-if", "named", "in-only", "in-src")}
    assert severities == {"only-if": Severity.REVIEW, "named": Severity.APPROX, "in-only": Severity.REVIEW, "in-src": Severity.APPROX}
    assert codes(report, "rule", "shaped") == ["HANDLING_NOT_CONVERTED"] and "PrimaryGateway=ISP2" in report.item("rule", "shaped").findings[0].message


def test_hosts_and_services_that_only_look_right() -> None:
    e = Entities()
    e.add('<IPHost transactionid=""><Name>member</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.1.1.1</IPAddress>'
          "<HostGroupList><HostGroup>grp</HostGroup><HostGroup>no-such-group</HostGroup></HostGroupList></IPHost>")  # fmt: skip
    e.add('<IPHostGroup transactionid=""><Name>grp</Name><IPFamily>IPv4</IPFamily></IPHostGroup>')
    e.add('<IPHost transactionid=""><Name>everything</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType>'
          "<IPAddress>10.0.0.0</IPAddress><Subnet>0.0.0.0</Subnet></IPHost>")  # fmt: skip
    e.add('<IPHost transactionid=""><Name>four-in-six</Name><IPFamily>IPv6</IPFamily><HostType>IP</HostType>'
          "<IPAddress>10.1.1.2</IPAddress></IPHost>")  # fmt: skip
    e.add('<IPHost transactionid=""><Name>list-six</Name><IPFamily>IPv4</IPFamily><HostType>IPList</HostType>'
          "<ListOfIPAddresses>10.1.1.3,2001:db8::1</ListOfIPAddresses></IPHost>")  # fmt: skip
    e.fqdn("star", "*").fqdn("inner", "www.*.example.com").fqdn("plain", "www.example.com")
    e.add('<Services transactionid=""><Name>wrong-names</Name><Type>ICMP</Type><ServiceDetails><ServiceDetail>'
          "<ICMPv6Type>128</ICMPv6Type><ICMPv6Code>-1</ICMPv6Code></ServiceDetail></ServiceDetails></Services>")  # fmt: skip
    e.add('<Services transactionid=""><Name>stray</Name><Type>TCPorUDP</Type><ServiceDetails><ServiceDetail><SourcePort>1:65535'
          "</SourcePort><DestinationPort>80</DestinationPort><Protocol>TCP</Protocol><DestinationAddress>10.0.0.1"
          "</DestinationAddress></ServiceDetail></ServiceDetails></Services>")  # fmt: skip
    e.service("echo-any", "icmp/8").service("six-zero", "icmp6/0")
    model, report = e.parse()
    assert model.address_groups["grp"].members == ["member"]  # a host says which groups hold it
    for name in ("everything", "four-in-six", "list-six"):
        assert model.addresses[name].kind == AddressKind.UNSUPPORTED and codes(report, "address", name) == ["INVALID_ADDRESS"], name
    assert model.addresses["star"].kind == model.addresses["inner"].kind == AddressKind.UNSUPPORTED
    assert model.addresses["plain"].kind == AddressKind.FQDN
    assert "<ICMPv6" in model.services["wrong-names"].unsupported and "DestinationAddress" in model.services["stray"].unsupported
    assert model.services["six-zero"].entries[0].icmp_type == 0 and not model.services["six-zero"].unsupported
    # An ICMP code of every type is nothing a Sophos service says.
    p = _policy(Rule("r", services=["code"]), Rule("s", services=["six-zero"]))
    p.services["code"] = Service("code", [ServiceEntry(Protocol.ICMP, icmp_code=3)])
    p.services["six-zero"] = Service("six-zero", [ServiceEntry(Protocol.ICMP6, icmp_type=0)])
    config, report, _ = convert(p)
    assert codes(report, "service", "code") == ["UNSUPPORTED_SERVICE"] and report.item("rule", "r").disabled
    assert config.services["six-zero"]["details"] == [{"icmp": "icmp6", "type": 0, "code": -1}]


def test_api_answers_namespaces_and_archives_that_are_not_what_they_seem() -> None:
    inner = "\n".join(base_entities().rule("r", sources=["net0"]).parts)
    # An entity of a kind the firewall has none of is answered with a status, not with a rule.
    empty = '<FirewallRule transactionid=""><Status>No. of records Zero.</Status></FirewallRule>'
    policy = parse_sophos.parse(f'<Response APIVersion="2000.1"><Login><status>Authentication Successful</status></Login>{inner}'
                                f"{empty}<NATRule><Status>No. of records Zero.</Status></NATRule></Response>".encode(), Report())  # fmt: skip
    assert [rule.name for rule in policy.rules] == ["r"] and not policy.nat_rules
    with pytest.raises(ParseError, match="login failed"):
        parse_sophos.parse(b'<Response APIVersion="2000.1"><Login><status>Authentication Failure</status></Login></Response>', Report())
    for doubled in (f"<Export><Configuration>{inner}</Configuration><Configuration>{inner}</Configuration></Export>",
                    f"<Configuration>{inner}<Configuration>{inner}</Configuration></Configuration>"):  # fmt: skip
        with pytest.raises(ParseError, match="several <Configuration> elements"):
            parse_sophos.parse(doubled.encode(), Report())
    # A namespace does not hide an entity (a blocking rule least of all).
    spaced = base_entities().rule("r", action="Drop").xml().replace("<FirewallRule ", '<s:FirewallRule xmlns:s="urn:x" ')
    spaced = spaced.replace("</FirewallRule>", "</s:FirewallRule>").replace('<Configuration ', '<Configuration xmlns="urn:y" ')
    policy = parse_sophos.parse(spaced.encode(), Report())
    assert [(rule.name, rule.action) for rule in policy.rules] == [("r", Action.DROP)] and "net0" in policy.addresses
    # A document type is refused whatever the encoding (the check on bytes alone missed UTF-16).
    evil = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE c [<!ENTITY a "EXPANDED">]><Configuration><x>&a;</x></Configuration>'
    for parse in (parse_sophos.parse, lambda data, report: cli.load(data, "panos", report)):
        with pytest.raises(ParseError, match="DOCTYPE"):
            parse(evil.encode("utf-16"), Report())
    assert parse_sophos.parse(base_entities().rule("r").xml().replace("UTF-8", "UTF-16").encode("utf-16"), Report()).rules
    xml = base_entities().rule("r").xml().encode()
    with pytest.raises(ParseError, match="more than one Entities.xml"):
        parse_sophos.parse(_tar({"a/Entities.xml": xml, "b/Entities.xml": xml}), Report())
    import gzip

    with pytest.raises(ParseError, match="compressed"):
        parse_sophos.parse(gzip.compress(_tar({"Entities.xml": xml})), Report())
    from fwshift.errors import FwshiftError

    with pytest.raises(FwshiftError, match="compressed"):
        cli.detect_format(gzip.compress(_tar({"Entities.xml": xml})))  # whatever the format: said, not guessed at
    assert cli.detect_format(xml.decode().replace("UTF-8", "UTF-16").encode("utf-16")) == "sophos"
    assert cli.detect_format("<config version='10.1.0'/>".encode("utf-16")) == "panos"


def test_zone_named_local_and_placeholder_names() -> None:
    e = base_entities().zone("local", "LAN").zone("LOCAL", "LOCAL").zone("Core", "LOCAL").interface("lo", "Core")
    e.rule("to-local", dst_zones=["local"]).rule("to-device", dst_zones=["LOCAL"]).rule("to-core", dst_zones=["Core"])
    e.nat("via-core", inbound=["lo"], source="MASQ")
    model, report = e.parse()
    rules = {rule.name: rule for rule in model.rules}
    assert "local" in model.zones and rules["to-local"].dst_zones == ["local"] and not rules["to-local"].unsupported
    assert rules["to-device"].unsupported and rules["to-core"].unsupported and "Core" not in model.zones
    assert model.nat_rules[0].src_zones == [ANY] and codes(report, "nat", "via-core") == ["NAT_INTERFACE"]
    # The host name of a placeholder is one nothing else has.
    p = _policy(Rule("r", sources=["gone", "mine"]))
    p.addresses["gone"] = Address("gone", AddressKind.UNSUPPORTED, "", raw="gone")
    p.addresses["mine"] = Address("mine", AddressKind.FQDN, "placeholder1.fwshift.invalid")
    config, report, _ = convert(p)
    assert config.hosts["gone"]["fqdn"] == "placeholder2.fwshift.invalid" and config.hosts["mine"]["fqdn"] == "placeholder1.fwshift.invalid"
    assert "SOPHOS_LOAD" in [note.code for note in report.notes if note.severity == Severity.REVIEW]


def test_translation_is_to_an_address_or_a_range_and_methods_are_said() -> None:
    p = _policy()
    p.addresses["pool-net"] = Address("pool-net", AddressKind.NETWORK, "192.0.2.8/30")
    p.addresses["servers"] = Address("servers", AddressKind.NETWORK, "10.0.5.0/30")
    p.nat_rules = [
        _nat("to-net", sources=["net-a"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pool-net"])),
        _nat("static-literal", sources=["10.0.6.0/30"], source_translation=SourceNat(SnatKind.STATIC, ["192.0.2.16/30"])),
        _nat("dnat-net", destinations=["pool-net"], destination_translation=DestNat("servers")),
    ]
    config, report, text = convert(p)
    nat = {rule["name"]: rule for rule in config.nat[4]}
    # What a rule translates to is written as a range, also where the policy has it as a network.
    assert nat["to-net"]["source"] == "r-192.0.2.8_30" and config.hosts["r-192.0.2.8_30"]["type"] == "IPRange"
    assert config.span(nat["to-net"]["source"]) == "192.0.2.8-192.0.2.11" and config.hosts["pool-net"]["type"] == "Network"
    assert nat["dnat-net"]["destinations"] == ["pool-net"] and config.hosts[nat["dnat-net"]["destination"]]["type"] == "IPRange"
    assert nat["dnat-net"]["method"] == "OnetoOne"
    assert "NAT_STATIC_RANGE" in codes(report, "nat", "static-literal")  # also without an object for the addresses
    # Read: a method the model has no word for, and a health check.
    e = base_entities().host("pub", "198.51.100.10").host("farm", "10.0.4.10-10.0.4.13")
    e.nat("sticky", destinations=["pub"], destination="farm", extra="<NATMethod>StickyIP</NATMethod>")
    e.nat("alive", destinations=["pub"], destination="farm", extra="<NATMethod>First_alive</NATMethod><HealthCheck>Enable</HealthCheck>")
    e.nat("round", destinations=["pub"], destination="farm", extra="<NATMethod>Round-robin</NATMethod><HealthCheck>Disable</HealthCheck>")
    e.nat("one", destinations=["pub"], destination="host", extra="<NATMethod>StickyIP</NATMethod>")
    _, report = e.parse()
    assert codes(report, "nat", "sticky") == ["NAT_LOAD_BALANCING"] and "with a health check" in report.item("nat", "alive").findings[0].message
    assert not codes(report, "nat", "round") and not codes(report, "nat", "one")
    assert report.item("nat", "sticky").status == "approximated"


def test_large_exports_are_read_in_reasonable_time() -> None:
    import time

    e = base_entities()
    for index in range(6000):
        e.rule(f"r{index}", sources=["net0"], services=["web"])
    names = []
    for index in range(6000):
        names.append(f"h{index}")
        e.host(names[-1], f"10.{100 + index // 65536}.{(index // 256) % 256}.{index % 256}")
    e.host("x", "10.100.0.5").rule("big", sources=names, exclusions={"SourceNetworks": ["x"]})
    started = time.monotonic()
    model, _ = e.parse()
    assert len(model.rules) == 6001 and model.rules[-1].sources == ["10.100.0.0-10.100.0.4", "10.100.0.6-10.100.23.111"]
    assert time.monotonic() - started < 20  # it takes about a second; the search for each rule's place was quadratic
