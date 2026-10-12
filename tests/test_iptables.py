# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""iptables: parser, emitter, and packet-level equivalence between a ruleset and the model."""

from __future__ import annotations

import copy
import functools
import random
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

import pytest
from helpers import FortiConfig, PanConfig, load, run

from fwshift import cli, transform
from fwshift.emitters import iptables as emit_iptables
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, ANY_V4, Action, Address, AddressGroup, AddressKind, DestNat, NatRule, Policy, Protocol
from fwshift.model import Rule, RuleScope, Service, ServiceEntry, ServiceGroup, SnatKind, SourceNat, Zone
from fwshift.netutil import parse_literal
from fwshift.options import Options
from fwshift.parsers import iptables as parse_iptables
from fwshift.report import Report, Severity

# -- a small packet filter simulator ----------------------------------------------


@dataclass
class Packet:
    in_if: str
    out_if: str
    src: str
    dst: str
    proto: str  # tcp, udp, icmp, icmp6 or a protocol number
    sport: int = 0
    dport: int = 0
    icmp_type: int = 0
    state: str = "NEW"


def _in(address: str, literal: str) -> bool:
    a, b = parse_literal(address), parse_literal(literal)
    assert a is not None and b is not None
    return a[0] == b[0] and b[1] <= a[1] <= b[2]


def _port_in(port: int, ports: str) -> bool:
    for part in ports.split(","):
        first, _, last = part.partition("-")
        if int(first) <= port <= int(last or first):
            return True
    return False


def _spec_matches(spec: parse_iptables._Spec, pkt: Packet) -> bool:
    assert not spec.unsupported, spec.unsupported
    if spec.in_if and spec.in_if != pkt.in_if:
        return False
    if spec.out_if and spec.out_if != pkt.out_if:
        return False
    if spec.src and _in(pkt.src, spec.src) == spec.src_negated:
        return False
    if spec.dst and _in(pkt.dst, spec.dst) == spec.dst_negated:
        return False
    if spec.proto and spec.proto != pkt.proto:
        return False
    if spec.dports and not _port_in(pkt.dport, spec.dports):
        return False
    if spec.sports and not _port_in(pkt.sport, spec.sports):
        return False
    if spec.has_icmp_type and spec.icmp_type != pkt.icmp_type:
        return False
    if spec.states is not None and pkt.state not in spec.states:
        return False
    return True


@functools.lru_cache(maxsize=8)
def _filter_table(text: str, family: int) -> parse_iptables._Table:
    return parse_iptables.read_tables(text, family)["filter"]


def iptables_allows(text: str, pkt: Packet, family: int = 4) -> bool:
    """Walk the FORWARD chain of an iptables-save text the way the kernel would."""
    table = _filter_table(text, family)

    def walk(chain: str, depth: int = 0) -> Optional[str]:
        assert depth < 20
        for spec in table.rules.get(chain, []):
            if not _spec_matches(spec, pkt):
                continue
            target = spec.target.split()[0]
            if target in ("ACCEPT", "DROP", "REJECT"):
                return target
            if target == "RETURN":
                return None
            if target in table.rules:
                verdict = walk(target, depth + 1)
                if verdict:
                    return verdict
        return None

    return (walk("FORWARD") or table.policies.get("FORWARD", "ACCEPT")) == "ACCEPT"


def _member_matches(p: Policy, member: str, address: str) -> bool:
    if member == ANY:
        return True
    intervals, _ = transform.known_intervals(p, member)
    probe = parse_literal(address)
    assert probe is not None
    return any(i[0] == probe[0] and i[1] <= probe[1] <= i[2] for i in intervals)


def _entry_matches(entry: ServiceEntry, pkt: Packet) -> bool:
    if entry.protocol in (Protocol.TCP, Protocol.UDP, Protocol.SCTP):
        if entry.protocol.value != pkt.proto:
            return False
        if entry.dst_ports and not _port_in(pkt.dport, entry.dst_ports):
            return False
        return not entry.src_ports or _port_in(pkt.sport, entry.src_ports)
    if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
        proto = "icmp" if entry.protocol == Protocol.ICMP else "icmp6"
        return pkt.proto == proto and (entry.icmp_type is None or entry.icmp_type == pkt.icmp_type)
    numbers = {"tcp": "6", "udp": "17", "icmp": "1", "icmp6": "58", "sctp": "132"}
    return entry.ip_protocol is None or str(entry.ip_protocol) == numbers.get(pkt.proto, pkt.proto)


def model_verdict(p: Policy, pkt: Packet) -> Optional[bool]:
    """First-match evaluation of the neutral model for a packet that opens a connection; None if no rule matches."""
    for rule in p.rules:
        # A packet here carries no user: a rule that matches users (an access role, a source user) never matches it.
        if not rule.enabled or rule.unsupported or rule.users != [ANY]:
            continue
        zone_ok = (ANY in rule.src_zones or pkt.in_if in rule.src_zones) and (
            ANY in rule.dst_zones or pkt.out_if in rule.dst_zones
        )
        if rule.scope == RuleScope.INTRAZONE:
            zone_ok = pkt.in_if == pkt.out_if and (ANY in rule.src_zones or pkt.in_if in rule.src_zones)
        elif rule.scope == RuleScope.INTERZONE:
            zone_ok = zone_ok and pkt.in_if != pkt.out_if
        if not zone_ok:
            continue
        if any(_member_matches(p, m, pkt.src) for m in rule.sources) == rule.negate_source:
            continue
        if any(_member_matches(p, m, pkt.dst) for m in rule.destinations) == rule.negate_destination:
            continue
        if rule.services == [ANY]:
            service_ok = True
        else:
            entries = [e for s in rule.services for e in (transform.flatten_services(p, s) or [])]
            service_ok = any(_entry_matches(e, pkt) for e in entries)
        if service_ok == rule.negate_service:
            continue
        return rule.action == Action.ALLOW
    return None


def model_allows(p: Policy, pkt: Packet) -> bool:
    verdict = model_verdict(p, pkt)
    return p.default_interzone == Action.ALLOW if verdict is None else verdict


ZONES = ["eth0", "eth1", "eth2"]
PORTS = [22, 53, 80, 443, 8000, 8005, 8080, 9000]


def random_packet(rng: random.Random, family: int = 4) -> Packet:
    if family == 4:
        src = f"10.0.{rng.randrange(5)}.{rng.randrange(0, 256, 17)}"
        dst = f"10.0.{rng.randrange(5)}.{rng.randrange(0, 256, 17)}"
    else:
        src = f"2001:db8:{rng.randrange(4)}::{rng.randrange(1, 4)}"
        dst = f"2001:db8:{rng.randrange(4)}::{rng.randrange(1, 4)}"
    proto = rng.choice(["tcp", "tcp", "udp", "icmp" if family == 4 else "icmp6", "47"])
    return Packet(rng.choice(ZONES), rng.choice(ZONES), src, dst, proto, rng.choice([1024, 40000]),
                  rng.choice(PORTS), rng.choice([0, 8, 13, 128]))  # fmt: skip


def random_model(rng: random.Random) -> Policy:
    p = Policy(vendor="panos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    for index in range(5):
        p.addresses[f"net{index}"] = Address(f"net{index}", AddressKind.NETWORK, f"10.0.{index}.0/24")
    p.addresses["half"] = Address("half", AddressKind.NETWORK, "10.0.1.128/25")
    p.addresses["span"] = Address("span", AddressKind.RANGE, "10.0.2.100-10.0.3.50")
    p.addresses["host"] = Address("host", AddressKind.NETWORK, "10.0.0.17/32")
    p.addresses["six"] = Address("six", AddressKind.NETWORK, "2001:db8:1::/48")
    p.address_groups["grp"] = AddressGroup("grp", ["net0", "span", "six"])
    p.address_groups["nested"] = AddressGroup("nested", ["grp", "host", "net4"])
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.TCP, "53"), ServiceEntry(Protocol.UDP, "53")])
    p.services["many"] = Service("many", [ServiceEntry(Protocol.TCP, ",".join(str(n) for n in range(7990, 8012)))])
    p.services["ranges"] = Service("ranges", [ServiceEntry(Protocol.TCP, "8000-8010,9000", "1024-2000")])
    p.services["ping"] = Service("ping", [ServiceEntry(Protocol.ICMP, icmp_type=8)])
    p.services["ping6"] = Service("ping6", [ServiceEntry(Protocol.ICMP6, icmp_type=128)])
    p.services["gre"] = Service("gre", [ServiceEntry(Protocol.IP, ip_protocol=47)])
    p.service_groups["mix"] = ServiceGroup("mix", ["web", "ping", "gre"])
    addresses = list(p.addresses) + list(p.address_groups) + ["10.0.3.0/24", "10.0.0.34", "2001:db8:2::/64"]
    services = list(p.services) + list(p.service_groups)

    def members(pool: List[str]) -> List[str]:
        return [ANY] if rng.random() < 0.25 else rng.sample(pool, rng.randint(1, 4))

    def zones() -> List[str]:
        return [ANY] if rng.random() < 0.3 else rng.sample(ZONES, rng.randint(1, 2))

    for index in range(rng.randint(4, 12)):
        rule = Rule(name=f"r{index}", src_zones=zones(), dst_zones=zones(), sources=members(addresses),
                    destinations=members(addresses), services=members(services))  # fmt: skip
        rule.origin = rule.name
        rule.action = rng.choice([Action.ALLOW, Action.ALLOW, Action.DROP, Action.DENY, Action.RESET_BOTH])
        rule.negate_source = rule.sources != [ANY] and rng.random() < 0.25
        rule.negate_destination = rule.destinations != [ANY] and rng.random() < 0.25
        rule.negate_service = rule.services != [ANY] and rng.random() < 0.15
        if rng.random() < 0.15 and ANY not in rule.src_zones:
            rule.scope = rng.choice([RuleScope.INTRAZONE, RuleScope.INTERZONE])
            if rule.scope == RuleScope.INTERZONE and ANY in rule.dst_zones:
                rule.dst_zones = rng.sample(ZONES, 2)
        rule.enabled = rng.random() > 0.1
        p.rules.append(rule)
    return p


@pytest.mark.parametrize("seed", range(40))
def test_emitted_ruleset_decides_like_the_model(seed: int) -> None:
    """Whatever the lists, negations and rule types: the emitted chains give the model's verdict."""
    rng = random.Random(seed)
    model = random_model(rng)
    for family, emit in ((4, emit_iptables.emit), (6, emit_iptables.emit_v6)):
        report = Report()
        text = emit(model, report, Options())
        for _ in range(300):
            pkt = random_packet(rng, family)
            assert iptables_allows(text, pkt, family) == model_allows(model, pkt), (seed, family, pkt, text)


def random_ruleset(rng: random.Random) -> str:
    """iptables-save text with user chains, jumps under a match, RETURN, negation and state matches."""
    literals = ["10.0.0.0/24", "10.0.1.0/24", "10.0.1.128/25", "10.0.2.0/23", "10.0.0.17/32"]

    def match(allow_if: bool = True) -> str:
        parts: List[str] = []
        if allow_if and rng.random() < 0.5:
            parts.append(f"-i {rng.choice(ZONES)}")
        if allow_if and rng.random() < 0.4:
            parts.append(f"-o {rng.choice(ZONES)}")
        if rng.random() < 0.5:
            parts.append(("! " if rng.random() < 0.2 else "") + f"-s {rng.choice(literals)}")
        if rng.random() < 0.5:
            if rng.random() < 0.2:
                parts.append("-m iprange --dst-range 10.0.2.100-10.0.3.50")
            else:
                parts.append(("! " if rng.random() < 0.2 else "") + f"-d {rng.choice(literals)}")
        kind = rng.random()
        if kind < 0.3:
            parts.append(f"-p tcp -m tcp --dport {rng.choice(PORTS)}")
        elif kind < 0.45:
            parts.append("-p tcp -m multiport --dports 80,443,8000:8010")
        elif kind < 0.55:
            parts.append("-p udp -m udp --dport 53 --sport 1024:65535")
        elif kind < 0.65:
            parts.append("-p icmp -m icmp --icmp-type 8")
        elif kind < 0.7:
            parts.append("-p gre")
        if rng.random() < 0.3:
            parts.append("-m conntrack --ctstate NEW")
        return " ".join(parts)

    lines = ["*filter", f":FORWARD {rng.choice(['DROP', 'DROP', 'ACCEPT'])} [0:0]", ":C1 - [0:0]", ":C2 - [0:0]",
             "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
             "-A FORWARD -m conntrack --ctstate INVALID -j DROP"]  # fmt: skip
    targets = ["ACCEPT", "ACCEPT", "DROP", "REJECT --reject-with icmp-port-unreachable"]
    for _ in range(rng.randint(3, 8)):
        choice = rng.random()
        if choice < 0.25:
            lines.append(f"-A FORWARD {match()} -j {rng.choice(['C1', 'C2'])}".replace("  ", " "))
        elif choice < 0.3:
            lines.append(f'-A FORWARD {match()} -j LOG --log-prefix "x "'.replace("  ", " "))
        else:
            lines.append(f"-A FORWARD {match()} -j {rng.choice(targets)}".replace("  ", " "))
    for chain in ("C1", "C2"):
        for _ in range(rng.randint(1, 4)):
            lines.append(f"-A {chain} {match(allow_if=False)} -j {rng.choice(targets)}".replace("  ", " "))
        if rng.random() < 0.3:
            lines.append(f"-A {chain} -j RETURN")
            lines.append(f"-A {chain} -j ACCEPT")  # never reached
    if rng.random() < 0.5:
        lines.append("-A C1 -p tcp -m tcp --dport 22 -j C2")
    return "\n".join(lines + ["COMMIT", ""])


def test_parsed_ruleset_decides_like_the_kernel_would() -> None:
    """Flattened chains, merged matches and the stateful reading agree with a walk through the chains.

    A ruleset with a construct the parser flags (those rules would be converted disabled) is left
    out of the comparison; most generated rulesets have none.
    """
    compared = 0
    for seed in range(60):
        rng = random.Random(1000 + seed)
        text = random_ruleset(rng)
        model = parse_iptables.parse(text.encode(), Report())
        if any(rule.unsupported for rule in model.rules):
            continue
        compared += 1
        for _ in range(300):
            pkt = random_packet(rng)
            assert model_allows(model, pkt) == iptables_allows(text, pkt), (seed, pkt, text)
    assert compared >= 40


def test_matches_of_a_jump_and_its_chain_are_combined() -> None:
    text = rules_of(
        "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
        "-A FORWARD -s 10.0.0.0/16 -p tcp -m multiport --dports 80,443,8000:8010 -j C\n"
        "-A C -s 10.0.1.0/24 -p tcp --dport 8005:9000 -j ACCEPT\n"   # narrower source, common ports
        "-A C -s 10.9.0.0/16 -j ACCEPT\n"                              # outside the jump's source
        "-A C ! -s 10.0.2.0/24 -p tcp --dport 22 -j ACCEPT\n"          # no common port
        "-A C ! -s 10.0.0.0/8 -j ACCEPT\n"                             # excludes all the jump lets in
        "-A C ! -s 10.5.0.0/16 -p tcp --dport 443 -j DROP\n"           # excludes nothing the jump lets in
        "-A C ! -s 10.0.3.0/24 -j DROP"                                # a hole in the middle
    )
    p = parse_iptables.parse(text.encode(), Report())
    assert len(p.rules) == 3
    first, second, third = p.rules
    assert first.sources == ["10.0.1.0/24"] and p.services[first.services[0]].entries[0].dst_ports == "8005-8010"
    assert second.sources == ["10.0.0.0/16"] and not second.negate_source and not second.unsupported
    assert p.services[second.services[0]].entries[0].dst_ports == "443"
    assert third.unsupported and third.action == Action.DROP


# -- the sample ruleset -----------------------------------------------------------


def test_iptables_sample_rules() -> None:
    p, report = load("iptables_sample.rules")
    assert p.vendor == "iptables" and p.scope == "IPv4" and p.default_interzone == Action.DENY
    names = [r.name for r in p.rules]
    # FORWARD order, with the rules of the chains in place of the jumps to them
    assert names[:5] == ["Block bad host", "Guests stay in", "LAN web", "LAN DNS", "LAN DNS-2"]
    assert "Admins SSH" in names and "Admins RDP" in names
    rules = {r.name: r for r in p.rules}
    web = rules["LAN web"]
    assert (web.src_zones, web.dst_zones) == (["eth1"], ["eth0"])  # taken from the jump
    assert web.sources == [ANY_V4] and web.destinations == [ANY]  # an IPv4 ruleset matches IPv4 only
    assert p.services[web.services[0]].entries[0].dst_ports == "80,443"
    ssh = rules["Admins SSH"]
    assert ssh.sources == ["10.10.5.10-10.10.5.20"] and ssh.destinations == ["10.20.0.0/24"]
    updates = rules["DMZ updates"]
    assert updates.negate_destination and updates.destinations == ["10.0.0.0/8"]
    assert updates.sources == [ANY_V4]  # negation covers IPv6 in the model: the source keeps it to IPv4
    assert rules["OT no internet"].action == Action.DENY and rules["OT no internet"].log_start
    assert rules["Rate limited mail"].unsupported == ["match module 'limit'"]
    assert p.services[rules["Ping the DMZ"].services[0]].entries[0].icmp_type == 8
    assert p.services[rules["Partner tunnel"].services[0]].entries[0].ip_protocol == 47
    codes = {n.code for n in report.notes}
    assert {"HOST_CHAIN_NOT_CONVERTED", "PASSIVE_TARGETS"} <= codes and "STATELESS_RULESET" not in codes
    assert [f.code for f in report.item("rule", "Block bad host").findings] == ["DROP_BEFORE_ESTABLISHED"]


def test_iptables_sample_nat() -> None:
    p, report = load("iptables_sample.rules")
    nat = {n.name: n for n in p.nat_rules}
    assert list(nat) == ["Web DNAT", "Mail DNAT", "No NAT to partner", "DMZ out", "LAN out"]
    web = nat["Web DNAT"]
    assert web.src_zones == ["eth0"] and web.destinations == ["203.0.113.10/32"]
    assert web.destination_translation is not None
    assert (web.destination_translation.address, web.destination_translation.port) == ("10.20.0.10", "8443")
    assert p.services[web.service].entries[0].dst_ports == "443"
    assert nat["No NAT to partner"].source_translation is None
    pool = nat["DMZ out"].source_translation
    assert pool is not None and pool.addresses == ["198.51.100.20-198.51.100.23"]
    masq = nat["LAN out"].source_translation
    assert masq is not None and masq.kind == SnatKind.INTERFACE and masq.interface == "eth0"
    # FORWARD names the translated address; the model also needs the original one.
    inbound = next(r for r in p.rules if r.name == "Inbound web")
    assert inbound.destinations == ["10.20.0.10/32", "203.0.113.10/32"]
    assert "NAT_PORT_TRANSLATION" in [f.code for f in report.item("rule", "Inbound web").findings]


def test_iptables_to_panos_and_fortios() -> None:
    text, report = run("iptables_sample.rules", "panos", Options(interface_map={"eth0": "ethernet1/1"}))
    cfg = PanConfig(text)
    assert cfg.get("security", "LAN web", "source") == ["0.0.0.0/0"]
    assert cfg.get("security", "Rate limited mail", "disabled") == ["yes"]
    assert cfg.get("security", "Ping the DMZ", "application") == ["ping"]
    assert cfg.names("security")[-1] == "fwshift-intrazone-deny"  # FORWARD policy DROP
    dipp = ("source-translation", "dynamic-ip-and-port")
    assert cfg.get("nat", "LAN out", *dipp, "interface-address", "interface") == ["ethernet1/1"]
    assert cfg.get("nat", "DMZ out", *dipp, "translated-address") == ["198.51.100.20-198.51.100.23"]
    text, report = run("iptables_sample.rules", "fortios")
    forti = FortiConfig(text)
    policies = forti.policies()
    assert policies["LAN web"].list("srcaddr") == ["all"] and policies["LAN web"].list("srcaddr6") == []
    assert policies["DMZ updates"].get("dstaddr-negate") == "enable"
    assert policies["Rate limited mail"].get("status") == "disable"
    assert forti.table("firewall vip")["Web DNAT"].get("mappedport") == "8443"
    # Both platforms look rules up after NAT: nothing to adjust, nothing to report.
    assert policies["Inbound web"].list("dstaddr") == ["h-10.20.0.10"]
    assert report.item("rule", "Inbound web").status == "exact"


def test_iptables_roundtrip_keeps_every_decision() -> None:
    source, _ = load("iptables_sample.rules")
    text = cli.convert(source, "iptables", Report())
    again = parse_iptables.parse(text.encode(), Report())
    rng = random.Random(7)
    zones = ["eth0", "eth1", "eth2", "eth3"]
    for _ in range(3000):
        pkt = Packet(rng.choice(zones), rng.choice(zones),
                     rng.choice(["10.10.5.15", "10.10.200.9", "10.10.7.15", "10.20.0.10", "198.51.100.66", "192.0.2.9"]),
                     rng.choice(["10.20.0.10", "10.20.0.25", "10.30.1.7", "192.0.2.80", "10.99.1.1"]),
                     rng.choice(["tcp", "udp", "icmp", "47"]), 40000, rng.choice([22, 25, 53, 80, 443, 502, 3389, 8443]),
                     rng.choice([0, 8]))  # fmt: skip
        assert model_allows(again, pkt) == model_allows(source, pkt), pkt


# -- emitter details ----------------------------------------------------------------


def test_panos_to_iptables_output() -> None:
    options = Options(zone_map={"trust": "eth1", "untrust": "eth0", "dmz": "eth2", "ot": "eth3"})
    text, report = run("panos_sample.xml", "iptables", options)
    lines = text.splitlines()
    assert lines[3:7] == ["*filter", ":FORWARD DROP [0:0]",
                          "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                          "-A FORWARD -m conntrack --ctstate INVALID -j DROP"]  # fmt: skip
    assert ":INPUT" not in text and ":OUTPUT" not in text  # the host's own chains are never touched
    assert ('-A FORWARD -i eth1 -o eth3 -s 10.10.7.15/32 -d 10.30.1.0/24 -p tcp -m multiport --dports 502,102 '
            '-m conntrack --ctstate NEW -m comment --comment "Engineering to PLCs" -j ACCEPT') in lines  # fmt: skip
    assert any(line.startswith('# FWSHIFT disabled, see the report: "Admin-SSH"') for line in lines)
    assert not any("Admin-SSH" in line and line.startswith("-A") for line in lines)  # not loaded
    assert report.item("rule", "Admin-SSH").disabled
    assert any("! -s 10.10.200.0/24" in line and "Not-From-Guests" in line for line in lines)
    nat = text[text.index("*nat"):]
    assert "-A PREROUTING -i eth0 -d 203.0.113.10/32 -p tcp -m tcp --dport 443" in nat
    assert "-j DNAT --to-destination 10.20.0.10:8443" in nat
    assert '-A POSTROUTING -o eth0 -m comment --comment "Outbound-PAT" -j MASQUERADE' in nat
    assert "-j SNAT --to-source 198.51.100.20-198.51.100.23" in nat
    assert '--comment "No-NAT-Partner" -j ACCEPT' in nat
    # FORWARD sees the translated address
    assert any("Inbound-Web" in line and "-d 10.20.0.10/32" in line for line in lines)
    codes = {n.code for n in report.notes}
    assert {"IPTABLES_LOAD", "INTERFACES_REQUIRED", "INTRAZONE_DEFAULT", "OTHER_IP_VERSION"} <= codes


def test_ip6tables_gets_only_the_ipv6_half() -> None:
    options = Options(zone_map={"trust": "eth1", "untrust": "eth0", "dmz": "eth2", "ot": "eth3"})
    text, report = run("panos_sample.xml", "ip6tables", options)
    assert "*nat" not in text and "10." not in text.split("COMMIT")[0].replace("# FWSHIFT", "")
    assert '-A FORWARD -i eth3 -o eth0 -m comment --comment "Block-OT-Outbound" -j REJECT' in text
    assert report.item("rule", "Allow-Web-Out").status == "skipped"  # an IPv4 source
    assert report.item("nat", "Outbound-PAT").status == "skipped"


def test_lists_become_chains_and_invalid_interface_names_are_not_loaded() -> None:
    p = Policy(vendor="panos")
    for index in range(6):
        p.addresses[f"a{index}"] = Address(f"a{index}", AddressKind.NETWORK, f"10.{index}.0.0/16")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443"), ServiceEntry(Protocol.UDP, "443")])
    many = Rule(name="many", src_zones=["eth1"], dst_zones=["eth0"], sources=[f"a{i}" for i in range(6)],
                destinations=["a0", "a1", "a2"], services=["web"], origin="many")  # fmt: skip
    bad = Rule(name="bad", src_zones=["DMZ Zone"], origin="bad")
    p.rules += [many, bad]
    report = Report()
    text = emit_iptables.emit(p, report, Options())
    assert ":FWS1 - [0:0]" in text and ":FWS1-1 - [0:0]" in text and ":FWS1-2 - [0:0]" in text
    assert '-A FORWARD -i eth1 -o eth0 -m conntrack --ctstate NEW -m comment --comment "many" -j FWS1' in text
    assert text.count("-j FWS1-1") == 6 and text.count("-j FWS1-2") == 3 and text.count("-A FWS1-2") == 2
    assert report.item("rule", "many").emitted_as == ["chain FWS1"]
    assert report.item("rule", "bad").disabled
    assert not any(line.startswith("-A") and "DMZ Zone" in line for line in text.splitlines())


def test_multiport_is_split_at_fifteen_ports() -> None:
    entries = [ServiceEntry(Protocol.TCP, ",".join(str(n) for n in range(1000, 1020)) + ",2000-2010")]
    fragments = emit_iptables.entry_fragments(entries, 4)
    assert len(fragments) == 2
    for fragment in fragments:
        ports = fragment.split("--dports ")[1].split(",")
        assert sum(2 if ":" in port else 1 for port in ports) <= 15
    assert fragments[1].endswith("2000:2010")


# -- parser details -----------------------------------------------------------------


def rules_of(body: str, policy: str = "DROP") -> str:
    return f"*filter\n:FORWARD {policy} [0:0]\n:C - [0:0]\n{body}\nCOMMIT\n"


def test_unknown_matches_never_read_as_any() -> None:
    text = rules_of(
        "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
        "-A FORWARD -m set --match-set allowed src -j ACCEPT\n"
        "-A FORWARD ! -i eth0 -j ACCEPT\n"
        "-A FORWARD -i eth+ -j ACCEPT\n"
        "-A FORWARD ! -p tcp -j ACCEPT\n"
        "-A FORWARD -p tcp -m tcp ! --dport 22 -j ACCEPT\n"
        "-A FORWARD -s www.example.com -j ACCEPT\n"
        "-A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT\n"
        "-A FORWARD -p tcp --dport 80 -j NOSUCHTARGET\n"
        "-A FORWARD -m mac --mac-source 00:00:5e:00:53:01 -j DROP\n"
    )
    p = parse_iptables.parse(text.encode(), Report())
    flagged = [bool(r.unsupported) for r in p.rules]
    assert flagged == [True, True, True, True, True, True, False, True, True]
    report = Report()
    out = cli.convert(p, "panos", report)
    assert out.count("disabled yes") == 8
    assert "NOT enforced" in report.item("rule", p.rules[-1].origin).findings[0].message  # the unreadable deny


def test_stateless_ruleset_and_state_only_rules() -> None:
    stateless = rules_of("-A FORWARD -i eth1 -o eth0 -j ACCEPT\n-A FORWARD -i eth0 -o eth1 -p tcp --sport 80 -j ACCEPT")
    report = Report()
    p = parse_iptables.parse(stateless.encode(), report)
    assert len(p.rules) == 2 and any(n.code == "STATELESS_RULESET" for n in report.notes) and report.needs_review
    stateful = rules_of(
        "-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
        "-A FORWARD -m conntrack --ctstate INVALID -j DROP\n"
        "-A FORWARD -i eth1 -m conntrack --ctstate ESTABLISHED -j DROP\n"
        "-A FORWARD -i eth1 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
    )
    report = Report()
    p = parse_iptables.parse(stateful.encode(), report)
    assert len(p.rules) == 2  # the two built-in behaviours are left out
    assert p.rules[0].unsupported and p.rules[0].action == Action.DROP  # dropping established packets: not expressible
    assert not p.rules[1].unsupported
    assert not any(n.code == "STATELESS_RULESET" for n in report.notes)


def test_chain_constructs_that_cannot_be_flattened() -> None:
    text = rules_of(
        "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
        "-A FORWARD -s 10.0.0.0/8 -j C\n"
        "-A FORWARD -s 172.16.0.0/12 -g C\n"
        "-A C -s 192.0.2.0/24 -j ACCEPT\n"
        "-A C -s 10.1.0.0/16 -p tcp --dport 22 -j RETURN\n"
        "-A C -s 10.1.2.0/24 -j ACCEPT\n"
        "-A C -j C"
    )
    p = parse_iptables.parse(text.encode(), Report())
    by_source = {(r.sources[0], r.description): r for r in p.rules}
    # 192.0.2.0/24 can never match under the jump for 10.0.0.0/8: no rule from that path
    assert not any(r.sources == ["192.0.2.0/24"] and "FORWARD-2." in r.description for r in p.rules)
    after_return = next(r for r in p.rules if r.sources == ["10.1.2.0/24"] and "FORWARD-2." in r.description)
    assert "conditional RETURN" in after_return.unsupported[0]  # the narrower of the two sources was kept
    assert any("jump loop" in u for r in p.rules for u in r.unsupported)
    assert any("conditional goto C" in u for r in p.rules for u in r.unsupported)
    assert len(by_source) == len(p.rules)


def test_nothing_after_a_conditional_goto_is_certain() -> None:
    text = rules_of(
        "-A FORWARD -p tcp --dport 22 -j ACCEPT\n"
        "-A FORWARD -s 10.1.0.0/16 -g X\n"
        "-A FORWARD -j ACCEPT\n"
        "-A X -d 10.2.0.4 -j ACCEPT"
    )
    report = Report()
    before, goto, after = parse_iptables.parse(text.encode(), report).rules
    assert not before.unsupported and "conditional goto X" in goto.unsupported[0]
    # Packets from 10.1.0.0/16 never reach the last rule on the source: it must not accept them here.
    assert after.unsupported == ["follows a conditional goto in chain FORWARD, which cannot be expressed"]


def test_unconditional_goto_is_followed() -> None:
    text = rules_of(
        "-A FORWARD -i eth1 -j LAN\n"
        "-A FORWARD -p tcp --dport 80 -j ACCEPT\n"
        "-A LAN -p tcp --dport 22 -j ACCEPT\n"
        "-A LAN -g TAIL\n"
        "-A LAN -j ACCEPT\n"  # never reached
        "-A TAIL -p udp --dport 53 -j ACCEPT"
    )
    report = Report()
    p = parse_iptables.parse(text.encode(), report)
    # After TAIL, a goto returns to where LAN was called from: FORWARD goes on.
    assert [(r.src_zones, r.services) for r in p.rules] == [
        (["eth1"], ["tcp-22"]), (["eth1"], ["udp-53"]), ([ANY], ["tcp-80"]),
    ]  # fmt: skip
    assert not any(r.unsupported for r in p.rules)
    for pkt in (Packet("eth1", "eth0", "10.0.0.1", "10.0.0.2", "tcp", 1024, 443),
                Packet("eth1", "eth0", "10.0.0.1", "10.0.0.2", "udp", 1024, 53),
                Packet("eth1", "eth0", "10.0.0.1", "10.0.0.2", "tcp", 1024, 80)):  # fmt: skip
        assert model_allows(p, pkt) == (pkt.dport != 443)


def test_two_address_matches_on_one_side_must_both_hold() -> None:
    text = rules_of(
        "-A FORWARD -s 10.0.0.0/8 -m iprange --src-range 10.1.0.1-10.1.0.9 -j ACCEPT\n"
        "-A FORWARD -s 10.0.0.0/8 -m iprange ! --src-range 10.0.0.1-10.0.0.9 -j ACCEPT\n"
        "-A FORWARD -s 10.0.0.0/8 -m iprange --src-range 192.168.0.1-192.168.0.9 -j ACCEPT\n"
        "-A FORWARD -d 10.0.0.0/8 -m iprange ! --dst-range 172.16.0.1-172.16.0.9 -j ACCEPT"
    )
    p = parse_iptables.parse(text.encode(), Report())
    inside, hole, disjoint, unrelated = p.rules
    assert inside.sources == ["10.1.0.1-10.1.0.9"] and not inside.negate_source and not inside.unsupported
    assert hole.unsupported == ["two source matches that one match cannot say"]
    assert disjoint.unsupported == ["two source matches that exclude each other"]
    # A negated range that excludes nothing of the network leaves the network.
    assert unrelated.destinations == ["10.0.0.0/8"] and not unrelated.negate_destination and not unrelated.unsupported
    report = Report()
    out = cli.convert(p, "panos", report)
    assert report.item("rule", hole.origin).disabled and report.item("rule", disjoint.origin).disabled
    assert "negate-source yes" not in out


def test_ip_version_comes_from_addresses_not_from_comments() -> None:
    body = '-A FORWARD -i lan -o wan -m comment --comment "see wiki::fw, icmpv6 -s ::1" -j ACCEPT'
    assert parse_iptables.detect_family(f"*filter\n{body}\nCOMMIT\n") == 4
    assert parse_iptables.parse(rules_of(body).encode(), Report()).scope == "IPv4"
    assert parse_iptables.detect_family("*filter\n-A FORWARD ! -s 2001:db8::/32 -j DROP\nCOMMIT\n") == 6
    assert parse_iptables.detect_family("*filter\n-A FORWARD -p ipv6-icmp -j ACCEPT\nCOMMIT\n") == 6
    assert parse_iptables.detect_family("*nat\n-A PREROUTING -j DNAT --to-destination 10.0.0.1:80\nCOMMIT\n") == 4
    # The header iptables-save writes settles it.
    saved = "# Generated by iptables-save v1.8.9\n*filter\n-A FORWARD -d 2001:db8::1 -j ACCEPT\nCOMMIT\n"
    assert parse_iptables.detect_family(saved) == 4
    assert parse_iptables.detect_family(saved.replace("iptables-save", "ip6tables-save")) == 6


def test_icmp_type_of_the_jump_and_code_inside_the_chain() -> None:
    text = rules_of(
        "-A FORWARD -p icmp --icmp-type 3 -j ICMPF\n"
        "-A ICMPF -p icmp --icmp-type 3/1 -j DROP\n"
        "-A ICMPF -p icmp --icmp-type 8 -j DROP\n"
        "-A ICMPF -j ACCEPT"
    )
    p = parse_iptables.parse(text.encode(), Report())
    assert [(r.services, r.action) for r in p.rules] == [(["icmp-3-1"], Action.DROP), (["icmp-3"], Action.ALLOW)]
    text = rules_of("-A FORWARD -p icmp --icmp-type 3/1 -j C\n-A C -p icmp --icmp-type 3/2 -j ACCEPT\n"
                    "-A C -p icmp --icmp-type 3 -j ACCEPT")  # fmt: skip
    p = parse_iptables.parse(text.encode(), Report())
    assert [r.services for r in p.rules] == [["icmp-3-1"]]  # 3/2 can never follow 3/1; 3 keeps the code


def test_accept_on_another_connection_state_is_not_dropped_silently() -> None:
    text = rules_of(
        "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
        "-A FORWARD -m conntrack --ctstate DNAT -j ACCEPT\n"
        "-A FORWARD -m conntrack --ctstate UNTRACKED,ESTABLISHED -j ACCEPT"
    )
    report = Report()
    p = parse_iptables.parse(text.encode(), report)
    assert len(p.rules) == 2 and all("without NEW" in r.unsupported[0] for r in p.rules)
    cli.convert(p, "fortios", report)
    assert all(report.item("rule", r.origin).disabled for r in p.rules)


def test_chains_that_multiply_are_refused_quickly() -> None:
    lines = [f"-A C{level} -j C{level + 1}" for level in range(9) for _ in range(30)]
    text = rules_of("-A FORWARD -j C0\n" + "\n".join(lines))
    with pytest.raises(ParseError, match="more than 50000 rules"):
        parse_iptables.parse(text.encode(), Report())


def test_forward_policy_accept_and_ipv6_detection() -> None:
    report = Report()
    p = parse_iptables.parse(rules_of("-A FORWARD -i eth0 -j DROP", policy="ACCEPT").encode(), report)
    assert p.default_interzone == Action.ALLOW and p.default_intrazone == Action.ALLOW
    out_report = Report()
    text = cli.convert(p, "panos", out_report)
    assert "fwshift-intrazone-deny" not in text
    assert any(n.code == "INTERZONE_DEFAULT" for n in out_report.notes)
    assert ":FORWARD ACCEPT [0:0]" in cli.convert(p, "iptables", Report())
    v6 = b"# Generated by ip6tables-save v1.8.9\n*filter\n:FORWARD DROP [0:0]\n-A FORWARD -i eth1 -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT\n-A FORWARD -s 2001:db8::/32 -j ACCEPT\nCOMMIT\n"
    p6 = cli.load(v6, cli.detect_format(v6), Report())
    assert p6.scope == "IPv6" and p6.rules[0].sources == ["::/0"] and p6.rules[0].destinations == [ANY]
    assert p6.services[p6.rules[0].services[0]].entries[0].protocol == Protocol.ICMP6
    assert "2001:db8::/32" in cli.convert(p6, "ip6tables", Report())
    assert "2001:db8" not in cli.convert(p6, "iptables", Report())


def test_nat_shapes() -> None:
    text = (
        "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n"
        "-A PREROUTING -i eth0 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128\n"
        "-A PREROUTING -i eth0 -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.5:80\n"
        "-A PREROUTING ! -s 10.0.0.0/8 -d 203.0.113.9/32 -j DNAT --to-destination 10.0.0.9\n"
        "-A POSTROUTING -o eth0 -j SNAT --to-source 198.51.100.7\n"
        "COMMIT\n*filter\n:FORWARD DROP [0:0]\n-A FORWARD -d 10.0.0.5/32 -p tcp --dport 80 -j ACCEPT\nCOMMIT\n"
    )
    report = Report()
    p = parse_iptables.parse(text.encode(), report)
    nat = p.nat_rules
    assert "target REDIRECT" in nat[0].unsupported[0]
    assert nat[1].destinations == [ANY] and nat[1].destination_translation is not None
    assert nat[2].unsupported == ["negated address in a NAT rule"]
    assert nat[3].source_translation is not None and nat[3].source_translation.addresses == ["198.51.100.7"]
    out_report = Report()
    out = cli.convert(p, "iptables", out_report)
    assert "-j REDIRECT" not in out and out_report.item("nat", nat[0].origin).status == "skipped"
    assert "-A PREROUTING -i eth0 -p tcp -m tcp --dport 8080" in out and "--to-destination 10.0.0.5:80" in out
    # Read from iptables and written for iptables: the rules stay as they were, nothing to report.
    assert "NAT_ANY_DESTINATION" not in [f.code for f in out_report.item("nat", nat[1].origin).findings]
    assert not out_report.item("rule", p.rules[0].origin).findings
    # A platform that looks rules up before NAT cannot match the redirected traffic with this rule.
    assert [f.code for f in report.item("rule", p.rules[0].origin).findings] == ["NAT_REDIRECT"]
    pan = Report()
    cli.convert(parse_iptables.parse(text.encode(), pan), "panos", pan, Options(nat_zone="lan"))
    assert pan.item("rule", p.rules[0].origin).status == "needs-review"


def test_redirect_of_every_destination_written_for_iptables() -> None:
    p = Policy(vendor="panos")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80")])
    nat = NatRule("proxy", src_zones=["lan"], dst_zones=["wan"], service="web", destination_translation=DestNat("10.0.0.9", "3128"))
    nat.origin = "proxy"
    p.nat_rules.append(nat)
    report = Report()
    assert "-j DNAT --to-destination 10.0.0.9:3128" in cli.convert(p, "iptables", report)
    assert [f.code for f in report.item("nat", "proxy").findings] == ["NAT_ANY_DESTINATION"]


def test_port_translation_is_reported_on_the_rules_it_concerns() -> None:
    text = (
        "*nat\n:PREROUTING ACCEPT [0:0]\n"
        "-A PREROUTING -d 203.0.113.9/32 -p tcp --dport 443 -j DNAT --to-destination 10.0.0.9:8443\nCOMMIT\n"
        "*filter\n:FORWARD DROP [0:0]\n"
        "-A FORWARD -d 10.0.0.0/24 -p tcp --dport 22 -j ACCEPT\n"
        "-A FORWARD -d 10.0.0.9/32 -p tcp --dport 8443 -j ACCEPT\n"
        "-A FORWARD -d 10.0.0.9/32 -j ACCEPT\nCOMMIT\n"
    )
    report = Report()
    ssh, web, everything = parse_iptables.parse(text.encode(), report).rules
    codes = {rule.name: [f.code for f in report.item("rule", rule.origin).findings] for rule in (ssh, web, everything)}
    assert "NAT_PORT_TRANSLATION" not in codes[ssh.name]  # port 22 is not what the NAT rule forwards
    assert "NAT_PORT_TRANSLATION" in codes[web.name]
    assert "NAT_PORT_TRANSLATION" not in codes[everything.name]  # every service: there is no port to adjust


def test_emitter_details_found_in_review() -> None:
    # More zone pairs than fit in line, and nothing else to match.
    wide = Rule("wide", src_zones=["a", "b", "c"], dst_zones=["d", "e", "f", "g", "h", "i"])
    wide.origin = "wide"
    # Reject of everything but a TCP service: the rest is not TCP, a reset cannot answer it.
    reject = Rule("reject", services=["web"], negate_service=True, action=Action.RESET_CLIENT)
    reject.origin = "reject"
    p = Policy(vendor="panos", rules=[wide, reject])
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,22")])
    for family, target in ((4, "iptables"), (6, "ip6tables")):
        out = cli.convert(p, target, Report())
        assert out.count('--comment "wide" -j ACCEPT') == 18, family
        assert "tcp-reset" not in out and "-j REJECT" in out
    report = Report()
    p.default_interzone, p.default_intrazone = Action.ALLOW, Action.DENY
    assert ":FORWARD ACCEPT" in cli.convert(p, "iptables", report)
    assert any(n.code == "INTRAZONE_DEFAULT" and "cannot tell the two apart" in n.message for n in report.notes)
    p.default_interzone = Action.DENY
    p.zones["a"] = Zone("a", intrazone_allow=True)
    report = Report()
    cli.convert(p, "iptables", report)
    assert "INTRAZONE_ALLOW" in [n.code for n in report.notes]
    # "Also matches IPv6" is about whole rules: any destination behind an IPv4-only source is IPv4.
    v4 = Rule("v4", sources=[ANY_V4])
    v4.origin = "v4"
    report = Report()
    cli.convert(Policy(vendor="fortios", rules=[v4]), "iptables", report)
    assert "OTHER_IP_VERSION" not in [n.code for n in report.notes]


def test_names_from_the_input_cannot_start_lines_of_their_own() -> None:
    hostile = Rule("r\n-A FORWARD -j ACCEPT", src_zones=["lan\ntouch /tmp/x #"], sources=["site"], action=Action.DROP,
                   tags=["t\nset mgt-config users evil"], users=["u\nset deviceconfig"])  # fmt: skip
    hostile.origin = hostile.name
    p = Policy(vendor="panos", rules=[hostile])
    p.addresses["site"] = Address("site", AddressKind.FQDN, "a.example.com -j ACCEPT\n-A FORWARD -j ACCEPT")
    for target in ("iptables", "panos", "fortios", "checkpoint"):
        report = Report()
        out = cli.convert(copy.deepcopy(p), target, report)
        lines = out.splitlines()
        assert not any(line.startswith(("-A FORWARD -j ACCEPT", "touch ", "set mgt-config", "set deviceconfig")) for line in lines), target
        assert "a.example.com -j" not in out, target  # not a host name: the object is unusable, the rule disabled
        assert report.needs_review


def test_malformed_input_is_a_clean_error() -> None:
    for bad in (b"*filter\n-I FORWARD -j ACCEPT\nCOMMIT\n", b"-A FORWARD -j ACCEPT\n",
                b'*filter\n-A FORWARD -m comment --comment "open -j ACCEPT\nCOMMIT\n'):  # fmt: skip
        with pytest.raises(ParseError):
            parse_iptables.parse(bad, Report())
    assert cli.detect_format(b"# Generated by iptables-save v1.8.9\n*filter\n") == "iptables"
    assert cli.detect_format(b"*nat\n:PREROUTING ACCEPT [0:0]\n") == "iptables"
    assert cli.detect_format(b"#config-version=FGT60F\nconfig system global\n") == "fortios"



# -- found in the second review round --------------------------------------------------------------


def test_digits_that_int_cannot_read() -> None:
    for body in ("-A FORWARD -p \u00b2 -j ACCEPT", "-A FORWARD -p icmp --icmp-type \u00b2 -j ACCEPT",
                 "-A FORWARD -p icmp --icmp-type 8/\u00b2 -j ACCEPT", "-A FORWARD -p tcp --dport \u0668\u0660 -j ACCEPT"):  # fmt: skip
        (rule,) = parse_iptables.parse(rules_of(body).encode(), Report()).rules
        assert rule.unsupported, body
    forti = (
        "config firewall service custom\n    edit \"odd-icmp\"\n        set protocol ICMP\n        set icmptype \u00b2\n    next\n"
        "    edit \"odd-ip\"\n        set protocol IP\n        set protocol-number \u00b2\n    next\n"
        "    edit \"all-icmp\"\n        set protocol ICMP\n    next\nend\n"
    )
    report = Report()
    p = cli.load(forti.encode(), "fortios", report)
    assert p.services["odd-icmp"].unsupported and p.services["odd-ip"].unsupported  # set but unreadable: not "any"
    assert p.services["all-icmp"].entries == [ServiceEntry(Protocol.ICMP)]
    assert not parse_literal("fe80::1%eth0") and not parse_literal('fe80::1%x" y')


def _nat(name: str, **fields: object) -> NatRule:
    nat = NatRule(name, **fields)  # type: ignore[arg-type]
    nat.origin = name
    return nat


def test_translated_port_from_the_input_is_checked() -> None:
    for port in ("8443 -j ACCEPT", "8443;id", "0", "99999", "80-90", "\uff18\uff14\uff14\uff13"):
        p = Policy(vendor="panos")
        p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "443")])
        p.nat_rules = [_nat("fwd", src_zones=["untrust"], dst_zones=["untrust"], destinations=["203.0.113.10"],
                            service="web", destination_translation=DestNat("10.20.0.10", port))]  # fmt: skip
        for target in ("iptables", "fortios", "panos", "checkpoint"):
            report = Report()
            out = cli.convert(copy.deepcopy(p), target, report)
            assert report.item("nat", "fwd").skipped, (port, target)
            assert "DNAT" not in out and "mappedport" not in out and "translated-" not in out, (port, target)


def test_option_values_cannot_start_lines_of_their_own() -> None:
    p = Policy(vendor="fortios")
    for target in ("panos", "fortios", "iptables", "checkpoint"):
        for options in (Options(zone_map={"lan": "x\ndelete rulebase"}), Options(interface_map={"wan1": "e\n1"}),
                        Options(target_scope="vsys:vsys1\ndelete rulebase"), Options(target_vdom="root\nend"),
                        Options(nat_zone="untrust\nset x")):  # fmt: skip
            with pytest.raises(FwshiftError, match="control characters are not allowed"):
                cli.convert(p, target, Report(), options)


def _nat_policy(*rules: NatRule) -> Policy:
    p = Policy(vendor="panos")
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "203.0.113.10/32")
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.20.0.10/32")
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.10.0.0/16")
    p.addresses["partner"] = Address("partner", AddressKind.NETWORK, "198.51.100.0/24")
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.nat_rules = list(rules)
    return p


def test_first_match_nat_order_on_a_platform_that_translates_each_direction_apart() -> None:
    exempt = _nat("exempt", src_zones=["untrust"], dst_zones=["untrust"], sources=["partner"], destinations=["pub"])
    dnat = _nat("dnat", src_zones=["untrust"], dst_zones=["untrust"], destinations=["pub"],
                destination_translation=DestNat("web"))  # fmt: skip
    masquerade = _nat("masq", src_zones=["trust"], dst_zones=["untrust"], sources=["lan"],
                      source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.7"]))  # fmt: skip
    unrelated = _nat("unrelated", src_zones=["dmz"], dst_zones=["untrust"], sources=["web"],
                     source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.8"]))  # fmt: skip
    inbound = _nat("inbound", src_zones=["trust"], dst_zones=["untrust"], destinations=["pub"],
                   destination_translation=DestNat("web"))  # fmt: skip
    for target in ("iptables", "fortios"):
        # A no-NAT rule above a destination NAT: the partner's traffic kept its destination.
        report = Report()
        cli.convert(_nat_policy(exempt, dnat), target, report)
        (found,) = [f for f in report.item("nat", "dnat").findings if f.code == "NAT_ORDER"]
        assert found.severity.name == "REVIEW" and "'exempt'" in found.message, target
        # A destination NAT above a source NAT that matches what it produces, and the other way round.
        report = Report()
        cli.convert(_nat_policy(inbound, masquerade, unrelated), target, report)
        (found,) = [f for f in report.item("nat", "inbound").findings if f.code == "NAT_ORDER"]
        assert "NAT rule 'masq' translates the source of that traffic as well" in found.message, target
        assert "NAT_ORDER" not in [f.code for f in report.item("nat", "unrelated").findings], target
        report = Report()
        cli.convert(_nat_policy(masquerade, inbound), target, report)
        assert "NAT_ORDER" in [f.code for f in report.item("nat", "inbound").findings], target
    # Both targets keep one first-match rulebase: nothing to say.
    for target in ("panos", "checkpoint"):
        report = Report()
        cli.convert(_nat_policy(exempt, dnat, masquerade), target, report)
        assert not any(f.code == "NAT_ORDER" for item in report.items.values() for f in item.findings), target
        assert "NAT_ORDER" not in [n.code for n in report.notes]


def test_nat_order_read_from_iptables() -> None:
    text = (
        "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n"
        "-A PREROUTING -i eth0 -d 203.0.113.10/32 -j DNAT --to-destination 10.20.0.10\n"
        "-A POSTROUTING -o eth2 -j MASQUERADE\nCOMMIT\n*filter\n:FORWARD DROP [0:0]\nCOMMIT\n"
    )
    for target, expected in (("panos", True), ("checkpoint", True), ("iptables", False), ("fortios", False)):
        report = Report()
        options = Options(nat_zone="eth0", target_gateway="gw", interface_map={"eth2": "ethernet1/2"})
        cli.convert(parse_iptables.parse(text.encode(), report), target, report, options)
        notes = [n for n in report.notes if n.code == "NAT_ORDER"]
        assert bool(notes) == expected, target
        assert not any(f.code == "NAT_ORDER" for item in report.items.values() for f in item.findings), target
        assert all(n.severity.name == "APPROX" and "destination translation only" in n.message for n in notes)


def test_rule_that_translates_destination_and_source() -> None:
    both = _nat("both", src_zones=["trust"], dst_zones=["untrust"], sources=["lan"], destinations=["pub"], service="https",
                destination_translation=DestNat("web", "8443"),
                source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["10.20.0.1"]))  # fmt: skip
    report = Report()
    out = cli.convert(_nat_policy(both), "iptables", report)
    assert "-A PREROUTING -i trust -s 10.10.0.0/16 -d 203.0.113.10/32 -p tcp -m tcp --dport 443" in out
    # After the destination NAT the packet goes to the new address and port, by whatever interface leads there.
    (post,) = [line for line in out.splitlines() if line.startswith("-A POSTROUTING")]
    assert post.startswith("-A POSTROUTING -s 10.10.0.0/16 -d 10.20.0.10/32 -p tcp -m tcp --dport 8443 ")
    assert "NAT_OUTPUT_INTERFACE" in [f.code for f in report.item("nat", "both").findings]
    report = Report()
    forti = FortiConfig(cli.convert(_nat_policy(both), "fortios", report))
    assert 'set dstintf "any"' in forti.text.split("config firewall central-snat-map")[1]
    assert "NAT_OUTPUT_INTERFACE" in [f.code for f in report.item("nat", "both").findings]


def test_disabled_nat_rule_is_a_comment_and_the_report_says_so() -> None:
    off = _nat("off", sources=["lan"], enabled=False, source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.7"]))
    report = Report()
    out = cli.convert(_nat_policy(off), "iptables", report)
    assert "# disabled in the source: -A POSTROUTING" in out
    item = report.item("nat", "off")
    assert item.emitted_as == [] and [f.code for f in item.findings] == ["NAT_DISABLED"]


def test_report_holds_one_line_per_finding_whatever_the_input_says() -> None:
    report = Report()
    report.add("address", "odd\nname", Severity.REVIEW, "X", "type 'a\n  [exact] everything is fine' cannot be read")
    report.note(Severity.INFO, "Y", "first\nsecond")
    report.add("address", "odd_name", Severity.INFO, "Z", "the same object under its cleaned name")
    assert report.counts("address")["total"] == 1
    text = report.to_text()
    assert "\n  [exact]" not in text and "first second" in text
    assert len([line for line in text.splitlines() if "odd_name" in line]) == 1


# -- the real thing, where the test host allows it ---------------------------------------------------


def _kernel(text: str, family: int = 4) -> "subprocess.CompletedProcess[bytes]":
    """Load a ruleset into netfilter in a network namespace of its own, and save it again."""
    tool = "iptables" if family == 4 else "ip6tables"
    command = ["unshare", "-n", "sh", "-c", f"{tool}-restore && {tool}-save"]
    return subprocess.run(command, input=text.encode(), capture_output=True, timeout=30)


def _kernel_available() -> bool:
    if not (shutil.which("unshare") and shutil.which("iptables-restore") and shutil.which("ip6tables-restore")):
        return False
    try:
        return _kernel("*filter\n:FORWARD DROP [0:0]\nCOMMIT\n").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_kernel = pytest.mark.skipif(not _kernel_available(), reason="needs root, unshare and iptables on Linux")


@needs_kernel
def test_kernel_loads_what_is_emitted() -> None:
    """Every emitted ruleset is accepted by iptables-restore, and what the kernel saves decides like the model."""
    for seed in range(12):
        rng = random.Random(seed)
        model = random_model(rng)
        for family, target in ((4, "iptables"), (6, "ip6tables")):
            done = _kernel(cli.convert(model, target, Report()), family)
            assert done.returncode == 0, (seed, family, done.stderr.decode())
            saved = done.stdout.decode()
            for _ in range(200):
                pkt = random_packet(rng, family)
                assert iptables_allows(saved, pkt, family) == model_allows(model, pkt), (seed, family, pkt)


@needs_kernel
def test_parser_reads_what_the_kernel_saves() -> None:
    """A hand-written ruleset and the form iptables-save gives it are read to the same policy."""
    compared = 0
    for seed in range(30):
        rng = random.Random(seed)
        text = random_ruleset(rng)
        done = _kernel(text)
        assert done.returncode == 0, (seed, done.stderr.decode())
        written = parse_iptables.parse(text.encode(), Report())
        saved = parse_iptables.parse(done.stdout, Report())
        assert saved.scope == "IPv4"
        assert [bool(r.unsupported) for r in written.rules] == [bool(r.unsupported) for r in saved.rules], seed
        if any(r.unsupported for r in written.rules):
            continue
        compared += 1
        for _ in range(200):
            pkt = random_packet(rng)
            assert model_allows(saved, pkt) == model_allows(written, pkt), (seed, pkt)
    assert compared >= 20, compared


@needs_kernel
@pytest.mark.parametrize("source", ["panos_sample.xml", "checkpoint_sample.json", "iptables_sample.rules"])
def test_kernel_loads_the_converted_samples(source: str) -> None:
    for family, target in ((4, "iptables"), (6, "ip6tables")):
        text, _ = run(source, target)
        done = _kernel(text, family)
        assert done.returncode == 0, (source, target, done.stderr.decode())
        assert b":FORWARD" in done.stdout


# -- found in the third review round ---------------------------------------------------------------


def test_mask_that_is_not_a_network_mask() -> None:
    assert parse_literal("0.0.2.34/0.0.255.255") is None and parse_literal("10.0.0.0/255.0.255.0") is None
    assert parse_literal("10.0.0.0/255.255.0.0") == parse_literal("10.0.0.0/16")
    text = rules_of("-A FORWARD -s 0.0.2.34/0.0.255.255 -j DROP\n-A FORWARD -j ACCEPT")
    report = Report()
    drop, accept = parse_iptables.parse(text.encode(), report).rules
    assert drop.unsupported and not accept.unsupported  # never a network the source did not mean
    forti = 'config firewall address\n    edit "odd"\n        set subnet 10.1.2.3 0.0.255.255\n    next\nend\n'
    assert cli.load(forti.encode(), "fortios", Report()).addresses["odd"].kind == AddressKind.UNSUPPORTED


def test_two_matches_of_one_kind_must_both_hold() -> None:
    text = rules_of(
        "-A FORWARD -p icmp -m icmp --icmp-type 8 -m icmp --icmp-type 13 -j ACCEPT\n"
        "-A FORWARD -m conntrack --ctstate NEW,RELATED -m conntrack --ctstate NEW,ESTABLISHED -p tcp --dport 22 -j ACCEPT\n"
        "-A FORWARD -m conntrack --ctstate NEW -m state --state ESTABLISHED -j ACCEPT"
    )
    icmp, both, never = parse_iptables.parse(text.encode(), Report()).rules
    assert icmp.unsupported == ["second ICMP type match 13"]
    assert not both.unsupported and both.services == ["tcp-22"]  # NEW is in both lists
    assert never.unsupported == ["two connection state matches that exclude each other"]


def test_nat_order_shapes_found_with_the_kernel() -> None:
    static = _nat("static", src_zones=["dmz"], dst_zones=["untrust"], sources=["web"],
                  source_translation=SourceNat(SnatKind.STATIC, ["pub"], bidirectional=True))  # fmt: skip
    exempt = _nat("exempt", src_zones=["untrust"], dst_zones=["untrust"], sources=["partner"], destinations=["pub"])
    nonat = _nat("dmz-nonat", src_zones=["trust"], sources=["lan"], destinations=["10.20.0.0/24"])
    uturn = _nat("uturn", src_zones=["trust"], dst_zones=["untrust"], sources=["lan"], destinations=["pub"],
                 destination_translation=DestNat("web"), source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["10.20.0.1"]))  # fmt: skip
    pub1 = _nat("pub1", dst_zones=["untrust"], destinations=["pub"], destination_translation=DestNat("web"))
    uturn2 = _nat("uturn2", src_zones=["trust"], dst_zones=["untrust"], sources=["lan"], destinations=["203.0.113.11"],
                  destination_translation=DestNat("web"), source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["10.20.0.1"]))  # fmt: skip
    masquerade = _nat("masq", src_zones=["trust"], dst_zones=["untrust"], sources=["lan"],
                      source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.7"]))  # fmt: skip
    to_dmz = _nat("to-dmz", dst_zones=["dmz"], destinations=["10.20.0.99"], destination_translation=DestNat("web"))

    def findings(target: str, *rules: NatRule) -> "dict[str, str]":
        report = Report()
        cli.convert(_nat_policy(*copy.deepcopy(list(rules))), target, report)
        return {rule.name: " ".join(f.message for f in report.item("nat", rule.name).findings if f.code == "NAT_ORDER")
                for rule in rules}  # fmt: skip

    for target in ("iptables", "fortios"):
        # A no-NAT rule above a bi-directional static NAT: its inbound half is a destination translation too.
        assert "'exempt'" in findings(target, exempt, static)["static"], target
        # A rule that matches the translated address stands before the source half of a later rule.
        assert "'dmz-nonat' above this one matches first" in findings(target, nonat, uturn)["uturn"], target
        # A destination-only rule and a later rule that translates source and destination to the same server.
        # iptables ties the source half of the later rule to its own original destination; FortiOS cannot.
        expected = "" if target == "iptables" else "NAT rule 'uturn2' translates the source of that traffic as well"
        assert expected in findings(target, pub1, uturn2)["pub1"] and bool(findings(target, pub1, uturn2)["pub1"]) == bool(expected)
        # Different destination zones: the two never met on the source, and do not here.
        assert findings(target, masquerade, to_dmz) == {"masq": "", "to-dmz": ""}, target
        # Rules the source applied together (Check Point automatic rules) keep doing so.
        inbound, hide = copy.deepcopy(pub1), copy.deepcopy(masquerade)
        inbound.combines = hide.combines = True
        hide.src_zones = hide.dst_zones = inbound.dst_zones = [ANY]
        assert findings(target, inbound, hide) == {"pub1": "", "masq": ""}, target
        hide.combines = False  # a manual rule below an automatic one is first match again
        assert "NAT rule 'masq' translates the source" in findings(target, inbound, hide)["pub1"], target


def test_prerouting_accept_is_not_a_rule_without_nat() -> None:
    text = (
        "*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n"
        "-A PREROUTING -s 10.10.0.0/16 -j ACCEPT\n"
        "-A PREROUTING -d 203.0.113.10/32 -j DNAT --to-destination 10.20.0.10\n"
        "-A POSTROUTING -s 10.10.0.0/16 -o eth0 -j SNAT --to-source 198.51.100.7\n"
        "-A POSTROUTING -s 10.10.0.0/16 -d 10.99.0.0/16 -j ACCEPT\nCOMMIT\n*filter\n:FORWARD DROP [0:0]\nCOMMIT\n"
    )
    for target in ("panos", "checkpoint", "fortios", "iptables"):
        report = Report()
        policy = parse_iptables.parse(text.encode(), report)
        only_dnat, dnat, snat, exempt = policy.nat_rules
        cli.convert(policy, target, report, Options(nat_zone="eth0"))
        # In PREROUTING it stops the destination NAT only; a no-NAT rule on top of a rulebase stops everything.
        assert report.item("nat", only_dnat.origin).skipped and "PREROUTING ACCEPT" in only_dnat.unsupported[0], target
        assert not report.item("nat", snat.origin).skipped and not exempt.unsupported, target


def test_source_half_of_a_rule_that_translates_both_is_tied_to_the_original_destination() -> None:
    both = _nat("both", src_zones=["trust"], dst_zones=["untrust"], sources=["lan"], destinations=["pub"], service="https",
                destination_translation=DestNat("web", "8443"),
                source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["10.20.0.1"]))  # fmt: skip
    report = Report()
    out = cli.convert(_nat_policy(both), "iptables", report)
    (post,) = [line for line in out.splitlines() if line.startswith("-A POSTROUTING")]
    assert "-m conntrack --ctorigdst 203.0.113.10/32" in post  # not traffic sent to the server directly
    assert "NAT_AFTER_DNAT" not in [f.code for f in report.item("nat", "both").findings]
    ranged = copy.deepcopy(both)
    ranged.destinations = ["203.0.113.10-203.0.113.12"]
    ranged.destination_translation = DestNat("10.20.0.10-10.20.0.12", "8443")
    report = Report()
    out = cli.convert(_nat_policy(ranged), "iptables", report)
    assert "ctorigdst" not in out and "NAT_AFTER_DNAT" in [f.code for f in report.item("nat", "both").findings]
    report = Report()
    cli.convert(_nat_policy(both), "fortios", report)
    assert "NAT_AFTER_DNAT" in [f.code for f in report.item("nat", "both").findings]  # central SNAT cannot tell


@needs_kernel
def test_kernel_loads_nat_rules_written_for_it() -> None:
    both = _nat("both", src_zones=["trust"], dst_zones=["untrust"], sources=["lan"], destinations=["pub"], service="https",
                destination_translation=DestNat("web", "8443"),
                source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["10.20.0.1"]))  # fmt: skip
    static = _nat("static", src_zones=["dmz"], dst_zones=["untrust"], sources=["web"],
                  source_translation=SourceNat(SnatKind.STATIC, ["pub"], bidirectional=True))  # fmt: skip
    done = _kernel(cli.convert(_nat_policy(both, static), "iptables", Report()))
    assert done.returncode == 0, done.stderr.decode()
    assert b"--ctorigdst 203.0.113.10" in done.stdout and b"-j SNAT --to-source 10.20.0.1" in done.stdout


def test_rule_names_that_differ_only_in_control_characters() -> None:
    p = Policy(vendor="panos")
    for name in ("r\n1", "r_1"):
        rule = Rule(name)
        rule.origin = name
        p.rules.append(rule)
    with pytest.raises(FwshiftError, match="share the name 'r_1'"):
        cli.convert(p, "fortios", Report())


# -- found in the fourth review round --------------------------------------------------------------


def _order_findings(target: str, policy: Policy) -> "dict[str, str]":
    report = Report()
    cli.convert(copy.deepcopy(policy), target, report)
    return {nat.name: " ".join(f.message for f in report.item("nat", nat.name).findings if f.code == "NAT_ORDER")
            for nat in policy.nat_rules}  # fmt: skip


def _allow(name: str, src: str, dst: str, destination: str) -> Rule:
    rule = Rule(name, src_zones=[src], dst_zones=[dst], destinations=[destination])
    rule.origin = name
    return rule


def test_nat_order_goes_by_where_the_translated_traffic_leaves() -> None:
    hide_dmz = _nat("hide-dmz", src_zones=["trust"], dst_zones=["dmz"], sources=["lan"],
                    source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["10.20.0.1"]))  # fmt: skip
    dnat = _nat("dnat", dst_zones=["untrust"], destinations=["pub"], destination_translation=DestNat("web"))
    for target in ("iptables", "fortios"):
        # The hide rule is for traffic to the DMZ. On the source it never met traffic for the public address,
        # which lies in untrust; on the target that traffic arrives in the DMZ with the new destination.
        policy = _nat_policy(hide_dmz, dnat)
        policy.rules = [_allow("web-in", "trust", "dmz", "pub")]
        assert "NAT rule 'hide-dmz' translates the source" in _order_findings(target, policy)["dnat"], target
        # The rule that names the address points elsewhere; the one that lets the traffic in names no address.
        policy = _nat_policy(dnat, hide_dmz)
        policy.rules = [_allow("named", "trust", "untrust", "203.0.113.0/24"), _allow("open", "trust", "dmz", ANY)]
        assert "NAT rule 'hide-dmz' translates the source" in _order_findings(target, policy)["dnat"], target
        # Nothing lets it into the DMZ: the entry bound to the DMZ is not reached.
        policy.rules = [_allow("named", "trust", "untrust", "203.0.113.0/24")]
        assert _order_findings(target, policy) == {"dnat": "", "hide-dmz": ""}, target


def test_nat_order_sees_a_rule_without_nat_that_stands_in_front() -> None:
    dnat = _nat("dnat", destinations=["pub"], destination_translation=DestNat("web"))
    nonat = _nat("dmz-nonat", sources=["lan"], destinations=["10.20.0.0/24"])
    masquerade = _nat("masq", sources=["lan"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.7"]))
    partial = _nat("partial", sources=["10.10.1.0/24"], destinations=["10.20.0.0/24"])
    for target in ("iptables", "fortios"):
        assert _order_findings(target, _nat_policy(dnat, nonat, masquerade)) == {"dnat": "", "dmz-nonat": "", "masq": ""}
        # A rule without NAT for a part of the sources leaves the rest to the source NAT below it.
        assert "'masq'" in _order_findings(target, _nat_policy(dnat, partial, masquerade))["dnat"], target


def test_nat_order_is_reported_once_on_the_side_with_fewer_rules() -> None:
    forward = _nat("forward", destinations=["pub"], destination_translation=DestNat("web"))
    hides = [_nat(f"hide-{n}", sources=[f"10.{n}.0.0/16"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.7"]))
             for n in range(1, 6)]  # fmt: skip
    found = _order_findings("fortios", _nat_policy(forward, *hides))
    assert "'hide-1', 'hide-2', 'hide-3' and 2 more translate the source" in found["forward"]
    assert not any(found[hide.name] for hide in hides)
    forwards = [_nat(f"fwd-{n}", destinations=[f"203.0.113.{n}"], destination_translation=DestNat(f"10.20.0.{n}"))
                for n in range(1, 6)]  # fmt: skip
    found = _order_findings("fortios", _nat_policy(*forwards, hides[0]))
    assert "'fwd-1' (to 10.20.0.1), 'fwd-2' (to 10.20.0.2), 'fwd-3' (to 10.20.0.3) and 2 more" in found["hide-1"]
    assert not any(found[rule.name] for rule in forwards)


def test_nat_rule_below_one_that_is_not_converted() -> None:
    exempt = _nat("exempt", sources=["site"], destinations=["pub"])  # a host name: iptables NAT cannot match it
    dnat = _nat("dnat", destinations=["pub"], destination_translation=DestNat("web"))
    other = _nat("other", destinations=["203.0.113.99"], destination_translation=DestNat("web"))
    policy = _nat_policy(exempt, dnat, other)
    policy.addresses["site"] = Address("site", AddressKind.FQDN, "partner.example.com")
    report = Report()
    cli.convert(policy, "iptables", report)
    assert report.item("nat", "exempt").skipped
    (found,) = [f for f in report.item("nat", "dnat").findings if f.code == "NAT_ORDER"]
    assert found.severity == Severity.REVIEW and "'exempt' above this one is not converted" in found.message
    assert not [f for f in report.item("nat", "other").findings if f.code == "NAT_ORDER"]


def test_dnat_to_a_range_is_not_address_for_address() -> None:
    """The kernel picks one address of the range per connection: a rule for one of them stood for the whole network."""
    text = (
        "*nat\n:PREROUTING ACCEPT [0:0]\n"
        "-A PREROUTING -d 198.51.100.0/24 -j DNAT --to-destination 10.20.0.0-10.20.0.255\nCOMMIT\n"
        "*filter\n:FORWARD DROP [0:0]\n-A FORWARD -d 10.20.0.10/32 -p tcp --dport 443 -j ACCEPT\nCOMMIT\n"
    )
    report = Report()
    p = parse_iptables.parse(text.encode(), report)
    assert p.nat_rules[0].destination_translation == DestNat("10.20.0.0-10.20.0.255", "", spread=True)
    finding = next(f for f in report.item("rule", p.rules[0].origin).findings if f.code == "NAT_DESTINATION_WIDENED")
    assert finding.severity == Severity.REVIEW and p.rules[0].destinations == ["10.20.0.10/32", "198.51.100.0/24"]
    # To one address there is nothing to pick.
    report = Report()
    p = parse_iptables.parse(text.replace("10.20.0.0-10.20.0.255", "10.20.0.10").encode(), report)
    assert not p.nat_rules[0].destination_translation.spread  # type: ignore[union-attr]
    assert [f.code for f in report.item("rule", p.rules[0].origin).findings] == ["NAT_DESTINATION_REWRITTEN"]
