# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cisco PIX 6.x (source only): configurations read into the model, trap by trap, and packets through both.

The random configurations at the end are judged by ``pix_allows``, which decides from the generator's own data
(interfaces and security levels, statics, nat and global statements, access lists, conduits) and shares no code with
the parser. Both are written from the same reading of Cisco's documentation (DEVELOPMENT.md): they find where the parser
disagrees with that reading, not where the reading is wrong.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import Packet, _entry_matches, _member_matches

from fwshift import cli, transform
from fwshift.errors import ParseError
from fwshift.model import ANY, ANY_V4, Action, Policy, Rule, RuleScope, SnatKind
from fwshift.netutil import parse_literal
from fwshift.parsers import pix as parse_pix
from fwshift.report import Report


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_pix.parse(text.encode(), report), report


def codes(report: Report, kind: str = "", name: str = "") -> List[str]:
    return [f.code for f in (report.item(kind, name).findings if name else report.notes)]


def rule(p: Policy, name: str) -> Rule:
    return next(r for r in p.rules if r.name == name)


HEAD = """\
PIX Version 6.3(5)
nameif ethernet0 outside security0
nameif ethernet1 inside security100
nameif ethernet2 dmz security50
nameif ethernet3 partner security20
ip address outside 203.0.113.2 255.255.255.0
ip address inside 10.10.0.1 255.255.0.0
ip address dmz 10.20.0.1 255.255.255.0
ip address partner 10.30.0.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 203.0.113.1 1
"""


# -- the sample ----------------------------------------------------------------------------------------------


def test_sample_rules() -> None:
    p, report = parse((DATA / "pix_sample.cfg").read_text())
    assert p.vendor == "pix" and p.scope == "PIX Version 6.3(5)" and not p.lookup_after_dnat
    assert set(p.zones) == {"outside", "inside", "dmz", "lab", "partner"} and p.zones["dmz"].interfaces == ["ethernet2"]
    # Access lists name the global addresses; the destination zone is the interface behind the static.
    first = rule(p, "outside_in-1")
    assert first.destinations == ["203.0.113.10"] and first.dst_zones == ["dmz"] and first.sources == [ANY_V4]
    assert rule(p, "outside_in-3").destinations == ["outside-interface"] and rule(p, "outside_in-3").dst_zones == ["dmz"]
    assert p.addresses["outside-interface"].raw == "interface outside"
    assert "PIX_TRANSLATION_REQUIRED" in codes(report, "rule", "outside_in-6")  # the real address: nothing publishes it
    assert "PIX_TRANSLATION_REQUIRED" not in codes(report, "rule", "outside_in-1")
    assert rule(p, "outside_in-5").action == Action.DROP and rule(p, "outside_in-5").log_end
    assert "PIX_TRANSLATION_REQUIRED" not in codes(report, "rule", "dmz_in-3")  # published by an identity static
    # The inside has no access list: implicit rules, for the sources a translation covers.
    assert rule(p, "implicit-inside-outside").sources == [ANY_V4]
    assert rule(p, "implicit-inside-partner").sources == ["10.10.0.0/16"]
    assert not any(r.name == "implicit-inside-lab" for r in p.rules) and "PIX_NO_TRANSLATION" in codes(report)
    assert rule(p, "implicit-partner-outside").unsupported and "PIX_OUTBOUND" in codes(report)
    # Conduits: global address first, for the interfaces without an access list.
    conduit = rule(p, "conduit-1")
    assert conduit.sources == ["10.30.0.0/24"] and conduit.destinations == ["10.10.0.60"] and conduit.services == ["tcp-3389"]
    assert conduit.src_zones == ["lab", "partner"] and conduit.dst_zones == ["inside"]
    assert "PIX_TRANSLATION_REQUIRED" in codes(report, "rule", "conduit-1")  # (from lab no static publishes it)
    assert rule(p, "conduit-3").action == Action.DROP
    assert "PIX_CONDUIT_IGNORED" in codes(report)
    for code in ("PIX_FIXUP", "PIX_ESTABLISHED", "VPN_BYPASS", "ICMP_STATELESS", "UNBOUND_ACL", "EGRESS_BY_ROUTE"):
        assert code in codes(report), code


def test_sample_nat() -> None:
    p, report = parse((DATA / "pix_sample.cfg").read_text())
    order = [n.name for n in p.nat_rules]
    assert order == ["nat0-inside-1", "static-1", "static-2", "static-4", "static-5", "static-3", "nat3-inside-1",
                     "nat2-inside", "nat1-inside-outside", "nat1-inside-dmz", "nat1-partner"]  # fmt: skip
    nats = {n.name: n for n in p.nat_rules}
    assert nats["nat0-inside-1"].source_translation is None and nats["nat0-inside-1"].destinations == ["10.99.0.0/16"]
    static = nats["static-1"].source_translation
    assert static is not None and static.kind == SnatKind.STATIC and static.addresses == ["203.0.113.10"] and static.bidirectional
    assert nats["static-1"].src_zones == ["dmz"] and nats["static-1"].dst_zones == ["outside"]
    assert nats["static-4"].source_translation is None  # identity
    port = nats["static-3"]
    assert port.src_zones == port.dst_zones == ["outside"] and port.destinations == ["outside-interface"]
    assert port.destination_translation is not None and (port.destination_translation.address, port.destination_translation.port) == ("10.20.0.30", "443")
    pool = nats["nat2-inside"].source_translation
    assert pool is not None and pool.kind == SnatKind.DYNAMIC and pool.addresses == ["203.0.113.100-203.0.113.150"]
    assert "PIX_PAT_FALLBACK" in codes(report, "nat", "nat2-inside")
    interface = nats["nat1-inside-outside"].source_translation
    assert interface is not None and interface.kind == SnatKind.INTERFACE and interface.interface_address == "203.0.113.2"
    assert all(n.combines for n in p.nat_rules)
    # partner (20) is below dmz (50): nat (partner) 1 does not apply towards global (dmz) 1.
    assert nats["nat1-partner"].dst_zones == ["outside"]


# -- traps, one by one ---------------------------------------------------------------------------------------


def test_access_group_overrides_conduits_and_outbound_lists() -> None:
    p, report = parse(HEAD + """\
nat (inside) 1 0.0.0.0 0.0.0.0
global (outside) 1 interface
static (dmz,outside) 203.0.113.10 10.20.0.10 netmask 255.255.255.255
access-list in permit tcp any host 203.0.113.10 eq www
access-group in in interface outside
conduit permit tcp host 203.0.113.10 eq smtp any
outbound 5 deny 0 0 0
apply (outside) 5 outgoing_src
apply (inside) 5 outgoing_dest
""")
    assert [r.name for r in p.rules if r.src_zones == ["outside"]] == ["in-1"]
    # The conduit is for an address published to the outside only; there it is overridden by the access list.
    assert not any(r.name.startswith("conduit") for r in p.rules) and "RULE_WITHOUT_EFFECT" in codes(report)
    assert rule(p, "implicit-inside-outside").unsupported  # an outbound list applies to inside
    assert "PIX_CONDUIT_IGNORED" in codes(report)


def test_conduit_order_of_addresses() -> None:
    p, _ = parse(HEAD + """\
static (dmz,outside) 203.0.113.0 10.20.0.0 netmask 255.255.255.0
conduit permit tcp 203.0.113.0 255.255.255.0 range 8000 8010 host 198.51.100.7 gt 1023
conduit permit udp host 203.0.113.5 eq domain any
""")
    first = rule(p, "conduit-1")
    assert first.sources == ["198.51.100.7"] and first.destinations == ["203.0.113.0/24"]
    entry = p.services[first.services[0]].entries[0]
    assert entry.dst_ports == "8000-8010" and entry.src_ports == "1024-65535"
    assert first.src_zones == ["outside"] and first.dst_zones == ["dmz"]
    assert rule(p, "conduit-2").destinations == ["203.0.113.5"]


def test_implicit_rules_follow_the_translations() -> None:
    p, report = parse(HEAD + """\
nat (inside) 1 0.0.0.0 0.0.0.0
nat (inside) 2 10.10.10.0 255.255.255.0
global (outside) 1 interface
global (outside) 2 203.0.113.100-203.0.113.110
global (dmz) 1 10.20.0.200
nat (dmz) 0 10.20.0.0 255.255.255.0
""")
    assert rule(p, "implicit-inside-outside").sources == [ANY_V4]
    # nat 2 matches 10.10.10.0/24 best and has no global on dmz: those sources do not get there.
    assert rule(p, "implicit-inside-dmz").sources == ["0.0.0.0-10.10.9.255", "10.10.11.0-255.255.255.255"]
    assert rule(p, "implicit-dmz-outside").sources == ["10.20.0.0/24"]  # identity nat 0
    assert not any(r.name.startswith("implicit-partner") for r in p.rules)
    assert "PIX_NO_TRANSLATION" in codes(report)


def test_permits_beyond_the_translations_are_reported() -> None:
    p, report = parse(HEAD + """\
static (inside,outside) 203.0.113.50 10.10.0.50 netmask 255.255.255.255
access-list out permit tcp any host 203.0.113.50 eq https
access-list out permit tcp any host 10.10.0.50 eq https
access-list out permit tcp any any eq ssh
access-group out in interface outside
access-list dmz permit tcp any any eq www
access-group dmz in interface dmz
nat (inside) 0 access-list nonat
access-list nonat permit ip 10.10.0.0 255.255.0.0 10.30.0.0 255.255.255.0
access-list part permit tcp 10.30.0.0 255.255.255.0 host 10.10.0.9 eq 22
access-list part permit tcp 10.30.0.0 255.255.255.0 host 10.20.0.9 eq 22
access-group part in interface partner
""")
    assert rule(p, "out-1").dst_zones == ["inside"] and "PIX_TRANSLATION_REQUIRED" not in codes(report, "rule", "out-1")
    assert rule(p, "out-2").dst_zones == ["inside"] and "PIX_TRANSLATION_REQUIRED" in codes(report, "rule", "out-2")
    assert "PIX_TRANSLATION_REQUIRED" in codes(report, "rule", "out-3")
    assert "PIX_TRANSLATION_REQUIRED" in codes(report, "rule", "dmz-1")  # dmz has no nat towards outside
    assert "PIX_TRANSLATION_REQUIRED" not in codes(report, "rule", "part-1")  # the exemption publishes it
    assert "PIX_TRANSLATION_REQUIRED" in codes(report, "rule", "part-2")


def test_nat_statements() -> None:
    p, report = parse(HEAD + """\
access-list pol permit ip 10.10.20.0 255.255.255.0 198.51.100.0 255.255.255.0
access-list pol permit tcp 10.10.21.0 255.255.255.0 198.51.100.0 255.255.255.0 eq www
access-list ex permit ip host 10.10.0.5 any
access-list ex deny ip host 10.10.0.6 any
access-list ex permit ip 10.10.0.0 255.255.255.0 any
access-list ps permit ip host 10.20.0.7 198.51.100.0 255.255.255.0
nat (inside) 0 access-list ex
nat (inside) 4 access-list pol
global (outside) 4 203.0.113.200
global (outside) 5 203.0.113.201
nat (inside) 9 10.10.30.0 255.255.255.0 dns 100 50
nat (partner) 1 10.30.0.0 255.255.255.0 outside
static (dmz,outside) 203.0.113.7 access-list ps
static (dmz,outside) udp 203.0.113.8 domain 10.20.0.8 domain netmask 255.255.255.255
static (dmz,outside) 203.0.113.16 10.20.0.17 netmask 255.255.255.240
""")
    nats = {n.name: n for n in p.nat_rules}
    assert not nats["nat0-inside-1"].unsupported and nats["nat0-inside-2"].unsupported and nats["nat0-inside-3"].unsupported
    assert nats["nat4-inside-2"].service == "tcp-80" and nats["nat4-inside-1"].service == ANY
    assert nats["nat4-inside-1"].dst_zones == ["outside"] and nats["nat4-inside-1"].destinations == ["198.51.100.0/24"]
    assert nats["nat9-inside"].unsupported  # no global 9
    assert nats["nat1-partner"].unsupported  # outside NAT
    policy_static = nats["static-1"]
    assert policy_static.destinations == ["198.51.100.0/24"] and "NAT_REVERSE_DIRECTION" in codes(report, "nat", "static-1")
    dns = nats["static-2"]
    assert dns.destination_translation is not None and dns.destination_translation.port == ""
    assert nats["static-3"].unsupported  # host bits under the netmask
    assert "PIX_GLOBAL_UNUSED" in codes(report)


def test_names_interfaces_and_any() -> None:
    p, _ = parse(HEAD.replace("PIX Version 6.3(5)\n", "PIX Version 6.2(2)\nnames\nname 10.20.0.10 web\n") + """\
static (dmz,outside) tcp interface www web www netmask 255.255.255.255
access-list in permit tcp any interface outside eq www
access-list in permit tcp any interface lab eq www
access-group in in interface outside
""")
    assert rule(p, "in-1").destinations == ["outside-interface"] and rule(p, "in-1").sources == [ANY_V4]
    assert rule(p, "in-2").unsupported  # no interface lab
    assert p.nat_rules[0].destination_translation is not None and p.nat_rules[0].destination_translation.address == "10.20.0.10"


def test_same_level_and_back_out_are_never_forwarded() -> None:
    p, report = parse(HEAD + """\
nameif ethernet4 dmz2 security50
ip address dmz2 10.21.0.1 255.255.255.0
access-list d permit ip any 10.21.0.0 255.255.255.0
access-list d permit ip any 10.20.0.0 255.255.255.0
access-group d in interface dmz
""")
    assert not any(r.name.startswith("d-") for r in p.rules)
    assert "RULE_WITHOUT_EFFECT" in codes(report)


def test_versions_and_detection() -> None:
    with pytest.raises(ParseError, match="--from asa"):
        parse("PIX Version 7.2(4)\ninterface Ethernet0\n nameif outside\n")
    with pytest.raises(ParseError, match="--from asa"):
        parse("ASA Version 9.12(4)\n")
    p, report = parse(HEAD.replace("PIX Version 6.3(5)\n", ""))
    assert "PIX_VERSION_ASSUMED" in codes(report) and set(p.zones) == {"outside", "inside", "dmz", "partner"}
    data = (DATA / "pix_sample.cfg").read_bytes()
    assert cli.detect_format(data) == "pix"
    assert cli.detect_format((DATA / "asa_sample.cfg").read_bytes()) == "asa"
    assert cli.detect_format(b"PIX Version 7.2(4)\ninterface Ethernet0\n nameif outside\n security-level 0\n") == "asa"
    assert cli.detect_format(b"nameif ethernet0 outside security0\nnameif ethernet1 inside security100\n") == "pix"
    for other in sorted(DATA.iterdir()):
        if other.is_file() and "_sample." in other.name and not other.name.startswith("pix"):
            text = other.read_bytes()[:1_000_000].decode("utf-8", errors="replace")
            assert not parse_pix.looks_like_pix(text), other.name


def test_commands_not_converted_are_reported() -> None:
    _, report = parse(HEAD + """\
aaa authentication include ftp inside 0 0 0 0 TACACS
filter url http 0 0 0 0
alias (inside) 10.10.0.9 203.0.113.9 255.255.255.255
established tcp 0 0 permitto tcp 6000
fixup protocol ftp 21
no fixup protocol smtp 25
""")
    assert {"PIX_NOT_CONVERTED", "PIX_ESTABLISHED", "PIX_FIXUP"} <= set(codes(report))


def test_converts_to_targets(tmp_path) -> None:  # type: ignore[no-untyped-def]
    for target in ("asa", "panos", "junos", "iptables"):
        out = tmp_path / f"out.{target}"
        assert cli.main(["convert", str(DATA / "pix_sample.cfg"), "--to", target, "-o", str(out), "-q"]) == 0
        assert out.read_text(encoding="utf-8")


# -- a PIX made up at random, judged without the parser ------------------------------------------------------

LEVELS = {"outside": 0, "partner": 20, "dmz": 50, "inside": 100}
NETWORKS = {"inside": "10.10.0.0/16", "dmz": "10.20.0.0/24", "partner": "10.30.0.0/24", "outside": "203.0.113.0/24"}
ADDRESSES = [("host 203.0.113.10", "203.0.113.10/32"), ("203.0.113.16 255.255.255.240", "203.0.113.16/28"),
             ("host 10.20.0.10", "10.20.0.10/32"), ("10.10.0.0 255.255.0.0", "10.10.0.0/16"),
             ("host 10.10.0.50", "10.10.0.50/32"), ("10.30.0.0 255.255.255.0", "10.30.0.0/24"),
             ("host 198.51.100.7", "198.51.100.7/32"), ("10.10.10.0 255.255.255.0", "10.10.10.0/24"),
             ("any", "0.0.0.0/0"), ("any", "0.0.0.0/0")]  # fmt: skip
SERVICES = [("tcp", "eq www", "80-80"), ("tcp", "range 8000 8010", "8000-8010"), ("udp", "eq domain", "53-53"),
            ("tcp", "gt 1023", "1024-65535"), ("icmp", "", ""), ("ip", "", "")]  # fmt: skip


@dataclass
class _Static:
    real_if: str
    mapped_if: str
    mapped: str  # network
    real: str


@dataclass
class _Entry:
    permit: bool
    protocol: str
    source: str
    destination: str
    ports: str  # first-last, or ""


@dataclass
class Lab:
    text: str
    statics: List[_Static]
    nats: List[Tuple[str, str, str]]  # (interface, id, network)
    globals_: List[Tuple[str, str]]  # (interface, id)
    exempt: List[Tuple[str, str, str]]  # (interface, source, destination)
    acls: Dict[str, List[_Entry]]  # interface -> entries
    conduits: List[_Entry] = field(default_factory=list)


def random_lab(rng: random.Random) -> Lab:
    lines = HEAD.splitlines()
    statics = [s for s in (_Static("dmz", "outside", "203.0.113.10/32", "10.20.0.10/32"),
                           _Static("dmz", "outside", "203.0.113.16/28", "10.20.0.16/28"),
                           _Static("inside", "dmz", "10.10.0.50/32", "10.10.0.50/32"),
                           _Static("inside", "partner", "10.10.0.0/16", "10.10.0.0/16")) if rng.random() < 0.6]  # fmt: skip
    for s in statics:
        mapped, length = s.mapped.split("/")
        mask = {"32": "255.255.255.255", "28": "255.255.255.240", "16": "255.255.0.0"}[length]
        lines.append(f"static ({s.real_if},{s.mapped_if}) {mapped} {s.real.split('/')[0]} netmask {mask}")
    nats = [n for n in (("inside", "1", "0.0.0.0/0"), ("inside", "2", "10.10.10.0/24"), ("dmz", "1", "10.20.0.0/24"),
                        ("partner", "1", "10.30.0.0/24"), ("dmz", "0", "10.20.0.0/24")) if rng.random() < 0.5]  # fmt: skip
    for interface, nat_id, network in nats:
        address, length = network.split("/")
        mask = {"0": "0.0.0.0", "24": "255.255.255.0"}[length]
        lines.append(f"nat ({interface}) {nat_id} {address} {mask}")
    globals_ = [g for g in (("outside", "1"), ("outside", "2"), ("dmz", "1"), ("partner", "1")) if rng.random() < 0.6]
    for interface, nat_id in globals_:
        lines.append(f"global ({interface}) {nat_id} " + ("interface" if interface == "outside" else NETWORKS[interface].replace("0/24", "200")))
    exempt: List[Tuple[str, str, str]] = []
    if rng.random() < 0.4:
        exempt.append(("inside", "10.10.0.0/16", "10.30.0.0/24"))
        lines += ["access-list nonat permit ip 10.10.0.0 255.255.0.0 10.30.0.0 255.255.255.0", "nat (inside) 0 access-list nonat"]

    def entry() -> Tuple[_Entry, str]:
        permit = rng.random() < 0.7
        protocol, port_words, ports = rng.choice(SERVICES)
        source, source_net = rng.choice(ADDRESSES)
        destination, destination_net = rng.choice(ADDRESSES)
        text = f"{'permit' if permit else 'deny'} {protocol} {source} {destination}" + (f" {port_words}" if port_words else "")
        return _Entry(permit, protocol, source_net, destination_net, ports), text

    acls: Dict[str, List[_Entry]] = {}
    for interface in LEVELS:
        if rng.random() < 0.5:
            acls[interface] = []
            for _ in range(rng.randint(1, 5)):
                found, text = entry()
                acls[interface].append(found)
                lines.append(f"access-list acl_{interface} {text}")
            lines.append(f"access-group acl_{interface} in interface {interface}")
    lab = Lab("", statics, nats, globals_, exempt, acls)
    for _ in range(rng.randint(0, 3)):
        found, text = entry()
        words = text.split()
        # A conduit names the global (destination) address first.
        source_words = 1 if words[2] == "any" else 2
        source = words[2 : 2 + source_words]
        rest = words[2 + source_words :]
        destination_words = 1 if rest[0] == "any" else 2
        lines.append(" ".join(["conduit"] + words[:2] + rest[:destination_words] + rest[destination_words:] + source))
        lab.conduits.append(found)
    lab.text = "\n".join(lines) + "\n"
    return lab


def _in(address: str, network: str) -> bool:
    a, n = parse_literal(address), parse_literal(network)
    assert a is not None and n is not None
    return n[1] <= a[1] <= n[2]


def _prefix(network: str) -> int:
    return int(network.split("/")[1])


def _matches(e: _Entry, pkt: Packet) -> bool:
    if not (_in(pkt.src, e.source) and _in(pkt.dst, e.destination)):
        return False
    if e.protocol == "ip":
        return True
    if e.protocol != pkt.proto:
        return False
    if not e.ports:
        return True
    low, high = e.ports.split("-")
    return int(low) <= pkt.dport <= int(high)


def egress_of(lab: Lab, pkt: Packet) -> str:
    """Where the PIX sends a packet: behind the static that publishes its destination where it arrives, else by route."""
    for s in lab.statics:
        if s.mapped_if == pkt.in_if and _in(pkt.dst, s.mapped):
            return s.real_if
    for interface, network in NETWORKS.items():
        if _in(pkt.dst, network):
            return interface
    return "outside"


def pix_allows(lab: Lab, pkt: Packet) -> bool:
    """What the made-up PIX does with a packet that opens a connection, from the generator's own data."""
    egress = egress_of(lab, pkt)
    level, other = LEVELS[pkt.in_if], LEVELS[egress]
    if egress == pkt.in_if or level == other:
        return False
    if pkt.in_if in lab.acls:
        found = next((e for e in lab.acls[pkt.in_if] if _matches(e, pkt)), None)
        if found is None or not found.permit:
            return False
    elif level < other:
        found = next((e for e in lab.conduits if _matches(e, pkt)), None)
        if found is None or not found.permit:
            return False
    # NAT is mandatory.
    if level > other:
        if any(s.real_if == pkt.in_if and s.mapped_if == egress and _in(pkt.src, s.real) for s in lab.statics):
            return True
        if any(i == pkt.in_if and _in(pkt.src, a) and _in(pkt.dst, b) for i, a, b in lab.exempt):
            return True
        own = sorted((n for n in lab.nats if n[0] == pkt.in_if and _in(pkt.src, n[2])), key=lambda n: -_prefix(n[2]))
        if not own:
            return False
        best = own[0]
        return best[1] == "0" or (egress, best[1]) in lab.globals_
    if any(s.real_if == egress and s.mapped_if == pkt.in_if and _in(pkt.dst, s.mapped) for s in lab.statics):
        return True
    return any(i == egress and _in(pkt.dst, a) and _in(pkt.src, b) for i, a, b in lab.exempt)


def deciding_rule(p: Policy, pkt: Packet) -> Optional[Rule]:
    """The first rule of the model that matches a packet (as ``test_iptables.model_verdict`` walks them)."""
    for r in p.rules:
        if not r.enabled or r.unsupported:
            continue
        if not ((ANY in r.src_zones or pkt.in_if in r.src_zones) and (ANY in r.dst_zones or pkt.out_if in r.dst_zones)):
            continue
        if r.scope == RuleScope.INTERZONE and pkt.in_if == pkt.out_if:
            continue
        if not any(_member_matches(p, m, pkt.src) for m in r.sources):
            continue
        if not any(_member_matches(p, m, pkt.dst) for m in r.destinations):
            continue
        if r.services != [ANY]:
            entries = [e for s in r.services for e in (transform.flatten_services(p, s) or [])]
            if not any(_entry_matches(e, pkt) for e in entries):
                continue
        return r
    return None


def random_packet(rng: random.Random) -> Packet:
    def address() -> str:
        return rng.choice(["203.0.113.10", "203.0.113.20", "203.0.113.2", "10.20.0.10", "10.20.0.20", "10.10.0.50",
                           "10.10.10.5", "10.10.3.3", "10.30.0.9", "198.51.100.7", "192.0.2.1"])  # fmt: skip

    return Packet(rng.choice(list(LEVELS)), "", address(), address(), rng.choice(["tcp", "tcp", "udp", "icmp", "47"]),
                  rng.choice([1024, 40000, 80]), rng.choice([80, 53, 8005, 22, 2000]), 8)  # fmt: skip


@pytest.mark.parametrize("seed", range(40))
def test_random_configurations_never_allow_more_without_a_finding(seed: int) -> None:
    rng = random.Random(seed)
    lab = random_lab(rng)
    p, report = parse(lab.text)
    assert not any(r.unsupported for r in p.rules), [(r.name, r.unsupported) for r in p.rules if r.unsupported]
    for _ in range(300):
        pkt = random_packet(rng)
        pkt.out_if = egress_of(lab, pkt)
        device = pix_allows(lab, pkt)
        found = deciding_rule(p, pkt)
        model = found is not None and found.action == Action.ALLOW
        if device:
            assert model, (pkt, found, lab.text)
        elif model:
            assert found is not None and "PIX_TRANSLATION_REQUIRED" in codes(report, "rule", found.origin), (pkt, found.name, lab.text)
