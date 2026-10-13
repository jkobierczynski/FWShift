# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""MikroTik RouterOS: parser, emitter, and packet-level equivalence between a script and the model.

The judge below walks RouterOS filter rules the way the router does (first match, jump and return, a built-in chain
that accepts what no rule decides). It is written apart from the parser and the emitter and shares no code with them.
"""

from __future__ import annotations

import copy
import random
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load, run
from test_iptables import Packet, model_verdict, random_model

from fwshift import cli
from fwshift.emitters import routeros as emit_routeros
from fwshift.errors import ParseError
from fwshift.model import ANY, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, Service
from fwshift.model import ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.netutil import parse_literal
from fwshift.options import Options
from fwshift.parsers import routeros as parse_routeros
from fwshift.report import Report, Severity

# -- the judge: a small RouterOS forward path -------------------------------------------------

_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "gre": 47, "sctp": 132}
_IGNORED = {"chain", "action", "comment", "disabled", "log", "log-prefix", "jump-target", "reject-with", "hw-offload",
            "address-list", "address-list-timeout"}  # fmt: skip


@dataclass
class Device:
    """Filter chains of one IP version, address lists and interface lists, read from terse or compact lines."""

    family: int
    chains: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    lists: Dict[str, List[str]] = field(default_factory=dict)
    if_lists: Dict[str, Dict[str, str]] = field(default_factory=dict)
    members: List[Tuple[str, str]] = field(default_factory=list)
    activate: bool = False

    @classmethod
    def read(cls, text: str, family: int = 4, activate: bool = False) -> "Device":
        device = cls(family, activate=activate)
        menu = ""
        ip = "ip" if family == 4 else "ipv6"
        for raw in re.sub(r"\\\n\s*", "", text).splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ":")):
                continue
            words = shlex.split(line)
            if words[0].startswith("/"):
                path = []
                while words and words[0] not in ("add", "set"):
                    path.append(words.pop(0).strip("/"))
                if not words:
                    menu = " ".join(path)
                    continue
                where = " ".join(path)
            else:
                where = menu
            verb = words[0]
            if verb != "add":
                continue
            args = dict(word.split("=", 1) for word in words[1:])
            if False:
                continue
            if where == f"{ip} firewall filter":
                device.chains.setdefault(args["chain"], []).append(args)
            elif where == f"{ip} firewall address-list":
                if args.get("disabled") != "yes":
                    device.lists.setdefault(args["list"], []).append(args["address"])
            elif where == "interface list":
                device.if_lists[args["name"]] = args
            elif where == "interface list member":
                device.members.append((args["list"], args["interface"]))
        return device

    def list_members(self, name: str) -> List[str]:
        out = [interface for list_name, interface in self.members if list_name == name]
        for other in [x for x in self.if_lists.get(name, {}).get("include", "").split(",") if x]:
            out += self.list_members(other)
        excluded = [i for x in self.if_lists.get(name, {}).get("exclude", "").split(",") if x for i in self.list_members(x)]
        return [i for i in out if i not in excluded]

    def _matches(self, rule: Dict[str, str], pkt: Packet) -> bool:
        for key, value in rule.items():
            if key in _IGNORED:
                continue
            negated = value.startswith("!")
            value = value[1:] if negated else value
            if key in ("in-interface", "out-interface"):
                hit = (pkt.in_if if key.startswith("in") else pkt.out_if) == value
            elif key in ("in-interface-list", "out-interface-list"):
                interface = pkt.in_if if key.startswith("in") else pkt.out_if
                hit = value == "all" or interface in self.list_members(value)
            elif key in ("src-address", "dst-address"):
                hit = _inside(pkt.src if key.startswith("src") else pkt.dst, value)
            elif key in ("src-address-list", "dst-address-list"):
                address = pkt.src if key.startswith("src") else pkt.dst
                hit = any(_inside(address, entry) for entry in self.lists.get(value, []))
            elif key == "protocol":
                number = _NUMBERS.get(value, int(value) if value.isdigit() else -1)
                hit = number == _NUMBERS.get(pkt.proto.replace("icmp6", "icmpv6"), int(pkt.proto) if pkt.proto.isdigit() else -2)
            elif key in ("dst-port", "src-port", "port"):
                if pkt.proto not in ("tcp", "udp"):
                    return False  # (the router takes a port match with these protocols only)
                ports = [pkt.dport] if key == "dst-port" else [pkt.sport] if key == "src-port" else [pkt.sport, pkt.dport]
                hit = any(_port_in(port, value) for port in ports)
            elif key == "icmp-options":
                kind, _, codes = value.partition(":")
                low, _, high = codes.partition("-")
                hit = pkt.icmp_type == int(kind) and int(low) <= 0 <= int(high or low)
            elif key == "connection-state":
                hit = pkt.state.lower() in value.split(",")
            else:
                raise AssertionError(f"the judge does not know {key}")
            if hit == negated:
                return False
        return True

    def verdict(self, pkt: Packet, chain: str = "forward", depth: int = 0) -> Optional[str]:
        assert depth < 10
        for rule in self.chains.get(chain, []):
            disabled = rule.get("disabled") == "yes"
            if disabled and not (self.activate and rule.get("comment", "").startswith("fwshift:")):
                continue
            if not self._matches(rule, pkt):
                continue
            action = rule.get("action", "accept")
            if action == "jump":
                found = self.verdict(pkt, rule["jump-target"], depth + 1)
                if found is not None:
                    return found
                continue
            if action == "return":
                return None
            if action in ("log", "passthrough", "fasttrack-connection", "add-src-to-address-list"):
                continue
            return action
        return None

    def allows(self, pkt: Packet) -> bool:
        return (self.verdict(pkt) or "accept") == "accept"


def _inside(address: str, literal: str) -> bool:
    a, b = parse_literal(address), parse_literal(literal)
    assert a is not None and b is not None, (address, literal)
    return a[0] == b[0] and b[1] <= a[1] <= b[2]


def _port_in(port: int, ports: str) -> bool:
    for part in ports.split(","):
        first, _, last = part.partition("-")
        if int(first) <= port <= int(last or first):
            return True
    return False


def zone_of(p: Policy, interface: str) -> str:
    for zone in p.zones.values():
        if interface in zone.interfaces:
            return zone.name
    return interface


def model_allows(p: Policy, pkt: Packet) -> bool:
    """The model's verdict for a packet that comes in and goes out by interfaces (not zones)."""
    moved = copy.copy(pkt)
    moved.in_if, moved.out_if = zone_of(p, pkt.in_if), zone_of(p, pkt.out_if)
    verdict = model_verdict(p, moved)
    if verdict is None:
        inside = moved.in_if == moved.out_if
        return (p.default_intrazone if inside else p.default_interzone) == Action.ALLOW
    return verdict


# -- random rulesets -------------------------------------------------------------------------------

INTERFACES = ["ether1", "ether2", "ether3", "ether4"]
ADDRESSES = ["10.0.0.5", "10.0.0.17", "10.0.1.130", "10.0.2.150", "10.0.3.20", "10.0.4.1"]
PORTS = [22, 53, 80, 443, 8000, 8080]

PROLOGUE = """\
/interface ethernet
set [ find default-name=ether4 ] comment=spare
/interface list
add name=L1
add name=L2
add include=L1,L2 name=BOTH
/interface list member
add interface=ether1 list=L1
add interface=ether2 list=L1
add interface=ether3 list=L2
/ip firewall address-list
add address=10.0.0.0/24 list=A
add address=10.0.2.100-10.0.3.50 list=A
add address=10.0.1.128/25 list=B
add address=10.0.0.17 list=B
add address=10.0.4.0/24 disabled=yes list=B
"""


def _match(rng: random.Random, lists_only: bool, in_return: bool = False) -> List[str]:
    parts: List[str] = []
    bang = lambda: "!" if rng.random() < 0.25 else ""  # noqa: E731
    if not in_return:
        if rng.random() < 0.4:
            if lists_only:
                parts.append(f"in-interface-list={bang()}{rng.choice(['L1', 'L2', 'BOTH'])}")
            else:
                parts.append(f"in-interface={bang()}{rng.choice(INTERFACES)}")
        if rng.random() < 0.3:
            if lists_only:
                parts.append(f"out-interface-list={bang()}{rng.choice(['L1', 'L2'])}")
            else:
                parts.append(f"out-interface={bang()}{rng.choice(INTERFACES)}")
    if rng.random() < 0.3:
        parts.append(f"src-address={bang()}{rng.choice(['10.0.0.0/24', '10.0.1.128/25', '10.0.2.100-10.0.3.50', '10.0.0.17'])}")
    if rng.random() < 0.3:
        parts.append(f"dst-address-list={bang()}{rng.choice(['A', 'B', 'C'])}")
    if rng.random() < 0.25:
        parts.append(f"src-address-list={bang()}{rng.choice(['A', 'B'])}")
    roll = rng.random()
    if roll < 0.45:
        proto = rng.choice(["tcp", "udp"])
        parts.append(f"protocol={proto}")
        if rng.random() < 0.6:
            key = rng.choice(["dst-port", "dst-port", "src-port"] + ([] if in_return else ["port"]))
            ports = ",".join(str(p) for p in rng.sample(PORTS, rng.randint(1, 3)))
            if rng.random() < 0.3:
                ports = "8000-8080"
            parts.append(f"{key}={'!' if rng.random() < 0.2 and key != 'port' else ''}{ports}")
    elif roll < 0.55 and not in_return:
        parts += ["protocol=icmp", f"icmp-options=8:{rng.choice(['0', '0-255'])}"]
    elif roll < 0.62:
        parts.append(rng.choice(["protocol=!tcp", "protocol=47"]))
    if rng.random() < 0.15 and not in_return:
        parts.append(rng.choice(["connection-state=new", "connection-state=!invalid"]))
    return parts


def random_ruleset(rng: random.Random) -> str:
    lists_only = rng.random() < 0.5
    lines = [PROLOGUE, "/ip firewall filter"]
    lines.append("add action=accept chain=forward connection-state=established,related,untracked")
    lines.append("add action=drop chain=forward connection-state=invalid")

    def rules(chain: str, count: int, custom: bool) -> None:
        for _ in range(count):
            roll = rng.random()
            if custom and roll < 0.25:
                action = "return"
            elif not custom and roll < 0.2:
                action = "jump"
            else:
                action = rng.choice(["accept", "accept", "drop", "reject", "log", "passthrough"])
            match = _match(rng, lists_only, in_return=action == "return")
            words = [f"action={action}", f"chain={chain}"] + match
            if action == "jump":
                words.append(f"jump-target={rng.choice(['c1', 'c2'])}")
            if action == "reject" and "protocol=tcp" in match and rng.random() < 0.5:
                words.append("reject-with=tcp-reset")
            if action in ("accept", "drop") and rng.random() < 0.1:
                words.append("disabled=yes")
            lines.append("add " + " ".join(words))

    rules("forward", rng.randint(3, 9), False)
    rules("c1", rng.randint(1, 5), True)
    rules("c2", rng.randint(1, 4), True)
    if rng.random() < 0.5:
        lines.append("add action=drop chain=forward")
    return "\n".join(lines) + "\n"


def random_packet(rng: random.Random) -> Packet:
    proto = rng.choice(["tcp", "tcp", "udp", "icmp", "47"])
    return Packet(rng.choice(INTERFACES), rng.choice(INTERFACES), rng.choice(ADDRESSES), rng.choice(ADDRESSES), proto,
                  rng.choice([53, 1024, 40000]), rng.choice(PORTS), rng.choice([0, 8]))  # fmt: skip


def parse_text(text: str, activate: bool = False) -> Tuple[Policy, Report]:
    report = Report()
    return parse_routeros.parse(text.encode(), report, activate=activate), report


@pytest.mark.parametrize("seed", range(60))
def test_parsed_rules_decide_like_the_router(seed: int) -> None:
    """Jumps, conditional returns on several matches, negations, lists and ports: the model gives the router's verdict."""
    rng = random.Random(seed)
    text = random_ruleset(rng)
    policy, _ = parse_text(text)
    assert not [r.name for r in policy.rules if r.unsupported and r.enabled], (text, [r.unsupported for r in policy.rules])
    device = Device.read(text)
    for _ in range(400):
        pkt = random_packet(rng)
        assert model_allows(policy, pkt) == device.allows(pkt), (seed, pkt, text)


def _emitted_device(model: Policy, family: int, options: Optional[Options] = None) -> Device:
    text = emit_routeros.emit(model, Report(), options or Options())
    device = Device.read(text, family, activate=True)
    return device


@pytest.mark.parametrize("seed", range(40))
def test_emitted_script_decides_like_the_model(seed: int) -> None:
    """Whatever the lists, negations and rule types: the emitted chains, switched on, give the model's verdict."""
    rng = random.Random(seed)
    model = random_model(rng)
    from test_iptables import random_packet as packet

    for family in (4, 6):
        device = _emitted_device(model, family)
        for _ in range(300):
            pkt = packet(rng, family)
            pkt.proto = pkt.proto.replace("icmp6", "icmpv6") if family == 6 else pkt.proto
            check = copy.copy(pkt)
            check.proto = pkt.proto.replace("icmpv6", "icmp6")
            assert device.allows(pkt) == model_allows(model, check), (seed, family, pkt)


@pytest.mark.parametrize("seed", range(10))
def test_emitted_defaults_inside_and_between_zones(seed: int) -> None:
    rng = random.Random(seed)
    model = random_model(rng)
    from test_iptables import ZONES
    from test_iptables import random_packet as packet

    for zone in ZONES:
        model.zones[zone] = Zone(zone, [zone])
    model.default_interzone, model.default_intrazone = rng.choice([(Action.ALLOW, Action.DENY), (Action.DENY, Action.ALLOW),
                                                                   (Action.ALLOW, Action.ALLOW)])  # fmt: skip
    model.zones[ZONES[0]].intrazone_allow = rng.choice([None, True, False])
    device = _emitted_device(model, 4)
    for _ in range(300):
        pkt = packet(rng, 4)
        verdict = model_verdict(model, pkt)
        if verdict is None:
            inside = pkt.in_if == pkt.out_if
            default = (model.default_intrazone if inside else model.default_interzone) == Action.ALLOW
            zone = model.zones[pkt.in_if]
            verdict = zone.intrazone_allow if inside and zone.intrazone_allow is not None else default
        assert device.allows(pkt) == verdict, (seed, pkt)


@pytest.mark.parametrize("seed", range(20))
def test_roundtrip_keeps_every_decision(seed: int) -> None:
    """A ruleset read, written as a script and read back (with its jumps on) decides as the ruleset did."""
    rng = random.Random(seed)
    text = random_ruleset(rng)
    policy, _ = parse_text(text)
    out = emit_routeros.emit(policy, Report(), Options())
    back, _ = parse_text(out, activate=True)
    device = Device.read(out, activate=True)
    original = Device.read(text)
    for _ in range(300):
        pkt = random_packet(rng)
        assert device.allows(pkt) == original.allows(pkt), (seed, pkt, out)
        assert model_allows(back, pkt) == original.allows(pkt), (seed, pkt, out)


# -- the reader --------------------------------------------------------------------------------------


def test_lines_joined_inside_strings_and_escapes() -> None:
    text = (
        "# 2026-10-13 10:00:00 by RouterOS 7.16\n"
        "/ip firewall filter\n"
        'add action=accept chain=forward comment="one two thr\\\n'
        '    ee\\\n'
        '    \\_four \\"five\\" \\$six \\4A\\\\" protocol=tcp \\\n'
        "    dst-port=80\n"
        'add action=drop chain=forward comment="partner\\_net" !connection-bytes src-address=10.0.0.1\n'
    )
    policy, _ = parse_text(text)
    assert [r.name for r in policy.rules] == ['one two three four "five" $six J\\', "partner net"]
    assert policy.services[policy.rules[0].services[0]].entries == [ServiceEntry(Protocol.TCP, "80")]


def test_terse_lines_and_slash_paths() -> None:
    text = ("/ip firewall address-list add address=10.0.0.0/24 list=n\n"
            "/ip/firewall/filter add action=drop chain=forward src-address-list=n\n")  # fmt: skip
    policy, _ = parse_text(text)
    assert policy.rules[0].sources == ["n"] and policy.address_groups["n"].members == ["10.0.0.0/24"]


def test_print_output_and_headerless_lines_are_refused() -> None:
    with pytest.raises(ParseError, match="print"):
        parse_text("Flags: X - disabled, I - invalid; D - dynamic\n 0    chain=forward action=accept\n")
    with pytest.raises(ParseError, match="before any menu"):
        parse_text("add action=accept chain=forward\n")
    with pytest.raises(ParseError, match="not closed"):
        parse_text('/ip firewall filter\nadd chain=forward comment="open\n')
    with pytest.raises(ParseError, match="set"):
        parse_text("/ip firewall filter\nset 0 disabled=yes\n")


def test_detection() -> None:
    assert cli.detect_format((DATA / "routeros_sample.rsc").read_bytes()) == "routeros"
    assert cli.detect_format(b"/ip firewall filter\nadd chain=forward action=drop\n") == "routeros"
    out, _ = run("routeros_sample.rsc", "routeros")
    assert cli.detect_format(out.encode()) == "routeros"
    assert cli.detect_format(b"config firewall policy\nend\n") == "fortios"


def test_scripting_lines_are_reported() -> None:
    _, report = parse_text('/ip firewall filter\n:foreach i in={1;2} do={ /ip firewall filter add chain=forward }\n')
    assert any(n.code == "ROUTEROS_SCRIPT_LINES" for n in report.notes)


# -- the sample --------------------------------------------------------------------------------------


def _rule(p: Policy, name: str) -> Rule:
    return next(r for r in p.rules if r.name == name)


def test_sample_rules() -> None:
    p, report = load("routeros_sample.rsc")
    assert p.vendor == "routeros" and p.default_interzone == p.default_intrazone == Action.ALLOW
    assert {z.name: z.interfaces for z in p.zones.values()} == {"DMZ": ["vlan20-dmz"], "LAN": ["bridge-lan"],
                                                                "GUEST": ["vlan30-guest"], "WAN": ["ether1"]}  # fmt: skip
    names = [r.name for r in p.rules]
    # established, invalid and the fasttrack rule are left out; the return splits what follows it exactly.
    assert not any("established" in n or "invalid" in n or "fasttrack" in n for n in names)
    ssh = _rule(p, "ssh from the admins")
    assert (ssh.dst_zones, ssh.sources, ssh.destinations, ssh.unsupported) == (["DMZ"], ["admins"], ["dmz-web"], [])
    web_admins, web_others = _rule(p, "web for everyone"), _rule(p, "web for everyone-2")
    assert web_admins.sources == web_others.sources == ["admins"] and web_others.negate_source and not web_admins.negate_source
    assert _rule(p, "nothing but TCP").negate_service and _rule(p, "nothing but TCP").action == Action.DENY
    assert _rule(p, "no other web from guests").action == Action.RESET_CLIENT
    dns = [_rule(p, "guest DNS, either port"), _rule(p, "guest DNS, either port-2")]
    assert [p.services[r.services[0]].entries for r in dns] == [[ServiceEntry(Protocol.UDP, "53")], [ServiceEntry(Protocol.UDP, "", "53")]]
    assert _rule(p, "guests to the internet").log_start  # the log rule just above it
    assert _rule(p, "guests to the internet").source_ids["routeros.log_prefix"] == "GUEST-OUT"
    assert _rule(p, "office hours for staff").schedule == "time=8h-18h,mon,tue,wed,thu,fri"
    assert not _rule(p, "old partner access").enabled
    assert _rule(p, "banned scanners").unsupported == ["address list 'scanners', which rules fill while the router runs"]
    assert "ipsec-policy=in,ipsec" in _rule(p, "defconf: accept in ipsec policy").unsupported[0]
    mirrors = _rule(p, "LAN to the package mirrors")
    assert mirrors.destinations == ["mirrors"] and p.addresses["updates.example.com"].fqdn_family == 4
    six = _rule(p, "the partners reach the web servers of the LAN by HTTPS and nothing else")
    assert six.sources == ["partners-ipv6"] and six.destinations == ["lan6"]
    assert p.address_groups["partners-ipv6"].members == ["2001:db8:99::/48"]
    assert p.address_groups["partners"].members == ["198.51.100.0/24"]  # the disabled entry is left out
    drop6 = _rule(p, "drop everything else not coming from LAN")
    assert drop6.src_zones == ["DMZ", "GUEST", "WAN"] and drop6.sources == ["::/0"]
    codes = {f.code for f in report.item("rule", drop6.origin).findings}
    assert "ROUTEROS_NEGATED_INTERFACE" in codes
    notes = {n.code for n in report.notes}
    assert {"HOST_CHAIN_NOT_CONVERTED", "TABLE_NOT_CONVERTED", "ROUTEROS_DYNAMIC_LIST", "ROUTEROS_FQDN_LIST",
            "ROUTEROS_BRIDGE", "ROUTEROS_ZONES", "FORWARD_POLICY_ACCEPT", "ROUTEROS_PASSIVE"} <= notes  # fmt: skip


def test_sample_dstnat_exception_and_nat() -> None:
    p, report = load("routeros_sample.rsc")
    names = [r.name for r in p.rules]
    deny = names.index("defconf: drop all from WAN not DSTNATed")
    allows = [_rule(p, n) for n in names[deny - 2 : deny]]
    assert [(r.src_zones, r.destinations, p.services[r.services[0]].entries, r.action) for r in allows] == [
        (["WAN"], ["203.0.113.3"], [ServiceEntry(Protocol.TCP, "8443")], Action.ALLOW),
        (["WAN"], ["203.0.113.4"], [ServiceEntry(Protocol.TCP, "25")], Action.ALLOW),
    ]
    assert _rule(p, "defconf: drop all from WAN not DSTNATed").sources == ["0.0.0.0/0"]
    nat = {n.name: n for n in p.nat_rules}
    assert nat["publish web"].destination_translation == DestNat("172.16.20.10", "443")
    assert nat["publish web"].destinations == ["203.0.113.3"] and nat["publish web"].src_zones == ["WAN"]
    masquerade = nat["defconf: masquerade"].source_translation
    assert masquerade == SourceNat(SnatKind.INTERFACE, interface="ether1")
    assert [f.code for f in report.item("nat", "defconf: masquerade").findings] == ["ROUTEROS_NAT_IPSEC_EXEMPT"]
    assert all(n.combines for n in p.nat_rules) and p.lookup_after_dnat


# -- the reader: smaller cases ------------------------------------------------------------------------


def _forward(*rules: str, nat: str = "", extra: str = "") -> str:
    head = ("/interface list\nadd name=WAN\nadd name=LAN\n/interface list member\nadd interface=ether1 list=WAN\n"
            "add interface=bridge list=LAN\n")  # fmt: skip
    return head + extra + "/ip firewall filter\n" + "".join(f"add {r}\n" for r in rules) + (f"/ip firewall nat\n{nat}" if nat else "")


def test_dstnat_exception_refused_where_a_rule_below_blocks_the_translated_traffic() -> None:
    text = _forward("action=drop chain=forward connection-nat-state=!dstnat connection-state=new in-interface-list=WAN",
                    "action=drop chain=forward dst-address=192.168.1.10 protocol=tcp",
                    nat="add action=dst-nat chain=dstnat dst-address=198.51.100.1 dst-port=80 in-interface-list=WAN "
                        "protocol=tcp to-addresses=192.168.1.10\n")  # fmt: skip
    p, _ = parse_text(text)
    assert "blocks part of what" in p.rules[0].unsupported[0]
    text = text.replace("dst-address=192.168.1.10 protocol=tcp", "dst-address=192.168.1.11 protocol=tcp")
    p, _ = parse_text(text)
    assert [r.action for r in p.rules] == [Action.ALLOW, Action.DROP, Action.DROP] and not p.rules[1].unsupported


def test_dstnat_exception_refused_for_unreadable_nat_and_other_matches() -> None:
    text = _forward("action=drop chain=forward connection-nat-state=!dstnat in-interface-list=WAN",
                    nat="add action=redirect chain=dstnat dst-port=53 protocol=udp to-ports=53\n")
    assert "cannot be read" in parse_text(text)[0].rules[0].unsupported[0]
    text = _forward("action=drop chain=forward connection-nat-state=!dstnat in-interface-list=WAN protocol=tcp")
    assert "together with" in parse_text(text)[0].rules[0].unsupported[0]
    text = _forward("action=accept chain=forward connection-nat-state=!dstnat in-interface-list=WAN")
    assert "allow rule" in parse_text(text)[0].rules[0].unsupported[0]
    text = _forward("action=drop chain=forward connection-nat-state=dstnat in-interface-list=WAN")
    assert parse_text(text)[0].rules[0].unsupported == ["connection-nat-state=dstnat"]


def test_dstnat_exception_without_nat_rules_is_a_plain_deny() -> None:
    p, report = parse_text(_forward("action=drop chain=forward connection-nat-state=!dstnat in-interface-list=WAN"))
    assert len(p.rules) == 1 and not p.rules[0].unsupported
    assert "No destination NAT rule" in report.item("rule", p.rules[0].origin).findings[0].message


def test_zones_from_interfaces_when_lists_overlap() -> None:
    text = ("/interface list\nadd name=A\nadd name=B\n/interface list member\nadd interface=e1 list=A\nadd interface=e2 list=A\n"
            "add interface=e2 list=B\n/ip firewall filter\nadd action=drop chain=forward in-interface-list=A\n"
            "add action=drop chain=forward in-interface-list=B out-interface=e3\n")  # fmt: skip
    p, report = parse_text(text)
    assert p.rules[0].src_zones == ["e1", "e2"] and p.rules[1].src_zones == ["e2"] and p.rules[1].dst_zones == ["e3"]
    assert "every interface is a zone" in next(n.message for n in report.notes if n.code == "ROUTEROS_ZONES")


def test_named_interface_inside_a_list_zone_falls_back_to_interfaces() -> None:
    text = ("/interface list\nadd name=A\n/interface list member\nadd interface=e1 list=A\nadd interface=e2 list=A\n"
            "/ip firewall filter\nadd action=drop chain=forward in-interface-list=A\nadd action=drop chain=forward in-interface=e1\n")  # fmt: skip
    p, _ = parse_text(text)
    assert p.rules[0].src_zones == ["e1", "e2"] and p.rules[1].src_zones == ["e1"]
    text = text.replace("add interface=e2 list=A\n", "")
    p, _ = parse_text(text)
    assert p.rules[0].src_zones == p.rules[1].src_zones == ["A"]  # the list is that one interface


def test_interfaces_that_cannot_be_zones() -> None:
    text = ("/interface bridge port\nadd bridge=br interface=ether2\n/interface list\nadd name=EMPTY\n/ip firewall filter\n"
            "add action=drop chain=forward in-interface=ether2\nadd action=drop chain=forward in-interface-list=EMPTY\n"
            "add action=drop chain=forward in-interface-list=dynamic\nadd action=drop chain=forward in-interface-list=none\n"
            "add action=drop chain=forward in-interface-list=all\n")  # fmt: skip
    p, _ = parse_text(text)
    assert "port of bridge br" in p.rules[0].unsupported[0]
    assert "no members in the export" in p.rules[1].unsupported[0]
    assert "known only while the router runs" in p.rules[2].unsupported[0]
    assert len(p.rules) == 4 and p.rules[3].src_zones == [ANY]  # none matches nothing; all is every interface


def test_unknown_and_unmodelled_matches_are_never_any() -> None:
    for match in ("layer7-protocol=x", "content=abc", "tls-host=*.example", "limit=10,5:packet", "src-mac-address=00:00:5E:00:53:01",
                  "connection-mark=m", "routing-mark=r", "ttl=equal:1", "tcp-flags=fin", "ipsec-policy=in,ipsec", "frobnicate=1",
                  "dst-address-type=local", "icmp-options=8 protocol=icmp", "protocol=ipip", "connection-state=established"):  # fmt: skip
        p, _ = parse_text(f"/ip firewall filter\nadd action=drop chain=forward {match}\n")
        assert p.rules and p.rules[0].unsupported, match


def test_conditional_return_on_an_interface_poisons_what_follows() -> None:
    text = _forward("action=jump chain=forward jump-target=x", "action=return chain=x in-interface-list=LAN",
                    "action=drop chain=x protocol=tcp")
    p, _ = parse_text(text)
    assert "conditional return" in p.rules[0].unsupported[0]


def test_jumps_that_cannot_be_followed() -> None:
    p, _ = parse_text("/ip firewall filter\nadd action=jump chain=forward jump-target=a\nadd action=jump chain=a jump-target=a\n"
                      "add action=jump chain=forward jump-target=input\n")  # fmt: skip
    assert "jump loop" in p.rules[0].unsupported[0] and "built-in chain input" in p.rules[1].unsupported[0]
    assert all(r.action == Action.DROP for r in p.rules)


def test_fasttrack_of_new_connections_and_disabled_flow_rules() -> None:
    p, report = parse_text("/ip firewall filter\nadd action=fasttrack-connection chain=forward\n"
                           "add action=jump chain=forward disabled=yes jump-target=x\nadd action=drop chain=x\n"
                           "add action=accept chain=forward connection-state=established disabled=yes\n")  # fmt: skip
    assert not p.rules
    assert {"ROUTEROS_FASTTRACK", "ROUTEROS_DISABLED_JUMP", "ROUTEROS_UNUSED_CHAIN"} <= {n.code for n in report.notes}


def test_lists_that_are_empty_or_filled_while_the_router_runs() -> None:
    p, report = parse_text("/ip firewall filter\nadd action=drop chain=forward src-address-list=nothing\n"
                           "add action=drop chain=forward src-address-list=!nothing protocol=tcp\n"
                           "/ip firewall mangle\nadd action=add-dst-to-address-list address-list=m chain=prerouting\n"
                           "/ip firewall filter\nadd action=drop chain=forward dst-address-list=m\n")  # fmt: skip
    assert [r.sources for r in p.rules[:1]] == [["0.0.0.0/0"]] or len(p.rules) == 2
    assert p.rules[0].services != [ANY] and not p.rules[0].unsupported  # the negated empty list matches everything
    assert "fill while the router runs" in p.rules[1].unsupported[0]
    assert {"ROUTEROS_EMPTY_LIST", "ROUTEROS_DYNAMIC_LIST"} <= {n.code for n in report.notes}


def test_stateless_and_tracking_off() -> None:
    _, report = parse_text("/ip firewall filter\nadd action=accept chain=forward protocol=tcp\nadd action=drop chain=forward\n")
    assert any(n.code == "STATELESS_RULESET" for n in report.notes)
    _, report = parse_text("/ip firewall connection tracking\nset enabled=no\n/ip firewall filter\nadd action=drop chain=forward\n")
    assert "switched off" in next(n.message for n in report.notes if n.code == "STATELESS_RULESET")


def test_ipv6_rules_stay_ipv6_and_icmp_belongs_to_its_version() -> None:
    p, _ = parse_text("/ipv6 firewall filter\nadd action=drop chain=forward protocol=icmpv6 icmp-options=1:0-255\n"
                      "add action=accept chain=forward protocol=icmp\nadd action=drop chain=forward\n")  # fmt: skip
    assert p.rules[0].services and p.services[p.rules[0].services[0]].entries == [ServiceEntry(Protocol.ICMP6, icmp_type=1)]
    assert "protocol=icmp" in p.rules[1].unsupported[0]
    assert p.rules[2].sources == ["::/0"]


def test_nat_shapes() -> None:
    nat = ("add action=src-nat chain=srcnat out-interface=ether1 src-address=10.0.0.0/24 to-addresses=198.51.100.1-198.51.100.4\n"
           "add action=netmap chain=srcnat src-address=10.1.0.0/30 to-addresses=198.51.100.8/30\n"
           "add action=netmap chain=dstnat dst-address=198.51.100.8/30 to-addresses=10.1.0.0/30\n"
           "add action=netmap chain=dstnat dst-address=198.51.100.8/29 to-addresses=10.1.0.0/30\n"
           "add action=dst-nat chain=dstnat dst-address=198.51.100.20 dst-port=2222 protocol=tcp to-ports=22\n"
           "add action=dst-nat chain=dstnat dst-address-type=local dst-port=80 in-interface=ether1 protocol=tcp to-addresses=10.0.0.9\n"
           "add action=redirect chain=dstnat dst-port=53 protocol=udp\n"
           "add action=accept chain=srcnat dst-address=10.9.0.0/16\n"
           "add action=same chain=srcnat to-addresses=198.51.100.30-198.51.100.31\n"
           "add action=masquerade chain=srcnat in-interface=ether2\n")  # fmt: skip
    extra = "/ip address\nadd address=198.51.100.50/24 interface=ether1\n/ip dhcp-client\nadd interface=ether3\n"
    p, report = parse_text(_forward(nat=nat, extra=extra))
    by = {n.description.split()[-1]: n for n in p.nat_rules}
    assert by["srcnat-1"].source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["198.51.100.1-198.51.100.4"])
    assert by["srcnat-2"].source_translation == SourceNat(SnatKind.STATIC, ["198.51.100.8/30"])
    assert by["dstnat-1"].destination_translation == DestNat("10.1.0.0/30")
    assert "one for one" in by["dstnat-2"].unsupported[0]
    assert by["dstnat-3"].destination_translation == DestNat("198.51.100.20", "22")
    assert by["dstnat-4"].destinations == ["198.51.100.50"] and by["dstnat-4"].destination_translation == DestNat("10.0.0.9")
    assert [f.code for f in report.item("nat", by["dstnat-4"].origin).findings] == ["ROUTEROS_LOCAL_ADDRESS"]
    assert "redirect" in by["dstnat-5"].unsupported[0]
    assert by["srcnat-3"].source_translation is None and not by["srcnat-3"].unsupported
    assert by["srcnat-4"].source_translation is not None and by["srcnat-4"].source_translation.kind == SnatKind.DYNAMIC
    assert "in-interface in chain srcnat" in by["srcnat-5"].unsupported
    p, _ = parse_text("/ipv6 firewall nat\nadd action=src-nat chain=srcnat to-address=2001:db8::1\n")
    assert "IPv6 NAT" in p.nat_rules[0].unsupported


def test_activate_reads_the_jumps_a_script_of_fwshift_ends_with() -> None:
    out, _ = run("routeros_sample.rsc", "routeros")
    assert not parse_text(out)[0].rules  # nothing is switched on as loaded
    assert parse_text(out, activate=True)[0].rules


# -- the writer --------------------------------------------------------------------------------------


def _policy(*rules: Rule) -> Policy:
    p = Policy(vendor="panos")
    for rule in rules:
        rule.origin = rule.origin or rule.name
        p.rules.append(rule)
    return p


def test_script_shape_and_safety() -> None:
    out, report = run("panos_sample.xml", "routeros")
    lines = out.splitlines()
    assert lines[3].startswith(":if ([:len [/ip firewall filter find where chain=\"fwshift-forward\"]] > 0)")
    assert not any(re.search(r"chain=(input|output)\b", line) for line in lines)
    assert not any(" remove" in line or line.startswith("/system") for line in lines if not line.startswith(("#", ":")))
    jumps = [line for line in lines if "jump-target=fwshift-" in line and "chain=forward" in line or "chain=dstnat action=jump" in line]
    assert jumps and all("disabled=yes" in line for line in jumps)
    assert lines[-1].startswith("/ip firewall nat add chain=srcnat action=jump")
    first = [line for line in lines if "chain=fwshift-forward" in line][:2]
    assert "connection-state=established,related,untracked" in first[0] and "connection-state=invalid" in first[1]
    assert {n.code for n in report.notes} >= {"ROUTEROS_LOAD", "INTERFACES_REQUIRED"}
    assert 'interface="ethernet1/1"' in out


def test_strings_are_escaped_and_names_are_safe() -> None:
    rule = Rule(name='say "hi" $HOME \\ ok? café', src_zones=["Trust Zone"], dst_zones=["dmz"], action=Action.DROP)
    out = emit_routeros.emit(_policy(rule), Report(), Options())
    assert 'comment="say \\"hi\\" \\$HOME \\\\ ok_ caf_"' in out
    assert "in-interface-list=fws-Trust_Zone" in out and 'interface="Trust Zone"' in out
    back, _ = parse_text(out, activate=True)
    assert back.rules[0].name == 'say "hi" $HOME \\ ok_ caf_'


def test_one_ip_version_writes_one_table() -> None:
    p, _ = load("iptables_sample.rules")
    report = Report()
    out = cli.convert(p, "routeros", report)
    assert "/ipv6 firewall" not in out and any(n.code == "ONE_IP_VERSION" for n in report.notes)


def test_negated_services_and_many_combinations_use_a_chain() -> None:
    p = _policy(Rule(name="r", sources=["10.0.0.0/24"], services=["web"], negate_service=True, action=Action.DROP),
                Rule(name="wide", src_zones=["a", "b", "c", "d", "e"], dst_zones=["f", "g", "h", "i"], services=["web"]))
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80"), ServiceEntry(Protocol.UDP, "53")])
    out = emit_routeros.emit(p, Report(), Options())
    assert "/ip firewall filter add chain=fwshift-r1 protocol=tcp dst-port=80 action=return" in out
    assert "/ip firewall filter add chain=fwshift-r1 action=drop comment=\"r\"" in out
    assert out.count("jump-target=fwshift-r2") == 20


def test_resets_lists_and_host_names() -> None:
    p = _policy(Rule(name="reset", services=["mix"], action=Action.RESET_BOTH),
                Rule(name="names", destinations=["grp"], action=Action.ALLOW))
    p.services["mix"] = Service("mix", [ServiceEntry(Protocol.TCP, "80"), ServiceEntry(Protocol.UDP, "53")])
    p.addresses["h"] = Address("h", AddressKind.FQDN, "updates.example.com")
    p.addresses["r6"] = Address("r6", AddressKind.RANGE, "2001:db8::1-2001:db8::4")
    from fwshift.model import AddressGroup

    p.address_groups["grp"] = AddressGroup("grp", ["h", "10.0.0.0/24", "r6"])
    report = Report()
    out = emit_routeros.emit(p, report, Options())
    assert "reject-with=tcp-reset" not in out and any(f.code == "RESET_ACTION" for f in report.item("rule", "reset").findings)
    assert '/ip firewall address-list add list=fws-grp address="updates.example.com"' in out
    assert '/ipv6 firewall address-list add list=fws-grp address="2001:db8::1"' in out
    assert '/ipv6 firewall address-list add list=fws-grp address="2001:db8::2/127"' in out
    assert any(f.code == "ROUTEROS_FQDN" for f in report.item("rule", "names").findings)


def test_nat_written_into_chains_of_its_own() -> None:
    p = _policy()
    p.zones["outside"] = Zone("outside", ["ether1"])
    p.nat_rules = [
        NatRule("web", src_zones=["outside"], dst_zones=["outside"], destinations=["198.51.100.1"], service="https",
                destination_translation=DestNat("10.0.0.5", "8443"), origin="web"),
        NatRule("hide", dst_zones=["outside"], sources=["10.0.0.0/24"], source_translation=SourceNat(SnatKind.INTERFACE),
                origin="hide", enabled=False),
        NatRule("v6", sources=["2001:db8::/64"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["2001:db8:1::1"]), origin="v6"),
    ]
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    report = Report()
    out = emit_routeros.emit(p, report, Options())
    assert ("/ip firewall nat add chain=fwshift-dstnat in-interface-list=fws-outside dst-address=198.51.100.1 protocol=tcp "
            "dst-port=443 action=dst-nat to-addresses=10.0.0.5 to-ports=8443 comment=\"web\"") in out
    assert "chain=fwshift-srcnat out-interface-list=fws-outside src-address=10.0.0.0/24 action=masquerade comment=\"hide\" disabled=yes" in out
    assert report.item("nat", "v6").skipped


def test_sample_to_every_target_and_back() -> None:
    for target in ("panos", "iptables", "nftables", "fortios", "junos"):
        out, report = run("routeros_sample.rsc", target)
        assert out
        statuses = [i for i in report.items.values() if i.kind == "rule" and i.name.startswith("banned scanners")]
        assert statuses and any(f.severity == Severity.REVIEW for f in statuses[0].findings)


# -- review round 31 --------------------------------------------------------------------------------


def test_r31_dstnat_state_on_a_jump_or_return_is_not_lost() -> None:
    text = _forward("action=jump chain=forward connection-nat-state=!dstnat in-interface-list=WAN jump-target=wan",
                    "action=drop chain=forward in-interface-list=WAN", "action=accept chain=wan protocol=tcp dst-port=22",
                    nat="add action=dst-nat chain=dstnat dst-address=198.51.100.1 dst-port=22 in-interface-list=WAN "
                        "protocol=tcp to-addresses=10.0.0.5\n")  # fmt: skip
    p, _ = parse_text(text)
    assert "connection-nat-state=!dstnat on action=jump" in p.rules[0].unsupported
    text = _forward("action=jump chain=forward jump-target=x", "action=return chain=x connection-nat-state=!dstnat protocol=tcp",
                    "action=drop chain=x protocol=tcp")
    p, _ = parse_text(text)
    assert p.rules[0].unsupported  # what the return takes away is not known: never all of it


def test_r31_menus_the_export_could_not_write() -> None:
    with pytest.raises(ParseError, match="could not export /ip/firewall/filter"):
        parse_text('#error exporting "/ip/firewall/filter" (timeout)\n/ip firewall nat\nadd action=masquerade chain=srcnat\n')
    _, report = parse_text('#error exporting "/system/scheduler" (timeout)\n/ip firewall filter\nadd action=drop chain=forward\n')
    assert any(n.code == "ROUTEROS_EXPORT_ERROR" for n in report.notes)


def test_r31_lists_filled_by_raw_dhcp_or_ppp() -> None:
    for filler in ("/ip firewall raw\nadd action=add-src-to-address-list address-list=blocked chain=prerouting\n",
                   "/ip dhcp-server\nadd address-lists=blocked interface=bridge name=d\n",
                   "/ppp profile\nadd address-list=blocked name=vpn\n"):  # fmt: skip
        p, report = parse_text("/ip firewall address-list\nadd address=203.0.113.9 list=blocked\n" + filler
                               + "/ip firewall filter\nadd action=drop chain=forward src-address-list=blocked\n")  # fmt: skip
        assert "fill while the router runs" in p.rules[0].unsupported[0], filler


def test_r31_negated_interface_on_the_jump_is_reported() -> None:
    text = _forward("action=jump chain=forward in-interface-list=!LAN jump-target=notlan", "action=drop chain=notlan",
                    nat="add action=dst-nat chain=dstnat in-interface=!bridge dst-port=80 protocol=tcp to-addresses=10.0.0.5\n")
    p, report = parse_text(text)
    assert [f.code for f in report.item("rule", p.rules[0].origin).findings] == ["ROUTEROS_NEGATED_INTERFACE"]
    assert report.item("rule", p.rules[0].origin).findings[0].severity == Severity.REVIEW
    assert [f.code for f in report.item("nat", p.nat_rules[0].origin).findings] == ["ROUTEROS_NEGATED_INTERFACE"]


def test_r31_dstnat_exception_counts_later_rules_on_translated_traffic() -> None:
    text = _forward("action=drop chain=forward connection-nat-state=!dstnat connection-state=new in-interface-list=WAN",
                    "action=drop chain=forward connection-nat-state=dstnat protocol=tcp dst-port=22",
                    nat="add action=dst-nat chain=dstnat dst-port=22 in-interface-list=WAN protocol=tcp to-addresses=10.0.0.5\n")
    p, _ = parse_text(text)
    assert "blocks part of what" in p.rules[0].unsupported[0]


def test_r31_verbose_empty_values_are_unset() -> None:
    p, _ = parse_text('/ip firewall filter\nadd action=drop chain=forward connection-state="" src-address=192.168.1.0/24 '
                      'comment="" log-prefix=""\n')  # fmt: skip
    assert not p.rules[0].unsupported and p.rules[0].sources == ["192.168.1.0/24"]


def test_r31_nat_of_both_sides_writes_no_property_nat_rules_lack() -> None:
    p = _policy()
    p.zones["in"] = Zone("in", ["ether2"])
    p.nat_rules = [NatRule("both", src_zones=["in"], sources=["10.0.0.0/24"], destinations=["198.51.100.1"], service="https",
                           destination_translation=DestNat("10.0.0.20", "8443"),
                           source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["10.0.0.1"]), origin="both")]  # fmt: skip
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    report = Report()
    out = emit_routeros.emit(p, report, Options())
    nat_lines = [line for line in out.splitlines() if line.startswith("/ip firewall nat add chain=fwshift-")]
    assert len(nat_lines) == 2 and not any("connection-nat-state" in line for line in nat_lines)
    messages = " ".join(f.message for f in report.item("nat", "both").findings)
    assert "NAT_AFTER_DNAT" in {f.code for f in report.item("nat", "both").findings}
    assert "fwsz" not in messages and "in only" in messages  # the zone, not the planner's placeholder


def test_r31_guard_for_each_ip_version_written() -> None:
    p = _policy(Rule(name="six", sources=["2001:db8::/64"], action=Action.DROP))
    p.scope = "IPv6"
    out = emit_routeros.emit(p, Report(), Options())
    assert out.splitlines()[3].startswith(':if ([:len [/ipv6 firewall filter find where chain="fwshift-forward"]] > 0)')
    assert "/ip firewall filter find" not in out
    assert parse_text(out, activate=True)[0].rules[0].name == "six"  # (the parser passes over the check)
    _, report = parse_text(out, activate=True)
    assert not any(n.code == "ROUTEROS_SCRIPT_LINES" for n in report.notes)


def test_r31_syn_flag_keeps_the_rule_to_tcp() -> None:
    p, _ = parse_text("/ip firewall filter\nadd action=accept chain=forward tcp-flags=syn\n")
    assert p.services[p.rules[0].services[0]].entries == [ServiceEntry(Protocol.TCP)]


def test_r31_nat_names_written_as_they_are() -> None:
    p = _policy()
    p.nat_rules = [NatRule('pub "web"  \\ x', destinations=["198.51.100.1"], destination_translation=DestNat("10.0.0.5"),
                           origin="pub")]  # fmt: skip
    out = emit_routeros.emit(p, Report(), Options())
    assert 'comment="pub \\"web\\"  \\\\ x"' in out
    back, _ = parse_text(out, activate=True)
    assert back.nat_rules[0].name == 'pub "web"  \\ x'


def test_negation_that_leaves_no_interface_the_export_shows_is_not_dropped() -> None:
    p, _ = parse_text("/ip firewall filter\nadd action=drop chain=forward in-interface=!ether1\n")
    assert len(p.rules) == 1 and "leaves none of the interfaces" in p.rules[0].unsupported[0]


def test_ports_without_a_port_protocol_are_one_clear_problem() -> None:
    for match in ("protocol=!tcp dst-port=80", "dst-port=80", "protocol=gre src-port=1", "port=53"):
        p, _ = parse_text(f"/ip firewall filter\nadd action=drop chain=forward {match}\n")
        assert len(p.rules) == 1 and len(p.rules[0].unsupported) == 1 and "without protocol" in p.rules[0].unsupported[0], match


def test_icmp_code_and_accepts_of_states_other_than_replies() -> None:
    p, _ = parse_text("/ip firewall filter\nadd action=drop chain=forward protocol=icmp icmp-options=3:4\n"
                      "add action=accept chain=forward connection-state=invalid\n")  # fmt: skip
    assert p.services[p.rules[0].services[0]].entries == [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)]
    assert len(p.rules) == 2 and "connection state invalid without new" in p.rules[1].unsupported[0]


def test_return_in_forward_is_an_accept_even_when_it_cannot_be_taken_away() -> None:
    p, _ = parse_text("/ip firewall filter\nadd action=return chain=forward in-interface=ether1\nadd action=drop chain=forward\n")
    assert [(r.action, r.src_zones, r.unsupported) for r in p.rules] == [(Action.ALLOW, ["ether1"], []), (Action.DROP, [ANY], [])]


def test_tcp_reset_on_a_rule_that_matches_more_than_tcp() -> None:
    p, report = parse_text("/ip firewall filter\nadd action=reject chain=forward reject-with=tcp-reset\n"
                           "add action=reject chain=forward protocol=tcp reject-with=tcp-reset\n")  # fmt: skip
    assert [r.action for r in p.rules] == [Action.DENY, Action.RESET_CLIENT]
    assert [f.code for f in report.item("rule", p.rules[0].origin).findings] == ["RESET_ACTION"]


def test_dstnat_exception_looks_at_the_translated_port() -> None:
    nat = ("add action=dst-nat chain=dstnat dst-address=198.51.100.1 dst-port=8443 in-interface-list=WAN protocol=tcp "
           "to-addresses=10.0.0.5 to-ports=443\n")  # fmt: skip
    rules = ["action=drop chain=forward connection-nat-state=!dstnat in-interface-list=WAN"]
    p, _ = parse_text(_forward(*rules, "action=drop chain=forward dst-address=10.0.0.5 protocol=tcp dst-port=443", nat=nat))
    assert "blocks part of what" in p.rules[0].unsupported[0]
    p, _ = parse_text(_forward(*rules, "action=drop chain=forward dst-address=10.0.0.5 protocol=tcp dst-port=8443", nat=nat))
    assert p.rules[0].action == Action.ALLOW and p.rules[0].destinations == ["198.51.100.1"]


def test_not_any_matches_nothing() -> None:
    report = Report()
    out = emit_routeros.emit(_policy(Rule(name="none", negate_source=True, action=Action.DROP)), report, Options())
    assert 'comment="none"' not in out and report.item("rule", "none").skipped


def test_icmp_codes_and_protocol_numbers_per_ip_version() -> None:
    p = _policy(Rule(name="icmp", services=["unreach", "unreach4", "proto1"], action=Action.DROP))
    p.services["unreach"] = Service("unreach", [ServiceEntry(Protocol.ICMP, icmp_type=3)])
    p.services["unreach4"] = Service("unreach4", [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)])
    p.services["proto1"] = Service("proto1", [ServiceEntry(Protocol.IP, ip_protocol=1)])
    out = emit_routeros.emit(p, Report(), Options())
    assert "icmp-options=3:0-255" in out and "icmp-options=3:4" in out
    assert not [line for line in out.splitlines() if line.startswith("/ipv6") and "protocol=icmp " in line]
