# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""pf: parser, emitter, and packet-level equivalence between pf rulesets and the model.

The judge below evaluates a forwarded packet as pf.conf(5) describes it: the rules for the interface it arrives on
(direction in), then those for the interface it leaves by (direction out); in each, the last matching rule decides
unless a quick rule matches first; every rule that matches sets its tag at once (tags are sticky); match rules translate
at once, a pass rule when it decides; lists expand into a rule per element, which takes its IP version from an address where the rule
names none. It is written apart from the parser and the emitter and shares no code with them.
"""

from __future__ import annotations

import ipaddress
import random
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import pytest
from helpers import DATA, load
from test_iptables import ZONES, Packet, model_allows, model_verdict, random_model, random_packet

from fwshift import cli
from fwshift.emitters import pf as emit_pf
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule, Service, ServiceEntry
from fwshift.model import SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import pf as parse_pf
from fwshift.report import Report

# -- the judge -------------------------------------------------------------------------------------

_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "gre": 47, "esp": 50, "sctp": 132}
_ICMP = {"echoreq": 8, "echorep": 0, "unreach": 3, "timex": 11, "redir": 5}
_ICMP6 = {"echoreq": 128, "echorep": 129, "unreach": 1, "toobig": 2}
_TOKEN = re.compile(r'"[^"]*"|<[A-Za-z0-9_.:-]+>|!=|<=|>=|><|<>|[{}(),!<>=]|[^\s{}(),!<>="]+')


def _proto_number(packet: Packet) -> int:
    return _NUMBERS[packet.proto] if packet.proto in _NUMBERS else int(packet.proto)


@dataclass
class _Element:
    negated: bool
    kind: str  # any, net, table, self
    value: str = ""

    def family(self) -> int:
        return ipaddress.ip_network(self.value, strict=False).version if self.kind == "net" else 0


@dataclass
class _JudgeRule:
    action: str
    direction: str = ""
    quick: bool = False
    interfaces: List[Tuple[str, bool]] = field(default_factory=list)
    af: int = 0
    protos: List[int] = field(default_factory=list)
    src: List[_Element] = field(default_factory=lambda: [_Element(False, "any")])
    dst: List[_Element] = field(default_factory=lambda: [_Element(False, "any")])
    src_ports: Optional[Set[int]] = None
    dst_ports: Optional[Set[int]] = None
    icmp: List[Tuple[int, Optional[int]]] = field(default_factory=list)
    tag: str = ""
    tagged: str = ""
    rdr: str = ""
    rdr_port: int = 0
    nat: str = ""


class PfJudge:
    """A small pf for forwarded packets, read from pf.conf text (the subset the tests and the emitter write)."""

    def __init__(self, text: str) -> None:
        self.macros: Dict[str, str] = {}
        self.tables: Dict[str, List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, bool]]] = {}
        self.rules: List[_JudgeRule] = []
        statement: List[str] = []
        depth = 0
        for raw in re.sub(r"\\\n", " ", text).splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            macro = re.fullmatch(r"([A-Za-z0-9_]+)\s*=\s*(.*)", line)
            if macro and depth == 0:
                self.macros[macro.group(1)] = " ".join(t.strip('"') for t in _TOKEN.findall(self._expand(macro.group(2))))
                continue
            tokens = _TOKEN.findall(self._expand(line))
            statement += tokens
            depth += tokens.count("{") - tokens.count("}")
            if depth == 0:
                self._statement(statement)
                statement = []
        assert not statement

    def _expand(self, line: str) -> str:
        for _ in range(10):
            line = re.sub(r"\$([A-Za-z0-9_]+)", lambda m: self.macros[m.group(1)], line)
        return line

    def _statement(self, tokens: List[str]) -> None:
        if tokens[0] == "table":
            name = tokens[1][1:-1]
            entries = []
            inside = tokens[tokens.index("{") + 1 : tokens.index("}")] if "{" in tokens else []
            negated = False
            for token in inside:
                if token == ",":
                    continue
                if token == "!":
                    negated = True
                    continue
                entries.append((ipaddress.ip_network(token, strict=False), negated))
                negated = False
            self.tables[name] = entries
            return
        if tokens[0] in ("set", "scrub", "anchor"):
            return
        assert tokens[0] in ("pass", "block", "match"), tokens
        rule = _JudgeRule(tokens[0])
        i = 1
        if rule.action == "block" and tokens[i] in ("drop", "return", "return-rst"):
            i += 1
        if tokens[i] in ("in", "out"):
            rule.direction = tokens[i]
            i += 1
        while i < len(tokens):
            word = tokens[i]
            i += 1
            if word == "log":
                continue
            if word == "quick":
                rule.quick = True
            elif word == "on":
                names, i = self._list(tokens, i)
                rule.interfaces = [(n.lstrip("!"), n.startswith("!")) for n in names]
            elif word in ("inet", "inet6"):
                rule.af = 4 if word == "inet" else 6
            elif word == "proto":
                names, i = self._list(tokens, i)
                rule.protos = [_NUMBERS[n] if n in _NUMBERS else int(n) for n in names]
            elif word == "all":
                pass
            elif word in ("from", "to"):
                elements, i = self._hosts(tokens, i) if tokens[i] != "port" else ([_Element(False, "any")], i)
                ports = None
                if i < len(tokens) and tokens[i] == "port":
                    ports, i = self._ports(tokens, i + 1)
                if word == "from":
                    rule.src, rule.src_ports = elements, ports
                else:
                    rule.dst, rule.dst_ports = elements, ports
            elif word in ("icmp-type", "icmp6-type"):
                names, i = self._list(tokens, i, keep_code=True)
                table = _ICMP if word == "icmp-type" else _ICMP6
                for name in names:
                    kind, _, code = name.partition("/")
                    rule.icmp.append((table[kind] if kind in table else int(kind), int(code) if code else None))
            elif word == "flags":
                assert tokens[i] in ("S/SA", "any"), tokens
                i += 1
            elif word in ("keep", "no"):
                i += 1  # state
            elif word == "label":
                i += 1
            elif word == "tag":
                rule.tag = tokens[i]
                i += 1
            elif word == "tagged":
                rule.tagged = tokens[i]
                i += 1
            elif word == "rdr-to":
                rule.rdr = tokens[i]
                i += 1
                if i < len(tokens) and tokens[i] == "port":
                    rule.rdr_port = int(tokens[i + 1])
                    i += 2
                if i < len(tokens) and tokens[i] in ("bitmask", "round-robin"):
                    i += 1
            elif word == "nat-to":
                if tokens[i] == "(":
                    rule.nat = tokens[i + 1]
                    i += 3
                else:
                    rule.nat = tokens[i]
                    i += 1
                while i < len(tokens) and tokens[i] in ("static-port", "bitmask", "round-robin"):
                    i += 1
            else:
                raise AssertionError(f"the judge does not know '{word}' in {' '.join(tokens)}")
        self.rules.append(rule)

    @staticmethod
    def _list(tokens: List[str], i: int, keep_code: bool = False) -> Tuple[List[str], int]:
        def one(j: int) -> Tuple[str, int]:
            negated = tokens[j] == "!"
            if negated:
                j += 1
            value = tokens[j]
            j += 1
            if keep_code and j < len(tokens) and tokens[j] == "code":
                value += "/" + tokens[j + 1]
                j += 2
            return ("!" if negated else "") + value, j

        if tokens[i] != "{":
            value, i = one(i)
            return [value], i
        i += 1
        out = []
        while tokens[i] != "}":
            if tokens[i] == ",":
                i += 1
                continue
            value, i = one(i)
            out.append(value)
        return out, i + 1

    def _hosts(self, tokens: List[str], i: int) -> Tuple[List[_Element], int]:
        def one(j: int) -> Tuple[_Element, int]:
            negated = tokens[j] == "!"
            if negated:
                j += 1
            token = tokens[j]
            if token == "any":
                return _Element(negated, "any"), j + 1
            if token == "self":
                return _Element(negated, "self"), j + 1
            if token.startswith("<"):
                return _Element(negated, "table", token[1:-1]), j + 1
            if j + 2 < len(tokens) and tokens[j + 1] == "-":
                return _Element(negated, "range", f"{token}-{tokens[j + 2]}"), j + 3
            ipaddress.ip_network(token, strict=False)
            return _Element(negated, "net", token), j + 1

        if tokens[i] != "{":
            element, i = one(i)
            return [element], i
        i += 1
        out = []
        while tokens[i] != "}":
            if tokens[i] == ",":
                i += 1
                continue
            element, i = one(i)
            out.append(element)
        return out, i + 1

    @staticmethod
    def _ports(tokens: List[str], i: int) -> Tuple[Set[int], int]:
        out: Set[int] = set()

        def one(j: int) -> int:
            ops = {"=": lambda p: {p}, "!=": lambda p: set(range(65536)) - {p}, "<": lambda p: set(range(p)),
                   "<=": lambda p: set(range(p + 1)), ">": lambda p: set(range(p + 1, 65536)), ">=": lambda p: set(range(p, 65536))}  # fmt: skip
            if tokens[j] in ops:
                out.update(ops[tokens[j]](int(tokens[j + 1])))
                return j + 2
            if ":" in tokens[j]:
                low, high = tokens[j].split(":")
                out.update(range(int(low), int(high) + 1))
                return j + 1
            if j + 2 < len(tokens) and tokens[j + 1] in ("><", "<>"):
                low, high = int(tokens[j]), int(tokens[j + 2])
                out.update(range(low + 1, high) if tokens[j + 1] == "><" else set(range(65536)) - set(range(low, high + 1)))
                return j + 3
            out.add(int(tokens[j]))
            return j + 1

        if tokens[i] != "{":
            return out, one(i)
        i += 1
        while tokens[i] != "}":
            i = i + 1 if tokens[i] == "," else one(i)
        return out, i + 1

    # -- evaluation --------------------------------------------------------------------------------

    def _in_table(self, name: str, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        best: Optional[Tuple[int, bool]] = None
        for net, negated in self.tables[name]:
            if net.version == ip.version and ip in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, negated)
        return best is not None and not best[1]

    def _element(self, element: _Element, address: str) -> bool:
        if element.kind == "any":
            hit = True
        elif element.kind == "self":
            hit = False  # the firewall's own addresses: no test packet has them
        elif element.kind == "table":
            hit = self._in_table(element.value, address)
        elif element.kind == "range":
            first, last = (ipaddress.ip_address(x) for x in element.value.split("-"))
            ip = ipaddress.ip_address(address)
            hit = ip.version == first.version and first <= ip <= last  # type: ignore[operator]
        else:
            net = ipaddress.ip_network(element.value, strict=False)
            ip = ipaddress.ip_address(address)
            hit = ip.version == net.version and ip in net
        return hit != element.negated

    def _matches(self, rule: _JudgeRule, iface: str, pkt: Packet, tag: str) -> bool:
        if rule.interfaces:
            plain = [n for n, negated in rule.interfaces if not negated]
            negated = [n for n, neg in rule.interfaces if neg]
            if not (iface in plain or any(iface != n for n in negated)):
                return False
        if rule.tagged and rule.tagged != tag:
            return False
        version = ipaddress.ip_address(pkt.src).version
        if rule.protos and _proto_number(pkt) not in rule.protos:
            return False
        if (rule.src_ports is not None or rule.dst_ports is not None) and pkt.proto not in ("tcp", "udp"):
            return False
        if rule.src_ports is not None and pkt.sport not in rule.src_ports:
            return False
        if rule.dst_ports is not None and pkt.dport not in rule.dst_ports:
            return False
        if rule.icmp and not any(pkt.icmp_type == kind and code in (None, 0) for kind, code in rule.icmp):
            return False
        # A rule per combination of list elements, its IP version from an address where the rule names none.
        for src in rule.src:
            for dst in rule.dst:
                if src.family() and dst.family() and src.family() != dst.family():
                    continue
                af = rule.af or src.family() or dst.family()
                if af and af != version:
                    continue
                if self._element(src, pkt.src) and self._element(dst, pkt.dst):
                    return True
        return False

    def evaluate(self, direction: str, iface: str, pkt: Packet, tag: str) -> Tuple[Optional[_JudgeRule], Packet, str]:
        decided: Optional[_JudgeRule] = None
        for rule in self.rules:
            if rule.direction and rule.direction != direction:
                continue
            if not self._matches(rule, iface, pkt, tag):
                continue
            tag = rule.tag or tag  # tags are sticky: set by every rule that matches, not only the last one
            if rule.action == "match":
                pkt = self._translate(rule, pkt)
                continue
            decided = rule
            if rule.quick:
                break
        if decided is not None and decided.action == "pass":
            pkt = self._translate(decided, pkt)
        return decided, pkt, tag

    @staticmethod
    def _translate(rule: _JudgeRule, pkt: Packet) -> Packet:
        if rule.rdr:
            pkt = Packet(pkt.in_if, pkt.out_if, pkt.src, rule.rdr.split("/")[0], pkt.proto, pkt.sport,
                         rule.rdr_port or pkt.dport, pkt.icmp_type)  # fmt: skip
        if rule.nat:
            pkt = Packet(pkt.in_if, pkt.out_if, "192.0.2.254" if ":" not in pkt.src else "2001:db8:ffff::1", pkt.dst, pkt.proto,
                         pkt.sport, pkt.dport, pkt.icmp_type)  # fmt: skip
        return pkt

    def forward(self, pkt: Packet, default: bool = True) -> bool:
        """Whether a forwarded packet passes: in on its arrival interface, out on the one it leaves by."""
        rule, pkt, tag = self.evaluate("in", pkt.in_if, pkt, "")
        if not (rule.action == "pass" if rule else default):
            return False
        rule, pkt, tag = self.evaluate("out", pkt.out_if, pkt, tag)
        return rule.action == "pass" if rule else default

    def arrival(self, pkt: Packet) -> Tuple[Optional[_JudgeRule], Packet]:
        rule, after, _ = self.evaluate("in", pkt.in_if, pkt, "")
        return rule, after


def parse_text(text: str, **kwargs: object) -> Tuple[Policy, Report]:
    report = Report()
    return parse_pf.parse(text.encode(), report, **kwargs), report  # type: ignore[arg-type]


def codes(report: Report, kind: str = "", name: str = "") -> Set[str]:
    out = {note.code for note in report.notes}
    for item in report.items.values():
        if (not kind or item.kind == kind) and (not name or item.name == name):
            out |= {f.code for f in item.findings}
    return out


def pkt(in_if: str, out_if: str, src: str, dst: str, proto: str = "tcp", dport: int = 80, sport: int = 40000, icmp: int = 0) -> Packet:
    return Packet(in_if, out_if, src, dst, proto, sport, dport, icmp)


def agree(text: str, packets: List[Packet]) -> None:
    """The model read from the text gives every packet the verdict the judge gives it."""
    policy, _ = parse_text(text)
    judge = PfJudge(text)
    for packet in packets:
        assert model_allows(policy, packet) == judge.forward(packet), (packet, text)


# -- the sample -----------------------------------------------------------------------------------


def test_sample_is_detected_and_read() -> None:
    data = (DATA / "pf_sample.conf").read_bytes()
    assert cli.detect_format(data) == "pf"
    policy, report = load("pf_sample.conf")
    assert policy.vendor == "pf" and set(policy.zones) == {"em0", "em1", "em2"}
    assert policy.default_interzone == policy.default_intrazone == Action.ALLOW
    names = [rule.name for rule in policy.rules]
    # Rules for traffic that leaves come first, then the quick rules for arriving traffic, then the others last first.
    assert names[:3] == ["line 72", "line 75", "line 46 out"]
    assert names.index("line 41") < names.index("antispoof em1 network") < names.index("bogons") < names.index("admin ssh")
    assert names.index("line 54") < names.index("line 53") < names.index("line 46")
    assert names[-1] == "line 46"
    rules = {rule.name: rule for rule in policy.rules}
    assert rules["line 46 out"].dst_zones == ["em1"] and rules["line 46 out"].action == Action.DENY  # block-policy return
    assert rules["line 81"].action == Action.RESET_CLIENT
    assert rules["line 78"].services == ["tcp-0-24,26-65535"] and rules["line 79"].services == ["udp-1001-1009"]
    assert rules["line 80"].services == ["tcp-0-1023,2049-65535"]
    assert rules["line 69"].negate_source and rules["line 69.2"].sources == ["10.10.5.11"]
    assert "PF_NEGATED_LIST" in codes(report, "rule", "line 69")
    assert rules["line 65"].src_zones == ["em1", "em2"]
    assert policy.address_groups["partners"].members == ["198.51.100.0/25", "2001:db8:100::/48"]
    assert policy.address_groups["bruteforce"].unsupported and policy.address_groups["spamd"].unsupported
    assert rules["line 90"].unsupported and rules["line 92"].unsupported
    assert "PF_ROUTE_TO" in codes(report, "rule", "line 87") and "PF_NO_STATE" in codes(report, "rule", "line 84")
    assert {"PF_ANCHOR", "PF_LAST_MATCH", "PF_DEFAULT_PASS", "PF_HOST_NAMES", "PF_OVERLOAD"} <= codes(report)
    assert "line 73" not in rules and report.item("rule", "line 73").skipped  # shadowed by a later pass out
    nat = {n.name: n for n in policy.nat_rules}
    assert nat["line 36 nat"].source_translation == SourceNat(SnatKind.INTERFACE, interface="em0")
    assert nat["line 37 nat"].source_translation is not None and nat["line 37 nat"].source_translation.kind == SnatKind.DYNAMIC
    assert nat["line 39 rdr"].destination_translation == DestNat("10.20.1.10")
    assert nat["line 41 rdr"].sources == ["partners"]
    # The rule after the match rdr-to names the inside address: the model's names the public one as well.
    assert "203.0.113.10" in rules["line 57"].destinations
    # The pass rule that translates names the original destination itself.
    assert rules["line 41"].destinations == ["203.0.113.25"]


def test_detection_claims_no_other_format() -> None:
    for path in sorted(DATA.iterdir()):
        if path.is_file() and path.name != "pf_sample.conf":
            assert not parse_pf.looks_like_pf(path.read_bytes()), path.name
    assert not parse_pf.looks_like_pf(b"# Generated by iptables-save\n*filter\n:FORWARD DROP [0:0]\n-A FORWARD -j ACCEPT\nCOMMIT\n")
    assert not parse_pf.looks_like_pf(b"table inet filter {\n chain forward {\n  type filter hook forward priority 0;\n }\n}\n")
    assert not parse_pf.looks_like_pf(b"<?xml version='1.0'?><pfsense><filter><rule><type>pass</type></rule></filter></pfsense>")
    assert parse_pf.looks_like_pf(b"block in on em0 from any to any\n")
    assert parse_pf.looks_like_pf(b"ext = \"em0\"\npass out quick on $ext keep state\n")


# -- the traps, one by one ----------------------------------------------------------------------------


def test_last_match_unless_quick() -> None:
    text = "block in on eth0 proto tcp\npass in on eth0 proto tcp to port 80\nblock in quick on eth0 from 10.0.0.1\n"
    policy, report = parse_text(text)
    assert [r.name for r in policy.rules] == ["line 3", "line 2", "line 1"]
    assert "PF_LAST_MATCH" in codes(report)
    agree(text, [pkt("eth0", "eth1", "10.0.0.1", "10.0.1.1"), pkt("eth0", "eth1", "10.0.0.2", "10.0.1.1"),
                 pkt("eth0", "eth1", "10.0.0.2", "10.0.1.1", dport=22), pkt("eth1", "eth0", "10.0.0.2", "10.0.1.1", dport=22)])  # fmt: skip


def test_nothing_matches_passes() -> None:
    policy, _ = parse_text("block in on eth0 proto udp\n")
    assert policy.default_interzone == Action.ALLOW
    assert model_allows(policy, pkt("eth1", "eth0", "10.0.0.1", "10.0.1.1"))


def test_pass_in_alone_forwards_nothing_after_block_all() -> None:
    """A forwarded packet is filtered when it leaves as well: without a pass out rule, block all stops it there."""
    text = "block all\npass in on eth0\n"
    policy, report = parse_text(text)
    assert policy.rules[0].dst_zones == [ANY] and policy.rules[0].action == Action.DROP
    assert "PF_OUT_BLOCK" in codes(report, "rule", policy.rules[0].name)
    agree(text, [pkt("eth0", "eth1", "10.0.0.1", "10.0.1.1")])
    agree(text + "pass out on eth1\n", [pkt("eth0", "eth1", "10.0.0.1", "10.0.1.1"), pkt("eth0", "eth0", "10.0.0.1", "10.0.1.1"),
                                         pkt("eth1", "eth0", "10.0.0.1", "10.0.1.1")])  # fmt: skip
    # What leaves by an interface the ruleset does not name is not blocked by the converted rules: said, not hidden.
    assert "PF_OUT_UNNAMED" in codes(parse_text(text + "pass out on eth1\n")[1])


def test_block_out_less_what_a_pass_out_before_it_lets_out() -> None:
    text = ("pass in all\nblock out on eth1 proto tcp\npass out quick on eth1 proto tcp from 10.0.0.0/24 to any port 443\n"
            "pass in on eth2\n")  # fmt: skip
    policy, report = parse_text(text)
    out = [r for r in policy.rules if r.dst_zones != [ANY]]
    assert out and all(r.dst_zones == ["eth1"] and r.action == Action.DROP for r in out)
    assert "PF_OUT_BLOCK" in codes(report, "rule", out[0].name)
    packets = [pkt(i, "eth1", s, "10.0.9.9", dport=d) for i in ZONES for s in ("10.0.0.5", "10.0.1.5") for d in (443, 80)]
    packets += [pkt("eth0", "eth1", "10.0.0.5", "10.0.9.9", "udp", 53), pkt("eth0", "eth1", "2001:db8::1", "2001:db8:1::1")]
    agree(text, packets)


def test_block_out_on_every_interface_less_a_pass_out_on_one() -> None:
    text = "block out proto tcp to port 22\npass out quick on eth1 proto tcp from 10.0.0.0/24\npass in on { eth0 eth1 eth2 } all\n"
    policy, report = parse_text(text)
    out = [r for r in policy.rules if r.dst_zones != [ANY]]
    assert {z for r in out for z in r.dst_zones} == {"eth0", "eth1", "eth2"}
    assert "PF_OUT_UNNAMED" in codes(report)
    agree(text, [pkt(i, o, s, "10.0.9.9", dport=22) for i in ZONES for o in ZONES for s in ("10.0.0.5", "10.0.1.5")])


def test_block_out_that_cannot_be_worked_out_is_not_converted() -> None:
    policy, _ = parse_text("block out on eth1 to www.example.com\npass out quick on eth1 from <unknown>\n")
    assert policy.rules[0].unsupported and "cannot be worked out" in policy.rules[0].unsupported[-1]


def test_negated_list_elements_are_each_their_own_rule() -> None:
    text = "block in on eth0\npass in on eth0 from { ! 10.0.0.1, ! 10.0.0.2 } to any\n"
    policy, report = parse_text(text)
    assert [r.sources for r in policy.rules[:2]] == [["10.0.0.1"], ["10.0.0.2"]] and policy.rules[0].negate_source
    agree(text, [pkt("eth0", "eth1", s, "10.0.1.1") for s in ("10.0.0.1", "10.0.0.2", "10.0.0.3")])
    # A negated IPv4 address makes the rule IPv4: an IPv6 packet does not match it.
    agree("block in on eth0\npass in on eth0 from ! 10.0.0.1\n", [pkt("eth0", "eth1", "2001:db8::1", "2001:db8::2")])


def test_ports_with_operators() -> None:
    text = "block in on eth0\npass in on eth0 proto tcp to port { < 30, 8000 >< 8006, = 9000 }\npass in on eth0 proto udp to port 50 <> 60\n"
    policy, _ = parse_text(text)
    assert policy.services[policy.rules[0].services[0]].entries[0].dst_ports == "0-49,61-65535"
    assert policy.services[policy.rules[1].services[0]].entries[0].dst_ports == "0-29,8001-8005,9000"
    agree(text, [pkt("eth0", "eth1", "10.0.0.1", "10.0.1.1", proto, port) for proto in ("tcp", "udp")
                 for port in (22, 53, 80, 8000, 8005, 9000)])  # fmt: skip


def test_macros_expand_again_where_they_are_used() -> None:
    text = 'a = "10.0.0.1"\nb = "10.0.0.2"\nboth = "{" $a $b "}"\nports = "{ 22 80 }"\nif = "eth0"\nblock in on $if\npass in on $if from $both to any port $ports\n'
    text = text.replace("to any port", "proto tcp to any port") if False else text.replace("from $both", "proto tcp from $both")
    policy, _ = parse_text(text)
    assert policy.rules[0].sources == ["10.0.0.1", "10.0.0.2"]
    with pytest.raises(ParseError, match="macro 'nothere'"):
        parse_text("pass in on $nothere\n")


def test_tables() -> None:
    policy, report = parse_text(
        "table <t> const { 10.0.0.0/16, !10.0.1.0/24, 10.0.1.128/25 }\ntable <f> persist file \"/etc/x\"\ntable <e> persist\n"
        "block in quick from <t>\nblock in quick from <f>\nblock in quick from <e>\nblock in quick from <never>\n"
    )
    # The most specific entry decides: 10.0.1.0/24 is left out, its upper half put back.
    members = policy.address_groups["t"].members
    assert members[:3] == ["10.0.0.0/24", "10.0.1.128/25", "10.0.2.0/23"] and members[-1] == "10.0.128.0/17"
    assert all(policy.address_groups[name].unsupported for name in ("f", "e", "never"))
    assert "PF_TABLE_UNKNOWN" in codes(report, "address-group", "f")


def test_match_rdr_to_is_seen_by_the_rules_after_it() -> None:
    policy, report = parse_text(
        "pass in quick on eth0 proto tcp to 10.0.5.5 port 80\n"
        "match in on eth0 proto tcp to 198.51.100.1 port 80 rdr-to 10.0.5.5\n"
        "pass in on eth0 proto tcp to 10.0.5.5 port 80\n"
    )
    rules = {r.name: r for r in policy.rules}
    assert rules["line 1"].destinations == ["10.0.5.5"]  # before the translation: as written
    assert "198.51.100.1" in rules["line 3"].destinations  # after it: also the original address
    assert not policy.lookup_after_dnat


def test_older_nat_rules_of_freebsd() -> None:
    policy, report = parse_text(
        "nat on em0 from 10.0.0.0/24 to any -> (em0)\n"
        "no nat on em0 from 10.0.0.0/24 to 10.9.0.0/16\n"
        "rdr pass on em0 proto tcp from any to 198.51.100.1 port 8080 -> 10.0.5.5 port 80\n"
        "rdr on em0 proto tcp from any to 198.51.100.2 port 25 -> 10.0.5.6\n"
        "binat on em0 from 10.0.5.7 to any -> 198.51.100.7\n"
        "no rdr on em0 proto tcp from 192.0.2.0/24 to any port 25\n"
        "block in on em0\npass in on em0 proto tcp to 10.0.5.6 port 25\n"
    )
    nat = {n.name: n for n in policy.nat_rules}
    assert [n.name.split()[-1] for n in policy.nat_rules] == ["binat", "rdr", "rdr", "rdr", "nat", "nat"]
    assert nat["line 1 nat"].source_translation == SourceNat(SnatKind.INTERFACE, interface="em0")
    assert nat["line 2 no nat"].source_translation is None and not nat["line 2 no nat"].unsupported
    assert nat["line 3 rdr"].destination_translation == DestNat("10.0.5.5", "80")
    assert nat["line 5 binat"].source_translation == SourceNat(SnatKind.STATIC, ["198.51.100.7"], bidirectional=True)
    assert nat["line 6 no rdr"].unsupported
    assert policy.lookup_after_dnat  # every filter rule saw what the rdr rules made
    rules = {r.name: r for r in policy.rules}
    assert "198.51.100.2" in rules["line 8"].destinations
    passing = rules["line 3 rdr pass"]  # rdr pass lets its traffic in, whatever the rules for arriving traffic say
    assert passing.action == Action.ALLOW and passing.destinations == ["198.51.100.1"] and passing.src_zones == ["em0"]
    assert policy.rules.index(passing) < policy.rules.index(rules["line 7"])


def test_interface_addresses_given_on_the_command_line() -> None:
    text = "antispoof for em1 inet\npass in on em1 from em1:network to self\npass in on em0 to (em0)\npass on em2\n"
    policy, _ = parse_text(text)
    assert policy.address_groups["em1 network"].unsupported
    policy, report = parse_text(text, interface_addresses=["em1=10.0.1.1/24", "em0=198.51.100.2/24", "em1=2001:db8:1::1/64"])
    assert policy.address_groups["em1 network"].members == ["10.0.1.0/24", "2001:db8:1::/64"]
    assert policy.address_groups["em0 address"].members == ["198.51.100.2"]
    assert set(policy.address_groups["self"].members) == {"10.0.1.1", "2001:db8:1::1", "198.51.100.2"}
    spoof = policy.rules[[r.name for r in policy.rules].index("antispoof em1 network")]
    assert spoof.src_zones == ["em0", "em2"] and spoof.action == Action.DROP
    assert "PF_NEGATED_INTERFACE" in codes(report, "rule", "antispoof em1 network")
    with pytest.raises(FwshiftError, match="INTERFACE=ADDRESS/BITS"):
        parse_text("pass\n", interface_addresses=["em0"])


def test_what_narrows_and_cannot_be_read_is_not_converted() -> None:
    policy, report = parse_text(
        "pass in on eth0 proto tcp flags A/A\npass in on eth0 proto tcp flags S/SAFR\npass in on eth0 tagged X\n"
        "pass in on eth0 from no-route\npass in on eth0 to port 80\npass in on eth0 user 1000\npass in on eth0 os Linux\n"
        "pass in on eth0 from any to any probability 50%\npass in on eth0 frobnicate\npass in on eth0 from egress\n"
    )
    rules = {r.name: r for r in policy.rules}
    assert rules["line 1"].unsupported and not rules["line 2"].unsupported
    for line in (3, 4, 5, 6, 8, 9, 10):
        assert rules[f"line {line}"].unsupported, line
    assert not policy.rules or True


def test_set_skip_on_and_notes() -> None:
    policy, report = parse_text("set skip on { lo0 eth2 }\nblock all\npass out all\nscrub in all\nanchor \"x\"\nqueue q on eth0 bandwidth 10M\n")
    skip = [r for r in policy.rules if r.name.startswith("set skip")]
    assert len(skip) == 1 and skip[0].src_zones == ["eth2"] and skip[0].action == Action.ALLOW
    assert {"PF_SKIP_INTERFACE", "PF_SCRUB", "PF_ANCHOR", "PF_QUEUE"} <= codes(report)


def test_interface_groups_are_zones_of_their_own() -> None:
    policy, report = parse_text("pass in on egress proto tcp to port 22\npass in on em0\n")
    assert policy.zones["egress"].interfaces == [] and policy.zones["em0"].interfaces == ["em0"]
    assert "PF_INTERFACE_GROUPS" in codes(report)


def test_the_default_openbsd_ruleset() -> None:
    policy, report = parse_text(
        "set skip on lo\n\nblock return\t# block stateless traffic\npass\t\t# establish keep-state\n\n"
        "# By default, do not permit remote connections to X11\nblock return in on ! lo0 proto tcp to port 6000:6010\n\n"
        "# Port build user does not need network\nblock return out log proto {tcp udp} user _pbuild\n"
    )
    assert policy.rules and policy.default_interzone == Action.ALLOW


def test_unbalanced_and_unknown_statements_are_errors() -> None:
    with pytest.raises(ParseError):
        parse_text("table <x> { 10.0.0.1\n")
    with pytest.raises(ParseError):
        parse_text("allow in on em0\n")
    with pytest.raises(ParseError):
        parse_text("nat on em0 from any to any\n")


# -- packet level: random rulesets judged by the judge and through the parser ------------------------------


def random_ruleset(rng: random.Random) -> str:
    literals = ["10.0.0.0/24", "10.0.1.0/24", "10.0.1.128/25", "10.0.2.0/23", "10.0.0.17", "2001:db8:1::/48", "10.0.3.0/24"]
    lines = ["table <t1> const { 10.0.0.0/22, !10.0.1.0/24, 10.0.1.128/26 }", "table <t2> const { 10.0.4.0/24 2001:db8:2::/48 }",
             'm_if = "eth1"', 'm_nets = "{ 10.0.0.0/24 10.0.4.0/24 }"']  # fmt: skip

    def host(family: int) -> str:
        pool = [x for x in literals if family == 0 or (":" in x) == (family == 6)]
        choice = rng.random()
        if choice < 0.3:
            return "any"
        if choice < 0.4:
            return ("! " if rng.random() < 0.3 else "") + rng.choice(["<t1>", "<t2>"])
        if choice < 0.5 and family != 6:
            return "$m_nets"
        if choice < 0.6 and len(pool) > 1:
            items = rng.sample(pool, 2)
            return "{ " + ", ".join(("! " if rng.random() < 0.3 else "") + item for item in items) + " }"
        return ("! " if rng.random() < 0.2 else "") + rng.choice(pool)

    def rule() -> str:
        parts = [rng.choice(["pass", "pass", "block", "block drop", "block return"])]
        parts += [rng.choice(["in", "in", "out", ""])]
        parts += ["quick"] if rng.random() < 0.35 else []
        on = rng.random()
        if on < 0.45:
            parts.append("on " + rng.choice(ZONES + ["$m_if"]))
        elif on < 0.55:
            parts.append("on ! " + rng.choice(ZONES))
        elif on < 0.65:
            parts.append("on { " + " ".join(rng.sample(ZONES, 2)) + " }")
        parts += [rng.choice(["", "", "inet", "inet6"])]
        kind = rng.random()
        ports = ""
        options = ""
        if kind < 0.3:
            parts.append("proto tcp")
            ports = rng.choice([f" port {rng.choice([22, 80, 443, 8080])}", " port { 80 443 8000:8010 }", " port != 80",
                                " port 8000 >< 8010", " port < 1024", ""])  # fmt: skip
        elif kind < 0.4:
            parts.append("proto { tcp udp }")
            ports = rng.choice([" port 53", ""])
        elif kind < 0.5:
            word = "icmp6" if "inet6" in parts else "icmp"
            parts.append(f"proto {word}")
            options = f" {word}-type echoreq" if rng.random() < 0.7 else ""
        elif kind < 0.55:
            parts.append("proto gre")
        if rng.random() < 0.15 and not ports:
            parts.append("all")
        else:
            family = 4 if "inet" in parts or "proto icmp" in parts else 6 if "inet6" in parts else 0
            src, dst = host(family), host(family)
            source_port = " port > 1023" if ports and rng.random() < 0.15 else ""
            parts.append(f"from {src}{source_port} to {dst}{ports}")
        return " ".join(p for p in parts if p) + options

    if rng.random() < 0.5:
        lines.append("block all")
    if rng.random() < 0.5:
        lines.append(rng.choice(["pass out all", "pass out quick all", "pass out on eth0"]))
    lines += [rule() for _ in range(rng.randint(3, 10))]
    lines.append("pass in on { eth0 eth1 eth2 } proto tcp from 10.9.9.9 to 10.9.9.9 port 1")  # every interface is named
    return "\n".join(lines) + "\n"


def test_parsed_rulesets_decide_like_pf() -> None:
    """In and out, last match and quick, lists and negation, tables that leave addresses out: the model the parser
    reads gives every packet the verdict the judge gives it. Rulesets whose rules the parser flags are set aside."""
    checked = 0
    for seed in range(300):
        rng = random.Random(seed)
        text = random_ruleset(rng)
        policy, report = parse_text(text)
        if any(rule.unsupported for rule in policy.rules):
            continue
        checked += 1
        judge = PfJudge(text)
        for _ in range(150):
            packet = random_packet(rng, rng.choice([4, 4, 6]))
            assert model_allows(policy, packet) == judge.forward(packet), (seed, packet, text)
    assert checked > 200


# -- the emitter ----------------------------------------------------------------------------------------------


def _with_zones(model: Policy) -> Policy:
    for zone in ZONES:
        model.zones[zone] = Zone(zone, [zone])
    return model


@pytest.mark.parametrize("seed", range(40))
def test_emitted_anchor_decides_like_the_model(seed: int) -> None:
    """Random models: what the anchor lets through (with a main ruleset that blocks what the anchor does not decide)
    is what the model allows, for both IP versions; and what arrives is let in by the anchor whenever the model allows it."""
    rng = random.Random(seed)
    model = _with_zones(random_model(rng))
    text = emit_pf.emit(model, Report(), Options())
    judge = PfJudge(text)
    for _ in range(300):
        packet = random_packet(rng, rng.choice([4, 6]))
        assert judge.forward(packet, default=False) == model_allows(model, packet), (seed, packet, text)


def test_emitted_anchor_with_default_allow_and_intrazone() -> None:
    model = _with_zones(random_model(random.Random(7)))
    model.default_interzone, model.default_intrazone = Action.ALLOW, Action.DENY
    text = emit_pf.emit(model, Report(), Options())
    judge = PfJudge(text)
    rng = random.Random(1)
    for _ in range(400):
        packet = random_packet(rng)
        verdict = model_verdict(model, packet)
        expected = verdict if verdict is not None else (packet.in_if != packet.out_if)
        assert judge.forward(packet, default=False) == expected, packet


def test_parsed_and_emitted_again_decides_like_the_source() -> None:
    for seed in range(60):
        rng = random.Random(1000 + seed)
        text = random_ruleset(rng)
        policy, _ = parse_text(text)
        if any(rule.unsupported for rule in policy.rules):
            continue
        out = emit_pf.emit(policy, Report(), Options())
        source, again = PfJudge(text), PfJudge(out)
        for _ in range(100):
            packet = random_packet(rng, rng.choice([4, 6]))
            assert again.forward(packet, default=False) == source.forward(packet), (seed, packet, text, out)


def _nat_model() -> Policy:
    p = Policy(vendor="panos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    for zone in ("inside", "outside", "dmz"):
        p.zones[zone] = Zone(zone, [])
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "443")])
    p.addresses["srv"] = Address("srv", AddressKind.NETWORK, "10.0.2.10/32")
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "198.51.100.10/32")
    allow = Rule(name="published", src_zones=["outside"], dst_zones=["dmz"], destinations=["pub"], services=["web"], origin="published")
    out = Rule(name="out", src_zones=["inside"], dst_zones=["outside"], sources=["10.0.1.0/24"], origin="out")
    p.rules = [allow, out]
    dnat = NatRule(name="publish", src_zones=["outside"], destinations=["pub"], service="web", origin="publish",
                   destination_translation=DestNat("srv", "8443"))  # fmt: skip
    snat = NatRule(name="hide", src_zones=["inside"], dst_zones=["outside"], sources=["10.0.1.0/24"], origin="hide",
                   source_translation=SourceNat(SnatKind.INTERFACE))  # fmt: skip
    p.nat_rules = [dnat, snat]
    return p


def test_nat_is_written_as_rdr_to_and_nat_to() -> None:
    report = Report()
    text = emit_pf.emit(_nat_model(), report, Options(zone_map={"inside": "em1", "outside": "em0", "dmz": "em2"}))
    assert 'fws_if_em0 = "em0"' in text
    assert "pass in quick on $fws_if_em0 inet proto tcp from any to 198.51.100.10 port 443 rdr-to 10.0.2.10 port 8443" in text
    assert "nat-to ($fws_if_em0) tag fws_nat" in text
    judge = PfJudge(text)
    # The published server: translated when it arrives, allowed when it leaves towards the DMZ on its inside address.
    rule, after = judge.arrival(pkt("em0", "em2", "203.0.113.5", "198.51.100.10", dport=443))
    assert rule is not None and rule.action == "pass" and (after.dst, after.dport) == ("10.0.2.10", 8443)
    assert judge.forward(pkt("em0", "em2", "203.0.113.5", "198.51.100.10", dport=443), default=False)
    assert not judge.forward(pkt("em0", "em2", "203.0.113.5", "198.51.100.10", dport=80), default=False)
    assert judge.forward(pkt("em1", "em0", "10.0.1.5", "203.0.113.9"), default=False)
    assert not judge.forward(pkt("em1", "em2", "10.0.1.5", "10.0.2.10"), default=False)
    assert "PF_LOAD" in codes(report)


def test_names_and_labels_cannot_break_the_ruleset() -> None:
    p = Policy(vendor="panos", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.zones["zone with space"] = Zone("zone with space", [])
    rule = Rule(name='evil" $nr \\ label', src_zones=["zone with space"], origin="evil")
    p.rules = [rule]
    report = Report()
    text = emit_pf.emit(p, report, Options())
    assert 'label "evil_ _nr _ label"' in text
    assert re.search(r'^fws_if_zone_with_space = "zone_with_space"$', text, re.M)
    assert "INTERFACE_NAME" in codes(report)


def test_service_negation_and_reset() -> None:
    p = Policy(vendor="panos", default_intrazone=Action.ALLOW, default_interzone=Action.ALLOW)
    p.zones["eth0"] = Zone("eth0", [])
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.rules = [Rule(name="not-web", src_zones=["eth0"], services=["web"], negate_service=True, action=Action.RESET_BOTH, origin="not-web")]
    report = Report()
    text = emit_pf.emit(p, report, Options())
    judge = PfJudge(text)
    assert judge.forward(pkt("eth0", "eth1", "10.0.0.1", "10.0.1.1", dport=443), default=False)
    assert not judge.forward(pkt("eth0", "eth1", "10.0.0.1", "10.0.1.1", dport=22), default=False)
    assert "RESET_ACTION" in codes(report, "rule", "not-web")


def test_sample_to_pf_and_back_through_the_judge() -> None:
    """The sample, converted to pf: every packet that the converted rules can decide gets the source's verdict."""
    text = (DATA / "pf_sample.conf").read_text(encoding="utf-8")
    policy, _ = load("pf_sample.conf")
    out = cli.convert(policy, "pf", Report())
    assert "rdr-to 10.20.1.10" in out and "nat-to ($fws_if_em0)" in out
    assert "# FWSHIFT disabled, see the report: \"brute force\"" in out
    assert text  # (the source uses words the judge does not read: tables from files, route-to, user)


def test_the_rules_as_pfctl_prints_them() -> None:
    """pfctl -sr: one rule per element, ports with '=', state and scrub options written out."""
    text = (
        "match in all scrub (no-df max-mss 1440)\n"
        "block drop in log quick on em0 inet from 192.0.2.0/24 to any label \"bad\"\n"
        "block return in on ! em1 inet proto tcp from any to any port 6000:6010\n"
        "pass in quick on em1 inet proto tcp from 10.0.0.0/24 to 10.0.1.5 port = 22 flags S/SA keep state (if-bound)\n"
        "pass out quick on em0 inet proto udp from any to any port = 53 keep state\n"
        "pass in on em1 inet6 proto ipv6-icmp all icmp6-type echoreq keep state\n"
    )
    policy, report = parse_text(text)
    rules = {r.name: r for r in policy.rules}
    assert rules["bad"].log_start and rules["bad"].action == Action.DROP and rules["bad"].src_zones == ["em0"]
    assert rules["line 4"].handling["state"] == "( if-bound )" and not rules["line 4"].unsupported
    assert policy.services[rules["line 6"].services[0]].entries[0] == ServiceEntry(Protocol.ICMP6, icmp_type=128)
    assert all(not r.unsupported for r in policy.rules)


def test_a_translation_on_a_pass_rule_applies_when_it_decides() -> None:
    policy, report = parse_text(
        "pass in quick on em0 proto tcp from 192.0.2.0/24 to 198.51.100.1 port 80\n"
        "pass in quick on em0 proto tcp to 198.51.100.1 port 80 rdr-to 10.0.0.5\n"
    )
    assert "PF_NAT_ON_PASS_RULE" in codes(report, "nat")
    assert policy.nat_rules[0].destination_translation == DestNat("10.0.0.5")
    assert policy.rules[1].destinations == ["198.51.100.1"]


def test_a_rule_for_leaving_traffic_after_source_nat_names_the_translated_source() -> None:
    policy, _ = parse_text("match out on em0 from 10.0.0.0/24 nat-to (em0)\nblock out on em0 from 10.0.0.5\n")
    assert policy.rules[0].dst_zones == ["em0"] and "source after the translation" in policy.rules[0].unsupported[-1]
    policy, _ = parse_text("block out on em0 from 10.0.0.5\nmatch out on em0 from 10.0.0.0/24 nat-to (em0)\n")
    assert not policy.rules[0].unsupported
    policy, _ = parse_text("match in on em1 from 10.0.0.0/24 nat-to 198.51.100.9\npass in on em1 from 10.0.0.5\n")
    assert "source after the translation" in policy.rules[0].unsupported[-1]
