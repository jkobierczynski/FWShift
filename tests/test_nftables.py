# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""nftables: parser, emitter, and packet-level equivalence between a ruleset and the model.

The reference below walks the chains of a ruleset the way the kernel does (every base chain at the forward hook in
the order of its priority, an accept going on to the next, a drop final; jump, goto, return, verdict maps, sets),
from the structure the reader got out of the text. It shares no code with the parser's reading of what a rule
matches. Where ``nft`` can run (as root, in a network namespace of its own), the generated rulesets are also loaded
into the kernel and read back as ``nft list ruleset`` and ``nft -j list ruleset`` print them.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import pytest
from helpers import load
from test_iptables import Packet, model_allows, random_model, random_packet

from fwshift import cli
from fwshift.emitters import nftables as emit_nftables
from fwshift.errors import ParseError
from fwshift.model import ANY, ANY_V4, ANY_V6, Action, Address, AddressKind, Policy, Rule, SnatKind
from fwshift.options import Options
from fwshift.parsers import nftables as parse_nftables
from fwshift.report import Report

# -- running nft ----------------------------------------------------------------------


def _nft_usable() -> bool:
    if not shutil.which("nft") or not shutil.which("unshare") or os.geteuid() != 0:
        return False
    try:
        done = subprocess.run(["unshare", "-n", "nft", "list", "ruleset"], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


NFT = _nft_usable()


def nft(text: str) -> Optional[Tuple[str, str]]:
    """Load a ruleset into the kernel (in a network namespace of its own) and list it back: (text, JSON).
    None when it does not load; the error is in the assertion message of the caller."""
    script = 'nft -f - && nft list ruleset && echo "=====JSON=====" && nft -j list ruleset'
    done = subprocess.run(["unshare", "-n", "sh", "-c", script], input=text.encode(), capture_output=True, timeout=60)
    if done.returncode:
        raise AssertionError(done.stderr.decode() + "\n" + text)
    listed, _, document = done.stdout.decode().partition("=====JSON=====\n")
    return listed, document


def nft_check(text: str) -> str:
    """What 'nft -c -f' says about a ruleset; "" when it accepts it."""
    done = subprocess.run(["unshare", "-n", "nft", "-c", "-f", "-"], input=text.encode(), capture_output=True, timeout=60)
    return done.stderr.decode() if done.returncode else ""


# -- the reference: a walk through the chains -------------------------------------------

_PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}
_NAMES = {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58, "icmpv6": 58, "gre": 47, "sctp": 132, "echo-request": 8,
          "echo-reply": 0, "established": "established", "related": "related",
          "new": "new", "invalid": "invalid", "untracked": "untracked", "ipv4": 4, "ipv6": 6}  # fmt: skip


def _family(pkt: Packet) -> int:
    return 6 if ":" in pkt.src else 4


def _field(key: str, pkt: Packet) -> Optional[object]:
    """What the packet has for a key of a match; None if the key does not apply to it (no match)."""
    family = _family(pkt)
    proto = _PROTO.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
    if key in ("meta iifname", "meta iif"):
        return pkt.in_if
    if key in ("meta oifname", "meta oif"):
        return pkt.out_if
    if key in ("ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr"):
        if (key.startswith("ip ")) != (family == 4):
            return None
        return ipaddress.ip_address(pkt.src if key.endswith("saddr") else pkt.dst)
    if key == "meta l4proto":
        return proto
    if key == "ip protocol":
        return proto if family == 4 else None
    if key == "meta nfproto":
        return family
    if key == "ct state":
        return pkt.state.lower()
    head, _, part = key.partition(" ")
    if part in ("dport", "sport"):
        if head == "th":
            ok = proto in (6, 17, 132)
        else:
            ok = proto == _PROTO.get(head, -2)
        if not ok:
            return None
        return pkt.dport if part == "dport" else pkt.sport
    if key == "icmp type":
        return pkt.icmp_type if proto == 1 and family == 4 else None
    if key == "icmpv6 type":
        return pkt.icmp_type if proto == 58 and family == 6 else None
    if key in ("icmp code", "icmpv6 code"):
        return 0 if (proto == 1) == (key == "icmp code") and proto in (1, 58) else None
    raise AssertionError(f"the reference does not know {key}")


_ICMP6 = {"echo-request": 128, "echo-reply": 129, "nd-neighbor-solicit": 135}


def _holds(value: object, text: str, key: str = "") -> bool:
    """Whether a value is the element written as text (an address, a prefix, a range, a number, a name)."""
    if key == "icmpv6 type" and text in _ICMP6:
        return value == _ICMP6[text]
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        if "-" in text:
            first, last = (ipaddress.ip_address(t) for t in text.split("-"))
            return first.version == value.version and first <= value <= last  # type: ignore[operator]
        network = ipaddress.ip_network(text, strict=False)
        return network.version == value.version and value in network
    if isinstance(value, int):
        if "-" in text and text[0].isdigit():
            first, last = text.split("-")
            return int(first) <= value <= int(last)
        return value == (_NAMES[text] if text in _NAMES else int(text))
    return value == _NAMES.get(text, text)


def _elements(match: "parse_nftables._Match", table: "parse_nftables._Table") -> List["parse_nftables._Elem"]:
    return table.sets[match.ref].elems if match.ref else match.elems


def _matches(rule: "parse_nftables._NRule", table: "parse_nftables._Table", pkt: Packet) -> bool:
    for match in rule.matches:
        values = [_field(key, pkt) for key in match.keys]
        if any(v is None for v in values):
            return False
        found = any(all(_holds(v, t, k) for v, t, k in zip(values, elem.key, match.keys)) for elem in _elements(match, table))
        if found != (match.op == "=="):
            return False
    return True


def reference_allows(ruleset: "parse_nftables._Ruleset", pkt: Packet) -> bool:
    family = _family(pkt)
    chains = []
    for table in ruleset.tables.values():
        if table.family not in ("inet", "ip" if family == 4 else "ip6"):
            continue
        for chain in table.chains.values():
            if chain.type == "filter" and chain.hook == "forward":
                chains.append((chain.priority, table.order, table, chain))
    chains.sort(key=lambda item: (item[0], item[1]))

    def walk(table: "parse_nftables._Table", chain: "parse_nftables._Chain", depth: int) -> Optional[str]:
        assert depth < 30
        for rule in chain.rules:
            assert not rule.unsupported, rule.unsupported
            if not _matches(rule, table, pkt):
                continue
            verdict = rule.verdict
            if rule.vmap is not None:
                verdict = None
                values = [_field(key, pkt) for key in rule.vmap.keys]
                if any(v is None for v in values):
                    continue
                for elem in _elements(rule.vmap, table):
                    if all(_holds(v, t, k) for v, t, k in zip(values, elem.key, rule.vmap.keys)):
                        verdict = elem.data
                        break
            if verdict is None or verdict.kind == "continue":
                continue
            if verdict.kind in ("accept", "drop", "reject"):
                return verdict.kind
            if verdict.kind == "return":
                return None
            if verdict.kind == "jump":
                result = walk(table, table.chains[verdict.target], depth + 1)
                if result is not None:
                    return result
                continue
            if verdict.kind == "goto":
                # The end of the other chain returns to where this one would have returned to.
                return walk(table, table.chains[verdict.target], depth + 1)
            raise AssertionError(verdict)
        return None

    for _, _, table, chain in chains:
        result = walk(table, chain, 0)
        if result is None:
            result = chain.policy
        if result != "accept":
            return False
    return True


# -- random rulesets ------------------------------------------------------------------

ZONES = ["eth0", "eth1", "eth2"]
PORTS = [22, 53, 80, 443, 8000, 8005, 8080, 9000]


def random_ruleset(rng: random.Random) -> str:
    """An nft input file: an ip and an inet table, several base chains at the forward hook, named and anonymous sets,
    negation, verdict maps, jump, goto and return, connection states, concatenations."""
    v4 = ["10.0.0.0/24", "10.0.1.0/24", "10.0.1.128/25", "10.0.2.0/23", "10.0.0.17", "10.0.2.100-10.0.3.50"]
    v6 = ["2001:db8:1::/48", "2001:db8:2::/64", "2001:db8::1"]

    def addresses(six: bool) -> str:
        pool = v6 if six else v4
        chosen = rng.sample(pool, rng.randint(1, 2))
        return chosen[0] if len(chosen) == 1 else "{ " + ", ".join(chosen) + " }"

    def match(table: str, interfaces: bool = True) -> str:
        parts: List[str] = []
        if interfaces and rng.random() < 0.4:
            parts.append(f'iifname "{rng.choice(ZONES)}"')
        if interfaces and rng.random() < 0.3:
            parts.append('oifname { "' + '", "'.join(rng.sample(ZONES, 2)) + '" }')
        six = table == "inet" and rng.random() < 0.3
        word = "ip6" if six else "ip"
        if rng.random() < 0.4:
            if not six and rng.random() < 0.3:
                parts.append(f"ip saddr {'!= ' if rng.random() < 0.3 else ''}@lan")
            else:
                parts.append(f"{word} saddr {'!= ' if rng.random() < 0.25 else ''}{addresses(six)}")
        if rng.random() < 0.4:
            parts.append(f"{word} daddr {'!= ' if rng.random() < 0.25 else ''}{addresses(six)}")
        kind = rng.random()
        if kind < 0.25:
            parts.append(f"tcp dport {rng.choice(PORTS)}")
        elif kind < 0.35:
            parts.append("tcp dport { 80, 443, 8000-8010 }")
        elif kind < 0.42:
            parts.append("meta l4proto { tcp, udp } th dport 53")
        elif kind < 0.48:
            parts.append("udp dport 53 udp sport 1024-65535")
        elif kind < 0.54:
            parts.append("icmpv6 type echo-request" if six else "icmp type echo-request")
        elif kind < 0.58:
            parts.append("meta l4proto gre")
        elif kind < 0.62:
            parts.append(f"tcp dport != {rng.choice(PORTS)}")
        elif kind < 0.66 and not six:
            parts.append("ip saddr . tcp dport { 10.0.0.17 . 22, 10.0.1.200 . 443 }")
        elif kind < 0.7:
            parts.append("meta l4proto != { tcp, udp }")
        if rng.random() < 0.25:
            parts.append("ct state new")
        return " ".join(parts)

    def verdict(chains: List[str]) -> str:
        choice = rng.random()
        if chains and choice < 0.2:
            return f"{rng.choice(['jump', 'jump', 'goto'])} {rng.choice(chains)}"
        return rng.choice(["accept", "accept", "drop", "reject", "counter accept", "log prefix \"x \" drop"])

    tables = []
    stateful = rng.random() < 0.75  # both tables accept established packets, or neither
    for family in ("ip", "inet"):
        if family == "ip" and rng.random() < 0.4:
            continue
        lines = [f"table {family} t{family} {{", "\tset lan { type ipv4_addr; flags interval; elements = { 10.0.0.0/24, 10.0.4.0/24 } }"]
        prio = rng.choice([-10, 0, 10]) if family == "ip" else 0
        policy = rng.choice(["drop", "drop", "accept"])
        lines += ["\tchain forward {", f"\t\ttype filter hook forward priority {prio}; policy {policy};"]
        if stateful:
            lines.append("\t\tct state vmap { invalid : drop, established : accept, related : accept }")
        for _ in range(rng.randint(2, 7)):
            choice = rng.random()
            if choice < 0.12:
                lines.append('\t\tiifname vmap { "eth1" : jump c1, "eth2" : goto c2 }')
            elif choice < 0.18:
                lines.append(f"\t\t{match(family)} log prefix \"seen \"")
            else:
                lines.append(f"\t\t{match(family)} {verdict(['c1', 'c2'])}".replace("\t\t ", "\t\t"))
        lines.append("\t}")
        for chain, others in (("c1", ["c2"]), ("c2", [])):
            lines.append(f"\tchain {chain} {{")
            for _ in range(rng.randint(1, 4)):
                if rng.random() < 0.15:
                    lines.append(f"\t\t{match(family, interfaces=False)} return".replace("\t\t ", "\t\t"))
                else:
                    lines.append(f"\t\t{match(family, interfaces=False)} {verdict(others)}".replace("\t\t ", "\t\t"))
            if rng.random() < 0.3:
                lines += ["\t\treturn", "\t\taccept"]
            lines.append("\t}")
        lines.append("}")
        tables.append("\n".join(lines))
    return "flush ruleset\n" + "\n".join(tables) + "\n"


def random_nft_packet(rng: random.Random) -> Packet:
    family = rng.choice([4, 4, 6])
    pkt = random_packet(rng, family)
    if family == 4 and rng.random() < 0.3:
        pkt.src = rng.choice(["10.0.0.17", "10.0.1.200", "10.0.4.9", "10.0.2.120"])
    if rng.random() < 0.2:
        pkt.proto = rng.choice(["sctp", "udp"])
    return pkt


def _compare(text: str, ruleset: "parse_nftables._Ruleset", rng: random.Random, seed: int) -> bool:
    model = parse_nftables._Builder(ruleset, Report()).build()
    if any(rule.unsupported for rule in model.rules):
        return False
    for _ in range(300):
        pkt = random_nft_packet(rng)
        assert model_allows(model, pkt) == reference_allows(ruleset, pkt), (seed, pkt, text)
    return True


def test_parsed_ruleset_decides_like_a_walk_through_the_chains() -> None:
    """Flattened chains, combined base chains, sets and maps agree with the reference walk.

    A ruleset with a construct the parser flags (those rules would be converted disabled) is left out of the
    comparison; most generated rulesets have none.
    """
    compared = 0
    for seed in range(120):
        rng = random.Random(3000 + seed)
        text = random_ruleset(rng)
        compared += _compare(text, parse_nftables.read(text.encode()), rng, seed)
    assert compared >= 80


@pytest.mark.skipif(not NFT, reason="needs nft, unshare and root")
def test_kernel_listing_reads_like_the_input() -> None:
    """The rulesets loaded into the kernel: 'nft list ruleset' and its JSON give the same model, which decides as
    the input does."""
    for seed in range(40):
        rng = random.Random(3000 + seed)
        text = random_ruleset(rng)
        listed = nft(text)
        assert listed is not None
        listing, document = listed
        from_text = parse_nftables.parse(listing.encode(), Report())
        from_json = parse_nftables.parse(document.encode(), Report())
        assert from_text.to_json() == from_json.to_json(), (seed, listing)
        _compare(listing, parse_nftables.read(listing.encode()), random.Random(seed), seed)


# -- the emitter ----------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(40))
def test_emitted_ruleset_decides_like_the_model(seed: int) -> None:
    """Whatever the lists, negations and rule types: the emitted table gives the model's verdict, for both IP
    versions at once."""
    rng = random.Random(seed)
    model = random_model(rng)
    text = emit_nftables.emit(model, Report(), Options())
    ruleset = parse_nftables.read(text.encode())
    for _ in range(400):
        pkt = random_packet(rng, rng.choice([4, 6]))
        assert reference_allows(ruleset, pkt) == model_allows(model, pkt), (seed, pkt, text)


@pytest.mark.skipif(not NFT, reason="needs nft, unshare and root")
def test_emitted_rulesets_load() -> None:
    for seed in range(40):
        text = emit_nftables.emit(random_model(random.Random(seed)), Report(), Options())
        assert nft_check(text) == "", (seed, text)
    for name in ("panos_sample.xml", "fortios_sample.conf", "checkpoint_sample.json", "iptables_sample.rules",
                 "nftables_sample.nft"):  # fmt: skip
        policy, report = load(name)
        text = cli.convert(policy, "nftables", report, Options(zone_map=_ZONES.get(name, {})))
        assert nft_check(text) == "", (name, text)


_ZONES: Dict[str, Dict[str, str]] = {
    "panos_sample.xml": {"trust": "eth1", "untrust": "eth0", "dmz": "eth2", "ot": "eth3"},
}


def test_roundtrip_through_nftables_keeps_every_decision() -> None:
    source, _ = load("nftables_sample.nft")
    text = cli.convert(source, "nftables", Report())
    again = parse_nftables.parse(text.encode(), Report())
    rng = random.Random(11)
    for _ in range(3000):
        pkt = random_nft_packet(rng)
        assert model_allows(again, pkt) == model_allows(source, pkt), pkt


def test_parse_errors_are_clean() -> None:
    for text in ("add rule inet t c accept\n", "include \"x.nft\"\n", 'table inet t { chain c { comment "x }\n',
                 "table inet t {\n chain c {\n type filter hook forward priority banana; policy drop;\n }\n}\n",
                 "table inet t {\n chain c {\n accept\n", "$UNDEFINED\n", "frobnicate\n"):  # fmt: skip
        with pytest.raises(ParseError):
            parse_nftables.parse(text.encode(), Report())
    with pytest.raises(ParseError):
        parse_nftables.parse(b'{"nftables": 5}', Report())


def test_detected_as_nftables() -> None:
    assert cli.detect_format(b"table inet filter {\n}\n") == "nftables"
    assert cli.detect_format(b"#!/usr/sbin/nft -f\n\nflush ruleset\ntable ip t {\n}\n") == "nftables"
    assert cli.detect_format(b'{"nftables": [{"metainfo": {"version": "1.0.9"}}]}') == "nftables"
    assert cli.detect_format(b"*filter\n:FORWARD DROP [0:0]\nCOMMIT\n") == "iptables"


# -- the sample -----------------------------------------------------------------------


def test_nftables_sample_rules() -> None:
    p, report = load("nftables_sample.nft")
    assert p.vendor == "nftables" and p.scope == "" and p.default_interzone == Action.DENY and p.lookup_after_dnat
    names = [r.name for r in p.rules]
    # Both base chains at the forward hook, in priority order; the verdict map's chains in place of the jump.
    assert names[:4] == ["Banned by fail2ban", "Block bad hosts", "Guests stay in", "LAN web"]
    assert names[-2:] == ["DMZ updates", "ICMPv6 basics"]
    rules = {r.name: r for r in p.rules}
    assert rules["Banned by fail2ban"].unsupported and rules["Banned by fail2ban"].action == Action.DROP
    assert rules["Banned by fail2ban"].sources == [ANY_V4]  # what the set holds is not known; its IP version is
    assert rules["Block bad hosts"].sources == ["blocked"] and p.address_groups["blocked"].members == ["192.0.2.128/25", "198.51.100.66"]
    web = rules["LAN web"]
    assert (web.src_zones, web.dst_zones) == (["eth1"], ["eth0"]) and web.sources == [ANY] and web.destinations == [ANY]
    assert [e.dst_ports for e in p.services[web.services[0]].entries] == ["80,443"]
    dns = p.services[rules["LAN DNS"].services[0]].entries
    assert [(e.protocol.value, e.dst_ports) for e in dns] == [("tcp", "53"), ("udp", "53")]
    assert rules["Rate limited mail"].unsupported == ["rate limit 10/minute"]
    assert rules["Partner tunnel"].services == ["ip-47"] and p.services["ip-47"].entries[0].ip_protocol == 47
    assert rules["Admins"].sources == ["admins"] and p.address_groups["admins"].members == ["10.10.5.10-10.10.5.20"]
    assert rules["Ping the DMZ"].sources == [ANY_V4] and p.services[rules["Ping the DMZ"].services[0]].entries[0].icmp_type == 8
    assert rules["OT no internet"].action == Action.DENY and rules["OT no internet"].log_start
    assert rules["DMZ updates"].negate_destination and rules["DMZ updates"].destinations == ["10.0.0.0/8"]
    assert rules["DMZ updates"].sources == [ANY_V4]  # negation covers IPv6 in the model: the source keeps it to IPv4
    assert rules["Inbound IPv6"].destinations == ["dmz_v6"]
    assert [e.icmp_type for e in p.services[rules["ICMPv6 basics"].services[0]].entries] == [128, 135, 136]
    codes = {n.code for n in report.notes}
    assert {"HOST_CHAIN_NOT_CONVERTED", "CHAIN_NOT_CONVERTED", "SEVERAL_BASE_CHAINS", "DYNAMIC_SET"} <= codes
    assert "STATELESS_RULESET" not in codes and "NO_IPV6_CHAIN" not in codes
    assert [f.code for f in report.item("rule", "Block bad hosts").findings] == ["DROP_BEFORE_ESTABLISHED"]


def test_nftables_sample_nat() -> None:
    p, report = load("nftables_sample.nft")
    nat = {n.name: n for n in p.nat_rules}
    assert list(nat) == ["Web DNAT", "Mail DNAT", "No NAT to partner", "DMZ out", "LAN out"]
    web = nat["Web DNAT"]
    assert web.src_zones == ["eth0"] and web.destinations == ["203.0.113.10"] and web.combines
    assert web.destination_translation is not None
    assert (web.destination_translation.address, web.destination_translation.port) == ("10.20.0.10", "8443")
    assert nat["No NAT to partner"].source_translation is None and not nat["No NAT to partner"].unsupported
    pool = nat["DMZ out"].source_translation
    assert pool is not None and pool.addresses == ["198.51.100.20-198.51.100.23"]  # nft lists the range as a /30
    masq = nat["LAN out"].source_translation
    assert masq is not None and masq.kind == SnatKind.INTERFACE and masq.interface == "eth0"
    # The forward hook names the translated address; the model also needs the original one.
    assert {r.name: r for r in p.rules}["Inbound web"].destinations == ["10.20.0.10", "203.0.113.10"]


def test_text_and_json_of_the_sample_give_the_same_model() -> None:
    from_text, text_report = load("nftables_sample.nft")
    from_json, json_report = load("nftables_sample.json")
    assert from_text.to_json() == from_json.to_json()
    assert text_report.to_text() == json_report.to_text()


def test_nftables_sample_to_iptables_and_panos() -> None:
    p, report = load("nftables_sample.nft")
    text = cli.convert(p, "iptables", report)
    assert '-A FORWARD -i eth1 -o eth0 -s 10.10.200.0/24 -m comment --comment "Guests stay in" -j DROP' in text
    assert "-A PREROUTING -i eth0 -d 203.0.113.10/32 -p tcp -m tcp --dport 443" in text
    p, report = load("nftables_sample.nft")
    text = cli.convert(p, "panos", report, Options(zone_map={"eth0": "untrust", "eth1": "trust"}))
    assert 'rulebase security rules "LAN web" from trust' in text


# -- parser details -------------------------------------------------------------------


def parse(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_nftables.parse(text.encode(), report), report


def forward(body: str, policy: str = "drop", family: str = "inet", head: str = "") -> str:
    return (f"table {family} t {{\n{head}\tchain forward {{\n\t\ttype filter hook forward priority filter; policy {policy};\n"
            f"{body}\n\t}}\n\tchain c {{\n\t}}\n}}\n")  # fmt: skip


def test_unknown_matches_never_read_as_any() -> None:
    p, _ = parse(forward(
        "\t\tct state established,related accept\n"
        "\t\tfib saddr . iif oif missing drop\n"
        "\t\tiifname != \"eth0\" accept\n"
        "\t\tiifname \"eth*\" accept\n"
        "\t\ttcp flags syn / fin,syn,rst,ack accept\n"
        "\t\tmeta mark 0x1 accept\n"
        "\t\tether saddr 00:00:5e:00:53:01 drop\n"
        "\t\tct status dnat accept\n"
        "\t\tip saddr . ip daddr != { 10.0.0.1 . 10.0.0.2 } accept\n"
        "\t\ttcp dport 80 queue num 1\n"
        "\t\txt match \"conntrack\" accept\n"
        "\t\tip saddr @nosuchset drop\n"
        "\t\ttcp dport 22 accept"
    ))
    flagged = [bool(r.unsupported) for r in p.rules]
    assert flagged == [True] * 11 + [False]
    assert p.rules[0].action == Action.DROP  # the verdict after fib is kept
    assert p.rules[8].action == Action.DROP and "queue" in " ".join(p.rules[8].unsupported)  # what queue decides is not known


def test_old_xt_comments_and_the_iptables_nft_warning() -> None:
    text = ("# Warning: table ip filter is managed by iptables-nft, do not touch!\n"
            "table ip filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n"
            "\t\tcounter packets 0 bytes 0 # xt_conntrack\n\t\tip saddr 10.0.0.0/8 counter packets 0 bytes 0 # xt_MASQUERADE\n"
            "\t\tip daddr 192.0.2.1 counter packets 0 bytes 0 accept\n\t}\n}\n")  # fmt: skip
    p, report = parse(text)
    assert [bool(r.unsupported) for r in p.rules] == [True, False]
    assert p.rules[0].action == Action.DROP and "xt" in p.rules[0].unsupported[0]  # a target: what it does is not known
    assert "IPTABLES_NFT" in {n.code for n in report.notes} and p.scope == "IPv4"
    assert "NO_IPV6_CHAIN" in {n.code for n in report.notes}


def test_input_files_with_defines_commands_and_anonymous_chains() -> None:
    text = (
        "#!/usr/sbin/nft -f\nflush ruleset\ndefine LAN = { 10.1.0.0/16, 10.2.0.0/16 }\ndefine WEB = 192.0.2.10\n"
        "table inet old {\n}\ndelete table inet old\n"
        "table inet t {\n\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n"
        "\t\tip saddr $LAN ip daddr $WEB tcp dport 443 accept\n"
        "\t\tiifname \"eth1\" jump {\n\t\t\ttcp dport 22 accept\n\t\t\tudp dport 53 accept\n\t\t}\n\t}\n}\n"
        "table inet t {\n\tchain forward {\n\t\ticmp type echo-request accept\n\t}\n}\n"  # a second block adds to the table
    )
    p, _ = parse(text)
    assert [r.name for r in p.rules] == ["forward-1", "forward-2.anonymous-1", "forward-2.anonymous-2", "forward-3"]
    assert p.rules[0].sources == ["10.1.0.0/16", "10.2.0.0/16"] and p.rules[0].destinations == ["192.0.2.10"]
    assert p.rules[1].src_zones == ["eth1"]


def test_named_maps_nat_maps_and_concatenations() -> None:
    text = (
        "table inet t {\n\tmap ports {\n\t\ttype inet_service : verdict\n\t\telements = { 22 : accept, 23 : drop }\n\t}\n"
        "\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n"
        "\t\tip daddr 10.0.0.1 tcp dport vmap @ports\n"
        "\t\tip saddr . tcp dport { 10.0.0.5 . 80, 10.0.0.6 . 443 } accept\n\t}\n}\n"
        "table ip nat {\n\tchain pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
        "\t\tdnat to ip daddr map { 203.0.113.1 : 10.0.0.1, 203.0.113.2 : 10.0.0.2 }\n\t}\n}\n"
    )
    p, _ = parse(text)
    assert [(r.action, r.services) for r in p.rules[:2]] == [(Action.ALLOW, ["tcp-22"]), (Action.DROP, ["tcp-23"])]
    assert [(r.sources, r.services) for r in p.rules[2:]] == [(["10.0.0.5"], ["tcp-80"]), (["10.0.0.6"], ["tcp-443"])]
    assert [(n.destinations, n.destination_translation.address if n.destination_translation else "") for n in p.nat_rules] == [
        (["203.0.113.1"], "10.0.0.1"), (["203.0.113.2"], "10.0.0.2")]  # fmt: skip


def test_return_and_goto_are_followed_exactly_where_one_condition_can_say_it() -> None:
    p, _ = parse(forward(
        "\t\ttcp dport < 1024 jump low\n\t\tiifname \"eth1\" goto out\n\t\taccept",
        head="\tchain low {\n\t\ttcp dport 22 return\n\t\taccept\n\t}\n\tchain out {\n\t\tip daddr 10.9.0.0/16 return\n\t\tdrop\n\t}\n",
    ))
    assert not any(r.unsupported for r in p.rules)
    low = p.rules[0]
    assert p.services[low.services[0]].entries[0].dst_ports == "0-21,23-1023"  # the rule below the return sees the rest
    # goto from the base chain: a return in the other chain, or its end, is the policy of the base chain
    assert [(r.name, r.action) for r in p.rules[1:3]] == [("forward-2.out-1-return", Action.DROP), ("forward-2.out-2", Action.DROP)]
    p, _ = parse(forward("\t\tjump c1", head="\tchain c1 {\n\t\tiifname \"eth1\" goto c2\n\t\taccept\n\t}\n\tchain c2 {\n\t\ttcp dport 22 accept\n\t}\n"))
    # a conditional goto below the base chain: its packets go on after the jump; the rest of the chain cannot say "not those"
    assert [(r.name, bool(r.unsupported)) for r in p.rules] == [("forward-1.c1-1.c2-1", False), ("forward-1.c1-2", True)]


def test_several_base_chains_combine_as_the_kernel_runs_them() -> None:
    text = ("table ip a {\n\tchain f {\n\t\ttype filter hook forward priority -10; policy accept;\n"
            "\t\tip saddr 10.0.0.0/8 tcp dport 22 accept\n\t\tip daddr 192.0.2.0/24 drop\n\t}\n}\n"
            "table inet b {\n\tchain f {\n\t\ttype filter hook forward priority 10; policy drop;\n"
            "\t\ttcp dport { 22, 80 } accept\n\t}\n}\n")  # fmt: skip
    p, report = parse(text)
    # IPv4 passes both chains, IPv6 only the inet one
    assert [(r.name, r.action, r.sources, r.destinations, r.services) for r in p.rules] == [
        ("b:f-1", Action.ALLOW, ["10.0.0.0/8"], [ANY], ["tcp-22"]),  # accepted by a, then by b: b's rule decides
        ("a:f-2", Action.DROP, [ANY], ["192.0.2.0/24"], [ANY]),  # (the destination keeps it to IPv4)
        ("b:f-1-2", Action.ALLOW, [ANY_V4], [ANY], ["tcp-22,80"]),
        ("b:f-1-3", Action.ALLOW, [ANY_V6], [ANY], ["tcp-22,80"]),
    ]  # fmt: skip
    assert p.default_interzone == Action.DENY and "SEVERAL_BASE_CHAINS" in {n.code for n in report.notes}


def test_versions_with_different_defaults_and_a_version_without_a_chain() -> None:
    p, _ = parse("table ip a {\n\tchain f {\n\t\ttype filter hook forward priority 0; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}\n"
                 "table ip6 b {\n\tchain f {\n\t\ttype filter hook forward priority 0; policy accept;\n\t\ttcp dport 23 drop\n\t}\n}\n")  # fmt: skip
    assert p.default_interzone == Action.DENY and p.scope == ""
    assert (p.rules[-1].name, p.rules[-1].action, p.rules[-1].sources) == ("IPv6 policy", Action.ALLOW, [ANY_V6])
    p, report = parse("table ip6 b {\n\tchain f {\n\t\ttype filter hook forward priority 0; policy drop;\n\t}\n}\n")
    assert p.scope == "IPv6" and "NO_IPV4_CHAIN" in {n.code for n in report.notes}
    p, report = parse("table inet h {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n")
    assert p.default_interzone == Action.ALLOW and not p.rules
    assert {"NO_FORWARD_CHAIN", "HOST_CHAIN_NOT_CONVERTED"} <= {n.code for n in report.notes}


def test_sets_filled_at_run_time_and_empty_sets() -> None:
    p, report = parse(forward("\t\tip saddr @dyn drop\n\t\tip saddr @empty drop\n\t\taccept",
                              head="\tset dyn {\n\t\ttype ipv4_addr\n\t\tflags dynamic\n\t}\n\tset empty {\n\t\ttype ipv4_addr\n\t}\n"))
    assert [r.name for r in p.rules] == ["forward-1", "forward-3"] and p.rules[0].unsupported
    assert {"DYNAMIC_SET", "EMPTY_SET"} <= {n.code for n in report.notes}


def test_logging_sets_log_start() -> None:
    p, report = parse(forward(
        "\t\tct state established,related accept\n\t\tct state new log prefix \"new \"\n\t\ttcp dport 22 accept\n"
        "\t\ttcp dport 80 log group 2 accept\n\t\ttcp dport 443 log prefix \"x \" limit rate 1/second accept"
    ))
    assert [r.log_start for r in p.rules] == [True, True, True]
    assert p.rules[1].source_ids == {}  # (the log of every new connection goes to the kernel log)
    p, _ = parse(forward("\t\tct state established,related accept\n\t\ttcp dport 80 log group 2 accept"))
    assert p.rules[0].source_ids == {"nftables.log_group": "2"}


def test_priority_names_and_numbers() -> None:
    assert parse_nftables._priority("filter", "inet", "forward") == 0
    assert parse_nftables._priority("filter - 5", "inet", "forward") == -5
    assert parse_nftables._priority("mangle + 10", "ip", "forward") == -140
    assert parse_nftables._priority("-100", "ip", "forward") == -100
    assert parse_nftables._priority("filter", "bridge", "forward") == -200
    assert parse_nftables._priority("sideways", "ip", "forward") is None


def test_other_families_and_hooks_are_reported() -> None:
    text = ("table bridge br {\n\tchain f {\n\t\ttype filter hook forward priority 0; policy accept;\n\t\tether type arp drop\n\t}\n}\n"
            "table netdev nd {\n\tchain i {\n\t\ttype filter hook ingress device \"eth0\" priority 0; policy accept;\n\t\tdrop\n\t}\n}\n"
            "table inet t {\n\tchain post {\n\t\ttype filter hook postrouting priority 0; policy accept;\n\t\toifname \"x\" drop\n\t}\n"
            "\tchain out {\n\t\ttype nat hook output priority -100; policy accept;\n\t\tdnat ip to 10.0.0.1\n\t}\n}\n")  # fmt: skip
    _, report = parse(text)
    notes = [n.code for n in report.notes]
    assert notes.count("TABLE_NOT_CONVERTED") == 2 and "CHAIN_NOT_CONVERTED" in notes and "HOST_CHAIN_NOT_CONVERTED" in notes


def test_nat_shapes() -> None:
    p, report = parse(
        "table inet nat {\n\tchain pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
        "\t\tiifname \"eth0\" tcp dport 8080 redirect to :3128\n"
        "\t\tiifname \"eth0\" ip daddr 203.0.113.5 tcp dport 80 dnat ip to 10.0.0.5:8080\n"
        "\t\tip6 daddr 2001:db8::5 dnat ip6 to [2001:db8:1::5]:80\n"
        "\t\tip daddr 203.0.113.6 accept\n\t}\n"
        "\tchain post {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n"
        "\t\toifname \"eth0\" masquerade\n\t\toifname \"eth0\" snat ip prefix to ip saddr map { 10.1.0.0/24 : 192.0.2.0/24 }\n\t}\n}\n"
    )
    nat = {n.name: n for n in p.nat_rules}
    assert "redirect" in nat["pre-1"].unsupported[0]
    assert nat["pre-2"].destination_translation is not None and not nat["pre-2"].unsupported
    assert "IPv6 NAT" in nat["pre-3"].unsupported
    assert "exception from destination NAT" in nat["pre-4"].unsupported[0]
    assert nat["post-1"].source_translation is not None and not nat["post-1"].unsupported
    assert [f.code for f in report.item("nat", "post-1").findings] == ["NAT_IPV6_NOT_CONVERTED"]
    assert nat["post-2"].source_translation is None and nat["post-2"].unsupported  # a prefix map is netmap


def test_json_specific_forms() -> None:
    document = {"nftables": [
        {"metainfo": {"version": "1.1.6", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "t", "handle": 1}},
        {"chain": {"family": "inet", "table": "t", "name": "forward", "handle": 1, "type": "filter", "hook": "forward",
                   "prio": 0, "policy": "drop"}},
        {"rule": {"family": "inet", "table": "t", "chain": "forward", "handle": 2, "expr": [
            {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": None}]}},
        {"rule": {"family": "inet", "table": "t", "chain": "forward", "handle": 3, "comment": "web", "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth1"}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                       "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"range": [8000, 8010]}}},
            {"limit": {"rate": 5, "per": "minute", "inv": True}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}},
        {"rule": {"family": "inet", "table": "t", "chain": "forward", "handle": 4, "expr": [
            {"match": {"op": "&", "left": {"tcp option": {"name": "maxseg"}}, "right": 1}}, {"xt": {"type": "target", "name": "TCPMSS"}}]}},
    ]}  # fmt: skip
    p, report = parse(json.dumps(document))
    assert [(r.name, r.sources, r.unsupported[:1]) for r in p.rules] == [
        ("web", ["10.0.0.0/8"], ["rate limit over 5/minute"]), ("forward-3", [ANY], ["tcp option & ... (a bit operation)"])]  # fmt: skip
    assert p.rules[1].action == Action.DROP and "IPTABLES_NFT" in {n.code for n in report.notes}


# -- emitter details ------------------------------------------------------------------


def test_panos_to_nftables_output() -> None:
    options = Options(zone_map={"trust": "eth1", "untrust": "eth0", "dmz": "eth2", "ot": "eth3"})
    policy, report = load("panos_sample.xml")
    text = cli.convert(policy, "nftables", report, options)
    lines = [line.strip() for line in text.splitlines()]
    assert lines[3:10] == ["table inet fwshift", "delete table inet fwshift", "table inet fwshift {", "chain forward {",
                           "type filter hook forward priority filter; policy drop;", "ct state established,related accept",
                           "ct state invalid drop"]  # fmt: skip
    assert ('iifname "eth1" oifname "eth3" ip saddr 10.10.7.15 ip daddr 10.30.1.0/24 tcp dport { 502, 102 } ct state new counter '
            'accept comment "Engineering to PLCs"') in lines  # fmt: skip
    assert any(line.startswith('# FWSHIFT disabled, see the report: "Admin-SSH"') for line in lines)
    assert report.item("rule", "Admin-SSH").disabled
    assert any('log prefix "Inbound-Web: "' in line for line in lines)
    assert 'iifname "eth0" ip daddr 203.0.113.10/32 tcp dport 443 counter dnat ip to 10.20.0.10:8443 comment "Inbound-Web-DNAT"' in lines
    assert 'meta nfproto ipv4 oifname "eth0" counter masquerade comment "Outbound-PAT"' in lines
    assert any("Inbound-Web" in line and "ip daddr 10.20.0.10" in line for line in lines)  # the forward hook sees the translated address
    codes = {n.code for n in report.notes}
    assert {"NFT_LOAD", "INTERFACES_REQUIRED", "INTRAZONE_DEFAULT", "LOG_STATEMENTS"} <= codes


def test_emitter_negation_lists_and_versions() -> None:
    p = Policy(vendor="panos")
    p.addresses["v4"] = Address("v4", AddressKind.NETWORK, "10.0.0.0/8")
    p.addresses["v6"] = Address("v6", AddressKind.NETWORK, "2001:db8::/32")
    p.addresses["name"] = Address("name", AddressKind.FQDN, "www.example.com")
    for rule in (Rule("both", sources=["v4", "v6"], destinations=["v4"], origin="both"),
                 Rule("not-both", sources=["v4", "v6"], negate_source=True, origin="not-both"),
                 Rule("fqdn", destinations=["name"], origin="fqdn"),
                 Rule("bad zone", src_zones=["DMZ Zone"], origin="bad zone"),
                 Rule("reset", action=Action.RESET_BOTH, origin="reset")):  # fmt: skip
        p.rules.append(rule)
    report = Report()
    text = emit_nftables.emit(p, report, Options())
    assert "ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 ct state new counter accept comment \"both\"" in text
    assert "ip6 saddr" not in text.split('"both"')[0].splitlines()[-1]  # the IPv6 half has no destination: no line
    assert 'ip saddr != 10.0.0.0/8 ct state new counter accept comment "not-both"' in text
    assert 'ip6 saddr != 2001:db8::/32 ct state new counter accept comment "not-both"' in text
    assert report.item("rule", "fqdn").disabled and report.item("rule", "bad zone").disabled
    assert 'counter reject comment "reset"' in text and "RESET_ACTION" in [f.code for f in report.item("rule", "reset").findings]


def test_one_version_source_is_said() -> None:
    policy, report = load("iptables_sample.rules")
    text = cli.convert(policy, "nftables", report)
    assert "ONE_IP_VERSION" in {n.code for n in report.notes}
    assert '-A' not in text and "iifname \"eth1\" oifname \"eth0\" ip saddr 10.10.200.0/24 counter drop" in text


def test_names_from_the_input_cannot_break_the_ruleset() -> None:
    p = Policy(vendor="panos")
    p.rules.append(Rule('evil" accept\n# x', origin="evil", action=Action.DROP, log_start=True))
    text = emit_nftables.emit(p, Report(), Options())
    rule = [line for line in text.splitlines() if "drop comment" in line]
    assert len(rule) == 1 and rule[0].count('"') == 4 and "\n" not in rule[0]


# -- usage ----------------------------------------------------------------------------


def test_usage_reads_the_kernel_lines_of_log_statements(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    ruleset = forward(
        "\t\tct state established,related accept\n\t\tct state new log prefix \"fw-new \"\n"
        "\t\ttcp dport 443 accept comment \"web\"\n\t\ttcp dport 22 accept comment \"ssh\"\n"
        "\t\ttcp dport 80 log group 1 accept comment \"plain web\""
    )
    log = "".join(f"Oct {day:2d} 10:00:00 fw1 kernel: fw-new IN=eth1 OUT=eth0 SRC=10.0.0.1 DST=192.0.2.1 LEN=60 PROTO=TCP "
                  "SPT=40000 DPT=443 WINDOW=1 RES=0x00 SYN URGP=0\n" for day in range(1, 31))  # fmt: skip
    (tmp_path / "fw.nft").write_text(ruleset, encoding="utf-8")
    (tmp_path / "fw.log").write_text(log, encoding="utf-8")
    assert cli.main(["usage", str(tmp_path / "fw.nft"), "--logs", str(tmp_path / "fw.log"), "--log-year", "2026", "--since", "30d",
                     "--unchanged-since", "2026-01-01", "--json"]) == 0  # fmt: skip
    data = json.loads(capsys.readouterr().out)
    rules = {r["name"]: r for r in data["rules"]}
    assert rules["web"]["connections"] == 30 and rules["ssh"]["connections"] == 0
    found = {f["name"]: f["check"] for f in data["findings"] if f["check"].startswith(("UNUSED", "NO_USAGE"))}
    assert found.get("ssh") == "UNUSED_RULE"
    assert found.get("plain web") == "UNUSED_RULE"  # its own log goes to nflog, the log of every new connection does not


# -- review round 26 ------------------------------------------------------------------


def deep_ruleset(rng: random.Random) -> str:
    """Three chains below the base chain, with jump, goto, return and continue at every level."""
    family = rng.choice(["ip", "inet"])
    chains = ["c1", "c2", "c3"]

    def match(base: bool = False) -> str:
        r = rng.random()
        if r < 0.25:
            return f"ip saddr {rng.choice(['10.0.0.0/24', '10.0.1.0/24', '10.0.0.17', '10.0.0.0/16'])}"
        if r < 0.4:
            return f"ip daddr {rng.choice(['10.0.0.0/24', '10.0.1.0/24'])}"
        if r < 0.55:
            return f"tcp dport {rng.choice([22, 80, 443])}"
        if r < 0.65:
            return "meta l4proto tcp"
        if r < 0.72:
            return "ct state new"
        if r < 0.78 and family == "inet":
            return "meta nfproto ipv4"
        if r < 0.85 and base:
            return f'iifname "{rng.choice(ZONES)}"'
        return ""

    def verdict(index: Optional[int]) -> str:
        others = chains if index is None else chains[index + 1 :]
        choices = ["accept", "drop", "continue"] + ([] if index is None else ["return"] * 2)
        if others:
            choices += [f"jump {rng.choice(others)}", f"goto {rng.choice(others)}"] * 2
        return rng.choice(choices)

    lines = [f"table {family} t {{", "\tchain fw {", f"\t\ttype filter hook forward priority 0; policy {rng.choice(['accept', 'drop'])};"]
    lines += [f"\t\t{match(True)} {verdict(None)}".replace("\t\t ", "\t\t") for _ in range(rng.randint(1, 4))] + ["\t}"]
    for index, chain in enumerate(chains):
        lines.append(f"\tchain {chain} {{")
        lines += [f"\t\t{match()} {verdict(index)}".replace("\t\t ", "\t\t") for _ in range(rng.randint(1, 4))] + ["\t}"]
    return "\n".join(lines + ["}"]) + "\n"


def test_r26_jump_goto_and_return_at_every_depth() -> None:
    """A conditional goto below the base chain, an unconditional one in a chain reached by a goto, returns that end a
    chain for everything: the flattened rules decide as the walk through the chains does."""
    compared = 0
    for seed in range(800):
        rng = random.Random(seed)
        text = deep_ruleset(rng)
        ruleset = parse_nftables.read(text.encode())
        model = parse_nftables._Builder(ruleset, Report()).build()
        if any(rule.unsupported for rule in model.rules):
            continue
        compared += 1
        for _ in range(60):
            pkt = random_nft_packet(rng)
            if text.startswith("table ip ") and ":" in pkt.src:
                continue
            assert model_allows(model, pkt) == reference_allows(ruleset, pkt), (seed, pkt, text)
    assert compared >= 400


def test_r26_goto_shapes_the_kernel_showed() -> None:
    # A conditional goto into a chain that returns at once: those packets go on after the jump, to the drop.
    p, _ = parse("table inet t {\n\tchain T {\n\t\treturn\n\t}\n\tchain X {\n\t\tip saddr 10.0.0.1 goto T\n\t\taccept\n\t}\n"
                 "\tchain fw {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tjump X\n\t\tdrop\n\t}\n}\n")  # fmt: skip
    assert [(r.sources, r.negate_source, r.action) for r in p.rules] == [(["10.0.0.1"], True, Action.ALLOW), ([ANY], False, Action.DROP)]
    # An unconditional goto in a chain reached by a conditional goto from the base chain: the end is the policy.
    p, _ = parse("table inet t {\n\tchain c3 {\n\t\tip saddr 10.0.0.66 accept\n\t}\n\tchain c2 {\n\t\tgoto c3\n\t}\n"
                 "\tchain c1 {\n\t\tip daddr 10.0.0.1 goto c2\n\t\taccept\n\t}\n"
                 "\tchain fw {\n\t\ttype filter hook forward priority filter; policy drop;\n\t\tgoto c1\n\t}\n}\n")  # fmt: skip
    assert [(r.destinations, r.action) for r in p.rules] == [(["10.0.0.1"], Action.ALLOW), (["10.0.0.1"], Action.DROP), ([ANY], Action.ALLOW)]


def test_r26_a_verdict_is_never_read_as_the_value_of_a_match() -> None:
    p, report = parse(forward(
        "\t\tip saddr 10.0.0.5 log flags tcp sequence,options drop\n"
        "\t\tip saddr 10.0.0.6 log flags ip options drop\n"
        "\t\tip saddr 10.0.0.7 quota name \"q1\" drop\n"
        "\t\tip saddr 10.0.0.8 quota over 25 mbytes used 0 bytes drop\n"
        "\t\tip saddr 10.1.0.1 tcp option maxseg exists drop\n"
        "\t\tip saddr 10.1.0.2 ip option rr exists drop\n"
        "\t\tip saddr 10.1.0.3 osf name \"Linux\" drop\n"
        "\t\tip saddr 10.1.0.4 rt classid 10 drop\n"
        "\t\tip saddr 10.1.0.5 exthdr hbh exists drop\n"
        "\t\tip saddr 10.1.0.6 sctp chunk data exists drop\n"
        "\t\tip saddr 10.1.0.7 meter m1 size 128 { ip saddr limit rate 10/second } drop\n"
        "\t\tip saddr 10.1.0.8 tcp dport 22 tcp option maxseg size set rt mtu drop\n"
        "\t\tip saddr 10.1.0.9 numgen inc mod 2 vmap { 0 : accept, 1 : drop }\n"
        "\t\tip saddr 10.1.1.0 osf name \"Linux\"",
        policy="accept",
    ))
    assert [r.sources for r in p.rules] == [[s] for s in ("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.1.0.1", "10.1.0.2", "10.1.0.3",
                                                          "10.1.0.4", "10.1.0.5", "10.1.0.6", "10.1.0.7", "10.1.0.8", "10.1.0.9", "10.1.1.0")]  # fmt: skip
    assert all(r.action == Action.DROP for r in p.rules)  # every one drops, or may: nothing is allowed on a guess
    assert [bool(r.unsupported) for r in p.rules] == [False, False] + [True] * 9 + [False, True, True]
    assert "PASSIVE_STATEMENTS" not in {n.code for n in report.notes}


def test_r26_json_without_the_anonymous_chain() -> None:
    document = {"nftables": [
        {"chain": {"family": "inet", "table": "t", "name": "fw", "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}},
        {"rule": {"family": "inet", "table": "t", "chain": "fw", "expr": [
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lan0"}}, "jump {\n ip daddr 192.0.2.20 drop\n }"]}},
    ]}  # fmt: skip
    p, _ = parse(json.dumps(document))
    assert len(p.rules) == 1 and p.rules[0].action == Action.DROP and p.rules[0].unsupported and p.rules[0].src_zones == ["lan0"]


def test_r26_an_established_accept_with_more_matches_is_a_rule_of_its_own() -> None:
    p, report = parse(forward('\t\tiifname "lan0" ct state established,related accept\n\t\tiifname "lan0" oifname "wan0" accept'))
    assert p.rules[0].unsupported and p.rules[0].src_zones == ["lan0"]
    assert "STATELESS_RULESET" in {n.code for n in report.notes}
    p, report = parse(forward("\t\tct state established,related accept\n\t\tiifname \"lan0\" ct state established accept\n\t\taccept"))
    assert len(p.rules) == 1 and not p.rules[0].unsupported  # (the second decides nothing the first did not)


def test_r26_dormant_tables_numeric_states_and_dollar_signs() -> None:
    p, report = parse("table ip old {\n\tflags dormant\n\tchain pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n"
                      "\t\tip daddr 192.0.2.5 tcp dport 22 dnat to 10.0.0.5\n\t}\n}\n"
                      + forward("\t\tct state established,related accept\n\t\tip daddr 10.0.0.5 tcp dport 22 accept", family="ip"))  # fmt: skip
    assert not p.nat_rules and p.rules[0].destinations == ["10.0.0.5"] and "TABLE_DORMANT" in {n.code for n in report.notes}
    p, _ = parse(forward("\t\tct state 0x2,0x4 accept\n\t\tct state 0x1 drop\n\t\ttcp dport 22 accept"))
    assert len(p.rules) == 1 and not p.rules[0].unsupported
    model = Policy(vendor="panos")
    model.rules.append(Rule("cost $5", origin="cost $5", log_start=True))
    text = emit_nftables.emit(model, Report(), Options())
    assert 'log prefix "cost _5: "' in text
    if NFT:
        assert nft_check(text) == ""


def test_r26_negated_states_and_what_a_protocol_implies() -> None:
    p, _ = parse(forward("\t\tct state established,related accept\n\t\tct state != new drop\n\t\ttcp dport 22 accept"))
    assert [(r.action, bool(r.unsupported)) for r in p.rules] == [(Action.DROP, True), (Action.ALLOW, False)]
    assert "UNTRACKED" in p.rules[0].unsupported[0]  # (every state but new, which the model has no place for)
    p, _ = parse(forward("\t\tmeta l4proto icmp accept\n\t\tmeta l4proto ipv6-icmp accept\n\t\tmeta nfproto ipv6 accept"))
    assert [r.sources for r in p.rules] == [[ANY_V4], [ANY_V6], [ANY_V6]]
