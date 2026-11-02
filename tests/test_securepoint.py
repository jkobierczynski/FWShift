# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Securepoint UTM: parser, emitter, and packet-level equivalence with a judge of its own.

``Utm`` reads commands of the UTM's CLI strictly, as a UTM of the reading of Securepoint's CLI reference and wiki would
take them (``node new``, ``node group new``, ``service new``, ``service group new``, ``rule group new``, ``rule new``;
each name created once, an object created before it is used, a group of network objects holds network objects, a node
has an address and a zone, a rule has one source, destination and service and known flags), and decides packets: the
rules in the order of their groups (the order the groups were created) and, within a group, in the order they were
added; a rule matches where a member of its source is in the zone the packet arrives from and holds its source
address, a member of its destination is in the zone it leaves to and holds its destination address, and its service
matches; first match; ACCEPT, QOS and STATELESS let the packet through, DROP and REJECT do not; what no rule matches is
dropped. None of it shares code with the parser or the emitter.
"""

from __future__ import annotations

import copy
import ipaddress
import random
import re
from typing import Dict, List, Optional, Tuple

import pytest
from helpers import DATA, load, run
from test_iptables import ZONES as MODEL_ZONES
from test_iptables import Packet, model_allows, random_model, random_packet

from fwshift import cli
from fwshift.emitters import securepoint as emit_securepoint
from fwshift.errors import ParseError
from fwshift.model import (
    ANY,
    Action,
    Address,
    AddressKind,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    Service,
    ServiceEntry,
    SnatKind,
    SourceNat,
    Zone,
)
from fwshift.options import Options
from fwshift.parsers import securepoint as parse_securepoint
from fwshift.report import Report

NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "gre": 47, "esp": 50, "ah": 51}


def codes(report: Report) -> set:
    return {f.code for f in report.notes} | {f.code for item in report.items.values() for f in item.findings}


def parse_text(text: str) -> Tuple[Policy, Report]:
    report = Report()
    return parse_securepoint.parse(text.encode(), report), report


# -- the judge: a UTM as the documentation reads -------------------------------------------------------------------

_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(\[|\])|([^\s"\[\]]+)')


def _tokens(line: str) -> List[Tuple[str, bool]]:
    """(text, quoted) for each token; a string must end on its line."""
    out: List[Tuple[str, bool]] = []
    pos = 0
    for match in _TOKEN.finditer(line):
        assert line[pos:match.start()].strip() == "", line
        pos = match.end()
        if match.group(1) is not None:
            out.append((re.sub(r"\\(.)", r"\1", match.group(1)), True))
        else:
            out.append((match.group(2) or match.group(3), False))
    assert line[pos:].strip() == "", line
    return out


class Utm:
    PARAMS = {
        ("node", "new"): {"name", "address", "zone"},
        ("node", "group", "new"): {"name", "nodes"},
        ("service", "new"): {"name", "proto", "dst-ports", "src-ports", "icmp-types"},
        ("service", "group", "new"): {"name", "services"},
        ("rule", "group", "new"): {"name"},
        ("rule", "new"): {"group", "src", "dst", "service", "comment", "flags", "nat_node", "nat_service"},
    }
    ACTIONS = {"ACCEPT", "DROP", "REJECT", "QOS", "STATELESS"}
    NATS = {"HIDENAT", "HIDENAT_EXCLUDE", "DESTNAT", "NETMAP", "FULLCONENAT"}

    def __init__(self, text: str, strict: bool = True) -> None:
        self.nodes: Dict[str, Tuple[ipaddress._BaseNetwork, str]] = {}
        self.groups: Dict[str, List[str]] = {}
        self.services: Dict[str, Dict[str, object]] = {"any": {"proto": "any"}}
        self.service_groups: Dict[str, List[str]] = {}
        self.rule_groups: List[str] = []
        self.rules: List[Dict[str, object]] = []
        self.strict = strict
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            self._line(line)

    def _taken(self, name: str) -> None:
        assert name and name not in self.nodes and name not in self.groups and name not in self.services and name not in self.service_groups, name

    def _line(self, line: str) -> None:
        tokens = _tokens(line)
        words = [t for t, q in tokens[:3]]
        for path in sorted(self.PARAMS, key=len, reverse=True):
            if tuple(words[: len(path)]) == path and not any(q for _, q in tokens[: len(path)]):
                break
        else:
            if self.strict:
                raise AssertionError(f"a command the reader does not take: {line}")
            return
        params: Dict[str, object] = {}
        rest = tokens[len(path):]
        i = 0
        while i < len(rest):
            key, quoted = rest[i]
            assert not quoted and key in self.PARAMS[path] and key not in params, line
            if rest[i + 1][0] == "[" and not rest[i + 1][1]:
                j = i + 2
                items: List[str] = []
                while not (rest[j][0] == "]" and not rest[j][1]):
                    assert rest[j][1], line  # (list items in quotes, as the UTM prints them)
                    items.append(rest[j][0])
                    j += 1
                params[key], i = items, j + 1
            else:
                assert rest[i + 1][1], line
                params[key], i = rest[i + 1][0], i + 2
        getattr(self, "_" + "_".join(path))(params, line)

    def _node_new(self, params: Dict[str, object], line: str) -> None:
        name = str(params["name"])
        self._taken(name)
        address = ipaddress.ip_network(str(params["address"]), strict=True)
        assert "/" in str(params["address"]), line
        assert params["zone"], line
        self.nodes[name] = (address, str(params["zone"]))

    def _node_group_new(self, params: Dict[str, object], line: str) -> None:
        name = str(params["name"])
        self._taken(name)
        members = list(params["nodes"])  # type: ignore[call-overload]
        assert members and all(m in self.nodes for m in members), line
        self.groups[name] = members

    def _service_new(self, params: Dict[str, object], line: str) -> None:
        name = str(params["name"])
        self._taken(name)
        proto = str(params["proto"])
        assert proto in NUMBERS, line
        service: Dict[str, object] = {"proto": proto}
        if proto in ("tcp", "udp"):
            dst, src = list(params["dst-ports"]), list(params["src-ports"])  # type: ignore[call-overload]
            assert len(dst) == 1 and len(src) <= 1, line
            for key, values in (("dst", dst), ("src", src)):
                ranges = []
                for value in values:
                    first, _, last = value.partition("-")
                    assert first.isdigit() and (not last or last.isdigit()) and 1 <= int(first) <= int(last or first) <= 65535, line
                    ranges.append((int(first), int(last or first)))
                service[key] = ranges
        elif proto in ("icmp", "icmpv6"):
            types = list(params["icmp-types"])  # type: ignore[call-overload]
            assert len(types) == 1 and (types[0] == "any" or (types[0].isdigit() and int(types[0]) <= 255)), line
            service["type"] = None if types[0] == "any" else int(types[0])
            assert "dst-ports" not in params, line
        else:
            assert set(params) == {"name", "proto"}, line
        self.services[name] = service

    def _service_group_new(self, params: Dict[str, object], line: str) -> None:
        name = str(params["name"])
        self._taken(name)
        members = list(params["services"])  # type: ignore[call-overload]
        assert members and all(m in self.services and m != "any" for m in members), line
        self.service_groups[name] = members

    def _rule_group_new(self, params: Dict[str, object], line: str) -> None:
        name = str(params["name"])
        assert name not in self.rule_groups, line
        self.rule_groups.append(name)

    def _rule_new(self, params: Dict[str, object], line: str) -> None:
        assert params["group"] in self.rule_groups, line
        for side in ("src", "dst"):
            assert params[side] in self.nodes or params[side] in self.groups, line
        assert params["service"] in self.services or params["service"] in self.service_groups, line
        flags = list(params["flags"])  # type: ignore[call-overload]
        actions = [f for f in flags if f in self.ACTIONS]
        nats = [f for f in flags if f in self.NATS]
        assert len(actions) == 1 and len(nats) <= 1 and all(f in self.ACTIONS | self.NATS | {"LOG", "LOG_ALL"} for f in flags), line
        if nats and nats[0] in ("HIDENAT", "DESTNAT"):
            assert params.get("nat_node"), line
        if "nat_node" in params:
            assert nats and (params["nat_node"] in self.nodes or str(params["nat_node"]).endswith("-interface")), line
        if "nat_service" in params:
            assert nats == ["DESTNAT"] and (params["nat_service"] in self.services or params["nat_service"] in self.service_groups), line
        rule = dict(params)
        rule["action"] = actions[0]
        rule["line"] = len(self.rules)
        self.rules.append(rule)

    # -- deciding -----------------------------------------------------------------------------------------------------

    def _members(self, name: str) -> List[Tuple[ipaddress._BaseNetwork, str]]:
        return [self.nodes[m] for m in self.groups[name]] if name in self.groups else [self.nodes[name]]

    def _service_matches(self, name: str, pkt: Packet) -> bool:
        names = self.service_groups.get(name, [name])
        for member in names:
            service = self.services[member]
            proto = str(service["proto"])
            if proto == "any":
                return True
            if proto in ("tcp", "udp"):
                if pkt.proto == proto and any(a <= pkt.dport <= b for a, b in service["dst"]) and (  # type: ignore[attr-defined]
                        not service["src"] or any(a <= pkt.sport <= b for a, b in service["src"])):  # type: ignore[attr-defined]
                    return True
            elif proto in ("icmp", "icmpv6"):
                if pkt.proto == ("icmp" if proto == "icmp" else "icmp6") and service["type"] in (None, pkt.icmp_type):
                    return True
            elif str(NUMBERS[proto]) == pkt.proto:
                return True
        return False

    def allows(self, pkt: Packet) -> bool:
        order = sorted(self.rules, key=lambda r: (self.rule_groups.index(str(r["group"])), int(r["line"])))  # type: ignore[call-overload]
        src, dst = ipaddress.ip_address(pkt.src), ipaddress.ip_address(pkt.dst)
        for rule in order:
            if not any(zone == pkt.in_if and src.version == net.version and src in net for net, zone in self._members(str(rule["src"]))):
                continue
            if not any(zone == pkt.out_if and dst.version == net.version and dst in net for net, zone in self._members(str(rule["dst"]))):
                continue
            if not self._service_matches(str(rule["service"]), pkt):
                continue
            return rule["action"] in ("ACCEPT", "QOS", "STATELESS")
        return False


def emit(model: Policy, options: Optional[Options] = None) -> Tuple[str, Report]:
    for item in list(model.rules) + list(model.nat_rules):
        item.origin = item.origin or item.name
    report = Report()
    return emit_securepoint.emit(model, report, options or Options()), report


def zoned(model: Policy) -> Policy:
    for zone in MODEL_ZONES:
        model.zones[zone] = Zone(zone, [zone])
    return model


def compare(model: Policy, report: Report, text: str, rng: random.Random, seed: int, packets: int = 300) -> int:
    model = copy.deepcopy(model)
    for rule in model.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False  # (written as a comment line, and said)
    device = Utm(text)
    count = 0
    for number in range(packets):
        pkt = random_packet(rng, 4 if number % 3 else 6)
        assert device.allows(pkt) == model_allows(model, pkt), (seed, pkt, text)
        count += 1
    return count


# -- the sample ---------------------------------------------------------------------------------------------------


def test_sample_is_detected_and_read() -> None:
    data = (DATA / "securepoint_sample.cfg").read_bytes()
    assert cli.detect_format(data) == "securepoint"
    policy, report = load("securepoint_sample.cfg")
    assert policy.vendor == "securepoint"
    assert policy.default_interzone == policy.default_intrazone == Action.DROP
    assert set(policy.zones) == {"external", "internal", "dmz1", "vpn-ipsec"}  # (the firewall-... zones are the UTM's own)
    assert policy.zones["internal"].interfaces == ["eth1"]
    assert policy.zone_networks["dmz1"] == ["172.16.20.0/24"]
    assert policy.addresses["internal-network"].value == "192.168.10.0/24"  # (the network of its interface)
    assert policy.addresses["external-interface"].value == "203.0.113.2"  # (the address of its interface)
    assert policy.addresses["printers"].kind == AddressKind.RANGE
    assert policy.addresses["update-host"].kind == AddressKind.FQDN
    assert policy.addresses["blocked-region"].kind == AddressKind.UNSUPPORTED
    assert policy.services["ntp-client"].entries == [ServiceEntry(Protocol.UDP, "123", "1024-65535")]
    assert policy.services["icmpv6-echo"].entries == [ServiceEntry(Protocol.ICMP6, icmp_type=128)]
    assert policy.services["gre"].entries == [ServiceEntry(Protocol.IP, ip_protocol=47)]
    assert policy.services["ssh"].builtin == "securepoint"  # (not defined: the service a UTM comes with)
    assert "SECUREPOINT_IMPLIED" in codes(report)


def test_rule_groups_decide_the_order_not_the_lines() -> None:
    policy, _ = load("securepoint_sample.cfg")
    names = [r.name for r in policy.rules]
    groups = [r.source_ids["securepoint.group"] for r in policy.rules]
    assert groups == sorted(groups, key=["default", "dmz", "blocked"].index)
    assert names.index("rule-18") < names.index("rule-2")  # (group default, added last, comes before group dmz)
    assert names[0] == "rule-1" and names[-1] == "rule-17"


def test_zones_come_from_the_objects_and_mixed_groups_split() -> None:
    policy, report = load("securepoint_sample.cfg")
    rules = {r.name: r for r in policy.rules}
    assert (rules["rule-1"].src_zones, rules["rule-1"].dst_zones) == (["internal"], ["external"])
    assert (rules["rule-7"].src_zones, rules["rule-7"].sources) == (["internal"], ["admin-pc"])
    assert (rules["rule-7-2"].src_zones, rules["rule-7-2"].sources) == (["vpn-ipsec"], ["partner-net"])
    assert rules["rule-7"].destinations == ["servers"]  # (a group in one zone stays the group)
    assert rules["rule-13"].dst_zones == [ANY]  # (the object any)
    assert "SECUREPOINT_SPLIT" in {f.code for f in report.item("rule", "rule-7-2").findings}


def test_rules_for_the_utm_itself_are_not_converted() -> None:
    policy, report = load("securepoint_sample.cfg")
    assert "rule-5" not in {r.name for r in policy.rules}
    assert report.item("rule", "rule-5").skipped


def test_actions_logging_and_flags() -> None:
    policy, report = load("securepoint_sample.cfg")
    rules = {r.name: r for r in policy.rules}
    assert rules["rule-3"].action == Action.DENY  # REJECT
    assert rules["rule-9"].action == Action.DROP and rules["rule-9"].log_end
    assert rules["rule-12"].action == Action.ALLOW and rules["rule-12"].handling["qos"]
    assert rules["rule-11"].handling["stateless"] == "yes"
    assert "SECUREPOINT_STATELESS" in {f.code for f in report.item("rule", "rule-11").findings}
    assert any("MIRROR" in u for u in rules["rule-16"].unsupported)
    assert rules["rule-14"].unsupported  # NETMAP
    assert not rules["rule-4"].log_end and rules["rule-1"].log_end


def test_destnat_is_read_for_the_traffic_it_translates() -> None:
    policy, report = load("securepoint_sample.cfg")
    rules = {r.name: r for r in policy.rules}
    nats = {n.name: n for n in policy.nat_rules}
    web = rules["rule-2"]
    assert web.destinations == ["external-interface"] and web.services == ["extern-https"] and web.dst_zones == ["dmz1"]
    nat = nats["rule-2-nat"]
    assert nat.destinations == ["external-interface"] and nat.service == "extern-https"
    assert nat.destination_translation == DestNat("webserver", "443")
    assert nat.dst_zones == ["external"] and nat.src_zones == ["external"]
    assert nats["rule-6-nat"].destination_translation == DestNat("mailserver", "")
    # A rule above it that names the server sees the translated traffic: rewritten, and reported.
    drop = rules["rule-18"]
    assert "external-interface" in drop.destinations and drop.nat_added
    assert "NAT_PORT_TRANSLATION" in {f.code for f in report.item("rule", "rule-18").findings}


def test_hidenat_and_its_exception() -> None:
    policy, _ = load("securepoint_sample.cfg")
    nats = {n.name: n for n in policy.nat_rules}
    hide = nats["rule-1-nat"].source_translation
    assert hide is not None and hide.kind == SnatKind.INTERFACE and hide.interface == "eth0" and hide.interface_address == "203.0.113.2"
    exclude = nats["rule-10-nat"]
    assert exclude.source_translation is None and exclude.destination_translation is None
    assert nats["rule-14-nat"].unsupported  # NETMAP
    assert all(n.combines for n in policy.nat_rules)


def test_unknown_words_never_widen() -> None:
    base = ('interface zone new name "lan" interface "eth1"\ninterface zone new name "wan" interface "eth0"\n'
            'node new name "a" address "10.0.0.0/24" zone "lan"\nnode new name "b" address "192.0.2.0/24" zone "wan"\n'
            'rule group new name "g"\n')  # fmt: skip
    policy, _ = parse_text(base + 'rule new group "g" src "a" dst "b" service "any" flags [ "ACCEPT" ] mark "5"\n')
    assert policy.rules[0].unsupported
    policy, _ = parse_text(base + 'rule new group "g" src "a" dst "nothere" service "any" flags [ "ACCEPT" ]\n')
    assert policy.rules[0].unsupported
    policy, _ = parse_text(base + 'rule new group "g" src "a" dst "b" service "unknown-svc" flags [ "ACCEPT" ]\n')
    assert policy.rules[0].unsupported
    policy, report = parse_text(base + 'rule new group "g" src "a" dst "b" service "any"\n')
    assert policy.rules[0].action == Action.ALLOW and "SECUREPOINT_NO_ACTION" in codes(report)
    policy, _ = parse_text(base + 'node new name "c" address "10.1.0.1/32"\nrule new group "g" src "c" dst "b" service "any" flags [ "DROP" ]\n')
    assert policy.addresses["c"].kind == AddressKind.UNSUPPORTED  # (a node without a zone)
    policy, report = parse_text(base + 'node set id "4" address "10.9.9.9"\nrule new group "g" src "a" dst "b" service "any" flags [ "DROP" ]\n')
    assert "SECUREPOINT_EDITS" in codes(report)
    policy, report = parse_text(base + 'service new name "s" proto "tcp" dst-ports [ "8x" ] src-ports [ ]\n'
                                'rule new group "g" src "a" dst "b" service "s" flags [ "ACCEPT" ]\n')  # fmt: skip
    assert policy.services["s"].unsupported


def test_full_cone_and_missing_rule_group() -> None:
    text = ('interface zone new name "lan" interface "eth1"\ninterface zone new name "wan" interface "eth0"\n'
            'interface zone new name "firewall-wan" interface "eth0" flags [ "INTERFACE" ]\n'
            'node new name "a" address "10.0.0.0/24" zone "lan"\nnode new name "b" address "0.0.0.0/0" zone "wan"\n'
            'node new name "wan-interface" address "eth0" zone "firewall-wan"\n'
            'rule new group "late" src "a" dst "b" service "any" flags [ "ACCEPT" "FULLCONENAT" ] nat_node "wan-interface"\n')  # fmt: skip
    policy, report = parse_text(text)
    nat = policy.nat_rules[0]
    assert nat.source_translation is not None and nat.source_translation.kind == SnatKind.INTERFACE
    assert nat.source_translation.interface == "eth0" and nat.source_translation.interface_address == ""
    assert {"SECUREPOINT_FULL_CONE", "SECUREPOINT_GROUP_IMPLIED"} <= codes(report)


def test_malformed_input_is_a_clean_error() -> None:
    with pytest.raises(ParseError):
        parse_text('node new name "a address "10.0.0.1/32" zone "lan"\nrule new group "g" src "a"\n')
    with pytest.raises(ParseError):
        parse_text('rule new group "g" src "a" dst "b" service "any" flags [ "ACCEPT" \n')
    with pytest.raises(ParseError):
        parse_text("extc value get\nsystem config save\n")


def test_detection_claims_no_other_sample() -> None:
    for path in DATA.glob("*sample*"):
        if path.name != "securepoint_sample.cfg":
            assert not parse_securepoint.looks_like_securepoint(path.read_bytes()), path.name


# -- the emitter --------------------------------------------------------------------------------------------------


def test_emitted_sample_is_taken_by_the_reader_and_adds_only() -> None:
    text, report = run("securepoint_sample.cfg", "securepoint")
    device = Utm(text)
    assert device.rule_groups == ["fwshift"]
    for line in text.splitlines():
        assert line.startswith("#") or line.split()[1] in ("new",) or line.split()[:3] in (["node", "group", "new"], ["service", "group", "new"],
                                                                                          ["rule", "group", "new"]), line  # fmt: skip
        assert "delete" not in line.split()[:3] and "config save" not in line and "update rule" not in line or line.startswith("#")
    destnat = [r for r in device.rules if "DESTNAT" in r["flags"]]  # type: ignore[operator]
    assert destnat and all(r["action"] == "DROP" and r["nat_service"] for r in destnat)
    web = next(r for r in destnat if r["comment"] == "rule-2-nat")
    assert device.nodes[str(web["dst"])][0] == ipaddress.ip_network("172.16.20.10/32")
    assert device.services[str(web["service"])]["dst"] == [(443, 443)] and device.services[str(web["nat_service"])]["dst"] == [(8443, 8443)]
    nat_node = device.nodes[str(web["nat_node"])]
    assert nat_node == (ipaddress.ip_network("203.0.113.2/32"), "firewall-external")
    # The NAT rules come after every rule that decides.
    last_decision = max(i for i, r in enumerate(device.rules) if r["action"] != "DROP" or not any(f in Utm.NATS for f in r["flags"]))  # type: ignore[operator]
    first_nat = min(i for i, r in enumerate(device.rules) if any(f in Utm.NATS for f in r["flags"]))  # type: ignore[operator]
    assert last_decision < first_nat
    assert {"SECUREPOINT_LOAD", "ZONES_REQUIRED", "SECUREPOINT_NAT_RULES"} <= codes(report)


def test_published_server_is_reached_as_the_source_reaches_it() -> None:
    """The rule of the DESTNAT rule is written for the translated destination and port, as the UTM sees it."""
    text, _ = run("securepoint_sample.cfg", "securepoint")
    device = Utm(text)
    to_server = Packet("external", "dmz1", "198.51.100.7", "172.16.20.10", "tcp", 40000, 443)
    # rule-18 (DROP internet -> webserver https, in an earlier group) wins over the publishing rule, on the UTM as here.
    assert not device.allows(to_server)
    smtp = Packet("external", "dmz1", "198.51.100.7", "172.16.20.25", "tcp", 40000, 25)
    assert device.allows(smtp)
    assert not device.allows(Packet("internal", "dmz1", "192.168.10.9", "172.16.20.25", "tcp", 40000, 25))  # rule-17


def test_objects_get_the_zone_they_are_used_in() -> None:
    p = zoned(Policy(vendor="panos"))
    p.addresses["srv"] = Address("srv", AddressKind.NETWORK, "10.0.1.5/32")
    p.rules = [Rule("a", src_zones=["eth0"], dst_zones=["eth1"], destinations=["srv"]),
               Rule("b", src_zones=["eth1"], dst_zones=["eth2"], sources=["srv"])]  # fmt: skip
    text, _ = emit(p)
    device = Utm(text)
    assert {zone for net, zone in device.nodes.values() if str(net) == "10.0.1.5/32"} == {"eth1"}  # (one object: used in eth1 both times)
    p.rules[1].src_zones = ["eth2"]
    text, _ = emit(p)
    assert {zone for net, zone in Utm(text).nodes.values() if str(net) == "10.0.1.5/32"} == {"eth1", "eth2"}


def test_what_the_utm_cannot_say_is_a_comment_line() -> None:
    p = zoned(Policy(vendor="panos"))
    p.addresses["host"] = Address("host", AddressKind.FQDN, "www.example.com")
    p.services["code"] = Service("code", [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)])
    p.services["sctp"] = Service("sctp", [ServiceEntry(Protocol.SCTP, "2905")])
    p.rules = [Rule("fqdn", src_zones=["eth0"], dst_zones=["eth1"], destinations=["host"]),
               Rule("code", src_zones=["eth0"], dst_zones=["eth1"], services=["code"]),
               Rule("sctp", src_zones=["eth0"], dst_zones=["eth1"], services=["sctp"]),
               Rule("neg", src_zones=["eth0"], dst_zones=["eth1"], services=["sctp"], negate_service=True),
               Rule("off", src_zones=["eth0"], dst_zones=["eth1"], enabled=False)]  # fmt: skip
    text, report = emit(p)
    assert Utm(text).rules == []
    for name in ("fqdn", "code", "sctp", "neg"):
        assert report.item("rule", name).disabled, name
    assert "SECUREPOINT_DISABLED" in {f.code for f in report.item("rule", "off").findings}
    assert sum(1 for line in text.splitlines() if line.startswith("# ")) >= 5


def test_nat_shapes() -> None:
    p = zoned(Policy(vendor="panos"))
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "203.0.113.10/32")
    p.addresses["srv"] = Address("srv", AddressKind.NETWORK, "10.0.1.10/32")
    p.addresses["pool"] = Address("pool", AddressKind.NETWORK, "203.0.113.16/28")
    p.zone_networks = {"eth1": ["10.0.1.0/24"]}
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80")])
    p.nat_rules = [
        NatRule("hide", src_zones=["eth1"], dst_zones=["eth0"], source_translation=SourceNat(SnatKind.INTERFACE, interface="eth0")),
        NatRule("pub", src_zones=["eth0"], dst_zones=["eth0"], destinations=["pub"], service="web",
                destination_translation=DestNat("srv", "8080")),
        NatRule("pool", src_zones=["eth1"], dst_zones=["eth0"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pool"])),
        NatRule("both", src_zones=["eth0"], dst_zones=["eth0"], destinations=["pub"],
                source_translation=SourceNat(SnatKind.INTERFACE), destination_translation=DestNat("srv")),
        NatRule("none", src_zones=["eth1"], dst_zones=["eth2"]),
    ]  # fmt: skip
    p.rules = [Rule("allow", src_zones=["eth0"], dst_zones=["eth1"], destinations=["pub"], services=["web"])]
    text, report = emit(p)
    device = Utm(text)
    by = {str(r["comment"]): r for r in device.rules}
    assert by["hide"]["flags"] == ["DROP", "HIDENAT"] and by["hide"]["nat_node"] == "eth0-interface"
    assert by["pub"]["flags"] == ["DROP", "DESTNAT"] and device.nodes[str(by["pub"]["dst"])] == (ipaddress.ip_network("10.0.1.10/32"), "eth1")
    assert device.services[str(by["pub"]["service"])]["dst"] == [(8080, 8080)]
    assert device.nodes[str(by["pub"]["nat_node"])] == (ipaddress.ip_network("203.0.113.10/32"), "firewall-eth0")
    assert by["none"]["flags"] == ["DROP", "HIDENAT_EXCLUDE"]
    assert report.item("nat", "pool").skipped and report.item("nat", "both").skipped
    # The rule allowing the published service is written for the server and the translated port.
    allow = by["allow"]
    assert device.nodes[str(allow["dst"])][0] == ipaddress.ip_network("10.0.1.10/32")
    assert device.services[str(allow["service"])]["dst"] == [(8080, 8080)]
    assert "SECUREPOINT_INTERFACE_OBJECTS" in codes(report)


def test_default_allow_is_written_and_names_are_safe() -> None:
    p = zoned(Policy(vendor="panos", default_interzone=Action.ALLOW, default_intrazone=Action.ALLOW))
    p.addresses["internet"] = Address("internet", AddressKind.NETWORK, "0.0.0.0/0")
    p.addresses['we"ird'] = Address('we"ird', AddressKind.NETWORK, "10.0.0.1/32")
    p.rules = [Rule("x", src_zones=["eth0"], dst_zones=["eth1"], sources=['we"ird'], destinations=["internet"], action=Action.DROP)]
    text, report = emit(p)
    device = Utm(text)
    assert "internet" not in device.nodes and all('"' not in n for n in device.nodes)
    assert sum(1 for r in device.rules if r["comment"] == "fwshift-default") == 9
    assert device.allows(Packet("eth2", "eth2", "10.0.2.1", "10.0.2.2", "tcp", 1024, 22))
    assert not device.allows(Packet("eth0", "eth1", "10.0.0.1", "192.0.2.1", "tcp", 1024, 22))
    assert "SECUREPOINT_RESERVED_NAME" in codes(report)


@pytest.mark.parametrize("seed", range(30))
def test_emitted_commands_decide_like_the_model(seed: int) -> None:
    rng = random.Random(seed)
    model = zoned(random_model(rng))
    for rule in model.rules:
        rule.log_start = rng.random() < 0.2
    if rng.random() < 0.3:
        model.default_interzone = model.default_intrazone = Action.ALLOW
    text, report = emit(model)
    assert compare(model, report, text, rng, seed) == 300


@pytest.mark.parametrize("seed", range(10))
def test_output_read_back_decides_like_the_model(seed: int) -> None:
    rng = random.Random(1000 + seed)
    model = zoned(random_model(rng))
    text, report = emit(model)
    back, _ = parse_text(text)
    expected = copy.deepcopy(model)
    for rule in expected.rules:
        if report.item("rule", rule.origin).disabled:
            rule.enabled = False
    for number in range(200):
        pkt = random_packet(rng, 4 if number % 3 else 6)
        assert model_allows(back, pkt) == model_allows(expected, pkt), (seed, pkt)


# -- random Securepoint configurations, read by the parser and judged by Utm ------------------------------------------

NETS = ["10.0.0.0/24", "10.0.1.0/25", "10.0.1.128/25", "10.0.2.16/28", "10.0.0.17/32", "10.0.0.0/16", "10.0.3.0/24",
        "2001:db8:1::/48", "2001:db8::/32", "0.0.0.0/0"]  # fmt: skip
SERVICES = {"web": 'proto "tcp" dst-ports [ "80" ] src-ports [ ]', "tls": 'proto "tcp" dst-ports [ "443" ] src-ports [ ]',
            "range": 'proto "tcp" dst-ports [ "8000-8010" ] src-ports [ ]', "dns": 'proto "udp" dst-ports [ "53" ] src-ports [ ]',
            "hi": 'proto "tcp" dst-ports [ "22" ] src-ports [ "1024-65535" ]', "ping": 'proto "icmp" icmp-types [ "8" ]',
            "anyicmp": 'proto "icmp" icmp-types [ "any" ]', "ping6": 'proto "icmpv6" icmp-types [ "128" ]', "gre": 'proto "gre"'}  # fmt: skip


def random_conf(rng: random.Random) -> str:
    lines = [f'interface zone new name "{z}" interface "{z}"' for z in MODEL_ZONES]
    lines.append('interface zone new name "firewall-eth0" interface "eth0" flags [ "INTERFACE" ]')
    nodes: List[str] = []
    for index in range(rng.randint(4, 9)):
        name = f"n{index}"
        zone = rng.choice(MODEL_ZONES + ["firewall-eth0"] if index else MODEL_ZONES)
        lines.append(f'node new name "{name}" address "{rng.choice(NETS)}" zone "{zone}"')
        nodes.append(name)
    groups: List[str] = []
    for index in range(rng.randint(0, 3)):
        name = f"g{index}"
        lines.append(f'node group new name "{name}" nodes [ {" ".join(chr(34) + n + chr(34) for n in rng.sample(nodes, rng.randint(1, 3)))} ]')
        groups.append(name)
    for name, words in SERVICES.items():
        lines.append(f'service new name "{name}" {words}')
    lines.append('service group new name "mail" services [ "web" "dns" "ping" ]')
    rule_groups = rng.sample(["alpha", "beta", "gamma"], rng.randint(1, 3))
    created = rule_groups[: rng.randint(1, len(rule_groups))]
    for name in created:
        lines.append(f'rule group new name "{name}"')
    for _ in range(rng.randint(3, 12)):
        src = rng.choice(nodes + groups + ["any"])
        dst = rng.choice(nodes + groups + ["any"])
        service = rng.choice(list(SERVICES) + ["mail", "any", "any"])
        action = rng.choice(["ACCEPT", "ACCEPT", "DROP", "REJECT", "QOS"])
        log = rng.choice([[], ["LOG"], ["LOG_ALL"]])
        flags = " ".join(f'"{f}"' for f in [action] + log)
        lines.append(f'rule new group "{rng.choice(rule_groups)}" src "{src}" dst "{dst}" service "{service}" comment "c" flags [ {flags} ]')
    return "\n".join(lines) + "\n"


def conf_judge(text: str) -> Utm:
    """The configuration as the UTM reads it: a rule group no command creates is placed where its first rule is."""
    utm = Utm("", strict=False)
    for line in text.splitlines():
        if line.startswith("interface zone new"):
            continue
        if line.startswith("rule new group"):
            group = _tokens(line)[3][0]
            if group not in utm.rule_groups:
                utm.rule_groups.append(group)
            if re.search(r'(src|dst) "any"', line):
                _any_rule(utm, line)
                continue
        utm._line(line)
    return utm


def _any_rule(utm: Utm, line: str) -> None:
    """A rule whose source or destination is the object any: every address, from or to every zone."""
    for zone in MODEL_ZONES:
        for family, net in ((4, "0.0.0.0/0"), (6, "::/0")):
            name = f"__any{family}_{zone}"
            if name not in utm.nodes:
                utm.nodes[name] = (ipaddress.ip_network(net), zone)
    if "__any" not in utm.groups:
        utm.groups["__any"] = [n for n in utm.nodes if n.startswith("__any")]
    line = re.sub(r'(src|dst) "any"', r'\1 "__any"', line)
    utm._line(line)


@pytest.mark.parametrize("seed", range(40))
def test_parsed_configuration_decides_like_the_utm(seed: int) -> None:
    rng = random.Random(seed)
    text = random_conf(rng)
    device = conf_judge(text)
    model, report = parse_text(text)
    for number in range(300):
        pkt = random_packet(rng, 4 if number % 3 else 6)
        assert model_allows(model, pkt) == device.allows(pkt), (seed, pkt, text)


def test_a_target_that_looks_up_after_destination_nat_sees_the_server() -> None:
    """iptables sees the destination after DNAT, as the UTM does: the publishing rule names the server and its port."""
    text, _ = run("securepoint_sample.cfg", "iptables")
    publish = [line for line in text.splitlines() if '"rule-2"' in line and line.startswith("-A FORWARD")]
    assert publish and all("-d 172.16.20.10/32" in line and "--dport 443" in line for line in publish)
    assert any("DNAT --to-destination 172.16.20.10:443" in line and "--dport 8443" in line for line in text.splitlines())
