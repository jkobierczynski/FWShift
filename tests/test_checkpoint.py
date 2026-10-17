# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Check Point: parser, emitter, and packet-level equivalence in both directions."""

from __future__ import annotations

import json
import random
import uuid
from typing import Any, Dict, List, Optional

import pytest
from helpers import DATA, CheckPointScript, FortiConfig, PanConfig, load, run
from test_iptables import ZONES, Packet, _in, _port_in, model_verdict, random_model, random_packet

from fwshift import cli
from fwshift.emitters import checkpoint as emit_checkpoint
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, ANY_V4, Action, Address, AddressKind, DestNat, NatRule, Policy, Protocol, Rule
from fwshift.model import RuleScope, Service, ServiceEntry, SnatKind, SourceNat, Zone
from fwshift.options import Options
from fwshift.parsers import checkpoint as parse_checkpoint
from fwshift.report import Report

PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132}

# -- what a gateway would do with an emitted script -------------------------------------


def _object_matches(script: CheckPointScript, name: str, address: str) -> bool:
    fields = script.objects[name]
    kind = fields["kind"]
    if kind == "host":
        return _in(address, str(fields["ip-address"]))
    if kind == "network":
        return _in(address, f"{fields['subnet']}/{fields['mask-length']}")
    if kind == "address-range":
        return _in(address, f"{fields['ip-address-first']}-{fields['ip-address-last']}")
    if kind == "group":
        members = fields.get("members", [])
        assert isinstance(members, list)
        return any(_object_matches(script, member, address) for member in members)
    assert kind == "dns-domain", fields
    return False


def _service_matches(script: CheckPointScript, name: str, pkt: Packet) -> bool:
    fields = script.objects[name]
    kind = str(fields["kind"])
    number = PROTOCOL_NUMBERS.get(pkt.proto) or int(pkt.proto)
    if kind == "service-group":
        members = fields.get("members", [])
        assert isinstance(members, list)
        return any(_service_matches(script, member, pkt) for member in members)
    if kind in ("service-tcp", "service-udp", "service-sctp"):
        if kind.split("-")[1] != pkt.proto or not _port_in(pkt.dport, str(fields["port"])):
            return False
        return "source-port" not in fields or _port_in(pkt.sport, str(fields["source-port"]))
    if kind in ("service-icmp", "service-icmp6"):
        proto = "icmp" if kind == "service-icmp" else "icmp6"
        return pkt.proto == proto and int(str(fields["icmp-type"])) == pkt.icmp_type
    assert kind == "service-other", fields
    return int(str(fields["ip-protocol"])) == number


def script_allows(script: CheckPointScript, pkt: Packet) -> bool:
    """First match in the target layer; an inline layer decides for everything sent into it."""

    def cell(rule: Dict[str, object], column: str, zone: str, address: str) -> bool:
        members = rule.get(column, [])
        assert isinstance(members, list)
        if not members:
            matched = True
        else:
            zones = [m for m in members if script.objects[m]["kind"] == "security-zone"]
            assert not zones or len(zones) == len(members), f"zones and addresses share a cell: {rule}"
            matched = zone in zones if zones else any(_object_matches(script, m, address) for m in members)
        return matched != (rule.get(f"{column}-negate") == "true")

    def walk(layer: str, depth: int = 0) -> bool:
        assert depth < 5
        for rule in script.layers[layer]:
            if rule.get("enabled") == "false":
                continue
            if not cell(rule, "source", pkt.in_if, pkt.src) or not cell(rule, "destination", pkt.out_if, pkt.dst):
                continue
            services = rule.get("service", [])
            assert isinstance(services, list)
            matched = not services or any(_service_matches(script, s, pkt) for s in services)
            if matched == (rule.get("service-negate") == "true"):
                continue
            if rule["action"] == "Apply Layer":
                return walk(str(rule["inline-layer"]), depth + 1)
            return rule["action"] == "Accept"
        raise AssertionError(f"layer '{layer}' has no rule for {pkt}: it would fall to an implicit cleanup")

    return walk(script.layer)


def model_expects(p: Policy, pkt: Packet) -> bool:
    """The model's verdict, with its defaults for traffic no rule matches."""
    verdict = model_verdict(p, pkt)
    if verdict is not None:
        return verdict
    if pkt.in_if != pkt.out_if or pkt.in_if not in p.zones:
        return False  # written with a final drop whatever the source default: see INTERZONE_DEFAULT
    own = p.zones[pkt.in_if].intrazone_allow  # (a zone's own setting, either way, before the policy's default)
    return bool(own) if own is not None else p.default_intrazone == Action.ALLOW


def _packets(rng: random.Random, count: int, zones: List[str]) -> List[Packet]:
    out: List[Packet] = []
    for index in range(count):
        pkt = random_packet(rng, 6 if index % 5 == 0 else 4)
        pkt.in_if, pkt.out_if = rng.choice(zones), rng.choice(zones)
        out.append(pkt)
    return out


@pytest.mark.parametrize("seed", range(40))
def test_emitted_layers_decide_like_the_model(seed: int) -> None:
    """Zone pairs, rule types, lists and negations: the layers of the script give the model's verdict."""
    rng = random.Random(seed)
    model = random_model(rng)
    model.zones = {zone: Zone(zone) for zone in ZONES}
    if seed % 4 == 0:
        model.default_intrazone = Action.ALLOW
    elif seed % 4 == 1:
        model.zones[ZONES[0]].intrazone_allow = True
    elif seed % 4 == 2:  # (allowed inside a zone by default, and one zone that blocks it)
        model.default_intrazone = Action.ALLOW
        model.zones[ZONES[0]].intrazone_allow = False
    for rule in model.rules:
        if rng.random() < 0.2:
            rule.sources, rule.negate_source = [ANY], False  # a rule that can stand alone
        if rng.random() < 0.2:
            rule.destinations, rule.negate_destination = [ANY], False
        if rng.random() < 0.15:
            rule.scope = rng.choice([RuleScope.INTRAZONE, RuleScope.INTERZONE])  # also with zone "any"
    report = Report()
    text = cli.convert(model, "checkpoint", report)
    script = CheckPointScript(text)
    # "eth8" and "eth9" are interfaces no rule names: they only reach the rules that name no zone.
    for pkt in _packets(rng, 500, ZONES + ["eth8", "eth9"]):
        got, expected = script_allows(script, pkt), model_expects(model, pkt)
        if pkt.in_if in ZONES or pkt.out_if in ZONES:
            assert got == expected, (seed, pkt, text)
        else:
            # Whether two unnamed zones are one zone cannot be told: never more is allowed than the model allows.
            assert expected or not got, (seed, pkt, text)


def test_rules_without_zones_need_no_layers() -> None:
    model = random_model(random.Random(1))
    for rule in model.rules:
        rule.src_zones, rule.dst_zones, rule.scope = [ANY], [ANY], RuleScope.UNIVERSAL
    report = Report()
    script = CheckPointScript(cli.convert(model, "checkpoint", report))
    assert script.names("access-layer") == [] and script.names("security-zone") == []
    assert [rule["position"] for rule in script.rules()] == [str(n) for n in range(1, len(script.rules()) + 1)]
    assert script.rules()[-1]["name"] == "FWShift cleanup" and script.rules()[-1]["action"] == "Drop"
    assert not any(note.code == "ZONES_REQUIRED" for note in report.notes)


# -- what a gateway would do with an export ---------------------------------------------

USER_DOMAIN = {"uid": "41e821a0-3720-11e3-aa6e-0800200c9fde", "name": "SMC User", "domain-type": "domain"}


class Export:
    """A small builder for Management API responses, and their first-match evaluation."""

    def __init__(self) -> None:
        self.objects: Dict[str, Dict[str, Any]] = {}
        self.layers: Dict[str, List[Dict[str, Any]]] = {}
        self.nat: List[Dict[str, Any]] = []
        for name, kind in (("Any", "CpmiAnyObject"), ("Original", "Global"), ("Policy Targets", "Global"),
                           ("Accept", "RulebaseAction"), ("Drop", "RulebaseAction"), ("Reject", "RulebaseAction"),
                           ("Inner Layer", "Global"), ("Log", "Track"), ("None", "Track")):  # fmt: skip
            self.add(name, kind)

    @staticmethod
    def uid(name: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))

    def add(self, name: str, kind: str, **fields: Any) -> str:
        entry = {"uid": self.uid(name), "name": name, "type": kind, "domain": USER_DOMAIN}
        entry.update({key.replace("_", "-"): value for key, value in fields.items()})
        self.objects[name] = entry
        return name

    def layer(self, name: str, implicit: str = "drop") -> None:
        self.add(name, "access-layer", implicit_cleanup_action=implicit)
        self.layers[name] = []

    def rule(self, layer: str, name: str, source: List[str], destination: List[str], service: List[str],
             action: str = "Accept", **extra: Any) -> Dict[str, Any]:  # fmt: skip
        entry: Dict[str, Any] = {
            "uid": self.uid(f"{layer}/{len(self.layers[layer])}"),
            "type": "access-rule",
            "name": name,
            "rule-number": len(self.layers[layer]) + 1,
            "source": [self.uid(n) for n in source],
            "destination": [self.uid(n) for n in destination],
            "service": [self.uid(n) for n in service],
            "source-negate": False,
            "destination-negate": False,
            "service-negate": False,
            "action": self.uid(action),
            "track": {"type": self.uid("Log")},
            "vpn": [self.uid("Any")],
            "content": [self.uid("Any")],
            "time": [self.uid("Any")],
            "enabled": True,
            "install-on": [self.uid("Policy Targets")],
        }
        for key, value in extra.items():
            entry[key.replace("_", "-")] = self.uid(value) if key == "inline_layer" else value
        self.layers[layer].append(entry)
        return entry

    def responses(self, with_layer_objects: bool = True) -> List[Dict[str, Any]]:
        dictionary = [o for o in self.objects.values() if with_layer_objects or o["type"] != "access-layer"]
        out: List[Dict[str, Any]] = []
        for name, rules in self.layers.items():
            out.append({"uid": self.uid(name), "name": name, "rulebase": rules, "objects-dictionary": dictionary,
                        "from": 1, "to": len(rules), "total": len(rules)})  # fmt: skip
        if self.nat:
            section = {"uid": self.uid("nat-section"), "type": "nat-section", "name": "Manual", "rulebase": self.nat}
            out.append({"uid": self.uid("nat"), "rulebase": [section], "objects-dictionary": dictionary,
                        "from": 1, "to": len(self.nat), "total": len(self.nat)})  # fmt: skip
        return out

    def parse(self, layer: str = "", **kwargs: Any) -> "tuple[Policy, Report]":
        report = Report()
        data = json.dumps(self.responses(**kwargs)).encode()
        return parse_checkpoint.parse(data, report, layer=layer), report

    # -- evaluation ---------------------------------------------------------------------

    def _address(self, name: str, address: str) -> bool:
        fields = self.objects[name]
        kind = fields["type"]
        if kind == "host":
            return _in(address, fields["ipv4-address"])
        if kind == "network":
            return _in(address, f"{fields['subnet4']}/{fields['mask-length4']}")
        if kind == "address-range":
            return _in(address, f"{fields['ipv4-address-first']}-{fields['ipv4-address-last']}")
        assert kind == "group", fields
        return any(self._address(member["name"], address) for member in fields["members"])

    def _service(self, name: str, pkt: Packet) -> bool:
        fields = self.objects[name]
        kind = fields["type"]
        if kind == "service-group":
            return any(self._service(member["name"], pkt) for member in fields["members"])
        if kind in ("service-tcp", "service-udp"):
            port = str(fields["port"])
            if kind.split("-")[1] != pkt.proto:
                return False
            if port[0] in "<>":
                return pkt.dport > int(port[1:]) if port[0] == ">" else pkt.dport < int(port[1:])
            return _port_in(pkt.dport, port)
        if kind == "service-icmp":
            return pkt.proto == "icmp" and fields["icmp-type"] == pkt.icmp_type
        assert kind == "service-other", fields
        return fields["ip-protocol"] == (PROTOCOL_NUMBERS.get(pkt.proto) or int(pkt.proto))

    def allows(self, pkt: Packet, layer: str) -> bool:
        names = {entry["uid"]: name for name, entry in self.objects.items()}

        def cell(rule: Dict[str, Any], column: str, zone: str, address: str) -> bool:
            members = [names[u] for u in rule[column]]
            matched = False
            for member in members:
                kind = self.objects[member]["type"]
                if kind == "CpmiAnyObject":
                    matched = True
                elif kind == "security-zone":
                    matched = matched or member == zone
                else:
                    matched = matched or self._address(member, address)
            return matched != rule[f"{column}-negate"]

        def walk(name: str) -> bool:
            for rule in self.layers[name]:
                if not rule["enabled"]:
                    continue
                if not cell(rule, "source", pkt.in_if, pkt.src) or not cell(rule, "destination", pkt.out_if, pkt.dst):
                    continue
                services = [names[u] for u in rule["service"]]
                matched = "Any" in services or any(self._service(s, pkt) for s in services)
                if matched == rule["service-negate"]:
                    continue
                if rule.get("inline-layer"):
                    return walk(names[rule["inline-layer"]])
                return names[rule["action"]] == "Accept"
            return self.objects[name]["implicit-cleanup-action"] == "accept"

        return walk(layer)


def random_export(rng: random.Random) -> Export:
    x = Export()
    for index in range(5):
        x.add(f"net{index}", "network", subnet4=f"10.0.{index}.0", mask_length4=24)
    x.add("half", "network", subnet4="10.0.1.128", mask_length4=25)
    x.add("span", "address-range", ipv4_address_first="10.0.2.100", ipv4_address_last="10.0.3.50")
    x.add("host", "host", ipv4_address="10.0.0.17")
    x.add("grp", "group", members=[x.objects["net0"], x.objects["span"]])
    x.add("nested", "group", members=[x.objects["grp"], x.objects["host"], x.objects["net4"]])
    for zone in ZONES:
        x.add(zone, "security-zone")
    x.add("web", "service-tcp", port="80")
    x.add("tls", "service-tcp", port="443")
    x.add("high", "service-tcp", port="8000-8080")
    x.add("above", "service-tcp", port=">8004")
    x.add("dns", "service-udp", port="53")
    x.add("ping", "service-icmp", icmp_type=8)
    x.add("gre", "service-other", ip_protocol=47)
    x.add("mix", "service-group", members=[x.objects["web"], x.objects["dns"], x.objects["ping"]])
    addresses = ["net0", "net1", "net2", "net3", "net4", "half", "span", "host", "grp", "nested"]
    services = ["web", "tls", "high", "above", "dns", "ping", "gre", "mix"]

    def column() -> List[str]:
        roll = rng.random()
        if roll < 0.3:
            return ["Any"]
        if roll < 0.4:
            return rng.sample(ZONES, rng.randint(1, 2))
        return rng.sample(addresses, rng.randint(1, 3))

    def fill(layer: str, depth: int) -> None:
        for index in range(rng.randint(2, 7)):
            service = ["Any"] if rng.random() < 0.4 else rng.sample(services, rng.randint(1, 3))
            source, destination = column(), column()
            if depth < 2 and rng.random() < 0.3:
                inner = f"{layer}-{index}"
                service = service if rng.random() < 0.2 else ["Any"]  # as in practice: a layer per network
                x.layer(inner, implicit=rng.choice(["drop", "drop", "accept"]))
                rule = x.rule(layer, f"{layer} rule {index}", source, destination, service, "Inner Layer",
                              inline_layer=inner)  # fmt: skip
                fill(inner, depth + 1)
            else:
                action = rng.choice(["Accept", "Accept", "Drop", "Reject"])
                rule = x.rule(layer, f"{layer} rule {index}", source, destination, service, action)
            for part, members in (("source", source), ("destination", destination), ("service", service)):
                plain = members != ["Any"] and not any(m in ZONES for m in members)
                rule[f"{part}-negate"] = plain and rng.random() < 0.15
            rule["enabled"] = rng.random() > 0.1
        if rng.random() < 0.5:
            x.rule(layer, f"{layer} cleanup", ["Any"], ["Any"], ["Any"], rng.choice(["Drop", "Accept"]))

    x.layer("Network", implicit="drop")
    fill("Network", 0)
    return x


def test_parsed_layers_decide_like_the_gateway_would() -> None:
    """Inline layers, their cleanups, zones in cells, negations: the flattened rules give the same verdict.

    A ruleset in which a rule could not be flattened exactly is set aside: its rules are flagged, not wrong.
    """
    compared = 0
    for seed in range(80):
        rng = random.Random(seed)
        export = random_export(rng)
        policy, _ = export.parse()
        if any(rule.unsupported for rule in policy.rules):
            continue
        compared += 1
        for pkt in _packets(rng, 300, ZONES):
            if pkt.proto == "icmp6" or ":" in pkt.src:
                continue
            expected = model_verdict(policy, pkt)
            assert (expected or False) == export.allows(pkt, "Network"), (seed, pkt, json.dumps(export.responses()))
    assert compared >= 55, compared


def test_roundtrip_of_a_random_export_keeps_every_decision() -> None:
    """Export -> model -> script: the script decides like the export it came from."""
    compared = 0
    for seed in range(40):
        rng = random.Random(1000 + seed)
        export = random_export(rng)
        policy, report = export.parse()
        if any(rule.unsupported for rule in policy.rules):
            continue
        compared += 1
        script = CheckPointScript(cli.convert(policy, "checkpoint", report))
        for pkt in _packets(rng, 200, ZONES):
            if pkt.proto == "icmp6" or ":" in pkt.src:
                continue
            assert script_allows(script, pkt) == export.allows(pkt, "Network"), (seed, pkt)
    assert compared >= 15, compared


# -- the sample ---------------------------------------------------------------------------


def test_sample_is_read_as_exported() -> None:
    policy, report = load("checkpoint_sample.json")
    assert policy.vendor == "checkpoint" and policy.scope == "Network"
    assert list(policy.zones) == ["InternalZone", "ExternalZone"]
    assert policy.default_interzone == Action.DENY and policy.default_intrazone == Action.DENY
    assert not policy.lookup_after_dnat  # rules match the original packet
    assert policy.addresses["lan-net"].value == "10.10.0.0/16"
    assert policy.addresses["lan6-net"].value == "2001:db8:10::/48"
    assert policy.addresses["admin-range"].kind == AddressKind.RANGE
    assert policy.addresses[".updates.example.com"].kind == AddressKind.FQDN
    assert policy.addresses[".updates.example.com"].value == "updates.example.com"
    assert policy.address_groups["dns-2"].members == ["192.0.2.54", "2001:db8:53::54"]  # one object, two addresses
    assert policy.address_groups["dns-servers"].members == ["dns-1", "dns-2"]
    assert policy.addresses["netadmins"].kind == AddressKind.UNSUPPORTED
    assert policy.addresses["gw-edge"].value == "198.51.100.1/32"
    assert policy.services["https"].builtin == "checkpoint" and policy.services["tcp-high"].builtin == ""
    assert policy.services["syslog-from-high"].entries == [ServiceEntry(Protocol.UDP, "514", "1024-65535")]
    assert policy.services["echo-request"].entries == [ServiceEntry(Protocol.ICMP, icmp_type=8)]
    assert policy.services["gre"].entries == [ServiceEntry(Protocol.IP, ip_protocol=47)]
    assert policy.services["Facebook"].unsupported
    by_name = {rule.name: rule for rule in policy.rules}
    assert [rule.name for rule in policy.rules][:3] == ["DNS", "rule-2", "Web out"]
    assert by_name["DNS"].tags == ["Infrastructure"] and by_name["DNS"].description == "Name resolution"
    web = by_name["Web out"]
    assert (web.src_zones, web.dst_zones, web.sources, web.destinations) == (["InternalZone"], ["ExternalZone"], [ANY], [ANY])
    guests = by_name["Guests stay out"]
    assert guests.negate_destination and guests.action == Action.DROP and guests.services == [ANY]
    assert by_name["Updates"].schedule == "Work-Hours"
    assert not by_name["Old rule"].enabled
    assert by_name["Partners"].unsupported == ["VPN community match Partner-VPN"]
    assert not by_name["IPv6 out"].log_end and by_name["DNS"].log_end
    assert by_name["No ident"].action == Action.RESET_CLIENT
    codes = {(item.name, f.code) for item in report.items.values() for f in item.findings}
    assert ("rule-2", "DEVICE_TARGET") in codes
    assert ("gw-edge", "GATEWAY_OBJECT") in codes and ("Tunnels", "GATEWAY_OBJECT") in codes
    assert policy.addresses["gw-edge"].builtin == "checkpoint"  # a script does not create a gateway
    assert [note.code for note in report.notes] == ["IMPLIED_RULES"]  # the layer ends in a cleanup rule


def test_sample_inline_layer_is_flattened_in_place() -> None:
    policy, report = load("checkpoint_sample.json")
    names = [rule.name for rule in policy.rules]
    start = names.index("DMZ access / Web in")
    assert names[start : start + 4] == [
        "DMZ access / Web in",
        "DMZ access / Mail in",
        "DMZ access / Ping from LAN",
        "DMZ access (cleanup of DMZ-Layer)",
    ]
    web, _, ping, cleanup = policy.rules[start : start + 4]
    # web-1 also stands for its public address, which the rule applying the layer does not let in.
    assert web.destinations == ["10.20.0.10/32"] and web.services == ["app-ports"]
    assert policy.rules[start + 1].destinations == ["mail-1"]  # inside dmz-net: the name is kept
    assert ping.sources == ["lan-net"] and ping.destinations == ["dmz-net"]  # the layer's rule limits it
    assert cleanup.action == Action.DROP and cleanup.destinations == ["dmz-net"] and not cleanup.log_end
    assert report.item("rule", cleanup.origin).status == "exact"  # the export shows the cleanup action
    assert all(rule.tags == ["Inbound"] for rule in (web, ping, cleanup))


def test_sample_nat() -> None:
    policy, report = load("checkpoint_sample.json")
    nat = {rule.name: rule for rule in policy.nat_rules}
    assert list(nat) == [f"nat-{n}" for n in range(1, 10)]
    # Automatic rules name the object where its translated address is meant; the NAT settings give the address.
    assert policy.addresses["web-1_valid_address"].value == "203.0.113.10/32"
    assert nat["nat-1"].sources == ["web-1"]
    assert nat["nat-1"].source_translation == SourceNat(SnatKind.STATIC, ["web-1_valid_address"])
    assert nat["nat-1"].description == "automatic NAT rule"
    assert nat["nat-2"].destinations == ["web-1_valid_address"] and nat["nat-2"].destination_translation == DestNat("web-1")
    assert nat["nat-3"].sources == nat["nat-3"].destinations == ["plc-net"]  # traffic inside the network keeps its addresses
    assert nat["nat-3"].source_translation is None and nat["nat-3"].destination_translation is None
    assert nat["nat-4"].source_translation == SourceNat(SnatKind.INTERFACE)  # hide behind the gateway
    assert nat["nat-5"].source_translation is None and nat["nat-5"].destination_translation is None
    assert nat["nat-6"].service == "tcp-2525" and nat["nat-6"].destination_translation == DestNat("mail-1", "25")
    assert nat["nat-7"].source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["nat-out"])
    assert nat["nat-8"].source_translation == SourceNat(SnatKind.INTERFACE, interface="gw-edge")
    assert not nat["nat-9"].enabled
    assert all(rule.src_zones == [ANY] and rule.dst_zones == [ANY] for rule in policy.nat_rules)
    assert not any(rule.unsupported for rule in policy.nat_rules)
    assert "NO_NAT_RULEBASE" not in [note.code for note in report.notes]


def test_object_with_automatic_static_nat_also_matches_its_translated_address() -> None:
    policy, report = load("checkpoint_sample.json")
    by_name = {rule.name: rule for rule in policy.rules}
    assert by_name["Public web"].destinations == ["web-1", "web-1_valid_address"]
    assert policy.address_groups["dmz-servers"].members == ["web-1", "web-1_valid_address", "mail-1"]
    assert "plc-net_hiding_address" not in policy.addresses and "plc-net_valid_address" not in policy.addresses
    assert by_name["Admins"].destinations == ["plc-net"]  # hide NAT gives nothing to connect to
    assert [f.code for f in report.item("address", "web-1").findings] == ["AUTOMATIC_NAT"]
    assert report.item("address", "web-1").status == "exact"
    # Inside the DMZ layer the public address cannot arrive: the rule applying the layer does not match it.
    assert by_name["DMZ access / Web in"].destinations == ["10.20.0.10/32"]
    # A target that looks rules up after NAT gets the real address only.
    text, target = run("checkpoint_sample.json", "fortios", Options(policy_id_start=1))
    assert FortiConfig(text).policies()["Public web"].get("dstaddr") == "web-1"


def test_automatic_nat_that_cannot_be_read() -> None:
    x = _simple()
    x.add("pool-net", "network", subnet4="10.5.0.0", mask_length4=24,
          nat_settings={"auto-rule": True, "method": "hide", "hide-behind": "ip-address", "ipv4-address": "203.0.113.77"})  # fmt: skip
    x.add("odd", "host", ipv4_address="10.5.1.1", nat_settings={"auto-rule": True, "method": "static"})
    x.add("plain", "host", ipv4_address="10.5.1.2", nat_settings={"auto-rule": False})
    x.add("block", "network", subnet4="10.6.0.0", mask_length4=30,
          nat_settings={"auto-rule": True, "method": "static", "ipv4-address": "203.0.113.64"})  # fmt: skip
    x.rule("Network", "r", ["pool-net", "odd", "plain", "block"], ["Any"], ["web"])
    for original, translated, method in (("pool-net", "pool-net", "hide"), ("block", "block", "static"),
                                         ("plain", "plain", "static")):  # fmt: skip
        x.nat.append({"uid": x.uid(f"auto-{original}"), "type": "nat-rule", "method": method, "auto-generated": True,
                      "original-source": x.uid(original), "original-destination": x.uid("Any"),
                      "original-service": x.uid("Any"), "translated-source": x.uid(translated),
                      "translated-destination": x.uid("Original"), "translated-service": x.uid("Original")})  # fmt: skip
    policy, report = x.parse()
    assert policy.rules[0].sources == ["pool-net", "odd", "plain", "block", "block_valid_address"]
    assert policy.addresses["block_valid_address"].value == "203.0.113.64/30"  # as many addresses as the network
    assert policy.addresses["pool-net_hiding_address"].value == "203.0.113.77/32"
    assert report.item("address", "odd").status == "needs-review"
    hide, static, missing = policy.nat_rules
    assert hide.source_translation == SourceNat(SnatKind.DYNAMIC_PORT, ["pool-net_hiding_address"])
    assert static.source_translation == SourceNat(SnatKind.STATIC, ["block_valid_address"])
    assert "NAT settings are not in the export" in missing.unsupported[0]  # never an identity translation
    # The inbound half of an automatic rule, for an object whose settings cannot be read: the same.
    for name in ("plain", "odd"):
        x.nat.append({"uid": x.uid(f"in-{name}"), "type": "nat-rule", "method": "static", "auto-generated": True,
                      "original-source": x.uid("Any"), "original-destination": x.uid(name),
                      "original-service": x.uid("Any"), "translated-source": x.uid("Original"),
                      "translated-destination": x.uid(name), "translated-service": x.uid("Original")})  # fmt: skip
    policy, _ = x.parse()
    for nat in policy.nat_rules[-2:]:
        assert "NAT settings are not in the export" in nat.unsupported[0]
        for target in ("fortios", "iptables", "checkpoint"):
            out = Report()
            cli.convert(policy, target, out, Options(nat_zone="untrust"))
            assert out.item("nat", nat.origin).skipped, (target, nat.name)


def test_export_without_nat_rulebase_says_so() -> None:
    x = _simple()
    x.rule("Network", "r", ["lan"], ["srv"], ["web"])
    _, report = x.parse()
    assert "NO_NAT_RULEBASE" in [note.code for note in report.notes]


def test_sample_to_panos() -> None:
    text, report = run("checkpoint_sample.json", "panos", Options(nat_zone="untrust"))
    config = PanConfig(text)
    assert config.get("security", "Web out", "from") == ["InternalZone"]
    assert config.get("security", "Guests stay out", "negate-destination") == ["yes"]
    assert config.get("security", "No ident", "action") == ["reset-client"]
    assert config.get("security", "Social", "disabled") == ["yes"]  # an application object is not a port
    assert config.get("security", "DMZ access _ Ping from LAN", "application") == ["ping"]
    assert config.get("nat", "nat-6", "destination-translation", "translated-port") == ["25"]
    assert config.get("nat", "nat-6", "to") == ["untrust"]
    codes = [f.code for f in report.item("nat", "nat-6").findings]
    assert "NAT_ZONE_ASSUMED" in codes  # the zone is an assumption
    assert "NAT_ORDER" in codes  # nat-4 above it could not be written and no longer claims its traffic
    assert report.item("nat", "nat-8").skipped  # hide behind the gateway: the interface is not known
    text, report = run("checkpoint_sample.json", "panos")
    assert " nat rules" not in text  # no destination zone, no NAT rule
    assert all("--target-nat-zone" in f.message for f in report.item("nat", "nat-1").findings)
    assert "fwshift-intrazone-deny" in text  # Check Point has no intrazone default


def test_sample_to_fortios_and_iptables() -> None:
    text, report = run("checkpoint_sample.json", "fortios", Options(policy_id_start=1))
    policies = FortiConfig(text).policies()
    assert policies["Web out"].get("srcintf") == "InternalZone"
    assert policies["DNS"].get("srcintf") == "any" and policies["DNS"].get("dstintf") == "any"
    assert policies["Social"].get("status") == "disable"
    assert report.item("rule", "Updates").disabled
    text, report = run("checkpoint_sample.json", "iptables", Options(zone_map={"InternalZone": "eth1", "ExternalZone": "eth0"}))
    assert "-A FORWARD -i eth1 -o eth0" in text
    assert "--reject-with tcp-reset" in text  # Reject of a TCP service
    assert "-j DNAT --to-destination 10.20.0.25:25" in text


def test_sample_roundtrip_keeps_every_decision() -> None:
    policy, report = load("checkpoint_sample.json")
    text = cli.convert(policy, "checkpoint", report)
    script = CheckPointScript(text, existing=tuple(n for n, s in policy.services.items() if s.builtin) + (
        "Network", "InternalZone", "ExternalZone", "gw-edge"))  # fmt: skip
    assert script.names("access-layer") == []  # zone-only cells need no layers
    assert script.rule("Web out")["source"] == ["InternalZone"]
    assert script.rule("Social")["service"] == ["Facebook"] and "enabled" not in script.rule("Social")
    assert "https" not in script.names("service-tcp")  # predefined: referenced, not created
    assert "gw-edge" not in script.names("host") and not any(line.startswith("zone ") for line in text.splitlines())
    assert script.rules()[-1]["name"] == "Cleanup rule"  # no second cleanup after the source's own
    nat = {str(rule["comments"]).split(":")[0]: rule for rule in script.nat}
    assert nat["nat-8"]["translated-source"] == "gw-edge" and nat["nat-8"]["method"] == "hide"
    assert script.rule("Public web")["destination"] == ["web-1", "web-1_valid_address"]
    assert nat["nat-2"]["original-destination"] == "web-1_valid_address"  # manual rules, with the address named
    assert "nat-4" not in nat and "--target-gateway" in report.item("nat", "nat-4").findings[0].message
    assert "IMPLIED_RULES" in [note.code for note in report.notes]
    # What the management server has already, for the replay: the gateway and the predefined services.
    script.objects["gw-edge"] = {"kind": "host", "ip-address": "198.51.100.1"}
    script.objects["InternalZone"] = script.objects["ExternalZone"] = {"kind": "security-zone"}
    script.objects["Facebook"] = {"kind": "service-group"}  # an application: no packet here is one
    for name, service in policy.services.items():
        if service.builtin and service.entries:
            entry = service.entries[0]
            if entry.protocol in (Protocol.TCP, Protocol.UDP):
                script.objects[name] = {"kind": f"service-{entry.protocol.value}", "port": entry.dst_ports}
            elif entry.protocol == Protocol.ICMP:
                script.objects[name] = {"kind": "service-icmp", "icmp-type": str(entry.icmp_type)}
            else:
                script.objects[name] = {"kind": "service-other", "ip-protocol": str(entry.ip_protocol)}
    rng = random.Random(7)
    for _ in range(600):
        pkt = Packet(rng.choice(["InternalZone", "ExternalZone", "eth9"]), rng.choice(["InternalZone", "ExternalZone"]),
                     rng.choice(["10.10.5.12", "10.10.200.7", "10.20.0.10", "192.0.2.9", "10.10.7.15"]),
                     rng.choice(["192.0.2.53", "10.20.0.10", "10.20.0.25", "10.20.0.99", "198.51.100.1", "203.0.113.80"]),
                     rng.choice(["tcp", "udp", "icmp", "47"]), 40000, rng.choice([22, 25, 53, 80, 113, 443, 9005]), 8)  # fmt: skip
        assert script_allows(script, pkt) == bool(model_verdict(policy, pkt)), pkt


# -- parser details -----------------------------------------------------------------------


def _simple() -> Export:
    x = Export()
    x.add("lan", "network", subnet4="10.0.0.0", mask_length4=24)
    x.add("srv", "host", ipv4_address="10.0.1.10")
    x.add("web", "service-tcp", port="80")
    x.add("dmz", "security-zone")
    x.layer("Network")
    return x


def test_what_is_missing_is_never_read_as_any() -> None:
    x = _simple()
    x.rule("Network", "ghost", ["lan"], ["srv"], ["web"])
    x.layers["Network"][0]["source"] = ["11111111-2222-3333-4444-555555555555"]  # not in the dictionary
    x.rule("Network", "empty", ["lan"], ["srv"], ["web"])
    del x.layers["Network"][1]["destination"]
    x.rule("Network", "summary", ["lan"], ["srv"], ["web"])
    # A group whose members come at details-level standard, with no full object anywhere.
    x.objects["grp"] = {"uid": x.uid("grp"), "name": "grp", "type": "group",
                        "members": [{"uid": x.uid("member"), "name": "member", "type": "host"}]}  # fmt: skip
    x.layers["Network"][2]["destination"] = [x.uid("grp")]
    x.rule("Network", "odd action", ["lan"], ["lan"], ["web"], "Accept")
    x.layers["Network"][3]["action"] = "Ask"
    policy, report = x.parse()
    ghost, empty, summary, odd = policy.rules
    assert ghost.sources != [ANY] and policy.addresses[ghost.sources[0]].kind == AddressKind.UNSUPPORTED
    assert empty.unsupported == ["rule without destination"]
    assert summary.destinations == ["grp"] and policy.addresses["member"].kind == AddressKind.UNSUPPORTED
    assert "dereference-group-members true" in report.item("address", "member").findings[0].message
    assert odd.action == Action.DROP and odd.unsupported == ["action 'Ask'"]
    for target in ("panos", "fortios", "iptables", "checkpoint"):
        report = Report()
        cli.convert(policy, target, report)
        assert all(report.item("rule", rule.origin).disabled for rule in policy.rules), target


def test_zone_cells() -> None:
    x = _simple()
    x.rule("Network", "zone only", ["dmz"], ["Any"], ["web"])
    x.rule("Network", "mixed", ["dmz", "lan"], ["srv"], ["web"])
    x.rule("Network", "negated zone", ["dmz"], ["srv"], ["web"], source_negate=True)
    policy, _ = x.parse()
    only, mixed, negated = policy.rules
    assert only.src_zones == ["dmz"] and only.sources == [ANY] and not only.unsupported
    assert "meaning either of them" in mixed.unsupported[0]
    assert negated.unsupported == ["negated zone in source"]


def test_layers_and_pages() -> None:
    x = _simple()
    x.rule("Network", "one", ["lan"], ["srv"], ["web"])
    x.rule("Network", "two", ["Any"], ["Any"], ["Any"], "Drop")
    first, second = dict(x.responses()[0]), dict(x.responses()[0])
    first.update({"rulebase": x.layers["Network"][:1], "from": 1, "to": 1})
    second.update({"rulebase": x.layers["Network"][1:], "from": 2, "to": 2})
    policy = parse_checkpoint.parse(json.dumps([second, first]).encode(), Report())
    assert [rule.name for rule in policy.rules] == ["one", "two"]  # pages are ordered by their 'from'
    wrapped = json.dumps({"access": [first, second], "anything": {"nested": []}}).encode()
    assert len(parse_checkpoint.parse(wrapped, Report()).rules) == 2

    x.layer("Application")
    x.rule("Application", "apps", ["Any"], ["Any"], ["Any"])
    with pytest.raises(ParseError, match="several access layers.*--layer: Application, Network"):
        x.parse()
    policy, _ = x.parse(layer="Application")
    assert policy.scope == "Application" and [rule.name for rule in policy.rules] == ["apps"]
    with pytest.raises(ParseError, match="layer 'Nope' not found; available: Application, Network"):
        x.parse(layer="Nope")


def test_inline_layer_cleanup_and_missing_layers() -> None:
    x = _simple()
    x.layer("Inner", implicit="accept")
    x.rule("Network", "parent", ["lan"], ["Any"], ["Any"], "Inner Layer", inline_layer="Inner")
    x.rule("Inner", "child", ["Any"], ["srv"], ["web"], "Drop")
    policy, report = x.parse()
    child, cleanup = policy.rules
    assert (child.sources, child.destinations, child.action) == (["lan"], ["srv"], Action.DROP)
    assert cleanup.action == Action.ALLOW and cleanup.sources == ["lan"]  # the layer accepts what it does not match
    assert report.item("rule", cleanup.origin).status == "exact"
    assert "IMPLICIT_CLEANUP" not in [note.code for note in report.notes]  # the Network layer's own is known: drop

    policy, report = x.parse(with_layer_objects=False)
    cleanup = policy.rules[1]
    assert cleanup.action == Action.DROP  # not shown: the restrictive reading, and a person is told
    assert report.item("rule", cleanup.origin).status == "needs-review"
    assert "IMPLICIT_CLEANUP" in [note.code for note in report.notes]

    x.rule("Inner", "catch", ["Any"], ["Any"], ["Any"], "Accept")
    policy, _ = x.parse()
    assert [rule.name for rule in policy.rules] == ["parent / child", "parent / catch"]  # nothing left to clean up

    del x.layers["Inner"]
    policy, report = x.parse(layer="Network")
    assert len(policy.rules) == 1 and "is not in the export" in policy.rules[0].unsupported[0]
    assert policy.rules[0].action == Action.DROP


def test_top_layer_with_accepting_implicit_cleanup() -> None:
    x = _simple()
    x.objects["Network"]["implicit-cleanup-action"] = "accept"
    x.rule("Network", "one", ["lan"], ["srv"], ["web"], "Drop")
    policy, report = x.parse()
    assert policy.default_interzone == Action.ALLOW and policy.default_intrazone == Action.ALLOW
    assert "IMPLICIT_CLEANUP" in [note.code for note in report.notes]
    target = Report()
    cli.convert(policy, "panos", target)
    assert "INTERZONE_DEFAULT" in [note.code for note in target.notes]


def test_rule_and_layer_matches_are_combined() -> None:
    x = _simple()
    x.add("big", "network", subnet4="10.0.0.0", mask_length4=23)
    x.add("other", "network", subnet4="10.9.0.0", mask_length4=24)
    x.add("overlap", "address-range", ipv4_address_first="10.0.1.200", ipv4_address_last="10.0.2.20")
    x.add("part", "network", subnet4="10.0.1.0", mask_length4=25)
    x.add("ports", "service-tcp", port="1-1023")
    x.add("dns", "service-udp", port="53")
    x.layer("Inner")
    x.rule("Network", "p", ["big"], ["Any"], ["ports"], "Inner Layer", inline_layer="Inner")
    x.rule("Inner", "narrower", ["lan"], ["srv"], ["web"])
    x.rule("Inner", "wider", ["Any"], ["Any"], ["Any"])
    x.rule("Inner", "disjoint", ["other"], ["Any"], ["Any"])
    x.rule("Inner", "partial", ["overlap"], ["Any"], ["Any"])
    x.rule("Inner", "other protocol", ["lan"], ["Any"], ["dns"])
    x.rule("Inner", "negated", ["lan"], ["Any"], ["Any"], source_negate=True)
    x.rule("Inner", "not here", ["other"], ["Any"], ["Any"], source_negate=True)
    x.rule("Inner", "none left", ["big", "other"], ["Any"], ["Any"], source_negate=True)
    x.layer("Second")
    x.rule("Network", "q", ["part"], ["srv"], ["Any"], "Inner Layer", inline_layer="Second", source_negate=True,
           destination_negate=True)  # fmt: skip
    x.rule("Second", "inside", ["big"], ["lan"], ["Any"], destination_negate=True)
    x.rule("Second", "rest", ["Any"], ["Any"], ["Any"], "Drop")
    policy, _ = x.parse()
    by_name = {rule.name: rule for rule in policy.rules}
    assert "p / disjoint" not in by_name  # can never match inside the layer
    assert (by_name["p / narrower"].sources, by_name["p / narrower"].services) == (["lan"], ["web"])
    assert (by_name["p / wider"].sources, by_name["p / wider"].services) == (["big"], ["ports"])
    assert by_name["p / partial"].sources == ["10.0.1.200-10.0.1.255"] and not by_name["p / partial"].unsupported
    assert "service limited both" in by_name["p / other protocol"].unsupported[0]
    # "in big and not in lan" is the other half of big; a list that excludes nothing of big changes nothing.
    assert (by_name["p / negated"].sources, by_name["p / negated"].negate_source) == (["10.0.1.0/24"], False)
    assert (by_name["p / not here"].sources, by_name["p / not here"].negate_source) == (["big"], False)
    assert "p / none left" not in by_name
    # "not in part" around "in big" leaves the rest of big; two negated lists exclude what is in either.
    inside = by_name["q / inside"]
    assert (inside.sources, inside.negate_source) == (["10.0.0.0/24", "10.0.1.128/25"], False)
    assert (inside.destinations, inside.negate_destination) == (["srv", "lan"], True)
    assert (by_name["q / rest"].sources, by_name["q / rest"].negate_source) == (["part"], True)
    assert not any(rule.unsupported for name, rule in by_name.items() if name != "p / other protocol")
    x.layers["Network"][0]["enabled"] = False
    policy, _ = x.parse()
    sent_in = [rule for rule in policy.rules if rule.name.startswith("p ")]
    assert len(sent_in) == 7 and not any(rule.enabled for rule in sent_in)  # a disabled rule sends nothing in


def test_services() -> None:
    x = _simple()
    x.add("low", "service-tcp", port="<1024")
    x.add("high", "service-udp", port=">1023", source_port="53")
    x.add("typed", "service-icmp", icmp_type=3, icmp_code=4)
    x.add("v6", "service-icmp6", icmp_type=128)
    x.add("inspect", "service-other", ip_protocol=17, match="uh_dport = 5000")
    x.add("rpc", "service-dce-rpc", interface_uuid="97f83d5c-1994-11d1-a90d-00c04fb960f8")
    x.add("broken", "service-tcp", port="http")
    x.rule("Network", "all", ["lan"], ["srv"], ["low", "high", "typed", "v6", "inspect", "rpc", "broken"])
    policy, report = x.parse()
    assert policy.services["low"].entries == [ServiceEntry(Protocol.TCP, "1-1023")]
    assert policy.services["high"].entries == [ServiceEntry(Protocol.UDP, "1024-65535", "53")]
    assert policy.services["typed"].entries == [ServiceEntry(Protocol.ICMP, icmp_type=3, icmp_code=4)]
    assert policy.services["v6"].entries == [ServiceEntry(Protocol.ICMP6, icmp_type=128)]
    for name in ("inspect", "rpc", "broken"):
        assert policy.services[name].unsupported and report.item("service", name).status == "needs-review"


def test_nat_shapes() -> None:
    x = _simple()
    x.add("pub", "host", ipv4_address="203.0.113.5")
    x.add("pool", "address-range", ipv4_address_first="203.0.113.20", ipv4_address_last="203.0.113.29")
    x.add("alt", "service-tcp", port="8080")
    x.add("multi", "service-tcp", port="8000-8010")

    def nat(**fields: str) -> None:
        columns = ["original-source", "original-destination", "original-service", "translated-source",
                   "translated-destination", "translated-service"]  # fmt: skip
        entry: Dict[str, Any] = {"uid": x.uid(f"nat{len(x.nat)}"), "type": "nat-rule", "method": "static", "enabled": True,
                                 "install-on": [x.uid("Policy Targets")]}  # fmt: skip
        for column in columns:
            default = "Original" if column.startswith("translated") else "Any"
            entry[column] = x.uid(fields.get(column.replace("-", "_"), default))
        entry["method"] = fields.get("method", "static")
        x.nat.append(entry)

    nat(original_destination="pub", original_service="alt", translated_destination="srv", translated_service="web")
    nat(original_service="alt", translated_service="web")  # a port change towards every destination
    nat(original_destination="pub", original_service="alt", translated_service="multi")
    nat(original_source="lan", translated_source="pool", method="hide")
    nat(original_source="dmz")  # a zone in a NAT cell
    nat(original_source="lan", translated_source="pub", method="nat64")
    x.nat[3]["translated-source"] = "22222222-3333-4444-5555-666666666666"  # not in the dictionary: not "Original"
    policy, _ = x.parse()
    forward, anywhere, ranged, unknown, zoned, nat64 = policy.nat_rules
    assert forward.destination_translation == DestNat("srv", "80") and not forward.unsupported
    assert anywhere.unsupported == ["port translation without a destination address"]
    assert "is not a single port" in ranged.unsupported[0]
    assert unknown.source_translation is not None  # an object that is missing is a translation that is unknown
    assert policy.addresses[unknown.source_translation.addresses[0]].kind == AddressKind.UNSUPPORTED
    assert zoned.unsupported == ["security zone in original-source"]
    assert nat64.unsupported == ["NAT method 'nat64'"]
    for target in ("panos", "fortios", "iptables", "checkpoint"):
        report = Report()
        cli.convert(policy, target, report, Options(nat_zone="untrust"))
        for rule in (anywhere, ranged, unknown, zoned, nat64):
            assert report.item("nat", rule.origin).skipped, (target, rule.name)


def test_malformed_input_is_a_clean_error() -> None:
    with pytest.raises(ParseError, match="not valid JSON"):
        parse_checkpoint.parse(b"{broken", Report())
    with pytest.raises(ParseError, match="no Management API response"):
        parse_checkpoint.parse(b'{"hello": [1, 2, "three"]}', Report())
    with pytest.raises(ParseError, match="no Management API response"):
        parse_checkpoint.parse(b"[]", Report())
    odd = {"uid": "u", "name": "L", "rulebase": [7, None, {"type": "access-rule", "source": 5, "service": {"x": 1}}],
           "objects-dictionary": ["x", {"no": "uid"}], "from": "one"}  # fmt: skip
    policy = parse_checkpoint.parse(json.dumps(odd).encode(), Report())
    assert len(policy.rules) == 1 and policy.rules[0].unsupported  # nothing guessed, nothing crashed
    assert cli.detect_format(b'  [{"rulebase": []}]') == "checkpoint" and cli.detect_format(b'{"uid": 1}') == "checkpoint"
    assert cli.main(["inspect", str(DATA / "checkpoint_sample.json"), "--layer", "Nope"]) == 1


# -- emitter details ----------------------------------------------------------------------


def _policy(*rules: Rule, vendor: str = "panos") -> Policy:
    p = Policy(vendor=vendor)
    p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.0.0.10/32", "It's the web server")
    p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.1.0.0/16")
    p.addresses["site"] = Address("site", AddressKind.FQDN, "www.example.com")
    p.addresses["pub"] = Address("pub", AddressKind.NETWORK, "203.0.113.10/32")
    p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "80,443")])
    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["dns"] = Service("dns", [ServiceEntry(Protocol.UDP, "53"), ServiceEntry(Protocol.TCP, "53")])
    for rule in rules:
        rule.origin = rule.name
        p.rules.append(rule)
    return p


def _convert(p: Policy, options: Optional[Options] = None, **kwargs: Any) -> "tuple[CheckPointScript, Report, str]":
    report = Report()
    text = cli.convert(p, "checkpoint", report, options)
    return CheckPointScript(text, **kwargs), report, text


def test_script_shape_and_quoting() -> None:
    p = _policy(Rule("It's \"quoted\"; $(rm -rf /)", sources=["lan"], destinations=["web"], services=["https"],
                     description="line one\nline two `id`"))  # fmt: skip
    script, report, text = _convert(p)
    assert text.startswith("#!/bin/sh\n") and "mgmt_cli publish" in text and "\nm publish" not in text
    assert all(call[0] == "add" for call in script.calls)  # nothing is changed, deleted, published or installed
    rule = script.rules()[0]
    assert rule["name"] == "It's \"quoted\"; $(rm -rf /)" and rule["comments"] == "line one line two `id`"
    assert script.objects["web"]["comments"] == "It's the web server"
    assert "'It'\\''s the web server'" in text  # single quotes: the shell expands nothing in them
    assert [note.code for note in report.notes][:2] == ["CHECKPOINT_SCRIPT", "IMPLIED_RULES"]
    assert "position 1 " in text and script.rules()[-1]["name"] == "FWShift cleanup"


def test_objects_of_one_namespace() -> None:
    p = _policy(Rule("r", sources=["lan", "10.9.0.0/24", "10.9.1.1", "10.9.2.1-10.9.2.9", ANY_V4],
                     destinations=["site"], services=["web", "dns"]))  # fmt: skip
    p.addresses["Any"] = Address("Any", AddressKind.NETWORK, "10.3.0.0/24")
    p.rules[0].destinations.append("Any")
    script, report, text = _convert(p)
    # A service and an address of the same name cannot both exist on Check Point.
    assert script.objects["web"]["kind"] == "host" and script.objects["web_2"]["kind"] == "service-group"
    assert script.objects["web_2"]["members"] == ["web_2-tcp80", "web_2-tcp443"]
    assert report.item("service", "web").emitted_as == ["web_2"]
    assert script.objects["dns"]["members"] == ["dns-udp53", "dns-tcp53"]
    rule = script.rules()[0]
    assert rule["source"] == ["lan", "n-10.9.0.0_24", "h-10.9.1.1", "r-10.9.2.1-10.9.2.9", "All-IPv4"]
    assert script.objects["All-IPv4"]["ip-address-last"] == "255.255.255.255"  # no network object of length 0
    assert rule["destination"] == [".www.example.com", "Any_2"]  # a domain object carries the domain's name
    assert script.objects[".www.example.com"]["is-sub-domain"] == "false"
    assert rule["service"] == ["web_2", "dns"]
    assert "DOMAIN_OBJECTS" in [note.code for note in report.notes]


def test_prefix_and_predefined_zones() -> None:
    p = _policy(Rule("r", src_zones=["InternalZone"], dst_zones=["dmz zone"], sources=["lan"], destinations=["web"],
                     services=["https"], applications=["ssh"]))  # fmt: skip
    p.rules[0].services = [ANY]
    script, report, text = _convert(p, Options(object_prefix="mig_", target_layer="Branch Policy"),
                                    existing=("Branch Policy", "InternalZone"), layer="Branch Policy")  # fmt: skip
    assert {"mig_lan", "mig_web", "mig_app-ssh", "mig_https"} <= set(script.objects)
    assert "\nzone dmz_zone\n" in text and "\nzone InternalZone" not in text
    assert "'dmz zone' to 'dmz_zone'" in [n.message for n in report.notes if n.code == "ZONE_RENAMED"][0]
    layer = "Branch_Policy_InternalZone_to_dmz_zone"
    assert script.names("access-layer") == [layer]
    assert script.rule("InternalZone to dmz_zone")["inline-layer"] == layer
    assert script.rule("r", layer)["service"] == ["mig_app-ssh"]
    assert "OBJECT_PREFIX" in [n.code for n in report.notes] and "NAME_COLLISIONS" not in [n.code for n in report.notes]


def test_rule_that_cannot_be_enforced_is_written_disabled() -> None:
    blocked = Rule("blocked", sources=["lan"], users=["corp\\admins"], action=Action.DENY)
    apps = Rule("apps", applications=["bittorrent"], action=Action.DROP)
    timed = Rule("timed", sources=["lan"], schedule="nights")
    negated = Rule("negated", negate_service=True)
    reset = Rule("reset", sources=["lan"], services=["https"], action=Action.RESET_BOTH)
    script, report, _ = _convert(_policy(blocked, apps, timed, negated, reset))
    for name in ("blocked", "apps", "timed", "negated"):
        assert script.rule(name)["enabled"] == "false" and report.item("rule", name).disabled
        assert str(script.rule(name)["comments"]).startswith("FWSHIFT: disabled by the converter")
    assert "NOT enforced" in report.item("rule", "blocked").findings[0].message
    assert script.rule("reset")["action"] == "Reject" and report.item("rule", "reset").status == "exact"
    assert script.rule("blocked")["action"] == "Drop"


def test_intrazone_and_interzone_rules() -> None:
    inside = Rule("inside", src_zones=["a"], scope=RuleScope.INTRAZONE, action=Action.DROP)
    between = Rule("between", src_zones=["a", "b"], dst_zones=["a", "b"], sources=["lan"], scope=RuleScope.INTERZONE)
    nowhere = Rule("nowhere", src_zones=["a"], dst_zones=["a"], scope=RuleScope.INTERZONE)
    p = _policy(inside, between, nowhere)
    p.default_intrazone = Action.ALLOW
    p.zones = {"a": Zone("a"), "b": Zone("b"), "c": Zone("c")}
    script, report, _ = _convert(p)
    assert sorted(script.names("access-layer")) == ["Network_a_to_a", "Network_a_to_b", "Network_b_to_a",
                                                    "Network_b_to_b", "Network_c_to_c"]  # fmt: skip
    assert [r["name"] for r in script.rules("Network_a_to_a")] == ["inside"]  # it matches all of it: no cleanup
    assert [(r["name"], r["action"]) for r in script.rules("Network_b_to_b")] == [("FWShift cleanup", "Accept")]
    assert [(r["name"], r["action"]) for r in script.rules("Network_a_to_b")] == [("between", "Accept"),
                                                                                  ("FWShift cleanup", "Drop")]  # fmt: skip
    assert report.item("rule", "nowhere").skipped and report.item("rule", "nowhere").status == "skipped"
    assert report.item("rule", "between").emitted_as == ["layer Network_a_to_b", "layer Network_b_to_a"]
    merged, target = Report(), Options(zone_map={"b": "a"})
    text = cli.convert(p, "checkpoint", merged, target)
    assert "INTRAZONE_ALLOW_MERGED" in [note.code for note in merged.notes]
    assert "Network_a_to_a position bottom name 'FWShift cleanup' action Accept" not in text


def test_source_default_allow_is_not_carried_over() -> None:
    p = _policy(Rule("one", sources=["lan"], action=Action.DROP))
    p.default_interzone = Action.ALLOW
    script, report, _ = _convert(p)
    assert script.rules()[-1]["action"] == "Drop"
    assert "INTERZONE_DEFAULT" in [note.code for note in report.notes]


def _nat(name: str, **fields: Any) -> NatRule:
    nat = NatRule(name, **fields)
    nat.origin = name
    return nat


def test_nat_rules() -> None:
    p = _policy()
    p.addresses["inside"] = Address("inside", AddressKind.NETWORK, "10.0.0.25/32")
    p.addresses["pool"] = Address("pool", AddressKind.RANGE, "203.0.113.20-203.0.113.29")
    p.nat_rules = [
        _nat("forward", src_zones=["untrust"], dst_zones=["untrust"], destinations=["pub"], service="https",
             destination_translation=DestNat("web", "8443")),
        _nat("static", sources=["inside"], dst_zones=["untrust"],
             source_translation=SourceNat(SnatKind.STATIC, ["pub"], bidirectional=True)),
        _nat("hide", sources=["lan", "10.2.0.0/16"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["203.0.113.9"])),
        _nat("egress", sources=["lan"], source_translation=SourceNat(SnatKind.INTERFACE, interface="ethernet1/1")),
        _nat("known", sources=["lan"], enabled=False,
             source_translation=SourceNat(SnatKind.INTERFACE, interface="wan1", interface_address="198.51.100.2")),
        _nat("pooled", sources=["lan"], source_translation=SourceNat(SnatKind.DYNAMIC_PORT, ["pool"])),
        _nat("dynamic", sources=["lan"], source_translation=SourceNat(SnatKind.DYNAMIC, ["pool"])),
        _nat("listed", destinations=["pub"], service="web", destination_translation=DestNat("web")),
        _nat("exempt", sources=["lan"], destinations=["web"]),
    ]  # fmt: skip
    script, report, text = _convert(p, existing=("Network",))
    by_comment = {str(rule["comments"]): rule for rule in script.nat}
    forward = by_comment["forward"]
    assert forward["original-destination"] == "pub" and forward["translated-destination"] == "web"
    assert forward["original-service"] == "https" and forward["translated-service"] == "tcp-8443"
    assert script.objects["tcp-8443"]["port"] == "8443" and forward["package"] == "Standard"
    assert [f.severity.name for f in report.item("nat", "forward").findings] == ["APPROX", "APPROX"]
    assert by_comment["static"]["translated-source"] == "pub" and by_comment["static"]["method"] == "static"
    assert by_comment["static (inbound)"]["translated-destination"] == "inside"
    zones = [f for f in report.item("nat", "static").findings if f.code == "NAT_ZONES"]
    assert zones[0].severity.name == "REVIEW" and "every other zone" in zones[0].message
    hide = by_comment["hide"]
    assert hide["method"] == "hide" and hide["translated-source"] == "h-203.0.113.9"
    assert script.objects[str(hide["original-source"])]["members"] == ["lan", "n-10.2.0.0_16"]  # one object per cell
    assert by_comment["known"]["translated-source"] == "h-198.51.100.2" and by_comment["known"]["enabled"] == "false"
    assert report.item("nat", "known").status == "approximated"
    assert "method" in by_comment["exempt"] and "translated-source" not in by_comment["exempt"]
    for name, why in (("egress", "--target-gateway"), ("pooled", "one address"), ("dynamic", "no Check Point equivalent"),
                      ("listed", "single protocol and port")):  # fmt: skip
        item = report.item("nat", name)
        assert item.skipped and why in item.findings[0].message, name
    assert "NAT_MANUAL_RULES" in [note.code for note in report.notes]
    script, report, _ = _convert(p, Options(target_gateway="gw-1", target_package="Branch"), existing=("Network", "gw-1"))
    egress = [rule for rule in script.nat if rule["comments"] == "egress"][0]
    assert egress["translated-source"] == "gw-1" and egress["method"] == "hide" and egress["package"] == "Branch"


def test_cli_options(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["convert", str(DATA / "panos_sample.xml"), "--to", "checkpoint", "-q", "--target-layer", "Branch",
            "--target-package", "Branch_Pkg", "--target-gateway", "gw-1", "--target-prefix", "m_"]  # fmt: skip
    assert cli.main(args) == 0
    out = capsys.readouterr().out
    script = CheckPointScript(out, existing=("Branch", "gw-1"), layer="Branch")
    assert script.nat and all(rule["package"] == "Branch_Pkg" for rule in script.nat)
    assert any(rule.get("translated-source") == "gw-1" for rule in script.nat)
    assert "m_lan-net" in script.objects and "Branch_trust_to_untrust" in script.layers
    assert cli.main(["convert", str(DATA / "checkpoint_sample.json"), "--to", "panos", "-q", "--target-nat-zone", "untrust"]) == 0
    assert "nat rules nat-1 to untrust" in capsys.readouterr().out


def test_every_sample_converts_to_a_script_that_replays() -> None:
    for name in ("panos_sample.xml", "fortios_sample.conf", "iptables_sample.rules"):
        text, report = run(name, "checkpoint")
        script = CheckPointScript(text)
        assert script.rules(), name
        assert emit_checkpoint.HEADER.splitlines()[0] == text.splitlines()[0]
        assert report.needs_review  # a script for a management server is never "just run it"


# -- found in review ----------------------------------------------------------------------


def test_objects_that_only_look_like_hosts() -> None:
    x = _simple()
    x.add("mask", "wildcard", ipv4_address="10.0.3.0", ipv4_mask_wildcard="0.255.0.255")
    x.add("odd", "some-new-type", ipv4_address="10.0.4.1")
    x.add("typeless", "service-icmp")  # as below details-level full: no icmp-type
    x.add("checked", "service-tcp", port="443", match_by_protocol_signature=True)
    x.add("both", "service-group", members=[x.objects["checked"], x.objects["web"]])
    x.rule("Network", "wild", ["Any"], ["mask"], ["web"], "Drop")
    x.rule("Network", "new", ["odd"], ["srv"], ["web"])
    x.rule("Network", "icmp", ["lan"], ["srv"], ["typeless"])
    x.rule("Network", "signed", ["lan"], ["srv"], ["both"])
    policy, report = x.parse()
    assert policy.addresses["mask"].kind == AddressKind.UNSUPPORTED  # never the one address it also carries
    assert policy.addresses["odd"].kind == AddressKind.UNSUPPORTED
    assert policy.services["typeless"].unsupported and not policy.services["typeless"].entries  # never "all ICMP"
    assert report.item("service", "checked").status == "approximated"
    assert [f.code for f in report.item("rule", "signed").findings] == ["PROTOCOL_SIGNATURE"]
    out = Report()
    cli.convert(policy, "fortios", out)
    assert [out.item("rule", name).disabled for name in ("wild", "new", "icmp", "signed")] == [True, True, True, False]
    assert "NOT enforced" in out.item("rule", "wild").findings[-1].message


def test_rule_fields_that_narrow_a_rule_are_not_ignored() -> None:
    x = _simple()
    x.rule("Network", "portal", ["lan"], ["srv"], ["web"], action_settings={"enable-identity-captive-portal": True})
    x.rule("Network", "plain", ["lan"], ["srv"], ["web"], action_settings={"enable-identity-captive-portal": False},
           custom_fields={"field-1": "x"}, meta_info={"creator": "admin"}, hits={"value": 7})  # fmt: skip
    x.rule("Network", "resource", ["lan"], ["srv"], ["web"], service_resource="uri-filter")
    x.rule("Network", "future", ["lan"], ["srv"], ["web"], data_center=["dc-1"], something_empty=[])
    policy, report = x.parse()
    portal, plain, resource, future = policy.rules
    assert "captive portal" in portal.unsupported[0] and not plain.unsupported
    assert resource.unsupported == ["service resource uri-filter"]
    # As with FortiOS attributes: reported for a person to check, the rule stays as it was read.
    assert not future.unsupported
    (found,) = report.item("rule", "future").findings
    assert found.code == "UNKNOWN_ATTRIBUTES" and found.severity.name == "REVIEW" and "data-center" in found.message
    assert not report.item("rule", "plain").findings


def test_rule_type_with_zone_any_and_zones_the_policy_does_not_name() -> None:
    # As read from a Panorama device group: the zones of the firewalls are not in the input.
    named = Rule("t2u", src_zones=["trust"], dst_zones=["untrust"], sources=["lan"])
    deny = Rule("deny-interzone", scope=RuleScope.INTERZONE, action=Action.DENY)
    inside = Rule("allow-intrazone", scope=RuleScope.INTRAZONE, services=["https"])
    https = Rule("allow-https", services=["https"])
    p = _policy(named, deny, inside, https)
    script, report, _ = _convert(p)
    for name in ("deny-interzone", "allow-intrazone"):
        assert [f.code for f in report.item("rule", name).findings] == ["RULE_TYPE_ANY_ZONE"]
        assert report.item("rule", name).status == "needs-review"

    def allowed(src: str, dst: str, port: int = 443) -> bool:
        return script_allows(script, Packet(src, dst, "10.1.0.1", "10.9.9.9", "tcp", 40000, port))

    assert allowed("trust", "untrust", 80) and not allowed("untrust", "trust")  # the interzone deny, between named zones
    assert allowed("trust", "trust") and allowed("untrust", "untrust")  # inside a named zone
    # Two zones no rule names: nothing tells whether they are one. The deny holds, the allow does not.
    assert not allowed("dmz1", "dmz2") and not allowed("dmz1", "dmz1")
    assert not allowed("dmz1", "trust") and not allowed("trust", "dmz1")


def test_words_that_mgmt_cli_or_the_shell_could_misread() -> None:
    rule = Rule("-r true", src_zones=["-s other.sid"], dst_zones=["dmz\ntouch /tmp/x #"], sources=["lan"],
                destinations=["web"], description="--version")  # fmt: skip
    script, report, text = _convert(_policy(rule))
    assert script.rules("Network_x-s_other.sid_to_dmz_touch__tmp_x__")[0]["name"] == "_r true"
    assert script.rules("Network_x-s_other.sid_to_dmz_touch__tmp_x__")[0]["comments"] == "_version"
    words = [word for call in script.calls for word in call]
    assert not any(word.startswith("-") for word in words)  # no value can pass for a switch
    assert all(line.startswith(("m add ", "zone ", "#", "echo ")) or not line for line in text.split("#!/bin/sh")[1].split("}\n")[-1].splitlines())
    assert "ZONE_RENAMED" in [note.code for note in report.notes]
    for option in ("target_layer", "target_package", "target_gateway"):
        with pytest.raises(FwshiftError, match="control characters are not allowed"):
            cli.convert(_policy(rule), "checkpoint", Report(), Options(**{option: "x\nrm -rf /"}))
        with pytest.raises(FwshiftError, match="not a name mgmt_cli can be given"):
            cli.convert(_policy(rule), "checkpoint", Report(), Options(**{option: "-d other"}))
    with pytest.raises(FwshiftError, match="--target-prefix"):
        cli.convert(_policy(rule), "checkpoint", Report(), Options(object_prefix="a b"))


def test_one_object_for_an_address_however_it_is_written() -> None:
    rule = Rule("r", sources=["10.20.0.10/32", "10.20.0.10", "10.20.0.10-10.20.0.10", "10.1.0.0/16"])
    script, _, _ = _convert(_policy(rule))
    assert script.rules()[0]["source"] == ["h-10.20.0.10", "lan"]  # "lan" is that network already
    assert script.names("host").count("h-10.20.0.10") == 1


def test_prefix_does_not_add_items_to_the_report() -> None:
    plain, prefixed = Report(), Report()
    policy, _ = load("fortios_sample.conf")
    cli.convert(policy, "checkpoint", plain)
    policy, _ = load("fortios_sample.conf")
    text = cli.convert(policy, "checkpoint", prefixed, Options(object_prefix="m_"))
    for kind in ("address", "address-group", "service", "service-group"):
        assert prefixed.counts(kind)["total"] == plain.counts(kind)["total"] == len(getattr(policy, {
            "address": "addresses", "address-group": "address_groups", "service": "services",
            "service-group": "service_groups"}[kind])), kind  # fmt: skip
    assert prefixed.item("address", "10.99.0.0/16").emitted_as == ["m_10.99.0.0_16"]
    assert "add network name m_10.99.0.0_16 " in text
    assert prefixed.item("service-group", "Web Access").emitted_as == ["m_Web_Access"]


def test_export_with_the_wrong_types_is_a_clean_error_or_a_flagged_rule() -> None:
    x = _simple()
    x.rule("Network", "r", ["lan"], ["srv"], ["web"])
    good = x.responses()[0]

    def parse(**changes: Any) -> Policy:
        return parse_checkpoint.parse(json.dumps({**good, **changes}).encode(), Report())

    without = parse(**{"objects-dictionary": 5})  # no object can be looked up: nothing is "any"
    assert len(without.rules) == 1 and without.rules[0].sources != [ANY] and without.rules[0].services != [ANY]
    assert all(a.kind == AddressKind.UNSUPPORTED for a in without.addresses.values())
    assert len(parse(uid=["x"]).rules) == 1 and len(parse(uid={"a": 1}).rules) == 1
    broken = [dict(o) for o in good["objects-dictionary"]]
    broken += [{"uid": ["x"], "name": "list uid", "type": "host"}, {"uid": {"a": 1}}, 7, None]
    broken += [{"uid": x.uid("g"), "name": "g", "type": "group", "members": 5},
               {"uid": x.uid("sg"), "name": "sg", "type": "service-group", "members": "http"},
               {"uid": x.uid("edge"), "name": "edge", "type": "host", "ipv4-address": "255.255.255.250",
                "nat-settings": {"auto-rule": True, "method": "static", "ipv4-address": "999.1.1.1"}},
               {"uid": x.uid("six"), "name": "six", "type": "network", "subnet6": "2001:db8::", "mask-length6": 64,
                "nat-settings": {"auto-rule": True, "method": "static", "ipv4-address": "203.0.113.1"}},
               {"uid": x.uid("top"), "name": "top", "type": "network", "subnet4": "10.0.0.0", "mask-length4": 8,
                "nat-settings": {"auto-rule": True, "method": "static", "ipv4-address": "255.255.255.0"}}]  # fmt: skip
    rule = dict(good["rulebase"][0], source=[x.uid("g"), x.uid("edge"), x.uid("six"), x.uid("top")], service=[x.uid("sg")],
                track=7, action=["Accept"], **{"inline-layer": {"a": 1}, "install-on": 3, "time": "x", "vpn": {"y": 2}})  # fmt: skip
    policy = parse(rulebase=[rule], **{"objects-dictionary": broken})
    assert len(policy.rules) == 1 and policy.rules[0].unsupported
    report = Report()
    cli.convert(policy, "panos", report)
    assert report.item("rule", policy.rules[0].origin).disabled
    for data in (b"[" * 100000, b'{"a":' * 3000 + b"1" + b"}" * 3000, b'{"rulebase": {"x": 1}}', b'{"rulebase": [[[]]]}'):
        try:
            assert parse_checkpoint.parse(data, Report()).rules == []
        except ParseError:
            pass


def test_input_without_a_rulebase_is_refused_with_the_reason() -> None:
    # Object listings alone ('show objects', 'show access-layers'): nothing to convert, not a policy of zero rules.
    objects_only = {"objects": [{"uid": "h1", "name": "web", "type": "host", "ipv4-address": "10.0.0.1"}], "total": 1}
    with pytest.raises(ParseError, match="no rulebase found.*top-level keys are 'objects', 'total'"):
        parse_checkpoint.parse(json.dumps(objects_only).encode(), Report())
    # A hand-written layout: rules in 'rules' lists that name their objects.
    invented = {
        "policy-package": {"name": "P"},
        "objects": {"networks": [{"name": "LAN", "subnet": "10.0.0.0", "mask-length": 8}]},
        "access-layers": [{"name": "Network", "sections": [{"name": "S", "rules": [
            {"name": "r", "source": ["LAN"], "destination": ["Any"], "service": ["https"], "action": "Accept"}]}]}],
        "nat-rules": [],
    }  # fmt: skip
    with pytest.raises(ParseError, match="no rulebase found.*'rules' lists that name their objects.*mgmt_cli"):
        parse_checkpoint.parse(json.dumps(invented).encode(), Report())


def test_perimeter_export_is_read_in_full() -> None:
    # checkpoint_perimeter.json: a hand-written 'R81.20 style' policy, reshaped into real Management API output.
    from fwshift import audit

    policy, report = load("checkpoint_perimeter.json")
    assert policy.scope == "Network"
    assert len(policy.rules) == 23 and len(policy.nat_rules) == 5
    assert policy.rules[0].name == "Drop Blacklisted IPs" and policy.rules[-1].name == "Cleanup rule"
    assert policy.rules[0].action == policy.rules[-1].action == Action.DROP
    unsupported = {item.name for item in report.items.values() if any(f.code == "UNSUPPORTED_ADDRESS" for f in item.findings)}
    assert unsupported == {"threat-intel-feed", "o365-endpoints", "azure-ip-ranges"}  # network feed, updatable objects
    hide = policy.nat_rules[0]
    assert hide.name == "Hide NAT Internal" and hide.source_translation.kind == SnatKind.INTERFACE
    web = policy.nat_rules[2]
    assert web.destination_translation is not None and web.destination_translation.address == "Web_LB_VIP"
    # The no-NAT rule for the VPN pool sits below the hide rule for 10.0.0.0/8, which takes the pool too.
    found = [(f.check, f.name) for f in audit.run(policy).before if f.kind == "nat"]
    assert ("SHADOWED_NAT", "No NAT for VPN") in found


def test_nat_only_export_does_not_claim_a_layer_was_read() -> None:
    nat_only = {"rulebase": [], "from": 0, "to": 0, "total": 0}
    report = Report()
    policy = parse_checkpoint.parse(json.dumps(nat_only).encode(), report)
    assert policy.rules == [] and policy.scope == ""
    implied = [note for note in report.notes if note.code == "IMPLIED_RULES"]
    assert implied and "no access layer was read" in implied[0].message and "one layer" not in implied[0].message


def test_inline_layers_that_multiply_are_refused_quickly() -> None:
    x = Export()
    x.layer("L0")
    for level in range(8):
        x.layer(f"L{level + 1}")
        for index in range(12):
            x.rule(f"L{level}", f"r{index}", ["Any"], ["Any"], ["Any"], "Inner Layer", inline_layer=f"L{level + 1}")
    x.rule("L8", "leaf", ["Any"], ["Any"], ["Any"])
    with pytest.raises(ParseError, match="more than 50000 rules"):
        x.parse(layer="L0")
    # A layer that applies itself, directly or through another one, is not followed.
    y = _simple()
    y.layer("A")
    y.rule("Network", "in", ["lan"], ["Any"], ["Any"], "Inner Layer", inline_layer="A")
    y.rule("A", "again", ["Any"], ["srv"], ["Any"], "Inner Layer", inline_layer="A")
    policy, _ = y.parse(layer="Network")
    assert any("applied from inside itself" in text for rule in policy.rules for text in rule.unsupported)


def test_automatic_nat_objects_in_nat_rules() -> None:
    x = _simple()
    x.add("web-1", "host", ipv4_address="10.20.0.10",
          nat_settings={"auto-rule": True, "method": "static", "ipv4-address": "203.0.113.10"})  # fmt: skip
    x.add("other", "host", ipv4_address="10.20.0.11")
    x.add("servers", "group", members=[x.objects["web-1"], x.objects["srv"]])
    x.rule("Network", "r", ["lan"], ["servers"], ["web"])

    def nat(source: str, destination: str, translated_destination: str = "Original", automatic: bool = False) -> None:
        x.nat.append({"uid": x.uid(f"n{len(x.nat)}"), "type": "nat-rule", "method": "static", "auto-generated": automatic,
                      "original-source": x.uid(source), "original-destination": x.uid(destination),
                      "original-service": x.uid("Any"), "translated-source": x.uid("Original"),
                      "translated-destination": x.uid(translated_destination), "translated-service": x.uid("Original")})  # fmt: skip

    nat("lan", "servers")  # manual, through a group
    nat("lan", "web-1")  # manual, the object itself
    nat("Any", "other", "web-1", automatic=True)  # an automatic rule that names two objects
    policy, report = x.parse()
    grouped, direct, mismatched = policy.nat_rules
    assert grouped.destinations == ["servers"] and direct.destinations == ["web-1"]
    assert [f.code for f in report.item("nat", grouped.origin).findings] == ["AUTOMATIC_NAT_IN_GROUP"]
    assert report.item("nat", grouped.origin).status == "needs-review" and not report.item("nat", direct.origin).findings
    assert "AUTOMATIC_NAT_SHAPE" in [f.code for f in report.item("nat", mismatched.origin).findings]
    assert mismatched.unsupported  # "other" has no automatic NAT to read the address from


def test_what_a_gateway_or_signature_loses_depends_on_negation_and_action() -> None:
    x = _simple()
    x.add("fw-1", "simple-gateway", ipv4_address="192.0.2.1")
    x.add("http-sig", "service-tcp", port="80", match_by_protocol_signature=True)
    x.rule("Network", "to gw", ["lan"], ["fw-1"], ["web"])
    x.rule("Network", "not gw", ["lan"], ["fw-1"], ["web"], destination_negate=True)
    x.rule("Network", "drop gw", ["lan"], ["fw-1"], ["web"], "Drop")
    x.rule("Network", "drop not gw", ["lan"], ["fw-1"], ["web"], "Drop", destination_negate=True)
    x.rule("Network", "allow http", ["lan"], ["srv"], ["http-sig"])
    x.rule("Network", "drop not http", ["lan"], ["srv"], ["http-sig"], "Drop", service_negate=True)
    _, report = x.parse()

    def finding(rule: str) -> "tuple[str, str]":
        (found,) = report.item("rule", rule).findings
        return found.severity.name, found.message

    assert finding("to gw")[0] == "APPROX" and "no longer applies to its other addresses" in finding("to gw")[1]
    assert finding("not gw")[0] == "REVIEW" and "more traffic gets through" in finding("not gw")[1]
    assert finding("drop gw")[0] == "REVIEW" and "more traffic gets through" in finding("drop gw")[1]
    assert finding("drop not gw")[0] == "APPROX"
    assert finding("allow http")[0] == "APPROX"
    assert finding("drop not http")[0] == "REVIEW" and "outside this rule" in finding("drop not http")[1]


def test_port_that_only_looks_like_a_number() -> None:
    x = _simple()
    x.add("odd", "service-tcp", port=">\u00b2")
    x.add("arabic", "service-udp", port="\u0668\u0660")
    x.rule("Network", "r", ["lan"], ["srv"], ["odd", "arabic"])
    policy, report = x.parse()  # a finding on the service, not the end of the whole file
    assert policy.services["odd"].unsupported and policy.services["arabic"].unsupported
    assert report.item("service", "odd").status == "needs-review"


def test_export_with_pages_missing_says_so() -> None:
    x = _simple()
    x.rule("Network", "one", ["lan"], ["srv"], ["web"])
    x.rule("Network", "two", ["Any"], ["Any"], ["Any"], "Drop")
    page = dict(x.responses()[0])
    page.update({"rulebase": x.layers["Network"][:1], "from": 1, "to": 1, "total": 2})
    report = Report()
    policy = parse_checkpoint.parse(json.dumps([page]).encode(), report)
    assert len(policy.rules) == 1
    (note,) = [n for n in report.notes if n.code == "INCOMPLETE_EXPORT"]
    assert note.severity.name == "REVIEW" and "layer 'Network' (1 of 2 rules)" in note.message
    complete = Report()
    parse_checkpoint.parse(json.dumps(x.responses()).encode(), complete)
    assert "INCOMPLETE_EXPORT" not in [n.code for n in complete.notes]
    # A page that is in the input twice counts once.
    twice = Report()
    assert len(parse_checkpoint.parse(json.dumps(x.responses() + x.responses()).encode(), twice).rules) == 2
    # An empty NAT rulebase is a NAT rulebase.
    empty = {"uid": x.uid("nat"), "rulebase": [], "from": 0, "to": 0, "total": 0}
    with_nat = Report()
    parse_checkpoint.parse(json.dumps(x.responses() + [empty]).encode(), with_nat)
    assert "NO_NAT_RULEBASE" not in [n.code for n in with_nat.notes]


def test_true_and_false_of_the_wrong_json_type() -> None:
    x = _simple()
    x.rule("Network", "text false", ["lan"], ["srv"], ["web"], enabled="false", source_negate="false")
    x.rule("Network", "text true", ["lan"], ["srv"], ["web"], enabled="True", source_negate="TRUE")
    x.rule("Network", "number", ["lan"], ["srv"], ["web"], enabled=0)
    x.rule("Network", "odd negate", ["lan"], ["srv"], ["web"], destination_negate="yes")
    policy, _ = x.parse()
    off, on, number, odd = policy.rules
    assert not off.enabled and not off.negate_source and not off.unsupported
    assert on.enabled and on.negate_source and not on.unsupported
    assert number.unsupported == ["field 'enabled' that is neither true nor false"]  # not guessed either way
    assert odd.unsupported == ["field 'destination-negate' that is neither true nor false"]


def test_rule_of_an_inline_layer_leaves_no_second_report_item() -> None:
    x = _simple()
    x.layer("Inner")
    x.rule("Network", "parent", ["lan"], ["Any"], ["Any"], "Inner Layer", inline_layer="Inner")
    x.rule("Inner", "chi\tld", ["Any"], ["srv"], ["web"], install_on=[])
    x.objects["gw"] = {"uid": x.uid("gw"), "name": "gw", "type": "simple-gateway", "ipv4-address": "192.0.2.1"}
    x.layers["Inner"][0]["destination"] = [x.uid("gw")]  # gives the rule a finding while it is read
    x.rule("Inner", "rest", ["Any"], ["Any"], ["Any"], "Drop")
    policy, report = x.parse()
    cli.convert(policy, "panos", report)
    assert report.counts("rule")["total"] == len(policy.rules) == 2
    assert [item.name for item in report.items.values() if item.kind == "rule"] == ["parent / chi_ld", "parent / rest"]
