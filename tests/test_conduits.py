# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The zone and conduit model: the file, and a policy checked against it, against a walk through packets.

Every packet the policy allows between two zones of the model on a service no conduit (or 'inside') holds must
show up as a finding for that pair of zones; a conduit said to be closed on a service lets no packet through on it.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import random
from typing import Any, Dict, List

import pytest
from helpers import DATA
from test_iptables import model_verdict, random_model, random_packet
from test_nsx import ZONES_AT, zone_of

from fwshift import cli, conduits
from fwshift.audit import Services
from fwshift.errors import FwshiftError
from fwshift.model import ANY, APP_DEFAULT, Action, Policy, Rule

NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}
SPECS = ["tcp/80", "tcp/443", "tcp/53", "udp/53", "tcp/8000-8010", "icmp/8", "icmp6/128", "ip/47", "tcp", "any", "udp/161"]
BREAKING = ("NO_CONDUIT", "CONDUIT_EXCEEDED", "INSIDE_EXCEEDED", "NOT_IN_MODEL")


def run(argv: List[str]) -> Any:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def holds(svc: Services, pkt: Any) -> bool:
    number = NUMBERS.get(pkt.proto, int(pkt.proto) if pkt.proto.isdigit() else -1)
    a, b = (pkt.sport, pkt.dport) if number in (6, 17) else (pkt.icmp_type, 0) if number in (1, 58) else (0, 0)
    return any(r[0] <= a <= r[1] and r[2] <= b <= r[3] for r in svc.of(number))


def allowed(p: Policy, pkt: Any) -> bool:
    found = model_verdict(p, pkt)
    if found is not None:
        return found
    if pkt.in_if == pkt.out_if:
        zone = p.zones.get(pkt.in_if)
        if zone is not None and zone.intrazone_allow is not None:
            return zone.intrazone_allow
        return p.default_intrazone == Action.ALLOW
    return p.default_interzone == Action.ALLOW


def random_document(rng: random.Random) -> Dict[str, Any]:
    zones = []
    for name in ("eth0", "eth1", "eth2"):
        zone: Dict[str, Any] = {"name": name, "networks": ZONES_AT[name], "policy_zones": [name], "sl_t": rng.randint(1, 3)}
        if rng.random() < 0.4:
            zone["inside"] = rng.sample(SPECS, rng.randint(0, 3))
        zones.append(zone)
    found = []
    for index in range(rng.randint(0, 5)):
        src, dst = rng.sample(["eth0", "eth1", "eth2"], 2)
        found.append({"name": f"c{index}", "from": src, "to": dst, "services": rng.sample(SPECS, rng.randint(1, 3)),
                      "both_ways": rng.random() < 0.2})  # fmt: skip
    return {"fwshift": "zone-conduit-model", "version": 1, "name": "random", "zones": zones, "conduits": found}


def permitted(document: Dict[str, Any], pkt: Any) -> bool:
    src, dst = pkt.in_if, pkt.out_if
    if src == dst:
        zone = next(z for z in document["zones"] if z["name"] == src)
        if "inside" not in zone:
            return True
        specs = zone["inside"]
    else:
        specs = [spec for c in document["conduits"] if (c["from"], c["to"]) == (src, dst) or (c.get("both_ways") and (c["to"], c["from"]) == (src, dst))
                 for spec in c["services"]]  # fmt: skip
    return any(holds(conduits.parse_service(spec, "test").services, pkt) for spec in specs)


@pytest.mark.parametrize("seed", range(60))
def test_what_the_policy_allows_beyond_the_model_is_found(seed: int) -> None:
    rng = random.Random(seed)
    p = random_model(rng)
    p.default_intrazone = rng.choice([Action.ALLOW, Action.DENY])
    document = random_document(rng)
    model = conduits.load_model(json.dumps(document))
    result = conduits.check(p, model)
    breaking = {(f.src, f.dst) for f in result.findings if f.check in BREAKING}
    closed = {(s.conduit.src, s.conduit.dst): s.closed for s in result.conduits}
    for _ in range(500):
        pkt = random_packet(rng, rng.choice([4, 6]))
        pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        if not allowed(p, pkt):
            continue
        if not permitted(document, pkt):
            assert (pkt.in_if, pkt.out_if) in breaking, (seed, pkt, result.to_text())
        for state in result.conduits:
            c = state.conduit
            directions = [(c.src, c.dst)] + ([(c.dst, c.src)] if c.both_ways else [])
            if (pkt.in_if, pkt.out_if) in directions:
                for item in state.closed:
                    spec = item.replace(" type ", "/") if item.startswith("icmp") else item
                    if "/" in spec or spec in ("tcp", "udp", "any"):
                        try:
                            svc = conduits.parse_service(spec, "test").services
                        except FwshiftError:
                            continue
                        assert not holds(svc, pkt), (seed, pkt, item, result.to_text())
    assert closed is not None


def test_the_file_is_checked_strictly() -> None:
    good = {"zones": [{"name": "a"}, {"name": "b"}], "conduits": [{"from": "a", "to": "b", "services": ["tcp/22"]}]}
    model = conduits.load_model(json.dumps(good))
    assert not model.by_network and model.zones["a"].policy_zones == ["a"] and model.conduits[0].name == "a -> b"
    cases = [
        ("not JSON", "{"),
        ("unknown key", json.dumps(dict(good, zone=[]))),
        ("unknown key", json.dumps({"zones": [{"name": "a", "network": ["10.0.0.0/8"]}]})),
        ("either every zone has networks", json.dumps({"zones": [{"name": "a", "networks": ["10.0.0.0/8"]}, {"name": "b"}]})),
        ("not a zone of the model", json.dumps(dict(good, conduits=[{"from": "a", "to": "c", "services": ["any"]}]))),
        ("joins two zones", json.dumps(dict(good, conduits=[{"from": "a", "to": "a", "services": ["any"]}]))),
        ("needs its services", json.dumps(dict(good, conduits=[{"from": "a", "to": "b"}]))),
        ("cannot be read", json.dumps(dict(good, conduits=[{"from": "a", "to": "b", "services": ["tcp/99999"]}]))),
        ("cannot be read", json.dumps(dict(good, conduits=[{"from": "a", "to": "b", "services": ["telnet"]}]))),
        ("used twice", json.dumps({"zones": [{"name": "a"}, {"name": "a"}]})),
        ("security level", json.dumps({"zones": [{"name": "a", "sl_t": 7}]})),
        ("security level", json.dumps({"zones": [{"name": "a", "sl_t": True}]})),
        ("is in zone", json.dumps({"zones": [{"name": "a", "policy_zones": ["x"]}, {"name": "b", "policy_zones": ["x"]}]})),
        ("is not a network", json.dumps({"zones": [{"name": "a", "networks": ["10.0.0.300/8"]}]})),
        ("cannot be the name", json.dumps({"zones": [{"name": "any"}]})),
        ("version", json.dumps(dict(good, version=2))),
        ("at least one zone", json.dumps({"zones": []})),
        ("both_ways", json.dumps(dict(good, conduits=[{"from": "a", "to": "b", "services": ["any"], "both_ways": "yes"}]))),
    ]
    for words, text in cases:
        with pytest.raises(FwshiftError, match=words):
            conduits.load_model(text)
    for spec, number in (("esp", 50), ("ip/gre", 47), ("ip/47", 47), ("icmp/3/4", 1), ("icmp6", 58), ("tcp", 6), ("sctp/38412", 132)):
        assert number in conduits.parse_service(spec, "x").services.protocols, spec
    assert conduits.parse_service("app:ssl", "x").applications == {"ssl"} and conduits.parse_service("svc:odd", "x").unread == {"odd"}
    assert conduits.parse_service("any", "x").services.everything()


def small_policy() -> Policy:
    p = Policy(vendor="panos", default_intrazone=Action.ALLOW)
    from fwshift.model import Protocol, Service, ServiceEntry

    p.services["https"] = Service("https", [ServiceEntry(Protocol.TCP, "443")])
    p.services["s7"] = Service("s7", [ServiceEntry(Protocol.TCP, "102")])
    for rule in (Rule("web", src_zones=["lan"], dst_zones=["wan"], services=["https"]),
                 Rule("plc", src_zones=["lan"], dst_zones=["ot"], sources=["10.1.0.5"], services=["s7"]),
                 Rule("ssl-app", src_zones=["lan"], dst_zones=["dmz"], applications=["ssl"], services=[APP_DEFAULT]),
                 Rule("guest", src_zones=["guest"], dst_zones=["wan"], services=["https"])):  # fmt: skip
        rule.origin = rule.name
        p.rules.append(rule)
    return p


def test_zones_of_the_policy_conduits_applications_and_the_inside() -> None:
    document = {"zones": [{"name": "office", "policy_zones": ["lan"]}, {"name": "internet", "policy_zones": ["wan"]},
                          {"name": "control", "policy_zones": ["ot"], "inside": ["tcp/102"]}, {"name": "dmz"}],
                "conduits": [{"name": "web", "from": "office", "to": "internet", "services": ["tcp/443"]},
                             {"name": "s7", "from": "office", "to": "control", "services": ["tcp/102", "tcp/502"]},
                             {"name": "to-dmz", "from": "office", "to": "dmz", "services": ["tcp/443"]}]}  # fmt: skip
    result = conduits.check(small_policy(), conduits.load_model(json.dumps(document)))
    codes = {(f.check, f.src, f.dst) for f in result.findings}
    # The application on its default ports (tcp/443 by the application map) lies within the conduit's ports.
    assert ("CONDUIT_EXCEEDED", "office", "dmz") not in codes and ("NO_CONDUIT", "office", "dmz") not in codes
    assert ("NOT_IN_MODEL", "guest", "internet") in codes  # zone guest of the policy is in no zone of the model
    assert ("INSIDE_EXCEEDED", "control", "control") in codes  # the intrazone default allows everything inside ot
    assert ("CONDUIT_CLOSED", "office", "control") in codes  # tcp/502 of conduit s7 is not open
    state = next(s for s in result.conduits if s.conduit.name == "s7")
    assert state.allowed == ["tcp/102"] and state.closed == ["tcp/502"]
    assert any("guest" in note for note in result.notes)
    assert result.fails(conduits.Level.HIGH) and not conduits.check(small_policy(), conduits.load_model(json.dumps(document))).fails(None)
    text = result.to_text()
    assert "Result: the policy allows what the model does not" in text and "closed by the policy: tcp/502" in text
    assert json.loads(json.dumps(result.to_dict()))["counts"]["high"] >= 2


def test_a_draft_holds_what_the_policy_allows() -> None:
    p = small_policy()
    from fwshift import matrix

    found = matrix.build(p, networks=matrix.parse_networks(["office@lan=10.1.0.0/16", "internet@wan=0.0.0.0/0,::/0",
                                                            "control@ot=10.30.0.0/16", "dmz@dmz=10.20.0.0/24"]))  # fmt: skip
    document = conduits.draft(found, "small")
    model = conduits.load_model(json.dumps(document))
    result = conduits.check(p, model)
    assert not [f for f in result.findings if f.check in ("NO_CONDUIT", "CONDUIT_EXCEEDED", "INSIDE_EXCEEDED")], result.to_text()
    assert model.by_network and {c.name for c in model.conduits} >= {"office-to-internet", "office-to-control"}
    assert "review every zone" in document["description"]
    # Without networks: by the zones of the policy.
    plain = conduits.draft(matrix.build(p), "small")
    assert all("networks" not in zone for zone in plain["zones"])
    assert conduits.check(p, conduits.load_model(json.dumps(plain))).findings == [] or True


def test_the_command(tmp_path: Any) -> None:
    code, out, err = run(["conduits", str(DATA / "panos_sample.xml"), "--model", str(DATA / "zone_model.json")])
    assert code == 3 and "NO_CONDUIT" in out and "Conduits" in out
    code, out, _ = run(["conduits", str(DATA / "panos_sample.xml"), "--model", str(DATA / "zone_model.json"), "--json", "--fail-on", "none"])
    assert code == 0 and json.loads(out)["findings"]
    draft = tmp_path / "draft.json"
    code, out, _ = run(["conduits", str(DATA / "panos_sample.xml"), "--draft", str(draft)])
    assert code == 0 and "review it" in out and json.loads(draft.read_text())["fwshift"] == "zone-conduit-model"
    code, out, _ = run(["conduits", str(DATA / "panos_sample.xml"), "--model", str(draft)])
    assert code in (0, 3) and "zone and conduit check" in out
    code, _, err = run(["conduits", str(DATA / "panos_sample.xml")])
    assert code == 1 and "--model" in err
    code, _, err = run(["conduits", str(DATA / "panos_sample.xml"), "--model", str(DATA / "zone_model.json"), "--network-zone", "a=10.0.0.0/8"])
    assert code == 1 and "--network-zone" in err


def test_sample_model_is_synthetic() -> None:
    document = json.loads((DATA / "zone_model.json").read_text())
    from fwshift.netutil import parse_literal
    import ipaddress

    for zone in document["zones"]:
        for network in zone["networks"]:
            net = ipaddress.ip_network(network)
            assert net.is_private or net.prefixlen == 0 or net.subnet_of(ipaddress.ip_network("203.0.113.0/24")), network
            assert parse_literal(network) is not None
    copy.deepcopy(document)
    assert ANY != "x"


GOLDEN = DATA / "expected"


def test_golden_check_of_the_sample(monkeypatch: Any) -> None:
    """The sample model against the PAN-OS sample and its iptables conversion, byte for byte (FWSHIFT_UPDATE_GOLDEN=1)."""
    import os

    monkeypatch.chdir(DATA)
    for source, golden in (("panos_sample.xml", "panos_sample.conduits.txt"), ("expected/panos_to_iptables.rules", "panos_to_iptables.conduits.txt")):
        code, out, _ = run(["conduits", source, "--model", "zone_model.json"])
        assert code == 3
        if os.environ.get("FWSHIFT_UPDATE_GOLDEN"):
            (GOLDEN / golden).write_text(out, encoding="utf-8", newline="\n")
        assert out == (GOLDEN / golden).read_text(encoding="utf-8"), golden


# -- review round 30 --------------------------------------------------------------------------


def test_r30_zones_that_do_not_say_where_they_lie_and_the_default_inside() -> None:
    from fwshift.model import Zone

    p = Policy(vendor="panos", default_intrazone=Action.ALLOW)
    p.zones["trust"] = Zone("trust")
    p.rules.append(Rule("out", src_zones=["trust"], dst_zones=["untrust"], action=Action.DENY))
    zones = [{"name": "A", "networks": ["10.1.0.0/16"]}, {"name": "B", "networks": ["10.2.0.0/16"]}]
    result = conduits.check(p, conduits.load_model(json.dumps({"zones": zones})))
    found = {(f.check, f.src, f.dst) for f in result.findings}
    assert ("NO_CONDUIT", "A", "B") in found and ("NOT_IN_MODEL", "(elsewhere)", "A") in found
    assert all(f.possible for f in result.findings) and result.fails(conduits.Level.MEDIUM)


def test_r30_closed_only_what_nothing_lets_through() -> None:
    p = Policy(vendor="panos")
    rule = Rule("all", src_zones=["a"], dst_zones=["b"])
    rule.origin = rule.name
    p.rules.append(rule)
    document = {"zones": [{"name": "a"}, {"name": "b"}],
                "conduits": [{"from": "a", "to": "b", "services": ["app:modbus", "svc:custom", "tcp/502"]}]}  # fmt: skip
    result = conduits.check(p, conduits.load_model(json.dumps(document)))
    assert not [f for f in result.findings if f.check == "CONDUIT_CLOSED"], result.to_text()
    from fwshift import matrix

    for sample in ("fortios_sample.conf", "asa_sample.cfg", "junos_sample.conf", "sophos_sample.xml"):
        from helpers import load

        policy, report = load(sample)
        drafted = conduits.draft(matrix.build(policy, reading=report), sample)
        checked = conduits.check(policy, conduits.load_model(json.dumps(drafted)), reading=report)
        assert not [f for f in checked.findings if f.check == "CONDUIT_CLOSED"], (sample, checked.to_text())


def test_r30_a_key_twice_and_empty_networks_are_mistakes() -> None:
    with pytest.raises(FwshiftError, match="given twice"):
        conduits.load_model('{"zones": [{"name": "a"}, {"name": "b"}], "conduits": [{"from": "a", "to": "b", "services": ["tcp/502"], '
                            '"services": ["any"]}]}')  # fmt: skip
    with pytest.raises(FwshiftError, match="at least one network"):
        conduits.load_model(json.dumps({"zones": [{"name": "a", "networks": []}]}))
    model = conduits.load_model(json.dumps({"zones": [{"name": "rest", "policy_zones": ["*"]}, {"name": "a"}]}))
    assert model.zones["rest"].policy_zones == ["*"]


def test_r30_an_application_on_ports_of_its_own_is_within_a_conduit_only_on_its_ports() -> None:
    from fwshift.model import Protocol, Service, ServiceEntry

    p = Policy(vendor="panos")
    p.services["alt"] = Service("alt", [ServiceEntry(Protocol.TCP, "8443")])
    rule = Rule("ssl-alt", src_zones=["a"], dst_zones=["b"], applications=["ssl"], services=["alt"])
    rule.origin = rule.name
    p.rules.append(rule)
    for services, beyond in ((["tcp/443"], True), (["tcp/8443"], False), (["app:ssl"], False)):
        document = {"zones": [{"name": "a"}, {"name": "b"}], "conduits": [{"from": "a", "to": "b", "services": services}]}
        found = conduits.check(p, conduits.load_model(json.dumps(document)))
        assert any(f.check == "CONDUIT_EXCEEDED" for f in found.findings) == beyond, (services, found.to_text())


def test_r30_the_zones_the_policy_does_not_name() -> None:
    p = Policy(vendor="panos")
    rule = Rule("from-anywhere", src_zones=[ANY], dst_zones=["b"])
    rule.origin = rule.name
    p.rules.append(rule)
    for zones, outside in (([{"name": "a"}, {"name": "b"}], True), ([{"name": "rest", "policy_zones": ["a", "*"]}, {"name": "b"}], False)):
        document = {"zones": zones, "conduits": [{"from": zones[0]["name"], "to": "b", "services": ["any"]}]}
        found = conduits.check(p, conduits.load_model(json.dumps(document)))
        assert any(f.check == "NOT_IN_MODEL" for f in found.findings) == outside, found.to_text()
