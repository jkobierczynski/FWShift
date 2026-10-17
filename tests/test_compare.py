# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The equivalence check (fwshift compare, convert --compare), against a walk through packets.

The walk decides a packet the way the model means it: the first rule that matches, else the default between
zones or inside one. A packet carries an application (on its default ports or not, as its port says), and users.
Every packet the two policies decide differently must lie in a difference the comparison reports, the right way
round; a packet in a difference that is reported as certain must be decided differently.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import random
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

import pytest
from helpers import DATA
from test_iptables import _entry_matches, _member_matches, random_model, random_packet
from test_nsx import ZONES_AT, zone_of

from fwshift import appmap, cli, compare, transform
from fwshift.audit import _DIFFERENT, _SAME
from fwshift.emitters import iptables as emit_iptables
from fwshift.emitters import nftables as emit_nftables
from fwshift.errors import FwshiftError
from fwshift.model import ANY, APP_DEFAULT, Action, Policy, Rule, RuleScope, Zone
from fwshift.netutil import parse_literal
from fwshift.options import Options
from fwshift.parsers import iptables as parse_iptables
from fwshift.parsers import nftables as parse_nftables
from fwshift.report import Report

@dataclass
class Ran:
    code: int
    stdout: str
    stderr: str


def run_cli(argv: List[str]) -> Ran:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return Ran(code, out.getvalue(), err.getvalue())


APPS = ["ssl", "web-browsing", "dns", "ping"]
USERS = ["alice", "ops", "guests"]
NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}


@dataclass
class Labelled:
    pkt: object
    app: str
    users: FrozenSet[str] = field(default_factory=frozenset)


def default_ports(app: str, pkt: object) -> bool:
    entries = appmap.entries_for(app, {})
    assert entries is not None
    return any(_entry_matches(entry, pkt) for entry in entries)  # type: ignore[arg-type]


HIDDEN: Dict[str, str] = {"dyn": "10.0.1.0/24"}  # what the dynamic group holds, which the comparison does not know


def member(p: Policy, name: str, address: str) -> bool:
    if name in HIDDEN:
        network, probe = parse_literal(HIDDEN[name]), parse_literal(address)
        assert network is not None and probe is not None
        return network[0] == probe[0] and network[1] <= probe[1] <= network[2]
    return _member_matches(p, name, address)


def matches(p: Policy, rule: Rule, item: Labelled) -> bool:
    pkt = item.pkt
    zone_ok = (ANY in rule.src_zones or pkt.in_if in rule.src_zones) and (ANY in rule.dst_zones or pkt.out_if in rule.dst_zones)  # type: ignore[attr-defined]
    if rule.scope == RuleScope.INTRAZONE:
        zone_ok = pkt.in_if == pkt.out_if and (ANY in rule.src_zones or pkt.in_if in rule.src_zones)  # type: ignore[attr-defined]
    elif rule.scope == RuleScope.INTERZONE:
        zone_ok = zone_ok and pkt.in_if != pkt.out_if  # type: ignore[attr-defined]
    if not zone_ok:
        return False
    if any(member(p, m, pkt.src) for m in rule.sources) == rule.negate_source:  # type: ignore[attr-defined]
        return False
    if any(member(p, m, pkt.dst) for m in rule.destinations) == rule.negate_destination:  # type: ignore[attr-defined]
        return False
    if rule.applications != [ANY] and item.app not in rule.applications:
        return False
    if rule.users != [ANY] and not item.users & set(rule.users):
        return False
    if rule.services == [APP_DEFAULT]:
        return default_ports(item.app, pkt)
    if rule.services == [ANY]:
        service_ok = True
    else:
        entries = [e for s in rule.services for e in (transform.flatten_services(p, s) or [])]
        service_ok = any(_entry_matches(e, pkt) for e in entries)  # type: ignore[arg-type]
    return service_ok != rule.negate_service


def verdict(p: Policy, item: Labelled) -> bool:
    for rule in p.rules:
        if rule.enabled and not rule.unsupported and matches(p, rule, item):
            return rule.action == Action.ALLOW
    pkt = item.pkt
    if pkt.in_if == pkt.out_if:  # type: ignore[attr-defined]
        zone = p.zones.get(pkt.in_if)  # type: ignore[attr-defined]
        if zone is not None and zone.intrazone_allow is not None:
            return zone.intrazone_allow
        return p.default_intrazone == Action.ALLOW
    return p.default_interzone == Action.ALLOW


def labelled(rng: random.Random, p: Policy) -> Policy:
    """Applications and users on some rules; a dynamic group (whose members only the walk knows) in some."""
    from fwshift.model import AddressGroup

    p.address_groups["dyn"] = AddressGroup("dyn", dynamic_filter="tag:web")
    for rule in p.rules:
        if rng.random() < 0.2:
            if rng.random() < 0.5:
                rule.sources = ["dyn"] if rule.sources == [ANY] else rule.sources + ["dyn"]
            else:
                rule.destinations = ["dyn"] if rule.destinations == [ANY] else rule.destinations + ["dyn"]
        roll = rng.random()
        if roll < 0.15:
            rule.applications = rng.sample(APPS, rng.randint(1, 2))
            rule.services = [APP_DEFAULT]
            rule.negate_service = False
        elif roll < 0.25:
            rule.applications = rng.sample(APPS, 1)
        if rng.random() < 0.15:
            rule.users = rng.sample(USERS, rng.randint(1, 2))
    return p


def changed(rng: random.Random, p: Policy) -> Policy:
    """The same policy with a few changes."""
    q = copy.deepcopy(p)
    for _ in range(rng.randint(0, 3)):
        kind = rng.random()
        if not q.rules:
            break
        rule = rng.choice(q.rules)
        if kind < 0.2:
            q.rules.remove(rule)
        elif kind < 0.4:
            rule.action = Action.DENY if rule.action == Action.ALLOW else Action.ALLOW
        elif kind < 0.55:
            position = q.rules.index(rule)
            q.rules.insert(rng.randrange(len(q.rules)), q.rules.pop(position))
        elif kind < 0.7:
            rule.sources = [rng.choice(["10.0.1.0/24", "10.0.0.17", "net2", ANY])]
        elif kind < 0.8:
            rule.enabled = not rule.enabled
        elif kind < 0.9:
            q.default_intrazone = Action.ALLOW if q.default_intrazone == Action.DENY else Action.DENY
        else:
            q.zones["eth1"] = Zone("eth1", intrazone_allow=rng.choice([True, False]))
    return q


def point(pkt: object) -> Optional[Tuple[int, int, int, int, int, int]]:
    src, dst = parse_literal(pkt.src), parse_literal(pkt.dst)  # type: ignore[attr-defined]
    assert src is not None and dst is not None
    proto = pkt.proto  # type: ignore[attr-defined]
    number = NUMBERS.get(proto, int(proto) if proto.isdigit() else -1)
    if number in (6, 17):
        return src[0], src[1], dst[1], number, pkt.sport, pkt.dport  # type: ignore[attr-defined]
    if number in (1, 58):
        return src[0], src[1], dst[1], number, pkt.icmp_type, 0  # type: ignore[attr-defined]
    return src[0], src[1], dst[1], number, 0, 0


def atom_of(result: compare.Comparison, item: Labelled, src: str, dst: str, relation: int) -> Optional[compare.Atom]:
    found = result.labels.get((src, dst, relation))
    if found is None:
        return None
    labels, dropped = found
    if dropped:
        return compare.Atom()
    app = item.app if item.app in labels.apps else compare._NO_APP
    default = default_ports(app, item.pkt) if app != compare._NO_APP and labels.apps[app] else None
    pkt = item.pkt
    unknown = frozenset(label for label in labels.unknown
                        if member(Policy("panos"), label[4:], pkt.src if label.startswith("src:") else pkt.dst))  # type: ignore[attr-defined]
    return compare.Atom(app, default, frozenset(item.users & labels.users), unknown=unknown)


def covered(result: compare.Comparison, item: Labelled, src: str, dst: str, relation: int, opened: bool, certain_only: bool) -> bool:
    names = {key[0] for key in result.labels}
    src = src if src in names else compare.OTHER  # (a zone neither policy names)
    dst = dst if dst in names else compare.OTHER
    spot = point(item.pkt)
    atom = atom_of(result, item, src, dst, relation)
    for d in result.differences:
        if (d.src, d.dst) != (src, dst) or d.opened != opened or (certain_only and not d.certain):
            continue
        if d.inside != (relation == _SAME):
            continue
        if atom is not None and atom not in d.atoms:
            continue
        if spot is not None and any(compare._holds(box, spot) for box in d.boxes):
            return True
    return False


def check(result: compare.Comparison, a: Policy, b: Policy, rng: random.Random, seed: int, by_zone: bool) -> int:
    compared = 0
    for _ in range(400):
        pkt = random_packet(rng, rng.choice([4, 6]))
        if by_zone:
            pkt.in_if, pkt.out_if = zone_of(pkt.src), zone_of(pkt.dst)
        item = Labelled(pkt, rng.choice(APPS + ["other"]), frozenset(rng.sample(USERS, rng.randint(0, 2))))
        first, second = verdict(a, item), verdict(b, item)
        relation = _SAME if pkt.in_if == pkt.out_if else _DIFFERENT
        compared += 1
        if first != second:
            assert covered(result, item, pkt.in_if, pkt.out_if, relation, second, False), (seed, pkt, item.app, item.users, first, second,
                                                                                         result.to_text())  # fmt: skip
        else:
            for opened in (True, False):
                assert not covered(result, item, pkt.in_if, pkt.out_if, relation, opened, True), (seed, pkt, item.app, item.users,
                                                                                                 result.to_text())  # fmt: skip
    return compared


@pytest.mark.parametrize("seed", range(60))
def test_every_difference_is_found_and_certain_ones_are_real(seed: int) -> None:
    rng = random.Random(seed)
    HIDDEN["dyn"] = rng.choice(["10.0.1.0/24", "10.0.0.0/23", "2001:db8:1::/48", "10.0.4.0/24", "10.0.0.17/32"])
    a = labelled(rng, random_model(rng)) if seed % 2 else random_model(rng)
    b = changed(rng, a)
    by_zone = seed % 3 == 0
    networks = ZONES_AT if by_zone else None
    result = compare.compare(a, b, "a", "b", zone_networks=networks)
    assert check(result, a, b, rng, seed, by_zone) == 400


@pytest.mark.parametrize("seed", range(20))
def test_a_policy_is_equal_to_itself(seed: int) -> None:
    rng = random.Random(500 + seed)
    a = labelled(rng, random_model(rng))
    result = compare.compare(a, copy.deepcopy(a), "a", "a")
    assert result.equal, result.to_text()


@pytest.mark.parametrize("seed", range(30))
def test_iptables_and_nftables_output_read_back_are_equal_to_the_model(seed: int) -> None:
    """What FWShift writes for iptables and nftables, read back, decides every connection as the model does: never
    differently for certain, and alike wherever the parser reads every rule back exactly (the chains of a negation it
    writes end in a RETURN the iptables parser does not follow)."""
    rng = random.Random(800 + seed)
    model = random_model(rng)
    backs = []
    for family, emit in ((4, emit_iptables.emit), (6, emit_iptables.emit_v6)):
        text = emit(model, Report(), Options())
        backs.append((f"iptables IPv{family}", parse_iptables.parse(text.encode(), Report(), family=family)))
    backs.append(("nftables", parse_nftables.parse(emit_nftables.emit(model, Report(), Options()).encode(), Report())))
    for label, back in backs:
        result = compare.compare(model, back, "model", label)
        assert not any(d.certain for d in result.differences), (seed, label, result.to_text())
        if not any(rule.unsupported for rule in back.rules):
            assert result.equal, (seed, label, result.to_text())


def test_what_differs_is_said_with_its_rules_and_labels() -> None:
    p = Policy(vendor="panos")
    for rule in (Rule("web", src_zones=["lan"], dst_zones=["wan"], applications=["ssl"], services=[APP_DEFAULT]),
                 Rule("dns", src_zones=["lan"], dst_zones=["wan"], destinations=["192.0.2.53"], services=[ANY])):  # fmt: skip
        rule.origin = rule.name
        p.rules.append(rule)
    q = copy.deepcopy(p)
    q.rules[0].applications, q.rules[0].services = [ANY], ["tcp-443"]
    from fwshift.model import Protocol, Service, ServiceEntry

    q.services["tcp-443"] = Service("tcp-443", [ServiceEntry(Protocol.TCP, "443")])
    q.rules.pop()
    result = compare.compare(p, q, "before", "after", zone_networks={"lan": ["10.1.0.0/16"], "wan": ["0.0.0.0/0", "::/0"]})
    text = result.to_text()
    opened = [d for d in result.differences if d.opened]
    closed = [d for d in result.differences if not d.opened]
    assert opened and all(d.certain for d in opened) and "other applications" in opened[0].condition
    assert "tcp/443" in " ".join(opened[0].lines())
    assert closed and any("192.0.2.53" in " ".join(d.lines()) for d in closed)
    assert any("rule 'dns' allows" in d.first_rule and "the default blocks" in d.second_rule for d in closed)
    assert result.level() == 3 and "opened, certain" in text
    document = result.to_dict()
    assert document["equivalent"] is False and document["differences"][0]["change"] in ("opened", "closed")


def test_unreadable_objects_make_differences_possible_only() -> None:
    p = Policy(vendor="panos")
    from fwshift.model import AddressGroup

    p.address_groups["dyn"] = AddressGroup("dyn", dynamic_filter="tag:web")
    rule = Rule("to-dyn", destinations=["dyn"])
    rule.origin = rule.name
    p.rules.append(rule)
    q = Policy(vendor="panos")
    result = compare.compare(p, q)
    assert result.differences and all(not d.certain for d in result.differences)
    assert result.level() == 1


def test_zones_without_networks_and_one_ip_version() -> None:
    p = Policy(vendor="iptables", scope="IPv4")
    q = Policy(vendor="panos", default_interzone=Action.ALLOW)
    result = compare.compare(p, q)
    assert all(box[0] == 4 for d in result.differences for box in d.boxes)
    assert any("IPv4" in note for note in result.notes)


def test_the_command(tmp_path: object) -> None:
    out = run_cli(["compare", str(DATA / "panos_sample.xml"), str(DATA / "panos_sample.xml")])
    assert out.code == 0 and "decide every connection alike" in out.stdout
    out = run_cli(["compare", str(DATA / "iptables_sample.rules"), str(DATA / "panos_sample.xml"), "--json", "--fail-on", "none"])
    assert out.code == 0 and json.loads(out.stdout)["equivalent"] is False
    out = run_cli(["compare", str(DATA / "iptables_sample.rules"), str(DATA / "panos_sample.xml")])
    assert out.code == 3
    out = run_cli(["compare", str(DATA / "panos_sample.xml"), str(DATA / "panos_sample.xml"), "--fail-on", "sometimes"])
    assert out.code == 1 and "--fail-on" in out.stderr
    with pytest.raises(FwshiftError):
        compare.parse_zone_map(["nothing"])


GOLDEN = DATA / "expected"
NETWORKS = ["--zone-network", "trust=10.10.0.0/16", "--zone-network", "dmz=10.20.0.0/24,203.0.113.0/24", "--zone-network", "ot=10.30.0.0/16",
            "--zone-network", "untrust=0.0.0.0/0,::/0"]  # fmt: skip


@pytest.mark.parametrize("target", ["iptables", "azure", "nsx", "fortios"])
def test_golden_conversion_compared(target: str, tmp_path: object, monkeypatch: object) -> None:
    """convert --compare on the PAN-OS sample, byte for byte (FWSHIFT_UPDATE_GOLDEN=1): what each conversion changes."""
    import os
    from pathlib import Path

    monkeypatch.chdir(DATA)  # type: ignore[attr-defined]
    out, report, written = Path(str(tmp_path)) / "out", Path(str(tmp_path)) / "report.txt", Path(str(tmp_path)) / "compare.txt"
    ran = run_cli(["convert", "panos_sample.xml", "--to", target, "-o", str(out), "--report", str(report), "-q", "--compare", str(written)] + NETWORKS)
    assert ran.code == 0, ran.stderr
    text = written.read_text(encoding="utf-8")
    golden = GOLDEN / f"panos_to_{target}.compare.txt"
    if os.environ.get("FWSHIFT_UPDATE_GOLDEN"):
        golden.write_text(text, encoding="utf-8", newline="\n")
    assert text == golden.read_text(encoding="utf-8")
    notes = report.read_text(encoding="utf-8")
    assert "COMPARE_OPENED" in notes or "COMPARE_EQUIVALENT" in notes


def test_convert_compare_says_what_it_cannot_read_back(tmp_path: object) -> None:
    from pathlib import Path

    report = Path(str(tmp_path)) / "report.txt"
    ran = run_cli(["convert", str(DATA / "panos_sample.xml"), "--to", "checkpoint", "-o", str(Path(str(tmp_path)) / "o"), "--report",
                   str(report), "-q", "--compare"])  # fmt: skip
    assert ran.code == 0 and "COMPARE_NOT_READ_BACK" in report.read_text(encoding="utf-8")


def test_fortios_output_reads_back_with_its_new_entries() -> None:
    """FortiOS output makes its policies with 'edit 0' (the next free number): read back, every one is there."""
    from fwshift.parsers import fortios as parse_fortios

    text = (GOLDEN / "panos_to_fortios.conf").read_bytes()
    p = parse_fortios.parse(text, Report())
    assert len(p.rules) == 14 and len({r.name for r in p.rules}) == 14
    assert parse_fortios.parse_tree("config firewall address\n    edit 0\n        set subnet 10.0.0.0/8\n    next\nend\n").children[
        "firewall address"].entries.keys() == {"0"}  # (a name, not a number, outside the numbered tables)


def test_zones_of_the_output_are_matched_with_a_prefix(tmp_path: object) -> None:
    from pathlib import Path

    report = Path(str(tmp_path)) / "report.txt"
    ran = run_cli(["convert", str(DATA / "panos_sample.xml"), "--to", "azure", "-o", str(Path(str(tmp_path)) / "o"), "--report", str(report),
                   "-q", "--compare", "--target-prefix", "nsg-"] + NETWORKS)  # fmt: skip
    text = report.read_text(encoding="utf-8")
    assert ran.code == 0 and "COMPARE_ZONES" not in text and ("COMPARE_OPENED" in text or "COMPARE_EQUIVALENT" in text)


# -- review round 30 --------------------------------------------------------------------------


def _policy(*rules: Rule, **more: object) -> Policy:
    p = Policy(vendor="panos", **more)  # type: ignore[arg-type]
    for rule in rules:
        rule.origin = rule.origin or rule.name
        p.rules.append(rule)
    return p


def test_r30_shared_objects_that_are_not_combined_count_from_above() -> None:
    from fwshift.model import AddressGroup, Protocol, Service, ServiceEntry

    def base(groups: int, apps: int) -> Policy:
        p = Policy(vendor="panos")
        p.services["ssh"] = Service("ssh", [ServiceEntry(Protocol.TCP, "22")])
        p.services["web"] = Service("web", [ServiceEntry(Protocol.TCP, "8080")])
        for i in range(groups):
            p.address_groups[f"dyn{i}"] = AddressGroup(f"dyn{i}", dynamic_filter=f"'tag{i}'")
            p.rules.append(Rule(f"web{i}", sources=[f"dyn{i}"], destinations=["10.0.0.10"], services=["web"]))
        for i in range(apps):
            p.rules.append(Rule(f"app{i}", destinations=["10.0.0.10"], applications=[f"app{i}"], services=["web"]))
        return p

    for groups, apps in ((7, 0), (1, 130)):
        first, second = base(groups, apps), base(groups, apps)
        first.rules.insert(0, Rule("ssh-from-dyn0", sources=["dyn0"], destinations=["10.0.0.10"], services=["ssh"]))
        result = compare.compare(first, second)
        closed = [d for d in result.differences if not d.opened]
        assert closed and any("tcp/22" in " ".join(d.lines()) for d in closed), (groups, apps, result.to_text())
        assert not any(d.certain for d in result.differences)


def test_r30_objects_alike_by_name_only_are_not_shared() -> None:
    from fwshift.model import Address, AddressGroup, AddressKind

    def tagged(extra: bool) -> Policy:
        p = _policy(Rule("ssh", sources=["dyn"], destinations=["10.0.0.10"]))
        p.addresses["web"] = Address("web", AddressKind.NETWORK, "10.20.0.10/32", tags=["servers"])
        p.addresses["lan"] = Address("lan", AddressKind.NETWORK, "10.10.0.0/16", tags=["servers"] if extra else [])
        p.address_groups["dyn"] = AddressGroup("dyn", dynamic_filter="'servers'")
        return p

    assert compare.compare(tagged(False), tagged(False)).equal
    assert not compare.compare(tagged(False), tagged(True)).equal  # (lan carries the tag now: the group holds more)
    excluded = [_policy(Rule("from-g", sources=["g"])) for _ in range(2)]
    for p in excluded:
        p.address_groups["g"] = AddressGroup("g", ["10.1.0.0/16"], unsupported="excludes h1")
    assert not compare.compare(*excluded).equal  # (what it excludes is not in the model: never alike)


def test_r30_a_rule_the_model_does_not_hold_exactly_may_do_anything() -> None:
    real_allow = Rule("ipsec", src_zones=["a"], dst_zones=["b"], action=Action.DROP)
    real_allow.unsupported = ["action ipsec is not converted"]
    first = _policy(real_allow)
    second = _policy()
    result = compare.compare(first, second)
    assert result.differences and all(not d.certain for d in result.differences)
    assert compare.compare(first, copy.deepcopy(first)).equal  # (alike in both: it decides alike)
    from fwshift import conduits

    model = conduits.load_model(json.dumps({"zones": [{"name": "a"}, {"name": "b"}]}))
    found = conduits.check(first, model)
    assert any(f.check == "NO_CONDUIT" and f.possible for f in found.findings)


def test_r30_zones_that_become_one() -> None:
    first = _policy(Rule("deny", src_zones=["lan"], dst_zones=["servers"], action=Action.DENY), default_intrazone=Action.ALLOW)
    second = _policy(default_intrazone=Action.ALLOW)
    result = compare.compare(first, second, zone_map={"lan": "inside", "servers": "inside"})
    opened = [d for d in result.differences if d.opened and d.src == "lan" and d.dst == "servers"]
    assert opened and opened[0].certain and "inside -> inside" in opened[0].second_pair


def test_r30_what_is_compared_by_name_and_users_that_overlap() -> None:
    first = _policy(Rule("maint", schedule="maint"), Rule("users", users=["known-user"], destinations=["10.0.0.1"]))
    assert compare.compare(first, copy.deepcopy(first)).by_name == ["users", "schedules"]
    assert "if the users, schedules of the same names hold the same" in compare.compare(first, copy.deepcopy(first)).summary()
    second = copy.deepcopy(first)
    second.rules[1].users = ["example\\alice"]
    result = compare.compare(first, second)
    assert result.differences and not any(d.certain for d in result.differences)  # (alice may be a known user)


def test_r30_policies_of_two_ip_versions_and_addresses_in_no_zone() -> None:
    with pytest.raises(FwshiftError, match="different IP versions"):
        compare.compare(Policy(vendor="iptables", scope="IPv4"), Policy(vendor="iptables", scope="IPv6"))
    result = compare.compare(_policy(Rule("out", src_zones=["trust"], dst_zones=["untrust"])), _policy(),
                             zone_networks={"trust": ["10.0.0.0/8"], "untrust": ["192.0.2.0/24"]})  # fmt: skip
    assert any(compare.ELSEWHERE in note for note in result.notes)
    assert {(d.src, d.dst) for d in result.differences} == {("trust", "untrust")}


def test_r30_the_text_tells_inside_from_between_and_names_the_deciding_rule() -> None:
    result = compare.compare(_policy(default_intrazone=Action.ALLOW), _policy())
    text = result.to_text()
    assert "(other zones) -> (other zones) (inside the zone)" in text
    web = Rule("web", src_zones=["lan"], dst_zones=["wan"], applications=["ssl"], services=[APP_DEFAULT])
    result = compare.compare(_policy(web), _policy())
    assert any(d.first_rule == "rule 'web' allows" for d in result.differences), result.to_text()


def test_r30_convert_compare_needs_the_networks_for_asa(tmp_path: object) -> None:
    from pathlib import Path

    report = Path(str(tmp_path)) / "report.txt"
    ran = run_cli(["convert", str(DATA / "asa_sample.cfg"), "--to", "asa", "-o", str(Path(str(tmp_path)) / "o"), "--report", str(report),
                   "-q", "--compare"])  # fmt: skip
    assert ran.code == 0 and "COMPARE_NOT_READ_BACK" in report.read_text(encoding="utf-8")
    ran = run_cli(["convert", str(DATA / "iptables_sample.rules"), "--to", "ip6tables", "-o", str(Path(str(tmp_path)) / "o6"), "--report",
                   str(report), "-q", "--compare"])  # fmt: skip
    assert ran.code == 0 and "different IP versions" in report.read_text(encoding="utf-8")


def test_r30_a_rule_alike_in_both_decides_by_its_labels() -> None:
    """A rule both hold alike but not exactly: whether it matches, and whether it allows, are labels of their own."""
    def wild() -> Rule:
        rule = Rule("odd", src_zones=["a"], dst_zones=["b"], action=Action.DROP)
        rule.unsupported = ["action ipsec is not converted"]
        return rule

    first = _policy(wild())
    second = _policy(Rule("deny-x", src_zones=["a"], dst_zones=["b"], destinations=["10.0.0.1"], action=Action.DENY), wild())
    result = compare.compare(first, second)
    closed = [d for d in result.differences if not d.opened]
    assert closed and not any(d.certain for d in closed)
    # Only where the rule matches and allows does the deny rule above it in the second make a difference.
    assert all("rule:odd" in atom.unknown and "allows:odd" in atom.unknown for d in closed for atom in d.atoms), result.to_text()


def test_r30_two_zones_neither_names_are_compared_between_them_too() -> None:
    result = compare.compare(_policy(default_interzone=Action.ALLOW), _policy())
    assert any(d.src == d.dst == compare.OTHER and not d.inside and d.certain and not d.opened for d in result.differences), result.to_text()
