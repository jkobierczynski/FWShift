# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""What no rule matches inside a zone, across the targets (0.33.0): a zone's own setting holds either way, also where
the policy's default inside a zone is the other one, and a --zone-map entry for a zone the source does not know merges
nothing.

The model says a zone's own setting with ``Zone.intrazone_allow`` (None: the policy's default). Some emitters read only
``True`` from it, and wrote "allowed inside every zone" where the default allows, also for a zone that blocks; no parser
gives that combination yet (PAN-OS has no setting per zone; FortiOS and SonicWall block by default), so it was latent.
"""

from __future__ import annotations

import random
from typing import List

import pytest
from test_iptables import random_model

from fwshift import cli, transform
from fwshift.model import Action, Policy, Rule, RuleScope, Zone
from fwshift.options import Options
from fwshift.report import Report

ZONES = ["eth0", "eth1", "eth2"]


def model(intra: Action, inter: Action, closed: str = "", opened: str = "", seed: int = 3) -> Policy:
    p = random_model(random.Random(seed))
    p.default_intrazone, p.default_interzone = intra, inter
    for zone in ZONES:
        p.zones.setdefault(zone, Zone(zone))
    if closed:
        p.zones[closed].intrazone_allow = False
    if opened:
        p.zones[opened].intrazone_allow = True
    return p


def codes(report: Report) -> List[str]:
    return [note.code for note in report.notes]


def test_panos_denies_inside_the_zone_that_blocks_it() -> None:
    """The default allows inside a zone, as PAN-OS does; eth1 blocks it: a deny for eth1 at the end, and for no other."""
    report = Report()
    lines = cli.convert(model(Action.ALLOW, Action.DENY, closed="eth1"), "panos", report).splitlines()
    tail = [line for line in lines if " fwshift-intrazone-deny " in line]
    assert "set rulebase security rules fwshift-intrazone-deny rule-type intrazone" in tail
    assert "set rulebase security rules fwshift-intrazone-deny from eth1" in tail and "set rulebase security rules fwshift-intrazone-deny to eth1" in tail
    assert "set rulebase security rules fwshift-intrazone-deny action deny" in tail and lines.index(tail[0]) > max(
        i for i, line in enumerate(lines) if line.startswith("set rulebase security rules r") and " fwshift-" not in line)  # fmt: skip
    assert "INTRAZONE_DENY_ADDED" in codes(report)
    # Nothing to add where every zone allows it, as PAN-OS does.
    report = Report()
    assert "fwshift-intrazone" not in cli.convert(model(Action.ALLOW, Action.DENY), "panos", report)


def test_sonicwall_denies_inside_the_zone_that_blocks_it() -> None:
    text = cli.convert(model(Action.ALLOW, Action.DENY, closed="eth1"), "sonicwall", Report())
    assert '"FWSHIFT eth1 to eth1"' in text and '"FWSHIFT eth0 to eth0"' not in text


@pytest.mark.parametrize("target", ["iptables", "nftables", "pfsense", "nsx", "junos"])
def test_targets_that_cannot_block_inside_one_zone_say_so(target: str) -> None:
    """Their default, written for traffic between zones, lets through traffic inside eth1, which the source blocks."""
    report = Report()
    cli.convert(model(Action.ALLOW, Action.ALLOW, closed="eth1"), target, report)
    note = next(n for n in report.notes if n.code == "INTRAZONE_DENY_NOT_WRITTEN")
    assert note.message.endswith(": eth1")
    report = Report()
    cli.convert(model(Action.ALLOW, Action.ALLOW), target, report)
    assert "INTRAZONE_DENY_NOT_WRITTEN" not in codes(report)


def test_a_zone_map_entry_for_a_zone_the_source_does_not_know_merges_nothing() -> None:
    """--zone-map trust=inside trsut=inside (a typo): trust is renamed, not merged; its allow inside is written."""
    p = Policy(vendor="fortios", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.zones["trust"] = Zone("trust", ["port1"], True)
    p.zones["dmz"] = Zone("dmz", ["port2"])
    p.rules.append(Rule("r", src_zones=["trust"], dst_zones=["dmz"]))
    assert transform.merged_zones(p, {"trust": "inside", "trsut": "inside"}, {"trust", "dmz"}) == set()
    assert transform.merged_zones(p, {"trust": "inside", "dmz": "inside"}, {"trust", "dmz"}) == {"inside"}
    for target in ("panos", "checkpoint", "sophos", "fmc", "forcepoint"):
        report = Report()
        text = cli.convert(p, target, report, Options(zone_map={"trust": "inside", "trsut": "inside", "dmz": "dmz"}))
        assert "INTRAZONE_ALLOW_MERGED" not in codes(report), target
        if target == "panos":
            assert "set rulebase security rules fwshift-intrazone-allow from inside" in text


def test_a_merge_of_zones_that_allow_inside_them_opens_nothing_between_them_on_panos() -> None:
    """PAN-OS source (inside a zone allowed, between denied), inside and dmz merged into internal: PAN-OS would allow
    between them by its own default; a deny inside internal keeps them apart, and is said."""
    p = model(Action.ALLOW, Action.DENY)
    report = Report()
    text = cli.convert(p, "panos", report, Options(zone_map={"eth0": "internal", "eth1": "internal"}))
    assert "set rulebase security rules fwshift-intrazone-deny from internal" in text
    assert "INTRAZONE_ALLOW_MERGED" in codes(report)


def test_intrazone_scope_rules_are_not_confused_with_the_default() -> None:
    """An intrazone rule of the source stays a rule; the tail comes after it (the order of first match)."""
    p = model(Action.ALLOW, Action.DENY, closed="eth1")
    p.rules.insert(0, Rule("inside-ssh", src_zones=["eth1"], scope=RuleScope.INTRAZONE, services=["web"]))
    lines = cli.convert(p, "panos", Report()).splitlines()
    first = next(i for i, line in enumerate(lines) if " inside-ssh " in line)
    tail = next(i for i, line in enumerate(lines) if " fwshift-intrazone-deny " in line)
    assert first < tail


@pytest.mark.parametrize("target", ["huawei", "ios", "stormshield", "routeros", "forcepoint", "vyos"])
def test_zones_merged_by_the_zone_map_are_not_opened_to_each_other(target: str) -> None:
    """PAN-OS source (inside a zone allowed, between zones denied), --zone-map eth0=m eth1=m: the targets that decide
    what passes inside a zone themselves must not pass traffic inside m, which is traffic between eth0 and eth1."""
    p = model(Action.ALLOW, Action.DENY)
    report = Report()
    text = cli.convert(p, target, report, Options(zone_map={"eth0": "m", "eth1": "m"}))
    assert "INTRAZONE_ALLOW_MERGED" in codes(report), target
    lines = text.splitlines()
    if target == "routeros":
        assert not any("in-interface-list=fws-m out-interface-list=fws-m action=accept" in line for line in lines)
    if target == "stormshield":
        assert not any("the source passes inside m" in line for line in lines)  # (the default inside m, not a rule)
    if target == "huawei":
        assert any("intrazone_m" in line for line in lines)  # (a USG passes inside a zone: a deny is written for m)
    if target == "forcepoint":
        assert "FWShift: inside zone m" not in text or '"discard"' in text
    if target == "vyos":
        # (no intra-zone-filtering: VyOS accepts inside a zone; a chain for m ends with drop)
        assert "set firewall ipv4 name FWS-m-m default-action 'drop'" in lines
        assert "set firewall zone m intra-zone-filtering firewall name 'FWS-m-m'" in lines


def test_sonicwall_leaves_out_a_zone_no_rule_names_whose_name_it_cannot_take() -> None:
    p = model(Action.DENY, Action.DENY)
    p.zones["x"] = Zone("x")
    report = Report()
    text = cli.convert(p, "sonicwall", report, Options(zone_map={"x": "name"}))  # ("name" is a word of the SonicOS CLI)
    assert "from name " not in text and "ZONE_NAME_INVALID" in codes(report)


def test_panos_writes_the_intrazone_deny_also_for_a_policy_without_security_rules() -> None:
    """A FortiOS source with no security rules: PAN-OS would allow inside a zone, which FortiOS denies."""
    p = Policy(vendor="fortios", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.zones["trust"] = Zone("trust", ["port1", "port2"])
    text = cli.convert(p, "panos", Report())
    assert "set rulebase security rules fwshift-intrazone-deny action deny" in text


def test_a_renamed_or_merged_zone_keeps_the_interfaces_of_its_source_zones() -> None:
    """--zone-map trust=m dmz=m: the hints put port1 and port2 in m, and nothing names the old zones."""
    p = Policy(vendor="fortios", default_intrazone=Action.DENY, default_interzone=Action.DENY)
    p.zones["trust"] = Zone("trust", ["port1"])
    p.zones["dmz"] = Zone("dmz", ["port2"])
    p.zones["wan"] = Zone("wan", ["port3"])
    p.rules.append(Rule("r", src_zones=["trust", "dmz"], dst_zones=["wan"]))
    options = Options(zone_map={"trust": "m", "dmz": "m"}, object_prefix="FWS_")
    huawei = cli.convert(p, "huawei", Report(), options)
    assert "firewall zone name FWS_m / add interface port1" in huawei and "add interface port2" in huawei
    assert "FWS_trust" not in huawei and "FWS_dmz" not in huawei
    ios = cli.convert(p, "ios", Report(), Options(zone_map={"trust": "m", "dmz": "m"}))
    assert "! interface port1" in ios and "! interface port2" in ios and "no interface is known" not in ios
    routeros = cli.convert(p, "routeros", Report(), Options(zone_map={"trust": "m", "dmz": "m"}))
    assert "list=fws-m interface=\"port1\"" in routeros and "list=fws-m interface=\"port2\"" in routeros
    vyos = cli.convert(p, "vyos", Report(), Options(zone_map={"trust": "m", "dmz": "m"}))
    assert "set firewall zone m interface 'port1'" in vyos and "set firewall zone m interface 'port2'" in vyos
    assert "zone trust" not in vyos and "zone dmz" not in vyos
    forcepoint = cli.convert(p, "forcepoint", Report(), Options(zone_map={"trust": "m", "dmz": "m"}))
    assert '"trust"' not in forcepoint and '"dmz"' not in forcepoint
