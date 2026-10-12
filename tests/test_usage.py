# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Rule identity, install-on targets, access roles and hit counters (0.13.0; docs/RULE_USAGE.md).

Every configuration and counter answer here is made up, with documentation and private addresses only.
"""

from __future__ import annotations

import json
import random
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from fwshift import audit, cli, hits
from fwshift.errors import FwshiftError, ParseError
from fwshift.model import ANY, Action, HitCount, Policy, Rule
from fwshift.netutil import parse_literal
from fwshift.parsers import checkpoint as parse_checkpoint
from fwshift.report import Report

# -- a small Check Point export ---------------------------------------------------------------------

_DOMAIN = {"uid": "d0", "name": "SMC User", "domain-type": "domain"}


class Export:
    """Objects and layers of a made-up 'show access-rulebase' answer (details-level full, object dictionary)."""

    def __init__(self) -> None:
        self.objects: Dict[str, Dict[str, Any]] = {}
        self.layers: List[Dict[str, Any]] = []
        for name, kind in (("Any", "CpmiAnyObject"), ("Policy Targets", "Global"), ("Accept", "RulebaseAction"),
                           ("Drop", "RulebaseAction"), ("Inner Layer", "Global"), ("Log", "Track")):  # fmt: skip
            self.add(name, kind)

    def add(self, name: str, kind: str, **fields: Any) -> str:
        entry = {"uid": f"uid-{name}", "name": name, "type": kind, "domain": _DOMAIN}
        entry.update({key.replace("_", "-"): value for key, value in fields.items()})
        self.objects[name] = entry
        return entry["uid"]

    def network(self, name: str, cidr: str) -> str:
        net, length = cidr.split("/")
        return self.add(name, "network", subnet4=net, mask_length4=int(length))

    def group(self, name: str) -> str:
        return self.add(name, "CpmiAdGroup")

    def role(self, name: str, networks: Any = "any", users: Any = "any", **fields: Any) -> str:
        nets = networks if isinstance(networks, str) else [self.objects[n] for n in networks]
        people = users if isinstance(users, str) else [self.objects[u] for u in users]
        return self.add(name, "access-role", networks=nets, users=people, **fields)

    def rule(self, name: str, source: Sequence[str], destination: Sequence[str] = ("Any",), action: str = "Accept",
             uid: str = "", **extra: Any) -> Dict[str, Any]:  # fmt: skip
        entry: Dict[str, Any] = {
            "uid": uid or f"rule-{name}", "name": name, "type": "access-rule", "domain": _DOMAIN,
            "source": [self.objects[n]["uid"] for n in source], "source-negate": False,
            "destination": [self.objects[n]["uid"] for n in destination], "destination-negate": False,
            "service": [self.objects["Any"]["uid"]], "service-negate": False, "action": self.objects[action]["uid"],
            "track": {"type": self.objects["Log"]["uid"]}, "enabled": True,
            "install-on": [self.objects["Policy Targets"]["uid"]],
        }  # fmt: skip
        for key, value in extra.items():
            key = key.replace("_", "-")
            if key == "install-on":
                value = [self.add(target, "simple-gateway", ipv4_address="198.51.100.1") if target not in self.objects
                         else self.objects[target]["uid"] for target in value]  # fmt: skip
            if key == "inline-layer":
                value = self.objects[value]["uid"]
            entry[key] = value
        return entry

    def layer(self, name: str, rules: List[Dict[str, Any]], cleanup: str = "drop") -> None:
        uid = self.add(name, "access-layer", implicit_cleanup_action=cleanup)
        self.layers.append({"uid": uid, "name": name, "rulebase": rules, "from": 1, "to": len(rules), "total": len(rules)})

    def data(self) -> bytes:
        out = []
        for layer in self.layers:
            out.append(dict(layer, **{"objects-dictionary": list(self.objects.values())}))
        return json.dumps(out).encode()

    def policy(self, report: Optional[Report] = None) -> Policy:
        return parse_checkpoint.parse(self.data(), report or Report(), layer=self.layers[0]["name"])


def hit(value: int, first: int = 0, last: int = 0) -> Dict[str, Any]:
    out: Dict[str, Any] = {"percentage": "0%", "level": "zero" if not value else "low", "value": value}
    for key, moment in (("first-date", first), ("last-date", last)):
        if moment:
            out[key] = {"posix": moment * 1000, "iso-8601": "..."}
    return out


# -- rule identity and targets ---------------------------------------------------------------------


def test_check_point_rules_keep_their_uids_and_targets() -> None:
    cp = Export()
    cp.network("lan", "10.10.0.0/16")
    cp.network("dmz", "10.20.0.0/24")
    cp.add("Inner", "access-layer")
    inner = [cp.rule("Web", ["Any"], ["dmz"], uid="u-web", install_on=["gw-a", "gw-b"]),
             cp.rule("Mail", ["Any"], ["dmz"], uid="u-mail", install_on=["gw-c"])]  # fmt: skip
    cp.layer("Main", [cp.rule("Plain", ["lan"], uid="u-plain", install_on=["gw-a"]),
                      cp.rule("Apply", ["Any"], ["dmz"], "Inner Layer", uid="u-apply", inline_layer="Inner", install_on=["gw-a"]),
                      cp.rule("Last", ["Any"], uid="u-last")])  # fmt: skip
    cp.layers.append({"uid": "uid-Inner", "name": "Inner", "rulebase": inner, "from": 1, "to": 2, "total": 2})
    report = Report()
    policy = cp.policy(report)
    rules = {rule.name: rule for rule in policy.rules}
    assert rules["Plain"].source_ids == {"checkpoint.rule_uid": "u-plain", "checkpoint.layer_uid": "uid-Main",
                                         "checkpoint.policy_layer_uid": "uid-Main"}  # (the layer the policy was read from, on every rule)
    assert rules["Plain"].targets == ["gw-a"] and rules["Last"].targets == []
    web = rules["Apply / Web"]
    assert web.source_ids == {"checkpoint.rule_uid": "u-web", "checkpoint.layer_uid": "uid-Inner", "checkpoint.policy_layer_uid": "uid-Main",
                              "checkpoint.parent_rule_uid": "u-apply", "checkpoint.rule_path": "u-apply u-web"}  # fmt: skip
    assert web.targets == ["gw-a"]  # installed where both the rule applying the layer and the rule inside are
    mail = rules["Apply / Mail"]
    assert mail.targets == [] and any("installed on no gateway" in text for text in mail.unsupported)
    cleanup = rules["Apply (cleanup of Inner)"]
    assert cleanup.source_ids == {"checkpoint.parent_rule_uid": "u-apply", "checkpoint.layer_uid": "uid-Inner", "checkpoint.policy_layer_uid": "uid-Main",
                                  "checkpoint.rule_path": "u-apply", "checkpoint.implicit": "cleanup"}  # fmt: skip
    # Still reported: the target is one firewall.
    assert "DEVICE_TARGET" in [f.code for f in report.item("rule", "Plain").findings]
    # Kept in the model as JSON, and nowhere converted.
    model = json.loads(cli.convert(policy, "json", Report()))
    assert model["rules"][0]["source_ids"]["checkpoint.rule_uid"] == "u-plain" and model["rules"][0]["targets"] == ["gw-a"]
    assert "u-plain" not in cli.convert(cp.policy(), "panos", Report())


def test_nested_inline_layers_keep_the_whole_path() -> None:
    cp = Export()
    cp.network("dmz", "10.20.0.0/24")
    cp.add("Middle", "access-layer")
    cp.add("Deep", "access-layer")
    cp.layer("Main", [cp.rule("Outer", ["Any"], ["dmz"], "Inner Layer", uid="u1", inline_layer="Middle")])
    cp.layers.append({"uid": "uid-Middle", "name": "Middle", "from": 1, "to": 1, "total": 1,
                      "rulebase": [cp.rule("Mid", ["Any"], ["dmz"], "Inner Layer", uid="u2", inline_layer="Deep")]})  # fmt: skip
    cp.layers.append({"uid": "uid-Deep", "name": "Deep", "from": 1, "to": 1, "total": 1, "rulebase": [cp.rule("In", ["Any"], uid="u3")]})
    ids = {rule.name: rule.source_ids for rule in cp.policy().rules}
    assert ids["Outer / Mid / In"]["checkpoint.rule_uid"] == "u3"
    assert ids["Outer / Mid / In"]["checkpoint.parent_rule_uid"] == "u2"  # the direct parent
    assert ids["Outer / Mid / In"]["checkpoint.rule_path"] == "u1 u2 u3"


def test_panos_and_fortios_keep_their_identifiers() -> None:
    xml = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
      <zone><entry name="a"/><entry name="b"/></zone>
      <rulebase><security><rules>
        <entry name="one" uuid="0b6d2a1e-0000-4000-8000-000000000001"><from><member>a</member></from><to><member>b</member></to>
          <source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application>
          <service><member>any</member></service><action>allow</action></entry>
        <entry name="two"><from><member>a</member></from><to><member>b</member></to>
          <source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application>
          <service><member>any</member></service><action>deny</action></entry>
      </rules></security></rulebase></entry></vsys></entry></devices></config>"""
    policy = cli.load(xml, "panos", Report())
    assert policy.rules[0].source_ids == {"panos.name": "one", "panos.uuid": "0b6d2a1e-0000-4000-8000-000000000001"}
    assert policy.rules[1].source_ids == {"panos.name": "two"}
    conf = b"""config firewall policy
    edit 7
        set name "web"
        set uuid 5a3c0f2e-0000-4000-8000-000000000007
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
    policy = cli.load(conf, "fortios", Report())
    assert policy.rules[0].source_ids == {"fortios.policyid": "7", "fortios.uuid": "5a3c0f2e-0000-4000-8000-000000000007"}


def test_panorama_targets_are_kept_unless_negated() -> None:
    def config(negate: str) -> bytes:
        return f"""<config><devices><entry name="localhost.localdomain"><device-group><entry name="DG">
          <pre-rulebase><security><rules><entry name="r"><from><member>any</member></from><to><member>any</member></to>
            <source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application>
            <service><member>any</member></service><action>allow</action>
            <target><devices><entry name="007000000001"/><entry name="007000000002"/></devices><negate>{negate}</negate></target>
          </entry></rules></security></pre-rulebase></entry></device-group></entry></devices></config>""".encode()

    assert cli.load(config("no"), "panos", Report()).rules[0].targets == ["007000000001", "007000000002"]
    assert cli.load(config("yes"), "panos", Report()).rules[0].targets == []  # every device but these is not a list


# -- access roles ------------------------------------------------------------------------------------


def _roles_export() -> Export:
    cp = Export()
    cp.network("lan", "10.10.0.0/16")
    cp.network("office", "10.10.5.0/24")
    cp.network("plc", "10.30.1.0/24")
    cp.network("admins", "10.10.9.0/24")
    cp.group("ad_group_Operators")
    cp.group("ad_group_Vendors")
    cp.role("operators", ["lan"], ["ad_group_Operators"], machines="any")
    cp.role("operators-office", ["office"], ["ad_group_Operators"])
    cp.role("vendors", "any", ["ad_group_Vendors"])
    cp.role("anyone-office", ["office"], "any")
    cp.role("signed-in", ["lan"], "all identified")
    return cp


def test_an_access_role_is_networks_with_users() -> None:
    cp = _roles_export()
    cp.layer("Main", [cp.rule("PLC", ["operators"], ["plc"]), cp.rule("Who", ["signed-in"], ["plc"])])
    report = Report()
    rules = cp.policy(report).rules
    assert [(r.name, r.sources, r.users) for r in rules] == [("PLC", ["lan"], ["ad_group_Operators"]), ("Who", ["lan"], ["known-user"])]
    finding = report.item("rule", "PLC").findings[0]
    assert finding.code == "ACCESS_ROLE" and "ad_group_Operators" in finding.message
    assert "known-user" in report.item("rule", "Who").findings[0].message
    # PAN-OS matches users; the others say they do not, and write the rule disabled.
    assert "source-user ad_group_Operators" in cli.convert(cp.policy(), "panos", Report())
    other = Report()
    cli.convert(cp.policy(), "fortios", other)
    assert other.item("rule", "PLC").disabled and "USER_MATCH" in [f.code for f in other.item("rule", "PLC").findings]


def test_roles_of_different_users_are_never_merged() -> None:
    cp = _roles_export()
    cp.layer("Main", [cp.rule("PLC", ["operators", "vendors", "admins", "operators-office", "anyone-office"], ["plc"], uid="u-plc",
                              hits=hit(5, 1751328000, 1759190400))])  # fmt: skip
    rules = cp.policy().rules
    assert [(r.name, r.sources, r.users) for r in rules] == [
        ("PLC", ["admins", "office"], [ANY]),  # the plain address and the role of any user
        ("PLC (operators, operators-office)", ["lan", "office"], ["ad_group_Operators"]),
        ("PLC (vendors)", [ANY], ["ad_group_Vendors"]),
    ]
    # Each keeps the identity and the counter of the rule it came from, and its action.
    assert {r.source_ids["checkpoint.rule_uid"] for r in rules} == {"u-plc"} and all(r.hits and r.hits.count == 5 for r in rules)
    assert all(r.action == Action.ALLOW for r in rules)


def test_a_role_of_any_user_on_any_network_is_any_source() -> None:
    cp = _roles_export()
    cp.role("everyone", "any", "any")
    cp.layer("Main", [cp.rule("Open", ["everyone", "operators"], ["plc"])])
    rules = cp.policy().rules
    assert [(r.name, r.sources, r.users) for r in rules] == [("Open", [ANY], [ANY])]


def test_roles_the_model_cannot_hold_stay_unsupported() -> None:
    cp = _roles_export()
    cp.role("laptops", ["lan"], "any", machines=[{"uid": "m1", "name": "corp-laptops", "type": "CpmiAdGroup"}])
    cp.role("vpn-only", ["lan"], ["ad_group_Operators"], remote_access_client={"uid": "c1", "name": "Endpoint VPN", "type": "Global"})
    cp.add("bare", "access-role")  # only the reference is in the export
    cases = {"Machines": ["laptops"], "Client": ["vpn-only"], "Bare": ["bare"]}
    cp.layer("Main", [cp.rule(name, source, ["plc"]) for name, source in cases.items()]
             + [cp.rule("Dest", ["lan"], ["operators"]), dict(cp.rule("Negated", ["operators"], ["plc"]), **{"source-negate": True})])  # fmt: skip
    report = Report()
    policy = cp.policy(report)
    for rule in policy.rules:
        members = rule.destinations if rule.name == "Dest" else rule.sources
        assert rule.users == [ANY], rule.name
        assert any(policy.addresses[m].kind.value == "unsupported" for m in members if m in policy.addresses), rule.name
    out = Report()
    cli.convert(cp.policy(), "panos", out)
    assert all(out.item("rule", rule.name).disabled for rule in policy.rules)  # never wider: written disabled


def test_users_of_the_rule_applying_an_inline_layer_reach_its_rules() -> None:
    cp = _roles_export()
    cp.add("Inner", "access-layer")
    cp.layer("Main", [cp.rule("Apply", ["operators"], ["plc"], "Inner Layer", uid="u-apply", inline_layer="Inner")])
    cp.layers.append({"uid": "uid-Inner", "name": "Inner", "from": 1, "to": 3, "total": 3, "rulebase": [
        cp.rule("Any user", ["Any"], ["plc"]), cp.rule("Same", ["operators"], ["plc"]), cp.rule("Others", ["vendors"], ["plc"])]})  # fmt: skip
    report = Report()
    rules = {r.name: r for r in cp.policy(report).rules}
    assert rules["Apply / Any user"].users == ["ad_group_Operators"]
    assert rules["Apply / Same"].users == ["ad_group_Operators"] and not rules["Apply / Same"].unsupported
    assert any("users limited both" in text for text in rules["Apply / Others"].unsupported)
    assert rules["Apply (cleanup of Inner)"].users == ["ad_group_Operators"]  # the cleanup is for the same traffic
    assert "ACCESS_ROLE" in [f.code for f in report.item("rule", "Apply / Any user").findings]


def test_a_split_rule_matches_what_the_cell_matched() -> None:
    """Oracle: the cell as Check Point reads it (any member: an address, or a role's networks for its users) against the model."""
    cp = _roles_export()
    cp.network("guest", "10.10.200.0/24")
    roles = {"operators": (["10.10.0.0/16"], {"op"}), "operators-office": (["10.10.5.0/24"], {"op"}), "vendors": ([], {"ven"}),
             "anyone-office": (["10.10.5.0/24"], None), "signed-in": (["10.10.0.0/16"], {"op", "ven", "other"})}  # fmt: skip
    plain = {"admins": "10.10.9.0/24", "guest": "10.10.200.0/24"}
    rng = random.Random(13)
    names = list(roles) + list(plain)
    for _ in range(60):
        cell = rng.sample(names, rng.randint(1, 4))
        cp.layers = []
        cp.layer("Main", [cp.rule("R", cell, ["plc"])])
        rules = cp.policy().rules
        users = {"op": "ad_group_Operators", "ven": "ad_group_Vendors", "other": "someone"}
        for source in ("10.10.5.7", "10.10.9.1", "10.10.200.3", "10.10.77.1", "192.0.2.9"):
            for user in (None, "op", "ven", "other"):
                expected = False
                for member in cell:
                    if member in plain:
                        expected |= _inside(source, plain[member])
                    else:
                        networks, who = roles[member]
                        expected |= (not networks or any(_inside(source, n) for n in networks)) and (who is None or user in who)
                got = any(_model_matches(cp, rule, source, users.get(user or "", None)) for rule in rules)
                assert got == expected, (cell, source, user)


def _inside(address: str, network: str) -> bool:
    import ipaddress

    return ipaddress.ip_address(address) in ipaddress.ip_network(network)


def _model_matches(cp: Export, rule: Rule, source: str, user: Optional[str]) -> bool:
    nets = {name: f"{o['subnet4']}/{o['mask-length4']}" for name, o in cp.objects.items() if o["type"] == "network"}
    if rule.users != [ANY]:
        if user is None or (user not in rule.users and not (rule.users == ["known-user"])):
            return False
    return rule.sources == [ANY] or any(_inside(source, nets[m]) for m in rule.sources)


# -- hit counts of a Check Point rulebase ---------------------------------------------------------------


def test_check_point_hits_are_read_in_seconds() -> None:
    cp = Export()
    cp.network("lan", "10.10.0.0/16")
    cp.layer("Main", [cp.rule("Used", ["lan"], hits=hit(3809576, 1568109939, 1580473988)), cp.rule("Idle", ["lan"], hits=hit(0)),
                      cp.rule("Odd", ["lan"], hits={"value": "many"}), cp.rule("None", ["lan"])])  # fmt: skip
    report = Report()
    rules = {r.name: r for r in cp.policy(report).rules}
    used = rules["Used"].hits
    assert used is not None and (used.count, used.first_hit, used.last_hit, used.counting_since) == (3809576, 1568109939, 1580473988, None)
    assert rules["Idle"].hits is not None and rules["Idle"].hits.count == 0 and rules["Idle"].hits.first_hit is None
    assert rules["Odd"].hits is None and rules["None"].hits is None
    assert "HITS_NOT_READ" in [note.code for note in report.notes]


# -- the audit -------------------------------------------------------------------------------------------


def _audited(policy: Policy, **thresholds: int) -> List[audit.Finding]:
    config = audit.AuditConfig()
    for key, value in thresholds.items():
        setattr(config, key, value)
    return [f for f in audit.run(policy, config).before if f.check in ("UNUSED_RULE", "NO_USAGE_EVIDENCE")]


def _policy(*rules: Tuple[str, Action, Optional[HitCount], Dict[str, str]]) -> Policy:
    policy = Policy(vendor="panos")
    for name, action, count, ids in rules:
        rule = Rule(name=name, origin=name, action=action, description="x", sources=["10.0.0.0/8"], services=["svc"])
        rule.hits, rule.source_ids = count, ids
        policy.rules.append(rule)
    from fwshift.model import Protocol, Service, ServiceEntry

    policy.services["svc"] = Service("svc", [ServiceEntry(Protocol.TCP, "443")])
    return policy


DAY = 86400


def test_a_zero_counter_is_an_unused_allow_rule() -> None:
    ids = {"panos.name": "x"}
    policy = _policy(("idle", Action.ALLOW, HitCount(0, None, None, 100 * DAY, read_until=300 * DAY), ids),
                     ("busy", Action.ALLOW, HitCount(9, 150 * DAY, 300 * DAY, 100 * DAY, read_until=300 * DAY), ids),
                     ("deny", Action.DENY, HitCount(0, None, None, 100 * DAY, read_until=300 * DAY), ids))  # fmt: skip
    found = _audited(policy)
    assert [(f.check, f.name) for f in found] == [("UNUSED_RULE", "idle")]
    assert "from 1970-04-11 to 1970-10-28 at least" in found[0].message and found[0].level == audit.Level.MEDIUM
    assert found[0].to_dict()["source_ids"] == ids


def test_a_counter_that_has_not_counted_long_is_no_evidence() -> None:
    ids = {"panos.name": "x"}
    policy = _policy(("new", Action.ALLOW, HitCount(0, None, None, 280 * DAY, read_until=300 * DAY), ids),
                     ("old", Action.ALLOW, HitCount(0, None, None, 100 * DAY, read_until=300 * DAY), ids),
                     ("busy", Action.ALLOW, HitCount(4, 290 * DAY, 300 * DAY, read_until=300 * DAY), ids))  # fmt: skip
    found = {f.name: f for f in _audited(policy)}
    assert found["new"].check == "NO_USAGE_EVIDENCE" and "20 day(s)" in found["new"].message
    assert found["old"].check == "UNUSED_RULE"
    found = {f.name: f for f in _audited(policy, usage_days=10)}
    assert found["new"].check == "UNUSED_RULE"


def test_a_rule_without_a_counter_among_counted_rules_is_named() -> None:
    policy = _policy(("counted", Action.ALLOW, HitCount(3), {"panos.name": "a"}), ("missing", Action.ALLOW, None, {"panos.name": "b"}),
                     ("added", Action.ALLOW, None, {"checkpoint.implicit": "cleanup"}))  # fmt: skip
    found = _audited(policy)
    assert [(f.check, f.name) for f in found] == [("NO_USAGE_EVIDENCE", "missing")]
    assert _audited(_policy(("plain", Action.ALLOW, None, {}))) == []  # no counters at all: nothing to say
    policy.rules[1].enabled = False
    assert _audited(policy) == []


def test_an_incomplete_zero_proves_nothing() -> None:
    policy = _policy(("r", Action.ALLOW, HitCount(0, complete=False, note="one firewall of several"), {"panos.name": "r"}))
    found = _audited(policy)
    assert [f.check for f in found] == ["NO_USAGE_EVIDENCE"] and "One firewall of several" in found[0].message


def test_unused_rule_can_be_disabled_by_a_conversion(tmp_path: Any) -> None:
    cp = Export()
    cp.network("lan", "10.10.0.0/16")
    created = {"creation-time": {"posix": 1735689600000, "iso-8601": "2025-01-01T00:00+0000"}}
    cp.layer("Main", [cp.rule("Idle", ["lan"], hits=hit(0), meta_info=created),
                      cp.rule("Busy", ["lan"], ["lan"], hits=hit(7, 1751328000, 1759190400))])  # fmt: skip
    path = tmp_path / "cp.json"
    path.write_bytes(cp.data())
    out, report = tmp_path / "out.set", tmp_path / "report.json"
    assert cli.main(["convert", str(path), "--to", "panos", "-o", str(out), "--report-json", str(report), "-q",
                     "--audit-action", "UNUSED_RULE=disable"]) == 0  # fmt: skip
    data = json.loads(report.read_text(encoding="utf-8"))
    idle = next(item for item in data["items"] if item["name"] == "Idle")
    assert "AUDIT_DISABLED" in [f["code"] for f in idle["findings"]]
    assert "rulebase security rules Idle disabled yes" in out.read_text(encoding="utf-8")


# -- files of counters -------------------------------------------------------------------------------


def _panos_policy(scope: str = "vsys1", names: Sequence[str] = ("web", "mail", "old")) -> Policy:
    policy = Policy(vendor="panos", scope=scope)
    for name in names:
        rule = Rule(name=name, origin=name, description="x")
        rule.source_ids = {"panos.name": name}
        policy.rules.append(rule)
    return policy


def _panos_answer(rules: Dict[str, Tuple[int, ...]], vsys: str = "vsys1") -> bytes:
    keys = ("hit-count", "last-hit-timestamp", "last-reset-timestamp", "first-hit-timestamp", "rule-creation-timestamp",
            "rule-modification-timestamp")  # fmt: skip
    entries = "".join(f'<entry name="{name}"><latest>yes</latest>' + "".join(f"<{k}>{v}</{k}>" for k, v in zip(keys, values)) + "</entry>"
                      for name, values in rules.items())  # fmt: skip
    return (f'<response status="success"><result><rule-hit-count><vsys><entry name="{vsys}"><rule-base><entry name="security">'
            f"<rules>{entries}</rules></entry></rule-base></entry></vsys></rule-hit-count></result></response>").encode()  # fmt: skip


def test_panos_rule_hit_count_answer() -> None:
    policy = _panos_policy()
    answer = _panos_answer({"web": (24, 1750872135, 0, 1745953063, 1745952837, 1745952837),
                            "mail": (0, 0, 1749000000, 0, 1745952837, 1748000000), "intrazone-default": (5, 0, 0, 0, 0, 0),
                            "gone": (3, 0, 0, 0, 0, 0)})  # fmt: skip
    applied = hits.apply(policy, answer, "fw1.xml")
    web, mail, old = (rule.hits for rule in policy.rules)
    assert web is not None and (web.count, web.first_hit, web.last_hit, web.counting_since) == (24, 1745953063, 1750872135, 1745952837)
    assert mail is not None and mail.count == 0 and mail.counting_since == 1749000000  # the latest of reset, creation, change
    assert old is None and applied.counted == 2 and applied.unknown == ["gone"]  # (the default rules are not rules of the file)
    assert "'gone'" in applied.text() and web.read_from == "fw1.xml (vsys vsys1)"


def test_panos_answers_that_do_not_fit_are_refused() -> None:
    answer = _panos_answer({"web": (1, 0, 0, 0, 0, 0)})
    with pytest.raises(FwshiftError, match="virtual system vsys2, for a policy of vsys1"):
        hits.apply(_panos_policy(), _panos_answer({"web": (1, 0, 0, 0, 0, 0)}, "vsys2"), "f")
    with pytest.raises(FwshiftError, match="for a policy read from fortios"):
        hits.apply(Policy(vendor="fortios"), answer, "f")
    panorama = b'<response status="success"><result><rule-hit-count><device-group><entry name="DG"/></device-group></rule-hit-count></result></response>'
    with pytest.raises(FwshiftError, match="answer of Panorama"):
        hits.apply(_panos_policy(), panorama, "f")
    for bad, message in ((answer.replace(b"<hit-count>1<", b"<hit-count>x<"), "not a whole number"),
                         (answer.replace(b'status="success"', b'status="error"'), "status 'error'"),
                         (b"<!DOCTYPE x>" + answer, "DOCTYPE"), (answer.replace(b"</entry></rules>", b'</entry><entry name="web"><hit-count>1'
                          b"</hit-count></entry></rules>"), "twice"),
                         (b"<response status='success'><result/></response>", "no <rule-hit-count>")):  # fmt: skip
        with pytest.raises(ParseError, match=message):
            hits.apply(_panos_policy(), bad, "f")
    with pytest.raises(FwshiftError, match="neither"):
        hits.apply(_panos_policy(), b"hit-count 5", "f")


def test_counters_of_one_firewall_for_a_device_group_are_incomplete() -> None:
    policy = _panos_policy("device-group DG")
    hits.apply(policy, _panos_answer({"web": (0, 0, 0, 0, 1, 1), "mail": (0, 0, 0, 0, 1, 1), "old": (2, 0, 0, 0, 1, 1)}, "vsys1"), "fw1")
    assert all(rule.hits is not None and not rule.hits.complete for rule in policy.rules)
    # A second firewall: added up, and still not known to be every firewall.
    hits.apply(policy, _panos_answer({"web": (3, 9, 0, 5, 1, 1)}, "vsys1"), "fw2")
    web = policy.rules[0].hits
    assert web is not None and web.count == 3 and web.read_from == "fw1 (vsys vsys1) and fw2 (vsys vsys1)" and not web.complete
    assert [f.check for f in _audited(policy)] == ["NO_USAGE_EVIDENCE"]  # mail: zero on the firewalls that were asked


def _fortios_policy(scope: str = "root") -> Policy:
    policy = Policy(vendor="fortios", scope=scope)
    for policyid, uuid in ((1, "u-1"), (2, ""), (3, "u-3")):
        rule = Rule(name=f"p{policyid}", origin=f"p{policyid}", description="x")
        rule.source_ids = {"fortios.policyid": str(policyid), **({"fortios.uuid": uuid} if uuid else {})}
        policy.rules.append(rule)
    return policy


def _fortios_answer(entries: List[Dict[str, Any]], vdom: str = "root") -> Dict[str, Any]:
    return {"http_method": "GET", "results": entries, "vdom": vdom, "path": "firewall", "name": "policy", "status": "success",
            "serial": "FGVM000000000000", "version": "v7.2.8", "build": 1639}  # fmt: skip


def test_fortios_monitor_answer() -> None:
    policy = _fortios_policy()
    entries = [{"policyid": 1, "uuid": "u-1", "hit_count": 1222, "first_used": 1617911276, "last_used": 1618340453, "bytes": 1},
               {"policyid": 2, "hit_count": 0},
               {"policyid": 3, "uuid": "other-device", "hit_count": 0, "last_used": 0}]  # fmt: skip
    applied = hits.apply(policy, json.dumps(_fortios_answer(entries)).encode(), "fg.json")
    one, two, three = (rule.hits for rule in policy.rules)
    assert one is not None and (one.count, one.first_hit, one.last_hit) == (1222, 1617911276, 1618340453)
    assert two is not None and two.count == 0 and "restarts" in two.note
    assert three is None and applied.unknown == ["other-device"]  # same policy ID, another uuid: another rule
    # Several VDOMs: the one of the policy.
    both = [_fortios_answer([{"policyid": 1, "hit_count": 5}], "dmz"), _fortios_answer([{"policyid": 1, "hit_count": 6}], "root")]
    policy = _fortios_policy()
    hits.apply(policy, json.dumps(both).encode(), "fg.json")
    assert policy.rules[0].hits is not None and policy.rules[0].hits.count == 6


def test_fortios_answers_that_do_not_fit_are_refused() -> None:
    ok = [{"policyid": 1, "hit_count": 1}]
    cases = [
        (json.dumps(_fortios_answer(ok, "dmz")), FwshiftError, "VDOM dmz, for a policy of VDOM root"),
        (json.dumps([_fortios_answer(ok, "a"), _fortios_answer(ok, "b")]), FwshiftError, "several VDOMs"),
        (json.dumps(dict(_fortios_answer(ok), status="error")), ParseError, "status 'error'"),
        (json.dumps(_fortios_answer([{"hit_count": 1}])), ParseError, "without a policy ID"),
        (json.dumps(_fortios_answer([{"policyid": 1}])), ParseError, "hit_count"),
        (json.dumps(_fortios_answer([{"policyid": 1, "hit_count": 1, "last_used": "yesterday"}])), ParseError, "not a time"),
        (json.dumps(_fortios_answer(ok + ok)), ParseError, "twice"),
        (json.dumps({"policies": []}), ParseError, "not the answer"),
        ("{", ParseError, "not valid JSON"),
    ]
    for text, error, message in cases:
        with pytest.raises(error, match=message):
            hits.apply(_fortios_policy(), text.encode(), "f")
    with pytest.raises(FwshiftError, match="for a policy read from panos"):
        hits.apply(Policy(vendor="panos"), json.dumps(_fortios_answer(ok)).encode(), "f")


def test_audit_command_with_counters(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    conf = tmp_path / "fg.conf"
    conf.write_text("""config firewall address
    edit "lan"
        set subnet 10.10.0.0 255.255.0.0
    next
end
config firewall policy
    edit 1
        set name "used"
        set uuid u-1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "lan"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
        set comments "x"
    next
    edit 2
        set name "idle"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "lan"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "SSH"
        set comments "x"
    next
end
""", encoding="utf-8")
    counters = tmp_path / "hits.json"
    counters.write_text(json.dumps(_fortios_answer([{"policyid": 1, "uuid": "u-1", "hit_count": 4, "first_used": 1609459200,
                                                     "last_used": 1618340453}, {"policyid": 2, "hit_count": 0},
                                                    {"policyid": 9, "hit_count": 1}])), encoding="utf-8")  # fmt: skip
    assert cli.main(["audit", str(conf), "--hits", str(counters)]) == 0
    text = capsys.readouterr().out
    assert "hit counters: " in text and "counters of 2 rule(s)" in text and "'9'" in text
    # FortiOS does not say since when a counter counts: no proof, until the user says.
    assert "NO_USAGE_EVIDENCE: rule 'idle' has a hit counter of 0" in text and "--hits-since" in text and "UNUSED_RULE" not in text
    assert cli.main(["audit", str(conf), "--hits", str(counters), "--hits-since", "2021-01-01"]) == 0
    text = capsys.readouterr().out
    assert "UNUSED_RULE: rule 'idle'" in text and "from 2021-01-01 (from --hits-since) to 2021-04-13" in text
    assert "UNUSED_RULE: rule 'used'" not in text
    assert cli.main(["audit", str(conf), "--hits", str(counters), "--hits-since", "2021-01-01", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["hit_counters"] and [f["source_ids"] for f in data["findings"] if f["check"] == "UNUSED_RULE"] == [{"fortios.policyid": "2"}]
    # --hits on a conversion audits it, and says so in the report.
    report = tmp_path / "r.json"
    assert cli.main(["convert", str(conf), "--to", "panos", "-o", str(tmp_path / "o"), "--report-json", str(report), "-q",
                     "--hits", str(counters)]) == 0  # fmt: skip
    notes = json.loads(report.read_text(encoding="utf-8"))["notes"]
    assert any(note["code"] == "HIT_COUNTERS" for note in notes)
    assert parse_literal("10.10.0.0/16") is not None


def test_an_unsupported_role_says_why() -> None:
    cp = _roles_export()
    cp.add("bare", "access-role")
    cp.role("laptops", ["lan"], "any", machines="all identified")
    cp.add("Any group", "CpmiAdGroup")
    cp.objects["Any group"]["name"] = "ANY"  # a group whose name is the word for every user
    cp.role("keyword", ["lan"], ["Any group"])
    cp.layer("Main", [cp.rule("A", ["bare"], ["plc"]), cp.rule("B", ["laptops"], ["plc"]), cp.rule("C", ["keyword"], ["plc"]),
                      cp.rule("D", ["lan"], ["operators"])])  # fmt: skip
    addresses = cp.policy().addresses
    assert "show access-roles details-level full" in addresses["bare"].raw
    assert "limits the machines" in addresses["laptops"].raw
    assert "with a user or group named 'any'" in addresses["keyword"].raw
    assert "in a destination or a negated source" in addresses["operators"].raw


# -- found in review (round 21) ----------------------------------------------------------------------


def test_an_inline_layer_that_ends_in_a_rule_for_some_users_keeps_its_cleanup() -> None:
    """F1: a last rule of the layer that is limited to users does not match everything the layer receives."""
    cp = _roles_export()
    cp.role("ops-anywhere", "any", ["ad_group_Operators"])
    cp.add("Inner", "access-layer", implicit_cleanup_action="drop")
    cp.layer("Main", [cp.rule("Apply", ["Any"], ["Any"], "Inner Layer", inline_layer="Inner"), cp.rule("Allow rest", ["Any"])])
    cp.layers.append({"uid": "uid-Inner", "name": "Inner", "from": 1, "to": 1, "total": 1,
                      "rulebase": [cp.rule("Operators", ["ops-anywhere"], ["Any"])]})  # fmt: skip
    rules = cp.policy().rules
    assert [r.name for r in rules] == ["Apply / Operators", "Apply (cleanup of Inner)", "Allow rest"]
    assert rules[1].action == Action.DROP and rules[1].users == [ANY]
    # The same users as the rule applying the layer: that is everything the layer receives.
    cp.layers[0]["rulebase"][0] = cp.rule("Apply", ["ops-anywhere"], ["Any"], "Inner Layer", inline_layer="Inner")
    assert [r.name for r in cp.policy().rules] == ["Apply / Operators", "Allow rest"]
    # And at the end of the main layer: a rule for some users is no cleanup rule.
    cp.layers = []
    cp.layer("Main", [cp.rule("Operators", ["ops-anywhere"], ["Any"])], cleanup="accept")
    report = Report()
    policy = cp.policy(report)
    assert policy.default_interzone == Action.ALLOW and "IMPLICIT_CLEANUP" in [n.code for n in report.notes]


def test_a_zero_without_a_known_start_proves_nothing() -> None:
    """F2: Check Point without the creation of the rule, PAN-OS without any timestamp: NO_USAGE_EVIDENCE."""
    cp = Export()
    cp.network("lan", "10.10.0.0/16")
    cp.layer("Main", [cp.rule("Idle", ["lan"], hits=hit(0)), cp.rule("Busy", ["lan"], ["lan"], hits=hit(7, 1751328000, 1759190400))])
    found = _audited(cp.policy())
    assert [f.check for f in found] == ["NO_USAGE_EVIDENCE"] and "does not tell since when" in found[0].message
    config = audit.AuditConfig(hits_since=audit.day_of("2025-01-01", "test"))
    found = [f for f in audit.run(cp.policy(), config).before if f.check == "UNUSED_RULE"]
    # From the user's day, but no earlier than the counts of the export reach back.
    assert [f.name for f in found] == ["Idle"] and "from 2025-07-01 to 2025-09-30" in found[0].message
    # No rule ever hit: how far back the counts reach is not known, even with the creation of the rule.
    created = {"creation-time": {"posix": 1735689600000}}
    cp.layers = []
    cp.layer("Main", [cp.rule("Idle", ["lan"], hits=hit(0), meta_info=created)])
    assert [f.check for f in _audited(cp.policy())] == ["NO_USAGE_EVIDENCE"]
    policy = _panos_policy(names=("web", "old"))
    hits.apply(policy, _panos_answer({"web": (5, 1750872135, 0, 1745953063, 1745952837, 1745952837), "old": (0, 0, 0, 0, 0, 0)}), "f")
    assert [(f.check, f.name) for f in _audited(policy)] == [("NO_USAGE_EVIDENCE", "old")]


def test_each_answer_is_measured_up_to_its_own_reading() -> None:
    """F3: a zero in an early answer is not stretched to the time of a later one; a rule one answer leaves out is incomplete."""
    policy = _panos_policy(names=("old", "web"))
    dec1, jan15, jun30 = 1764547200, 1768435200, 1782777600
    hits.apply(policy, _panos_answer({"old": (0, 0, 0, 0, dec1, dec1), "web": (3, jan15, 0, dec1, dec1, dec1)}), "fw1")
    hits.apply(policy, _panos_answer({"web": (9, jun30, 0, dec1, dec1, dec1)}), "fw2")
    old = policy.rules[0].hits
    assert old is not None and old.read_until == jan15
    found = {f.name: f for f in _audited(policy)}
    assert found["old"].check == "NO_USAGE_EVIDENCE" and "45 day(s)" in found["old"].message


def test_a_rule_that_one_of_several_answers_leaves_out_is_not_proven_unused(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    conf = tmp_path / "fw.xml"
    conf.write_text("""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
      <zone><entry name="a"/><entry name="b"/></zone><rulebase><security><rules>
        <entry name="old"><from><member>a</member></from><to><member>b</member></to><source><member>10.1.0.0/16</member></source>
          <destination><member>any</member></destination><application><member>any</member></application><service><member>service-https</member></service>
          <action>allow</action><description>x</description></entry>
      </rules></security></rulebase></entry></vsys></entry></devices></config>""", encoding="utf-8")
    dec1 = 1764547200
    (tmp_path / "fw1.xml").write_bytes(_panos_answer({"old": (0, 0, 0, 0, dec1, dec1), "x": (1, dec1 + 200 * DAY, 0, 0, 0, 0)}))
    (tmp_path / "fw2.xml").write_bytes(_panos_answer({"y": (1, dec1 + 200 * DAY, 0, 0, 0, 0)}))
    assert cli.main(["audit", str(conf), "--hits", str(tmp_path / "fw1.xml")]) == 0
    assert "UNUSED_RULE: rule 'old'" in capsys.readouterr().out
    assert cli.main(["audit", str(conf), "--hits", str(tmp_path / "fw1.xml"), "--hits", str(tmp_path / "fw2.xml")]) == 0
    text = capsys.readouterr().out
    assert "UNUSED_RULE" not in text and "1 of the 2 answers given do not count it" in text
    # F11: one answer given twice would be counted twice.
    assert cli.main(["audit", str(conf), "--hits", str(tmp_path / "fw1.xml"), "--hits", str(tmp_path / "fw1.xml")]) == 1
    assert "given twice" in capsys.readouterr().err


def test_digits_that_are_not_ascii_are_refused() -> None:
    """F4: '²'.isdigit() is true, int('²') fails."""
    answer = _panos_answer({"web": (1, 0, 0, 0, 0, 0)})
    for digit in ("²", "٣"):
        with pytest.raises(ParseError, match="not a whole number"):
            hits.apply(_panos_policy(), answer.replace(b"<hit-count>1<", f"<hit-count>{digit}<".encode()), "f")


def test_an_install_on_target_the_export_does_not_resolve_is_still_a_target() -> None:
    """F5: never "every target"."""
    cp = Export()
    cp.network("lan", "10.10.0.0/16")
    entry = cp.rule("R", ["lan"])
    entry["install-on"] = ["uid-not-in-the-export"]
    cp.layer("Main", [entry])
    report = Report()
    rule = cp.policy(report).rules[0]
    assert rule.targets == ["uid-not-in-the-export"] and "DEVICE_TARGET" in [f.code for f in report.item("rule", "R").findings]


def test_user_names_that_are_words_of_pan_os_are_refused() -> None:
    """F6: 'unknown' and 'pre-logon' mean every user not signed in, every user before signing in."""
    for word in ("unknown", "Pre-Logon"):
        cp = _roles_export()
        cp.group(word)
        cp.role("odd", ["lan"], [word])
        cp.layer("Main", [cp.rule("R", ["odd"], ["plc"])])
        policy = cp.policy()
        assert policy.rules[0].users == [ANY] and policy.addresses["odd"].kind.value == "unsupported", word


def test_an_answer_without_a_vdom_matches_a_vdom_policy_by_uuid_only() -> None:
    """F7: policy IDs are per VDOM."""
    policy = _fortios_policy("dmz")
    answer = _fortios_answer([{"policyid": 1, "uuid": "u-1", "hit_count": 3}, {"policyid": 2, "hit_count": 0}], "")
    del answer["vdom"]
    applied = hits.apply(policy, json.dumps(answer).encode(), "f")
    assert policy.rules[0].hits is not None and policy.rules[1].hits is None and applied.unknown == ["2"]


def test_a_remote_access_client_given_by_uid() -> None:
    """F10: the uid of the Any object is any client."""
    cp = _roles_export()
    cp.role("ops-uid", ["lan"], ["ad_group_Operators"], remote_access_client=cp.objects["Any"]["uid"])
    cp.layer("Main", [cp.rule("R", ["ops-uid"], ["plc"])])
    assert cp.policy().rules[0].users == ["ad_group_Operators"]
