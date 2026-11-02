# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AWS Network Firewall in tier 1 (0.41.7): a managed firewall, no image, no login.

The run: Terraform makes the network and the test hosts (``tier1/awsnfw``); FWShift's script makes the firewall
policy and its rule group (the output of ``--to aws-network-firewall``, run as it is, with ``--target-policy`` the run's
id); a second apply makes the firewall with that policy, its endpoint in a subnet of its own, and routes that send each
zone's traffic to the other zones to the endpoint (routes more specific than the VPC's own: both halves of a connection
pass it). Then the probes, and the read-back: ``describe-firewall-policy`` and ``describe-rule-group``, which FWShift
reads. The teardown destroys what Terraform made, firewall first, then deletes the policy and the rule group the script
made.

Network Firewall does no NAT: FWShift does not convert the lab policy's NAT rules (``NAT_NOT_CONVERTED``), and the plan
has no NAT checks, as for the security groups of tier 1. Traffic inside a zone does not pass the firewall (the VPC
delivers it within the subnet), as in tier 3. Written from AWS's documentation of Network Firewall and its Terraform
provider; never run before its first lab run.
"""

from __future__ import annotations

import json
import sys
import re
import time
from pathlib import Path
from typing import Any, Dict, List

import labplan
import labrun
import readback
import tier1
from labrun import LabError, Runner

NAME = "aws-network-firewall"


def conversion(run_id: str) -> "tuple[str, List[str]]":
    return NAME, labplan.zone_options() + ["--target-policy", run_id]


def _aws(region: str) -> List[str]:
    return ["--region", region]


def policy_arn(runner: Runner, region: str, name: str) -> str:
    return runner.run(["aws", "network-firewall", "describe-firewall-policy", *_aws(region), "--firewall-policy-name", name,
                       "--query", "FirewallPolicyResponse.FirewallPolicyArn", "--output", "text"],
                      fake=f"arn:aws:network-firewall:{region}:000000000000:firewall-policy/{name}").strip()  # fmt: skip


def wait_in_sync(runner: Runner, region: str, name: str, minutes: float = 20) -> None:
    """Until the firewall is READY and its policy IN_SYNC on its endpoint (fw.txt keeps every answer)."""
    if runner.dry_run:
        return
    deadline = time.time() + minutes * 60
    log = runner.work / "fw.txt"
    while True:
        answer = runner.run(["aws", "network-firewall", "describe-firewall", *_aws(region), "--firewall-name", name, "--query",
                             "FirewallStatus.[Status,ConfigurationSyncStateSummary]", "--output", "text"], check=False, quiet=True)  # fmt: skip
        with log.open("a", encoding="utf-8") as out:
            out.write(f"{time.strftime('%H:%M:%S')} {answer.strip()}\n")
        if "READY" in answer and "IN_SYNC" in answer:
            return
        if time.time() > deadline:
            raise LabError(f"the firewall was not READY and IN_SYNC within {minutes:g} minutes (fw.txt)")
        time.sleep(20)


def export(runner: Runner, region: str, name: str, loaded: str = "") -> str:
    """The policy and its rule group as AWS holds them: the describe answers one after the other, as FWShift reads them
    (and the VPC, for HOME_NET). In a dry run: answers made from the script's own JSON."""
    policy = runner.run(["aws", "network-firewall", "describe-firewall-policy", *_aws(region), "--firewall-policy-name", name, "--output", "json"],
                        quiet=True, fake="")  # fmt: skip
    group = runner.run(["aws", "network-firewall", "describe-rule-group", *_aws(region), "--rule-group-name", f"{name}-rules", "--type", "STATEFUL",
                        "--output", "json"], quiet=True, fake="")  # fmt: skip
    if runner.dry_run:
        return dry_answers(loaded, name)
    return policy.strip() + "\n" + group.strip() + "\n"


def dry_answers(script: str, name: str) -> str:
    """The describe answers a dry run stands in for, from the JSON documents FWShift's script would send (its heredocs):
    the rule group's document, and the policy's, with the group's ARN where the script puts it (${G1})."""
    documents = re.findall(r"<<'?FWSHIFT_JSON'?\n(.*?)\nFWSHIFT_JSON", script, re.S)
    arn = f"arn:aws:network-firewall:dryrun:000000000000:stateful-rulegroup/{name}-rules"
    group = next((json.loads(d) for d in documents if '"RulesSource"' in d), {})
    policy = next((json.loads(d.replace("${G1}", arn).replace("$G1", arn)) for d in documents if '"StatelessDefaultActions"' in d and "RuleGroupReferences" in d),
                  next((json.loads(d) for d in documents if '"StatelessDefaultActions"' in d), {}))  # fmt: skip
    answers = [{"FirewallPolicyResponse": {"FirewallPolicyName": name, "FirewallPolicyArn": f"arn:aws:network-firewall:dryrun:000000000000:firewall-policy/{name}"},
                "FirewallPolicy": policy},
               {"RuleGroupResponse": {"RuleGroupName": f"{name}-rules", "RuleGroupArn": arn, "Type": "STATEFUL"}, "RuleGroup": group}]  # fmt: skip
    return "\n".join(json.dumps(a, indent=1) for a in answers) + "\n"


def run(runner: Runner, args: Any) -> bool:
    region = args.region or "eu-west-1"
    name = runner.work.name
    labrun.save_state(runner.work, tier="tier1", firewall=NAME, region=region, policy=name)
    if not runner.dry_run:
        labrun.need("ssh", "ssh-keygen", "scp", "aws")
    key = labrun.ssh_key(runner, "ed25519")
    out = runner.work / "policy.sh"
    target, options = conversion(name)
    report = labrun.fwshift(runner, target, out, options)
    data = labplan.build_plan(target, report, through_target_inside_zone=False, refused_means="blocked")
    labplan.save(runner.work / "plan.json", data)
    tf = tier1.Terraform(runner, labrun.ROOT / "tier1" / "awsnfw", tier1.terraform_binary(args.terraform))
    variables = {"region": region, **tier1.common_variables(runner, args, key)}
    try:
        tf.apply(variables)
        labrun.save_state(runner.work, script_ran=True)  # (from here on the teardown looks for the policy and its rule group)
        runner.run(["sh", str(out)], env={"AWS_OPTS": f"--region {region}"}, timeout=900)
        arn = policy_arn(runner, region, name)
        if not arn.startswith("arn:"):
            raise LabError(f"the firewall policy {name} was not found after FWShift's script: {arn[:200]!r}")
        tf.apply({**variables, "firewall_policy_arn": arn})
        outputs = tf.output({"vpc_id": "vpc-dryrun", "endpoint": "vpce-0dryrun", "user": "ec2-user", "hosts": tier1.fake_hosts({"interface": "eni-{name}"})})
        if not str(outputs.get("endpoint", "")).startswith("vpce-"):
            raise LabError(f"the firewall has no endpoint to route to: {outputs.get('endpoint')!r}")
        wait_in_sync(runner, region, name)
        warm_up(runner, key, outputs, data)
        passed = False
        try:
            passed = tier1.probe_hosts(runner, key, outputs, data)
            return passed
        finally:
            if not isinstance(sys.exc_info()[1], KeyboardInterrupt):
                readback.safely(runner, lambda: readback.check(runner, NAME, out, export(runner, region, name, out.read_text(encoding="utf-8")),
                                                               readback.Export(NAME, (), lambda text: text, "json"), options))  # fmt: skip
                with labrun.shielded():
                    diagnose(runner, region, name, key, outputs, data, passed)
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown(runner, tf)


# -- what the firewall saw (0.42.2): the second run blocked every connection too, with a rule for the replies ----------

# A few flows the lab policy allows, of each kind, for the control probes.
CONTROL = ("in10>dmz10:tcp/22", "in10>dmz10:tcp/80", "in10>dmz10:icmp/8", "in10>out10:udp/123", "in10>out10:tcp/80", "dmz10>out10:tcp/8005")
CONTROL_RULES = 'pass ip any any <> any any (msg:"fwlab-control"; sid:1; rev:1;)\n'
METRICS = ("ReceivedPackets", "PassedPackets", "DroppedPackets")


def _metrics(runner: Runner, region: str, name: str) -> List[str]:
    """The firewall's own counters (CloudWatch, namespace AWS/NetworkFirewall), summed over the last two hours."""
    found = runner.run(["aws", "cloudwatch", "list-metrics", *_aws(region), "--namespace", "AWS/NetworkFirewall", "--dimensions",
                        f"Name=FirewallName,Value={name}", "--output", "json"], check=False, quiet=True, fake='{"Metrics": []}')  # fmt: skip
    try:
        metrics = json.loads(found or "{}").get("Metrics", [])
    except ValueError:
        return [f"  list-metrics: {found[:300]!r} {runner.last_stderr[:300]}"]
    end = time.time()
    lines = []
    for metric in sorted(metrics, key=lambda m: (m.get("MetricName", ""), json.dumps(m.get("Dimensions", []), sort_keys=True))):
        if metric.get("MetricName") not in METRICS:
            continue
        dims = [f"Name={d['Name']},Value={d['Value']}" for d in metric.get("Dimensions", [])]
        answer = runner.run(["aws", "cloudwatch", "get-metric-statistics", *_aws(region), "--namespace", "AWS/NetworkFirewall", "--metric-name",
                             metric["MetricName"], "--dimensions", *dims, "--start-time", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end - 7200)),
                             "--end-time", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end)), "--period", "300", "--statistics", "Sum",
                             "--output", "json"], check=False, quiet=True, fake='{"Datapoints": []}')  # fmt: skip
        try:
            total = sum(point.get("Sum", 0) for point in json.loads(answer or "{}").get("Datapoints", []))
        except ValueError:
            total = -1
        shown = ", ".join(f"{d['Name']}={d['Value']}" for d in metric.get("Dimensions", []) if d["Name"] != "FirewallName")
        lines.append(f"  {metric['MetricName']:<16} {total:>10.0f}  ({shown})")
    return lines or ["  (CloudWatch has no counters of the firewall yet: they come a few minutes late)"]


def _routes(runner: Runner, region: str, vpc: str) -> List[str]:
    answer = runner.run(["aws", "ec2", "describe-route-tables", *_aws(region), "--filters", f"Name=vpc-id,Values={vpc}", "--output", "json"],
                        check=False, quiet=True, fake='{"RouteTables": []}')  # fmt: skip
    try:
        tables = json.loads(answer or "{}").get("RouteTables", [])
    except ValueError:
        return [f"  describe-route-tables: {answer[:300]!r}"]
    lines = []
    for table in tables:
        subnets = [a.get("SubnetId", "main" if a.get("Main") else "?") for a in table.get("Associations", [])]
        lines.append(f"  {table.get('RouteTableId')} ({', '.join(subnets) or 'no subnet'}):")
        for route in table.get("Routes", []):
            target = route.get("VpcEndpointId") or route.get("GatewayId") or route.get("NetworkInterfaceId") or "?"
            lines.append(f"    {route.get('DestinationCidrBlock', route.get('DestinationIpv6CidrBlock', '?')):<18} -> {target:<24} {route.get('State', '')}")
    return lines


def _probe_subset(runner: Runner, key: Path, outputs: Dict[str, Any], data: Dict[str, Any], folder: str) -> Dict[str, str]:
    """The CONTROL flows probed again, from a folder of their own (its plan, its results): flow id -> what was seen."""
    sub = labrun.Runner(runner.work / folder, dry_run=runner.dry_run, echo=runner.echo)
    sub.work.mkdir(exist_ok=True)
    if (runner.work / "known_hosts").exists():
        (sub.work / "known_hosts").write_text((runner.work / "known_hosts").read_text(encoding="utf-8"), encoding="utf-8")
    flows = [f for f in data["flows"] if f["id"] in CONTROL]
    subset = {**data, "flows": flows}
    labplan.save(sub.work / "plan.json", subset)
    sources = {f["src"] for f in flows}
    hosts = {n: h for n, h in outputs["hosts"].items() if h["test_ip"] in sources}
    results = labrun.probe(sub, tier1.targets(sub, key, outputs["user"], hosts), subset, tier1.scp_copier(sub, key, outputs["user"], outputs["hosts"]))
    runner.log.extend(sub.log)
    return {r["id"]: r.get("observed", "?") for r in results}


def warm_up(runner: Runner, key: Path, outputs: Dict[str, Any], data: Dict[str, Any], minutes: float = 15) -> None:
    """Until the firewall forwards (warmup.txt): READY and IN_SYNC come before its endpoint takes traffic. The third run
    (0.42.2) showed it: the firewall's counters had 0 packets received during the probes, which started at once, and 40
    of the control probes minutes later. The CONTROL flows, which the lab policy allows, are probed every minute until
    one passes."""
    if runner.dry_run:
        return
    labrun.wait_ready(runner, tier1.targets(runner, key, outputs["user"], outputs["hosts"]))
    started = time.time()
    log = runner.work / "warmup.txt"
    while True:
        seen = _probe_subset(runner, key, outputs, data, "warmup")
        through = sum(1 for flow in CONTROL if seen.get(flow) == "passed")
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%H:%M:%S')} ({time.time() - started:.0f} s) {through} of {len(CONTROL)} passed\n")
        if through:
            return
        if time.time() - started > minutes * 60:
            with log.open("a", encoding="utf-8") as handle:
                handle.write(f"none passed within {minutes:g} minutes: the probes go on (diagnose.txt says more)\n")
            return
        time.sleep(60)


def _replace_rules(runner: Runner, region: str, name: str, rules: str, file_name: str) -> str:
    """The rule group's rules replaced (variables and options kept), and the firewall in sync again; returns the rules
    there were, or an error line."""
    answer = runner.run(["aws", "network-firewall", "describe-rule-group", *_aws(region), "--rule-group-name", f"{name}-rules", "--type", "STATEFUL",
                         "--output", "json"], check=False, quiet=True, fake='{"UpdateToken": "t", "RuleGroup": {"RulesSource": {"RulesString": ""}}}')  # fmt: skip
    try:
        described = json.loads(answer)
    except ValueError:
        raise LabError(f"describe-rule-group: {answer[:300]!r} {runner.last_stderr[:300]}")
    group = dict(described.get("RuleGroup", {}))
    before = str(group.get("RulesSource", {}).get("RulesString", ""))
    group["RulesSource"] = {"RulesString": rules}
    path = runner.work / file_name
    path.write_text(json.dumps(group, indent=1), encoding="utf-8")
    runner.run(["aws", "network-firewall", "update-rule-group", *_aws(region), "--rule-group-name", f"{name}-rules", "--type", "STATEFUL",
                "--update-token", described.get("UpdateToken", ""), "--rule-group", f"file://{path}"], quiet=True, fake="{}")  # fmt: skip
    if not runner.dry_run:
        time.sleep(30)  # (the firewall says IN_SYNC until it has noticed the change)
    wait_in_sync(runner, region, name)
    if not runner.dry_run:
        time.sleep(30)
    return before


def _replies_test(runner: Runner, region: str, name: str, key: Path, outputs: Dict[str, Any], data: Dict[str, Any]) -> List[str]:
    """The converted rules without the first rule, which passes the replies (flow:to_client), and the CONTROL flows
    again: whether a pass rule for the first packet passes the whole connection under strict order and aws:drop_strict
    (then the reply rule, and FWShift's per-packet reading of such a policy, are not needed)."""
    answer = runner.run(["aws", "network-firewall", "describe-rule-group", *_aws(region), "--rule-group-name", f"{name}-rules", "--type", "STATEFUL",
                         "--query", "RuleGroup.RulesSource.RulesString", "--output", "text"], check=False, quiet=True, fake="")  # fmt: skip
    kept = "".join(line + "\n" for line in answer.splitlines() if line.strip() and "fwshift-replies" not in line)
    if not runner.dry_run and kept == answer.strip() + "\n":
        return ["  (the rule group holds no rule for the replies: nothing to compare)"]
    _replace_rules(runner, region, name, kept or CONTROL_RULES, "replies-test-rulegroup.json")
    seen = _probe_subset(runner, key, outputs, data, "replies-test")
    lines = [f"  {flow:<24} {seen.get(flow, 'not sent')}" for flow in CONTROL]
    through = sum(1 for flow in CONTROL if seen.get(flow) == "passed")
    lines.append(f"  {through} of {len(CONTROL)} passed without the rule for the replies: "
                 + ("a pass rule for the first packet passes the whole connection (the reply rule and the per-packet reading are not needed)"
                    if through == len(CONTROL) else "the replies need a rule of their own (FWShift's per-packet reading)"
                    if through == 0 else "some passed and some did not: look at each"))  # fmt: skip
    return lines


def _control(runner: Runner, region: str, name: str, key: Path, outputs: Dict[str, Any], data: Dict[str, Any]) -> List[str]:
    """The same firewall with a rule group that passes everything, and a few allowed flows again: whether a connection
    gets through the firewall at all (routes, endpoint), apart from the converted rules."""
    _replace_rules(runner, region, name, CONTROL_RULES, "control-rulegroup.json")
    seen = _probe_subset(runner, key, outputs, data, "control")
    lines = [f"  {flow:<24} {seen.get(flow, 'not sent')}" for flow in CONTROL]
    through = sum(1 for flow in CONTROL if seen.get(flow) == "passed")
    lines.append(f"  {through} of {len(CONTROL)} passed with a rule group that passes everything: "
                 + ("the firewall forwards; what blocked them is in the converted rules or in how the firewall reads them" if through
                    else "nothing gets through the firewall at all: the routes or the endpoint, not the rules"))  # fmt: skip
    return lines


def diagnose(runner: Runner, region: str, name: str, key: Path, outputs: Dict[str, Any], data: Dict[str, Any], passed: bool) -> None:
    """What the firewall saw (diagnose.txt): the routes of the VPC, the firewall's counters, the CONTROL flows without
    the rule for the replies and, after a run that failed, with a rule group that passes everything."""
    lines = ["== the route tables of the VPC", *_routes(runner, region, str(outputs.get("vpc_id", "")))]
    if not runner.dry_run:
        time.sleep(120)  # (CloudWatch's counters come a few minutes late)
    lines += ["", "== the firewall's counters after the probes", *_metrics(runner, region, name)]
    lines += ["", "== the converted rules without the rule for the replies (flow:to_client)", *_replies_test(runner, region, name, key, outputs, data)]
    if not passed:
        lines += ["", "== control: the rule group replaced by one rule that passes everything", *_control(runner, region, name, key, outputs, data)]
    if not runner.dry_run:
        time.sleep(120)
    lines += ["", "== the firewall's counters at the end", *_metrics(runner, region, name)]
    text = "\n".join(lines) + "\n"
    (runner.work / "diagnose.txt").write_text(text, encoding="utf-8")
    sys.stdout.write("\n" + text)


def _delete_made(runner: Runner, region: str, name: str, problems: List[str]) -> None:
    """The policy, then its rule group (a group a policy still names is not deleted: tried again for two minutes, while
    the policy's deletion goes on), and the wait until the group is gone."""
    policy = ["aws", "network-firewall", "delete-firewall-policy", *_aws(region), "--firewall-policy-name", name]
    group = ["aws", "network-firewall", "delete-rule-group", *_aws(region), "--rule-group-name", f"{name}-rules", "--type", "STATEFUL"]
    answer = runner.run(policy, check=False, quiet=True)
    if runner.last_stderr and "ResourceNotFound" not in runner.last_stderr:
        problems.append(f"delete-firewall-policy {name}: {runner.last_stderr.strip()[:200]} {answer[:100]}")
    deadline = time.time() + 120
    while True:
        runner.run(group, check=False, quiet=True)
        failed = runner.last_stderr.strip()
        if runner.dry_run or "ResourceNotFound" in failed:
            return
        if not failed:
            break
        if time.time() > deadline:
            problems.append(f"delete-rule-group {name}-rules: {failed[:200]}")
            return
        time.sleep(15)
    # The deletion goes on after the answer (the group is DELETING, and listed, for a while: the run of 0.41.7 reported
    # it as left behind): until it is gone, for five minutes at most.
    describe = ["aws", "network-firewall", "describe-rule-group", *_aws(region), "--rule-group-name", f"{name}-rules", "--type",
                "STATEFUL", "--query", "RuleGroupResponse.RuleGroupStatus", "--output", "text"]  # fmt: skip
    deadline = time.time() + 300
    while time.time() < deadline:
        runner.run(describe, check=False, quiet=True)
        if "ResourceNotFound" in runner.last_stderr:
            return
        time.sleep(15)


def teardown(runner: Runner, tf: "tier1.Terraform") -> None:
    state = labrun.load_state(runner.work)
    region, name, problems = state.get("region", "eu-west-1"), state.get("policy", runner.work.name), []
    try:
        tf.destroy()  # (the firewall, then the routes and the network)
    except LabError as error:
        problems.append(str(error))
    if state.get("script_ran"):
        _delete_made(runner, region, name, problems)
    found = [] if runner.dry_run else leftovers(runner, region, name)
    if not found and not problems:
        labrun.save_state(runner.work, torn_down=True)
    tier1.report_leftovers(found + problems, runner.work.name)


def leftovers(runner: Runner, region: str, name: str) -> List[str]:
    out = tier1.leftovers_aws(runner, region)
    for what, args, key in (("firewall", ["list-firewalls"], "Firewalls"), ("firewall policy", ["list-firewall-policies"], "FirewallPolicies"),
                            ("rule group", ["list-rule-groups"], "RuleGroups")):  # fmt: skip
        text = runner.run(["aws", "network-firewall", *args, *_aws(region), "--output", "json"], check=False, quiet=True)
        try:
            listed = json.loads(text or "{}").get(key, [])
        except ValueError:
            out.append(f"could not list the {what}s of the run: look for {name}")
            continue
        out += [f"{what} {item.get('Name') or item.get('FirewallName')}" for item in listed
                if str(item.get("Name") or item.get("FirewallName") or "").startswith(name)]  # fmt: skip
    return out


