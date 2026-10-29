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
import re
import time
from typing import Any, List

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
        try:
            return tier1.probe_hosts(runner, key, outputs, data)
        finally:
            readback.safely(runner, lambda: readback.check(runner, NAME, out, export(runner, region, name, out.read_text(encoding="utf-8")),
                                                           readback.Export(NAME, (), lambda text: text, "json"), options))  # fmt: skip
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown(runner, tf)


def _delete_made(runner: Runner, region: str, name: str, problems: List[str]) -> None:
    """The policy, then its rule group (a group a policy still names is not deleted: tried again for two minutes, while
    the policy's deletion goes on)."""
    policy = ["aws", "network-firewall", "delete-firewall-policy", *_aws(region), "--firewall-policy-name", name]
    group = ["aws", "network-firewall", "delete-rule-group", *_aws(region), "--rule-group-name", f"{name}-rules", "--type", "STATEFUL"]
    answer = runner.run(policy, check=False, quiet=True)
    if runner.last_stderr and "ResourceNotFound" not in runner.last_stderr:
        problems.append(f"delete-firewall-policy {name}: {runner.last_stderr.strip()[:200]} {answer[:100]}")
    deadline = time.time() + 120
    while True:
        runner.run(group, check=False, quiet=True)
        failed = runner.last_stderr.strip()
        if runner.dry_run or not failed or "ResourceNotFound" in failed:
            return
        if time.time() > deadline:
            problems.append(f"delete-rule-group {name}-rules: {failed[:200]}")
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


