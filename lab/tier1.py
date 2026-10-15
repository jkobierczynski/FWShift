# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tier 1 of the lab: the cloud-native targets (AWS security groups, Azure network security groups, Google Cloud
network firewall policies). No firewall image: the converted policy is applied to the test hosts' own network."""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import labplan
import labrun
from labrun import LabError, Runner, Target


def terraform_binary(given: Optional[str]) -> str:
    if given:
        return given
    for name in ("terraform", "tofu"):
        if shutil.which(name):
            return name
    return "terraform"


class Terraform:
    """One module, copied into the work folder so that its state stays with the run."""

    def __init__(self, runner: Runner, module: Path, binary: str) -> None:
        self.runner, self.binary = runner, binary
        self.dir = runner.work / "terraform"
        if not (self.dir / "main.tf").exists():
            self.dir.mkdir(exist_ok=True)
            shutil.copy(module / "main.tf", self.dir / "main.tf")
        self.applied = (self.dir / "terraform.tfstate").exists() or (self.dir / "terraform.tfvars.json").exists()

    def apply(self, variables: Dict[str, Any]) -> None:
        (self.dir / "terraform.tfvars.json").write_text(json.dumps(variables, indent=1), encoding="utf-8")
        self.runner.run([self.binary, f"-chdir={self.dir}", "init", "-input=false", "-no-color"], timeout=900)
        self.applied = True  # (from here on, destroy: a failed apply may have made part of it)
        self.runner.run([self.binary, f"-chdir={self.dir}", "apply", "-auto-approve", "-input=false", "-no-color"], timeout=3600)

    def output(self, fake: Dict[str, Any]) -> Dict[str, Any]:
        out = self.runner.run([self.binary, f"-chdir={self.dir}", "output", "-json", "-no-color"], fake=json.dumps({k: {"value": v} for k, v in fake.items()}))
        values = {k: v["value"] for k, v in json.loads(out).items()}
        labrun.save_state(self.runner.work, outputs=values)
        return values

    def destroy(self) -> None:
        if self.applied:
            if not (self.dir / ".terraform").exists() and not self.runner.dry_run:  # (a later lab.py destroy, or the plugins removed)
                self.runner.run([self.binary, f"-chdir={self.dir}", "init", "-input=false", "-no-color"], timeout=900)
            self.runner.run([self.binary, f"-chdir={self.dir}", "destroy", "-auto-approve", "-input=false", "-no-color"], timeout=3600)


def host_variables(gateway: str = "first") -> Dict[str, Dict[str, str]]:
    """The hosts as the modules take them, with their first-boot script. Tier 1 routes between the test subnets
    through the cloud's own router (the first address of each subnet); tier 3 through the firewall (.4)."""
    out = {}
    for host in labplan.HOSTS:
        net = labplan.ZONES[host.zone]
        gw = str(ipaddress.ip_network(net).network_address + (1 if gateway == "first" else 4))
        out[host.name] = {"zone": host.zone, "ip": host.ip, "user_data": labrun.host_init(host.ip, gw, net)}
    return out


def fake_hosts(extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return {h.name: {"mgmt_ip": f"192.0.2.{20 + i}", "test_ip": h.ip, **{k: v.format(name=h.name) for k, v in (extra or {}).items()}}
            for i, h in enumerate(labplan.HOSTS)}  # fmt: skip


def targets(runner: Runner, key: Path, user: str, hosts: Dict[str, Any]) -> List[Target]:
    known = runner.work / "known_hosts"
    return [Target(name, h["test_ip"], labrun.ssh_prefix(key, user, h["mgmt_ip"], known)) for name, h in hosts.items()]


def scp_copier(runner: Runner, key: Path, user: str, hosts: Dict[str, Any]) -> Callable[[Target, Path], Tuple[str, str]]:
    known = runner.work / "known_hosts"

    def copy(target: Target, plan_file: Path) -> Tuple[str, str]:
        host = hosts[target.name]["mgmt_ip"]
        runner.run(["scp", "-q", "-i", str(key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known}",
                    str(plan_file), f"{user}@{host}:/tmp/fwlab-plan.json"], timeout=120)  # fmt: skip
        return "/opt/fwlab/probe.py", "/tmp/fwlab-plan.json"

    return copy


def probe_hosts(runner: Runner, key: Path, outputs: Dict[str, Any], data: Dict[str, Any]) -> bool:
    hosts = targets(runner, key, outputs["user"], outputs["hosts"])
    if not runner.dry_run:
        labrun.wait_ready(runner, hosts)
    results = labrun.probe(runner, hosts, data, scp_copier(runner, key, outputs["user"], outputs["hosts"]))
    return labrun.finish(runner, data, results)


def conversion(cloud: str, run_id: str) -> Tuple[str, List[str]]:
    """(target, options) of the conversion a run of tier 1 makes."""
    inside = [x for z in labplan.ZONES for x in ("--inside-zone", z)]
    if cloud == "gcp":
        return "gcp", labplan.zone_options() + ["--target-policy", run_id]
    return cloud, labplan.zone_options() + inside + ["--target-prefix", f"{run_id}-"]


def prepare(runner: Runner, cloud: str, out_name: str) -> Tuple[Path, Path, Dict[str, Any]]:
    """The run's key, the conversion and the plan (security groups and NSGs act on each interface, so flows inside a
    zone pass them; they never answer with a reset, so a reset came from the host behind them)."""
    key = labrun.ssh_key(runner)
    out = runner.work / out_name
    target, options = conversion(cloud, runner.work.name)
    report = labrun.fwshift(runner, target, out, options)
    data = labplan.build_plan(target, report, through_target_inside_zone=True, refused_means="passed")
    labplan.save(runner.work / "plan.json", data)
    return key, out, data


def common_variables(runner: Runner, args: Any, key: Path) -> Dict[str, Any]:
    return {"run_id": runner.work.name, "admin_cidr": labrun.admin_cidr(args.admin_cidr, runner, getattr(args, "allow_wide_admin", False)),
            "ssh_public_key": key.with_suffix(".pub").read_text().strip(), "zones": labplan.ZONES, "hosts": host_variables()}  # fmt: skip


def report_leftovers(found: List[str], run_id: str) -> None:
    if found:
        print(f"\n*** RUN {run_id} LEFT THESE BEHIND, and they may cost money: ***\n  " + "\n  ".join(found) +
              f"\n  try again: python3 lab/lab.py destroy {run_id}\n")  # fmt: skip


# -- AWS ---------------------------------------------------------------------------------------------------------


def parse_attach(script: str) -> Dict[str, List[ipaddress.IPv4Network]]:
    """'# attach NAME: addresses' lines of the AWS output -> group name -> networks."""
    out: Dict[str, List[ipaddress.IPv4Network]] = {}
    for line in script.splitlines():
        found = re.match(r"# attach (\S+): (.*)$", line)
        if found:
            out[found.group(1)] = labrun.addresses(found.group(2))
    return out


def parse_created(stderr: str) -> Dict[str, str]:
    """'created NAME sg-...' lines the AWS output writes -> group name -> id."""
    return {m.group(1): m.group(2) for m in re.finditer(r"^created (\S+) (sg-[0-9a-z]+)$", stderr, re.M)}


def groups_for(address: str, attach: Dict[str, List[ipaddress.IPv4Network]]) -> List[str]:
    ip = ipaddress.ip_address(address)
    return sorted(name for name, nets in attach.items() if any(ip in net for net in nets))


def run_aws(runner: Runner, args: Any) -> bool:
    region = args.region or "eu-west-1"
    labrun.save_state(runner.work, tier="tier1", firewall="aws", region=region)
    if not runner.dry_run:
        labrun.need("ssh", "ssh-keygen", "scp", "aws")
    key, out, data = prepare(runner, "aws", "groups.sh")
    tf = Terraform(runner, labrun.ROOT / "tier1" / "aws", terraform_binary(args.terraform))
    try:
        tf.apply({"region": region, **common_variables(runner, args, key)})
        outputs = tf.output({"vpc_id": "vpc-dryrun", "hold_group": "sg-hold", "user": "ec2-user", "hosts": fake_hosts({"interface": "eni-{name}"})})
        attach = parse_attach(out.read_text(encoding="utf-8"))
        fake = "\n".join(f"created {name} sg-{i:08x}" for i, name in enumerate(attach)) + "\n"
        try:
            runner.run(["sh", str(out)], env={"VPC_ID": outputs["vpc_id"], "AWS_OPTS": f"--region {region}"}, timeout=1800)
        finally:
            created = parse_created(fake if runner.dry_run else runner.last_stderr)
            labrun.save_state(runner.work, created=created)
            if created:  # (so that the run's tag finds them as well)
                runner.run(["aws", "ec2", "create-tags", "--region", region, "--resources", *created.values(), "--tags",
                            f"Key=fwshift-lab,Value={runner.work.name}"], check=False)  # fmt: skip
        missing = [n for n in attach if n not in created]
        if missing:
            raise LabError("the AWS output did not say the ids of groups " + ", ".join(missing))
        for name, host in outputs["hosts"].items():
            names = groups_for(host["test_ip"], attach)
            if not names:
                raise LabError(f"no converted group is for {host['test_ip']} ({name})")
            runner.run(["aws", "ec2", "modify-network-interface-attribute", "--region", region, "--network-interface-id", host["interface"],
                        "--groups", *[created[n] for n in names]])  # fmt: skip
        return probe_hosts(runner, key, outputs, data)
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown_aws(runner, tf)


def _aws_groups(runner: Runner, region: str, vpc: str) -> List[str]:
    listed = runner.run(["aws", "ec2", "describe-security-groups", "--region", region, "--filters", f"Name=vpc-id,Values={vpc}",
                         "Name=tag:fwshift,Values=generated", "--query", "SecurityGroups[].GroupId", "--output", "json"],
                        check=False, fake=json.dumps(sorted(labrun.load_state(runner.work).get("created", {}).values())))  # fmt: skip
    try:
        return list(json.loads(listed or "[]"))
    except ValueError:
        return []


def _aws_delete_groups(runner: Runner, region: str, groups: List[str], problems: List[str]) -> None:
    for group in groups:  # (rules that name other groups keep those alive: take every rule off first)
        rules = runner.run(["aws", "ec2", "describe-security-group-rules", "--region", region, "--filters", f"Name=group-id,Values={group}",
                            "--query", "SecurityGroupRules[].[SecurityGroupRuleId,IsEgress]", "--output", "json"], check=False, fake="[]")  # fmt: skip
        try:
            listed = json.loads(rules or "[]")
        except ValueError:
            listed = []
        for egress, verb in ((False, "revoke-security-group-ingress"), (True, "revoke-security-group-egress")):
            ids = [r[0] for r in listed if bool(r[1]) == egress]
            if ids:
                try:
                    runner.run(["aws", "ec2", verb, "--region", region, "--group-id", group, "--security-group-rule-ids", *ids])
                except LabError as error:
                    problems.append(str(error))
    for group in groups:
        try:
            runner.run(["aws", "ec2", "delete-security-group", "--region", region, "--group-id", group])
        except LabError as error:
            problems.append(str(error))


def teardown_aws(runner: Runner, tf: Terraform) -> None:
    state = labrun.load_state(runner.work)
    region, outputs, problems = state.get("region", "eu-west-1"), state.get("outputs", {}), []
    groups: List[str] = []
    if outputs:
        for host in outputs.get("hosts", {}).values():
            try:
                runner.run(["aws", "ec2", "modify-network-interface-attribute", "--region", region, "--network-interface-id", host["interface"],
                            "--groups", outputs["hold_group"]])  # fmt: skip
            except LabError as error:
                problems.append(str(error))
        groups = _aws_groups(runner, region, outputs["vpc_id"])
        _aws_delete_groups(runner, region, groups, problems)
    try:
        tf.destroy()
    except LabError as error:
        # The interfaces are gone with their instances now: the groups that could not go before can go now.
        if groups:
            problems = []
            _aws_delete_groups(runner, region, _aws_groups(runner, region, outputs["vpc_id"]), problems)
        try:
            tf.destroy()
        except LabError as again:
            problems += [str(error), str(again)]
    found = [] if runner.dry_run else leftovers_aws(runner, region)
    if not found and not problems:
        labrun.save_state(runner.work, torn_down=True)
    report_leftovers(found + problems, runner.work.name)


def leftovers_aws(runner: Runner, region: str) -> List[str]:
    tag = f"Name=tag:fwshift-lab,Values={runner.work.name}"
    out: List[str] = []
    for what, args in (("instance", ["describe-instances", "--filters", tag, "Name=instance-state-name,Values=pending,running,stopping,stopped",
                                     "--query", "Reservations[].Instances[].InstanceId"]),
                       ("Elastic IP", ["describe-addresses", "--filters", tag, "--query", "Addresses[].AllocationId"]),
                       ("VPC", ["describe-vpcs", "--filters", tag, "--query", "Vpcs[].VpcId"]),
                       ("security group", ["describe-security-groups", "--filters", tag, "--query", "SecurityGroups[].GroupId"])):  # fmt: skip
        text = runner.run(["aws", "ec2", *args, "--region", region, "--output", "json"], check=False, quiet=True)
        try:
            out += [f"{what} {item}" for item in json.loads(text or "[]")]
        except ValueError:
            out.append(f"could not list the {what}s of the run: look for tag fwshift-lab={runner.work.name}")
    return out


# -- Azure -------------------------------------------------------------------------------------------------------


def nsg_for_zones(template: Dict[str, Any]) -> Dict[str, str]:
    """Zone -> the converted NSG for its subnet, from the networks the template's metadata lists."""
    networks: Dict[str, List[str]] = template.get("metadata", {}).get("networks", {})
    out = {}
    for zone, net in labplan.ZONES.items():
        found = [name for name, nets in networks.items() if net in nets]
        if len(found) != 1:
            raise LabError(f"the template has {len(found)} groups for zone {zone} ({net})")
        out[zone] = found[0]
    return out


def run_azure(runner: Runner, args: Any) -> bool:
    location = args.region or "westeurope"
    labrun.save_state(runner.work, tier="tier1", firewall="azure", region=location)
    if not runner.dry_run:
        labrun.need("ssh", "ssh-keygen", "scp", "az")
    key, out, data = prepare(runner, "azure", "nsgs.json")
    tf = Terraform(runner, labrun.ROOT / "tier1" / "azure", terraform_binary(args.terraform))
    try:
        tf.apply({"location": location, **common_variables(runner, args, key)})
        outputs = tf.output({"resource_group": runner.work.name, "vnet": runner.work.name, "user": "azureuser", "hosts": fake_hosts()})
        group = outputs["resource_group"]
        runner.run(["az", "deployment", "group", "create", "--only-show-errors", "-g", group, "--name", "fwshift-lab", "--template-file", str(out),
                    "--mode", "Incremental", "-o", "none"], timeout=1800)  # fmt: skip
        for zone, nsg in nsg_for_zones(json.loads(out.read_text(encoding="utf-8"))).items():
            runner.run(["az", "network", "vnet", "subnet", "update", "--only-show-errors", "-g", group, "--vnet-name", outputs["vnet"], "-n", zone,
                        "--network-security-group", nsg, "-o", "none"])  # fmt: skip
        return probe_hosts(runner, key, outputs, data)
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown_azure(runner, tf)


def teardown_azure(runner: Runner, tf: Terraform) -> None:
    problems = []
    try:
        tf.destroy()  # (the resource group goes, with the converted NSGs in it)
    except LabError as error:
        problems.append(str(error))
        runner.run(["az", "group", "delete", "-n", runner.work.name, "--yes"], check=False, timeout=3600)
    found = [] if runner.dry_run else leftovers_azure(runner)
    if not found:
        labrun.save_state(runner.work, torn_down=True)
        problems = []
    report_leftovers(found + problems, runner.work.name)


def leftovers_azure(runner: Runner) -> List[str]:
    out = runner.run(["az", "group", "exists", "-n", runner.work.name], check=False, quiet=True).strip()
    return [] if out == "false" else [f"resource group {runner.work.name} (az group delete -n {runner.work.name} --yes)"]


# -- Google Cloud ------------------------------------------------------------------------------------------------


def run_gcp(runner: Runner, args: Any) -> bool:
    project = args.project or ("dry-run-project" if runner.dry_run else "")
    if not project:
        raise LabError("--project is needed for Google Cloud")
    region = args.region or "europe-west1"
    zone = args.zone or f"{region}-b"
    name = runner.work.name
    labrun.save_state(runner.work, tier="tier1", firewall="gcp", region=region, project=project)
    if not runner.dry_run:
        labrun.need("ssh", "ssh-keygen", "scp", "gcloud")
    key, out, data = prepare(runner, "gcp", "policy.sh")
    tf = Terraform(runner, labrun.ROOT / "tier1" / "gcp", terraform_binary(args.terraform))
    try:
        tf.apply({"project": project, "region": region, "zone": zone, **common_variables(runner, args, key)})
        outputs = tf.output({"test_network": f"{name}-test", "user": "lab", "hosts": fake_hosts()})
        labrun.save_state(runner.work, policy=name)
        runner.run(["sh", str(out)], env={"GCLOUD_OPTS": f"--project {project}"}, timeout=1800)
        runner.run(["gcloud", "compute", "network-firewall-policies", "associations", "create", "--firewall-policy", name, "--network",
                    outputs["test_network"], "--name", name, "--global-firewall-policy", "--project", project, "--quiet"])  # fmt: skip
        return probe_hosts(runner, key, outputs, data)
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown_gcp(runner, tf)


def teardown_gcp(runner: Runner, tf: Terraform) -> None:
    state = labrun.load_state(runner.work)
    project, name, problems = state.get("project", ""), runner.work.name, []
    if state.get("policy"):  # (whether or not its association was made: deleting one that is not there is harmless)
        runner.run(["gcloud", "compute", "network-firewall-policies", "associations", "delete", "--firewall-policy", name, "--name", name,
                    "--global-firewall-policy", "--project", project, "--quiet"], check=False)  # fmt: skip
        runner.run(["gcloud", "compute", "network-firewall-policies", "delete", name, "--global", "--project", project, "--quiet"], check=False)
    try:
        tf.destroy()
    except LabError as error:
        problems.append(str(error))
    found = [] if runner.dry_run else leftovers_gcp(runner, project)
    if not found and not problems:
        labrun.save_state(runner.work, torn_down=True)
    report_leftovers(found + problems, name)


def leftovers_gcp(runner: Runner, project: str) -> List[str]:
    name = runner.work.name
    out: List[str] = []
    for what, args in (("instance", ["instances", "list", f"--filter=labels.fwshift-lab={name}"]),
                       ("network", ["networks", "list", f"--filter=name~^{name}-"]),
                       ("firewall policy", ["network-firewall-policies", "list", "--global", f"--filter=name={name}"])):  # fmt: skip
        text = runner.run(["gcloud", "compute", *args, "--project", project, "--format=value(name)"], check=False, quiet=True)
        out += [f"{what} {line.strip()}" for line in text.splitlines() if line.strip()]
    return out


RUNS = {"aws": run_aws, "azure": run_azure, "gcp": run_gcp}
TEARDOWNS = {"aws": teardown_aws, "azure": teardown_azure, "gcp": teardown_gcp}
MODULES = {"aws": "tier1/aws", "azure": "tier1/azure", "gcp": "tier1/gcp"}
