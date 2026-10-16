# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tier 3 of the lab: firewall images of the AWS Marketplace (pay per hour or trial). One firewall with an interface
in each zone; the converted policy is loaded over SSH with the vendor's CLI, after a base configuration (interface
addresses, the zones) that FWShift does not write."""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import labplan
import labrun
import tier1
from labrun import LabError, Runner

ORDER = ["inside", "dmz", "outside"]  # the firewall's data interfaces, in this order


def _addr(zone: str) -> str:
    return labplan.ZONES[zone].replace(".0/24", ".4")


def _lines(path: Path, comment: str, drop_end: bool = False) -> List[str]:
    """The lines of a conversion without comments; for IOS and ASA without its own `end` (the session ends config mode)."""
    return [line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith(comment) and not (drop_end and line.strip() == "end")]  # fmt: skip


@dataclass
class Vendor:
    name: str
    title: str
    target: str
    ami_pattern: str
    instance_type: str
    user: str
    ready: str  # a command that answers once the CLI is up
    errors: str  # what in the output of the session means a line was refused
    options: List[str] = field(default_factory=list)
    user_data: str = ""
    session: Callable[[Path], List[str]] = lambda out: []
    status: str = "scripted, never run"
    ready_answer: str = r"\S"  # what the answer to `ready` must hold
    success: str = ""  # what the output of the session must hold (a committed configuration), where the CLI says so
    # The Marketplace product codes of the pay-as-you-go image, where its name does not tell it from the image for a licence
    # of your own (VM-Series: BYOL, Bundle 1 and Bundle 2 are all named PA-VM-AWS-*).
    product_codes: Tuple[str, ...] = ()
    # Lines typed before the session, whose answers do not count: the clean-up of what an image may or may not ship with
    # (PAN-OS answers a delete of what is not there with an error, also "Invalid syntax").
    prepare: Callable[[], List[str]] = lambda: []


# -- FortiGate ---------------------------------------------------------------------------------------------------

_FGT_PORTS = {"inside": "port2", "dmz": "port3", "outside": "port4"}


def _fortigate_user_data() -> str:
    lines = ["config system interface"]
    for zone, port in _FGT_PORTS.items():
        lines += [f"    edit {port}", "        set mode static", f"        set ip {_addr(zone)} 255.255.255.0", "        set allowaccess ping", "    next"]
    return "\n".join(lines + ["end", ""])


def _fortigate_session(out: Path) -> List[str]:
    return [*_lines(out, "#"), "exit"]


# -- PAN-OS ------------------------------------------------------------------------------------------------------

_PAN_PORTS = {"inside": "ethernet1/1", "dmz": "ethernet1/2", "outside": "ethernet1/3"}


def _panos_prepare() -> List[str]:
    """Older images ship an example (a virtual wire, zones trust and untrust on ethernet1/1-2, rule1); 11.2 ships none of
    it, and a delete of what is not there is an error. Its own session, committed, whose answers do not count."""
    deletes = ["delete rulebase security rules rule1", "delete network virtual-wire default-vwire", "delete zone trust", "delete zone untrust"]
    return ["set cli scripting-mode on", "set cli pager off", "configure", *deletes, "commit", "exit", "exit"]


def _panos_session(out: Path) -> List[str]:
    base = ["set network profiles interface-management-profile fwlab-ping ping yes"]
    for zone, port in _PAN_PORTS.items():
        base += [f"set network interface ethernet {port} layer3 ip {_addr(zone)}/24",
                 f"set network interface ethernet {port} layer3 interface-management-profile fwlab-ping",
                 f"set network virtual-router default interface {port}", f"set zone {zone} network layer3 {port}"]  # fmt: skip
    return ["set cli scripting-mode on", "set cli pager off", "configure", *base, *_lines(out, "#"), "commit", "exit", "exit"]


# -- Juniper vSRX ------------------------------------------------------------------------------------------------

_SRX_PORTS = {"inside": "ge-0/0/0", "dmz": "ge-0/0/1", "outside": "ge-0/0/2"}


def _vsrx_session(out: Path) -> List[str]:
    base = ["delete security policies", "delete security zones"]
    for zone, port in _SRX_PORTS.items():
        base += [f"delete interfaces {port} unit 0 family inet",  # (the image may give it DHCP)
                 f"set interfaces {port} unit 0 family inet address {_addr(zone)}/24",
                 f"set security zones security-zone {zone} interfaces {port}.0 host-inbound-traffic system-services ping"]  # fmt: skip
    return ["set cli screen-length 0", "configure private", *base, *_lines(out, "#"), "commit check", "commit and-quit", "exit"]


# -- Cisco Catalyst 8000V (IOS XE) -------------------------------------------------------------------------------

_IOS_PORTS = {"inside": "GigabitEthernet2", "dmz": "GigabitEthernet3", "outside": "GigabitEthernet4"}


def ios_zone_members(text: str) -> Dict[str, str]:
    """The interface -> zone lines the IOS output leaves as comments ('! interface X' then '!  zone-member security Z')."""
    out, interface = {}, ""
    for line in text.splitlines():
        found = re.match(r"^! interface (\S+)$", line)
        if found:
            interface = found.group(1)
            continue
        found = re.match(r"^!  zone-member security (\S+)$", line)
        if found and interface:
            out[interface] = found.group(1)
        interface = "" if not found else interface
    return out


def _c8000v_session(out: Path) -> List[str]:
    text = out.read_text(encoding="utf-8")
    members = ios_zone_members(text)
    base = []
    for zone, port in _IOS_PORTS.items():
        base += [f"interface {port}", f" ip address {_addr(zone)} 255.255.255.0", " no shutdown"]
        if port in members:
            base.append(f" zone-member security {members[port]}")
        base.append(" exit")
    return ["terminal length 0", "configure terminal", *_lines(out, "!", drop_end=True), *base, "end", "exit"]


# -- Cisco ASAv --------------------------------------------------------------------------------------------------

_ASA_PORTS = {"inside": ("GigabitEthernet0/0", 100), "dmz": ("GigabitEthernet0/1", 50), "outside": ("GigabitEthernet0/2", 0)}


def _asav_session(out: Path) -> List[str]:
    base = []
    for zone, (port, level) in _ASA_PORTS.items():
        base += [f"interface {port}", f" nameif {zone}", f" security-level {level}", f" ip address {_addr(zone)} 255.255.255.0", " no shutdown",
                 " exit"]  # fmt: skip
    base += ["policy-map global_policy", " class inspection_default", "  inspect icmp", "  exit", " exit"]  # (replies to ping)
    return ["terminal pager 0", "configure terminal", *base, *_lines(out, "!", drop_end=True), "end", "exit"]


_ZONE_NETWORKS = labplan.zone_options()

VENDORS: Dict[str, Vendor] = {
    "fortigate": Vendor("fortigate", "FortiGate-VM (pay as you go)", "fortios", "FortiGate-VM64-AWSONDEMAND*", "c5.xlarge", "admin",
                        "get system status", r"Command fail|command parse error|Unknown action|entry not found|value parse error",
                        [x for z, p in _FGT_PORTS.items() for x in ("--zone-map", f"{z}={p}")], _fortigate_user_data(), _fortigate_session,
                        ready_answer=r"Version:", status="run: passed (FortiOS 8.0.1, 0.32.1)"),  # fmt: skip
    "panos": Vendor("panos", "Palo Alto VM-Series (pay as you go bundle)", "panos", "PA-VM-AWS-*", "m5.xlarge", "admin", "show chassis-ready",
                    r"Invalid syntax|Server error|Commit failed|Validation Error|is not a valid reference|Unknown command", [], "", _panos_session,
                    ready_answer=r"\byes\b", success=r"Configuration committed successfully",
                    product_codes=("e9yfvyj3uag5uo5j2hjikv74n",), prepare=_panos_prepare, status="run: passed (PAN-OS 11.2.15, 0.32.1)"),  # fmt: skip  (PAYG Bundle 1; Bundle 2 is hd44w1chf26uv4p52cdynb2o, by --ami)
    "vsrx": Vendor("vsrx", "Juniper vSRX (pay as you go)", "junos", "junos-vsrx3-x86-64-*", "c5.xlarge", "ec2-user", "show version",
                   r"syntax error|^error:|\nerror:|missing mandatory|unknown command", [], "", _vsrx_session, ready_answer=r"Junos:",
                   success=r"commit complete"),
    "c8000v": Vendor("c8000v", "Cisco Catalyst 8000V, IOS XE (pay as you go)", "ios", "Cisco-C8K-*", "c5.xlarge", "ec2-user",
                     "show version | include uptime", r"% Invalid input|% Incomplete command|% Ambiguous command|% Unknown command",
                     [x for p, i in (("ethernet1/2", "GigabitEthernet2"), ("ethernet1/3", "GigabitEthernet3"), ("ethernet1/1", "GigabitEthernet4"))
                      for x in ("--interface-map", f"{p}={i}")], "", _c8000v_session, ready_answer=r"uptime"),  # fmt: skip
    "asav": Vendor("asav", "Cisco ASAv (pay as you go)", "asa", "asav*", "c5.xlarge", "admin", "show version | include up",
                   r"ERROR:|% Invalid input|% Incomplete command", list(_ZONE_NETWORKS), "", _asav_session,
                   "scripted, never run; the privilege of the admin user after an SSH login with a key is assumed", ready_answer=r" up "),
}

NOT_SCRIPTED = {
    "checkpoint": "needs a management server (a second, large instance) and a first-time setup of about half an hour; the script it gets is mgmt_cli",
    "sonicwall": "SonicWall NSv: the command line is pasted into an SSH session that asks questions on first login",
    "stormshield": "Stormshield EVA: the licence of a pay-as-you-go image and snscli's login are not checked yet",
    "sophos": "Sophos Firewall: the XML API must first be switched on and opened to an address in the web console",
    "barracuda": "Barracuda CloudGen: the REST API needs a token made in Firewall Admin first",
    "watchguard": "WatchGuard: the output is merged into a configuration with Policy Manager, a Windows program",
    "forcepoint": "Forcepoint NGFW: needs a Security Management Center",
    "meraki": "Meraki vMX: needs a Meraki licence and a Dashboard organisation; there is no image to start alone",
}


def find_ami(runner: Runner, region: str, pattern: str, product_codes: Tuple[str, ...] = ()) -> str:
    """The newest x86 Marketplace image of the name, and of the pay-as-you-go product where the vendor names it (the name
    alone does not tell it from the image for a licence of your own): the one found is printed, and --ami (the id your
    subscription's launch page shows) settles it."""
    codes = ["Name=product-code,Values=" + ",".join(product_codes)] if product_codes else []
    out = runner.run(["aws", "ec2", "describe-images", "--region", region, "--owners", "aws-marketplace", "--filters", f"Name=name,Values={pattern}",
                      *codes, "Name=architecture,Values=x86_64", "--query", "sort_by(Images,&CreationDate)[-1].[ImageId,Name,join(',',ProductCodes[].ProductCodeId)]",
                      "--output", "text"], fake="ami-0dryrun\tdry run\t")  # fmt: skip
    fields = out.strip().split("\t")
    if not fields or not fields[0].startswith("ami-"):
        raise LabError(f"no Marketplace image named {pattern} in {region}: subscribe to it first, or give --ami (the id the subscription shows)")
    print(f"image {fields[0]}: {' '.join(fields[1:2])} (product code {fields[2] if len(fields) > 2 else '?'}); give --ami if this is not "
          "the pay-as-you-go image you subscribed to", file=sys.stderr)  # fmt: skip
    labrun.save_state(runner.work, image=fields[0], image_name=" ".join(fields[1:2]), product_code=fields[2] if len(fields) > 2 else "")
    return fields[0]


def describe_ami(runner: Runner, region: str, ami: str) -> None:
    """The name of an image given with --ami, for run.json (which version the firewall ran)."""
    out = runner.run(["aws", "ec2", "describe-images", "--region", region, "--image-ids", ami, "--query",
                      "Images[0].[Name,join(',',ProductCodes[].ProductCodeId)]", "--output", "text"], check=False, fake="dry run\t")  # fmt: skip
    fields = out.strip().split("\t")
    labrun.save_state(runner.work, image=ami, image_name=fields[0] if fields else "", product_code=fields[1] if len(fields) > 1 else "")


def session(runner: Runner, key: Path, user: str, host: str, lines: List[str], errors: str, name: str, success: str = "") -> str:
    """Types the lines into the CLI over SSH (with a terminal: the CLIs want one) and checks what it answered: no line
    refused, and the success line where the CLI writes one. A session that hangs (a failed commit asks before it lets
    the CLI exit) ends after 20 minutes."""
    prefix = labrun.ssh_prefix(key, user, host, runner.work / "known_hosts")
    (runner.work / f"{name}.commands.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = runner.run(prefix[:1] + ["-tt"] + prefix[1:], stdin="\n".join(lines) + "\n", timeout=1200, fake=f"(dry run) {success}")
    (runner.work / f"{name}.txt").write_text(out, encoding="utf-8")
    refused = [line.strip() for line in out.splitlines() if errors and re.search(errors, line)]
    if refused:
        raise LabError(f"the firewall refused {len(refused)} lines (all in {name}.txt), the first: {refused[0][:200]}")
    if success and not re.search(success, out):
        raise LabError(f"the firewall did not say the configuration was committed ({name}.txt)")
    return out


def wait_cli(runner: Runner, key: Path, user: str, host: str, command: str, answer: str, minutes: float) -> None:
    """Until the CLI answers the ready command as it should (PAN-OS: chassis ready, after its first commit)."""
    deadline = time.time() + minutes * 60
    prefix = labrun.ssh_prefix(key, user, host, runner.work / "known_hosts")
    while True:
        try:
            out = runner.run(prefix[:1] + ["-tt"] + prefix[1:], stdin=command + "\nexit\n", quiet=True, timeout=120)
            if re.search(answer, out):
                (runner.work / "ready.txt").write_text(out, encoding="utf-8")  # (the version the firewall runs, for the record)
                return
        except LabError:  # (not up yet: SSH refused or timed out)
            pass
        if time.time() > deadline:
            raise LabError(f"the firewall's CLI did not answer within {minutes:.0f} minutes")
        time.sleep(30)


def conversion(name: str) -> Tuple[str, List[str]]:
    vendor = VENDORS[name]
    return vendor.target, list(vendor.options)


def run_vendor(runner: Runner, args: Any) -> bool:
    vendor = VENDORS[args.firewall]
    region = args.region or "eu-west-1"
    labrun.save_state(runner.work, tier="tier3", firewall=vendor.name, region=region)
    if not runner.dry_run:
        labrun.need("ssh", "ssh-keygen", "scp", "aws")
    key = labrun.ssh_key(runner, "rsa")  # (the key pair of AWS reaches the firewall images, and not all take Ed25519)
    out = runner.work / f"policy.{vendor.target}"
    report = labrun.fwshift(runner, vendor.target, out, vendor.options)
    # Two hosts of one zone talk over their subnet, not through the firewall; a reset can be the firewall's own.
    data = labplan.build_plan(vendor.target, report, through_target_inside_zone=False, refused_means="blocked")
    labplan.save(runner.work / "plan.json", data)
    tf = tier1.Terraform(runner, labrun.ROOT / "tier3" / "aws", tier1.terraform_binary(args.terraform))
    try:
        ami = args.ami or find_ami(runner, region, vendor.ami_pattern, vendor.product_codes)
        if args.ami:
            describe_ami(runner, region, args.ami)
        tf.apply({"region": region, "run_id": runner.work.name, "zone_order": ORDER, "firewall_ami": ami,
                  "firewall_instance_type": args.instance_type or vendor.instance_type, "firewall_user_data": vendor.user_data,
                  **tier1.common_variables(runner, args, key), "hosts": tier1.host_variables(gateway="firewall")})  # fmt: skip
        outputs = tf.output({"firewall_ip": "192.0.2.4", "firewall_instance": "i-0dryrun", "user": "ec2-user", "hosts": tier1.fake_hosts()})
        if not runner.dry_run:
            wait_cli(runner, key, vendor.user, outputs["firewall_ip"], vendor.ready, vendor.ready_answer, args.boot_minutes)
        if vendor.prepare():  # (answers that do not count, kept in prepare.txt)
            session(runner, key, vendor.user, outputs["firewall_ip"], vendor.prepare(), "", "prepare")
        session(runner, key, vendor.user, outputs["firewall_ip"], vendor.session(out), vendor.errors, "load", vendor.success)
        return tier1.probe_hosts(runner, key, outputs, data)
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown(runner, tf)


def teardown(runner: Runner, tf: "tier1.Terraform") -> None:
    region = labrun.load_state(runner.work).get("region", "eu-west-1")
    problems = []
    try:
        tf.destroy()
    except LabError as error:
        problems.append(str(error))
    found = [] if runner.dry_run else tier1.leftovers_aws(runner, region)
    if not found and not problems:
        labrun.save_state(runner.work, torn_down=True)
    tier1.report_leftovers(found + problems, runner.work.name)


def describe() -> str:
    rows = [f"  {v.name:<12} {v.title}: {v.status}" for v in VENDORS.values()]
    rows += [f"  {name:<12} not scripted: {why}" for name, why in NOT_SCRIPTED.items()]
    return "\n".join(rows)

