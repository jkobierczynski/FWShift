# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tier 3 of the lab: firewall images of the AWS Marketplace (pay per hour or trial). One firewall with an interface
in each zone; the converted policy is loaded over SSH with the vendor's CLI, after a base configuration (interface
addresses, the zones) that FWShift does not write."""

from __future__ import annotations

import base64
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence, Tuple

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
    # The size of the run's RSA key, where the firewall cannot take 4096 bits, and the ssh settings the firewall needs
    # (the ASAv: its key on one line of at most 511 characters; its host key and logins only ssh-rsa, which OpenSSH
    # turns down unless it is asked for).
    key_bits: int = 4096
    ssh_options: Tuple[str, ...] = ()
    # Show commands typed after the probes, whose answers do not count (diagnose.txt): what the firewall's own counters
    # say, for a run that went wrong after the firewall was torn down (the sixth ASAv run forwarded nothing).
    diagnose: Callable[[], List[str]] = lambda: []
    # A command whose answer names the data interfaces, for a firewall whose names are read from it ({port1}, ...).
    ports_command: str = ""
    # The CLI's prompt, for a firewall whose lines are typed one at a time, each after its prompt (the ASAv: given them
    # all ahead, it closed the session after one letter of its greeting, and nothing was configured).
    prompt: str = ""


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

# The data interfaces by their order (the second, third and fourth network card of the instance): their names are read
# from the ASA (`show interface ip brief`) before the session, and put in for {port1} to {port3}. The seventh run found
# no GigabitEthernet0/0 on a c5 instance; the dry run, which reads nothing, uses these.
_ASA_PORTS = {"inside": ("{port1}", 100), "dmz": ("{port2}", 50), "outside": ("{port3}", 0)}
_ASA_DRY_PORTS = ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2"]


def asa_data_ports(text: str) -> List[str]:
    """The data interfaces in the answer to `show interface ip brief`, in the order the ASA lists them (not Management)."""
    found = re.findall(r"^\s*((?:\w*Ethernet)\d+/\d+)\s", text, re.M)
    return list(dict.fromkeys(name for name in found if not name.lower().startswith("management")))


def fill_ports(lines: List[str], ports: Sequence[str]) -> List[str]:
    """The session's lines with the interface names read from the firewall in place of {port1}, {port2}, ..."""
    out = []
    for line in lines:
        for number, name in enumerate(ports, 1):
            line = line.replace("{port%d}" % number, name)
        out.append(line)
    left = [line for line in out if re.search(r"\{port\d+\}", line)]
    if left:
        raise LabError(f"the firewall has {len(ports)} data interfaces ({', '.join(ports) or 'none'}), the session needs more: {left[0].strip()}")
    return out


def _asav_user_data() -> str:
    """The Day 0 configuration of the ASAv: without one it boots with SSH off (its first run, 0.36.0: "Connection
    refused" for 30 minutes, the console at the ciscoasa> prompt; its own configuration had "ssh 0 0 management", while
    the management interface had no address yet, and showed no host key made). The management interface by DHCP, a host
    key, SSH on it, and the run's key for admin, who lands in privileged mode. {ssh_key} is the base64 part of the key,
    filled in by the run."""
    return "\n".join([
        "interface Management0/0", " management-only", " nameif management", " security-level 100", " ip address dhcp setroute",
        " no shutdown", "!", "crypto key generate rsa general-keys modulus 2048 noconfirm", "ssh 0.0.0.0 0.0.0.0 management", "ssh timeout 30",
        "aaa authentication ssh console LOCAL", "aaa authorization exec LOCAL auto-enable",
        # Without an enable password the ASA asks for one at the first login, and takes the lines typed as the answers
        # (the fourth run: "The enable password is not set. Please set it now."): one made for the run.
        "enable password {enable_password}",
        "username admin nopassword privilege 15", "username admin attributes", " service-type admin",
        " ssh authentication publickey {ssh_key}", "!", ""])  # fmt: skip


def _asav_session(out: Path) -> List[str]:
    base = []
    for zone, (port, level) in _ASA_PORTS.items():
        base += [f"interface {port}", f" nameif {zone}", f" security-level {level}", f" ip address {_addr(zone)} 255.255.255.0", " no shutdown",
                 " exit"]  # fmt: skip
    base += ["policy-map global_policy", " class inspection_default", "  inspect icmp", "  exit", " exit"]  # (replies to ping)
    return ["terminal pager 0", "configure terminal", *base, *_lines(out, "!", drop_end=True), "end", "exit"]


# All three data interfaces listed (an interface line, not the command typed: a digit after ge-0/0/).
_VSRX_READY = r"(?sm)(?=.*^ge-0/0/0\s)(?=.*^ge-0/0/1\s)(?=.*^ge-0/0/2\s)"


def _vsrx_diagnose() -> List[str]:
    """The vSRX's interfaces, zones, routes, policy hits and sessions, and the configuration as it stands."""
    return ["set cli screen-length 0", "show interfaces terse", "show security zones", "show route", "show security policies", "show security policies hit-count",
            "show security flow session summary", "show configuration | display set", "exit"]  # fmt: skip


def _asav_diagnose() -> List[str]:
    """The ASA's interfaces, routes, rule hits and drops, and two flows the policy passes as the ASA traces them."""
    host = {zone: labplan.ZONES[zone].replace(".0/24", ".10") for zone in ("inside", "dmz", "outside")}
    return ["terminal pager 0", "show version", "show interface ip brief", "show nameif", "show interface", "show running-config interface",
            "show running-config access-group", "show route", "show arp", "show access-list", "show conn count", "show asp drop",
            f"packet-tracer input inside tcp {host['inside']} 40000 {host['dmz']} 22 detailed",
            f"packet-tracer input inside icmp {host['inside']} 8 0 {host['outside']} detailed", "exit"]  # fmt: skip


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
    # Ready once the data interfaces exist: the CLI answers minutes before the forwarding engine makes them (the second
    # vSRX run loaded and probed 10 seconds after `show version` answered, and found no ge-0/0/x). (`| no-more`: the
    # first run stopped at the pager's ---(more)---, which took the `exit` after it for a filter, and every try hung.)
    "vsrx": Vendor("vsrx", "Juniper vSRX (pay as you go)", "junos", "junos-vsrx3-x86-64-*", "c5.xlarge", "ec2-user",
                   "show interfaces terse | match ge-0/0 | no-more", r"syntax error|^error:|\nerror:|missing mandatory|unknown command", [], "",
                   _vsrx_session, ready_answer=_VSRX_READY,
                   success=r"commit complete", diagnose=_vsrx_diagnose,
                   status="run: passed (vSRX 23.4R2-S8.9, appsec PAYG, 0.36.1)"),
    "c8000v": Vendor("c8000v", "Cisco Catalyst 8000V, IOS XE (pay as you go)", "ios", "Cisco-C8K-*", "c5.xlarge", "ec2-user",
                     "show version | include uptime", r"% Invalid input|% Incomplete command|% Ambiguous command|% Unknown command",
                     [x for p, i in (("ethernet1/2", "GigabitEthernet2"), ("ethernet1/3", "GigabitEthernet3"), ("ethernet1/1", "GigabitEthernet4"))
                      for x in ("--interface-map", f"{p}={i}")], "", _c8000v_session, ready_answer=r"uptime"),  # fmt: skip
    "asav": Vendor("asav", "Cisco ASAv (pay as you go)", "asa", "asav*", "c5.xlarge", "admin", "show version | include up",
                   r"ERROR:|% Invalid input|% Incomplete command", list(_ZONE_NETWORKS), _asav_user_data(), _asav_session,
                   "run: passed (ASAv 9.24.10, 0.36.1)",
                   ready_answer=r" up ", key_bits=2048, ssh_options=("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa"),
                   diagnose=_asav_diagnose, prompt=r"[>#] ?$", ports_command="show interface ip brief"),
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


def session(runner: Runner, key: Path, user: str, host: str, lines: List[str], errors: str, name: str, success: str = "",
            options: Sequence[str] = (), prompt: str = "") -> str:  # fmt: skip
    """Types the lines into the CLI over SSH (with a terminal: the CLIs want one) and checks what it answered: no line
    refused, and the success line where the CLI writes one. A session that hangs (a failed commit asks before it lets
    the CLI exit) ends after 20 minutes."""
    prefix = labrun.ssh_prefix(key, user, host, runner.work / "known_hosts", options=options)
    (runner.work / f"{name}.commands.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    args = prefix[:1] + ["-tt"] + prefix[1:]
    ended = None
    if prompt:
        try:
            out = runner.run_paced(args, lines, prompt, timeout=1200, fake=f"(dry run) {success}")
        except labrun.SessionEnded as error:  # (what it wrote till then: the refused lines are the likelier reason)
            out, ended = error.output, error
    else:
        out = runner.run(args, stdin="\n".join(lines) + "\n", timeout=1200, fake=f"(dry run) {success}")
    (runner.work / f"{name}.txt").write_text(out, encoding="utf-8")
    if not runner.dry_run and len(out.strip()) < 40:  # (the sixth ASAv run: "U", and nothing configured, and no line refused)
        raise LabError(f"the firewall answered almost nothing ({name}.txt: {out.strip()!r}): the lines were not run")
    refused = [line.strip() for line in out.splitlines() if errors and re.search(errors, line)]
    if refused:
        raise LabError(f"the firewall refused {len(refused)} lines (all in {name}.txt), the first: {refused[0][:200]}"
                       + (" (and the session ended early)" if ended else ""))
    if ended:
        raise ended
    if success and not re.search(success, out):
        raise LabError(f"the firewall did not say the configuration was committed ({name}.txt)")
    return out


# What ssh says when it and the firewall have no algorithm in common: that does not change while the firewall boots.
_NO_COMMON = "Unable to negotiate"


def wait_cli(runner: Runner, key: Path, user: str, host: str, command: str, answer: str, minutes: float,
             options: Sequence[str] = ()) -> None:  # fmt: skip
    """Until the CLI answers the ready command as it should (PAN-OS: chassis ready, after its first commit). Every try is
    kept in boot.txt: when the CLI never answers, it says whether SSH was refused, the key not taken, or what came back.
    A try that finds no algorithm in common with the firewall ends the wait at once."""
    deadline = time.time() + minutes * 60
    prefix = labrun.ssh_prefix(key, user, host, runner.work / "known_hosts", options=options)
    tries = runner.work / "boot.txt"
    last = ""
    while True:
        try:
            out = runner.run(prefix[:1] + ["-tt"] + prefix[1:], stdin=command + "\nexit\n", quiet=True, timeout=120)
            if re.search(answer, out):
                (runner.work / "ready.txt").write_text(out, encoding="utf-8")  # (the version the firewall runs, for the record)
                return
            last = "answered, but not as expected:\n" + out[-2000:] + ("\n" + runner.last_stderr[-1000:] if runner.last_stderr else "")
        except LabError as error:  # (not up yet: SSH refused or timed out; or the key not taken)
            last = str(error)
        with tries.open("a", encoding="utf-8") as handle:
            handle.write(f"--- {time.strftime('%H:%M:%S')}\n{last.strip()}\n")
        if _NO_COMMON in last:
            raise LabError(f"ssh and the firewall have no algorithm in common (waiting longer will not change it): {last.strip()[-300:]} "
                           "(every try in boot.txt, the firewall's console in console.txt)")  # fmt: skip
        if time.time() > deadline:
            raise LabError(f"the firewall's CLI did not answer within {minutes:.0f} minutes; the last try: {last.strip()[-300:]} "
                           "(every try in boot.txt, the firewall's console in console.txt)")  # fmt: skip
        time.sleep(30)


def save_console(runner: Runner, region: str, instance: str) -> None:
    """The firewall's serial console (its boot messages) and a screenshot of it, before it is torn down."""
    with labrun.shielded():
        text = runner.run(["aws", "ec2", "get-console-output", "--region", region, "--instance-id", instance, "--latest", "--output", "text"],
                          check=False, quiet=True, fake="(dry run)")  # fmt: skip
        (runner.work / "console.txt").write_text(text or "(the console gave nothing)\n", encoding="utf-8")
        shot = runner.run(["aws", "ec2", "get-console-screenshot", "--region", region, "--instance-id", instance, "--query", "ImageData",
                           "--output", "text"], check=False, quiet=True, fake="")  # fmt: skip
        if shot.strip() and shot.strip() != "None":
            try:
                (runner.work / "console.jpg").write_bytes(base64.b64decode(shot.strip()))
            except ValueError:
                pass


def user_data(vendor: Vendor, key: Path, password: str = "") -> str:
    """The firewall's first-boot data, with the run's public key where it asks for one ({ssh_key}: its base64 part) and
    the run's password where it asks for one ({enable_password})."""
    data = vendor.user_data
    if "{ssh_key}" in data:
        parts = key.with_suffix(".pub").read_text(encoding="utf-8").split()
        data = data.replace("{ssh_key}", parts[1] if len(parts) > 1 else parts[0])
    if "{enable_password}" in data:
        if not password:
            raise LabError(f"the first-boot data of {vendor.name} needs a password, and none was given")
        data = data.replace("{enable_password}", password)
    return data


def run_password(work: Path) -> str:
    """A password made for the run (the ASAv's enable password), kept in the work folder for a run left up with --keep:
    letters, digits and a dash, which no CLI reads as anything else."""
    password = "Lab-" + secrets.token_hex(10)
    path = work / "enable_password.txt"
    path.write_text(password + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return password


def conversion(name: str) -> Tuple[str, List[str]]:
    vendor = VENDORS[name]
    return vendor.target, list(vendor.options)


def run_vendor(runner: Runner, args: Any) -> bool:
    vendor = VENDORS[args.firewall]
    region = args.region or "eu-west-1"
    labrun.save_state(runner.work, tier="tier3", firewall=vendor.name, region=region)
    if not runner.dry_run:
        labrun.need("ssh", "ssh-keygen", "scp", "aws")
    key = labrun.ssh_key(runner, "rsa", vendor.key_bits)  # (the key pair of AWS reaches the firewall images, and not all take Ed25519)
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
                  "firewall_instance_type": args.instance_type or vendor.instance_type, "firewall_user_data": user_data(vendor, key, run_password(runner.work) if "{enable_password}" in vendor.user_data else ""),
                  **tier1.common_variables(runner, args, key), "hosts": tier1.host_variables(gateway="firewall")})  # fmt: skip
        outputs = tf.output({"firewall_ip": "192.0.2.4", "firewall_instance": "i-0dryrun", "user": "ec2-user", "hosts": tier1.fake_hosts()})
        if not runner.dry_run:
            try:
                wait_cli(runner, key, vendor.user, outputs["firewall_ip"], vendor.ready, vendor.ready_answer, args.boot_minutes,
                         vendor.ssh_options)
            except LabError:
                save_console(runner, region, outputs["firewall_instance"])
                raise
        if vendor.prepare():  # (answers that do not count, kept in prepare.txt)
            session(runner, key, vendor.user, outputs["firewall_ip"], vendor.prepare(), "", "prepare", options=vendor.ssh_options,
                    prompt=vendor.prompt)
        lines = vendor.session(out)
        if vendor.ports_command:
            ports = _ASA_DRY_PORTS if runner.dry_run else asa_data_ports(
                session(runner, key, vendor.user, outputs["firewall_ip"], ["terminal pager 0", vendor.ports_command, "exit"], "", "ports",
                        options=vendor.ssh_options, prompt=vendor.prompt))  # fmt: skip
            lines = fill_ports(lines, ports)
        session(runner, key, vendor.user, outputs["firewall_ip"], lines, vendor.errors, "load", vendor.success, vendor.ssh_options,
                vendor.prompt)
        try:
            return tier1.probe_hosts(runner, key, outputs, data)
        finally:
            diagnose(runner, vendor, key, outputs["firewall_ip"])
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown(runner, tf)


def diagnose(runner: Runner, vendor: Vendor, key: Path, host: str) -> None:
    """The firewall's own view after the probes (diagnose.txt), where the vendor has show commands for it; a failure here
    is noted and does not change the result."""
    lines = vendor.diagnose()
    if not lines:
        return
    try:
        session(runner, key, vendor.user, host, lines, "", "diagnose", options=vendor.ssh_options, prompt=vendor.prompt)
    except LabError as error:
        (runner.work / "diagnose.txt").write_text(f"(the diagnosis did not finish: {error})\n", encoding="utf-8")


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

