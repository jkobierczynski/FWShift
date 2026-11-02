# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""WatchGuard Firebox Cloud in tier 3 (0.42.1): the lab loads FWShift's output as Policy Manager would, into the
configuration file of the Firebox, through the Fireware CLI.

Written from WatchGuard's documentation (Deploy Firebox Cloud on AWS, Firebox Cloud feature differences, Administer
Firebox Cloud with the CLI, the Fireware CLI Reference 12.9, Manage the Firebox configuration file), never run before
the first lab run. What it counts on:

* The Marketplace image (WatchGuard Firebox Cloud, hourly) takes eth0 as its external interface, in a public subnet
  with the Elastic IP, and up to seven private interfaces, eth1 to eth7, all of them addressed by DHCP (the interface
  page of the Web UI is hidden: AWS gives the addresses). The lab's management interface is eth0 (device index 0),
  its zones eth1 to eth3 in the lab's order.
* The admin's first passphrase is the instance id, and the first login to the Web UI (https://ADDRESS:8080) runs the
  setup wizard: the licence agreement and new passphrases for status and admin. Nothing documented takes these steps
  without a browser: the lab asks for them and waits (``wizard``).
* The CLI is SSH on port 4118, as admin with the instance's key pair (an RSA key). Its main mode has
  ``export config to (location)`` and ``import config from (location)``, the location an FTP or TFTP URL. FWShift's
  output is the policy part of a configuration file, to merge into the Firebox's own (manual, section 10): the lab
  exports the configuration to a TFTP server it runs on a test host (``tftpd.py``, on in10, which the Firebox reaches
  on eth1), merges the output into it as the manual says (``merge``), and imports the result.
* What the merge does that the manual leaves to a person: the zones of the lab policy are the names of the interfaces
  in the output, and become the names the Firebox gives eth1 to eth3 (read from its configuration: the interface
  whose entry holds the device name); the Firebox's own policies are taken out, except those that end at the Firebox
  itself (management: WatchGuard, WatchGuard Web UI), so that its default Outgoing and Ping policies decide no lab
  traffic.

What is not known before the first run: the element that holds an interface's device name, whether a Firebox Cloud
takes a configuration whose policies hold only the elements FWShift writes, whether ``import config`` asks before it
applies and whether it restarts, and the address a static NAT action of Firebox Cloud may use (the lab publishes
secondary addresses of the outside interface, which the Firebox does not configure by itself).
"""

from __future__ import annotations

import json
import re
import shlex
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Tuple

import labrun
from labrun import LabError, Runner

NAME = "watchguard"
CLI_PORT = 4118
WEB_PORT = 8080
# The lab's zones on the Firebox's cards (eth0 is the external, management interface).
DEVICES = {"inside": "eth1", "dmz": "eth2", "outside": "eth3"}
# The TFTP server: a test host the Firebox reaches on its own subnet (inside, eth1).
TFTP_HOST = "in10"
TFTP_ADDRESS = "10.20.1.10"
TFTP_FOLDER = "/tmp/fwlab-tftp"
# What in the CLI's answers means a command was refused.
ERRORS = r"(?i)(^\s*%|\berror\b|\bfailed\b|invalid input|unknown command|incomplete command)"
PROMPT = r"[#>]\s*$"
ANSWERS = ((r"(?i)(\(y/n\)|\[y/n\]|\[yes/no\]|yes/no|continue\?|are you sure)", "y"),)
# The lists of the output, merged into the lists of the same name (manual, section 10).
LISTS = ("address-group-list", "service-list", "nat-list", "alias-list", "abs-policy-list", "policy-list")


def wizard(runner: Runner, host: str, instance: str, minutes: float = 45) -> None:
    """The one step the lab cannot take: the setup wizard of the Web UI. It says what to do and waits for Enter (or,
    without a terminal, for the file wizard-done in the run's folder)."""
    if runner.dry_run:
        return
    done = runner.work / "wizard-done"
    print(f"""
WatchGuard Firebox Cloud: run its setup wizard (the one step the lab cannot take).
  1. Open https://{host}:{WEB_PORT} once it answers (the first boot takes a few minutes; the certificate is the
     Firebox's own) and log in as admin with the passphrase {instance} (the instance id).
  2. The Firebox Cloud Setup Wizard: accept the licence agreement, give the status and admin accounts passphrases of
     your own (the lab logs in with its key, not with them), and finish.
""" + ("Then press Enter here." if sys.stdin.isatty() else f"Then create the file {done} (touch it)."), file=sys.stderr, flush=True)  # fmt: skip
    if sys.stdin.isatty():
        input()
        return
    deadline = time.time() + minutes * 60
    while not done.exists():
        if time.time() > deadline:
            raise LabError(f"the setup wizard was not done within {minutes:g} minutes (no {done}); the run stops")
        time.sleep(10)


# -- the TFTP server on a test host ------------------------------------------------------------------------------------


class Tftp:
    """The lab's TFTP server on TFTP_HOST: copied there, started as root, its folder read and written over scp."""

    def __init__(self, runner: Runner, key: Path) -> None:
        self.runner = runner
        self.key = key
        outputs = labrun.load_state(runner.work).get("outputs", {})
        host = outputs.get("hosts", {}).get(TFTP_HOST, {})
        self.address = host.get("mgmt_ip", "192.0.2.20")
        self.user = outputs.get("user", "ec2-user")
        self.known = runner.work / "known_hosts"

    def _ssh(self, command: str, check: bool = True) -> str:
        prefix = labrun.ssh_prefix(self.key, self.user, self.address, self.known)
        return self.runner.run(prefix + [command], check=check, quiet=True, timeout=120, fake="")

    def _scp(self, source: str, target: str) -> None:
        self.runner.run(["scp", "-q", "-i", str(self.key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
                         "-o", f"UserKnownHostsFile={self.known}", "-o", "ConnectTimeout=10", source, target], timeout=300)  # fmt: skip

    def start(self) -> None:
        self._scp(str(Path(__file__).with_name("tftpd.py")), f"{self.user}@{self.address}:/tmp/fwlab-tftpd.py")
        folder = shlex.quote(TFTP_FOLDER)
        self._ssh(f"sudo pkill -f fwlab-tftpd.py; mkdir -p {folder}; chmod 777 {folder}; "
                  f"sudo nohup python3 /tmp/fwlab-tftpd.py {folder} > /tmp/fwlab-tftpd.log 2>&1 < /dev/null & sleep 2; "
                  "pgrep -f fwlab-tftpd.py > /dev/null || { cat /tmp/fwlab-tftpd.log; exit 1; }")  # fmt: skip

    def stop(self) -> None:
        log = self._ssh("sudo pkill -f fwlab-tftpd.py; cat /tmp/fwlab-tftpd.log", check=False)
        with (self.runner.work / "tftpd.log").open("a", encoding="utf-8") as handle:
            handle.write(log)

    def get(self, name: str, target: Path) -> str:
        if self.runner.dry_run:
            return ""
        self._scp(f"{self.user}@{self.address}:{TFTP_FOLDER}/{name}", str(target))
        return target.read_text(encoding="utf-8", errors="replace")

    def put(self, source: Path, name: str) -> None:
        self._scp(str(source), f"{self.user}@{self.address}:{TFTP_FOLDER}/{name}")
        self._ssh(f"chmod 644 {shlex.quote(TFTP_FOLDER + '/' + name)}")

    @staticmethod
    def url(name: str) -> str:
        return f"tftp://{TFTP_ADDRESS}/{name}"


# -- the configuration file ---------------------------------------------------------------------------------------------


def interfaces(config: str) -> Dict[str, str]:
    """The Firebox's device names (eth1 ...) -> the names of their interfaces in the configuration: the interface whose
    entry holds the device name, in any element (which one is not documented)."""
    root = ET.fromstring(config.encode("utf-8"))
    out: Dict[str, str] = {}
    for interface in root.findall("interface-list/interface"):
        name = (interface.findtext("name") or "").strip()
        if not name:
            continue
        for element in interface.iter():
            text = (element.text or "").strip()
            if re.fullmatch(r"eth\d+", text) and text not in out:
                out[text] = name
    return out


def _name(element: ET.Element) -> str:
    return (element.findtext("name") or "").strip()


def merge(config: str, policy: str, names: Dict[str, str]) -> Tuple[str, List[str]]:
    """FWShift's policy part merged into a configuration of the Firebox (manual, section 10): each list's entries into
    the list of the same name (an entry of the same name replaced), manual order, the zones of the output renamed to
    the Firebox's interfaces, and the Firebox's own policies taken out except those that end at the Firebox."""
    root = ET.fromstring(config.encode("utf-8"))
    part = ET.fromstring(policy.encode("utf-8"))
    notes: List[str] = []
    for element in part.iter("interface"):
        text = (element.text or "").strip()
        if text in names:
            element.text = names[text]
    abs_list, concrete = root.find("abs-policy-list"), root.find("policy-list")
    for policy_entry in list(abs_list if abs_list is not None else []):
        targets = [(a.text or "").strip().lower() for a in policy_entry.findall("to-alias-list/alias")]
        if targets and all(t == "firebox" for t in targets):
            notes.append(f"kept the Firebox's policy {_name(policy_entry)} (to the Firebox itself)")
            continue
        own = {(p.text or "").strip() for p in policy_entry.findall("policy-list/policy")}
        assert abs_list is not None
        abs_list.remove(policy_entry)
        notes.append(f"took out the Firebox's policy {_name(policy_entry)}")
        for entry in list(concrete if concrete is not None else []):
            if _name(entry) in own:
                assert concrete is not None
                concrete.remove(entry)
    for tag in LISTS:
        source = part.find(tag)
        if source is None or not len(source):
            continue
        target = root.find(tag)
        if target is None:
            target = ET.SubElement(root, tag)
            notes.append(f"the configuration had no {tag}: added at its end")
        existing = {_name(entry): entry for entry in target}
        for entry in list(source):
            if _name(entry) in existing:
                target.remove(existing[_name(entry)])
                notes.append(f"{tag}: the Firebox's {_name(entry)} replaced by FWShift's")
            target.append(entry)
    misc = root.find("system-parameters/misc-global-setting")
    if misc is None:
        parameters = root.find("system-parameters")
        if parameters is None:
            parameters = ET.SubElement(root, "system-parameters")
        misc = ET.SubElement(parameters, "misc-global-setting")
        notes.append("the configuration had no misc-global-setting: added")
    order = misc.find("auto-order-enabled")
    if order is None:
        order = ET.SubElement(misc, "auto-order-enabled")
    order.text = "0"
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n", notes


def zone_options(work: Path) -> List[str]:
    """--zone-map for the read-back: the lab's zones as the Firebox names its interfaces (found by the load)."""
    names = labrun.load_state(work).get("watchguard_interfaces", {})
    return [word for zone, name in names.items() for word in ("--zone-map", f"{zone}={name}")]


# -- the load and the export ---------------------------------------------------------------------------------------------


def _cli(runner: Runner, vendor: Any, key: Path, host: str, lines: List[str], name: str) -> str:
    import tier3  # (tier3 imports this module)

    try:
        return tier3.session(runner, key, vendor.user, host, lines + ["exit"], ERRORS, name, options=vendor.ssh_options, prompt=PROMPT,
                             answers=ANSWERS)  # fmt: skip
    except labrun.SessionEnded as error:  # (an import that restarts the Firebox ends the session)
        text = error.output
        (runner.work / f"{name}.txt").write_text(text, encoding="utf-8")
        return text


def _export(runner: Runner, vendor: Any, key: Path, host: str, tftp: Tftp, name: str) -> str:
    _cli(runner, vendor, key, host, [f"export config to {tftp.url(name)}"], name.replace(".xml", ""))
    text = tftp.get(name, runner.work / name)
    if not runner.dry_run and "<profile" not in text:
        raise LabError(f"the Firebox exported no configuration file ({name}: {text[:200]!r}; the CLI's answer in "
                       f"{name.replace('.xml', '')}.txt, the TFTP server's in tftpd.log)")  # fmt: skip
    return text


def load(runner: Runner, vendor: Any, key: Path, host: str, out: Path) -> None:
    """The configuration exported, FWShift's output merged into it, the result imported (merge.txt, import.txt)."""
    import tier3

    tftp = Tftp(runner, key)
    tftp.start()
    try:
        config = _export(runner, vendor, key, host, tftp, "fwlab-original.xml")
        if runner.dry_run:
            config = "<profile><interface-list>" + "".join(
                f"<interface><name>{zone}</name><if-dev-name>{device}</if-dev-name></interface>" for zone, device in DEVICES.items()) + (
                "</interface-list><abs-policy-list/><policy-list/></profile>")  # fmt: skip
        found = interfaces(config)
        missing = [device for device in DEVICES.values() if device not in found]
        if missing:
            raise LabError(f"the Firebox's configuration names no interface for {', '.join(missing)} (it has: "
                           f"{json.dumps(found) if found else 'none'}; fwlab-original.xml): the lab's zones need eth1 to eth3")  # fmt: skip
        names = {zone: found[device] for zone, device in DEVICES.items()}
        labrun.save_state(runner.work, watchguard_interfaces=names)
        merged, notes = merge(config, out.read_text(encoding="utf-8"), names)
        path = runner.work / "config.merged.xml"
        path.write_text(merged, encoding="utf-8")
        (runner.work / "merge.txt").write_text("the lab's zones: " + json.dumps(names) + "\n" + "\n".join(notes) + "\n", encoding="utf-8")
        tftp.put(path, "fwlab-merged.xml")
        _cli(runner, vendor, key, host, [f"import config from {tftp.url('fwlab-merged.xml')}"], "import")
    finally:
        tftp.stop()
    if runner.dry_run:
        return
    time.sleep(60)  # (an import may restart the Firebox: its CLI again before the probes)
    tier3.wait_cli(runner, key, vendor.user, host, vendor.ready, vendor.ready_answer, 20, vendor.ssh_options)


def export(runner: Runner, vendor: Any, key: Path, host: str) -> str:
    """The configuration as the Firebox holds it after the probes (the read-back)."""
    tftp = Tftp(runner, key)
    tftp.start()
    try:
        if runner.dry_run:
            return (runner.work / "config.merged.xml").read_text(encoding="utf-8")
        return _export(runner, vendor, key, host, tftp, "fwlab-export.xml")
    finally:
        tftp.stop()
