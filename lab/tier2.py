# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tier 2 of the lab: free firewall images (MikroTik RouterOS CHR, OPNsense, pfSense CE) on a local Linux host with KVM,
and the Linux kernel itself (nftables, iptables) in a network namespace, which needs no image at all.

Everything lives in network namespaces, so nothing of the host's own networking changes: a "switch" namespace holds the
three bridges, one per zone (its own iptables are empty, so bridged traffic is not filtered there even where the host
sends bridged traffic to iptables); each test host is a namespace with one interface on its zone's bridge and the
firewall's address in its zone (.1) as default route. The firewall is a namespace whose interfaces are named after the
zones (nftables, iptables), or a QEMU virtual machine started inside the switch namespace with four NICs: the first on
QEMU's user network (SSH forwarded from that namespace's 127.0.0.1), the others on the three bridges. A virtual machine
starts from a copy-on-write overlay of a base image prepared once (lab/README.md), which stays as it was. Needs root.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import labplan
import labrun
from labrun import LabError, Runner, Target

ORDER = ["inside", "dmz", "outside"]  # the firewall's second, third and fourth NIC
SWITCH = "fwl-sw"
FIREWALL_NS = "fwl-fw"
SSH_PORT = 2222  # (in the switch namespace, which has nothing else)


@dataclass
class Image:
    name: str
    target: str
    user: str
    options: List[str]
    note: str
    kind: str = "vm"  # or "netns": the firewall is a network namespace


_PF_ZONES = {"inside": "opt1", "dmz": "opt2", "outside": "wan"}
_PF_OPTIONS = [*(x for z, i in _PF_ZONES.items() for x in ("--zone-map", f"{z}={i}")), *labplan.zone_options(_PF_ZONES)]
IMAGES: Dict[str, Image] = {
    "nftables": Image("nftables", "nftables", "", [], "no image: a network namespace whose interfaces are the zones", "netns"),
    "iptables": Image("iptables", "iptables", "", [], "no image: a network namespace whose interfaces are the zones", "netns"),
    "routeros": Image("routeros", "routeros", "admin",
                      ["--interface-map", "ethernet1/2=ether2", "--interface-map", "ethernet1/3=ether3", "--interface-map", "ethernet1/1=ether4"],
                      "the base image: CHR with the lab key imported for admin; ether1 on DHCP (the default)"),  # fmt: skip
    "opnsense": Image("opnsense", "opnsense", "root", _PF_OPTIONS,
                      "the base image: LAN on vtnet0 (DHCP from QEMU, SSH with the lab key for root), OPT1 vtnet1 10.20.1.1/24, "
                      "OPT2 vtnet2 10.20.2.1/24, WAN vtnet3 10.20.3.1/24 without 'Block private networks'; installed on a virtio disk"),  # fmt: skip
    "pfsense": Image("pfsense", "pfsense", "root", _PF_OPTIONS,
                     "the base image: as for OPNsense (LAN vtnet0 for management, OPT1, OPT2, WAN vtnet3 without 'Block private networks')"),  # fmt: skip
}


def conversion(name: str, target_version: Optional[str] = None) -> Tuple[str, List[str]]:
    image = IMAGES[name]
    options = list(image.options)
    if image.target == "opnsense" and target_version:
        options += ["--target-version", target_version]
    return image.target, options


def names(host: labplan.Host) -> Tuple[str, str, str]:
    """(namespace, its interface, the bridge's end), each at most 15 characters."""
    return f"fwl-{host.name}", f"fwl-{host.name}-h", f"fwl-{host.name}-b"


def bridge(zone: str) -> str:
    return f"fwl-br-{zone}"


def tap(zone: str) -> str:
    return f"fwl-tap-{zone}"


def in_switch(command: List[str]) -> List[str]:
    return ["ip", "netns", "exec", SWITCH, *command]


# -- the areas of a pfSense or OPNsense configuration --------------------------------------------------------------


def merge_areas(base_xml: str, converted_xml: str, flavour: str) -> str:
    """The configuration of the firewall with the areas of the converted file put in, as a restore of each area does:
    an area of the file replaces that area; what the file does not hold stays as it was."""
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    base = ET.fromstring(base_xml, parser=parser)
    new = ET.fromstring(converted_xml)
    if flavour == "pfsense":
        for area in ("aliases", "nat", "filter"):
            found = new.find(area)
            if found is not None:
                _replace_child(base, area, found)
    elif flavour == "opnsense":
        firewall = _ensure(_ensure(base, "OPNsense"), "Firewall")
        alias = new.find("OPNsense/Firewall/Alias")
        if alias is not None:
            _replace_child(firewall, "Alias", alias)
        filt = new.find("OPNsense/Firewall/Filter")
        nat = new.find("nat")
        if filt is not None:
            target = _ensure(firewall, "Filter")
            target.attrib.update(filt.attrib)
            for child in ("snatrules", "npt", "onetoone", "rules"):
                found = filt.find(child)
                if found is not None:
                    _replace_child(target, child, found)
            legacy = base.find("filter")  # (the restore of Firewall Rules empties the old rule page as well)
            if legacy is not None:
                for rule in legacy.findall("rule"):
                    legacy.remove(rule)
        if nat is not None:
            _replace_child(base, "nat", nat)
    else:
        raise ValueError(flavour)
    return '<?xml version="1.0"?>\n' + ET.tostring(base, encoding="unicode") + "\n"


def _ensure(parent: ET.Element, tag: str) -> ET.Element:
    found = parent.find(tag)
    if found is None:
        found = ET.SubElement(parent, tag)
    return found


def _replace_child(parent: ET.Element, tag: str, element: ET.Element) -> None:
    old = parent.find(tag)
    if old is None:
        parent.append(element)
        return
    index = list(parent).index(old)
    parent.remove(old)
    parent.insert(index, element)


# -- the network ---------------------------------------------------------------------------------------------------


def network_up(runner: Runner, taps: bool) -> None:
    runner.run(["ip", "netns", "add", SWITCH])
    runner.run(in_switch(["ip", "link", "set", "lo", "up"]))
    for zone in ORDER:
        runner.run(in_switch(["ip", "link", "add", bridge(zone), "type", "bridge"]))
        runner.run(in_switch(["ip", "link", "set", bridge(zone), "up"]))
        if taps:
            runner.run(in_switch(["ip", "tuntap", "add", "dev", tap(zone), "mode", "tap"]))
            runner.run(in_switch(["ip", "link", "set", tap(zone), "master", bridge(zone), "up"]))
    for host in labplan.HOSTS:
        ns, inner, outer = names(host)
        runner.run(["ip", "netns", "add", ns])
        runner.run(in_switch(["ip", "link", "add", outer, "type", "veth", "peer", "name", inner, "netns", ns]))
        runner.run(in_switch(["ip", "link", "set", outer, "master", bridge(host.zone), "up"]))
        prefix = labplan.ZONES[host.zone].split("/")[1]
        for command in (["ip", "link", "set", "lo", "up"], ["ip", "addr", "add", f"{host.ip}/{prefix}", "dev", inner],
                        ["ip", "link", "set", inner, "up"], ["ip", "route", "add", "default", "via", labplan.gateway(host.zone)]):  # fmt: skip
            runner.run(["ip", "netns", "exec", ns, *command])


def firewall_ns_up(runner: Runner) -> None:
    """A network namespace as the firewall: an interface named after each zone, on its bridge, with the zone's .1."""
    runner.run(["ip", "netns", "add", FIREWALL_NS])
    runner.run(["ip", "netns", "exec", FIREWALL_NS, "ip", "link", "set", "lo", "up"])
    for zone in ORDER:
        outer = f"fwl-fwz-{zone}"
        runner.run(in_switch(["ip", "link", "add", outer, "type", "veth", "peer", "name", zone, "netns", FIREWALL_NS]))
        runner.run(in_switch(["ip", "link", "set", outer, "master", bridge(zone), "up"]))
        runner.run(["ip", "netns", "exec", FIREWALL_NS, "ip", "addr", "add", f"{labplan.gateway(zone)}/24", "dev", zone])
        runner.run(["ip", "netns", "exec", FIREWALL_NS, "ip", "link", "set", zone, "up"])
    runner.run(["ip", "netns", "exec", FIREWALL_NS, "sysctl", "-qw", "net.ipv4.ip_forward=1"])


def network_down(runner: Runner) -> None:
    """Deleting the namespaces takes their interfaces, bridges and taps with them."""
    for ns in [FIREWALL_NS, *[names(h)[0] for h in labplan.HOSTS], SWITCH]:
        runner.run(["ip", "netns", "del", ns], check=False, quiet=True)


def leftovers(runner: Runner) -> List[str]:
    listed = runner.run(["ip", "netns", "list"], check=False, quiet=True)
    found = [f"network namespace {line.split()[0]}" for line in listed.splitlines() if line.startswith("fwl-")]
    pidfile = runner.work / "qemu.pid"
    if pidfile.exists():
        try:
            os.kill(int(pidfile.read_text().strip()), 0)
            found.append(f"QEMU process {pidfile.read_text().strip()}")
        except (ValueError, ProcessLookupError, PermissionError):
            pass
    return found


# -- the virtual machine -------------------------------------------------------------------------------------------


def start_vm(runner: Runner, base: Path, memory: int) -> Path:
    fmt = "raw" if base.suffix in (".img", ".raw") else "qcow2"
    overlay = runner.work / "firewall.qcow2"
    runner.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", str(base.resolve()), "-F", fmt, str(overlay)])
    pidfile = runner.work / "qemu.pid"
    command = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-smp", "2", "-m", str(memory), "-drive", f"file={overlay},if=virtio",
               "-netdev", f"user,id=mgmt,hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22", "-device", "virtio-net-pci,netdev=mgmt"]  # fmt: skip
    for index, zone in enumerate(ORDER, 1):
        command += ["-netdev", f"tap,id=z{index},ifname={tap(zone)},script=no,downscript=no", "-device", f"virtio-net-pci,netdev=z{index}"]
    command += ["-display", "none", "-serial", f"file:{runner.work / 'console.log'}", "-daemonize", "-pidfile", str(pidfile)]
    runner.run(in_switch(command))
    return pidfile


def stop_vm(runner: Runner) -> None:
    pidfile = runner.work / "qemu.pid"
    runner.log.append(f"kill $(cat {pidfile})")
    if runner.dry_run or not pidfile.exists():
        return
    try:
        pid = int(pidfile.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.5)
            os.kill(pid, 0)
        os.kill(pid, signal.SIGKILL)
    except (ValueError, ProcessLookupError):
        pass


def wait_ssh(runner: Runner, prefix: List[str], minutes: float, probe_command: str) -> None:
    deadline = time.time() + minutes * 60
    while True:
        try:
            runner.run(prefix + [probe_command], quiet=True, timeout=60)
            return
        except LabError:
            if time.time() > deadline:
                raise LabError(f"the firewall did not answer SSH within {minutes:.0f} minutes (see console.log)") from None
            time.sleep(10)


def load_routeros(runner: Runner, prefix: List[str], scp: List[str], remote: str, out: Path) -> None:
    for index, zone in enumerate(ORDER, 2):
        runner.run(prefix + [f"/ip address add address={labplan.gateway(zone)}/24 interface=ether{index}"])
    runner.run(scp + [str(out), f"{remote}:fwshift.rsc"])
    answer = runner.run(prefix + ["/import file-name=fwshift.rsc verbose=yes"], fake="Script file loaded and executed successfully")
    (runner.work / "load.txt").write_text(answer, encoding="utf-8")
    if "Script file loaded and executed successfully" not in answer or \
            re.search(r"failure|syntax error|expected end of command|bad command name|no such item|invalid value", answer, re.I):  # fmt: skip
        raise LabError("RouterOS did not load the whole script (load.txt)")
    runner.run(prefix + ['/ip firewall filter enable [find where comment~"fwshift: enable"]'])
    runner.run(prefix + ['/ip firewall filter move [find where comment~"fwshift: enable"] destination=0'])
    rules = runner.run(prefix + ['/ip firewall filter print count-only where chain~"fwshift" disabled=no'], fake="10")
    if not rules.strip().isdigit() or int(rules.strip()) == 0:
        raise LabError(f"RouterOS has no enabled rules in the fwshift chains after the import ({rules.strip()[:80]})")


def load_config_xml(runner: Runner, prefix: List[str], scp: List[str], remote: str, out: Path, flavour: str) -> None:
    path = "/conf/config.xml"
    base_file = runner.work / "config.base.xml"
    if runner.dry_run:
        base_file.write_text((labrun.REPO / "tests" / "data" / f"{flavour}_sample.xml").read_text(encoding="utf-8"), encoding="utf-8")
    runner.run(scp + [f"{remote}:{path}", str(base_file)])
    merged = merge_areas(base_file.read_text(encoding="utf-8"), out.read_text(encoding="utf-8"), flavour)
    merged_file = runner.work / "config.merged.xml"
    merged_file.write_text(merged, encoding="utf-8")
    runner.run(scp + [str(merged_file), f"{remote}:{path}"])
    reload = "rm -f /tmp/config.cache && /etc/rc.filter_configure_sync" if flavour == "pfsense" else "configctl filter reload"
    answer = runner.run(prefix + [reload], fake="OK")
    rules = runner.run(prefix + ["pfctl -sr"], fake="pass in quick on vtnet1 inet proto tcp from 10.20.1.0/24 to 10.20.2.10")
    (runner.work / "load.txt").write_text(answer + "\n--- pfctl -sr\n" + rules, encoding="utf-8")
    if "10.20.2.10" not in rules:  # (the web server of the lab policy: its rules are in pf, or the reload did not take)
        raise LabError("the firewall's pf has no rule for the lab's web server after the reload (load.txt)")


# -- the runs ------------------------------------------------------------------------------------------------------


def _serve(runner: Runner) -> List["subprocess.Popen[bytes]"]:
    probe = labrun.ROOT / "probe.py"
    servers: List["subprocess.Popen[bytes]"] = []
    for host in labplan.HOSTS:
        command = ["ip", "netns", "exec", names(host)[0], sys.executable, str(probe), "serve", "--bind", host.ip, "--tcp",
                   ",".join(map(str, labplan.TCP_PORTS)), "--udp", ",".join(map(str, labplan.UDP_PORTS))]  # fmt: skip
        runner.log.append(" ".join(command) + " &")
        if not runner.dry_run:
            servers.append(subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True))
    return servers


def _probe_and_check(runner: Runner, data: Dict[str, Any]) -> bool:
    probe = labrun.ROOT / "probe.py"
    hosts = [Target(h.name, h.ip, ["ip", "netns", "exec", names(h)[0], "sh", "-c"]) for h in labplan.HOSTS]
    if not runner.dry_run:
        labrun.wait_ready(runner, hosts, minutes=1, probe_path=str(probe), python=sys.executable)
    results = labrun.probe(runner, hosts, data, lambda target, plan_file: (str(probe), str(plan_file)), python=sys.executable)
    return labrun.finish(runner, data, results)


def _plan(runner: Runner, name: str, args: Any) -> Tuple[Path, Dict[str, Any]]:
    """The conversion and the plan: two hosts of one zone talk over their bridge, not through the firewall."""
    target, options = conversion(name, getattr(args, "target_version", None))
    out = runner.work / f"policy.{target}"
    report = labrun.fwshift(runner, target, out, options)
    data = labplan.build_plan(target, report, through_target_inside_zone=False, refused_means="blocked")
    labplan.save(runner.work / "plan.json", data)
    return out, data


def teardown(runner: Runner, servers: List["subprocess.Popen[bytes]"]) -> None:
    for server in servers:
        server.terminate()
    stop_vm(runner)
    network_down(runner)
    found = [] if runner.dry_run else leftovers(runner)
    if not found:
        labrun.save_state(runner.work, torn_down=True)
    else:
        print("\n*** left behind: " + ", ".join(found) + f"\n  try again: sudo python3 lab/lab.py destroy {runner.work.name}\n")


def run_image(runner: Runner, args: Any) -> bool:
    image = IMAGES[args.firewall]
    labrun.save_state(runner.work, tier="tier2", firewall=image.name)
    if image.kind == "vm":
        if not args.image:
            raise LabError("--image: the base image of the firewall, prepared once as lab/README.md says (" + image.note + ")")
        if not args.ssh_key:
            raise LabError("--ssh-key: the private key the base image lets in")
    if not runner.dry_run:
        if os.geteuid() != 0:
            raise LabError("tier 2 makes network namespaces: run it as root (sudo -E)")
        if image.kind == "netns":
            labrun.need("ip", "ping", "nft" if image.target == "nftables" else "iptables-restore")
        else:
            labrun.need("qemu-system-x86_64", "qemu-img", "ip", "ping", "ssh", "scp")
            if not Path("/dev/kvm").exists():
                raise LabError("no /dev/kvm: this host cannot run KVM guests")
        if leftovers(runner):
            raise LabError("namespaces of another lab run are there (" + ", ".join(leftovers(runner)) + "): one tier-2 run at a time")
    out, data = _plan(runner, image.name, args)
    servers: List["subprocess.Popen[bytes]"] = []
    try:
        network_up(runner, taps=image.kind == "vm")
        if image.kind == "netns":
            firewall_ns_up(runner)
            command = ["nft", "-f", str(out)] if image.target == "nftables" else ["iptables-restore", str(out)]
            (runner.work / "load.txt").write_text(runner.run(["ip", "netns", "exec", FIREWALL_NS, *command]), encoding="utf-8")
        else:
            key, user = Path(args.ssh_key), args.ssh_user or image.user
            known = runner.work / "known_hosts"
            prefix = in_switch(labrun.ssh_prefix(key, user, "127.0.0.1", known, SSH_PORT))
            scp = in_switch(["scp", "-q", "-P", str(SSH_PORT), "-i", str(key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o",
                             f"UserKnownHostsFile={known}"])  # fmt: skip
            start_vm(runner, Path(args.image), args.memory)
            if not runner.dry_run:
                wait_ssh(runner, prefix, args.boot_minutes or 30, "/system resource print" if image.name == "routeros" else "uname -a")
            if image.name == "routeros":
                load_routeros(runner, prefix, scp, f"{user}@127.0.0.1", out)
            else:
                load_config_xml(runner, prefix, scp, f"{user}@127.0.0.1", out, image.name)
        servers = _serve(runner)
        return _probe_and_check(runner, data)
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown(runner, servers)
