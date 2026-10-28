# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tier 3 of the lab: firewall images of the AWS Marketplace (pay per hour or trial). One firewall with an interface
in each zone; the converted policy is loaded over SSH with the vendor's CLI, after a base configuration (interface
addresses, the zones) that FWShift does not write."""

from __future__ import annotations

import base64
import dataclasses
import ipaddress
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

import labplan
import readback
import labrun
import sophos
import tier1
import tier2
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
    # Files copied to the firewall's home folder before the load (scp), made from the conversion: for a firewall whose
    # load is a script it runs, not lines typed into its CLI (Check Point: FWShift's mgmt_cli script and the lab's own).
    uploads: Callable[[Path], List[Path]] = lambda out: []
    # How long first boot may take, unless --boot-minutes says (Check Point's first-time setup: up to an hour).
    boot_minutes: float = 30
    # The CLI's prompt, for a firewall whose lines are typed one at a time, each after its prompt (the ASAv: given them
    # all ahead, it closed the session after one letter of its greeting, and nothing was configured).
    prompt: str = ""
    # A firewall with a shell, not a CLI: each command is given to ssh to run (pfSense's admin gets a menu when logged in
    # with a terminal), with sudo where the user is not root (OPNsense's ec2-user); and its own way to load the policy,
    # in place of typed lines (pfSense and OPNsense: their config.xml with the areas of the conversion put in).
    as_command: bool = False
    sudo: str = ""
    # A login by password, the instance id (SonicWall NSv: no key; SSH_ASKPASS gives it), and questions the CLI may ask
    # before its prompt, with their answers ({password}: the same id): SonicOS asks for its own user and password.
    password_login: bool = False
    answers: Tuple[Tuple[str, str], ...] = ()
    # Keys sent once a session has written something, before any line (the NSv: Ctrl+S and a space take its management
    # console to the SonicOS CLI), and a session closed by the lab after its last line, for a CLI that does not end it.
    preamble: str = ""
    close_after: float = 0
    # The preamble only when the screen, once drawn, shows this (the NSv's SSH lands in the window it was left in).
    preamble_when: str = ""
    # A long answer stopped at this is shown on with a space (SonicOS's pager).
    pager: str = ""
    # A session quiet this long after a line is taken to be at its prompt, six times as long after a line that matches
    # slow (SonicOS's screen scrolled to the left hides the start of its prompt).
    idle: float = 0
    slow: str = ""
    # A full-screen console: its answers read as plain text, without this pattern (the NSv's status bar).
    screen_noise: str = ""
    load: Optional[Callable[["Runner", "Vendor", Path, str, Path], None]] = None
    # The cards of the zones, for a firewall the lab puts its zones on itself (pfSense, OPNsense: ena1 to ena3 on AWS).
    ports: Dict[str, str] = field(default_factory=dict)
    # A firewall the lab talks to through an API, not a CLI (Sophos: its XML API on 4444): its boot waited for on the
    # API, its diagnosis and its export through it (sophos.py).
    api: bool = False
    # The device index of the management interface (Sophos: 1, its WAN port PortB), the TCP ports open on it to the
    # admin address, the secrets the image reads at first boot (Terraform makes them, named RUN_ID-NAME, with the run's
    # password, and a role to read them), and IMDSv2 required.
    mgmt_index: int = 0
    mgmt_ports: Tuple[int, ...] = ()
    secrets: Tuple[str, ...] = ()
    imdsv2: bool = False


@dataclass(frozen=True)
class CloudImage:
    """A vendor's image on Azure or Google Cloud (0.39.0). Azure: PUBLISHER:OFFER:SKU (its plan the same three, unless
    plan is False); Google Cloud: the image or its family, as projects/PROJECT/global/images/family/FAMILY. What of the
    vendor differs there (its user, the names of its cards, the ready answer, the first-boot data) in changes."""

    image: str
    size: str
    plan: bool = True
    changes: Tuple[Tuple[str, Any], ...] = ()
    metadata_key: str = "user-data"  # (Google Cloud: the metadata the first-boot data goes in)
    key_metadata: str = ""  # (Google Cloud: a metadata the image reads the run's key from, beside ssh-keys)
    vm_user: str = "fwlab"  # (Azure: the VM's user, which Azure makes; never admin)
    # What is known not to fit the cloud yet: a run stops before it starts anything, unless --untested.
    open_point: str = ""
    status: str = "scripted from the vendor's documentation, never run"
    source: str = ""  # (where the image's name was found)


# -- FortiGate ---------------------------------------------------------------------------------------------------

_FGT_PORTS = {"inside": "port2", "dmz": "port3", "outside": "port4"}


def _fortigate_user_data() -> str:
    lines = ["config system interface"]
    for zone, port in _FGT_PORTS.items():
        lines += [f"    edit {port}", "        set mode static", f"        set ip {_addr(zone)} 255.255.255.0", "        set allowaccess ping", "    next"]
    return "\n".join(lines + ["end", ""])


def _fortigate_session(out: Path) -> List[str]:
    # Central NAT on before the output, as its report says (CENTRAL_NAT): FWShift writes the source NAT as central NAT,
    # and a FortiGate in its default mode (NAT per policy) took the central-snat-map and did not hide the inside (the
    # first run with NAT, 0.40.16).
    return ["config system settings", "set central-nat enable", "end", *_lines(out, "#"), "exit"]


# -- PAN-OS ------------------------------------------------------------------------------------------------------

_PAN_PORTS = {"inside": "ethernet1/1", "dmz": "ethernet1/2", "outside": "ethernet1/3"}
# The source's interfaces (outside ethernet1/1, inside 1/2, dmz 1/3) as the VM-Series has its zones: the hide NAT names
# the interface whose address it takes (0.37.0).
_PAN_INTERFACES = [w for source, zone in (("ethernet1/2", "inside"), ("ethernet1/3", "dmz"), ("ethernet1/1", "outside"))
                   for w in ("--interface-map", f"{source}={_PAN_PORTS[zone]}")]  # fmt: skip


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
_IOS_ZONE_OF = {port: zone for zone, port in _IOS_PORTS.items()}


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


def ios_nat(text: str) -> Tuple[List[str], Dict[str, str]]:
    """The NAT the IOS output leaves as comments: its commands, and which side each interface is (interface -> inside
    or outside), from the notes that follow them (by zone, or toward the address of a published host)."""
    members = ios_zone_members(text)
    commands: List[str] = []
    sides: Dict[str, str] = {}
    lines = text.splitlines()
    if "! NAT, which changes traffic at once on interfaces with ip nat inside or outside:" not in lines:
        return [], {}
    for line in lines[lines.index("! NAT, which changes traffic at once on interfaces with ip nat inside or outside:") + 1:]:
        if not line.startswith("! ") or line.startswith("! Not written"):
            break
        body = line[2:]
        side = re.match(r"\(the interfaces (?:of zone (\S+)|toward (\S+), .*): ip nat (inside|outside)\)$", body)
        if side:
            zone, address, which = side.groups()
            for port, member in members.items():
                if (zone and member == zone) or (address and ipaddress.ip_address(address.rstrip(",")) in
                                                 ipaddress.ip_network(labplan.ZONES[_IOS_ZONE_OF[port]])):
                    sides.setdefault(port, which)
        elif not body.startswith("("):
            commands.append(body)
    return commands, sides


def _c8000v_session(out: Path) -> List[str]:
    text = out.read_text(encoding="utf-8")
    members = ios_zone_members(text)
    nat, sides = ios_nat(text)
    base = []
    for zone, port in _IOS_PORTS.items():
        base += [f"interface {port}", f" ip address {_addr(zone)} 255.255.255.0", " no shutdown"]
        if port in members:
            base.append(f" zone-member security {members[port]}")
        if port in sides:  # (0.37.0: the lab policy's NAT; the output leaves it as comments, as it leaves the zones)
            base.append(f" ip nat {sides[port]}")
        base.append(" exit")
    return ["terminal length 0", "configure terminal", *_lines(out, "!", drop_end=True), *base, *nat, "end", "exit"]


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
        "username {user} nopassword privilege 15", "username {user} attributes", " service-type admin",
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


def _c8000v_user_data() -> str:
    """Day 0 configuration in the user data (Cisco's format: `Section: IOS configuration`, one command a line). The second
    run: every login of ec2-user refused, "Permission denied (publickey...)"; the image (IOS XE 26.02) takes no ssh-rsa
    signature by default (SSH_COMPLIANCE_SSH_RSA_DISABLED, from 17.16.1), and its own set-up gave ec2-user the AWS key as
    an MD5 key-hash. Here the run's key is given whole (key-string, wrapped) and the RSA signatures are allowed, with
    ssh-rsa for a client that is not told which the router takes. {ssh_key_lines}: the key's base64 part, wrapped."""
    return "\n".join(["Section: IOS configuration", "hostname fwlab-c8k",
                      "ip ssh server algorithm publickey rsa-sha2-512 rsa-sha2-256 ssh-rsa",
                      "ip ssh pubkey-chain", " username {user}", "  key-string", "{ssh_key_lines}", "  exit", " exit", " exit", ""])  # fmt: skip


# All three data interfaces listed by `show ip interface brief` (an interface line: the name at the start of a line;
# filtered, so that no pager stops it).
_C8000V_READY = r"(?sm)(?=.*^GigabitEthernet2\s)(?=.*^GigabitEthernet3\s)(?=.*^GigabitEthernet4\s)"


def _c8000v_diagnose() -> List[str]:
    """The router's interfaces, zones, zone pairs with their sessions and counters, routes, and the configuration."""
    return ["terminal length 0", "show version", "show ip interface brief", "show zone security", "show zone-pair security",
            "show policy-map type inspect zone-pair", "show policy-map type inspect zone-pair sessions", "show ip route",
            "show ip arp", "show running-config", "exit"]  # fmt: skip


# -- SonicWall NSv (SonicOS 7) ------------------------------------------------------------------------------------

# AWS's first card is X1 (WAN: management, by DHCP) and the second X0 (LAN), as SonicWall's AWS guide says; the third
# and fourth are taken to be X2 and X3. The interfaces go in SonicOS's own zones, LAN, DMZ and WAN, and the policy is
# converted for those names (--zone-map): SonicOS 8.2.2 (the sixth to eighth runs) refused `ip-assignment inside static`
# at `inside`, the zone made by the CLI and committed, with configure mode left and entered again. Their default rules
# (LAN to WAN allowed, ...) end in the rules that deny the conversion adds, and the NAT policies SonicOS adds for a WAN
# interface in the NAT policy that translates nothing.
_SW_PORTS = {"inside": "X0", "dmz": "X2", "outside": "X3"}
# What SonicOS says when it refuses a line: "% Error: ..." with the reason, or the marker under the word it did not take.
# Not every line that starts with "%" (its status: "% User logout.", "% Applying changes...", "% Changes made."), nor
# "% Error encountered processing command:", which a commit writes above every rule it adds (the thirteenth run).
_NSV_REFUSED = r"% Error:|% Error encountered at|Unknown command|Invalid input|not allowed"
_SW_ZONES = {"inside": "LAN", "dmz": "DMZ", "outside": "WAN"}


# SonicOS's pager stops a long answer at "--MORE--" and waits for a key: the eleventh run's commit failed, and its
# reason was below the pager. No command switched it off (`cli screen length session 1600`, from SonicWall's article for
# SonicOS 7, refused at `screen` by SonicOS 8.2.2, the twelfth run): the lab answers it with a space.
_SW_PAGER = r"--MORE--\s*$"


def _sonicwall_session(out: Path) -> List[str]:
    base = ["configure terminal"]
    for zone, port in _SW_PORTS.items():
        base += [f"interface {port}", f"ip-assignment {_SW_ZONES[zone]} static", f"ip {_addr(zone)} netmask 255.255.255.0", "exit",
                 "management ping", "exit"]  # fmt: skip
    base += ["commit", "exit"]
    return [*base, *_lines(out, "#"), "exit"]


# A login question at the end of what the session wrote, perhaps followed by a terminal's escape codes. SonicOS 8 on the
# NSv (the fifth run, by hand): its window shows the boot log, and "User:" with a line of that log written after it
# ("User:delay interval:60, clockrate:1, report interval:15"): the question is the last line that starts with it.
_ESCAPES = r"(?:\x1b\[[0-9;?]*[A-Za-z]|\s)*$"
_ASKS_USER = r"(?i)(?:^|\n)\s*(?:user|login)(?:name)?:[^\n]*" + _ESCAPES
_ASKS_PASSWORD = r"(?i)(?:^|\n)\s*password: ?" + _ESCAPES
# SonicOS's first login as admin: "Your password is too simple and must be changed", then the old password, a new one
# (at least 8 characters, an upper and a lower case letter, a digit and one of !@#$%^&*(); a dash refused) and again.
_ASKS_OLD_PASSWORD = r"(?i)enter old password[^\n]*: ?" + _ESCAPES
_ASKS_NEW_PASSWORD = r"(?i)enter a new password[^\n]*: ?" + _ESCAPES
_ASKS_NEW_AGAIN = r"(?i)re-enter new password[^\n]*: ?" + _ESCAPES
# The NSv's two windows, switched between with Ctrl+S and a space: the SonicCore console (prompt "NSv >": show
# system|sonicos|status..., no show version) and SonicOS. SSH lands in the window last used; the fifth run's tries after
# its first all switched from SonicOS to the console, and typed show version there ("Syntax error: Illegal parameter").
_NSV_CORE_PROMPT = r"(?:^|\n)NSv\s*>\s*$"
# SonicOS's own prompts (admin@SERIAL>, config(SERIAL)#): no space before > or #, which the console's "NSv >" has. A
# sub-mode's prompt names its object in brackets, with the spaces of its name (the fourteenth run waited at
# "(add-ipv4-address-group[FWSHIFT all IPv4])#"). Or only the end of one: after a line longer than the terminal, SonicOS
# scrolls its screen to the left and leaves it so, and the prompt shows without its first characters (the sixteenth
# run: "config(004010211E1B)# " scrolled 20 columns, "# ").
_NSV_PROMPT = r"(?:^|[\n@])(?:[^\s>#@\[]|\[[^\]\n]*\]|[^\s>#@\[]*\])*(?:\([^)\s]*\))?\)?[>#] ?$"


# What only the SonicOS CLI's `show version` answers: its fields. The third NSv run took "Please wait for SonicOS to
# startup ..." on the SonicCore console (which then said "CPU configuration updated, will reboot in 10 seconds") for an
# answer, called the NSv ready, and its load met the reboot.
# The CLI writes them lowercase with hyphens (firmware-version "SonicOS ..."); the console's boot text has "Firmware
# Version : SonicOSX ..." and "Serial Number :", which must not count (the fourth run: the console seen, the CLI's
# prompt `NSv >` reached, never recognised).
_NSV_READY = r"firmware-version|rom-version|serial-number|system-uptime"
# Its status bar, redrawn after every output: "SonicWall (c) 2026 |   [Ctrl-s spacebar] to switch console".
_NSV_STATUS_BAR = r"SonicWall \(c\) \d{4} \|\s*\[Ctrl-s spacebar\] to switch console"


# The answers, in the order they are looked for: the forced change first (the old password is the one this session
# logged in with), then the logins: the instance id (SonicWall's AWS guide; the fifth run, by hand: taken, and "too
# simple"), the run's own password (set by an earlier session), "password" (SonicWall's SonicOS 8 guides), each tried
# once a session.
_NSV_ANSWERS = ((_ASKS_OLD_PASSWORD, "{previous}"), (_ASKS_NEW_PASSWORD, "{new_password}"), (_ASKS_NEW_AGAIN, "{new_password}"),
                (_ASKS_USER, "admin"), (_ASKS_PASSWORD, "{password}"), (_ASKS_USER, "admin"), (_ASKS_PASSWORD, "{new_password}"),
                (_ASKS_USER, "admin"), (_ASKS_PASSWORD, "password"))  # fmt: skip


def nsv_password(work: Path) -> str:
    """SonicOS's new admin password for the run, made once and kept in the work folder (later sessions log in with it):
    what SonicOS 8 takes, at least 8 characters with an upper and a lower case letter, a digit and one of !@#$%^&*()."""
    path = work / "sonicwall_password.txt"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    password = "Fw" + secrets.token_hex(8) + "#7"
    path.write_text(password + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return password


def _sonicwall_diagnose() -> List[str]:
    """The interfaces, zones, access rules and connections as SonicOS shows them."""
    # (`show interfaces ip` and `show route` ambiguous on SonicOS 8.2.2, the eighteenth run)
    return ["show interfaces ipv4", "show zones", "show access-rules", "show nat-policies", "show connections", "show routing", "exit"]


# -- pfSense Plus and OPNsense (config.xml over SSH) -------------------------------------------------------------

# The first network card is the image's WAN (DHCP: management); the zones are OPT1 to OPT3 on the second to fourth,
# named ena1 to ena3 on an instance with the ENA driver (c5, m5).
_PF_AWS_ZONES = {"inside": "opt1", "dmz": "opt2", "outside": "opt3"}
_PF_AWS_PORTS = {"inside": "ena1", "dmz": "ena2", "outside": "ena3"}
_PF_AWS_OPTIONS = [*(x for z, i in _PF_AWS_ZONES.items() for x in ("--zone-map", f"{z}={i}")), *labplan.zone_options(_PF_AWS_ZONES)]


def assign_zone_interfaces(xml: str, flavour: str, cards: Optional[Dict[str, str]] = None) -> str:
    """The zones on the data interfaces: OPT1 to OPT3 on ena1 to ena3, enabled, with the lab's address (.4/24), private
    networks and bogons not blocked. An interface the image had on one of those cards (LAN, say) is taken out; WAN, the
    management interface, stays as it is."""
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    root = ET.fromstring(xml, parser=parser)
    interfaces = root.find("interfaces")
    if interfaces is None:
        interfaces = ET.SubElement(root, "interfaces")
    cards = cards or _PF_AWS_PORTS
    ports = set(cards.values())
    for child in list(interfaces):
        name = child.findtext("if") or ""
        if child.tag in _PF_AWS_ZONES.values() or (name in ports and child.tag != "wan"):
            interfaces.remove(child)
    on = "" if flavour == "pfsense" else "1"
    for zone, key in _PF_AWS_ZONES.items():
        entry = ET.SubElement(interfaces, key)
        for tag, text in (("enable", on), ("if", cards[zone]), ("descr", zone), ("ipaddr", _addr(zone)),
                          ("subnet", "24"), ("spoofmac", "")):  # fmt: skip
            ET.SubElement(entry, tag).text = text
    return '<?xml version="1.0"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


_WEB_SERVER_IN_PF = tier2.WEB_SERVER_IN_PF


def keep_management_rules(base_xml: str, merged_xml: str) -> str:
    """The image's own rules for its WAN, the management interface, kept in front of the converted rules. The merge
    replaces the rules as a restore does; the first pfSense run lost the image's "Default SSH rule" on WAN that way, and
    after the reboot SSH timed out for good. Both the rule list of pfSense and OPNsense's legacy one (filter/rule), and
    OPNsense's own (OPNsense/Firewall/Filter/rules/rule), keep their WAN rules."""
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    base = ET.fromstring(base_xml)
    merged = ET.fromstring(merged_xml, parser=parser)
    for path in ("filter", "OPNsense/Firewall/Filter/rules"):
        old = base.find(path)
        if old is None:
            continue
        keep = [rule for rule in old.findall("rule") if (rule.findtext("interface") or "").strip() == "wan"]
        if not keep:
            continue
        target = merged
        for part in path.split("/"):
            found = target.find(part)
            target = found if found is not None else ET.SubElement(target, part)
        for position, rule in enumerate(keep):
            target.insert(position, rule)
    return '<?xml version="1.0"?>\n' + ET.tostring(merged, encoding="unicode") + "\n"


def _scp_prefix(runner: Runner, key: Path, options: Sequence[str]) -> List[str]:
    extra = [word for option in options for word in ("-o", option)]
    return ["scp", "-q", "-i", str(key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={runner.work / 'known_hosts'}", "-o", "ConnectTimeout=10", *extra]  # fmt: skip


def load_pf_config(runner: Runner, vendor: "Vendor", key: Path, host: str, out: Path) -> None:
    """pfSense and OPNsense: the image's config.xml with the areas of the conversion put in (as a restore of each area
    does) and the zones on the data interfaces, written back; then a reboot, so that interfaces and rules start
    together. Ready again when the last zone's address is on its card; loaded when pf has a rule for the lab's web
    server (load.txt)."""
    flavour = vendor.target
    prefix = labrun.ssh_prefix(key, vendor.user, host, runner.work / "known_hosts", options=vendor.ssh_options)
    sample = (labrun.REPO / "tests" / "data" / f"{flavour}_sample.xml").read_text(encoding="utf-8")
    base = runner.run(prefix + [f"{vendor.sudo}cat /conf/config.xml"], quiet=True, fake=sample)
    if "<interfaces>" not in base:
        raise LabError(f"/conf/config.xml of the firewall could not be read: {base[-300:]!r}")
    (runner.work / "config.base.xml").write_text(base, encoding="utf-8")
    cards = vendor.ports or _PF_AWS_PORTS
    merged = assign_zone_interfaces(keep_management_rules(base, tier2.merge_areas(base, out.read_text(encoding="utf-8"), flavour)), flavour, cards)
    merged_file = runner.work / "config.merged.xml"
    merged_file.write_text(merged, encoding="utf-8")
    runner.run(_scp_prefix(runner, key, vendor.ssh_options) + [str(merged_file), f"{vendor.user}@{host}:fwlab-config.xml"], timeout=300)
    write = f"{vendor.sudo}cp fwlab-config.xml /conf/config.xml && {vendor.sudo}rm -f /tmp/config.cache && echo FWLAB-WRITTEN"
    answer = runner.run(prefix + [write], fake="FWLAB-WRITTEN")
    if "FWLAB-WRITTEN" not in answer:
        raise LabError(f"the merged config.xml was not written: {answer[-300:]!r}")
    runner.run(prefix + [f"{vendor.sudo}shutdown -r now"], check=False, quiet=True, timeout=60)  # (the connection drops)
    if not runner.dry_run:
        time.sleep(60)
        wait_cli(runner, key, vendor.user, host, f"ifconfig {cards['outside']}", _addr("outside").replace(".", r"\."),
                 15, vendor.ssh_options, as_command=True)  # fmt: skip
    shown = runner.run(prefix + ["ifconfig"], quiet=True, fake="".join(f"{p}: inet {_addr(z)}\n" for z, p in cards.items()))
    rules = runner.run(prefix + [f"{vendor.sudo}pfctl -sr"], quiet=True, fake="pass in quick on ena1 inet proto tcp from 10.20.1.0/24 to 10.20.2.10")
    nat = runner.run(prefix + [f"{vendor.sudo}pfctl -sn"], quiet=True, check=False, fake="nat on ena3 inet from 10.20.1.0/24 to any -> 10.20.3.4")
    (runner.work / "load.txt").write_text(f"{answer}\n--- ifconfig\n{shown}\n--- pfctl -sr\n{rules}\n--- pfctl -sn\n{nat}", encoding="utf-8")
    missing = [z for z in ORDER if _addr(z) not in shown]
    if missing:
        raise LabError(f"after the reboot, the zones {', '.join(missing)} have no address on their card (load.txt)")
    if not re.search(_WEB_SERVER_IN_PF, rules):  # (the web server of the lab policy: its rules are in pf, or the configuration did not take)
        raise LabError("after the reboot, pf has no rule for the lab's web server (load.txt)")


def _pf_diagnose() -> List[str]:
    """pf's rules with their counters, its states and statistics, the interfaces and the routes."""
    return ["pfctl -vsr", "pfctl -ss", "pfctl -si", "ifconfig", "netstat -rn"]


# -- Check Point (All-In-One: gateway and management on one instance) --------------------------------------------

# The data interfaces by zone: the second to fourth network card are eth1 to eth3 (Check Point's templates: device
# index N = ethN). The hostname names the gateway object of the standalone.
_CP_PORTS = {"inside": "eth1", "dmz": "eth2", "outside": "eth3"}
_CP_HOSTNAME = "fwlab-cp"


def _checkpoint_user_data() -> str:
    """The first-time setup as Check Point's own Terraform module for a standalone writes it (standalone_userdata.yaml,
    terraform-aws-cloudguard-network-security, October 2026): the image's /etc/cloud_config.py with the installation
    type, the admin shell (bash, for mgmt_cli over SSH) and the hostname. No admin password: SSH takes the run's key
    and the lab uses `mgmt_cli -r true`. {os_version} is the image's (R82.20), from its name."""
    values = {"enableCloudWatch": "false", "installationType": "standalone", "osVersion": "{os_version}", "allowUploadDownload": "true",
              "templateVersion": "1.2.1", "templateName": "standalone", "templateType": "terraform_registry", "shell": "/bin/bash",
              "enableInstanceConnect": "false", "hostName": _CP_HOSTNAME, "ntpPrimary": "169.254.169.123", "ntpSecondary": "0.pool.ntp.org",
              "passwordHash": "", "MaintenanceModePassword": "", "adminSubnet": "0.0.0.0/0", "allocatePublicAddress": "false",
              "bootstrapScript64": ""}  # fmt: skip
    command = "python3 /etc/cloud_config.py " + " ".join(f'{name}=\\"{value}\\"' for name, value in values.items())
    return "#cloud-config\nruncmd:\n  - |\n    " + command + "\n"


def checkpoint_driver() -> str:
    """The lab's load on the standalone, run in bash after FWShift's script and it are copied over: the data interfaces'
    addresses (clish), FWShift's script in a session of its own, the interfaces' topology and security zones (one
    `set simple-gateway` naming every interface, eth0 too: it replaces the list), a rule that lets the lab manage the
    gateway, publish, and the install of the policy package. It prints FWLAB-FAILED and why at the first step that
    fails, and FWLAB-LOADED-42 at the end.

    The management rule: on a standalone the management interface (eth0) is under the policy too, and the converted
    policy ends its layer in FWShift's cleanup rule (drop): the first run (0.40.18) lost its SSH session to eth0 at the
    install ("Timeout, server not responding"), and with it the load's output. SSH and HTTPS (the Management API) from
    the address the lab's session comes from ($SSH_CLIENT) to the gateway, at the top of layer Network; the AWS security
    group lets only that address reach eth0 anyway, and the rule names none of the lab's zones."""
    lines = ["#!/bin/bash", "# The FWShift lab: the converted policy onto a Check Point standalone (gateway and management on one instance).",
             '[ -r /etc/profile.d/CP.sh ] && . /etc/profile.d/CP.sh', 'cd "$HOME" || exit 2',
             'step() { echo "== $*"; }',
             'fail() { echo "FWLAB-FAILED: $*"; if [ -f fwshift.sid ]; then mgmt_cli discard -s fwshift.sid >/dev/null 2>&1; '
             'mgmt_cli logout -s fwshift.sid >/dev/null 2>&1; fi; exit 1; }',
             'step "data interfaces"']  # fmt: skip
    for zone, port in _CP_PORTS.items():
        lines += [f'clish -c "set interface {port} ipv4-address {_addr(zone)} mask-length 24" -s || fail "the address of {port}"',
                  f'clish -c "set interface {port} state on" -s || fail "{port} on"']  # fmt: skip
    lines += ["ip -4 -o addr show",
              'step "the gateway object"',
              'mgmt_cli login -r true > fwshift.sid || fail "mgmt_cli login -r true"',
              'mgmt_cli show gateways-and-servers details-level standard -s fwshift.sid -f json > gateways.json || fail "show gateways-and-servers"',
              "python3 -c 'import json,sys; [print(o.get(\"name\"), o.get(\"type\")) for o in json.load(open(sys.argv[1])).get(\"objects\", [])]' gateways.json",
              # (a simple-gateway by the hostname, else any simple-gateway, else the object by the hostname: the type of a
              # standalone's object is not confirmed)
              "GW=$(python3 -c 'import json,sys; a=json.load(open(sys.argv[1])).get(\"objects\", []); g=[x for x in a if x.get(\"type\") == \"simple-gateway\"]; "
              f"n=[x[\"name\"] for x in g if x.get(\"name\") == \"{_CP_HOSTNAME}\"] or [x[\"name\"] for x in g] or "
              f"[x[\"name\"] for x in a if x.get(\"name\") == \"{_CP_HOSTNAME}\"]; print(n[0] if n else \"\")' gateways.json)",
              '[ -n "$GW" ] || fail "no gateway object on the management (the objects are listed above)"',
              'echo "gateway object: $GW"',
              'step "the converted policy"',
              # (hide NAT names the gateway object, converted with --target-gateway {_CP_HOSTNAME}: the object found)
              f'[ "$GW" = "{_CP_HOSTNAME}" ] || sed -i "s/{_CP_HOSTNAME}/$GW/g" ./policy.checkpoint',
              'SID=fwshift.sid sh ./policy.checkpoint || fail "the converted policy (the call above)"',
              'step "topology and security zones"',
              "E0=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | head -n 1)",
              '[ -n "$E0" ] || fail "no address on eth0"']  # fmt: skip
    interfaces = ['interfaces.1.name eth0 interfaces.1.ipv4-address "${E0%/*}" interfaces.1.ipv4-mask-length "${E0#*/}" '
                  'interfaces.1.topology external interfaces.1.anti-spoofing false']
    for index, (zone, port) in enumerate(_CP_PORTS.items(), 2):
        prefix = f"interfaces.{index}."
        interfaces.append(f"{prefix}name {port} {prefix}ipv4-address {_addr(zone)} {prefix}ipv4-mask-length 24 {prefix}topology internal "
                          f'{prefix}topology-settings.ip-address-behind-this-interface "network defined by the interface ip and net mask" '
                          f"{prefix}anti-spoofing false {prefix}security-zone true {prefix}security-zone-settings.auto-calculated false "
                          f"{prefix}security-zone-settings.specific-zone {zone}")  # fmt: skip
    lines += ['mgmt_cli set simple-gateway name "$GW" ' + " ".join(interfaces) + ' ignore-warnings true -s fwshift.sid || fail "set simple-gateway (interfaces and zones)"',
              'step "the lab\'s management of the gateway"',
              'ADMIN=${SSH_CLIENT%% *}',
              '[ -n "$ADMIN" ] || fail "no SSH_CLIENT: the address the lab manages from is not known"',
              'echo "managed from: $ADMIN"',
              'mgmt_cli add host name fwlab-admin ip-address "$ADMIN" ignore-warnings true -s fwshift.sid || fail "the host the lab manages from"',
              'mgmt_cli add access-rule layer Network position 1 name "FWLAB management" source.1 fwlab-admin destination.1 "$GW" '
              'service.1 ssh service.2 https action Accept track.type Log comments "The FWShift lab: its own access to the gateway, not the converted policy" '
              'ignore-warnings true -s fwshift.sid || fail "the management rule"',
              'step "publish"', 'mgmt_cli publish -s fwshift.sid || fail "publish"',
              'step "install"',
              'mgmt_cli install-policy policy-package Standard access true threat-prevention false targets.1 "$GW" -s fwshift.sid || fail "install-policy"',
              "mgmt_cli logout -s fwshift.sid >/dev/null 2>&1", "rm -f fwshift.sid", "fw stat",
              'echo "FWLAB-LOADED-$((40 + 2))"']  # fmt: skip
    return "\n".join(lines) + "\n"


def _checkpoint_uploads(out: Path) -> List[Path]:
    driver = out.with_name("fwlab_load.sh")
    driver.write_text(checkpoint_driver(), encoding="utf-8")
    return [out, driver]


def _checkpoint_session(out: Path) -> List[str]:
    # (its output kept on the gateway as well: the first run's SSH session died at the install, and what the script had
    # said died with it; the diagnose step shows the file)
    return ["bash ./fwlab_load.sh 2>&1 | tee fwlab_load.log", "exit"]


def _checkpoint_diagnose() -> List[str]:
    """The gateway's policy and interfaces, the management's rulebase, and the end of the first-time setup's log."""
    return ["tail -n 80 fwlab_load.log", "fw stat", "ip -4 -o addr show", "ip route", "clish -c 'show interfaces all'", "cpstat fw -f policy",
            "mgmt_cli -r true show access-rulebase name Network details-level standard -f json | head -c 40000",
            "tail -n 60 /opt/CPcge/log/boot.log 2>/dev/null || tail -n 60 \"$CGEDIR/log/boot.log\"", "exit"]  # fmt: skip


def checkpoint_version(image_name: str) -> str:
    """The Gaia version in the image's name (R82.20, R81.20, R82), for the setup's osVersion; R82 when it says none."""
    found = re.search(r"\bR(\d{2}(?:\.\d{1,2})?)", image_name or "")
    return "R" + found.group(1) if found else "R82"


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
# The SonicWall's interfaces for the PAN-OS ones (inside X0, dmz X2, outside X3; X1 is the management): the hide NAT
# names the interface it leaves by.
_SONICWALL_INTERFACES = ["--interface-map", "ethernet1/2=X0", "--interface-map", "ethernet1/3=X2", "--interface-map", "ethernet1/1=X3"]
_SONICWALL_ZONES = [*(x for z, n in _SW_ZONES.items() for x in ("--zone-map", f"{z}={n}")), *labplan.zone_options(_SW_ZONES)]

VENDORS: Dict[str, Vendor] = {
    "fortigate": Vendor("fortigate", "FortiGate-VM (pay as you go)", "fortios", "FortiGate-VM64-AWSONDEMAND*", "c5.xlarge", "admin",
                        "get system status", r"Command fail|command parse error|Unknown action|entry not found|value parse error",
                        [x for z, p in _FGT_PORTS.items() for x in ("--zone-map", f"{z}={p}")], _fortigate_user_data(), _fortigate_session,
                        ready_answer=r"Version:", status="run: passed (FortiOS 8.0.1, 0.32.1)"),  # fmt: skip
    "panos": Vendor("panos", "Palo Alto VM-Series (pay as you go bundle)", "panos", "PA-VM-AWS-*", "m5.xlarge", "admin", "show chassis-ready",
                    r"Invalid syntax|Server error|Commit failed|Validation Error|is not a valid reference|Unknown command", _PAN_INTERFACES, "", _panos_session,
                    ready_answer=r"\byes\b", success=r"Configuration committed successfully",
                    product_codes=("e9yfvyj3uag5uo5j2hjikv74n",), prepare=_panos_prepare, status="run: passed (PAN-OS 11.2.15, 0.32.1)"),  # fmt: skip  (PAYG Bundle 1; Bundle 2 is hd44w1chf26uv4p52cdynb2o, by --ami)
    # Ready once the data interfaces exist: the CLI answers minutes before the forwarding engine makes them (the second
    # vSRX run loaded and probed 10 seconds after `show version` answered, and found no ge-0/0/x). (`| no-more`: the
    # first run stopped at the pager's ---(more)---, which took the `exit` after it for a filter, and every try hung.)
    "vsrx": Vendor("vsrx", "Juniper vSRX (pay as you go)", "junos", "junos-vsrx3-x86-64-*,*vSRX*", "c5.xlarge", "ec2-user",
                   "show interfaces terse | match ge-0/0 | no-more", r"syntax error|^error:|\nerror:|missing mandatory|unknown command", [], "",
                   _vsrx_session, ready_answer=_VSRX_READY,
                   success=r"commit complete", diagnose=_vsrx_diagnose,
                   status="run: passed (vSRX 23.4R2-S8.9, appsec PAYG, 0.36.1; NAT included, 0.41.0)"),
    # The All-In-One image (gateway and management): Check Point's templates find it by a map of ids, not a name; the
    # lab takes the subscribed product among the images named Check Point or CloudGuard (find_ami), or --ami, the id the
    # subscription's launch page shows. 16 GB: the management API may not start below 8.
    "checkpoint": Vendor("checkpoint", "Check Point All-In-One, gateway and management (pay as you go)", "checkpoint", "Check Point*,*CloudGuard*", "m5.xlarge", "admin",
                         "api status", r"FWLAB-FAILED|FAILED: mgmt_cli", ["--target-gateway", _CP_HOSTNAME], _checkpoint_user_data(), _checkpoint_session,
                         ready_answer=r"API readiness test SUCCESSFUL", success=r"FWLAB-LOADED-42", diagnose=_checkpoint_diagnose,
                         uploads=_checkpoint_uploads, boot_minutes=60,
                         status="scripted from Check Point's templates and API reference; passed on AWS (0.40.21, R82.20 All-In-One, NAT included) after three runs"),  # fmt: skip
    # Ready once its data interfaces are listed (the vSRX had none for a while after its CLI answered); lines typed one at
    # a time after the prompt (the ASAv lost what was typed ahead); a 2048-bit key (the ASAv's limit; the size AWS makes).
    # The image: "Cisco Catalyst 8000V SD-WAN & Router - PAYG - DNA Essentials", named Cisco-C8K-PAYG-ESS-<version>-<id>
    # (26.02.01, October 2026); the pattern leaves out the bring-your-own-licence and DNA Advantage editions.
    "c8000v": Vendor("c8000v", "Cisco Catalyst 8000V, IOS XE (pay as you go, DNA Essentials)", "ios", "Cisco-C8K-PAYG-ESS-*", "c5.xlarge", "ec2-user",
                     "show ip interface brief | include GigabitEthernet", r"% Invalid input|% Incomplete command|% Ambiguous command|% Unknown command",
                     [x for p, i in (("ethernet1/2", "GigabitEthernet2"), ("ethernet1/3", "GigabitEthernet3"), ("ethernet1/1", "GigabitEthernet4"))
                      for x in ("--interface-map", f"{p}={i}")] + list(_ZONE_NETWORKS), _c8000v_user_data(), _c8000v_session, ready_answer=_C8000V_READY,
                     key_bits=2048, diagnose=_c8000v_diagnose, prompt=r"[>#] ?$", ssh_options=("PubkeyAcceptedAlgorithms=+ssh-rsa",),
                     status="run: passed (Catalyst 8000V, IOS XE 26.02.1, PAYG DNA Essentials, 0.36.3)"),  # fmt: skip
    # Netgate's pfSense Plus ("Netgate pfSense Plus Firewall/VPN/Router", named pfSense-plus-ec2-26.07-RELEASE-amd64...,
    # the x86 AMI, not the CloudFormation offer) and Deciso's OPNsense (its image name not seen yet: the subscribed one
    # among those named OPNsense, find_ami): hourly images.
    # The image's WAN on the first card is management, by DHCP.
    "pfsense": Vendor("pfsense", "Netgate pfSense Plus (hourly)", "pfsense", "pfSense-plus-ec2-*-RELEASE-amd64*", "c5.xlarge", "admin", "ifconfig ena3", r"$^",
                      _PF_AWS_OPTIONS, ready_answer=r"ena3:", as_command=True, load=load_pf_config, diagnose=_pf_diagnose,
                      status="run: passed (pfSense Plus 26.07, 0.36.4; NAT included, 0.41.0)"),  # fmt: skip
    "opnsense": Vendor("opnsense", "OPNsense, Deciso's image (hourly)", "opnsense", "*OPNsense*,*opnsense*", "c5.xlarge", "ec2-user", "ifconfig ena3", r"$^",
                       _PF_AWS_OPTIONS, ready_answer=r"ena3:", as_command=True, sudo="sudo ", load=load_pf_config, diagnose=_pf_diagnose,
                       status="run: passed (OPNsense 26.1.5, 0.36.4; NAT included, 0.41.2)"),  # fmt: skip
    # SonicWall NSv, pay as you go (the subscribed product among the images named SonicWall or NSv, find_ami). SonicWall's
    # AWS guide: SSH as `management` with the key pair; Ctrl+S and a space switch between the SonicCore console and the
    # SonicOS CLI, which asks for its own user (admin) and password (the instance id). The first run: `admin` refused,
    # "Only 'management' user is allowed to login". The fifth (SonicOS 8.2.2, by hand): SSH lands in the window last
    # used, SonicOS's "User:" has a log line after it, and the first login must change the password. Leaving the CLI goes
    # back to the console: the lab closes the session.
    "sonicwall": Vendor("sonicwall", "SonicWall NSv (pay as you go)", "sonicwall", "*SonicWall*,*Sonicwall*,*sonicwall*,*NSv*", "c5.xlarge", "management", "show version",
                        _NSV_REFUSED, [*_SONICWALL_ZONES, *_SONICWALL_INTERFACES], "", _sonicwall_session,
                        ready_answer=_NSV_READY, prompt=_NSV_PROMPT, preamble="\x13 ", preamble_when=_NSV_CORE_PROMPT, pager=_SW_PAGER, idle=15, slow=r"^commit$", close_after=15, boot_minutes=45,
                        screen_noise=_NSV_STATUS_BAR, answers=_NSV_ANSWERS, diagnose=_sonicwall_diagnose,
                        status="scripted from SonicWall's AWS guide; passed on AWS (0.40.16, SonicOSX 8.2.2, NAT included) after twenty runs"),  # fmt: skip
    # Sophos Firewall, the PAYG listing "Sophos Cloud Firewall" (SFOS 22.0 MR2, 0.41.4; lab/sophos.py). The first-boot
    # data is JSON, the admin password in Secrets Manager; the XML API is turned on by hand, once (sophos.enable_api).
    "sophos": Vendor("sophos", "Sophos Firewall (PAYG)", "sophos", "*sophos*,*Sophos*,*SOPHOS*", "c5.xlarge", "admin", "", "",
                     list(sophos.OPTIONS), sophos.user_data("{run_id}", "{region}"), key_bits=2048, boot_minutes=40,
                     # (the PAYG product, sophos_xg_standalone_22.0.2.546-payg-*: one of five products named Sophos in
                     # us-east-1, the first run's look-up, 0.41.4)
                     product_codes=("31lokbvwfdxe8t385jh45lgpu",),
                     load=lambda runner, vendor, key, host, out: sophos.load(runner, vendor, key, host, out, sophos.password(runner.work),
                                                                           {zone: _addr(zone) for zone in ORDER}),
                     api=True, mgmt_index=1, mgmt_ports=(22, sophos.API_PORT), secrets=("admin", "backup"), imdsv2=True,
                     status="scripted from Sophos's CloudFormation templates and XML API documentation; passed on AWS (0.41.5, SFOS 22.0 MR2, NAT included; four web connections answered by its web proxy, counted as blocked); one step by hand (the XML API)"),  # fmt: skip
    "asav": Vendor("asav", "Cisco ASAv (pay as you go)", "asa", "asav*,*ASAv*", "c5.xlarge", "admin", "show version | include up",
                   r"ERROR:|% Invalid input|% Incomplete command", list(_ZONE_NETWORKS), _asav_user_data(), _asav_session,
                   "run: passed (ASAv 9.24.10, 0.36.1; NAT included, 0.40.21)",
                   ready_answer=r" up ", key_bits=2048, ssh_options=("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa"),
                   diagnose=_asav_diagnose, prompt=r"[>#] ?$", ports_command="show interface ip brief"),
}

def _fortigate_azure_data() -> str:
    """FortiGate on Azure: its custom data as Fortinet's own Azure templates write it (MIME, the configuration as
    text/x-shellscript), with the run's key for the VM's user, whom Azure makes (it takes no user named admin)."""
    config = _fortigate_user_data() + "\n".join(["config system admin", '    edit "{user}"', '        set accprofile "super_admin"',
                                                  '        set vdom "root"', '        set ssh-public-key1 "ssh-rsa {ssh_key}"', "    next", "end", ""])  # fmt: skip
    return ('Content-Type: multipart/mixed; boundary="==FWLAB=="\nMIME-Version: 1.0\n\n--==FWLAB==\n'
            'Content-Type: text/x-shellscript; charset="us-ascii"\nMIME-Version: 1.0\n\n' + config + "\n--==FWLAB==--\n")


def _checkpoint_azure_data() -> str:
    """Check Point on Azure: /etc/cloud_config.py as the interpreter of the custom data, one value a line, as the
    CloudGuardIaaS templates for Azure write it (cloud-init.sh): a standalone, bash as the admin shell, the API on."""
    values = {"installationType": "standalone", "allowUploadDownload": "true", "osVersion": "{os_version}", "templateName": "standalone",
              "templateVersion": "20240101", "templateType": "terraform", "isBlink": "false", "bootstrapScript64": "", "location": "",
              "managementGUIClientNetwork": "0.0.0.0/0", "enableApi": "all", "adminShell": "/bin/bash", "passwordHash": "",
              "MaintenanceModePassword": ""}  # fmt: skip
    return "#!/usr/bin/python3 /etc/cloud_config.py\n\n" + "".join(f'{name}="{value}"\n' for name, value in values.items())


def _checkpoint_gcp_data() -> str:
    """Check Point on Google Cloud: its startup script as the CloudGuardIaaS module for Google Cloud writes it (#cloud-config,
    /etc/cloud_config.py with the values of a standalone; their own X...X quoting of values with spaces)."""
    values = {"generatePassword": "false", "allowUploadDownload": "true", "templateName": "single_tf", "templateVersion": "20240101",
              "mgmtNIC": "XEphemeral Public IP (eth0)X", "hasInternet": "true", "installationType": "XGateway and Management (Standalone)X",
              "enableMonitoring": "false", "shell": "/bin/bash", "managementGUIClientNetwork": "0.0.0.0/0", "numAdditionalNICs": "3",
              "osVersion": "{os_version}", "MaintenanceModePassword": ""}  # fmt: skip
    command = "python3 /etc/cloud_config.py " + " ".join(f'{name}=\\"{value}\\"' if not value.startswith("X") else f'{name}="{value}"'
                                                         for name, value in values.items())  # fmt: skip
    return "#cloud-config\nruncmd:\n  - '" + command + "'\n"


CLOUD_TITLES = {"aws": "AWS", "azure": "Azure", "gcp": "Google Cloud"}
# Four NICs: on Azure a size with four (Standard_D3_v2 is the smallest: D4s_v5 and F4s_v2 have two); on Google Cloud a
# machine with four vCPUs (as many NICs as vCPUs). The user of the VM on Azure is never admin, which Azure refuses.
_AZ4 = "Standard_D3_v2"
_GCP4 = "n2-standard-4"
# The review of 0.40.0: Google Cloud delivers through each subnet's gateway, not to a neighbour found by ARP (tier 1
# found it for the test hosts, which route their own subnet through the gateway there); the firewalls' zone interfaces
# are set as /24 on the link, as on AWS and Azure, and would not reach the hosts. Google Cloud's way (a /32 address, or
# DHCP, and the subnet through its gateway) is not written for any vendor yet.
_GCP_ON_LINK = ("its zone interfaces are set as /24 on the link, and Google Cloud delivers only through each subnet's gateway: "
                "the firewall would not reach the hosts (a /32 address and the subnet through the gateway are not written yet)")
CLOUD_IMAGES: Dict[str, Dict[str, CloudImage]] = {
    "fortigate": {
        "azure": CloudImage("fortinet:fortinet_fortigate-vm:fortinet_fg-vm_payg_76_g2", _AZ4,
                            changes=(("user", "fwlab"), ("user_data", _fortigate_azure_data())),
                            source="fortinet/fortigate-terraform-deploy, azure/7.6/single"),
        "gcp": CloudImage("projects/fortigcp-project-001/global/images/family/fortigate-72-payg", _GCP4, open_point=_GCP_ON_LINK,
                          source="Fortinet's GCP administration guide (the image families; 7.2 the one confirmed)"),
    },
    "panos": {
        # (no first-boot data: the management interface by DHCP, the rest by the session, as on AWS)
        "azure": CloudImage("paloaltonetworks:vmseries-flex:bundle1", _AZ4, changes=(("user", "fwlab"),),
                            source="PaloAltoNetworks/terraform-azurerm-swfw-modules, modules/vmseries"),
        "gcp": CloudImage("projects/paloaltonetworksgcp-public/global/images/vmseries-flex-bundle1-*", _GCP4, open_point=_GCP_ON_LINK,
                          source="PaloAltoNetworks/terraform-google-swfw-modules, and Palo Alto's list of image names"),
    },
    "vsrx": {
        "azure": CloudImage("juniper-networks:vsrx-next-generation-firewall-payg:vsrx-azure-image-payg-b1", _AZ4, changes=(("user", "fwlab"),),
                            source="Juniper/vSRX-Azure (2022: check the plan with az vm image list --publisher juniper-networks --all)"),
    },
    "c8000v": {
        # (the PAYG plan's name was not found; unlicensed, the BYOL image forwards little, which the probes are)
        "azure": CloudImage("cisco:cisco-c8000v-byol:17_12_01a-byol", _AZ4, changes=(("user", "fwlab"),),
                            status="scripted from Cisco's Azure guide, never run; BYOL (unlicensed: throughput limited)",
                            source="Cisco's Catalyst 8000V Azure guide; a Terraform example of the Marketplace image"),
    },
    "asav": {
        "azure": CloudImage("cisco:cisco-asav:asav-azure-byol", _AZ4, changes=(("user", "fwlab"),),
                            status="scripted from Cisco's Azure guide, never run; BYOL (unlicensed: throughput limited)",
                            source="Cisco's ASAv Azure guide; a Terraform example of the Marketplace image"),
        "gcp": CloudImage("projects/cisco-public/global/images/cisco-asav-9-*", _GCP4, metadata_key="startup-script", open_point=_GCP_ON_LINK,
                          status="scripted from Cisco's ASAv Google Cloud guide, never run; BYOL (unlicensed: throughput limited)",
                          source="gehoumi/terraform-google-ciscoasav-vm (Day 0 in the startup script)"),
    },
    "checkpoint": {
        "azure": CloudImage("checkpoint:check-point-cg-r82:sg-ngtp", _AZ4, changes=(("user_data", _checkpoint_azure_data()),),
                            vm_user="notused", source="CheckPointSW/CloudGuardIaaS, terraform/azure (cloud-init.sh)"),
        "gcp": CloudImage("projects/checkpoint-public/global/images/check-point-r8210-gw-payg-single-*", _GCP4, open_point=_GCP_ON_LINK,
                          changes=(("user_data", _checkpoint_gcp_data()),), metadata_key="startup-script", key_metadata="instanceSSHKey",
                          source="CheckPointSW/CloudGuardIaaS, terraform/gcp/single"),
    },
}
# Where a vendor's image is not on a cloud, or is there in a way the lab cannot use yet.
NOT_ON: Dict[Tuple[str, str], str] = {
    ("vsrx", "gcp"): "on the Marketplace, but its image project was not found (and it takes logins as gcp-user only)",
    ("c8000v", "gcp"): "BYOL only on Google Cloud, and its image project was not found",
    ("pfsense", "azure"): "Netgate's image is there (netgate:pfsense-plus-public-cloud-fw-vpn-router), but its plan was not found and "
                          "Netgate says several NICs cannot be set up from the portal; no first-boot data to put the zones on",
    ("pfsense", "gcp"): "not offered on Google Cloud (Netgate: AWS and Azure)",
    ("opnsense", "azure"): "Deciso's image is there (decisosalesbv:opnsense), with one NIC in its guide; its plan was not found",
    ("opnsense", "gcp"): "no image on Google Cloud",
    ("sonicwall", "azure"): "on Azure as BYOL only (a licence of your own); the offer's id was not found",
    ("sonicwall", "gcp"): "not offered on Google Cloud",
    ("sophos", "azure"): "scripted for AWS first: its first-boot data, ports and secrets differ on Azure (not researched yet)",
    ("sophos", "gcp"): "scripted for AWS first: Sophos Firewall on Google Cloud not researched yet",
}


NOT_SCRIPTED = {
    "stormshield": "Stormshield EVA: the licence of a pay-as-you-go image and snscli's login are not checked yet",
    "barracuda": "Barracuda CloudGen: the REST API needs a token made in Firewall Admin first",
    "watchguard": "WatchGuard: the output is merged into a configuration with Policy Manager, a Windows program",
    "forcepoint": "Forcepoint NGFW: needs a Security Management Center",
    "meraki": "Meraki vMX: needs a Meraki licence and a Dashboard organisation; there is no image to start alone",
}


def find_ami(runner: Runner, region: str, pattern: str, product_codes: Tuple[str, ...] = (), instance_type: str = "c5.xlarge") -> str:
    """The image to start: of the x86 Marketplace images whose name matches one of the vendor's patterns (comma between
    them), and of its pay-as-you-go product where the vendor names it, the newest of a product this account is
    subscribed to. A launch tried with --dry-run tells: AWS answers OptInRequired for a product not subscribed to. One
    product only: no try. Every product found, and what the try said, is kept in amis.txt; --ami settles it."""
    if not pattern and not runner.dry_run:
        raise LabError("this image has no name to look for: give --ami, the id your subscription's launch page shows for the region")
    names = ",".join(part.strip() for part in pattern.split(",") if part.strip())
    codes = ["Name=product-code,Values=" + ",".join(product_codes)] if product_codes else []
    out = runner.run(["aws", "ec2", "describe-images", "--region", region, "--owners", "aws-marketplace", "--filters", f"Name=name,Values={names}",
                      *codes, "Name=architecture,Values=x86_64", "--query",
                      "reverse(sort_by(Images,&CreationDate))[].[ImageId,Name,join(',',ProductCodes[].ProductCodeId)]",
                      "--output", "text"], fake="ami-0dryrun\tdry run\t")  # fmt: skip
    rows = [line.split("\t") for line in out.splitlines() if line.startswith("ami-")]
    if not rows:
        raise LabError(f"no Marketplace image named {names} in {region}: subscribe to it first, or give --ami (the id the subscription shows)")
    products: List[List[str]] = []
    for row in rows:  # (newest first: the first image of each product is its newest)
        code = row[2] if len(row) > 2 else ""
        if all((p[2] if len(p) > 2 else "") != code for p in products):
            products.append(row)
    notes, chosen, unsure = [], None, []
    if len(products) == 1:
        chosen = products[0]
        notes.append(f"{chosen[0]}  {chosen[1]}  product {chosen[2] if len(chosen) > 2 else '?'}: the only product of the name")
    else:
        for row in products[:12]:
            verdict = subscribed(runner, region, row[0], instance_type)
            said = {True: "subscribed", False: "not subscribed (OptInRequired)", None: "not told"}[verdict]
            notes.append(f"{row[0]}  {row[1]}  product {row[2] if len(row) > 2 else '?'}: {said}")
            if verdict:
                chosen = row
                break
            if verdict is None:
                unsure.append(row)
    (runner.work / "amis.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")
    if chosen is None:
        if not unsure:
            raise LabError(f"this account is subscribed to none of the {len(products)} products named {names} in {region} (amis.txt): "
                           "subscribe to the pay-as-you-go one, or give --ami")  # fmt: skip
        chosen = unsure[0]
        print("the dry-run launch did not tell which product is subscribed to (amis.txt): the newest is taken", file=sys.stderr)
    code = chosen[2] if len(chosen) > 2 else ""
    print(f"image {chosen[0]}: {chosen[1] if len(chosen) > 1 else ''} (product code {code or '?'}; {len(products)} products of the name, "
          "amis.txt); give --ami if this is not the image you subscribed to", file=sys.stderr)  # fmt: skip
    labrun.save_state(runner.work, image=chosen[0], image_name=chosen[1] if len(chosen) > 1 else "", product_code=code)
    return chosen[0]


def try_launch(runner: Runner, region: str, ami: str, instance_type: str) -> str:
    """A launch tried with --dry-run (nothing is started): "ok" (DryRunOperation), "not subscribed" (OptInRequired),
    "type not supported" (UnsupportedOperation: the product does not take that instance type), or "not told" (no
    default VPC, and the like)."""
    out = runner.run(["aws", "ec2", "run-instances", "--dry-run", "--region", region, "--image-id", ami, "--instance-type", instance_type,
                      "--count", "1"], check=False, quiet=True, timeout=60)  # fmt: skip
    said = out + runner.last_stderr
    for code, verdict in (("DryRunOperation", "ok"), ("OptInRequired", "not subscribed"), ("UnsupportedOperation", "type not supported")):
        if code in said:
            return verdict
    return "not told"


def subscribed(runner: Runner, region: str, ami: str, instance_type: str) -> Optional[bool]:
    """Whether this account may start the image: True, False (OptInRequired), or None when the try does not tell."""
    verdict = try_launch(runner, region, ami, instance_type)
    return {"ok": True, "not subscribed": False}.get(verdict)


# Instance types the lab can use: x86, the ENA driver (the FreeBSD images name its cards ena0, ena1, ...), four network
# cards or more. The vendor's own comes first; a product takes only some (OPNsense: not c5.xlarge, not m5.xlarge).
INSTANCE_TYPES = ("c5.xlarge", "m5.xlarge", "t3.xlarge", "c6i.xlarge", "m6i.xlarge", "r5.xlarge", "c5n.xlarge", "m5a.xlarge",
                  "c5.2xlarge", "m5.2xlarge")  # fmt: skip


def pick_instance_type(runner: Runner, region: str, ami: str, first: str) -> str:
    """The vendor's instance type, or the first of the others the product takes: each is tried with a dry-run launch,
    which answers UnsupportedOperation for a type the product does not take (the first OPNsense runs). A try that does
    not tell (no default VPC) ends the search with the vendor's own; what each try said goes to instance-types.txt."""
    if runner.dry_run:
        return first
    notes = []
    chosen = first
    for instance_type in dict.fromkeys((first, *INSTANCE_TYPES)):
        verdict = try_launch(runner, region, ami, instance_type)
        notes.append(f"{instance_type}: {verdict}")
        if verdict == "type not supported":
            continue
        chosen = instance_type
        break
    else:
        (runner.work / "instance-types.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")
        raise LabError(f"the image takes none of the instance types {', '.join(dict.fromkeys((first, *INSTANCE_TYPES)))} "
                       "(instance-types.txt): give one it takes with --instance-type (four network cards or more)")  # fmt: skip
    (runner.work / "instance-types.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")
    if chosen != first:
        print(f"instance type {chosen}: the image does not take {first} (instance-types.txt)", file=sys.stderr)
    return chosen


def describe_ami(runner: Runner, region: str, ami: str) -> None:
    """The name of an image given with --ami, for run.json (which version the firewall ran)."""
    out = runner.run(["aws", "ec2", "describe-images", "--region", region, "--image-ids", ami, "--query",
                      "Images[0].[Name,join(',',ProductCodes[].ProductCodeId)]", "--output", "text"], check=False, fake="dry run\t")  # fmt: skip
    fields = out.strip().split("\t")
    if not runner.dry_run and (not fields[0] or fields[0] == "None"):
        # The first 8000V run: an id copied from the launch page of another region went on to Terraform, which failed.
        raise LabError(f"image {ami} does not exist in {region}: an image id belongs to one region. Take the id the "
                       "subscription's launch page shows with this region chosen, or run in the image's own region (--region)")
    labrun.save_state(runner.work, image=ami, image_name=fields[0] if fields else "", product_code=fields[1] if len(fields) > 1 else "")


def session(runner: Runner, key: Path, user: str, host: str, lines: List[str], errors: str, name: str, success: str = "",
            options: Sequence[str] = (), prompt: str = "", answers: Sequence[Tuple[str, str]] = (), batch: bool = True,
            preamble: str = "", close_after: float = 0, noise: str = "", preamble_when: str = "", pager: str = "", idle: float = 0, slow: str = "") -> str:  # fmt: skip
    """Types the lines into the CLI over SSH (with a terminal: the CLIs want one) and checks what it answered: no line
    refused, and the success line where the CLI writes one. A session that hangs (a failed commit asks before it lets
    the CLI exit) ends after 20 minutes."""
    prefix = labrun.ssh_prefix(key, user, host, runner.work / "known_hosts", options=options, batch=batch)
    (runner.work / f"{name}.commands.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    args = prefix[:1] + ["-tt"] + prefix[1:]
    ended = None
    if prompt:
        try:
            out = runner.run_paced(args, lines, prompt, timeout=1200, fake=f"(dry run) {success}", answers=answers, preamble=preamble, preamble_when=preamble_when,
                                   close_after=close_after, noise=noise, pager=pager, idle=idle, slow=slow)
        except labrun.SessionEnded as error:  # (what it wrote till then: the refused lines are the likelier reason)
            out, ended = error.output, error
    else:
        out = runner.run(args, stdin="\n".join(lines) + "\n", timeout=1200, fake=f"(dry run) {success}")
    if noise:  # (the console's own text kept too, beside its plain text)
        (runner.work / f"{name}.raw.txt").write_text(out, encoding="utf-8")
        out = labrun.screen_text(out, noise)
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


# What `ssh -v` says about the login: the key offered or skipped, the firewall's answer, the signatures it takes.
_SSH_AUTH_LINES = r"Offering|Server accepts|Authentications that can continue|server-sig-algs|kex_input_ext_info|no mutual signature|send_pubkey|Will attempt|Skipping|identity file|Remote protocol version|Authenticated|denied"


def wait_cli(runner: Runner, key: Path, user: str, host: str, command: str, answer: str, minutes: float,
             options: Sequence[str] = (), as_command: bool = False, prompt: str = "", answers: Sequence[Tuple[str, str]] = (),
             batch: bool = True, preamble: str = "", close_after: float = 0, noise: str = "", preamble_when: str = "", pager: str = "",
             idle: float = 0, slow: str = "") -> None:  # fmt: skip
    """Until the CLI answers the ready command as it should (PAN-OS: chassis ready, after its first commit). Every try is
    kept in boot.txt: when the CLI never answers, it says whether SSH was refused, the key not taken, or what came back.
    A try that finds no algorithm in common with the firewall ends the wait at once."""
    deadline = time.time() + minutes * 60
    prefix = labrun.ssh_prefix(key, user, host, runner.work / "known_hosts", options=options, batch=batch)
    tries = runner.work / "boot.txt"
    last = ""
    verbose_done = False
    while True:
        try:
            if as_command:  # (a shell: the command given to ssh, no terminal)
                out = runner.run(prefix + [command], quiet=True, timeout=120)
            elif answers:  # (a CLI with a login of its own: the questions answered, then the command typed after the prompt)
                try:
                    out = runner.run_paced(prefix[:1] + ["-tt"] + prefix[1:], [command, "exit"], prompt, timeout=150, step=60, answers=answers,
                                           preamble=preamble, close_after=close_after, noise=noise, preamble_when=preamble_when, pager=pager, idle=idle, slow=slow)
                except labrun.SessionEnded as error:
                    out = error.output
                if noise:
                    out = labrun.screen_text(out, noise)
            else:
                out = runner.run(prefix[:1] + ["-tt"] + prefix[1:], stdin=command + "\nexit\n", quiet=True, timeout=120)
            if re.search(answer, out):
                (runner.work / "ready.txt").write_text(out, encoding="utf-8")  # (the version the firewall runs, for the record)
                return
            last = "answered, but not as expected:\n" + out[-2000:] + ("\n" + runner.last_stderr[-1000:] if runner.last_stderr else "")
        except LabError as error:  # (not up yet: SSH refused or timed out; or the key not taken)
            last = str(error)
        with tries.open("a", encoding="utf-8") as handle:
            handle.write(f"--- {time.strftime('%H:%M:%S')}\n{last.strip()}\n")
            if "Permission denied" in last and not verbose_done:
                # Once: what ssh offered and what the firewall said it takes (the second 8000V run had only "denied").
                verbose_done = True
                runner.run(prefix[:1] + ["-v"] + prefix[1:] + ["exit"], check=False, quiet=True, timeout=60)
                seen = [line for line in runner.last_stderr.splitlines() if re.search(_SSH_AUTH_LINES, line)]
                handle.write("ssh -v, once (the lines about the login):\n" + "\n".join(seen) + "\n")
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


def user_data(vendor: Vendor, key: Path, password: str = "", image_name: str = "") -> str:
    """The firewall's first-boot data, with the run's public key where it asks for one ({ssh_key}: its base64 part),
    the run's password where it asks for one ({enable_password}) and the image's version ({os_version})."""
    data = vendor.user_data.replace("{os_version}", checkpoint_version(image_name)).replace("{user}", vendor.user)
    if "{ssh_key}" in data or "{ssh_key_lines}" in data:
        parts = key.with_suffix(".pub").read_text(encoding="utf-8").split()
        blob = parts[1] if len(parts) > 1 else parts[0]
        data = data.replace("{ssh_key_lines}", "\n".join("   " + blob[i:i + 64] for i in range(0, len(blob), 64)))
        data = data.replace("{ssh_key}", blob)
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


# -- the read-back (0.38.0): the policy as the firewall holds it after the probes --------------------------------------

_CP_OPTS = "details-level full use-object-dictionary true dereference-group-members true limit 500 --format json -s rb.sid"
EXPORTS: Dict[str, readback.Export] = {
    "fortigate": readback.Export("fortios", ("config system console", "set output standard", "end", "show system settings", "show system zone",
                                             "show firewall address", "show firewall addrgrp", "show firewall service custom",
                                             "show firewall service group", "show firewall vip", "show firewall ippool",
                                             "show firewall central-snat-map", "show firewall policy", "exit"), readback.fortios_sections, "conf"),
    "panos": readback.Export("panos", ("set cli pager off", "set cli config-output-format set", "configure", "show", "exit", "exit"), suffix="set"),
    "vsrx": readback.Export("junos", ("set cli screen-length 0", "show configuration | display inheritance no-comments | display set | no-more", "exit"),
                            readback.only(r"set "), "set"),
    "c8000v": readback.Export("ios", ("terminal length 0", "show running-config", "exit"),
                              readback.between(r"^(Building configuration|Current configuration|version \d)", r"^end\s*$"), "cfg"),
    "asav": readback.Export("asa", ("terminal pager 0", "show running-config", "exit"), readback.between(r"^(: Saved|: Serial|ASA Version)", r"^: end"), "cfg"),
    "sophos": readback.Export("sophos", (), lambda text: text, "xml"),  # (through the XML API: sophos.export)
    "pfsense": readback.Export("pfsense", ("cat /conf/config.xml",), readback.between(r"<\?xml|<pfsense", r"</pfsense>"), "xml"),
    "opnsense": readback.Export("opnsense", ("cat /conf/config.xml",), readback.between(r"<\?xml|<opnsense", r"</opnsense>"), "xml"),
    # (every access layer, the inline ones of the converted policy among them, and the NAT rules: the manual's export)
    "checkpoint": readback.Export("checkpoint", ("mgmt_cli login -r true > rb.sid", f"mgmt_cli show nat-rulebase package Standard offset 0 {_CP_OPTS}",
                                                 "mgmt_cli show access-layers details-level full limit 500 --format json -s rb.sid",
                                                 'python3 -c \'import json,subprocess,sys; o=["details-level","full","use-object-dictionary","true","dereference-group-members","true","limit","500","--format","json","-s","rb.sid"]; layers=json.loads(subprocess.check_output(["mgmt_cli","show","access-layers","limit","500","--format","json","-s","rb.sid"])).get("access-layers",[]); [sys.stdout.write(subprocess.check_output(["mgmt_cli","show","access-rulebase","name",l["name"],"offset","0"]+o).decode()+"\\n") for l in layers]\'', "mgmt_cli logout -s rb.sid", "exit"),
                                  readback.json_array, "json"),
}


def read_back(runner: Runner, vendor: Vendor, key: Path, host: str, out: Path, login: Optional[Dict[str, Any]] = None) -> None:
    """Exports the policy from the firewall and compares it (readback.py); in a dry run, the export is what was
    loaded."""
    export = EXPORTS.get(vendor.name)
    if export is None:
        readback.not_read(runner, readback.NOT_READ.get(vendor.name, f"no export for {vendor.name} yet"))
        return

    def step() -> Dict[str, Any]:
        merged = runner.work / "config.merged.xml"
        if vendor.api:
            text = sophos.export(runner, host, sophos.password(runner.work), loaded=out.read_text(encoding="utf-8"))
        elif runner.dry_run:
            text = readback.as_loaded(vendor.target, (merged if merged.exists() else out).read_text(encoding="utf-8"))
            raw = text if vendor.name != "checkpoint" else "{}"
        elif vendor.as_command:
            prefix = labrun.ssh_prefix(key, vendor.user, host, runner.work / "known_hosts", options=vendor.ssh_options)
            raw = runner.run(prefix + [vendor.sudo + export.lines[0]], quiet=True, timeout=300)
            text = export.extract(raw)
        else:
            raw = session(runner, key, vendor.user, host, list(export.lines), "", "export", options=vendor.ssh_options, prompt=vendor.prompt,
                          **(login or {}))  # fmt: skip
            text = export.extract(raw)
        if runner.dry_run and vendor.name == "checkpoint":
            return readback.not_read(runner, "a dry run has no Management API to export from")
        return readback.check(runner, vendor.target, out, text, export, vendor.options)

    readback.safely(runner, step)


def published_addresses() -> Dict[str, List[str]]:
    """The addresses the lab policy publishes, by zone: secondary addresses of the firewall's interface there, so that
    the VPC delivers them to it (0.37.0)."""
    out: Dict[str, List[str]] = {}
    for pub in labplan.published():
        if pub["address"] not in out.setdefault(pub["zone"], []):
            out[pub["zone"]].append(pub["address"])
    return out


def conversion(name: str) -> Tuple[str, List[str]]:
    vendor = VENDORS[name]
    return vendor.target, list(vendor.options)


def run_vendor(runner: Runner, args: Any) -> bool:
    vendor = VENDORS[args.firewall]
    cloud = getattr(args, "cloud", None) or "aws"
    if cloud != "aws":
        return run_cloud(runner, args, vendor, cloud)
    region = args.region or "eu-west-1"
    labrun.save_state(runner.work, tier="tier3", firewall=vendor.name, region=region)
    if not runner.dry_run:
        labrun.need("ssh", "ssh-keygen", "scp", "aws")
    key = labrun.ssh_key(runner, "rsa", vendor.key_bits)  # (the key pair of AWS reaches the firewall images, and not all take Ed25519)
    out = runner.work / f"policy.{vendor.target}"
    report = labrun.fwshift(runner, vendor.target, out, vendor.options)
    # Two hosts of one zone talk over their subnet, not through the firewall; a reset can be the firewall's own.
    data = labplan.build_plan(vendor.target, report, through_target_inside_zone=False, refused_means="blocked", nat_address=_addr)
    labplan.save(runner.work / "plan.json", data)
    tf = tier1.Terraform(runner, labrun.ROOT / "tier3" / "aws", tier1.terraform_binary(args.terraform))
    try:
        ami = args.ami or find_ami(runner, region, vendor.ami_pattern, vendor.product_codes, args.instance_type or vendor.instance_type)
        if args.ami:
            describe_ami(runner, region, args.ami)
        instance_type = args.instance_type or pick_instance_type(runner, region, ami, vendor.instance_type)
        labrun.save_state(runner.work, instance_type=instance_type)
        first_boot = user_data(vendor, key, run_password(runner.work) if "{enable_password}" in vendor.user_data else "",
                               str(labrun.load_state(runner.work).get("image_name", ""))).replace("{run_id}", runner.work.name).replace("{region}", region)
        tf.apply({"region": region, "run_id": runner.work.name, "zone_order": ORDER, "firewall_ami": ami, "published": published_addresses(),
                  "firewall_instance_type": instance_type, "firewall_user_data": first_boot, **aws_firewall_variables(runner, vendor),
                  **tier1.common_variables(runner, args, key), "hosts": tier1.host_variables(gateway="firewall")})  # fmt: skip
        outputs = tf.output({"firewall_ip": "192.0.2.4", "firewall_instance": "i-0dryrun", "user": "ec2-user", "hosts": tier1.fake_hosts()})
        return _boot_load_probe(runner, vendor, key, outputs, out, data, args,
                                lambda: save_console(runner, region, outputs["firewall_instance"]))
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown(runner, tf)


def aws_firewall_variables(runner: Runner, vendor: Vendor) -> Dict[str, Any]:
    """What of the AWS module a vendor sets beside the defaults: the management interface's device index and ports, the
    first-boot secrets (with the run's password) and IMDSv2."""
    out: Dict[str, Any] = {}
    if vendor.mgmt_index:
        out["mgmt_device_index"] = vendor.mgmt_index
    if vendor.mgmt_ports:
        out["firewall_ports"] = list(vendor.mgmt_ports)
    if vendor.secrets:
        word = sophos.password(runner.work) if vendor.api else run_password(runner.work)
        out["firewall_secrets"] = {name: word for name in vendor.secrets}
    if vendor.imdsv2:
        out["require_imdsv2"] = True
    return out


def _filled(text: str, values: Dict[str, str]) -> str:
    for name, value in values.items():
        text = text.replace(name, value)
    return text


def _boot_load_probe(runner: Runner, vendor: Vendor, key: Path, outputs: Dict[str, Any], out: Path, data: Dict[str, Any], args: Any,
                     console: Callable[[], None]) -> bool:  # fmt: skip
    """Once the firewall exists, on any cloud: wait for its CLI, load the policy, probe, and look at it afterwards
    (diagnose.txt, the read-back). console: keeps its boot messages, for a firewall that did not come up."""
    if vendor.password_login:
        labrun.askpass(runner.work, outputs["firewall_instance"])
    fill = {"{password}": outputs["firewall_instance"]}
    if any("{new_password}" in a for _, a in vendor.answers):
        fill["{new_password}"] = nsv_password(runner.work)
    login: Dict[str, Any] = {"answers": tuple((q, _filled(a, fill)) for q, a in vendor.answers), "batch": not vendor.password_login,
                             "preamble": vendor.preamble, "preamble_when": vendor.preamble_when, "pager": vendor.pager, "idle": vendor.idle, "slow": vendor.slow, "close_after": vendor.close_after,
                             "noise": vendor.screen_noise}  # fmt: skip
    if vendor.api:
        sophos.wait_web_console(runner, outputs["firewall_ip"], args.boot_minutes or vendor.boot_minutes)
    elif not runner.dry_run:
        try:
            wait_cli(runner, key, vendor.user, outputs["firewall_ip"], vendor.ready, vendor.ready_answer,
                     args.boot_minutes or vendor.boot_minutes, vendor.ssh_options, as_command=vendor.as_command, prompt=vendor.prompt,
                     **login)  # fmt: skip
        except LabError:
            console()
            raise
    if vendor.load is not None:
        try:
            vendor.load(runner, vendor, key, outputs["firewall_ip"], out)
        except LabError:
            console()  # (a firewall that did not come back: its boot)
            raise
    elif vendor.prepare():  # (answers that do not count, kept in prepare.txt)
        session(runner, key, vendor.user, outputs["firewall_ip"], vendor.prepare(), "", "prepare", options=vendor.ssh_options,
                prompt=vendor.prompt, **login)
    if vendor.load is None:
        files = vendor.uploads(out)
        if files:
            upload(runner, key, vendor.user, outputs["firewall_ip"], files, vendor.ssh_options)
        lines = vendor.session(out)
        if vendor.ports_command:
            ports = _ASA_DRY_PORTS if runner.dry_run else asa_data_ports(
                session(runner, key, vendor.user, outputs["firewall_ip"], ["terminal pager 0", vendor.ports_command, "exit"], "",
                        "ports", options=vendor.ssh_options, prompt=vendor.prompt))  # fmt: skip
            lines = fill_ports(lines, ports)
        session(runner, key, vendor.user, outputs["firewall_ip"], lines, vendor.errors, "load", vendor.success, vendor.ssh_options,
                vendor.prompt, **login)
    try:
        return tier1.probe_hosts(runner, key, outputs, data)
    finally:
        if not isinstance(sys.exc_info()[1], KeyboardInterrupt):  # (Ctrl-C: straight to the teardown)
            diagnose(runner, vendor, key, outputs["firewall_ip"], login)
            read_back(runner, vendor, key, outputs["firewall_ip"], out, login)


def upload(runner: Runner, key: Path, user: str, host: str, files: Sequence[Path], options: Sequence[str] = ()) -> None:
    """Copies files to the firewall's home folder (scp, with the run's key and the firewall's ssh settings)."""
    extra = [word for option in options for word in ("-o", option)]
    runner.run(["scp", "-q", "-i", str(key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new", "-o",
                f"UserKnownHostsFile={runner.work / 'known_hosts'}", "-o", "ConnectTimeout=10", *extra, *[str(f) for f in files],
                f"{user}@{host}:"], timeout=300)  # fmt: skip


def diagnose(runner: Runner, vendor: Vendor, key: Path, host: str, login: Optional[Dict[str, Any]] = None) -> None:
    """The firewall's own view after the probes (diagnose.txt), where the vendor has show commands for it; a failure here
    is noted and does not change the result."""
    if vendor.api:
        sophos.diagnose(runner, host, sophos.password(runner.work))
        return
    lines = vendor.diagnose()
    if not lines:
        return
    if vendor.as_command:
        prefix = labrun.ssh_prefix(key, vendor.user, host, runner.work / "known_hosts", options=vendor.ssh_options)
        parts = []
        for line in lines:
            answer = runner.run(prefix + [vendor.sudo + line], check=False, quiet=True, timeout=120, fake="(dry run)")
            parts.append(f"$ {line}\n{answer}{runner.last_stderr if not answer else ''}")
        (runner.work / "diagnose.txt").write_text("\n".join(parts), encoding="utf-8")
        return
    try:
        session(runner, key, vendor.user, host, lines, "", "diagnose", options=vendor.ssh_options, prompt=vendor.prompt, **(login or {}))
    except LabError as error:
        (runner.work / "diagnose.txt").write_text(f"(the diagnosis did not finish: {error})\n", encoding="utf-8")


CLOUD_REGIONS = {"azure": "westeurope", "gcp": "europe-west1"}


def find_gcp_image(runner: Runner, pattern: str, project: str) -> str:
    """The newest image of a publisher's project whose name starts as the pattern says (projects/P/global/images/NAME-*):
    the publishers name their images by version and give no family (Palo Alto, Cisco, Check Point)."""
    found = re.match(r"^projects/([^/]+)/global/images/([^*]+)\*$", pattern)
    if not found:
        raise LabError(f"not an image pattern: {pattern} (projects/PROJECT/global/images/NAME-*)")
    owner, prefix = found.groups()
    out = runner.run(["gcloud", "compute", "images", "list", "--project", owner, "--no-standard-images", f"--filter=name~^{prefix}",
                      "--sort-by=~creationTimestamp", "--limit=1", "--format=value(name)", "--quiet"], check=False, fake=f"{prefix}dry-run")  # fmt: skip
    name = out.strip().splitlines()[0].strip() if out.strip() else ""
    if not name:
        raise LabError(f"no image named {prefix}... in project {owner}: give one with --cloud-image")
    labrun.save_state(runner.work, image=f"projects/{owner}/global/images/{name}", image_name=name)
    return f"projects/{owner}/global/images/{name}"


def cloud_os_version(image_name: str) -> str:
    """Check Point's version in an image's name as Azure and Google Cloud name it (check-point-cg-r82, check-point-r8210-...),
    written as CloudGuardIaaS writes it there (R82, R8210); R82 when the name says none."""
    found = re.search(r"[Rr](\d{2})(?:\.?(\d{1,2}))?(?!\d)", image_name or "")
    return "R" + found.group(1) + (found.group(2) or "") if found else "R82"


def cloud_vendor(vendor: Vendor, image: CloudImage) -> Vendor:
    """The vendor as it is on another cloud: its changes put in."""
    return dataclasses.replace(vendor, **dict(image.changes)) if image.changes else vendor


def run_cloud(runner: Runner, args: Any, vendor: Vendor, cloud: str) -> bool:
    """Tier 3 on Azure or Google Cloud (0.39.0): the vendor's Marketplace image there, the same plan, load and probes."""
    image = CLOUD_IMAGES.get(vendor.name, {}).get(cloud)
    if image is None:
        why = NOT_ON.get((vendor.name, cloud), "not scripted there yet")
        raise LabError(f"{vendor.title} on {CLOUD_TITLES[cloud]}: {why}")
    if image.open_point and not getattr(args, "untested", False):
        raise LabError(f"{vendor.title} on {CLOUD_TITLES[cloud]} is not ready: {image.open_point}. --untested runs it anyway")
    vendor = cloud_vendor(vendor, image)
    region = args.region or CLOUD_REGIONS[cloud]
    project = getattr(args, "project", None) or ("dry-run-project" if runner.dry_run else "")
    if cloud == "gcp" and not project:
        raise LabError("--project is needed for Google Cloud")
    zone = getattr(args, "zone", None) or f"{region}-b"
    labrun.save_state(runner.work, tier="tier3", firewall=vendor.name, cloud=cloud, region=region, project=project,
                      image=getattr(args, "cloud_image", None) or image.image)  # fmt: skip
    if not runner.dry_run:
        labrun.need("ssh", "ssh-keygen", "scp", "az" if cloud == "azure" else "gcloud")
    key = labrun.ssh_key(runner, "rsa", vendor.key_bits)  # (Azure takes RSA keys only)
    out = runner.work / f"policy.{vendor.target}"
    report = labrun.fwshift(runner, vendor.target, out, vendor.options)
    data = labplan.build_plan(vendor.target, report, through_target_inside_zone=False, refused_means="blocked", nat_address=_addr)
    labplan.save(runner.work / "plan.json", data)
    tf = tier1.Terraform(runner, labrun.ROOT / "tier3" / cloud, tier1.terraform_binary(args.terraform))
    name = getattr(args, "cloud_image", None) or image.image
    common = tier1.common_variables(runner, args, key)

    def first_boot_for(image_name: str) -> str:
        # (Check Point's version as its templates for Azure and Google Cloud write it: R82, R8120; from the image's name)
        made = dataclasses.replace(vendor, user_data=vendor.user_data.replace("{os_version}", cloud_os_version(image_name)))
        return user_data(made, key, run_password(runner.work) if "{enable_password}" in vendor.user_data else "")
    try:
        if cloud == "azure":
            publisher, offer, sku = (name.split(":") + ["", "", ""])[:3]
            if image.plan and not runner.dry_run:  # (the terms of a Marketplace image are accepted once per subscription)
                runner.run(["az", "vm", "image", "terms", "accept", "--urn", f"{publisher}:{offer}:{sku}:latest", "-o", "none"], check=False)
            first_boot = first_boot_for(offer)
            tf.apply({**common, "location": region, "zone_order": ORDER, "published": published_addresses(),
                      "firewall_image": {"publisher": publisher, "offer": offer, "sku": sku, "version": "latest"}, "firewall_plan": image.plan,
                      "firewall_size": args.instance_type or image.size, "firewall_user": image.vm_user, "firewall_custom_data": first_boot,
                      "hosts": tier1.host_variables(gateway="first")})  # fmt: skip
            outputs = tf.output({"firewall_ip": "192.0.2.4", "firewall_instance": "00000000-dry-run", "resource_group": runner.work.name,
                                 "user": "azureuser", "hosts": tier1.fake_hosts()})  # fmt: skip

            def console() -> None:
                with labrun.shielded():
                    text = runner.run(["az", "vm", "boot-diagnostics", "get-boot-log", "-g", runner.work.name, "-n", f"{runner.work.name}-firewall"],
                                      check=False, quiet=True, fake="(dry run)")  # fmt: skip
                    (runner.work / "console.txt").write_text(text or "(the console gave nothing)\n", encoding="utf-8")
        else:
            if "*" in name:
                name = find_gcp_image(runner, name, project)
            first_boot = first_boot_for(name.rsplit("/", 1)[-1])
            metadata = {image.metadata_key: first_boot} if first_boot else {}
            if image.key_metadata:
                metadata[image.key_metadata] = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
            tf.apply({**common, "project": project, "region": region, "zone": zone, "zone_order": ORDER, "published": published_addresses(),
                      "firewall_image": name, "firewall_machine_type": args.instance_type or image.size, "firewall_user": vendor.user,
                      "firewall_metadata": metadata,
                      "hosts": tier1.host_variables(gateway="first", subnet_via_gateway=True)})  # fmt: skip
            outputs = tf.output({"firewall_ip": "192.0.2.4", "firewall_instance": "1234567890", "user": "lab", "hosts": tier1.fake_hosts()})

            def console() -> None:
                with labrun.shielded():
                    text = runner.run(["gcloud", "compute", "instances", "get-serial-port-output", f"{runner.work.name}-firewall", "--zone", zone,
                                       "--project", project], check=False, quiet=True, fake="(dry run)")  # fmt: skip
                    (runner.work / "console.txt").write_text(text or "(the console gave nothing)\n", encoding="utf-8")
        return _boot_load_probe(runner, vendor, key, outputs, out, data, args, console)
    finally:
        if not args.keep:
            with labrun.shielded():
                teardown(runner, tf)


def teardown(runner: Runner, tf: "tier1.Terraform") -> None:
    state = labrun.load_state(runner.work)
    region, cloud = state.get("region", "eu-west-1"), state.get("cloud", "aws")
    problems = []
    try:
        tf.destroy()
    except LabError as error:
        problems.append(str(error))
        if cloud == "azure":  # (the resource group holds everything of the run)
            runner.run(["az", "group", "delete", "-n", runner.work.name, "--yes"], check=False, timeout=3600)
    if runner.dry_run:
        found: List[str] = []
    elif cloud == "azure":
        found = tier1.leftovers_azure(runner)
    elif cloud == "gcp":
        found = tier1.leftovers_gcp(runner, str(state.get("project", "")))
    else:
        found = tier1.leftovers_aws(runner, region)
    if not found and not problems:
        labrun.save_state(runner.work, torn_down=True)
    tier1.report_leftovers(found + problems, runner.work.name)


def coverage() -> List[Tuple[str, str, str]]:
    """(vendor, cloud, what the lab has there): every vendor of tier 3 on every cloud."""
    rows = []
    for name, vendor in VENDORS.items():
        rows.append((name, "aws", vendor.status))
        for cloud in ("azure", "gcp"):
            image = CLOUD_IMAGES.get(name, {}).get(cloud)
            if image is None:
                rows.append((name, cloud, "not scripted: " + NOT_ON.get((name, cloud), "not scripted there yet")))
            elif image.open_point:
                rows.append((name, cloud, f"image found ({image.image}), not ready: {image.open_point}"))
            else:
                rows.append((name, cloud, f"{image.status} ({image.image})"))
    return rows


def describe() -> str:
    rows = [f"  {v.name:<12} {v.title}: {v.status}" for v in VENDORS.values()]
    rows += [f"  {name:<12} on {CLOUD_TITLES[cloud]}: {status}" for name, cloud, status in coverage() if cloud != "aws"]
    rows += [f"  {name:<12} not scripted: {why}" for name, why in NOT_SCRIPTED.items()]
    return "\n".join(rows)

