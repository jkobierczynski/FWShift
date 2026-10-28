# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Sophos Firewall in tier 3 (0.41.4): the lab talks to it through its XML API, not a CLI.

Written from Sophos's documentation and its CloudFormation templates for SFOS 22.0 MR2 (sophos-iaas/aws-cf-templates),
never run before the first lab run. What it counts on:

* The image of the PAYG listing ("Sophos Cloud Firewall (PAYG)") takes its first-boot settings as one line of JSON in
  the user data (``acceptedEULA``, ``hostname``, ``sendstats``, ``region``, ``secretId``, ``configSecretId``), and the
  admin password from AWS Secrets Manager, by the secret's name or ARN, through the instance's role (Terraform makes the
  secret and the role). Its first card (device index 0) is PortA, its second PortB, the WAN port that gets the Elastic
  IP in Sophos's own template: the lab puts its management interface there and the zones on PortA, PortC and PortD.
* The XML API (``https://FIREWALL:4444/webconsole/APIController``) is off on a new firewall, and only the web console
  turns it on (Administration > API access, with the addresses allowed as IP host objects). No user-data key, CLI
  command or documented call does it: the lab asks for that one step and waits (``enable_api``). Before that, an API
  request is answered with status 532 (API access off) or 534 (address not allowed): the web console is up.
* A request carries its own login (``<Login>``) and one or more entities under ``<Set operation="add|update">`` or
  ``<Get>``; the answer has a ``<Status code="...">`` per entity (200: applied). The lab sends one entity per request,
  in the order of the file, so that a refusal names its entity and stops nothing else.
* A static port in the WAN zone needs a gateway, which would compete with PortB's for the default route (and the
  management traffic with it): the outside port goes into a zone of the lab's own, ``Outside`` (type DMZ), and FWShift
  converts with ``--zone-map outside=Outside``.
* A new firewall may have firewall rules of its own, and has the NAT rule "Default SNAT IPv4": the lab disables every
  firewall rule and NAT rule that is there before it loads (disabled, not deleted: Sophos recreates its default NAT
  rule).

The firewall's certificate is its own, self-signed: the lab does not check it, and talks only to the address it was
given for the instance it made.
"""

from __future__ import annotations

import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from labrun import LabError, Runner

API_PORT = 4444
API_VERSION = "2200.1"
# The lab's zones on the firewall's ports (the management interface is PortB) and the zone each is put in.
PORTS = {"inside": "PortA", "dmz": "PortC", "outside": "PortD"}
ZONES = {"inside": "LAN", "dmz": "DMZ", "outside": "Outside"}
OPTIONS = ["--zone-map", "inside=LAN", "--zone-map", "dmz=DMZ", "--zone-map", "outside=Outside",
           # (the interfaces of the lab's PAN-OS policy, for the NAT rules, which match interfaces on Sophos)
           "--interface-map", "ethernet1/2=PortA", "--interface-map", "ethernet1/3=PortC", "--interface-map", "ethernet1/1=PortD"]  # fmt: skip
# What the read-back asks for: the entities FWShift's Sophos reader takes.
EXPORTED = ("Zone", "Interface", "IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "Services", "ServiceGroup", "FirewallRule", "NATRule")
NOT_ON = {"532": "API access is off", "534": "this address is not allowed to use the API"}


def user_data(run_id: str, region: str) -> str:
    """The first-boot data: one line of JSON, as Sophos's template writes it; the password is in Secrets Manager."""
    return json.dumps({"acceptedEULA": "yes", "hostname": run_id[:30], "sendstats": "off", "region": region, "enableCloudWatch": "no",
                       "secretId": f"{run_id}-admin", "configSecretId": f"{run_id}-backup"}, separators=(",", ":"))  # fmt: skip


def _context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False  # (its own certificate, for no name the lab could check)
    context.verify_mode = ssl.CERT_NONE
    return context


def post(host: str, reqxml: str, timeout: float = 60) -> str:
    """One request to the XML API, as a form field (a long request does not fit in the URL)."""
    body = urllib.parse.urlencode({"reqxml": reqxml}).encode("utf-8")
    request = urllib.request.Request(f"https://{host}:{API_PORT}/webconsole/APIController", data=body, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})  # fmt: skip
    with urllib.request.urlopen(request, timeout=timeout, context=_context()) as answer:  # noqa: S310 (the lab's own firewall)
        return str(answer.read().decode("utf-8", errors="replace"))


def request_xml(password: str, body: str) -> str:
    login = f"<Login><Username>admin</Username><Password>{_escape(password)}</Password></Login>"
    return f'<Request APIVersion="{API_VERSION}">{login}{body}</Request>'


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def state(answer: str) -> str:
    """What an answer says of the API: ready (logged in), off, not-allowed, login-failed, or unknown."""
    if re.search(r"Authentication Successful", answer):
        return "ready"
    if re.search(r"Authentication Failure", answer):
        return "login-failed"
    codes = re.findall(r'code="(\d+)"', answer)
    if "532" in codes:
        return "off"
    if "534" in codes:
        return "not-allowed"
    return "unknown"


def statuses(answer: str) -> List[Tuple[str, str, str]]:
    """(entity, code, text) for every entity of an answer that has a status."""
    try:
        root = ET.fromstring(answer)
    except ET.ParseError:
        return [("(answer)", "", answer[:200])]
    out = []
    for element in root:
        status = element.find("Status")
        if element.tag != "Login" and status is not None:
            out.append((element.tag, status.get("code", ""), (status.text or "").strip()))
    return out


class Api:
    """The firewall's XML API for one run: every request logged without its login (commands.log), answers faked in a
    dry run."""

    def __init__(self, runner: Runner, host: str, password: str) -> None:
        self.runner, self.host, self.password = runner, host, password

    def call(self, body: str, fake: str = "") -> str:
        body = re.sub(r">\s+<", "><", body.strip())  # (FWShift's file is indented: one line per request, here and in the log)
        self.runner.log.append(f"POST https://{self.host}:{API_PORT}/webconsole/APIController {body[:300]}")
        if self.runner.dry_run:
            return fake or "<Response><Login><status>Authentication Successful</status></Login></Response>"
        try:
            return post(self.host, request_xml(self.password, body))
        except (urllib.error.URLError, OSError) as error:
            raise LabError(f"the XML API of the firewall did not answer: {error}") from error

    def get(self, entity: str, fake: str = "") -> str:
        return self.call(f"<Get><{entity}/></Get>", fake or "<Response><Login><status>Authentication Successful</status></Login></Response>")

    def set(self, element: ET.Element, operation: str) -> Tuple[str, str]:
        """Adds or updates one entity: (code, text) of its status."""
        tag = element.tag
        answer = self.call(f'<Set operation="{operation}">{ET.tostring(element, encoding="unicode")}</Set>',
                           f'<Response><Login><status>Authentication Successful</status></Login><{tag}><Status code="200">Configuration applied successfully.</Status></{tag}></Response>')  # fmt: skip
        found = statuses(answer)
        if state(answer) == "login-failed":
            raise LabError("the XML API refused the login")
        return (found[0][1], found[0][2]) if found else ("", answer[:200])


def wait_web_console(runner: Runner, host: str, minutes: float) -> None:
    """Until the web console answers on its API (532 or 534 before the API is on, a login after): first boot takes 5 to
    20 minutes (Sophos's community). Every try is kept in boot.txt."""
    if runner.dry_run:
        return
    deadline = time.time() + minutes * 60
    tries = runner.work / "boot.txt"
    while True:
        try:
            answer = post(host, request_xml("x", "<Get><Zone/></Get>"), timeout=20)
            seen = state(answer)
            with tries.open("a", encoding="utf-8") as log:
                log.write(f"{time.strftime('%H:%M:%S')} {seen}: {answer[:200]}\n")
            if seen != "unknown":
                return
        except (urllib.error.URLError, OSError, ssl.SSLError) as error:
            with tries.open("a", encoding="utf-8") as log:
                log.write(f"{time.strftime('%H:%M:%S')} {error}\n")
        if time.time() > deadline:
            raise LabError(f"the web console of the firewall did not answer on port {API_PORT} within {minutes:g} minutes (boot.txt)")
        time.sleep(20)


def admin_address(work: Path) -> str:
    """The address the run is managed from, as Terraform was given it."""
    try:
        variables = json.loads((work / "terraform" / "terraform.tfvars.json").read_text(encoding="utf-8"))
        return str(variables["admin_cidr"]).split("/")[0]
    except (OSError, ValueError, KeyError):
        return "(your public address)"


def enable_api(runner: Runner, api: Api, minutes: float = 30) -> None:
    """The one step the lab cannot take: API access on, for the address the run is managed from. It says what to do and
    waits until a login through the API works (asks again every 15 seconds)."""
    if runner.dry_run:
        return
    seen = state(api.call("<Get><Zone/></Get>"))
    if seen == "ready":
        return
    address = admin_address(runner.work)
    print(f"""
Sophos Firewall: switch on its XML API (the one step the lab cannot take; {NOT_ON.get(seen, seen) if seen in ('off', 'not-allowed') else seen}).
  1. Open https://{api.host}:{API_PORT} and log in as admin, with the password in {runner.work / 'sophos_password.txt'}.
  2. Hosts and services > IP host > Add: name fwlab-admin, type IP, address {address}.
  3. Administration > API access (on older versions: Backup & firmware > API): turn API access on, add the IP host
     fwlab-admin to the allowed addresses, and apply.
The lab goes on by itself once the API lets it in (it asks every 15 seconds, for {minutes:g} minutes).
""", file=sys.stderr, flush=True)  # fmt: skip
    deadline = time.time() + minutes * 60
    while time.time() < deadline:
        time.sleep(15)
        try:
            seen = state(api.call("<Get><Zone/></Get>"))
        except LabError:
            continue
        if seen == "ready":
            print("Sophos Firewall: the XML API lets the lab in.", file=sys.stderr, flush=True)
            return
        if seen == "login-failed":
            raise LabError("the XML API is on, but refused the admin login (sophos_password.txt)")
    raise LabError(f"the XML API was not switched on within {minutes:g} minutes; the run stops (nothing was loaded)")


def _entities(answer: str, tag: str) -> List[ET.Element]:
    try:
        return [e for e in ET.fromstring(answer) if e.tag == tag]
    except ET.ParseError:
        return []


def _text(element: ET.Element, tag: str) -> str:
    found = element.find(tag)
    return (found.text or "").strip() if found is not None else ""


def _set_text(element: ET.Element, tag: str, value: str) -> None:
    found = element.find(tag)
    if found is None:
        found = ET.SubElement(element, tag)
    found.text = value


def zone_element(name: str) -> ET.Element:
    zone = ET.Element("Zone")
    _set_text(zone, "Name", name)
    _set_text(zone, "Type", "DMZ")
    _set_text(zone, "Description", "FWShift lab")
    return zone


def interface_element(found: Optional[ET.Element], port: str, zone: str, address: str) -> ET.Element:
    """The port as the firewall has it, in the zone and with the static address the lab gives it, and no gateway."""
    element = ET.fromstring(ET.tostring(found)) if found is not None else ET.Element("Interface")
    _set_text(element, "Name", _text(element, "Name") or port)
    _set_text(element, "Hardware", _text(element, "Hardware") or port)
    _set_text(element, "NetworkZone", zone)
    _set_text(element, "IPv4Configuration", "Enable")
    _set_text(element, "IPv4Assignment", "Static")
    _set_text(element, "IPAddress", address)
    _set_text(element, "Netmask", "255.255.255.0")
    for tag in ("GatewayName", "GatewayAddress", "DHCPRapidCommit"):
        for child in element.findall(tag):
            element.remove(child)
    return element


def disabled(element: ET.Element) -> Optional[ET.Element]:
    """A copy of a rule with Status Disable, or None when it is disabled already."""
    if _text(element, "Status") == "Disable":
        return None
    copy = ET.fromstring(ET.tostring(element))
    _set_text(copy, "Status", "Disable")
    return copy


def converted_entities(text: str) -> List[ET.Element]:
    root = ET.fromstring(text)
    return [element for element in root if isinstance(element.tag, str)]


def _name(element: ET.Element) -> str:
    return _text(element, "Name") or element.tag


def load(runner: Runner, vendor: Any, key: Path, host: str, out: Path, password: str, addresses: Dict[str, str]) -> None:
    """After the API step: the lab's zone and ports, the firewall's own rules disabled, then FWShift's entities one by
    one, in the order of the file (load.txt). A refused entity fails the run, as a refused line does elsewhere."""
    api = Api(runner, host, password)
    enable_api(runner, api)
    lines: List[str] = []
    before = {entity: api.get(entity) for entity in ("Zone", "Interface", "FirewallRule", "NATRule")}
    (runner.work / "prepare.txt").write_text("\n\n".join(f"== {e}\n{a}" for e, a in before.items()), encoding="utf-8")
    refused: List[str] = []

    def apply(element: ET.Element, operation: str, what: str, counts: bool = True) -> None:
        code, text = api.set(element, operation)
        lines.append(f"{what}: {code} {text}")
        if code not in ("200", "216") and counts:
            refused.append(f"{what}: {code} {text}")

    zones = {_name(z) for z in _entities(before["Zone"], "Zone")}
    for zone in sorted(set(ZONES.values()) - {"LAN", "DMZ", "WAN"}):
        if zone not in zones:
            apply(zone_element(zone), "add", f"Zone {zone} (the lab's)")
    interfaces = {(_text(i, "Hardware") or _name(i)): i for i in _entities(before["Interface"], "Interface")}
    for lab_zone, port in PORTS.items():
        found = interfaces.get(port)  # (a port the firewall does not list yet is added)
        apply(interface_element(found, port, ZONES[lab_zone], addresses[lab_zone]), "update" if found is not None else "add",
              f"Interface {port} ({ZONES[lab_zone]})")
    for tag in ("FirewallRule", "NATRule"):
        for rule in _entities(before[tag], tag):
            off = disabled(rule)
            if off is not None:
                apply(off, "update", f"{tag} {_name(rule)} (the firewall's own, disabled)")
    for element in converted_entities(out.read_text(encoding="utf-8")):
        apply(element, "add", f"{element.tag} {_name(element)}")
    after = api.get("FirewallRule", "<Response><FirewallRule><Name>outside-web</Name></FirewallRule></Response>")
    (runner.work / "load.txt").write_text("\n".join(lines) + "\n\n== FirewallRule after the load\n" + after, encoding="utf-8")
    if refused:
        raise LabError(f"the firewall refused {len(refused)} entities (load.txt), the first: {refused[0]}")


def export(runner: Runner, host: str, password: str, loaded: str = "") -> str:
    """The configuration as the API gives it, every entity FWShift reads, in one answer (FWShift reads a Get answer as an
    export). In a dry run: what was loaded."""
    api = Api(runner, host, password)
    parts: List[ET.Element] = []
    for entity in EXPORTED:
        answer = api.get(entity)
        parts += _entities(answer, entity)
    if runner.dry_run:
        return loaded
    root = ET.Element("Response", {"APIVersion": API_VERSION})
    root.extend(parts)
    return ET.tostring(root, encoding="unicode")


def diagnose(runner: Runner, host: str, password: str, entities: Sequence[str] = ("Interface", "Zone", "FirewallRule", "NATRule")) -> None:
    """The firewall's view after the probes, through the API (diagnose.txt): its ports, zones and rules as it holds them.
    A failure here is noted and does not change the result."""
    api = Api(runner, host, password)
    parts = []
    for entity in entities:
        try:
            parts.append(f"== {entity}\n{api.get(entity)}")
        except LabError as error:
            parts.append(f"== {entity}\n(not answered: {error})")
    (runner.work / "diagnose.txt").write_text("\n\n".join(parts) + "\n", encoding="utf-8")


def password(work: Path) -> str:
    """The admin password for the run, made once and kept in the work folder: what Sophos's template asks for, at least
    10 characters with a lower and an upper case letter, a digit and a special character."""
    import os
    import secrets

    path = work / "sophos_password.txt"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    made = "Fw" + secrets.token_hex(8) + "#7"
    path.write_text(made + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return made

