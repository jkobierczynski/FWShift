# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/sonicwall_sample.exp: a made-up SonicOS settings export.

Every address is a documentation or private address. The keys are those of the format as the
parser reads them (see DEVELOPMENT.md); the file is what *Export Settings* gives: Base64 of the
URL-encoded pairs joined by "&", with "&&" at the end.

    python3 tests/tools/make_sonicwall_sample.py
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import quote

Row = Dict[str, str]


def table(rows: List[Row], start: int = 0) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for offset, row in enumerate(rows):
        for key, value in row.items():
            out.append((f"{key}_{start + offset}", value))
    return out


def encode(pairs: List[Tuple[str, str]]) -> bytes:
    text = "&".join(f"{key}={quote(value, safe='')}" for key, value in pairs) + "&&"
    return base64.b64encode(text.encode("utf-8"))


def zone(name: str, kind: str, trust: str = "1") -> Row:
    return {"zoneObjId": name, "zoneObjZoneType": kind, "zoneObjIntraZoneCom": trust}


def iface(number: str, name: str, zone_name: str, ip: str = "", mask: str = "", static: bool = False, gateway: str = "") -> Row:
    row = {"iface_ifnum": number, "iface_name": name, "interface_Zone": zone_name}
    if static:
        row.update({"iface_static_ip": ip, "iface_static_mask": mask, "iface_static_gateway": gateway})
    else:
        row.update({"iface_lan_ip": ip or "0.0.0.0", "iface_lan_mask": mask or "0.0.0.0"})
    return row


def address(name: str, kind: str, zone_name: str, ip1: str, ip2: str) -> Row:
    return {"addrObjId": name, "addrObjIdDisp": name, "addrObjType": kind, "addrObjZone": zone_name, "addrObjProperties": "14",
            "addrObjIp1": ip1, "addrObjIp2": ip2}  # fmt: skip


def service(name: str, protocol: str, first: str, last: str) -> Row:
    return {"svcObjId": name, "svcObjType": "1", "svcObjIpType": protocol, "svcObjPort1": first, "svcObjPort2": last}


def rule(action: str, src_zone: str, dst_zone: str, src: str = "", dst: str = "", svc: str = "", comment: str = "",
         enabled: str = "1", name: str = "", whom: str = "0", time: str = "", default: str = "0", six: bool = False) -> Row:  # fmt: skip
    tail = "V6" if six else ""
    row = {"Action": action, "SrcZone": src_zone, "DstZone": dst_zone, "SrcNet": src, "DstNet": dst, "DstSvc": svc,
           "Whom": whom, "Time": time, "Comment": comment, "Log": "1", "Enabled": enabled, "Name": name, "DefaultRule": default}  # fmt: skip
    return {f"policy{key}{tail}": value for key, value in row.items()}


def nat(orig_src: str = "", orig_dst: str = "", orig_svc: str = "", trans_src: str = "", trans_dst: str = "", trans_svc: str = "",
        inbound: str = "-1", outbound: str = "-1", enabled: str = "1", reflexive: str = "0", comment: str = "", fixed: str = "0") -> Row:  # fmt: skip
    row = {"OrigSrc": orig_src, "OrigDst": orig_dst, "OrigSvc": orig_svc, "TransSrc": trans_src, "TransDst": trans_dst,
           "TransSvc": trans_svc, "SrcIface": inbound, "DstIface": outbound, "Enabled": enabled, "Reflexive": reflexive,
           "Comment": comment, "NonDeletable": fixed, "Properties": "16384"}  # fmt: skip
    return {f"natPolicy{key}": value for key, value in row.items()}


def sample() -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = [("buildNum", "7.1.2-7019"), ("shortProdName", "TZ 470")]
    pairs += table([zone("LAN", "1"), zone("WAN", "0", "0"), zone("DMZ", "2", "0"), zone("Servers", "1"), zone("VPN", "5")])
    pairs += table([
        iface("0", "X0", "LAN", "10.10.0.1", "255.255.0.0"),
        iface("1", "X1", "WAN", "198.51.100.2", "255.255.255.0", static=True, gateway="198.51.100.1"),
        iface("2", "X2", "DMZ", "10.20.0.1", "255.255.255.0"),
        iface("3", "X3", "Servers", "10.30.0.1", "255.255.255.0"),
        iface("4", "X4", "WAN"),
    ])  # fmt: skip
    pairs += table([
        address("Web Server", "1", "DMZ", "10.20.0.10", "255.255.255.255"),
        address("Mail Server", "1", "DMZ", "10.20.0.25", "255.255.255.255"),
        address("Web Public", "1", "WAN", "198.51.100.10", "255.255.255.255"),
        address("Mail Public", "1", "WAN", "198.51.100.11", "255.255.255.255"),
        address("Server Range", "4", "Servers", "10.30.0.0", "255.255.255.240"),
        address("Server Public", "4", "WAN", "198.51.100.32", "255.255.255.240"),
        address("Database", "1", "Servers", "10.30.0.5", "255.255.255.255"),
        address("Admin PCs", "2", "LAN", "10.10.5.10", "10.10.5.20"),
        address("Bad Networks", "8", "WAN", "0.0.0.0", "0.0.0.0"),
        address("Bad Net One", "4", "WAN", "203.0.113.0", "255.255.255.128"),
        address("Bad Host", "1", "WAN", "192.0.2.66", "255.255.255.255"),
        address("Partners", "8", "WAN", "0.0.0.0", "0.0.0.0"),
        address("Partner Net", "4", "WAN", "192.0.2.128", "255.255.255.192"),
    ], start=1)  # fmt: skip
    pairs += [("addrObjFqdnId_0", "Update Site"), ("addrObjFqdnType_0", "0"), ("addrObjFqdnZone_0", "WAN"),
              ("addrObjFqdn_0", "updates.example.com")]  # fmt: skip
    memberships = [("Bad Net One", "Bad Networks"), ("Bad Host", "Bad Networks"), ("Partner Net", "Partners"), ("Bad Networks", "Partners")]
    for index, (member, group) in enumerate(memberships, start=1):
        pairs += [(f"addro_atomToGrp_{index}", member), (f"addro_grpToGrp_{index}", group)]
    pairs += table([
        service("HTTPS Alt", "6", "8443", "8443"),
        service("SMTP Alt", "6", "2525", "2525"),
        service("Media", "17", "16384", "16484"),
        service("GRE Tunnel", "47", "0", "0"),
        service("Echo Object", "1", "8", "0"),
        {"svcObjId": "Web Services", "svcObjType": "2", "svcObjIpType": "0", "svcObjPort1": "0", "svcObjPort2": "0"},
    ], start=1)  # fmt: skip
    for index, (member, group) in enumerate([("HTTP", "Web Services"), ("HTTPS", "Web Services"), ("HTTPS Alt", "Web Services")], start=1):
        pairs += [(f"so_atomToGrp_{index}", member), (f"so_grpToGrp_{index}", group)]
    pairs += table([
        rule("1", "LAN", "WAN", dst="Bad Networks", comment="nothing to the bad networks"),
        rule("2", "LAN", "WAN", src="Admin PCs", svc="SSH", name="Admins out by SSH"),
        rule("2", "LAN", "WAN", svc="Web Services", comment="browsing"),
        rule("2", "LAN", "WAN", svc="GRE Tunnel", comment="tunnels to partners", enabled="0"),
        rule("2", "LAN", "WAN", default="1", comment="Auto added default rule"),
        rule("2", "WAN", "DMZ", dst="Web Public", svc="HTTPS", name="Web server from the internet"),
        rule("2", "WAN", "DMZ", src="Partners", dst="Mail Public", svc="SMTP Alt", name="Mail from partners"),
        rule("0", "WAN", "DMZ", default="1"),
        rule("0", "WAN", "LAN", default="1"),
        rule("2", "DMZ", "Servers", src="Web Server", dst="Database", svc="Media", name="Web server to the database"),
        rule("2", "DMZ", "LAN", src="Mail Server", svc="Echo Object", name="Mail server pings the LAN"),
        rule("2", "LAN", "DMZ", whom="Admins", name="Administrators to the DMZ"),
        rule("2", "Servers", "WAN", dst="Update Site", svc="HTTPS", time="Work Hours", name="Updates in working hours"),
        rule("2", "LAN", "WAN", six=True, name="IPv6 out"),
    ])  # fmt: skip
    pairs += table([
        nat(orig_src="X0 Subnet", trans_src="X1 IP", outbound="1", comment="Default NAT", fixed="1"),
        nat(orig_dst="Web Public", trans_dst="Web Server", orig_svc="HTTPS", inbound="1", comment="Web server"),
        nat(orig_dst="Mail Public", trans_dst="Mail Server", orig_svc="SMTP Alt", trans_svc="SMTP (Send E-Mail)", inbound="1",
            comment="Mail on another port"),
        nat(orig_src="Server Range", trans_src="Server Public", outbound="1", reflexive="1", comment="Servers one to one"),
        nat(orig_src="Admin PCs", trans_src="Web Public", outbound="1", enabled="0", comment="Old admin NAT"),
    ])  # fmt: skip
    return pairs


def main() -> None:
    path = Path(__file__).resolve().parents[1] / "data" / "sonicwall_sample.exp"
    path.write_bytes(encode(sample()) + b"\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
