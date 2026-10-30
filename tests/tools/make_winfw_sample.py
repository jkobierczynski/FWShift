# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/winfw_sample.reg: a made-up Windows Defender Firewall policy, as two exports of reg joined into one
file, the way the manual says to make it:

    reg export "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" local.reg /y
    reg export "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall" gpo.reg /y
    copy /b local.reg + gpo.reg winfw.reg

reg writes UTF-16 (little endian) with a byte order mark and CRLF line ends; the second file keeps its own mark and
header in the middle. It holds the traps of the platform: no rule order (block rules among allow rules, an allow
below a block that overlaps it), the defaults of each profile from two stores, Group Policy that does not merge local
rules on one profile and blocks outbound on another, a rule of the same id in both stores, profiles, both directions,
local and remote addresses and ports, ranges and masks, IPv6, address keywords for one IP version and for both, ICMP
types and codes, other protocols, disabled rules, rules that name a program, a service, an interface type, IPsec and
authenticated bypass, a port keyword, edge traversal, a field Windows does not know, a rule Windows cannot parse,
connection security and service hardening rules. Every address is a documentation or private address; every id is
made up.

    python3 tests/tools/make_winfw_sample.py
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Sequence, Tuple

LOCAL = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
GPO = r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall"


def quoted(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def key(path: str, values: Sequence[Tuple[str, object]]) -> List[str]:
    lines = [f"[{path}]"]
    for name, value in values:
        data = f"dword:{value:08x}" if isinstance(value, int) else quoted(str(value))
        lines.append(f"{quoted(name)}={data}")
    return lines + [""]


def export(blocks: List[List[str]]) -> bytes:
    lines = ["Windows Registry Editor Version 5.00", ""]
    for block in blocks:
        lines += block
    return ("\ufeff" + "\r\n".join(lines) + "\r\n").encode("utf-16-le")


LOCAL_RULES = [
    ("CoreNet-ICMP4-EchoRequest-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=1|ICMP4=8:*|Name=Echo request (ICMPv4-In)|"
     "Desc=Lets the host answer ping|EmbedCtxt=Core Networking|"),
    ("CoreNet-ICMP6-EchoRequest-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=128:*|RA6=LocalSubnet|"
     "Name=Echo request (ICMPv6-In)|EmbedCtxt=Core Networking|"),
    ("CoreNet-ICMP4-Unreachable-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=1|ICMP4=3:4|ICMP4=11:0|"
     "Name=Fragmentation needed and time exceeded|EmbedCtxt=Core Networking|"),
    ("RemoteDesktop-In-TCP", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=3389|"
     "RA4=192.0.2.0/24|RA4=10.20.0.0/255.255.0.0|RA6=2001:db8:20::/48|Name=Remote Desktop from the admin networks|"
     "EmbedCtxt=Remote Desktop|"),
    ("WebServer-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|LPort=443|LA4=10.10.0.5|LA6=2001:db8:10::5|"
     "Name=Web server|"),
    ("FtpPassive-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort2_10=50000-50100|"
     "RA4=10.10.0.0/16|Name=FTP passive ports|"),
    ("Snmp-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=161|RPort2_10=1024-65535|RA4=LocalSubnet|"
     "Name=SNMP from the local subnet|"),
    ("Gre-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=47|RA4=198.51.100.1|Name=GRE from the tunnel peer|"),
    ("Block-Telnet-Out", "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=23|Name=Block telnet out|"),
    ("Block-BadNet-In", "v2.30|Action=Block|Active=TRUE|Dir=In|RA4=203.0.113.0/24|RA4=198.51.100.10-198.51.100.20|"
     "Name=Block the scanner networks|"),
    ("Block-Smb-Public", "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=445|LPort=139|"
     "Name=Block SMB on public networks|"),
    ("App-Server-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8443|"
     "App=C:\\Program Files\\Example\\server.exe|Name=Example application server|"),
    ("Spooler-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|Svc=Spooler|Name=Print spooler (RPC)|"),
    ("Ssh-In-Disabled", "v2.30|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=22|Name=OpenSSH server|"),
    ("Wireless-Only-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=5353|IFType=Wireless|Name=mDNS on wireless|"),
    ("Teredo-Edge-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Public|LPort=3544|Edge=TRUE|"
     "Name=Game server through edge traversal|"),
    ("Ipsec-Bypass-In", "v2.30|Action=ByPass|Active=TRUE|Dir=In|Protocol=6|LPort=5986|Security=Authenticate|"
     "RMauth=O:LSD:(A;;CC;;;WD)|Name=Management over IPsec, overriding block rules|"),
    ("Future-Field-In", "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=9100|NewField2_40=1|Name=Printer port|"),
    ("Broken-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=1|LPort=80|Name=A rule Windows cannot parse|"),
    ("Platform-In", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=1900|RA4=LocalSubnet|RA6=LocalSubnet|"
     "Platform=2:6:2|Platform2=GTEQ|Name=SSDP discovery|"),
    ("Shared-Id", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=53|Name=DNS server (local copy)|"),
    ("Backup-Out", "v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=10000-10010|RA4=10.30.0.20|"
     "Name=Backup agent to the backup server|"),
]

GPO_RULES = [
    ("{4C1F0A3E-1111-4A2B-9C3D-0A1B2C3D4E01}", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|LPort=5985|"
     "RA4=10.0.0.0/8|Name=Allow WinRM from management|EmbedCtxt=Server management|"),
    ("{4C1F0A3E-1111-4A2B-9C3D-0A1B2C3D4E02}", "v2.30|Action=Block|Active=TRUE|Dir=Out|RA4=192.0.2.66|RA6=2001:db8:66::1|"
     "Name=Block a known bad host|"),
    ("{4C1F0A3E-1111-4A2B-9C3D-0A1B2C3D4E03}", "v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|RPort=443|"
     "RPort=80|Name=Web out on private networks|"),
    ("{4C1F0A3E-1111-4A2B-9C3D-0A1B2C3D4E04}", "v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|Profile=Private|RPort=53|"
     "RA4=DNS|RA6=DNS|Name=DNS out on private networks|"),
    ("{4C1F0A3E-1111-4A2B-9C3D-0A1B2C3D4E05}", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|"
     "Profile=Private|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|Name=SMB from the local subnet|"),
    ("{4C1F0A3E-1111-4A2B-9C3D-0A1B2C3D4E06}", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=22|"
     "RA6=2001:db8:abcd::/48|Name=SSH from the IPv6 jump hosts|"),
    ("{4C1F0A3E-1111-4A2B-9C3D-0A1B2C3D4E07}", "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|"
     "RA4=192.0.2.128/25|Name=Block RDP from the guest half of the admin network|"),
    ("Shared-Id", "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|LPort=53|RA4=10.0.0.0/8|"
     "Name=DNS server|"),
]


def main() -> None:
    local = export([
        key(LOCAL, [("PolicyVersion", 0x21F)]),
        key(LOCAL + r"\DomainProfile", [("EnableFirewall", 1), ("DefaultInboundAction", 1), ("DefaultOutboundAction", 0)]),
        key(LOCAL + r"\StandardProfile", [("EnableFirewall", 1), ("DisableNotifications", 0)]),
        key(LOCAL + r"\PublicProfile", [("EnableFirewall", 1), ("DoNotAllowExceptions", 0),
                                        ("DisableUnicastResponsesToMulticastBroadcast", 1)]),
        key(LOCAL + r"\PublicProfile\Logging", [("LogFilePath", r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log")]),
        key(LOCAL + r"\FirewallRules", LOCAL_RULES),
        key(LOCAL + r"\ConSecRules", [("{7A0B1C2D-2222-4E3F-8A9B-0C1D2E3F4A51}",
                                       "v2.30|Action=RequireInRequestOut|Active=TRUE|EP2_4=10.0.0.0/8|Name=Require IPsec|")]),
        key(LOCAL + r"\RestrictedServices\Static\System", [("ExampleSvc-Block-All", "v2.30|Action=Block|Active=TRUE|Dir=In|"
                                                             "Svc=examplesvc|Name=Block examplesvc|")]),
    ])
    gpo = export([
        key(GPO, [("PolicyVersion", 0x21F)]),
        key(GPO + r"\DomainProfile", [("EnableFirewall", 1), ("DefaultInboundAction", 1), ("DefaultOutboundAction", 0),
                                      ("AllowLocalPolicyMerge", 0)]),
        key(GPO + r"\PrivateProfile", [("DefaultOutboundAction", 1)]),
        key(GPO + r"\PublicProfile", [("EnableFirewall", 1), ("AllowLocalPolicyMerge", 1)]),
        key(GPO + r"\FirewallRules", GPO_RULES),
    ])
    target = Path(__file__).resolve().parents[1] / "data" / "winfw_sample.reg"
    target.write_bytes(local + gpo)


if __name__ == "__main__":
    main()
