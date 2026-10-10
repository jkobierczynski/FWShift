# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Application <-> layer-4 mapping tables.

``APP_PORTS`` lists the well-known default ports of common PAN-OS App-IDs. It
is **not** Palo Alto's application database: it holds the standard port of
each protocol, which is what a layer-4 policy can express. Extend or override
it per conversion with ``--app-map``.

A port spec is ``tcp/80``, ``udp/1812-1813``, ``icmp/8``, ``icmp/any``,
``icmp6/128`` or ``ip/47``.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

from .errors import FwshiftError
from .model import Protocol, ServiceEntry

APP_PORTS: Dict[str, List[str]] = {
    # web and name services
    "web-browsing": ["tcp/80"],
    "ssl": ["tcp/443"],
    "dns": ["tcp/53", "udp/53"],
    "ntp": ["udp/123"],
    "dhcp": ["udp/67-68"],
    # remote access and file transfer
    "ssh": ["tcp/22"],
    "telnet": ["tcp/23"],
    "ms-rdp": ["tcp/3389"],
    "ftp": ["tcp/21"],
    "tftp": ["udp/69"],
    "ms-ds-smb": ["tcp/445"],
    # mail
    "smtp": ["tcp/25"],
    "imap": ["tcp/143"],
    "pop3": ["tcp/110"],
    # directory, authentication, management
    "ldap": ["tcp/389", "udp/389"],
    "kerberos": ["tcp/88", "udp/88"],
    "radius": ["udp/1812-1813"],
    "tacacs-plus": ["tcp/49"],
    "snmp": ["udp/161"],
    "snmp-trap": ["udp/162"],
    "syslog": ["udp/514"],
    # databases
    "mysql": ["tcp/3306"],
    "mssql-db": ["tcp/1433"],
    "postgres": ["tcp/5432"],
    "oracle": ["tcp/1521"],
    # routing and tunnelling
    "bgp": ["tcp/179"],
    "ospf": ["ip/89"],
    "ike": ["udp/500"],
    "ipsec-esp-udp": ["udp/4500"],
    "ipsec-esp": ["ip/50"],
    "ipsec-ah": ["ip/51"],
    "gre": ["ip/47"],
    # ICMP
    "ping": ["icmp/8"],
    "icmp": ["icmp/any"],
    "ping6": ["icmp6/128"],
    "ipv6-icmp": ["icmp6/any"],
    # industrial protocols
    "modbus": ["tcp/502"],
    "dnp3": ["tcp/20000", "udp/20000"],
    "siemens-s7": ["tcp/102"],
    "bacnet": ["udp/47808"],
    "mqtt": ["tcp/1883"],
}

# IP protocol number -> App-ID, for platforms that match these as applications.
IP_PROTOCOL_APPS: Dict[int, str] = {
    2: "igmp",
    47: "gre",
    50: "ipsec-esp",
    51: "ipsec-ah",
    88: "eigrp",
    89: "ospf",
    103: "pim",
    112: "vrrp",
}


# FortiOS factory-default services: assumed when a FortiOS input refers to one
# without defining it (a fragment rather than a full backup), and reserved names
# when writing FortiOS.
FORTIOS_DEFAULT_SERVICES: Dict[str, List[str]] = {
    "ALL_TCP": ["tcp/1-65535"],
    "ALL_UDP": ["udp/1-65535"],
    "ALL_ICMP": ["icmp/any"],
    "ALL_ICMP6": ["icmp6/any"],
    "PING": ["icmp/8"],
    "HTTP": ["tcp/80"],
    "HTTPS": ["tcp/443"],
    "DNS": ["tcp/53", "udp/53"],
    "SSH": ["tcp/22"],
    "TELNET": ["tcp/23"],
    "FTP": ["tcp/21"],
    "TFTP": ["udp/69"],
    "SMTP": ["tcp/25"],
    "SMTPS": ["tcp/465"],
    "IMAP": ["tcp/143"],
    "IMAPS": ["tcp/993"],
    "POP3": ["tcp/110"],
    "POP3S": ["tcp/995"],
    "NTP": ["tcp/123", "udp/123"],
    "SNMP": ["tcp/161-162", "udp/161-162"],
    "SYSLOG": ["udp/514"],
    "RDP": ["tcp/3389"],
    "SMB": ["tcp/445"],
    "LDAP": ["tcp/389"],
    "LDAPS": ["tcp/636"],
    "KERBEROS": ["tcp/88", "udp/88"],
    "RADIUS": ["udp/1812-1813"],
    "MYSQL": ["tcp/3306"],
    "MS-SQL": ["tcp/1433-1434"],
    "BGP": ["tcp/179"],
    "DHCP": ["udp/67-68"],
    "IKE": ["udp/500", "udp/4500"],
    "ESP": ["ip/50"],
    "AH": ["ip/51"],
    "GRE": ["ip/47"],
    "OSPF": ["ip/89"],
}


# Names of the services a factory-default FortiGate defines. Objects from another
# platform that carry one of these names are renamed when FortiOS is written.
FORTIOS_FACTORY_SERVICE_NAMES = frozenset(
    """ALL ALL_TCP ALL_UDP ALL_ICMP ALL_ICMP6 AFS3 AH AOL BGP CVSPSERVER DCE-RPC DHCP DHCP6 DNS ESP FINGER FTP
    FTP_GET FTP_PUT GOPHER GRE GTP H323 HTTP HTTPS IKE IMAP IMAPS INFO_ADDRESS INFO_REQUEST IRC
    Internet-Locator-Service KERBEROS L2TP LDAP LDAP_UDP LDAPS MGCP MMS MS-SQL MYSQL NFS NNTP NONE NTP NetMeeting
    ONC-RPC OSPF PC-Anywhere PING PING6 POP3 POP3S PPTP QUAKE RADIUS RADIUS-OLD RAUDIO RDP REXEC RIP RLOGIN RSH
    RTSP SAMBA SCCP SIP SIP-MSNmessenger SMB SMTP SMTPS SNMP SOCKS SQUID SSH SYSLOG TALK TELNET TFTP TIMESTAMP
    TRACEROUTE UUCP VDOLIVE VNC WAIS WINFRAME WINS X-WINDOWS webproxy""".split()
) | frozenset(FORTIOS_DEFAULT_SERVICES) | frozenset({"Email Access", "Web Access", "Windows AD", "Exchange Server"})

_PORTS = re.compile(r"[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*")


def valid_ports(text: str) -> bool:
    """True for a port list such as ``80,443,8000-8080`` with every port in 0-65535 and ordered ranges."""
    if not _PORTS.fullmatch(text):
        return False
    for part in text.split(","):
        first, _, last = part.partition("-")
        if int(first) > 65535 or int(last or first) > 65535 or int(last or first) < int(first):
            return False
    return True


def parse_spec(spec: str) -> ServiceEntry:
    proto, sep, value = spec.strip().lower().partition("/")
    if not sep or not value:
        raise FwshiftError(f"invalid port spec '{spec}' (expected e.g. tcp/443)")
    if proto in ("tcp", "udp", "sctp"):
        if not valid_ports(value):
            raise FwshiftError(f"invalid port spec '{spec}': expected ports such as 443 or 8000-8080")
        return ServiceEntry(Protocol(proto), dst_ports=value)
    if proto not in ("icmp", "icmp6", "ip"):
        raise FwshiftError(f"invalid port spec '{spec}': unknown protocol '{proto}'")
    if value == "any":
        if proto == "ip":
            raise FwshiftError(f"invalid port spec '{spec}': that would match every protocol")
        number = None
    elif value.isascii() and value.isdigit() and int(value) <= 255 and (proto != "ip" or int(value) > 0):
        number = int(value)
    else:
        raise FwshiftError(f"invalid port spec '{spec}': expected a number up to 255" + ("" if proto == "ip" else " or 'any'"))
    if proto == "ip":
        return ServiceEntry(Protocol.IP, ip_protocol=number)
    return ServiceEntry(Protocol.ICMP if proto == "icmp" else Protocol.ICMP6, icmp_type=number)


def entries_for(app: str, overrides: Dict[str, List[str]]) -> Optional[List[ServiceEntry]]:
    """Layer-4 definition of an application, or None when it is not in the table."""
    specs = overrides.get(app, APP_PORTS.get(app))
    if specs is None:
        return None
    return [parse_spec(spec) for spec in specs]


def load_app_map(path: str) -> Dict[str, List[str]]:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise FwshiftError(f"cannot read application map {path}: {exc}") from None
    if not isinstance(data, dict):
        raise FwshiftError(f"{path}: expected a JSON object of application -> list of port specs")
    out: Dict[str, List[str]] = {}
    for app, specs in data.items():
        if isinstance(specs, str):
            specs = [specs]
        if not isinstance(specs, list) or not all(isinstance(s, str) for s in specs):
            raise FwshiftError(f"{path}: '{app}' must map to a list of port specs")
        for spec in specs:
            parse_spec(spec)
        out[str(app)] = specs
    return out
