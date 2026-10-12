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
from typing import Dict, List, Optional, Tuple

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


# -- Sophos Firewall --------------------------------------------------------------------------------

# IP protocols as Sophos names them in a service of type IP: the keywords of the IANA registry, and
# IPProto<n> for numbers without one. The API documentation shows the start of the list (HOPOPT, ICMP,
# IGMP, GGP, IP, ST, TCP, CBT, EGP, IGP ... UDP, GRE, ESP, AH, SCTP, UDPLite, IPProto143 ... IPProto255);
# the names in between are taken from the registry.
SOPHOS_PROTOCOL_NAMES: Dict[int, str] = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IP", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP",
    10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP",
    18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1",
    26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP",
    34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 40: "IL", 41: "IPv6", 42: "SDRP",
    43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR", 49: "BNA", 50: "ESP", 51: "AH",
    52: "I-NLSP", 53: "SWIPE", 54: "NARP", 55: "MOBILE", 56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt",
    60: "IPv6-Opts", 62: "CFTP", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC", 69: "SAT-MON", 70: "VISA",
    71: "IPCV", 72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON",
    79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP", 82: "SECURE-VMTP", 83: "VINES", 84: "TTP", 85: "NSFNET-IGP", 86: "DGP",
    87: "TCF", 88: "EIGRP", 89: "OSPFIGP", 90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25", 94: "IPIP",
    95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM",
    104: "ARIS", 105: "SCPS", 106: "QNX", 107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer",
    111: "IPX-in-IP", 112: "VRRP", 113: "PGM", 115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP", 119: "SRP",
    120: "UTI", 121: "SMP", 122: "SM", 123: "PTP", 124: "ISIS", 125: "FIRE", 126: "CRTP", 127: "CRUDP",
    128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE", 132: "SCTP", 133: "FC", 134: "RSVP-E2E-IGNORE",
    135: "Mobility Header", 136: "UDPLite", 137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6", 141: "WESP",
    142: "ROHC",
}  # fmt: skip
# The names the API documentation itself shows: an emitter can write these without a second look.
SOPHOS_PROTOCOLS_CONFIRMED = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 17, 47, 50, 51, 132, 136})
_SOPHOS_PROTOCOL_ALIASES = {"ospf": 89, "ipv6-icmp": 58, "icmpv6": 58, "icmp6": 58, "ipv4": 4, "ip-in-ip": 4, "isis over ipv4": 124,
                            "ttp/iptm": 84, "iptm": 84, "udp-lite": 136}  # fmt: skip
_SOPHOS_PROTOCOL_NUMBERS = {name.lower(): number for number, name in SOPHOS_PROTOCOL_NAMES.items()}


def sophos_protocol_number(name: str) -> Optional[int]:
    """The IP protocol behind a name of a Sophos service of type IP: a keyword, ``IPProto<n>`` or a number."""
    text = name.strip().lower()
    if text.startswith("ipproto"):
        text = text[len("ipproto"):]
    if text.isascii() and text.isdigit() and len(text) <= 3:
        return int(text) if int(text) <= 255 else None
    if text in _SOPHOS_PROTOCOL_NUMBERS:
        return _SOPHOS_PROTOCOL_NUMBERS[text]
    return _SOPHOS_PROTOCOL_ALIASES.get(text)


# ICMP types and codes are numbers in the XML API, -1 for any; these are the values it lists.
SOPHOS_ICMP_TYPES = frozenset([0, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18] + list(range(30, 41)))
SOPHOS_ICMP6_TYPES = frozenset([0, 1, 2, 3, 4, 100, 101] + list(range(128, 159)) + [200, 201])
SOPHOS_ICMP_CODES = frozenset(range(0, 16))
# Names, for a file that spells them out (the web console does).
SOPHOS_ICMP_NAMES = {
    "echo reply": 0, "destination unreachable": 3, "source quench": 4, "redirect": 5, "alternate host address": 6,
    "echo": 8, "echo request": 8, "router advertisement": 9, "router selection": 10, "router solicitation": 10,
    "time exceeded": 11, "parameter problem": 12, "timestamp": 13, "timestamp reply": 14, "information request": 15,
    "information reply": 16, "address mask request": 17, "address mask reply": 18, "traceroute": 30,
}  # fmt: skip
SOPHOS_ICMP6_NAMES = {
    "destination unreachable": 1, "packet too big": 2, "time exceeded": 3, "parameter problem": 4, "echo request": 128,
    "echo reply": 129, "multicast listener query": 130, "multicast listener report": 131, "multicast listener done": 132,
    "router solicitation": 133, "router advertisement": 134, "neighbor solicitation": 135, "neighbor advertisement": 136,
    "redirect": 137, "redirect message": 137,
}  # fmt: skip

# Services a Sophos Firewall comes with. An object of another platform that carries one of these names is
# renamed: an import overwrites what has the same name.
SOPHOS_FACTORY_SERVICE_NAMES = frozenset(
    """AH AOL BGP DHCP DNS ESP FINGER FTP FTP_GET FTP_PUT GOPHER GRE H323 HTTP HTTPS ICMP_ANY IKE IMAP IMAPS
    Internet-Locator-Service IRC L2TP LDAP NetMeeting NFS NNTP NTP OSPF PC-Anywhere PING PING6 POP3 POP3S PPTP QUAKE
    RAUDIO REXEC RIP RLOGIN SAMBA SIP SIP-MSNmessenger SMTP SMTPS SMTP(S) SNMP SSH SYSLOG TALK TCP TELNET TFTP MGCP
    UUCP VDOLIVE WAIS WINFRAME X-WINDOWS UDP ICMP ICMPv6 RDP SMB TRACEROUTE VNC MS-SQL MYSQL RADIUS KERBEROS
    Chromecast SSLVPN Any""".split()
)


# -- Cisco Secure Firewall -------------------------------------------------------------------------

_ALNUM = re.compile(r"[^a-z0-9]")
# Other spellings of a protocol than the keyword of the IANA registry, as the managers and their
# tools write them. A name that means two things somewhere is left out.
_PROTOCOL_ALIASES = {"icmpv6": 58, "icmp6": 58, "ipv6icmp": 58, "ospf": 89, "ipinip": 4, "ipv4": 4, "ipencap": 4,
                     "udplite": 136, "tpplusplus": 39, "threepc": 34, "nvp2": 11, "st2": 5, "ipv6nonxt": 59,
                     "ipv6route": 43, "ipv6frag": 44, "ipv6opts": 60, "mobilityheader": 135}  # fmt: skip
_IANA_NUMBERS = {_ALNUM.sub("", name.lower()): number for number, name in SOPHOS_PROTOCOL_NAMES.items()}


def protocol_number(name: str) -> Optional[int]:
    """The IP protocol behind a name or a number as a Cisco manager writes it; None when that is not known.

    Names are compared without case and punctuation, against the keywords of the IANA registry.
    """
    text = name.strip()
    if is_plain_number(text):
        # 0 is "ip" on a Cisco command line, which is every protocol: not a protocol to convert as one.
        return int(text) if len(text) <= 3 and 0 < int(text) <= 255 else None
    key = _ALNUM.sub("", text.lower())
    if key in ("ip", "all", "any", "hopopt"):
        return None
    if key in _PROTOCOL_ALIASES:
        return _PROTOCOL_ALIASES[key]
    return _IANA_NUMBERS.get(key)


def is_plain_number(text: str) -> bool:
    return text.isascii() and text.isdigit()


# The Device Manager names protocols, ICMP types and ICMP codes with an enumeration. The names are the
# keywords of the IANA registries without punctuation; the numbers were taken from the registries.
FDM_PROTOCOLS: Dict[str, int] = {
    "IGMP": 2, "GGP": 3, "ST2": 5, "TCP": 6, "CBT": 7, "EGP": 8, "IGP": 9, "BBNRCCMON": 10, "NVP2": 11, "PUP": 12,
    "ARGUS": 13, "EMCON": 14, "XNET": 15, "CHAOS": 16, "UDP": 17, "MUX": 18, "DCNMEAS": 19, "HMP": 20, "PRM": 21,
    "XNSIDP": 22, "TRUNK1": 23, "TRUNK2": 24, "LEAF1": 25, "LEAF2": 26, "RDP": 27, "IRTP": 28, "ISOTP4": 29,
    "NETBLT": 30, "MFENSP": 31, "MERITINP": 32, "SEP": 33, "THREEPC": 34, "IDPR": 35, "XTP": 36, "DDP": 37,
    "IDPRCMTP": 38, "TPPLUSPLUS": 39, "IL": 40, "SDRP": 42, "IDRP": 45, "RSVP": 46, "GRE": 47, "MHRP": 48, "BNA": 49,
    "ESP": 50, "AH": 51, "INLSP": 52, "SWIPE": 53, "NARP": 54, "MOBILE": 55, "TLSP": 56, "SKIP": 57, "IPv6NONXT": 59,
    "CFTP": 62, "SATEXPAK": 64, "KRYPTOLAN": 65, "RVD": 66, "IPPC": 67, "SATMON": 69, "VISA": 70, "IPCV": 71,
    "CPNX": 72, "CPHB": 73, "WSN": 74, "PVP": 75, "BRSATMON": 76, "SUNND": 77, "WBMON": 78, "WBEXPAK": 79,
    "ISOIP": 80, "VMTP": 81, "SECUREVMTP": 82, "VINES": 83, "TTP": 84, "NSFNETIGP": 85, "DGP": 86, "TCF": 87,
    "EIGRP": 88, "OSPFIGP": 89, "SPRITERPC": 90, "LARP": 91, "MTP": 92, "AX25": 93, "IPIP": 94, "MICP": 95,
    "SCCSP": 96, "ETHERIP": 97, "ENCAP": 98, "GMTP": 100, "IFMP": 101, "PNNI": 102, "PIM": 103, "ARIS": 104,
    "SCPS": 105, "QNX": 106, "AN": 107, "IPCOMP": 108, "SNP": 109, "COMPAQPEER": 110, "IPXINIP": 111, "VRRP": 112,
    "PGM": 113, "L2TP": 115, "DDX": 116, "IATP": 117, "ST": 118, "SRP": 119, "UTI": 120, "SMP": 121, "SM": 122,
    "PTP": 123, "ISIS": 124, "FIRE": 125, "CRTP": 126, "CRUDP": 127, "SSCOPMCE": 128, "IPLT": 129, "SPS": 130,
    "PIPE": 131, "SCTP": 132, "FC": 133,
}  # fmt: skip
FDM_PROTOCOL_NAMES: Dict[int, str] = {number: name for name, number in FDM_PROTOCOLS.items()}
FDM_ICMP_TYPES: Dict[str, int] = {
    "ECHO_REPLY": 0, "DESTINATION_UNREACHABLE": 3, "SOURCE_QUENCH": 4, "REDIRECT_MESSAGE": 5, "ALTERNATE_HOST_ADDRESS": 6,
    "ECHO_REQUEST": 8, "ROUTER_ADVERTISEMENT": 9, "ROUTER_SOLICITATION": 10, "TIME_EXCEEDED": 11, "PARAMETER_PROBLEM": 12,
    "TIMESTAMP": 13, "TIMESTAMP_REPLY": 14, "INFO_REQUEST": 15, "INFO_REPLY": 16, "ADDR_MASK_REQUEST": 17,
    "ADDR_MASK_REPLY": 18, "TRACEROUTE": 30, "DATAGRAM_CONVERSION_ERROR": 31, "MOBILE_HOST_REDIRECT": 32,
    "WHERE_ARE_YOU": 33, "HERE_I_AM": 34, "MOBILE_REG_REQUEST": 35, "MOBILE_REG_REPLY": 36, "DOMAIN_NAME_REQUEST": 37,
    "DOMAIN_NAME_REPLY": 38, "SKIP_ALGORITHM_DISCOVERY_PROTOCOL": 39, "PHOTURIS": 40, "EXPERIMENTAL_MOB_PROTOCOLS": 41,
}  # fmt: skip
# Code name -> (type it belongs to, code).
FDM_ICMP_CODES: Dict[str, Tuple[int, int]] = {
    "NET_UNREACHABLE": (3, 0), "HOST_UNREACHABLE": (3, 1), "PROTOCOL_UNREACHABLE": (3, 2), "PORT_UNREACHABLE": (3, 3),
    "FRAGMENTATION_NEEDED": (3, 4), "SOURCE_ROUTE_FAILED": (3, 5), "DEST_NETWORK_UNKNOWN": (3, 6),
    "DEST_HOST_UNKNOWN": (3, 7), "SRC_HOST_ISOLATED": (3, 8), "COMMUNICATION_DEST_NET_PROHIBITED": (3, 9),
    "COMMUNICATION_DEST_HOST_PROHIBITED": (3, 10), "DEST_NET_UNREACHABLE_FOR_TOS": (3, 11),
    "DEST_HOST_UNREACHABLE_FOR_TOS": (3, 12), "COMM_ADMINISTRATIVELY_PROHIBITED": (3, 13),
    "HOST_PRECEDENCE_VIOLATION": (3, 14), "PRECEDENCE_CUTOFF": (3, 15), "REDIRECT_DATAGRAM_NETWORK": (5, 0),
    "REDIRECT_DATAGRAM_HOST": (5, 1), "REDIRECT_DATAGRAM_SERVICE_NETWORK": (5, 2), "REDIRECT_DATAGRAM_SERVICE_HOST": (5, 3),
    "ALTERNATE_HOST_ADDR": (6, 0), "NORMAL_ROUTER_ADV": (9, 0), "DO_NOT_ROUTE_COMMON_TRAFFIC": (9, 16),
    "TTL_EXPIRED_TRANSIT": (11, 0), "FRAG_ASSEMBLY": (11, 1), "PTR_ERROR": (12, 0), "MISSING_REQD_OPTION": (12, 1),
    "BAD_LENGTH": (12, 2), "BAD_SPI": (40, 0), "AUTH_FAILED": (40, 1), "DECOMPRESSION_FAILED": (40, 2),
    "DECRYPTION_FAILED": (40, 3), "NEED_AUTHENTICATION": (40, 4), "NEED_AUTHORIZATION": (40, 5),
}  # fmt: skip
FDM_ICMP6_TYPES: Dict[str, int] = {
    "DESTINATION_UNREACHABLE": 1, "PACKET_TOO_BIG": 2, "TIME_EXCEEDED": 3, "PARAMETER_PROBLEM": 4, "ECHO_REQUEST": 128,
    "ECHO_REPLY": 129, "MULTICAST_LISTENER_QUERY": 130, "MULTICAST_LISTENER_REPORT": 131, "MULTICAST_LISTENER_DONE": 132,
    "ROUTER_SOLICITATION": 133, "ROUTER_ADVERTISEMENT": 134, "NEIGHBOUR_SOLICITATION": 135,
    "NEIGHBOUR_ADVERTISEMENT": 136, "REDIRECT_MESSAGE": 137, "ROUTER_RENUMBERING": 138, "ICMP_NODE_INFO_QUERY": 139,
    "ICMP_NODE_INFO_RESPONSE": 140, "INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION": 141,
    "INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT": 142, "VER2_MULTICAST_LISTENER_REPORT": 143,
    "HOME_AGENT_ADDR_DISCOVERY_REQ": 144, "HOME_AGENT_ADDR_DISCOVERY_REPLY": 145, "MOBILE_PREFIX_SOLICITATION": 146,
    "MOBILE_PREFIX_ADVERTISEMENT": 147, "CERT_PATH_SOLICITATION": 148, "CERT_PATH_ADVERTISEMENT": 149,
    "ICMP_EXP_MOBILITY_PROTOCOLS": 150, "MULTICAST_ROUTER_ADVERTISEMENT": 151, "MULTICAST_ROUTER_SOLICITATION": 152,
    "MULTICAST_ROUTER_TERMINATION": 153, "FMIPv6_MSG": 154, "RPL_CTRL_MSG": 155,
}  # fmt: skip
FDM_ICMP6_CODES: Dict[str, Tuple[int, int]] = {
    "NO_ROUTE_DEST": (1, 0), "COMMUNICATION_PROHIBITED": (1, 1), "BEYOND_SCOPE_SRC_ADDR": (1, 2),
    "ADDRESS_UNREACHABLE": (1, 3), "PORT_UNREACHABLE": (1, 4), "SOURCE_ADDRESS_FAILED": (1, 5), "REJECT_ROUTE": (1, 6),
    "ERROR_SRC_ROUTING_HEADER": (1, 7), "HOP_LIMIT_EXCEEDED": (3, 0), "FRAGMENT_REASSEMBLY_TIME_EXCEEDED": (3, 1),
    "ERRONEOUS_HEADER_ENCOUNTERED": (4, 0), "UNRECOGNIZED_NEXT_HEADER_TYPE_ENCOUNTERED": (4, 1),
    "UNRECOGNIZED_IPv6_OPTION_ENCOUNTERED": (4, 2), "ROUTER_RENUMBERING_COMMAND": (138, 0),
    "ROUTER_RENUMBERING_RESULT": (138, 1), "SEQUENCE_NUMBER_RESET": (138, 255), "DATA_CONTAINS_IPv6": (139, 0),
    "DATA_CONTAINS_NAME": (139, 1), "DATA_CONTAINS_IPv4": (139, 2), "SUCCESSFUL_REPLY": (140, 0),
    "RESPONDER_REFUSES_ANSWER": (140, 1), "QTYPE_UNKNOWN": (140, 2),
}  # fmt: skip
