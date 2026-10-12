# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Build the two synthetic Cisco Secure Firewall samples.

``tests/data/fmc_sample.json`` is what the REST API of a Management Center answers (lists with
``expanded=true``, the policies themselves), ``tests/data/fdm_sample.txt`` the text file of a
configuration export of a Device Manager. Both are written with the builder the tests use
(``Manager`` in ``tests/test_cisco.py``), to the shapes of the API documentation and of the
tooling Cisco publishes; nothing in them came from a device. All names and addresses are invented.

Usage: python3 tests/tools/make_cisco_samples.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "src")]

from test_cisco import Manager, plit  # noqa: E402

SYSTEM = {"metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}}}

def fmc() -> bytes:
    m = Manager(policy="Edge")
    m.policy["description"] = "Access control policy of the edge firewalls"
    out_if = m.interface("outside", "GigabitEthernet0/0", "203.0.113.2", "255.255.255.0", "2001:db8:ffff::2/64")
    in_if = m.interface("inside", "GigabitEthernet0/1", "10.10.0.1")
    dmz_if = m.interface("dmz", "GigabitEthernet0/2", "10.20.0.1")
    outside, inside, dmz = m.zone("outside", [out_if]), m.zone("inside", [in_if]), m.zone("dmz", [dmz_if])
    any4 = m.network("any-ipv4", "0.0.0.0/0", **SYSTEM)
    m.network("any-ipv6", "::/0", **SYSTEM)
    private = m.network("IPv4-Private-10.0.0.0-8", "10.0.0.0/8", **SYSTEM)
    lan, dmz_net = m.network("lan-net", "10.10.0.0/24", description="Office LAN"), m.network("dmz-net", "10.20.0.0/24")
    ot = m.network("ot-net", "10.30.0.0/24", description="Production cell", overridable=True)
    partner, branch6 = m.network("partner-net", "198.51.100.0/24"), m.network("branch-v6", "2001:db8:10::/48")
    web, web_pub = m.host("web-srv", "10.20.0.10"), m.host("web-srv-pub", "203.0.113.10")
    mail, mail_pub = m.host("mail-srv", "10.20.0.25"), m.host("mail-srv-pub", "203.0.113.25")
    admins, pool = m.range("admin-pcs", "10.10.0.100-10.10.0.120"), m.range("nat-pool", "203.0.113.100-203.0.113.110")
    updates = m.fqdn("updates", "updates.example.com")
    servers = m.group("servers", [web, mail], ["10.20.0.30"])
    internal = m.group("internal", [lan, dmz_net, servers], description="Everything behind the firewall")
    http, https, ssh = m.tcp("HTTP", "80", **SYSTEM), m.tcp("HTTPS", "443", **SYSTEM), m.tcp("SSH", "22", **SYSTEM)
    dns_udp, dns_tcp, ntp = m.udp("DNS_over_UDP", "53", **SYSTEM), m.tcp("DNS_over_TCP", "53", **SYSTEM), m.udp("NTP-UDP", "123", **SYSTEM)
    alt, smtp, backup = m.tcp("web-alt", "8080-8081"), m.tcp("smtp", "25"), m.tcp("backup", "10000")
    http_alt, published = m.tcp("http-8080", "8080"), m.tcp("http-8443", "8443")
    echo, echo6, esp = m.icmp("echo", 8), m.icmp("echo6", 128, six=True), m.protocol("ipsec-esp", "ESP")
    web_ports, mgmt = m.port_group("web", [http, https, alt]), m.port_group("mgmt", [ssh, echo])

    m.use_prefilter("Edge prefilter", "BLOCK_TUNNELS")
    m.prefilter["description"] = "Backup and tunnels past inspection"
    m.prefilter_rule("pre-backup", "FASTPATH", src_zones=[inside], dst_zones=[dmz], sources=[lan], destinations=[mail], dst_ports=[backup])
    m.prefilter_rule("pre-spoofed", "BLOCK", src_zones=[outside], sources=[private], logBegin=True, sendEventsToFMC=True)
    m.prefilter_rule("pre-partner-gre", "FASTPATH", kind="TUNNEL", src_zones=[outside], dst_zones=[dmz], sources=[partner],
                     destinations=[web], encapsulationPorts=["GRE"], bidirectional=True)

    m.rule("Block OT outbound", "BLOCK", src_zones=[inside], dst_zones=[outside], sources=[ot], log="both",
           commentHistoryList=[{"comment": "No production cell talks to the Internet", "user": {"name": "admin"}, "date": "2026-01-05T10:00:00.000Z"}])
    m.rule("LAN web", src_zones=[inside], dst_zones=[outside], sources=[lan], dst_ports=[web_ports],
           ipsPolicy={"name": "Balanced Security and Connectivity", "id": "ips-1", "type": "IntrusionPolicy"},
           filePolicy={"name": "Block Malware", "id": "file-1", "type": "FilePolicy"})
    m.rule("LAN DNS and NTP", src_zones=[inside], dst_zones=[outside], sources=[lan], dst_ports=[dns_udp, dns_tcp, ntp], log="none")
    m.rule("Updates", src_zones=[inside, dmz], dst_zones=[outside], destinations=[updates], dst_ports=[https])
    m.rule("Inbound web", src_zones=[outside], dst_zones=[dmz], destinations=[web], dst_ports=[http, https])
    m.rule("Inbound mail", src_zones=[outside], dst_zones=[dmz], destinations=[mail], dst_ports=[smtp], log="both")
    m.rule("Admin access", src_zones=[inside], dst_zones=[dmz], sources=[admins], destinations=[servers], dst_ports=[mgmt])
    m.rule("Helpdesk RDP", src_zones=[inside], dst_zones=[dmz], destinations=[servers], dst_ports=[plit(6, "3389")],
           users={"objects": [{"type": "RealmUserGroup", "id": "grp-1", "name": "CORP\\helpdesk", "realm": {"id": "realm-1", "type": "Realm"}}]})
    m.rule("Staff social media", "BLOCK", src_zones=[inside], dst_zones=[outside],
           applications={"applications": [{"type": "Application", "id": "629", "name": "Facebook"}, {"type": "Application", "id": "2496", "name": "Instagram"}]})
    m.rule("Partner service", "TRUST", src_zones=[outside], dst_zones=[dmz], sources=[partner], destinations=[web], dst_ports=[plit(6, "8443"), esp])
    m.rule("Watch DMZ", "MONITOR", src_zones=[dmz], log="end")
    m.rule("Uncategorised web", "BLOCK_INTERACTIVE", src_zones=[inside], dst_zones=[outside], sources=["10.10.0.200-10.10.0.250"], dst_ports=[http, https])
    m.rule("Old FTP", src_zones=[inside], dst_zones=[outside], dst_ports=[plit(6, "21")], enabled=False)
    m.rule("DNS answers to resolver", src_zones=[outside], dst_zones=[dmz], destinations=["10.20.0.53"], src_ports=[plit(17, "53")],
           dst_ports=[plit(17, "1024-65535")], log="none")
    m.rule("Branch IPv6", src_zones=[outside], dst_zones=[dmz], sources=[branch6], destinations=["2001:db8:20::10"], dst_ports=[https, echo6])
    m.rule("Ping out", src_zones=[inside, dmz], dst_ports=[echo], log="none")
    m.rule("Reset the rest from inside", "BLOCK_RESET", section="Default", src_zones=[inside], log="both")

    m.nat_policy["name"] = "Edge NAT"
    m.manual_nat("STATIC", originalSource=lan, translatedSource=lan, originalDestination=partner, translatedDestination=partner,
                 sourceInterface=inside, destinationInterface=outside, noProxyArp=True, routeLookup=True, unidirectional=False,
                 description="No NAT towards the partner")
    m.manual_nat("STATIC", originalSource=any4, translatedSource=any4, originalDestination=web_pub, translatedDestination=web,
                 sourceInterface=outside, destinationInterface=dmz, unidirectional=True, description="Web server")
    m.manual_nat("STATIC", originalSource=web, interfaceInTranslatedSource=True, originalSourcePort=http_alt, translatedSourcePort=published,
                 sourceInterface=dmz, destinationInterface=outside, unidirectional=False, description="Test site on the interface address")
    m.manual_nat("DYNAMIC", originalSource=lan, sourceInterface=inside, destinationInterface=outside, unidirectional=False,
                 patOptions={"patPoolAddress": m.ref(pool), "interfacePat": True, "includeReserve": False, "roundRobin": True,
                             "extendedPat": False, "flatPortRange": True})
    m.auto_nat("STATIC", originalNetwork=mail, translatedNetwork=mail_pub, sourceInterface=dmz, destinationInterface=outside, dns=True)
    m.auto_nat("DYNAMIC", originalNetwork=dmz_net, interfaceInTranslatedNetwork=True, sourceInterface=dmz, destinationInterface=outside)
    m.manual_nat("DYNAMIC", after_auto=True, originalSource=internal, interfaceInTranslatedSource=True, destinationInterface=outside,
                 unidirectional=False, description="Whatever else leaves")
    answers = m.answers()
    answers.insert(-1, m.nat_policy)
    return (json.dumps(answers, indent=1) + "\n").encode("utf-8")


def fdm() -> bytes:
    m = Manager(fdm=True)
    m.metadata.update(hardwareModel="Cisco Firepower 1010 Threat Defense", softwareVersion="7.2.5-208")
    outside_if = m.interface("outside", "Ethernet1/1", "192.0.2.2", "255.255.255.0")
    inside_if = m.interface("inside", "Ethernet1/2", "10.40.0.1", "255.255.255.0")
    iot_if = m.interface("iot", "Ethernet1/3", "10.41.0.1", "255.255.255.0")
    outside, inside = m.zone("outside_zone", [outside_if]), m.zone("inside_zone", [inside_if])
    any4 = m.network("any-ipv4", "0.0.0.0/0", isSystemDefined=True)
    m.network("any-ipv6", "::/0", isSystemDefined=True)
    lan, iot = m.network("office-lan", "10.40.0.0/24", description="Branch office"), m.network("iot-net", "10.41.0.0/24")
    nas, nas_pub = m.host("nas", "10.40.0.10"), m.host("nas-public", "192.0.2.10")
    printers = m.range("printers", "10.40.0.200-10.40.0.220")
    head6 = m.network("head-office-v6", "2001:db8:1::/48")
    vendor = m.fqdn("vendor-cloud", "telemetry.example.net", "IPV4_ONLY")
    devices = m.group("office-devices", [nas, printers])
    https, http = m.tcp("HTTPS", "443", isSystemDefined=True), m.tcp("HTTP", "80", isSystemDefined=True)
    dns = m.udp("DNS_over_UDP", "53", isSystemDefined=True)
    rdp, nas_web, nas_ext = m.tcp("rdp", "3389"), m.tcp("nas-web", "5001"), m.tcp("nas-external", "8443")
    high = m.udp("udp-high", "1024-65535")
    echo, gre = m.icmp("echo-request", "ECHO_REQUEST"), m.protocol("gre", "GRE")
    unreachable = m.icmp("port-unreachable", "DESTINATION_UNREACHABLE", "PORT_UNREACHABLE")
    web = m.port_group("web", [http, https])
    m.policy["defaultAction"] = {"action": "DENY", "eventLogAction": "LOG_FLOW_END", "intrusionPolicy": None, "syslogServer": None,
                                 "type": "accessdefaultaction"}
    m.rule("Block_IoT_to_office", "DENY", src_zones=[inside], dst_zones=[inside], sources=[iot], destinations=[lan], log="both")
    m.rule("Inside_Outside_web", src_zones=[inside], dst_zones=[outside], sources=[lan], dst_ports=[web, dns],
           intrusionPolicy={"name": "Balanced Security and Connectivity", "id": "ips-1", "type": "intrusionpolicy", "version": "v1"})
    m.rule("IoT_telemetry", src_zones=[inside], dst_zones=[outside], sources=[iot], destinations=[vendor], dst_ports=[https])
    m.rule("NAS_from_Internet", src_zones=[outside], dst_zones=[inside], destinations=[nas], dst_ports=[nas_web])
    m.rule("Head_office_v6", "TRUST", src_zones=[outside], sources=[head6], destinations=[devices], dst_ports=[rdp, echo, gre], log="none")
    m.rule("DNS_answers", src_zones=[outside], dst_zones=[inside], src_ports=[dns], dst_ports=[high], log="none")
    m.rule("Staff_streaming", "DENY", src_zones=[inside], dst_zones=[outside],
           embeddedAppFilter={"applications": [{"name": "Netflix", "id": "app-756", "type": "application", "version": "v1"}],
                              "applicationFilters": [], "conditions": [], "type": "embeddedappfilter"})
    m.rule("Guests_by_time", src_zones=[inside], dst_zones=[outside], sources=[printers],
           timeRangeObjects=[{"name": "office-hours", "id": "tr-1", "type": "timerangeobject", "version": "v1"}], dst_ports=[unreachable])
    m.manual_nat("STATIC", name="NAS_published", originalSource=nas, interfaceInTranslatedSource=True, originalSourcePort=nas_web,
                 translatedSourcePort=nas_ext, sourceInterface=inside_if, destinationInterface=outside_if, unidirectional=False,
                 interfaceInOriginalDestination=False, description="NAS web interface on the outside address")
    m.auto_nat("STATIC", name="nas_static", originalNetwork=nas, translatedNetwork=nas_pub, sourceInterface=inside_if,
               destinationInterface=outside_if, interfaceInTranslatedNetwork=False, dns=False)
    m.manual_nat("DYNAMIC", after_auto=True, name="InsideOutsideNatRule", originalSource=any4, interfaceInTranslatedSource=True,
                 sourceInterface=inside_if, destinationInterface=outside_if, unidirectional=False, interfaceInOriginalDestination=False)
    m.manual_nat("DYNAMIC", after_auto=True, name="IoT_out", originalSource=iot, interfaceInTranslatedSource=True,
                 sourceInterface=iot_if, destinationInterface=outside_if, unidirectional=False, enabled=False)
    return m.export()


if __name__ == "__main__":
    (ROOT / "tests" / "data" / "fmc_sample.json").write_bytes(fmc())
    (ROOT / "tests" / "data" / "fdm_sample.txt").write_bytes(fdm())
