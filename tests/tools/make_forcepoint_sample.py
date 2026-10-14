# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/forcepoint_sample.json: a made-up firewall policy of a Forcepoint Security Management Center, as
the program of 'fwshift script forcepoint-dump' writes it: the answers of the SMC API one per line, each list answer
with the key ``fwshift_list`` naming the list it is.

Every address is a documentation or private address. Not taken from any real SMC.

    python3 tests/tools/make_forcepoint_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE = "https://smc.example.net:8082/7.4"
E = f"{BASE}/elements"
RULE_LISTS = ("fw_ipv4_access_rule", "fw_ipv6_access_rule", "fw_ipv4_nat_rule", "fw_ipv6_nat_rule")


def link(href: str, *extra: str) -> List[Dict[str, str]]:
    out = [{"rel": "self", "href": href, "type": href.rsplit("/", 2)[-2]}]
    out += [{"rel": rel, "href": f"{href}/{rel}"} for rel in extra]
    return out


def policy(kind: str, key: int, name: str, template: Optional[str], system: bool = False, nat: bool = True) -> Dict[str, Any]:
    href = f"{E}/{kind}/{key}"
    lists = RULE_LISTS if nat else RULE_LISTS[:1]
    body: Dict[str, Any] = {"name": name, "key": key, "comment": None, "read_only": system, "system": system}
    if kind != "sub_ipv4_fw_policy":
        body["template"] = template
    body["link"] = link(href) + [{"rel": f"{rel}s", "href": f"{href}/{rel}"} for rel in lists]
    return body


class Sample:
    def __init__(self) -> None:
        self.out: List[Dict[str, Any]] = []
        self.ranks: Dict[str, int] = {}

    def add(self, obj: Dict[str, Any]) -> None:
        self.out.append(obj)

    def element(self, kind: str, key: int, name: str, **fields: Any) -> str:
        href = f"{E}/{kind}/{key}"
        self.add({"name": name, **fields, "key": key, "link": link(href)})
        return href

    def rules(self, parent: str, rel: str, entries: List[Dict[str, Any]]) -> None:
        where = f"{parent}/{rel}"
        listing = {"fwshift_list": where, "result": []}
        self.add(listing)
        for rank, entry in enumerate(entries, 1):
            key = entry.pop("key")
            href = f"{where}/{key}"
            listing["result"].append({"href": href, "name": entry.get("name", ""), "type": rel})
            body = {**entry, "tag": f"{key}.0", "rank": float(rank), "parent_policy": parent}
            body["link"] = link(href, "add_before", "add_after")
            self.add(body)


def cell(*hrefs: str) -> Dict[str, Any]:
    return {"src": list(hrefs)}


def dcell(*hrefs: str) -> Dict[str, Any]:
    return {"dst": list(hrefs)}


def scell(*hrefs: str) -> Dict[str, Any]:
    return {"service": list(hrefs)}


ANY: Dict[str, Any] = {"any": True}


def rule(key: int, name: str, src: Dict[str, Any], dst: Dict[str, Any], svc: Dict[str, Any], action: Any, log: str = "undefined",
         closing: bool = False, parent: str = "", **extra: Any) -> Dict[str, Any]:
    act = action if isinstance(action, dict) else {"action": [action]}
    act.setdefault("connection_tracking_options", {"timeout": -1, "mss_enforced": False, "mss_enforced_min": 0, "mss_enforced_max": 0})
    body: Dict[str, Any] = {"key": key, "is_disabled": False, "sources": src, "destinations": dst, "services": svc, "action": act,
                            "options": {"log_level": log, "log_closing_mode": closing, "log_accounting_info_mode": False}}
    if name:
        body["name"] = name
    if parent:
        body["parent_insert_point"] = parent
    body.update(extra)
    return body


def section(key: int, comment: str, parent: str = "") -> Dict[str, Any]:
    body: Dict[str, Any] = {"key": key, "comment": comment}
    if parent:
        body["parent_insert_point"] = parent
    return body


def insert_point(key: int, name: str, kind: str = "normal", parent: str = "") -> Dict[str, Any]:
    body: Dict[str, Any] = {"key": key, "name": name, "type": kind}
    if parent:
        body["parent_insert_point"] = parent
    return body


def nat(key: int, name: str, src: Dict[str, Any], dst: Dict[str, Any], svc: Dict[str, Any], used_on: Any = None, **options: Any) -> Dict[str, Any]:
    return {"key": key, "name": name, "is_disabled": False, "used_on": used_on if used_on is not None else {"any": True}, "sources": src,
            "destinations": dst, "services": svc, "options": {"log_level": "undefined", **options}}


def sample() -> List[Dict[str, Any]]:
    s = Sample()
    top = f"{E}/fw_template_policy/11"
    mid = f"{E}/fw_template_policy/12"
    pol = f"{E}/fw_policy/272"
    sub = f"{E}/sub_ipv4_fw_policy/3001"
    s.add(policy("fw_policy", 272, "Branch Policy", mid))
    s.add(policy("fw_template_policy", 12, "Branch Template", top))
    s.add(policy("fw_template_policy", 11, "Firewall Template", None, system=True))

    # -- elements ------------------------------------------------------------------------------------
    mgt = s.element("mgt_servers_alias", 7, "$$ Management Servers", system=True)
    cluster = s.element("local_cluster_alias", 8, "$$ Local Cluster", system=True)
    default_nat = s.element("default_nat_address_alias", 9, "$$ Default NAT Address", system=True)
    sg_control = s.element("tcp_service", 650, "SG Control", min_dst_port=3020, max_dst_port=3021, system=True)
    ident = s.element("tcp_service", 113, "Ident", min_dst_port=113, max_dst_port=None, system=True)
    https = s.element("tcp_service", 440, "HTTPS", min_dst_port=443, max_dst_port=None, protocol_agent_ref=None, system=True)
    http = s.element("tcp_service", 441, "HTTP", min_dst_port=80, max_dst_port=None, system=True)
    ssh = s.element("tcp_service", 451, "SSH", min_dst_port=22, system=True)
    dns_udp = s.element("udp_service", 530, "DNS (UDP)", min_dst_port=53, system=True)
    dns_tcp = s.element("tcp_service", 531, "DNS (TCP)", min_dst_port=53, system=True)
    dns = s.element("service_group", 532, "DNS", element=[dns_udp, dns_tcp], system=True)
    nb_udp = s.element("udp_service", 137, "NetBIOS (UDP)", min_dst_port=137, max_dst_port=138, system=True)
    nb_tcp = s.element("tcp_service", 139, "NetBIOS (TCP)", min_dst_port=139, system=True)
    netbios = s.element("service_group", 140, "NetBIOS", element=[nb_udp, nb_tcp], system=True)
    ping = s.element("icmp_service", 800, "Echo Request", icmp_type=8, icmp_code=None, system=True)
    ping6 = s.element("icmp_ipv6_service", 801, "IPv6 Echo Request", icmp_type=128, icmp_code=0, system=True)
    gre = s.element("ip_service", 847, "GRE", protocol_number=47, system=True)
    t8443 = s.element("tcp_service", 2102, "tcp-8443", min_dst_port=8443)
    t8000 = s.element("tcp_service", 2103, "tcp-8000-8010", min_dst_port=8000, max_dst_port=8010)
    syslog = s.element("udp_service", 2104, "syslog-from-514", min_dst_port=514, min_src_port=514, max_src_port=514)
    web_services = s.element("service_group", 2101, "web-services", element=[t8443, t8000])
    social = s.element("application_situation", 5001, "Facebook", system=True)

    web_v6 = s.element("host", 2002, "web-01-v6", address=None, ipv6_address="2001:db8:10::10", secondary=[])
    pub_web = s.element("host", 2003, "pub-web", address="203.0.113.10", secondary=[])
    web = s.element("host", 2004, "web-01", address="192.168.10.10", ipv6_address=None, secondary=["192.168.10.11"])
    dns_host = s.element("host", 2005, "dns-01", address="192.168.10.53", secondary=[])
    mail = s.element("host", 2006, "mail-01", address="192.168.10.25", ipv6_address="2001:db8:10::25", secondary=[],
                     comment="dual stack")
    router = s.element("router", 2007, "isp-gw", address="198.51.100.1", secondary=[])
    dmz = s.element("network", 2010, "net-dmz", ipv4_network="192.168.10.0/24", ipv6_network=None, broadcast=True)
    lan = s.element("network", 2011, "net-lan", ipv4_network="10.1.0.0/16", ipv6_network=None, broadcast=False)
    admins = s.element("address_range", 2012, "admins", ip_range="10.1.5.10-10.1.5.20")
    lan6 = s.element("network", 2013, "net-lan-v6", ipv4_network=None, ipv6_network="2001:db8:20::/64")
    guest = s.element("network", 2014, "net-guest", ipv4_network="172.16.30.0/24", ipv6_network="2001:db8:30::/64", broadcast=True)
    grp_web = s.element("group", 2001, "grp-web", element=[web, dmz])
    grp_inside = s.element("group", 2015, "grp-inside", element=[lan, guest], comment="networks behind the branch firewall")
    s.element("group", 2016, "grp-empty", element=[])
    internal = s.element("interface_zone", 2020, "Internal")
    external = s.element("interface_zone", 2021, "External")
    s.element("interface_zone", 2022, "DMZ")
    zone_lan = s.element("match_expression", 2201, "zone Internal and lan", ref=[internal, lan], service_port_selection="standard")
    not_dmz = s.element("expression", 2301, "not dmz", operator="exclusion", ne_ref=[dmz], sub_expression=[])
    lan_not_admins = s.element("expression", 2302, "lan without admins", operator="intersection", ne_ref=[lan],
                               sub_expression=[{"operator": "exclusion", "ne_ref": [admins], "sub_expression": []}])
    updates = s.element("domain_name", 2401, "updates.example.com", domain_name_entry=[{"name": "cdn.example.com"}])
    helpdesk = s.element("internal_user_group", 2501, "helpdesk", comment="users of the internal LDAP")
    office = s.element("rule_validity_time", 2601, "Office hours", rule_time_active="day_of_week", rule_time_zone="engine_time",
                       rule_time_start="08:00:00", rule_time_end="18:00:00", week_day=["monday", "tuesday", "wednesday", "thursday", "friday"])
    branch = s.element("single_fw", 50, "fw-branch")

    # -- Firewall Template (predefined) --------------------------------------------------------------
    top_ip4 = f"{top}/fw_ipv4_access_rule/901"
    top_ip6 = f"{top}/fw_ipv6_access_rule/951"
    s.rules(top, "fw_ipv4_access_rule", [
        rule(900, "", cell(mgt), dcell(cluster), scell(sg_control), "allow", comment="SMC communications (abbreviated)"),
        insert_point(899, "Automatic Rules Insert Point", "automatic"),
        insert_point(901, "Insert Point"),
        rule(902, "", ANY, ANY, scell(ident), "refuse", "stored"),
        rule(903, "", ANY, ANY, ANY, "discard", "stored"),
    ])
    s.rules(top, "fw_ipv6_access_rule", [
        insert_point(951, "Insert Point"),
        rule(952, "", ANY, ANY, scell(ident), "refuse", "stored"),
        rule(953, "", ANY, ANY, ANY, "discard", "stored"),
    ])
    s.rules(top, "fw_ipv4_nat_rule", [insert_point(961, "Insert Point")])
    s.rules(top, "fw_ipv6_nat_rule", [insert_point(971, "Insert Point")])

    # -- Branch Template -----------------------------------------------------------------------------
    mid_ip4 = f"{mid}/fw_ipv4_access_rule/1503"
    mid_ip6 = f"{mid}/fw_ipv6_access_rule/1551"
    mid_nat4 = f"{mid}/fw_ipv4_nat_rule/1571"
    s.rules(mid, "fw_ipv4_access_rule", [
        section(1501, "Branch template", top_ip4),
        rule(1502, "dns to resolver", ANY, dcell(dns_host), scell(dns), "allow", "none", parent=top_ip4),
        insert_point(1503, "Policy rules", parent=top_ip4),
        rule(1504, "drop netbios", ANY, ANY, scell(netbios), "discard", "none", parent=top_ip4),
    ])
    s.rules(mid, "fw_ipv6_access_rule", [
        insert_point(1551, "Policy rules (IPv6)", parent=top_ip6),
    ])
    s.rules(mid, "fw_ipv4_nat_rule", [insert_point(1571, "Policy NAT", parent=f"{top}/fw_ipv4_nat_rule/961")])
    s.rules(mid, "fw_ipv6_nat_rule", [])

    # -- Branch Policy -------------------------------------------------------------------------------
    s.rules(pol, "fw_ipv4_access_rule", [
        section(1000, "Inbound", mid_ip4),
        rule(1001, "allow web", ANY, dcell(grp_web), scell(https, web_services), "allow", "stored", True, mid_ip4),
        rule(1002, "lan defaults", cell(lan), ANY, ANY, {"action": ["continue"], "connection_tracking_options": {"timeout": 3600}}, "stored",
             parent=mid_ip4),
        rule(1003, "to admin sub-policy", cell(lan), dcell(dmz), scell(ssh), {"action": ["jump"], "sub_policy": sub}, parent=mid_ip4),
        rule(1004, "refuse admins 8443", cell(admins), dcell(pub_web), scell(t8443), "refuse", "stored", parent=mid_ip4),
        dict(rule(1005, "old block", cell(lan), ANY, ANY, "discard", "none", parent=mid_ip4), is_disabled=True),
        rule(1006, "internal zone out", cell(zone_lan), ANY, scell(web_services), "allow", parent=mid_ip4),
        rule(1007, "not to dmz", cell(lan), dcell(not_dmz), scell(https), "allow", "stored", parent=mid_ip4),
        section(1008, "Outbound", mid_ip4),
        rule(1009, "updates by name", cell(lan), dcell(updates), scell(https), "allow", "stored", True, mid_ip4),
        rule(1010, "zone or web host out", cell(internal, web), dcell(external), scell(http), "allow", "stored", parent=mid_ip4),
        rule(1011, "vpn only", cell(lan), dcell(dmz), ANY, "allow", parent=mid_ip4,
             match_vpn_options={"match_type": "normal", "match_vpns": []}),
        rule(1012, "ping out", cell(grp_inside), ANY, scell(ping), "allow", "transient", parent=mid_ip4,
             match_vpn_options={"match_type": "no_vpn", "match_vpns": []}),
        rule(1013, "no social", cell(lan), ANY, scell(social), "discard", "stored", parent=mid_ip4),
        rule(1014, "helpdesk to dmz", cell(helpdesk), dcell(dmz), scell(ssh), "allow", "stored", parent=mid_ip4),
        rule(1015, "unfinished", cell(lan), {"none": True}, scell(ssh), "allow", parent=mid_ip4),
        rule(1016, "office web", cell(lan), ANY, scell(http), "allow", parent=mid_ip4, rule_validity_times=[office]),
        rule(1017, "limited guests", cell(guest), ANY, scell(https),
             {"action": ["allow"], "deep_inspection": True, "connection_tracking_options": {"state": "normal", "src_limit": 50}},
             "essential", parent=mid_ip4),
        rule(1018, "block list", ANY, ANY, ANY, "apply_blacklist", parent=mid_ip4),
        rule(1019, "gre to isp", cell(lan), dcell(router), scell(gre), "allow", parent=mid_ip4),
        rule(1020, "lan but admins", cell(lan_not_admins), dcell(mail), scell(syslog, ping), "allow", "alert", parent=mid_ip4),
        rule(1021, "", cell(guest), dcell(lan), ANY, "discard", "stored", parent=mid_ip4, comment="guests stay out"),
    ])
    s.rules(pol, "fw_ipv6_access_rule", [
        rule(1100, "v6 web", cell(lan6), dcell(web_v6), scell(https), "allow", "stored", parent=mid_ip6),
        rule(1101, "v6 ping", cell(lan6), ANY, scell(ping6), "allow", parent=mid_ip6),
        rule(1102, "v6 mail", ANY, dcell(mail), scell(https), "allow", "stored", parent=mid_ip6),
        rule(1103, "v6 guests", cell(grp_inside), dcell(web_v6), ANY, "refuse", parent=mid_ip6),
    ])
    s.rules(pol, "fw_ipv4_nat_rule", [
        nat(1200, "publish web", ANY, dcell(pub_web), scell(https), static_dst_nat={
            "automatic_proxy": True,
            "original_value": {"element": pub_web, "ip_descriptor": "203.0.113.10", "min_port": "443", "max_port": "443"},
            "translated_value": {"element": web, "ip_descriptor": "192.168.10.10", "min_port": "8443", "max_port": "8443"}}),
        nat(1201, "no nat inside", cell(lan), dcell(dmz), ANY),
        nat(1202, "lan out", cell(lan), ANY, ANY, dynamic_src_nat={
            "automatic_proxy": True, "translation_values": [{"ip_descriptor": "203.0.113.1", "min_port": 1024, "max_port": 65535}]}),
        nat(1203, "mail static", cell(mail), ANY, ANY, static_src_nat={
            "automatic_proxy": True, "original_value": {"element": mail}, "translated_value": {"ip_descriptor": "203.0.113.25"}}),
        nat(1204, "guests hide", cell(guest), ANY, ANY, {"firewall_ref": branch}, dynamic_src_nat={
            "automatic_proxy": True, "translation_values": [{"element": default_nat, "min_port": 1024, "max_port": 65535}]}),
    ])
    # The NAT rules of the policy stand at the insert point of the Branch Template.
    for obj in s.out:
        if "used_on" in obj and _self(obj).startswith(f"{pol}/"):
            obj["parent_insert_point"] = mid_nat4
    s.rules(pol, "fw_ipv6_nat_rule", [])

    # -- the sub-policy ------------------------------------------------------------------------------
    s.add(policy("sub_ipv4_fw_policy", 3001, "Admin Access", None, nat=False))
    s.rules(sub, "fw_ipv4_access_rule", [
        rule(1300, "admins in", cell(admins), ANY, ANY, "allow"),
        rule(1301, "others out", ANY, ANY, ANY, "discard", "stored"),
    ])
    return s.out


def _self(obj: Dict[str, Any]) -> str:
    return next((str(entry["href"]) for entry in obj.get("link") or [] if entry.get("rel") == "self"), "")


def main() -> None:
    data = Path(__file__).resolve().parents[1] / "data"
    lines = [json.dumps(obj, ensure_ascii=False, separators=(",", ":")) for obj in sample()]
    (data / "forcepoint_sample.json").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
