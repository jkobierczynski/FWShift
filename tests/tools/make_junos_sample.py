# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/junos_sample.conf: a made-up SRX configuration, as 'show configuration | display set' prints it.

Every address is a documentation or private address.

    python3 tests/tools/make_junos_sample.py
"""

from __future__ import annotations

from pathlib import Path
from typing import List


def sample() -> str:
    lines: List[str] = [
        "set version 21.4R3.15",
        "set system host-name srx-lab",
        "set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.2/24",
        "set interfaces ge-0/0/1 unit 0 family inet address 10.10.0.1/16",
        "set interfaces ge-0/0/2 unit 0 family inet address 10.20.0.1/24",
    ]
    zones = {"untrust": ["ge-0/0/0.0"], "trust": ["ge-0/0/1.0"], "dmz": ["ge-0/0/2.0", "ge-0/0/3.0"], "guest": ["ge-0/0/4.0"]}
    for zone, interfaces in zones.items():
        for interface in interfaces:
            lines.append(f"set security zones security-zone {zone} interfaces {interface} host-inbound-traffic system-services ping")
    book = "set security address-book global"
    lines += [
        f"{book} address lan-net 10.10.0.0/16",
        f'{book} address lan-net description "office \\"LAN\\""',
        f"{book} address web-srv 10.20.0.80/32",
        f"{book} address mail-srv 10.20.0.25/32",
        f"{book} address admin-range range-address 10.10.5.10 to 10.10.5.20",
        f"{book} address bad-net 198.51.100.0/24",
        f"{book} address bad-host 192.0.2.66/32",
        f"{book} address updates dns-name updates.example.com ipv4-only",
        f"{book} address v6-net 2001:db8:10::/48",
        f"{book} address-set servers address web-srv",
        f"{book} address-set servers address mail-srv",
        f"{book} address-set bad address bad-net",
        f"{book} address-set bad address bad-host",
        f"{book} address-set watched address-set bad",
        f"{book} address-set watched address v6-net",
        "set security address-book dmz-book address dmz-net 10.20.0.0/24",
        "set security address-book dmz-book address lan-net 10.20.0.64/26",
        "set security address-book dmz-book attach zone dmz",
    ]
    app = "set applications application"
    lines += [
        f"{app} app-web-alt protocol tcp",
        f"{app} app-web-alt destination-port 8080-8081",
        f"{app} app-mail-sub term t1 protocol tcp destination-port 587",
        f"{app} app-mail-sub term t2 protocol tcp destination-port 465",
        f"{app} app-ping protocol icmp",
        f"{app} app-ping icmp-type echo-request",
        f"{app} app-gre protocol gre",
        f"{app} app-high protocol tcp",
        f"{app} app-high destination-port 1000-2000",
        f"{app} app-high source-port 1024-65535",
        f"{app} app-ntp protocol udp",
        f"{app} app-ntp destination-port ntp",
        "set applications application-set web-all application junos-http",
        "set applications application-set web-all application junos-https",
        "set applications application-set web-all application app-web-alt",
    ]

    def policy(context: str, name: str, sources: List[str], destinations: List[str], applications: List[str], action: str,
               extra: List[str] = ()) -> None:  # type: ignore[assignment]
        where = f"set security policies {context} policy {name}"
        lines.extend(f"{where} match source-address {s}" for s in sources)
        lines.extend(f"{where} match destination-address {d}" for d in destinations)
        lines.extend(f"{where} match application {a}" for a in applications)
        lines.extend(f"{where} {e}" for e in extra)
        lines.append(f"{where} then {action}")

    policy("from-zone trust to-zone untrust", "block-bad", ["any"], ["watched"], ["any"], "deny", ["then log session-init"])
    policy("from-zone trust to-zone untrust", "web-out", ["lan-net"], ["any"], ["web-all"], "permit",
           ['description "web for the office"', "then log session-close"])
    policy("from-zone trust to-zone untrust", "updates", ["lan-net"], ["updates"], ["junos-https"], "permit")
    policy("from-zone trust to-zone untrust", "ping-out", ["any"], ["any"], ["app-ping"], "permit")
    policy("from-zone untrust to-zone dmz", "web-in", ["any"], ["web-srv"], ["app-web-alt"], "permit")
    policy("from-zone untrust to-zone dmz", "mail-in", ["any"], ["mail-srv"], ["junos-smtp", "app-mail-sub"], "permit")
    policy("from-zone trust to-zone dmz", "admin", ["admin-range"], ["dmz-net"], ["junos-ssh"], "permit")
    policy("from-zone trust to-zone dmz", "not-servers", ["servers"], ["lan-net"], ["app-gre"], "permit",
           ["match source-address-excluded"])
    policy("from-zone dmz to-zone untrust", "dmz-out", ["dmz-net"], ["any"], ["junos-dns-udp", "app-ntp"], "permit")
    policy("from-zone guest to-zone untrust", "guest-web", ["any"], ["any-ipv4"], ["junos-http"], "permit",
           ["scheduler-name work-hours"])
    policy("from-zone guest to-zone untrust", "guest-ping", ["any"], ["any"], ["junos-ping"], "permit")
    policy("from-zone trust to-zone trust", "intra", ["any"], ["any"], ["any"], "permit")
    policy("from-zone trust to-zone junos-host", "to-box", ["any"], ["any"], ["junos-ssh"], "permit")
    policy("global", "global-block", ["bad"], ["any"], ["any"], "reject")
    policy("global", "global-ntp", ["any"], ["any"], ["app-ntp", "app-high"], "permit", ["match from-zone trust", "match to-zone untrust"])
    lines.append("set security policies default-policy deny-all")
    lines.append("deactivate security policies from-zone dmz to-zone untrust policy dmz-out")
    nat = "set security nat"
    lines += [
        f"{nat} source pool dmz-pool address 203.0.113.50/32 to 203.0.113.59/32",
        f"{nat} source rule-set trust-out from zone trust",
        f"{nat} source rule-set trust-out to zone untrust",
        f"{nat} source rule-set trust-out rule snat-lan match source-address 10.10.0.0/16",
        f"{nat} source rule-set trust-out rule snat-lan then source-nat interface",
        f"{nat} source rule-set dmz-out from zone dmz",
        f"{nat} source rule-set dmz-out to zone untrust",
        f"{nat} source rule-set dmz-out rule snat-dmz match source-address 10.20.0.0/24",
        f"{nat} source rule-set dmz-out rule snat-dmz then source-nat pool dmz-pool",
        f"{nat} destination pool web-pool address 10.20.0.80/32 port 8080",
        f"{nat} destination rule-set from-internet from zone untrust",
        f"{nat} destination rule-set from-internet rule dnat-web match destination-address 203.0.113.10/32",
        f"{nat} destination rule-set from-internet rule dnat-web match destination-port 80",
        f"{nat} destination rule-set from-internet rule dnat-web then destination-nat pool web-pool",
        f"{nat} static rule-set inbound from zone untrust",
        f"{nat} static rule-set inbound rule static-mail match destination-address 203.0.113.25/32",
        f"{nat} static rule-set inbound rule static-mail then static-nat prefix 10.20.0.25/32",
        f"{nat} source rule-set vr-out from routing-instance VR1",
        f"{nat} source rule-set vr-out to zone untrust",
        f"{nat} source rule-set vr-out rule snat-vr match source-address 10.30.0.0/16",
        f"{nat} source rule-set vr-out rule snat-vr then source-nat interface",
        f"{nat} proxy-arp interface ge-0/0/0.0 address 203.0.113.10/32 to 203.0.113.59/32",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    path = Path(__file__).resolve().parents[1] / "data" / "junos_sample.conf"
    path.write_text(sample(), encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
