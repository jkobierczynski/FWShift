# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/lancomuf_sample.json: made-up answers of the REST API of a LANCOM R&S Unified Firewall.

One JSON object, the answer of each collection of the API under the collection's name (``/model/<name>``), as the
command of section 3 of the manual saves them. Every address is a documentation or private address. The keys of
networks, desktop connections and user-defined services are those of LANCOM's LMC add-in examples; the others are
assumed, as the parser reads them (see DEVELOPMENT.md).

    python3 tests/tools/make_lancomuf_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

Json = Dict[str, Any]

ALWAYS: List[Json] = [{"repeattype": "weekly", "starttime": "00:00:00", "endtime": "23:59:59", "startweekday": day,
                       "endweekday": day} for day in range(7)]  # fmt: skip


def _ident(number: int) -> str:
    return f"0e5f1a2b-0000-4000-8000-{number:012d}"


def _object(number: int, name: str, kind: str, icon: str, **keys: Any) -> Json:
    return {"id": _ident(number), "name": name, "type": kind, "description": keys.pop("description", ""), "tags": [],
            "color": 7891540, "icon": icon, "top": 100 + number * 10, "left": 200, "layer": 0, **keys}  # fmt: skip


def host(number: int, name: str, interface: Optional[str], ipv4: str, **keys: Any) -> Json:
    body = _object(number, name, "host", "host", ipv4=ipv4, nologin=False, exemptFromIdps=False, exemptFromAv=False, **keys)
    if interface is not None:
        body["interface"] = interface
    return body


def network(number: int, name: str, interface: str, ipv4: str, **keys: Any) -> Json:
    return _object(number, name, "network", "network", interface=interface, ipv4=ipv4, nologin=False, exemptFromIdps=False,
                   exemptFromAv=False, **keys)  # fmt: skip


def iprange(number: int, name: str, interface: str, start: str, end: str) -> Json:
    return _object(number, name, "iprange", "iprange", interface=interface, start=start, end=end, nologin=False)


def member(name: str, interface: str, ipv4: str) -> Json:
    return {"name": name, "interface": interface, "ipv4": ipv4, "nologin": False}


def group(number: int, name: str, members: Sequence[Union[str, Json]]) -> Json:
    return _object(number, name, "hostgroup", "hostgroup", hostgroupobjectitems=list(members), exemptFromIdps=False,
                   exemptFromAv=False)  # fmt: skip


def internet(number: int, name: str, connections: Sequence[str]) -> Json:
    return _object(number, name, "internet", "internet", connections=list(connections))


def vpngroup(number: int, name: str) -> Json:
    return _object(number, name, "vpngroup", "vpn-network", vpngroupobjectitems=[])


def entry(protocol: str, portfrom: Optional[int] = None, portto: Optional[int] = None, **extra: Any) -> Json:
    body: Json = {"protocol": protocol, "noproxy": True, **extra}
    if portfrom is not None:
        body["portfrom"] = portfrom
        body["portto"] = portfrom if portto is None else portto
    return body


def service(ident: str, name: str, entries: Sequence[Union[str, Json]], userdefined: bool = True) -> Json:
    return {"id": ident, "name": name, "userdefined": userdefined, "services": list(entries)}


def rule(service_id: str, action: str = "leftToRight", nat: str = "none", log: bool = False,
         times: Optional[List[Json]] = None, dmz: Any = False, use_connection: bool = False, **extra: Any) -> Json:  # fmt: skip
    """A service of a connection, in the form of LCOS FX 10.8 and later."""
    return {"uniqueId": service_id, "dmz": dmz, "natactive": nat, "editable": True,
            "timeranges": ALWAYS if times is None else times, "action": action, "log": log,
            "applicationfilter": {"useconnection": True, "activeprofiles": []}, "useConnection": use_connection,
            "useConnectionTrafficShaping": False, "trafficShaping": {"trafficGroup": "", "outgoingDscp": None}, **extra}  # fmt: skip


def connection(number: int, a: str, b: str, rules: Sequence[Json], **extra: Any) -> Json:
    return {"id": _ident(900 + number), "obja": a, "objb": b, "rules": list(rules), "description": "", "color": 1562591,
            "points": [], "blockall": False, "webfiltersettings": [], "applicationfilter": {"mode": "off", "activeprofiles": []},
            "appfilterRoutingProfiles": [], "trafficShaping": {"trafficGroup": "", "outgoingDscp": None}, **extra}  # fmt: skip


def answers(objects: Dict[str, List[Json]], services: Dict[str, List[Json]], connections: List[Json],
            extra: Optional[Json] = None) -> Json:  # fmt: skip
    out: Json = {"fwshift": "lancom-uf"}
    out.update(objects)
    out.update(services)
    out["desktop-connections"] = connections
    out.update(extra or {})
    return out


def sample() -> Json:
    i = _ident
    hosts = [
        host(1, "Webserver", "eth2", "172.16.20.10", description="public web server"),
        host(2, "Mailserver", "eth2", "172.16.20.25"),
        host(3, "HMI", "eth3", "10.30.0.50"),
        host(4, "Printer", None, "192.168.10.40"),  # names no interface: not used
    ]
    networks = [
        network(10, "LAN", "eth1", "192.168.10.0/24"),
        network(11, "DMZ", "eth2", "172.16.20.0/24"),
        network(12, "OT-Cell", "eth3", "10.30.0.0/24"),
        network(13, "Lab-v6", "eth4", "10.40.0.0/24", ipv6="2001:db8:40::/64"),  # an attribute the parser does not read
    ]
    ipranges = [
        iprange(20, "Admin-PCs", "eth1", "192.168.10.200", "192.168.10.220"),
        iprange(21, "Monitoring", "any", "198.51.100.10", "198.51.100.20"),
    ]
    hostgroups = [
        group(30, "Servers", [i(1), i(2)]),
        group(31, "Jump-Hosts", [member("jump-it", "eth1", "192.168.10.5"), member("jump-ot", "eth3", "10.30.0.5")]),
    ]
    internets = [internet(40, "Internet", ["nc-wan"])]
    vpngroups = [vpngroup(50, "Branch Sites")]
    firewall = [_object(60, "Firewall", "firewall", "firewall")]
    predefined = [
        service("internet.http", "internet.http", [entry("tcp", 80)], False),
        service("internet.https", "internet.https", [entry("tcp", 443)], False),
        service("standard.dns", "standard.dns", [entry("tcp", 53), entry("udp", 53)], False),
        service("standard.ping", "standard.ping", [entry("icmp")], False),
        service("standard.ssh", "standard.ssh", [entry("tcp", 22)], False),
        service("remote.rdp", "remote.rdp", [entry("tcp", 3389)], False),
        service("internet.smtp", "internet.smtp", [entry("tcp", 25, noproxy=False)], False),
        service("vpn.ipsec", "vpn.ipsec", [entry("udp", 500), entry("udp", 4500), entry("esp")], False),
    ]
    userdefined = [
        service(i(70), "Modbus-TCP", [entry("tcp", 502)]),
        service(i(71), "OPC-UA", [entry("tcp", 4840, 4843)]),
        service(i(72), "GRE-Tunnel", [entry("gre")]),
        service(i(73), "Legacy-App", [entry("tcp", 7000, 7010, sourceport=1024)]),  # a key the parser does not read
    ]
    servicegroups = [service(i(80), "Web", ["internet.http", "internet.https"])]
    weekdays = [{"repeattype": "weekly", "starttime": "06:00:00", "endtime": "22:00:00", "startweekday": day, "endweekday": day}
                for day in range(5)]  # fmt: skip
    connections = [
        connection(1, i(10), i(40), [rule("internet.http", nat="left", log=True), rule("internet.https", nat="left", log=True),
                                     rule("standard.dns", nat="left"), rule("standard.ping", nat="left")]),  # fmt: skip
        connection(2, i(1), i(40), [rule("internet.https", action="rightToLeft",
                                         dmz={"externalIp": "203.0.113.10", "destinationPort": 443})]),  # fmt: skip
        connection(3, i(20), i(30), [rule("standard.ssh"), rule("remote.rdp", action="both")]),
        connection(4, i(31), i(12), [rule(i(70), log=True)]),
        connection(5, i(3), i(12), [rule(i(71), action="both", times=weekdays)]),
        connection(6, i(21), i(12), [rule("standard.ping", times=[])]),
        connection(7, i(10), i(2), [rule("internet.smtp", use_connection=True)], nat={"mode": "leftToRight", "sourceIp": ""}),
        connection(8, i(50), i(10), [rule("remote.rdp")]),
        connection(9, i(10), i(60), [rule("standard.ssh")]),
        connection(10, i(10), i(13), [rule("internet.http")]),
        connection(11, i(11), i(40), [rule(i(72), nat="both"), rule(i(73)), rule("standard.ssh", action="drop")]),
        connection(12, i(40), i(999), [rule("internet.https")]),
        connection(13, i(10), i(11), [rule(i(80), action="both"), rule("vpn.ipsec", action="rightToLeft", log=True)]),
        connection(14, i(4), i(11), [rule("internet.http")]),
    ]
    extra = {"network-connections": [{"id": "nc-wan", "name": "WAN", "interface": "eth0"}],
             "protocols": [{"id": "gre", "name": "GRE", "number": 47}]}  # fmt: skip
    return answers({"hosts": hosts, "networks": networks, "ipranges": ipranges, "hostgroups": hostgroups, "internet": internets,
                    "vpngroups": vpngroups, "firewall": firewall},
                   {"predefined-services": predefined, "userdefined-services": userdefined, "servicegroups": servicegroups},
                   connections, extra)  # fmt: skip


def main() -> None:
    path = Path(__file__).resolve().parents[1] / "data" / "lancomuf_sample.json"
    path.write_text(json.dumps(sample(), indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
