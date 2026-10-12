# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/barracuda_sample.json: made-up answers of the REST API of a CloudGen Firewall.

The forwarding rules (GET .../forwarding-firewall/rules?expand=true), then each network and service
object they name, one answer after the other. Every address is a documentation or private address.
The keys are those of the API as the parser reads them (see DEVELOPMENT.md).

    python3 tests/tools/make_barracuda_sample.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

Json = Dict[str, Any]


def entry(ip: str, interface: str = "", comment: str = "") -> Json:
    found: Json = {"ip": ip}
    if interface:
        found["interface"] = interface
    if comment:
        found["comment"] = comment
    return {"entry": found}


def ref(name: str) -> Json:
    return {"references": name}


def net(name: str, included: Sequence[Union[str, Json]], excluded: Sequence[str] = (), kind: str = "generic",
        comment: str = "") -> Json:  # fmt: skip
    body: Json = {"name": name, "type": kind, "comment": comment,
                  "included": [entry(item) if isinstance(item, str) else item for item in included],
                  "excluded": [entry(item) for item in excluded]}  # fmt: skip
    return body


def port(protocol: str, *ports: str, client: Optional[Json] = None, **extra: Any) -> Json:
    found: Json = {"protocol": protocol, "ports": list(ports), **extra}
    if client is not None:
        found["clientPortUsed"] = client
    return {"entry": found}


def proto(protocol: str, **extra: Any) -> Json:
    return {"entry": {"protocol": protocol, **extra}}


def svc(name: str, entries: Sequence[Json], comment: str = "") -> Json:
    return {"name": name, "comment": comment, "entries": list(entries)}


def rule(name: str, source: str, destination: str, service: str, action: Union[str, Json] = "pass", version: str = "IPv4",
         deactivated: bool = False, bidirectional: bool = False, comment: str = "", policies: Optional[Json] = None,
         **extra: Any) -> Json:  # fmt: skip
    body: Json = {"name": name, "comment": comment, "ipVersion": version, "deactivated": deactivated, "dynamic": False,
                  "bidirectional": bidirectional, "source": ref(source), "destination": ref(destination),
                  "service": ref(service), "action": {"type": action} if isinstance(action, str) else action,
                  "policies": policies or {"schedule": {"type": "always"}}, **extra}  # fmt: skip
    return body


def answers() -> List[Json]:
    networks = [
        net("Office-LAN", ["10.10.0.0/16"], comment="the office"),
        net("DMZ-Servers", ["10.20.0.0/24"], excluded=["10.20.0.0/28"]),
        net("Web-Server", ["10.20.0.80"], kind="singleIPv4Address"),
        net("Mail-Server", ["10.20.0.25"], kind="singleIPv4Address"),
        net("Public-Web", ["203.0.113.10"], kind="singleIPv4Address"),
        net("Admin-Hosts", [entry("10.10.5.10", "port2"), entry("10.10.5.11", "port2"), entry("192.0.2.50", "port1", "remote admin")]),
        net("Blocked-Nets", ["198.51.100.0/24", "2001:db8:bad::/48"]),
        net("Server-Group", [ref("Web-Server"), ref("Mail-Server")]),
        net("Updates", ["updates.example.com"], kind="hostname"),
        net("V6-Servers", ["2001:db8:20::/64"], kind="singleIPv6Network"),
    ]
    services = [
        svc("HTTP+S", [port("tcp", "80", "443")]),
        svc("SSH", [port("tcp", "22", sessionTimeout=86400)]),
        svc("SMTP", [port("tcp", "25")]),
        svc("DNS", [port("tcp", "53"), port("udp", "53")]),
        svc("Ping", [proto("icmp", maxPingSize=1024, minDelay=10)]),
        svc("Web-Group", [ref("HTTP+S"), port("tcp", "8080")]),
        svc("GRE", [proto("47")]),
        svc("Odd-Ports", [port("tcp", "1000-2000", client={"from": 1024, "to": 65535})]),
    ]
    rules = [
        rule("BLOCK-BAD", "Blocked-Nets", "Any", "Any", "block", comment="known bad networks"),
        rule("BLOCK-BAD-V6", "Blocked-Nets", "Any", "Any", "block", version="IPv6"),
        rule("ADMIN-SSH", "Admin-Hosts", "DMZ-Servers", "SSH"),
        rule("LAN-2-INTERNET", "Office-LAN", "Any", "HTTP+S", {"type": "pass", "connection": ref("Dynamic NAT")}),
        rule("WEB-IN", "Any", "Public-Web", "HTTP+S", "dnat"),
        rule("SERVER-SYNC", "DMZ-Servers", "Office-LAN", "Web-Group", bidirectional=True),
        rule("DNS-OUT", "Server-Group", "Any", "DNS", deactivated=True),
        rule("PING-ALL", "Office-LAN", "Any", "Ping"),
        rule("UPDATES", "DMZ-Servers", "Updates", "HTTP+S"),
        rule("V6-WEB", "Any", "V6-Servers", "HTTP+S", version="IPv6"),
        rule("DENY-LAN-DMZ", "Office-LAN", "DMZ-Servers", "Any", "deny"),
        rule("GRE-LAB", "Office-LAN", "Mail-Server", "GRE",
             policies={"application": {"applicationControl": False, "urlFilter": True}, "ips": "Default", "schedule": {"type": "always"}}),
        rule("TO-LAB", "Office-LAN", "Any", "Any", "cascade"),
        rule("ODD", "Office-LAN", "Any", "Odd-Ports", policies={"schedule": {"type": "recurring", "name": "Work-Hours"}}),
        rule("BLOCKALL", "Any", "Any", "Any", "block"),
    ]
    return [{"rules": rules}, *networks, *services]


def sample() -> str:
    return "\n".join(json.dumps(answer, indent=2) for answer in answers()) + "\n"


def main() -> None:
    path = Path(__file__).resolve().parents[1] / "data" / "barracuda_sample.json"
    path.write_text(sample(), encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
