# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/checkpoint_sample.log: made-up Log Exporter output for the policy of checkpoint_sample.json.

90 days (2026-07-03 to 2026-09-30) of one gateway, gw-edge, mostly in the syslog format of Log Exporter, a few lines
in its splunk and cef formats, and the lines that are no connection of a rule (updates, a packet out of state, a VPN
event). The rule uids are read from the sample policy. Every address is a documentation or private address.

    python3 tests/tools/make_checkpoint_logs.py
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DATA = Path(__file__).resolve().parents[1] / "data"
START = datetime.datetime(2026, 7, 3, tzinfo=datetime.timezone.utc)
DAYS = 90
SIC = "CN=gw-edge,O=mgmt.example.net.7f3k2q"
ORIGIN = "198.51.100.1"


def rules() -> Tuple[Dict[str, str], Dict[str, str]]:
    """Rule name -> uid, and layer name -> uid, from the sample policy."""
    document = json.loads((DATA / "checkpoint_sample.json").read_text(encoding="utf-8"))
    names: Dict[str, str] = {}
    layers: Dict[str, str] = {}

    def walk(rulebase: List[dict], layer: str) -> None:
        for entry in rulebase:
            if "rulebase" in entry:
                walk(entry["rulebase"], layer)
            elif entry.get("type") == "access-rule":
                names[f"{layer}/{entry.get('name') or entry['rule-number']}"] = entry["uid"]

    for answer in document:
        if answer.get("name") in ("Network", "DMZ-Layer"):
            layers[answer["name"]] = answer["uid"]
            walk(answer["rulebase"], answer["name"])
    return names, layers


UIDS, LAYERS = rules()


def syslog(moment: datetime.datetime, fields: List[Tuple[str, str]]) -> str:
    body = "; ".join(f'{key}:"{value}"' for key, value in fields)
    return f"<134>1 {moment.strftime('%Y-%m-%dT%H:%M:%SZ')} mgmt CheckPoint 2210 - [{body}]"


def base(moment: datetime.datetime, action: str, number: int) -> List[Tuple[str, str]]:
    return [("action", action), ("flags", "411908"), ("ifdir", "inbound"), ("ifname", "eth1"), ("logid", "0"),
            ("loguid", f"{{0x{int(moment.timestamp()):x},0x0,0x{number:x},0xc0000001}}"), ("origin", ORIGIN), ("originsicname", SIC),
            ("sequencenum", str(number)), ("time", str(int(moment.timestamp()))), ("version", "5"),
            ("__policy_id_tag", "product=VPN-1 & FireWall-1[db_tag={0A1B2C3D-0000-4000-8000-000000000001};mgmt=mgmt;"
                                "date=1782000000;policy_name=Standard\\]")]  # fmt: skip


def match(chain: List[Tuple[str, str, int, int, str, Optional[str]]]) -> List[Tuple[str, str]]:
    """The match table, flattened column by column: (layer, uuid, match_id, parent_rule, action, rule uid or None)."""
    out: List[Tuple[str, str]] = []
    for column, index in (("layer_name", 0), ("layer_uuid", 1), ("match_id", 2), ("parent_rule", 3), ("rule_action", 4)):
        out += [(column, str(row[index])) for row in chain]
    out += [("rule_uid", row[5]) for row in chain if row[5]]
    return out


def network(rule: str, number: int, action: str = "Accept") -> List[Tuple[str, str, int, int, str, Optional[str]]]:
    return [("Network", LAYERS["Network"], number, 0, action, UIDS[f"Network/{rule}"])]


def connection(moment: datetime.datetime, number: int, chain: list, src: str, dst: str, proto: int, port: Optional[int],
               action: str = "Accept", extra: Optional[List[Tuple[str, str]]] = None) -> str:  # fmt: skip
    fields = base(moment, action, number) + [("dst", dst)] + match(chain) + [("product", "VPN-1 & FireWall-1"), ("proto", str(proto))]
    if proto in (6, 17):
        fields += [("s_port", str(40000 + number % 20000)), ("service", str(port))]
    elif proto == 1:
        fields += [("icmp", "Echo Request"), ("icmp_code", "0"), ("icmp_type", str(port))]
    fields += [("src", src)] + (extra or [])
    return syslog(moment, fields)


def main() -> None:
    lines: List[str] = []
    number = 0
    inline = ("DMZ-Layer", LAYERS["DMZ-Layer"])
    for day in range(DAYS):
        noon = START + datetime.timedelta(days=day, hours=12)

        def at(minutes: int) -> datetime.datetime:
            return noon + datetime.timedelta(minutes=minutes)

        def add(line: str) -> None:
            nonlocal number
            number += 1
            lines.append(line)

        add(connection(at(1), number, network("DNS", 1), "10.10.4.20", "192.0.2.53", 17, 53))
        add(connection(at(2), number, network("Web out", 3), "10.10.4.21", "203.0.113.200", 6, 443))
        add(connection(at(3), number, network("Cleanup rule", 17, "Drop"), "192.0.2.99", "10.20.0.99", 6, 23, "Drop"))
        if day % 3 == 0:
            add(connection(at(4), number, network("Public web", 13), "192.0.2.80", "203.0.113.10", 6, 443))
            add(connection(at(5), number, network("2", 2), "10.10.5.12", "10.20.0.10", 6, 22))
        if day % 7 == 0:
            web_in = [("Network", LAYERS["Network"], 14, 0, "Inline", UIDS["Network/DMZ access"]),
                      (*inline, 16777217, 14, "Accept", UIDS["DMZ-Layer/Web in"])]  # fmt: skip
            add(connection(at(6), number, web_in, "192.0.2.81", "10.20.0.10", 6, 9005))
            cleanup = [("Network", LAYERS["Network"], 14, 0, "Inline", UIDS["Network/DMZ access"]),
                       (*inline, 16777215 + 16777216, 14, "Drop", None)]  # the implicit cleanup of the inline layer: no uid
            add(connection(at(7), number, cleanup, "192.0.2.82", "10.20.0.30", 6, 8080, "Drop"))
            add(connection(at(8), number, network("Social", 5), "10.10.4.22", "203.0.113.150", 6, 443))
            add(connection(at(9), number, network("Updates", 9), "10.20.0.25", "203.0.113.160", 6, 443))
        if day % 10 == 0:
            add(connection(at(10), number, network("PLC access", 7), "192.0.2.140", "10.30.1.5", 6, 443,
                           extra=[("src_user_name", "Vendor Engineer (vendor1)")]))  # fmt: skip
            add(connection(at(11), number, network("No ident", 16, "Reject"), "192.0.2.77", "10.10.4.20", 6, 113, "Reject"))
        if day % 15 == 0:
            # The same connections in the other two formats of Log Exporter.
            moment = at(12)
            number += 1
            lines.append(
                f"time={int(moment.timestamp())}|hostname=mgmt|product=Firewall|layer_name=Network|layer_uuid={LAYERS['Network']}|"
                f"match_id=3|parent_rule=0|rule_action=Accept|rule_name=Web out|rule_uid={UIDS['Network/Web out']}|action=Accept|"
                f"ifdir=inbound|ifname=eth1|origin={ORIGIN}|originsicname=CN\\=gw-edge,O\\=mgmt.example.net.7f3k2q|sequencenum={number}|"
                f"time={int(moment.timestamp())}|version=5|dst=203.0.113.201|proto=6|s_port=51515|service=80|service_id=http|src=10.10.4.23|"
            )  # fmt: skip
            number += 1
            lines.append(
                f"CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|domain-udp|Unknown|act=Accept rt={int(moment.timestamp()) * 1000 + 1} "
                f"spt=53001 dpt=53 cs2Label=Rule Name cs2=DNS layer_name=Network layer_uuid={LAYERS['Network']} match_id=1 parent_rule=0 "
                f"rule_action=Accept rule_uid={UIDS['Network/DNS']} ifname=eth1 origin={ORIGIN} originsicname=CN\\=gw-edge,O\\=mgmt.example.net.7f3k2q "
                f"dst=192.0.2.53 product=VPN-1 & FireWall-1 proto=17 src=10.10.6.30"
            )  # fmt: skip
        # Lines that are no connection of a rule.
        update = base(at(20), "Accept", number) + [("product", "Log Update"), ("dst", "203.0.113.200"), ("src", "10.10.4.21")]
        add(syslog(at(20), update))
        if day % 5 == 0:
            out_of_state = base(at(21), "Drop", number) + [("dst", "10.10.4.20"), ("product", "VPN-1 & FireWall-1"), ("proto", "6"),
                                                           ("s_port", "443"), ("service", "50122"), ("src", "203.0.113.200"),
                                                           ("tcp_packet_out_of_state", "First packet isn't SYN; tcp_flags: ACK")]  # fmt: skip
            add(syslog(at(21), out_of_state))
            vpn = base(at(22), "Key Install", number) + [("product", "VPN-1 & FireWall-1"), ("proto", "0"), ("service", "0"),
                                                         ("src", "0.0.0.0"), ("dst", "0.0.0.0")]  # fmt: skip
            add(syslog(at(22), vpn))
    path = DATA / "checkpoint_sample.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
