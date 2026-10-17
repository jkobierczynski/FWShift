# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The networks behind the zones from the source (0.35.0): FortiOS, PAN-OS and the ASA tell them by their interfaces
and static routes, and the targets and --compare that need them take them where --zone-network does not give them.

The differential test: a conversion with the networks from the source is the conversion with the same networks given
with --zone-network, byte for byte.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from fwshift import cli, zonenets
from fwshift.netutil import parse_literal
from fwshift.parsers import asa as parse_asa
from fwshift.parsers import fortios as parse_fortios
from fwshift.parsers import panos as parse_panos
from fwshift.options import Options
from fwshift.report import Report

DATA = Path(__file__).parent / "data"


def route(network: str, interface: str = "", gateway: str = "", distance: int = 10, metric: int = 0, connected: bool = False,
          nowhere: str = "") -> zonenets.Route:  # fmt: skip
    found = parse_literal(network)
    assert found is not None
    return zonenets.Route(found, interface, parse_literal(gateway) if gateway else None, (distance, metric), connected, nowhere)


def codes(report: Report) -> List[str]:
    return [note.code for note in report.notes]


def test_a_network_goes_to_the_zone_of_its_interface_and_the_preferred_route_wins() -> None:
    routes = [
        route("10.10.0.0/16", "port2", connected=True), route("198.51.100.0/24", "port1", connected=True),
        route("0.0.0.0/0", gateway="198.51.100.254"),  # (by its next hop: port1)
        route("10.40.0.0/16", "port2", distance=10), route("10.40.0.0/16", "port1", distance=20),  # (a floating route)
        route("10.50.0.0/16", "port2"), route("10.50.0.0/16", "port1"),  # (equal-cost: in no zone)
        route("192.168.1.0/24", "mgmt", connected=True),  # (an interface in no zone of the policy)
    ]  # fmt: skip
    report = Report()
    placed = zonenets.place(routes, {"port1": "wan", "port2": "lan"}, report)
    assert placed.zones == {"lan": ["10.10.0.0/16", "10.40.0.0/16"], "wan": ["0.0.0.0/0", "198.51.100.0/24"]}
    assert placed.unzoned == ["10.50.0.0/16", "192.168.1.0/24"]  # (behind no zone: not the default route's either)
    conflict = next(n for n in report.notes if n.code == "ZONE_NETWORKS_CONFLICT")
    assert "10.50.0.0/16 (lan, wan)" in conflict.message
    assert "mgmt=192.168.1.0/24" in next(n for n in report.notes if n.code == "ZONE_NETWORKS").message


def test_routes_that_drop_lead_elsewhere_or_nowhere_are_behind_no_zone_and_next_hops_recurse() -> None:
    routes = [
        route("10.10.0.0/24", "port2", connected=True), route("0.0.0.0/0", "port1"),
        route("10.40.0.0/16", gateway="10.10.0.254"), route("10.60.0.0/16", gateway="10.40.0.1"),  # (recursive: port2)
        route("10.70.0.0/16", gateway="192.0.2.99"),  # (a next hop in no network: by the default route, port1)
        route("172.16.0.0/12", nowhere="a blackhole route"),
    ]  # fmt: skip
    placed = zonenets.place(routes, {"port1": "wan", "port2": "lan"}, Report())
    assert placed.zones == {"lan": ["10.10.0.0/24", "10.40.0.0/16", "10.60.0.0/16"], "wan": ["0.0.0.0/0", "10.70.0.0/16"]}
    assert placed.unzoned == ["172.16.0.0/12"]
    report = Report()
    placed = zonenets.place([route("10.10.0.0/24", "port2", connected=True), route("10.80.0.0/16", gateway="10.99.0.1")],
                            {"port2": "lan"}, report)  # fmt: skip
    assert placed.unzoned == ["10.80.0.0/16"] and "its next hop leads nowhere known" in report.notes[0].message


def test_with_routing_protocols_the_default_route_is_not_everything_else() -> None:
    report = Report()
    placed = zonenets.place([route("10.10.0.0/24", "port2", connected=True), route("0.0.0.0/0", "port1"), route("10.40.0.0/16", "port2")],
                            {"port1": "wan", "port2": "lan"}, report, partial="routing protocols are configured (ospf)")  # fmt: skip
    assert placed.zones == {"lan": ["10.10.0.0/24", "10.40.0.0/16"]}
    assert "ZONE_NETWORKS_PARTIAL" in codes(report)


def test_networks_behind_no_zone_are_in_no_zone_space_and_not_the_default_one() -> None:
    from fwshift.emitters.asa import zone_spaces

    spaces = zone_spaces({"outside": ["0.0.0.0/0"], "inside": ["10.10.0.0/16"]}, ["192.168.1.0/24", "10.10.5.0/24"])
    assert parse_literal("192.168.1.0/24") not in spaces["outside"] and spaces["inside"] == [
        parse_literal("10.10.0.0-10.10.4.255"), parse_literal("10.10.6.0-10.10.255.255")]  # fmt: skip


def test_a_connected_network_beats_a_route_to_it_by_another_zone() -> None:
    placed = zonenets.place([route("10.10.0.0/24", "a", connected=True), route("10.10.0.0/24", "b", distance=1)], {"a": "A", "b": "B"}, Report())
    assert placed.zones == {"A": ["10.10.0.0/24"]} and placed.unzoned == []


def test_for_target_renames_merges_and_gives_way_to_what_was_given() -> None:
    source = {"trust": ["10.10.0.0/16"], "guest": ["10.30.0.0/24"], "dmz": ["10.20.0.0/24"], "untrust": ["0.0.0.0/0", "::/0"]}
    given = {"internal": ["10.0.0.0/8"], "web": ["10.20.0.0/24"]}
    report = Report()
    out, apart = zonenets.for_target(source, ["192.168.1.0/24"], {"trust": "internal", "guest": "internal", "untrust": "outside"}, given, report)
    assert out == {"internal": ["10.0.0.0/8"], "web": ["10.20.0.0/24"], "outside": ["0.0.0.0/0", "::/0"]}
    assert apart == ["192.168.1.0/24"]
    note = next(n for n in report.notes if n.code == "ZONE_NETWORKS_FROM_SOURCE")
    assert "outside=0.0.0.0/0,::/0" in note.message and "10.20.0.0/24 (dmz)" in note.message  # (given to web: left out)
    assert "ZONE_NETWORKS_ONE_VERSION" not in codes(report)
    # A zone given other networks: what of the source's they do not hold is behind no zone, not the default route's.
    out, apart = zonenets.for_target({"dmz": ["10.20.0.0/24"], "out": ["0.0.0.0/0"]}, [], {}, {"dmz": ["10.20.0.0/25"]}, Report())
    assert out == {"dmz": ["10.20.0.0/25"], "out": ["0.0.0.0/0"]} and apart == ["10.20.0.0/24"]
    report = Report()
    assert zonenets.for_target({"a": ["10.0.0.0/8"]}, [], {}, {}, report, {4, 6})[0] == {"a": ["10.0.0.0/8"]}
    assert "ZONE_NETWORKS_ONE_VERSION" in codes(report)
    report = Report()
    zonenets.for_target({"a": ["10.0.0.0/8"]}, [], {}, {}, report, {4})
    assert "ZONE_NETWORKS_ONE_VERSION" not in codes(report)  # (the policy has no IPv6 addresses)


FORTIOS = """\
config global
config system interface
    edit "port1"
        set vdom "root"
        set ip 198.51.100.2 255.255.255.0
        config ipv6
            set ip6-address 2001:db8:100::2/64
        end
    next
    edit "port2"
        set vdom "root"
        set ip 10.10.0.1 255.255.0.0
    next
    edit "port3"
        set vdom "root"
        set ip 10.11.0.1/16
    next
    edit "port9"
        set vdom "other"
        set ip 10.99.0.1 255.255.0.0
    next
end
end
config vdom
edit root
config system zone
    edit "lan"
        set interface "port2" "port3"
    next
end
config router static
    edit 1
        set gateway 198.51.100.1
        set device "port1"
    next
    edit 2
        set dst 10.40.0.0 255.255.0.0
        set gateway 10.10.0.254
        set device "port2"
    next
    edit 3
        set dst 10.66.0.0 255.255.0.0
        set blackhole enable
    next
    edit 4
        set dst 10.77.0.0 255.255.0.0
        set status disable
        set device "port1"
    next
    edit 5
        set sdwan-zone "virtual-wan-link"
    next
end
config router static6
    edit 1
        set device "port1"
        set gateway 2001:db8:100::1
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
next
edit other
end
"""


def test_fortios_interfaces_of_its_vdom_zones_and_static_routes() -> None:
    report = Report()
    p = parse_fortios.parse(FORTIOS.encode(), report, vdom="root")
    # (route 5, by SD-WAN at the same distance as route 1, makes the default route ambiguous: behind no zone)
    assert p.zone_networks == {"lan": ["10.10.0.0/16", "10.11.0.0/16", "10.40.0.0/16"],
                               "port1": ["198.51.100.0/24", "::/0", "2001:db8:100::/64"]}  # fmt: skip
    assert p.unzoned_networks == ["0.0.0.0/0", "10.66.0.0/16"]  # (and the blackhole; port9 is of another VDOM)
    assert "0.0.0.0/0 (port1, virtual-wan-link)" in next(n for n in report.notes if n.code == "ZONE_NETWORKS_CONFLICT").message
    floating = FORTIOS.replace('set sdwan-zone "virtual-wan-link"', 'set sdwan-zone "virtual-wan-link"\n        set distance 20')
    assert parse_fortios.parse(floating.encode(), Report(), vdom="root").zone_networks["port1"][0] == "0.0.0.0/0"


SECONDARY = """\
        set ip 10.10.0.1 255.255.0.0
        config secondaryip
            edit 1
                set ip 10.12.0.1 255.255.255.0
            next
        end
    next
    edit "port4"
        set vdom "root"
        set status down
        set ip 10.13.0.1 255.255.255.0
    next"""
POOL = """\
config firewall address
    edit "pool"
        set type iprange
        set start-ip 10.212.134.200
        set end-ip 10.212.134.210
    next
end
config vpn ssl settings
    set tunnel-ip-pools "pool"
end
config router static
"""


def test_fortios_secondary_addresses_vpn_pools_and_interfaces_that_are_down() -> None:
    text = FORTIOS.replace("        set ip 10.10.0.1 255.255.0.0\n    next", SECONDARY).replace("config router static\n", POOL, 1)
    p = parse_fortios.parse(text.encode(), Report(), vdom="root")
    assert "10.12.0.0/24" in p.zone_networks["lan"]
    # (down; and the pool, as the networks it is made of: no rule names ssl.root)
    assert {"10.13.0.0/24", "10.212.134.200/29", "10.212.134.208/31", "10.212.134.210"} <= set(p.unzoned_networks)


PANOS = """\
<config><devices><entry name="localhost.localdomain"><network>
<interface><ethernet>
<entry name="ethernet1/1"><layer3><ip><entry name="198.51.100.2/24"/></ip><ipv6><address><entry name="2001:db8:100::2/64"/></address></ipv6></layer3></entry>
<entry name="ethernet1/2"><layer3><ip><entry name="gw-lan"/></ip><units><entry name="ethernet1/2.20"><ip><entry name="10.20.0.1/24"/></ip></entry></units></layer3></entry>
<entry name="ethernet1/3"><layer3><dhcp-client/></layer3></entry>
</ethernet><loopback><units><entry name="loopback.1"><ip><entry name="10.255.0.1/32"/></ip></entry></units></loopback></interface>
<virtual-router><entry name="default"><routing-table><ip><static-route>
<entry name="def"><destination>0.0.0.0/0</destination><nexthop><ip-address>198.51.100.1</ip-address></nexthop></entry>
<entry name="branch"><destination>branch-net</destination><interface>ethernet1/2</interface><nexthop><ip-address>10.10.0.254</ip-address></nexthop></entry>
<entry name="sink"><destination>10.66.0.0/16</destination><nexthop><discard/></nexthop></entry>
</static-route></ip><ipv6><static-route><entry name="def6"><destination>::/0</destination><interface>ethernet1/1</interface><nexthop><ipv6-address>2001:db8:100::1</ipv6-address></nexthop></entry></static-route></ipv6></routing-table>
<protocol><bgp><enable>yes</enable></bgp></protocol></entry></virtual-router>
<logical-router><entry name="lr"><vrf><entry name="default"><routing-table><ip><static-route>
<entry name="dmz-far"><destination>10.21.0.0/16</destination><interface>ethernet1/2.20</interface></entry></static-route></ip></routing-table></entry></vrf></entry></logical-router>
</network><vsys><entry name="vsys1">
<zone><entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
<entry name="trust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
<entry name="dmz"><network><layer3><member>ethernet1/2.20</member></layer3></network></entry>
<entry name="dyn"><network><layer3><member>ethernet1/3</member></layer3></network></entry></zone>
<address><entry name="gw-lan"><ip-netmask>10.10.0.1/16</ip-netmask></entry><entry name="branch-net"><ip-netmask>10.40.0.0/16</ip-netmask></entry></address>
<rulebase><security><rules><entry name="r"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source>
<destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>allow</action></entry>
</rules></security></rulebase></entry></vsys></entry></devices></config>
"""


def test_panos_interfaces_units_address_objects_virtual_and_logical_routers() -> None:
    report = Report()
    p = parse_panos.parse(PANOS.encode(), report)
    # (BGP is on: the default routes are not taken as everything else)
    assert p.zone_networks == {"dmz": ["10.20.0.0/24", "10.21.0.0/16"], "trust": ["10.10.0.0/16", "10.40.0.0/16"],
                               "untrust": ["198.51.100.0/24", "2001:db8:100::/64"]}  # fmt: skip
    assert p.unzoned_networks == ["10.66.0.0/16", "10.255.0.1"]  # (a route that discards; a loopback in no zone)
    assert "ZONE_NETWORKS_PARTIAL" in codes(report)
    p = parse_panos.parse(PANOS.replace("<enable>yes</enable>", "<enable>no</enable>").encode(), Report())
    assert p.zone_networks["untrust"] == ["0.0.0.0/0", "198.51.100.0/24", "::/0", "2001:db8:100::/64"]
    assert "ethernet1/3 takes its address from DHCP" in next(n for n in report.notes if n.code == "ZONE_ROUTES_NOT_READ").message


def test_panos_set_format_gives_the_same_networks() -> None:
    from test_panos_set import printed

    assert parse_panos.parse(printed(PANOS.encode()).encode(), Report()).zone_networks == parse_panos.parse(PANOS.encode(), Report()).zone_networks


def test_asa_interfaces_routes_and_what_is_no_zone() -> None:
    report = Report()
    p = parse_asa.parse((DATA / "asa_sample.cfg").read_bytes(), report)
    assert p.zone_networks == {"dmz": ["10.20.0.0/24"], "guest": ["10.30.0.0/24"],
                               "inside": ["10.10.0.0/16", "10.40.0.0/16", "2001:db8:10::/64"],
                               "outside": ["0.0.0.0/0", "203.0.113.0/24"]}  # fmt: skip
    assert "mgmt=192.168.1.0/24" in next(n for n in report.notes if n.code == "ZONE_NETWORKS").message
    text = (DATA / "asa_sample.cfg").read_text() + "route inside 10.40.0.0 255.255.0.0 10.10.0.253 1\nroute dmz 10.40.0.0 255.255.0.0 10.20.0.254 1\nroute Null0 10.66.0.0 255.255.0.0\n"
    report = Report()
    p = parse_asa.parse(text.encode(), report)
    assert "10.40.0.0/16" not in p.zone_networks["inside"] and "ZONE_NETWORKS_CONFLICT" in codes(report)


def write_networks(networks: Dict[str, List[str]]) -> List[str]:
    out: List[str] = []
    for zone, listed in networks.items():
        out += ["--zone-network", f"{zone}={','.join(listed)}"]
    return out


@pytest.mark.parametrize("sample", ["fortios_sample.conf", "asa_sample.cfg"])
@pytest.mark.parametrize("target", ["asa", "pfsense", "aws", "azure", "nsx", "gcp", "meraki", "barracuda", "sonicwall"])
def test_networks_from_the_source_are_the_networks_given(sample: str, target: str, tmp_path: Path) -> None:
    """The differential: with the networks of the source, the output is the output with them given (and the networks
    behind no zone given as such)."""
    data = (DATA / sample).read_bytes()
    policy = cli.load(data, cli.detect_format(data), Report())
    assert policy.zone_networks
    auto = tmp_path / "auto"
    assert cli.main(["convert", str(DATA / sample), "--to", target, "-o", str(auto), "-q"]) == 0
    options = Options(zone_networks={z: list(n) for z, n in policy.zone_networks.items()}, zone_excluded=list(policy.unzoned_networks))
    given = cli.convert(cli.load(data, cli.detect_format(data), Report()), target, Report(), options)
    assert auto.read_text(encoding="utf-8") == given
    if not policy.unzoned_networks:
        plain = tmp_path / "plain"
        assert cli.main(["convert", str(DATA / sample), "--to", target, "-o", str(plain), "-q", "--no-source-networks"]
                        + write_networks(policy.zone_networks)) == 0  # fmt: skip
        assert plain.read_bytes() == auto.read_bytes()


def test_no_source_networks_and_targets_that_need_none(tmp_path: Path) -> None:
    out, report = tmp_path / "out", tmp_path / "report.json"
    cli.main(["convert", str(DATA / "fortios_sample.conf"), "--to", "asa", "-o", str(out), "-q", "--no-source-networks", "--report-json", str(report)])
    assert "ZONE_NETWORKS_FROM_SOURCE" not in report.read_text()
    cli.main(["convert", str(DATA / "fortios_sample.conf"), "--to", "panos", "-o", str(out), "-q", "--report-json", str(report)])
    assert "ZONE_NETWORKS_FROM_SOURCE" not in report.read_text() and "ZONE_NETWORKS" in report.read_text()


def test_convert_compare_to_asa_needs_no_networks_given_where_the_source_tells(tmp_path: Path) -> None:
    out, report = tmp_path / "out", tmp_path / "report.json"
    cli.main(["convert", str(DATA / "asa_sample.cfg"), "--to", "asa", "-o", str(out), "-q", "--compare", "--report-json", str(report)])
    found = [n["code"] for n in json.loads(report.read_text())["notes"]]
    assert "COMPARE_NOT_READ_BACK" not in found and any(code.startswith("COMPARE_") for code in found)


def test_fwshift_compare_takes_the_networks_of_the_first(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["compare", str(DATA / "asa_sample.cfg"), str(DATA / "asa_sample.cfg"), "--fail-on", "none"])
    text = capsys.readouterr().out
    assert "taken from the configuration" in text
    cli.main(["compare", str(DATA / "asa_sample.cfg"), str(DATA / "asa_sample.cfg"), "--fail-on", "none", "--no-source-networks"])
    assert "taken from the configuration" not in capsys.readouterr().out


def _oracle(routes: List[zonenets.Route], zone_of: Dict[str, str], address: Tuple[int, int], dynamic: bool, depth: int = 0) -> str:
    """Where a firewall sends an address, by its routes: the longest prefix, then the best route to it (connected, then
    distance, metric); the zone of its interface, or '' (behind no zone: a route that drops, an interface in no zone,
    routes alike by different zones, a next hop that leads nowhere). Written apart from zonenets, as the judge."""
    version, value = address
    if depth > 8:
        return ""
    holding = [r for r in routes if r.network[0] == version and r.network[1] <= value <= r.network[2]
               and not (dynamic and not r.connected and r.network[1:] in ((0, 2**32 - 1), (0, 2**128 - 1)) and not r.nowhere)]  # fmt: skip
    if not holding:
        return "?"  # (in none of the networks)
    longest = max(r.network[1] - r.network[2] for r in holding)
    top = [r for r in holding if r.network[1] - r.network[2] == longest]
    rank = min((0 if r.connected else 1, *r.preference) for r in top)
    winners = [r for r in top if (0 if r.connected else 1, *r.preference) == rank]
    zones = set()
    for r in winners:
        if r.nowhere:
            zones.add("")
        elif r.interface:
            zones.add(zone_of.get(r.interface, ""))
        else:
            assert r.gateway is not None
            others = [x for x in routes if x is not r and x.network != r.network]
            via = _oracle(others, zone_of, (r.gateway[0], r.gateway[1]), dynamic, depth + 1)
            zones.add("" if via == "?" else via)
    return zones.pop() if len(zones) == 1 else ""


@pytest.mark.parametrize("seed", range(150))
def test_place_agrees_with_routing_each_address(seed: int) -> None:
    """Random routing tables (interfaces in zones and in none, static routes by interface and by next hop, floating
    routes, routes that drop, equal-cost routes): for sample addresses, the zone whose networks hold it (zone_spaces of
    what place found, with the networks behind no zone) is the zone the firewall sends it to."""
    import random

    from fwshift.emitters.asa import zone_spaces

    rng = random.Random(seed)
    interfaces = [f"if{i}" for i in range(5)]
    zone_of = {name: rng.choice(["a", "b", "c"]) for name in interfaces[:4]}  # (if4: in no zone)
    routes: List[zonenets.Route] = []
    for name in interfaces:
        base = rng.randrange(0, 255)
        routes.append(route(f"10.{base}.0.0/{rng.choice([16, 20, 24])}", name, connected=True))
    for _ in range(rng.randint(0, 8)):
        length = rng.choice([0, 8, 12, 16, 20, 24, 28])
        net = f"10.{rng.randrange(0, 255)}.{rng.randrange(0, 255)}.0/{length}" if length else "0.0.0.0/0"
        kind = rng.random()
        if kind < 0.1:
            routes.append(route(net, nowhere="a blackhole route", distance=rng.choice([10, 254])))
        elif kind < 0.2:  # (an address pool: a range, behind a tunnel interface)
            first = rng.randrange(10 << 24, 11 << 24)
            pool = f"{ipaddress.ip_address(first)}-{ipaddress.ip_address(first + rng.randrange(1, 600))}"
            routes.append(route(pool, rng.choice(interfaces), connected=True))
        elif kind < 0.5:
            hop = routes[rng.randrange(len(routes))].network
            routes.append(route(net, gateway=str(ipaddress.ip_address(hop[1] + 1)), distance=rng.choice([5, 10, 20])))
        else:
            routes.append(route(net, rng.choice(interfaces), distance=rng.choice([5, 10, 20])))
    dynamic = rng.random() < 0.2
    placed = zonenets.place(routes, zone_of, Report(), partial="ospf" if dynamic else "")
    spaces = zone_spaces(placed.zones, placed.unzoned)
    covered = [i for space in spaces.values() for i in space]
    for _ in range(300):
        r = routes[rng.randrange(len(routes))]
        value = rng.randint(r.network[1], r.network[2]) if rng.random() < 0.8 else rng.randrange(2**32)
        expected = _oracle(routes, zone_of, (4, value), dynamic)
        found = [zone for zone, space in spaces.items() if any(i[0] == 4 and i[1] <= value <= i[2] for i in space)]
        unplaced = not any(i[1] <= value <= i[2] for i in covered)
        held = [i for i in map(parse_literal, placed.unzoned) if i and i[1] <= value <= i[2]]
        if expected == "?":
            assert not found, (value, found)
        elif expected == "":
            assert not found and unplaced and held, (ipaddress.ip_address(value), found, routes)
        else:
            assert found == [expected], (ipaddress.ip_address(value), expected, found, routes)


def test_asa_tunneled_routes_and_transparent_mode_take_no_default() -> None:
    text = (DATA / "asa_sample.cfg").read_text().replace("route outside 0.0.0.0 0.0.0.0 203.0.113.1 1",
                                                          "route outside 0.0.0.0 0.0.0.0 203.0.113.1 5\nroute inside 0 0 10.10.0.254 tunneled")  # fmt: skip
    report = Report()
    p = parse_asa.parse(text.encode(), report)
    assert "0.0.0.0/0" in p.zone_networks["outside"] and "0.0.0.0/0" not in p.zone_networks["inside"]
    assert "tunneled" in next(n for n in report.notes if n.code == "ZONE_ROUTES_NOT_READ").message


def test_fortios_internet_service_routes_dialup_subnets_and_pools_across_networks() -> None:
    text = FORTIOS.replace("config router static\n", """config router static
    edit 7
        set internet-service 65646
        set device "port3"
        set distance 5
    next
""", 1).replace("config router static6\n", """config vpn ipsec phase1-interface
    edit "dialup"
        set type dynamic
        set interface "port1"
    next
end
config vpn ipsec phase2-interface
    edit "dialup-p2"
        set phase1name "dialup"
        set dst-subnet 10.99.0.0 255.255.0.0
    next
end
config firewall address
    edit "wide-pool"
        set type iprange
        set start-ip 10.10.255.200
        set end-ip 10.11.0.20
    next
end
config vpn ssl settings
    set tunnel-ip-pools "wide-pool"
end
config router static6
""", 1)
    report = Report()
    p = parse_fortios.parse(text.encode(), report, vdom="root")  # (a pool across two networks: no error)
    assert all("0.0.0.0/0" not in nets for zone, nets in p.zone_networks.items() if zone == "lan")
    assert "10.99.0.0/16" in p.unzoned_networks  # (behind the dial-up tunnel, which no rule names)
    assert "internet service" in next(n for n in report.notes if n.code == "ZONE_ROUTES_NOT_READ").message
    for target in ("asa", "nsx", "pfsense", "aws"):
        cli.convert(p, target, Report(), Options(zone_networks=dict(p.zone_networks), zone_excluded=list(p.unzoned_networks)))


PANOS_VRS = PANOS.replace("<virtual-router><entry name=\"default\">", """<virtual-router><entry name="vr2"><interface><member>ethernet1/9</member></interface><routing-table><ip><static-route>
<entry name="other"><destination>10.10.0.0/16</destination><interface>ethernet1/9</interface></entry></static-route></ip></routing-table></entry>
<entry name="default"><interface><member>ethernet1/1</member><member>ethernet1/2</member><member>ethernet1/2.20</member></interface>""").replace(
    "<entry name=\"ethernet1/3\">", "<entry name=\"ethernet1/9\"><layer3><ip><entry name=\"10.10.0.1/16\"/></ip></layer3></entry><entry name=\"ethernet1/3\">")


def test_panos_routers_of_another_virtual_system_take_no_part() -> None:
    report = Report()
    p = parse_panos.parse(PANOS_VRS.encode(), report)
    assert "10.10.0.0/16" in p.zone_networks["trust"] and "ZONE_NETWORKS_CONFLICT" not in codes(report)


def test_panos_zones_without_layer3_interfaces_take_no_default() -> None:
    text = PANOS.replace("<enable>yes</enable>", "<enable>no</enable>").replace(
        '<entry name="dyn"><network><layer3><member>ethernet1/3</member></layer3></network></entry>',
        '<entry name="dyn"><network><virtual-wire><member>ethernet1/3</member></virtual-wire></network></entry>')
    report = Report()
    p = parse_panos.parse(text.encode(), report)
    assert "0.0.0.0/0" not in p.zone_networks["untrust"]
    assert "zones without layer-3 interfaces (dyn)" in next(n for n in report.notes if n.code == "ZONE_NETWORKS_PARTIAL").message


def test_an_allow_for_any_zone_does_not_reach_the_networks_behind_no_zone(tmp_path: Path) -> None:
    """ASA source: inside to any (DNS) written for NSX: the management network, which the ASA forwards nothing to, is
    not in its destination; a deny for any zone keeps it."""
    out = tmp_path / "nsx.json"
    assert cli.main(["convert", str(DATA / "asa_sample.cfg"), "--to", "nsx", "-o", str(out), "-q"]) == 0
    rules = {r["id"]: r for policy in json.loads(out.read_text())["children"] for r in _nsx_rules(policy)}
    dns = rules["inside_access_in-1"]
    assert dns["action"] == "ALLOW" and dns["destination_groups"] != ["ANY"]
    group = next(g for g in _nsx_groups(json.loads(out.read_text())) if g["id"].startswith("FWSHIFT-ROUTED"))
    assert "192.168.1.0/24" not in json.dumps(group) and "192.168.0.255" in json.dumps(group)


def _nsx_rules(node: object) -> List[Dict[str, object]]:
    found: List[Dict[str, object]] = []
    if isinstance(node, dict):
        if node.get("resource_type") == "Rule":
            found.append(node)
        for value in node.values():
            found += _nsx_rules(value)
    elif isinstance(node, list):
        for value in node:
            found += _nsx_rules(value)
    return found


def _nsx_groups(node: object) -> List[Dict[str, object]]:
    found: List[Dict[str, object]] = []
    if isinstance(node, dict):
        if node.get("resource_type") == "Group":
            found.append(node)
        for value in node.values():
            found += _nsx_groups(value)
    elif isinstance(node, list):
        for value in node:
            found += _nsx_groups(value)
    return found
