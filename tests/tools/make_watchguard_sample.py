# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/watchguard_sample.xml: a made-up Policy Manager configuration file.

Every address is a documentation or private address. The elements are those of the format as the
parser reads them (see DEVELOPMENT.md).

    python3 tests/tools/make_watchguard_sample.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Tuple
from xml.sax.saxutils import escape

BUILTIN_ALIASES = [("Any", "Any", "Any"), ("Any-External", "Any", "Any-External"), ("Any-Trusted", "Any", "Any-Trusted"),
                   ("Any-Optional", "Any", "Any-Optional"), ("Firebox", "Firebox", "Firebox")]  # fmt: skip


def e(tag: str, text: str) -> str:
    return f"<{tag}>{escape(text)}</{tag}>"


def interface(name: str, kind: str, ip: str = "", mask: str = "") -> str:
    addr = e("ip", ip) + e("netmask", mask) if ip else ""
    return (f"<interface>{e('name', name)}<property>0</property><if-item-list><item><item-type>1</item-type><physical-if>"
            f"{e('if-property', kind)}{addr}</physical-if></item></if-item-list></interface>")  # fmt: skip


def address_group(name: str, *members: Tuple[str, ...], prop: str = "0") -> str:
    body = ""
    for member in members:
        kind = member[0]
        if kind == "host":
            body += f"<member><type>1</type>{e('host-ip-addr', member[1])}</member>"
        elif kind == "net":
            body += f"<member><type>2</type>{e('ip-network-addr', member[1])}{e('ip-mask', member[2])}</member>"
        elif kind == "range":
            body += f"<member><type>3</type>{e('start-ip-addr', member[1])}{e('end-ip-addr', member[2])}</member>"
        else:
            body += f"<member><type>8</type>{e('domain', member[1])}</member>"
    return f"<address-group>{e('name', name)}<description/><property>{prop}</property><addr-group-member>{body}</addr-group-member></address-group>"


def alias(name: str, members: Sequence[Tuple[str, ...]], prop: str = "0") -> str:
    """Members: ("ref", alias) or ("tuple", address, interface[, user])."""
    body = ""
    for member in members:
        if member[0] == "ref":
            body += f"<alias-member><type>2</type>{e('alias-name', member[1])}</alias-member>"
        else:
            user = member[3] if len(member) > 3 else "Any"
            body += f"<alias-member><type>1</type>{e('user', user)}{e('address', member[1])}{e('interface', member[2])}</alias-member>"
    return f"<alias>{e('name', name)}<description/><property>{prop}</property><alias-member-list>{body}</alias-member-list></alias>"


def service(name: str, *members: Tuple[int, ...]) -> str:
    """Members: (protocol, port) or (protocol, low, high) or (1, "icmp", type, code)."""
    body = ""
    for member in members:
        if len(member) == 4:
            body += f"<member><type>1</type><protocol>{member[0]}</protocol><icmp-type>{member[2]}</icmp-type><icmp-code>{member[3]}</icmp-code></member>"
        elif len(member) == 3:
            body += (f"<member><type>2</type><protocol>{member[0]}</protocol><start-server-port>{member[1]}</start-server-port>"
                     f"<end-server-port>{member[2]}</end-server-port></member>")  # fmt: skip
        else:
            body += f"<member><type>1</type><protocol>{member[0]}</protocol><server-port>{member[1]}</server-port></member>"
    return f"<service>{e('name', name)}<description/><property>0</property><proxy-type/><service-item>{body}</service-item></service>"


def snat(name: str, external: str, internal: str, port: int = 0, interface_name: str = "Any-External") -> str:
    return (f"<nat>{e('name', name)}<property>0</property><type>7</type><nat-item><member><addr-type>4</addr-type><port>{port}</port>"
            f"{e('ext-addr-name', external)}{e('interface', interface_name)}{e('addr-name', internal)}</member></nat-item></nat>")  # fmt: skip


def policy(name: str, service_name: str, sources: Sequence[str], targets: Sequence[str], action: str = "Allow", enabled: bool = True,
           schedule: str = "Always On", proxy: str = "") -> Tuple[str, str]:  # fmt: skip
    froms = "".join(e("alias", a) for a in sources)
    tos = "".join(e("alias", a) for a in targets)
    abs_policy = (f"<abs-policy>{e('name', name)}<property>0</property>{e('service', service_name)}<description/><type>Firewall</type>"
                  f"<enabled>{'true' if enabled else 'false'}</enabled>{e('firewall', action)}<reject-action>TCP_RST</reject-action>"
                  f"<from-alias-list>{froms}</from-alias-list><to-alias-list>{tos}</to-alias-list>"
                  f"<settings>{e('proxy', proxy) if proxy else '<proxy/>'}{e('schedule', schedule)}<log-enabled>true</log-enabled></settings>"
                  f"<policy-list>{e('policy', name + '-00')}</policy-list></abs-policy>")  # fmt: skip
    number = {"Allow": "1", "Proxy": "4"}.get(action, "2")
    concrete = (f"<policy>{e('name', name + '-00')}{e('service', service_name)}<firewall>{number}</firewall><enable>{'1' if enabled else '0'}</enable>"
                f"<from-alias-list>{froms}</from-alias-list><to-alias-list>{tos}</to-alias-list></policy>")  # fmt: skip
    return abs_policy, concrete


def profile(interfaces: Sequence[str], groups: Sequence[str], aliases: Sequence[str], services: Sequence[str], nats: Sequence[str],
            policies: Sequence[Tuple[str, str]], auto_order: str = "0") -> str:  # fmt: skip
    builtin = [alias(name, [("tuple", address, iface)], "4") for name, address, iface in BUILTIN_ALIASES]
    return "\n".join([
        '<?xml version="1.0" encoding="UTF-8"?>', "<profile>", " <for-version>12.10.4</for-version>",
        " <address-group-list>", *groups, " </address-group-list>",
        " <service-list>", *services, " </service-list>",
        " <nat-list>", *nats, " </nat-list>",
        " <alias-list>", *builtin, *aliases, " </alias-list>",
        " <interface-list>", *interfaces, " </interface-list>",
        " <abs-policy-list>", *(p[0] for p in policies), " </abs-policy-list>",
        " <policy-list>", *(p[1] for p in policies), " </policy-list>",
        f" <system-parameters><misc-global-setting><auto-order-enabled>{auto_order}</auto-order-enabled></misc-global-setting></system-parameters>",
        "</profile>",
    ]) + "\n"  # fmt: skip


def sample() -> str:
    interfaces = [interface("External", "2", "198.51.100.2", "255.255.255.0"), interface("Trusted", "1", "10.10.0.1", "255.255.0.0"),
                  interface("DMZ", "3", "10.20.0.1", "255.255.255.0"), interface("Guests", "1", "10.30.0.1", "255.255.255.0"),
                  interface("Lab", "8", "10.40.0.1", "255.255.255.0")]  # fmt: skip
    groups = [
        address_group("Web-Server.1.alm", ("host", "10.20.0.10"), prop="16"),
        address_group("Mail-Server.1.alm", ("host", "10.20.0.25"), prop="16"),
        address_group("Admins.1.alm", ("range", "10.10.5.10", "10.10.5.20"), prop="16"),
        address_group("Bad-Nets.1.alm", ("net", "203.0.113.0", "255.255.255.128"), prop="16"),
        address_group("Bad-Nets.2.alm", ("host", "192.0.2.66"), prop="16"),
        address_group("Update-Site.1.alm", ("fqdn", "updates.example.com"), prop="16"),
        address_group("Web-Public.1.snat", ("host", "198.51.100.10"), prop="16"),
        address_group("Web-Public.2.snat", ("host", "10.20.0.10"), prop="16"),
        address_group("Mail-Public.1.snat", ("host", "198.51.100.11"), prop="16"),
        address_group("Mail-Public.2.snat", ("host", "10.20.0.25"), prop="16"),
    ]
    aliases = [
        alias("Web-Server", [("tuple", "Web-Server.1.alm", "Any")]),
        alias("Mail-Server", [("tuple", "Mail-Server.1.alm", "Any")]),
        alias("Admins", [("tuple", "Admins.1.alm", "Trusted")]),
        alias("Bad-Nets", [("tuple", "Bad-Nets.1.alm", "Any"), ("tuple", "Bad-Nets.2.alm", "Any")]),
        alias("Update-Site", [("tuple", "Update-Site.1.alm", "Any")]),
        alias("Web-Public.snat", [("tuple", "Web-Public.1.snat", "Any-External")], "32"),
        alias("Mail-Public.snat", [("tuple", "Mail-Public.1.snat", "Any-External")], "32"),
        alias("Block Bad.1.from", [("ref", "Any-Trusted")], "16"), alias("Block Bad.1.to", [("ref", "Bad-Nets")], "16"),
        alias("Admin SSH.1.from", [("ref", "Admins")], "16"), alias("Admin SSH.1.to", [("ref", "Any-External")], "16"),
        alias("Web Out.1.from", [("ref", "Any-Trusted"), ("ref", "Any-Optional")], "16"), alias("Web Out.1.to", [("ref", "Any-External")], "16"),
        alias("Web In.1.from", [("ref", "Any-External")], "16"), alias("Web In.1.to", [("ref", "Web-Public.snat")], "16"),
        alias("Mail In.1.from", [("ref", "Any-External")], "16"), alias("Mail In.1.to", [("ref", "Mail-Public.snat")], "16"),
        alias("DMZ Updates.1.from", [("tuple", "Any", "DMZ")], "16"), alias("DMZ Updates.1.to", [("ref", "Update-Site")], "16"),
        alias("Guests Out.1.from", [("tuple", "Any", "Guests")], "16"), alias("Guests Out.1.to", [("ref", "Any-External")], "16"),
        alias("Staff Only.1.from", [("tuple", "Any", "Trusted", "Staff")], "16"), alias("Staff Only.1.to", [("ref", "Web-Server")], "16"),
        alias("Ping.1.from", [("ref", "Any-Trusted")], "16"), alias("Ping.1.to", [("ref", "Any")], "16"),
        alias("Lab Tunnel.1.from", [("tuple", "Any", "Lab")], "16"), alias("Lab Tunnel.1.to", [("ref", "Any-External")], "16"),
    ]  # fmt: skip
    services = [
        service("Block Bad", (0, 0)), service("SSH", (6, 22)), service("Web Out", (6, 80), (6, 443), (6, 8000, 8010)),
        service("HTTPS", (6, 443)), service("SMTP", (6, 25)), service("Staff Only", (6, 3389)), service("Ping", (1, "icmp", 8, 255)),
        service("Lab Tunnel", (47, 0)), service("DNS", (6, 53), (17, 53)),
    ]  # fmt: skip
    nats = [snat("Web-Public", "Web-Public.1.snat", "Web-Public.2.snat"), snat("Mail-Public", "Mail-Public.1.snat", "Mail-Public.2.snat", 2525)]
    policies = [
        policy("Block Bad", "Block Bad", ["Block Bad.1.from"], ["Block Bad.1.to"], "Deny"),
        policy("Admin SSH", "SSH", ["Admin SSH.1.from"], ["Admin SSH.1.to"]),
        policy("Web Out", "Web Out", ["Web Out.1.from"], ["Web Out.1.to"], "Proxy", proxy="HTTP-proxy"),
        policy("Web In", "HTTPS", ["Web In.1.from"], ["Web In.1.to"]),
        policy("Mail In", "SMTP", ["Mail In.1.from"], ["Mail In.1.to"]),
        policy("DMZ Updates", "HTTPS", ["DMZ Updates.1.from"], ["DMZ Updates.1.to"], schedule="Business Hours"),
        policy("Guests Out", "DNS", ["Guests Out.1.from"], ["Guests Out.1.to"], enabled=False),
        policy("Staff Only", "Staff Only", ["Staff Only.1.from"], ["Staff Only.1.to"]),
        policy("Ping", "Ping", ["Ping.1.from"], ["Ping.1.to"]),
        policy("Lab Tunnel", "Lab Tunnel", ["Lab Tunnel.1.from"], ["Lab Tunnel.1.to"]),
    ]
    return profile(interfaces, groups, aliases, services, nats, policies)


def main() -> None:
    path = Path(__file__).resolve().parents[1] / "data" / "watchguard_sample.xml"
    path.write_text(sample(), encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
