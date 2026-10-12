# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""WatchGuard parser: the configuration file of Policy Manager (Fireware 12) -> neutral model.

What an administrator has is the XML file Policy Manager saves (*File > Save > As File*), which is
also what the Web UI downloads, zipped. WatchGuard publishes no schema of it: the element names
are those the published readers of the format agree on (see DEVELOPMENT.md).

How Fireware differs from the model, and what is done about it:

* A policy has no zones. Its From and To lists hold aliases, and an alias holds members that are
  an address *and* an interface (``Any-Trusted``, ``External``, a named interface). Interfaces are
  the zones here. A policy whose lists hold members of different interfaces becomes one rule per
  pair of members, which together match what the policy matched.
* Policies are first match, in the order of the file when the configuration orders them by hand.
  In automatic order the Firebox orders them itself by how specific they are: the order of the file
  is read, and the report says so.
* Static NAT is an action in the To list of a policy: the policy names the public address, as the
  model does, and the translation becomes a NAT rule of its own. Network dynamic NAT and 1-to-1 NAT
  are not where the readers of the format found them, and are not read.
* The Firebox denies what no policy allows.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .. import xmlread
from ..errors import ParseError
from ..model import (
    ANY,
    Action,
    Address,
    AddressGroup,
    AddressKind,
    DestNat,
    NatRule,
    Policy,
    Protocol,
    Rule,
    Service,
    ServiceEntry,
    Zone,
)
from ..netutil import is_number, netmask_to_cidr, parse_literal
from ..report import Report, Severity

# The interfaces Fireware has for every Firebox, and what they stand for.
_CLASSES = {"any-trusted": "trusted", "any-external": "external", "any-optional": "optional"}
_KINDS = {"1": "trusted", "2": "external", "3": "optional", "8": "custom"}
_VPN = ("any-bovpn", "any-muvpn", "ssl-vpn", "any-multicast")
_ALLOW = ("allow", "allowed", "proxy", "1", "4")
_DENY = ("deny", "denied", "block", "blocked", "2")
_MAX_NESTING = 64
_MAX_MEMBERS = 200000
_MAX_PAIRS = 1000


def looks_like_watchguard(data: bytes) -> bool:
    head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    head = re.sub(rb"<\?.*?\?>|<!--.*?-->", b"", head, flags=re.S).lstrip()
    return head.startswith((b"<profile>", b"<profile "))


def _text(element: Optional[ET.Element], path: str = "") -> str:
    if element is None:
        return ""
    found = element.find(path) if path else element
    if found is None or found.text is None:
        return ""
    return found.text.strip()


def _short(text: str, limit: int = 60) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def parse(data: bytes, report: Report) -> Policy:
    root = xmlread.fromstring(data, "configuration files of Policy Manager")
    if root.tag != "profile":
        raise ParseError(f"not a configuration of a Firebox: the first element is <{str(root.tag)[:40]}>, not <profile>")
    if root.find("abs-policy-list") is None and root.find("policy-list") is None:
        raise ParseError("the configuration holds no <abs-policy-list>: is it the file Policy Manager saves?")
    version = _text(root, "for-version")
    policy = Policy(vendor="watchguard", scope=f"Fireware {version}" if version else "")
    _Reader(root, policy, report).run()
    return policy


@dataclass(frozen=True)
class _Member:
    """One member of an alias: an address (a name, or "any") at an interface (a zone list, or [ANY])."""

    address: str
    zones: Tuple[str, ...]
    user: str = ""


@dataclass(frozen=True)
class _Group:
    zones: Tuple[str, ...]
    user: str
    addresses: Tuple[str, ...]


class _Reader:
    def __init__(self, root: ET.Element, policy: Policy, report: Report) -> None:
        self.root, self.p, self.report = root, policy, report
        self.kinds: Dict[str, str] = {}  # interface -> trusted, external, optional, custom
        self.addresses: Dict[str, str] = {}  # interface -> its network
        self.firebox: List[str] = []
        self.aliases: Dict[str, ET.Element] = {}
        self.resolved: Dict[str, Optional[List[_Member]]] = {}
        self.problems: Dict[str, str] = {}
        self.snat: Dict[str, ET.Element] = {}
        self.rule_names: Set[str] = set()
        self.snat_zones: Dict[str, List[str]] = {}
        self.members_read = 0
        self.untyped: List[str] = []

    def run(self) -> None:
        self._interfaces()
        self._address_groups()
        self._services()
        for alias in self.root.findall("alias-list/alias"):
            if _text(alias, "name") in self.aliases:
                raise ParseError(f"alias '{_short(_text(alias, 'name'), 40)}' is defined twice")
            self.aliases[_text(alias, "name")] = alias
        for nat in self.root.findall("nat-list/nat"):
            self.snat[_text(nat, "name")] = nat
        self._policies()
        order = [_text(e) for e in self.root.iter("auto-order-enabled")]
        if not order or any(value not in ("0", "false") for value in order):
            self.report.note(
                Severity.REVIEW, "POLICY_ORDER_AUTOMATIC",
                "the configuration " + ("orders its policies automatically" if order else "does not say whether its policies are "
                                        "in automatic or manual order") + ": the Firebox then puts them in an order of its own, "
                "by how specific they are. The policies were read in the order of the file: check it against Policy Manager, "
                "or switch to manual order there and save the file again",
            )  # fmt: skip
        if self.root.find("nat-list") is not None or self.root.find("system-parameters") is not None:
            self.report.note(
                Severity.REVIEW, "NAT_NOT_READ",
                "network dynamic NAT, 1-to-1 NAT and the NAT settings of a policy are not read: where the file keeps them is not "
                "known. Static NAT actions in the To list of a policy are read",
            )  # fmt: skip
        self.report.note(
            Severity.INFO, "WATCHGUARD_FORMAT",
            "the configuration file of Policy Manager is not documented by WatchGuard. The elements read are those the "
            "published readers of the format agree on",
        )  # fmt: skip

    # -- interfaces --------------------------------------------------------------------------------

    def _interfaces(self) -> None:
        for interface in self.root.findall("interface-list/interface"):
            name = _text(interface, "name")
            if not name or _text(interface, "property") == "4" or name.lower() in _CLASSES or name.lower() in _VPN or name in ("Any", "Firebox"):
                continue
            kind, address = "", ""
            for item in interface.iter():
                if item.tag in ("if-property", "vif-property") and _text(item) in _KINDS:
                    kind = kind or _KINDS[_text(item)]
                if item.tag == "ip" and parse_literal(_text(item)) and not address:
                    mask = next((_text(m) for m in interface.iter("netmask")), "")
                    cidr = netmask_to_cidr(_text(item), mask) if mask else None
                    address = cidr or ""
                    self.firebox.append(_text(item))
            self.kinds[name] = kind or "custom"
            if not kind:
                self.untyped.append(name)
            if address:
                self.addresses[name] = address
            self.p.zones[name] = Zone(name, [name])

    def _interface_zones(self, name: str) -> Optional[Tuple[str, ...]]:
        """The zones of an interface of an alias member; None when it is no interface of the configuration."""
        low = name.lower()
        if low in ("", "any", "firebox"):
            return (ANY,)  # the Firebox itself: what is there is the address, "Firebox"
        if low in _CLASSES:
            if self.untyped:
                return None
            return tuple(z for z, kind in self.kinds.items() if kind == _CLASSES[low]) or None
        if name in self.kinds:
            return (name,)
        return None

    # -- objects ----------------------------------------------------------------------------------

    def _address_groups(self) -> None:
        seen: Set[str] = set()
        for group in self.root.findall("address-group-list/address-group"):
            name = _text(group, "name")
            if name in seen:
                raise ParseError(f"address group '{_short(name, 40)}' is defined twice")
            seen.add(name)
            if not name or name == "Firebox":
                continue
            members: List[str] = []
            problem = ""
            for member in group.findall("addr-group-member/member"):
                kind = _text(member, "type")
                if kind == "1" and parse_literal(_text(member, "host-ip-addr")):
                    members.append(_text(member, "host-ip-addr"))
                elif kind == "2":
                    cidr = netmask_to_cidr(_text(member, "ip-network-addr"), _text(member, "ip-mask"))
                    if cidr is None:
                        problem = f"a network that could not be read ({_short(_text(member, 'ip-network-addr'), 30)})"
                    else:
                        members.append(cidr)
                elif kind == "3" and parse_literal(f"{_text(member, 'start-ip-addr')}-{_text(member, 'end-ip-addr')}"):
                    members.append(f"{_text(member, 'start-ip-addr')}-{_text(member, 'end-ip-addr')}")
                elif kind == "8" and _text(member, "domain"):
                    fqdn = f"{name} {_text(member, 'domain')}"
                    self.p.addresses[fqdn] = Address(fqdn, AddressKind.FQDN, _text(member, "domain"))
                    members.append(fqdn)
                else:
                    problem = f"an address member of type '{_short(kind, 10)}' that could not be read"
            if problem or not members:
                self.p.address_groups[name] = AddressGroup(name, [], unsupported=problem or "an address group without members")
            elif len(members) == 1 and members[0] not in self.p.addresses:
                literal = members[0]
                self.p.addresses[name] = Address(name, AddressKind.RANGE if "-" in literal else AddressKind.NETWORK, literal)
            else:
                self.p.address_groups[name] = AddressGroup(name, members)
        if self.firebox:
            self.p.address_groups["Firebox"] = AddressGroup("Firebox", list(dict.fromkeys(self.firebox)),
                                                            "the addresses of the interfaces of the Firebox", builtin="watchguard")  # fmt: skip
        else:
            self.p.addresses["Firebox"] = Address("Firebox", AddressKind.UNSUPPORTED, "", raw="the Firebox itself: the configuration "
                                                  "holds no address of its interfaces", builtin="watchguard", fqdn_family=4)  # fmt: skip

    def _services(self) -> None:
        for service in self.root.findall("service-list/service"):
            name = _text(service, "name")
            if not name:
                continue
            if name in self.p.services:
                raise ParseError(f"service '{_short(name, 40)}' is defined twice")
            entries: List[ServiceEntry] = []
            problem = ""
            for member in service.findall("service-item/member"):
                protocol, kind = _text(member, "protocol"), _text(member, "type")
                if not is_number(protocol) or int(protocol) > 255:
                    problem = f"protocol '{_short(protocol, 10)}' that could not be read"
                    break
                number = int(protocol)
                if number in (6, 17):
                    if kind == "2":
                        low, high = _text(member, "start-server-port"), _text(member, "end-server-port")
                    else:
                        low = high = _text(member, "server-port")
                    if not (is_number(low) and is_number(high)) or int(high) < int(low) or int(high) > 65535:
                        problem = f"ports '{_short(low, 10)}' to '{_short(high, 10)}' that could not be read"
                        break
                    ports = "" if int(low) == 0 and int(high) in (0, 65535) else (low if low == high else f"{low}-{high}")
                    entries.append(ServiceEntry(Protocol.TCP if number == 6 else Protocol.UDP, ports))
                elif number in (1, 58):
                    kind_text, code_text = _text(member, "icmp-type"), _text(member, "icmp-code")
                    if not kind_text:
                        problem = "an ICMP member without a type"
                        break
                    icmp_type = None if kind_text == "255" else int(kind_text) if is_number(kind_text) and int(kind_text) < 256 else -1
                    icmp_code = None if code_text in ("", "255") else int(code_text) if is_number(code_text) and int(code_text) < 256 else -1
                    if icmp_type == -1 or icmp_code == -1:
                        problem = "an ICMP type or code that could not be read"
                        break
                    entries.append(ServiceEntry(Protocol.ICMP if number == 1 else Protocol.ICMP6, icmp_type=icmp_type, icmp_code=icmp_code))
                elif number == 0:
                    entries.append(ServiceEntry(Protocol.IP))
                else:
                    entries.append(ServiceEntry(Protocol.IP, ip_protocol=number))
            if not entries and not problem:
                problem = "a service without members"
            self.p.services[name] = Service(name, [] if problem else entries, unsupported=problem)

    # -- aliases -----------------------------------------------------------------------------------

    def _alias(self, name: str, depth: int = 0) -> Optional[List[_Member]]:
        """The members of an alias, aliases in it followed; None when it cannot be read (the reason in problems)."""
        if name in self.resolved:
            return self.resolved[name]
        if depth > _MAX_NESTING:
            self.problems[name] = "aliases nested more than 64 deep, or in a circle"
            return None
        alias = self.aliases.get(name)
        if alias is None:
            self.problems[name] = f"alias '{_short(name, 40)}' is not in the configuration"
            self.resolved[name] = None
            return None
        out: List[_Member] = []
        for member in alias.findall("alias-member-list/alias-member"):
            kind = _text(member, "type")
            if kind == "2":
                inner = self._alias(_text(member, "alias-name"), depth + 1)
                if inner is None:
                    self.problems.setdefault(name, self.problems.get(_text(member, "alias-name"), "an alias that could not be read"))
                    self.resolved[name] = None
                    return None
                out += [m for m in inner if m not in out]
            elif kind == "1":
                zones = self._interface_zones(_text(member, "interface"))
                if zones is None and self.untyped and _text(member, "interface").lower() in _CLASSES:
                    self.problems[name] = (f"interface '{_text(member, 'interface')}': the configuration does not say of what type "
                                           f"{', '.join(self.untyped[:4])} is, so what it holds is not known")  # fmt: skip
                    self.resolved[name] = None
                    return None
                if zones is None:
                    self.problems[name] = f"interface '{_short(_text(member, 'interface'), 30)}', which is no interface of the configuration"
                    self.resolved[name] = None
                    return None
                address = _text(member, "address")
                if address.lower() in ("", "any"):
                    address = ANY
                elif address not in self.p.addresses and address not in self.p.address_groups:
                    self.problems[name] = f"address '{_short(address, 40)}' is not in the configuration"
                    self.resolved[name] = None
                    return None
                user = _text(member, "user")
                found = _Member(address, zones, "" if user.lower() in ("", "any") else user)
                if found not in out:
                    out.append(found)
            else:
                self.problems[name] = f"an alias member of type '{_short(kind, 10)}', which this parser does not know"
                self.resolved[name] = None
                return None
        self.members_read += len(out)
        if self.members_read > _MAX_MEMBERS:
            raise ParseError(f"the aliases of the configuration hold more than {_MAX_MEMBERS} members in all: refusing to read on")
        self.resolved[name] = out
        return out

    # -- policies ----------------------------------------------------------------------------------

    def _policies(self) -> None:
        concrete = {_text(p, "name"): p for p in self.root.findall("policy-list/policy")}
        listed = self.root.findall("abs-policy-list/abs-policy")
        if not listed:
            listed = list(concrete.values())
        for element in listed:
            name = _text(element, "name") or "unnamed"
            self._policy(element, name, concrete)

    def _policy(self, element: ET.Element, name: str, concrete: Dict[str, ET.Element]) -> None:
        problems: List[str] = []
        enabled_text = (_text(element, "enabled") or _text(element, "enable")).lower()
        action_text = _text(element, "firewall").lower()
        inner = [concrete.get(_text(p)) for p in element.findall("policy-list/policy")]
        if not action_text and inner and inner[0] is not None:
            action_text = _text(inner[0], "firewall").lower()
        if action_text in _ALLOW:
            action = Action.ALLOW
        elif action_text in _DENY:
            action = Action.DENY
        else:
            action = Action.DENY
            problems.append(f"action '{_short(action_text, 20)}', which this parser does not know")
        if enabled_text not in ("true", "1", "false", "0"):
            problems.append("the configuration does not say whether the policy is enabled")
        enabled = enabled_text in ("true", "1")
        for other in inner:
            if other is None:
                continue
            code, on = _text(other, "firewall"), _text(other, "enable")
            if (code and (code in _ALLOW) != (action == Action.ALLOW)) or (on and (on == "1") != enabled):
                problems.append(f"the policy and its rule '{_short(_text(other, 'name'), 40)}' in <policy-list> say different things "
                                "about its action or whether it is enabled")  # fmt: skip
        service = _text(element, "service")
        if not service or service not in self.p.services:
            problems.append(f"service '{_short(service, 40)}' is not in the configuration")
        settings = element.find("settings")
        schedule = _text(settings, "schedule")
        sources = self._side(element, "from-alias-list", problems)
        targets, nats = self._targets(element, problems)
        if not sources or not targets:
            if not problems:
                problems.append("an empty From or To list")
            sources = sources or [_Member(ANY, (ANY,))]
            targets = targets or [_Member(ANY, (ANY,))]
        pairs = [(s, t) for s in self._grouped(sources) for t in self._grouped(targets)]
        if len(pairs) > _MAX_PAIRS:
            problems.append(f"the policy would be {len(pairs)} rules, more than FWShift reads for one policy ({_MAX_PAIRS})")
            pairs = pairs[:1]
        made: List[Rule] = []
        for number, (src, dst) in enumerate(pairs, start=1):
            label = name if len(pairs) == 1 else f"{name} ({number})"
            rule_name = label
            counter = 2
            while rule_name in self.rule_names:
                rule_name = f"{label} {counter}"
                counter += 1
            self.rule_names.add(rule_name)
            rule = Rule(name=rule_name, origin=rule_name, action=action, enabled=enabled, description=_text(element, "description"))
            rule.src_zones, rule.dst_zones = list(src.zones), list(dst.zones)
            rule.sources, rule.destinations = list(src.addresses), list(dst.addresses)
            rule.services = [service] if service else [ANY]
            rule.unsupported = list(problems)
            if src.user:
                rule.users = [src.user]
            if dst.user:
                rule.unsupported.append(f"user '{_short(dst.user, 40)}' in the To list")
            if schedule and schedule.lower() not in ("always on", ""):
                rule.schedule = schedule
            if settings is not None:
                if _text(settings, "proxy") or action_text in ("proxy", "4"):
                    rule.profiles["proxy"] = _text(settings, "proxy") or "proxy"
                if _text(settings, "policy-routing"):
                    rule.handling["policy-routing"] = _text(settings, "policy-routing")
            self.p.rules.append(rule)
            made.append(rule)
        if len(pairs) > 1:
            for rule in made:
                self.report.add("rule", rule.origin, Severity.INFO, "POLICY_SPLIT",
                                f"policy '{name}' names members of several interfaces: it is read as {len(pairs)} rules, one per "
                                "pair of From and To members")  # fmt: skip
        for nat_name, public in nats:
            for group in self._grouped(sources):
                self._static_nat(name, nat_name, public, group, service, enabled and not problems)

    @staticmethod
    def _grouped(members: List[_Member]) -> List["_Group"]:
        """Members of one side by interface and user: the addresses of each, which one rule can name together."""
        out: Dict[Tuple[Tuple[str, ...], str], List[str]] = {}
        for member in members:
            out.setdefault((member.zones, member.user), []).append(member.address)
        merged: Dict[Tuple[Tuple[str, ...], str], List[str]] = {}
        for (zones, user), addresses in out.items():
            key = (tuple([ANY] if ANY in addresses else dict.fromkeys(addresses)), user)
            held = merged.setdefault(key, [])
            held += [zone for zone in zones if zone not in held]
        return [_Group((ANY,) if ANY in zones else tuple(zones), user, addresses) for (addresses, user), zones in merged.items()]

    def _side(self, element: ET.Element, path: str, problems: List[str]) -> List[_Member]:
        out: List[_Member] = []
        for alias in element.findall(f"{path}/alias"):
            members = self._alias(_text(alias))
            if members is None:
                problems.append(self.problems.get(_text(alias), f"alias '{_short(_text(alias), 40)}' could not be read"))
                continue
            out += members
        return list(dict.fromkeys(out))

    def _targets(self, element: ET.Element, problems: List[str]) -> Tuple[List[_Member], List[Tuple[str, str]]]:
        """The To members of a policy, with the static NAT actions in it: (NAT action, its public address)."""
        out: List[_Member] = []
        nats: List[Tuple[str, str]] = []
        for alias in element.findall("to-alias-list/alias"):
            names = [_text(alias)]
            node = self.aliases.get(_text(alias))
            if _text(alias).endswith(".snat") and _text(alias)[: -len(".snat")] in self.snat:
                public = self._snat_public(_text(alias), problems)
                if public is not None:
                    out.append(_Member(public.address, (ANY,), public.user))
                    nats.append((_text(alias)[: -len(".snat")], public.address))
                    self.snat_zones[_text(alias)[: -len(".snat")]] = list(public.zones)
                continue
            if node is not None:
                inner = [_text(m, "alias-name") for m in node.findall("alias-member-list/alias-member") if _text(m, "type") == "2"]
                snats = [n for n in inner if n.endswith(".snat") and n[: -len(".snat")] in self.snat]
                if snats:
                    names = [n for n in inner if n not in snats]
                    for snat in snats:
                        public = self._snat_public(snat, problems)
                        if public is not None:
                            # The rule names the public address; the zone the translated traffic goes to is not said.
                            out.append(_Member(public.address, (ANY,), public.user))
                            nats.append((snat[: -len(".snat")], public.address))
                            self.snat_zones[snat[: -len(".snat")]] = list(public.zones)
                    if [m for m in node.findall("alias-member-list/alias-member") if _text(m, "type") != "2"]:
                        problems.append(f"alias '{_short(_text(alias), 40)}' holds a static NAT action and other members")
            for name in names:
                members = self._alias(name)
                if members is None:
                    problems.append(self.problems.get(name, f"alias '{_short(name, 40)}' could not be read"))
                else:
                    out += members
        return list(dict.fromkeys(out)), nats

    def _snat_public(self, snat: str, problems: List[str]) -> Optional[_Member]:
        members = self._alias(snat)
        if members is None or len(members) != 1:
            problems.append(f"static NAT action '{_short(snat, 40)}' could not be read")
            return None
        return members[0]

    def _static_nat(self, policy: str, name: str, public: str, sources: "_Group", service: str, enabled: bool) -> None:
        """The translation of a static NAT action, for what the policy that holds it matches: on a Firebox it is part of
        the policy, and a policy without it does not translate."""
        nat = self.snat[name]
        items = nat.findall("nat-item/member")
        label = f"{name} ({policy})"
        nat_name, counter = label, 2
        while any(n.name == nat_name for n in self.p.nat_rules):
            nat_name = f"{label} {counter}"
            counter += 1
        rule = NatRule(name=nat_name, origin=nat_name, description=f"static NAT action {name} of policy {policy}")
        rule.destinations = [public]
        rule.sources = list(sources.addresses)
        rule.service = service or ANY
        rule.enabled = enabled
        rule.src_zones = list(sources.zones)
        if sources.user:
            rule.unsupported.append(f"user '{_short(sources.user, 40)}' in the From list of policy {policy}")
        rule.dst_zones = self.snat_zones.get(name, [ANY])
        if len(items) != 1 or _text(items[0], "addr-type") != "4":
            rule.unsupported.append("a static NAT action with several members or of a kind this parser does not know "
                                    "(server load balancing)")  # fmt: skip
        else:
            item = items[0]
            inside = _text(item, "addr-name")
            if inside not in self.p.addresses and inside not in self.p.address_groups:
                rule.unsupported.append(f"address '{_short(inside, 40)}' is not in the configuration")
            port = _text(item, "port")
            rule.destination_translation = DestNat(inside, "" if port in ("", "0") else port)
            if port not in ("", "0") and not is_number(port):
                rule.unsupported.append(f"port '{_short(port, 10)}' that could not be read")
        self.p.nat_rules.append(rule)


__all__ = ["looks_like_watchguard", "parse"]
