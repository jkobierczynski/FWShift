# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""pfSense emitter: neutral model -> the areas *Aliases*, *NAT* and *Firewall Rules* of a ``config.xml``.

The output is one file with the root ``<pfsense>`` that holds ``<aliases>``, ``<nat>`` and
``<filter>``. *Diagnostics > Backup & Restore* restores one area at a time from it, and each
restore **replaces** that area of the firewall. Written for pfSense 2.7 and later (the outbound
NAT rules are in the form of configuration version 23.0).

Design rules:

* Rules are written on the tab of the interface their traffic arrives on, in the order of the
  model. A rule for several zones, or for every zone, is written on each of those tabs: the rules
  of one interface are first match, and what is on other tabs does not matter to them.
* No rule of an interface can name the interface traffic leaves by. A rule for a destination zone
  is kept to the networks behind its zones where they were given (``--zone-network``), as for an
  ASA. Rules that block whatever leaves towards a zone, and stand above all others, are written
  as floating rules for outgoing traffic, which is what pfSense has for that.
* pfSense has no service objects: a rule names one protocol with a port, a range or an alias of
  ports. A rule with services of several kinds becomes one rule per kind.
* Rules see the destination after port forwards and 1:1 NAT: they are rewritten to the translated
  address, as for every platform that looks its rules up after destination NAT.
* A rule that cannot be enforced is written disabled, a NAT rule that cannot be written is left
  out; both are in the report.
"""

from __future__ import annotations

import copy
import html
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, Type

from .. import transform
from ..errors import FwshiftError
from ..model import (
    ANY,
    ANY_V4,
    ANY_V6,
    L4_PROTOCOLS,
    Action,
    AddressKind,
    NatRule,
    Policy,
    Protocol,
    Rule,
    RuleScope,
    ServiceEntry,
    SnatKind,
)
from ..names import PFSENSE, PFSENSE_TEXT, clean, unique
from ..netutil import FULL_V4, FULL_V6, Interval, int_to_ip, normalize, overlaps, parse_literal, size, subtract
from ..options import Options
from ..parsers.pfsense import ICMP6_TYPES, ICMP_TYPES, KEY, PROTOCOLS, SYSTEM_GROUPS
from ..report import Report, Severity
from .asa import _Areas, zone_areas, zone_spaces

Problem = Tuple[str, str, Severity]
Finding = Tuple[Severity, str, str]
BOTH: FrozenSet[int] = frozenset({4, 6})
_PLACEHOLDER = "192.0.0.8"  # the dummy address of RFC 7600: nothing is sent from it or to it
_MAX_ENTRIES = 5000  # what an alias holds
_FIRST_TRACKER = 2000000000  # above what pfSense gives its own rules and what the web interface hands out today
_ZONE_OF = {zone: key for key, zone in SYSTEM_GROUPS.items()}  # IPsec -> enc0, ...
_SAME_KIND = ("pfsense", "opnsense")  # sources whose objects and words are those of pf as pfSense writes it
_GROUP = re.compile(r"[A-Za-z_]|[A-Za-z_][A-Za-z0-9_]{0,13}[A-Za-z_]")  # an interface group: 15 characters, no digit at an end
_ICMP_NAMES = {number: name for name, number in reversed(list(ICMP_TYPES.items()))}
_ICMP6_NAMES = {number: name for name, number in reversed(list(ICMP6_TYPES.items()))}
_PROTOCOL_NAMES = {number: name for name, number in PROTOCOLS.items()}
# Words an alias cannot be called: those of pf.conf that could be a name, the tables and aliases pfSense has itself,
# protocols, and the services most likely to be met. pfSense compares most of them without case.
_WORDS = frozenset(
    """all altq anchor antispoof any bandwidth binat bitmask block buckets cbq code codelq crop debug dnpipe dnqueue drop
    ether fairq fastroute file fingerprints flags floating flush for fragment from global group hfsc hogs hostid in
    include inet inet6 interval keep keepcounters l3 label limit linkshare load log loginterface match max modulate nat
    no on optimization os out overload pass port prio priority priq probability proto qlimit queue quick random rdr
    realtime reassemble return ridentifier route rtable rule scrub set skip sloppy state syncookies synproxy table tag
    tagged target tbrsize timeout to tos ttl upperlimit user self
    allowopts binatanchor blockpolicy divertreply divertto dupto icmptype icmp6type ifbound maxmss maxsrcconn
    maxsrcconnrate maxsrcnodes maxsrcstates minttl natanchor nodf noroute nosync randomid rdranchor replyto
    requireorder returnicmp returnicmp6 returnrst roundrobin routeto settos sourcehash sourcetrack statepolicy
    staticport stickyaddress urpffailed
    ipsec l2tp openvpn pppoe pptp wireguard tailscale
    bogons bogonsv6 negate_networks snort2c sshguard tonatsubnets virusprot vpn_networks
    ip hopopt icmp igmp ggp ipencap st tcp egp igp pup udp hmp rdp dccp xtp ddp ipv6 idrp rsvp gre esp ah rspf vmtp
    eigrp ospf ipip etherip encap pim ipcomp vrrp isis sctp fc udplite manet hip shim6 wesp rohc ethernet mptcp carp
    pfsync divert
    ftp ssh telnet smtp domain dns tftp gopher finger http www kerberos pop2 pop3 sunrpc auth sftp nntp ntp imap snmp
    snmptrap bgp irc ldap https smtps syslog printer talk ntalk route rip submission ldaps rsync ftps imaps pop3s
    socks nfs mysql postgresql radius radacct ipp mdns isakmp svn git amqp xmpp sip sips rtsp openvpn echo discard daytime
    chargen time router mobile ups netstat name nameserver whois login shell exec uucp kerberos klogin kshell biff who
    timed tempo courier conference netnews webster""".split()
)


def _reserved(name: str) -> bool:
    """Whether pfSense refuses an alias of this name, or would take the name for something else."""
    low = name.lower()
    return (
        low in _WORDS or not re.search(r"[A-Za-z]", name) or KEY.fullmatch(low) is not None or low.endswith("__network")
        or low.startswith(("pkg_", "cpzoneid_", "_"))
    )  # fmt: skip


def valid_interface(name: str) -> bool:
    """What a rule can name as its interface: an assigned interface, one of the tunnel interfaces, or a group."""
    return KEY.fullmatch(name) is not None or name in SYSTEM_GROUPS or (_GROUP.fullmatch(name) is not None and not _reserved(name))


def _is_key(name: str) -> bool:
    return KEY.fullmatch(name) is not None or name in SYSTEM_GROUPS


def _target_interfaces(policy: Policy, options: Options) -> Dict[str, List[str]]:
    """Zone, under the name it has on the target -> the interfaces of pfSense its rules go on.

    A zone is an interface when its name is one (``--zone-map inside=lan``), or when its interfaces
    are (``--interface-map ethernet1/2=lan``; for a pfSense source they are as they come). Any other
    zone keeps its name, which pfSense takes when an interface group is called so.
    """
    out: Dict[str, List[str]] = {}
    names = list(policy.zones) + [
        z for r in list(policy.rules) + list(policy.nat_rules) for z in r.src_zones + r.dst_zones if z != ANY and z not in policy.zones
    ]
    for name in transform.dedupe(names):
        target = options.zone_map.get(name, name)
        found = out.setdefault(target, [])
        zone = policy.zones.get(name)
        hints = [options.interface_map.get(i, i) for i in zone.interfaces] if zone is not None else []
        if _is_key(target.lower()):
            add = [target.lower()]
        elif target in _ZONE_OF and policy.vendor in _SAME_KIND:
            add = [_ZONE_OF[target]]
        elif hints and all(_is_key(hint) for hint in hints):
            add = hints
        else:
            add = [target]
        found += [interface for interface in add if interface not in found]
    # A zone that only an option names is a zone of the target as well: rules are kept away from its networks.
    for extra in ([options.nat_zone] if options.nat_zone else []) + list(options.zone_networks):
        out.setdefault(extra, [extra.lower() if _is_key(extra.lower()) else extra])
    return out


def _keywords(policy: Policy, interfaces: Dict[str, List[str]], options: Options) -> Dict[str, str]:
    """Objects a pfSense source has for what the firewall itself is -> the word pfSense has for them."""
    out: Dict[str, str] = {}
    if policy.vendor not in _SAME_KIND:
        return out
    names = [(n, a.builtin) for n, a in policy.addresses.items()] + [(n, g.builtin) for n, g in policy.address_groups.items()]
    for name, builtin in names:
        if builtin != "pfsense":
            continue
        if name in ("This Firewall", "This Firewall IPv6"):
            out[name] = "(self)"
            continue
        match = re.fullmatch(r"(.+) (net|address)( IPv6)?", name)
        if not match:
            continue
        keys = interfaces.get(options.zone_map.get(match.group(1), match.group(1)), [])
        if len(keys) == 1 and KEY.fullmatch(keys[0]):
            out[name] = keys[0] + ("ip" if match.group(2) == "address" else "")
    return out


def emit(policy: Policy, report: Report, options: Options) -> str:
    return emit_with(policy, report, options, _Emitter)


def emit_with(policy: Policy, report: Report, options: Options, emitter: Type["_Emitter"]) -> str:
    """The conversion with an emitter that writes what pfSense has in another form (OPNsense)."""
    zone_spaces(options.zone_networks)  # refuses networks that contradict each other
    interfaces = _target_interfaces(policy, options)
    if options.nat_zone and not all(valid_interface(i) for i in interfaces[options.nat_zone]):
        raise FwshiftError(f"--target-nat-zone: '{options.nat_zone[:40]}' is no interface a pfSense rule can name")
    p = copy.deepcopy(policy)
    keywords = emitter.keywords_of(p, interfaces, options)
    transform.apply_zone_map(p, options.zone_map)
    transform.ensure_references(p, report)
    native = p.vendor in _SAME_KIND
    listed = list(p.addresses) + list(p.address_groups)
    names = emitter.NAMES
    reserved = set() if native else {clean(name, names) for name in listed if _reserved(clean(name, names))}
    descriptions = [nat.name for nat in p.nat_rules]
    # pfSense has no service objects: a rule says protocol and ports itself. Their names stay as they are.
    services, service_groups = p.services, p.service_groups
    p.services, p.service_groups = {}, {}
    transform.sanitize_names(p, names, PFSENSE_TEXT, report, reserved_addresses=reserved, prefix=options.object_prefix, keep=set(keywords))
    p.services, p.service_groups = services, service_groups
    for nat, description in zip(p.nat_rules, descriptions):
        nat.name = clean(description, PFSENSE_TEXT)  # the description of a NAT rule is free text, not a name
    # The rules of pfSense see the translated destination. Rewrite them for the translations that are really written.
    probe = emitter(p, Report(), options, interfaces, keywords)
    written = {origin for origins, _, plan in probe.plans() if plan.problem is None and (plan.forwards or plan.one_to_one) for origin in origins}
    transform.to_post_nat_lookup(p, report, written)
    if options.written is not None:
        options.written.append(p)
    return emitter(p, report, options, interfaces, keywords).run()


# -- XML as pfSense writes it ---------------------------------------------------------------------


@dataclass
class _X:
    tag: str
    text: str = ""
    children: List["_X"] = field(default_factory=list)
    cdata: bool = False

    def add(self, tag: str, text: str = "", cdata: bool = False) -> "_X":
        child = _X(tag, text, cdata=cdata)
        self.children.append(child)
        return child

    def lines(self, depth: int = 0) -> List[str]:
        tab = "\t" * depth
        if self.children:
            out = [f"{tab}<{self.tag}>"]
            for child in self.children:
                out += child.lines(depth + 1)
            return out + [f"{tab}</{self.tag}>"]
        # pfSense decodes entities in text once more than XML does, also inside CDATA.
        kept = (c for c in self.text if (c >= " " or c == "\t") and c not in "\ufffe\uffff" and not "\ud800" <= c <= "\udfff")
        text = html.escape("".join(kept), quote=True)
        if self.cdata and text:
            return [f"{tab}<{self.tag}><![CDATA[{text}]]></{self.tag}>"]
        return [f"{tab}<{self.tag}>{html.escape(text, quote=False)}</{self.tag}>"]


@dataclass(frozen=True)
class _Spec:
    """One side of a rule as pfSense says it."""

    kind: str  # "any", "address" (an address, a network or an alias) or "network" (a word of pfSense)
    value: str = ""
    negated: bool = False
    families: FrozenSet[int] = BOTH


@dataclass(frozen=True)
class _Class:
    """Services a single rule of pfSense can name: one protocol with its ports or ICMP types."""

    protocol: str = ""
    src: str = ""  # ports in the syntax of the model
    dst: str = ""
    icmp: Tuple[str, ...] = ()
    families: FrozenSet[int] = BOTH


@dataclass
class _NatPlan:
    problem: Optional[Problem] = None
    forwards: List[_X] = field(default_factory=list)
    one_to_one: List[_X] = field(default_factory=list)
    outbound: List[_X] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    summary: List[str] = field(default_factory=list)


def _networks(intervals: Sequence[Interval]) -> List[str]:
    """Address ranges as the networks an alias holds."""
    out: List[str] = []
    for version, first, last in normalize(list(intervals)):
        for network in ipaddress.summarize_address_range(int_to_ip(version, first), int_to_ip(version, last)):
            out.append(str(network.network_address) if network.num_addresses == 1 else str(network))
    return out


def _items(ports: str) -> List[str]:
    return [item for item in ports.split(",") if item]


class _Emitter:
    NAMES = PFSENSE  # what an alias can be called

    @staticmethod
    def keywords_of(policy: Policy, interfaces: Dict[str, List[str]], options: Options) -> Dict[str, str]:
        return _keywords(policy, interfaces, options)

    def __init__(self, p: Policy, report: Report, options: Options, interfaces: Dict[str, List[str]], keywords: Dict[str, str]) -> None:
        self.p, self.report, self.options = p, report, options
        self.interfaces, self.keywords = interfaces, keywords
        self.native = p.vendor in _SAME_KIND
        self.universe = list(interfaces)
        self.known_zones = {options.zone_map.get(zone, zone) for zone in p.zones} | {
            z for r in list(p.rules) + list(p.nat_rules) for z in r.src_zones + r.dst_zones
        }
        self.areas: _Areas = zone_areas(self.universe, zone_spaces(options.zone_networks))
        # An object pfSense has a word for is written as that word, whatever its addresses; a group that holds
        # one whose addresses are not known stays unusable.
        self.taint_all = transform.tainted_addresses(p)
        self.taint_a = {name: reason for name, reason in self.taint_all.items() if name not in keywords}
        self.taint_s = transform.tainted_services(p)
        self.aliases: Dict[str, _X] = {}  # in the order they are written
        self.kinds: Dict[str, str] = {}  # alias -> host or network
        self.taken: Set[str] = set(p.addresses) | set(p.address_groups)
        self.lists: Dict[Tuple[str, ...], str] = {}  # members -> the alias made for them
        self.port_aliases: Dict[str, str] = {}  # ports -> the alias made for them
        self.floating: List[_X] = []
        self.tabs: Dict[str, List[_X]] = {}
        self.tracker = _FIRST_TRACKER
        self.unknown: List[str] = []  # interfaces that are neither assigned interfaces nor known to be groups
        self.unnamed: List[str] = []  # zones whose name no rule of pfSense can carry, met in a rule for every zone
        self.implied = self.gap_used = False
        self.leading = True  # no rule that passes was written yet: rules that block can stand in any order
        self.snat_interfaces: Set[str] = set()
        self.nat_counts = (0, 0, 0)
        self.nat_written = False
        self.self_excluded = False
        self.keyword_alias: Dict[str, str] = {}
        self.lazy: Set[str] = set()  # host names that stand in aliases as they are, and get an alias of their own when a rule names them
        self._define_objects()

    # -- aliases -----------------------------------------------------------------------------------

    def _alias(self, name: str, kind: str, entries: List[str], description: str) -> None:
        if kind == "network" and all("/" not in entry and self.kinds.get(entry, "host") == "host" for entry in entries):
            kind = "host"  # nothing but addresses, host names and aliases of them
        self.kinds[name] = kind
        node = _X("alias")
        node.add("name", name)
        node.add("type", kind)
        node.add("address", " ".join(entries))
        node.add("descr", description, cdata=True)
        node.add("detail", "||".join("Entry added by FWShift" for _ in entries), cdata=True)
        self.aliases[name] = node

    def _placeholder(self, name: str, reason: str) -> None:
        self._alias(name, "host", [_PLACEHOLDER], f"FWSHIFT PLACEHOLDER, matches nothing: {reason}"[:200])

    def _entries(self, member: str) -> List[str]:
        """What a member of a rule or a group is inside an alias."""
        if member in self.lazy:
            return [self.p.addresses[member].value]
        if member in self.aliases or member in self.p.addresses or member in self.p.address_groups:
            return [self._object_alias(member)]
        interval = parse_literal(member)
        return _networks([interval]) if interval else []

    def _object_alias(self, name: str) -> str:
        """The alias of an object. One that pfSense has a word for gets an alias only where a list needs it."""
        if name in self.lazy and name not in self.aliases:
            address = self.p.addresses[name]
            self._alias(name, "host", [address.value], address.description)
        if name not in self.keywords:
            return name
        if name not in self.keyword_alias:
            alias = unique(name, self.taken, self.NAMES)
            intervals, complete = transform.known_intervals(self.p, name)
            if complete and intervals:
                self._alias(alias, "network", _networks(intervals), f"{name} of the source, as the addresses it had there")
            else:
                self._placeholder(alias, f"{name} of the source, whose addresses are not in its configuration")
            self.keyword_alias[name] = alias
        return self.keyword_alias[name]

    def _define_objects(self) -> None:
        for address in self.p.addresses.values():
            if address.name in self.keywords:
                continue
            if address.kind == AddressKind.UNSUPPORTED:
                self._placeholder(address.name, address.raw or "unsupported address type")
            elif address.kind == AddressKind.FQDN:
                if clean(address.value, self.NAMES) == address.name and not address.description:
                    self.lazy.add(address.name)  # an object that is nothing but the host name: no alias unless a rule wants one
                else:
                    self._alias(address.name, "host", [address.value], address.description)
            else:
                interval = parse_literal(address.value)
                entries = _networks([interval]) if interval else []
                if not entries:
                    self._placeholder(address.name, "an address that could not be read")
                else:
                    self._alias(address.name, "network", entries, address.description)
        for group in transform.topo_groups(self.p.address_groups):
            if group.name in self.keywords:
                continue
            if group.name in self.taint_a and transform.is_placeholder_group(group):
                self._placeholder(group.name, self.taint_a[group.name])
                continue
            entries = transform.dedupe([entry for member in group.members for entry in self._group_entries(member)])
            if not entries:
                self._placeholder(group.name, "empty group")
            elif len(entries) > _MAX_ENTRIES:
                self._placeholder(group.name, f"{len(entries)} entries, where an alias holds {_MAX_ENTRIES}")
                self.taint_a[group.name] = f"{len(entries)} entries, where an alias of pfSense holds {_MAX_ENTRIES}"
            else:
                self._alias(group.name, "network", entries, group.description)

    def _group_entries(self, member: str) -> List[str]:
        if member in self.keywords:
            # A word of pfSense cannot stand in an alias: the addresses the object had on the source do.
            intervals, complete = transform.known_intervals(self.p, member)
            return _networks(intervals) if complete else [_PLACEHOLDER]
        if member in self.lazy:
            return [self.p.addresses[member].value]
        if member in self.p.addresses or member in self.p.address_groups:
            return [member]
        interval = parse_literal(member)
        return _networks([interval]) if interval else []

    def _list_alias(self, members: Sequence[str], label: str, description: str) -> str:
        """An alias for several members of a rule, or for address ranges that are no single network."""
        key = tuple(members)
        if key not in self.lists:
            name = unique(self.options.object_prefix + label, self.taken, self.NAMES)
            entries = transform.dedupe([entry for member in members for entry in self._entries(member)])
            self._alias(name, "network", entries, description)
            self.lists[key] = name
        return self.lists[key]

    def _port_alias(self, ports: str, hint: str) -> str:
        """An alias of ports. Its name has an upper-case letter or an underscore, which no name of a service has: the
        web interface refuses an alias called like a service (is_validaliasname), and that way none is."""
        if ports not in self.port_aliases:
            label = clean(hint, self.NAMES) if hint else "ports_" + "_".join(_items(ports)).replace("-", "to")
            if len(label) > self.NAMES.max_len or _reserved(label) or not re.search(r"[A-Z_]", label):
                label = clean(f"{label[:20]}_ports" if hint else f"ports_{len(self.port_aliases) + 1}", self.NAMES)
            name = unique(self.options.object_prefix + label, self.taken, self.NAMES)
            node = _X("alias")
            node.add("name", name)
            node.add("type", "port")
            node.add("address", " ".join(item.replace("-", ":") for item in _items(ports)))
            node.add("descr", f"ports of {hint}" if hint else "", cdata=True)
            node.add("detail", "||".join("Entry added by FWShift" for _ in _items(ports)), cdata=True)
            self.aliases[name] = node
            self.port_aliases[ports] = name
        return self.port_aliases[ports]

    def _port(self, ports: str, hint: str = "") -> str:
        """Ports as the port of a rule: one port, one range, or an alias."""
        items = _items(ports)
        if not items:
            return ""
        return items[0] if len(items) == 1 else self._port_alias(ports, hint)

    # -- the sides of a rule ---------------------------------------------------------------------

    def _families(self, member: str) -> Set[int]:
        if member in self.keywords:
            return {6} if member.endswith(" IPv6") else {4}
        address = self.p.addresses.get(member)
        if address is not None and address.kind == AddressKind.UNSUPPORTED and address.fqdn_family:
            return {address.fqdn_family}
        return transform.families(self.p, member)

    def _members_spec(self, members: List[str], negated: bool, label: str, description: str) -> _Spec:
        families = frozenset(f for member in members for f in self._families(member))
        if negated:
            families = BOTH
        words = transform.dedupe([self.keywords.get(member, "") for member in members])
        if len(words) == 1 and words[0]:
            return _Spec("network", words[0], negated, families)
        if len(members) == 1:
            member = members[0]
            if member in self.keywords or member in self.p.addresses or member in self.p.address_groups:
                return _Spec("address", self._object_alias(member), negated, families)
            entries = self._entries(member)
            # "Not this address" is said with an alias: pf takes an address of one IP version in a rule for the
            # other as an error, and a table without one as a table.
            if len(entries) == 1 and not negated:
                return _Spec("address", entries[0], negated, families)
        members = [self._object_alias(member) if member in self.keywords else member for member in members]
        return _Spec("address", self._list_alias(members, label, description), negated, families)

    def _mixed(self, rule: Rule, reasons: List[transform.Reason]) -> None:
        """An object pfSense has a word for, next to other members: then its addresses are needed after all."""
        for members in (rule.sources, rule.destinations):
            if len(transform.dedupe([self.keywords.get(member, "") for member in members])) > 1:
                for member in members:
                    if member in self.keywords and member in self.taint_all:
                        reasons.append(("UNCONVERTIBLE_OBJECT", f"references '{member}': {self.taint_all[member]}"))

    def _side(self, rule: Rule, source: bool, limit: Optional[List[Interval]] = None) -> Optional[_Spec]:
        """The source or the destination of a rule; None when it can match nothing.

        ``limit`` keeps a destination to the zones of the rule: the addresses to leave out of it.
        """
        members = rule.sources if source else rule.destinations
        negated = rule.negate_source if source else rule.negate_destination
        what = "source" if source else "destination"
        label = ("src_" if source else "dst_") + rule.name
        everything = ANY in members or (ANY_V4 in members and ANY_V6 in members)
        if limit:
            resolved = [transform.known_intervals(self.p, member) for member in members]
            listed = normalize([interval for intervals, _ in resolved for interval in intervals])
            static = all(complete for _, complete in resolved) and not any(member in self.taint_a for member in members)
            if negated or everything or static:
                if negated:
                    left = [] if everything else subtract([FULL_V4, FULL_V6], listed)
                else:
                    left = [FULL_V4, FULL_V6] if everything else listed
                cut = subtract(left, limit)
                if cut != normalize(left):
                    if not cut:
                        return None
                    alias = self._list_alias(_networks(cut), label, f"{what} of rule {rule.name}, kept to the networks of its zones")
                    return _Spec("address", alias, False, frozenset(interval[0] for interval in cut))
        if negated and everything:
            return None
        # On pfSense the rules of an interface are also the rules for the firewall itself. A rule of another platform
        # that passes traffic to any destination was a rule for what goes through: it does not open the firewall.
        through = not source and not self.native and rule.action == Action.ALLOW and not negated
        if everything or (members in ([ANY_V4], [ANY_V6]) and not negated):
            families = BOTH if everything else frozenset({4 if members == [ANY_V4] else 6})
            if through:
                self.self_excluded = True
                return _Spec("network", "(self)", True, families)
            return _Spec("any", families=families)
        return self._members_spec(members, negated, label, f"{what} of rule {rule.name}")

    @staticmethod
    def _side_node(tag: str, spec: _Spec, port: str = "") -> _X:
        node = _X(tag)
        if spec.kind == "any":
            node.add("any")
        elif spec.kind == "network":
            node.add("network", spec.value)
        else:
            node.add("address", spec.value)
        if spec.negated:
            node.add("not")
        if port:
            node.add("port", port)
        if not node.children:
            node.add("any")
        return node

    # -- services ----------------------------------------------------------------------------------

    def _classes(self, rule: Rule, reasons: List[transform.Reason]) -> List[_Class]:
        """The services of a rule, as the kinds one rule of pfSense can name each."""
        lowered = transform.lower_applications(rule, self.options.app_ports, self.report, reasons)
        entries: List[ServiceEntry] = []
        if lowered is not None:
            entries = [entry for _, found in lowered for entry in found]
        elif rule.services == [ANY]:
            return [_Class()]
        else:
            for service in rule.services:
                entries += transform.flatten_services(self.p, service) or []
        return self._entry_classes(entries, reasons)

    def _entry_classes(self, entries: List[ServiceEntry], reasons: List[transform.Reason]) -> List[_Class]:
        out: List[_Class] = []
        ports: Dict[str, Dict[str, List[str]]] = {}  # source ports -> protocol -> destination ports
        icmp: Dict[int, Optional[List[int]]] = {}  # IP version -> types, None for every type
        for entry in entries:
            protocol, number = entry.protocol, entry.ip_protocol
            if protocol == Protocol.IP and number in (6, 17, 132):
                protocol = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP}[number]
            if protocol == Protocol.IP and number in (1, 58):
                protocol = Protocol.ICMP if number == 1 else Protocol.ICMP6
            if protocol in L4_PROTOCOLS:
                found = ports.setdefault(entry.src_ports, {}).setdefault(protocol.value, [])
                found += [item for item in (_items(entry.dst_ports) or [""]) if item not in found]
            elif protocol in (Protocol.ICMP, Protocol.ICMP6):
                version = 4 if protocol == Protocol.ICMP else 6
                if entry.icmp_code is not None:
                    reasons.append(("ICMP_CODE", f"ICMP type {entry.icmp_type} with code {entry.icmp_code}: a rule of pfSense names types, no codes"))
                elif entry.icmp_type is None:
                    icmp[version] = None
                elif entry.icmp_type not in (_ICMP_NAMES if version == 4 else _ICMP6_NAMES):
                    reasons.append(("ICMP_TYPE", f"ICMP{'v6' if version == 6 else ''} type {entry.icmp_type}, which pfSense has no name for"))
                elif version not in icmp or icmp[version] is not None:
                    types = icmp.setdefault(version, [])
                    if types is not None and entry.icmp_type not in types:
                        types.append(entry.icmp_type)
            elif number is None:
                return [_Class()]  # every protocol: nothing else is left to say
            elif number in _PROTOCOL_NAMES:
                out.append(_Class(_PROTOCOL_NAMES[number]))
            else:
                reasons.append(("PROTOCOL_NOT_AVAILABLE", f"IP protocol {number}, which a rule of pfSense cannot name"))
        for src, by_protocol in ports.items():
            tcp, udp = by_protocol.get("tcp"), by_protocol.get("udp")
            every = {protocol: "" if "" in found else ",".join(found) for protocol, found in by_protocol.items()}
            if tcp is not None and udp is not None and every["tcp"] == every["udp"]:
                out.append(_Class("tcp/udp", src, every["tcp"]))
                del every["tcp"], every["udp"]
            out += [_Class(protocol, src, dst) for protocol, dst in every.items()]
        names4 = None if icmp.get(4, []) is None else tuple(_ICMP_NAMES[t] for t in icmp.get(4) or [])
        names6 = None if icmp.get(6, []) is None else tuple(_ICMP6_NAMES[t] for t in icmp.get(6) or [])
        if 4 in icmp and 6 in icmp and names4 == names6 and all(name in ICMP6_TYPES for name in names4 or ()):
            out.append(_Class("icmp", icmp=names4 or ()))
        else:
            if 4 in icmp:
                out.append(_Class("icmp", icmp=names4 or (), families=frozenset({4})))
            if 6 in icmp:
                out.append(_Class("icmp", icmp=names6 or (), families=frozenset({6})))
        return list(dict.fromkeys(out))

    def _hint(self, rule: Rule, ports: str) -> str:
        """The name of the service of a rule, where it is the one that holds these ports."""
        if len(rule.services) == 1 and rule.services[0] in self.p.services and rule.applications == [ANY]:
            entries = self.p.services[rule.services[0]].entries
            if entries and all(entry.dst_ports == ports and not entry.src_ports for entry in entries):
                return rule.services[0]
        return ""

    # -- destination zones ------------------------------------------------------------------------

    def _egress(self, rule: Rule, pairs: List[Tuple[str, List[str]]], reasons: List[transform.Reason]) -> Dict[str, List[Interval]]:
        """Deal with destination zones: a rule of an interface cannot name the interface traffic leaves by.

        Returns, per source zone, the addresses to leave out of the destination to keep the rule to
        its zones, by the networks the user gave (--zone-network), where that is needed and can be
        done. Where the networks do not tell, the side that allows less is taken: a rule that passes
        leaves out the addresses that lie in no network given, a rule that blocks keeps them.
        """
        if rule.egress_implied:
            self.implied = True
            return {}
        intervals = [i for member in rule.destinations for i in transform.known_intervals(self.p, member)[0]]
        complete = all(transform.known_intervals(self.p, member)[1] for member in rule.destinations)
        named = not rule.negate_destination and ANY not in rule.destinations and FULL_V4 not in intervals and FULL_V6 not in intervals
        allow = rule.action == Action.ALLOW
        areas = self.areas
        limits: Dict[str, List[Interval]] = {}
        unknown: List[str] = []
        wanted: List[str] = []
        for source, dst_zones in pairs:
            if rule.scope == RuleScope.INTRAZONE:
                reached = [source]
            elif ANY not in dst_zones:
                reached = dst_zones
            elif rule.scope == RuleScope.INTERZONE:
                reached = [zone for zone in self.universe if zone != source]
            else:
                continue
            others = [zone for zone in self.universe if zone not in reached]
            if not others:
                continue  # every zone there is
            away = normalize([i for zone in others for i in areas.zones.get(zone, [])])
            missing = [zone for zone in others + reached if zone not in areas.zones]
            if missing or (named and not complete):
                unknown += missing
                wanted += reached
                continue
            to = "zone " + ", ".join(reached)
            extra, severity = "", Severity.INFO
            if named:
                if overlaps(subtract(intervals, away), areas.nowhere):
                    self.report.add(
                        "rule", rule.origin, Severity.APPROX, "EGRESS_INTERFACE",
                        f"the rule is for traffic to {to}, and part of its destination lies in none of the networks given "
                        "with --zone-network. A rule of pfSense cannot name the interface traffic leaves by: for those "
                        "addresses it applies by whatever interface they are reached",
                    )  # fmt: skip
                if not overlaps(intervals, away):
                    continue  # the destination lies where the rule is for as it is
                limits[source] = away
            else:
                limits[source] = normalize(away + areas.nowhere) if allow else away
                if areas.nowhere:
                    self.gap_used = True
                    severity = Severity.APPROX
                    extra = (
                        ", and the addresses that lie in none of the networks given" if allow
                        else ". The addresses that lie in none of the networks given are blocked by it as well"
                    )  # fmt: skip
                if not limits[source]:
                    del limits[source]
                    continue
            self.report.add(
                "rule", rule.origin, severity, "EGRESS_BY_NETWORKS",
                f"the rule is for traffic to {to}. A rule of pfSense cannot name the interface traffic leaves by: the "
                f"destination leaves out the networks given for the other zones (--zone-network){extra}",
            )  # fmt: skip
        if not wanted:
            return limits
        zones = ", ".join(transform.dedupe(wanted))
        inside = "inside one zone" if rule.scope == RuleScope.INTRAZONE else f"that leaves by {zones}"
        hint = ""
        if unknown:
            hint = " Or name the networks behind " + ", ".join(transform.dedupe(unknown)) + " with --zone-network."
        if named:
            self.report.add(
                "rule", rule.origin, Severity.APPROX, "EGRESS_INTERFACE",
                f"the rule is for traffic {inside}. A rule of pfSense cannot name the interface traffic leaves by: it "
                "applies to its destination addresses by whatever interface they are reached",
            )  # fmt: skip
        else:
            reasons.append(
                ("EGRESS_INTERFACE", (f"the rule is for traffic {inside}, to any address. A rule of pfSense cannot name "
                 "the interface traffic leaves by: give the rule the networks behind it as destination." + hint).rstrip("."))  # fmt: skip
            )
        return limits

    # -- rules -------------------------------------------------------------------------------------

    def _keys(self, zones: List[str], reasons: List[transform.Reason]) -> List[str]:
        """The interfaces of pfSense for zones; every one there is for "any"."""
        names = self.universe if ANY in zones else zones
        out: List[str] = []
        for zone in names:
            for interface in self.interfaces.get(zone, [zone]):
                if not valid_interface(interface) and ANY in zones:
                    # A rule for every zone is written where it can be. Nothing at all is written for this one.
                    if interface not in self.unnamed:
                        self.unnamed.append(interface)
                elif not valid_interface(interface):
                    reasons.append(
                        ("INTERFACE_NAME", f"'{interface}' is no interface a rule of pfSense can name; map the zone to "
                         "wan, lan or an optN with --zone-map")  # fmt: skip
                    )
                elif interface not in out:
                    out.append(interface)
                    if not _is_key(interface) and interface not in self.unknown:
                        self.unknown.append(interface)
        return out

    def _floating_block(self, rule: Rule) -> bool:
        """Whether a rule is written as a floating rule for traffic that leaves by an interface.

        That is what a rule is that blocks, for every source zone and named destination zones, and
        stands above every rule that passes: whatever leaves there is blocked, whatever the rules of
        the arrival interfaces pass. pf looks at such a rule after outbound NAT, so it can only name
        a source where nothing is translated. Without a NAT area the firewall keeps the outbound NAT
        it has (automatic, on an interface with a gateway): where the networks of every zone are
        known, such a rule is written for the interfaces traffic arrives on instead, and otherwise
        it stays a floating rule and the report says what to check.
        """
        if not self.leading or rule.action == Action.ALLOW or rule.scope != RuleScope.UNIVERSAL:
            return False
        if rule.src_zones != [ANY] or ANY in rule.dst_zones or rule.egress_implied:
            return False
        names = [interface for zone in rule.dst_zones for interface in self.interfaces.get(zone, [zone])]
        named = rule.negate_source or any(member not in (ANY, ANY_V4, ANY_V6) for member in rule.sources)
        if named and set(names) & self.snat_interfaces:
            return False
        return not (named and not self.nat_written and all(zone in self.areas.zones for zone in self.universe))

    def _rule_node(
        self, rule: Rule, interface: str, cls: _Class, source: _Spec, destination: _Spec, disabled: bool, note: str,
        leaving: bool = False,
    ) -> Optional[_X]:  # fmt: skip
        families = source.families & destination.families & cls.families
        if not families:
            return None
        node = _X("rule")
        node.add("id")
        self.tracker += 1
        node.add("tracker", str(self.tracker))
        node.add("type", {Action.ALLOW: "pass", Action.DROP: "block", Action.DENY: "block"}.get(rule.action, "reject"))
        node.add("interface", interface)
        node.add("ipprotocol", "inet46" if families == BOTH else "inet" if families == {4} else "inet6")
        node.add("statetype", "keep state", cdata=True)
        if leaving:
            node.add("direction", "out")
            node.add("quick", "yes")
            node.add("floating", "yes")
        if cls.protocol:
            node.add("protocol", cls.protocol)
        if cls.icmp:
            node.add("icmptype", ",".join(cls.icmp))
        ported = cls.protocol in ("tcp", "udp", "tcp/udp", "sctp")
        node.children.append(self._side_node("source", source, self._port(cls.src) if ported else ""))
        node.children.append(self._side_node("destination", destination, self._port(cls.dst, self._hint(rule, cls.dst)) if ported else ""))
        if disabled:
            node.add("disabled")
        if rule.log_start or rule.log_end:
            node.add("log")
        text = ": ".join(part for part in ((note or rule.name), "" if self.native else " ".join(rule.description.split())) if part)
        node.add("descr", text[:200], cdata=True)
        return node

    def _rule(self, rule: Rule) -> None:
        item = self.report.item("rule", rule.origin)
        transform.note_profiles(self.report, rule)
        transform.note_fqdn_families(self.p, rule, self.report, "pfSense")
        reasons = transform.blocking_reasons(rule, self.taint_a, self.taint_s)
        if rule.users != [ANY]:
            reasons.append(("USER_MATCH", "source user match " + ", ".join(rule.users) + " is not converted"))
        if rule.url_categories != [ANY]:
            reasons.append(("URL_CATEGORY", "URL category match " + ", ".join(rule.url_categories) + " is not converted"))
        if rule.negate_service:
            reasons.append(("SERVICE_NEGATE", "a negated service match does not exist in a rule of pfSense"))
        self._mixed(rule, reasons)
        classes = self._classes(rule, reasons)
        leaving = self._floating_block(rule)
        if rule.scope == RuleScope.INTRAZONE:
            if ANY in rule.src_zones:
                reasons.append(("RULE_TYPE", "intrazone rule with 'any' zone cannot be written per interface"))
            pairs = [(zone, [zone]) for zone in rule.src_zones]
        elif rule.scope == RuleScope.INTERZONE:
            names = self.universe if ANY in rule.src_zones else rule.src_zones
            pairs = [(zone, [other for other in rule.dst_zones if other == ANY or other != zone]) for zone in names]
            pairs = [(zone, dst_zones) for zone, dst_zones in pairs if dst_zones]
        else:
            names = self.universe if ANY in rule.src_zones and ANY not in rule.dst_zones and not leaving else rule.src_zones
            pairs = [(zone, rule.dst_zones) for zone in names]
        if not pairs:
            self.report.skip(
                "rule", rule.origin, "RULE_TYPE_EMPTY",
                "interzone rule whose zones leave no pair of different zones: it matches nothing", Severity.INFO,
            )  # fmt: skip
            return
        limits = {} if leaving else self._egress(rule, pairs, reasons)
        source = self._side(rule, True)
        if rule.action in (Action.RESET_SERVER, Action.RESET_BOTH):
            self.report.add(
                "rule", rule.origin, Severity.INFO, "RESET_ACTION",
                f"action {rule.action.value} becomes 'reject': pfSense answers the sender, with a TCP reset or an ICMP "
                "message, and tells the other side nothing",
            )  # fmt: skip
        # Where the rule goes: (interface or list of them, what to leave out of the destination).
        places: List[Tuple[str, Tuple[Interval, ...]]] = []
        if leaving:
            keys = self._keys(rule.dst_zones, reasons)
            places = [(",".join(keys), ())] if keys else []
        else:
            for zone, _ in pairs:
                places += [(key, tuple(limits.get(zone, []))) for key in self._keys([zone], reasons)]
            places = list(dict.fromkeys(places))
        reasons = [reason for index, reason in enumerate(reasons) if reason not in reasons[:index]]
        if not classes:
            classes = [_Class("tcp", dst="1")]  # stands in for services that could not be written: the rule is disabled
            if not reasons:
                reasons.append(("UNCONVERTIBLE_OBJECT", "its services could not be written"))
        if reasons:
            transform.disable_rule(self.report, rule, reasons)
        # A disabled rule for a negation that could not be written would read as its opposite.
        unsafe = any(code in ("SERVICE_NEGATE", "EGRESS_INTERFACE", "APP_UNKNOWN", "APP_DEFAULT_ANY") for code, _ in reasons)
        if unsafe:
            classes = [_Class("tcp", dst="1")]
        note = f"FWSHIFT inactive, see the report: {rule.name}" if reasons else ""
        disabled = bool(reasons) or not rule.enabled
        written: Dict[str, int] = {}
        emptied: List[str] = []
        for key, limit in places:
            destination = self._side(rule, False, list(limit) if limit else None)
            if source is None or destination is None:
                if limit and destination is None and source is not None:
                    emptied.append(key)
                continue
            for cls in classes:
                node = self._rule_node(rule, key, cls, source, destination, disabled, note, leaving)
                if node is None:
                    continue
                (self.floating if leaving else self.tabs.setdefault(key, [])).append(node)
                written[key] = written.get(key, 0) + 1
        if not leaving and written and rule.action == Action.ALLOW:
            self.leading = False  # from here on a rule that blocks may stand behind a rule that passes the same
        if emptied and rule.action != Action.ALLOW:
            severity = Severity.REVIEW
        else:
            severity = Severity.APPROX
        nothing = "by the networks given with --zone-network no address of its destination lies behind the zones the rule is for"
        if emptied and written:
            self.report.add("rule", rule.origin, severity, "EGRESS_NO_ADDRESS", f"on {', '.join(emptied)}: {nothing}. No rule is written there")
        elif emptied:
            self.report.skip("rule", rule.origin, "EGRESS_NO_ADDRESS", f"{nothing}: it is left out", severity)
            return
        if not written:
            if places or not reasons:
                self.report.skip(
                    "rule", rule.origin, "NO_COMMON_FAMILY",
                    "source, destination and service share no IP version, or a negation leaves no address: the rule "
                    "matches nothing and is left out", Severity.INFO,
                )  # fmt: skip
            return
        if leaving:
            item.emitted_as = [f"floating rule for what leaves by {key}" for key in written]
            named = rule.negate_source or any(member not in (ANY, ANY_V4, ANY_V6) for member in rule.sources)
            if named and not self.nat_written:
                # Without a NAT area in the file the firewall keeps the outbound NAT it has, which may translate the source.
                self.report.add(
                    "rule", rule.origin, Severity.REVIEW, "FLOATING_AFTER_NAT",
                    "the rule is a floating rule for what leaves by " + ", ".join(written) + ", and names a source. pfSense "
                    "looks at it after outbound NAT, and the file holds no NAT area: if the firewall translates the "
                    "source there (automatic outbound NAT does on an interface with a gateway), the rule does not match. "
                    "With the networks of every zone given (--zone-network) the rule is written for the interfaces "
                    "traffic arrives on instead",
                )  # fmt: skip
        else:
            item.emitted_as = [f"{key} ({count} rules)" if count != 1 else key for key, count in written.items()]
        total = sum(written.values())
        if len(classes) > 1 and not reasons and total > len(written):
            self.report.add(
                "rule", rule.origin, Severity.INFO, "RULE_SPLIT",
                f"a rule of pfSense names one protocol: the rule is written as {len(classes)} rules, one per kind of service",
            )  # fmt: skip

    # -- NAT ---------------------------------------------------------------------------------------

    def _static_spec(self, members: List[str], label: str, description: str) -> Optional[_Spec]:
        """Source or destination of a NAT rule; None unless it is static addresses of IPv4."""
        if ANY in members or ANY_V4 in members:
            return _Spec("any")
        resolved = [transform.known_intervals(self.p, member) for member in members]
        if not all(complete for _, complete in resolved) or any(i[0] != 4 for intervals, _ in resolved for i in intervals):
            return None
        if any(member in self.taint_a for member in members) or not members:
            return None
        return self._members_spec(members, False, label, description)

    def _nat_interfaces(self, zones: List[str], problems: List[str]) -> List[str]:
        reasons: List[transform.Reason] = []
        keys = self._keys(zones, reasons)
        problems += [message for _, message in reasons]
        return keys

    def _nat_classes(self, nat: NatRule) -> Optional[List[_Class]]:
        """The services of a NAT rule; None when they are no ports of TCP, UDP or SCTP."""
        if nat.service == ANY:
            return [_Class()]
        entries = transform.flatten_services(self.p, nat.service) or []
        if not entries or any(entry.protocol not in L4_PROTOCOLS for entry in entries):
            return None
        return self._entry_classes(entries, [])

    def nat_plan(self, nat: NatRule) -> _NatPlan:
        """What a NAT rule becomes, or why it cannot be written. Aliases apart, without side effects."""
        plan = _NatPlan()
        source, destination = nat.source_translation, nat.destination_translation

        def fail(code: str, message: str, severity: Severity = Severity.REVIEW) -> _NatPlan:
            return _NatPlan(problem=(code, message, severity))

        members = nat.sources + nat.destinations
        members = members + (source.addresses if source else []) + ([destination.address] if destination else [])
        problems = list(nat.unsupported)
        problems += [f"references '{m}': {self.taint_a[m]}" for m in members if m in self.taint_a]
        if nat.service in self.taint_s:
            problems.append(f"references '{nat.service}': {self.taint_s[nat.service]}")
        if problems:
            return fail("NAT_NOT_CONVERTED", "not converted: " + "; ".join(problems))
        if any(6 in transform.families(self.p, m) and 4 not in transform.families(self.p, m) for m in members if m != ANY):
            return fail("NAT_IPV6", "NAT rules are written for IPv4 only")
        classes = self._nat_classes(nat)
        if classes is None:
            return fail("NAT_SERVICE", f"service '{nat.service}' is not a TCP, UDP or SCTP service")
        sources = self._static_spec(nat.sources, f"nat_src_{nat.name}", f"source of NAT rule {nat.name}")
        destinations = self._static_spec(nat.destinations, f"nat_dst_{nat.name}", f"destination of NAT rule {nat.name}")
        if sources is None or destinations is None:
            return fail("NAT_ADDRESSES", "the rule needs static IPv4 addresses as source and destination")
        pair = transform.bidirectional_pair(self.p, nat)
        if source is not None and source.bidirectional and source.kind == SnatKind.STATIC and destination is None:
            return self._one_to_one(nat, plan, pair, destinations, classes)
        arriving: List[str] = []
        if destination is not None:
            zones = nat.src_zones if nat.src_zones != [ANY] else nat.dst_zones if nat.dst_zones != [ANY] else [self.options.nat_zone or ANY]
            arriving = self._nat_interfaces(zones, problems)
            if nat.src_zones == [ANY] and nat.dst_zones != [ANY]:
                plan.findings.append(
                    (Severity.APPROX, "NAT_INPUT_INTERFACE", "the rule is for traffic from every zone; a port forward of "
                     "pfSense is for one interface, and it is written for " + ", ".join(arriving) + ", where its address lies")  # fmt: skip
                )
            if problems or not arriving:
                return fail("NAT_INTERFACE", "; ".join(problems) or "the rule names no zone its traffic arrives from, and no "
                            "interface is known to put the port forward on: name one with --target-nat-zone")  # fmt: skip
            target = transform.address_intervals(self.p, destination.address)
            if not target or len(target) != 1 or target[0][0] != 4 or size(target[0]) != 1:
                return fail("NAT_DESTINATION", "a port forward of pfSense sends to one IPv4 address")
            if destination.port and (not valid_port(destination.port) or classes == [_Class()]):
                return fail("NAT_PORT", "a port translation needs a TCP, UDP or SCTP service on the rule, and one port to translate to")
            host = str(int_to_ip(4, target[0][1]))
            for cls in classes:
                for item in _items(cls.dst) or [""]:
                    if destination.port and "-" in item:
                        return fail("NAT_PORT", f"ports {item} translated to the one port {destination.port}: pfSense maps a range of ports to a range")
                    for interface in arriving:
                        plan.forwards.append(self._forward_node(nat, interface, cls, item, sources, destinations, host, destination.port))
            plan.summary.append(f"{len(plan.forwards)} port forward{'s' if len(plan.forwards) != 1 else ''}")
        if source is not None or destination is None:
            zones = nat.dst_zones
            if destination is not None or zones == [ANY]:
                # After a translation of the destination the traffic leaves where the new address is, which the rule does not say.
                zones = [self.options.nat_zone] if self.options.nat_zone else [z for z in self.universe if destination is not None and self.interfaces.get(z, [z])[0] not in arriving]
                if destination is not None and nat.dst_zones != [ANY] and zones:
                    plan.findings.append(
                        (Severity.APPROX, "NAT_OUTPUT_INTERFACE", "the rule also translates the destination, so the traffic "
                         "does not leave by " + ", ".join(nat.dst_zones) + "; its source translation is written for "
                         + ", ".join(zones))  # fmt: skip
                    )
            leaving = self._nat_interfaces(zones, problems) if zones else []
            if problems or not leaving:
                return fail("NAT_INTERFACE", "; ".join(problems) or "the rule names no zone its traffic leaves by: outbound NAT "
                            "of pfSense is per interface. Name one with --target-nat-zone")  # fmt: skip
            target_nodes: Optional[List[_X]] = []
            if source is not None:
                target_nodes = self._translation(nat, plan)
                if target_nodes is None:
                    return fail("NAT_POOL", "the translated source is not an IPv4 address, a network or a short list of them")
            if nat.src_zones != [ANY]:
                severity = Severity.REVIEW if sources.kind == "any" else Severity.APPROX
                plan.findings.append(
                    (severity, "NAT_INPUT_INTERFACE", "the rule applied to traffic from " + ", ".join(nat.src_zones)
                     + " only; outbound NAT of pfSense cannot match the interface traffic arrived on, so it applies to "
                     "traffic from every interface")  # fmt: skip
                )
            after = destinations
            if destination is not None:
                after = _Spec("address", str(int_to_ip(4, (transform.address_intervals(self.p, destination.address) or [FULL_V4])[0][1])))
                plan.findings.append(
                    (Severity.APPROX, "NAT_AFTER_DNAT", "the source translation of this rule is matched after its "
                     "destination translation; it also applies to traffic from the same sources that is sent to the "
                     "translated address directly")  # fmt: skip
                )
            for cls in classes:
                moved = cls if destination is None or not destination.port else _Class(cls.protocol, cls.src, destination.port)
                for src_item in _items(moved.src) or [""]:
                    for dst_item in _items(moved.dst) or [""]:
                        for interface in leaving:
                            plan.outbound.append(self._outbound_node(nat, interface, moved, src_item, dst_item, sources, after, target_nodes or []))
            plan.summary.append(f"{len(plan.outbound)} outbound NAT rule{'s' if len(plan.outbound) != 1 else ''}")
        return plan

    def _one_to_one(self, nat: NatRule, plan: _NatPlan, pair: Optional[Tuple[Interval, Interval]], destinations: _Spec, classes: List[_Class]) -> _NatPlan:
        if pair is None or classes != [_Class()]:
            return _NatPlan(problem=("NAT_BIDIRECTIONAL", "a 1:1 rule of pfSense maps one IPv4 address or network to another "
                                     "of the same size, for every service", Severity.REVIEW))  # fmt: skip
        inside, outside = pair
        networks = _networks([inside])
        if len(networks) != 1 or len(_networks([outside])) != 1:
            return _NatPlan(problem=("NAT_BIDIRECTIONAL", "a 1:1 rule of pfSense maps networks, and these addresses are no "
                                     "network", Severity.REVIEW))  # fmt: skip
        problems: List[str] = []
        zones = nat.dst_zones if nat.dst_zones != [ANY] else [self.options.nat_zone or ANY]
        interfaces = self._nat_interfaces(zones, problems)
        if problems or not interfaces:
            return _NatPlan(problem=("NAT_INTERFACE", "; ".join(problems) or "the rule names no zone its outside address lies "
                                     "in: name the interface with --target-nat-zone", Severity.REVIEW))  # fmt: skip
        for interface in interfaces:
            node = _X("onetoone")
            if not nat.enabled:
                node.add("disabled")
            node.add("external", str(int_to_ip(4, outside[1])))
            node.add("descr", nat.name, cdata=True)
            node.add("interface", interface)
            node.children.append(self._side_node("source", _Spec("address", networks[0])))
            node.children.append(self._side_node("destination", destinations))
            node.add("ipprotocol", "inet")
            node.add("natreflection", "disable")
            plan.one_to_one.append(node)
        if nat.src_zones != [ANY]:
            plan.findings.append(
                (Severity.INFO, "NAT_INPUT_INTERFACE", "the rule names the zone of the inside address ("
                 + ", ".join(nat.src_zones) + "), which a 1:1 rule of pfSense has no place for")  # fmt: skip
            )
        plan.summary.append("1:1 NAT")
        return plan

    def _forward_node(self, nat: NatRule, interface: str, cls: _Class, item: str, sources: _Spec, destinations: _Spec, host: str, port: str) -> _X:
        node = _X("rule")
        if not nat.enabled:
            node.add("disabled")
        ported = cls.protocol in ("tcp", "udp", "tcp/udp", "sctp")
        node.children.append(self._side_node("source", sources, self._port(cls.src) if ported else ""))
        node.children.append(self._side_node("destination", destinations, item if ported else ""))
        node.add("ipprotocol", "inet")
        node.add("protocol", cls.protocol or "any")
        node.add("target", host)
        if ported and item:
            node.add("local-port", port or item.split("-")[0])
        node.add("interface", interface)
        node.add("descr", nat.name, cdata=True)
        node.add("associated-rule-id")
        node.add("natreflection", "disable")
        return node

    def _translation(self, nat: NatRule, plan: _NatPlan) -> Optional[List[_X]]:
        """The elements that say what the source becomes; None when pfSense cannot say it."""
        source = nat.source_translation
        assert source is not None
        if source.kind == SnatKind.INTERFACE:
            return [_X("target", "INTERFACE"), _X("target_subnet")]
        pool: List[Interval] = []
        for address in source.addresses:
            resolved = transform.address_intervals(self.p, address)
            if not resolved or any(interval[0] != 4 for interval in resolved):
                return None
            pool += resolved
        networks = _networks(pool)
        if not networks:
            return None
        out: List[_X] = []
        if len(networks) == 1:
            network = ipaddress.ip_network(networks[0])
            out = [_X("target", str(network.network_address)), _X("target_subnet", str(network.prefixlen))]
            if source.kind == SnatKind.STATIC and network.num_addresses > 1:
                out.append(_X("poolopts", "bitmask"))
        else:
            hosts = [str(int_to_ip(4, value)) for _, first, last in normalize(pool) for value in range(first, min(last, first + 256) + 1)]
            if len(hosts) > 256 or source.kind == SnatKind.STATIC:
                return None
            alias = self._list_alias(hosts, f"nat_pool_{nat.name}", f"addresses NAT rule {nat.name} translates to")
            out = [_X("target", alias), _X("target_subnet"), _X("poolopts", "round-robin")]
        if source.kind in (SnatKind.DYNAMIC, SnatKind.STATIC):
            out.append(_X("staticnatport"))
        if source.kind == SnatKind.DYNAMIC:
            plan.findings.append(
                (Severity.APPROX, "NAT_STATIC_PORT", "address translation without port translation is written with "
                 "'Static port': pfSense keeps the source port and still shares the addresses between connections")  # fmt: skip
            )
        if source.kind == SnatKind.STATIC and len(networks) == 1 and ipaddress.ip_network(networks[0]).num_addresses == 1:
            inside = [i for member in nat.sources for i in transform.known_intervals(self.p, member)[0]]
            if sum(size(i) for i in inside) != 1:
                plan.findings.append(
                    (Severity.APPROX, "NAT_STATIC_RANGE", "static NAT of several addresses to one becomes a translation "
                     "to that address that keeps the source port")  # fmt: skip
                )
        return out

    def _outbound_node(self, nat: NatRule, interface: str, cls: _Class, src: str, dst: str, sources: _Spec, destinations: _Spec, target: List[_X]) -> _X:
        node = _X("rule")
        if not nat.enabled:
            node.add("disabled")
        node.children.append(_X("source", children=[_X("network", "any" if sources.kind == "any" else self._as_network(sources.value))]))
        node.add("sourceport", src.replace("-", ":"))
        node.add("descr", nat.name, cdata=True)
        for element in target:
            if element.tag in ("target", "target_subnet"):
                node.add(element.tag, f"{interface}ip" if element.text == "INTERFACE" else element.text)
        if not target:
            node.add("target")
            node.add("target_subnet")
        node.add("interface", interface)
        node.add("poolopts", next((element.text for element in target if element.tag == "poolopts"), ""))
        node.add("source_hash_key")
        if any(element.tag == "staticnatport" for element in target):
            node.add("staticnatport")
        if not target:
            node.add("nonat")
        if cls.protocol:
            node.add("protocol", cls.protocol)
        node.add("ipprotocol", "inet")
        if destinations.kind == "any":
            node.children.append(_X("destination", children=[_X("any")]))
        else:
            node.children.append(_X("destination", children=[_X("network", self._as_network(destinations.value))]))
        if dst:
            node.add("dstport", dst.replace("-", ":"))
        return node

    def _as_network(self, value: str) -> str:
        """An address as outbound NAT keeps it: with its prefix length. An alias stays as it is, unless its name has
        "opt" in it, which filter.inc takes for the name of an interface there: then an alias holds it."""
        try:
            return f"{ipaddress.ip_address(value)}/32"
        except ValueError:
            pass
        if "opt" not in value or value in self.keywords.values():
            return value  # (a word of pfSense, opt1 among them, is what it is)
        if ("opt", value) not in self.lists:
            name = unique("nat_set", self.taken, self.NAMES)
            counter = 1
            while "opt" in name:
                name = unique(f"nat_set_{counter}", self.taken, self.NAMES)
                counter += 1
            self._alias(name, "network", [value], f"holds {value} for outbound NAT")
            self.lists[("opt", value)] = name
        return self.lists[("opt", value)]

    def _pairs(self) -> Dict[str, NatRule]:
        """The two halves a pfSense source has for a 1:1 rule: the origin of the first -> the second."""
        out: Dict[str, NatRule] = {}
        rules = self.p.nat_rules
        for first, second in zip(rules, rules[1:]):
            arriving, leaving = first.destination_translation, second.source_translation
            if arriving is None or leaving is None or first.source_translation or second.destination_translation:
                continue
            if leaving.kind != SnatKind.STATIC or leaving.bidirectional or arriving.port or arriving.spread:
                continue
            if first.service != ANY or second.service != ANY or first.enabled != second.enabled or first.unsupported or second.unsupported:
                continue
            if first.destinations != leaving.addresses or second.sources != [arriving.address] or first.dst_zones != second.dst_zones:
                continue
            if first.sources != second.destinations or second.src_zones != [ANY] or first.dst_zones == [ANY] or any(first is half for half in out.values()):
                continue
            out[first.origin] = second
        return out

    def plans(self) -> List[Tuple[List[str], NatRule, _NatPlan]]:
        """(origins, rule, what it becomes) for every NAT rule; the two halves of a 1:1 rule of pfSense are one."""
        out: List[Tuple[List[str], NatRule, _NatPlan]] = []
        pairs = self._pairs() if self.native else {}
        halves = {second.origin for second in pairs.values()}
        for nat in self.p.nat_rules:
            if nat.origin in halves:
                continue  # written with its first half
            whole = nat
            if nat.origin in pairs:
                whole = copy.deepcopy(pairs[nat.origin])
                whole.name = nat.name[: -len(" - inbound")] if nat.name.endswith(" - inbound") else nat.name
                assert whole.source_translation is not None
                whole.source_translation.bidirectional = True
            out.append(([nat.origin] + ([pairs[nat.origin].origin] if nat.origin in pairs else []), nat, self.nat_plan(whole)))
        return out

    def _nat(self) -> _X:
        section = _X("nat")
        forwards: List[_X] = []
        one_to_one: List[_X] = []
        outbound: List[_X] = []
        for origins, nat, plan in self.plans():
            for origin in origins:
                if plan.problem is not None:
                    self.report.skip("nat", origin, *plan.problem)
                    continue
                for severity, code, message in plan.findings:
                    self.report.add("nat", origin, severity, code, message)
                if not nat.enabled:
                    self.report.add("nat", origin, Severity.INFO, "NAT_DISABLED", "disabled in the source; written disabled")
                self.report.item("nat", origin).emitted_as = list(plan.summary)
            if plan.problem is not None:
                continue
            forwards += plan.forwards
            one_to_one += plan.one_to_one
            outbound += plan.outbound
            self.snat_interfaces |= {child.text for node in plan.outbound + plan.one_to_one for child in node.children if child.tag == "interface"}
        self.nat_counts = (len(forwards), len(one_to_one), len(outbound))
        self.nat_written = bool(forwards or one_to_one or outbound)
        if forwards or one_to_one or outbound:
            mode = _X("outbound")
            mode.add("mode", "advanced" if outbound else "disabled")
            mode.children += outbound
            section.children.append(mode)
            section.children += forwards + one_to_one
        return section

    # -- output ------------------------------------------------------------------------------------

    def run(self) -> str:
        nat = self._nat()
        written = {nat_rule.origin for nat_rule in self.p.nat_rules if not self.report.item("nat", nat_rule.origin).skipped}
        transform.note_nat_order(self.p, self.report, written, "per-direction")
        for rule in self.p.rules:
            self._rule(rule)
        self._default()
        self._notes()
        root = _X("pfsense")
        if self.aliases:
            root.children.append(_X("aliases", children=list(self.aliases.values())))
        if nat.children:
            root.children.append(nat)
        rules = list(self.floating)
        for interface in transform.dedupe([i for names in self.interfaces.values() for i in names] + list(self.tabs)):
            rules += self.tabs.get(interface, [])
        if rules:
            root.children.append(_X("filter", children=rules))
        if not root.children:
            root.add("filter")
        head = [
            '<?xml version="1.0"?>',
            "<!-- Generated by FWShift - review the conversion report before restoring this.",
            "     The areas Aliases, NAT and Firewall Rules of a pfSense configuration, for Diagnostics, Backup and Restore:",
            "     choose the area under 'Restore area' and restore this file once per area, the aliases first.",
            "     Each restore REPLACES that area of the firewall: its rules, its aliases, its NAT rules and outbound NAT mode. -->",
        ]
        return "\n".join(head + root.lines()) + "\n"

    def _default(self) -> None:
        if self.p.default_interzone != Action.ALLOW:
            return
        for interface in transform.dedupe([i for names in self.interfaces.values() for i in names if valid_interface(i)]):
            node = _X("rule")
            node.add("id")
            self.tracker += 1
            node.add("tracker", str(self.tracker))
            node.add("type", "pass")
            node.add("interface", interface)
            node.add("ipprotocol", "inet46")
            node.add("statetype", "keep state", cdata=True)
            node.children.append(self._side_node("source", _Spec("any")))
            node.children.append(self._side_node("destination", _Spec("any")))
            node.add("descr", "FWSHIFT: the source accepts what no rule matches", cdata=True)
            self.tabs.setdefault(interface, []).append(node)

    def _notes(self) -> None:
        note = self.report.note
        forwards, one_to_one, outbound = self.nat_counts
        if forwards or one_to_one or outbound:
            mode = (
                f"sets outbound NAT to manual mode with the {outbound} rule{'s' if outbound != 1 else ''} of the source"
                if outbound else "switches outbound NAT off, as the source translates no source address"
            )  # fmt: skip
            nat_text = f"The NAT area holds {forwards} port forward{'s' if forwards != 1 else ''} and {one_to_one} 1:1 rule{'s' if one_to_one != 1 else ''}, and {mode}"
        else:
            nat_text = "There is no NAT area in the file: the NAT of the firewall stays as it is"
        note(
            Severity.REVIEW, "PFSENSE_RESTORE",
            "the output holds the areas Aliases, NAT and Firewall Rules of a pfSense configuration. Under Diagnostics > "
            "Backup & Restore, restore the file once per area, the aliases first. Each restore replaces that area of the "
            "firewall with what the file holds: every rule, every alias, every NAT rule that is there now is gone, with "
            "the separators, the rules pfSense linked to port forwards and the setting to bypass the rules for static "
            "routes. What the interfaces say (Block private networks, Block bogon networks) stays as it is on the "
            "firewall. " + nat_text + ". Keep a backup, and look at "
            "the rules before anything depends on them: pfSense does not check what it restores, and a rule it cannot "
            "resolve is not loaded. Written for pfSense 2.7 and later",
        )  # fmt: skip
        if self.unknown:
            note(
                Severity.REVIEW, "INTERFACES_REQUIRED",
                "pfSense loads a rule only for an interface or an interface group it has. These zones are neither wan, lan "
                "nor an optN: map each to its interface with --zone-map (or its interfaces with --interface-map), or "
                "create an interface group of that name on the firewall: " + ", ".join(self.unknown),
            )  # fmt: skip
        if self.self_excluded:
            note(
                Severity.INFO, "SELF_EXCLUDED",
                "on pfSense the rules of an interface are also the rules for traffic to the firewall itself. Rules of the "
                "source that pass traffic to any destination are written for any destination but the firewall itself "
                "('not This Firewall'). A rule that names addresses of the firewall still reaches them",
            )
        if self.unnamed:
            note(
                Severity.REVIEW, "INTERFACE_NAME",
                "rules for every zone were written for the interfaces pfSense can name, and not for " + ", ".join(self.unnamed)
                + ": map those zones to wan, lan or an optN with --zone-map. No rule at all is written for them",
            )
        strangers = [zone for zone in self.options.zone_networks if zone not in self.known_zones]
        if strangers:
            note(
                Severity.REVIEW, "ZONE_NETWORK_UNKNOWN",
                "--zone-network names zones the policy does not know: " + ", ".join(strangers) + ". They were taken as "
                "further interfaces of the firewall, and rules for other zones leave their networks out. Check the "
                "names: they are the names after --zone-map",
            )
        if self.implied and not self.native:
            note(
                Severity.INFO, "EGRESS_IMPLIED",
                "the source rules name no interface traffic leaves by either; destination zones FWShift had worked out "
                "for them were left out again",
            )
        if self.gap_used:
            note(
                Severity.APPROX, "ZONE_NETWORK_GAP",
                "the networks given with --zone-network do not cover every address: " + ", ".join(_networks(self.areas.nowhere)[:6])
                + ". Rules that pass traffic to a zone leave those addresses out, rules that block keep them",
            )
        if self.p.default_interzone == Action.ALLOW:
            note(
                Severity.REVIEW, "INTERZONE_DEFAULT",
                "the source accepts what no rule matches; a rule that passes everything was added at the end of every "
                "interface",
            )
        if self.p.default_intrazone == Action.ALLOW and self.p.default_interzone != Action.ALLOW:
            note(
                Severity.REVIEW, "INTRAZONE_DEFAULT",
                "the source allows traffic inside a zone unless a rule denies it; on pfSense traffic that leaves by the "
                "interface it came in on, or goes from one interface of a zone to another, is dropped unless a rule "
                "passes it",
            )
        open_zones = [zone.name for zone in self.p.zones.values() if zone.intrazone_allow]
        if open_zones and self.p.default_interzone != Action.ALLOW and self.p.default_intrazone != Action.ALLOW:
            note(
                Severity.REVIEW, "INTRAZONE_ALLOW",
                "these zones allow traffic between their own interfaces on the source without a rule; no rule was "
                "written for that: " + ", ".join(open_zones),
            )
        if any(rule.schedule for rule in self.p.rules) and self.native:
            note(
                Severity.INFO, "SCHEDULES_NOT_WRITTEN",
                "schedules are not part of the three areas the file holds: rules with a schedule are written disabled",
            )


def valid_port(text: str) -> bool:
    return text.isdigit() and 1 <= int(text) <= 65535
