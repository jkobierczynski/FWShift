# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Vendor-neutral firewall policy model.

Every parser normalises to these semantics and every emitter may rely on them:

* Security rules match the **pre-NAT** addresses and ports of the original
  packet and the **post-NAT** destination zone (the PAN-OS convention).
* ``any`` means any address of either family. IPv4-only "any" is the literal
  ``0.0.0.0/0`` and IPv6-only "any" is ``::/0``.
* Address members of a rule are object names or literals (``10.0.0.1``,
  ``10.0.0.0/24``, ``10.0.0.1-10.0.0.9``). A name wins over a literal.
* Port lists use the PAN-OS syntax ``80,443,8000-8080``; empty means all ports.
* Application names are PAN-OS App-ID names.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

ANY = "any"
ANY_V4 = "0.0.0.0/0"
ANY_V6 = "::/0"
APP_DEFAULT = "application-default"


class AddressKind(str, Enum):
    NETWORK = "network"  # host or subnet in CIDR notation
    RANGE = "range"  # first-last
    FQDN = "fqdn"
    UNSUPPORTED = "unsupported"  # kept so that references stay resolvable


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    ICMP = "icmp"
    ICMP6 = "icmp6"
    IP = "ip"


L4_PROTOCOLS = (Protocol.TCP, Protocol.UDP, Protocol.SCTP)


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"  # vendor default deny behaviour
    DROP = "drop"  # silent drop
    RESET_CLIENT = "reset-client"
    RESET_SERVER = "reset-server"
    RESET_BOTH = "reset-both"


class RuleScope(str, Enum):
    UNIVERSAL = "universal"
    INTRAZONE = "intrazone"
    INTERZONE = "interzone"


class SnatKind(str, Enum):
    INTERFACE = "interface"  # port translation to the egress interface address
    DYNAMIC_PORT = "dynamic-ip-and-port"
    DYNAMIC = "dynamic-ip"
    STATIC = "static"


@dataclass
class Address:
    name: str
    kind: AddressKind
    value: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    # What it was in the source: for UNSUPPORTED, and for an object that stands for something of the
    # source device (builtin), such as "interface outside" for the address of an ASA interface.
    raw: str = ""
    # FQDN: 4 or 6 when the source resolves the name for one IP version only, 0 for both. For a builtin object
    # without an address of its own (a system host of a Sophos Firewall): the IP version it is of.
    fqdn_family: int = 0
    # Vendor on which this object exists without a conversion creating it: predefined, or a gateway.
    builtin: str = ""
    # The object this one is part of: the translated address of a Check Point object with automatic static NAT,
    # which rules that name the object match as well. Its use is the use of that object.
    part_of: str = ""


@dataclass
class AddressGroup:
    name: str
    members: List[str] = field(default_factory=list)
    description: str = ""
    tags: List[str] = field(default_factory=list)
    dynamic_filter: str = ""  # non-empty: tag-based dynamic group
    unsupported: str = ""  # non-empty: reason the group cannot be converted
    builtin: str = ""


@dataclass
class ServiceEntry:
    protocol: Protocol
    dst_ports: str = ""
    src_ports: str = ""
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    ip_protocol: Optional[int] = None  # Protocol.IP only; None = any protocol


@dataclass
class Service:
    name: str
    entries: List[ServiceEntry] = field(default_factory=list)
    description: str = ""
    tags: List[str] = field(default_factory=list)
    builtin: str = ""  # vendor that predefines this object, if any
    unsupported: str = ""  # non-empty: reason the service cannot be converted as it is


@dataclass
class ServiceGroup:
    name: str
    members: List[str] = field(default_factory=list)
    description: str = ""
    tags: List[str] = field(default_factory=list)
    builtin: str = ""


@dataclass
class Zone:
    name: str
    interfaces: List[str] = field(default_factory=list)
    intrazone_allow: Optional[bool] = None  # None = vendor default


@dataclass
class HitCount:
    """The hit counter a firewall keeps for a rule: how often it matched, in the period it counted.

    Times are UTC, in seconds since 1970. None: no such time (never hit), or the source does not say.
    """

    count: int
    first_hit: Optional[int] = None
    last_hit: Optional[int] = None
    # Since when the counter counts: the later of its last reset and the creation of the rule, where the source
    # tells either. None: not known, and nothing can be said about how long a zero has lasted.
    counting_since: Optional[int] = None
    read_from: str = ""  # where it was read: "the rulebase", or the name of a file of counters
    # What else limits the counter, as the source documents it (gateways that do not count, a retention period).
    note: str = ""
    # False when the counter may leave out firewalls the rule is on (one firewall's counters for a policy of
    # Panorama): then a zero proves nothing.
    complete: bool = True
    # The latest time the answer the counter came from shows: it was read no earlier. No export records when it was
    # read; this stands in for it, and makes a period shorter, never longer, than it was.
    read_until: Optional[int] = None
    # For a source that keeps counts for a period only (Check Point): the earliest time its answer is known to reach
    # back to, the earliest first hit of any rule in it. None where a counter counts from counting_since on.
    covers_from: Optional[int] = None


@dataclass
class LogUsage:
    """What the logs of the firewall say about a rule, over a window of whole days (UTC).

    Filled by ``fwshift usage`` (usage.py) from the connections the gateway itself attributed to the rule.
    """

    first_day: str  # YYYY-MM-DD, the window
    last_day: str
    connections: int = 0  # connections that certainly went through the rule (the gateway said so, or the policy does)
    simulated: int = 0  # of those, the ones whose log named no rule: the policy says it was this one
    possible: int = 0  # connections that may have gone through the rule, or through another one: never certain
    method: str = "gateway"  # how the connections were attributed: "gateway", "simulation", "gateway and simulation"
    # Connections of the other rules the same source rule became (a cell of access roles split by users): the rule
    # of the source was used, if not this part of it.
    shared: int = 0
    # Connections per member, by cell: "source", "destination" (the members of the rule and every object they hold,
    # top-level members first), "service", "user". A negated cell has the single member "(outside the listed)".
    members: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # Members that cannot be told from an address and a port (a host name, an application, an unsupported object):
    # never called unused.
    unjudged: Dict[str, List[str]] = field(default_factory=dict)
    # Why the logs prove nothing about the rule (it does not log, a gateway sent no logs on some days, it changed
    # within the window); empty when they do.
    no_evidence: List[str] = field(default_factory=list)
    rolled_up: bool = False  # addresses beyond the limit per rule were kept as networks
    gateways: List[str] = field(default_factory=list)  # the gateways whose logs the rule depends on
    elsewhere: List[str] = field(default_factory=list)  # gateways that logged it although it is not installed there
    # What the connections through the rule (certain and possible) were, for a narrower rule (narrow.py): "source"
    # and "destination" addresses (or the networks a store kept beyond its limit), "service" as "protocol/port"
    # ("6/443", "1/8" for an ICMP type, "47/-1" where there is no port). A cell in ``blind`` had a connection that
    # did not say (no address, no port, a destination NAT), or more than can be kept: it is not narrowed.
    seen: Dict[str, List[str]] = field(default_factory=dict)
    blind: List[str] = field(default_factory=list)


@dataclass
class Rule:
    name: str
    src_zones: List[str] = field(default_factory=lambda: [ANY])
    dst_zones: List[str] = field(default_factory=lambda: [ANY])
    sources: List[str] = field(default_factory=lambda: [ANY])
    destinations: List[str] = field(default_factory=lambda: [ANY])
    services: List[str] = field(default_factory=lambda: [ANY])
    applications: List[str] = field(default_factory=lambda: [ANY])
    action: Action = Action.ALLOW
    enabled: bool = True
    scope: RuleScope = RuleScope.UNIVERSAL
    negate_source: bool = False
    negate_destination: bool = False
    negate_service: bool = False
    log_start: bool = False
    log_end: bool = True
    description: str = ""
    tags: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=lambda: [ANY])
    url_categories: List[str] = field(default_factory=lambda: [ANY])
    schedule: str = ""  # empty = always
    profiles: Dict[str, str] = field(default_factory=dict)  # reported, not converted
    # What else the source rule does with the traffic it matches and the model has no place for:
    # NAT set on a FortiOS policy, shaping, a log profile. Nothing is converted from here; the
    # audit uses it to tell whether two rules handle traffic the same way.
    handling: Dict[str, str] = field(default_factory=dict)
    unsupported: List[str] = field(default_factory=list)  # match criteria not modelled
    origin: str = ""  # stable key of the source rule, used by the report
    # True when the source rule named no destination zone and the zones here were worked out:
    # they are where its destination addresses are routed to, or every zone the source platform
    # forwards to at all. A target that cannot match the outgoing interface loses nothing by
    # leaving them out.
    egress_implied: bool = False
    # Destinations a parser added: the pre-NAT address of a translated destination the source rule
    # named, with the origins of the NAT rules it was added for. A target that looks rules up as
    # the source did takes them away again (transform.rewrite_destinations).
    nat_added: Dict[str, List[str]] = field(default_factory=dict)
    # The source platform's own identifiers of the rule, which its hit counters and logs name it by:
    # "checkpoint.rule_uid", "checkpoint.layer_uid", "checkpoint.parent_rule_uid", "panos.name", "panos.uuid",
    # "fortios.policyid", "fortios.uuid", ... A rule the parser split or combined keeps those of its source rule;
    # nothing is converted from here.
    source_ids: Dict[str, str] = field(default_factory=dict)
    # The devices the source installs the rule on, by the names the source gives them; empty: every device the
    # policy is installed on. Converted nowhere: a target is one firewall (DEVICE_TARGET says so).
    targets: List[str] = field(default_factory=list)
    hits: Optional[HitCount] = None  # the hit counter of the source rule, where the input holds one
    changed: Optional[int] = None  # when the source rule was created or last changed (UTC seconds), where the source says
    log_usage: Optional[LogUsage] = None  # what the logs say about the rule (fwshift usage)


@dataclass
class SourceNat:
    kind: SnatKind
    addresses: List[str] = field(default_factory=list)  # configured translated addresses
    interface: str = ""
    interface_address: str = ""  # INTERFACE only: address the interface had when read, if known
    bidirectional: bool = False


@dataclass
class DestNat:
    address: str
    port: str = ""
    spread: bool = False  # several addresses, one picked per connection (iptables DNAT to a range): not address for address


@dataclass
class NatRule:
    name: str
    src_zones: List[str] = field(default_factory=lambda: [ANY])
    dst_zones: List[str] = field(default_factory=lambda: [ANY])
    sources: List[str] = field(default_factory=lambda: [ANY])
    destinations: List[str] = field(default_factory=lambda: [ANY])
    service: str = ANY
    source_translation: Optional[SourceNat] = None
    destination_translation: Optional[DestNat] = None
    enabled: bool = True
    description: str = ""
    tags: List[str] = field(default_factory=list)
    unsupported: List[str] = field(default_factory=list)
    origin: str = ""
    # NAT rules are first match: one rule applies to a connection. Where the source applies a
    # rule that translates the destination together with one that translates the source
    # (iptables PREROUTING and POSTROUTING, FortiOS virtual IPs and central SNAT, Check Point
    # automatic rules), both rules carry this flag.
    combines: bool = False


@dataclass
class Policy:
    vendor: str
    scope: str = ""  # vsys, device group or VDOM the policy was read from
    addresses: Dict[str, Address] = field(default_factory=dict)
    address_groups: Dict[str, AddressGroup] = field(default_factory=dict)
    services: Dict[str, Service] = field(default_factory=dict)
    service_groups: Dict[str, ServiceGroup] = field(default_factory=dict)
    zones: Dict[str, Zone] = field(default_factory=dict)
    rules: List[Rule] = field(default_factory=list)
    nat_rules: List[NatRule] = field(default_factory=list)
    # What happens to traffic no rule matches, inside one zone and between zones.
    default_intrazone: Action = Action.DENY
    default_interzone: Action = Action.DENY
    # True when the source platform looks rules up after destination NAT. The rules
    # here are already normalised to pre-NAT addresses; an emitter for a platform of
    # the same kind uses this to tell that their services still name post-NAT ports.
    lookup_after_dnat: bool = False
    # True when a rule of the source that names the object of a destination NAT itself applied
    # to the translated traffic (a FortiOS virtual IP in a policy).
    named_translations: bool = False
    # The networks behind each zone, as the source tells them (its interfaces and static routes; 0.35.0), by the names
    # of the zones of the policy; empty where the source does not say.
    zone_networks: Dict[str, List[str]] = field(default_factory=dict)
    # The networks the source routes to no zone of the policy: an interface in no zone, a route that drops, ...
    unzoned_networks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"
