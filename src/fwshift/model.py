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
    # FQDN only: 4 or 6 when the source resolves the name for one IP version only, 0 for both.
    fqdn_family: int = 0
    # Vendor on which this object exists without a conversion creating it: predefined, or a gateway.
    builtin: str = ""


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

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"
