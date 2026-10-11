# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Conversion options shared by the emitters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .model import Policy


@dataclass
class Options:
    # Source zone/interface name -> name to use on the target.
    zone_map: Dict[str, str] = field(default_factory=dict)
    # Source interface name -> target interface name (zone members, interface NAT).
    interface_map: Dict[str, str] = field(default_factory=dict)
    # Extra or overriding application -> port specs, e.g. {"myapp": ["tcp/8443"]}.
    app_ports: Dict[str, List[str]] = field(default_factory=dict)
    # PAN-OS target: "" (single-vsys firewall), "vsys:NAME", "shared" or
    # "device-group:NAME".
    target_scope: str = ""
    # PAN-OS target: destination zone for NAT rules of a source that has none (Check Point, iptables).
    # ASA target: interface for source NAT to "the outgoing interface" where the rule names none.
    nat_zone: str = ""
    # FortiOS target: wrap the output in this VDOM.
    target_vdom: str = ""
    # FortiOS target: first policy id; 0 lets the FortiGate pick free ids.
    policy_id_start: int = 0
    # Check Point target: access layer the rules go into, and package whose NAT rulebase is used.
    target_layer: str = "Network"
    target_package: str = "Standard"
    # Check Point target: gateway or cluster object that "NAT to the outgoing interface" hides behind.
    target_gateway: str = ""
    # Check Point and ASA targets: prefix for the name of every object that is created.
    object_prefix: str = ""
    # ASA target: networks behind a zone, for rules that an access list can only keep to their
    # destination zone by leaving out the networks of the other zones.
    zone_networks: Dict[str, List[str]] = field(default_factory=dict)
    # When a list: an emitter adds the model it writes its output from, with the names, zones and
    # addresses as the target gets them. The audit proves what it disables on that as well.
    written: Optional[List[Policy]] = None
