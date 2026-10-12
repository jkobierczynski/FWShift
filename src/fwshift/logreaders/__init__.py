# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Firewall logs, read into connections and the rules the gateway says matched them.

One module per log format. Each yields, per line, a ``Line``: a connection (``LogRecord``), or the reason the line
is not one. Nothing is skipped without a reason, and every reason is counted (docs/RULE_USAGE.md, principle 5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class LayerMatch:
    """One row of the match table of a log: the rule of one layer that the connection matched."""

    layer_uuid: str
    match_id: Optional[int]
    parent_rule: Optional[int]
    rule_uid: str = ""  # lower case, no braces; empty where the log does not say which row it belongs to
    implicit: bool = False  # the implicit cleanup of the layer: no rule, the default of the layer
    layer_name: str = ""


@dataclass
class LogRecord:
    """A connection, as the gateway logged it."""

    time: int  # UTC seconds
    gateway: str  # the name of the gateway object (the CN of its SIC name), or its address
    src: str  # the addresses of the original packet; empty where the log does not give one
    dst: str
    protocol: int  # IANA number; -1 where the log does not give one
    port: Optional[int]  # destination port (TCP, UDP, SCTP), ICMP type (ICMP, ICMPv6); None for other protocols or not given
    action: str
    layers: List[LayerMatch] = field(default_factory=list)  # outer layer first
    # Rule uids of the line when they cannot be put on their rows (the log leaves some out): a rule named here
    # counts as used, and nothing more is claimed.
    loose_uids: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    count: int = 1  # connections the line stands for (an aggregated log)
    gateway_address: str = ""
    # The zones the connection came in and went out by, where the log gives them (iptables: the interfaces).
    in_zone: str = ""
    out_zone: str = ""


@dataclass
class Line:
    """What one line of a log is: a connection, or why it is not one."""

    record: Optional[LogRecord] = None
    reason: str = ""  # why it is not a connection that names a rule
    # True when the line may have been a connection of some rule that could not be read: it weakens every claim
    # that a rule was not used. False for what is known not to be such a connection (an update, a VPN event).
    doubt: bool = False
    time: Optional[int] = None  # when and from where, where the line says: this is what shows a gateway was logging
    gateway: str = ""


__all__ = ["LayerMatch", "Line", "LogRecord"]
