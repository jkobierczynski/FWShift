# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Hit counters from a file of their own, put on the rules they count.

Two answers are read, as the firewalls give them:

* PAN-OS: the XML API answer of ``show rule-hit-count vsys vsys-name <vsys> rule-base security rules all``.
  Rules by name; times in seconds, 0 for never. The creation and modification times of a rule are kept as the day it
  was last changed (``Rule.changed``), where the configuration does not say: what proving it unused from logs needs.
* FortiOS: the answer of ``GET /api/v2/monitor/firewall/policy``, one VDOM or an array of VDOMs.
  Policies by uuid, or by policy ID where the configuration has no uuid; times in seconds.

A Check Point rulebase exported with ``show-hits`` carries its counters itself (parsers/checkpoint.py).

A counter is matched to a rule by the identifiers the parser kept (``Rule.source_ids``), never by position.
Two files that count the same rule (two firewalls of one device group) are added up.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from . import xmlread
from .errors import FwshiftError, ParseError
from .model import HitCount, Policy

_PANOS_DEFAULTS = ("intrazone-default", "interzone-default")  # counted by PAN-OS, not rules of the configuration
_MAX_COUNTERS = 200_000
_FORTIOS_NOTE = ("a FortiGate starts its counters again when they are cleared, and a model without a disk when it restarts; "
                 "the answer does not say when that last happened")  # fmt: skip


@dataclass
class Applied:
    """What a file of counters did: the rules it counted, and what it names that the policy does not have."""

    source: str
    counted: int = 0
    unknown: List[str] = field(default_factory=list)  # rules the file counts and the policy does not have
    partial: str = ""  # why the counters may not cover every firewall the rules are on
    rules: Set[str] = field(default_factory=set)  # origins of the rules that got a counter

    def text(self) -> str:
        out = f"{self.source}: counters of {self.counted} rule(s)"
        if self.unknown:
            shown = ", ".join(f"'{name}'" for name in self.unknown[:8]) + (f" and {len(self.unknown) - 8} more" if len(self.unknown) > 8 else "")
            out += f"; it also counts {len(self.unknown)} rule(s) the policy does not have ({shown}): are the counters and the configuration from the same moment?"
        if self.partial:
            out += f"; {self.partial}"
        return out


def apply(policy: Policy, data: bytes, name: str) -> Applied:
    """Read a file of counters and put each counter on the rule it counts."""
    head = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    changed: Dict[str, int] = {}  # PAN-OS: rule name -> when it was created or last changed
    if head.startswith(b"<"):
        counters, scope, partial = _panos(policy, data, name, changed)
        key = "panos.name"
    elif head.startswith((b"{", b"[")):
        counters, scope, partial = _fortios(policy, data, name)
        key = ""
    else:
        raise FwshiftError(f"--hits {name}: neither the XML answer of PAN-OS 'show rule-hit-count' nor the JSON answer of the "
                           "FortiOS monitor 'firewall/policy'")  # fmt: skip
    applied = Applied(f"{name} ({scope})" if scope else name, partial=partial)
    moments = [moment for _, count in counters for moment in (count.first_hit, count.last_hit, count.counting_since) if moment is not None]
    read_until = max(moments) if moments else None
    by_id: Dict[Tuple[str, str], List[Any]] = {}
    for rule in policy.rules:
        for id_key, value in rule.source_ids.items():
            by_id.setdefault((id_key, value), []).append(rule)
    for ids, count in counters:
        rules: List[Any] = []
        for position, (id_key, value) in enumerate(ids):
            rules = by_id.get((key or id_key, value), [])
            # A rule found by a weaker identifier whose stronger one says otherwise is another rule (a policy ID
            # taken again on another device, with a uuid of its own).
            rules = [rule for rule in rules if all(rule.source_ids.get(earlier, other) == other for earlier, other in ids[:position])]
            if rules:
                break
        if not rules:
            applied.unknown.append(ids[0][1] if ids else "?")
            continue
        applied.counted += 1
        count.read_from, count.read_until = applied.source, read_until
        for rule in rules:
            applied.rules.add(rule.origin or rule.name)
            if ids and ids[0][1] in changed:
                # What a log of use needs to know: the rule has been as it is since then (the latest, of several firewalls).
                rule.changed = max(rule.changed or 0, changed[ids[0][1]])
            rule.hits = count if rule.hits is None else _added(rule.hits, count)
            if partial:
                rule.hits.complete = False
                if partial not in rule.hits.note:
                    rule.hits.note = "; ".join(part for part in (rule.hits.note, partial) if part)
    return applied


def _added(a: HitCount, b: HitCount) -> HitCount:
    """Two counters of one rule (two firewalls): the sum, over the time both have counted."""

    def first(x: Optional[int], y: Optional[int]) -> Optional[int]:
        return y if x is None else x if y is None else min(x, y)

    def last(x: Optional[int], y: Optional[int]) -> Optional[int]:
        return y if x is None else x if y is None else max(x, y)

    # Zero on both is zero over the time both counted: from the later start to the earlier reading.
    since = None if a.counting_since is None or b.counting_since is None else max(a.counting_since, b.counting_since)
    until = None if a.read_until is None or b.read_until is None else min(a.read_until, b.read_until)
    where = a.read_from if a.read_from == b.read_from else f"{a.read_from} and {b.read_from}"
    note = "; ".join(dict.fromkeys(part for part in (a.note, b.note) if part))
    return HitCount(a.count + b.count, first(a.first_hit, b.first_hit), last(a.last_hit, b.last_hit), since, where, note,
                    a.complete and b.complete, until, last(a.covers_from, b.covers_from))


def _whole(text: Optional[str], what: str, name: str) -> int:
    value = (text or "").strip()
    if not re.fullmatch(r"[0-9]{1,18}", value):
        raise ParseError(f"--hits {name}: {what} is not a whole number: '{value[:30]}'")
    return int(value)


def _panos(policy: Policy, data: bytes, name: str, changed: Dict[str, int]) -> Tuple[List[Tuple[List[Tuple[str, str]], HitCount]], str, str]:
    root = xmlread.fromstring(data, "the answers of the PAN-OS XML API")
    if root.tag != "response":
        raise ParseError(f"--hits {name}: XML that is not an answer of the PAN-OS XML API (<{root.tag[:30]}>)")
    if root.get("status") != "success":
        raise ParseError(f"--hits {name}: the answer says status '{root.get('status', '')[:20]}', not success")
    if root.find("result/rule-hit-count/device-group") is not None or root.find("result/rule-hit-count/shared") is not None:
        raise FwshiftError(f"--hits {name}: this is the answer of Panorama, which counts rules per device group and not per "
                           "firewall; give the answers of the firewalls themselves (one --hits per firewall)")  # fmt: skip
    if policy.vendor != "panos":
        raise FwshiftError(f"--hits {name}: hit counters of PAN-OS, for a policy read from {policy.vendor}")
    vsys_entries = root.findall("result/rule-hit-count/vsys/entry")
    if not vsys_entries:
        raise ParseError(f"--hits {name}: no <rule-hit-count><vsys> in the answer: is it the answer of 'show rule-hit-count vsys "
                         "vsys-name ... rule-base security rules all'?")  # fmt: skip
    panorama = policy.scope.startswith("device-group ") or policy.scope == "shared"
    if not panorama:
        vsys_entries = [entry for entry in vsys_entries if entry.get("name") == policy.scope] or vsys_entries
        named = sorted({entry.get("name", "") for entry in vsys_entries})
        if policy.scope and named != [policy.scope]:
            raise FwshiftError(f"--hits {name}: counters of virtual system {', '.join(named)}, for a policy of {policy.scope}")
    out: List[Tuple[List[Tuple[str, str]], HitCount]] = []
    seen: Dict[str, int] = {}
    for vsys in vsys_entries:
        for base in vsys.findall("rule-base/entry"):
            if base.get("name") != "security":
                continue
            for entry in base.findall("rules/entry"):
                rule = entry.get("name", "")
                if not rule or rule in _PANOS_DEFAULTS:
                    continue
                if rule in seen:
                    raise ParseError(f"--hits {name}: the answer counts rule '{rule[:60]}' twice")
                seen[rule] = 1
                if len(seen) > _MAX_COUNTERS:
                    raise ParseError(f"--hits {name}: more than {_MAX_COUNTERS} counters")

                def moment(tag: str) -> Optional[int]:
                    value = _whole(entry.findtext(tag), f"<{tag}> of rule '{rule[:60]}'", name) if entry.find(tag) is not None else 0
                    return value or None  # 0: never

                count = _whole(entry.findtext("hit-count"), f"<hit-count> of rule '{rule[:60]}'", name)
                # The rule as it stands has been counted since the latest of its reset, creation and change.
                since = [value for value in (moment("last-reset-timestamp"), moment("rule-creation-timestamp"),
                                             moment("rule-modification-timestamp")) if value is not None]  # fmt: skip
                made = [value for value in (moment("rule-creation-timestamp"), moment("rule-modification-timestamp")) if value is not None]
                if made:
                    changed[rule] = max(made)
                out.append(([("panos.name", rule)], HitCount(count, moment("first-hit-timestamp"), moment("last-hit-timestamp"),
                                                               max(since) if since else None)))  # fmt: skip
    if not seen:
        raise ParseError(f"--hits {name}: the answer counts no rule of the security rulebase")
    partial = ""
    if panorama:
        partial = (f"the counters are those of one firewall, for a policy of Panorama ({policy.scope}): a rule pushed to "
                   "several firewalls is counted only on the firewalls whose answers were given")  # fmt: skip
    return out, "vsys " + ", ".join(sorted({entry.get("name", "") for entry in vsys_entries})), partial


def _fortios(policy: Policy, data: bytes, name: str) -> Tuple[List[Tuple[List[Tuple[str, str]], HitCount]], str, str]:
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ParseError(f"--hits {name}: not valid JSON: {str(exc)[:120]}") from None
    if policy.vendor != "fortios":
        raise FwshiftError(f"--hits {name}: hit counters of FortiOS, for a policy read from {policy.vendor}")
    envelopes = document if isinstance(document, list) else [document]
    if not all(isinstance(envelope, dict) and isinstance(envelope.get("results"), list) for envelope in envelopes) or not envelopes:
        raise ParseError(f"--hits {name}: not the answer of the FortiOS monitor 'firewall/policy' (an object with 'results', or an "
                         "array of them, one per VDOM)")  # fmt: skip
    bad = [str(envelope.get("status")) for envelope in envelopes if envelope.get("status") not in (None, "success")]
    if bad:
        raise ParseError(f"--hits {name}: the answer says status '{bad[0][:20]}', not success")
    vdoms = [str(envelope.get("vdom") or "") for envelope in envelopes]
    if policy.scope and policy.scope in vdoms:
        envelopes = [envelope for envelope, vdom in zip(envelopes, vdoms) if vdom == policy.scope][:1]
    elif len(envelopes) > 1:
        raise FwshiftError(f"--hits {name}: counters of several VDOMs ({', '.join(vdoms)}) and none is "
                           f"{policy.scope or 'the VDOM of the policy'}")  # fmt: skip
    elif policy.scope and vdoms[0] and vdoms[0] != policy.scope:
        raise FwshiftError(f"--hits {name}: counters of VDOM {vdoms[0]}, for a policy of VDOM {policy.scope}")
    out: List[Tuple[List[Tuple[str, str]], HitCount]] = []
    seen: Dict[str, int] = {}
    unnamed = bool(policy.scope) and not envelopes[0].get("vdom")  # an answer that names no VDOM, for a policy of one
    for entry in envelopes[0]["results"]:
        if not isinstance(entry, dict):
            raise ParseError(f"--hits {name}: an entry of 'results' that is not an object")
        policyid = entry.get("policyid")
        if not isinstance(policyid, int) or isinstance(policyid, bool) or policyid < 0:
            raise ParseError(f"--hits {name}: an entry without a policy ID ('policyid')")
        if str(policyid) in seen:
            raise ParseError(f"--hits {name}: the answer counts policy {policyid} twice")
        seen[str(policyid)] = 1
        if len(seen) > _MAX_COUNTERS:
            raise ParseError(f"--hits {name}: more than {_MAX_COUNTERS} counters")
        count = entry.get("hit_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ParseError(f"--hits {name}: policy {policyid} has no whole number in 'hit_count'")

        def moment(key: str) -> Optional[int]:
            value = entry.get(key)
            if value is None:
                return None
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ParseError(f"--hits {name}: '{key}' of policy {policyid} is not a time in seconds")
            return value or None

        ids = [("fortios.uuid", str(entry["uuid"]))] if isinstance(entry.get("uuid"), str) and entry["uuid"] else []
        if not unnamed:
            ids.append(("fortios.policyid", str(policyid)))  # (policy IDs are per VDOM: only where the VDOM is known)
        elif not ids:
            ids.append(("fortios.policyid of an unnamed VDOM", str(policyid)))  # names no rule: listed as not in the policy
        out.append((ids, HitCount(count, moment("first_used"), moment("last_used"), None, note=_FORTIOS_NOTE)))
    vdom = str(envelopes[0].get("vdom") or "")
    return out, (f"VDOM {vdom}" if vdom else ""), ""


__all__ = ["Applied", "apply"]
