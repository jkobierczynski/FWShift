# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Rule usage from firewall logs (docs/RULE_USAGE.md; 0.14.0: Check Point, by the rule the gateway names; 0.15.0: iptables, by simulation).

Three steps:

* **Reading** (``ingest``): the lines of the log files become connections, counted per day, gateway, rule, source,
  destination, protocol, port and user, in a store (SQLite). A file that is in the store already is not read
  again. Every line that is not a connection is counted by its reason; a line that may have been one (it could
  not be read) is a doubt against the gateway and day it came from, or against everything when even those are
  not known. Beyond ``cap`` addresses per rule and side (per pair of interfaces, for logs that name no rule),
  addresses are kept as their /24 (IPv4) or /64 (IPv6).
* **Attribution** (``evaluate``): over a window of whole days, each connection goes to the rule of the policy the
  gateway named: the uid of the rule, and for a rule of an inline layer the uids of every rule on the way. Then,
  inside the rule, to every object of its source and destination that holds the address (through groups, each
  once), and to every service that holds the protocol and port. A connection whose log names no rule (iptables)
  is matched against the rules of the policy (simulate.py): certain where the first rule it meets surely matches
  it, possible for every rule it may have gone through where not.
* **Evidence**: whether the logs can prove anything about a rule: it logs its connections, every gateway it is on
  sent logs on every day of the window and none of them could not be read, it did not change within the window.

The result is ``Rule.log_usage``; the audit turns it into findings (UNUSED_RULE, UNUSED_RULE_OBJECT,
UNUSED_RULE_SERVICE, NO_USAGE_EVIDENCE).
"""

from __future__ import annotations

import datetime
import hashlib
import html
import json
import os
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import transform
from .errors import FwshiftError
from .logreaders import LayerMatch, LogRecord
from .logreaders import checkpoint as checkpoint_logs
from .logreaders import iptables as iptables_logs
from .audit import _blocks
from .model import ANY, LogUsage, Policy, Protocol, Rule, ServiceEntry
from .simulate import Simulator
from .netutil import Interval, overlaps, parse_literal

FORMAT = "1"
VENDORS = {"checkpoint": "checkpoint", "iptables": "iptables"}  # the policies whose logs are read, and the reader of their logs
DEFAULT_CAP = 256
OUTSIDE = "(outside the listed)"
_FLUSH = 100_000
_PROTOCOL_NUMBERS = {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.SCTP: 132, Protocol.ICMP: 1, Protocol.ICMP6: 58}
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, policy TEXT, policy_digest TEXT, lines INTEGER, connections INTEGER,
                                 skipped TEXT);
CREATE TABLE IF NOT EXISTS files (digest TEXT PRIMARY KEY, name TEXT NOT NULL, run INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS coverage (day TEXT NOT NULL, gateway TEXT NOT NULL, lines INTEGER NOT NULL, doubtful INTEGER NOT NULL,
                                     accepts INTEGER NOT NULL, PRIMARY KEY (day, gateway));
CREATE TABLE IF NOT EXISTS unplaced (run INTEGER NOT NULL, reason TEXT NOT NULL, lines INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records (day TEXT NOT NULL, gateway TEXT NOT NULL, rule_key TEXT NOT NULL, src TEXT NOT NULL,
                                    dst TEXT NOT NULL, protocol INTEGER NOT NULL, port INTEGER NOT NULL, user TEXT NOT NULL,
                                    count INTEGER NOT NULL,
                                    PRIMARY KEY (day, gateway, rule_key, src, dst, protocol, port, user));
CREATE TABLE IF NOT EXISTS rolled (rule_key TEXT NOT NULL, side TEXT NOT NULL, PRIMARY KEY (rule_key, side));
CREATE TABLE IF NOT EXISTS kept (rule_key TEXT NOT NULL, side TEXT NOT NULL, address TEXT NOT NULL, PRIMARY KEY (rule_key, side, address));
"""
_TABLES = {"meta", "runs", "files", "coverage", "unplaced", "records", "rolled", "kept"}
_RECORD_COLUMNS = ["day", "gateway", "rule_key", "src", "dst", "protocol", "port", "user", "count"]
UNKNOWN = "(not in the log)"
_USERS = "\x1f"  # between the users of one connection in the store (a name may hold a comma)

Key = Tuple[str, str, str, str, str, int, int, str]


# -- the store --------------------------------------------------------------------------------------


class Store:
    """The connections read so far, per day; a file of its own (SQLite), or ":memory:" for one run."""

    def __init__(self, path: str, create: bool = True) -> None:
        self.path = path
        if path != ":memory:" and not create and not os.path.exists(path):
            raise FwshiftError(f"{path}: no such usage store")
        try:
            self.db = sqlite3.connect(path)
            tables = {row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            if tables and not _TABLES <= tables:
                raise FwshiftError(f"{path}: an SQLite file, but not a usage store of FWShift")
            if not tables:
                if not create:
                    raise FwshiftError(f"{path}: an empty file, not a usage store of FWShift")
                self.db.executescript(_SCHEMA)
                self.db.execute("INSERT INTO meta VALUES ('format', ?)", (FORMAT,))
                self.db.commit()
            version = self.db.execute("SELECT value FROM meta WHERE key = 'format'").fetchone()
            columns = [row[1] for row in self.db.execute("PRAGMA table_info(records)")]
            if version and version[0] == FORMAT and columns != _RECORD_COLUMNS:
                raise FwshiftError(f"{path}: a usage store whose tables are not as this version writes them")
            if not version or version[0] != FORMAT:
                raise FwshiftError(f"{path}: a usage store of another format ({version[0] if version else 'none'}); this version "
                                   f"writes format {FORMAT}")  # fmt: skip
        except sqlite3.OperationalError as error:
            raise FwshiftError(f"{path}: the usage store cannot be used ({error})") from None
        except sqlite3.DatabaseError as error:
            raise FwshiftError(f"{path}: not a usage store ({error})") from None

    def close(self) -> None:
        self.db.close()

    def known(self, digest: str) -> Optional[str]:
        row = self.db.execute("SELECT name FROM files WHERE digest = ?", (digest,)).fetchone()
        return str(row[0]) if row else None

    def days(self) -> Tuple[Optional[str], Optional[str]]:
        row = self.db.execute("SELECT MIN(day), MAX(day) FROM coverage").fetchone()
        return (row[0], row[1]) if row else (None, None)

    def runs(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0])


@dataclass
class Ingested:
    """What reading the log files did."""

    files: List[str] = field(default_factory=list)
    already: List[Tuple[str, str]] = field(default_factory=list)  # (file, the file of the same content in the store)
    lines: int = 0
    connections: int = 0
    skipped: Dict[str, int] = field(default_factory=dict)
    zoneless: int = 0  # lines whose time had no zone, read as UTC


def _day(moment: int) -> Optional[str]:
    try:
        return datetime.datetime.fromtimestamp(moment, datetime.timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return None


def _rule_key(record: LogRecord) -> str:
    """The rules a log names, as text that needs no policy to be written: the rows of its match table; for a log that
    names none (iptables), the zones it came in and went out by, which simulating the policy needs."""
    rows = [[row.layer_uuid, row.match_id, row.parent_rule, row.rule_uid, int(row.implicit)] for row in record.layers]
    key: Dict[str, Any] = {"rows": rows, "loose": sorted(set(record.loose_uids))}
    if not rows and not record.loose_uids:
        key.update({"in": record.in_zone, "out": record.out_zone})
    return json.dumps(key, separators=(",", ":"), sort_keys=True)


def _prefix(address: str) -> str:
    """The network an address is kept as beyond the limit of addresses per rule: its /24, or its /64."""
    if ":" not in address:
        return address.rsplit(".", 1)[0] + ".0/24"  # (the readers give addresses in their plain form)
    import ipaddress

    return str(ipaddress.ip_network(f"{address}/64", strict=False))


def ingest(store: Store, files: Sequence[Tuple[str, Any]], policy: str = "", policy_digest: str = "",
           cap: int = DEFAULT_CAP, kind: str = "checkpoint", year: Optional[int] = None, offset: Optional[int] = None) -> Ingested:  # fmt: skip
    """Read log files into the store, one at a time; a file is (name, its bytes, or a function that reads them).

    A file whose content is in the store already is not read again; a file in which no line was a connection is
    not marked as read (a later version may read it).
    """
    try:
        return _ingest(store, files, policy, policy_digest, cap, kind, year, offset)
    except sqlite3.Error as error:
        raise FwshiftError(f"{store.path}: the usage store cannot be written ({error})") from None


def _ingest(store: Store, files: Sequence[Tuple[str, Any]], policy: str, policy_digest: str, cap: int, kind: str,
            year: Optional[int], offset: Optional[int]) -> Ingested:  # fmt: skip
    done = Ingested()
    kernel = iptables_logs.Reader(year, offset) if kind == "iptables" else None
    db = store.db
    cursor = db.execute("INSERT INTO runs (policy, policy_digest, lines, connections, skipped) VALUES (?, ?, 0, 0, '{}')",
                        (policy, policy_digest))  # fmt: skip
    run = int(cursor.lastrowid or 0)  # (a run that read nothing new is removed again below)
    skipped: Counter[str] = Counter()
    unplaced: Counter[str] = Counter()
    coverage: Counter[Tuple[str, str]] = Counter()
    doubtful: Counter[Tuple[str, str]] = Counter()
    accepts: Counter[Tuple[str, str]] = Counter()
    seen: Dict[str, str] = {}
    pending: Counter[Key] = Counter()
    known: Dict[Tuple[str, str], Set[str]] = {}  # (rule key, side) -> addresses kept as they are
    rolled: Set[Tuple[str, str]] = set()

    def address(rule_key: str, side: str, value: str) -> str:
        if not value:
            return value
        kept = known.get((rule_key, side))
        if kept is None:
            kept = known[(rule_key, side)] = {
                row[0] for row in db.execute("SELECT address FROM kept WHERE rule_key = ? AND side = ?", (rule_key, side))}  # fmt: skip
        if value in kept:
            return value
        if len(kept) < cap:
            kept.add(value)
            db.execute("INSERT OR IGNORE INTO kept VALUES (?, ?, ?)", (rule_key, side, value))
            return value
        rolled.add((rule_key, side))
        return _prefix(value)

    def flush() -> None:
        rows = [key + (count,) for key, count in pending.items()]
        db.executemany("INSERT OR IGNORE INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)", [row[:8] for row in rows])
        db.executemany("UPDATE records SET count = count + ? WHERE day = ? AND gateway = ? AND rule_key = ? AND src = ? AND dst = ? "
                       "AND protocol = ? AND port = ? AND user = ?", [(row[8],) + row[:8] for row in rows])  # fmt: skip
        pending.clear()

    for name, source in files:
        data = source() if callable(source) else source
        digest = hashlib.sha256(data).hexdigest()
        earlier = store.known(digest) or seen.get(digest)
        if earlier is not None:
            done.already.append((name, earlier))
            continue
        seen[digest] = name
        done.files.append(name)
        connections = done.connections
        for line in (kernel.read(data, name) if kernel is not None else checkpoint_logs.read(data, name)):
            done.lines += 1
            day = _day(line.time) if line.time is not None else None
            where = (day, line.gateway) if day and line.gateway else None
            record = line.record
            if record is None or where is None:
                reason = line.reason or "a connection without a day it can be counted on"
                skipped[reason] += 1
                if line.doubt or record is not None:
                    if where is not None:
                        doubtful[where] += 1
                    else:
                        unplaced[reason] += 1
                continue
            # A day of a gateway counts as logged by the connections it logged that name a rule, nothing else: a
            # log of another blade or an update shows the exporter worked, not that it sent the connections.
            coverage[where] += 1
            if record.action.lower() == "accept":
                accepts[where] += 1
            rule_key = _rule_key(record)
            key: Key = (where[0], where[1], rule_key, address(rule_key, "source", record.src), address(rule_key, "destination", record.dst),
                        record.protocol, -1 if record.port is None else record.port, _USERS.join(record.users))  # fmt: skip
            pending[key] += record.count
            done.connections += record.count
            if len(pending) >= _FLUSH:
                flush()
        if done.connections > connections:
            db.execute("INSERT INTO files VALUES (?, ?, ?)", (digest, name, run))
        del data
    flush()
    for where in set(coverage) | set(doubtful):
        db.execute("INSERT OR IGNORE INTO coverage VALUES (?, ?, 0, 0, 0)", where)
        db.execute("UPDATE coverage SET lines = lines + ?, doubtful = doubtful + ?, accepts = accepts + ? WHERE day = ? AND gateway = ?",
                   (coverage[where], doubtful[where], accepts[where]) + where)  # fmt: skip
    db.executemany("INSERT INTO unplaced VALUES (?, ?, ?)", [(run, reason, lines) for reason, lines in unplaced.items()])
    db.executemany("INSERT OR IGNORE INTO rolled VALUES (?, ?)", sorted(rolled))
    db.execute("UPDATE runs SET lines = ?, connections = ?, skipped = ? WHERE id = ?",
               (done.lines, done.connections, json.dumps(dict(sorted(skipped.items()))), run))  # fmt: skip
    if not done.files:
        db.execute("DELETE FROM runs WHERE id = ?", (run,))
    done.zoneless = kernel.zoneless if kernel is not None else 0
    db.commit()
    done.skipped = dict(sorted(skipped.items(), key=lambda item: (-item[1], item[0])))
    return done


# -- the window ------------------------------------------------------------------------------------------


@dataclass
class Window:
    first: str  # YYYY-MM-DD
    last: str

    @property
    def days(self) -> int:
        return (_date(self.last) - _date(self.first)).days + 1

    def all_days(self) -> List[str]:
        start = _date(self.first)
        return [(start + datetime.timedelta(days=offset)).isoformat() for offset in range(self.days)]


def _date(text: str) -> datetime.date:
    return datetime.datetime.strptime(text, "%Y-%m-%d").date()


def window(store: Store, since: str = "", until: str = "", days: int = 90) -> Window:
    """The days to look at: up to ``until`` (default: the last day the store has logs of), back ``since`` (a number of days
    such as 90d, or the first day as YYYY-MM-DD; default: ``days``)."""
    first_known, last_known = store.days()
    if last_known is None:
        raise FwshiftError("the usage store holds no logs yet: give log files with --logs")
    try:
        last = _date(until) if until else _date(last_known)
    except ValueError:
        raise FwshiftError(f"--until: '{until[:20]}' is not a day written YYYY-MM-DD") from None
    text = since.strip().lower()
    if not text:
        count = days
    elif text.endswith("d") and text[:-1].isdigit():
        count = int(text[:-1])
    else:
        try:
            count = (last - _date(text)).days + 1
        except ValueError:
            raise FwshiftError(f"--since: '{since[:20]}' is neither a number of days (90d) nor a day written YYYY-MM-DD") from None
    if not 1 <= count <= 3660:
        raise FwshiftError("--since and --until leave no window of 1 to 3660 days")
    try:
        first = last - datetime.timedelta(days=count - 1)
    except OverflowError:
        raise FwshiftError("--since and --until leave no window that a calendar has") from None
    return Window(first.isoformat(), last.isoformat())


# -- attribution -------------------------------------------------------------------------------------


@dataclass
class Evaluation:
    """What the logs say over a window: per rule on the rules (Rule.log_usage), and about the logs themselves."""

    window: Window
    gateways: Dict[str, Tuple[int, int]] = field(default_factory=dict)  # gateway -> (days with logs, lines that could not be read)
    connections: int = 0
    attributed: int = 0
    unattributed: Dict[str, int] = field(default_factory=dict)
    unplaced: int = 0  # lines that could not be read, from no known gateway and day
    cross_check: List[str] = field(default_factory=list)
    store_days: Tuple[Optional[str], Optional[str]] = (None, None)
    runs: int = 0
    accepts: Dict[str, int] = field(default_factory=dict)  # gateway -> accepted connections in the window
    simulated: int = 0  # connections whose log names no rule, attributed by matching them against the rules
    possible: int = 0  # connections that may have gone through one of several rules
    only_possible: List[str] = field(default_factory=list)  # why simulated connections are counted as possible only
    judged_by: List[str] = field(default_factory=list)  # the gateways whose logs judge a rule installed on every target


def _norm(uid: str) -> str:
    return uid.strip().strip("{}").lower()


class _Rules:
    """The rules of a Check Point policy by what its logs call them."""

    def __init__(self, p: Policy) -> None:
        self.by_path: Dict[str, List[Rule]] = {}
        self.cleanups: Dict[str, List[Rule]] = {}  # parent rule uid -> the implicit cleanup of the layer it applies
        layers: Set[str] = {_norm(rule.source_ids["checkpoint.policy_layer_uid"]) for rule in p.rules
                            if rule.source_ids.get("checkpoint.policy_layer_uid")}  # fmt: skip
        for rule in p.rules:
            ids = rule.source_ids
            if not rule.enabled:
                continue
            if ids.get("checkpoint.implicit") == "cleanup":
                self.cleanups.setdefault(_norm(ids.get("checkpoint.parent_rule_uid", "")), []).append(rule)
                continue
            uid = _norm(ids.get("checkpoint.rule_uid", ""))
            if not uid:
                continue
            path = " ".join(_norm(part) for part in ids.get("checkpoint.rule_path", uid).split())
            self.by_path.setdefault(path, []).append(rule)
        self.layers = layers  # the layer the policy was read from: its rows start the chain, whatever layer applies it

    def find(self, rows: List[LayerMatch], loose: List[str]) -> Tuple[List[Rule], str, bool]:
        """The rules a log names, or why none; and whether the log names them for certain (not loosely)."""
        found, reason = self._find(rows, loose)
        return found, reason, bool(found) and not (loose or any(not row.rule_uid and not row.implicit for row in rows))

    def _find(self, rows: List[LayerMatch], loose: List[str]) -> Tuple[List[Rule], str]:
        if not rows:
            return [], "a log that names no rule"
        main = [row for row in rows if row.layer_uuid in self.layers]
        if not main and len(rows) == 1 and not rows[0].layer_uuid:
            main = rows  # a log from before layers: the rule alone
        if not main:
            return [], "rules of a layer this policy does not hold (another ordered layer, or another policy)"
        chain = [main[0]]
        while len(chain) <= len(rows):
            inner = [row for row in rows if row is not chain[-1] and row.parent_rule and row.parent_rule == chain[-1].match_id]
            if not inner:
                break
            chain.append(inner[0])
        if chain[0].implicit:
            return [], "the implicit cleanup of the layer (no rule)"
        if chain[-1].implicit:
            parent = chain[-2].rule_uid if len(chain) > 1 else ""
            found = self.cleanups.get(parent, []) if parent else []
            return (found, "") if found else ([], "the implicit cleanup of an inline layer the policy does not have")
        uids = [row.rule_uid for row in chain]
        if all(uids):
            found = self.by_path.get(" ".join(uids)) or []
            if found:
                return found, ""
            return [], "a rule this policy does not have (another revision of it?)"
        # The uids could not be put on their rows: the rules named by them at all count as used, nothing more.
        named = set(loose) | {uid for uid in uids if uid}
        found = [rule for path, rules in self.by_path.items() if set(path.split()) <= named for rule in rules]
        return (found, "") if found else ([], "a rule this policy does not have (another revision of it?)")


class _Cells:
    """What a rule's cells hold, to count connections against: objects with their addresses, services with their ports."""

    def __init__(self, p: Policy, rule: Rule) -> None:
        self.p = p
        self.rule = rule
        self.addresses: Dict[str, List[Tuple[str, List[Interval], bool]]] = {}
        destinations = rule.destinations
        if p.lookup_after_dnat and rule.nat_added:
            # The pre-NAT addresses a parser added: the log has the address after NAT, and holds them under that one.
            destinations = [member for member in rule.destinations if member not in rule.nat_added] or rule.destinations
        for cell, members, negated in (("source", rule.sources, rule.negate_source), ("destination", destinations, rule.negate_destination)):
            if negated or ANY in members:
                continue
            self.addresses[cell] = [(name, *transform.known_intervals(p, name)) for name in _reachable(p, members, groups=True)]
        self.services: List[Tuple[str, Optional[List[ServiceEntry]]]] = []
        if ANY not in rule.services and not rule.negate_service:
            tainted = transform.tainted_services(p)
            self.services = [(name, None if name in tainted else transform.flatten_services(p, name))
                             for name in _reachable(p, rule.services, groups=False)]  # fmt: skip
        self.memo: Dict[Tuple[str, str], List[str]] = {}

    def objects(self, cell: str, address: str) -> List[str]:
        """The objects of a cell that hold an address (or part of a network the address stands for)."""
        key = (cell, address)
        if key not in self.memo:
            interval = parse_literal(address)
            hits = [name for name, known, _ in self.addresses.get(cell, []) if interval is not None and overlaps([interval], known)]
            parts = {name: self.p.addresses[name].part_of for name in hits if name in self.p.addresses and self.p.addresses[name].part_of}
            self.memo[key] = list(dict.fromkeys([parts.get(name, name) for name in hits] + hits))
        return self.memo[key]

    def service_hits(self, protocol: int, port: int) -> List[str]:
        return [name for name, entries in self.services if entries is not None and any(_entry_holds(entry, protocol, port) for entry in entries)]


def _reachable(p: Policy, members: Sequence[str], groups: bool) -> List[str]:
    """The members, then everything they hold through groups, each once."""
    out: List[str] = []
    todo = list(members)
    while todo:
        name = todo.pop(0)
        if name in out or name == ANY:
            continue
        out.append(name)
        table: Any = p.address_groups if groups else p.service_groups
        if name in table:
            todo += table[name].members
    return out


def _ranges(ports: str) -> Optional[List[Tuple[int, int]]]:
    out: List[Tuple[int, int]] = []
    for part in (ports or "0-65535").split(","):
        first, _, last = part.strip().partition("-")
        if not first.isdigit() or (last and not last.isdigit()):
            return None
        out.append((int(first), int(last or first)))
    return out


def _entry_holds(entry: ServiceEntry, protocol: int, port: int) -> bool:
    """Whether a service entry holds a connection; where the log does not tell (no port, no ICMP type), it may."""
    if entry.protocol == Protocol.IP:
        return entry.ip_protocol is None or entry.ip_protocol == protocol
    if _PROTOCOL_NUMBERS.get(entry.protocol) != protocol:
        return False
    if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
        return entry.icmp_type is None or port < 0 or entry.icmp_type == port
    ranges = _ranges(entry.dst_ports)
    return ranges is None or port < 0 or any(low <= port <= high for low, high in ranges)


def gateway_names(values: Sequence[str]) -> Tuple[List[str], Dict[str, str]]:
    """--gateway NAME or NAME=LOGNAME,LOGNAME: the gateways declared, and the names their logs come under (cluster members)."""
    declared: List[str] = []
    aliases: Dict[str, str] = {}
    for value in values:
        name, sep, members = value.partition("=")
        name = name.strip()
        if not name or (sep and not members.strip()):
            raise FwshiftError(f"--gateway expects NAME or NAME=LOGNAME[,LOGNAME...], got '{value[:60]}'")
        declared.append(name)
        for member in members.split(",") if sep else []:
            if member.strip():
                aliases[member.strip().lower()] = name.lower()
    return declared, aliases


def evaluate(p: Policy, store: Store, span: Window, gateways: Sequence[str] = (), reading: Any = None,
             unchanged_since: Optional[int] = None) -> Evaluation:  # fmt: skip
    """Put on every enabled rule what the logs of the window say about it (Rule.log_usage).

    ``reading`` is what the parser said (audit.Reading): a rule it read approximately is never certain in a simulation.
    ``unchanged_since`` is the user's word that the rules have been as they are since then, where the export does not say.
    """
    try:
        return _evaluate(p, store, span, gateways, reading, unchanged_since)
    except sqlite3.Error as error:
        raise FwshiftError(f"{store.path}: the usage store cannot be read ({error})") from None


def _evaluate(p: Policy, store: Store, span: Window, gateways: Sequence[str], reading: Any, unchanged_since: Optional[int]) -> Evaluation:
    result = Evaluation(span, store_days=store.days(), runs=store.runs())
    db = store.db
    days = set(span.all_days())
    declared, aliases = gateway_names(gateways)
    coverage: Dict[str, Set[str]] = {}
    doubts: Counter[str] = Counter()
    accepted: Counter[str] = Counter()
    for day, logged_as, lines, doubtful, accepts in db.execute(
            "SELECT day, gateway, lines, doubtful, accepts FROM coverage WHERE day BETWEEN ? AND ?", (span.first, span.last)):  # fmt: skip
        gateway = aliases.get(logged_as.lower(), logged_as.lower())
        if lines:
            coverage.setdefault(gateway, set()).add(day)
        doubts[gateway] += doubtful
        accepted[gateway] += accepts
    names = {aliases.get(gateway.lower(), gateway.lower()): gateway for (gateway,) in db.execute("SELECT DISTINCT gateway FROM coverage")}
    for name in declared:
        names[name.lower()] = name
    result.gateways = {names[g]: (len(coverage.get(g, set()) & days), doubts[g]) for g in sorted(names)}
    result.accepts = {names[g]: accepted[g] for g in sorted(names)}
    result.unplaced = int(db.execute("SELECT COALESCE(SUM(lines), 0) FROM unplaced").fetchone()[0])
    rules = _Rules(p)
    cells: Dict[int, _Cells] = {}
    usage: Dict[int, LogUsage] = {}
    for rule in p.rules:
        if rule.enabled:
            rule.log_usage = usage[id(rule)] = LogUsage(span.first, span.last)
    unattributed: Counter[str] = Counter()
    found_for: Dict[str, Tuple[List[Rule], str, bool, Optional[Tuple[str, str]]]] = {}
    simulator: Optional[Simulator] = None
    rolled = {row[0] for row in db.execute("SELECT DISTINCT rule_key FROM rolled")}
    rolled_rules: Set[int] = set()
    declared_lower = {name.lower() for name in declared}
    everywhere = sorted(declared_lower) if declared and p.vendor == "iptables" else sorted(names)  # (a rule with no targets is on these)
    result.judged_by = [names[g] for g in everywhere]
    tcp_only = bool(reading is not None and getattr(reading, "every_packet", False))
    if tcp_only:
        result.only_possible.append("the logs may hold packets of connections already open (a LOG rule ahead of the rule that accepts "
                                    "established connections): a line of a protocol other than TCP may be one of those")  # fmt: skip
    many_hosts = not declared and len(names) > 1
    if many_hosts and p.vendor == "iptables":
        result.only_possible.append(f"the logs come from {len(names)} hosts and no --gateway says which of them run this policy")
    ours = 0  # connections that name a row of the layer of the policy at all, or are simulated against it
    query = ("SELECT rule_key, gateway, src, dst, protocol, port, user, SUM(count) FROM records WHERE day BETWEEN ? AND ? "
             "GROUP BY rule_key, gateway, src, dst, protocol, port, user")  # fmt: skip
    for rule_key, gateway, src, dst, protocol, port, user, count in db.execute(query, (span.first, span.last)):
        result.connections += count
        gateway = names.get(aliases.get(gateway.lower(), gateway.lower()), gateway)
        if rule_key not in found_for:
            try:
                decoded = json.loads(rule_key)
                rows = [LayerMatch(str(row[0]), row[1], row[2], str(row[3]), bool(row[4])) for row in decoded.get("rows", [])]
                if rows or decoded.get("loose"):
                    found, reason, certain = rules.find(rows, [str(uid) for uid in decoded.get("loose", [])])
                    found_for[rule_key] = found, reason, certain, None
                else:
                    found_for[rule_key] = [], "", False, (str(decoded.get("in", "")), str(decoded.get("out", "")))
            except (ValueError, TypeError, IndexError, AttributeError):
                found_for[rule_key] = [], "a record of the store that cannot be read", False, None
        found, reason, certain, zones = found_for[rule_key]
        simulated = zones is not None
        if simulated and declared and aliases.get(gateway.lower(), gateway.lower()) not in declared_lower:
            # A line names no rule and comes from a host that is not a gateway given: not a connection of this policy.
            unattributed["a line from a host that is not among the gateways given (--gateway)"] += count
            continue
        if simulated:
            # The log names no rule: the policy says which, certainly or possibly (simulate.py).
            if simulator is None:
                simulator = Simulator(p, reading)
            answer = simulator.attribute((zones[0], zones[1], src, dst, protocol, None if port is None or port < 0 else port))  # type: ignore[index]
            if answer.certain is not None and not ((tcp_only and protocol != 6) or (many_hosts and p.vendor == "iptables")):
                found, certain, reason = [answer.certain], True, ""
            elif answer.certain is not None:
                found, certain, reason = [answer.certain], False, ""
            else:
                found, certain, reason = answer.possible, False, answer.reason
            result.simulated += count
        if found or not reason.startswith("rules of a layer"):
            ours += count
        if not found:
            unattributed[reason] += count
            continue
        if len(found) > 1 and not simulated:
            # One rule of the source that is several in the model (a cell of access roles): the ones whose source
            # holds the address, and whose users hold the user where the log names one; all of them if that leaves none.
            fitting = [rule for rule in found if (not src or _source_holds(p, rule, src)) and _users_hold(rule, user)]
            found = fitting or found
            certain = certain and len(found) == 1
        if certain:
            result.attributed += count
        else:
            result.possible += count
        if rule_key in rolled:
            rolled_rules.update(id(rule) for rule in found)
        for rule in found:
            log = usage.get(id(rule))
            if log is None:
                continue
            if certain:
                log.connections += count
                log.simulated += count if simulated else 0
                if simulated and not _blocks(rule):
                    result.accepts[gateway] = result.accepts.get(gateway, 0) + count  # (the policy allowed it: it was accepted)
            else:
                log.possible += count
            if rule.targets and gateway.lower() not in {target.lower() for target in rule.targets} and gateway not in log.elsewhere:
                log.elsewhere.append(gateway)
            what = cells.get(id(rule))
            if what is None:
                what = cells[id(rule)] = _Cells(p, rule)
            for cell, address in (("source", src), ("destination", dst)):
                negated = rule.negate_source if cell == "source" else rule.negate_destination
                bucket = log.members.setdefault(cell, {})
                if negated:
                    bucket[OUTSIDE] = bucket.get(OUTSIDE, 0) + count
                elif not address:
                    bucket[UNKNOWN] = bucket.get(UNKNOWN, 0) + count  # (it may have been any of them: none is called unused)
                else:
                    for name in what.objects(cell, address):
                        bucket[name] = bucket.get(name, 0) + count
            bucket = log.members.setdefault("service", {})
            if rule.negate_service:
                bucket[OUTSIDE] = bucket.get(OUTSIDE, 0) + count
            elif protocol < 0:
                bucket[UNKNOWN] = bucket.get(UNKNOWN, 0) + count
            else:
                for name in what.service_hits(protocol, port):
                    bucket[name] = bucket.get(name, 0) + count
            for person in [name for name in user.split(_USERS) if name]:
                bucket = log.members.setdefault("user", {})
                bucket[person] = bucket.get(person, 0) + count
    result.unattributed = dict(sorted(unattributed.items(), key=lambda item: (-item[1], item[0])))
    siblings: Dict[str, List[Rule]] = {}
    for rule in p.rules:
        ids = rule.source_ids
        key = ids.get("checkpoint.rule_path") or ids.get("checkpoint.rule_uid") or ""
        if key and rule.enabled:
            siblings.setdefault(key, []).append(rule)
    for group in siblings.values():
        total = sum(usage[id(rule)].connections for rule in group if id(rule) in usage)
        for rule in group:
            if id(rule) in usage and len(group) > 1:
                usage[id(rule)].shared = total - usage[id(rule)].connections

    for rule in p.rules:
        log = usage.get(id(rule))
        if log is None:
            continue
        what = cells.get(id(rule)) or _Cells(p, rule)
        _complete(log, what)
        log.rolled_up = id(rule) in rolled_rules
        log.no_evidence = _evidence(rule, span, result, coverage, doubts, names, unchanged_since, everywhere)
        if p.vendor == "checkpoint" and not rules.layers:
            log.no_evidence.append("the export does not give the uid of the layer, which the logs name it by")
        elif result.connections and not ours:
            log.no_evidence.append("no connection in the window names a rule of this layer: are these the logs of this policy?")
        if result.simulated:
            log.method = "simulation" if not result.connections - result.simulated else "gateway and simulation"
        for gateway in (rule.targets and [t.lower() for t in rule.targets]) or everywhere:
            if names.get(gateway, gateway) in result.accepts and not result.accepts[names.get(gateway, gateway)] and rule.action.value == "allow":
                log.no_evidence.append(f"gateway {names.get(gateway, gateway)} logged no accepted connection in the window (are accepts exported?)")
        log.gateways = sorted({names.get(g.lower(), g) for g in (rule.targets or list(names.values()))}, key=str.lower)
        total = log.connections + log.shared  # (a counter counts the rule of the source, all its parts)
        if rule.hits is not None:
            if rule.hits.count == 0 and total:
                result.cross_check.append(f"'{rule.name}': hit counter 0, and {total} connection(s) in the logs from "
                                          f"{span.first} to {span.last} (the two cover other periods)")  # fmt: skip
            elif rule.hits.count and not total and not log.no_evidence:
                result.cross_check.append(f"'{rule.name}': hit counter {rule.hits.count}, and no connection in the logs from "
                                          f"{span.first} to {span.last} (the two cover other periods)")  # fmt: skip
    return result


def _complete(log: LogUsage, what: _Cells) -> None:
    """Members with no connection get 0; members that cannot be told from an address or a port are named as such."""
    for cell, objects in what.addresses.items():
        bucket = log.members.setdefault(cell, {})
        for name, _, complete in objects:
            bucket.setdefault(name, 0)
            if not complete and not bucket[name]:
                log.unjudged.setdefault(cell, []).append(name)
        listed = [name for name, _, _ in objects]
        log.members[cell] = {name: bucket[name] for name in listed + [name for name in bucket if name not in listed]}
    if what.services:
        bucket = log.members.setdefault("service", {})
        for name, entries in what.services:
            bucket.setdefault(name, 0)
            if entries is None and not bucket[name]:
                log.unjudged.setdefault("service", []).append(name)


def _source_holds(p: Policy, rule: Rule, address: str) -> bool:
    if ANY in rule.sources:
        return True
    interval = parse_literal(address)
    known: List[Interval] = []
    for member in rule.sources:
        known += transform.known_intervals(p, member)[0]
    return interval is not None and (overlaps([interval], known) != rule.negate_source)


def _users_hold(rule: Rule, user: str) -> bool:
    """Whether a rule of users can have matched: not without an identity in the log. A person and a group cannot be compared."""
    return rule.users == [ANY] or bool(user)


def _evidence(rule: Rule, span: Window, result: Evaluation, coverage: Dict[str, Set[str]], doubts: Counter[str],
              names: Dict[str, str], unchanged_since: Optional[int] = None, scope: Optional[List[str]] = None) -> List[str]:  # fmt: skip
    """Why the logs of the window cannot prove that the rule was not used; empty when they can.

    ``scope`` is the gateways a rule installed on every target is on (by default every gateway that sent logs).
    """
    out: List[str] = []
    if not (rule.log_end or rule.log_start):
        out.append("it does not log its connections")
    elif rule.source_ids.get("iptables.log_target"):
        out.append(f"it logs through {rule.source_ids['iptables.log_target']}, whose lines go to ulogd, not to the kernel log that is read")
    first = int(datetime.datetime.combine(_date(span.first), datetime.time(), datetime.timezone.utc).timestamp())
    changed = rule.changed if rule.changed is not None else unchanged_since
    if changed is None:
        out.append("the export does not say when it was created or last changed (give the day with --unchanged-since, if it is known)")
    elif changed > first:
        out.append(f"it was created or changed on {_day(changed)}, after the window began")
    days = set(span.all_days())
    wanted = [target.lower() for target in rule.targets] or (scope if scope is not None else list(names))
    if not wanted:
        out.append("no gateway sent logs")
    for gateway in wanted:
        shown = names.get(gateway, gateway)
        seen = coverage.get(gateway, set()) & days
        if not seen:
            out.append(f"gateway {shown} sent no logs from {span.first} to {span.last}")
        elif len(seen) < span.days:
            out.append(f"gateway {shown} sent logs on {len(seen)} of the {span.days} days")
        if doubts.get(gateway):
            out.append(f"{doubts[gateway]} line(s) from gateway {shown} in the window could not be read")
    if result.unplaced:
        out.append(f"{result.unplaced} line(s) of the logs could not be read, and their gateway and day are not known")
    return out


# -- reports ----------------------------------------------------------------------------------------------


def _rules_dict(p: Policy) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rule in p.rules:
        log = rule.log_usage
        if log is None:
            continue
        entry: Dict[str, Any] = {"name": rule.name, "action": rule.action.value, "source_ids": dict(rule.source_ids),
                                 "connections": log.connections, "members": log.members}  # fmt: skip
        if log.simulated:
            entry["by_simulation"] = log.simulated
        if log.possible:
            entry["possible"] = log.possible
        for key in ("unjudged", "no_evidence", "elsewhere"):
            if getattr(log, key):
                entry[key] = getattr(log, key)
        if log.rolled_up:
            entry["rolled_up"] = True
        if log.shared:
            entry["shared"] = log.shared
        out.append(entry)
    return out


def to_dict(p: Policy, source: str, store: str, evaluation: Evaluation, ingested: Optional[Ingested], findings: Sequence[Any],
            counters: Sequence[str] = ()) -> Dict[str, Any]:  # fmt: skip
    window_ = evaluation.window
    out: Dict[str, Any] = {
        "source": source, "scope": p.scope, "store": store,
        "window": {"first": window_.first, "last": window_.last, "days": window_.days},
        "store_days": {"first": evaluation.store_days[0], "last": evaluation.store_days[1], "runs": evaluation.runs},
    }  # fmt: skip
    if ingested is not None:
        out["read"] = {"files": ingested.files, "already_in_store": [list(pair) for pair in ingested.already], "lines": ingested.lines,
                       "connections": ingested.connections, "skipped": ingested.skipped}  # fmt: skip
        if ingested.zoneless:
            out["read"]["times_read_as_utc"] = ingested.zoneless
    if counters:
        out["hit_counters"] = list(counters)
    out["gateways"] = {name: {"days_with_logs": days, "unreadable_lines": doubtful} for name, (days, doubtful) in evaluation.gateways.items()}
    if evaluation.judged_by != list(evaluation.gateways):
        out["judged_by"] = evaluation.judged_by
    out["connections"] = {"in_window": evaluation.connections, "attributed": evaluation.attributed, "possible": evaluation.possible,
                          "by_simulation": evaluation.simulated, "not_attributed": evaluation.unattributed,
                          "unreadable_without_gateway_or_day": evaluation.unplaced}  # fmt: skip
    if evaluation.only_possible and evaluation.simulated:
        out["connections"]["possible_only_because"] = evaluation.only_possible
    out["findings"] = [f.to_dict() for f in findings]
    out["rules"] = _rules_dict(p)
    if evaluation.cross_check:
        out["cross_check"] = evaluation.cross_check
    return out


def to_text(data: Dict[str, Any]) -> str:
    w = data["window"]
    scope = f" ({data['scope']})" if data.get("scope") else ""
    lines = ["FWShift usage", f"  source: {data['source']}{scope}",
             f"  store: {data['store']} (logs from {data['store_days']['first']} to {data['store_days']['last']}, {data['store_days']['runs']} run(s))",
             f"  window: {w['first']} to {w['last']} ({w['days']} days)"]  # fmt: skip
    read = data.get("read")
    if read:
        lines.append(f"  read now: {len(read['files'])} file(s), {read['lines']} line(s), {read['connections']} connection(s)")
        for name, earlier in read["already_in_store"]:
            lines.append(f"  not read again: {name} (in the store already, as {earlier})")
        for reason, count in read["skipped"].items():
            lines.append(f"    {count} not counted: {reason}")
        if read.get("times_read_as_utc"):
            lines.append(f"    {read['times_read_as_utc']} time(s) without a zone read as UTC (give the offset of the log)")
    for line in data.get("hit_counters", []):
        lines.append(f"  hit counters: {line}")
    for name, info in data["gateways"].items():
        extra = f", {info['unreadable_lines']} line(s) that could not be read" if info["unreadable_lines"] else ""
        lines.append(f"  gateway {name}: logs on {info['days_with_logs']} of {w['days']} days{extra}")
    if data["gateways"]:
        judges = ", ".join(data.get("judged_by", data["gateways"]))
        lines.append(f"  rules installed on every target are judged by the logs of {judges}; name a gateway that sent none "
                     "with --gateway")  # fmt: skip
    c = data["connections"]
    lines.append(f"  connections in the window: {c['in_window']}, attributed to a rule of the policy: {c['attributed']}"
                 + (f", possibly to one of several: {c['possible']}" if c.get("possible") else ""))
    if c.get("by_simulation"):
        lines.append(f"    {c['by_simulation']} named no rule and were matched against the rules of the policy as read (certain where the "
                     "first rule they meet surely matches them, possible where it only might)")  # fmt: skip
    for why in c.get("possible_only_because", []):
        lines.append(f"    counted as possible only: {why}")
    for reason, count in c["not_attributed"].items():
        lines.append(f"    {count} not attributed: {reason}")
    if c["unreadable_without_gateway_or_day"]:
        lines.append(f"    {c['unreadable_without_gateway_or_day']} line(s) could not be read, from no known gateway and day")
    lines += ["", "Findings"]
    findings = [f for f in data["findings"] if f["action"] != "accept"]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for f in sorted(findings, key=lambda f: order[f["level"]]):
        lines.append(f"  [{f['level']}] {f['check']}: {f['kind']} '{f['name']}' {f['message']}")
    if not findings:
        lines.append("  none")
    accepted = [f for f in data["findings"] if f["action"] == "accept"]
    if accepted:
        lines += ["", "Accepted"] + [f"  {f['check']}: {f['kind']} '{f['name']}'" + (f" ({f['reason']})" if f.get("reason") else "") for f in accepted]
    lines += ["", "Rules"]
    for rule in data["rules"]:
        state = f"{rule['connections']} connection(s)"
        if rule.get("by_simulation"):
            state += f" ({rule['by_simulation']} by simulation)"
        if rule.get("possible"):
            state += f", {rule['possible']} possible"
        if rule.get("no_evidence"):
            state += "; proves nothing: " + "; ".join(rule["no_evidence"])
        lines.append(f"  '{rule['name']}' ({rule['action']}): {state}")
        if rule.get("shared"):
            lines.append(f"      the other parts of the same rule of the source: {rule['shared']} connection(s)")
        for cell in ("source", "destination", "service", "user"):
            members = rule["members"].get(cell)
            unjudged = set(rule.get("unjudged", {}).get(cell, []))
            if members:
                shown = ", ".join(f"{name} {'?' if name in unjudged else count}" for name, count in members.items())
                lines.append(f"      {cell}: {shown}")
        if rule.get("elsewhere"):
            lines.append("      logged by gateways it is not installed on: " + ", ".join(rule["elsewhere"]))
        if rule.get("rolled_up"):
            lines.append("      (addresses beyond the limit per rule kept as networks)")
    if data.get("cross_check"):
        lines += ["", "Hit counters and logs disagree"] + [f"  {line}" for line in data["cross_check"]]
    return "\n".join(lines) + "\n"


_CSS = """
:root { --bg: #ffffff; --fg: #1d2330; --muted: #5d6576; --line: #d9dde5; --zero: #b3261e; --zero-bg: #fbeae9; --head: #f3f5f8; }
@media (prefers-color-scheme: dark) { :root { --bg: #15181e; --fg: #e5e8ee; --muted: #9aa3b2; --line: #2c323d; --zero: #ff8a80;
  --zero-bg: #3a1f1f; --head: #1d2129; } }
body { background: var(--bg); color: var(--fg); font: 14px/1.45 system-ui, sans-serif; margin: 0 auto; max-width: 1100px; padding: 16px; }
h1 { font-size: 1.4em; } h2 { font-size: 1.15em; margin-top: 2em; } .muted { color: var(--muted); }
table { border-collapse: collapse; width: 100%; margin: .5em 0 1em; } th, td { border-bottom: 1px solid var(--line); padding: 4px 8px;
  text-align: left; vertical-align: top; } th { background: var(--head); } td.n { text-align: right; font-variant-numeric: tabular-nums; }
.zero { color: var(--zero); background: var(--zero-bg); } .level { font-weight: 600; } code { font-size: .95em; }
section.rule { border: 1px solid var(--line); border-radius: 6px; padding: 8px 12px; margin: 12px 0; overflow-x: auto; }
"""


def to_html(data: Dict[str, Any]) -> str:
    """The report as one page that needs nothing else: findings, then per rule the connections of each member."""
    e = html.escape
    w = data["window"]
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>",
           f"<title>FWShift usage</title><style>{_CSS}</style></head><body>",
           f"<h1>Rule usage: {e(data['source'])}{(' (' + e(data['scope']) + ')') if data.get('scope') else ''}</h1>",
           f"<p class='muted'>Window {e(w['first'])} to {e(w['last'])} ({w['days']} days). Store {e(data['store'])}, logs from "
           f"{e(str(data['store_days']['first']))} to {e(str(data['store_days']['last']))}.</p>"]  # fmt: skip
    out.append("<h2>Gateways</h2><table><tr><th>Gateway</th><th>Days with logs</th><th>Lines that could not be read</th></tr>")
    for name, info in data["gateways"].items():
        cls = " class='n zero'" if info["days_with_logs"] < w["days"] else " class='n'"
        out.append(f"<tr><td>{e(name)}</td><td{cls}>{info['days_with_logs']} of {w['days']}</td><td class='n'>{info['unreadable_lines']}</td></tr>")
    out.append("</table>")
    c = data["connections"]
    out.append(f"<p>{c['in_window']} connections in the window, {c['attributed']} attributed to a rule of the policy"
               + (f", {c['possible']} possibly to one of several" if c.get("possible") else "")
               + (f"; {c['by_simulation']} named no rule and were matched against the rules" if c.get("by_simulation") else "") + ".</p>")
    out += [f"<p>Counted as possible only: {e(why)}.</p>" for why in c.get("possible_only_because", [])]
    if c["not_attributed"]:
        out.append("<table><tr><th>Not attributed</th><th>Connections</th></tr>")
        out += [f"<tr><td>{e(reason)}</td><td class='n'>{count}</td></tr>" for reason, count in c["not_attributed"].items()]
        out.append("</table>")
    out.append("<h2>Findings</h2>")
    findings = data["findings"]
    if findings:
        out.append("<table><tr><th>Level</th><th>Check</th><th>Rule</th><th>What</th></tr>")
        for f in findings:
            accepted = " (accepted" + (": " + e(f["reason"]) if f.get("reason") else "") + ")" if f["action"] == "accept" else ""
            out.append(f"<tr><td class='level'>{e(f['level'])}</td><td><code>{e(f['check'])}</code></td><td>{e(f['name'])}</td>"
                       f"<td>{e(f['message'])}{accepted}</td></tr>")  # fmt: skip
        out.append("</table>")
    else:
        out.append("<p>None.</p>")
    out.append("<h2>Rules</h2>")
    for rule in data["rules"]:
        extra = (f", {rule['by_simulation']} by simulation" if rule.get("by_simulation") else "") + (
            f", {rule['possible']} possible" if rule.get("possible") else "")  # fmt: skip
        out.append(f"<section class='rule'><h3>{e(rule['name'])} <span class='muted'>({e(rule['action'])}, {rule['connections']} "
                   f"connections{extra})</span></h3>")  # fmt: skip
        if rule.get("no_evidence"):
            out.append("<p class='muted'>The logs prove nothing about this rule: " + e("; ".join(rule["no_evidence"])) + ".</p>")
        for cell in ("source", "destination", "service", "user"):
            members = rule["members"].get(cell)
            if not members:
                continue
            unjudged = set(rule.get("unjudged", {}).get(cell, []))
            out.append(f"<table><tr><th>{e(cell.capitalize())}</th><th>Connections</th></tr>")
            for name, count in members.items():
                cls = " class='n zero'" if count == 0 and name not in unjudged else " class='n'"
                note = " <span class='muted'>(cannot be told from an address or port)</span>" if name in unjudged else ""
                out.append(f"<tr><td>{e(name)}{note}</td><td{cls}>{count}</td></tr>")
            out.append("</table>")
        out.append("</section>")
    if data.get("cross_check"):
        out.append("<h2>Hit counters and logs disagree</h2><ul>" + "".join(f"<li>{e(line)}</li>" for line in data["cross_check"]) + "</ul>")
    out.append("</body></html>")
    return "\n".join(out) + "\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_files(paths: Iterable[str], reader: Any) -> List[Tuple[str, bytes]]:
    return [(path, reader(path)) for path in paths]


__all__ = ["DEFAULT_CAP", "Evaluation", "Ingested", "Store", "Window", "evaluate", "ingest", "to_dict", "to_html", "to_text", "window"]
