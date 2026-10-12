# Rule usage: design

**Status:** accepted on 2026-10-12; 0.13.0 (rule identity and hit counters)
is done. The releases 0.13.0 to 0.17.0 carry it out (section 7); what each release built is in the development log of
[DEVELOPMENT.md](../DEVELOPMENT.md).

This document started as a feature brief written in a separate session for
the one that implements it. Sections 1 to 6, 8 and 10 are that brief, with
the corrections of the review in section 11 worked in where they change the
plan. Section 7 (the releases) and section 9 (the open questions, with the
answers chosen) were rewritten after the review. Where this document and
`DEVELOPMENT.md` disagree on names, codes or the way the code is written,
`DEVELOPMENT.md` wins.

---

## 1. Summary

Add a `usage` command that reads firewall logs, attributes each connection
to the rule that handled it, and counts which **objects, services and
subnets inside each rule** were actually used. The results become audit
findings: rules never used, objects in a rule never used, and allow rules
that are wider than the traffic they carry, with a proposed narrower rule.

The static audit answers "what does this policy allow?". `usage` answers
"what of that is actually used?". Together they are what commercial tools
(AlgoSec, Tufin, FireMon) sell as policy optimisation.

Before logs, a cheaper source answers part of the question: the **hit
counters** that Check Point, PAN-OS and FortiOS keep per rule (section 6.10).
They say which rules were used, not which objects in them, and need no log
store and no simulation.

## 2. Background: fwanalyser

Jurgen Kobierczynski wrote `fwanalyser` in Perl around 2016 and used it in
production to prune complex Check Point policies. Repositories:

- <https://github.com/jkobierczynski/fwanalyser> (Perl original)
- <https://github.com/jkobierczynski/fwanalyser-python> (Python port, August 2026)

How it worked:

1. `odumper` converted `objects_5_0.C` and `rulebases_5_0.fws` into one CSV
   of objects and rules. `fwm logexport` produced semicolon-separated logs.
   `fwpolicy.cfg` mapped gateways to policies.
2. Rule cells were resolved recursively through groups and exclusion groups
   into CIDRs with an include/exclude flag.
3. A global source trie and destination trie per policy gave candidate rules
   for an IP pair. Per-rule tries gave the objects inside the rule. Subnets
   were inserted supernet-first and each new prefix copied the entries of its
   covering prefix, so a longest-prefix lookup returned **every** covering
   object.
4. First match in rule order: the first candidate where source, destination
   and service matched got the hit, counted per object, per service (and
   parent service groups), and per /0, /8, /16, /24, /32 subnet.
5. Output was an HTML table per rule showing which objects were used.

The idea is proven in practice. The implementation had limits that this
feature must not repeat.

### 2.1 Defects verified in fwanalyser (regression tests)

Verified by running both the Perl original and the Python port on a small
test policy:

| # | Defect | Effect |
|---|---|---|
| D1 | A negated cell (`!X`) produces only exclude entries and no implicit "everything else" include. | The rule never matches. Its traffic lands in a later rule, usually the cleanup rule, so a rule in active use looks unused and gets pruned. |
| D2 | After the first `!` in a cell, all following entries in that cell are treated as excluded. | Wrong matches for mixed cells. |
| D3 | The install-on column is stored but never checked. | Logs from gateway B are counted against rules installed only on gateway A. |
| D4 | The last rule is assumed to match any service. | Wrong for policies without an Any/Any/Any cleanup rule. |
| D5 | Two objects with the same CIDR in one rule keep one counter. | The other object always shows zero hits. |
| D6 | Log parsing: `#` starts a comment anywhere, IPv4-only regex, service matched by name only, only tcp/udp/icmp. | Lines and services silently skipped. |
| D7 | Persistence restores the old object graph *after* parsing the new config. | Reports built against a stale rulebase. |
| D8 | Every distinct /32 is kept per rule. | Unbounded memory on wide rules over long periods. |
| D9 | Counters keyed by rule *number*. | History is attributed to the wrong rule after a reorder. |

The Python port fixed some of these but kept D1, and its per-rule matching by
default counts only the most specific covering object, which diverges from
the Perl behaviour (its `--all-covering` flag is the faithful one). Its
`BUGS_AND_CHANGES.md` misdiagnoses the global lookup as longest-prefix-only;
the Perl insert-time copying made it correct.

In FWShift's model negation belongs to a whole cell (`Rule.negate_source`,
`negate_destination`, `negate_service`), as it does in the Check Point
Management API, so D2 cannot arise; one test shows that.

### 2.2 Known limitations of fwanalyser this feature must solve

- **Check Point inline layers** are not supported.
- **Access Roles** (Identity Awareness: networks combined with AD users,
  groups or machines) are not supported.

Both come from the same root cause: the pre-R80 file format has no
representation for them. FWShift reads the Management API instead, which has
both.

## 3. Goals and non-goals

**Goals**

- Usage per rule, per object in each rule cell, per service, and per subnet,
  over a chosen time window.
- Correct handling of inline layers, negated cells, nested groups, Access
  Roles, IPv6 and install-on targets.
- Multi-vendor through the existing parsers: Check Point first, then PAN-OS
  and FortiOS, then iptables.
- Counters that survive policy revisions and rule reordering.
- Findings through the existing audit framework (levels, actions, acceptance
  with a reason, JSON report).
- Proposals for narrower rules, written through the existing emitters.
- No new runtime dependencies (`sqlite3` is in the standard library).

**Non-goals**

- Changing a policy on its own. `usage` produces findings; narrowing goes
  through the existing audit actions and the user's review.
- Real-time log collection. Input is files (or later an export from an API),
  read in batches.
- Replacing a SIEM. Only what is needed to attribute traffic to rules and
  objects is stored.

## 4. Principles

These follow "Rules the code follows" in `DEVELOPMENT.md`.

1. **Trust the gateway when it says which rule matched.** If a log or a
   counter carries the rule identity, use it. Simulate only when it does
   not, and say in the finding that the attribution was simulated.
2. **Absence of evidence is not evidence of absence.** A rule that does not
   log (`NO_LOG`), a gateway without logs in the window, a log source that was
   down, or a hit counter that was reset or switched off cannot produce an
   "unused" finding. Say why instead.
3. **Claims follow what can be proven.** Reuse the audit's distinction
   between what a rule *surely* matches and what it *might* match. A
   simulated attribution that depends on a loose rule (`_Match.loose`) is not
   counted as certain.
4. **Narrower beats wider when unsure**, except for deny rules: never propose
   narrowing a deny rule from usage data.
5. **Say what was done.** Every log line that could not be read or attributed
   is counted and reported by reason.

## 5. Architecture

```
config (any vendor) ──► parsers ──► Policy (model, with vendor rule IDs)
                                           │
hit counters (per vendor) ─────────────────┤  rule level only (0.13.0)
                                           │
logs (per vendor) ──► logreaders ──► LogRecord stream
                                           │
                               aggregate by key while reading
                                           │
                     attribute: by rule ID  │  or simulate (first match)
                                           │
                     object/service/subnet attribution within the rule
                                           │
                               SQLite store (counts per day)
                                           │
                    usage checks in audit ──► findings, report, proposals
```

## 6. Changes by component

### 6.1 Model (`model.py`)

- **Vendor rule identity.** `Rule.origin` is a generated, unique name. Add a
  field for the source platform's own identifiers, `source_ids: Dict[str,
  str]`, with keys such as `checkpoint.rule_uid`, `checkpoint.layer_uid`,
  `checkpoint.parent_rule_uid`, `panos.uuid`, `panos.name`,
  `fortios.policyid`, `fortios.uuid`. A rule produced by flattening an inline
  layer (`parsers/checkpoint.py`, `_combine`) keeps both the parent and the
  child identifiers.
- **Access Roles.** Today an access role becomes an unsupported address
  (`_unsupported_address`). Represent it as its network part plus its
  identities, using the existing `Rule.users` field for the identity part, so
  conversion stops losing it as well. If a role's network part is "any", the
  address cell stays `any` and the users carry the restriction. Several roles
  in one cell, or roles next to plain addresses, must not be merged into one
  wider rule (the networks of one role with the users of another): see 11.3.
- **Install-on targets.** `parsers/checkpoint.py` reads `install-on`
  (`_install_on`) only to report `DEVICE_TARGET`; the targets are not kept.
  Keep them on the rule (`Rule.targets`, empty for all), in a form `usage`
  can compare with the gateway name in a log.

These model changes are useful for conversion on their own and come before
any usage code.

### 6.2 Parsers

| Vendor | Rule identity to keep | Notes |
|---|---|---|
| Check Point | rule `uid`, layer `uid`, parent rule `uid` for inline rules | Already reads Management API JSON and flattens inline layers. |
| PAN-OS | rule `uuid` (PAN-OS 9.0 and later) and name | |
| FortiOS | `policyid` and `uuid` | `uuid` is already among the known fields. |
| Others | none at first | `usage` falls back to simulation. |

### 6.3 Log readers (new package `logreaders/`)

One module per format, each producing normalised records:

```python
@dataclass
class LogRecord:
    time: datetime            # UTC
    gateway: str              # originating gateway / device
    src: str                  # pre-NAT source address
    dst: str                  # pre-NAT destination address
    dst_zone: str             # post-NAT destination zone, where the platform logs it
    protocol: str             # tcp, udp, icmp, icmp6, sctp, or an IP protocol number
    dst_port: Optional[int]
    icmp_type: Optional[int]
    action: str
    rule_ids: List[Dict[str, str]]   # one entry per layer, outer first; empty when the log has none
    users: List[str]                 # identities when the log carries them
    raw_service: str                 # the service as logged, for diagnostics
```

The model's rules match pre-NAT destinations and the post-NAT destination
zone (`DEVELOPMENT.md`, "The neutral model"); a record keeps exactly those, so
a simulated match needs no NAT of its own.

Formats, in order of priority:

1. **Check Point Log Exporter** (key=value syslog). In inline-layer logs,
   `layer_name`, `layer_uuid`, `match_id`, `parent_rule`, `rule_action`,
   `rule_name` and `rule_uid` each appear **twice**: the first occurrence
   describes the outer layer, the second the inline layer. Parse each line as
   an ordered multimap, never as a dict, or the inline match is lost.
2. **Check Point CSV export** from SmartConsole / `fwm logexport`, with a
   header row. Accept both service names and port numbers (fwanalyser D6).
3. **PAN-OS traffic logs** (CSV and syslog).
4. **FortiOS traffic logs** (key=value).
5. **iptables `LOG` lines** (no rule identity: simulation only).

Every line that cannot be read is counted by reason (bad format, unknown
protocol, no address, IPv6 where not expected, and so on) and reported.
Nothing is skipped silently.

### 6.4 Aggregation and store

Aggregate while reading: millions of log lines collapse into a small number
of distinct keys. The key is:

```
(gateway, rule identity or "unattributed", src, dst, protocol, dst_port or icmp_type, day)
```

Store the aggregates in SQLite (`sqlite3`, standard library):

- `records(day, gateway, rule_key, src, dst, protocol, port, count)`: the
  aggregated traffic.
- `policy_revisions(id, read_at, source_file, digest)`: which policy each run
  was attributed against.
- `runs(id, started_at, log_files, lines_read, lines_skipped_by_reason)`:
  what was read, so a gap in coverage is visible.

Counters are keyed by vendor rule identity, never by rule number (fwanalyser
D9), so history survives reordering and edits. A rule that disappears from
the policy keeps its history in the store but produces no findings.

To bound storage (fwanalyser D8), keep individual addresses only up to a
configurable number per rule cell (256 by default) and roll the rest up into
prefixes (heavy-hitter style), noting in the report when this happened.

### 6.5 Rule attribution

**By rule identity (authoritative).** When the record carries rule
identities, look up the rule by `source_ids`. For an inline match, the
flattened rule is the one whose parent and child identities both match. This
covers inline layers, Access Roles, time objects and application control
without simulating any of them, because the gateway already decided.

**By simulation (fallback).** When the record has no rule identity:

- Evaluate rules in order on the model, first match wins.
- Build the evaluator on the audit's existing machinery:
  `audit._Reader.match(rule, index)` already yields what each rule surely
  matches (`src_under`, `dst_under`, `svc_under`) and what it might match
  (`*_over`), with negation handled through `address_sets(members, negated)`.
  A record is one point; whether it lies in a rule's sets is a lookup, not a
  set operation.
- A record that falls in a rule's "sure" set counts as certain. A record that
  only falls in the "might" set, or reaches a `loose` rule first, counts as
  possible and is reported separately.
- Filter by install-on target and gateway first (fwanalyser D3).
- Do not assume the last rule matches everything (fwanalyser D4); Check
  Point's implicit cleanup and each vendor's default action are modelled as
  they are elsewhere in FWShift.

Simulation runs once per aggregated key, not once per log line.

### 6.6 Attribution within the rule

For each attributed record, count:

- **Every** object in the source cell and destination cell that covers the
  address, through nested groups, each object counted once per record
  (fwanalyser semantics, fixing D5).
- For a negated cell, the hit is "outside the listed objects"; count it as
  such, not against the listed objects.
- Every service and service group that covers the protocol and port, each
  counted once per record.
- For Access Roles, the role, and the identities when the log carries them.
- Subnet usage per cell, for the narrowing proposal (6.7).

### 6.7 Audit checks

New entries in `audit.CHECKS`, using the existing levels, actions and
acceptance:

| Code | Level | Meaning | Release |
|---|---|---|---|
| `UNUSED_RULE` | MEDIUM | Allow rule with no traffic: zero on the hit counter (0.13.0), or no attributed log records in the window (0.14.0). | 0.13.0 |
| `NO_USAGE_EVIDENCE` | INFO | A rule for which no conclusion is possible (does not log, gateway without logs in the window, counter reset in the window or off, only possible attributions). | 0.13.0 |
| `UNUSED_RULE_OBJECT` | LOW | Object in a rule cell with no traffic in the window. | 0.14.0 |
| `UNUSED_RULE_SERVICE` | LOW | Service in a rule with no traffic in the window. | 0.14.0 |
| `WIDER_THAN_TRAFFIC` | LOW | Allow rule whose observed traffic is a small part of what it allows; includes a proposed narrower rule. | 0.17.0 |

The brief named the per-object checks `UNUSED_OBJECT` and `UNUSED_SERVICE`;
`UNUSED_OBJECT` is taken (objects no rule refers to), so they carry the word
`RULE`.

Rules:

- No usage finding for deny rules except `NO_USAGE_EVIDENCE`.
- No `UNUSED_*` finding for a rule that does not log or whose gateways had no
  logs for part of the window. Report `NO_USAGE_EVIDENCE` instead.
- Findings state the window, the number of log lines (or the counter) behind
  them, and whether attribution was by rule identity or simulated.
- The `disable` action applies to `UNUSED_RULE` as it does to other checks;
  narrowing proposals are written through the emitters, never applied
  silently.
- Add each new code to `MANUAL.md` section 7, as `DEVELOPMENT.md` requires.

### 6.8 CLI

A proposal; align with the existing `_source_options` and `_audit_options`
helpers.

```
fwshift usage --from checkpoint policy.json \
              --logs logs/*.log --log-format checkpoint-logexporter \
              --store usage.db --since 90d \
              --report usage.json --html usage.html
```

- `--store` accumulates across runs; reading the same log file twice must not
  double-count (record file name and digest in `runs`).
- `--since` / `--until` select the window for findings (90 days by default);
  the store keeps everything.
- Without `--logs`, report from the store only.

Hit counters (0.13.0) need no new command: they are an input of `audit`,
either inside the configuration (Check Point rulebases exported with
`show-hits`) or as a separate file (`--hits FILE`, the PAN-OS and FortiOS
answers in 6.10).

### 6.9 Output

- JSON in the same shape as the existing audit report, so tooling that reads
  one reads both.
- HTML per rule: rule text, hits per object, service and subnet, as
  fwanalyser showed, plus the findings. Self-contained, no external assets.
  The renderer is shared with the HTML findings of `TODO.md` (*Audit and
  matrix* 8).
- A summary of what was read and skipped, by reason.

### 6.10 Hit counters (0.13.0)

What each platform exports per rule, and what FWShift reads from it:

| Platform | Where | Per rule | Matched by |
|---|---|---|---|
| Check Point | `show-access-rulebase` with `show-hits: true` (optionally `hits-settings` with `from-date`, `to-date`, `target`); the `hits` object of each rule, and `meta-info` (`creation-time`, `last-modify-time`) | `value`, `first-date`, `last-date` (`posix` in milliseconds) | the rule itself (same file) |
| PAN-OS | the answer of `show rule-hit-count vsys vsys-name <vsys> rule-base security rules all` (XML API) | `hit-count`, `first-hit-timestamp`, `last-hit-timestamp`, `last-reset-timestamp`, `rule-creation-timestamp`, `rule-modification-timestamp` (seconds) | vsys and rule name |
| FortiOS | the answer of `GET /api/v2/monitor/firewall/policy` | `hit_count`, `first_used`, `last_used` (seconds) | `policyid`, `uuid` |

A counter of zero is evidence only for the time it has been counting, from
its start to the moment it was read, for which the latest time its answer
shows stands in (each answer by its own times). The start is the latest of
the reset, creation and change of the rule on PAN-OS; on Check Point, which
keeps counts for a period only, the later of the creation or change of the
rule and the earliest first hit in the export; FortiOS gives none.
`--hits-since` is the user's word for a start the counters do not give.
`UNUSED_RULE` needs a known start at least `usage_days` (90) before the
reading; otherwise, and for counters that may leave out a firewall (one
firewall's answer for a Panorama device group, a rule that one of several
answers does not count), `NO_USAGE_EVIDENCE`. A gateway with hit counting off
(Check Point counts only gateways that have it on) limits the claim, and the
finding says so.

## 7. Releases

One release per step, each done when its tests pass and the documents say
what was built and verified, as for the firewall brands. The model changes
come first because they are useful without the usage feature.

| Version | Content | Done when |
|---|---|---|
| 0.13.0 | **Rule identity and hit counters.** `source_ids` on rules (Check Point rule, layer and parent rule UIDs, also for flattened inline rules; PAN-OS UUID and name; FortiOS `policyid` and UUID), kept in `--to json` and in the JSON findings of the audit. Install-on targets on the rule (`Rule.targets`). Access Roles in the model instead of unsupported addresses, and conversion keeps or flags them per target. `UNUSED_RULE` and `NO_USAGE_EVIDENCE` from hit counters: Check Point hits inside the rulebase, PAN-OS and FortiOS through `audit --hits FILE`. | Parser tests check the IDs and targets; conversion tests for rules with Access Roles; audit tests for counters, resets and the absence of evidence. |
| 0.14.0 | **`fwshift usage` for Check Point.** Log Exporter and CSV readers, aggregation, SQLite store, attribution by rule identity, attribution to objects and services, `UNUSED_RULE_OBJECT`, `UNUSED_RULE_SERVICE`, JSON and HTML output. Hit counters as a cross-check of the totals. | The regression tests of section 8 pass; manual updated. |
| 0.15.0 | **Simulation.** A first-match evaluator on the audit's matches; certain against possible; the iptables `LOG` reader. | Simulated and ID-based attribution agree on the test fixtures. |
| 0.16.0 | **PAN-OS and FortiOS logs.** Readers for their traffic logs. | Fixture tests per vendor. |
| 0.17.0 | **Narrowing.** `WIDER_THAN_TRAFFIC` with a proposed rule written through the emitters. | Proposal tests: never wider than the original, never for deny rules. |

## 8. Tests

Synthetic fixtures in `tests/data`, in the style of `test_semantics.py`: one
small configuration per trap. No log or configuration from a real network,
anonymised or not; log fixtures are written from the vendors' documentation
(see 11.4).

Regression tests from fwanalyser (section 2.1), using this policy:

```
Net10    = 10.0.0.0/8
Net10_1  = 10.1.0.0/16
Host1    = 10.1.1.1
Srv      = 172.16.0.10
BigSrc   = group(Net10, Host1)

1  Net10_1   -> Srv  http   accept
2  !Net10_1  -> Srv  http   accept
3  BigSrc    -> Srv  https  accept
4  Any       -> Any  Any    drop    (cleanup)
```

| Log | Expected rule | Expected object hits |
|---|---|---|
| 10.1.5.5 → Srv https | 3 (falls past rule 1 on service) | Net10 |
| 10.2.0.1 → Srv http | **2** (negated source) | "outside Net10_1" |
| 10.1.1.1 → Srv https | 3 | **Net10 and Host1** |
| 192.168.1.1 → Srv http | **2** | "outside Net10_1" |

fwanalyser sends the second and fourth lines to rule 4 (D1), and the Python
port's default counts only Host1 for the third line.

Further cases:

- A negated cell with two members (D2 does not arise in the model).
- A rule installed on gateway A, a log from gateway B (D3).
- A policy without a cleanup rule (D4).
- Two objects with the same CIDR in one rule (D5).
- A log line with `#` in a field, an IPv6 line, a numeric service, an
  ESP/GRE line (D6).
- Reordering rules between two runs; counts stay with the right rules (D9).
- An inline-layer Log Exporter line with repeated keys; attributed to the
  flattened inline rule.
- A rule with an Access Role and a log that carries the user.
- A rule that does not log: `NO_USAGE_EVIDENCE`, not `UNUSED_RULE`.
- The same log file read twice: counts unchanged.
- Simulated attribution through a `loose` rule: reported as possible, not
  certain.
- Hit counters (0.13.0): a counter of zero; a counter reset after the start
  of the window; a rule created recently; a counter file that names a rule
  the policy does not have, and a rule the file does not name.

## 9. Open questions, and the answers chosen

1. *Which Check Point log sources first?* Log Exporter syslog and the
   SmartConsole CSV export. The `show-logs` output of the Management API
   later, if asked for.
2. *Read the rule hit counts of the Management API as a cross-check?* Yes,
   and first: they are the whole of 0.13.0's `UNUSED_RULE`, and a cross-check
   of the log totals from 0.14.0.
3. *Which identity fields do the gateways log for Access Roles?* Open. It
   needs the documentation of the Log Exporter fields; no real log is used.
   Until then a rule with an Access Role is attributed by its rule UID only.
4. *Default window for findings?* 90 days; every finding states its own
   window.
5. *Addresses per cell before the roll-up into prefixes?* 256, as an option.
6. *One store per policy package or per site?* One per management server,
   with the policy revisions recorded in it; rule identities keep history with
   the right rule across packages and reorderings.

## 10. References

- fwanalyser (Perl): <https://github.com/jkobierczynski/fwanalyser>
- fwanalyser (Python port): <https://github.com/jkobierczynski/fwanalyser-python>
- Check Point CheckMates, Log Exporter and inline layers (repeated layer and
  rule fields):
  <https://community.checkpoint.com/t5/Firewall-and-Security-Management/Logexporter-Inline-Layer-filtering/m-p/161275/highlight/true>

## 11. Review against the code (2026-10-12)

The brief was checked against FWShift 0.12.4 before it was accepted.

### 11.1 What holds

The functions and fields the brief builds on exist as described:
`audit._Reader.match`, the sets `src_under`, `dst_under`, `svc_under` and
their `*_over` counterparts, `address_sets(members, negated)`, `_Match.loose`,
`audit.CHECKS`, the `NO_LOG` check, `Rule.users`, and in the Check Point
parser `_install_on`, `_combine` and `_unsupported_address`. TODO item 7 of
*Audit and matrix* ("Hit counts where a source exports them") is the same
idea at rule level.

FWShift is the right home for it, rather than a tool of its own: the hard part
of fwanalyser was understanding the policy (groups, exclusions, negation,
rule order), and FWShift already reads that for thirteen platforms into one
model, with inline layers through the Management API and the audit's
distinction between what a rule surely and possibly matches. The principle
"absence of evidence is not evidence of absence" is FWShift's "missing is
never any" applied to traffic.

### 11.2 What the brief had to correct

- **Install-on is not kept.** The Check Point parser reports `DEVICE_TARGET`
  and drops the targets. The model needs `Rule.targets` before anything can
  filter by gateway (D3).
- **D2 cannot arise** in the model (negation per cell; section 2.1).
- **Hit counters first.** The rule-level question needs neither logs nor a
  store, three of the platforms export the counters, and they cross-check the
  log totals later. They became part of 0.13.0.
- **The record needs the destination zone** for platforms whose rules match
  the post-NAT zone (PAN-OS); added to `LogRecord`.
- **HTML output** is shared with the HTML findings already planned.

### 11.3 Access Roles and the promise

A cell may hold several Access Roles, or Access Roles next to plain
addresses. Putting the networks of all of them into the address cell and the
identities of all of them into `Rule.users` would let the network of one
role through for the users of another: wider than the source, which a
conversion must never be without saying so. Such a rule is split instead,
one rule per role and one for the plain addresses, in place and with the
same action; adjacent rules with the same action match what the original
matched. Identities FWShift cannot express (machines, remote access clients)
keep the rule disabled and reported, as an unsupported address does today.

### 11.4 What the tests can and cannot show

Test data is synthetic only. The configurations, counter answers and log
lines are written from the vendors' documentation, SDKs and the examples
they publish, so the tests prove the logic and the formats as documented,
not that every line a real gateway writes is read. As for the converters,
"verified on devices" stays "no" until someone runs FWShift on a real export.
