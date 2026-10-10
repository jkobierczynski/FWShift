# FWShift development notes

How the code is organised, the rules it follows, how to extend and test it,
and a log of what has been done. For using the tool, see the
[user manual](docs/MANUAL.md).

## Status

| | |
|---|---|
| Version | 0.2.0 (alpha) |
| Platforms | PAN-OS and Panorama (read XML, write `set` commands); FortiOS (read and write CLI configuration); Check Point (read Management API JSON, write a `mgmt_cli` script); iptables and ip6tables (read `iptables-save`, write `iptables-restore` files) |
| Tests | 300, all passing (6 of them need root and iptables and are skipped elsewhere); `mypy --strict` clean |
| Verified on devices | **iptables only**: rulesets loaded into a Linux kernel and real packets forwarded through it (below). Nothing has been loaded on PAN-OS, FortiOS or a Check Point management server |
| Next | Lab validation of the sample conversions |

## Layout

```
src/fwshift/
    model.py          the vendor-neutral policy model and its semantics
    parsers/
        panos.py      PAN-OS / Panorama XML  -> model
        fortios.py    FortiOS configuration  -> model
        checkpoint.py Management API JSON    -> model (inline layers flattened)
        iptables.py   iptables-save output   -> model (chains flattened)
    emitters/
        panos.py      model -> PAN-OS set commands
        fortios.py    model -> FortiOS CLI configuration
        checkpoint.py model -> shell script of mgmt_cli calls
        iptables.py   model -> iptables-restore / ip6tables-restore file
    transform.py      passes shared by the emitters: hardening of names,
                      references, placeholders, names, application lowering,
                      NAT destination rewriting, NAT order, pruning
    appmap.py         application/port table, protocol tables, reserved names
    netutil.py        IP intervals
    names.py          naming rules of the targets
    report.py         findings, item status, text and JSON report
    options.py        conversion options
    cli.py            command line; also the small Python API (load, convert)
tests/
    data/             one synthetic sample per format
    data/expected/    their conversions and reports, byte for byte
    tools/            the script that writes the Check Point sample
    helpers.py        loaders, and readers for emitted PAN-OS, FortiOS and
                      Check Point output
    test_parsers.py   netutil, FortiOS syntax, PAN-OS and FortiOS parsers
    test_emitters.py  PAN-OS and FortiOS emitters
    test_semantics.py one small configuration per semantic trap
    test_iptables.py  iptables both ways, a packet simulator, cross-format NAT
    test_checkpoint.py Check Point both ways, with simulators for an export
                      and for an emitted script
    test_cli.py       command line, golden files
docs/MANUAL.md        user manual
```

No third-party dependencies at run time. Python 3.9 is the floor because it is
the system Python of RHEL 9.

## How a conversion runs

```
bytes ──parser──▶ Policy ──emitter──▶ text
                    │                  ▲
                    └── Report ────────┘   (findings from both sides)
```

1. `cli.load` picks the parser. The parser returns a `Policy` and records
   findings about what it could not read.
2. `cli.convert` checks the option values, runs `transform.harden` on the
   model (control characters out of every name, host names and ports that are
   none made unusable), registers every rule and object in the `Report`, in
   source order, then calls the emitter.
3. The emitter works on a deep copy. In order: `apply_zone_map`,
   `ensure_references` (placeholders for dangling references),
   `sanitize_names`, target-specific lowering, rendering.

Parsers know one vendor and the model. Emitters know one vendor and the model.
Neither knows the other vendor; where an emitter needs to know where a policy
came from (same-vendor conversions, default behaviour), it reads
`Policy.vendor` and the `default_intrazone` / `default_interzone` fields.

## The neutral model

`model.py` states the semantics every parser normalises to:

* Security rules match **pre-NAT** addresses and ports and the **post-NAT**
  destination zone.
* `any` is any address of either IP version. IPv4-only "any" is the literal
  `0.0.0.0/0`, IPv6-only "any" is `::/0`.
* A negate flag covers both IP versions.
* Rule members are object names or literals; a name wins over a literal.
* Port lists use PAN-OS syntax (`80,443,8000-8080`); empty means all ports.
* Application names are PAN-OS App-ID names.
* An FQDN is resolved for both IP versions unless `fqdn_family` says otherwise.
* NAT is an ordered, first-match rulebase separate from the security rules.

A vendor whose behaviour differs has to be translated *in its parser and
emitter*, never by bending the model. FortiOS and iptables are the examples:
they look rules up after destination NAT, so their parsers call
`rewrite_destinations(to_post_nat=False)` and their emitters
`to_post_nat_lookup`.

A few fields tell an emitter what kind of platform the rules came from, so
that it need not know the vendor:

| Field | Meaning |
|---|---|
| `default_intrazone`, `default_interzone` | what happens to traffic no rule matches |
| `lookup_after_dnat` | the source looks rules up after destination NAT; a target of the same kind undoes what the parser did and withdraws its findings |
| `NatRule.combines` | per NAT rule: the source applies it together with one rule of the other direction, instead of one rule, first match. Set for iptables, FortiOS and Check Point automatic rules (`transform.note_nat_order`) |

`builtin` on an object names the vendor on which the object exists without a
conversion creating it: a predefined service, a Check Point gateway. An
emitter for that vendor refers to it by name; every other emitter treats it as
an ordinary object.

## Rules the code follows

1. **Never widen silently.** If the target cannot express a match, the rule is
   emitted disabled (`transform.disable_rule`) or the NAT rule is skipped, with
   a `REVIEW` finding. An enabled approximation gets at least `APPROX`.
2. **Never read absence as "any".** A missing element, an unreadable value, or
   an attribute the parser does not know goes into `Rule.unsupported`, a
   tainted object, or a `REVIEW` finding.
3. **Keep every rule, in order.** Disabled rules stay in place so that the
   position of the gap is visible.
4. **Keep references resolvable.** Unconvertible objects become placeholders
   (`0.0.0.0/32`, `tcp/1`) that match nothing.
5. **Say what was done.** Anything the converter adds, renames, splits or
   merges is in the report.
6. **Narrower beats wider when unsure**, except for deny rules, where narrower
   is the dangerous direction: treat those separately (`APP_TO_PORTS` on a deny
   is `REVIEW`).

### Severity of findings

| Severity | Use it when |
|---|---|
| `INFO` | The result is exact; the reader should still know (rename, split, merged NAT rule). |
| `APPROX` | The rule is enabled and its semantics changed in a known, bounded way. |
| `REVIEW` | A person must decide: the rule is disabled or skipped, or it is enabled and may be wider or narrower than the source. |

Codes are upper-case identifiers and are part of the interface (JSON report,
manual section 7). When adding one, add it to the manual.

## Adding a vendor

The work is:

1. **Parser** `parsers/<vendor>.py` with `parse(data: bytes, report, ...) -> Policy`.
   Normalise to the model semantics above. Give every rule a unique `name` and
   set `origin` to it; the report is keyed by `origin`. Put anything that
   narrows a match and cannot be modelled into `Rule.unsupported`.
2. **Emitter** `emitters/<vendor>.py` with `emit(policy, report, options) -> str`.
   Start with the shared passes in `transform.py`; write the lowering so that
   every lossy step adds a finding.
3. **Register** both in `cli.py` (`load`, `EMITTERS`, `VENDORS`, format
   detection, options for scope selection).
4. **Names**: add the target's rules to `names.py` and its reserved names to
   the emitter.
5. **Sample and tests**: a synthetic configuration in `tests/data`, golden
   conversions to and from the existing vendors, and a case in
   `test_semantics.py` for every behaviour that differs from the model.
6. **A simulator** where the format allows one. For iptables and Check Point
   the tests evaluate packets against the source, the model and the emitted
   output and require the same verdict; that found defects no hand-written
   case had.
7. **Manual**: how to get the input (section 3), conversion notes in section
   8, new findings in section 7, how to load the output (section 10).

## Testing

```sh
pip install -e ".[dev]"
python -m pytest -q
python -m mypy
```

* **Sample tests** convert `tests/data/*` and assert on the parsed result.
  `tests/helpers.py` reads emitted FortiOS back with the project's own tree
  parser and emitted PAN-OS `set` commands with a small indexer, so assertions
  are on structure, not on text.
* **Golden files** in `tests/data/expected/` hold the full conversions and
  reports. After an intended change:

  ```sh
  FWSHIFT_UPDATE_GOLDEN=1 python -m pytest tests/test_cli.py
  git diff tests/data/expected
  ```

  Review that diff like code: it is the output users get.
* **`test_semantics.py`** has one small configuration per trap. Every defect
  found in review has a test there. Add one whenever a conversion rule changes.
* **Round trip**: FortiOS -> model -> FortiOS -> model is asserted equal for a
  configuration without NAT. PAN-OS output cannot be read back, since the
  parser reads XML and the emitter writes `set` commands.
* **Packet-level equivalence** (`test_iptables.py`, `test_checkpoint.py`).
  Random models are emitted and random packets are evaluated against the
  model and against the output: an iptables ruleset walked like the kernel
  walks it, a `mgmt_cli` script replayed call by call (every reference must
  exist when it is used) and then matched like a gateway matches layers. In
  the other direction random rulesets and random exports with nested inline
  layers are evaluated directly and through the parser. A ruleset in which
  the parser flagged a rule is set aside, and the tests require that most
  are not.

  Know what these tests cannot see: the iptables simulator reads rules with
  the project's own `parse_rule`, so a misreading of one line is invisible to
  it, and no generator produces NAT. The cases a reviewer found that way are
  hand-written tests at the end of both files.
* **The kernel** (`test_iptables.py`, the tests marked `needs_kernel`). Where
  the test host allows it (root, `unshare`, iptables), emitted rulesets and
  the converted samples are loaded with `iptables-restore` into a network
  namespace of their own, saved again and compared with the model; random
  hand-written rulesets are parsed both as written and as `iptables-save`
  prints them. Elsewhere these tests are skipped.
* **Real packets** (`tests/tools/kernel_check.py`, not part of the suite).
  Builds three veth pairs in a private network namespace, loads a ruleset,
  injects TCP, UDP, ICMP and GRE packets on one pair and watches whether they
  come out of another, for random models (emitter) and random rulesets
  (parser). Needs root and `pyroute2`:

  ```sh
  unshare -n python3 tests/tools/kernel_check.py 40
  ```

  Last run (40 seeds): 75 rulesets, 13836 packets, of which 5998 forwarded,
  on kernel 6.18 with iptables 1.8.10 (nf_tables): the kernel and the model
  agreed on every packet. Half of the packets are aimed at allow rules, so
  that "forwarded" is tested as much as "dropped". It covers the `filter`
  table for IPv4; NAT and IPv6 forwarding are not exercised.
* `tests/tools/make_checkpoint_sample.py` writes `checkpoint_sample.json`.
  The shape of that export follows the API documentation; it has not been
  compared with the output of a real management server.

Test data is synthetic: hand-written, with RFC 1918, RFC 5737 and RFC 3849
addresses. Do not add configurations from real networks, anonymised or not.

CI (`.github/workflows/ci.yml`) runs mypy and pytest on Linux for Python 3.9
to 3.13, and on Windows and macOS for 3.12.

## Design decisions

| Decision | Reason |
|---|---|
| Neutral model with parsers and emitters | Four formats need eight components instead of twelve pairwise converters; a fifth adds two. |
| Model follows PAN-OS for NAT and matching | PAN-OS and Check Point both match pre-NAT; FortiOS is the exception and is handled at its edges. |
| Disabled rule instead of best guess | A disabled rule is visible and safe; a guessed rule is neither. |
| Central NAT for FortiOS output | It is the FortiOS model that maps one-to-one onto a NAT rulebase. Per-policy NAT would need NAT rules to be merged into security policies, which is lossy in the general case. Cost: it must be enabled on the FortiGate. |
| Small application table, not a copy of App-ID | A port-based policy can only express ports. A table that is small and readable can be checked; `--app-map` covers the rest. |
| `set` commands for PAN-OS output | They can be pasted into any PAN-OS or Panorama CLI and merged into an existing configuration; XML would have to replace or be merged by hand. |
| PAN-OS output holds no comments | The CLI has no comment syntax; everything goes to the report instead. |
| `edit 0` for FortiOS policies | Appends without colliding with existing policy ids. `--policy-id-start` exists for scripted setups. |
| iptables: `FORWARD` and `nat` only | The other platforms filter what passes through them; `INPUT` and `OUTPUT` protect the host itself and have no counterpart. Writing them would also lock people out of the host they load the file on. |
| iptables: lists become chains | iptables has no objects and a rule matches one address per side. A chain per list keeps a rule with long or negated lists to one jump, instead of a product of lines. |
| Check Point input is API JSON | There is no configuration file. The API export is documented, versioned and what other tools consume. |
| Check Point output is a `mgmt_cli` script that stops at the first error and never publishes | The session is the unit of change on a management server: a person reviews it in SmartConsole and publishes or discards. A script that carried on after a refused call would leave a policy with rules missing. |
| Check Point: one inline layer per zone pair | A cell that holds a zone and an address means "either". Zone and address on one side need two rules in sequence, and a layer per rule would swallow the traffic that the rule does not match. A layer per zone pair holds every rule for that pair. Rules whose cells can carry the zone stay single rules. |
| Check Point: explicit cleanup in every layer written | The implicit cleanup action is a property of the layer that the script does not control. |
| NAT order is reported, not emulated | A first-match NAT rulebase and two NAT tables differ in ways `PREROUTING` cannot express (it does not know the outgoing interface). The report names each rule that changes meaning. |
| Reserved names are renamed | An object called `all` or `HTTP` from another platform would otherwise redefine a FortiOS built-in. |
| Standard library only | Runs on a bare RHEL box and is easy to audit. |
| GPL-3.0-or-later | Copyleft: changes to a tool that rewrites security policy stay open to inspection. |

## Vendor behaviour the code relies on

These come from documentation and community knowledge, not from a lab. Each
needs confirming on a device, and each is a place to look first if a converted
policy behaves unexpectedly.

| Assumption | Used in |
|---|---|
| FortiOS looks policies up after destination NAT; with central NAT the policy names the mapped address and VIPs cannot be used in policies | `rewrite_destinations`, FortiOS emitter |
| With per-policy NAT a FortiOS policy naming the mapped address also matches VIP traffic | FortiOS parser |
| A FortiOS deny policy matches VIP traffic only with `match-vip enable` (default from 7.2.3) | `_deny_and_vips` |
| FortiOS `all` is IPv4-only; `srcaddr6`/`dstaddr6` must both be set for IPv6 to match | FortiOS parser and emitter |
| FortiOS has `srcaddr6-negate` / `dstaddr6-negate` and `address6` of type `fqdn` | FortiOS emitter |
| A FortiOS zone can be created without interfaces | FortiOS emitter |
| PAN-OS negation and FQDN objects cover both IP versions | PAN-OS emitter, FortiOS parser |
| PAN-OS accepts `0.0.0.0/32` as an address, a bare `set tag NAME`, FQDN objects as NAT match, and a service group in a NAT rule | PAN-OS emitter |
| The App-ID names in `appmap.py` (`ping`, `icmp`, `gre`, `ipsec-esp`, ...) | PAN-OS emitter |
| A PAN-OS NAT rule needs one destination zone; `any` is not accepted | PAN-OS emitter (`--target-nat-zone`) |
| iptables NAT: `FORWARD` sees destinations after `PREROUTING`; `POSTROUTING` cannot match the input interface; `iptables-restore --noflush` adds to existing chains. (The filter-table syntax and semantics the emitter and parser rely on are checked against a kernel, see Testing.) | iptables parser and emitter |
| Check Point matches the access rulebase on the original packet and takes the destination zone after NAT | model, Check Point parser and emitter |
| A connection sent into an inline layer never returns to the parent layer; a layer without a matching rule applies its implicit cleanup action | Check Point parser |
| An object with automatic static NAT matches its translated address in the rulebase; with manual NAT the rules name the original address | `_automatic_nat`, `_also_valid` |
| Automatic NAT rules in `show nat-rulebase` name the object itself in the translated column; the address is in the object's `nat-settings` | `_nat_rule` |
| Shape of `show access-rulebase` / `show nat-rulebase` answers: `rulebase`, `objects-dictionary`, sections, `from`/`to`/`total` (with `total` counting rules, not section titles), `inline-layer`, the field names of each object type; objects of data domains are predefined | Check Point parser |
| `mgmt_cli` syntax of every call the script makes (`add host`, `add network`, `add address-range`, `add dns-domain`, `add group`, `add service-tcp/-udp/-sctp/-icmp/-icmp6/-other`, `add service-group`, `add security-zone`, `add access-layer ... add-default-rule false`, `add access-rule ... position N`, `add nat-rule ... position bottom`), switches after the command, a non-zero exit status when the server refuses a call | Check Point emitter |
| Check Point accepts an address range `0.0.0.0`-`255.255.255.255`, domain objects as group members, empty groups as placeholders, and object names made of letters, digits, `.`, `_` and `-` | Check Point emitter |

## Development log

### 2026-10-10: version 0.1.0

**Built**

* Neutral model, findings and report (text and JSON).
* PAN-OS parser: firewall and Panorama XML, vsys, `shared`, device-group
  hierarchy with pre- and post-rulebases, application groups, default-rule
  overrides.
* FortiOS parser: generic configuration tree (quoting, multi-line values,
  VDOMs), addresses and groups for both IP versions, services, virtual IPs,
  IP pools, per-policy NAT and central NAT.
* Emitters for both platforms, including NAT in both directions, rule types,
  name sanitising, placeholders.
* Command line with `convert` and `inspect`; zone, interface and application
  maps; target scopes; pruning.
* Two synthetic sample configurations with golden conversions.
* Renamed from the working name `fwconv` to FWShift.
* README, user manual, this file; GPL-3.0-or-later with SPDX headers.

**Reviewed**

An independent reviewer attacked the tool three times, with reproduction
scripts, a mutation fuzzer and a generator of structured configurations.

| Round | Found | Examples |
|---|---|---|
| 1 | 12 silent widenings, 3 crash classes, 6 wrong outputs, 5 minor | negation applied to the wrong IP version; objects named `any` read as the wildcard; objects named `all` redefining FortiOS built-ins; unknown FortiOS attributes ignored; rules on the internal address matching translated traffic; per-policy NAT translating traffic the source did not; unbalanced quote swallowing a deny |
| 2 | 8 | groups holding an FQDN hidden from the NAT analysis; one-sided IPv6 address lists; `--zone-map` merge creating an intrazone allow |
| 3 | 3 | missing PAN-OS elements read as "any"; gaps in reserved names |

All are fixed, each with a test in `tests/test_semantics.py`. Apart from the
crash classes of round 1, the fuzzers ran without a traceback in every round.

**Not done, known**

* No validation on devices (see the table above).
* The service of a rule behind a port-translating NAT is reported, not fixed.
* FortiOS output offers central NAT only.
* PAN-OS `set`-format input is not read.
* Schedules, users and groups, security profiles are not converted.

### 2026-10-10: version 0.2.0

**Built**

* iptables and ip6tables, read and written. The parser flattens user chains
  into the rules that jump to them and merges the matches exactly; the emitter
  writes lists and negations as chains.
* Check Point, read and written. The parser flattens inline layers, reads
  automatic NAT from object settings and marks predefined objects and
  gateways; the emitter writes a `mgmt_cli` script with inline layers per zone
  pair.
* Shared: `transform.lower_applications` (one implementation of application
  to port lowering for the three port-based targets), `to_post_nat_lookup`,
  `note_nat_order`, `harden`, `Policy.lookup_after_dnat`,
  `NatRule.combines`, `builtin` on every object class, `Report.retract`.
* PAN-OS output: NAT rules of a source without zones need
  `--target-nat-zone`.
* Packet-level equivalence tests in both directions for both new formats, and
  for iptables against a real kernel: rulesets loaded with `iptables-restore`,
  and real packets forwarded through netfilter.

**Reviewed**

Four more rounds by the independent reviewer, on the new formats and on the
changes to shared code. From round 6 on the reviewer had the kernel to check
iptables against, and used it.

| Round | Found | Examples |
|---|---|---|
| 4 | 12 silent errors, 2 injections, 1 emitter crash, parser tracebacks and hangs | `-s` next to `--src-range` overwriting each other; a comment with `::` turning an IPv4 ruleset into IPv6; a Check Point wildcard object read as one host; a rule type with zone `any` not applied between unnamed zones; a zone name with a line break starting a shell command in the script |
| 5 | 4 silent NAT errors, 2 understated findings, robustness gaps | first-match NAT order lost on FortiOS and iptables; the source half of a destination-and-source NAT rule matched on pre-NAT port and interface; an automatic NAT rule turned into an identity translation; `str.isdigit` accepting digits `int` cannot read; a translated port written unchecked |
| 6 | 5 silent errors (2 found by sending packets through the kernel), 2 understated, 3 robustness | NAT order shapes the first check missed; `-s a/0.0.255.255` read as a /16 because `ipaddress` accepts host masks; two `--icmp-type` matches where the last one won; a missing page of a Check Point export going unnoticed; `"enabled": "false"` read as enabled |
| 7 | 2 missed and 2 needless NAT order findings, nothing else | a hide rule bound to another zone than the original address; a no-NAT rule that shields the traffic anyway |

All are fixed, with tests at the end of `tests/test_iptables.py` and
`tests/test_checkpoint.py`. Round 5 also checked, with the reviewer's own
generators (some 1650 random models), that the Check Point emitter does not
widen for zones the policy names; merging zones with `--zone-map` does widen,
there as on the other targets, and is the user's choice. A generated script
with hostile names was run under sh, bash and dash against a stand-in for
`mgmt_cli`: every name arrived as one argument and nothing else was executed.

**Not done, known**

* No validation on PAN-OS or FortiOS devices or a Check Point management
  server. For Check Point the input format itself is unverified: the sample is
  written from the API documentation. iptables is verified for the filter
  table on one kernel and iptables version; its NAT output is not.
* NAT order between a first-match rulebase and per-direction tables is
  reported, not reproduced, and the check behind the report is a comparison of
  rule pairs by zone, address and service: every review round found a shape
  it missed. Treat `NAT_ORDER` as a list of places to look, not as proof that
  the rest is unchanged.
* An iptables `ACCEPT` in `PREROUTING` is not converted, not even to iptables:
  the model cannot say "exempt from destination NAT only".
* iptables: `INPUT`/`OUTPUT`, IPv6 NAT, `nft` syntax and most match modules.
* Check Point: several ordered layers per run, implied rules, identity,
  application control, VPN.
* Names that differ only in case are reported for Check Point, not resolved.

## To do

1. Load `tests/data/expected/fortios_to_panos.set` on a PAN-OS VM and
   `panos_to_fortios.conf` on a FortiGate VM; record what each CLI rejects and
   correct the emitters. Work through the assumptions table.
2. Run `*_to_checkpoint.sh` against a management server in a lab, and export a
   real rulebase with automatic NAT to compare with the sample. Extend
   `kernel_check.py` to NAT and IPv6, and run it on the legacy iptables
   backend.
3. Correct services for port-translating destination NAT.
4. FortiOS output with per-policy NAT as an option.
5. PAN-OS `set`-format parser, which also allows a PAN-OS round-trip test.
6. Schedule objects; a user/group mapping file.
7. Differential check as a command: evaluate the source and the converted
   model against sampled flows and report every flow whose verdict changed.
   The simulators in the tests are the start of it.
8. Release workflow that builds a wheel and a single-file `.pyz` on a version tag.
