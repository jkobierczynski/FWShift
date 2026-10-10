# FWShift development notes

How the code is organised, the rules it follows, how to extend and test it,
and a log of what has been done. For using the tool, see the
[user manual](docs/MANUAL.md).

## Status

| | |
|---|---|
| Version | 0.1.0 (alpha) |
| Platforms | PAN-OS and Panorama (read XML, write `set` commands); FortiOS (read and write CLI configuration) |
| Tests | 113, all passing; `mypy --strict` clean |
| Verified on devices | **No.** Nothing has been loaded on PAN-OS or FortiOS yet |
| Next | Lab validation of the two sample conversions, then Check Point |

## Layout

```
src/fwshift/
    model.py          the vendor-neutral policy model and its semantics
    parsers/
        panos.py      PAN-OS / Panorama XML  -> model
        fortios.py    FortiOS configuration  -> model
    emitters/
        panos.py      model -> PAN-OS set commands
        fortios.py    model -> FortiOS CLI configuration
    transform.py      passes shared by the emitters: references, placeholders,
                      names, NAT destination rewriting, pruning
    appmap.py         application/port table, protocol tables, reserved names
    netutil.py        IP intervals
    names.py          naming rules of the targets
    report.py         findings, item status, text and JSON report
    options.py        conversion options
    cli.py            command line; also the small Python API (load, convert)
tests/
    data/             synthetic PAN-OS and FortiOS samples
    data/expected/    their conversions and reports, byte for byte
    test_parsers.py   netutil, FortiOS syntax, both parsers, Panorama, VDOMs
    test_emitters.py  both emitters on the samples, options, constructed cases
    test_semantics.py one small configuration per semantic trap
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
2. `cli.convert` registers every rule and object in the `Report`, in source
   order, then calls the emitter.
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
emitter*, never by bending the model. FortiOS is the example: it looks
policies up after destination NAT, so its parser calls
`rewrite_destinations(to_post_nat=False)` and its emitter calls it with
`True`.

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

Check Point is next. The work is:

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
6. **Manual**: conversion notes in section 8, new findings in section 7.

Notes for Check Point specifically: there is no configuration file, so the
input is a Management API export (JSON); layers and inline layers have to be
flattened into one ordered rulebase; implied rules are not in the export;
zones are optional, so `--zone-map` or topology has to supply them; NAT has
automatic rules defined on objects next to manual rules. Rule matching is
pre-NAT, like the model.

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

Test data is synthetic: hand-written, with RFC 1918, RFC 5737 and RFC 3849
addresses. Do not add configurations from real networks, anonymised or not.

CI (`.github/workflows/ci.yml`) runs mypy and pytest on Linux for Python 3.9
to 3.13, and on Windows and macOS for 3.12.

## Design decisions

| Decision | Reason |
|---|---|
| Neutral model with parsers and emitters | Three vendors need six components instead of six pairwise converters; a fourth adds two. |
| Model follows PAN-OS for NAT and matching | PAN-OS and Check Point both match pre-NAT; FortiOS is the exception and is handled at its edges. |
| Disabled rule instead of best guess | A disabled rule is visible and safe; a guessed rule is neither. |
| Central NAT for FortiOS output | It is the FortiOS model that maps one-to-one onto a NAT rulebase. Per-policy NAT would need NAT rules to be merged into security policies, which is lossy in the general case. Cost: it must be enabled on the FortiGate. |
| Small application table, not a copy of App-ID | A port-based policy can only express ports. A table that is small and readable can be checked; `--app-map` covers the rest. |
| `set` commands for PAN-OS output | They can be pasted into any PAN-OS or Panorama CLI and merged into an existing configuration; XML would have to replace or be merged by hand. |
| PAN-OS output holds no comments | The CLI has no comment syntax; everything goes to the report instead. |
| `edit 0` for FortiOS policies | Appends without colliding with existing policy ids. `--policy-id-start` exists for scripted setups. |
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

## To do

1. Load `tests/data/expected/fortios_to_panos.set` on a PAN-OS VM and
   `panos_to_fortios.conf` on a FortiGate VM; record what each CLI rejects and
   correct the emitters. Work through the assumptions table.
2. Check Point parser, then emitter.
3. Correct services for port-translating destination NAT.
4. FortiOS output with per-policy NAT as an option.
5. PAN-OS `set`-format parser, which also allows a PAN-OS round-trip test.
6. Schedule objects; a user/group mapping file.
7. Differential check: evaluate the source and the converted model against
   sampled flows and report every flow whose verdict changed.
8. Release workflow that builds a wheel and a single-file `.pyz` on a version tag.
