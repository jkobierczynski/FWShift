# FWShift development notes

How the code is organised, the rules it follows, how to extend and test it,
and a log of what has been done. For using the tool, see the
[user manual](docs/MANUAL.md).

## Status

| | |
|---|---|
| Version | 0.6.1 (alpha) |
| Platforms | PAN-OS and Panorama (read XML, write `set` commands); FortiOS (read and write CLI configuration); Check Point (read Management API JSON, write a `mgmt_cli` script); Cisco ASA (read `show running-config`, also of an FTD; write ASA commands); Sophos Firewall, SFOS 18 and later (read and write the `Entities.xml` of *Import export*, plain or in its `.tar`); iptables and ip6tables (read `iptables-save`, write `iptables-restore` files) |
| Tests | 1814, all passing (6 of them need root and iptables and are skipped elsewhere); `mypy --strict` clean |
| Verified on devices | **iptables only**: rulesets loaded into a Linux kernel and real packets forwarded through it (below). Nothing has been loaded on PAN-OS, FortiOS, an ASA, a Sophos Firewall or a Check Point management server |
| Next | 0.7.0: Cisco Secure Firewall (see `TODO.md`); lab validation of the sample conversions |

## Layout

```
src/fwshift/
    model.py          the vendor-neutral policy model and its semantics
    parsers/
        panos.py      PAN-OS / Panorama XML  -> model
        fortios.py    FortiOS configuration  -> model
        checkpoint.py Management API JSON    -> model (inline layers flattened)
        asa.py        ASA running-config     -> model (bound access lists, NAT sections)
        sophos.py     Sophos Entities.xml    -> model (exclusions, a rulebase per IP version)
        iptables.py   iptables-save output   -> model (chains flattened)
    emitters/
        panos.py      model -> PAN-OS set commands
        fortios.py    model -> FortiOS CLI configuration
        checkpoint.py model -> shell script of mgmt_cli calls
        asa.py        model -> ASA commands (access lists per interface, twice NAT)
        sophos.py     model -> Entities.xml (a rule per IP version, flat groups)
        iptables.py   model -> iptables-restore / ip6tables-restore file
    transform.py      passes shared by the emitters: hardening of names,
                      references, placeholders, names, application lowering,
                      NAT destination rewriting, NAT order, pruning
    audit.py          the audit: what rules match as sets, the checks, the
                      actions (accept, disable, reorder), before and after
    matrix.py         the zone matrix: what each zone may reach in each other
                      zone, from the sets of the audit; zones of the policy or
                      zones given as networks
    appmap.py         application/port table, protocol tables, reserved names
    netutil.py        IP intervals
    xmlread.py        XML from outside: no document type, whatever the encoding
    names.py          naming rules of the targets
    report.py         findings, item status, text and JSON report
    options.py        conversion options
    cli.py            command line; also the small Python API (load, convert)
.github/workflows/
    ci.yml            mypy and the tests, on every push
    release.yml       on a version tag: a release with a zip of the project, a
                      single-file fwshift.pyz, a wheel and a source distribution
tests/
    data/             one synthetic sample per format
    data/expected/    their conversions and reports, byte for byte
    tools/            the script that writes the Check Point sample
    helpers.py        loaders, and readers for emitted PAN-OS, FortiOS,
                      Check Point, ASA and Sophos output
    test_parsers.py   netutil, FortiOS syntax, PAN-OS and FortiOS parsers
    test_emitters.py  PAN-OS and FortiOS emitters
    test_semantics.py one small configuration per semantic trap
    test_iptables.py  iptables both ways, a packet simulator, cross-format NAT
    test_checkpoint.py Check Point both ways, with simulators for an export
                      and for an emitted script
    test_asa.py       Cisco ASA both ways, with a random ASA that judges
                      packets itself and a strict reader of emitted commands
    test_sophos.py    Sophos Firewall both ways, against a strict reader of
                      Entities.xml that shares no code with the parser
    test_audit.py     the audit, against a walk through every packet of a
                      small world
    test_matrix.py    the zone matrix, against the same walk: every packet
                      that gets through is in it, and nothing else
    test_cli.py       command line, golden files
docs/MANUAL.md        user manual
TODO.md               what is planned, release by release
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
emitter*, never by bending the model. FortiOS, iptables and ASA are the
examples: they look rules up after destination NAT, so their parsers call
`rewrite_destinations(to_post_nat=False)` and their emitters
`to_post_nat_lookup`. ASA is also the example for zones: its access lists name
no outgoing interface, so its parser works the destination zones out (from
what an ASA never forwards, and from routes) and its emitter has to get rid of
them again.

A few fields tell an emitter what kind of platform the rules came from, so
that it need not know the vendor:

| Field | Meaning |
|---|---|
| `default_intrazone`, `default_interzone` | what happens to traffic no rule matches |
| `lookup_after_dnat` | the source looks rules up after destination NAT; a target of the same kind undoes what the parser did and withdraws its findings |
| `NatRule.combines` | per NAT rule: the source applies it together with one rule of the other direction, instead of one rule, first match. Set for iptables, FortiOS, ASA and Check Point automatic rules (`transform.note_nat_order`) |
| `Rule.egress_implied` | the source rule named no destination zone; the zones in the model were worked out (ASA). A target that cannot match the outgoing interface loses nothing by leaving them out |
| `DestNat.spread` | the translation picks one of several addresses per connection (iptables `DNAT` to a range) instead of mapping address for address. A rule for one of them cannot be given "the same part of the other side" |
| `Rule.nat_added` | the destinations a parser of a post-NAT platform added to reach the pre-NAT model, with the origins of the NAT rules they were added for. A target of the same kind takes exactly these away again and leaves the rest of the rule alone |
| `named_translations` | a rule of the source that names the object of a destination NAT itself applied to the translated traffic (a FortiOS virtual IP in a policy). Such a member is rewritten for a target of the same kind too |

Two fields are for the audit only:

| Field | Meaning |
|---|---|
| `Rule.handling` | what the source rule does to a session besides its verdict, logging and profiles, as far as a parser reads it: NAT and a traffic shaper in a FortiOS policy (and every other key of a policy that the parser does not model and that is not switched off), a PAN-OS log forwarding profile, QoS marking and the like, the track setting of a Check Point rule. Two rules handle traffic "the same way" only when this is equal too. No emitter reads it |
| `Options.written` | not in the model but next to it: when it is a list, an emitter adds the copy of the policy it writes its output from (zones mapped, names made valid, destinations rewritten for the side of NAT the target matches on). The audit proves on it that a rule it disables changes nothing for the target either |

A finding on a rule that is about one NAT rule carries the origin of that NAT
rule (`Finding.subject`, not shown in the report). `to_post_nat_lookup` uses
it to withdraw, on a target of the same kind as the source, only the findings
of NAT rules the target really gets.

`builtin` on an object names the vendor on which the object exists without a
conversion creating it: a predefined service, a Check Point gateway, a service
that an ASA access list entry spells out, the address of an ASA interface
(`raw` then says `interface <name>`). An emitter for that vendor refers to it
in its own way; every other emitter treats it as an ordinary object.

The resolvers in `transform.py` (`address_intervals`, `known_intervals`,
`families`, `flatten_services`) walk groups inside groups. They resolve a
group once per call and return each address once: with two groups per level
that both hold both groups below, anything else doubles with every level.
`transform.harden` makes groups that hold themselves unusable before any
emitter sees them. A walker of your own needs the same two things.

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
6. **A simulator** where the format allows one. For iptables, Check Point
   and ASA the tests evaluate packets against the source, the model and the
   emitted output and require the same verdict; that found defects no
   hand-written case had. Build the judge of the source from the generator's
   own data, not from the parser under test, and give the generator NAT: the
   one silent error of the ASA review that the tests could have found was a
   NAT rewrite they had no way to see.
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
* **Packet-level equivalence** (`test_iptables.py`, `test_checkpoint.py`,
  `test_asa.py`).
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
  it, and the iptables and Check Point generators produce no NAT. The cases a
  reviewer found that way are hand-written tests at the end of both files.

  For ASA the test builds a random ASA (`random_lab`): interfaces with
  security levels, `same-security-traffic`, lists per interface and a global
  one, every form of an entry, optionally routes and NAT. Each entry is
  generated as text together with a predicate, so the lab judges a packet
  without any of the project's code. The model read from the text has to
  agree with it; so has the ASA output for that model, read by
  `helpers.AsaConfig`, which is strict about what an ASA would take (objects
  before use, one name once, no empty groups) and is not the project's
  parser. In the other direction random models are written for an ASA with
  `--zone-network` for every zone and compared packet by packet; with
  networks that are incomplete in the ways a person leaves them incomplete,
  the output may allow less than the model but never more without a finding
  on the rule that decides. None of this
  replaces an ASA: the lab and the reader are both written from the same
  reading of Cisco's documentation as the code they check.
  For Sophos Firewall, `helpers.SophosConfig` reads an `Entities.xml` the
  way an import would and decides about packets as the firewall would:
  entities in the order of the file, each name defined before it is used and
  only once whatever its case, a host of the IP version of what uses it,
  only element names and values that the API documentation or Sophos's SDK
  show, a rulebase per IP version with each rule placed by its `Position`,
  first match, exclusions that apply together. It is the judge in both
  directions: for random models written by the emitter (with every
  combination of negated fields), and for random files (`random_entities`,
  with exclusions of one to three kinds and rules placed at the top, the
  bottom, before and after others) read by the parser. NAT has an oracle
  too, small as it is: the first rule that matches and what it translates
  to, for random NAT models and random NAT files. A mutation check (38 ways
  to break the parser and the emitter, among them the defects of review
  round 14) is not part of the suite; all were caught when it was run. As with the ASA, the reader is written
  from the same reading of the documentation as the code it checks.
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

## Releasing

A version tag gets a GitHub release with its packages
(`.github/workflows/release.yml`):

| Package | |
|---|---|
| `fwshift-X.Y.Z.zip` | the project as tagged, under one directory: sources, tests, sample configurations, manual |
| `fwshift-X.Y.Z.pyz` | one file that runs with `python3 fwshift-X.Y.Z.pyz ...` (Python 3.9 or newer); nothing to install |
| `fwshift-X.Y.Z-py3-none-any.whl`, `fwshift-X.Y.Z.tar.gz` | the wheel and the source distribution, for pip |

To release:

1. Set `__version__` in `src/fwshift/__init__.py`, and write the entry
   `### <date>: version X.Y.Z` in the development log below. What stands under
   its `**Built**` becomes the text of the release.
2. Commit, then tag and push the tag:

   ```sh
   git tag v0.6.1
   git push origin v0.6.1
   ```

The workflow refuses a tag that is not the version the package says, runs
mypy and the tests, builds the packages, and checks them before anything is
published: the zip unpacks to the project, the single file prints its
version, converts a sample to the byte and hands on its exit status, the
wheel installs. A release that exists already gets its packages replaced.

For a version that was tagged before the workflow existed, run it by hand
(*Actions > Release > Run workflow*) and give the tag. Its steps take nothing
from the tree but the sources, so they work for every tag; `skip_tests` is
there for an old tag whose tests no longer run on today's tools.

## Design decisions

| Decision | Reason |
|---|---|
| Neutral model with parsers and emitters | Six formats need twelve components instead of thirty pairwise converters; a seventh adds two. |
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
| ASA: only bound access lists, and permit entries get destination zones | An ASA has dozens of lists that are not policy; `access-group` says which are. "Permit to any" on an ASA never means "back out of the same interface", so the model must not say it either: the zones an entry can reach are written out, narrowed by routes where the entry names addresses. |
| ASA output: a list per zone plus a global list that ends the policy | The lists an ASA reads first are per interface. A rule for every zone above a rule of one zone is repeated in that zone's list to keep the order. Binding a global list that ends in a deny is what makes sure that no interface falls back to the security-level permit. |
| ASA output: a rule that needs the outgoing interface is inactive unless networks are given | An entry cannot name it. Written without it, an allow to "any address in zone B" allows every zone. `--zone-network` lets the user say what lies behind a zone; then the networks of the other zones can be left out of the destination, by longest prefix like a route. Nothing is assumed about a zone or an address the user did not mention: such a rule stays inactive, and of an address nobody placed a permit keeps clear and a deny does not. |
| ASA output: twice NAT for every rule, destination translations `unidirectional` | One line per rule keeps the order of the model. A static rule of an ASA works both ways; the model's destination translation does not. A combining published port is written from the server side because that is the form an ASA combines with source NAT. |
| NAT order is reported, not emulated | A first-match NAT rulebase and two NAT tables differ in ways `PREROUTING` cannot express (it does not know the outgoing interface). The report names each rule that changes meaning. |
| Reserved names are renamed | An object called `all` or `HTTP` from another platform would otherwise redefine a FortiOS built-in. |
| Audit: a rule is called dead only when that is proven, and unknowns count against the claim | The finding has an action, `disable`, that people will use without reading each rule. A wrong "redundant" removes a rule that was needed; a missed one costs nothing. |
| Audit: `reorder` is carried out but always needs review | Moving a shadowed rule up flips verdicts, and which of the two rules was the mistake is not in the configuration. The tool can do the edit; it cannot make the decision. |
| Audit after a conversion works on the model, not on the output read back | Two of the six targets have no parser for what is written (PAN-OS `set` commands, the Check Point script), and what is read back is not always what was meant (a Sophos NAT rule names interfaces, not zones). It shows what the conversion knows it changed, which is where a lost deny rule shows. |
| Sophos: a rule with exclusions of N kinds becomes N rules | Exclusions are one condition for the whole rule ("skip where all of them hold"); the model negates per field. "Not (A and B)" is "not A, or not B": two rules, each with one field cut down, say exactly that, and every target can write them. |
| Sophos output: of several negated fields, all but one are written as address ranges | The other way round. Two exclusions would skip the rule only where both hold, which is a wider rule than the source had. A complement of addresses is exact; a host name has none, and then the rule is disabled. |
| Sophos output: zones are not written | A zone entity carries the device access of the zone (which services of the firewall itself answer there). An import overwrites what has the same name: writing `LAN` would change who can reach the admin console. |
| Sophos output: every rule stands after the one before it | With `Bottom` for each, the order would hang on the order in which the firewall takes the entities, and a rule it does not take would let the rules after it move up. |
| Sophos output: a placeholder is a host name under `.invalid` | It has to be an object every firewall takes and that matches nothing; `0.0.0.0` may be refused, and a refused entity can end an import. A name under `.invalid` never resolves. |
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
| ASA: interface list, then global list, then deny; an interface without list (and no global one) permits to lower security levels; `any` is both IP versions from 9.0; access lists name real addresses and ports from 8.3. (Checked against Cisco's configuration guide in review.) | ASA parser |
| ASA never forwards back out of the arrival interface or between equal security levels unless `same-security-traffic` permits it, whatever the lists say; an FTD forwards between and within all interfaces | `_blocked`, `_place` |
| ASA picks the outgoing interface by its routing table (connected networks, static routes) for real addresses; a NAT rule does not send traffic elsewhere than the route would. (Not verified, and known to be too simple: an ASA takes the outgoing interface from the NAT rule that translates the destination unless `route-lookup` is set, so this holds where the routes agree with the NAT rules.) | `_routed`, `_egress` |
| ASA NAT: twice NAT in order, then object NAT sorted (static first, fewest real addresses, lowest address, name), then `after-auto`; one rule may translate the destination and another the source, but a twice NAT rule that names both claims the connection; `destination static <mapped> <real>`; `service <original> <translated>`; `interface` in the source is the mapped interface's address, in the destination the real interface's. (Syntax and service order checked against Cisco's guide in review.) | ASA parser, ASA emitter, `note_nat_order(whole=...)` |
| ASA: `fqdn` without `v4`/`v6` resolves IPv4; running-config always prints the `(real,mapped)` pair of a NAT rule; the port, protocol and ICMP names in `parsers/asa.py` | ASA parser |
| An ASA accepts what the emitter writes and has not been loaded anywhere: `range` objects for IPv6 and from `0.0.0.0`, `network-object ::/0`, `service 255`, host `192.0.0.8`, `lt`/`gt` in service objects used by NAT, `pat-pool` with an object group, `nat (any,any)`, `unidirectional` on `source static any any destination static`, `no-proxy-arp` with interface `any`, `fqdn v6`, names that start with a digit | ASA emitter |
| An ASA refuses a NAT rule that names one of its own interface addresses as an object (the keyword `interface` is wanted), and an object group with IPv4 and IPv6 members in NAT. (Both confirmed from Cisco sources in review.) | ASA emitter |
| Sophos: firewall rules are first match with an implicit drop, IPv4 and IPv6 in rulebases of their own; a rule matches the destination address before destination NAT and the destination zone after it. (A third-party knowledge base and a Sophos community article; not found in Sophos's own reference.) Whether the *service* of a rule is the one before or after a port translation is not known: FWShift takes the original, as the model does | Sophos parser and emitter |
| Sophos: a list that is absent is "Any" (the templates of Sophos's SDK leave the element out for Any) | Sophos parser and emitter |
| Sophos: exclusions apply together, a rule is skipped only for traffic that matches every kind of exclusion it has. (A third-party knowledge base; a community report of a Drop rule with two exclusions "not working" fits it. Not found in Sophos's documentation.) | `_exclusions`, `_variants` |
| Sophos: traffic between two interfaces of one zone needs a rule (from memory) | Sophos parser (`default_intrazone`), `INTRAZONE_ALLOW_ADDED` |
| Sophos: Security Heartbeat on a rule limits who the rule is for (not confirmed) | Sophos parser |
| Sophos NAT: one table, first match; a rule can translate source and destination; it matches original source, destination and service and the inbound and outbound interface; "Any" is the outbound interface of a rule that publishes an address; a linked rule is source NAT only, takes all criteria of its firewall rule, and an independent rule above it wins. (Sophos help and API documentation.) Not known: what an outbound interface on a destination NAT rule matches | Sophos parser and emitter |
| Sophos: the element names of a NAT rule's match, `OriginalSourceNetworks`, `OriginalDestinationNetworks` (child `Network`), `OriginalServices` (child `Service`), `InboundInterfaces` (child `Interface`). **From memory of exports.** The API page names the parameters Network, Service and Interface without their containers; `OutboundInterfaces/Interface` is read by a community script. A file that names them otherwise is not misread: an unknown element that looks like a criterion makes the NAT rule unsupported | Sophos parser and emitter |
| Sophos: the root `<Configuration APIVersion="..." IPS_CAT_VER="1">` (seen quoted from an export of 19.5 as `1905.1`; `1800.1` for 18.0 is by that pattern), entities with `transactionid=""`, IPv6 `Subnet` as a prefix length (not found), `HostType` `IPList` with `ListOfIPAddresses` and `System Host` (API documentation) | Sophos parser and emitter |
| Sophos services: ICMP types and codes as numbers, -1 for any, from the lists of the API page (the web console shows names; both are read); IP protocols by the keyword of the IANA registry, of which the API page shows some (`HOPOPT`, `IPv6-ICMP`, `OSPFIGP`, `IPProto143` to `IPProto255`); port 0 is not taken | `appmap.py`, Sophos emitter |
| Sophos names: 60 characters for a host or rule, 50 for a service, no comma (API documentation). Whether names differ by case is not known: names of another platform are kept apart whatever their case. The list of services a firewall comes with (`SOPHOS_FACTORY_SERVICE_NAMES`) is from memory and not complete | `names.py`, Sophos emitter |
| Sophos import: takes a `.tar` that holds `Entities.xml`, of its own version or an older one; overwrites entities of the same name; can stop at an entity it does not take (a community log shows "IMPORT Failed ... Exiting"; another source describes other settings still being imported). What the web console says then is not known | Sophos emitter, manual |
| A Sophos Firewall accepts what the emitter writes and has not been imported anywhere: an FQDN host under `.invalid`, IP ranges as what a NAT rule translates to, `Position` `After` with an anchor of the same IP version, `NATMethod` `OnetoOne` and `Round-robin` as written, rule names with spaces, a firewall rule without `WebFilter` and the other policy elements | Sophos emitter |
| FTD: the device shows its access rules as `access-list CSM_FW_ACL_ advanced` with `ifc`, `rule-id` and remarks `rule-id N: L4 RULE: name` / `L7 RULE: name`; an L7 rule appears as `permit` whatever its action. From documentation and memory, no device output was available | ASA parser |

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

### 2026-10-11: version 0.3.0

**Built**

* Cisco ASA, read and written; the device configuration of an FTD, read.
  The parser takes the access lists that `access-group` binds, gives permit
  entries the interfaces their traffic can leave by (what an ASA never
  forwards; routes where the entry names addresses), adds the implicit rule
  of an interface without list, converts outbound lists that only deny, and
  reads twice NAT and object NAT in the order of the ASA. The emitter writes
  one access list per zone and a global one, object groups for lists,
  complements for negated addresses, and twice NAT.
* `--zone-network`: the networks behind a zone, with which a rule for one
  destination zone can be written for an ASA (how they are read was settled
  in round 9, below).
* Shared: `Rule.egress_implied`; `note_nat_order(whole=...)` for a target
  that translates per direction but can write a rule that claims a connection
  whole; `rewrite_destinations` maps part of a translated network to the same
  part of the other side and reports where it cannot
  (`NAT_DESTINATION_WIDENED`), and reports a rule that names the port on the
  wrong side of a port translation; `harden` refuses groups that hold
  themselves; the group resolvers are linear in the number of groups;
  `netutil.subtract`, `intersect`, `interval_text`; `Report.withdraw`.

**Reviewed**

| Round | Found | Examples |
|---|---|---|
| 8 | 4 silent errors (2 in shared code that predate ASA), 2 wrong facts, 2 crashes, an exponential blow-up, several refused or misleading outputs | a rule for one host behind a static NAT of a network became a rule for the whole network, on every same-kind conversion; a rule for the original port of a port translation, dead on the source, came alive on PAN-OS; an FTD configuration lost every permit because FTD has no `same-security-traffic`; `--zone-network` with overlapping or incomplete networks wrote wrong destinations as "exact"; a destination NAT written as a static rule translated the server's outgoing connections too; a group that holds itself crashed the ASA emitter; two groups per level that hold both groups below took minutes at 28 levels; the address of an interface written as an object, which an ASA refuses |
| 9 | 3 silent errors (2 in shared code, 1 brought in by the round 8 fix for `--zone-network`), 1 crash, 1 wrong fact, 9 statements in the documents that did not match the code | a rule naming addresses on both sides of one translation (a group with a real host and the mapped address of another) was widened without a finding; with networks for every zone and no default route, a deny rule was cut down to the networks given and the Internet fell through to the permit below; a port translation was not looked at on rules to any destination; `<translated-address>any` from PAN-OS ended in an `AssertionError`; new twice NAT lines go to the end of section 1, not in front |
| 10 | 4 silent errors (1 brought in by the round 9 service filter, 1 a gap of the strict `--zone-network` reading), 3 false needs-review findings | what a rule exposes depended on the order of the NAT rules (a rule for one of two public addresses of one server, flagged only when its NAT rule came second); a dead rule of iptables or FortiOS (public address, internal port) came alive on a target of the same kind; a negated destination naming part of a translated network kept its list and changed meaning; `inside=10.0.0.0/8` with no networks for a dmz inside it cut a deny for every other zone |

The findings of round 8 are fixed, with tests at the end of
`tests/test_asa.py`. The first of them was found by an oracle the tests
lacked: a same-kind round trip with NAT, access lists compared packet by
packet on real addresses. `random_lab` has NAT now. The reviewer checked the
facts it could against Cisco's documents (what it verified is marked in the
table of assumptions) and ran the parser against the tests' random ASA for
another 1200 seeds without a difference.

Round 9 looked at those fixes. What it found, and what was done:

* **Both sides of one translation.** `rewrite_destinations` now works out,
  per translation and rule, what the rule names on the new side that does not
  go with what it names on the side being left, and reports that part
  (`NAT_ADDRESS_EXPOSED`) whatever else the rule names. An addition is only
  silent when it puts back what the parser of a same-kind source took. The
  check also looks at the services: a rule for port 22 is not exposed by a
  forwarding of port 443 (that was a false finding in the Check Point golden
  report). Findings carry the NAT rule they are about (`Finding.subject`), so
  that a same-kind target withdraws only those of NAT rules it really gets.
* **`--zone-network`.** One way of reading the networks instead of two
  ("only" and "without"), and no assumption left in it: the networks of the
  zones a rule is not for are left out of its destination, and that is done
  only when every zone the rule is for or has to be told apart from was given
  networks. A zone without networks is not "the rest" (the first version of
  this fix said it was, and a forgotten zone inside the range of another one
  then made rules wider without a word). An address in none of the networks
  belongs to nobody: a permit for any address leaves it out, a deny keeps it
  (`ZONE_NETWORK_GAP`), and that goes for all of IPv6 when only IPv4 networks
  were given. "Everything else" for one zone while another has none is
  reported (`ZONE_NETWORK_INCOMPLETE`). A rule to every other zone is not
  touched, except for the zone's own networks. A rule left without an address
  is skipped with `EGRESS_NO_ADDRESS`, at needs-review for a deny. The
  reviewer's fuzzer for this (random models, nine ways of giving the
  networks, 300 seeds each) now finds every difference on a flagged rule, and
  none with complete networks.
* **Ports on rules to any destination** are checked, in both directions; the
  port form has its own code (`NAT_PORT_EXPOSED`), which a same-kind target
  withdraws. Protocols without ports (an ICMP rule) no longer count as a
  possible match.
* The crash, the `ASA_LOAD` text and the manual (section 10, step 4), the
  statements in the manual that did not match, the message for protocol and
  ICMP-type groups nested too deep, the object left behind for an interface
  address: fixed. iptables `DNAT` to a range is marked as picking an address
  per connection (`DestNat.spread`), so a rule for one of them is not mapped
  address for address.

Left as they are, on purpose:

* Before 9.0, an interface with only an IPv4 list gets no implicit rule for
  IPv6. Narrower, never wider.
* The assumption about NAT rules and routes in the table above.

Round 10 looked at the fixes of round 9, and led to the last change of this
version in `rewrite_destinations`:

* **Order.** Rules are the outer loop now. Hits are looked for in what the
  rule named before any translation, and what the rule exposes is worked out
  at the end, per translation, from what the rule names then. A translation
  that keeps the address and changes the port takes part in that (a rule that
  reaches the server through another NAT rule).
* **Services.** A NAT rule with a service does not rewrite a rule whose
  services cannot meet it, and does not count as exposed by it either: one
  filter for both, where round 9 had it for one. A public address with two
  port forwardings to two servers gives each rule the server of its port.
* **Same kind.** The parser notes what it adds (`Rule.nat_added`), and a
  target of the same kind takes away exactly that and nothing else. Round
  trips of iptables, FortiOS and ASA through the model are exact for the
  destinations, dead entries included; `NAT_ADDRESS_EXPOSED` and
  `NAT_DESTINATION_WIDENED` are withdrawn there with the other findings of a
  NAT rule that is written. FortiOS policies that name a virtual IP are the
  exception that is still rewritten (`Policy.named_translations`).
* **Negation** over part of a translated network disables the rule unless it
  names the same part of both sides.
* **Ports.** A service that holds both ports of a port translation is not
  reported.
* **`--zone-network`.** A rule to every other zone has its own zone's
  networks left out only when every zone has networks.

The tests for round 9 are at the end of `tests/test_asa.py` too, among them
`test_incomplete_zone_networks_never_widen_without_a_word`: random policies
converted with networks as a person might give them (a zone forgotten, IPv6
forgotten, one network missing, a default with a zone missing), where a packet
the model denies may only be allowed by an entry of a rule the report flags.

**Not done, known**

* Nothing was loaded on an ASA or an FTD. The ASA syntax written and the FTD
  syntax read are from documentation and memory; the table of assumptions
  lists what the emitter writes that nobody has seen an ASA accept.
* To an ASA, rules "to zone B, any address" are inactive without
  `--zone-network`, and the networks given are taken to be right. A zone or
  an address nobody mentioned is handled on the side that allows less; a
  network given to the wrong zone is not noticed.
* The fixes of round 10 were not reviewed again by the independent reviewer.
  They are covered by the tests named above and by the reviewer's own
  oracles, rerun after the fixes: no difference without a needs-review
  finding on a deciding rule in 2500 seeds each way between pre-NAT and
  post-NAT platforms, and no difference at all in the round trips of
  iptables, FortiOS and ASA.
* An FQDN destination on a rule from the zone a NAT rule serves gets no NAT
  finding: whether the name resolves to the published address cannot be
  known when converting.
* Destination zones from routes: static routes and connected networks only.
* ASA to ASA changes list names, loses `log` on denies and time ranges, and
  writes object NAT back as twice NAT.
* Outbound access lists beyond "deny, then permit everything", time ranges,
  identity matches, NAT before 8.3, IPv6 lists before 9.0, bridge groups,
  VPN filters, inspection.
* The older walkers over nested groups in the PAN-OS and FortiOS parsers and
  the iptables emitter were made linear in passing; they have no test of
  their own beyond the ASA one that goes through every emitter.

### 2026-10-11: version 0.4.0

**Built**

* `audit.py` and the command `fwshift audit`; `--audit` and its options on
  `convert`. Twenty-three checks in four groups: rules that allow a lot, the
  order of the rules, loose ends, and one that only exists after a conversion.
* Per check an action (`off`, `accept`, `report`, `disable`, and `reorder`
  for shadowed rules), per-rule acceptance with a reason, a JSON
  configuration file, `--audit-fail-on` with exit status 3.
* In a conversion the audit runs twice: on the policy as read, where the
  actions are carried out, and on the policy without the rules the
  conversion wrote disabled or left out. `EXPOSED_BY_CONVERSION` names the
  allow rules below a blocking rule that was lost.

**How a rule is proven dead**

A rule is a box: source zones, destination zones, whether the two are the
same zone or different ones, sources, destinations and services. Zones are
bits of an integer, with one bit for "the zones nobody names", so that `any`
is more than the zones of the policy; the relation is a dimension of its own,
which keeps a set of zone pairs at two integers instead of their product (the
first version had a bit per pair, and 2000 interfaces made integers of four
million bits). Addresses are the intervals of `netutil`, one IP version per
box: no packet goes from an IPv4 address to an IPv6 one. Services are
rectangles per protocol number (source port by destination port, ICMP type
by code) plus "every other protocol". A rule is dead when its box, with the
boxes of all earlier rules taken out, is empty.

Every rule has two boxes. *Over*: all it might match. *Under*: what it surely
matches. They differ where the model cannot say (a host name, a dynamic
group, a group with excluded members, `application-default`, an unsupported
object, an object or rule the parser reported as approximated). The rule that
is covered enters with its over box, the rules that cover with their under
box, so a wrong claim needs a wrong box, not an unknown. Applications, users,
URL categories and schedules are not in the boxes: an earlier rule that is
narrower in one of them than the later rule is left out as a cover. Two lists
with the same names are equal whatever the names stand for, which is what
makes rules with host names or `application-default` comparable at all.

What a parser said about its own reading counts (`Reading`, taken from the
report before anything else is written to it): a rule with a finding of
severity approximated or higher, other than those about destination NAT, is
neither called dead nor used as a cover; an object with such a finding
proves nothing by its addresses. A source that looks rules up after
destination NAT is read without the pre-NAT addresses its parser added
(`Rule.nat_added`): those stand for the translated traffic, not for
everything sent to that address.

The decision is made in three steps, because the obvious one (take the
earlier rules out in their order) cuts a broad rule under three thousand host
rules into three thousand pieces before it reaches the clean-up rule that
holds all of it:

1. *Counting.* If the earlier rules together hold fewer addresses and
   services of the rule than the rule has, something is left, however they
   lie. That settles nearly every rule that is alive without cutting anything.
2. *Largest first.* Otherwise the covers are taken out starting with the
   largest; then in their order, should that fall into more than 4096 pieces;
   then the rule is listed as not followed.
3. *Who takes part* is only asked for a dead rule (and for
   `OVERLAPPING_RULES`), and answered in the order of the rules, as first
   match would: a rule takes part when the rules above it leave it something
   of this rule. In few pieces that is read off while taking the covers out
   in order; otherwise cover by cover.

Most pairs of rules never get that far: a rule is first tried against the
others on the lowest and highest address of each side and on its zone bits,
in one list comprehension.

A dead rule is `REDUNDANT_RULE` when earlier rules with the same kind of
action that are themselves alive hold all of it, and `SHADOWED_RULE`
otherwise. A rule that is alive is redundant when a later live rule with the
same action, logging, profiles and handling holds all of it and every rule
in between that touches it handles traffic the same way.

**Why disabling them is safe, all at once**

A dead rule is missed by no packet. A rule that "adds nothing" hands each of
its packets to the next rule that matches it; every such rule up to the one
that holds it all handles traffic alike, or the finding would not have been
raised; and the rule that holds it all is alive and therefore not itself
removed as dead. If it is removed as adding nothing, the same argument goes on
from there, and the chain ends because it only goes down. Actions that do
change verdicts (disabling for what a rule allows, reordering) are carried
out first, and the order is looked at again before anything is disabled as
dead.

That argument is about one policy, and a conversion has two: what the source
enforced and what the target will. They differ in more than the rules that
are lost. A target that matches on the other side of destination NAT has
other addresses in the same rule; `--zone-map` can make two zones one. So a
rule is disabled only when it changes nothing in both: in the policy as read
without the rules the target cannot take, and in the copy the emitter writes
from (`Options.written`, from a conversion on trial), read as it stands. The
same is checked once more after the real conversion (`EXPOSED_BY_CONVERSION`,
"is needed again").

**Tests**

`test_audit.py` has an oracle that shares nothing with the audit's sets: a
small world (three named zones and two that no rule names, the addresses and
ports at which any two rules of the policy can differ) in which every packet
is walked through the rules, first match, with the matching code of the
iptables tests. For random policies where everything can be read, the rules
the audit calls dead are exactly the rules that decide no packet, and the two
findings are told apart as the walk tells them apart. Disabling what the
audit flags leaves the verdict, logging and action of every packet as it was.
For policies with host names, applications on default ports, schedules and
unsupported criteria the same is checked under several ways of filling in
what the model leaves open. Reordering changes only packets that a moved rule
now decides. The two ways of finding the rules that take part are run against
each other, the count of services against "a set is as large as its two
parts", and iptables rulesets with NAT are disabled-and-compared packet by
packet.

**Reviewed**

Two rounds by the independent reviewer, who wrote oracles of its own (a world
of 1.4 million packets with every packet one bit of an integer; a plain
subtraction in rule order without cap or filter; real parsers and emitters
with the outputs compared packet by packet with and without `disable`).

*Round 11*, on the first version: 11 findings, all fixed.

| | Finding | Fix |
|---|---|---|
| high | iptables, FortiOS, ASA: the pre-NAT addresses a parser added were read as matched, so a rule for the published address was "redundant" next to the rule for the server | the audit reads such a source without `nat_added`; a FortiOS virtual IP in a policy proves nothing about the plain address |
| high | a group with excluded members (FortiOS), or any unsupported or dynamic group, counted with its listed members as a cover | such a group proves nothing |
| high | rules the parser itself had reported as approximated (installed on one gateway, unknown attributes, per-policy NAT) were compared as if exact | `Reading`: left out on both sides and listed; `Rule.handling` |
| high | a rule was disabled as redundant next to a rule the target then could not write | conversion on trial before anything is disabled; the net after the conversion |
| medium | `NO_LOG=disable` disabled blocking rules | `NO_LOG` and `NO_PROFILE` cannot be `disable`; `NO_LOG` only where the model holds logging |
| medium | a bit per zone pair: 2000 interfaces took minutes and gigabytes; broad rules under thousands of host rules were "not followed" | zones as three dimensions; counting, largest first |
| medium | `ANY_ANY_ANY` was never high on an ASA or iptables source, where every rule names its interface | one level lower only when a rule does not reach every other zone |
| medium | `EXPOSED_BY_CONVERSION` missed the default for traffic inside a zone; the summary counted only the first audit | both |
| low | a rule from IPv4 addresses to "any" was compared in IPv6 as well | a box per IP version |
| low | a configuration with an unknown check and only a level ended in a traceback | refused with a message, as every unknown key now is |
| low | `[` in a rule name was a pattern; an acceptance nothing answered to went unnoticed; `--to json` ignored audit options | names first, two wildcards, *Accepted, but not found*, refused |

*Round 12*, on the fixes: the eleven confirmed fixed; the new decision code
compared with plain in-order subtraction on 310,000 rules of 2,960 policies
(identical check, dead set and related rules) and with first match on 9.6
million packets; six new findings, all fixed.

| | Finding | Fix |
|---|---|---|
| high | `disable` was proven on one side of destination NAT and written for the other: iptables to PAN-OS, a drop for the server's address and port was "redundant" and was the rule that blocked the published address there (5 of 2000 random rulesets wider, 9 narrower); PAN-OS to iptables the same in the other direction | the proof is given on the emitter's copy as well (`Options.written`) |
| medium | `--audit-accept 'no-*'` also accepted the `EXPOSED_BY_CONVERSION` of those rules, which was then not listed anywhere | accepted only by the name of the check; accepted findings of the second audit are listed; a rule that was accepted as dead and matches in the output is still named |
| low | `--audit-fail-on` counted the other findings of a rule the audit had disabled | they do not count |
| low | an acceptance pattern with many `*` did not return (a regular expression) | a matcher written out |
| low | policies in which nearly every rule is dead: 3000 rules in 84 s | rules that take part are read off in order while the rule stays in few pieces: 49 s. Still the slow case |
| nit | iptables wrote an audit-disabled rule as "disabled in the source"; an object read approximately was listed as a duplicate | both |

The fixes of round 12 were not reviewed again. They are covered by the tests
at the end of `test_audit.py` and by the reviewer's own scripts, rerun after
the fixes with the flow of the CLI as it is now: across the two sides of
destination NAT (iptables to a pre-NAT reading, 1500 rulesets; PAN-OS-kind
policies to iptables, 600) no packet differs with and without `disable`; nor
in same-kind conversions (iptables with NAT 400 + 250 seeds, without 250;
FortiOS 200 + 250; ASA 200 + 150), in the 1.4-million-packet world (500
static and 600 open policies; reordering and mixed actions 500 each) or
against the in-order reference (350 policies). In that world four dead rules
of the 500 static policies are not called dead; what is left of each lies
between the addresses the world has (the reviewer traced such cases to the
same conclusion), and with four more addresses in the world the audit and
the world agree on every rule of those policies.

**Not done, known**

* The audit has seen synthetic policies only.
* It is quadratic in the number of rules: 3000 rules take about five
  seconds, 6000 about half a minute on the machine it was written on (random
  policies, a third of the rules dead). Where nearly every rule is dead it is
  ten times that.
* "Never matches" is a statement about the model. The audit leaves out what a
  parser *said* it read approximately; a parser that is wrong without saying
  so makes the audit wrong. `audit.run` called without the parser's report
  knows nothing of either.
* The proof on what is written uses the emitter's copy of the policy, not
  the output text. What an emitter decides while writing (the networks an ASA
  rule is kept to with `--zone-network`, the chains of iptables) is not in it.
* The second audit lists new findings on the policy as read without the lost
  rules, not on the emitter's copy: a rule that is dead only as the target
  matches (after a destination was rewritten) is reported by the NAT findings
  of the conversion, not by the audit.
* The reviewer's fuzz across the two sides of destination NAT is not in the
  repository; `test_audit.py` has the two hand-made cases.
* No zone ranks, no hit counts, no audit of NAT beyond shadowing, no
  comparison of the output read back.
* `NO_LOG` and `NO_PROFILE` rest on what each parser reads of logging and
  profiles, which was written for the conversion report, not for an audit.
  `NO_LOG` is not raised for FortiOS: the model does not hold `logtraffic
  utm` apart from `disable`.
* A host name on a rule is compared by name only (two rules with the same
  name are equal, a name and an address never are).

### 2026-10-11: version 0.5.0

**Built**

* `matrix.py` and the command `fwshift matrix`: per ordered pair of zones the
  services the policy allows there and the rules that allow them, as text
  (a grid and a list of conduits), JSON or CSV.
* Zones of the policy, or zones given as networks (`--network-zone
  NAME[@ZONE]=NETWORK,...`), which is how the zones of a zone and conduit
  model are laid over a firewall that knows interfaces.
* `TODO.md`, with the to-do list that was at the end of this file and the
  firewall brands that are planned, one per release.

**How it is made**

The matrix is a second reader of the audit's sets. For every allow rule that
is enabled and not dead it takes the rule's *over* boxes and takes out the
*under* boxes of the blocking rules above it (largest first; a rule that
falls into more than 4096 pieces is shown as written). Earlier allow rules
are not taken out: what they take is allowed all the same, and the union per
cell is exact without it. What is left is a list of boxes, and each box is
laid into the cells it reaches:

* between the zones of the policy, a box reaches every pair of its source and
  destination zone bits that its relation (same zone, different zones)
  allows, with the bit for "the zones nobody names" as a row and column of
  its own;
* between zones given as networks, every pair of zones its source and
  destination addresses meet. A zone that is said to lie behind zones of the
  policy (`@ZONE`) takes a box only when the box is for one of those.

"At most what is allowed, never less" follows from the two boxes: allow rules
enter with all they might match, blocking rules with what they surely do.
The default (traffic no rule decides, where the policy lets it through) is a
pseudo-rule at the end: the universe of a cell minus the under boxes of every
rule without an application, user, category or schedule.

Decisions that were not obvious:

| Decision | Reason |
|---|---|
| Entries per rule are "what no *blocking* rule above takes", not "what the rule decides first" | The union per cell is the same, the subtraction is far smaller, and a reader who looks for "which rules let office reach the DMZ" wants every rule that would. Rules that never match are left out, so the list is not padded with dead rules. |
| A service that cannot be read is named (`svc:Facebook`), not shown as "any" | A Check Point rule for an application object is not a rule for every service; "any ~" on every such rule made the grid useless. Internally the entry still holds every service, for whoever asks the matrix what could get through. |
| A FortiOS virtual IP stays a name in the rule, and the box is cut to the mapped address when it is placed | Replacing the name by the address (the first version) broke the comparison by name with a blocking policy for the same virtual IP above it: "deny SSH to the VIP, allow the VIP" showed as any. |
| A zone of the policy nothing is given for, and an address that lies behind "the wrong" zone, go to a row `(ZONE: other addresses)`; the latter only for rules that name the address | The networks a user gives need not be all there is behind a zone, so a rule must not vanish for it. Showing it under the zones given for its own zone would be a guess (the first fix did that, and "deny telnet from the office, allow the rest of the zone" then showed telnet for the office). Doing it for rules with "any" address would add such a row to every matrix: "any" names no address behind another zone. |
| Destination NAT of a pre-NAT source is followed for every NAT rule that translates a destination, with "any zone" where the translated address cannot be read | `destination_translations` returns only the shapes the converter can rewrite (one published address). A matrix cannot leave the others out: the first version lost the rule. |
| What the parser said about the whole policy is printed with the matrix | "Nothing is allowed" next to a `policy6` table that was not read, or to VPN traffic that bypasses the access lists, is a wrong answer however exact the matrix is about what was read. |
| The intrazone default is not shown for network zones without `@ZONE` | Whether two networks lie in one zone of the firewall is what `@ZONE` says. Without it the default would be in every cell of every PAN-OS matrix. A note says that it is missing. |
| An iptables ruleset has a default for one IP version | The file is for IPv4 or IPv6; "any" for the other half made every cell "any" under a `FORWARD ACCEPT` policy. |

**Tests**

`test_matrix.py` walks the small world of the audit tests packet by packet
and notes, per pair of zones, which services each allow rule passes that no
blocking rule above it takes, which packets each rule decides, and which
services no rule decides. For policies that can be read exactly the matrix
equals that, entry by entry, with random defaults (150 seeds) and between
zones given as networks, unbound, bound and two behind one zone (90 seeds);
for policies with host names, applications, schedules and unsupported
criteria every packet that gets through under three ways of filling in the
unknowns is in its cell (40 seeds). Sixteen deliberate mistakes in
`matrix.py` (blocks not taken out, dead rules shown, relation ignored,
bindings ignored, NAT rules of one shape only and so on) are each caught by
the tests. The random oracle has no NAT: NAT placement, virtual IPs, the
rest-of-zone rows and the parser notes have hand-made cases.

**Reviewed**

*Round 13* by the independent reviewer, on the matrix and on the fixes of
round 12. Its own oracles (policy zones: 2500 static and 1500 open policies;
network zones: 2000 and 900; pre-NAT sources with destination NAT, 1500
seeds in four ways of declaring zones, 44,563 allowed packets; real parsers
against packet simulators for iptables, ASA and FortiOS, 500 seeds each)
found no allowed packet missing. Seven findings came from hand-built cases:

| | Finding | Fix |
|---|---|---|
| high | Between network zones with `@ZONE`, a rule for a published address vanished when its NAT rule named two addresses, translated to a host name, or was a static NAT of a range; more generally any rule whose zone and addresses contradicted the networks given vanished without a word | every NAT rule that translates a destination is followed; rows for the rest of a zone; a note should a rule still be in no cell |
| high | Notes of the parser about traffic outside the model (VPN bypass, implied rules, tables not converted) were not shown: "nothing is allowed" next to an unread `policy6` | printed with the matrix, and in the JSON |
| medium | An IPv4 iptables ruleset with `FORWARD ACCEPT` showed "any" in every cell: the IPv6 half of the default | the default of an iptables ruleset is for its IP version |
| medium | FortiOS: deny for a virtual IP, then allow for the same one, showed "any" without a mark | the name stays in the rule |
| low | A policy named `(default)` or an interface named `(other zones)` passed for the matrix's own entries | a flag instead of a name; another label when the name is taken |
| low | A thousand rules for any zone on fifty zones: 110 MB of text, 2.6 GB of memory | such rules are listed once in the text (280 kB); cells share entries (1 GB). JSON and CSV are as large as they were |
| nits | `(elsewhere) -> (elsewhere)` called "inside the zone"; a zone no rule names refused; duplicate networks; `a@=`; DEL and U+2028 in names; a raw line break in an error; `-o -` wrote a file named `-` | all fixed; U+0085, U+2028 and U+2029 are now control characters everywhere names are made safe |

The reviewer confirmed the six fixes of round 12, with a fuzz across the two
sides of destination NAT in seven directions (PAN-OS-kind to iptables,
FortiOS and Check Point, with zones merged and with objects renamed;
iptables to PAN-OS, iptables, FortiOS and Check Point): 2.7 million packets
compared with and without `disable`, 13,000 rules disabled, none decided
differently.

The fixes of round 13 were not reviewed again. They have tests at the end of
`test_matrix.py`, and the reviewer's oracles were rerun on them (policy
zones 800 static and 500 open policies, network zones 500 and 300, pre-NAT
with NAT 500 seeds in four modes, real parsers 100 to 200 seeds each, 600
mutated inputs through the command): no allowed packet missing, no
traceback.

**Not done, known**

* The matrix has seen synthetic policies only.
* The random oracle of the tests has no NAT. The reviewer's NAT oracle is
  not in the repository.
* Rows for the rest of a zone are checked by hand-made cases only.
* With network zones and no `@ZONE`, what the firewall allows by default
  inside a zone is not in the matrix (a note says so).
* Port translation, source NAT and routing are not applied. Applications are
  not turned into ports.
* JSON and CSV repeat a rule for any zone in every cell: a thousand such
  rules on fifty zones are 280 MB of JSON and a gigabyte of memory.
* A conversion with `--audit-action ...=disable` converts twice (once on
  trial) and takes about twice as long as `--audit` alone.

### 2026-10-11: version 0.6.0

**Built**

* Sophos Firewall (SFOS 18 and later), read and written: `parsers/sophos.py`
  and `emitters/sophos.py`. The input is the export of *Backup & firmware >
  Import export*, as the `.tar` it comes in or as the `Entities.xml` inside,
  or what the XML API answers to a `Get`. The output is an `Entities.xml`,
  or the archive itself when `-o` names a `.tar`.
* `xmlread.py`: XML from outside is refused when it declares a document
  type, whatever its encoding. The PAN-OS parser uses it too; its check was
  on the bytes of the file, which a UTF-16 file passes.
* The audit takes logging and profiles of a Sophos rule into account
  (`NO_LOG`, `NO_PROFILE`); the matrix reads a Sophos policy like any other.
* Compressed input (gzip, bzip2, xz, zip) is refused with a message that
  says so, for every format.

**What the format made necessary**

* *Exclusions.* A Sophos rule is skipped for traffic that matches all the
  kinds of exclusion it has. The model negates per field. Read: one model
  rule per kind of exclusion, each with that field cut down (zones by set
  difference, addresses out of "any" as a negation, addresses out of a list
  as the ranges that are left, services out of "any" as a negated service).
  Written: one negated field is an exclusion; of several, all but one are
  written as complement ranges, and where that cannot be done (a host name)
  the rule is disabled. A negated service always stays the exclusion.
* *IP versions.* Two rulebases. "Any" of an IPv4 rule is `0.0.0.0/0` in the
  model. Written, a rule that matches both versions is two rules, hosts and
  groups are of one version, and a group of the model becomes up to three
  (`name`, `name_v6`, `name_fqdn`): groups are flat on a Sophos Firewall.
* *NAT rules match interfaces.* Read, an interface becomes its zone where
  the export holds the interfaces. Written, the interfaces come from
  `--interface-map`; without it the rule is for any interface and says so.
* *Linked NAT rules* take their match from a firewall rule. They are read as
  rules of their own, with a finding where that is more than they were.
* *An import overwrites by name and can stop midway.* So: no zones are
  written, names of services a firewall comes with are avoided, names of
  another platform are kept apart whatever their case, every rule stands
  after the one before it, and a placeholder is something no firewall
  refuses and nothing matches (a host name under `.invalid`).

**Sources**

Sophos Firewall help (firewall rules, NAT rules, import and export), the XML
API reference (IP host, services, NAT rule, interface), the templates of
Sophos's Python SDK (`sophosfirewall-python`: firewall rule, IP host,
service, groups, zone), a community script that reads NAT rules from the
API, and a third-party knowledge base for how exclusions combine and which
side of a translation a rule sees. What comes from where, and what from
none of them, is in the table *Vendor behaviour the code relies on*.

**Review**

*Round 14* by the independent reviewer. Its own oracles, written without
the project's test reader: random `Entities.xml` against the parser (4,500
files, 36,000 rules, 1.8 million packets), random models of all six vendors
against the emitter (5,000 models, 1.5 million packets), Sophos to Sophos
(4,500 files), Sophos to iptables, ip6tables, FortiOS, Check Point and ASA
(800 files each), and the audit's `disable` and `reorder` with a Sophos
source or target (6,000 policies). No packet was decided differently
without a finding on the rule that decides. The findings came from NAT and
from hand-built cases:

| | Finding | Fix |
|---|---|---|
| high | A destination NAT rule was given the zone it arrives in as the zone of its original destination. For a rule that redirects ("DNS from the LAN to the resolver", destination any) that made a PAN-OS rule "from LAN to LAN", which redirects nothing that leaves; in the other direction a PAN-OS rule for traffic towards one zone became a Sophos rule for all of it, without a word | the zone is taken from the networks of the interfaces where they tell, and is "none" otherwise (PAN-OS then asks for `--target-nat-zone`); `NAT_DESTINATION_ZONE` when a rule loses that limit and names no address, or many |
| medium | A zone or interface called `Any` (from PAN-OS, iptables or an ASA, or through `--zone-map`) was written as `<Zone>Any</Zone>`: every zone | the conversion stops and asks for another name |
| medium | A NAT rule linked to a disabled or blocking firewall rule became an active rule of its own | converted disabled (`NAT_LINKED_INACTIVE`); a link to a name two rules have is not followed |
| medium | Port ranges that start at 0 were written as they were; a Sophos service starts at 1, and a refused entity can end an import | port 0 is left out (`PORT_ZERO`) |
| medium | Security Heartbeat on a rule was reported as an inspection profile; it says who the rule is for | a condition: the rule is unsupported, for every target |
| low | Read too kindly: a status that is neither Enable nor Disable, a list or action given twice, text next to list members, a position FWShift does not know, a `<UserPolicy>` next to a `<NetworkPolicy>`, entities in a namespace (ignored, also blocking rules), group membership given on the IP host, a network with mask 0.0.0.0, an IPv4 address in an IPv6 host, ICMPv6 elements in an ICMP service, `*` inside a host name | each makes its rule or object unsupported, or is read as what it says; namespaces are stripped |
| low | Severity: "any zone except" on a blocking rule (a zone the file does not hold is no longer blocked), an interface that was all that limited a NAT rule, load balancing methods and health checks, shaping and gateways of a rule | REVIEW for the first two; `NAT_LOAD_BALANCING`; `HANDLING_NOT_CONVERTED` |
| low | The emitter wrote "ICMP code N of every type", which nothing reads; `NAT_STATIC_RANGE` was missed for addresses without an object; a NAT rule translated to a network object | unsupported; fixed; what a rule translates to is written as an address or a range |
| low | API answers: "No. of records Zero." became a rule called "unnamed"; a failed login was an empty policy; a second `<Configuration>` was ignored | skipped; an error; an error |
| low | The check for a document type was on bytes: a UTF-16 file passed it and had its entities expanded | `xmlread.py`, also for PAN-OS |
| low | 20,000 rules in export style took 76 s, a rule with 200,000 members 267 s | 8 s and 10 s through the command: the search for a rule's place and a list without duplicates were quadratic |
| nits | Two `Entities.xml` in one archive; a `.tar.gz` gave an error about quotes; a zone called `local` taken for the firewall itself; ICMPv6 type 0; `SOPHOS_LOAD` only informational although imported rules land below existing ones; a placeholder sharing its host name with an object of the policy | all fixed |

The reviewer also went through `SophosConfig`, the reader the tests stand
on. It found it strict where it matters and named four gaps: it took `Any`
as a zone name and a network as what a rule translates to (both closed), no
generator produces port 0 (a test does now), and it ignores ICMP codes,
because the packets of the tests have none (open).

The fixes were not reviewed again. They have tests at the end of
`test_sophos.py`, and the reviewer's scripts were rerun on them: the parser
oracle (1,500 files, 600,000 packets), the emitter oracle (600 models), the
round trips (900 files), the five other targets (150 files each), the
audit (1,100 policies), its reproductions of the findings and its hostile
inputs (about fifty archives and XML files, no traceback). Every difference had a
finding, as before.

**Not done, known**

* Nothing has been imported on a Sophos Firewall. The reader of the tests
  and the code share one reading of the documentation.
* The element names of a NAT rule's match and the first line of the file
  are from memory of exports. If they are wrong, FWShift reads such a NAT
  rule as unsupported (not as a wider rule), and writes NAT rules a firewall
  will not take: the import would stop at the first of them.
* How exclusions combine is from a third-party source. If they did not
  apply together, rules with exclusions of several kinds would be read too
  wide: the split writes "skipped only where all hold".
* Whether a rule sees the original or the translated service of a port
  translation is not known.
* Users and schedules are not written, also Sophos to Sophos. Linked NAT
  rules come out as rules of their own, IP lists as host groups. A file
  FWShift wrote names interfaces without saying which zone they are in:
  read again, its NAT rules are for any zone, and say so.
* The NAT oracle of the tests knows first match and what a rule translates
  to. It does not send a packet through a translation and on to the firewall
  rules; that is what the reviewer's NAT oracle of round 12 did, for other
  platforms.
* SFOS before 18, Sophos UTM, web server protection, device access and VPN
  are not read.

### 2026-10-11: version 0.6.1

**Built**

* A release workflow (`.github/workflows/release.yml`). Every version tag
  gets a GitHub release with `fwshift-X.Y.Z.zip` (the project as tagged),
  `fwshift-X.Y.Z.pyz` (one file that runs with Python 3.9 or newer, nothing
  to install), the wheel and the source distribution.
* Run by hand with a tag, the workflow gives a version that was tagged
  earlier its packages.
* `pyproject.toml` gives the licence as an SPDX expression with the licence
  file, which is what setuptools asks for now (it builds from 77 on).
* The converter itself is as it was in 0.6.0.

**How it is made**

The workflow is shell steps and nothing else, so that it can build an old
tag, which holds no build script. The zip is `git archive` of the tag under
`fwshift-X.Y.Z/`. The single file is the package with a `__main__` of its
own: the one `zipapp -m` writes calls `main()` and drops what it returns, and
the exit status of FWShift means something (1 for an error, 2 for `--strict`,
3 for `--audit-fail-on`). The text of a release is what the log entry of the
version lists under **Built**.

**Verified, and not**

The steps were run outside GitHub, in a copy of the project with a commit and
a tag: the version check (also with a tag that does not match, and one that
is no version), the packages, their checks, and the release notes for every
version in this log. The same steps built and checked the packages of 0.1.0
and 0.3.0 from the trees of those versions, as a run by hand for an old tag
would. Not run: the workflow on GitHub itself, so neither the
trigger on a tag, nor the two actions it uses, nor the step that creates the
release with `gh`. A test (`test_cli.py`) keeps the version, this log, the
manual and the README in step, and the line of `__init__.py` in the form the
workflow reads.

## To do

See [TODO.md](TODO.md): the firewall brands that are planned, one per
release, and what else is on the list for the audit, the matrix, the
conversion and its validation.
