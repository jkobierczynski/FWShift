# FWShift development notes

How the code is organised, the rules it follows, how to extend and test it,
and a log of what has been done. For using the tool, see the
[user manual](docs/MANUAL.md).

## Status

| | |
|---|---|
| Version | 0.12.4 (alpha) |
| Platforms | PAN-OS and Panorama (read XML, write `set` commands); FortiOS (read and write CLI configuration); Check Point (read Management API JSON, write a `mgmt_cli` script); Cisco ASA (read `show running-config`, also of an FTD; write ASA commands); Cisco Secure Firewall managed by a Management Center (read the JSON of its REST API; write a Python script that loads a new policy through that API) or by its Device Manager (read the configuration export or the JSON of its API; write a file for the configuration import); Sophos Firewall, SFOS 18 and later (read and write the `Entities.xml` of *Import export*, plain or in its `.tar`); pfSense 2.6 and later (read `config.xml`; write the areas Aliases, NAT and Firewall Rules for a restore, for 2.7 and later); SonicWall, SonicOS 6.5 and 7 (read the settings export `.exp`; write commands of the SonicOS 7 command line); WatchGuard, Fireware 12 (read the configuration file of Policy Manager; write its policy part, to merge into a configuration of the target); Barracuda CloudGen Firewall, 8.0 and later (read saved answers of its REST API; write a shell script that creates the rules through that API); Juniper SRX, Junos OS (read `display set` or the configuration in braces; write set commands for `load set`); iptables and ip6tables (read `iptables-save`, write `iptables-restore` files) |
| Tests | 3175, all passing (6 of them need root and iptables and are skipped elsewhere); `mypy --strict` clean |
| Verified on devices | **iptables only**: rulesets loaded into a Linux kernel and real packets forwarded through it (below). Nothing has been loaded on PAN-OS, FortiOS, an ASA, a Sophos Firewall, a pfSense, a SonicWall, a Firebox, a CloudGen Firewall, an SRX, a Check Point management server, a Cisco Management Center or a Device Manager |
| Next | lab validation of the sample conversions; the brands not planned yet (see `TODO.md`) |

## Layout

```
src/fwshift/
    model.py          the vendor-neutral policy model and its semantics
    parsers/
        panos.py      PAN-OS / Panorama XML  -> model
        fortios.py    FortiOS configuration  -> model
        checkpoint.py Management API JSON    -> model (inline layers flattened)
        asa.py        ASA running-config     -> model (bound access lists, NAT sections)
        cisco.py      JSON of a Management Center or a Device Manager -> model
                      (sections and inheritance, the prefilter policy, NAT in
                      the order of the device)
        sophos.py     Sophos Entities.xml    -> model (exclusions, a rulebase per IP version)
        pfsense.py    pfSense config.xml     -> model (the order of pf, interface
                      groups, port forwards and the rules pfSense adds itself)
        sonicwall.py  SonicOS settings export -> model (rules per pair of zones,
                      default rules, objects of SonicOS from the interfaces)
        watchguard.py Policy Manager XML     -> model (interfaces as zones, a
                      policy per pair of interfaces it names, static NAT actions)
        barracuda.py  CloudGen REST API JSON -> model (interfaces of source
                      entries as zones, exclusions, bi-directional rules)
        junos.py      SRX set lines or braces -> model (pairs of zones, then
                      global policies; books of zones; NAT before the policy)
        iptables.py   iptables-save output   -> model (chains flattened)
    emitters/
        panos.py      model -> PAN-OS set commands
        fortios.py    model -> FortiOS CLI configuration
        checkpoint.py model -> shell script of mgmt_cli calls
        asa.py        model -> ASA commands (access lists per interface, twice NAT)
        cisco.py      model -> the script for a Management Center (fmc_loader.py
                      and the policy as data), or the import file of a Device
                      Manager
        fmc_loader.py the program of that script: stands alone, imports
                      nothing of the package, and is shipped as it is
        sophos.py     model -> Entities.xml (a rule per IP version, flat groups)
        pfsense.py    model -> the areas aliases, nat and filter of a pfSense
                      configuration (a rule per arrival interface)
        sonicwall.py  model -> SonicOS 7 commands (a rule per pair of zones and
                      IP version, a rule that denies at the end of each pair)
        watchguard.py model -> the policy part of a Policy Manager file (aliases
                      of zone and address, static NAT actions in policies)
        barracuda.py  model -> a shell script of REST calls (rules created
                      deactivated at the top, then activated in order)
        junos.py      model -> SRX set commands (policies per pair of zones,
                      the end of the model as global policies, NAT rule sets)
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
    tools/            the scripts that write the Check Point sample, the two
                      Cisco Secure Firewall samples and the SonicWall,
                      WatchGuard, Barracuda and Juniper samples,
                      and the kernel check
    helpers.py        loaders, and readers for emitted PAN-OS, FortiOS,
                      Check Point, ASA, Sophos and Cisco Secure Firewall output;
                      a pfSense that judges packets from its configuration;
                      a SonicWall that judges by an export and by commands;
                      a Firebox that judges by its configuration file;
                      a CloudGen Firewall that judges by API answers or a script;
                      an SRX that judges by set lines
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
    test_cisco.py     Cisco Secure Firewall both ways and for both managers:
                      a made-up device that judges packets, a strict reader
                      of what is written, a made-up Management Center that
                      the script is run against
    test_pfsense.py   pfSense both ways: random configurations against the
                      judge in helpers.py, emitted files restored into it
    test_sonicwall.py SonicWall both ways, against the two judges in helpers.py
    test_watchguard.py WatchGuard both ways, against the judge in helpers.py
    test_barracuda.py Barracuda both ways, against the judge in helpers.py
    test_junos.py     Juniper SRX both ways, against the judge in helpers.py
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
  For Cisco Secure Firewall there are three judges, none of them the
  project's parser. `Lab` is a made-up device: random zones, objects, access
  rules in sections with an inherited policy, a prefilter policy, and for
  each a predicate that says what the device does with a packet; `Manager`
  writes what a Management Center answers for it, or what a Device Manager
  exports. The model read from that JSON has to agree with the lab on every
  packet. `helpers.CiscoConfig` reads what the emitter writes, the plan of
  the script or the import file, strictly: an object exists before it is
  used (for a Management Center: an earlier call created it), a name is
  given once whatever its case, a group has members, holds no port group and
  no host name, and a rule says only what a rule of that manager can say.
  `FakeFmc` is a made-up Management Center that speaks the REST API as far as
  the script uses it (tokens that run out, paging, bulk calls, "too many
  requests", names that are taken, objects in use that cannot be deleted):
  the script is run against it, over a socket as well, and what it built is
  read back by the parser and compared packet by packet with the model. A
  mutation check (95 ways to break the parser, the emitter and the script) is
  not part of the suite; when it was run, the ones the tests did not catch
  got tests. All three judges are written from the same reading of Cisco's
  documentation and tooling as the code they check: they find where the code
  disagrees with that reading, not where the reading is wrong.
* `tests/tools/make_checkpoint_sample.py` writes `checkpoint_sample.json`.
  The shape of that export follows the API documentation; it has not been
  compared with the output of a real management server.
  `tests/tools/make_cisco_samples.py` writes `fmc_sample.json` and
  `fdm_sample.txt` with the builder of the tests; neither has been compared
  with what a manager gives.

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
2. Run the tests with the oldest Python the package supports (3.9) as well as
   a current one: syntax that only newer releases take (a backslash in an
   expression of an f-string, before 3.12) compiles here and fails there.
3. Commit, then tag and push the tag:

   ```sh
   git tag v0.7.0
   git push origin v0.7.0
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
| Cisco Secure Firewall: two formats, `fmc` and `fdm`, one parser and one emitter | The two managers hold the same policy for the same device in two shapes of JSON (CamelCase types with `objects`/`literals`, lower-case types with plain lists and wrappers). What a rule means, how NAT is ordered and what an object can say is the same; a second parser would repeat all of it. |
| Management Center input is REST API JSON | There is no configuration file a person can export and read: the `.sfo` of Import/Export is a binary archive. The API is documented, and its answers are what Cisco's own tooling reads. |
| Management Center output is a script that calls the API, and carries the policy as data | The API is the only way in. A list of `curl` calls cannot be written ahead of time: every reference needs the id the Management Center gave the object when it was created. So the output is a program that creates, remembers ids and goes on, and the policy it creates is data at its end, which a person (and a test) can read without running anything. |
| The script creates new policies and changes nothing that exists | A Management Center has no session to review and discard, as a Check Point server has. What can be offered instead is a run that looks before it creates anything, refuses to touch a name that is taken, assigns nothing to a device, writes down what it created, and can delete it again. |
| The loader is a file of its own that imports nothing of the package | It runs on another machine, long after the conversion, and has to be readable as what it is: 700 lines that talk to a firewall manager with someone's password. It is tested as a module and shipped as text. |
| Prefilter rules are read as the first rules of the policy | They are evaluated first, and Fastpath and Block are final. Analyze is the one thing a single list cannot say: "the rules below me in this list do not get this traffic, the next list does". A Fastpath rule below an overlapping Analyze rule is therefore not converted, and a Block rule in that place is reported. |
| A Device Manager gets no disabled rules and no placeholders | It has no rule that is switched off, and an import that is refused half way is worse than a shorter file. What cannot be written is left out and listed as skipped, with the warning for blocking rules. |
| A file for a Device Manager holds no zones | An import replaces what has the same name: a zone written without its interfaces would take them out of the zone the device has. |
| Access rules of a Cisco source keep their real addresses until an emitter needs otherwise | As for an ASA: the parser rewrites the rules for the model (pre-NAT), and the Cisco emitters turn that round again for the NAT rules that are really written. |
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
| Management Center, access control: rules are first match; mandatory rules before default rules; with inheritance the mandatory rules of the parent, then the child, then the default rules of the child, then of the parent; the default action of the policy applies last; *Monitor* decides nothing; *Trust* allows without inspection; the access rules see the real (translated) destination. (Configuration guide; not run.) | Cisco parser, `Lab` of the tests |
| Management Center, prefilter: evaluated before the access rules; *Fastpath* and *Block* are final, *Analyze* hands the traffic to the access rules **and ends the prefilter for it** (the first matching prefilter rule decides); tunnel rules match the outer packet of GRE, IP in IP, IPv6 in IP and Teredo (UDP 3544); the default action is "analyze all tunnel traffic" or "block all tunnel traffic". (Configuration guide.) | Cisco parser |
| Management Center REST API, as read: object types `Host`, `Network`, `Range`, `FQDN`, `NetworkGroup` (`objects` and `literals`), `ProtocolPortObject` (`protocol`, `port`), `ICMPV4Object`/`ICMPV6Object` (`icmpType`, `code`; **without `icmpType`: every type**, an inference), `PortObjectGroup`, `SecurityZone`, `InterfaceGroup`; `AccessRule` with `sourceZones`, `destinationZones`, `sourceNetworks`, `destinationNetworks`, `sourcePorts`, `destinationPorts` (each `objects`/`literals`), `action`, `enabled`, `logBegin`, `logEnd`, `metadata.ruleIndex`, `metadata.section`, `metadata.accessPolicy`; lists with `items` and `paging.count`; names and ids only without `expanded=true`. (API documentation, the Python client `fmcapi`, the Terraform providers. Field by field, not from an answer of a real server.) | Cisco parser, `fmc_sample.json` |
| Management Center, where a policy says it inherits: an `AccessPolicyInheritanceSetting` with `basePolicy` (a call of its own, `policy/accesspolicies/{id}/inheritancesettings`; a community post shows it with the id of the policy), or `metadata.inherit` and `metadata.parentPolicy` on the access policy (**not confirmed**, from tooling), or rules in the list of the policy that name another policy in `metadata.accessPolicy` (a community post reports that the list of a child holds the rules it inherits; whether those rules name the parent there is not known). Where none of the three is in the input, the policy is read without a parent and the report says that it is not known whether it has one (`INHERITANCE_UNKNOWN`). | `_inheritance` |
| Management Center, `PrefilterRule`: `ruleType` `PREFILTER` or `TUNNEL`, `action` `FASTPATH`/`BLOCK`/`ANALYZE`, `sourceInterfaces`/`destinationInterfaces`, `encapsulationPorts` (`GRE`, `IP_IN_IP`, `IPV6_IN_IP`, `TEREDO`), `bidirectional`, `tunnelZone`; `PrefilterPolicy.defaultAction.action` `ANALYZE_TUNNELS`/`BLOCK_TUNNELS`; the access policy names its prefilter policy in `prefilterPolicySetting`. (API reference and the Terraform provider.) | `_prefilter` |
| Management Center NAT: `FTDManualNatRule` and `FTDAutoNatRule` with the fields of the ASA `nat` command (`originalSource`, `translatedSource`, `originalDestination`, `translatedDestination`, the four port fields, `interfaceInTranslatedSource`, `interfaceInOriginalDestination`, `unidirectional`, `patOptions`, `dns`, `noProxyArp`, `routeLookup`, `fallThrough`); manual rules in `metadata.section` `BEFORE_AUTO`/`AFTER_AUTO` with `metadata.index`; automatic rules sorted by the device as on an ASA. `sourceInterface`/`destinationInterface` name a security zone or an interface group. (`fmcapi`, Terraform provider.) | `_nat`, `_manual`, `_automatic` |
| Device Manager, as read: the export is a JSON list, first a `metadata` object (`hardwareModel`, `softwareVersion`, `apiVersion`, `configType`, `exportType`), then `identitywrapper` objects with `data`, `action` and, for a rule, `parentName` and `index`; types `networkobject` (`subType` `HOST`/`NETWORK`/`RANGE`/`FQDN`), `networkobjectgroup`, `tcpportobject`, `udpportobject`, `protocolobject`, `icmpv4portobject`, `icmpv6portobject`, `portobjectgroup`, `securityzone`, `accessrule` (`ruleAction` `PERMIT`/`TRUST`/`DENY`, `eventLogAction`), `manualnatrule`, `objectnatrule`. (The import/export chapter of the API guide and the API specification that ships with Cisco's Ansible modules.) | Cisco parser, `fdm_sample.txt` |
| Device Manager: the names of its protocols (`GRE`, `ESP`, `OSPFIGP`, ... 121 of them, none for protocols 4 and 41) and of its ICMP types and codes (`ECHO_REQUEST`, `DESTINATION_UNREACHABLE`/`PORT_UNREACHABLE`, ...), and **which number each stands for**. The names are from the API specification; the numbers are those of the IANA registries for the same keywords, which the specification does not give. A wrong pair would read or write another protocol than was meant. | `appmap.py` (`FDM_PROTOCOLS`, `FDM_ICMP_TYPES`, ...) |
| Device Manager: the containers of its NAT rules are called `NGFW-Before-Auto-NAT-Policy`, `NGFW-After-Auto-NAT-Policy` and `NGFW-Object-NAT-Policy`, its access policy `NGFW-Access-Policy`; a manual rule is "after auto" when its container says `afterAuto`. **The first name is what the emitter writes as `parentName`**; if a device calls it otherwise, the import of the NAT rules fails. (Seen in examples of the API guide; not on a device.) | Cisco parser and emitter |
| Device Manager import: takes a text file or a zip of one; wants `hardwareModel` and `softwareVersion` of the target in the first object; `apiVersion` may be `latest`; `configType` `DELTA_CONFIG` and `exportType` `PARTIAL_EXPORT` are right for a file that adds; an object without `id` and `version` and with `action` `CREATE` is created, or replaces what has its name; **references are resolved by type and name**; an access rule without `parentName` goes to the one access policy, and one without `index` to the end of its rules; nothing is deployed unless `autoDeploy` says so. (API guide, import/export chapter, where the reviewer of round 15 found each of these stated, except two: that the model and the version are wanted for a file that only adds (the guide says it for a full import), and where manual NAT rules without an index land.) | `as_fdm` |
| Device Manager: an access rule cannot be disabled (no `enabled` field in the specification); it has no description; a NAT rule can (`enabled`). Interfaces in a NAT rule are referred to with their own type (`physicalinterface`, `subinterface`, ...), which the emitter cannot know and writes as `physicalinterface`. | Cisco emitter (`DISABLED_RULE`, `INTERFACES_REQUIRED`) |
| Both managers: a network group holds no FQDN object; a port group holds port objects and no group; source and destination ports of a rule are of one protocol; a rule that blocks cannot log at the end of a connection; object names take letters, digits, `.`, `_`, `-` up to 64 characters (rule names 50 on a Management Center, with spaces); names are compared without case. (Configuration guides for the first four; the name rules are **conservative guesses**: the managers take more. A name FWShift makes up, and a name from another platform, is never one they would refuse by these rules; a name read from a manager of the same kind is written back as it was.) | Cisco emitter, `names.py`, `helpers.CiscoConfig` |
| Both managers come with `any-ipv4` (0.0.0.0/0) and `any-ipv6` (::/0), and the reader knows them without their being in the input. The value of the object `any` is **not** assumed. The other predefined objects whose names are avoided when writing (`IPv4-Private-10.0.0.0-8`, `HTTP`, `HTTPS`, `SSH`, `DNS_over_UDP`, ...) are a list from documentation and screenshots; a Management Center is asked for its names before anything is created, a Device Manager is not. | `_EVERY_ADDRESS`, `_SYSTEM_NETWORKS`, `_SYSTEM_PORTS` |
| Management Center REST API, as the script uses it: `POST /api/fmc_platform/v1/auth/generatetoken` with basic authentication answers with `X-auth-access-token`, `DOMAIN_UUID` and `DOMAINS`; lists take `limit` (1000 at most) and `offset` and say `paging.count`; `POST <collection>?bulk=true` takes a list (1000 items, 2 MB) and answers with the created `items`; **`POST .../accessrules?bulk=true&section=mandatory` appends in the order of the list, and a second call below the first**; `POST .../manualnatrules?bulk=true&section=before_auto` likewise; **a list of the rules gives them in the order of the policy**, with their names also when it is not expanded; 429 with `Retry-After` when asked too often, 401 when the token ran out; `DELETE <collection>/<id>`; a new `AccessPolicy` takes `defaultAction.action` `BLOCK`; a `SecurityZone` takes `interfaceMode` `ROUTED` and no interfaces. a redirect is never the right answer to an API call. (API documentation and `fmcapi`. The order of bulk-created rules is the assumption everything hangs on: if a Management Center orders them otherwise, the policy is not the policy that was converted. The script lists the rules after it created them and stops when their number or their order is not what it sent, which finds a wrong order as long as the list itself is in the order of the policy.) Object and zone names are compared without case, and zones share their names with interface groups: both are the cautious reading, neither is confirmed. | `fmc_loader.py`, `FakeFmc` of the tests |
| A manager accepts what the emitter writes and has not been loaded anywhere: host `192.0.0.8` as a placeholder, ranges from `0.0.0.0`, a `PortLiteral` with only a protocol number in a rule, `ICMPV4Object` with `icmpType` and `code` as strings, a NAT rule with `any-ipv4` as original and translated source, a PAT pool that is a network group of ranges, `newComments` on a rule that is created, `sendEventsToFMC` with `logBegin`. | Cisco emitter |
| FTD: the device shows its access rules as `access-list CSM_FW_ACL_ advanced` with `ifc`, `rule-id` and remarks `rule-id N: L4 RULE: name` / `L7 RULE: name`; an L7 rule appears as `permit` whatever its action. From documentation and memory, no device output was available | ASA parser |
| pfSense, all rows below: read in its source code (`filter.inc`, `util.inc`, `interfaces.inc`, `pfsense-utils.inc`, `diag_backup.php` and the edit pages) of RELENG_2_6_0 (config 22.2), RELENG_2_7_2 (23.3) and the development branch (config 24.5, commit 9363ac5); nothing was run, no pf ruleset was loaded | pfSense parser and emitter |
| pfSense: interface rules are `quick` on arrival; the order is floating rules, then interface groups (and l2tp, pppoe, enc0, openvpn), then the interface; non-quick floating rules decide where nothing matched, the last one; groups that share an interface are evaluated in the order of the file up to 2.7.2 and group by group later (config version above 23.3; whether 2.8.0 is "later" is not checked) | `_ordered`, `RULE_ORDER_VERSION` |
| pfSense: an `out` rule is evaluated on egress after rdr and outbound NAT; pass out is the default; `rdr pass` skips the in rules (and *Block private networks*), not the out rules | `_leaving`, `_pass_rule`, emitter `_floating_block` |
| pfSense: *Block private networks* drops 10/8, 127/8, 172.16/12, 192.168/16 and fc00::/7 before the rules; without `ipv6allow` all IPv6 is dropped; a rule without `ipprotocol` is IPv4; a type it does not know is `pass`; types and families are case-sensitive | pfSense parser |
| pfSense: a port is a number, a range or a port alias; a service name is looked up by `getservbyname` (the table in the parser has the IANA numbers of the names a FreeBSD `/etc/services` has, as far as known: not checked against one); a protocol and no port is every port, a port and no protocol is `proto tcp`; a range that runs backwards matches nothing | `_ports`, `SERVICE_PORTS` |
| pfSense: the network of an interface includes its virtual IPs (also an IP alias on a CARP address, `_vip<uniqid>`); from config 24.0 on it is one table for both IP versions, earlier a list, of which "not" is every address in pf when it has more than one entry (2.6; 2.7.2 for IPv6 of WAN and LAN) | `_network`, `NEGATED_LIST` |
| pfSense NAT: rdr before binat for what arrives, binat before nat for what leaves; a port forward with a numeric local port and several ports maps all of them to that port; NAT reflection in pure NAT mode puts the forward on the interfaces without a gateway (an `ovpn*` or `ipsec*` device counts as one with a gateway); automatic outbound NAT translates what leaves an interface with a gateway from the networks of the others, static routes over them, OpenVPN tunnel networks and the IPsec mobile pool; an outbound NAT rule without family and addresses is written for IPv4 and IPv6; `opt` in the source of an outbound NAT rule is read as an interface name | pfSense parser and emitter |
| pfSense restore of an area: the file may have the root `<pfsense>`; the whole section is replaced; an empty or missing section is refused; no version check and no upgrade; the filter reloads by itself; separators, `bypassstaticroutes` and linked rules go with the section | emitter, `PFSENSE_RESTORE`, manual |
| pfSense XML: a flag is an element, empty or not; text is decoded twice (also inside CDATA); alias names are up to 31 of `[A-Za-z0-9_]`, not a word of pf or of pfSense; descriptions take any text. A pfSense accepts what the emitter writes and has not restored it anywhere: trackers from 2000000001, `associated-rule-id` empty, `natreflection` `disable`, outbound NAT in the form of config 23.x | emitter |
| SonicWall, all rows below: from SonicWall's knowledge base and documentation where it says so, otherwise from the published readers of the settings export (faridlav/SonicWallParser, pryorda/sonicwallRuleParser, angeloxx/dumpwall on GitHub). Nothing was run on a SonicWall | SonicWall parser and emitter |
| SonicWall `.exp`: Base64 of `key=value` joined by `&`, values URL-encoded, `&&` at the end (KB); the key names of address objects (`addrObj*`, type 1 host, 2 range, 4 network, 8 group), groups (`addro_atomToGrp`/`addro_grpToGrp`), services (`svcObj*`, `svcObjIpType` the protocol number), zones (`zoneObj*`), interfaces (`iface_*`, `interface_Zone`), access rules (`policy*`, `V6` for IPv6) and NAT (`natPolicy*`, interfaces by `iface_ifnum`, -1 any) (the readers agree) | SonicWall parser |
| SonicWall `.exp`: action 2 is allow, 0 and 1 are deny and discard in an order the readers disagree on; empty source, destination, service is any, empty translation is original; `Port1 0` with `Port2 N` is port N; the codes of `zoneObjZoneType` (0 untrusted, 1 trusted, 2 public, 4 wireless, 5 encrypted) are one reader's reading | SonicWall parser |
| SonicOS: access rules per pair of zones, first match by priority, the default ("Any") rule at the bottom of each pair; by default LAN/WLAN to WAN/DMZ and DMZ to WAN allowed, the reverse denied (documented); other security types not documented | parser (`_default_rules`), emitter (deny tails) |
| SonicOS: an access rule names the original (public) destination and the zone of the server; NAT policies one table, first match by priority, matching inbound and outbound interface; a reflexive policy adds its mirror (the shape of the mirror assumed) | SonicWall parser and emitter |
| SonicOS CLI: `configure terminal` (7; `configure` on 6.5), `commit`; `address-object ipv4 "N" host|network|range ... zone Z`, `address-group ipv4 "G"` with member lines, `service-object "N" TCP a b`, `service-group`, `access-rule ipv4 from Z to Z action allow source address any|name|group ... service ... destination address ...` with `name` and `no enable`, `nat-policy inbound ... translated-service ...` (KB). Assumed: `priority manual N`, `access-rule ipv6`, `address-object ipv6` and `fqdn`, the `name` and `comment` of a NAT policy, zone names with a space in double quotes | SonicWall emitter, `SONICWALL_LOAD` |
| WatchGuard, all rows below: from WatchGuard's Help Center where it says so, otherwise from the published readers of the configuration file (ins1gn1a/WatchGuard-Config-Parser, watchguard-toolbox-project/xmlcheck, MattParkin14/Watchguard-Firewall-Mapping on GitHub; read, never run). Nothing was opened in Policy Manager or loaded on a Firebox | WatchGuard parser and emitter |
| Policy Manager file: root `<profile>`; `address-group-list` (member type 1 host, 2 network with mask, 3 range, 8 domain), `service-list` (member protocol number, type 1 one port, 2 range, ICMP type and code with 255 any, protocol 0 any), `alias-list` (member type 1 address at an interface with a user, type 2 another alias), `abs-policy-list` (the policies in order, `firewall`, `enabled`, `from-alias-list`, `to-alias-list`, `service`), `policy-list` (the rule of each, `-00`), `interface-list` (`if-property`/`vif-property` 1 trusted, 2 external, 3 optional, 8 custom: one reader's reading), `nat-list` (static NAT `.snat`, type 7) (the readers agree where not said) | WatchGuard parser and emitter |
| Fireware: policies are first match in manual order; automatic order sorts them by how specific they are (Help Center), and the flag `auto-order-enabled` is found in two places by two readers (searched anywhere); the Firebox denies what no policy allows (Help Center); static NAT is an action in the To list of a policy, which names the public address (Help Center) | WatchGuard parser and emitter |
| Assumed when writing: `Allow` and `Deny` as the text of `firewall` in `abs-policy-list` (the readers show numbers and words), the members of a static NAT action as they are written, and that Policy Manager reads a file of policies whose aliases name interfaces by name | WatchGuard emitter, `WATCHGUARD_LOAD` |
| Barracuda, all rows below: from Barracuda Campus (the REST API pages and the how-to articles whose examples use it) where it says so; the rest assumed, and the keys of a rule also as an MCP server for the API on GitHub (LanceHardwoodXXX/Barracuda-MCP-v2; read, never run) sends them. Nothing was run against a CloudGen Firewall | Barracuda parser and emitter |
| CloudGen REST API: base `/rest/config/v1`, header `X-API-Token`; `GET forwarding-firewall/rules` (with `expand=true`) answers `{"rules": [...]}`; `POST forwarding-firewall/objects/networks` with `name` and `included: [{"entry": {"ip": ...}}]`; `POST .../networks/<name>/included` with `{"entry": {"ip", "interface", "comment"}}`; `POST forwarding-firewall/rules` (or `rules/lists/<list>`) with `name`, `source`/`destination`/`service` as `{"references": ...}`, `action: {"type": "block"}`, `position: {"placement": "top"}`; `PATCH forwarding-firewall/rules/<name>` with `{"deactivated": false}` (Campus examples) | Barracuda parser and emitter |
| Assumed: `ipVersion` `IPv4`/`IPv6`, `bidirectional`, `comment`, the action types `pass` and `deny`, `excluded` entries, service objects as `entries` of `{"entry": {"protocol", "ports", "clientPortUsed": {"from", "to"}}}`, a reference among the entries of an object, names of up to 32 letters, digits, `.`, `_` and `-` told apart without regard to case | Barracuda parser and emitter, `BARRACUDA_LOAD` |
| CloudGen semantics: first match, IPv4 and IPv6 rules apart, Block drops, Deny answers, what no rule matches is blocked, the interface of an entry counts in a source only, a bi-directional rule matches the other way round, excluded entries leave addresses out, an ICMP service entry matches every type (Campus) | Barracuda parser, emitter and judge |
| Juniper, all rows below: from Juniper's documentation (security policies, global policies, address books, predefined applications, application sets, NAT, static NAT, configuration groups, viewing the configuration) where it says so, and from the Junos grammar of Batfish (read, never run) for the exact statements; the rest assumed. Nothing was loaded on an SRX | Juniper parser and emitter |
| Junos: policies per pair of zones, first match, then global policies, first match, then the default policy (deny-all); static NAT, then destination NAT, then the policy (which sees the translated destination and its zone), then source NAT; NAT rule sets of an interface before those of a zone, first match within a set; an address name is looked up in the book of the zone, then the global one; global policies and NAT use the global book (documentation) | Juniper parser, emitter and judge |
| Junos syntax: `set security policies from-zone A to-zone B policy P match source-address/destination-address/application ...`, `match source-address-excluded`, `then permit/deny/reject`, `then log session-init/session-close`; `set security address-book global address N prefix / range-address A to B / dns-name H [ipv4-only/ipv6-only]`, `address-set`; `set applications application A [term T] protocol P destination-port N-M source-port ...`, `icmp-type`/`icmp6-type`; NAT `pool ... address A [to B] [port N]`, `rule-set ... from/to zone ...`, `match destination-port N to M`, `then destination-nat pool`, `then source-nat interface/pool/off`, `then static-nat prefix` (Batfish, documentation) | Juniper parser and emitter |
| Assumed: names of up to 63 characters (third-party documentation); `match from-zone`/`to-zone` in global policies (a published generator writes them); the definitions of the predefined applications of the table (documentation and Batfish agree; `junos-ping` they do not, and it is not used); that `display inheritance \| display set` shows what groups give where it applies; the order of NAT rule sets of one context | Juniper parser and emitter, `JUNOS_LOAD` |

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

### 2026-10-12: version 0.7.0

**Built**

* Cisco Secure Firewall, read and written, for both of its managers:
  `parsers/cisco.py` and `emitters/cisco.py`, as the formats `fmc`
  (Management Center) and `fdm` (Device Manager).
* Read from a Management Center: the JSON its REST API answers, saved to a
  file. Access rules in their sections, with the policies a policy inherits
  from; the prefilter policy (Fastpath, Block, Analyze, tunnel rules, its
  default for tunnels); objects, groups and what a rule spells out; manual
  and automatic NAT in the order the device applies it. `--policy` and
  `--nat-policy` choose among several.
* Read from a Device Manager: its configuration export, as the text file or
  as the zip it comes in, or what its REST API answers.
* Written for a Management Center: a Python script (`--to fmc`). It holds a
  loader, `emitters/fmc_loader.py`, and the policy as data. The loader lists
  what the Management Center has, stops before it creates anything when a
  name is taken, creates objects, a new access control policy and a new NAT
  policy, assigns them to no device, checks the rules it made, keeps a
  journal and can undo its run. `--show` and `--dry-run` look first.
  `--target-policy` names the policies.
* Written for a Device Manager: a file for its configuration import
  (`--to fdm`).
* The audit takes logging and inspection of a rule of both managers into
  account; the matrix reads their policies like any other.
* An ASA target writes "the interface" again for a NAT rule that was read
  from a Management Center or a Device Manager as the address of one.
* Groups nested more than 64 deep are not converted, for every source: the
  passes that follow groups into groups would not come back from them.
* Two samples, `fmc_sample.json` and `fdm_sample.txt`, with their
  conversions to every target, and the conversions of the other six samples
  to both managers.
* The release workflow checks that the single-file package finds the loader
  inside itself and writes a script that runs.

**What the platform made necessary**

* *Two lists in front of each other.* The prefilter policy is evaluated
  before the access rules. Fastpath and Block are final, so its rules are
  read as the first rules of the policy. Analyze is not: it hands traffic to
  the access rules and ends the prefilter for it, which one list cannot say.
  The Analyze rule itself is nothing to convert; a Fastpath rule below it
  that overlaps it is not converted (it would let through what the access
  rules were to decide), and a Block rule there is kept and reported.
* *Inheritance.* The mandatory rules of a parent come before those of its
  child, its default rules after them. Where a policy says that it inherits
  is the least certain part of the format (below): the reader takes three
  forms, and says so when it finds none.
* *Source ports and destination ports are two conditions.* Read: one
  service with both. Written: a rule per set of source ports, each with the
  destination ports that go with it.
* *No negation.* Written as the addresses that are left; a negated list
  with a host name, or a negated service, cannot be written, and such a rule
  is left out rather than written without its negation.
* *Objects say one thing.* A port object is one port or range of one
  protocol, a network group holds no host names, a port group no groups: a
  service of the model becomes a group of objects, a host name moves from
  the group into the rules that use the group.
* *The only way into a Management Center is its API,* and every reference
  needs the id an object got when it was created. So the output is a
  program. It was built to be read and to be stopped: nothing that exists is
  changed, nothing is assigned, everything created is written down.
* *A Device Manager has no disabled rules,* and an import replaces what has
  the same name. So: rules that are disabled or cannot be converted are left
  out and reported as skipped, no placeholders, no zones in the file.
* *NAT is the ASA's.* The reading of manual and automatic rules follows the
  ASA parser; a manual rule with a destination is the rule of its
  connections; access rules name real addresses and are rewritten for the
  model, and back for the NAT rules that are written.

**Sources**

Cisco's REST API documentation for both managers (quick start guides, the
import and export chapter of the Device Manager guide), the configuration
guides for access control, prefilter and NAT, and the tooling Cisco and its
community publish, which is where most field names come from: the Python
client `fmcapi`, the Terraform providers for the Management Center, and the
API specification that ships with Cisco's Ansible modules for the Device
Manager. None of it was checked against an answer of a real manager. What
comes from where is in the table *Vendor behaviour the code relies on*.

**Review**

*Round 15* by the independent reviewer, with its own generators and
evaluators (none of the project's test helpers as judges): random Management
Center JSON against the parser (600 policies, 6,365 rules, 240,000 packets),
random Device Manager exports (600, 240,000 packets), its own policies
through eight pairs of source and target with its own readers of the script
and the import file (720,000 packets), the same through the project's
simulators for the other platforms (323,000 packets), random models to both
managers (1,200 models, 360,000 packets), the eight samples to both, NAT
followed through to the access rules (500 policies, 30,000 packets), a
mutation fuzz of both readers (4,060 inputs), about 90 hostile files through
the command line, and about 85 scenarios of a hostile or sloppy server
against the loader, 45 of them over real HTTP and HTTPS. No packet got
through a converted policy that the device would not let through without a
finding on the rule that decides. The findings were in the loader, in what
the reader does with an incomplete input, and in the documents:

| | Finding | Fix |
|---|---|---|
| high | A child policy was read without its parent, silently, when nothing in the input said that it inherits; the recipe of the manual did not fetch what says so, and the error for several policies pointed the user at `--policy` | the inheritance settings are in the recipe; a parent is also told from rules in the list of a policy that name another; where nothing tells, `INHERITANCE_UNKNOWN` at review level |
| high | The loader followed redirects, and sent the password and the token along, also from https to plain http | no redirect is followed; it is an error that says why |
| medium | The journal was not true after a call that was carried out and answered badly (a 500, a page of HTML, half an answer): objects existed that `--undo` did not know | after such a call the loader asks what is there; an object is the run's if it was not there before and says what was sent |
| medium | The journal was first opened after the first object existed and rewritten in place: a path that cannot be written gave a traceback with a zone already created, a full disk a journal that could not be read | written before anything is created, replaced in one step, per call; `--name` is checked like `--target-policy` |
| medium | From a Management Center to a Management Center, names FWShift made up held colons (`h-2001:db8::1`) and could differ from a name of the source in case only | made-up names follow the strict rule whatever the source, and names are kept apart whatever their case |
| medium | A policy without the list of its rules, an error of the API saved in place of an answer, a list that says it has rules and holds none, and items of a rules list with a type FWShift does not know were all passed over without a word | `EXPORT_INCOMPLETE` for each |
| medium | `--undo` counted a 404 as deleted (a journal run against another Management Center "deleted" everything and renamed the journal), and the manual said that changed objects are kept, which they are not | the journal names its host and domain and is refused elsewhere; what is gone is said to be gone; the manual says what a delete by id does |
| medium | With a server that hid an object from the list and passed over it in the bulk call, the loader took the old object for its own, used it in the rules and deleted it on undo | ids are taken from the answer of the creating call; anything else is only the run's when it was not there before and says what was sent, otherwise the run stops and leaves it alone |
| medium | The answer to the rules call was not looked at: 15 of 18 rules created, "created with 18 rules" | the rules are listed afterwards and compared, number and order |
| low | Tracebacks of the loader: a `--cafile` that is none, a host with a space, an answer that is not HTTP, no password and no terminal, a policy or a journal that was edited | one line each; an edited policy is checked before anything is done, and can only post objects where objects go |
| low | Zones were matched with their case and objects without; a zone name an interface group has was found out after two zones were created | a zone that exists in another case is used; the interface groups are listed first |
| low | `RecursionError` in a conversion for groups nested about a thousand deep, or in a ring of that length | groups nested more than 64 deep are not converted, for every source |
| low | An encrypted zip given without `--from` got the general "compressed" message; an empty zip was taken for FortiOS | a zip is looked into, and the message says what is wrong with it |
| low | A Device Manager input without its interfaces and zones (FWShift's own import file read back): each interface of a NAT rule became a zone of its own, without a finding | read for any zone, `NAT_INTERFACE` at review level |
| low | Time: the journal was rewritten for every object (55 s for 4,000), the Device Manager emitter was quadratic in port objects (34 s for 10,000 rules), a listing could go on for ever, a zip unpacked to 500 MB was read | per call; an index (5,000 rules in 6 s on a shared CPU); 5,000 pages at most; 128 MB |
| low | A port object of a Device Manager with an empty port was every port, one without the field made the rule unusable; `"any"` as a port was every port | all three make the object unusable |
| nits | `PERMIT` for a Management Center and `ALLOW` for a Device Manager were taken; an unknown section was mandatory without a note; a holder with nothing but a type inside another was "nothing"; ping with code 0 could not be written for a Device Manager; a second undo said "deleted" | each manager its own words; `RULE_SECTIONS_UNKNOWN`; a type further in is content; written as the type alone (`ICMP_CODE`); fixed |

Not changed: a blocking rule that names protocols 4 and 41 next to others
is left out whole for a Device Manager (the reviewer: "worse than it
sounds"; it is now said in the manual and on the to-do list); `--policy` is
ignored for sources that have no such thing, like `--vsys`; a zone map that
merges two zones widens a rule between them without a note (older than this
release, on the to-do list).

The reviewer also went through the helpers the tests stand on. What it named
and what was done: the reader of emitted output skipped the name check for a
source of the same kind (a test of its own now), and did not keep ICMP codes
(it does); the made-up Management Center accepted any name, any value and a
blocking rule that logs at the end (it refuses them now), always answered in
full (it can now answer badly after carrying a call out, hide an object from
a list, pass over existing names, drop or reverse rules), and has interface
groups. Open: the made-up device of the tests has no ICMP codes and no
protocols 4 and 41, does not translate (packets name real addresses), and
the round trip between managers is compared with the model the project's own
parser read.

The fixes were not reviewed again. They have tests (the last sections of
`test_cisco.py`), and the suite, the mutation check and the type check were
run on them.

**Verified, and not**

* The tests: `tests/test_cisco.py` holds 437 tests, the suite
  2283. A mutation check with 67 ways to break the parser, the emitter
  and the loader was run before the review: 66 were caught, the one that was
  not (prefilter rules in the order of the file instead of their index) has a
  test now. The fixes of the review got a check of their own, 28 ways to
  take a fix back out: 27 were caught, and the one that was not was a line
  of the loader that did nothing (it is gone).
* **Nothing was run against a Management Center or a Device Manager.** The
  script has only talked to the stand-in of the tests and to the reviewer's;
  no import file was imported. The stand-ins are written from the same
  documentation as the code.
* The largest unknowns, in the order they would hurt: that rules created in
  bulk keep the order of the list (the script now checks, as long as a list
  of rules is in the order of the policy); how a real Management Center says
  that a policy inherits (the reader takes three forms and reports when it
  sees none); the names of the NAT containers of a Device Manager and the
  numbers behind its protocol and ICMP names (a wrong container name makes
  the import of NAT rules fail; a wrong number would read or write another
  protocol); whether a Management Center folds the case of names and shares
  them between zones and interface groups (the script assumes both, which is
  the cautious side); what a Management Center says to a name with a colon
  or a space (FWShift writes neither, except names it read from one).
* Application, URL, user and time conditions are not converted: such rules
  are written disabled, or left out for a Device Manager. Intrusion and file
  policies are reported and not written, also from a manager to a manager of
  the same kind.
* Not read: SSL, identity and DNS policies, platform settings, object
  overrides per device, routes. A cloud-delivered Management Center logs in
  another way than the script does.

### 2026-10-12: version 0.8.0

**Built**

* pfSense, read and written: `parsers/pfsense.py` and `emitters/pfsense.py`,
  as the format `pfsense`. Detected by the first element, `<pfsense>`.
* Read: the configuration backup (`config.xml`) of pfSense 2.6 and later, CE
  and Plus. Interface rules, rules of interface groups and of the groups
  pfSense makes itself (OpenVPN, IPsec, L2TP, PPPoE), floating rules quick
  and not, in, out and both, in the order pfSense evaluates them, which
  depends on its version; aliases of hosts, networks and ports, nested; the
  networks and addresses of interfaces with their virtual IPs, *This
  Firewall*; port forwards with NAT reflection and their filter rule
  association, 1:1 NAT, outbound NAT in its four modes; the rules pfSense
  adds for *Block private networks*, for port forwards that pass by
  themselves and for automatic outbound NAT. `--interface-address` gives the
  address of an interface that has none in the file (DHCP, PPPoE, SLAAC).
* Written: the areas Aliases, NAT and Firewall Rules of a configuration, for
  a restore under *Diagnostics > Backup & Restore*, for pfSense 2.7 and
  later. A rule per arrival interface; with `--zone-network` a rule for a
  destination zone is kept to it, as for an ASA (the code of the ASA
  emitter is shared); a leading deny for traffic that leaves becomes a
  floating rule; a rule that passes to any address leaves the firewall
  itself out; port forwards, 1:1 rules and manual outbound NAT.
* OPNsense is refused with a reason: it was planned with pfSense "where the
  two agree", and they agree less than expected (aliases, automatic rules
  and parts of NAT live elsewhere).
* `--interface-address` for any other source is an error; so is a second
  address of one IP version for one interface.
* A sample, `pfsense_sample.xml`, with its conversions to every target, its
  audit and matrix, and the conversions of the other eight samples to
  pfSense.

**What the platform made necessary**

* *The order is pf's, and the version decides it.* Floating rules first,
  then groups, then the interface; floating rules that are not quick decide
  last, the last one; group rules that share an interface are taken in the
  order of the file up to 2.7.2 and group by group after it.
* *Rules for what leaves are looked at after outbound NAT.* Read: a floating
  rule that blocks what leaves becomes a rule from every zone to that zone,
  ahead of the rest, and names the source after translation only where
  nothing is translated; one that passes what leaves decides nothing for
  forwarded traffic. Written: such a rule names a source only where the file
  decides outbound NAT, or else the report says so.
* *Rules see the translated destination.* As for FortiOS and Sophos: read
  rules are rewritten to the model's pre-NAT addresses, written rules to the
  translated ones, for the translations that are really written.
* *pfSense adds rules of its own.* Those that change what a policy lets
  through and are in the configuration (*Block private networks*, port
  forwards that pass, automatic outbound NAT) are converted as rules; the
  others are named.
* *Interface rules are also the rules for the firewall itself.* Other
  platforms filter forwarded traffic apart from what goes to the firewall:
  their "to any" leaves the firewall out when written for pfSense.
* *One protocol per rule, no service objects.* A rule per protocol, port
  aliases whose names cannot be taken for a service name.
* *A restore replaces an area.* The output is one file for three restores,
  and the report says what each takes along.

**Sources**

The source code of pfSense: RELENG_2_6_0, RELENG_2_7_2 and the development
branch (commit 9363ac5), above all `filter.inc` (what a rule becomes for
pf), `util.inc`, `interfaces.inc`, the edit pages of rules, aliases and NAT,
and `diag_backup.php` with `restore_config_section()`; the ICMP type names
of pfctl. Nothing was run on a pfSense, and no pf ruleset was loaded. The
judge in `tests/helpers.py` is written from the same reading of the same
code, apart from the parser.

**Review**

*Round 16* by the independent reviewer, with repro scripts of its own and
about 6,000 mutation-fuzz runs through the parser and four emitters, all
eight samples converted to pfSense, and the source code of all three
pfSense versions. 3 high, 8 medium and 8 low findings; in five of them the
judge of the tests made the same mistake as the code.

| | Finding | Fix |
|---|---|---|
| high | A floating rule that blocks what leaves, with a source, was written without a NAT area: the firewall keeps its own outbound NAT (automatic on a stock pfSense), translates the source first, and the rule never matches | written for the arrival interfaces where the networks of every zone are known; otherwise a floating rule with `FLOATING_AFTER_NAT` at review level. A test restores onto a firewall with automatic outbound NAT |
| high | Rules of platforms that filter only forwarded traffic opened the firewall itself: an iptables `FORWARD` rule for port 443 became `pass ... to any port 443` on WAN, the web interface included, "exact" | a rule of another platform that passes to any address is written for "any but This Firewall" (`SELF_EXCLUDED`) |
| high | Ports given as service names (`ssh`, `https`), which pfSense takes, made the rule "not loaded" | read by a table of service names; a name not in it makes the rule unusable, not unloaded |
| medium | Port forwards and 1:1 rules on an interface group or on OpenVPN, IPsec, L2TP, PPPoE were "not loaded" | read on the interfaces of the group or the system group |
| medium | A port alias forwarded to one numeric port was read as port to the same port | as `filter.inc` does it: all to that one port, unsupported (`several ports translated to the one port`) |
| medium | A virtual IP on a CARP address (`_vip<uniqid>`) was left out of the interface networks, *This Firewall* and automatic NAT | its parent's interface |
| medium | pfSense reads `opt` in an alias name in the source of outbound NAT as an interface (2.7.2: a ruleset that does not load) | such an alias is wrapped in another (`nat_set`) |
| medium | A floating rule without direction was read as `in`; pf has it for both | both |
| medium | The development branch keeps one table for both IP versions of an interface network (`not` of the version it lacks is every address); 2.6, and 2.7.2 for IPv6 of WAN and LAN, write `not` of a network with virtual IPs as a list that pf reads as every address | both by the version in the file; the second with `NEGATED_LIST` at review level |
| medium | Which interface has a gateway differed from pfSense (OpenVPN, IPsec, GIF, GRE), with NAT reflection on tunnel interfaces as a result; `NAT_AUTOMATIC_SOURCES` claimed tunnel networks were missing that were there | as `interface_has_gateway`; OpenVPN tunnel networks and the IPsec pool in automatic NAT, the finding for what is not in the file |
| medium | Aliases nested about 1,000 deep: a traceback | more than 64 deep is unusable, also for ports |
| low | Bridge members are separated by commas, and pfSense finds them by substring | as pfSense |
| low | No protocol and a port is `proto tcp` without a port; a range that runs backwards matches nothing; type and family are case-sensitive; 2.6 loads no floating rule on `any` | each as pfSense |
| low | Two interfaces with one description became one zone | a zone name of its own for the second |
| low | U+FFFE and other characters XML cannot hold reached the output | left out |
| low | Report texts: `MATCH_RULE_SKIPPED` said floating, `PFSENSE_RESTORE` did not say what a restore takes along; `--interface-address` was ignored for other sources and a second address replaced the first | fixed; both are errors |
| low | An outbound NAT rule without family and addresses is also IPv6 NAT | `NAT_IPV6_ALSO` |
| low | *This Firewall* is narrower than pf's `(self)` | in the manual |

Not changed: alias names that `/etc/services` or `/etc/protocols` hold are
not avoided (the web interface refuses them on the next edit, the restore
does not); leading spaces in values, which pfSense keeps; SCTP ports, which
2.6 ignores; whether `no rdr` and `no binat` reach further than their own
kind of NAT (a suspicion from pf, not checked). All four are on the to-do
list.

The judge of the tests was corrected with the code for service names, a
port and no protocol, floating rules without direction, virtual IPs on CARP
addresses and NAT on groups. The fixes were not reviewed again. They have
tests (the last section of `test_pfsense.py`, and an oracle that restores
onto a firewall with automatic outbound NAT), and the suite, the mutation
check and the type check were run on them; the check for `--interface-address`
with another source found that the option had been ignored there after all.

**Verified, and not**

* The tests: `tests/test_pfsense.py` holds 217 tests, the suite 2519. The
  parser is compared with the judge on random configurations (four versions
  and modes, 70 each, 300 packets each), NAT on 80, the emitter restored
  into the judge on 100 random models and on 30 more with automatic
  outbound NAT on the target, and the round trip pfSense to pfSense on 120.
  A mutation check with 14 ways to break the parser and the emitter, run
  after the fixes: all 14 were caught, three of them at first only by a
  golden file or not at all (service names in random rules, the last-match
  order of floating rules for what leaves, NAT reflection on a written 1:1
  rule); those have tests of their own now, and the judge refuses a 1:1
  rule with reflection.
* **Nothing was restored on a pfSense, and no pf ruleset was loaded.** The
  judge is written from the same reading of the same source code as the
  parser and the emitter, by the same hand; the reviewer read the code
  again, independently.
* The largest unknowns, in the order they would hurt: whether pfSense 2.8.0
  orders group rules as the development branch does (config 24.0 is read so);
  the names `getservbyname` knows; whether the restore of an area keeps
  references to aliases that are restored later (the manual says aliases
  first); what a restore does with a file written for 2.7 on a firewall
  with a configuration that pfSense upgraded since.
* Not converted: schedules, URL table aliases, policy routing, tags,
  limiters and shaping, match rules, IPv6 NAT, NPt, bogon networks, the
  captive portal, bridges, and the rules of packages and services.

### 2026-10-12: version 0.9.0

**Built**

* SonicWall, read and written: `parsers/sonicwall.py` and
  `emitters/sonicwall.py`, as the format `sonicwall`.
* Read: the settings export of SonicOS 6.5 and 7 (`.exp`, Base64 of
  URL-encoded pairs), or its decoded text. Address objects and groups,
  services and groups, zones and their security types, interfaces, access
  rules of both IP versions per pair of zones, NAT policies with interfaces
  as zones, reflexive policies. Objects SonicOS has by itself are worked out
  from the interfaces of the export (`X1 IP`, `X0 Subnet`, `LAN Subnets`,
  `Firewalled Subnets`, ...), default services from a table; the default rule
  of a pair of zones that has none in the export from the security types of
  its zones. `--interface-address` also for a SonicWall source.
* Written: commands of the SonicOS 7 command line. One rule per pair of zones
  and IP version with its place in the pair, groups for lists, the addresses
  that are left for a negation, a rule that denies at the end of every pair
  (SonicOS allows LAN to WAN by itself), NAT policies per pair of interfaces.
* A sample, `sonicwall_sample.exp`, written by `tests/tools/make_sonicwall_sample.py`,
  with its conversions to every target, its audit and matrix, and the
  conversions of the other nine samples to SonicWall.

**What the platform made necessary**

* *An undocumented format.* SonicWall documents how to decode the export and
  nothing of its keys. The parser reads what the published readers agree on,
  says so in a note, and treats every key a row does not have as unknown
  rather than as "any".
* *Rules per pair of zones, and defaults per pair.* The model's rules are one
  list; a SonicOS rule is for one pair. Read: rows of a pair in order, the
  default rule last. Written: a rule per pair, numbered within it.
* *Defaults that allow.* SonicOS lets LAN reach WAN with no rule. A policy of
  another platform denies that by default: every pair gets a rule that denies
  at its end.
* *One object per field, no negation, objects per IP version.* As for the
  Cisco managers and Sophos.
* *Objects of the firewall itself* (`X1 IP`) are in no export: worked out
  from the interfaces, and avoided as names when writing for a SonicWall.

**Sources**

SonicWall's knowledge base and documentation (decoding the export, the CLI
forms of objects, access rules and NAT policies, default access rules, zones,
NAT and its reflexive option), and three published readers of the export
for the key names. What comes from where, and what is assumed, is in the
table *Vendor behaviour the code relies on*.

**Review**

*Round 17* by the independent reviewer, with repro scripts of its own (about
40 hostile inputs through the command line). 5 high, 4 medium, 3 low:

| | Finding | Fix |
|---|---|---|
| high | A key a row did not have was read as empty, and empty is "any": a row with only an action became "allow any to any"; a missing `Enabled` was enabled, a missing interface of a NAT policy any | a key that is not there makes the rule unusable (written disabled, reported); an empty zone too |
| high | Nested service groups were written in the order of the model; a group before its member group lost that member, silently | groups after the groups in them; a member that cannot be written makes the group unusable |
| high | SonicWall to SonicWall: a group of SonicOS (`VPN Subnets`) inside a group was spelled out, and dropped when the export showed no interface of it | named, as SonicOS has it |
| high | A group that holds itself crashed the emitter | followed once |
| high | A zone with a space in its name was written without quotes: the commands that deny for it would be refused, and SonicOS's defaults apply | quoted |
| medium | `Port1 0` and `Port2 80` was read as ports 1 to 80 | port 80, as the readers show it |
| medium | An IPv6 rule that names an object of SonicOS got its IPv4 addresses | such a rule is unusable |
| medium | A priority of 5,000 digits: a traceback; 600 zones: 119 MB of output | a priority nobody can mean is none; more than 100 zones is an error that says why |
| medium | The version was not raised yet | raised |
| low | A default rule with a low priority number could stand before the rules of its pair; a NAT comment could end in a backslash; an FQDN was written without quotes | last of its pair; the characters left out; quoted |

Not changed: NAT policies are written in order without a priority (the
command is not known; the report says to check the order); the zone of an
address object is not read (SonicOS does not match by it). The judges were
corrected with the code where they shared a mistake (the place of the
default rule, `Port1 0`). The fixes were not reviewed again; they have tests
(the last section of `test_sonicwall.py`).

**Verified, and not**

* The tests: `tests/test_sonicwall.py` holds 153 tests, the suite 2693. The
  parser is compared with an independent reading of the export on 120 random
  exports (300 packets each), the emitter with the model on 60 random models
  on a firewall whose own defaults allow some pairs, the round trip on 30, the
  NAT of the emitter on 40. A mutation check with 12 ways to break parser and
  emitter: 11 caught, the twelfth changes nothing a packet can show (an ICMP
  rule written for IPv6 as well).
* **Nothing was run on a SonicWall.** The format of the export comes from
  third-party readers, the commands from knowledge-base articles; the judges
  are written from the same reading. NAT parsing has hand tests only.
* The largest unknowns: whether `priority manual N` is the command (without
  it SonicOS orders the rules of a pair by itself); which of the action codes
  0 and 1 is deny; how an export stores ICMP services, IPv6 and MAC objects;
  whether the default rules of a pair are rows of every export; the shape of
  a reflexive mirror.

### 2026-10-12: version 0.10.0

**Built**

* WatchGuard, read and written: `parsers/watchguard.py` and
  `emitters/watchguard.py`, as the format `watchguard`.
* Read: the configuration file of Policy Manager (Fireware 12). Interfaces
  as zones with their types, address groups, aliases (members that are an
  address at an interface, and other aliases), services, policies in the
  order of the file with their action and whether they are enabled, and the
  static NAT actions of their To lists as NAT rules of their own. A policy
  that names members of several interfaces becomes one rule per pair of
  From and To members. Automatic policy order is reported.
* Written: the policy part of a configuration file, to merge into one of
  the target: address groups, services, aliases of every zone and address a
  rule names, policies in manual order, and static NAT actions in the
  policies that allow exactly their traffic. Placeholders and disabled
  policies carry `FWSHIFT` in their description.
* A sample, `watchguard_sample.xml`, written by
  `tests/tools/make_watchguard_sample.py`, with its conversions to every
  target, its audit and matrix, and the conversions of the other ten samples
  to WatchGuard.

**What the platform made necessary**

* *An undocumented format.* WatchGuard publishes no schema and no sample of
  the file. The parser reads what three published readers agree on, says so
  in a note, and makes a policy unusable where an element it needs is not
  there (whether it is enabled, its service, an alias it names) rather than
  reading "any".
* *No zones, addresses at interfaces.* A member of an alias is an address
  and an interface together; the interfaces are the zones. A policy can
  name members of several interfaces on each side; the model's rule has one
  list of zones and one of addresses per side, so it becomes a rule per
  pair of member groups, which together match what the policy matched.
* *Automatic order.* By default the Firebox orders policies itself, by a
  cascade of how specific they are. That order is not worked out: the
  report says the file's order was read, and the output switches to manual
  order.
* *NAT inside the policy.* A static NAT action is part of the policy that
  uses it, so a NAT rule of the model can only be written into a policy
  that allows exactly its traffic, and is translated only there. Network
  dynamic NAT and 1-to-1 NAT are where none of the readers found them: not
  read and not written, and the report says so.

**Sources**

WatchGuard's Help Center (the file and how to get it, aliases and their
members, policy precedence and automatic order, unhandled packets, SNAT,
dynamic and 1-to-1 NAT, the default policies) and three published readers
of the file for the element names, read and never run. What comes from
where, and what is assumed, is in the table *Vendor behaviour the code
relies on*.

**Review**

*Round 18* by the independent reviewer, with repro scripts of its own
(hostile files through the command line, and the parser and emitter
against the judge). 5 high, 5 medium, 4 low:

| | Finding | Fix |
|---|---|---|
| high | A static NAT action was written into any policy for its public address, whatever its service, zones and sources: traffic the NAT rule did not translate was translated, and the reverse | only into a policy that allows exactly the NAT rule's traffic, which is enabled, allows, and has no other NAT rule before it; otherwise `NAT_NOT_IN_POLICY` |
| high | Read: one NAT rule for a static NAT action, for any source: the translation of one policy applied to traffic of others | one NAT rule per policy and source interface, with the sources, service and state of the policy |
| high | A user in the To list was dropped: the policy matched every user | the policy is unusable (written disabled) |
| high | Aliases that name each other many times over multiplied their members without end (memory) | members de-duplicated as they are read, and a cap on members in all, which is an error that says why |
| high | WatchGuard to WatchGuard: a policy naming the Firebox itself crashed the emitter (an assertion) | the Firebox is named as an alias, as Fireware has it |
| medium | Automatic order was taken to be off unless the flag said `1`; another value or no flag at all went unreported | anything but `0` is automatic, and a file without the flag is reported too |
| medium | An interface without a type took part in no class: `Any-Trusted` silently lost it | a member of a class is unusable when an interface of the file does not say its type |
| medium | `Firebox` as the interface of a member was read as no interface | it stands for every zone, as `Any` does |
| medium | A static NAT action named directly in the To list, not inside an alias, was not found | found both ways |
| medium | A policy with many members on both sides became thousands of rules | more than 1000 pairs makes the policy unusable |
| low | An ICMP member without a type was ICMP of any type; port 0 alone and protocol 0 were written as "every port" and "every protocol"; two objects of one name, the later one won; a policy and its rule in `policy-list` that disagree were not noticed | unusable; not written, and the rules that use them disabled; an error; the policy is unusable |

The judge was corrected with the code where it shared a mistake (a static
NAT member matches whatever interface the traffic leaves by). The fixes were
not reviewed again; they have tests (the last section of
`test_watchguard.py`).

**Verified, and not**

* The tests: `tests/test_watchguard.py` holds 105 tests, the suite
  2821. The parser is compared with an independent reading of the file
  on 80 random configurations, the emitter with the model on 60 random
  models, the round trip on 30. A mutation check with 12 ways to break parser and
  emitter: all 12 caught.
* **Nothing was opened in Policy Manager or loaded on a Firebox.** The
  format comes from third-party readers, one of which works from a sample it
  generated itself; the judge is written from the same reading. NAT has hand
  tests only.
* The largest unknowns: whether Policy Manager accepts a file merged from
  these lists, and the words it writes for the action of a policy; where the
  file keeps dynamic NAT, 1-to-1 NAT and the NAT settings of a policy; the
  codes of interface types (one reader); where `auto-order-enabled` sits.

### 2026-10-12: version 0.11.0

**Built**

* Barracuda CloudGen Firewall, read and written: `parsers/barracuda.py` and
  `emitters/barracuda.py`, as the format `barracuda`.
* Read: saved answers of the REST API of the firewall (8.0 and later), one
  after the other: the forwarding rules and the network and service objects
  they name. Rules of both IP versions, first match; pass, block and deny;
  deactivated; bi-directional rules as two rules; the interfaces of the
  entries of a source object as zones, a rule per interface; excluded entries
  subtracted; references between objects; TCP and UDP with client ports,
  ICMP, IP protocols.
* Written: a shell script of curl calls to the same API. Objects; then every
  rule, deactivated, at the top of the list, last rule first; then the rules
  that are to be active are activated, first rule first, so that a refused
  call leaves only the start of the policy active. Zones as the interfaces of
  source entries or as networks; a rule that blocks the rest, deactivated.
  `DRY_RUN=1` prints the calls.
* A sample, `barracuda_sample.json`, written by
  `tests/tools/make_barracuda_sample.py`, with its conversions to every
  target, its audit and matrix, and the conversions of the other eleven
  samples to Barracuda.
* Names are told apart without regard to case where a target asks for it
  (`sanitize_names(fold_case=True)`); a lone UTF-16 surrogate in any JSON
  input is an error instead of a traceback when the report is written.

**What the platform made necessary**

* *No export.* The configuration backup of a CloudGen Firewall (PAR, PCA,
  PGZ) is in a format of its own that Barracuda does not document, and
  Firewall Admin copies rules only between its own windows. The REST API is
  the one way out a program can read, and the one way in: input and output
  are both JSON of that API, documented by examples only. What is not in an
  example is assumed, and listed.
* *No zones.* A rule names addresses; the way out is the routes. The
  interface of an entry of a source object is the only interface a rule
  matches, and becomes the zone. Written, a zone is that interface or the
  networks behind it.
* *A list that is already there.* The script cannot replace the rules of the
  firewall, only add to them: its rules go above, its rule that blocks the
  rest is deactivated for a person to switch on, and rules are activated in
  order so that a stop half way never leaves an allow without the blocks
  above it.
* *NAT in the rule.* Dst NAT and Map are actions, source NAT a connection
  object, in a JSON no example shows: not read and not written, and said so.

**Sources**

Barracuda Campus (REST API, access rules, actions, bi-directional rules,
cascading rule lists, network, service and connection objects, the CSV import
of network objects, backup and restore) and the examples in its integration
articles; a published MCP server for the API for the keys of a rule, read and
never run. What comes from where, and what is assumed, is in the table
*Vendor behaviour the code relies on*.

**Review**

*Round 19* by the independent reviewer, with repro scripts of its own (14,508
mutated inputs through the parser and three emitters, a fake curl that
refuses a call). 2 high, 7 medium, 9 low:

| | Finding | Fix |
|---|---|---|
| high | The script created rules active, last first, and stopped at the first refused call: a later allow could be active without the blocks above it | rules are created deactivated and activated first rule first; the report says what a stop leaves |
| high | Names were told apart by case when written and not when read: an object `ANY` became a reference the firewall, and FWShift itself, take for the object Any | names are told apart without regard to case when written; read, only `Any` is Any, and an object of that name in the input wins |
| medium | Every rule made its own copy of the addresses of an object it needed by IP version or interface: 3 MB of input took 3 GB | a group per object, interface and IP version, made once |
| medium | A lone UTF-16 surrogate in JSON gave a traceback when the report was written (every JSON source) | an error that says why |
| medium | A user condition not spelled as a reference was read as any user; `bidirectional: 1` as one-way | read strictly, otherwise the rule is not used |
| medium | A bi-directional rule whose destination names interfaces: the way back was read for every interface | not used |
| medium | A rule that expires was converted as permanent, reported as information | an allowing rule that expires is not used; a blocking one is approximated |
| medium | Keys inside the protocol settings of a service entry were not checked; a null at the top hid client ports below | checked, and two values of one key are refused |
| low | ICMP limits were a note only; a service group naming a missing service went unreported; an interface `0` or `[]` read as none; the range shorthand `192.168.50-100` read as a host name; generated rule names could collide with names of the input; IP protocol 6 written without ports; ICMPv4 written into IPv6 rules; destinations an ASA worked out from its routes needed networks; the codes were not documented, curl hid the answer of a refused call and the token was visible to `ps` | on the rule; reported, and the rule not used; refused; refused; made unique; TCP with every port; only into the rule of its version; taken as they are; documented, `--fail-with-body`, the token in a file |

The judge was corrected with the code where it shared a mistake (the way back
of a bi-directional rule with interfaces; `"false"` as a flag). The fixes
were not reviewed again; they have tests (the last section of
`test_barracuda.py`).

**Verified, and not**

* The tests: `tests/test_barracuda.py` holds 181 tests, the suite
  3027. The parser is compared with an independent reading of the
  answers on 100 random inputs, the emitter with the model on 60 random models
  in two ways (zones as interfaces, zones as networks), the round trip on 30.
  The script itself runs in `sh` against a fake curl. A mutation check with
  12 ways to break parser and emitter: all 12 caught.
* **Nothing was run against a CloudGen Firewall.** The keys come from the
  examples in Barracuda's documentation and one published tool; the judge is
  written from the same reading.
* The largest unknowns: the JSON of a service object and its entries; whether
  `ipVersion`, `bidirectional`, the action `pass` and `deny` and `excluded`
  are spelled so; the limits of names; whether the API resolves names with
  regard to case; what `expand=true` holds for rule lists; the JSON of Dst
  NAT, Map and connection objects.

### 2026-10-12: version 0.12.4

**Built**

* Windows, again: 0.12.3 asked for the password only when standard input was a
  terminal, but on Windows `isatty()` also says yes to `NUL`, a character
  device, so the test (standard input from `NUL`) still reached `getpass` and
  waited. The script now asks only when standard input is a terminal and, on
  Windows, a handle with a console mode (`GetConsoleMode`, through `ctypes`);
  whatever cannot be checked counts as nobody there.

**Verified, and not**

* A new test plays Windows on Linux: `NUL` without a console mode is not asked,
  a console is, a missing `msvcrt` is not, and `main` stops with the message
  without reaching `getpass`. It fails when the console check is taken out.
  mypy `--strict` passes, also with `--platform win32`. That the wait is gone
  on a real Windows is for the CI run on `windows-latest` to show.

### 2026-10-12: version 0.12.3

**Built**

* Windows: the script for a Management Center asked for the password with
  `getpass` when `FMC_PASSWORD` was not set. On Windows that reads the console
  whatever standard input is, so a run without a terminal (the test, a
  scheduled job) waited until it was killed instead of stopping. The script
  now asks only when standard input is a terminal, and otherwise stops with
  the message it gave before.

**Verified, and not**

* The tests of the script pass with Python 3.9 and 3.13 on Linux. That the
  wait is gone on Windows is for the CI run on `windows-latest` to show.

### 2026-10-12: version 0.12.2

**Built**

* Python 3.9 to 3.11: the SonicWall emitter (0.9.0) had a backslash in an
  expression of an f-string, which only Python 3.12 and later accept; on older
  releases no module that imports the command line could be loaded. The
  expression is now outside the f-string. A variable used for two types in the
  Barracuda emitter, which the mypy of Python 3.9 finds, is split in two.

**Verified, and not**

* Every source and test file compiles with Python 3.9, 3.10 and 3.11; the
  whole suite (3174 tests) passes with Python 3.9 and with 3.13; mypy
  `--strict` passes with the mypy that pip installs for 3.9, 3.10, 3.11 and
  3.12. The release steps now name the oldest Python.

### 2026-10-12: version 0.12.1

**Built**

* Windows: the tests failed on `windows-latest`, because Git there checks out
  text files with CRLF line endings and the loader for a Management Center
  (`fmc_loader.py`) went into the generated script with them. The repository
  now has a `.gitattributes` that keeps LF everywhere, the loader is read with
  its line endings made LF whatever the checkout did, the tests read and write
  their files as UTF-8 instead of the code page of the system, and the two
  tests that run the Barracuda script in `sh` are skipped where there is no
  POSIX shell.

**Verified, and not**

* The whole suite passes on a copy of the project with every text file
  converted to CRLF, as a Windows checkout without `.gitattributes` would have
  it. It was not run on Windows itself: the CI run on `windows-latest` is the
  check.

### 2026-10-12: version 0.12.0

**Built**

* Juniper SRX, read and written: `parsers/junos.py` and `emitters/junos.py`,
  as the format `junos`.
* Read: `show configuration | display set` (set and deactivate lines), or the
  configuration in braces, flattened to the same lines first. Zones and their
  interfaces; the global address book, books attached to zones and the books
  of zones; applications with terms and application sets; the predefined
  applications of a table; policies per pair of zones, global policies with
  their zones, the default policy; negation; deactivated policies and
  members; static, destination and source NAT with pools, brought back to
  the model's pre-NAT destinations.
* Written: set commands for `load set`: applications, the global address
  book, a policy per pair of zones in the order of the model, the rules at
  the end that are for every zone as global policies where that takes fewer
  policies, negation as `...-excluded` or as what is left, deactivated
  policies; NAT rule sets per zone and pair of zones, a destination NAT and
  its way back as static NAT.
* A sample, `junos_sample.conf`, written by `tests/tools/make_junos_sample.py`,
  with its conversions to every target, its audit and matrix, and the
  conversions of the other twelve samples to Juniper.
* The test that the manual and the code name the same findings now converts
  every sample to every target.
* Shared: a rule rewritten for a target that looks rules up after destination
  NAT, where the NAT rule translates only some of its services, is now
  reported for review (`NAT_DESTINATION_WIDENED`): for the other services it
  names the translated address, reached directly. Four reports of the
  FortiOS sample changed accordingly.

**What the platform made necessary**

* *Two places for policies.* A policy is for one pair of zones, and global
  policies come after those of every pair. Read: the pairs in order, then the
  global policies. Written: only rules at the end of the model can be global;
  where they go is chosen by the number of policies it takes.
* *Policies after destination NAT, source NAT after the policy.* As for the
  ASA: the parser brings policies back to the pre-NAT destination, the
  emitter takes them forward again for the NAT rules it writes.
* *Names per zone.* The same address name can mean different addresses in
  two zones; such objects keep their book in their name in the model.
* *Predefined applications that are not in the configuration.* A table of
  those whose definition the sources agree on; the rest make a policy
  unusable.
* *Two forms of one configuration, and groups.* The braces are flattened to
  set lines; a configuration whose security policy comes from groups not
  shown where they apply is refused with the export that shows them.

**Sources**

Juniper's documentation (security policies and their order, global policies,
address books and sets, predefined applications, application sets, NAT and
its order, static NAT, configuration groups, viewing the configuration) and
the Junos grammar of Batfish, with the Junos generators of Aerleon and
Capirca, read and never run. What comes from where, and what is assumed, is
in the table *Vendor behaviour the code relies on*.

**Review**

*Round 20* by the independent reviewer, with repro scripts of its own (3,000
mutated set configurations, 20,000 random token sequences in braces). 4 high,
5 medium, 9 low:

| | Finding | Fix |
|---|---|---|
| high | A bi-directional static NAT was written as static NAT, and the policies were not taken forward to the address the SRX sees after it: a deny for the public address no longer matched | they are |
| high | ICMPv6 types by name were read as ICMPv4 types (`echo-request` 8, not 128) | a table of ICMPv6 names; the judge corrected with it |
| high | A destination NAT and its way back written as static NAT, which the SRX applies before every destination NAT: an earlier port forward for the same address lost | not paired where an earlier destination NAT meets it |
| high | Several lists in one statement in braces multiplied: a few KB of input, gigabytes of memory | one list per statement, and blocks no deeper than 64 |
| medium | Deep braces and very long lines took minutes (the path rebuilt at every block, every prefix of a line looked up) | the path kept as it goes; only the depths that are deactivated looked up |
| medium | A global object whose name looks like an address took the place of that address in a NAT rule | such objects are renamed in the model |
| medium | A named book called like a zone and the book of that zone gave objects one name | told apart |
| medium | (shared) A rule for more services than its destination NAT, taken forward to the translated address for all of them, was only approximated | for review, on every target of that kind |
| low | `then` of a NAT rule on two lines (mapped port, persistent NAT) read as the last one only; an interzone rule that leaves no pair in the global part reported exact; `ZONES_EXPANDED` said too much; IPv6 addresses written another way refused; a short pool line reported as not read; a reserved prefix after cleaning a name; prompt lines in braces refused; groups shown by `display inheritance` refused; a zone named `any` read as every zone; the new codes not documented | merged; skipped as matching nothing; reworded; compared as addresses; ignored; checked after cleaning; dropped; read; not used; documented, and the test covers every sample and target |

Not changed: the ranking of source NAT rule sets by their `to` context is
not read (it changes what is translated, not what a policy allows). The
fixes were not reviewed again; they have tests (the last section of
`test_junos.py`).

**Verified, and not**

* The tests: `tests/test_junos.py` holds 120 tests, the suite
  3174. The parser is compared with an independent reading of the set
  lines on 100 random configurations, the emitter with the model on 60
  random models, the round trip on 30; the braces against their set lines.
  NAT has hand tests only. A mutation check with 12 ways to break parser and
  emitter: all 12 caught.
* **Nothing was loaded on an SRX.** The statements come from Juniper's
  documentation and from Batfish's grammar; the judge is written from the
  same reading.
* The largest unknowns: the exact predefined applications of a release;
  whether `display inheritance | display set` is accepted and what it prints
  for groups; names of 63 characters; `match from-zone` in global policies;
  the order of NAT rule sets of one context.

## To do

See [TODO.md](TODO.md): the firewall brands that are planned, one per
release, and what else is on the list for the audit, the matrix, the
conversion and its validation.
