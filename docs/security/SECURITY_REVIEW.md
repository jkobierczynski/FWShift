# Security review by ChatGPT, and what was done about it

On 14 October 2026 ChatGPT reviewed the FWShift repository (commit c67f137f) from its source: the README, the project
configuration, the command line, some emitters, the loader for a Cisco Management Center and the GitHub workflows. It
was a static review, not a penetration test. The full report is in this folder, as ChatGPT wrote it, in Markdown
([CHATGPT_SECURITY_REVIEW.md](CHATGPT_SECURITY_REVIEW.md)).

**Its verdict:** promising, not yet production-assured. It found no exploitable vulnerability. Its largest concern is
not a software flaw but migration safety: a converted policy that quietly opens more than the source did. It ranks
five risks and recommends a remediation order.

This page answers each point: what FWShift already did about it, what changed in 0.25.0, and what is still open. The
reaction was written by Claude (Anthropic), which builds FWShift with its maintainer.

## The points, one by one

### P1: firewall policy semantic errors

> A conversion that changes rule ordering, address matching, service definitions, NAT or the default policy can permit
> or block traffic. Require a zero-unexplained-differences equivalence check before production.

**Agreed: this is the main risk.** It is also the risk the project was built around.

* **Already in place.**
  * The converter does not widen a policy without saying so. A rule it cannot write is written disabled and reported
    for review, and nothing unknown is read as "any".
  * Every parser and emitter is tested against an independent model of its platform with random policies and
    random packets (the "oracle" tests). After each release a separate adversarial reviewer goes through it, and
    mutation testing checks that the tests catch a deliberately broken line.
  * The equivalence check already exists:
    * `fwshift compare` names every connection two policies decide differently.
    * `convert --compare` reads the output back for the targets FWShift can read and compares it with the source.
  * `--strict` exits with status 2 when anything needs review, so a pipeline can refuse it.
* **New in 0.25.0.** The README now opens its use with a short procedure ("Using it safely"). Step 3 makes the
  equivalence check, with every difference accepted explicitly, part of the recommended way to work.
* **Open.**
  * Most targets have never been loaded on a real device (the README says so).
  * Only iptables and nftables are checked against the real thing (a Linux kernel).
  * The equivalence check cannot read back every target yet (for example the Check Point, Management Center and
    Forcepoint scripts).
  * Closing these gaps needs lab devices. The TODO lists that work per vendor.

### P1: generated scripts can change live security controls

> Treat every generated artifact as privileged code; test quoting, command injection, partial failure, rollback and
> idempotency per emitter.

**Agreed.** The safeguards differ per target, because the targets differ.

* **Already in place.**
  * No output installs, publishes or deploys anything:
    * The Check Point script changes one session and publishes nothing.
    * The Management Center and Forcepoint loaders create a new policy that is assigned to no device, and they
      never change an existing object.
    * The RouterOS script switches nothing on until one disabled rule is enabled.
  * Text that goes into a script is quoted or cleaned for that target, with tests for hostile names (quotes,
    newlines, leading hyphens, shell metacharacters).
  * The loaders:
    * look before they create (`--show`, `--dry-run`);
    * stop at the first refusal;
    * write a journal call by call, and `--undo` deletes what a run created.
  * Tests make the loader fail halfway and check what it says and what the journal holds.
* **Open.**
  * Some outputs act the moment they are loaded, by their nature: an iptables or nftables ruleset, an area restored
    on pfSense or OPNsense. FWShift cannot add a confirmation step to a file the device reads. The README tells you
    to load those only with console access.
  * The AWS and Barracuda scripts create objects through an API with no journal; a journal and undo for them are a
    sensible next step.

### P2: credential and API transport security

> Verify TLS validation, token exposure, logging of secrets, URL validation, environment-variable credentials; test
> untrusted URLs, redirects, invalid certificates, authentication failures and secret redaction.

* **Already in place.** In the Management Center loader, and now in the Forcepoint loader and dump program:
  * Certificates are checked unless `--insecure` is given, and that prints a warning.
  * A redirect is never followed, so the password or token cannot go to another address.
  * Plain http is refused except to the computer itself (tests).
  * The password or key comes from an environment variable or a prompt, and is asked for only at a real terminal.
  * Secrets are never printed or written to the journal.
  * An address an SMC answers with that points to another host is refused, so the session cookie goes nowhere else.
  * There are tests for redirects, a refused login, plain http, and a halfway failure.
* **New in 0.25.0.** The README asks for a least-privilege API account and says never to use `--insecure`.
* **Open.** There is no test with a deliberately invalid certificate against a real TLS server. Today that check
  rests on Python's `ssl` defaults, which verify by default.

### P2: untrusted configuration input and resource exhaustion

> Bound input sizes, archive expansion, nesting depth, collection counts and expensive operations; fail safely rather
> than produce partial policies.

* **Already in place.**
  * XML with a DOCTYPE or entity declaration is refused outright, so there is no entity expansion and no external
    entities.
  * The one archive that is read, a Device Manager zip, is bounded: it holds one text file of at most 128 MiB, and
    encrypted entries are refused.
  * JSON nested too deeply ends in a clean error.
  * Group nesting stops at 64 levels, and groups that contain themselves are found.
  * The audit, the zone matrix and the equivalence check cap the pieces a rule may break into.
  * A malformed input gives an error, not a partial policy.
  * Nothing in FWShift runs a subprocess, `eval`, `exec` or `pickle` on input.
* **New in 0.25.0.** Every input file is read up to a limit: 1 GiB by default, or another size with
  `FWSHIFT_MAX_INPUT_MB`. A larger file is refused before it is parsed.
* **Open.** There is no general limit on the number of rules or objects; a 1 GiB configuration can still take a long
  time. A parser-fuzzing suite with truncated and huge inputs would add assurance.

### P2: release workflow and artifact integrity

> Pin third-party Actions to full commit SHAs, minimise write permissions, validate release refs against tags, add
> provenance and checksums.

* **New in 0.25.0.**
  * `actions/checkout` and `actions/setup-python` are pinned to the commits of the releases v4.4.0 and v5.6.0 (looked
    up with `git ls-remote`).
  * The CI workflow may only read the repository. The release workflow grants nothing by default; only its release
    job may write releases, and only its last step gets the token.
  * The checkout does not keep the token, so the tests, the build and what pip installs for them cannot use it.
  * The release tag must match `vX.Y.Z` exactly and must be the tag that was checked out.
  * Every release carries a `SHA256SUMS` file for its packages.
* **Open.**
  * Signed build provenance (`actions/attest-build-provenance`) and protected tags are repository settings and one
    more Action, which the maintainer can add on GitHub.
  * A manual re-run of a release still replaces its packages (`--clobber`), on purpose, to rebuild an old tag. The
    checksums make such a replacement visible.
  * These workflow changes were written here and not yet run on GitHub: watch the first run.

## The review's test list, and where FWShift stands

| Area | Status |
|---|---|
| Policy equivalence (overlaps, negation, IPv4/IPv6) | covered by the random oracle tests per vendor; `fwshift compare` for real policies |
| NAT (overlaps, port remapping, no-NAT) | covered per vendor, and the order of NAT rules is checked and reported (`NAT_ORDER`) |
| Command generation (hostile names) | covered per emitter |
| Partial failure | covered for the Management Center and Forcepoint loaders; not for the AWS and Barracuda scripts |
| Parser robustness | bounded sizes, refused DOCTYPEs, bounded nesting; no fuzzing suite yet |
| API security | redirects, plain http, failed logins tested; invalid certificates rest on Python's defaults |
| Release integrity | pinned Actions, least permissions, strict tags, checksums; provenance open |

## In short

The review is fair. Its most important sentence matches the project's own rule: a converter must keep the security
decisions of the source, not merely produce valid syntax. The cheap, concrete measures (input limit, workflow
hardening, checksums, the safe-use procedure) are in 0.25.0. The expensive ones need real devices or repository
settings (lab validation, read-back for every target, signed provenance) and stay on the list.
