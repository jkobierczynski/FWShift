# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Ground truth for nftables: forward real packets through the kernel and compare with the model.

The same laboratory as ``kernel_check.py`` (three veth pairs, packets injected on one and watched for on another),
with the ruleset loaded by ``nft -f``. Two things are checked, with the generators of ``tests/test_iptables.py``
and ``tests/test_nftables.py``:

* emitter: a random model is written for nftables; the kernel must forward exactly the IPv4 packets the model
  allows;
* parser: a random ruleset (several base chains, sets, verdict maps, jump, goto, return; and one of chains three deep)
  is loaded; the kernel must forward exactly the packets that the model read from it allows.

Run it as root on Linux, in a network namespace of its own so that nothing of the host is touched (needs nft and
the ``pyroute2`` package)::

    unshare -n python3 tests/tools/nft_kernel_check.py [number of rulesets, default 10]

It is not part of the test suite: it needs root and a kernel with nftables.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
from pathlib import Path
from typing import List, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests"), str(ROOT / "tests" / "tools")]

from kernel_check import Lab, compare  # noqa: E402
from test_iptables import random_model  # noqa: E402
from test_nftables import deep_ruleset, random_ruleset  # noqa: E402

from fwshift import cli  # noqa: E402
from fwshift.parsers import nftables as parse_nftables  # noqa: E402
from fwshift.report import Report  # noqa: E402


class NftLab(Lab):
    def load(self, ruleset: str) -> None:
        text = ruleset if ruleset.startswith("flush ruleset") else "flush ruleset\n" + ruleset
        done = subprocess.run(["nft", "-f", "-"], input=text.encode(), capture_output=True)
        if done.returncode:
            raise SystemExit(f"nft refused the ruleset:\n{done.stderr.decode()}\n{text}")


def main(argv: List[str]) -> int:
    if os.geteuid() != 0:
        raise SystemExit("needs root; run it as: unshare -n python3 tests/tools/nft_kernel_check.py")
    count = int(argv[1]) if len(argv) > 1 else 10
    lab = NftLab()
    total = forwarded = rulesets = 0
    replied: Set[Tuple[str, str, str]] = set()
    for seed in range(count):
        rng = random.Random(seed)
        model = random_model(rng)
        emitted = cli.convert(model, "nftables", Report())
        checked, passed = compare(lab, model, emitted, rng, 200, f"emitter, seed {seed}", replied)
        total, forwarded, rulesets = total + checked, forwarded + passed, rulesets + 1
        for make in (random_ruleset, deep_ruleset):
            text = make(rng)
            parsed = parse_nftables.parse(text.encode(), Report())
            if not any(rule.unsupported for rule in parsed.rules):
                checked, passed = compare(lab, parsed, text, rng, 200, f"parser ({make.__name__}), seed {seed}", replied)
                total, forwarded, rulesets = total + checked, forwarded + passed, rulesets + 1
    print(
        f"{rulesets} rulesets, {total} packets ({forwarded} forwarded, {total - forwarded} dropped): "
        "the kernel and the model agree on every one"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
