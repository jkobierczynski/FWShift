# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Allow ``python -m fwshift``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
