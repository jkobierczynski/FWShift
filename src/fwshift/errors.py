# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Exceptions raised by fwshift."""

from __future__ import annotations


class FwshiftError(Exception):
    """Base class: a problem the user can act on."""


class ParseError(FwshiftError):
    """The input configuration could not be read."""
