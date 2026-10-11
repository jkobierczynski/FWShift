# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reading XML that comes from somewhere else: no document type, no entities of its own."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

from .errors import ParseError


class _DocumentType(Exception):
    pass


class _Builder(ET.TreeBuilder):
    def doctype(self, name: Optional[str], pubid: Optional[str], system: Optional[str]) -> None:
        raise _DocumentType()  # whatever the encoding of the file: this is what the parser itself saw


def fromstring(data: bytes, never: str) -> ET.Element:
    """The root element of an XML document; ``never`` names what never holds a DOCTYPE, for the error message.

    A configuration export declares no document type. One that does can define entities that expand
    to gigabytes, or that name files: it is refused before anything of it is read.
    """
    refused = f"the XML contains a DOCTYPE or entity declaration; {never} never do, refusing to read it"
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ParseError(refused)
    parser = ET.XMLParser(target=_Builder())
    try:
        parser.feed(data)
        root = parser.close()
    except _DocumentType:
        raise ParseError(refused) from None
    except (ET.ParseError, LookupError, ValueError) as exc:  # bad syntax, unknown or broken encoding
        raise ParseError(f"not well-formed XML: {exc}") from None
    if not isinstance(root, ET.Element):
        raise ParseError("not well-formed XML: no element found")
    return root
