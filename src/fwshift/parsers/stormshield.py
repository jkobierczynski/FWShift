# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Stormshield SNS parser: the configuration files of a Stormshield Network Security firewall (SNS v4) -> neutral
model.

What is read is the folder ``/usr/Firewall/ConfigFiles`` as a ``.tar`` or ``.tgz``: what ``decbackup`` makes of a
backup (``.na``, which is encrypted and refused with the command that opens it), or the folder copied from the
firewall and packed. How SNS decides traffic, and how that is mapped onto the neutral model:

* The interfaces (``network``) are the zones, by the names rules use (``in``, ``out``, ``dmz1``). A rule names an
  interface with ``on``; without one it applies to any.
* The filter policy is the active slot of ``Filter/NN`` (``Filter/slotinfo``, or ``--policy``), after the global policy
  (``Global/Filter``) where there is one: first match, top to bottom; ``pass``, ``block`` and ``reset`` decide;
  ``decrypt`` and ``log`` do not, and are left out; ``deleg`` leaves the global policy for the local one. What no rule
  matches is blocked. The implicit rules that come before the policy are not converted.
* Filter rules name the addresses as they arrive, before NAT. The NAT rules of a slot are not read (their syntax in
  the file is not published).
* Objects (``object``, ``objectgroup``, ``servicegroup``) are matched by name without regard to case. ``Network_<if>``,
  ``Firewall_<if>``, ``firewall_all``, ``Network_internals`` and ``Internet`` are made from the interfaces;
  ``Network_internals`` knows the networks of the protected interfaces only.

The syntax of a rule line in a slot file is not published: what is read is what Stormshield's own tools and their
test data show (``pass log from A on in to B port https # comment``). Any word not in that grammar makes its rule not
converted.
"""

from __future__ import annotations

import gzip
import io
import re
import tarfile
import zlib
from typing import Dict, List, Optional, Set, Tuple

from .. import transform
from ..errors import ParseError
from ..model import ANY, Action, Address, AddressGroup, AddressKind, Policy, Protocol, Rule, Service, ServiceEntry, ServiceGroup, Zone
from ..netutil import FULL_V4, FULL_V6, Interval, interval_text, parse_literal, subtract
from ..report import Report, Severity

_MAX_UNPACKED = 512 * 1024 * 1024
_MAX_FILE = 64 * 1024 * 1024
_MAX_NESTING = 32
_MAX_MEMBERS = 100_000
# Services SNS predefines, by their well-known ports, for a configuration whose object file does not hold them.
PREDEFINED: Dict[str, List[ServiceEntry]] = {
    "http": [ServiceEntry(Protocol.TCP, "80")], "https": [ServiceEntry(Protocol.TCP, "443")], "ssh": [ServiceEntry(Protocol.TCP, "22")],
    "ftp": [ServiceEntry(Protocol.TCP, "21")], "smtp": [ServiceEntry(Protocol.TCP, "25")], "telnet": [ServiceEntry(Protocol.TCP, "23")],
    "dns_udp": [ServiceEntry(Protocol.UDP, "53")], "dns_tcp": [ServiceEntry(Protocol.TCP, "53")], "pop3": [ServiceEntry(Protocol.TCP, "110")],
    "imap": [ServiceEntry(Protocol.TCP, "143")], "ntp": [ServiceEntry(Protocol.UDP, "123")], "snmp": [ServiceEntry(Protocol.UDP, "161")],
    "ident": [ServiceEntry(Protocol.TCP, "113")], "ldap": [ServiceEntry(Protocol.TCP, "389")], "firewall_srv": [ServiceEntry(Protocol.TCP, "1300")],
    "rdp": [ServiceEntry(Protocol.TCP, "3389")], "syslog": [ServiceEntry(Protocol.UDP, "514")],
}  # fmt: skip
# The protocols SNS predefines (read only), for ipproto.
PROTOCOLS = {"icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47, "vpn-esp": 50, "vpn-ah": 51}
_ACTIONS = {"pass": Action.ALLOW, "block": Action.DROP, "reset": Action.RESET_CLIENT}
_AUTO_COMMENT = re.compile(r"\s*(Created on|Créée le) \d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s*,\s*(by|par) .*$")


def looks_like_backup(data: bytes) -> bool:
    """A ``.na`` backup: a header of ``key=value`` lines before the encrypted part."""
    head = data[:0x400]
    return b"majversion=" in head and (b"algo=" in head or b"iv=" in head) and not _is_tar(data)


def _is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


def gunzip(data: bytes) -> bytes:
    """A gzip file, unpacked; at most 512 MB."""
    out = io.BytesIO()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                if out.tell() > _MAX_UNPACKED:
                    raise ParseError("the archive unpacks to more than 512 MB; refusing to read it")
    except (OSError, EOFError, ValueError, zlib.error) as error:
        raise ParseError(f"the gzip file could not be read: {error}") from None
    return out.getvalue()


def _members(archive: tarfile.TarFile) -> List[tarfile.TarInfo]:
    out: List[tarfile.TarInfo] = []
    for member in archive:
        if len(out) >= _MAX_MEMBERS:
            raise ParseError(f"the archive holds more than {_MAX_MEMBERS} files; not the ConfigFiles of a firewall")
        if member.isfile() or member.islnk():
            out.append(member)
    return out


def _names(data: bytes) -> List[str]:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            return [m.name.replace("\\", "/") for m in _members(archive)]
    except (tarfile.TarError, EOFError, OSError, ValueError):
        return []


def _root(names: List[str]) -> Optional[str]:
    """The folder of the archive that is ConfigFiles (the one that holds Filter/slotinfo, a slot or object), as a
    prefix of the names; None if there is none. More than one is refused."""
    roots: Set[str] = set()
    for name in names:
        clean = name[2:] if name.startswith("./") else name
        found = re.match(r"^(.*?)(Filter/slotinfo|Filter/\d\d|object)$", clean)
        if found and (found.group(1) == "" or found.group(1).endswith("/")) and not found.group(1).endswith("Global/"):
            roots.add(found.group(1))
    outer = {root for root in roots if not any(other != root and root.startswith(other) for other in roots)}
    if len(outer) > 1:
        raise ParseError("the archive holds the ConfigFiles of more than one firewall (" + ", ".join(sorted(r or "." for r in outer))[:200]
                         + "); give FWShift one")  # fmt: skip
    return outer.pop() if outer else None


def looks_like_stormshield(data: bytes) -> bool:
    """A backup (.na), or a tar or tgz of ConfigFiles."""
    if looks_like_backup(data):
        return True
    if data[:2] == b"\x1f\x8b":
        try:
            data = gunzip(data)
        except ParseError:
            return False
    if not _is_tar(data):
        return False
    try:
        names = _names(data)
        if any(name.rsplit("/", 1)[-1] == "Entities.xml" for name in names):
            return False  # (an export of a Sophos Firewall)
        return _root(names) is not None
    except ParseError:
        return True  # (and refused when read)


def read_tree(data: bytes) -> Dict[str, str]:
    """The text files of ConfigFiles, by their path below it."""
    if data[:2] == b"\x1f\x8b":
        data = gunzip(data)
    if not _is_tar(data):
        raise ParseError("not a tar archive of the ConfigFiles of a Stormshield firewall")
    files: Dict[str, str] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            members = _members(archive)
            root = _root([m.name.replace("\\", "/") for m in members])
            if root is None:
                raise ParseError("the archive holds no ConfigFiles (no Filter/slotinfo, filter slot or object file)")
            for member in members:
                name = member.name.replace("\\", "/")
                name = name[2:] if name.startswith("./") else name
                if not name.startswith(root):
                    continue
                if member.size > _MAX_FILE:
                    raise ParseError(f"{name[:80]} in the archive is larger than 64 MB; refusing to read it")
                handle = archive.extractfile(member)
                if handle is not None:
                    raw = handle.read()
                    files[name[len(root):]] = raw.decode("utf-8") if _utf8(raw) else raw.decode("latin-1")
    except (tarfile.TarError, EOFError, OSError, ValueError) as error:
        raise ParseError(f"the archive could not be read: {error}") from None
    return files


def _utf8(raw: bytes) -> bool:
    try:
        raw.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def sections(text: str) -> List[Tuple[str, List[Tuple[int, str]]]]:
    """The ``[Section]`` blocks of a file of ConfigFiles, with their lines (number, text) in order."""
    out: List[Tuple[str, List[Tuple[int, str]]]] = []
    for number, line in enumerate(text.split("\n"), 1):
        stripped = line.strip(" \t\r")
        if not stripped:
            continue
        header = re.match(r"^\[([^\]]*)\]\s*(#.*)?$", stripped)
        if header:
            out.append((header.group(1).strip(), []))
            continue
        if not out:
            out.append(("", []))  # (lines before the first section)
        out[-1][1].append((number, stripped))
    return out


def _uncomment(text: str) -> Tuple[str, str]:
    """(the text before a ``#`` outside double quotes, the comment)."""
    quoted = False
    for index, char in enumerate(text):
        if char == '"':
            quoted = not quoted
        elif char == "#" and not quoted:
            return text[:index].strip(), text[index + 1:].strip()
    return text.strip(), ""


def _words(text: str) -> List[str]:
    """Words separated by blanks outside double quotes; the quotes stay in the word."""
    out: List[str] = []
    current = ""
    quoted = False
    for char in text:
        if char == '"':
            quoted = not quoted
            current += char
        elif char in " \t" and not quoted:
            if current:
                out.append(current)
            current = ""
        else:
            current += char
    if current:
        out.append(current)
    return out


def _keys(lines: List[Tuple[int, str]]) -> Dict[str, str]:
    """``key=value`` lines, keys in lower case, comments taken off."""
    out: Dict[str, str] = {}
    for _, line in lines:
        text, _ = _uncomment(line)
        key, equal, value = text.partition("=")
        if equal:
            out[key.strip().lower()] = value.strip().strip('"')
    return out


def _network(address: str, mask: str) -> Optional[Interval]:
    if not address or not mask:
        return None
    return parse_literal(f"{address}/{mask}")


class _Builder:
    def __init__(self, files: Dict[str, str], report: Report, slot: str) -> None:
        self.files, self.report, self.slot = files, report, slot
        self.p = Policy(vendor="stormshield", default_intrazone=Action.DROP, default_interzone=Action.DROP)
        self.names: Dict[str, str] = {}  # lower-case name -> the name in the model, addresses
        self.service_names: Dict[str, str] = {}
        self.ambiguous: Set[str] = set()
        self.interfaces: Dict[str, str] = {}  # lower-case interface name -> its name
        self.notes: Dict[str, List[str]] = {}
        self.rule_names: Set[str] = set()
        self.tag = ""
        self.protected: List[str] = []
        self.internet: Dict[str, str] = {}
        self.group_memo: Dict[str, List[str]] = {}
        self.internet_base = ""
        self.service_memo: Dict[str, List[str]] = {}
        self.interface_objects: Set[str] = set()
        self.bridges: Set[str] = set()

    def _say(self, code: str, text: str) -> None:
        if text not in self.notes.setdefault(code, []):
            self.notes[code].append(text)

    def build(self) -> Policy:
        if not any(name.startswith("Filter/") for name in self.files) and "object" not in self.files:
            raise ParseError("no filter slot and no object file: not the ConfigFiles of a Stormshield firewall")
        self._interfaces()
        for prefix in ("", "Global/"):
            self._objects(prefix)
        for prefix in ("", "Global/"):
            self._groups(prefix, "objectgroup", False)
            self._groups(prefix, "servicegroup", True)
        self._builtins()
        global_slot = self._active("Global/Filter/", "")
        if global_slot:
            self._slot(f"Global/Filter/{global_slot}", "global")
        local = self._active("Filter/", self.slot)
        if not local:
            raise ParseError("no filter slot to read: Filter/slotinfo names none and no slot file is there; say which with --policy N")
        self._slot(f"Filter/{local}", "local")
        self._notes(local, global_slot)
        return self.p

    # -- interfaces -------------------------------------------------------------------------------

    def _interfaces(self) -> None:
        text = self.files.get("network")
        if text is None:
            self._say("STORMSHIELD_NO_NETWORK", "network")
            return
        found: Dict[str, Dict[str, str]] = {}
        for section, lines in sections(text):
            keys = _keys(lines)
            if "name" in keys:
                found[section] = keys
        for section, keys in found.items():
            name = keys["name"]
            if name.lower() in self.interfaces:
                continue
            self.interfaces[name.lower()] = name
            self.p.zones[name] = Zone(name, interfaces=[section])
            address, mask = keys.get("address", ""), keys.get("mask", "")
            bridge = found.get(keys.get("bridge", ""))
            if not address and bridge is not None:
                address, mask = bridge.get("address", ""), bridge.get("mask", "")
            first = address.split(",")[0].strip()
            net = _network(first, mask.split(",")[0].strip())
            host = parse_literal(first) if first else None
            if bridge is not None or section.lower().startswith("bridge"):
                self.bridges.add(name)
            if net is not None and host is not None and host[1] == host[2]:
                self._builtin_address(f"Network_{name}", interval_text(net))
                self._builtin_address(f"Firewall_{name}", interval_text(host))
                self.interface_objects |= {f"Network_{name}", f"Firewall_{name}"}
                if keys.get("protected") == "1":
                    self.protected.append(f"Network_{name}")

    def _builtin_address(self, name: str, value: str) -> None:
        self.p.addresses[name] = Address(name, AddressKind.NETWORK, value, builtin="stormshield")
        self.names.setdefault(name.lower(), name)

    # -- objects ----------------------------------------------------------------------------------

    def _take(self, name: str, services: bool) -> Optional[str]:
        """A name for an object of the input: None when the other file (local or global) has it already."""
        table = self.service_names if services else self.names
        if name.lower() in table:
            self.ambiguous.add(("s:" if services else "a:") + name.lower())
            return None
        table[name.lower()] = name
        return name

    def _objects(self, prefix: str) -> None:
        text = self.files.get(prefix + "object")
        if text is None:
            return
        for section, lines in sections(text):
            kind = section.lower()
            for number, line in lines:
                body, comment = _uncomment(line)
                key, equal, value = body.partition("=")
                key = key.strip()
                if not equal or not key:
                    continue
                if kind == "internet":
                    self.internet[key.lower()] = value.strip()
                    continue
                if kind in ("host", "network", "range", "fqdn"):
                    if self._take(key, False) is not None:
                        self._address(key, kind, value.strip(), comment)
                elif kind in ("service", "protocol"):
                    if self._take(key, True) is not None:
                        self._service(key, kind, value.strip(), comment)
                elif self._take(key, False) is not None:
                    self.p.addresses[key] = Address(key, AddressKind.UNSUPPORTED, value.strip()[:200], description=comment,
                                                    raw=f"a {section} object, which is not an address")  # fmt: skip

    def _address(self, name: str, kind: str, value: str, comment: str) -> None:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        options = {part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip() for part in parts if "=" in part}
        values = [part for part in parts if "=" not in part]
        unknown = [key for key in options if key not in ("resolve", "mac", "color", "localfirst")]
        if unknown:
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, value[:200], description=comment,
                                             raw=f"option {unknown[0][:20]} is not converted")  # fmt: skip
            return
        if kind == "fqdn" or options.get("resolve") == "dynamic":
            if "." not in name or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, value[:200], description=comment,
                                                 raw="a host the firewall resolves by a name that is not a DNS name")  # fmt: skip
                return
            self.p.addresses[name] = Address(name, AddressKind.FQDN, name, description=comment, raw=",".join(values))
            return
        found: List[Interval] = []
        for item in values:
            interval = parse_literal(item)
            if interval is not None and kind in ("host", "range") and "/" in item and interval[1] != interval[2]:
                interval = None  # (a host is one address or a range)
            if interval is not None and kind == "network" and "/" in item and parse_literal(item.split("/")[0]) not in (None, (interval[0], interval[1], interval[1])):
                interval = None  # (a network written with host bits)
            if interval is None:
                self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, value[:200], description=comment,
                                                 raw=f"address '{item[:60]}' cannot be read")  # fmt: skip
                return
            found.append(interval)
        if not found:
            self.p.addresses[name] = Address(name, AddressKind.UNSUPPORTED, value[:200], description=comment, raw="no address")
            return
        if len(found) == 1:
            interval = found[0]
            text = interval_text(interval)
            self.p.addresses[name] = Address(name, AddressKind.RANGE if "-" in text else AddressKind.NETWORK, text, description=comment)
            return
        self.p.address_groups[name] = AddressGroup(name, [interval_text(i) for i in found], description=comment)

    def _service(self, name: str, kind: str, value: str, comment: str) -> None:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        first = parts[0] if parts else ""
        if kind == "protocol":
            if first.isascii() and first.isdigit() and 0 < int(first) <= 255:
                self.p.services[name] = Service(name, [ServiceEntry(Protocol.IP, ip_protocol=int(first))], description=comment)
            else:
                self.p.services[name] = Service(name, [], description=comment, unsupported=f"protocol '{first[:20]}' cannot be read")
            return
        found = re.fullmatch(r"(\d+)(?:-(\d+))?/(tcp|udp|any)", first.lower())
        if not found or int(found.group(1)) > int(found.group(2) or found.group(1)) or int(found.group(2) or found.group(1)) > 65535:
            self.p.services[name] = Service(name, [], description=comment, unsupported=f"service '{first[:40]}' cannot be read")
            return
        low, high, proto = int(found.group(1)), int(found.group(2) or found.group(1)), found.group(3)
        ports = str(low) if low == high else f"{low}-{high}"
        if ports == "0-65535":
            ports = ""
        kinds = [Protocol.TCP, Protocol.UDP] if proto == "any" else [Protocol(proto)]
        self.p.services[name] = Service(name, [ServiceEntry(k, ports) for k in kinds], description=comment)

    def _groups(self, prefix: str, file: str, services: bool) -> None:
        text = self.files.get(prefix + file)
        if text is None:
            return
        for section, lines in sections(text):
            if self._take(section, services) is None:
                continue
            members = [_uncomment(line)[0] for _, line in lines]
            members = [m for m in members if m]
            if services:
                self.p.service_groups[section] = ServiceGroup(section, members)
            else:
                self.p.address_groups[section] = AddressGroup(section, members)

    def _builtins(self) -> None:
        firewall = [name for name in self.p.addresses if name.startswith("Firewall_") and self.p.addresses[name].builtin]
        if "firewall_all" not in self.names:
            self.p.address_groups["firewall_all"] = AddressGroup("firewall_all", firewall, builtin="stormshield")
            self.names["firewall_all"] = "firewall_all"
        if "network_internals" not in self.names:
            self.p.address_groups["Network_internals"] = AddressGroup("Network_internals", list(self.protected), builtin="stormshield")
            self.names["network_internals"] = "Network_internals"
        for name, group in self.p.address_groups.items():
            if group.builtin:
                continue
            resolved: List[str] = []
            for member in group.members:
                canonical = self.names.get(member.lower())
                if canonical is None and parse_literal(member) is None:
                    group.unsupported = f"member {member[:40]} is not in the configuration"
                resolved.append(canonical or member)
            group.members = resolved
        for name, service_group in self.p.service_groups.items():
            resolved = []
            for member in service_group.members:
                canonical = self._service_name(member)
                if canonical is None:
                    self.p.services.setdefault(f"(missing) {member}", Service(f"(missing) {member}", [], unsupported=f"service {member[:40]} is not in the configuration"))
                    canonical = f"(missing) {member}"
                resolved.append(canonical)
            service_group.members = resolved
        if "internet" not in self.names:
            operator, base = self.internet.get("operator", "ne"), self.internet.get("object", "Network_internals")
            canonical = self.names.get(base.lower())
            problems = self._group_problems(canonical, 0) if canonical is not None else []
            intervals, complete = transform.known_intervals(self.p, canonical) if canonical is not None else ([], False)
            if operator == "ne" and canonical is not None and complete and not problems and "network" in self.files:
                left = subtract([FULL_V4], [i for i in intervals if i[0] == 4]) + subtract([FULL_V6], [i for i in intervals if i[0] == 6])
                self.p.address_groups["Internet"] = AddressGroup("Internet", [interval_text(i) for i in left], builtin="stormshield")
                self.internet_base = canonical
            else:
                why = f"Internet defined as {operator} {base[:40]}" if operator != "ne" or canonical is None else \
                    "Internet is everything but an object that cannot be read" if "network" in self.files else "no network file"
                self.p.address_groups["Internet"] = AddressGroup("Internet", [], builtin="stormshield", unsupported=why)
            self.names["internet"] = "Internet"

    def _service_name(self, name: str) -> Optional[str]:
        canonical = self.service_names.get(name.lower())
        if canonical is not None:
            return canonical
        if name.lower() in PREDEFINED:
            self.p.services[name.lower()] = Service(name.lower(), list(PREDEFINED[name.lower()]), builtin="stormshield")
            self.service_names[name.lower()] = name.lower()
            self._say("STORMSHIELD_PREDEFINED", name.lower())
            return name.lower()
        return None

    # -- slots -----------------------------------------------------------------------------------

    def _active(self, folder: str, wanted: str) -> str:
        """The two digits of the slot to read in a folder of slots: the one asked for, or the active one."""
        slots = sorted(name[len(folder):] for name in self.files if re.fullmatch(re.escape(folder) + r"\d\d", name))
        info = self.files.get(folder + "slotinfo")
        names: Dict[str, str] = {}
        active = ""
        if info is not None:
            for section, lines in sections(info):
                keys = _keys(lines)
                if section.lower() == "global":
                    active = keys.get("active", "")
                if keys.get("progtime") or keys.get("progdays"):
                    self._say("STORMSHIELD_SCHEDULED", f"{folder}slotinfo [{section}]")
                elif section.isdigit() and "name" in keys:
                    names[f"{int(section):02d}"] = keys["name"]
        if wanted:
            if wanted.isdigit():
                slot = f"{int(wanted):02d}"
            else:
                matches = [number for number, name in names.items() if name.lower() == wanted.lower()]
                if len(matches) != 1:
                    raise ParseError(f"no filter slot is called '{wanted[:40]}'; the slots are: "
                                     + ", ".join(f"{n} ({names.get(n, '')})" for n in slots))  # fmt: skip
                slot = matches[0]
            if slot not in slots:
                raise ParseError(f"there is no filter slot {slot}; the slots are: {', '.join(slots) or 'none'}")
            return slot
        if active.isdigit() and f"{int(active):02d}" in slots:
            return f"{int(active):02d}"
        if active.isdigit() and int(active) > 0:
            raise ParseError(f"slotinfo of {folder.rstrip('/')} names slot {active}, which is not there")
        if folder.startswith("Global/"):
            for number in slots:
                if any(line and not line.startswith(("#", "separator", "[")) for line in
                       (raw.strip() for raw in self.files[folder + number].split("\n"))):
                    raise ParseError(f"global filter slot {number} holds rules and {folder}slotinfo names no active slot; the global "
                                     "policy comes before the local one and cannot be left out")  # fmt: skip
            return ""
        if len(slots) == 1:
            return slots[0]
        if slots:
            raise ParseError("several filter slots and no slotinfo that names the active one; say which with --policy N: " + ", ".join(slots))
        return ""

    def _slot(self, path: str, where: str) -> None:
        current = ""
        self.tag = ""
        delegated = False
        index = 0
        nat_lines = 0
        for section, lines in sections(self.files[path]):
            current = section.lower()
            for number, line in lines:
                if current == "nat":
                    if not line.startswith("#") and not line.startswith("separator"):
                        nat_lines += 1
                    continue
                if current == "":
                    raise ParseError(f"{path}, line {number}: a line before the [Filter] section")
                if current != "filter":
                    self._say("STORMSHIELD_SECTION", f"[{section}] in {path}")
                    continue
                if line.startswith("#"):
                    continue
                body, comment = _uncomment(line)
                words = _words(body)
                if not words:
                    continue
                if words[0] == "separator":
                    found = re.search(r'comment="([^"]*)"', body)
                    self.tag = found.group(1) if found else ""
                    continue
                index += 1
                if delegated:
                    raise ParseError(f"{path}, line {number}: a rule after a deleg rule of the global policy that does not match "
                                     "everything; such a policy cannot be read as one list of rules")  # fmt: skip
                result = self._rule(words, comment, where, index, number, path)
                if result == "deleg":
                    delegated = True
        if delegated:
            self._say("STORMSHIELD_DELEG", path)
        if nat_lines:
            self._say("STORMSHIELD_NAT_NOT_READ", f"{nat_lines} lines in {path}")

    def _rule(self, words: List[str], comment: str, where: str, index: int, number: int, path: str) -> str:
        problems: List[str] = []
        action_word = words[0].lower()
        name = transform.dedupe([f"{where} {index}"])[0]
        rule = Rule(name, action=_ACTIONS.get(action_word, Action.DROP))
        rule.origin = name
        rule.log_end = True
        rule.description = _AUTO_COMMENT.sub("", comment).strip()
        rule.source_ids = {"stormshield.slot": path, "stormshield.rule": str(index), "stormshield.line": str(number)}
        if self.tag:
            rule.tags.append(self.tag)
        if action_word in ("decrypt", "log"):
            self.report.skip("rule", name, "STORMSHIELD_NON_TERMINAL", f"action {action_word}: the firewall goes on to the next rule; "
                             "nothing is decided here", Severity.INFO)  # fmt: skip
            return action_word
        if action_word == "deleg":
            if where != "global":
                problems.append("deleg outside the global policy")
                action_word = "deleg in the local policy"
            elif words[1:] == ["from", "any", "to", "any"]:
                self.report.skip("rule", name, "STORMSHIELD_DELEG", "deleg of everything: the rest goes to the local policy", Severity.INFO)
                return "deleg"
            else:
                raise ParseError(f"{path}, line {number}: a deleg rule that does not match everything; the global and the local "
                                 "policy cannot be read as one list of rules")  # fmt: skip
        if action_word not in _ACTIONS and action_word != "deleg":
            problems.append(f"action '{action_word[:20]}' is not converted")
        index_word = 1
        ipproto = ""
        seen_options: Set[str] = set()
        while index_word < len(words) and words[index_word] != "from":
            word = words[index_word]
            following = words[index_word + 1] if index_word + 1 < len(words) else ""
            if word in seen_options:
                problems.append(f"'{word[:30]}' twice")
            seen_options.add(word)
            if word == "log":
                rule.log_start = True
                index_word += 1
            elif word == "inspection" and following in ("firewall", "ids", "ips"):
                rule.profiles["inspection"] = following
                index_word += 2
            elif word == "ipproto" and following:
                ipproto = following
                index_word += 2
            elif word == "proto" and following:
                if following not in ("none", "auto"):
                    rule.profiles["application protocol"] = following
                    self._say("STORMSHIELD_PROTOCOL_ANALYSIS", name)
                index_word += 2
            elif word == "tos" and following.isdigit():
                problems.append(f"a match of the type of service (tos {following[:5]})")
                index_word += 2
            elif word in ("settos", "route") and following:
                rule.handling[word] = following
                self.report.add("rule", name, Severity.REVIEW, "STORMSHIELD_HANDLING",
                                ("sets the type of service" if word == "settos" else "routes what it passes by its own gateway (policy routing)")
                                + f" ({word} {following[:40]}): not converted")  # fmt: skip
                index_word += 2
            else:
                problems.append(f"'{word[:30]}' is not converted")
                index_word += 1
        rest = words[index_word:]
        source, rest = self._side(rest, "from", problems)
        source_if, rest = self._on(rest, problems)
        destination, rest = self._side(rest, "to", problems)
        destination_if, rest = self._on(rest, problems)
        services: List[str] = []
        if rest[:1] == ["port"] and len(rest) >= 2:
            services = rest[1].split(",")
            if any(not part for part in services):
                problems.append(f"an empty name in 'port {rest[1][:40]}'")
            services = [part for part in services if part]
            rest = rest[2:]
        if rest:
            problems.append(f"'{' '.join(rest)[:60]}' is not converted")
        rule.src_zones = [source_if] if source_if else [ANY]
        rule.dst_zones = [destination_if] if destination_if else [ANY]
        users, members, negated = source
        rule.sources, rule.negate_source = self._members(members, negated, problems)
        if users:
            rule.users = users
        users, members, negated = destination
        if users:
            problems.append("a user on the destination")
        rule.destinations, rule.negate_destination = self._members(members, negated, problems)
        rule.services = self._services(services, ipproto, problems)
        if source_if in self.bridges or destination_if in self.bridges:
            self.report.add("rule", name, Severity.REVIEW, "STORMSHIELD_BRIDGE",
                            "names a bridge or a port of one: read as that interface only; whether the firewall matches the bridge "
                            "for its ports, or the reverse, is not documented")  # fmt: skip
        if any(m in self.interface_objects or m == "firewall_all" for m in rule.sources + rule.destinations):
            self.report.add("rule", name, Severity.REVIEW, "STORMSHIELD_INTERFACE_OBJECTS",
                            "Network_* and Firewall_* objects are read from the first IPv4 address of their interface")  # fmt: skip
        if any(m in ("Network_internals", "Internet") for m in rule.sources + rule.destinations):
            self._say("STORMSHIELD_INTERNALS", name)
            self.report.add("rule", name, Severity.REVIEW, "STORMSHIELD_INTERNALS",
                            "Network_internals and Internet are read as the networks of the protected interfaces (their first IPv4 "
                            "address) and everything else; networks reached through them by routes, and their IPv6 networks, are "
                            "not known")  # fmt: skip
        rule.unsupported = list(dict.fromkeys(problems))
        self.p.rules.append(rule)
        return action_word

    def _side(self, words: List[str], keyword: str, problems: List[str]) -> Tuple[Tuple[List[str], List[str], bool], List[str]]:
        """(users, members, negated) after ``from`` or ``to``, and the words that are left."""
        if not words or words[0] != keyword:
            problems.append(f"no '{keyword}'")
            return ([], [], False), words[1:] if words else []
        rest = words[1:]
        negated = False
        if rest[:1] == ["!"]:
            negated, rest = True, rest[1:]
        if not rest:
            problems.append(f"nothing after '{keyword}'")
            return ([], [], negated), []
        value, rest = rest[0], rest[1:]
        if value.startswith("!"):
            if negated or value.startswith("!!"):
                problems.append("a negation of a negation")
            negated, value = True, value[1:]
        users: List[str] = []
        user = re.fullmatch(r'(user|group)="([^"]*)"@(.+)', value)
        if user:
            domain = ""
            if rest[:1] == ["domain"] and len(rest) >= 2:
                domain, rest = rest[1], rest[2:]
            users = [f"{user.group(2)}@{domain}" if domain else user.group(2)]
            value = user.group(3)
            if negated:
                problems.append("a negated source with a user")
        elif "@" in value or '"' in value:
            problems.append(f"'{value[:40]}' is not converted")
        parts = value.split(",")
        if any(not part for part in parts):
            problems.append(f"an empty name in '{value[:40]}'")
        return (users, [part for part in parts if part], negated), rest

    def _on(self, words: List[str], problems: List[str]) -> Tuple[str, List[str]]:
        if words[:1] != ["on"]:
            return "", words
        if len(words) < 2:
            problems.append("'on' without an interface")
            return "", []
        name = words[1]
        if name.lower() == "any":
            return "", words[2:]
        canonical = self.interfaces.get(name.lower())
        if canonical is None:
            problems.append(f"interface {name[:40]} is not in the network configuration")
            self.p.zones.setdefault(name, Zone(name))
            return name, words[2:]
        return canonical, words[2:]

    def _members(self, members: List[str], negated: bool, problems: List[str]) -> Tuple[List[str], bool]:
        out: List[str] = []
        for member in members:
            if member.lower() == "any":
                out.append(ANY)
                continue
            if "a:" + member.lower() in self.ambiguous:
                problems.append(f"object {member[:40]} is both a local and a global object")
            canonical = self.names.get(member.lower())
            if canonical is None:
                problems.append(f"object {member[:40]} is not in the configuration")
                out.append(member)
                continue
            found = self.p.addresses.get(canonical)
            if found is not None and found.kind == AddressKind.UNSUPPORTED:
                problems.append(f"object {canonical[:40]}: {found.raw[:80]}")
            group = self.p.address_groups.get(canonical)
            if group is not None:
                problems += [f"group {canonical[:40]}: {why}" for why in self._group_problems(canonical, 0)]
            out.append(canonical)
        if ANY in out:
            if negated:
                problems.append("every address but every address: the rule matches no packet")
            return [ANY], False
        if not negated and out == ["Internet"] and self.internet_base == "Network_internals" and self.p.address_groups["Internet"].builtin \
                and not self.p.address_groups["Internet"].unsupported:
            return ["Network_internals"], True  # (exactly what Internet is defined as)
        return transform.dedupe(out) or [ANY], negated

    def _group_problems(self, name: str, depth: int, seen: Optional[Set[str]] = None) -> List[str]:
        """Why a group (or an address) cannot be read: each group looked at once, a group in itself said."""
        if name in self.group_memo:
            return self.group_memo[name]
        seen = seen if seen is not None else set()
        group = self.p.address_groups.get(name)
        if group is None:
            found = self.p.addresses.get(name)
            return [found.raw[:80]] if found is not None and found.kind == AddressKind.UNSUPPORTED else []
        if name in seen or depth > _MAX_NESTING:
            return [f"group {name[:40]} holds itself, or is nested too deep"]
        out = [group.unsupported] if group.unsupported else []
        for member in dict.fromkeys(group.members):
            out += self._group_problems(member, depth + 1, seen | {name})
        out = list(dict.fromkeys(out))
        if depth == 0 or not out:
            self.group_memo[name] = out
        return out

    def _service_problems(self, name: str, depth: int, seen: Optional[Set[str]] = None) -> List[str]:
        if name in self.service_memo:
            return self.service_memo[name]
        seen = seen if seen is not None else set()
        service = self.p.services.get(name)
        if service is not None:
            return [service.unsupported] if service.unsupported else []
        group = self.p.service_groups.get(name)
        if group is None or name in seen or depth > _MAX_NESTING:
            return [f"service {name[:40]} is not in the configuration, holds itself or is nested too deep"]
        out = list(dict.fromkeys(why for member in dict.fromkeys(group.members) for why in self._service_problems(member, depth + 1, seen | {name})))
        if depth == 0 or not out:
            self.service_memo[name] = out
        return out

    def _services(self, names: List[str], ipproto: str, problems: List[str]) -> List[str]:
        number: Optional[int] = None
        if ipproto and ipproto != "any":
            canonical = self.service_names.get(ipproto.lower())
            if ipproto.lower() in PROTOCOLS:
                number = PROTOCOLS[ipproto.lower()]
            elif canonical is not None and self.p.services[canonical].entries and self.p.services[canonical].entries[0].protocol == Protocol.IP:
                number = self.p.services[canonical].entries[0].ip_protocol
            else:
                problems.append(f"ipproto {ipproto[:30]} cannot be read")
                return [ANY]
        resolved: List[str] = []
        for name in names:
            if "s:" + name.lower() in self.ambiguous:
                problems.append(f"service {name[:40]} is both a local and a global object")
            canonical = self._service_name(name)
            if canonical is None:
                problems.append(f"service {name[:40]} is not in the configuration")
                continue
            problems += [f"service {canonical[:40]}: {why}" for why in self._service_problems(canonical, 0)]
            resolved.append(canonical)
        if number is None:
            return transform.dedupe(resolved) or [ANY]
        kind = {6: Protocol.TCP, 17: Protocol.UDP, 1: Protocol.ICMP}.get(number)
        if not resolved:
            entry = ServiceEntry(kind) if kind is not None else ServiceEntry(Protocol.IP, ip_protocol=number)
            return [self._inline([entry], f"ipproto-{ipproto.lower()}")]
        if kind not in (Protocol.TCP, Protocol.UDP):
            problems.append(f"ports with ipproto {ipproto[:20]}")
            return resolved
        entries: List[ServiceEntry] = []
        for name in resolved:
            flat = transform.flatten_services(self.p, name)
            if flat is None:
                problems.append(f"service {name[:40]} cannot be read")
                return resolved
            entries += [e for e in flat if e.protocol == kind or (e.protocol == Protocol.IP and e.ip_protocol in (None, number))]
        if not entries:
            problems.append(f"no service of the rule is {ipproto}: the rule matches no packet")
            return resolved
        entries = [ServiceEntry(kind, e.dst_ports, e.src_ports) if e.protocol == Protocol.IP else e for e in entries]
        return [self._inline(entries, f"{'-'.join(resolved)[:40]}-{ipproto.lower()}")]

    def _inline(self, entries: List[ServiceEntry], label: str) -> str:
        for name, service in self.p.services.items():
            if service.entries == entries and name.startswith("(rule) "):
                return name
        name = f"(rule) {label}"
        counter = 2
        while name in self.p.services:
            name = f"(rule) {label}-{counter}"
            counter += 1
        self.p.services[name] = Service(name, entries)
        return name

    # -- the report --------------------------------------------------------------------------------

    def _notes(self, local: str, global_slot: str) -> None:
        self.report.note(Severity.INFO, "STORMSHIELD_SOURCE",
                         f"{len(self.p.zones)} interfaces as zones ({', '.join(list(self.p.zones)[:8])}{' ...' if len(self.p.zones) > 8 else ''}); "
                         f"filter slot {local}" + (f" after global slot {global_slot}" if global_slot else "")
                         + f": {len(self.p.rules)} rules, first match; what no rule matches is blocked")  # fmt: skip
        self.report.note(Severity.REVIEW, "STORMSHIELD_IMPLICIT",
                         "the implicit rules (administration, DNS, IPsec, SSL VPN and the other services the firewall answers itself) "
                         "come before the policy and are not converted")  # fmt: skip
        texts = {
            "STORMSHIELD_PREDEFINED": (Severity.REVIEW, "predefined services not in the object file, read by their well-known ports"),
            "STORMSHIELD_INTERNALS": (Severity.REVIEW, "rules with Network_internals or Internet, read as the networks of the protected "
                                      "interfaces and everything else: networks behind them by routes are not known"),
            "STORMSHIELD_PROTOCOL_ANALYSIS": (Severity.REVIEW, "rules that force the analysis of an application protocol: read as not "
                                              "narrowing what the rule matches"),
            "STORMSHIELD_NAT_NOT_READ": (Severity.REVIEW, "NAT rules of the slot are not read (the filter rules name the addresses as they "
                                         "arrive, so they do not depend on them)"),
            "STORMSHIELD_DELEG": (Severity.INFO, "global policies that end in a deleg of everything: the rest goes to the local policy"),
            "STORMSHIELD_SECTION": (Severity.REVIEW, "sections of a slot file that are not read"),
            "STORMSHIELD_NO_NETWORK": (Severity.REVIEW, "no network file: the interfaces, Network_* and Firewall_* objects are not known"),
            "STORMSHIELD_SCHEDULED": (Severity.REVIEW, "slots activated on a schedule: the slot read is the one named active"),
        }
        for code, items in self.notes.items():
            severity, text = texts[code]
            self.report.note(severity, code, f"{text}: {', '.join(items[:12])}" + (" ..." if len(items) > 12 else ""))


def parse(data: bytes, report: Report, slot: str = "") -> Policy:
    if looks_like_backup(data):
        raise ParseError("a backup of a Stormshield firewall (.na), which is encrypted: open it with decbackup (on the firewall, "
                         "or from MyStormshield): 'decbackup -i backup.na -o backup.tgz [-p PASSWORD]', and give FWShift backup.tgz")  # fmt: skip
    files = read_tree(data)
    try:
        return _Builder(files, report, slot).build()
    except ParseError:
        raise
    except (RecursionError, IndexError, KeyError, ValueError, TypeError, AttributeError, AssertionError) as error:
        raise ParseError(f"the configuration could not be read ({type(error).__name__}: {str(error)[:120]})") from None
