#!/usr/bin/env python3
# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Load a converted policy into a Cisco Secure Firewall Management Center through its REST API.

This file is what "fwshift convert --to fmc" writes: the program below, and after it the policy
as data (the lines at the end that start with "#: "). It needs Python 3.8 or newer and nothing else.

    python3 THIS_FILE --show                              what it would create, without connecting
    python3 THIS_FILE --host fmc.example.com --user api --dry-run
                                                          log in, check every name, create nothing
    python3 THIS_FILE --host fmc.example.com --user api   create the objects and the policies
    python3 THIS_FILE --host fmc.example.com --user api --undo
                                                          delete what a run created

The password is asked for, or taken from the environment variable FMC_PASSWORD.

What a run does, in this order, stopping at the first thing the Management Center refuses:

1. It lists the objects and policies the Management Center has. If an object it would create
   exists under the same name, if an object it counts on is missing, or if a policy of its name
   exists, it says so and creates nothing. Nothing that exists is ever changed.
2. It creates the security zones the rules name and that are missing (empty: put the interfaces
   of the devices in them), then the network and port objects and the groups.
3. It creates a new access control policy with the rules, and a new NAT policy with the NAT rules.

The policies are assigned to no device: nothing reaches a firewall until someone assigns them and
deploys. What was created is written to a journal file call by call; --undo reads that file and
deletes it all again, the policies first, on the Management Center and in the domain the journal
names. It deletes by id: an object that was changed since goes too, one that something else uses
by then is refused by the Management Center and stays.

A redirect is not followed, and plain http is spoken only to this computer itself: the password
and the token go to the Management Center that was named, and nowhere else.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import http.client
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

FORMAT = 1
MARK = "#: "
BULK_ITEMS = 1000  # objects or rules the Management Center takes in one call
BULK_BYTES = 1_000_000  # and half the size it takes
PAGE = 1000
MAX_PAGES = 5000  # a listing that goes on longer than this is not believed
NETWORKS = {"Host": "object/hosts", "Network": "object/networks", "Range": "object/ranges", "FQDN": "object/fqdns",
            "NetworkGroup": "object/networkgroups"}  # fmt: skip
PORTS = {"ProtocolPortObject": "object/protocolportobjects", "ICMPV4Object": "object/icmpv4objects",
         "ICMPV6Object": "object/icmpv6objects", "PortObjectGroup": "object/portobjectgroups"}  # fmt: skip
ZONES = "object/securityzones"
GROUPS = "object/interfacegroups"  # they share their names with the security zones
NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,48}[A-Za-z0-9._-])?")  # a name for a policy
ACCESS = "policy/accesspolicies"
NAT = "policy/ftdnatpolicies"
Json = Dict[str, Any]


class Stop(Exception):
    """Something the run cannot go on after; the text says what, and what state things are in."""

    def __init__(self, text: str, status: int = 0) -> None:
        super().__init__(text)
        self.status = status  # the HTTP status behind it, if there is one


def read_plan(path: str) -> Json:
    """The policy this file carries: the JSON in the lines that start with the mark."""
    with open(path, encoding="utf-8") as handle:
        lines = [line[len(MARK):] for line in handle if line.startswith(MARK)]
    if not lines:
        raise Stop("this file holds no policy (no lines that start with '#: '): it is the loader alone")
    try:
        plan = json.loads("".join(lines))
    except ValueError as exc:
        raise Stop(f"the policy in this file could not be read ({exc}): the file was changed or cut off") from None
    return check_plan(plan)


def check_plan(plan: Any) -> Json:
    """The policy, if it is what FWShift writes; a file that was edited is not run half way."""
    wrong = "the policy in this file is not in the form this loader reads"
    if not isinstance(plan, dict) or plan.get("format") != FORMAT:
        raise Stop(wrong)

    def dicts(value: Any) -> bool:
        return isinstance(value, list) and all(isinstance(item, dict) for item in value)

    zones = plan.get("zones", [])
    if not isinstance(zones, list) or not all(isinstance(zone, str) and zone for zone in zones):
        raise Stop(f"{wrong} (zones)")
    for key in ("existing", "steps", "rules", "nat"):
        if not dicts(plan.get(key, [])):
            raise Stop(f"{wrong} ({key})")
    for step in plan.get("steps", []):
        kind, path, items = step.get("type"), step.get("path"), step.get("items", [])
        # Objects are created in the collection of their type, and nowhere else.
        if not isinstance(kind, str) or not path or (NETWORKS.get(kind) or PORTS.get(kind)) != path:
            raise Stop(f"{wrong} (a step for '{str(kind)[:40]}' at '{str(path)[:60]}')")
        if not dicts(items) or not all(isinstance(item.get("name"), str) and item["name"] for item in items):
            raise Stop(f"{wrong} (the {step.get('what', 'objects')})")
    if not all(isinstance(rule.get("name"), str) and rule["name"] for rule in plan.get("rules", [])):
        raise Stop(f"{wrong} (a rule without a name)")
    if not all(isinstance(entry.get("type"), str) and isinstance(entry.get("name"), str) for entry in plan.get("existing", [])):
        raise Stop(f"{wrong} (existing)")
    if not isinstance(plan.get("policy", ""), str):
        raise Stop(f"{wrong} (policy)")
    return plan


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is not followed: the password and the token would go with it, wherever it points."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Transport:
    """HTTPS to the Management Center. A test puts something else in its place."""

    def __init__(self, base: str, context: Optional[ssl.SSLContext]) -> None:
        self.base = base
        handlers: List[Any] = [_NoRedirect()] + ([urllib.request.HTTPSHandler(context=context)] if context is not None else [])
        self.opener = urllib.request.build_opener(*handlers)

    def send(self, method: str, path: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, str], bytes]:
        try:
            request = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
            try:
                with self.opener.open(request, timeout=300) as answer:
                    return answer.status, {key.lower(): value for key, value in answer.headers.items()}, answer.read()
            except urllib.error.HTTPError as error:
                return error.code, {key.lower(): value for key, value in error.headers.items()}, error.read()
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as error:
            # No connection, a certificate that is not trusted, an answer that is not HTTP or breaks off.
            raise Stop(f"no usable answer from {self.base}: {getattr(error, 'reason', None) or error or type(error).__name__}") from None


class Api:
    def __init__(self, transport: Any, user: str, password: str, domain: str, say: Any) -> None:
        self.transport, self.user, self.password, self.domain = transport, user, password, domain
        self.say = say
        self.token = ""
        self.root = ""
        self.uuid = ""
        self.host = str(getattr(transport, "base", ""))

    def login(self) -> None:
        basic = base64.b64encode(f"{self.user}:{self.password}".encode("utf-8")).decode("ascii")
        status, headers, body = self.transport.send("POST", "/api/fmc_platform/v1/auth/generatetoken", {"Authorization": f"Basic {basic}"}, b"")
        token = headers.get("x-auth-access-token", "")
        if 300 <= status < 400:
            raise Stop(_redirected(headers), status)
        if status not in (200, 204) or not token:
            raise Stop(f"the Management Center refused the login (HTTP {status}): {_text(body)}", status)
        self.token = token
        uuid = headers.get("domain_uuid", "")
        if self.domain:
            try:
                domains = json.loads(headers.get("domains", "[]"))
            except ValueError:
                domains = []
            found = [str(entry.get("uuid", "")) for entry in domains if isinstance(entry, dict) and entry.get("name") == self.domain]
            if len(found) != 1:
                names = ", ".join(sorted(str(entry.get("name")) for entry in domains if isinstance(entry, dict)))
                raise Stop(f"domain '{self.domain}' is not one this user can use (there are: {names or 'none said'})")
            uuid = found[0]
        if not uuid:
            raise Stop("the Management Center did not say which domain this user works in; name it with --domain")
        self.uuid = uuid
        self.root = f"/api/fmc_config/v1/domain/{urllib.parse.quote(uuid, safe='')}/"

    def call(self, method: str, path: str, body: Any = None) -> Any:
        """One call. Waits when the Management Center says it is asked too often, logs in again when the token ran out."""
        data = None if body is None else json.dumps(body).encode("utf-8")
        renewed = False
        for attempt in range(12):
            headers = {"X-auth-access-token": self.token, "Accept": "application/json"}
            if data is not None:
                headers["Content-Type"] = "application/json"
            status, answered, raw = self.transport.send(method, self.root + path, headers, data)
            if status == 429:
                pause = answered.get("retry-after", "")
                time.sleep(min(float(pause), 120.0) if pause.replace(".", "", 1).isdigit() else 15.0)
                continue
            if status == 401 and not renewed:
                renewed = True
                self.login()
                continue
            if status == 404 and method == "DELETE":
                return None
            if 300 <= status < 400:
                raise Stop(_redirected(answered), status)
            if not 200 <= status < 300:
                raise Stop(f"{method} {path.split('?')[0]} was refused (HTTP {status}): {_text(raw)}", status)
            if not raw.strip():
                return {}
            try:
                return json.loads(raw.decode("utf-8"))
            except ValueError:
                # Carried out, by its status, and what it says cannot be read: not the same as refused.
                raise Stop(f"{method} {path.split('?')[0]}: the answer (HTTP {status}) is not JSON: {_text(raw)}", status) from None
        raise Stop(f"{method} {path.split('?')[0]}: the Management Center kept answering that it is asked too often", 429)

    def items(self, path: str, expanded: bool = False) -> List[Json]:
        """Everything a collection holds, in the order it is listed: names and ids, or with ``expanded`` all of it."""
        out: List[Json] = []
        offset = 0
        extra = "&expanded=true" if expanded else ""
        for _ in range(MAX_PAGES):
            answer = self.call("GET", f"{path}?limit={PAGE}&offset={offset}{extra}")
            items = answer.get("items") if isinstance(answer, dict) else None
            items = items if isinstance(items, list) else []
            out += [item for item in items if isinstance(item, dict)]
            paging = answer.get("paging") if isinstance(answer, dict) else None
            count = paging.get("count") if isinstance(paging, dict) else None
            offset += len(items)  # what it gave, which can be less than what was asked for
            more = offset < count if isinstance(count, int) and not isinstance(count, bool) else len(items) >= PAGE
            if not items or not more:
                return out
        raise Stop(f"GET {path}: the list does not end after {MAX_PAGES} pages")

    def listing(self, path: str) -> Dict[str, str]:
        """Name -> id of everything a collection holds."""
        out: Dict[str, str] = {}
        for item in self.items(path):
            if isinstance(item.get("name"), str) and isinstance(item.get("id"), str):
                out.setdefault(item["name"], item["id"])
        return out


def _redirected(headers: Dict[str, str]) -> str:
    return (f"the Management Center answered with a redirect (to {headers.get('location', 'somewhere')[:120]}). It is not "
            "followed, because the password and the token would be sent along: give --host the name it answers under")  # fmt: skip


def _text(raw: bytes) -> str:
    """What the Management Center said, short enough to read."""
    text = raw.decode("utf-8", errors="replace")
    try:
        answer = json.loads(text)
        messages = answer["error"]["messages"]
        text = "; ".join(str(message.get("description", message)) for message in messages)
    except (ValueError, KeyError, TypeError, AttributeError):
        pass
    return " ".join(text.split())[:600] or "(no text)"


def chunks(items: Sequence[Json]) -> List[List[Json]]:
    """Items in the portions one call takes, in their order."""
    out: List[List[Json]] = [[]]
    used = 0
    for item in items:
        length = len(json.dumps(item)) + 2
        if out[-1] and (len(out[-1]) >= BULK_ITEMS or used + length > BULK_BYTES):
            out.append([])
            used = 0
        out[-1].append(item)
        used += length
    return [portion for portion in out if portion]


def references(value: Any) -> List[Json]:
    """Every reference to another object inside a payload: {"@ref": type, "name": name}."""
    if isinstance(value, list):
        return [found for item in value for found in references(item)]
    if not isinstance(value, dict):
        return []
    if "@ref" in value:
        return [value]
    return [found for inner in value.values() for found in references(inner)]


def resolved(value: Any, ids: Dict[Tuple[str, str], str], spelled: Optional[Dict[Tuple[str, str], str]] = None) -> Any:
    """A payload with every reference as the Management Center wants it: type, name and id.

    ``spelled`` holds the name an object has there, where that is written otherwise than in the policy.
    """
    if isinstance(value, list):
        return [resolved(item, ids, spelled) for item in value]
    if not isinstance(value, dict):
        return value
    if "@ref" in value:
        key = (str(value["@ref"]), str(value.get("name")))
        if key not in ids:
            raise Stop(f"{key[0]} '{key[1]}' is used before it exists: the policy in this file is not in order")
        return {"type": key[0], "name": (spelled or {}).get(key, key[1]), "id": ids[key]}
    return {name: resolved(inner, ids, spelled) for name, inner in value.items()}


def same(held: Json, sent: Json) -> bool:
    """Whether an object the Management Center lists is the object this run sent: by what it says, not by its name alone."""
    for key, value in sent.items():
        if key in ("name", "description"):
            continue
        if key == "objects":
            mine = sorted(str(member.get("name")) for member in value if isinstance(member, dict))
            theirs = sorted(str(member.get("name")) for member in held.get("objects") or [] if isinstance(member, dict))
            if mine != theirs:
                return False
        elif str(held.get(key, "")).lower() != str(value).lower():
            return False
    return True


class Run:
    def __init__(self, plan: Json, api: Any, say: Any, journal: str, name: str = "") -> None:
        self.plan, self.api, self.say, self.journal = plan, api, say, journal
        self.name = name or str(plan.get("policy") or "FWShift")
        self.ids: Dict[Tuple[str, str], str] = {}
        self.made: List[Json] = []
        self.written = 0  # how many of them the journal on disk lists
        self.zones_there: Dict[str, str] = {}  # zone of the policy -> id of the zone that exists for it
        self.spelled: Dict[Tuple[str, str], str] = {}  # (type, name in the policy) -> the name it has on the Management Center
        self.before: Dict[str, List[str]] = {}  # collection -> the names it held before the run, in lower case

    # -- what there is ----------------------------------------------------

    def steps(self) -> List[Json]:
        steps = self.plan.get("steps")
        return [step for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []

    def check(self) -> None:
        """Compare the policy with what the Management Center has. Raises Stop on anything that is in the way."""
        self.say("Reading what the Management Center has ...")
        there: Dict[str, Dict[str, str]] = {}
        for path in list(NETWORKS.values()) + list(PORTS.values()) + [ZONES, ACCESS, NAT]:
            there[path] = self.api.listing(path)
            self.before[path] = [name.lower() for name in there[path]]
        try:
            groups = self.api.listing(GROUPS)
        except Stop as error:
            if error.status != 404:  # a release without them has no names to collide with
                raise
            groups = {}
        families = (("network object", NETWORKS), ("port object", PORTS))
        taken: Dict[str, Dict[str, str]] = {}
        for label, family in families:
            taken[label] = {}
            for path in family.values():
                for name in there[path]:
                    taken[label].setdefault(name.lower(), name)
        clashes: List[str] = []
        for step in self.steps():
            kind = str(step.get("type"))
            label = "network object" if kind in NETWORKS else "port object"
            for item in step.get("items", []):
                held = taken[label].get(str(item.get("name")).lower())
                if held is not None:
                    clashes.append(f"{label} '{held}'")
        if clashes:
            shown = ", ".join(clashes[:20]) + (f" and {len(clashes) - 20} more" if len(clashes) > 20 else "")
            raise Stop(
                f"{len(clashes)} object(s) this policy would create exist already: {shown}. Nothing was created. Convert "
                "again with --target-prefix, which gives every object that is created a name of its own"
            )
        missing: List[str] = []
        for entry in self.plan.get("existing", []):
            kind, name = str(entry.get("type")), str(entry.get("name"))
            path = NETWORKS.get(kind) or PORTS.get(kind) or ""
            if name in there.get(path, {}):
                self.ids[(kind, name)] = there[path][name]
            else:
                missing.append(f"{kind} '{name}'")
        if missing:
            raise Stop("the policy counts on objects the Management Center does not have: " + ", ".join(missing[:20])
                       + ". Nothing was created")  # fmt: skip
        for path, what in ((ACCESS, "access control policy"), (NAT, "NAT policy")):
            needed = path == ACCESS or bool(self.plan.get("nat"))
            if needed and self.name.lower() in {name.lower() for name in there[path]}:
                raise Stop(f"{what} '{self.name}' exists already. Nothing was created. Give the new policies another name with --name")
        # A zone that exists is used, whatever the case it is written in there; a name an interface
        # group has cannot be given to a zone.
        zones = {name.lower(): name for name in there[ZONES]}
        other = {name.lower(): name for name in groups}
        for zone in [str(zone) for zone in self.plan.get("zones", [])]:
            if zone.lower() in zones:
                self.zones_there[zone] = there[ZONES][zones[zone.lower()]]
                if zones[zone.lower()] != zone:
                    self.spelled[("SecurityZone", zone)] = zones[zone.lower()]
                    self.say(f"  security zone '{zone}' exists as '{zones[zone.lower()]}': that one is used")
            elif zone.lower() in other:
                raise Stop(f"'{other[zone.lower()]}' is an interface group, and the policy names a security zone '{zone}': the two "
                           "share their names. Nothing was created. Give the zone another name with --zone-map and convert again")  # fmt: skip

    def summary(self) -> List[str]:
        lines = [f"Access control policy '{self.name}': {len(self.plan.get('rules', []))} rules, default action "
                 f"{self.plan.get('default_action', 'BLOCK')}"]  # fmt: skip
        if self.plan.get("nat"):
            lines.append(f"NAT policy '{self.name}': {len(self.plan['nat'])} rules")
        for step in self.steps():
            lines.append(f"{len(step.get('items', []))} {step.get('what', 'objects')}")
        zones = [str(zone) for zone in self.plan.get("zones", [])]
        if zones:
            lines.append("security zones (used if they exist, created empty if not): " + ", ".join(zones))
        existing = [str(entry.get("name")) for entry in self.plan.get("existing", [])]
        if existing:
            lines.append("objects that must exist already: " + ", ".join(existing))
        return lines

    # -- the journal ------------------------------------------------------

    def save(self) -> None:
        """Put on disk what was created so far. The file is replaced in one step: it is whole, or it is the one before."""
        data = {"format": FORMAT, "host": self.api.host, "domain": self.api.uuid, "created": self.made}
        try:
            with open(self.journal + ".tmp", "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=1)
                handle.write("\n")
            os.replace(self.journal + ".tmp", self.journal)
        except OSError as error:
            raise Stop(f"the journal {self.journal} could not be written ({error})") from None
        self.written = len(self.made)

    def note(self, path: str, ident: str, name: str) -> None:
        self.made.append({"path": path, "id": ident, "name": name})

    def unwritten(self) -> List[str]:
        """What was created and is not in the journal on disk, because the journal could not be written."""
        return [f"{entry['path'].rsplit('/', 1)[-1]} '{entry['name']}'" for entry in self.made[self.written:]]

    # -- creating ---------------------------------------------------------

    def create(self) -> None:
        self.save()  # the journal is there before the first object is
        for zone in [str(zone) for zone in self.plan.get("zones", [])]:
            if zone in self.zones_there:
                self.ids[("SecurityZone", zone)] = self.zones_there[zone]
                continue
            self._one(ZONES, "SecurityZone", zone, {"type": "SecurityZone", "name": zone, "interfaceMode": "ROUTED"})
            self.say(f"  security zone '{zone}' created, without interfaces")
        for step in self.steps():
            kind, path = str(step.get("type")), str(step.get("path"))
            items = [item for item in step.get("items", []) if isinstance(item, dict)]
            for portion in chunks(items):
                self._many(path, kind, portion)
            self.say(f"  {len(items)} {step.get('what', 'objects')} created")
        policy = {"type": "AccessPolicy", "name": self.name, "description": str(self.plan.get("description", ""))[:255],
                  "defaultAction": {"action": str(self.plan.get("default_action", "BLOCK"))}}  # fmt: skip
        ident = self._one(ACCESS, "AccessPolicy", self.name, policy)
        rules = [rule for rule in self.plan.get("rules", []) if isinstance(rule, dict)]
        for portion in chunks(rules):
            # Each call adds its rules below those that are there: the order of the calls is the order of the rules.
            self.api.call("POST", f"{ACCESS}/{ident}/accessrules?bulk=true&section=mandatory", [resolved(rule, self.ids, self.spelled) for rule in portion])
        self._verify(f"{ACCESS}/{ident}/accessrules", [str(rule.get("name")) for rule in rules], "access control policy")
        self.say(f"  access control policy '{self.name}' created with {len(rules)} rules")
        nat = [rule for rule in self.plan.get("nat", []) if isinstance(rule, dict)]
        if nat:
            ident = self._one(NAT, "FTDNatPolicy", self.name, {"type": "FTDNatPolicy", "name": self.name})
            for portion in chunks(nat):
                self.api.call("POST", f"{NAT}/{ident}/manualnatrules?bulk=true&section=before_auto", [resolved(rule, self.ids, self.spelled) for rule in portion])
            self._verify(f"{NAT}/{ident}/manualnatrules", [None] * len(nat), "NAT policy")
            self.say(f"  NAT policy '{self.name}' created with {len(nat)} rules")

    def _post(self, path: str, body: Any) -> Tuple[Any, Optional[Stop]]:
        try:
            return self.api.call("POST", path, body), None
        except Stop as error:
            return None, error

    def _one(self, path: str, kind: str, name: str, body: Json) -> str:
        """Create one thing. What it is on the Management Center afterwards is found out even when the answer does not say."""
        answer, error = self._post(path, body)
        ident = answer.get("id") if isinstance(answer, dict) else None
        if not isinstance(ident, str) or not ident:
            # Refused, or carried out and answered badly. It is this run's if it is there now and was not before.
            ident = self.api.listing(path).get(name, "") if name.lower() not in self.before.get(path, []) else ""
        if ident:
            self.ids[(kind, name)] = ident
            self.note(path, ident, name)
            self.save()
        if error is not None:
            raise error
        if not ident:
            raise Stop(f"{kind} '{name}' was sent and the Management Center does not list it")
        return ident

    def _many(self, path: str, kind: str, sent: List[Json]) -> None:
        """Create a portion of objects, and write down which of them exist afterwards as what was sent."""
        answer, error = self._post(f"{path}?bulk=true", [resolved(item, self.ids, self.spelled) for item in sent])
        items = answer.get("items") if isinstance(answer, dict) else None
        found = {item["name"]: item["id"] for item in items or []
                 if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("id"), str)}  # fmt: skip
        names = [str(item.get("name")) for item in sent]
        others: List[str] = []
        if any(name not in found for name in names):
            # The answer does not account for every object: refused, cut short, or not what was asked for. Ask what is
            # there. An object is taken as created by this run only if it was not there before and says what was sent.
            listed = {str(item.get("name")): item for item in self.api.items(path, expanded=True)}
            for item in sent:
                name = str(item.get("name"))
                held = listed.get(name)
                if name in found or held is None:
                    continue
                if name.lower() not in self.before.get(path, []) and isinstance(held.get("id"), str) and same(held, item):
                    found[name] = held["id"]
                else:
                    others.append(name)
        for name in names:
            if name in found:
                self.ids[(kind, name)] = found[name]
                self.note(path, found[name], name)
        self.save()
        if error is not None:
            raise error
        if others:
            raise Stop(f"{len(others)} {kind} object(s) exist under names of this policy and are not what it sent, so they are "
                       "someone else's and were left alone: " + ", ".join(others[:10]))  # fmt: skip
        lost = [name for name in names if name not in found]
        if lost:
            raise Stop(f"{len(lost)} {kind} object(s) were sent and the Management Center does not list them: " + ", ".join(lost[:10]))

    def _verify(self, path: str, sent: List[Optional[str]], what: str) -> None:
        """The rules as the Management Center has them now: as many as were sent, and in that order."""
        held = self.api.items(path)
        if len(held) != len(sent):
            raise Stop(f"the {what} '{self.name}' holds {len(held)} rules and {len(sent)} were sent: it is not the policy that "
                       "was converted")  # fmt: skip
        names = [item.get("name") for item in held]
        if all(name is not None for name in sent) and names != sent:
            place = next(index for index, (mine, theirs) in enumerate(zip(sent, names)) if mine != theirs)
            raise Stop(f"the {what} '{self.name}' lists its rules in another order than they were sent (rule {place + 1} is "
                       f"'{names[place]}', not '{sent[place]}'): it is not the policy that was converted")  # fmt: skip


def read_journal(journal: str) -> Json:
    try:
        with open(journal, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as error:
        raise Stop(f"the journal {journal} could not be read: {error}") from None
    created = data.get("created") if isinstance(data, dict) else None
    if not isinstance(created, list) or not all(
        isinstance(entry, dict) and all(isinstance(entry.get(key), str) and entry[key] for key in ("path", "id", "name")) for entry in created
    ):
        raise Stop(f"{journal} is not a journal of this loader: nothing was deleted")
    known = list(NETWORKS.values()) + list(PORTS.values()) + [ZONES, ACCESS, NAT]
    if any(entry["path"] not in known for entry in created):
        raise Stop(f"{journal} lists something this loader does not create: nothing was deleted")
    return dict(data)


def undo(api: Any, journal: str, say: Any) -> int:
    data = read_journal(journal)
    created = data["created"]
    host, domain = data.get("host"), data.get("domain")
    if (host and host != api.host) or (domain and domain != api.uuid):
        raise Stop(f"the journal is of a run on {host}, domain {domain}; this is {api.host}, domain {api.uuid}. Nothing was "
                   "deleted")  # fmt: skip
    failed = gone = 0
    for entry in reversed(created):
        path, ident, name = entry["path"], entry["id"], entry["name"]
        what = f"{path.rsplit('/', 1)[-1]} '{name}'"
        try:
            if api.call("DELETE", f"{path}/{urllib.parse.quote(ident, safe='')}") is None:
                gone += 1
                say(f"  was not there any more: {what}")
            else:
                say(f"  deleted {what}")
        except Stop as error:
            failed += 1
            say(f"  NOT deleted: {what}: {error}")
    if failed:
        say(f"{failed} of {len(created)} could not be deleted (in use, or refused): see above. The journal is kept")
        return 1
    try:
        os.replace(journal, journal + ".undone")
    except OSError as error:
        raise Stop(f"everything is deleted, and the journal could not be renamed ({error})") from None
    say(f"Of the {len(created)} the run created, {len(created) - gone} were deleted" + (f" and {gone} were not there any more" if gone else "")
        + f". The journal is now {journal}.undone")  # fmt: skip
    return 0


def base_url(host: str) -> str:
    """https://host, whatever was given; plain HTTP only to this computer itself (a test)."""
    if not host or any(character.isspace() or ord(character) < 33 for character in host):
        raise Stop("--host takes the name or the address of the Management Center, without spaces")
    url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    try:
        parts = urllib.parse.urlsplit(url)
        name, _ = parts.hostname, parts.port  # asking for the port is what finds one that is none
    except ValueError as error:
        raise Stop(f"--host '{host[:80]}' is not a name or an address ({error})") from None
    if not name or parts.path.strip("/") or parts.query or parts.fragment or parts.username is not None:
        raise Stop(f"--host '{host[:80]}': give the name or the address of the Management Center, and nothing after it")
    if parts.scheme == "http" and name not in ("127.0.0.1", "localhost", "::1"):
        raise Stop("this would send the password without encryption: only https is used")
    return f"{parts.scheme}://{parts.netloc}"


def someone_to_ask() -> bool:
    """Whether a person can type the password: standard input is a terminal, and on Windows a console.

    On Windows getpass reads the console whatever standard input is, and NUL is a character device that isatty() calls a
    terminal: only a handle that has a console mode is one somebody types at.
    """
    stream = sys.stdin
    try:
        if stream is None or not stream.isatty():
            return False
        if sys.platform != "win32":
            return True
        import ctypes
        import msvcrt
        from ctypes import wintypes

        mode = wintypes.DWORD()
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno()))
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    except (AttributeError, ImportError, OSError, ValueError):
        return False


def main(argv: Optional[Sequence[str]] = None, transport: Any = None, say: Any = print, plan: Optional[Json] = None) -> int:
    parser = argparse.ArgumentParser(description="Load the converted policy in this file into a Cisco Secure Firewall Management Center.")
    parser.add_argument("--show", action="store_true", help="say what would be created, without connecting")
    parser.add_argument("--plan", action="store_true", help="print the policy this file carries, as JSON")
    parser.add_argument("--host", help="name or address of the Management Center")
    parser.add_argument("--user", help="user for the REST API (not one that is logged in to the web interface)")
    parser.add_argument("--domain", default="", help="domain to work in (default: the domain of the user)")
    parser.add_argument("--name", default="", help="name for the new access control policy and NAT policy")
    parser.add_argument("--cafile", help="certificate of the authority that signed the certificate of the Management Center")
    parser.add_argument("--insecure", action="store_true", help="do not check the certificate of the Management Center")
    parser.add_argument("--dry-run", action="store_true", help="log in and check every name, create nothing")
    parser.add_argument("--undo", action="store_true", help="delete what a run created, as its journal lists it")
    parser.add_argument("--journal", default="", help="file that lists what was created (default: fwshift-fmc-NAME.journal.json)")
    args = parser.parse_args(argv)
    try:
        plan = check_plan(plan) if plan is not None else read_plan(os.path.abspath(__file__))
        if args.plan:
            say(json.dumps(plan, indent=1, sort_keys=True))
            return 0
        name = args.name or str(plan.get("policy") or "FWShift")
        if not NAME.fullmatch(name):
            raise Stop(f"'{name[:60]}' is not a name for a policy: up to 50 letters, digits, spaces, periods, underscores and "
                       "hyphens (--name gives another)")  # fmt: skip
        journal = args.journal or f"fwshift-fmc-{''.join(c if c.isalnum() or c in '._-' else '_' for c in name)}.journal.json"
        if args.show:
            for line in Run(plan, None, say, journal, name).summary():
                say(line)
            return 0
        if not args.host or not args.user:
            raise Stop("--host and --user are needed (or --show, to look without connecting)")
        if transport is None:
            base = base_url(args.host)
            if args.insecure:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                say("WARNING: the certificate of the Management Center is not checked (--insecure)")
            else:
                try:
                    context = ssl.create_default_context(cafile=args.cafile)
                except (OSError, ValueError) as error:  # ssl.SSLError is an OSError
                    raise Stop(f"--cafile {args.cafile}: no certificates could be read from it ({error})") from None
            transport = Transport(base, context)
        password = os.environ.get("FMC_PASSWORD", "")
        if not password:
            # Only a person at a terminal is asked: getpass would otherwise wait for someone who is not there.
            if not someone_to_ask():
                raise Stop("no password: set the environment variable FMC_PASSWORD, or run this from a terminal")
            try:
                password = getpass.getpass(f"Password of {args.user}: ")
            except (EOFError, OSError):
                raise Stop("no password: set the environment variable FMC_PASSWORD, or run this from a terminal") from None
        api = Api(transport, args.user, password, args.domain, say)
        api.login()
        if args.undo:
            return undo(api, journal, say)
        if os.path.exists(journal):
            raise Stop(f"{journal} exists: it lists what an earlier run created. Undo that run (--undo), or name another "
                       "journal with --journal")  # fmt: skip
        run = Run(plan, api, say, journal, name)
        run.check()
        for line in run.summary():
            say(line)
        if args.dry_run:
            say("Every name is free and every object the policy counts on is there. Nothing was created (--dry-run).")
            return 0
        try:
            run.create()
        except Stop as error:
            loose = run.unwritten()
            if loose:
                raise Stop(f"{error}\nStopped. Created and NOT in the journal, which could not be written: {', '.join(loose)}. "
                           f"Delete them by hand; --undo deletes the {run.written} that {journal} lists") from None  # fmt: skip
            if not run.made:
                try:
                    os.remove(journal)  # it lists nothing
                except OSError:
                    pass
                raise Stop(f"{error}\nStopped. Nothing was created.") from None
            raise Stop(f"{error}\nStopped. {len(run.made)} object(s) exist that this run created; they are listed in {journal}: "
                       "delete them again with --undo, correct the cause and run this file again") from None  # fmt: skip
        say(f"Done. What was created is listed in {journal}. The policies are assigned to no device: assign them and "
            "deploy when the report of the conversion has been worked through.")  # fmt: skip
        return 0
    except Stop as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 1  # nobody reads what is said any more (a pager that was closed); what was created is in the journal


if __name__ == "__main__":
    status = main()
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())  # so that the end of the program does not try again
        except (OSError, ValueError, AttributeError):
            pass
        status = 1
    sys.exit(status)
