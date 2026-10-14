#!/usr/bin/env python3
# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Load a converted policy into a Forcepoint Security Management Center (SMC) through its REST API.

This file is what "fwshift convert --to forcepoint" writes: the program below, and after it the policy
as data (the lines at the end that start with "#: "). It needs Python 3.8 or newer and nothing else.

    python3 THIS_FILE --show                              what it would create, without connecting
    python3 THIS_FILE --host smc.example.com --dry-run    log in, check every name, create nothing
    python3 THIS_FILE --host smc.example.com              create the elements and the policy
    python3 THIS_FILE --host smc.example.com --undo       delete what a run created

The API client key is asked for, or taken from the environment variable SMC_API_KEY. The SMC answers
on port 8082 unless --host names another.

What a run does, in this order, stopping at the first thing the SMC refuses:

1. It logs in, and looks up every element it would create. An element of the same type and name that
   says the same (a predefined service, say) is used as it is; one that says something else stops
   the run before anything is created. So does a missing template, an element the policy counts on
   that is missing, or a firewall policy of the same name. Nothing that exists is ever changed.
2. It creates the zones the rules name and the SMC does not have (without interfaces: set them on the
   interfaces of the engines), then the other elements.
3. It creates a new firewall policy on the template, and adds the rules one after the other, each
   after the one before, at the insert point of the template; then the NAT rules. It reads the rule
   lists back and compares them with what it sent.

The policy is installed on no engine: nothing reaches a firewall until someone installs it. What was
created is written to a journal file call by call; --undo reads that file and deletes it all again,
the policy first. A redirect is not followed, and plain http is spoken only to this computer itself.
"""

from __future__ import annotations

import argparse
import getpass
import http.client
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

FORMAT = 1
MARK = "#: "
KNOWN_VERSIONS = ("6.10", "6.11", "7.0", "7.1", "7.2", "7.3", "7.4")  # the API versions this program was written for
ELEMENTS = ("host", "network", "address_range", "domain_name", "group", "expression", "match_expression", "tcp_service",
            "udp_service", "icmp_service", "icmp_ipv6_service", "ip_service", "service_group")  # fmt: skip
EXISTING = ELEMENTS + ("application_situation", "default_nat_address_alias", "interface_nic_x_ip_alias", "interface_zone")
RULE_LISTS = ("fw_ipv4_access_rule", "fw_ipv6_access_rule")
NAT_LISTS = ("fw_ipv4_nat_rule", "fw_ipv6_nat_rule")
ZONE = "interface_zone"
POLICY = "fw_policy"
TEMPLATE = "fw_template_policy"
Json = Dict[str, Any]


class Stop(Exception):
    """Something the run cannot go on after; the text says what, and what state things are in."""

    def __init__(self, text: str, status: int = 0) -> None:
        super().__init__(text)
        self.status = status


def read_plan(path: str) -> Json:
    with open(path, encoding="utf-8") as handle:
        lines = [line[len(MARK):] for line in handle if line.startswith(MARK)]
    if not lines:
        raise Stop("this file holds no policy (no lines that start with '#: '): it is the loader alone")
    try:
        plan = json.loads("".join(lines))
    except ValueError as exc:
        raise Stop(f"the policy in this file could not be read ({exc}): the file was changed or cut off") from None
    return check_plan(plan)


def references(value: Any) -> List[Json]:
    """Every reference to an element inside a payload: {"@ref": type, "name": name}."""
    if isinstance(value, list):
        return [found for item in value for found in references(item)]
    if not isinstance(value, dict):
        return []
    if "@ref" in value:
        return [value]
    return [found for inner in value.values() for found in references(inner)]


def check_plan(plan: Any) -> Json:
    """The policy, if it is what FWShift writes; a file that was edited is not run half way."""
    wrong = "the policy in this file is not in the form this loader reads"
    if not isinstance(plan, dict) or plan.get("format") != FORMAT:
        raise Stop(wrong)
    for key in ("policy", "template"):
        if not isinstance(plan.get(key), str) or not plan[key]:
            raise Stop(f"{wrong} ({key})")
    zones = plan.get("zones", [])
    if not isinstance(zones, list) or not all(isinstance(zone, str) and zone for zone in zones):
        raise Stop(f"{wrong} (zones)")
    for key, kinds in (("elements", ELEMENTS), ("existing", EXISTING)):
        items = plan.get(key, [])
        if not isinstance(items, list) or not all(isinstance(item, dict) and item.get("type") in kinds for item in items):
            raise Stop(f"{wrong} ({key})")
    for item in plan.get("elements", []):
        body = item.get("body")
        if not isinstance(body, dict) or not isinstance(body.get("name"), str) or not body["name"]:
            raise Stop(f"{wrong} (an element without a name)")
    if not all(isinstance(item.get("name"), str) and item["name"] for item in plan.get("existing", [])):
        raise Stop(f"{wrong} (existing)")
    for key, names in (("rules", RULE_LISTS), ("nat", NAT_LISTS)):
        lists = plan.get(key, {})
        if not isinstance(lists, dict) or set(lists) - set(names):
            raise Stop(f"{wrong} ({key})")
        for entries in lists.values():
            if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
                raise Stop(f"{wrong} ({key})")
    # Every reference names an element the policy creates, a zone, or an element it counts on.
    known = {(item["type"], item["body"]["name"]) for item in plan.get("elements", [])}
    known |= {(ZONE, zone) for zone in zones} | {(item["type"], item["name"]) for item in plan.get("existing", [])}
    for found in references([plan.get("elements"), plan.get("rules"), plan.get("nat")]):
        if (found.get("@ref"), found.get("name")) not in known:
            raise Stop(f"{wrong} (a reference to {str(found.get('@ref'))[:40]} '{str(found.get('name'))[:60]}')")
    return plan


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Transport:
    """HTTPS to the SMC. A test puts something else in its place."""

    def __init__(self, base: str, context: Optional[ssl.SSLContext]) -> None:
        self.base = base
        handlers: List[Any] = [_NoRedirect()] + ([urllib.request.HTTPSHandler(context=context)] if context is not None else [])
        self.opener = urllib.request.build_opener(*handlers)

    def send(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, str], bytes]:
        try:
            request = urllib.request.Request(url, data=body, method=method, headers=headers)
            try:
                with self.opener.open(request, timeout=300) as answer:
                    return answer.status, _headers(answer.headers), answer.read()
            except urllib.error.HTTPError as error:
                return error.code, _headers(error.headers), error.read()
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as error:
            raise Stop(f"no usable answer from {self.base}: {getattr(error, 'reason', None) or error or type(error).__name__}") from None


def _headers(message: Any) -> Dict[str, str]:
    """The headers of an answer by their names in lower case; several Set-Cookie headers one per line."""
    out = {key.lower(): value for key, value in message.items()}
    cookies = message.get_all("Set-Cookie") if hasattr(message, "get_all") else None
    if cookies:
        out["set-cookie"] = "\n".join(cookies)
    return out


def cookies(header: str) -> str:
    """The Cookie header for what the SMC set: the name=value of each cookie, without its attributes."""
    found = [line.split(";", 1)[0].strip() for line in header.splitlines()]
    return "; ".join(item for item in found if "=" in item)


def _text(raw: bytes) -> str:
    """What the SMC said, short enough to read."""
    text = raw.decode("utf-8", errors="replace")
    try:
        answer = json.loads(text)
        parts = [str(answer.get("message") or "")] + [str(item) for item in answer.get("details") or []]
        text = "; ".join(part for part in parts if part) or text
    except (ValueError, TypeError, AttributeError):
        pass
    return " ".join(text.split())[:600] or "(no text)"


class Api:
    def __init__(self, transport: Any, key: str, version: str, domain: str, say: Any) -> None:
        self.transport, self.key, self.wanted, self.domain, self.say = transport, key, version, domain, say
        self.host = str(getattr(transport, "base", ""))
        self.version = ""
        self.cookie = ""
        self.entries: Dict[str, str] = {}

    def url(self, path: str) -> str:
        return f"{self.host}/{path.lstrip('/')}"

    def _own(self, href: str) -> str:
        """An href the SMC gave, if it points to the SMC that was named: nothing is sent anywhere else."""
        if not isinstance(href, str) or not href.startswith(self.host + "/"):
            raise Stop(f"the SMC answered with a link to somewhere else ({str(href)[:120]}): stopped")
        return href

    def login(self) -> None:
        status, headers, raw = self.transport.send("GET", self.url("api"), {"Accept": "application/json"}, None)
        if status != 200:
            raise Stop(f"GET /api was refused (HTTP {status}): {_text(raw)}. Is this an SMC with its API enabled?", status)
        try:
            offered = [str(item.get("rel")) for item in json.loads(raw.decode("utf-8")).get("version") or [] if isinstance(item, dict)]
        except (ValueError, AttributeError):
            offered = []
        if self.wanted:
            if self.wanted not in offered:
                raise Stop(f"the SMC does not offer API version {self.wanted} (it offers: {', '.join(offered) or 'none said'})")
            self.version = self.wanted
        else:
            known = [v for v in offered if v in KNOWN_VERSIONS]
            if not known:
                raise Stop(f"the SMC offers none of the API versions this program knows ({', '.join(offered) or 'none said'}); "
                           "name one with --api-version")  # fmt: skip
            self.version = max(known, key=lambda v: tuple(int(part) for part in v.split(".")))
        body: Json = {"authenticationkey": self.key}
        if self.domain:
            body["domain"] = self.domain
        status, headers, raw = self.transport.send("POST", self.url(f"{self.version}/login"), {"Content-Type": "application/json"},
                                                   json.dumps(body).encode("utf-8"))  # fmt: skip
        if 300 <= status < 400:
            raise Stop("the SMC answered the login with a redirect, which is not followed: give --host the name it answers under", status)
        if status not in (200, 201, 204):
            raise Stop(f"the SMC refused the login (HTTP {status}): {_text(raw)}", status)
        self.cookie = cookies(headers.get("set-cookie", ""))
        answer = self.call("GET", self.url(f"{self.version}/api"))
        for item in answer.get("entry_point") or [] if isinstance(answer, dict) else []:
            if isinstance(item, dict) and isinstance(item.get("rel"), str) and isinstance(item.get("href"), str):
                self.entries[item["rel"]] = self._own(item["href"])

    def logout(self) -> None:
        try:
            self.call("PUT", self.url(f"{self.version}/logout"))
        except Stop:
            pass

    def call(self, method: str, url: str, body: Any = None, want_location: bool = False) -> Any:
        """One call; waits when the SMC is busy. With ``want_location`` the answer is the href of what was created."""
        data = None if body is None else json.dumps(body).encode("utf-8")
        for _ in range(12):
            headers = {"Accept": "application/json"}
            if self.cookie:
                headers["Cookie"] = self.cookie
            if data is not None:
                headers["Content-Type"] = "application/json"
            status, answered, raw = self.transport.send(method, url, headers, data)
            if status in (429, 503):
                pause = answered.get("retry-after", "")
                time.sleep(min(float(pause), 120.0) if pause.replace(".", "", 1).isdigit() else 10.0)
                continue
            if status == 404 and method == "DELETE":
                return None
            if 300 <= status < 400:
                raise Stop(f"{method} {url}: the SMC answered with a redirect, which is not followed", status)
            if not 200 <= status < 300:
                raise Stop(f"{method} {url.split('?')[0]} was refused (HTTP {status}): {_text(raw)}", status)
            if want_location:
                location = answered.get("location", "")
                if not location:
                    raise Stop(f"{method} {url}: the SMC did not say where it created what was sent", -status)
                try:
                    return self._own(location)
                except Stop as error:
                    raise Stop(str(error), -status) from None  # (carried out, by its status)
            if not raw.strip():
                return {}
            try:
                return json.loads(raw.decode("utf-8"))
            except ValueError:
                raise Stop(f"{method} {url.split('?')[0]}: the answer (HTTP {status}) is not JSON: {_text(raw)}", status) from None
        raise Stop(f"{method} {url.split('?')[0]}: the SMC kept answering that it is busy", 429)

    def entry(self, kind: str) -> str:
        if kind not in self.entries:
            raise Stop(f"the SMC has no entry point '{kind}' in API version {self.version}")
        return self.entries[kind]

    def find(self, kind: str, name: str) -> List[str]:
        """The hrefs of the elements of a type with exactly this name."""
        query = urllib.parse.urlencode({"filter": name, "exact_match": "true"})
        answer = self.call("GET", f"{self.entry(kind)}?{query}")
        found = answer.get("result") if isinstance(answer, dict) else None
        return [self._own(item["href"]) for item in found or []
                if isinstance(item, dict) and item.get("name") == name and isinstance(item.get("href"), str)]  # fmt: skip

    def get(self, href: str) -> Json:
        answer = self.call("GET", self._own(href))
        if not isinstance(answer, dict):
            raise Stop(f"GET {href}: the answer is not an element")
        return answer


def link(element: Json, rel: str) -> str:
    for item in element.get("link") or []:
        if isinstance(item, dict) and item.get("rel") == rel and isinstance(item.get("href"), str):
            return str(item["href"])
    return ""


def resolved(value: Any, hrefs: Dict[Tuple[str, str], str]) -> Any:
    """A payload with every reference as the href of the element."""
    if isinstance(value, list):
        return [resolved(item, hrefs) for item in value]
    if not isinstance(value, dict):
        return value
    if "@ref" in value:
        key = (str(value["@ref"]), str(value.get("name")))
        if key not in hrefs:
            raise Stop(f"{key[0]} '{key[1]}' is used before it exists: the policy in this file is not in order")
        return hrefs[key]
    return {name: resolved(inner, hrefs) for name, inner in value.items()}


def _plain(value: Any) -> Any:
    """A value as it is compared: numbers as numbers, lists without order."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    if isinstance(value, list):
        return sorted(json.dumps(_plain(item), sort_keys=True) for item in value)
    if isinstance(value, dict):
        return {key: _plain(inner) for key, inner in value.items()}
    return value


FIELDS = {
    "host": ("address", "ipv6_address", "secondary"), "router": ("address", "ipv6_address", "secondary"),
    "network": ("ipv4_network", "ipv6_network", "broadcast"), "address_range": ("ip_range",),
    "domain_name": ("domain_name_entry",), "group": ("element",), "service_group": ("element",),
    "expression": ("operator", "ne_ref", "sub_expression"), "match_expression": ("ref",),
    "tcp_service": ("min_dst_port", "max_dst_port", "min_src_port", "max_src_port", "protocol_agent_ref"),
    "udp_service": ("min_dst_port", "max_dst_port", "min_src_port", "max_src_port", "protocol_agent_ref"),
    "icmp_service": ("icmp_type", "icmp_code"), "icmp_ipv6_service": ("icmp_type", "icmp_code"),
    "ip_service": ("protocol_number", "protocol_agent_ref"),
}  # fmt: skip


def same(kind: str, held: Json, sent: Json) -> bool:
    """Whether an element the SMC has matches exactly what this run would send: every field that decides what it matches,
    on both sides, and not only those this run sends (a host with another address of its own matches more)."""
    sent, held = dict(sent), dict(held)
    if kind in ("tcp_service", "udp_service"):
        for low, high in (("min_dst_port", "max_dst_port"), ("min_src_port", "max_src_port")):
            for body in (sent, held):
                if body.get(low) not in (None, "") and body.get(high) in (None, "", 0):
                    body[high] = body[low]
    if kind == "network":
        for body in (sent, held):
            body["broadcast"] = body.get("broadcast") is not False
    for key in FIELDS.get(kind, ()):
        if _plain(_empty(held.get(key))) != _plain(_empty(sent.get(key))):
            return False
    return kind in FIELDS


def _empty(value: Any) -> Any:
    return None if value in (None, "", [], {}) else value


class Run:
    def __init__(self, plan: Json, api: Any, say: Any, journal: str, name: str = "") -> None:
        self.plan, self.api, self.say, self.journal = plan, api, say, journal
        self.name = name or str(plan.get("policy") or "FWShift")
        self.hrefs: Dict[Tuple[str, str], str] = {}
        self.reused: List[str] = []
        self.template = ""
        self.made: List[Json] = []
        self.written = 0
        self.uncertain: List[str] = []  # what the SMC may have created without saying where

    def elements(self) -> List[Json]:
        return [item for item in self.plan.get("elements", []) if isinstance(item, dict)]

    def rules(self, key: str) -> Dict[str, List[Json]]:
        lists = self.plan.get(key) or {}
        return {name: [entry for entry in lists.get(name) or [] if isinstance(entry, dict)] for name in (RULE_LISTS if key == "rules" else NAT_LISTS)}

    # -- what there is ----------------------------------------------------

    def check(self) -> None:
        self.say("Reading what the SMC has ...")
        found = self.api.find(TEMPLATE, str(self.plan["template"]))
        if len(found) != 1:
            raise Stop(f"the SMC has {'no' if not found else 'more than one'} template '{self.plan['template']}'. Nothing was "
                       "created. Name another with --template, or convert again with --target-template")  # fmt: skip
        self.template = found[0]
        if self.api.find(POLICY, self.name):
            raise Stop(f"firewall policy '{self.name}' exists already. Nothing was created. Give the new policy another name with --name")
        missing: List[str] = []
        for entry in self.plan.get("existing", []):
            kind, name = str(entry["type"]), str(entry["name"])
            there = self.api.find(kind, name)
            if there:
                self.hrefs[(kind, name)] = there[0]
            else:
                missing.append(f"{kind} '{name}'")
        if missing:
            raise Stop("the policy counts on elements the SMC does not have: " + ", ".join(missing[:20]) + ". Nothing was created")
        for zone in [str(zone) for zone in self.plan.get("zones", [])]:
            there = self.api.find(ZONE, zone)
            if there:
                self.hrefs[(ZONE, zone)] = there[0]
        clashes: List[str] = []
        for item in self.elements():
            kind, body = str(item["type"]), item["body"]
            there = self.api.find(kind, str(body["name"]))
            if not there:
                continue
            refs = references(body)
            if all((str(r["@ref"]), str(r["name"])) in self.hrefs for r in refs) and same(kind, self.api.get(there[0]), resolved(body, self.hrefs)):
                self.hrefs[(kind, str(body["name"]))] = there[0]
                self.reused.append(f"{kind} '{body['name']}'")
            else:
                clashes.append(f"{kind} '{body['name']}'")
        if clashes:
            shown = ", ".join(clashes[:20]) + (f" and {len(clashes) - 20} more" if len(clashes) > 20 else "")
            raise Stop(f"{len(clashes)} element(s) this policy would create exist already and say something else: {shown}. "
                       "Nothing was created. Convert again with --target-prefix, which gives every element that is created "
                       "a name of its own")  # fmt: skip

    def summary(self) -> List[str]:
        rules, nat = self.rules("rules"), self.rules("nat")
        lines = [f"Firewall policy '{self.name}' on template '{self.plan['template']}': "
                 + ", ".join(f"{len(rules[key])} {key.split('_')[1]} access rule entries" for key in RULE_LISTS)
                 + ", " + ", ".join(f"{len(nat[key])} {key.split('_')[1]} NAT rules" for key in NAT_LISTS)]  # fmt: skip
        counts: Dict[str, int] = {}
        for item in self.elements():
            counts[str(item["type"])] = counts.get(str(item["type"]), 0) + 1
        if counts:
            lines.append("elements: " + ", ".join(f"{count} {kind}" for kind, count in counts.items()))
        zones = [str(zone) for zone in self.plan.get("zones", [])]
        if zones:
            lines.append("zones (used if they exist, created without interfaces if not): " + ", ".join(zones))
        existing = [f"{entry['name']}" for entry in self.plan.get("existing", [])]
        if existing:
            lines.append("elements that must exist already: " + ", ".join(existing))
        if self.reused:
            lines.append("elements that exist already and say the same, used as they are: " + ", ".join(self.reused[:20])
                         + (" ..." if len(self.reused) > 20 else ""))  # fmt: skip
        return lines

    # -- the journal ------------------------------------------------------

    def save(self) -> None:
        data = {"format": FORMAT, "host": self.api.host, "created": self.made}
        try:
            with open(self.journal + ".tmp", "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=1)
                handle.write("\n")
            os.replace(self.journal + ".tmp", self.journal)
        except OSError as error:
            raise Stop(f"the journal {self.journal} could not be written ({error})") from None
        self.written = len(self.made)

    def unwritten(self) -> List[str]:
        return [f"{entry['type']} '{entry['name']}'" for entry in self.made[self.written:]]

    # -- creating ---------------------------------------------------------

    def _create(self, kind: str, name: str, url: str, body: Json) -> str:
        try:
            href = self.api.call("POST", url, body, want_location=True)
        except Stop as error:
            if error.status < 0:  # the SMC said it created it, and not where
                self.uncertain.append(f"{kind} '{name}'")
            raise
        self.made.append({"type": kind, "name": name, "href": href})
        self.save()
        return str(href)

    def create(self) -> None:
        self.save()  # the journal is there before the first element is
        for zone in [str(zone) for zone in self.plan.get("zones", [])]:
            if (ZONE, zone) not in self.hrefs:
                self.hrefs[(ZONE, zone)] = self._create(ZONE, zone, self.api.entry(ZONE), {"name": zone})
                self.say(f"  zone '{zone}' created, without interfaces")
        count = 0
        for item in self.elements():
            kind, body = str(item["type"]), item["body"]
            key = (kind, str(body["name"]))
            if key in self.hrefs:
                continue
            self.hrefs[key] = self._create(kind, key[1], self.api.entry(kind), resolved(body, self.hrefs))
            count += 1
        self.say(f"  {count} elements created")
        body = {"name": self.name, "template": self.template, "comment": str(self.plan.get("comment", ""))[:1000]}
        href = self._create(POLICY, self.name, self.api.entry(POLICY), body)
        policy = self.api.get(href)
        for part in ("rules", "nat"):
            for rel, entries in self.rules(part).items():
                if not entries:
                    continue
                collection = link(policy, rel + "s")
                if not collection:
                    raise Stop(f"the new policy has no list {rel}s")
                where = self.api._own(collection)
                for entry in entries:
                    # The first rule goes into the list (at the insert point), each other one after the rule before it.
                    try:
                        created = self.api.call("POST", where, resolved(entry, self.hrefs), want_location=True)
                    except Stop as error:
                        if error.status < 0:
                            self.uncertain.append(f"a rule in {rel} of policy '{self.name}' (deleted with the policy)")
                        raise
                    held = self.api.get(created)
                    if bool(held.get("is_disabled")) != bool(entry.get("is_disabled")) or ("action" in entry and _plain(held.get("action", {}).get("action")) != _plain(entry["action"].get("action"))):
                        raise Stop(f"the SMC holds rule '{entry.get('name', '')}' in {rel} otherwise than it was sent (enabled or action): "
                                   "it is not the policy that was converted")  # fmt: skip
                    where = link(held, "add_after")
                    if not where:
                        raise Stop(f"the SMC gave the rule it created in {rel} no place to add the next one after (add_after)")
                    where = self.api._own(where)
                self._verify(collection, entries, rel)
                self.say(f"  {len(entries)} entries written to {rel}")

    def _verify(self, collection: str, sent: List[Json], rel: str) -> None:
        answer = self.api.call("GET", collection)
        held = answer.get("result") if isinstance(answer, dict) else None
        names = [str(item.get("name") or "") for item in held or [] if isinstance(item, dict)]
        # The list holds the insert points of the template as well, without a place of their own in the policy.
        own = [item for item in held or [] if isinstance(item, dict) and "/fw_policy/" in str(item.get("href", ""))]
        wanted = [str(entry.get("name") or "") for entry in sent]
        mine = [str(item.get("name") or "") for item in own]
        if len(own) != len(sent) or mine != wanted:
            raise Stop(f"the list {rel} of policy '{self.name}' holds {len(own)} entries of it ({', '.join(names[:6])}...) and "
                       f"{len(sent)} were sent, in another order or under other names: it is not the policy that was converted")  # fmt: skip


def read_journal(journal: str) -> Json:
    try:
        with open(journal, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as error:
        raise Stop(f"the journal {journal} could not be read: {error}") from None
    created = data.get("created") if isinstance(data, dict) else None
    if not isinstance(created, list) or not all(
        isinstance(entry, dict) and all(isinstance(entry.get(key), str) and entry[key] for key in ("type", "name", "href")) for entry in created
    ):
        raise Stop(f"{journal} is not a journal of this loader: nothing was deleted")
    if any(entry["type"] not in ELEMENTS + (ZONE, POLICY) for entry in created):
        raise Stop(f"{journal} lists something this loader does not create: nothing was deleted")
    return dict(data)


def undo(api: Any, journal: str, say: Any) -> int:
    data = read_journal(journal)
    created = data["created"]
    if data.get("host") and data["host"] != api.host:
        raise Stop(f"the journal is of a run on {data['host']}; this is {api.host}. Nothing was deleted")
    failed = gone = 0
    # The policy first (its rules go with it), then the elements, the last one created first.
    order = [entry for entry in created if entry["type"] == POLICY] + [entry for entry in reversed(created) if entry["type"] != POLICY]
    for entry in order:
        what = f"{entry['type']} '{entry['name']}'"
        try:
            if api.call("DELETE", api._own(entry["href"])) is None:
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
    """https://host:8082, whatever was given; plain HTTP only to this computer itself (a test)."""
    if not host or any(character.isspace() or ord(character) < 33 for character in host):
        raise Stop("--host takes the name or the address of the SMC, without spaces")
    url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    try:
        parts = urllib.parse.urlsplit(url)
        name, port = parts.hostname, parts.port
    except ValueError as error:
        raise Stop(f"--host '{host[:80]}' is not a name or an address ({error})") from None
    if not name or parts.path.strip("/") or parts.query or parts.fragment or parts.username is not None:
        raise Stop(f"--host '{host[:80]}': give the name or the address of the SMC, and nothing after it")
    if parts.scheme == "http" and name not in ("127.0.0.1", "localhost", "::1"):
        raise Stop("this would send the API key without encryption: only https is used")
    netloc = parts.netloc if port else f"{parts.netloc}:8082"
    return f"{parts.scheme}://{netloc}"


def someone_to_ask() -> bool:
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
    parser = argparse.ArgumentParser(description="Load the converted policy in this file into a Forcepoint Security Management Center.")
    parser.add_argument("--show", action="store_true", help="say what would be created, without connecting")
    parser.add_argument("--plan", action="store_true", help="print the policy this file carries, as JSON")
    parser.add_argument("--host", help="name or address of the SMC (port 8082 unless given: smc.example.com:8443)")
    parser.add_argument("--api-version", default="", help="API version to use (default: the newest the SMC offers that this program knows)")
    parser.add_argument("--domain", default="", help="administrative domain to log in to (default: the one of the API client)")
    parser.add_argument("--name", default="", help="name for the new firewall policy")
    parser.add_argument("--template", default="", help="template for the new policy (default: the one of the conversion)")
    parser.add_argument("--cafile", help="certificate of the authority that signed the certificate of the SMC")
    parser.add_argument("--insecure", action="store_true", help="do not check the certificate of the SMC")
    parser.add_argument("--dry-run", action="store_true", help="log in and check every name, create nothing")
    parser.add_argument("--undo", action="store_true", help="delete what a run created, as its journal lists it")
    parser.add_argument("--journal", default="", help="file that lists what was created (default: fwshift-smc-NAME.journal.json)")
    args = parser.parse_args(argv)
    api: Any = None
    try:
        plan = check_plan(plan) if plan is not None else read_plan(os.path.abspath(__file__))
        if args.template:
            plan = dict(plan, template=args.template)
        if args.plan:
            say(json.dumps(plan, indent=1, sort_keys=True))
            return 0
        name = args.name or str(plan.get("policy") or "FWShift")
        if not name.strip() or len(name) > 254 or any(ord(c) < 32 for c in name):
            raise Stop(f"'{name[:60]}' is not a name for a policy (--name gives another)")
        journal = args.journal or f"fwshift-smc-{''.join(c if c.isalnum() or c in '._-' else '_' for c in name)}.journal.json"
        if args.show:
            for line in Run(plan, None, say, journal, name).summary():
                say(line)
            return 0
        if not args.host:
            raise Stop("--host is needed (or --show, to look without connecting)")
        if transport is None:
            base = base_url(args.host)
            if args.insecure:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                say("WARNING: the certificate of the SMC is not checked (--insecure)")
            else:
                try:
                    context = ssl.create_default_context(cafile=args.cafile)
                except (OSError, ValueError) as error:
                    raise Stop(f"--cafile {args.cafile}: no certificates could be read from it ({error})") from None
            transport = Transport(base, context)
        key = os.environ.get("SMC_API_KEY", "")
        if not key:
            if not someone_to_ask():
                raise Stop("no API key: set the environment variable SMC_API_KEY, or run this from a terminal")
            try:
                key = getpass.getpass("Authentication key of the API client: ")
            except (EOFError, OSError):
                raise Stop("no API key: set the environment variable SMC_API_KEY, or run this from a terminal") from None
        api = Api(transport, key, args.api_version, args.domain, say)
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
            say("Every name is free or holds the same element, and everything the policy counts on is there. Nothing was created (--dry-run).")
            return 0
        try:
            run.create()
        except Stop as error:
            loose = run.unwritten()
            if run.uncertain:
                loose += [f"{what} (the SMC said it created it, and not where)" for what in run.uncertain]
            if loose:
                raise Stop(f"{error}\nStopped. Created and NOT in the journal, which could not be written: {', '.join(loose)}. "
                           f"Delete them by hand; --undo deletes the {run.written} that {journal} lists") from None  # fmt: skip
            if not run.made:
                try:
                    os.remove(journal)
                except OSError:
                    pass
                raise Stop(f"{error}\nStopped. Nothing was created.") from None
            raise Stop(f"{error}\nStopped. {len(run.made)} element(s) exist that this run created; they are listed in {journal}: "
                       "delete them again with --undo, correct the cause and run this file again") from None  # fmt: skip
        say(f"Done. What was created is listed in {journal}. The policy is installed on no engine: install it when the "
            "report of the conversion has been worked through.")  # fmt: skip
        return 0
    except Stop as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 1
    finally:
        if api is not None and api.version:
            api.logout()


if __name__ == "__main__":
    status = main()
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            pass
        status = 1
    sys.exit(status)
