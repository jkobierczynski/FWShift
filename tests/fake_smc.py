# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""A made-up Forcepoint Security Management Center, for the loader and the dump program: the calls of its REST API that
they make, answered as smc-python and the SMC API guide describe them, and strict about what is sent.

It holds the predefined Firewall Template (rules above its insert point for the traffic of the engine, an insert point,
Refuse Ident, Discard all), a few predefined services and aliases, and what is created. A rule POSTed to the list of a
policy goes to the top of it, at the insert point of the template; a rule POSTed to the add_after link of a rule goes
after that one. References must name elements that exist.
"""

from __future__ import annotations

import copy
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

BASE = "https://smc.example.net:8082"
VERSION = "7.4"
ROOT = f"{BASE}/{VERSION}"
E = f"{ROOT}/elements"
TYPES = ("host", "router", "network", "address_range", "domain_name", "group", "expression", "match_expression", "interface_zone",
         "tcp_service", "udp_service", "icmp_service", "icmp_ipv6_service", "ip_service", "service_group", "fw_policy",
         "fw_template_policy", "sub_ipv4_fw_policy", "application_situation", "default_nat_address_alias", "mgt_servers_alias",
         "local_cluster_alias", "interface_nic_x_ip_alias")  # fmt: skip
LISTS = ("fw_ipv4_access_rule", "fw_ipv6_access_rule", "fw_ipv4_nat_rule", "fw_ipv6_nat_rule")
REF_KEYS = ("element", "ne_ref", "ref", "src", "dst", "service", "template", "sub_policy")
Json = Dict[str, Any]


class FakeSmc:
    def __init__(self, key: str = "secret-key") -> None:
        self.base = BASE
        self.key = key
        self.cookie = "JSESSIONID=fake0001"
        self.logged_in = False
        self.next_key = 100
        self.elements: Dict[str, Json] = {}  # href -> body
        self.rules: Dict[str, List[str]] = {}  # list href -> rule hrefs, in order
        self.calls: List[Tuple[str, str]] = []
        self.refuse: Dict[str, int] = {}  # type -> HTTP status to answer a POST of it with
        self.broken_location = False
        self.missing_lists: List[str] = []  # rule lists that answer 404
        self.foreign_entries = False  # entry points on another host
        self.drop_disabled = False  # an SMC that does not keep is_disabled
        self.add_after_before = False  # an SMC that puts a rule posted to add_after before the other
        top = self._add("fw_template_policy", {"name": "Firewall Template", "template": None, "system": True, "read_only": True})
        alias_m = self._add("mgt_servers_alias", {"name": "$$ Management Servers", "system": True})
        alias_c = self._add("local_cluster_alias", {"name": "$$ Local Cluster", "system": True})
        self._add("default_nat_address_alias", {"name": "$$ Default NAT Address", "system": True})
        control = self._add("tcp_service", {"name": "SG Control", "min_dst_port": 3020, "max_dst_port": 3021, "system": True})
        ident = self._add("tcp_service", {"name": "Ident", "min_dst_port": 113, "max_dst_port": None, "system": True})
        self._add("tcp_service", {"name": "HTTPS", "min_dst_port": 443, "max_dst_port": None, "system": True})
        self._add("tcp_service", {"name": "SSH", "min_dst_port": 22, "max_dst_port": None, "system": True})
        self._add("application_situation", {"name": "Facebook", "system": True})
        self.insert_points: Dict[str, str] = {}
        for rel in LISTS:
            where = f"{top}/{rel}"
            entries: List[Json] = []
            if rel == "fw_ipv4_access_rule":
                entries.append({"comment": "SMC communications", "sources": {"src": [alias_m]}, "destinations": {"dst": [alias_c]},
                                "services": {"service": [control]}, "action": {"action": ["allow"]}, "is_disabled": False})  # fmt: skip
                entries.append({"name": "Automatic Rules Insert Point", "type": "automatic"})
            entries.append({"name": "Insert Point", "type": "normal"})
            if rel.endswith("access_rule"):
                entries.append({"sources": {"any": True}, "destinations": {"any": True}, "services": {"service": [ident]},
                                "action": {"action": ["refuse"]}, "options": {"log_level": "stored"}, "is_disabled": False})  # fmt: skip
                entries.append({"sources": {"any": True}, "destinations": {"any": True}, "services": {"any": True},
                                "action": {"action": ["discard"]}, "options": {"log_level": "stored"}, "is_disabled": False})  # fmt: skip
            self.rules[where] = []
            for entry in entries:
                href = self._rule_href(where)
                self.elements[href] = dict(entry, tag=f"{href.rsplit('/', 1)[-1]}.0")
                self.rules[where].append(href)
                if entry.get("type") == "normal":
                    self.insert_points[rel] = href

    # -- the store ------------------------------------------------------------------------------

    def _key(self) -> int:
        self.next_key += 1
        return self.next_key

    def _add(self, kind: str, body: Json) -> str:
        href = f"{E}/{kind}/{self._key()}"
        self.elements[href] = dict(body)
        if kind in ("fw_policy", "fw_template_policy"):
            for rel in LISTS:
                self.rules[f"{href}/{rel}"] = []
        if kind == "sub_ipv4_fw_policy":
            self.rules[f"{href}/fw_ipv4_access_rule"] = []
        return href

    def _rule_href(self, where: str) -> str:
        return f"{where}/{self._key()}"

    def answer(self, href: str) -> Json:
        body = copy.deepcopy(self.elements[href])
        links = [{"rel": "self", "href": href, "type": href.rsplit("/", 2)[-2]}]
        parts = href[len(E) + 1:].split("/")
        if len(parts) == 2 and parts[0] in ("fw_policy", "fw_template_policy", "sub_ipv4_fw_policy"):
            for rel in LISTS:
                if f"{href}/{rel}" in self.rules:
                    links.append({"rel": rel + "s", "href": f"{href}/{rel}"})
        if len(parts) == 4:
            links += [{"rel": "add_after", "href": f"{href}/add_after"}, {"rel": "add_before", "href": f"{href}/add_before"}]
        body["key"] = int(parts[-1]) if parts[-1].isdigit() else 0
        body["link"] = links
        return body

    def refs(self, value: Any, key: str = "") -> List[str]:
        if isinstance(value, list):
            return [found for item in value for found in self.refs(item, key)]
        if isinstance(value, dict):
            return [found for name, inner in value.items() for found in self.refs(inner, name)]
        return [value] if key in REF_KEYS and isinstance(value, str) else []

    def dump_policy(self, name: str) -> str:
        """The answers the dump program would write for a policy (without running it)."""
        from fwshift.parsers import smc_dump

        lines: List[str] = []
        session = smc_dump.Session(self, self.key, "", "")
        session.login()
        smc_dump.dump(session, name, lambda answer: lines.append(json.dumps(answer)), lambda line: None)
        return "\n".join(lines) + "\n"

    # -- HTTP -----------------------------------------------------------------------------------

    def send(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, str], bytes]:
        self.calls.append((method, url))

        def reply(status: int, data: Any = None, extra: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
            raw = b"" if data is None else json.dumps(data).encode("utf-8")
            return status, dict(extra or {}), raw

        def error(status: int, message: str) -> Tuple[int, Dict[str, str], bytes]:
            return reply(status, {"message": message, "details": [message]})

        parts = urllib.parse.urlsplit(url)
        path = f"{parts.scheme}://{parts.netloc}{parts.path}"
        query = dict(urllib.parse.parse_qsl(parts.query))
        if path == f"{BASE}/api" and method == "GET":
            return reply(200, {"version": [{"rel": "6.10", "href": f"{BASE}/6.10/api"}, {"rel": VERSION, "href": f"{ROOT}/api"}]})
        if path == f"{ROOT}/login" and method == "POST":
            sent = json.loads(body or b"{}")
            if sent.get("authenticationkey") != self.key:
                return error(401, "Login failed")
            self.logged_in = True
            return reply(200, None, {"set-cookie": f"{self.cookie}; Path=/; Secure; HttpOnly"})
        if headers.get("Cookie") != self.cookie or not self.logged_in:
            return error(401, "Not logged in")
        if path == f"{ROOT}/logout" and method == "PUT":
            self.logged_in = False
            return reply(204)
        if path == f"{ROOT}/api" and method == "GET":
            where = "https://elsewhere.example.org/7.4/elements" if self.foreign_entries else E
            return reply(200, {"entry_point": [{"rel": kind, "href": f"{where}/{kind}", "method": "GET"} for kind in TYPES]})
        if not path.startswith(E + "/"):
            return error(404, "no such path")
        rest = path[len(E) + 1:].split("/")
        data = json.loads(body) if body else None
        if len(rest) == 1:  # an entry point
            kind = rest[0]
            if kind not in TYPES:
                return error(404, f"no entry point {kind}")
            if method == "GET":
                wanted = query.get("filter", "")
                found = [href for href in self.elements if href.startswith(f"{E}/{kind}/") and href.count("/") == f"{E}/{kind}/x".count("/")]
                if query.get("exact_match") == "true":
                    found = [href for href in found if self.elements[href].get("name") == wanted]
                else:
                    found = [href for href in found if wanted.lower() in str(self.elements[href].get("name", "")).lower()]
                return reply(200, {"result": [{"href": h, "name": self.elements[h].get("name"), "type": kind} for h in found]})
            if method == "POST":
                if kind in self.refuse:
                    return error(self.refuse[kind], f"refused: {kind}")
                if not isinstance(data, dict) or not isinstance(data.get("name"), str) or not data["name"]:
                    return error(400, "an element needs a name")
                if any(e.get("name") == data["name"] for h, e in self.elements.items() if h.startswith(f"{E}/{kind}/")):
                    return error(400, f"Element name {data['name']} is already used")
                bad = [r for r in self.refs(data) if r not in self.elements]
                if bad or (kind == "fw_policy" and not data.get("template")):
                    return error(400, f"invalid reference {bad[:1]}")
                href = self._add(kind, data)
                return reply(201, None, {"location": "https://elsewhere.example.org/x" if self.broken_location else href})
            return error(405, "method not allowed")
        if len(rest) == 2:  # an element
            href = path
            if href not in self.elements:
                return error(404, "no such element")
            if method == "GET":
                return reply(200, self.answer(href))
            if method == "DELETE":
                if any(href in self.refs(other) for h, other in self.elements.items() if h != href and not h.startswith(href + "/")):
                    return error(409, "the element is in use")
                for where in [w for w in self.rules if w.startswith(href + "/")]:
                    for rule in self.rules.pop(where):
                        self.elements.pop(rule, None)
                del self.elements[href]
                return reply(204)
            return error(405, "method not allowed")
        if len(rest) == 3 and f"{E}/{rest[0]}/{rest[1]}" in self.elements:  # a rule list
            where = path
            if where not in self.rules or where in self.missing_lists:
                return error(404, "no such list")
            if method == "GET":
                return reply(200, {"result": [{"href": h, "name": self.elements[h].get("name", ""), "type": rest[2]} for h in self.rules[where]]})
            if method == "POST":
                return self._new_rule(where, 0, data)
            return error(405, "method not allowed")
        if len(rest) in (4, 5):
            where = f"{E}/{rest[0]}/{rest[1]}/{rest[2]}"
            href = f"{where}/{rest[3]}"
            if href not in self.elements or where not in self.rules:
                return error(404, "no such rule")
            if len(rest) == 4 and method == "GET":
                return reply(200, self.answer(href))
            if len(rest) == 5 and rest[4] in ("add_after", "add_before") and method == "POST":
                index = self.rules[where].index(href) + (1 if rest[4] == "add_after" and not self.add_after_before else 0)
                return self._new_rule(where, index, data, self.elements[href].get("parent_insert_point"))
            return error(405, "method not allowed")
        return error(404, "no such path")

    def _new_rule(self, where: str, index: int, data: Any, parent: Optional[str] = None) -> Tuple[int, Dict[str, str], bytes]:
        status_error = (400, {}, json.dumps({"message": "invalid rule"}).encode("utf-8"))
        if not isinstance(data, dict):
            return status_error
        if "sources" in data and not all(key in data for key in ("destinations", "services")):
            return status_error
        bad = [r for r in self.refs(data) if r not in self.elements]
        if bad:
            return 400, {}, json.dumps({"message": f"invalid reference {bad[0]}"}).encode("utf-8")
        rel = where.rsplit("/", 1)[-1]
        href = self._rule_href(where)
        body = dict(data, tag=f"{href.rsplit('/', 1)[-1]}.0")
        if self.drop_disabled:
            body.pop("is_disabled", None)
        if "/fw_policy/" in where:
            body["parent_insert_point"] = parent or self.insert_points[rel]
        self.elements[href] = body
        self.rules[where].insert(index, href)
        return 201, {"location": href}, b""
