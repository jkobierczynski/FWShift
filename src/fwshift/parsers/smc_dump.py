#!/usr/bin/env python3
# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read one firewall policy out of a Forcepoint Security Management Center (SMC), for FWShift.

This is what "fwshift script forcepoint-dump" writes. It needs Python 3.8 or newer and nothing else, and
only reads: it logs in to the REST API, fetches the policy, the templates it is based on, their rule lists,
every rule, every sub-policy a rule jumps to and every element a rule or an element names, and writes the
answers one per line. FWShift reads that file (fwshift convert FILE --from forcepoint ...).

    python3 THIS_FILE --host smc.example.com --policy "Branch Policy" -o branch.json

The API client key is asked for, or taken from the environment variable SMC_API_KEY. The SMC answers on
port 8082 unless --host names another. A redirect is not followed, links to anywhere but the SMC that was
named are not fetched, and plain http is spoken only to this computer itself.
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
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

KNOWN_VERSIONS = ("6.10", "6.11", "7.0", "7.1", "7.2", "7.3", "7.4")
RULE_LISTS = ("fw_ipv4_access_rules", "fw_ipv6_access_rules", "fw_ipv4_nat_rules", "fw_ipv6_nat_rules")
# The fields of rules and elements whose links are followed: what a rule matches, translates to and jumps to, and what
# a group, an expression or a match expression holds. Nothing else is fetched (not the inspection policy, say).
FOLLOW = ("src", "dst", "service", "sub_policy", "rule_validity_times", "users", "methods", "element", "ne_ref", "ref",
          "firewall_ref", "template")  # fmt: skip
MAX_ANSWERS = 200000  # a policy that needs more than this many answers is not believed
Json = Dict[str, Any]


class Stop(Exception):
    pass


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
    out = {key.lower(): value for key, value in message.items()}
    cookies = message.get_all("Set-Cookie") if hasattr(message, "get_all") else None
    if cookies:
        out["set-cookie"] = "\n".join(cookies)
    return out


def _text(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    try:
        answer = json.loads(text)
        parts = [str(answer.get("message") or "")] + [str(item) for item in answer.get("details") or []]
        text = "; ".join(part for part in parts if part) or text
    except (ValueError, TypeError, AttributeError):
        pass
    return " ".join(text.split())[:600] or "(no text)"


class Session:
    def __init__(self, transport: Any, key: str, version: str, domain: str) -> None:
        self.transport, self.key, self.wanted, self.domain = transport, key, version, domain
        self.host = str(getattr(transport, "base", ""))
        self.version = ""
        self.cookie = ""
        self.entries: Dict[str, str] = {}

    def own(self, href: Any, entry: bool = False) -> bool:
        prefix = f"{self.host}/{self.version}/" if entry else f"{self.host}/{self.version}/elements/"
        return isinstance(href, str) and href.startswith(prefix) and ".." not in href

    def login(self) -> None:
        status, _, raw = self.transport.send("GET", f"{self.host}/api", {"Accept": "application/json"}, None)
        if status != 200:
            raise Stop(f"GET /api was refused (HTTP {status}): {_text(raw)}. Is this an SMC with its API enabled?")
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
        status, headers, raw = self.transport.send("POST", f"{self.host}/{self.version}/login", {"Content-Type": "application/json"},
                                                   json.dumps(body).encode("utf-8"))  # fmt: skip
        if status not in (200, 201, 204):
            raise Stop(f"the SMC refused the login (HTTP {status}): {_text(raw)}")
        found = [line.split(";", 1)[0].strip() for line in headers.get("set-cookie", "").splitlines()]
        self.cookie = "; ".join(item for item in found if "=" in item)
        answer = self.get(f"{self.host}/{self.version}/api")
        for item in answer.get("entry_point") or []:
            # Only entry points on the SMC that was named: the session cookie goes nowhere else.
            if isinstance(item, dict) and isinstance(item.get("rel"), str) and self.own(item.get("href"), entry=True):
                self.entries[item["rel"]] = item["href"]

    def logout(self) -> None:
        try:
            self.transport.send("PUT", f"{self.host}/{self.version}/logout", {"Cookie": self.cookie}, None)
        except Stop:
            pass

    def get(self, url: str) -> Json:
        for _ in range(12):
            headers = {"Accept": "application/json"}
            if self.cookie:
                headers["Cookie"] = self.cookie
            status, answered, raw = self.transport.send("GET", url, headers, None)
            if status in (429, 503):
                pause = answered.get("retry-after", "")
                time.sleep(min(float(pause), 120.0) if pause.replace(".", "", 1).isdigit() else 10.0)
                continue
            if status == 404:
                return {}
            if not 200 <= status < 300:
                raise Stop(f"GET {url.split('?')[0]} was refused (HTTP {status}): {_text(raw)}")
            try:
                answer = json.loads(raw.decode("utf-8"))
            except ValueError:
                raise Stop(f"GET {url.split('?')[0]}: the answer is not JSON: {_text(raw)}") from None
            if not isinstance(answer, dict):
                raise Stop(f"GET {url.split('?')[0]}: the answer is not an element or a list")
            return answer
        raise Stop(f"GET {url.split('?')[0]}: the SMC kept answering that it is busy")


def links(value: Any, key: str = "") -> List[str]:
    """The hrefs in the fields that are followed."""
    if isinstance(value, list):
        return [found for item in value for found in links(item, key)]
    if isinstance(value, dict):
        return [found for name, inner in value.items() if name != "link" for found in links(inner, name)]
    return [value] if key in FOLLOW and isinstance(value, str) else []


def link(element: Json, rel: str) -> str:
    for item in element.get("link") or []:
        if isinstance(item, dict) and item.get("rel") == rel and isinstance(item.get("href"), str):
            return str(item["href"])
    return ""


def dump(session: Session, policy: str, write: Any, say: Any) -> int:
    """Write the answers for one policy; the number of answers written."""
    query = urllib.parse.urlencode({"filter": policy, "exact_match": "true"})
    if "fw_policy" not in session.entries:
        raise Stop(f"the SMC has no entry point fw_policy in API version {session.version}")
    found = session.get(f"{session.entries['fw_policy']}?{query}").get("result") or []
    hrefs = [item["href"] for item in found if isinstance(item, dict) and item.get("name") == policy and session.own(item.get("href"))]
    if len(hrefs) != 1:
        raise Stop(f"the SMC has {'no' if not hrefs else 'more than one'} firewall policy '{policy}'")
    write({"fwshift_dump": 1, "smc": session.host, "api": session.version, "policy": policy})
    todo: List[str] = [hrefs[0]]
    seen: Set[str] = set()
    count = 0
    while todo:
        href = todo.pop(0)
        if href in seen or not session.own(href):
            continue
        seen.add(href)
        count += 1
        if count > MAX_ANSWERS:
            raise Stop(f"more than {MAX_ANSWERS} answers: stopped")
        element = session.get(href)
        if not element:
            continue  # gone, or not readable for this client: FWShift reports what is missing
        write(element)
        found_links = links(element)
        for rel in RULE_LISTS:
            where = link(element, rel)
            if where and session.own(where) and where not in seen:
                seen.add(where)
                listing = session.get(where)
                if not isinstance(listing.get("result"), list):
                    say(f"  the list {where} could not be read: left out, and FWShift reports it missing")
                    continue
                entries = [item for item in listing["result"] if isinstance(item, dict)]
                write({"fwshift_list": where, "result": entries})
                found_links += [str(item.get("href")) for item in entries]
        todo += [found for found in found_links if found not in seen]
        if count % 200 == 0:
            say(f"  {count} answers ...")
    return count


def base_url(host: str) -> str:
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
    return f"{parts.scheme}://{parts.netloc if port else parts.netloc + ':8082'}"


def main(argv: Optional[Sequence[str]] = None, transport: Any = None, say: Any = print, key: str = "") -> int:
    parser = argparse.ArgumentParser(description="Read one firewall policy out of a Forcepoint SMC, for FWShift.")
    parser.add_argument("--host", required=True, help="name or address of the SMC (port 8082 unless given: smc.example.com:8443)")
    parser.add_argument("--policy", required=True, help="name of the firewall policy to read")
    parser.add_argument("-o", "--output", required=True, help="file to write")
    parser.add_argument("--api-version", default="", help="API version to use (default: the newest the SMC offers that this program knows)")
    parser.add_argument("--domain", default="", help="administrative domain to log in to")
    parser.add_argument("--cafile", help="certificate of the authority that signed the certificate of the SMC")
    parser.add_argument("--insecure", action="store_true", help="do not check the certificate of the SMC")
    args = parser.parse_args(argv)
    session: Optional[Session] = None
    try:
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
        key = key or os.environ.get("SMC_API_KEY", "")
        if not key:
            if sys.stdin is None or not sys.stdin.isatty():
                raise Stop("no API key: set the environment variable SMC_API_KEY, or run this from a terminal")
            key = getpass.getpass("Authentication key of the API client: ")
        session = Session(transport, key, args.api_version, args.domain)
        session.login()
        try:
            with open(args.output + ".tmp", "w", encoding="utf-8") as handle:
                count = dump(session, args.policy, lambda answer: handle.write(json.dumps(answer, ensure_ascii=False) + "\n"), say)
            os.replace(args.output + ".tmp", args.output)
        except OSError as error:
            raise Stop(f"{args.output} could not be written ({error})") from None
        finally:
            if os.path.exists(args.output + ".tmp"):
                os.remove(args.output + ".tmp")  # what a run that stopped wrote: not an input for FWShift
        say(f"Done: {count} answers in {args.output}. Convert it with: fwshift convert {args.output} --from forcepoint --to ...")
        return 0
    except Stop as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("interrupted", file=sys.stderr)
        return 1
    finally:
        if session is not None and session.version:
            session.logout()


if __name__ == "__main__":
    sys.exit(main())
