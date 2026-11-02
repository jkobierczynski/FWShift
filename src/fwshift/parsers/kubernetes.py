# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Kubernetes NetworkPolicy and Calico policy parser: the JSON of kubectl and calicoctl -> neutral model.

What is read: one or more JSON documents (a ``List`` as ``kubectl get ... -o json`` writes it, a ``...List`` as
``calicoctl get ... -o json`` writes it, single objects, arrays of them, or several such documents one after the
other) holding ``Pod``, ``Namespace``, ``Service`` and ``ServiceAccount`` objects, ``NetworkPolicy`` of
``networking.k8s.io/v1``, and for Calico ``NetworkPolicy``, ``GlobalNetworkPolicy``, ``NetworkSet``,
``GlobalNetworkSet``, ``Tier`` and ``HostEndpoint`` of ``projectcalico.org/v3`` (or ``crd.projectcalico.org/v1``,
as ``kubectl get`` of the CRDs gives them). YAML is not read: the standard library has no YAML parser, and the pods
have to come from the cluster anyway (``kubectl ... -o json``). Two dialects: ``kubernetes`` reads the
NetworkPolicies only, ``calico`` reads them as Calico enforces them (in the default tier, order 1000) together with
Calico's own policies.

How the platform decides, and how that is mapped onto the neutral model:

* A policy applies to the pods its selector picks. A pod is isolated for ingress (egress) once a policy with that
  type applies to it. NetworkPolicy only allows: the rules of all policies that apply to a pod are one union, and
  what none allows is denied. Calico walks tiers in order, the policies of a tier by ``order`` (none: after the
  others; then by name), each policy's rules in order: Allow and Deny decide, Pass goes to the next tier, Log goes
  on. A tier that applies to the pod and decides nothing denies (``defaultAction: Pass`` passes); after the last
  tier the pod's profile allows, as for a pod no policy applies to.
* A connection between two pods needs the egress side of the source and the ingress side of the destination; a
  connection from outside the cluster the ingress side only, to outside the egress side only. Replies are allowed
  (connection tracking), as in the model.
* **A selector becomes the addresses of the pods it picks when the export was made: the model is a snapshot.** A pod
  that is created or moved later is not in it. Pods without an address and pods on the host network (policies do
  not apply to them) are left out.
* The model has no zones: a namespace has no interface and its pods' addresses mix with those of the others in the
  pod network. Namespaces, selectors and the pods each set of policies applies to are address groups.
* The model is one first-match list. For each set of pods with the same egress policies, its egress list; for each
  rule there that allows, the ingress list of every set of isolated pods cut to it, then the rule itself towards
  everything else. Then the ingress lists for connections from everywhere else. Then allow what is left to and from
  pods; what touches no pod is not the cluster's to decide and is denied by default. NetworkPolicy also always
  allows traffic between a pod and the node it runs on (``status.hostIP``): rules at the top.
* Ports: ``port`` with ``endPort`` is a range; a named port is the port of that name and protocol of the pod at the
  side it is matched on (the destination), so a rule with a named port becomes a rule per number. ``ipBlock`` is
  its CIDR without its exceptions, for every address (whether it matches pod addresses is the network plugin's
  matter, ``K8S_IPBLOCK_PODS``). Calico's nets, notNets, selectors, notSelectors, protocols, notProtocol, ports,
  notPorts, ICMP and notICMP are worked out as sets of addresses and services, exactly.
* What cannot be read (an unknown field, a selector that cannot be parsed, an HTTP match, a Service match) leaves
  its rule in the model with the reason in ``unsupported``; a policy whose selector cannot be read is not converted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from .. import regions, transform
from ..errors import ParseError
from ..model import ANY, Action, Address, AddressGroup, AddressKind, Policy, Protocol, Rule, Service, ServiceEntry
from ..netutil import FULL_V4, FULL_V6, Interval, intersect, interval_text, normalize, parse_literal, subtract
from ..report import Report, Severity

_K8S_API = "networking.k8s.io/v1"
_CALICO_APIS = ("projectcalico.org/v3", "crd.projectcalico.org/v1")
_DEFAULT_TIER_ORDER = 1_000_000.0
_KNP_ORDER = 1000.0  # where Calico puts a Kubernetes NetworkPolicy in the default tier (not documented)
_MAX_COMPOSED = 5000  # rules for connections between pods
_MAX_PIECES = 2000
_PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "sctp": 132, "udplite": 136}
_K8S_PROTOCOLS = {"TCP": Protocol.TCP, "UDP": Protocol.UDP, "SCTP": Protocol.SCTP}
_FULL = [FULL_V4, FULL_V6]
_NAME_KEYS = {"kubernetes.io/metadata.name", "projectcalico.org/name"}
_K8S_SPEC = {"podSelector", "policyTypes", "ingress", "egress"}
_K8S_RULE = {"from", "to", "ports"}
_K8S_PEER = {"podSelector", "namespaceSelector", "ipBlock"}
_K8S_PORT = {"protocol", "port", "endPort"}
_CALICO_SPEC = {"order", "tier", "selector", "types", "ingress", "egress", "doNotTrack", "preDNAT", "applyOnForward",
                "namespaceSelector", "serviceAccountSelector", "performanceHints"}  # fmt: skip
_CALICO_RULE = {"action", "protocol", "notProtocol", "icmp", "notICMP", "ipVersion", "source", "destination", "http", "metadata"}
_CALICO_ENTITY = {"nets", "notNets", "selector", "notSelector", "namespaceSelector", "ports", "notPorts", "serviceAccounts", "services"}


def _head(data: bytes) -> bytes:
    return data[:2_000_000].lstrip(b"\xef\xbb\xbf \t\r\n")


def looks_like_calico(data: bytes) -> bool:
    """JSON with Calico policy objects in it."""
    head = _head(data)
    if not head.startswith((b"{", b"[")):
        return False
    return re.search(rb'"(crd\.)?projectcalico\.org/v[13]"', head) is not None and \
        re.search(rb'"kind"\s*:\s*"(Global)?NetworkPolicy(List)?"', head) is not None  # fmt: skip


def looks_like_kubernetes(data: bytes) -> bool:
    """JSON of kubectl with NetworkPolicy objects of networking.k8s.io in it (and no Calico policies)."""
    head = _head(data)
    if not head.startswith((b"{", b"[")) or looks_like_calico(data):
        return False
    return b'"networking.k8s.io/v1"' in head and re.search(rb'"kind"\s*:\s*"NetworkPolicy"', head) is not None


# -- reading the documents ------------------------------------------------------------------------


def _documents(text: str) -> List[Any]:
    """Every JSON value in the text, one after the other."""
    decoder = json.JSONDecoder()
    out: List[Any] = []
    index, end = 0, len(text)
    while True:
        while index < end and text[index] in " \t\r\n﻿":
            index += 1
        if index >= end:
            return out
        value, index = decoder.raw_decode(text, index)
        out.append(value)


def _objects(value: Any, kind: str = "", api: str = "") -> Iterator[Dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            yield from _objects(item, kind, api)
        return
    if not isinstance(value, dict):
        return
    own = str(value.get("kind") or "")
    if isinstance(value.get("items"), list) and (own.endswith("List") or not own):
        inner = own[:-4] if own.endswith("List") and own != "List" else ""
        yield from _objects(value["items"], inner, str(value.get("apiVersion") or ""))
        return
    if not own and kind:
        value = dict(value, kind=kind)
    if not value.get("apiVersion") and api and api != "v1":
        value = dict(value, apiVersion=api)
    if value.get("kind"):
        yield value


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _labels(meta: Dict[str, Any]) -> Dict[str, str]:
    return {str(k): str(v) for k, v in _dict(meta.get("labels")).items()}


def _host(text: str) -> Optional[Interval]:
    interval = parse_literal(str(text or ""))
    if interval is None or interval[1] != interval[2] or "/" in str(text) or "-" in str(text):
        return None
    return interval


# -- the things selectors pick ---------------------------------------------------------------------


@dataclass
class _Pod:
    namespace: str
    name: str
    labels: Dict[str, str]
    ips: List[Interval]
    nodes: List[Interval]
    ports: Dict[str, List[Tuple[int, int]]]  # name -> (protocol number, port)
    account: str


@dataclass
class _NetSet:
    namespace: str  # "" for a GlobalNetworkSet or a HostEndpoint
    name: str
    labels: Dict[str, str]
    nets: List[Interval]
    kind: str


@dataclass
class _Namespace:
    name: str
    labels: Dict[str, str]
    known: bool  # False: made up from the pods, only its name is known


class _Bad(Exception):
    """Something of a policy that cannot be read."""


Predicate = Callable[[Dict[str, str]], bool]


def _k8s_selector(value: Any) -> Tuple[Predicate, Set[str]]:
    """A label selector of Kubernetes: the predicate and the label keys it reads."""
    if value is None:
        raise _Bad("a selector that is null")
    if not isinstance(value, dict):
        raise _Bad("a selector that is not an object")
    unknown = set(value) - {"matchLabels", "matchExpressions"}
    if unknown:
        raise _Bad(f"selector field {sorted(unknown)[0]}")
    wanted = {str(k): str(v) for k, v in _dict(value.get("matchLabels")).items()}
    tests: List[Predicate] = []
    keys = set(wanted)
    for item in value.get("matchExpressions") or []:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            raise _Bad("a match expression without a key")
        key, operator = item["key"], str(item.get("operator", ""))
        values = {str(v) for v in item.get("values") or []}
        keys.add(key)
        if operator == "In":
            tests.append(lambda labels, k=key, v=values: k in labels and labels[k] in v)  # type: ignore[misc]
        elif operator == "NotIn":
            tests.append(lambda labels, k=key, v=values: k not in labels or labels[k] not in v)  # type: ignore[misc]
        elif operator == "Exists":
            tests.append(lambda labels, k=key: k in labels)  # type: ignore[misc]
        elif operator == "DoesNotExist":
            tests.append(lambda labels, k=key: k not in labels)  # type: ignore[misc]
        else:
            raise _Bad(f"match expression operator '{operator[:20]}'")

    def predicate(labels: Dict[str, str]) -> bool:
        return all(labels.get(k) == v for k, v in wanted.items()) and all(test(labels) for test in tests)

    return predicate, keys


class _CalicoSelector:
    """Calico's selector expressions: ==, !=, has(), in {}, not in {}, contains, starts with, ends with, all(),
    global(), !, &&, || and parentheses."""

    _TOKEN = re.compile(r"\s*(?:(\|\||&&|==|!=|[!(){},])|'([^']*)'|\"([^\"]*)\"|([A-Za-z0-9_./-]+))")

    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens: List[Tuple[str, str]] = []
        position = 0
        stripped = text.rstrip()
        while position < len(stripped):
            found = self._TOKEN.match(stripped, position)
            if found is None or found.end() == position:
                raise _Bad(f"selector '{text[:80]}' cannot be read")
            position = found.end()
            if found.group(1):
                self.tokens.append(("op", found.group(1)))
            elif found.group(2) is not None or found.group(3) is not None:
                self.tokens.append(("str", found.group(2) if found.group(2) is not None else found.group(3)))
            else:
                self.tokens.append(("word", found.group(4)))
        self.index = 0
        self.keys: Set[str] = set()
        self.uses_global = False
        self.predicate = self._or() if self.tokens else self._everything
        if self.index != len(self.tokens):
            raise _Bad(f"selector '{text[:80]}' cannot be read")

    @staticmethod
    def _everything(labels: Dict[str, str], glob: bool = False) -> bool:
        return True

    def _peek(self) -> Tuple[str, str]:
        return self.tokens[self.index] if self.index < len(self.tokens) else ("end", "")

    def _take(self, kind: str, value: str = "") -> str:
        token = self._peek()
        if token[0] != kind or (value and token[1] != value):
            raise _Bad(f"selector '{self.text[:80]}' cannot be read")
        self.index += 1
        return token[1]

    def _or(self) -> Callable[..., bool]:
        parts = [self._and()]
        while self._peek() == ("op", "||"):
            self.index += 1
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda labels, glob=False: any(p(labels, glob) for p in parts))

    def _and(self) -> Callable[..., bool]:
        parts = [self._not()]
        while self._peek() == ("op", "&&"):
            self.index += 1
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda labels, glob=False: all(p(labels, glob) for p in parts))

    def _not(self) -> Callable[..., bool]:
        if self._peek() == ("op", "!"):
            self.index += 1
            inner = self._not()
            return lambda labels, glob=False: not inner(labels, glob)
        return self._atom()

    def _set(self) -> Set[str]:
        self._take("op", "{")
        values: Set[str] = set()
        while self._peek() != ("op", "}"):
            values.add(self._take("str"))
            if self._peek() == ("op", ","):
                self.index += 1
            elif self._peek() != ("op", "}"):
                raise _Bad(f"selector '{self.text[:80]}' cannot be read")
        self._take("op", "}")
        return values

    def _atom(self) -> Callable[..., bool]:
        kind, value = self._peek()
        if (kind, value) == ("op", "("):
            self.index += 1
            inner = self._or()
            self._take("op", ")")
            return inner
        word = self._take("word")
        if word in ("all", "global", "has") and self._peek() == ("op", "("):
            self.index += 1
            if word == "has":
                key = self._take("word")
                self._take("op", ")")
                self.keys.add(key)
                return lambda labels, glob=False: key in labels
            self._take("op", ")")
            if word == "all":
                return lambda labels, glob=False: not glob
            self.uses_global = True
            return lambda labels, glob=False: glob
        key = word
        self.keys.add(key)
        kind, value = self._peek()
        if (kind, value) == ("op", "=="):
            self.index += 1
            wanted = self._take("str")
            return lambda labels, glob=False: labels.get(key) == wanted
        if (kind, value) == ("op", "!="):
            self.index += 1
            wanted = self._take("str")
            return lambda labels, glob=False: labels.get(key) != wanted
        if (kind, value) == ("word", "in"):
            self.index += 1
            values = self._set()
            return lambda labels, glob=False: key in labels and labels[key] in values
        if (kind, value) == ("word", "not"):
            self.index += 1
            self._take("word", "in")
            values = self._set()
            return lambda labels, glob=False: key not in labels or labels[key] not in values
        if (kind, value) == ("word", "contains"):
            self.index += 1
            part = self._take("str")
            return lambda labels, glob=False: key in labels and part in labels[key]
        if (kind, value) in (("word", "starts"), ("word", "ends")):
            self.index += 1
            self._take("word", "with")
            part = self._take("str")
            if value == "starts":
                return lambda labels, glob=False: key in labels and labels[key].startswith(part)
            return lambda labels, glob=False: key in labels and labels[key].endswith(part)
        raise _Bad(f"selector '{self.text[:80]}' cannot be read")

    def __call__(self, labels: Dict[str, str], glob: bool = False) -> bool:
        return bool(self.predicate(labels, glob))


# -- policies as the parser holds them ---------------------------------------------------------------


@dataclass
class _Policy:
    kind: str  # "k8s", "calico", "global"
    namespace: str
    name: str
    tier: str
    order: Optional[float]
    types: Set[str]
    ingress: List[Any]
    egress: List[Any]
    applies: Callable[[_Pod], bool] = lambda pod: False
    label: str = ""  # how the report names it
    ids_key: str = ""  # "kubernetes" or "calico"


@dataclass
class _Entry:
    """One step of the list of a set of pods: what it matches (boxes), and what it does."""

    action: str  # "allow", "deny", "pass"
    boxes: List[regions.Box]
    name: str
    ids: Dict[str, str] = field(default_factory=dict)
    unsupported: List[str] = field(default_factory=list)
    description: str = ""
    catch_all: bool = False


@dataclass
class _Profile:
    direction: str  # "ingress" or "egress"
    policies: Tuple[int, ...]
    pods: List[_Pod]
    members: List[Interval] = field(default_factory=list)
    label: str = ""
    entries: List[_Entry] = field(default_factory=list)


class _Builder:
    def __init__(self, documents: List[Any], report: Report, dialect: str) -> None:
        self.report, self.dialect = report, dialect
        self.p = Policy(vendor=dialect)
        self.namespaces: Dict[str, _Namespace] = {}
        self.pods: List[_Pod] = []
        self.sets: List[_NetSet] = []
        self.accounts: Dict[Tuple[str, str], Dict[str, str]] = {}
        self.tiers: Dict[str, Tuple[float, str]] = {"default": (_DEFAULT_TIER_ORDER, "Deny")}
        self.policies: List[_Policy] = []
        self.services: List[Dict[str, Any]] = []
        self.host_endpoints = 0
        self.ignored: Dict[str, int] = {}
        self.rule_names: Set[str] = set()
        self.group_of: Dict[Tuple[Interval, ...], str] = {}
        self.pod_address: Dict[Interval, str] = {}
        self.taken: Set[str] = set()
        self.service_of: Dict[Tuple[Any, ...], Tuple[List[str], bool]] = {}
        self.taken_services: Set[str] = set()
        self.raw: List[Dict[str, Any]] = [obj for document in documents for obj in _objects(document)]
        self.composed = 0
        self.capped = False

    # -- names ------------------------------------------------------------------

    @staticmethod
    def _unique(name: str, taken: Set[str]) -> str:
        candidate, counter = name or "unnamed", 2
        while candidate.lower() in taken:
            candidate = f"{name}-{counter}"
            counter += 1
        taken.add(candidate.lower())
        return candidate

    def _group(self, intervals: List[Interval], label: str, description: str = "") -> str:
        """The address group that holds exactly these addresses: one there is, or a new one."""
        key = tuple(normalize(intervals))
        if key in self.group_of:
            return self.group_of[key]
        name = self._unique(label, self.taken)
        self.p.address_groups[name] = AddressGroup(name, self._literals(list(key)), description)
        self.group_of[key] = name
        return name

    def _literals(self, intervals: List[Interval]) -> List[str]:
        """Members for addresses: the pods by name where the addresses are theirs, else the addresses."""
        out: List[str] = []
        for version, first, last in intervals:
            hosts = [(version, n, n) for n in range(first, last + 1)] if last - first < 1024 else []
            if hosts and all(host in self.pod_address for host in hosts):
                out += [self.pod_address[host] for host in hosts]
            else:
                out.append(interval_text((version, first, last)))
        return out

    def _members(self, intervals: List[Interval], fallback: str) -> List[str]:
        if intervals == normalize(_FULL):
            return [ANY]
        key = tuple(normalize(intervals))
        if key in self.group_of:
            return [self.group_of[key]]
        literals = self._literals(list(key))
        if len(literals) <= 4:
            return literals
        return [self._group(list(key), fallback)]

    def _side(self, intervals: List[Interval], fallback: str) -> Tuple[List[str], bool]:
        """A side of a rule: the addresses, or everything but a group of addresses where that reads better."""
        found = normalize(intervals)
        rest = subtract(_FULL, found)
        if rest and found != normalize(_FULL) and (tuple(rest) in self.group_of and tuple(found) not in self.group_of
                                                   or len(rest) <= 4 < len(found)):  # fmt: skip
            return self._members(rest, fallback + " (not)"), True
        return self._members(found, fallback), False

    def _pod_names(self, pods: List[_Pod]) -> str:
        names = [f"{pod.namespace}/{pod.name}" for pod in pods]
        return ", ".join(names[:12]) + (f" and {len(names) - 12} more" if len(names) > 12 else "")

    # -- reading ------------------------------------------------------------------

    def build(self) -> Policy:
        policies = ("NetworkPolicy", "GlobalNetworkPolicy")
        for obj in self.raw:
            if str(obj.get("kind")) not in policies:
                self._read(obj)
        self._namespaces_from_pods()
        for obj in self.raw:
            if str(obj.get("kind")) in policies:
                self._read(obj)
        if not self.pods:
            raise ParseError("no pods with an address in the export: a policy picks pods by their labels, and without them nothing "
                             "can be converted. Export them with the policies: kubectl get networkpolicy,pod,namespace,service -A "
                             "-o json")  # fmt: skip
        if not self.policies:
            raise ParseError("no network policies in the export" + (" (Calico policies are read with --from calico)"
                                                                    if self.dialect == "kubernetes" and self._calico_seen() else ""))  # fmt: skip
        self._base_groups()
        profiles = {"ingress": self._profiles("ingress"), "egress": self._profiles("egress")}
        for direction in ("ingress", "egress"):
            for profile in profiles[direction]:
                self._program(profile)
        for direction in ("ingress", "egress"):
            self._name_profiles(profiles[direction])
        self._node_rules()
        self._compose(profiles)
        self._notes()
        return self.p

    def _calico_seen(self) -> bool:
        return any(str(o.get("apiVersion")) in _CALICO_APIS for o in self.raw)

    def _read(self, obj: Dict[str, Any]) -> None:
        kind, api = str(obj.get("kind")), str(obj.get("apiVersion") or "")
        meta = _dict(obj.get("metadata"))
        calico = api in _CALICO_APIS
        if kind == "Namespace" and not calico:
            name = str(meta.get("name") or "")
            labels = _labels(meta)
            labels.setdefault("kubernetes.io/metadata.name", name)
            self.namespaces[name] = _Namespace(name, labels, True)
        elif kind == "Pod" and not calico:
            self._pod(obj, meta)
        elif kind == "Service" and not calico:
            self.services.append(obj)
        elif kind == "ServiceAccount" and not calico:
            self.accounts[(str(meta.get("namespace") or ""), str(meta.get("name") or ""))] = _labels(meta)
        elif kind == "NetworkPolicy" and api == _K8S_API:
            self._k8s_policy(obj, meta)
        elif calico and kind in ("NetworkPolicy", "GlobalNetworkPolicy"):
            if self.dialect == "calico":
                self._calico_policy(obj, meta, kind)
            else:
                self.ignored[f"Calico {kind}"] = self.ignored.get(f"Calico {kind}", 0) + 1
        elif calico and kind in ("NetworkSet", "GlobalNetworkSet"):
            self._netset(obj, meta, kind)
        elif calico and kind == "HostEndpoint":
            self.host_endpoints += 1
            ips = [i for i in (_host(str(a)) for a in _dict(obj.get("spec")).get("expectedIPs") or []) if i is not None]
            self.sets.append(_NetSet("", str(meta.get("name") or ""), _labels(meta), ips, kind))
        elif calico and kind == "Tier":
            spec = _dict(obj.get("spec"))
            order = spec.get("order")
            action = str(spec.get("defaultAction") or "Deny")
            name = str(meta.get("name") or "")
            if name != "default":
                self.tiers[name] = (float(order) if isinstance(order, (int, float)) and not isinstance(order, bool)
                                    else _DEFAULT_TIER_ORDER, action)  # fmt: skip
            else:
                self.tiers[name] = (_DEFAULT_TIER_ORDER, action)
        else:
            label = kind if not calico else f"Calico {kind}"
            self.ignored[label] = self.ignored.get(label, 0) + 1

    def _pod(self, obj: Dict[str, Any], meta: Dict[str, Any]) -> None:
        spec, status = _dict(obj.get("spec")), _dict(obj.get("status"))
        namespace, name = str(meta.get("namespace") or "default"), str(meta.get("name") or "")
        if spec.get("hostNetwork"):
            self.ignored["Pod on the host network"] = self.ignored.get("Pod on the host network", 0) + 1
            return
        if str(status.get("phase") or "") in ("Succeeded", "Failed"):
            self.ignored["Pod that has ended"] = self.ignored.get("Pod that has ended", 0) + 1
            return
        texts = [str(item.get("ip") or "") for item in status.get("podIPs") or [] if isinstance(item, dict)]
        if not texts and status.get("podIP"):
            texts = [str(status["podIP"])]
        ips = [i for i in (_host(t) for t in texts) if i is not None]
        if len(ips) != len(texts):
            raise ParseError(f"pod {namespace}/{name}: an address that cannot be read ({', '.join(texts)[:80]})")
        if not ips:
            self.ignored["Pod without an address"] = self.ignored.get("Pod without an address", 0) + 1
            return
        nodes_text = [str(item.get("ip") or "") for item in status.get("hostIPs") or [] if isinstance(item, dict)]
        if not nodes_text and status.get("hostIP"):
            nodes_text = [str(status["hostIP"])]
        nodes = [i for i in (_host(t) for t in nodes_text) if i is not None]
        ports: Dict[str, List[Tuple[int, int]]] = {}
        for container in list(spec.get("containers") or []) + list(spec.get("initContainers") or []):
            for port in _dict(container).get("ports") or []:
                port = _dict(port)
                number = port.get("containerPort")
                protocol = _PROTOCOL_NUMBERS.get(str(port.get("protocol") or "TCP").lower())
                if port.get("name") and isinstance(number, int) and protocol:
                    ports.setdefault(str(port["name"]), []).append((protocol, number))
        account = str(spec.get("serviceAccountName") or spec.get("serviceAccount") or "default")
        self.pods.append(_Pod(namespace, name, _labels(meta), normalize(ips), normalize(nodes), ports, account))

    def _netset(self, obj: Dict[str, Any], meta: Dict[str, Any], kind: str) -> None:
        nets: List[Interval] = []
        for text in _dict(obj.get("spec")).get("nets") or []:
            interval = parse_literal(str(text))
            if interval is None or "/" not in str(text) and _host(str(text)) is None:
                raise ParseError(f"{kind} {meta.get('name')}: '{str(text)[:60]}' is not a CIDR")
            nets.append(interval)
        namespace = str(meta.get("namespace") or "") if kind == "NetworkSet" else ""
        self.sets.append(_NetSet(namespace, str(meta.get("name") or ""), _labels(meta), normalize(nets), kind))

    def _namespaces_from_pods(self) -> None:
        named = {str(_dict(o.get("metadata")).get("namespace") or "default") for o in self.raw if o.get("kind") == "NetworkPolicy"}
        missing = sorted({pod.namespace for pod in self.pods} - set(self.namespaces) | named - set(self.namespaces))
        for name in missing:
            self.namespaces[name] = _Namespace(name, {"kubernetes.io/metadata.name": name}, False)
        if missing:
            self.report.note(Severity.INFO if len(missing) < len(self.namespaces) else Severity.REVIEW, "K8S_NAMESPACE_MISSING",
                             "these namespaces are not in the export, only their names are known: " + ", ".join(missing[:10])
                             + (" ..." if len(missing) > 10 else "") + ". A rule whose namespace selector reads another label "
                             "is not converted; add the namespaces (kubectl get namespace -o json)")  # fmt: skip

    # -- policies -----------------------------------------------------------------

    def _k8s_policy(self, obj: Dict[str, Any], meta: Dict[str, Any]) -> None:
        spec = _dict(obj.get("spec"))
        namespace, name = str(meta.get("namespace") or "default"), str(meta.get("name") or "")
        types = {str(t) for t in spec.get("policyTypes") or []}
        if not types:
            # (What the API server would have filled in: kubectl get shows it; a file written by hand may not.)
            types = {"Ingress"} | ({"Egress"} if spec.get("egress") else set())
        policy = _Policy("k8s", namespace, name, "default", _KNP_ORDER, types, list(spec.get("ingress") or []),
                         list(spec.get("egress") or []), label=f"{namespace}/{name}", ids_key="kubernetes")  # fmt: skip
        problem = ""
        unknown = set(spec) - _K8S_SPEC
        if unknown:
            problem = f"field {sorted(unknown)[0]} of its spec is not known"
        elif types - {"Ingress", "Egress"}:
            problem = f"policy type {sorted(types - {'Ingress', 'Egress'})[0]}"
        else:
            try:
                predicate, _ = _k8s_selector(spec.get("podSelector", {}))
                policy.applies = lambda pod, ns=namespace, test=predicate: pod.namespace == ns and test(pod.labels)  # type: ignore[misc]
            except _Bad as error:
                problem = str(error)
        self._add_policy(policy, problem)

    def _add_policy(self, policy: _Policy, problem: str) -> None:
        if problem:
            self.report.note(Severity.REVIEW, "K8S_POLICY_NOT_CONVERTED",
                             f"policy {policy.label} is not converted: {problem}. The pods it applies to are not known; the "
                             "converted policy treats them as if it did not exist, which may allow more")  # fmt: skip
            return
        self.policies.append(policy)

    def _calico_policy(self, obj: Dict[str, Any], meta: Dict[str, Any], kind: str) -> None:
        spec = _dict(obj.get("spec"))
        name = str(meta.get("name") or "")
        namespace = str(meta.get("namespace") or "default") if kind == "NetworkPolicy" else ""
        tier = str(spec.get("tier") or "default")
        label = (f"{namespace}/" if namespace else "") + name
        if tier != "default" and not name.startswith(tier + "."):
            label = f"{tier}.{label}"
        order = spec.get("order")
        types = {str(t) for t in spec.get("types") or []}
        if not types:
            types = ({"Ingress"} if "ingress" in spec or "egress" not in spec else set()) | ({"Egress"} if "egress" in spec else set())
        policy = _Policy("calico" if namespace else "global", namespace, name, tier,
                         float(order) if isinstance(order, (int, float)) and not isinstance(order, bool) else None, types,
                         list(spec.get("ingress") or []), list(spec.get("egress") or []), label=label, ids_key="calico")  # fmt: skip
        if name.startswith("knp.default.") and any(p.kind == "k8s" and p.namespace == namespace and p.name == name[12:] for p in self.policies):
            return  # Calico's own copy of a Kubernetes policy that is in the export
        if order is not None and policy.order is None:
            self._add_policy(policy, f"order '{str(order)[:20]}' is not a number")
            return
        unknown = set(spec) - _CALICO_SPEC
        if unknown:
            self._add_policy(policy, f"field {sorted(unknown)[0]} of its spec is not known")
            return
        if types - {"Ingress", "Egress"}:
            self._add_policy(policy, f"type {sorted(types - {'Ingress', 'Egress'})[0]}")
            return
        if tier not in self.tiers and not any(str(o.get("kind")) == "Tier" and _dict(o.get("metadata")).get("name") == tier for o in self.raw):
            self._add_policy(policy, f"tier {tier} is not in the export, so where it stands is not known (add calicoctl get tier -o "
                             "json)")  # fmt: skip
            return
        if spec.get("doNotTrack") or spec.get("preDNAT"):
            self.report.note(Severity.INFO, "CALICO_HOST_ONLY",
                             f"policy {label} has doNotTrack or preDNAT: it applies to host endpoints only, which are not converted")  # fmt: skip
            return
        try:
            selector = _CalicoSelector(str(spec.get("selector") or "all()"))
            accounts = _CalicoSelector(str(spec.get("serviceAccountSelector") or "all()"))
            spaces = _CalicoSelector(str(spec.get("namespaceSelector") or "all()")) if not namespace else None
        except _Bad as error:
            self._add_policy(policy, str(error))
            return
        if accounts.keys - {"projectcalico.org/name"} and not self.accounts and \
                not any(str(o.get("kind")) == "ServiceAccount" for o in self.raw):  # fmt: skip
            self._add_policy(policy, "its service account selector reads labels of service accounts, which are not in the export")
            return
        if spaces is not None and spaces.keys - _NAME_KEYS and any(not ns.known for ns in self.namespaces.values()):
            self._add_policy(policy, "its namespace selector reads labels of namespaces that are not in the export")
            return

        def applies(pod: _Pod) -> bool:
            if namespace and pod.namespace != namespace:
                return False
            if spaces is not None and not spaces(self._namespace_labels(pod.namespace)):
                return False
            account = dict(self.accounts.get((pod.namespace, pod.account), {}), **{"projectcalico.org/name": pod.account})
            return selector(self._calico_labels(pod)) and accounts(account)

        policy.applies = applies
        if not namespace:
            hosts = [s.name for s in self.sets if s.kind == "HostEndpoint" and selector(s.labels)]
            if hosts:
                self.report.note(Severity.REVIEW, "CALICO_HOST_ENDPOINTS",
                                 f"global policy {label} applies to host endpoints as well ({', '.join(hosts[:5])}); what it does "
                                 "for them is not converted")  # fmt: skip
        self._add_policy(policy, "")

    def _namespace_labels(self, namespace: str) -> Dict[str, str]:
        found = self.namespaces.get(namespace)
        labels = dict(found.labels) if found else {"kubernetes.io/metadata.name": namespace}
        labels.setdefault("projectcalico.org/name", namespace)
        return labels

    def _calico_labels(self, pod: _Pod) -> Dict[str, str]:
        labels = dict(pod.labels)
        labels["projectcalico.org/namespace"] = pod.namespace
        labels["projectcalico.org/orchestrator"] = "k8s"
        labels["projectcalico.org/serviceaccount"] = pod.account
        for key, value in self._namespace_labels(pod.namespace).items():
            labels.setdefault(f"pcns.{key}", value)
        return labels

    # -- groups -------------------------------------------------------------------

    def _base_groups(self) -> None:
        for pod in self.pods:
            for interval in pod.ips:
                both = len({i[0] for i in pod.ips}) > 1
                name = self._unique(f"{pod.namespace}/{pod.name}" + ("-ipv6" if both and interval[0] == 6 else ""), self.taken)
                self.p.addresses[name] = Address(name, AddressKind.NETWORK, f"{interval_text(interval)}/{32 if interval[0] == 4 else 128}",
                                                 f"pod {pod.name} in namespace {pod.namespace}")  # fmt: skip
                self.pod_address[interval] = name
        everything = normalize([i for pod in self.pods for i in pod.ips])
        self.all_pods = everything
        for namespace in sorted({pod.namespace for pod in self.pods}):
            pods = [pod for pod in self.pods if pod.namespace == namespace]
            self._group([i for pod in pods for i in pod.ips], f"ns-{namespace}", "the pods of namespace " + namespace
                        + ": " + self._pod_names(pods))  # fmt: skip
        self.all_name = self._group(everything, "all-pods", f"every pod of the export ({len(self.pods)})")
        self.p.address_groups[self.all_name].builtin = "kubernetes"  # (a Kubernetes target takes it for the pods)

    # -- which policies apply to which pods -------------------------------------------

    def _sorted(self) -> List[int]:
        def key(index: int) -> Tuple[float, str, int, float, str, str]:
            policy = self.policies[index]
            order, _ = self.tiers.get(policy.tier, (_DEFAULT_TIER_ORDER, "Deny"))
            # (Calico names a Kubernetes policy knp.default.NAME; equal orders go by name, not confirmed with the namespace.)
            name = ("knp.default." if policy.kind == "k8s" else "") + policy.name
            return (order, policy.tier, policy.order is None, policy.order or 0.0, policy.namespace, name)

        return sorted(range(len(self.policies)), key=key)

    def _profiles(self, direction: str) -> List[_Profile]:
        wanted = "Ingress" if direction == "ingress" else "Egress"
        ordered = [i for i in self._sorted() if wanted in self.policies[i].types]
        by_key: Dict[Tuple[int, ...], _Profile] = {}
        for pod in self.pods:
            key = tuple(i for i in ordered if self.policies[i].applies(pod))
            if key not in by_key:
                by_key[key] = _Profile(direction, key, [])
            by_key[key].pods.append(pod)
        out = list(by_key.values())
        for profile in out:
            profile.members = normalize([i for pod in profile.pods for i in pod.ips])
        return out

    def _name_profiles(self, profiles: List[_Profile]) -> None:
        """A group for the pods of each set (after the selectors have theirs, which it may be)."""
        for profile in profiles:
            if not profile.policies:
                continue
            names = ", ".join(self.policies[i].label for i in profile.policies)
            spaces = sorted({pod.namespace for pod in profile.pods})
            if len(profile.pods) <= 3 and len(spaces) == 1:
                label = "pods " + spaces[0] + "/" + "+".join(pod.name for pod in profile.pods)
            else:
                label = f"{len(profile.pods)} pods in " + "+".join(spaces[:3]) + ("+..." if len(spaces) > 3 else "")
            profile.label = self._group(profile.members, label[:120], f"the pods the {profile.direction} policies {names} "
                                        "apply to: " + self._pod_names(profile.pods))  # fmt: skip

    # -- the list of a set of pods ------------------------------------------------------

    def _program(self, profile: _Profile) -> None:
        """The ordered list of what the policies of a set of pods do in one direction, ending with a decision."""
        entries: List[_Entry] = []
        tiers: List[str] = []
        for index in profile.policies:
            if self.policies[index].tier not in tiers:
                tiers.append(self.policies[index].tier)
        everything = self._catch_all(profile)
        for tier in tiers:
            passes: List[regions.Box] = []
            for index in profile.policies:
                policy = self.policies[index]
                if policy.tier != tier:
                    continue
                rules = policy.ingress if profile.direction == "ingress" else policy.egress
                for number, raw in enumerate(rules, 1):
                    entry = self._rule(policy, profile, raw, number)
                    if entry is None:
                        continue
                    if passes:
                        cut = regions.minus_all(entry.boxes, passes, limit=_MAX_PIECES)
                        if cut is None:
                            entry.unsupported.append("what a Pass rule above it in its tier takes away is too complex to work out")
                        else:
                            entry.boxes = cut
                    if entry.action == "pass":
                        passes += entry.boxes
                        continue
                    if entry.boxes and self._decides(entry, entries, everything, passes):
                        entries.append(entry)
            _, default = self.tiers.get(tier, (_DEFAULT_TIER_ORDER, "Deny"))
            if default != "Pass":
                left = regions.minus_all(everything, passes, limit=_MAX_PIECES)
                end = _Entry("deny", left if left is not None else everything, f"{tier} tier end/{profile.direction}",
                             description=f"the end of tier {tier}: what the policies there do not decide is denied",
                             catch_all=not passes)  # fmt: skip
                if left is None:
                    end.unsupported.append("what the Pass rules of the tier take away is too complex to work out")
                if end.boxes and self._decides(end, entries, everything, []):
                    entries.append(end)
                if not passes:
                    break  # (nothing goes on to the next tier)
        else:
            last = _Entry("allow", everything, f"profile/{profile.direction}", catch_all=True,
                          description="what the tiers pass on is allowed (the pod's profile)")  # fmt: skip
            if self._decides(last, entries, everything, []):
                entries.append(last)
        if self.dialect == "kubernetes" or all(self.policies[i].kind == "k8s" for i in profile.policies):
            for entry in entries:
                if entry.name.startswith("default tier end/"):
                    entry.name = f"isolated/{profile.direction}"
                    entry.description = f"the pods are isolated for {profile.direction}: what no policy allows is denied"
        profile.entries = entries

    @staticmethod
    def _decides(entry: _Entry, before: List[_Entry], everything: List[regions.Box], passes: List[regions.Box]) -> bool:
        """Whether a step decides anything the steps before it (and the Pass rules of its tier) have not; one that
        decides all that is left is marked as the end of the list."""
        # (A step that is not converted does not count: a target leaves it out, and the steps after it decide.)
        left = regions.minus_all(everything, [b for e in before if not e.unsupported for b in e.boxes] + passes, limit=_MAX_PIECES)
        if left is None:
            return True
        if not any(regions.box_and(x, y) is not None for x in left for y in entry.boxes):
            return False
        if not entry.unsupported and regions.minus_all(left, entry.boxes, limit=_MAX_PIECES) == []:
            entry.catch_all = True
        return True

    def _catch_all(self, profile: _Profile) -> List[regions.Box]:
        out: List[regions.Box] = []
        for version in (4, 6):
            mine = regions.addresses(profile.members, version)
            if not mine:
                continue
            full = [regions.full(version)]
            out.append((version, full, mine, regions.ALL_SERVICES) if profile.direction == "ingress"
                       else (version, mine, full, regions.ALL_SERVICES))  # fmt: skip
        return out

    def _rule(self, policy: _Policy, profile: _Profile, raw: Any, number: int) -> Optional[_Entry]:
        direction = profile.direction
        base = f"{policy.label}/{direction}-{number}"
        ids = {f"{policy.ids_key}.{direction}_rule": f"{policy.label} {direction} {number}"}
        if not isinstance(raw, dict):
            return _Entry("allow", [], base, ids, ["a rule that is not an object"])
        if policy.kind == "k8s":
            return self._k8s_rule(policy, profile, raw, base, ids)
        return self._calico_rule(policy, profile, raw, base, ids)

    def _boxes(self, src: List[Interval], dst: List[Interval], svc: regions.Services) -> List[regions.Box]:
        out: List[regions.Box] = []
        for version in (4, 6):
            s, d = regions.addresses(src, version), regions.addresses(dst, version)
            if s and d and not svc.empty():
                found = regions.entries_of(svc, version)
                if found is not None and not found[0] and not found[1]:
                    continue  # (only the ICMP of the other IP version)
                out.append((version, s, d, svc))
        return out

    def _sides(self, profile: _Profile, peers: List[Interval]) -> Tuple[List[Interval], List[Interval]]:
        return (peers, profile.members) if profile.direction == "ingress" else (profile.members, peers)

    def _named(self, profile: _Profile, peers: List[Interval], name: str, protocol: int,
               src_ports: str = "") -> List[regions.Box]:  # fmt: skip
        """A named destination port: the port of that name and protocol of each pod on the destination side."""
        pods = profile.pods if profile.direction == "ingress" else [pod for pod in self.pods if intersect(pod.ips, peers)]
        by_number: Dict[int, List[Interval]] = {}
        for pod in pods:
            for kind, port in pod.ports.get(name, []):
                if kind == protocol:
                    by_number.setdefault(port, []).extend(pod.ips)
        out: List[regions.Box] = []
        kind_name = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP}[protocol]
        for port, ips in sorted(by_number.items()):
            svc = regions.service_set([ServiceEntry(kind_name, dst_ports=str(port), src_ports=src_ports)])
            if svc is None:
                continue
            src, dst = self._sides(profile, peers)
            dst = intersect(dst, normalize(ips))
            out += self._boxes(src, dst, svc)
        return out

    # -- Kubernetes rules ----------------------------------------------------------------

    def _k8s_rule(self, policy: _Policy, profile: _Profile, raw: Dict[str, Any], base: str, ids: Dict[str, str]) -> _Entry:
        problems: List[str] = []
        unknown = set(raw) - _K8S_RULE
        if unknown:
            problems.append(f"field {sorted(unknown)[0]} of the rule is not known")
        peers_raw = raw.get("from" if profile.direction == "ingress" else "to")
        peers: List[Interval] = []
        described: List[str] = []
        if not peers_raw:
            peers = list(_FULL)
        else:
            for peer in peers_raw if isinstance(peers_raw, list) else [peers_raw]:
                found, text, problem = self._k8s_peer(policy, peer)
                if problem:
                    problems.append(problem)
                    found = list(_FULL)
                peers += found
                described.append(text)
            peers = normalize(peers)
        unnamed: List[regions.Services] = []
        named: List[Tuple[str, int]] = []
        ports_raw = raw.get("ports")
        if not ports_raw:
            unnamed.append(regions.ALL_SERVICES)
        else:
            for port in ports_raw if isinstance(ports_raw, list) else [ports_raw]:
                found_svc, port_name, problem = self._k8s_port(port)
                if problem:
                    problems.append(problem)
                    unnamed.append(regions.ALL_SERVICES)
                elif port_name:
                    named.append(port_name)
                elif found_svc is not None:
                    unnamed.append(found_svc)
        boxes: List[regions.Box] = []
        if unnamed:
            union = regions.ALL_SERVICES if any(s.everything() for s in unnamed) else _union(unnamed)
            src, dst = self._sides(profile, peers)
            boxes += self._boxes(src, dst, union)
        unresolved = []
        for name, protocol in named:
            found_boxes = self._named(profile, peers, name, protocol)
            if not found_boxes:
                unresolved.append(name)
            boxes += found_boxes
        entry = _Entry("allow", boxes, base, ids, problems,
                       f"{policy.label} {profile.direction} rule" + (": " + "; ".join(described) if described else ""))  # fmt: skip
        if unresolved:
            self.report.note(Severity.INFO, "K8S_NAMED_PORT_UNRESOLVED",
                             f"{policy.label}: named port {', '.join(sorted(set(unresolved)))} of a {profile.direction} rule is "
                             "the port of no pod it could apply to; that part of the rule allows nothing")  # fmt: skip
        if any(self._ipblock_holds_pods(_dict(p).get("ipBlock")) for p in _list(peers_raw) if "ipBlock" in _dict(p)):
            self.report.note(Severity.REVIEW, "K8S_IPBLOCK_PODS",
                             f"{policy.label}: an ipBlock of a {profile.direction} rule holds pod addresses. Whether an ipBlock "
                             "matches pods depends on the network plugin (the Kubernetes documentation says it is meant for "
                             "addresses outside the cluster); FWShift reads it as matching every address in it")  # fmt: skip
        return entry

    def _ipblock_holds_pods(self, block: Any) -> bool:
        interval = parse_literal(str(_dict(block).get("cidr") or ""))
        return interval is not None and bool(intersect([interval], self.all_pods))

    def _k8s_peer(self, policy: _Policy, peer: Any) -> Tuple[List[Interval], str, str]:
        """(the addresses of a peer, how to describe it, why it cannot be read)."""
        if not isinstance(peer, dict) or not peer:
            return [], "", "a peer that is empty or not an object"
        unknown = set(peer) - _K8S_PEER
        if unknown:
            return [], "", f"field {sorted(unknown)[0]} of a peer is not known"
        if "ipBlock" in peer:
            if len(peer) > 1:
                return [], "", "a peer with an ipBlock and a selector (the API refuses it)"
            block = _dict(peer["ipBlock"])
            text = str(block.get("cidr") or "")
            whole = parse_literal(text)
            if whole is None or "/" not in text:
                return [], "", f"ipBlock CIDR '{text[:60]}' cannot be read"
            excepts: List[Interval] = []
            for item in block.get("except") or []:
                cut = parse_literal(str(item))
                if cut is None or "/" not in str(item) or cut[0] != whole[0] or intersect([cut], [whole]) != [cut]:
                    return [], "", f"ipBlock exception '{str(item)[:60]}' is not a CIDR inside {text}"
                excepts.append(cut)
            return subtract([whole], excepts), f"ipBlock {text}" + (f" except {len(excepts)}" if excepts else ""), ""
        try:
            if "namespaceSelector" in peer:
                spaces, keys = _k8s_selector(peer["namespaceSelector"])
                if keys - _NAME_KEYS and any(not ns.known for ns in self.namespaces.values()):
                    return [], "", "a namespace selector that reads labels of namespaces that are not in the export"
                chosen = {name for name, ns in self.namespaces.items() if spaces(ns.labels)}
            else:
                chosen = {policy.namespace}
            pods_test, _ = _k8s_selector(peer.get("podSelector", {}))
        except _Bad as error:
            return [], "", str(error)
        pods = [pod for pod in self.pods if pod.namespace in chosen and pods_test(pod.labels)]
        found = normalize([i for pod in pods for i in pod.ips])
        text = _describe_peer(peer, policy.namespace)
        if found:
            self._group(found, text[:120], "the pods of " + text + ": " + self._pod_names(pods))
        return found, text, ""

    @staticmethod
    def _k8s_port(port: Any) -> Tuple[Optional[regions.Services], Optional[Tuple[str, int]], str]:
        if not isinstance(port, dict):
            return None, None, "a port that is not an object"
        unknown = set(port) - _K8S_PORT
        if unknown:
            return None, None, f"field {sorted(unknown)[0]} of a port is not known"
        protocol_text = str(port.get("protocol") or "TCP")
        if protocol_text not in _K8S_PROTOCOLS:
            return None, None, f"protocol '{protocol_text[:20]}' (TCP, UDP or SCTP)"
        protocol = _K8S_PROTOCOLS[protocol_text]
        value, end = port.get("port"), port.get("endPort")
        if value is None:
            if end is not None:
                return None, None, "endPort without port (the API refuses it)"
            return regions.service_set([ServiceEntry(protocol)]), None, ""
        if isinstance(value, str) and not value.isdigit():
            if end is not None:
                return None, None, "endPort with a named port (the API refuses it)"
            return None, (value, {Protocol.TCP: 6, Protocol.UDP: 17, Protocol.SCTP: 132}[protocol]), ""
        try:
            first = int(value)
            last = int(end) if end is not None else first
        except (TypeError, ValueError):
            return None, None, f"port '{str(value)[:20]}' cannot be read"
        if isinstance(value, bool) or isinstance(end, bool) or not 1 <= first <= last <= 65535:
            return None, None, f"ports {value}-{end} cannot be read"
        return regions.service_set([ServiceEntry(protocol, dst_ports=str(first) if first == last else f"{first}-{last}")]), None, ""

    # -- Calico rules ----------------------------------------------------------------------

    def _calico_rule(self, policy: _Policy, profile: _Profile, raw: Dict[str, Any], base: str, ids: Dict[str, str]) -> Optional[_Entry]:
        action = str(raw.get("action") or "")
        problems: List[str] = []
        unknown = set(raw) - _CALICO_RULE
        if unknown:
            problems.append(f"field {sorted(unknown)[0]} of the rule is not known")
        if action == "Log":
            self.report.note(Severity.INFO, "CALICO_LOG_RULE",
                             f"{policy.label}: a {profile.direction} rule with action Log only logs and goes on; it is left out")  # fmt: skip
            return None
        if action not in ("Allow", "Deny", "Pass"):
            problems.append(f"action '{action[:20]}'")
            action = "Deny"
        if raw.get("http"):
            problems.append("an HTTP match (application layer policy)")
        svc, named, svc_problems = self._calico_services(raw)
        problems += svc_problems
        src, src_text, more = self._entity(policy, raw.get("source"), "source")
        problems += more
        dst, dst_text, more = self._entity(policy, raw.get("destination"), "destination")
        problems += more
        version = raw.get("ipVersion")
        if version is not None:
            if version not in (4, 6):
                problems.append(f"ipVersion '{str(version)[:10]}'")
            else:
                full = [regions.full(int(version))]
                src, dst = intersect(src, full), intersect(dst, full)
        if profile.direction == "ingress":
            dst = intersect(dst, profile.members)
        else:
            src = intersect(src, profile.members)
        boxes = self._boxes(src, dst, svc) if svc is not None else []
        for name, protocol, src_ports in named:
            pods = profile.pods if profile.direction == "ingress" else [pod for pod in self.pods if intersect(pod.ips, dst)]
            for port, ips in self._named_numbers(pods, name, protocol).items():
                found = regions.service_set([ServiceEntry({6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP}[protocol],
                                                          dst_ports=str(port), src_ports=src_ports)])  # fmt: skip
                if found is not None:
                    boxes += self._boxes(src, intersect(dst, ips), found)
        description = f"{policy.label} {profile.direction} rule ({action})"
        if src_text or dst_text:
            description += ": " + "; ".join(t for t in (src_text, dst_text) if t)
        return _Entry({"Allow": "allow", "Deny": "deny", "Pass": "pass"}[action], boxes, base, ids, problems, description)

    @staticmethod
    def _named_numbers(pods: List[_Pod], name: str, protocol: int) -> Dict[int, List[Interval]]:
        out: Dict[int, List[Interval]] = {}
        for pod in pods:
            for kind, port in pod.ports.get(name, []):
                if kind == protocol:
                    out.setdefault(port, []).extend(pod.ips)
        return {port: normalize(ips) for port, ips in out.items()}

    def _calico_services(self, raw: Dict[str, Any]) -> Tuple[Optional[regions.Services], List[Tuple[str, int, str]], List[str]]:
        """What a rule's protocol, ports and ICMP match: (the set for numeric ports, named destination ports, problems)."""
        problems: List[str] = []
        protocol = _protocol(raw.get("protocol"), problems)
        negated = _protocol(raw.get("notProtocol"), problems)
        source, destination = _dict(raw.get("source")), _dict(raw.get("destination"))
        ports = {"sports": _calico_ports(source.get("ports"), problems), "dports": _calico_ports(destination.get("ports"), problems)}
        ports["snot"] = _calico_ports(source.get("notPorts"), problems)
        ports["dnot"] = _calico_ports(destination.get("notPorts"), problems)
        has_ports = any(numbers or names for numbers, names in ports.values())
        named: List[Tuple[str, int, str]] = []
        if has_ports and protocol not in (6, 17, 132):
            if protocol == 136:
                problems.append("ports of UDPLite, which the model cannot hold")
            else:
                problems.append(f"ports with protocol {protocol or 'none'} (ports need TCP, UDP or SCTP)")
            return regions.ALL_SERVICES if protocol is None else _number_set(protocol), [], problems
        if ports["sports"][1] or ports["snot"][1] or ports["dnot"][1]:
            problems.append("a named port as a source port or in notPorts")
        if raw.get("icmp") is not None or raw.get("notICMP") is not None:
            if protocol not in (1, 58):
                problems.append("ICMP fields without protocol ICMP or ICMPv6")
        if protocol is None:
            svc = regions.ALL_SERVICES
        elif protocol in (6, 17, 132):
            kind = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP}[protocol]
            sports, dports = ",".join(ports["sports"][0]), ",".join(ports["dports"][0])
            if ports["dports"][1]:
                named = [(name, protocol, sports) for name in ports["dports"][1]]
            if ports["dports"][1] and not dports:
                svc = regions.Services()
            else:
                found = regions.service_set([ServiceEntry(kind, dst_ports=dports, src_ports=sports)])
                svc = found if found is not None else regions.Services()
            for key, side in (("snot", "src"), ("dnot", "dst")):
                if ports[key][0]:
                    spec = ",".join(ports[key][0])
                    cut = regions.service_set([ServiceEntry(kind, dst_ports=spec if side == "dst" else "",
                                                            src_ports=spec if side == "src" else "")])  # fmt: skip
                    if cut is not None:
                        svc = svc.minus(cut)
        elif protocol in (1, 58):
            kind = Protocol.ICMP if protocol == 1 else Protocol.ICMP6
            svc = _icmp_set(kind, raw.get("icmp"), problems) or regions.Services()
            if raw.get("notICMP") is not None:
                cut = _icmp_set(kind, raw.get("notICMP"), problems)
                if cut is not None:
                    svc = svc.minus(cut)
        else:
            svc = _number_set(protocol)
        if negated is not None:
            svc = svc.minus(_number_set(negated))
        return svc, named, problems

    def _entity(self, policy: _Policy, raw: Any, side: str) -> Tuple[List[Interval], str, List[str]]:
        """The addresses a source or destination of a Calico rule matches, a description, problems."""
        if raw is None:
            return list(_FULL), "", []
        if not isinstance(raw, dict):
            return list(_FULL), "", [f"a {side} that is not an object"]
        problems: List[str] = []
        unknown = set(raw) - _CALICO_ENTITY
        if unknown:
            problems.append(f"field {sorted(unknown)[0]} of the {side} is not known")
        found = list(_FULL)
        parts: List[str] = []
        nets = _nets(raw.get("nets"), problems)
        if nets is not None:
            found = intersect(found, nets)
            parts.append("nets " + ", ".join(str(n) for n in raw.get("nets") or [])[:80])
        not_nets = _nets(raw.get("notNets"), problems)
        if not_nets is not None:
            found = subtract(found, not_nets)
            parts.append("not nets " + ", ".join(str(n) for n in raw.get("notNets") or [])[:80])
        try:
            spaces = _CalicoSelector(str(raw["namespaceSelector"])) if raw.get("namespaceSelector") else None
            selector = _CalicoSelector(str(raw["selector"])) if raw.get("selector") else None
            negated = _CalicoSelector(str(raw["notSelector"])) if raw.get("notSelector") else None
        except _Bad as error:
            return list(_FULL), "", problems + [str(error)]
        if spaces is not None and spaces.keys - _NAME_KEYS and any(not ns.known for ns in self.namespaces.values()):
            problems.append("a namespace selector that reads labels of namespaces that are not in the export")
        if spaces is not None or selector is not None:
            chosen = self._scope_addresses(policy, spaces, selector or _CalicoSelector("all()"))
            found = intersect(found, chosen)
            parts.append(" ".join(t for t in (f"namespaces {raw['namespaceSelector']}" if spaces else "",
                                               f"selector {raw['selector']}" if selector else "") if t))  # fmt: skip
            if selector is not None and chosen:
                self._group(chosen, f"{policy.namespace + '/' if policy.namespace and spaces is None else ''}{raw['selector']}"[:120],
                            f"what selector {raw['selector']} picks for policy {policy.label}")  # fmt: skip
        if negated is not None:
            found = subtract(found, self._scope_addresses(policy, spaces, negated))
            parts.append(f"not selector {raw['notSelector']}")
        accounts = _dict(raw.get("serviceAccounts"))
        if accounts:
            names = {str(n) for n in accounts.get("names") or []}
            try:
                account_test = _CalicoSelector(str(accounts["selector"])) if accounts.get("selector") else None
            except _Bad as error:
                problems.append(str(error))
                account_test = None
            if account_test is not None and account_test.keys - {"projectcalico.org/name"} and not self.accounts:
                problems.append("a service account selector that reads labels of service accounts not in the export")
            pods = [pod for pod in self._scope_pods(policy, spaces)
                    if (not names or pod.account in names)
                    and (account_test is None or account_test(dict(self.accounts.get((pod.namespace, pod.account), {}),
                                                                   **{"projectcalico.org/name": pod.account})))]  # fmt: skip
            found = intersect(found, normalize([i for pod in pods for i in pod.ips]))
            parts.append("service accounts")
        if raw.get("services"):
            problems.append(f"a match on a Service in the {side} (needs its endpoints, which are not worked out)")
        return normalize(found), " ".join(p for p in parts if p), problems

    def _scope_pods(self, policy: _Policy, spaces: Optional[_CalicoSelector]) -> List[_Pod]:
        if spaces is not None:
            return [pod for pod in self.pods if spaces(self._namespace_labels(pod.namespace))]
        if policy.namespace:
            return [pod for pod in self.pods if pod.namespace == policy.namespace]
        return list(self.pods)

    def _scope_addresses(self, policy: _Policy, spaces: Optional[_CalicoSelector], selector: _CalicoSelector) -> List[Interval]:
        """The addresses of what a selector picks in the scope of a rule: pods, network sets and host endpoints."""
        found: List[Interval] = []
        for pod in self._scope_pods(policy, spaces):
            if selector(self._calico_labels(pod)):
                found += pod.ips
        for item in self.sets:
            if item.namespace:
                if spaces is not None:
                    inside = spaces(self._namespace_labels(item.namespace))
                else:
                    inside = not policy.namespace or item.namespace == policy.namespace
            else:
                inside = spaces(self._namespace_labels(""), True) if spaces is not None else not policy.namespace
            if inside and selector(item.labels):
                found += item.nets
        return normalize(found)

    # -- the model --------------------------------------------------------------------------

    def _node_rules(self) -> None:
        """NetworkPolicy always allows traffic between a pod and the node it runs on."""
        if self.dialect != "kubernetes":
            return
        by_node: Dict[Interval, List[_Pod]] = {}
        for pod in self.pods:
            for node in pod.nodes:
                by_node.setdefault(node, []).append(pod)
        for node, pods in sorted(by_node.items()):
            mine = normalize([i for pod in pods for i in pod.ips])
            node_name = interval_text(node)
            group = self._group(mine, f"pods on node {node_name}", f"the pods on node {node_name}: " + self._pod_names(pods))
            for word, src, dst in (("to", [node_name], [group]), ("from", [group], [node_name])):
                rule = self._new_rule(f"node {node_name} {word} its pods" if word == "to" else f"pods {word} node {node_name}"[:120])
                rule.sources, rule.destinations = src, dst
                rule.description = "traffic between a pod and the node it runs on is always allowed"

    def _new_rule(self, base: str) -> Rule:
        rule = Rule(self._unique(base, self.rule_names))
        rule.origin = rule.name
        rule.log_end = False
        self.p.rules.append(rule)
        return rule

    def _service(self, svc: regions.Services) -> Optional[Tuple[List[str], bool]]:
        """The services a set of the model's services is written as: (names, negated); None for nothing."""
        if svc.everything():
            return [ANY], False
        key = (tuple(sorted((n, tuple(sorted(r))) for n, r in svc.protocols.items())), svc.rest)
        if key in self.service_of:
            return self.service_of[key]
        entries: List[ServiceEntry] = []
        negated = svc.rest
        for version in (4, 6):
            found = regions.entries_of(svc, version)
            if found is None:
                return None
            entries += [e for e in found[0] if e not in entries]
        if not entries:
            out: Tuple[List[str], bool] = ([ANY], False) if negated else ([], False)
        else:
            label = "+".join(_entry_label(e) for e in entries[:4]) + ("+more" if len(entries) > 4 else "")
            name = self._unique(("not " if negated else "") + label, self.taken_services)
            self.p.services[name] = Service(name, entries)
            out = ([name], negated)
        self.service_of[key] = out
        return out

    def _write(self, action: str, boxes: List[regions.Box], name: str, ids: Dict[str, str], unsupported: List[str],
               description: str) -> int:  # fmt: skip
        """Model rules for boxes: one per box, a box of each IP version with the same services together."""
        written = 0
        pending: Dict[Tuple[Any, ...], List[regions.Box]] = {}
        for box in boxes:
            if regions.empty(box):
                continue
            key = (tuple(sorted((n, tuple(sorted(r))) for n, r in box[3].protocols.items())), box[3].rest)
            pending.setdefault(key, []).append(box)
        for group in pending.values():
            fours = [b for b in group if b[0] == 4]
            sixes = [b for b in group if b[0] == 6]
            pairs: List[List[regions.Box]] = []
            for index in range(max(len(fours), len(sixes))):
                pairs.append([b for b in (fours[index] if index < len(fours) else None, sixes[index] if index < len(sixes) else None) if b])
            for pair in pairs:
                services = self._service(pair[0][3])
                if services is None:
                    unsupported = unsupported + ["a service with too many ICMP types and codes"]
                    services = ([ANY], False)
                if not services[0]:
                    continue
                rule = self._new_rule(name)
                rule.action = Action.ALLOW if action == "allow" else Action.DROP
                src = [i for box in pair for i in box[1]]
                dst = [i for box in pair for i in box[2]]
                rule.sources, rule.negate_source = self._side(src, f"{rule.name} sources")
                rule.destinations, rule.negate_destination = self._side(dst, f"{rule.name} destinations")
                rule.services, rule.negate_service = services
                rule.unsupported = transform.dedupe(list(unsupported))
                rule.source_ids = dict(ids)
                rule.description = description[:1000]
                written += 1
        return written

    def _compose(self, profiles: Dict[str, List[_Profile]]) -> None:
        closed_in = [p for p in profiles["ingress"] if p.policies]
        closed_out = [p for p in profiles["egress"] if p.policies]
        isolated = normalize([i for p in closed_in for i in p.members])
        for egress in closed_out:
            entries = list(egress.entries)
            if entries and entries[-1].catch_all and entries[-1].action == "allow":
                entries.pop()  # (what falls through is decided by the ingress side below)
            for entry in entries:
                where = f" (from {egress.label})"
                if entry.action == "deny":
                    self._write("deny", entry.boxes, entry.name, entry.ids, entry.unsupported, entry.description + where)
                    continue
                if not self._composed(entry, closed_in, where):
                    continue
                rest = [b for b in (_box_dst_minus(box, isolated) for box in entry.boxes) if b is not None]
                self._write("allow", rest, entry.name, entry.ids, entry.unsupported, entry.description + where
                            + ", to what no ingress policy isolates")  # fmt: skip
        for ingress in closed_in:
            entries = list(ingress.entries)
            if entries and entries[-1].catch_all and entries[-1].action == "allow":
                entries.pop()
            for entry in entries:
                self._write(entry.action, entry.boxes, entry.name, entry.ids, entry.unsupported,
                            entry.description + f" (to {ingress.label})")  # fmt: skip
        for word, src, dst in (("from", self.all_name, ANY), ("to", ANY, self.all_name)):
            rule = self._new_rule(f"not isolated: {word} pods")
            rule.sources, rule.destinations = [src], [dst]
            rule.description = "what no policy decides is allowed to and from pods"

    def _composed(self, entry: _Entry, closed_in: List[_Profile], where: str) -> bool:
        """An egress rule that allows, with the ingress lists of the isolated pods it reaches cut to it. False when
        that is too much: then the rule blocks instead, which allows less."""
        planned: List[Tuple[str, List[regions.Box], _Entry]] = []
        remaining = entry.boxes  # (what the ingress lists have not decided yet: a step that meets none of it is left out)
        for ingress in closed_in:
            for other in ingress.entries:
                if not any(regions.box_and(x, y) is not None for x in remaining for y in other.boxes):
                    continue
                both = [b for x in entry.boxes for y in other.boxes for b in [regions.box_and(x, y)] if b is not None]
                planned.append((other.action, both, other))
                cut = None if other.unsupported else regions.minus_all(remaining, other.boxes, limit=_MAX_PIECES)
                if cut is not None:
                    remaining = cut
        if self.composed + len(planned) > _MAX_COMPOSED:
            self.capped = True
            self._write("deny", entry.boxes, entry.name, entry.ids, entry.unsupported,
                        entry.description + where + " -- blocked: too many rules to work out what the ingress side allows")  # fmt: skip
            return False
        for action, both, other in planned:
            ids = dict(entry.ids, **other.ids)
            self.composed += self._write(action, both, f"{entry.name} + {other.name}", ids,
                                         transform.dedupe(entry.unsupported + other.unsupported),
                                         f"{entry.description}{where}; {other.description}")  # fmt: skip
        return True

    def _notes(self) -> None:
        self.report.note(Severity.REVIEW, "K8S_SNAPSHOT",
                         f"the selectors were worked out for the {len(self.pods)} pods of the export: every rule names the addresses "
                         "those pods had then. Pods created, deleted or moved since, and new labels, are not in it")  # fmt: skip
        if self.ignored:
            self.report.note(Severity.INFO, "K8S_IGNORED",
                             "left out: " + ", ".join(f"{count} {kind}" for kind, count in sorted(self.ignored.items()))
                             + ". Policies do not apply to pods on the host network, nor to pods without an address")  # fmt: skip
        if self.dialect == "kubernetes" and any(k.startswith("Calico ") and "Policy" in k for k in self.ignored):
            self.report.note(Severity.REVIEW, "K8S_CALICO_IGNORED",
                             "the export holds Calico policies; --from kubernetes reads the NetworkPolicies only. Read it with "
                             "--from calico to have them as Calico enforces them")  # fmt: skip
        external = [s for s in self.services if str(_dict(s.get("spec")).get("type") or "ClusterIP") in ("NodePort", "LoadBalancer")]
        if self.services:
            self.report.note(Severity.REVIEW if external else Severity.INFO, "K8S_SERVICES",
                             "Services are not converted: kube-proxy translates a Service's address to a pod's before the policy "
                             "sees the connection, and the rules name pod addresses"
                             + (". Traffic through a NodePort or LoadBalancer (" + ", ".join(
                                 str(_dict(s.get('metadata')).get('name')) for s in external[:5])
                                + ") may also reach the pod with a node's address as its source, which the rules do not name"
                                if external else ""))  # fmt: skip
        self.report.note(Severity.INFO, "K8S_SELF_TRAFFIC",
                         "a pod can always reach itself; the converted policy has no rule for it (it never leaves the pod)")
        if self.dialect == "calico":
            self.report.note(Severity.INFO, "CALICO_NODE_TRAFFIC",
                             "traffic between a pod and its node is decided by Felix's configuration and the policies of host "
                             "endpoints; it is not converted")  # fmt: skip
            if self.host_endpoints:
                self.report.note(Severity.REVIEW, "CALICO_HOST_ENDPOINTS",
                                 f"the export holds {self.host_endpoints} host endpoints: their addresses are matched by selectors, "
                                 "but the policies that apply to them are not converted")  # fmt: skip
        if self.capped:
            self.report.note(Severity.REVIEW, "K8S_COMPOSED_CAPPED",
                             f"more than {_MAX_COMPOSED} rules would be needed for connections between pods; egress rules beyond "
                             "that block what they allow (the converted policy allows less)")  # fmt: skip


# -- helpers -----------------------------------------------------------------------------------------


def _list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _union(sets: List[regions.Services]) -> regions.Services:
    out = regions.Services()
    for one in sets:
        numbers = set(out.protocols) | set(one.protocols)
        out = regions.Services({n: out.of(n) + one.of(n) for n in numbers}, out.rest or one.rest)
    return out


def _box_dst_minus(box: regions.Box, away: List[Interval]) -> Optional[regions.Box]:
    rest = subtract(box[2], away)
    return (box[0], box[1], rest, box[3]) if rest else None


def _describe_peer(peer: Dict[str, Any], namespace: str) -> str:
    def selector(value: Any) -> str:
        value = _dict(value)
        parts = [f"{k}={v}" for k, v in sorted(_dict(value.get("matchLabels")).items())]
        for item in value.get("matchExpressions") or []:
            item = _dict(item)
            values = ",".join(str(v) for v in item.get("values") or [])
            parts.append(f"{item.get('key')} {item.get('operator')}" + (f" ({values})" if values else ""))
        return ",".join(parts) or "all"

    if "namespaceSelector" in peer:
        text = f"namespaces {selector(peer['namespaceSelector'])}"
        if "podSelector" in peer:
            text += f" pods {selector(peer['podSelector'])}"
        return text
    return f"{namespace}/{selector(peer.get('podSelector'))}"


def _protocol(value: Any, problems: List[str]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and value.isdigit():
        number = int(value)
    elif isinstance(value, str) and value.lower() in _PROTOCOL_NUMBERS:
        return _PROTOCOL_NUMBERS[value.lower()]
    else:
        problems.append(f"protocol '{str(value)[:20]}'")
        return None
    if not 1 <= number <= 255:
        problems.append(f"protocol {number}")
        return None
    return number


def _number_set(number: int) -> regions.Services:
    kind = {6: Protocol.TCP, 17: Protocol.UDP, 132: Protocol.SCTP, 1: Protocol.ICMP, 58: Protocol.ICMP6}.get(number)
    entry = ServiceEntry(kind) if kind is not None else ServiceEntry(Protocol.IP, ip_protocol=number)
    found = regions.service_set([entry])
    assert found is not None
    return found


def _calico_ports(value: Any, problems: List[str]) -> Tuple[List[str], List[str]]:
    """(numeric ports and ranges in the model's syntax, named ports)."""
    numbers: List[str] = []
    names: List[str] = []
    for item in _list(value):
        if isinstance(item, int) and not isinstance(item, bool):
            if 0 <= item <= 65535:
                numbers.append(str(item))
                continue
        elif isinstance(item, str):
            found = re.fullmatch(r"(\d+)(?::(\d+))?", item.strip())
            if found:
                low, high = int(found.group(1)), int(found.group(2) or found.group(1))
                if 0 <= low <= high <= 65535:
                    numbers.append(str(low) if low == high else f"{low}-{high}")
                    continue
            elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", item.strip()):
                names.append(item.strip())
                continue
        problems.append(f"port '{str(item)[:20]}' cannot be read")
    return numbers, names


def _icmp_set(kind: Protocol, value: Any, problems: List[str]) -> Optional[regions.Services]:
    if value is None:
        return regions.service_set([ServiceEntry(kind)])
    value = _dict(value)
    kind_value, code = value.get("type"), value.get("code")
    if code is not None and kind_value is None:
        problems.append("an ICMP code without a type")
        return None
    for item in (kind_value, code):
        if item is not None and (not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 255):
            problems.append(f"ICMP type or code '{str(item)[:10]}'")
            return None
    return regions.service_set([ServiceEntry(kind, icmp_type=kind_value, icmp_code=code)])


def _nets(value: Any, problems: List[str]) -> Optional[List[Interval]]:
    if not value:
        return None  # (an empty list does not restrict)
    out: List[Interval] = []
    for item in _list(value):
        interval = parse_literal(str(item))
        if interval is None or "-" in str(item):
            problems.append(f"net '{str(item)[:60]}' cannot be read")
            return None
        out.append(interval)
    return normalize(out)


def _entry_label(entry: ServiceEntry) -> str:
    if entry.protocol in (Protocol.ICMP, Protocol.ICMP6):
        label = str(entry.protocol.value)
        if entry.icmp_type is not None:
            label += f"-{entry.icmp_type}" + (f"-{entry.icmp_code}" if entry.icmp_code is not None else "")
        return label
    if entry.protocol == Protocol.IP:
        return f"ip-{entry.ip_protocol}" if entry.ip_protocol is not None else "ip"
    label = f"{str(entry.protocol.value)}-{entry.dst_ports or 'all'}"
    return label + (f"-from-{entry.src_ports}" if entry.src_ports else "")


def parse(data: bytes, report: Report, dialect: str = "kubernetes") -> Policy:
    if dialect not in ("kubernetes", "calico"):
        raise ParseError(f"unknown dialect '{dialect}'")
    try:
        documents = _documents(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        raise ParseError(f"the JSON cannot be read: {str(error)[:200]} (YAML is not read: convert it with kubectl ... -o json)") from None
    try:
        return _Builder(documents, report, dialect).build()
    except RecursionError:
        raise ParseError("JSON nested deeper than can be followed") from None
    except (TypeError, AttributeError, KeyError, ValueError, OverflowError) as error:
        raise ParseError(f"an object of an unexpected shape: {type(error).__name__} {str(error)[:120]}") from None


__all__ = ["looks_like_calico", "looks_like_kubernetes", "parse"]
