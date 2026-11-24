# Copyright (c) 2026 Rick Bohm
# Summit Cyber Group, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Build the network-map graph for a scan.

Shape: the scanner sits at the core, each /24 (or /64) with live hosts is a hub,
and hosts hang off their hub. Every link says where it came from, because a map
in a client deliverable must not imply paths we never saw:

  observed  trace     consecutive traceroute hops (only with the traceroute option)
  inferred  member    host lives in the hub's /24
            uplink    scanner reached the subnet; path unknown
            gateway   a router/firewall host inside the subnet fronts it
            domain    host reports the same AD domain as a DC (NTLM/SMB evidence)
"""
from __future__ import annotations

import ipaddress
from typing import Any

from .models import Host, Scan

CORE = "core"
PRIO_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "clean": 4}
# when two kinds claim the same node pair, keep the one with the most evidence
KIND_RANK = {"trace": 0, "domain": 1, "gateway": 2, "member": 3, "uplink": 4}


def _hub_net(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    plen = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))


def ad_domain(host: Host) -> str:
    """AD DNS domain the host itself reported via NTLM info or SMB discovery."""
    for p in host.ports:
        for sid, out in p.scripts.items():
            for line in out.splitlines():
                key, _, val = line.strip().partition(":")
                key = key.strip().lower()
                if (sid.endswith("ntlm-info") and key == "dns_domain_name") or \
                   (sid == "smb-os-discovery" and key == "domain name"):
                    val = val.strip().strip("\x00").lower()
                    if val:
                        return val
    return ""


class _Graph:
    def __init__(self):
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[frozenset, dict[str, Any]] = {}

    def node(self, nid: str, **attrs) -> None:
        self.nodes.setdefault(nid, {"id": nid}).update(attrs)

    def edge(self, a: str, b: str, kind: str, note: str = "", gap: bool = False) -> None:
        if a == b:
            return
        key = frozenset((a, b))
        cur = self.edges.get(key)
        if cur and KIND_RANK[cur["kind"]] <= KIND_RANK[kind]:
            return
        self.edges[key] = {"a": a, "b": b, "kind": kind,
                           "observed": kind == "trace", "note": note, "gap": gap}


def build(scan: Scan, hosts: list[Host]) -> dict[str, Any]:
    g = _Graph()
    g.node(CORE, kind="core", label="d1sc0v3r", ip="")
    host_ids = {h.ip: f"host:{h.ip}" for h in hosts}

    # --- hubs + members ------------------------------------------------------
    hub_of: dict[str, str] = {}
    for h in hosts:
        net = _hub_net(h.ip)
        hub = f"net:{net}"
        hub_of[h.ip] = hub
        hn = g.nodes.get(hub) or {"count": 0, "worst": "clean"}
        g.node(hub, kind="hub", label=net, ip=net, count=hn["count"] + 1,
               worst=min(hn["worst"], h.priority_level, key=lambda x: PRIO_RANK.get(x, 9)))
        g.node(host_ids[h.ip], kind="host", ip=h.ip, hub=hub,
               label=h.hostname or h.ip, hostname=h.hostname,
               category=h.category, priority=h.priority_level,
               score=h.priority_score, reason=(h.reasons or [""])[0],
               ports=sorted({p.port for p in h.open_ports()}))
        g.edge(hub, host_ids[h.ip], "member", f"in {net}")

    # --- observed paths (traceroute) -----------------------------------------
    traced_hubs: set[str] = set()
    for h in hosts:
        hops = sorted((x for x in h.trace if x.get("ip")), key=lambda x: x["ttl"])
        if not hops:
            continue
        hub = hub_of[h.ip]
        traced_hubs.add(hub)
        # final hop is the target itself; everything before it is a router
        routers = [x for x in hops if x["ip"] != h.ip]
        prev, prev_ttl = CORE, 0
        for hop in routers:
            rid = host_ids.get(hop["ip"]) or f"hop:{hop['ip']}"
            if rid not in g.nodes:
                g.node(rid, kind="router", ip=hop["ip"], label=hop.get("host") or hop["ip"])
            g.edge(prev, rid, "trace", f"ttl {hop['ttl']}", gap=hop["ttl"] - prev_ttl > 1)
            prev, prev_ttl = rid, hop["ttl"]
        last_ttl = hops[-1]["ttl"] if hops[-1]["ip"] == h.ip else prev_ttl + 1
        g.edge(prev, hub, "trace", "on-link" if prev == CORE else "last hop",
               gap=last_ttl - prev_ttl > 1)

    # --- inferred uplinks + gateways -----------------------------------------
    for h in hosts:
        if h.category == "router-firewall":
            hub = hub_of[h.ip]
            g.edge(hub, host_ids[h.ip], "gateway", "router/firewall in subnet")
            g.nodes[host_ids[h.ip]]["role"] = "gateway"
            if hub not in traced_hubs:
                g.edge(CORE, host_ids[h.ip], "uplink", "path not traced")
    gw_hubs = {n["hub"] for n in g.nodes.values() if n.get("role") == "gateway"}
    for nid, n in list(g.nodes.items()):
        if n["kind"] == "hub" and nid not in traced_hubs and nid not in gw_hubs:
            g.edge(CORE, nid, "uplink", "path not traced")

    # --- AD domain membership ------------------------------------------------
    domains: dict[str, list[Host]] = {}
    for h in hosts:
        d = ad_domain(h)
        if d:
            domains.setdefault(d, []).append(h)
    for d, members in domains.items():
        dcs = [h for h in members if h.category == "domain-controller"]
        for dc in dcs:
            g.nodes[host_ids[dc.ip]]["role"] = "dc"
        for a, b in zip(dcs, dcs[1:]):
            g.edge(host_ids[a.ip], host_ids[b.ip], "domain", f"{d} replication peers")
        if not dcs:
            continue
        for h in members:
            if h.category == "domain-controller":
                continue
            # prefer a DC in the same subnet, else the first one seen
            dc = next((x for x in dcs if hub_of[x.ip] == hub_of[h.ip]), dcs[0])
            g.edge(host_ids[h.ip], host_ids[dc.ip], "domain", f"member of {d}")

    edges = list(g.edges.values())
    kinds: dict[str, int] = {}
    for e in edges:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    return {
        "nodes": list(g.nodes.values()),
        "edges": edges,
        "meta": {
            "scan_id": scan.id,
            "subnets": scan.subnets,
            "status": scan.status,
            "traceroute": bool(scan.options.get("traceroute")),
            "hosts": len(hosts),
            "edge_kinds": kinds,
        },
    }
