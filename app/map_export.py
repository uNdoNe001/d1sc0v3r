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

"""Standalone network-map export: one self-contained .html per scan, for the
client deliverable. Renderer, styles, logo, and scan data are all inlined so the
file opens offline with no network calls. Raw NSE output is left out; the
host panel shows ports, findings, and the priority story only."""
from __future__ import annotations

import base64
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import topology
from .models import Host, Scan

STATIC = Path(__file__).parent / "web" / "static"
PRIO_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "clean": 4}


def _js_json(obj) -> str:
    """JSON safe to drop inside a <script> block (hostnames are untrusted)."""
    return (json.dumps(obj, separators=(",", ":"))
            .replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _host_detail(h: Host) -> dict:
    return {
        "ip": h.ip, "hostname": h.hostname, "category": h.category,
        "os": h.os_guess, "vendor": h.vendor, "priority": h.priority_level,
        "score": h.priority_score, "reasons": h.reasons, "story": h.llm_story,
        "ports": [
            {"port": p.port, "proto": p.proto, "service": p.service,
             "detail": " ".join(x for x in (p.product, p.version, p.extrainfo) if x)}
            for p in sorted(h.open_ports(), key=lambda p: p.port)
        ],
    }


def render(scan: Scan, hosts: list[Host], engagement: str = "") -> str:
    topo = topology.build(scan, hosts)
    css = (STATIC / "style.css").read_text()
    map_css = css[css.index("/* network map"):]
    logo = base64.b64encode((STATIC / "summit-logo-96.png").read_bytes()).decode()

    counts = {k: 0 for k in PRIO_ORDER}
    for h in hosts:
        counts[h.priority_level] = counts.get(h.priority_level, 0) + 1
    kinds = topo["meta"]["edge_kinds"]
    observed = kinds.get("trace", 0)
    stats = [
        (len(hosts), "hosts"),
        (sum(1 for n in topo["nodes"] if n["kind"] == "hub"), "subnets"),
        (counts["critical"], "critical"),
        (counts["high"], "high"),
        (observed, "observed links"),
        (len(topo["edges"]) - observed, "inferred links"),
    ]
    targets = sorted((h for h in hosts if h.priority_level in ("critical", "high")),
                     key=lambda h: (PRIO_ORDER[h.priority_level], -h.priority_score))

    esc = html.escape
    title = engagement.strip() or "Network discovery"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    values = {
        "%%TITLE%%": esc(title),
        "%%LOGO%%": logo,
        "%%SCOPE%%": " ".join(f"<code>{esc(s)}</code>" for s in scan.subnets),
        "%%META%%": esc(f"scan {scan.id} · {scan.profile} profile · "
                        f"traceroute {'on' if scan.options.get('traceroute') else 'off'} · "
                        f"generated {generated}"),
        "%%STATS%%": "".join(
            f'<div class="stat {esc(label.split()[0])}"><b>{n}</b><span>{esc(label)}</span></div>'
            for n, label in stats),
        "%%TARGETS%%": "".join(
            f'<li data-ip="{esc(h.ip)}"><span class="badge {h.priority_level}">'
            f'{h.priority_level} {h.priority_score}</span><code>{esc(h.ip)}</code>'
            f'<span class="t-why">{esc((h.reasons or [h.category])[0])}</span></li>'
            for h in targets) or '<li class="muted">No critical or high hosts.</li>',
        "%%MAP_CSS%%": map_css,
        "%%NETMAP_JS%%": (STATIC / "netmap.js").read_text(),
        "%%TOPO%%": _js_json(topo),
        "%%HOSTS%%": _js_json({h.ip: _host_detail(h) for h in hosts}),
    }
    # single pass, so scan-derived text can never expand another placeholder
    return re.sub(r"%%[A-Z_]+%%", lambda m: values[m.group(0)], TEMPLATE)


TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%%TITLE%% · Network map</title>
<style>
:root {
  --bg: #0b1017; --panel: #111823; --panel2: #161f2c; --line: #243041;
  --fg: #e6edf3; --dim: #8b9bb0; --accent: #3db2e8;
  --crit: #f85149; --high: #f2a65a; --med: #d29922; --low: #3fb950; --clean: #6e7681;
  --mono: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  color-scheme: dark;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif; }
.wrap { max-width: 1400px; margin: 0 auto; padding: 24px 16px 40px; }
header { display: flex; gap: 14px; align-items: center; margin-bottom: 18px; }
header img { width: 44px; height: 44px; }
.eyebrow { font: 11px var(--mono); letter-spacing: .12em; text-transform: uppercase; color: var(--accent); }
h1 { margin: 2px 0 0; font-size: 26px; font-weight: 600; letter-spacing: -.01em; }
h2 { font: 11px var(--mono); letter-spacing: .12em; text-transform: uppercase; color: var(--dim); margin: 0 0 10px; }
.scope { margin: 0 0 4px; }
.scope code { font: 12px var(--mono); color: var(--accent); background: var(--panel2);
  border: 1px solid var(--line); border-radius: 4px; padding: 1px 6px; margin: 0 4px 4px 0; display: inline-block; }
.meta, .muted { color: var(--dim); font-size: 12px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 8px; margin: 16px 0; }
.stat { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
.stat b { display: block; font: 600 22px var(--mono); }
.stat span { color: var(--dim); font-size: 12px; }
.stat.critical b { color: var(--crit); } .stat.high b { color: var(--high); }
.grid { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 16px; }
@media (max-width: 1000px) { .grid { grid-template-columns: minmax(0, 1fr); } }
.side { display: grid; gap: 16px; align-content: start; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px; min-width: 0; }
.targets { list-style: none; margin: 0; padding: 0; max-height: 300px; overflow: auto;
  scrollbar-color: #2d3a4c transparent; scrollbar-width: thin; }
.targets li { display: grid; grid-template-columns: auto 1fr; gap: 2px 8px; padding: 7px 4px;
  border-bottom: 1px solid var(--line); cursor: pointer; font-size: 12px; }
.targets li:hover { background: var(--panel2); }
.targets code { font: 12px var(--mono); }
.t-why { grid-column: 1 / -1; color: var(--dim); }
.badge { font: 700 10px var(--mono); text-transform: uppercase; padding: 1px 6px; border-radius: 9px; align-self: center; }
.badge.critical { background: var(--crit); color: #1a0000; } .badge.high { background: var(--high); color: #1a0c00; }
.badge.medium { background: var(--med); color: #1a1400; } .badge.low { background: var(--low); color: #001a06; }
.badge.clean { background: var(--clean); color: #fff; }
#detail h3 { margin: 0 0 4px; font: 600 15px var(--mono); word-break: break-all; }
#detail .reason { display: inline-block; font-size: 11px; border: 1px solid var(--line); border-radius: 4px; padding: 1px 6px; margin: 4px 4px 0 0; }
#detail .story { margin-top: 10px; padding: 8px 10px; border: 1px dashed var(--accent); border-radius: 6px; font-size: 13px; }
#detail table { width: 100%; border-collapse: collapse; margin-top: 10px; font: 11px var(--mono); }
#detail td { border-bottom: 1px solid var(--line); padding: 4px 6px 4px 0; vertical-align: top; word-break: break-word; }
.map-ctl button { background: rgba(11,16,23,.72); color: var(--fg); border: 1px solid var(--line);
  border-radius: 6px; cursor: pointer; font-size: 14px; }
footer { margin-top: 22px; color: var(--dim); font-size: 12px; border-top: 1px solid var(--line); padding-top: 12px; }
%%MAP_CSS%%
.map-stage { margin-top: 0; height: min(680px, 75vh); }
@media (max-width: 600px) { .map-term { display: none; } h1 { font-size: 21px; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <img src="data:image/png;base64,%%LOGO%%" alt="Summit Cyber Group">
    <div>
      <div class="eyebrow">Summit Cyber Group · network discovery</div>
      <h1>%%TITLE%%</h1>
    </div>
  </header>
  <p class="scope">%%SCOPE%%</p>
  <div class="meta">%%META%%</div>
  <div class="stats">%%STATS%%</div>

  <div class="grid">
    <div>
      <div class="map-stage">
        <canvas id="map-canvas"></canvas>
        <div id="map-legend" class="map-legend"></div>
        <div class="map-term">
          <div class="map-term-bar"><span>summit@ops — assessment</span><span class="map-live">● replay</span></div>
          <div id="map-log" class="map-log"></div>
        </div>
        <div class="map-ctl">
          <button id="map-anim" title="Pause / resume animation">⏸</button>
          <button id="map-reset" title="Reset rotation + zoom">⟲</button>
        </div>
      </div>
      <p class="muted">Drag to rotate · scroll to zoom · click a host or a target for details</p>
    </div>
    <div class="side">
      <div class="card"><h2>Priority targets</h2><ul class="targets" id="targets">%%TARGETS%%</ul></div>
      <div class="card" id="detail"><h2>Host detail</h2><p class="muted">Select a host on the map.</p></div>
    </div>
  </div>

  <footer>
    Generated by d1sc0v3r for an authorized assessment. Solid links are observed
    traceroute hops; dashed and dotted links are inferred from scan evidence
    (subnet membership, gateways, AD domain) and do not represent observed routing.
  </footer>
</div>

<script>
%%NETMAP_JS%%
</script>
<script>
(() => {
  const TOPO = %%TOPO%%;
  const HOSTS = %%HOSTS%%;
  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };

  // all host fields are rendered via textContent: they came off the network
  function showHost(ip) {
    const h = HOSTS[ip], box = document.getElementById("detail");
    if (!h) return;
    const head = el("h3", null, h.ip + (h.hostname ? " · " + h.hostname : ""));
    const badge = el("span", "badge " + h.priority, h.priority + " " + h.score);
    const sub = el("div", "muted", [h.category, h.os, h.vendor].filter(Boolean).join(" · "));
    const kids = [el("h2", null, "Host detail"), head, badge, sub];
    if (h.reasons.length) {
      const r = el("div");
      h.reasons.forEach((x) => r.appendChild(el("span", "reason", x)));
      kids.push(r);
    }
    if (h.story) kids.push(el("div", "story", h.story));
    if (h.ports.length) {
      const t = el("table");
      h.ports.forEach((p) => {
        const tr = el("tr");
        tr.append(el("td", null, p.port + "/" + p.proto), el("td", null, p.service), el("td", null, p.detail));
        t.appendChild(tr);
      });
      kids.push(t);
    }
    box.replaceChildren(...kids);
    if (window.innerWidth <= 1000) box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  const map = new NetMap(document.querySelector(".map-stage"), {
    term: document.getElementById("map-log"),
    legend: document.getElementById("map-legend"),
    onSelect: (n) => { if (n.kind === "host") showHost(n.ip); },
  });
  map.setData(TOPO);
  const anim = document.getElementById("map-anim");
  anim.textContent = map.animate ? "⏸" : "▶";
  anim.onclick = () => { map.setAnimate(!map.animate); anim.textContent = map.animate ? "⏸" : "▶"; };
  document.getElementById("map-reset").onclick = () => map.resetView();
  document.querySelectorAll("#targets li[data-ip]").forEach((li) => {
    li.onclick = () => { map.focus("host:" + li.dataset.ip); showHost(li.dataset.ip); };
  });
})();
</script>
</body>
</html>
"""
