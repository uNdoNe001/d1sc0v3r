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

"""Report generation: Obsidian-flavored Markdown and CSV for a scan's hosts.

The Markdown is built for an Obsidian vault — YAML frontmatter (queryable
properties + tags), callouts for priority stories, and tables. Drop the file
straight into the customer's folder.
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone

from .models import Host, Scan

# priority bucket → (emoji header, obsidian callout type)
_PRIO_STYLE = {
    "critical": ("🔴 Critical", "danger"),
    "high": ("🟠 High", "warning"),
    "medium": ("🟡 Medium", "note"),
    "low": ("🟢 Low", "note"),
    "clean": ("⚪ Clean", "note"),
}
_CAT_LABEL = {
    "domain-controller": "Domain Controllers", "windows-server": "Windows Servers",
    "windows-workstation": "Windows Workstations", "linux-server": "Linux Servers",
    "web-server": "Web Servers", "database": "Databases", "hypervisor": "Hypervisors",
    "storage-nas": "Storage / NAS", "router-firewall": "Routers / Firewalls",
    "network-switch": "Switches / Network", "voip": "VoIP", "printer": "Printers",
    "ip-camera": "IP Cameras", "iot-device": "IoT", "unknown": "Unknown",
    "clean": "Clean Assets",
}
_CAT_ORDER = list(_CAT_LABEL.keys())
_PRIO_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "clean": 4}


def safe_slug(name: str) -> str:
    """Filesystem/Obsidian-safe slug for filenames."""
    s = re.sub(r"[^\w\-. ]+", "", name or "").strip().replace(" ", "-")
    return s or "engagement"


def _open(host: Host):
    return [p for p in host.ports if p.state == "open"]


def _ports_inline(host: Host) -> str:
    return " ".join(str(p.port) for p in sorted(_open(host), key=lambda x: x.port)) or "—"


def _version(p) -> str:
    return " ".join(x for x in (p.product, p.version, p.extrainfo) if x) or ""


def _sort_hosts(hosts: list[Host]) -> list[Host]:
    return sorted(hosts, key=lambda h: (_PRIO_ORDER.get(h.priority_level, 9), -h.priority_score))


# --- markdown --------------------------------------------------------------
def to_markdown(scan: Scan, hosts: list[Host], engagement: str) -> str:
    eng = engagement.strip() or "Engagement"
    hosts = _sort_hosts(hosts)
    counts: dict[str, int] = {}
    for h in hosts:
        counts[h.priority_level] = counts.get(h.priority_level, 0) + 1
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out: list[str] = []

    # --- frontmatter ---
    out.append("---")
    out.append(f"engagement: {eng}")
    out.append(f'scan_id: "{scan.id}"')
    out.append(f"date: {scan.created_at[:10]}")
    out.append("type: pentest-discovery")
    out.append("subnets:")
    for s in scan.subnets:
        out.append(f"  - {s}")
    for level in ("critical", "high", "medium", "low", "clean"):
        out.append(f"{level}: {counts.get(level, 0)}")
    out.append("tags:")
    out.append("  - pentest/discovery")
    if counts.get("critical"):
        out.append("  - pentest/critical")
    out.append("---")
    out.append("")

    # --- header + summary callout ---
    out.append(f"# {eng} — Discovery & Priority List")
    out.append("")
    t = scan.totals
    out.append("> [!info] Scan summary")
    out.append(f"> - **Generated:** {now}  |  **Scan ID:** `{scan.id}`  |  **Profile:** {scan.profile}")
    out.append(f"> - **Subnets:** {', '.join(f'`{s}`' for s in scan.subnets)}")
    out.append(
        f"> - **Live:** {t.get('live_hosts', '?')}  |  "
        f"**Interesting:** {t.get('interesting_hosts', '?')}  |  "
        f"**Total assets:** {t.get('total_assets', len(hosts))}"
    )
    out.append(
        f"> - **Priority:** 🔴 {counts.get('critical',0)} critical · "
        f"🟠 {counts.get('high',0)} high · 🟡 {counts.get('medium',0)} medium · "
        f"🟢 {counts.get('low',0)} low · ⚪ {counts.get('clean',0)} clean"
    )
    out.append("")

    # --- priority targets (critical + high) ---
    out.append("## 🎯 Priority targets")
    out.append("")
    prio_hosts = [h for h in hosts if h.priority_level in ("critical", "high")]
    if not prio_hosts:
        out.append("_No critical or high-priority targets identified._")
        out.append("")
    for level in ("critical", "high"):
        group = [h for h in prio_hosts if h.priority_level == level]
        if not group:
            continue
        label, callout = _PRIO_STYLE[level]
        out.append(f"### {label}")
        out.append("")
        for h in group:
            title = f"{h.ip}" + (f" · {h.hostname}" if h.hostname else "")
            out.append(f"#### {title} — {h.category} · score {h.priority_score}")
            meta = []
            if h.os_guess:
                meta.append(f"OS: {h.os_guess}")
            if h.vendor:
                meta.append(f"Vendor: {h.vendor}")
            if h.category_source == "llm":
                meta.append("category via qwen3")
            if meta:
                out.append("*" + " · ".join(meta) + "*")
                out.append("")
            if h.llm_story:
                out.append(f"> [!{callout}] Why this is a priority")
                for line in h.llm_story.splitlines() or [h.llm_story]:
                    out.append(f"> {line}")
                out.append("")
            if h.reasons:
                out.append("**Flags:** " + "; ".join(h.reasons))
                out.append("")
            opens = _open(h)
            if opens:
                out.append("| Port | Service | Version |")
                out.append("|---|---|---|")
                for p in sorted(opens, key=lambda x: x.port):
                    out.append(f"| {p.port}/{p.proto} | {p.service or '?'} | {_version(p) or '—'} |")
                out.append("")

    # --- full inventory by category ---
    out.append("## 📋 Assets by category")
    out.append("")
    by_cat: dict[str, list[Host]] = {}
    for h in hosts:
        by_cat.setdefault(h.category, []).append(h)
    for cat in _CAT_ORDER:
        group = by_cat.get(cat)
        if not group:
            continue
        out.append(f"### {_CAT_LABEL.get(cat, cat)} ({len(group)})")
        out.append("")
        out.append("| IP | Hostname | Priority | Score | Open ports | OS |")
        out.append("|---|---|---|---|---|---|")
        for h in _sort_hosts(group):
            out.append(
                f"| `{h.ip}` | {h.hostname or '—'} | {h.priority_level} | "
                f"{h.priority_score} | {_ports_inline(h)} | {h.os_guess or '—'} |"
            )
        out.append("")

    out.append("---")
    out.append(f"*Generated by d1sc0v3r · {now}*")
    out.append("")
    return "\n".join(out)


# --- csv -------------------------------------------------------------------
def to_csv(hosts: list[Host]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "ip", "hostname", "category", "category_source", "confidence",
        "priority_level", "priority_score", "os_guess", "vendor",
        "open_ports", "services", "reasons", "qwen3_story",
    ])
    for h in _sort_hosts(hosts):
        opens = _open(h)
        w.writerow([
            h.ip, h.hostname, h.category, h.category_source, f"{h.confidence:.2f}",
            h.priority_level, h.priority_score, h.os_guess, h.vendor,
            " ".join(str(p.port) for p in sorted(opens, key=lambda x: x.port)),
            "; ".join(f"{p.port}:{p.label()}" for p in opens),
            "; ".join(h.reasons),
            h.llm_story.replace("\n", " "),
        ])
    return buf.getvalue()
