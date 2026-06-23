/*
 * Copyright (c) 2026 Rick Bohm
 * Summit Cyber Group, LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const $ = (s) => document.querySelector(s);
const api = (p, opts) => fetch(p, opts).then((r) => r.json());

let activeScan = null;
let poll = null;
const CAT_ORDER = [
  "domain-controller", "windows-server", "windows-workstation", "linux-server",
  "web-server", "database", "hypervisor", "storage-nas", "router-firewall",
  "network-switch", "voip", "printer", "ip-camera", "iot-device", "unknown", "clean",
];
const CAT_LABEL = {
  "domain-controller": "Domain Controllers", "windows-server": "Windows Servers",
  "windows-workstation": "Windows Workstations", "linux-server": "Linux Servers",
  "web-server": "Web Servers", "database": "Databases", "hypervisor": "Hypervisors",
  "storage-nas": "Storage / NAS", "router-firewall": "Routers / Firewalls",
  "network-switch": "Switches / Network", "voip": "VoIP", "printer": "Printers",
  "ip-camera": "IP Cameras", "iot-device": "IoT", "unknown": "Unknown", "clean": "Clean assets",
};

// --- startup ---------------------------------------------------------------
async function boot() {
  const h = await api("/api/health");
  const sel = $("#profile");
  sel.innerHTML = "";
  for (const [k, v] of Object.entries(h.profiles)) {
    const o = document.createElement("option");
    o.value = k; o.textContent = v.label;
    if (k === "balanced") o.selected = true;
    sel.appendChild(o);
  }
  const ls = $("#llm-status");
  if (h.llm.ok && h.llm.model_present) {
    ls.textContent = `llm: ${h.llm.model} ✓`; ls.className = "pill ok";
  } else if (h.llm.ok) {
    ls.textContent = `llm: up, ${h.llm.model} missing`; ls.className = "pill bad";
  } else {
    ls.textContent = "llm: unreachable"; ls.className = "pill bad";
  }
  loadHistory();
  pollRunning();
  setInterval(pollRunning, 2500);
}

// --- stop-all (always-visible header button) -------------------------------
async function pollRunning() {
  try {
    const r = await api("/api/scans/running");
    const btn = $("#stop-all");
    $("#run-count").textContent = r.count;
    btn.classList.toggle("hidden", r.count === 0);
  } catch { /* ignore */ }
}
$("#stop-all").onclick = async () => {
  const r = await fetch("/api/scans/stop_all", { method: "POST" }).then((r) => r.json());
  $("#stop-all").textContent = `cancelled ${r.cancelled}`;
  setTimeout(pollRunning, 800);
  if (activeScan) refresh();
  loadHistory();
};

async function loadHistory() {
  const scans = await api("/api/scans");
  const ul = $("#history");
  ul.innerHTML = "";
  for (const s of scans) {
    const li = document.createElement("li");
    const when = new Date(s.created_at).toLocaleString();
    const nets = s.subnets || [];
    // first 2 subnets inline; rest summarized as "+N more". Full list on hover.
    const preview = nets.length === 0 ? "(no subnets)"
      : nets.length <= 2 ? nets.join(", ")
      : `${nets.slice(0, 2).join(", ")} +${nets.length - 2} more`;
    li.title = nets.join("\n");
    li.innerHTML = `
      <div class="h-top">
        <span class="h-id">${esc(s.id)}</span>
        <span class="h-right">
          <span class="st">${esc(s.status)}</span>
          <button class="h-del" title="Delete this scan (removes hosts + raw nmap evidence)">×</button>
        </span>
      </div>
      <div class="h-nets">${esc(preview)}</div>
      <div class="h-when muted">${esc(when)}</div>`;
    li.onclick = () => openScan(s.id);
    // delete button must NOT bubble up to the row's openScan handler
    li.querySelector(".h-del").onclick = (e) => {
      e.stopPropagation();
      deleteScan(s.id, nets);
    };
    ul.appendChild(li);
  }
}

async function deleteScan(id, nets) {
  const scope = nets && nets.length ? ` (${nets.length} net${nets.length === 1 ? "" : "s"})` : "";
  if (!confirm(`Delete scan ${id}${scope}?\n\nThis permanently removes its hosts, priority list, and raw nmap XML evidence. Cannot be undone.`)) return;
  await fetch(`/api/scan/${id}`, { method: "DELETE" });
  if (activeScan === id) {
    activeScan = null;
    if (poll) { clearInterval(poll); poll = null; }
    $("#scan-head").classList.add("hidden");
    $("#priority").classList.add("hidden");
    $("#categories").classList.add("hidden");
    $("#export").classList.add("hidden");
    $("#empty").classList.remove("hidden");
  }
  loadHistory();
}

// --- launch ----------------------------------------------------------------
$("#preview-btn").onclick = async () => {
  const r = await api("/api/preview", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ subnets: $("#subnets").value }),
  });
  $("#preview").innerHTML = `${r.subnets.length} subnet(s), ~${r.estimated_hosts} hosts`
    + (r.rejected.length ? ` · <span style="color:var(--crit)">rejected: ${r.rejected.join(", ")}</span>` : "");
};

$("#scan-btn").onclick = async () => {
  const r = await api("/api/scan", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ subnets: $("#subnets").value, profile: $("#profile").value }),
  });
  if (r.scan_id) { openScan(r.scan_id); loadHistory(); }
  else alert(r.detail || "scan failed to start");
};

$("#stop-btn").onclick = async () => {
  if (activeScan) await api(`/api/scan/${activeScan}/stop`, { method: "POST" });
};
$("#delete-btn").onclick = () => {
  if (activeScan) {
    const d = window.__lastDetail || {};
    deleteScan(activeScan, d.scan ? d.scan.subnets : []);
  }
};

// --- scan view -------------------------------------------------------------
function openScan(id) {
  activeScan = id;
  if (poll) clearInterval(poll);
  $("#empty").classList.add("hidden");
  $("#scan-head").classList.remove("hidden");
  refresh();
  poll = setInterval(refresh, 2000);
}

async function refresh() {
  if (!activeScan) return;
  const d = await api(`/api/scan/${activeScan}`);
  window.__lastDetail = d;   // so the head Delete button knows the scope
  const s = d.scan;
  $("#bar").style.width = `${(s.progress * 100).toFixed(0)}%`;
  $("#stage").textContent = `[${s.status}] ${s.stage}`;
  $("#scan-subnets").innerHTML = `<span class="muted">scope:</span> `
    + (s.subnets || []).map((n) => `<code class="net">${esc(n)}</code>`).join(" ")
    + ` <span class="muted">· ${s.profile} · ${esc(s.id)}</span>`;
  $("#stop-btn").classList.toggle("hidden", !["queued", "sweeping", "deep", "analyzing"].includes(s.status));

  const t = s.totals || {};
  const keys = ["live_hosts", "interesting_hosts", "total_assets", "llm_enriched", "elapsed_s"];
  $("#totals").innerHTML = keys.filter((k) => k in t)
    .map((k) => `<span>${k.replace(/_/g, " ")}: ${t[k]}</span>`).join("");

  renderHosts(d.hosts);
  $("#export").classList.toggle("hidden", d.hosts.length === 0);
  if (["done", "error", "stopped"].includes(s.status)) {
    clearInterval(poll); poll = null;
    loadHistory();
  }
}

// --- export ----------------------------------------------------------------
function reportUrl(ext) {
  const eng = encodeURIComponent($("#engagement").value.trim());
  return `/api/scan/${activeScan}/report.${ext}?engagement=${eng}`;
}
$("#md-btn").onclick = () => { if (activeScan) window.location = reportUrl("md"); };
$("#csv-btn").onclick = () => { if (activeScan) window.location = reportUrl("csv"); };
$("#copy-btn").onclick = async () => {
  if (!activeScan) return;
  const md = await fetch(reportUrl("md")).then((r) => r.text());
  try {
    await navigator.clipboard.writeText(md);
    $("#copy-note").textContent = "Markdown copied — paste into your Obsidian note.";
  } catch {
    $("#copy-note").textContent = "Clipboard blocked; use the Markdown download instead.";
  }
  setTimeout(() => ($("#copy-note").textContent = ""), 4000);
};

function renderHosts(hosts) {
  const prio = hosts.filter((h) => ["critical", "high"].includes(h.priority_level));
  const pl = $("#priority-list");
  $("#priority").classList.toggle("hidden", prio.length === 0);
  pl.innerHTML = prio.map(hostCard).join("");

  $("#categories").classList.toggle("hidden", hosts.length === 0);
  const byCat = {};
  for (const h of hosts) (byCat[h.category] ||= []).push(h);
  const cl = $("#category-list");
  cl.innerHTML = "";
  for (const cat of CAT_ORDER) {
    const list = byCat[cat];
    if (!list || !list.length) continue;
    const div = document.createElement("div");
    div.className = "cat-group";
    div.innerHTML = `<h3>${CAT_LABEL[cat] || cat} <span class="cat-count">(${list.length})</span></h3>`
      + list.map(hostCard).join("");
    cl.appendChild(div);
  }
  // wire clicks
  document.querySelectorAll(".host").forEach((el) => {
    el.onclick = () => showHost(JSON.parse(el.dataset.h));
  });
}

function hostCard(h) {
  const ports = (h.port_summary || []).join(" ");
  const reasons = (h.reasons || []).map((r) =>
    `<span class="reason ${/vuln|risky|smbv1|signing/i.test(r) ? "vuln" : ""}">${esc(r)}</span>`).join("");
  const story = h.llm_story ? `<div class="story"><b>qwen3:</b> ${esc(h.llm_story)}</div>` : "";
  const src = h.category_source === "llm" ? " · llm" : "";
  return `<div class="host ${h.priority_level}" data-h='${attr(h)}'>
    <div class="host-top">
      <span class="host-ip">${esc(h.ip)}${h.hostname ? " · " + esc(h.hostname) : ""}</span>
      <span class="badge ${h.priority_level}">${h.priority_level} ${h.priority_score}</span>
    </div>
    <div class="host-cat">${esc(h.category)}${src}${h.os_guess ? " · " + esc(h.os_guess) : ""}${h.vendor ? " · " + esc(h.vendor) : ""}</div>
    ${ports ? `<div class="ports">${ports}</div>` : ""}
    ${reasons ? `<div class="reasons">${reasons}</div>` : ""}
    ${story}
  </div>`;
}

function showHost(h) {
  const rows = (h.ports || []).filter((p) => p.state === "open").map((p) => {
    const scripts = Object.entries(p.scripts || {}).map(([k, v]) =>
      `<div class="muted"><b>${esc(k)}</b>: ${esc(v)}</div>`).join("");
    return `<tr><td>${p.port}/${p.proto}</td><td>${esc(p.service)}</td>
      <td>${esc([p.product, p.version, p.extrainfo].filter(Boolean).join(" "))}${scripts}</td></tr>`;
  }).join("");
  $("#modal-body").innerHTML = `
    <h2>${esc(h.ip)} ${h.hostname ? "· " + esc(h.hostname) : ""}</h2>
    <p><b class="badge ${h.priority_level}">${h.priority_level} ${h.priority_score}</b>
       &nbsp; ${esc(h.category)} (${h.category_source}, conf ${h.confidence})</p>
    ${h.os_guess ? `<p class="muted">OS: ${esc(h.os_guess)} (${h.os_accuracy}%)</p>` : ""}
    ${h.llm_rationale ? `<p class="muted"><b>qwen3 class:</b> ${esc(h.llm_rationale)}</p>` : ""}
    ${h.llm_story ? `<div class="story"><b>Priority story:</b> ${esc(h.llm_story)}</div>` : ""}
    ${(h.reasons || []).length ? `<p>${h.reasons.map((r) => `<span class="reason">${esc(r)}</span>`).join(" ")}</p>` : ""}
    <table class="ports-tbl"><tr><th>port</th><th>service</th><th>details</th></tr>${rows}</table>`;
  $("#modal").classList.remove("hidden");
}
$("#modal-close").onclick = () => $("#modal").classList.add("hidden");
$("#modal").onclick = (e) => { if (e.target.id === "modal") $("#modal").classList.add("hidden"); };

// --- utils -----------------------------------------------------------------
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function attr(o) { return esc(JSON.stringify(o)); }

boot();
