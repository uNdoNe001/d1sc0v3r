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

// Wire-mesh network map, same visual language as the summitcyber.io hero:
// a slowly rotating point cloud of subnet hubs around the scanner core, hosts
// clustered on their hub, packets drifting along links, and an attack-path
// trace that walks to each critical/high host in turn.
//
// Fed by /api/scan/<id>/topology. Layout is deterministic (seeded by node id),
// so polling during a live scan adds nodes without reshuffling the map.

const NM_RGB = {
  base: "150,178,205",    // slate wire + quiet hosts
  bright: "220,232,242",  // hubs, observed hops, hover
  path: "61,178,232",     // attack-path trace + AD links
  high: "242,166,90",     // amber
  critical: "248,81,73",  // red
};
const NM_TARGET_SECONDS = 11;   // dwell per target, matches the site cadence

function nmHash(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function nmRand(seed) {   // mulberry32
  let a = seed;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function nmGauss(rand) {
  let u = 0, v = 0;
  while (!u) u = rand();
  while (!v) v = rand();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}
function nmIpKey(s) {   // sort "10.0.4.0/24" numerically
  return (s.split("/")[0].split(".").map((n) => n.padStart(3, "0")).join("."));
}

class NetMap {
  constructor(stage, { onSelect, term, legend } = {}) {
    this.stage = stage;
    this.canvas = stage.querySelector("canvas");
    this.ctx = this.canvas.getContext("2d");
    this.termEl = term;
    this.legendEl = legend;
    this.onSelect = onSelect || (() => {});
    this.reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    this.animate = !this.reduced;
    this.font = getComputedStyle(document.documentElement).getPropertyValue("--mono") || "monospace";

    this.nodes = []; this.edges = []; this.adj = []; this.index = new Map();
    this.meta = null; this.sig = "";
    this.proj = []; this.packets = [];
    this.mouse = { x: 0, y: 0, tx: 0, ty: 0, px: null, py: 0 };
    this.yaw = 0; this.zoom = 1; this.drag = null;
    this.t = 0; this.last = 0; this.raf = 0; this.visible = false;
    this.hover = -1; this.run = null; this.targetCursor = 0; this.log = [];

    this._bind();
  }

  // --- data -----------------------------------------------------------------
  setData(topo) {
    // cheap change detector so 2s polling doesn't rebuild an unchanged graph
    const sig = topo.nodes.map((n) => n.id + (n.priority || "")).join("|") + "#" + topo.edges.length;
    if (!this.meta || this.meta.scan_id !== topo.meta.scan_id) {
      this.run = null; this.targetCursor = 0; this.yaw = 0; this.zoom = 1;
    }
    this.meta = topo.meta;
    if (sig === this.sig) return;
    this.sig = sig;

    this.nodes = topo.nodes.map((n) => ({ ...n }));
    this.index = new Map(this.nodes.map((n, i) => [n.id, i]));
    this.edges = topo.edges
      .filter((e) => this.index.has(e.a) && this.index.has(e.b))
      .map((e) => ({ ...e, i: this.index.get(e.a), j: this.index.get(e.b) }));
    this.adj = this.nodes.map(() => []);
    for (const e of this.edges) { this.adj[e.i].push(e.j); this.adj[e.j].push(e.i); }
    this.packets = [];

    this._layout();
    this.targets = this.nodes
      .map((n, i) => ({ n, i }))
      .filter(({ n }) => n.kind === "host" && (n.priority === "critical" || n.priority === "high"))
      .sort((a, b) => (b.n.score || 0) - (a.n.score || 0))
      .map(({ i }) => i);
    if (this.run && !this.targets.includes(this.run.target)) this.run = null;
    this._renderLegend();
    this._resetLog();
    if (!this.raf) this._frame(0);
  }

  _layout() {
    const N = this.nodes, core = this.index.get("core");
    const hubs = N.map((n, i) => i).filter((i) => N[i].kind === "hub")
      .sort((a, b) => nmIpKey(N[a].ip).localeCompare(nmIpKey(N[b].ip)));

    // hubs on a jittered ring around the core, like the site
    hubs.forEach((i, k) => {
      const r = nmRand(nmHash(N[i].id));
      const ang = (k / hubs.length) * Math.PI * 2 + 0.5 * r();
      const rad = hubs.length === 1 ? 0.9 : 0.55 + 0.75 * r();
      Object.assign(N[i], { x: Math.cos(ang) * rad * 1.3, y: 0.35 * nmGauss(r), z: Math.sin(ang) * rad });
    });
    if (core !== undefined) Object.assign(N[core], { x: 0, y: 0, z: 0 });

    // hosts cluster on their hub; bigger subnets spread wider
    const counts = {};
    N.forEach((n) => { if (n.kind === "host") counts[n.hub] = (counts[n.hub] || 0) + 1; });
    N.forEach((n) => {
      if (n.kind !== "host") return;
      const hub = N[this.index.get(n.hub)];
      const r = nmRand(nmHash(n.id));
      const spread = Math.min(2.2, Math.max(0.6, Math.sqrt((counts[n.hub] || 1) / 13)));
      if (n.role === "gateway") {
        // gateways sit between their subnet and the core
        Object.assign(n, { x: hub.x * 0.78, y: hub.y * 0.78 + 0.05 * nmGauss(r), z: hub.z * 0.78 });
        return;
      }
      Object.assign(n, {
        x: hub.x + 0.24 * spread * nmGauss(r),
        y: hub.y + 0.2 * spread * nmGauss(r),
        z: hub.z + 0.24 * spread * nmGauss(r),
      });
    });

    // observed routers: place along the line toward the hubs they lead to,
    // at a fraction set by their hop depth
    const depth = this._bfs(core, (e) => e.kind === "trace").dist;
    N.forEach((n, i) => {
      if (n.kind !== "router") return;
      const down = this._downstreamHubs(i, depth);
      const r = nmRand(nmHash(n.id));
      if (!down.length) { Object.assign(n, { x: 0.3 * nmGauss(r), y: 0.2 * nmGauss(r), z: 0.3 * nmGauss(r) }); return; }
      const ax = down.reduce((s, h) => s + N[h].x, 0) / down.length;
      const ay = down.reduce((s, h) => s + N[h].y, 0) / down.length;
      const az = down.reduce((s, h) => s + N[h].z, 0) / down.length;
      const hd = Math.max(...down.map((h) => depth[h])) || 1;
      const f = Math.min(0.9, depth[i] / hd);
      Object.assign(n, { x: ax * f + 0.04 * nmGauss(r), y: ay * f + 0.04 * nmGauss(r), z: az * f + 0.04 * nmGauss(r) });
    });

    // normalize so any scan size fits the stage
    let m = 0.01;
    N.forEach((n) => { m = Math.max(m, Math.hypot(n.x, n.z), Math.abs(n.y) * 1.5); });
    const k = 1.5 / m;
    N.forEach((n) => { n.x *= k; n.y *= k; n.z *= k; });
  }

  _downstreamHubs(start, depth) {
    const out = new Set(), seen = new Set([start]), stack = [start];
    while (stack.length) {
      const i = stack.pop();
      for (const j of this.adj[i]) {
        if (seen.has(j) || !(depth[j] > depth[i])) continue;
        seen.add(j);
        if (this.nodes[j].kind === "hub") out.add(j); else stack.push(j);
      }
    }
    return [...out];
  }

  // BFS from `from`, optionally restricted to edges passing `keep`
  _bfs(from, keep) {
    const dist = new Array(this.nodes.length).fill(-1), prev = new Array(this.nodes.length).fill(-1);
    if (from === undefined) return { dist, prev };
    const ok = keep ? new Set(this.edges.filter(keep).flatMap((e) => [`${e.i}-${e.j}`, `${e.j}-${e.i}`])) : null;
    dist[from] = 0;
    const q = [from];
    while (q.length) {
      const i = q.shift();
      for (const j of this.adj[i]) {
        if (dist[j] >= 0 || (ok && !ok.has(`${i}-${j}`))) continue;
        dist[j] = dist[i] + 1; prev[j] = i; q.push(j);
      }
    }
    return { dist, prev };
  }

  // --- lifecycle + input ----------------------------------------------------
  _bind() {
    const c = this.canvas;
    this._resize = () => {
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      this.w = c.clientWidth; this.h = c.clientHeight;
      c.width = this.w * dpr; c.height = this.h * dpr;
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (!this.raf) this._frame(0);
    };
    new ResizeObserver(this._resize).observe(c);
    new IntersectionObserver(([e]) => { this.visible = e.isIntersecting; this.visible ? this.start() : this.stop(); }).observe(c);
    document.addEventListener("visibilitychange", () => (document.hidden ? this.stop() : this.start()));

    c.addEventListener("pointermove", (ev) => {
      const r = c.getBoundingClientRect();
      this.mouse.px = ev.clientX - r.left; this.mouse.py = ev.clientY - r.top;
      if (this.drag) {
        this.yaw += (ev.clientX - this.drag.x) * 0.006;
        this.drag.moved ||= Math.abs(ev.clientX - this.drag.x0) > 3;
        this.drag.x = ev.clientX;
      } else {
        this.mouse.tx = ((ev.clientX - r.left) / r.width - 0.5) * 2;
        this.mouse.ty = Math.max(-1, Math.min(1, ((ev.clientY - r.top) / r.height - 0.5) * 2));
      }
      if (!this.raf) this._frame(0);
    });
    c.addEventListener("pointerleave", () => { this.mouse.px = null; this.drag = null; if (!this.raf) this._frame(0); });
    c.addEventListener("pointerdown", (ev) => { this.drag = { x: ev.clientX, x0: ev.clientX, moved: false }; });
    c.addEventListener("pointerup", () => {
      const clicked = this.drag && !this.drag.moved;
      this.drag = null;
      if (clicked && this.hover >= 0) {
        this.focus(this.nodes[this.hover].id);
        this.onSelect(this.nodes[this.hover]);
      }
    });
    c.addEventListener("wheel", (ev) => {
      ev.preventDefault();
      this.zoom = Math.max(0.5, Math.min(4, this.zoom * Math.exp(-ev.deltaY * 0.0015)));
      if (!this.raf) this._frame(0);
    }, { passive: false });
  }

  start() {
    if (this.raf || !this.visible || document.hidden || !this.animate) return;
    this.last = performance.now();
    const loop = (now) => {
      this.raf = requestAnimationFrame(loop);
      const dt = Math.min(0.05, (now - this.last) / 1000);
      this.last = now; this.t += dt;
      this._frame(dt);
    };
    this.raf = requestAnimationFrame(loop);
  }

  stop() { cancelAnimationFrame(this.raf); this.raf = 0; }

  setAnimate(on) {
    this.animate = on;
    if (on) this.start(); else { this.stop(); this._frame(0); }
  }

  resetView() { this.yaw = 0; this.zoom = 1; if (!this.raf) this._frame(0); }

  // --- attack-path cycle ----------------------------------------------------
  _label(i) {
    const n = this.nodes[i];
    return n.kind === "host" && n.hostname ? `${n.ip} (${n.hostname})` : (n.ip || n.label);
  }

  _nextTarget() {
    if (!this.targets || !this.targets.length) { this.run = null; return; }
    this._startRun(this.targets[this.targetCursor++ % this.targets.length]);
  }

  // jump the attack-path trace to a node (target list click, host click)
  focus(id) {
    const i = this.index.get(id);
    if (i === undefined || this.nodes[i].kind !== "host") return;
    const k = (this.targets || []).indexOf(i);
    if (k >= 0) this.targetCursor = k + 1;
    this._startRun(i);
    if (!this.raf) this._frame(0);
  }

  _startRun(target) {
    const { prev } = this._bfs(this.index.get("core"));
    const path = [];
    for (let i = target; i >= 0; i = prev[i]) path.unshift(i);
    // when paused, show the finished trace instead of a frozen first frame
    const t0 = this.animate ? this.t : this.t - (1.4 + 0.5 * (path.length - 1));
    this.run = { target, path, t0, logged: 0, found: false };
    this._resetLog();
  }

  // --- drawing --------------------------------------------------------------
  _frame(dt) {
    const ctx = this.ctx, w = this.w, h = this.h, N = this.nodes;
    if (!w || !N.length) { if (w) ctx.clearRect(0, 0, w, h); return; }
    const m = this.mouse;
    if (this.animate) {
      m.x += (m.tx - m.x) * 0.04; m.y += (m.ty - m.y) * 0.04;
      if (!this.run || this.t - this.run.t0 > NM_TARGET_SECONDS) this._nextTarget();
    }

    // run timing: first hop lights at 0.9s, then one hop every 0.5s
    const run = this.run;
    const age = run ? this.t - run.t0 : 0;
    const hops = run ? run.path.length - 1 : 0;
    const prog = Math.max(0, (age - 0.9) / 0.5);
    const reached = !!run && prog >= hops;
    const lit = Math.min(hops, Math.floor(prog));
    const fade = age > NM_TARGET_SECONDS - 1 ? Math.max(0, NM_TARGET_SECONDS - age) : 1;
    if (run) this._advanceLog(run, lit, hops, reached);

    // project: yaw from time + mouse + drag, slight tilt from mouse
    const yaw = 0.05 * this.t + 0.35 * m.x + this.yaw, tilt = 0.62 + 0.12 * m.y;
    const cy = Math.cos(yaw), sy = Math.sin(yaw), ct = Math.cos(tilt), st = Math.sin(tilt);
    const ox = w / 2, oy = h * 0.42, A = Math.min(w * 0.3, h * 0.5) * this.zoom;
    N.forEach((n, i) => {
      const x1 = n.x * cy - n.z * sy, z1 = n.x * sy + n.z * cy;
      const y2 = n.y * ct - z1 * st, z2 = n.y * st + z1 * ct;
      const s = 3.5 / (3.5 + z2);
      this.proj[i] = { x: ox + x1 * A * s, y: oy + y2 * A * s, s, d: Math.max(0.15, Math.min(1, 0.75 - 0.3 * z2)) };
    });
    const P = this.proj;

    // hover: nearest node within 22px
    let hover = -1, best = 484;
    if (m.px != null) P.forEach((p, i) => {
      const d2 = (p.x - m.px) ** 2 + (p.y - m.py) ** 2;
      if (d2 < best) { best = d2; hover = i; }
    });
    this.hover = hover;

    ctx.clearRect(0, 0, w, h);
    this._drawEdges(P, hover);
    this._drawPackets(P, dt);

    // attack path glow, drawn hop by hop
    if (run && fade > 0) {
      ctx.save();
      ctx.shadowColor = `rgba(${NM_RGB.path},0.8)`; ctx.shadowBlur = 10;
      ctx.lineWidth = 1.6; ctx.strokeStyle = `rgba(${NM_RGB.path},${(0.9 * fade).toFixed(3)})`;
      ctx.beginPath();
      for (let k = 0; k < hops; k++) {
        const f = Math.min(1, prog - k);
        if (f <= 0) break;
        const a = P[run.path[k]], b = P[run.path[k + 1]];
        ctx.moveTo(a.x, a.y); ctx.lineTo(a.x + (b.x - a.x) * f, a.y + (b.y - a.y) * f);
      }
      ctx.stroke(); ctx.restore();
    }

    const onPath = new Set(run ? run.path.slice(0, lit + 1) : []);
    this._drawNodes(P, hover, onPath, fade);
    ctx.font = `500 11px ${this.font}`;
    if (run && reached && fade > 0) this._drawCallout(P[run.target], N[run.target], age, fade);
    if (hover >= 0) {
      const p = P[hover], n = N[hover];
      const extra = n.kind === "host" ? ` · ${n.category}` : n.kind === "hub" ? ` · ${n.count} hosts` : "";
      ctx.fillStyle = `rgb(${NM_RGB.bright})`;
      ctx.fillText(`${this._label(hover)}${extra} · ${this.adj[hover].length} links`, p.x + 10, p.y + 4);
    }
    this.canvas.style.cursor = hover >= 0 && N[hover].kind === "host" ? "pointer" : this.drag ? "grabbing" : "grab";
  }

  _drawEdges(P, hover) {
    const ctx = this.ctx;
    ctx.lineWidth = 1;
    for (const e of this.edges) {
      const a = P[e.i], b = P[e.j], d = (a.d + b.d) / 2;
      let rgb = NM_RGB.base, alpha = 0.14 * d, dash = null;
      if (e.kind === "trace") { rgb = NM_RGB.bright; alpha = 0.3 * d; if (e.gap) dash = [3, 4]; }
      else if (e.kind === "gateway") alpha = 0.22 * d;
      else if (e.kind === "uplink") { alpha = 0.16 * d; dash = [2, 5]; }
      else if (e.kind === "domain") { rgb = NM_RGB.path; alpha = 0.22 * d; dash = [1, 3]; }
      if (hover >= 0 && (e.i === hover || e.j === hover)) { rgb = NM_RGB.bright; alpha = 0.6; }
      ctx.setLineDash(dash || []);
      ctx.strokeStyle = `rgba(${rgb},${alpha.toFixed(3)})`;
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    }
    ctx.setLineDash([]);
  }

  _drawPackets(P, dt) {
    const ctx = this.ctx;
    if (this.animate && this.edges.length && this.packets.length < 26 && Math.random() < 0.35) {
      this.packets.push({ e: this.edges[(Math.random() * this.edges.length) | 0], t: 0, v: 0.4 + 0.6 * Math.random(), rev: Math.random() < 0.5 });
    }
    for (let k = this.packets.length - 1; k >= 0; k--) {
      const pk = this.packets[k];
      pk.t += dt * pk.v;
      if (pk.t >= 1) { this.packets.splice(k, 1); continue; }
      const a = P[pk.rev ? pk.e.j : pk.e.i], b = P[pk.rev ? pk.e.i : pk.e.j];
      ctx.fillStyle = `rgba(${NM_RGB.bright},${(0.55 * a.d).toFixed(3)})`;
      ctx.fillRect(a.x + (b.x - a.x) * pk.t - 1, a.y + (b.y - a.y) * pk.t - 1, 2, 2);
    }
  }

  _drawNodes(P, hover, onPath, fade) {
    const ctx = this.ctx;
    this.nodes.forEach((n, i) => {
      const p = P[i];
      let rgb = NM_RGB.base, alpha = 0.8 * p.d, r = 1.4;
      if (n.kind === "core") { rgb = NM_RGB.bright; alpha = p.d; r = 3.4; }
      else if (n.kind === "hub") { rgb = NM_RGB.bright; alpha = p.d; r = 2.6; }
      else if (n.kind === "router") { rgb = NM_RGB.bright; alpha = 0.9 * p.d; r = 2.2; }
      else if (n.priority === "critical") { rgb = NM_RGB.critical; alpha = p.d; r = 2.4; }
      else if (n.priority === "high") { rgb = NM_RGB.high; alpha = p.d; r = 2.0; }
      else if (n.priority === "clean") alpha = 0.45 * p.d;
      r *= p.s;
      if (onPath.has(i) && fade > 0) { rgb = NM_RGB.path; alpha = fade; r += 0.8; }
      if (i === hover) { rgb = NM_RGB.bright; alpha = 1; r += 1.5; }
      ctx.fillStyle = `rgba(${rgb},${alpha.toFixed(3)})`;
      ctx.beginPath();
      // squares = routing (observed hops, gateways); circles = everything else
      if (n.kind === "router" || n.role === "gateway") ctx.rect(p.x - r, p.y - r, r * 2, r * 2);
      else ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
      ctx.fill();
      if (n.role === "dc") {
        ctx.strokeStyle = `rgba(${rgb},${(0.7 * alpha).toFixed(3)})`; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(p.x, p.y, r + 2.5, 0, Math.PI * 2); ctx.stroke();
      }
      if (n.kind === "hub") {
        ctx.font = `400 10px ${this.font}`;
        ctx.fillStyle = `rgba(${NM_RGB.base},${(0.55 * p.d).toFixed(3)})`;
        ctx.fillText(n.label, p.x + 6, p.y - 6);
      }
    });
  }

  _drawCallout(p, n, age, fade) {
    const ctx = this.ctx, rgb = NM_RGB[n.priority] || NM_RGB.high, pulse = (age * 1.2) % 1;
    ctx.strokeStyle = `rgba(${rgb},${((1 - pulse) * fade).toFixed(3)})`; ctx.lineWidth = 1.2;
    ctx.beginPath(); ctx.arc(p.x, p.y, 4 + 18 * pulse, 0, Math.PI * 2); ctx.stroke();
    ctx.fillStyle = `rgba(${rgb},${fade.toFixed(3)})`;
    ctx.beginPath(); ctx.arc(p.x, p.y, 3.5, 0, Math.PI * 2); ctx.fill();
    // leader line flips left near the right edge so the label stays on canvas
    const text = `${n.ip} — ${n.reason || n.category}`;
    const tw = ctx.measureText(text).width, left = p.x + 46 + tw > this.w - 8;
    const sx = left ? -1 : 1;
    ctx.strokeStyle = `rgba(${rgb},${(0.5 * fade).toFixed(3)})`; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(p.x + 6 * sx, p.y - 6); ctx.lineTo(p.x + 26 * sx, p.y - 26); ctx.lineTo(p.x + 40 * sx, p.y - 26); ctx.stroke();
    ctx.fillText(text, left ? p.x - 46 - tw : p.x + 46, p.y - 22);
  }

  // --- terminal log + legend ------------------------------------------------
  _resetLog() {
    const mt = this.meta || {}, obs = this.edges.filter((e) => e.observed).length;
    const scope = (mt.subnets || []).slice(0, 3).join(" ") + ((mt.subnets || []).length > 3 ? " …" : "");
    this.log = [
      { text: `$ d1sc0v3r --scope ${scope}`, color: "#c4d0dc" },
      { text: `  ${mt.hosts || 0} hosts · ${this.edges.length} links · ${obs ? obs + " observed" : "uplinks inferred"}`, color: "#7f90a3" },
    ];
    if (this.targets && !this.targets.length && mt.hosts) this.log.push({ text: "✓ no critical/high hosts", color: "#6cc36e" });
    this._renderLog();
  }

  _advanceLog(run, lit, hops, reached) {
    let changed = false;
    while (run.logged < lit && run.logged < hops - 1) {
      run.logged++;
      this.log.push({ text: `→ via ${this._label(run.path[run.logged])}`, color: "#93a3b5" });
      changed = true;
    }
    if (reached && !run.found) {
      run.found = true;
      const n = this.nodes[run.target];
      this.log.push({ text: `! ${this._label(run.target)} · ${n.reason || n.category}`, color: n.priority === "critical" ? "#f85149" : "#f2a65a" });
      this.log.push({ text: `  ${n.category} · ${n.priority} ${n.score} · ${(n.ports || []).slice(0, 8).join(",")}`, color: "#7f90a3" });
      changed = true;
    }
    if (changed) { this.log = this.log.slice(-9); this._renderLog(); }
  }

  _renderLog() {
    if (!this.termEl) return;
    // built with textContent: hostnames come from rDNS/NTLM and are untrusted
    this.termEl.replaceChildren(...this.log.map((l) => {
      const div = document.createElement("div");
      div.textContent = l.text; div.style.color = l.color;
      return div;
    }));
  }

  _renderLegend() {
    if (!this.legendEl) return;
    const tr = this.meta && this.meta.traceroute;
    this.legendEl.innerHTML = `
      <div><i class="dot crit"></i>critical <i class="dot high"></i>high <i class="dot"></i>other</div>
      <div><i class="sq"></i>router / gateway <i class="ring"></i>domain controller</div>
      <div><i class="ln trace"></i>observed hop <i class="ln up"></i>inferred uplink</div>
      <div><i class="ln dom"></i>same AD domain</div>
      <div class="muted">${tr ? "traceroute on: hops observed" : "traceroute off: paths inferred"}</div>`;
  }
}

window.NetMap = NetMap;
