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

"""FastAPI app: serves the dashboard and the scan API on :8040 (local only)."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config, report, store
from .fingerprint import rules
from .llm import ollama
from .scanner import discovery, pipeline

app = FastAPI(title="d1sc0v3r", docs_url="/api/docs")

STATIC = Path(__file__).parent / "web" / "static"


@app.on_event("startup")
def _startup():
    config.ensure_dirs()
    store.init()
    # If the container restarted while scans were running, their tasks died but
    # their DB rows still claim 'sweeping'. Heal that on every boot.
    fixed = store.reconcile_orphans(live_ids=set(pipeline._running.keys()))
    if fixed:
        print(f"[startup] reconciled {len(fixed)} orphaned scan(s): {fixed}")


# --- models ----------------------------------------------------------------
class ScanRequest(BaseModel):
    subnets: str
    profile: str = config.DEFAULT_PROFILE


# --- api -------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return {"ok": True, "llm": await ollama.health(), "profiles": config.PROFILES}


@app.post("/api/preview")
def preview(req: ScanRequest):
    """Validate pasted subnets without scanning — shows host count + rejects."""
    valid, bad = discovery.parse_subnets(req.subnets)
    return {
        "subnets": valid,
        "rejected": bad,
        "estimated_hosts": discovery.estimate_hosts(valid) if valid else 0,
    }


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    valid, bad = discovery.parse_subnets(req.subnets)
    if not valid:
        raise HTTPException(400, f"No valid subnets. Rejected: {bad}")
    if req.profile not in config.PROFILES:
        raise HTTPException(400, f"Unknown profile {req.profile}")
    scan = await pipeline.run_scan(valid, req.profile)
    return {"scan_id": scan.id, "rejected": bad}


@app.get("/api/scans")
def scans():
    return store.list_scans()


@app.get("/api/scan/{scan_id}")
def scan_detail(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    hosts = [h.to_dict() for h in store.get_hosts(scan_id)]
    # priority order: critical→clean, then score desc
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "clean": 4}
    hosts.sort(key=lambda h: (order.get(h["priority_level"], 9), -h["priority_score"]))
    return {"scan": scan.to_dict(), "hosts": hosts}


@app.get("/api/scan/{scan_id}/report.md")
def report_md(scan_id: str, engagement: str = ""):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    md = report.to_markdown(scan, store.get_hosts(scan_id), engagement)
    fname = f"{report.safe_slug(engagement) if engagement else 'discovery'}-{scan_id}.md"
    return PlainTextResponse(
        md, media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/api/scan/{scan_id}/report.csv")
def report_csv(scan_id: str, engagement: str = ""):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    csv_text = report.to_csv(store.get_hosts(scan_id))
    fname = f"{report.safe_slug(engagement) if engagement else 'discovery'}-{scan_id}.csv"
    return Response(
        csv_text, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.post("/api/scan/{scan_id}/stop")
def stop(scan_id: str):
    return {"stopped": pipeline.stop_scan(scan_id)}


@app.post("/api/scans/stop_all")
def stop_all():
    """Cancel live tasks AND clean up any stale 'still sweeping' DB rows that
    are orphans from a previous restart."""
    cancelled = pipeline.stop_all_scans()
    orphaned = store.reconcile_orphans(live_ids=set(pipeline._running.keys()))
    return {"cancelled": cancelled, "orphaned_fixed": len(orphaned)}


@app.get("/api/scans/running")
def running():
    return {"count": pipeline.running_count()}


@app.post("/api/scan/{scan_id}/recategorize")
def recategorize(scan_id: str):
    """Re-apply the categorization + priority rules to a stored scan, without
    rescanning. Useful after tightening a rule. Preserves LLM enrichments."""
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan not found")
    hosts = store.get_hosts(scan_id)
    changed = 0
    for h in hosts:
        prev_cat, prev_lvl = h.category, h.priority_level
        llm_cat, llm_story, llm_rationale = h.llm_category, h.llm_story, h.llm_rationale
        rules.categorize(h)
        rules.score_priority(h)
        # restore LLM enrichment + adopt LLM category if rules still uncertain
        h.llm_category, h.llm_story, h.llm_rationale = llm_cat, llm_story, llm_rationale
        if llm_cat and h.confidence < 0.6:
            h.category, h.category_source = llm_cat, "llm"
        store.save_host(scan_id, h)
        if (h.category, h.priority_level) != (prev_cat, prev_lvl):
            changed += 1
    return {"recategorized": len(hosts), "changed": changed}


@app.delete("/api/scan/{scan_id}")
def delete(scan_id: str):
    # cancel a live task first so we don't leave a ghost scanning into a row
    # that no longer exists
    cancelled = pipeline.stop_scan(scan_id)
    store.delete_scan(scan_id)
    return {"deleted": True, "cancelled_running": cancelled}


# --- ui --------------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
