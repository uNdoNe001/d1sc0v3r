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

"""Scan orchestration. Runs as a background asyncio task per scan and walks the
stages: discover → deep scan → categorize/score → LLM enrich. Progress is
persisted to the store after each stage so the UI can poll it."""
from __future__ import annotations

import asyncio
import time
import traceback
import uuid
from datetime import datetime, timezone

from .. import config, store
from ..fingerprint import rules
from ..llm import enrich
from ..models import Scan
from . import deepscan, discovery

# scan_id -> asyncio.Task, so we can stop running scans
_running: dict[str, asyncio.Task] = {}


def new_scan_id() -> str:
    return uuid.uuid4().hex[:12]


async def _update(scan: Scan, *, status=None, stage=None, progress=None, **totals):
    if status:
        scan.status = status
    if stage:
        scan.stage = stage
    if progress is not None:
        scan.progress = round(progress, 3)
    if totals:
        scan.totals.update(totals)
    store.save_scan(scan)


async def run_scan(subnets: list[str], profile_name: str) -> Scan:
    profile = config.PROFILES.get(profile_name, config.PROFILES[config.DEFAULT_PROFILE])
    scan = Scan(
        id=new_scan_id(),
        created_at=datetime.now(timezone.utc).isoformat(),
        subnets=subnets,
        profile=profile_name,
        status="queued",
        totals={"estimated_hosts": discovery.estimate_hosts(subnets)},
    )
    store.save_scan(scan)
    task = asyncio.create_task(_drive(scan, profile))
    _running[scan.id] = task
    return scan


def stop_scan(scan_id: str) -> bool:
    task = _running.get(scan_id)
    if task and not task.done():
        task.cancel()
        return True
    return False


def stop_all_scans() -> int:
    """Cancel every running scan. Returns the count cancelled. Subprocesses are
    killed in discovery._run's finally block so masscan/nmap die with the task."""
    n = 0
    for scan_id, task in list(_running.items()):
        if not task.done():
            task.cancel()
            n += 1
    return n


def running_count() -> int:
    return sum(1 for t in _running.values() if not t.done())


async def _drive(scan: Scan, profile: dict):
    started = time.time()
    try:
        # --- stage 1: discovery ---------------------------------------------
        await _update(scan, status="sweeping", stage="Sweeping subnets for live hosts", progress=0.05)
        targets = await discovery.discover(scan.subnets, profile["masscan_rate"], profile["icmp"])
        live = len(targets)
        interesting = {ip: ports for ip, ports in targets.items() if ports}
        await _update(
            scan, stage=f"Found {live} live hosts, {len(interesting)} with open ports",
            progress=0.25, live_hosts=live, interesting_hosts=len(interesting),
        )

        if not targets:
            await _update(scan, status="done", stage="No live hosts found", progress=1.0)
            return

        # persist bare live hosts immediately (so clean assets are logged even
        # before deep scan finishes)
        from ..models import Host, Port
        for ip, ports in targets.items():
            h = Host(ip=ip, ports=[Port(port=p) for p in sorted(ports)])
            rules.categorize(h)
            rules.score_priority(h)
            store.save_host(scan.id, h)

        # --- stage 2: deep scan ---------------------------------------------
        await _update(scan, status="deep", stage="Deep nmap -sV on interesting hosts", progress=0.3)

        async def deep_progress(done, total, ip):
            frac = 0.3 + 0.5 * (done / max(total, 1))
            await _update(scan, stage=f"Deep scan {done}/{total} ({ip})", progress=frac)

        deep_targets = interesting or targets
        hosts = await deepscan.deep_scan_all(deep_targets, scan.id, profile, deep_progress)

        # --- stage 3: categorize + score ------------------------------------
        await _update(scan, status="analyzing", stage="Categorizing & scoring", progress=0.82)
        for h in hosts:
            rules.categorize(h)
            rules.score_priority(h)
            store.save_host(scan.id, h)

        # --- stage 4: LLM enrichment ----------------------------------------
        to_enrich = [h for h in hosts if rules.needs_llm(h)]
        if config.LLM_ENABLED and to_enrich:
            sem = asyncio.Semaphore(3)   # don't hammer the 8B box

            async def enrich_one(idx, h):
                async with sem:
                    await enrich.enrich_host(h)
                store.save_host(scan.id, h)
                await _update(
                    scan, stage=f"qwen3 enriching {idx + 1}/{len(to_enrich)}",
                    progress=0.85 + 0.13 * ((idx + 1) / len(to_enrich)),
                )

            await asyncio.gather(*(enrich_one(i, h) for i, h in enumerate(to_enrich)))

        # --- done -----------------------------------------------------------
        all_hosts = store.get_hosts(scan.id)
        buckets: dict[str, int] = {}
        for h in all_hosts:
            buckets[h.priority_level] = buckets.get(h.priority_level, 0) + 1
        elapsed = int(time.time() - started)
        await _update(
            scan, status="done",
            stage=f"Complete in {elapsed}s — {len(all_hosts)} assets",
            progress=1.0, elapsed_s=elapsed, total_assets=len(all_hosts),
            llm_enriched=len(to_enrich) if config.LLM_ENABLED else 0,
            **{f"prio_{k}": v for k, v in buckets.items()},
        )

    except asyncio.CancelledError:
        await _update(scan, status="stopped", stage="Stopped by operator")
        raise
    except Exception:
        scan.error = traceback.format_exc()[-2000:]
        await _update(scan, status="error", stage="Error — see details")
    finally:
        _running.pop(scan.id, None)
