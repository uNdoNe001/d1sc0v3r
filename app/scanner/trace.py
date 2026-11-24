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

"""Optional traceroute stage. Off by default: it sends TTL-limited probes to
every live host, which is slower and shows up in IDS/firewall logs. When on, the
network map draws observed router hops instead of inferring subnet uplinks.

Uses nmap's --traceroute on a host-discovery-only pass (-sn), so no ports are
touched. nmap reuses shared hops between targets in one run, so hosts are
batched to keep the probe count down."""
from __future__ import annotations

import shutil
from pathlib import Path

from .. import config
from .discovery import _run
from .nmap_parse import parse_nmap_xml

BATCH = 256


async def trace_all(ips: list[str], scan_id: str, profile: dict,
                    progress_cb=None) -> dict[str, list[dict]]:
    """Traceroute every IP. Returns {ip: [hop, ...]} for hosts that answered."""
    if not shutil.which("nmap") or not ips:
        return {}
    traces: dict[str, list[dict]] = {}
    batches = [ips[i:i + BATCH] for i in range(0, len(ips), BATCH)]
    for n, batch in enumerate(batches):
        raw_path = config.RAW_DIR / f"{scan_id}_trace_{n}.xml"
        cmd = [
            "nmap", "-sn", "--traceroute",
            f"-T{profile['nmap_timing']}",
            "-oX", str(raw_path), *batch,
        ]
        await _run(cmd, timeout=900)
        try:
            parsed = parse_nmap_xml(Path(raw_path).read_text(errors="replace"))
        except FileNotFoundError:
            parsed = []
        for h in parsed:
            if h.trace:
                traces[h.ip] = h.trace
        if progress_cb:
            await progress_cb(n + 1, len(batches))
    return traces
