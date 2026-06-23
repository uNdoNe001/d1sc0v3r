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

"""Deep per-host nmap pass: service/version detection on the ports the sweep
found open, plus optional OS detection and NSE scripts. Raw XML is saved under
data/raw/ as evidence you can keep with the engagement backup."""
from __future__ import annotations

import asyncio
import shutil
import urllib.error
import urllib.request
from pathlib import Path

from .. import config
from ..models import Host, Port
from .discovery import _run
from .nmap_parse import parse_nmap_xml

# Path that confirms each AI stack + whether it answers without auth. nmap -sV
# can't speak these API dialects, so we probe out-of-band and stash the result
# in a synthetic NSE script field so the rules engine picks it up unchanged.
AI_PROBES = {
    11434: "/api/tags",     # Ollama
    11435: "/api/tags",
    8000:  "/v1/models",    # vLLM / LocalAI / OpenAI-compatible
    8080:  "/v1/models",
    1234:  "/v1/models",    # LM Studio
    1235:  "/v1/models",
    7860:  "/",             # Gradio (A1111 / oobabooga)
    8188:  "/system_stats", # ComfyUI
    8888:  "/api",          # Jupyter
}


def _probe_ai(ip: str, port: int, path: str) -> str | None:
    """Best-effort HTTP GET. Returns a short marker string for _haystack, or None."""
    for scheme in ("http", "https"):
        try:
            req = urllib.request.Request(f"{scheme}://{ip}:{port}{path}",
                                         headers={"User-Agent": "d1sc0v3r"})
            with urllib.request.urlopen(req, timeout=4) as r:   # nosec - authorized scan
                body = r.read(4096).decode("utf-8", "replace").lower()
                tag = f"ai-probe {path} http {r.status} unauthenticated"
                if "models" in body or "ollama" in body or "gradio" in body:
                    tag += " confirmed"
                return tag
        except urllib.error.HTTPError as e:
            return f"ai-probe {path} http {e.code} (auth required)" if e.code in (401, 403) else None
        except Exception:
            continue
    return None

# Targeted NSE scripts that only make sense when a given port is open. These
# pull SMB dialect/signing posture and NTLM info (domain/FQDN/OS build) — the
# signals that decide whether a Windows box is a relay/EternalBlue priority.
# All are info-gathering / safe-default; none are intrusive or DoS-prone.
SMB_SCRIPTS = "smb-protocols,smb-security-mode,smb2-security-mode,smb-os-discovery,smb2-capabilities"
NTLM_SCRIPTS_BY_PORT = {
    3389: "rdp-ntlm-info",
    80: "http-ntlm-info",
    443: "http-ntlm-info",
    8080: "http-ntlm-info",
    8443: "http-ntlm-info",
    1433: "ms-sql-ntlm-info",
    25: "smtp-ntlm-info",
    587: "smtp-ntlm-info",
    110: "pop3-ntlm-info",
    143: "imap-ntlm-info",
}


def _targeted_scripts(ports: set[int]) -> str:
    """Build the extra --script list based on which ports the host has open."""
    extra: list[str] = []
    if {139, 445} & ports:
        extra.append(SMB_SCRIPTS)
    for p in ports:
        if p in NTLM_SCRIPTS_BY_PORT:
            extra.append(NTLM_SCRIPTS_BY_PORT[p])
    return ",".join(dict.fromkeys(extra))  # de-dupe, keep order


async def deep_scan_host(ip: str, ports: set[int], scan_id: str, profile: dict) -> Host:
    """Run nmap -sV (+scripts/-O per profile) against one host's open ports."""
    if not ports:
        # ICMP-only host: try a light top-ports version scan so we still learn
        # something, but keep it quick.
        port_arg = ["--top-ports", "100"]
    else:
        port_arg = ["-p", ",".join(str(p) for p in sorted(ports))]

    raw_path = config.RAW_DIR / f"{scan_id}_{ip.replace(':', '_')}.xml"
    cmd = [
        "nmap", "-Pn", "-sV",
        f"-T{profile['nmap_timing']}",
        "--version-intensity", "5",
        *port_arg,
    ]
    scripts = [s for s in (profile.get("nmap_scripts", ""), _targeted_scripts(ports)) if s]
    if scripts:
        cmd += ["--script", ",".join(scripts)]
    if profile.get("os_detect"):
        cmd += ["-O", "--osscan-guess"]
    cmd += ["-oX", str(raw_path), ip]

    if not shutil.which("nmap"):
        return Host(ip=ip, ports=[Port(port=p) for p in sorted(ports)])

    await _run(cmd, timeout=900)

    try:
        xml_text = Path(raw_path).read_text(errors="replace")
        parsed = parse_nmap_xml(xml_text)
    except FileNotFoundError:
        parsed = []

    if parsed:
        host = parsed[0]
        # keep any sweep ports nmap didn't report (filtered but interesting)
        seen = {p.port for p in host.ports}
        for p in sorted(ports):
            if p not in seen:
                host.ports.append(Port(port=p, state="open", service="?"))
        # confirm any AI ports out-of-band (runs in a thread; nmap -sV won't
        # speak the LLM API dialects). Marker text lands in p.scripts so the
        # existing rules engine picks it up unchanged.
        loop = asyncio.get_running_loop()
        for p in host.ports:
            if p.port in AI_PROBES and p.state == "open":
                marker = await loop.run_in_executor(
                    None, _probe_ai, ip, p.port, AI_PROBES[p.port])
                if marker:
                    p.scripts["ai-probe"] = marker
        return host
    return Host(ip=ip, ports=[Port(port=p) for p in sorted(ports)])


async def deep_scan_all(targets: dict[str, set[int]], scan_id: str, profile: dict,
                        progress_cb=None) -> list[Host]:
    """Deep-scan every interesting host with bounded concurrency."""
    sem = asyncio.Semaphore(config.DEEP_SCAN_CONCURRENCY)
    results: list[Host] = []
    done = 0
    total = len(targets)
    lock = asyncio.Lock()

    async def one(ip: str, ports: set[int]):
        nonlocal done
        async with sem:
            host = await deep_scan_host(ip, ports, scan_id, profile)
        async with lock:
            results.append(host)
            done += 1
            if progress_cb:
                await progress_cb(done, total, ip)

    await asyncio.gather(*(one(ip, ports) for ip, ports in targets.items()))
    return results
