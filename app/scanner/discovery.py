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

"""Fast discovery sweep.

Two parallel signals to decide what's live:
  * fping  — ICMP echo across the ranges (routes fine over VPN/L3).
  * masscan — SYN sweep of the interesting-ports set (catches hosts that drop
              ICMP, and gives us open ports for free to seed the deep scan).

masscan picks ARP for on-link targets and SYN for routed ones automatically, so
this works whether we're on Linux host networking or bridged on Windows.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import shutil
import tempfile
from pathlib import Path

from .. import config


def parse_subnets(raw: str) -> tuple[list[str], list[str]]:
    """Split pasted text into valid CIDRs/IPs and rejects. Accepts commas,
    whitespace, or newlines; bare IPs become /32."""
    valid: list[str] = []
    bad: list[str] = []
    tokens = [t.strip() for t in raw.replace(",", "\n").split() if t.strip()]
    for tok in tokens:
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
            else:
                net = ipaddress.ip_network(f"{tok}/32", strict=False)
            valid.append(str(net))
        except ValueError:
            bad.append(tok)
    # de-dupe, preserve order
    seen: set[str] = set()
    uniq = [n for n in valid if not (n in seen or seen.add(n))]
    return uniq, bad


def estimate_hosts(subnets: list[str]) -> int:
    total = 0
    for s in subnets:
        net = ipaddress.ip_network(s, strict=False)
        total += net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2
    return total


async def _run(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    """Run a subprocess and ALWAYS reap it. If the caller's task is cancelled
    (operator hit Stop) or we hit the timeout, we SIGKILL the child so masscan/
    nmap don't keep blasting the network after the scan was 'stopped'."""
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")
    except asyncio.TimeoutError:
        return 124, "", "timeout"
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass


async def fping_sweep(subnets: list[str], timeout: float = 600) -> set[str]:
    """ICMP liveness. Returns set of responding IPs."""
    if not shutil.which("fping"):
        return set()
    cmd = ["fping", "-a", "-q", "-r", "1", "-t", "300", "-g", *subnets]
    # fping -g wants ranges; it accepts CIDR per arg. Multiple via repeated -g
    # isn't supported, so feed each network separately and merge.
    alive: set[str] = set()
    for net in subnets:
        rc, out, _ = await _run(["fping", "-a", "-q", "-r", "1", "-t", "300", "-g", net], timeout)
        for line in out.splitlines():
            ip = line.strip()
            if ip:
                alive.add(ip)
    return alive


async def masscan_sweep(subnets: list[str], rate: int, timeout: float = 1800) -> dict[str, set[int]]:
    """SYN sweep of SWEEP_PORTS. Returns {ip: {open_ports}}."""
    if not shutil.which("masscan"):
        return {}
    ports = ",".join(str(p) for p in config.SWEEP_PORTS)
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        out_path = tf.name
    cmd = [
        "masscan", *subnets,
        "-p", ports,
        "--rate", str(rate),
        "--wait", "2",
        "-oJ", out_path,
    ]
    await _run(cmd, timeout)
    results: dict[str, set[int]] = {}
    try:
        text = Path(out_path).read_text(errors="replace").strip()
        # masscan json is a list of {ip, ports:[{port,proto,status}]} records
        # but can be malformed (trailing comma / no closing bracket) if killed.
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = rec.get("ip")
            for p in rec.get("ports", []):
                if p.get("status") == "open":
                    results.setdefault(ip, set()).add(int(p["port"]))
    finally:
        Path(out_path).unlink(missing_ok=True)
    return results


async def discover(subnets: list[str], rate: int, icmp: bool) -> dict[str, set[int]]:
    """Run both sweeps concurrently and merge. Returns {ip: {open_ports}}.
    Hosts alive via ICMP only show up with an empty port set."""
    tasks = [masscan_sweep(subnets, rate)]
    if icmp:
        tasks.append(fping_sweep(subnets))
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    ports_map: dict[str, set[int]] = {}
    masscan_res = gathered[0] if not isinstance(gathered[0], Exception) else {}
    for ip, ports in masscan_res.items():
        ports_map.setdefault(ip, set()).update(ports)

    if icmp and len(gathered) > 1 and not isinstance(gathered[1], Exception):
        for ip in gathered[1]:
            ports_map.setdefault(ip, set())

    return ports_map
