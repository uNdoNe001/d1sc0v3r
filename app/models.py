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

"""Typed shapes for scans, hosts, and ports. Kept as plain dataclasses so they
serialize cleanly to/from sqlite JSON columns and to the web API."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


# Categories the fingerprinter / LLM can assign.
CATEGORIES = [
    "domain-controller",
    "windows-server",
    "windows-workstation",
    "linux-server",
    "web-server",
    "database",
    "hypervisor",
    "storage-nas",
    "printer",
    "ip-camera",
    "voip",
    "iot-device",
    "router-firewall",
    "network-switch",
    "unknown",
    "clean",          # alive but nothing interesting exposed
]

# Priority buckets, high→low.
PRIORITY_LEVELS = ["critical", "high", "medium", "low", "clean"]


@dataclass
class Port:
    port: int
    proto: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)  # nse id -> output

    def label(self) -> str:
        bits = [self.service or "?"]
        if self.product:
            bits.append(self.product)
        if self.version:
            bits.append(self.version)
        return " ".join(bits)


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""          # from MAC OUI
    hostname: str = ""
    alive: bool = True
    os_guess: str = ""
    os_accuracy: int = 0
    ports: list[Port] = field(default_factory=list)

    # categorization
    category: str = "unknown"
    category_source: str = "rules"     # "rules" | "llm"
    confidence: float = 0.0

    # prioritization
    priority_score: int = 0
    priority_level: str = "low"
    reasons: list[str] = field(default_factory=list)   # rule-derived flags

    # llm enrichment
    llm_category: str = ""
    llm_rationale: str = ""
    llm_story: str = ""        # the "this is juicy, here's why" narrative

    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["port_summary"] = sorted({p.port for p in self.open_ports()})
        return d


@dataclass
class Scan:
    id: str
    created_at: str
    subnets: list[str]
    profile: str
    status: str = "queued"      # queued|sweeping|deep|analyzing|done|error|stopped
    stage: str = ""             # human-readable current step
    progress: float = 0.0       # 0..1
    error: str = ""
    totals: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
