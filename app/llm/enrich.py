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

"""Use qwen3 to (a) categorize hosts the rules were unsure about, and (b) write
a short priority 'story' for high-value targets the operator should hit first.

The model only sees scan evidence (ports, versions, OS guess, banners) — never
anything outside the engagement. Output augments, never silently overrides:
LLM category is recorded separately and only adopted when rules had low
confidence.
"""
from __future__ import annotations

from ..models import CATEGORIES, Host
from . import ollama

_CAT_SYSTEM = (
    "You are a network asset classifier for an authorized penetration test. "
    "Given nmap evidence about one host, classify it into exactly one category "
    f"from this list: {', '.join(CATEGORIES)}. "
    "Respond ONLY with JSON: {\"category\": <one category>, \"confidence\": <0..1>, "
    "\"rationale\": <one sentence>}."
)

_STORY_SYSTEM = (
    "You are a senior penetration tester triaging discovery results on an "
    "authorized engagement. Given evidence about one host, write a concise "
    "operator-facing note (2-4 sentences) on WHY this host matters and the "
    "first concrete avenue to investigate (e.g. likely exposed service, known "
    "weak version, default-cred-prone device, lateral-movement value). Be "
    "specific and practical; do not invent versions not in the evidence. "
    "Respond ONLY with JSON: {\"story\": <text>}."
)


def _evidence(host: Host) -> str:
    lines = [f"IP: {host.ip}"]
    if host.hostname:
        lines.append(f"Hostname: {host.hostname}")
    if host.vendor:
        lines.append(f"MAC vendor: {host.vendor}")
    if host.os_guess:
        lines.append(f"OS guess: {host.os_guess} ({host.os_accuracy}%)")
    lines.append(f"Rule category: {host.category} (conf {host.confidence:.2f})")
    if host.reasons:
        lines.append("Flags: " + "; ".join(host.reasons))
    lines.append("Open ports / services:")
    for p in host.open_ports():
        extra = ""
        if p.scripts:
            joined = " | ".join(f"{k}: {v[:160]}" for k, v in p.scripts.items())
            extra = f"  [{joined}]"
        lines.append(f"  {p.port}/{p.proto} {p.label()}{extra}")
    return "\n".join(lines)


async def enrich_host(host: Host) -> None:
    """Mutates host with LLM category (if rules unsure) and a story (if juicy)."""
    evidence = _evidence(host)

    # categorize when rules had low confidence
    if host.confidence < 0.6:
        res = await ollama.chat_json(_CAT_SYSTEM, evidence)
        if res and res.get("category") in CATEGORIES:
            host.llm_category = res["category"]
            host.llm_rationale = str(res.get("rationale", ""))[:300]
            # adopt the LLM call since rules weren't confident
            host.category = res["category"]
            host.category_source = "llm"
            try:
                host.confidence = max(host.confidence, float(res.get("confidence", 0.6)))
            except (TypeError, ValueError):
                pass

    # write a priority story for high-value targets
    if host.priority_level in ("critical", "high"):
        res = await ollama.chat_json(_STORY_SYSTEM, evidence)
        if res and res.get("story"):
            host.llm_story = str(res["story"])[:800]
