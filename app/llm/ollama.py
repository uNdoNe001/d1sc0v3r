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

"""Minimal async Ollama client for the local qwen3:8b.

qwen3 is a reasoning model — Ollama may emit a <think>...</think> block. We ask
it to skip thinking (think=false) and also strip any stray block defensively.
All calls are best-effort: on any error we return None so the pipeline falls
back to rule-based results and never blocks on the LLM.
"""
from __future__ import annotations

import json
import re

import httpx

from .. import config

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def _strip_think(text: str) -> str:
    return _THINK_RE.sub("", text).strip()


async def chat_json(system: str, user: str) -> dict | None:
    """Ask qwen3 for a JSON object. Returns parsed dict or None on failure."""
    if not config.LLM_ENABLED:
        return None
    payload = {
        "model": config.LLM_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "format": "json",
        "think": False,
        "stream": False,
        "options": {"temperature": 0.2, "num_ctx": 8192},
    }
    try:
        async with httpx.AsyncClient(timeout=config.LLM_TIMEOUT) as client:
            r = await client.post(f"{config.LLM_URL}/api/chat", json=payload)
            r.raise_for_status()
            content = r.json().get("message", {}).get("content", "")
    except Exception:
        return None

    content = _strip_think(content)
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # try to salvage the first {...} blob
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


async def health() -> dict:
    """Check the LLM endpoint and confirm the model is present."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{config.LLM_URL}/api/tags")
            r.raise_for_status()
            models = [m.get("name") for m in r.json().get("models", [])]
            return {
                "ok": True,
                "url": config.LLM_URL,
                "model": config.LLM_MODEL,
                "model_present": config.LLM_MODEL in models,
                "models": models,
            }
    except Exception as e:
        return {"ok": False, "url": config.LLM_URL, "error": str(e)}
