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

"""Central configuration: paths, LLM endpoint, scan profiles, port lists.

Everything tunable lives here so you can adjust scan aggressiveness or the
interesting-ports set without hunting through the scanner code.
"""
import os
from pathlib import Path

# --- paths -----------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("D1_DATA_DIR", BASE_DIR.parent / "data"))
DB_PATH = DATA_DIR / "d1sc0v3r.db"
RAW_DIR = DATA_DIR / "raw"          # raw nmap xml per host, for evidence/backup

# --- web -------------------------------------------------------------------
HOST = os.getenv("D1_HOST", "127.0.0.1")
PORT = int(os.getenv("D1_PORT", "8040"))

# --- llm (local qwen3 via Ollama) ------------------------------------------
LLM_URL = os.getenv("D1_LLM_URL", "http://127.0.0.1:11434")
LLM_MODEL = os.getenv("D1_LLM_MODEL", "qwen3:8b")
LLM_TIMEOUT = float(os.getenv("D1_LLM_TIMEOUT", "90"))
LLM_ENABLED = os.getenv("D1_LLM_ENABLED", "1") != "0"

# --- interesting ports for the fast sweep ----------------------------------
# Curated for pentest discovery: remote access, auth/dir services, web, db,
# mgmt, printers, cameras, voip, virtualization, IPMI. Hitting a host on any of
# these flags it as "interesting" and queues it for a deep nmap -sV pass.
SWEEP_PORTS = [
    21, 22, 23, 25, 53, 79, 80, 88, 110, 111, 113, 119, 123, 135, 137, 139,
    143, 161, 179, 389, 443, 445, 465, 500, 502, 512, 513, 514, 515, 543, 544,
    548, 554, 587, 593, 623, 631, 636, 873, 902, 989, 990, 993, 995, 1080, 1099,
    1194, 1234, 1433, 1434, 1521, 1604, 1723, 1883, 1900, 2000, 2049, 2082, 2083,
    2222, 2375, 2376, 2379, 2483, 2484, 3000, 3128, 3260, 3268, 3269, 3306, 3389,
    3478, 3632, 3690, 4443, 4444, 4567, 4786, 4848, 5000, 5001, 5006, 5009, 5051,
    5060, 5061, 5222, 5353, 5357, 5432, 5560, 5601, 5631, 5666, 5672, 5800, 5900,
    5901, 5984, 5985, 5986, 6000, 6379, 6443, 6667, 7000, 7001, 7070, 7080, 7474,
    7547, 7657, 8000, 8008, 8009, 8010, 8020, 8042, 8060, 8069, 8080, 8081, 8083,
    8086, 8088, 8089, 8090, 8123, 8161, 8181, 8200, 8222, 8243, 8280, 8333, 8400,
    8443, 8500, 8530, 8531, 8800, 8834, 8880, 8888, 8983, 9000, 9001, 9002, 9042,
    9060, 9080, 9090, 9091, 9100, 9200, 9300, 9389, 9443, 9999, 10000, 10250,
    11211, 12345, 16992, 16993, 27017, 27018, 28017, 32400, 49152, 49153, 50000,
    50070, 61616,
    # local AI / inference stacks
    11434,  # Ollama
    7860,   # Gradio (Automatic1111, oobabooga text-generation-webui)
    8188,   # ComfyUI
    8265,   # Ray dashboard
    1235,   # LM Studio (alt)
    11435,  # Ollama (alt / second instance)
]

# --- scan profiles ---------------------------------------------------------
# Each profile tunes how loud/fast the sweep and deep scan are.
#   masscan_rate : packets/sec for the sweep (higher = faster, louder)
#   nmap_timing  : nmap -T value for the deep -sV pass
#   nmap_scripts : default NSE scripts on the deep pass (kept safe/non-DoS)
#   os_detect    : run nmap -O (needs raw sockets; helps categorization)
PROFILES = {
    "stealth": {
        "label": "Stealth — slow & quiet",
        "masscan_rate": 300,
        "nmap_timing": 2,
        "nmap_scripts": "banner",
        "os_detect": False,
        "icmp": False,
    },
    "balanced": {
        "label": "Balanced — default",
        "masscan_rate": 1500,
        "nmap_timing": 4,
        "nmap_scripts": "banner,default",
        "os_detect": True,
        "icmp": True,
    },
    "aggressive": {
        "label": "Aggressive — fast & loud (internal)",
        "masscan_rate": 8000,
        "nmap_timing": 4,
        "nmap_scripts": "banner,default,vuln",
        "os_detect": True,
        "icmp": True,
    },
}
DEFAULT_PROFILE = "balanced"

# Cap how many hosts get the deep nmap pass concurrently (resource guard).
DEEP_SCAN_CONCURRENCY = int(os.getenv("D1_DEEP_CONCURRENCY", "8"))


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
