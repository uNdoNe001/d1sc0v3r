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

"""SQLite persistence. One db file under data/ — that's your backup target.

Scans and their hosts are stored as JSON blobs in two tables. Simple, durable,
and trivial to copy. A module-level lock serializes writes since scans run in
background tasks while the API reads concurrently.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from . import config
from .models import Host, Port, Scan

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def init() -> None:
    global _conn
    config.ensure_dirs()
    _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    with _lock:
        _conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id          TEXT PRIMARY KEY,
                created_at  TEXT NOT NULL,
                status      TEXT NOT NULL,
                data        TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hosts (
                scan_id     TEXT NOT NULL,
                ip          TEXT NOT NULL,
                data        TEXT NOT NULL,
                PRIMARY KEY (scan_id, ip)
            );
            CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
            """
        )
        _conn.commit()


def _c() -> sqlite3.Connection:
    if _conn is None:
        raise RuntimeError("store.init() not called")
    return _conn


# --- scans -----------------------------------------------------------------
def save_scan(scan: Scan) -> None:
    with _lock:
        _c().execute(
            "INSERT OR REPLACE INTO scans (id, created_at, status, data) VALUES (?,?,?,?)",
            (scan.id, scan.created_at, scan.status, json.dumps(scan.to_dict())),
        )
        _c().commit()


def get_scan(scan_id: str) -> Scan | None:
    with _lock:
        row = _c().execute("SELECT data FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    return Scan(**json.loads(row["data"]))


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    with _lock:
        rows = _c().execute(
            "SELECT data FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [json.loads(r["data"]) for r in rows]


def delete_scan(scan_id: str) -> None:
    """Remove a scan's DB rows AND its raw nmap XML evidence on disk."""
    with _lock:
        _c().execute("DELETE FROM hosts WHERE scan_id=?", (scan_id,))
        _c().execute("DELETE FROM scans WHERE id=?", (scan_id,))
        _c().commit()
    # nmap XML files are named "<scan_id>_<ip>.xml" — wipe all matches
    for xml in config.RAW_DIR.glob(f"{scan_id}_*.xml"):
        try:
            xml.unlink()
        except OSError:
            pass


def reconcile_orphans(live_ids: set[str]) -> list[str]:
    """Any scan with a 'still running' status that isn't actually in the live
    set is an orphan (container restart killed its task). Mark them stopped so
    the UI stops claiming they're sweeping forever. Returns the IDs fixed."""
    active = {"queued", "sweeping", "deep", "analyzing"}
    fixed: list[str] = []
    with _lock:
        rows = _c().execute("SELECT id, data FROM scans").fetchall()
        for r in rows:
            d = json.loads(r["data"])
            if d.get("status") in active and r["id"] not in live_ids:
                d["status"] = "stopped"
                d["stage"] = "Orphaned — container restarted before completion"
                _c().execute(
                    "UPDATE scans SET status=?, data=? WHERE id=?",
                    ("stopped", json.dumps(d), r["id"]),
                )
                fixed.append(r["id"])
        if fixed:
            _c().commit()
    return fixed


# --- hosts -----------------------------------------------------------------
def _host_to_row(host: Host) -> str:
    d = {k: v for k, v in host.__dict__.items()}
    d["ports"] = [p.__dict__ for p in host.ports]
    return json.dumps(d)


def _row_to_host(data: str) -> Host:
    d = json.loads(data)
    ports = [Port(**p) for p in d.pop("ports", [])]
    h = Host(**{k: v for k, v in d.items() if k in Host.__dataclass_fields__})
    h.ports = ports
    return h


def save_host(scan_id: str, host: Host) -> None:
    with _lock:
        _c().execute(
            "INSERT OR REPLACE INTO hosts (scan_id, ip, data) VALUES (?,?,?)",
            (scan_id, host.ip, _host_to_row(host)),
        )
        _c().commit()


def save_hosts(scan_id: str, hosts: list[Host]) -> None:
    with _lock:
        _c().executemany(
            "INSERT OR REPLACE INTO hosts (scan_id, ip, data) VALUES (?,?,?)",
            [(scan_id, h.ip, _host_to_row(h)) for h in hosts],
        )
        _c().commit()


def get_hosts(scan_id: str) -> list[Host]:
    with _lock:
        rows = _c().execute(
            "SELECT data FROM hosts WHERE scan_id=?", (scan_id,)
        ).fetchall()
    return [_row_to_host(r["data"]) for r in rows]
