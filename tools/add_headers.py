#!/usr/bin/env python3
"""Idempotently prepend Apache-2.0 license headers to source files.

Run from the project root:  python3 tools/add_headers.py

Re-runs are safe — files already containing 'SPDX-License-Identifier' are
skipped. Add new file globs to TARGETS as the project grows.
"""
from __future__ import annotations

from pathlib import Path

YEAR = "2026"
NOTICE_LINES = [
    f"Copyright (c) {YEAR} Rick Bohm",
    "Summit Cyber Group, LLC",
    "SPDX-License-Identifier: Apache-2.0",
    "",
    'Licensed under the Apache License, Version 2.0 (the "License");',
    "you may not use this file except in compliance with the License.",
    "You may obtain a copy of the License at",
    "",
    "    http://www.apache.org/licenses/LICENSE-2.0",
    "",
    "Unless required by applicable law or agreed to in writing, software",
    'distributed under the License is distributed on an "AS IS" BASIS,',
    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
    "See the License for the specific language governing permissions and",
    "limitations under the License.",
]


def hash_header() -> str:
    return "\n".join(f"# {line}".rstrip() for line in NOTICE_LINES) + "\n"


def block_header() -> str:
    body = "\n".join(f" * {line}".rstrip() for line in NOTICE_LINES)
    return f"/*\n{body}\n */\n"


def html_header() -> str:
    body = "\n".join(f"  {line}".rstrip() for line in NOTICE_LINES)
    return f"<!--\n{body}\n-->\n"


ROOT = Path(__file__).resolve().parent.parent

# Each entry: (glob relative to project root, header-builder fn)
TARGETS: list[tuple[str, callable]] = [
    ("app/**/*.py", hash_header),
    ("app/web/static/*.css", block_header),
    ("app/web/static/*.js", block_header),
    ("app/web/static/*.html", html_header),
    ("Dockerfile", hash_header),
    ("docker-compose*.yml", hash_header),
    ("tools/*.py", hash_header),
]


def needs_header(path: Path) -> bool:
    try:
        head = path.read_text(errors="replace")[:2000]
    except OSError:
        return False
    return "SPDX-License-Identifier" not in head


def add_header(path: Path, header_text: str) -> None:
    content = path.read_text()
    # Preserve shebangs on line 1 (Python scripts) and the HTML doctype.
    if content.startswith("#!"):
        nl = content.find("\n") + 1
        new = content[:nl] + header_text + "\n" + content[nl:]
    elif content.lstrip().startswith("<!DOCTYPE"):
        nl = content.find("\n") + 1
        new = content[:nl] + header_text + "\n" + content[nl:]
    else:
        sep = "\n" if content and not content.startswith("\n") else ""
        new = header_text + sep + content
    path.write_text(new)


def main() -> None:
    added = skipped = 0
    for pattern, header_fn in TARGETS:
        for p in sorted(ROOT.glob(pattern)):
            if not p.is_file():
                continue
            if needs_header(p):
                add_header(p, header_fn())
                print(f"added  {p.relative_to(ROOT)}")
                added += 1
            else:
                print(f"skip   {p.relative_to(ROOT)} (already tagged)")
                skipped += 1
    print(f"\n{added} added, {skipped} skipped")


if __name__ == "__main__":
    main()
