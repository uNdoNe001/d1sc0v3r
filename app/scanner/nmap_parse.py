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

"""Parse nmap XML into our Host/Port models."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ..models import Host, Port


def parse_nmap_xml(xml_text: str) -> list[Host]:
    hosts: list[Host] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") == "down":
            continue

        ip = ""
        mac = ""
        vendor = ""
        for addr in h.findall("address"):
            kind = addr.get("addrtype")
            if kind in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
            elif kind == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        if not ip:
            continue

        host = Host(ip=ip, mac=mac, vendor=vendor)

        hn = h.find("hostnames/hostname")
        if hn is not None:
            host.hostname = hn.get("name", "")

        # OS detection
        osmatch = h.find("os/osmatch")
        if osmatch is not None:
            host.os_guess = osmatch.get("name", "")
            try:
                host.os_accuracy = int(osmatch.get("accuracy", "0"))
            except ValueError:
                host.os_accuracy = 0

        for port_el in h.findall("ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state not in ("open", "open|filtered"):
                continue
            p = Port(
                port=int(port_el.get("portid", "0")),
                proto=port_el.get("protocol", "tcp"),
                state="open",
            )
            svc = port_el.find("service")
            if svc is not None:
                p.service = svc.get("name", "")
                p.product = svc.get("product", "")
                p.version = svc.get("version", "")
                p.extrainfo = svc.get("extrainfo", "")
                p.cpe = [c.text for c in svc.findall("cpe") if c.text]
            for scr in port_el.findall("script"):
                sid = scr.get("id", "")
                out = scr.get("output", "")
                if sid:
                    p.scripts[sid] = out
            host.ports.append(p)

        hosts.append(host)
    return hosts
