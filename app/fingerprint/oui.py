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

"""Tiny built-in MAC OUI → vendor/device-class hint map. nmap already resolves
vendor strings when it has the MAC; this gives us a device-class nudge for
categorization (e.g. an HP/Canon NIC strongly implies a printer) without
shipping the full IEEE OUI database."""
from __future__ import annotations

# vendor substring -> coarse device class hint
VENDOR_CLASS = {
    "hewlett": "printer",
    "hp inc": "printer",
    "canon": "printer",
    "brother": "printer",
    "lexmark": "printer",
    "xerox": "printer",
    "kyocera": "printer",
    "ricoh": "printer",
    "epson": "printer",
    "zebra": "printer",
    "axis": "ip-camera",
    "hikvision": "ip-camera",
    "dahua": "ip-camera",
    "hanwha": "ip-camera",
    "ubiquiti": "network-switch",
    "mikrotik": "router-firewall",
    "cisco": "network-switch",
    "juniper": "network-switch",
    "fortinet": "router-firewall",
    "palo alto": "router-firewall",
    "sonicwall": "router-firewall",
    "netgear": "network-switch",
    "tp-link": "network-switch",
    "aruba": "network-switch",
    "vmware": "hypervisor",
    "synology": "storage-nas",
    "qnap": "storage-nas",
    "raspberry": "iot-device",
    "espressif": "iot-device",
    "polycom": "voip",
    "yealink": "voip",
    "avaya": "voip",
    "grandstream": "voip",
}


def vendor_hint(vendor: str) -> str:
    v = (vendor or "").lower()
    for key, cls in VENDOR_CLASS.items():
        if key in v:
            return cls
    return ""
