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

"""Deterministic categorization + priority scoring.

Runs first, before any LLM. Produces a category, a confidence, a numeric
priority score, a bucket (critical/high/medium/low/clean), and human-readable
reason flags. Hosts the rules can't confidently place are marked low-confidence
so the pipeline can hand them to qwen3.
"""
from __future__ import annotations

from ..models import Host
from .oui import vendor_hint

# Known weak/dangerous version markers worth flagging when nmap reports them.
# (substring match on "product version extrainfo", lowercased)
RISKY_VERSION_MARKERS = [
    ("smbv1", "SMBv1 / legacy SMB"),
    ("microsoft-ds workgroup", "SMB exposed"),
    ("openssh 7.", "old OpenSSH 7.x"),
    ("openssh 6.", "old OpenSSH 6.x"),
    ("openssh 5.", "old OpenSSH 5.x"),
    ("vsftpd 2.3.4", "vsftpd 2.3.4 backdoor"),
    ("proftpd 1.3.3", "ProFTPD 1.3.3 RCE"),
    ("apache/2.2", "EOL Apache 2.2"),
    ("apache/2.4.49", "Apache 2.4.49 path traversal"),
    ("apache/2.4.50", "Apache 2.4.50 path traversal"),
    ("iis/6.0", "EOL IIS 6.0"),
    ("iis/7.", "old IIS 7.x"),
    ("php/5.", "EOL PHP 5.x"),
    ("microsoft windows xp", "Windows XP"),
    ("windows server 2003", "Windows Server 2003"),
    ("windows server 2008", "Windows Server 2008"),
    ("windows 7", "Windows 7 (EOL)"),
    ("samba smbd 3", "old Samba 3.x"),
    ("samba smbd 4.5", "old Samba 4.5"),
    ("mysql 5.", "old MySQL 5.x"),
    ("exim 4.8", "vulnerable Exim 4.8x"),
    ("log4j", "possible Log4j exposure"),
]

# Ports that should never just be "clean" — their mere presence is interesting.
JUICY_PORTS = {
    21: ("FTP", 8),
    23: ("Telnet (cleartext)", 18),
    445: ("SMB", 12),
    3389: ("RDP", 16),
    5985: ("WinRM", 12),
    5986: ("WinRM/TLS", 10),
    1433: ("MSSQL", 14),
    3306: ("MySQL", 12),
    5432: ("PostgreSQL", 12),
    6379: ("Redis (often no auth)", 18),
    27017: ("MongoDB (often no auth)", 18),
    11211: ("memcached", 14),
    9200: ("Elasticsearch (often no auth)", 16),
    2049: ("NFS export", 14),
    623: ("IPMI (BMC)", 16),
    161: ("SNMP", 10),
    512: ("rexec", 16),
    513: ("rlogin", 16),
    514: ("rsh/syslog", 12),
    5900: ("VNC", 16),
    2375: ("Docker API (unauth)", 22),
    2376: ("Docker API/TLS", 14),
    10250: ("Kubelet API", 18),
    8834: ("Nessus", 6),
    4786: ("Cisco Smart Install", 16),
}

# Domain-controller signal: kerberos + ldap + (global catalog | smb)
DC_PORTS = {88, 389, 636, 3268, 3269}
WIN_PORTS = {135, 139, 445}
DB_PORTS = {1433, 3306, 5432, 1521, 27017, 5984, 9042, 6379, 5984}
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008, 4443, 9443, 7001, 9090}
PRINTER_PORTS = {515, 631, 9100}
CAMERA_PORTS = {554}
VOIP_PORTS = {5060, 5061}
NET_MGMT_PORTS = {161, 162, 23}

# Local AI / inference stacks. Split into "unambiguous" (the port alone is a
# strong signal) vs "shared" web ports that need a banner/probe keyword to
# avoid stealing every generic web server.
AI_PORTS_STRONG = {11434, 11435, 7860, 8188, 8265, 1234, 1235}
AI_PORTS_SHARED = {8000, 8080, 3000, 5000, 8888}
AI_KEYWORDS = (
    "ollama", "llama.cpp", "lm studio", "lmstudio", "vllm", "localai",
    "open webui", "open-webui", "text-generation-webui", "gradio", "comfyui",
    "stable diffusion", "automatic1111", "koboldcpp", "tabbyapi", "jupyter",
    "ray dashboard", "triton inference", "huggingface", "/v1/models", "/api/tags",
    "ai-probe",
)


def _haystack(host: Host) -> str:
    parts = [host.os_guess, host.hostname, host.vendor]
    for p in host.ports:
        parts += [p.service, p.product, p.version, p.extrainfo]
        parts += list(p.scripts.values())
    return " ".join(parts).lower()


def categorize(host: Host) -> None:
    """Set host.category / category_source / confidence in place."""
    open_ports = {p.port for p in host.open_ports()}
    text = _haystack(host)
    vh = vendor_hint(host.vendor)

    def has(*ps) -> bool:
        return any(p in open_ports for p in ps)

    # --- high-confidence signals first --------------------------------------
    if (DC_PORTS & open_ports) and (88 in open_ports) and has(389, 636, 3268):
        host.category, host.confidence = "domain-controller", 0.95
    elif "windows" in text and (WIN_PORTS & open_ports):
        is_server = any(k in text for k in ("server", "iis", "active directory")) \
            or has(1433, 389, 53, 88, 3389) and not _looks_workstation(text)
        if "server" in text or has(1433, 53, 88):
            host.category, host.confidence = "windows-server", 0.85
        else:
            host.category, host.confidence = "windows-workstation", 0.8
    elif vh == "printer" or (PRINTER_PORTS & open_ports) or "jetdirect" in text or "printer" in text:
        host.category, host.confidence = "printer", 0.9
    # router/firewall BEFORE ip-camera — a /24 gateway is more common than a
    # camera and we want to catch consumer/OpenWrt/Linksys/UDM before loose
    # keyword matches steal it.
    elif vh in ("router-firewall",) or any(k in text for k in (
        "fortinet", "fortigate", "palo alto", "pan-os", "sonicwall", "pfsense",
        "opnsense", "mikrotik", "routeros", "openwrt", "dd-wrt", "tomato",
        "edgeos", "edgerouter", "ubiquiti unifi", "udm", "linksys", "wap upnpd",
        "openbsd", "vyos", "asuswrt", "merlin",
    )):
        host.category, host.confidence = "router-firewall", 0.85
    # Camera trigger tightened: require an actual camera signal (port 554,
    # vendor OUI, or word-boundary keyword), not loose substring matches.
    elif vh == "ip-camera" or (CAMERA_PORTS & open_ports) or any(k in text for k in (
        "rtsp", "ip camera", "ipcamera", "hikvision", "dahua", "axis communications",
        "network camera", "onvif",
    )):
        host.category, host.confidence = "ip-camera", 0.85
    elif vh == "network-switch" or any(k in text for k in ("cisco ios", "switch", "juniper", "arista", "procurve", "aruba")):
        host.category, host.confidence = "network-switch", 0.8
    elif vh == "hypervisor" or any(k in text for k in ("vmware esx", "esxi", "proxmox", "hyper-v", "xenserver")):
        host.category, host.confidence = "hypervisor", 0.85
    elif vh == "storage-nas" or any(k in text for k in ("synology", "qnap", "truenas", "freenas", "netapp")) or has(2049, 548, 3260):
        host.category, host.confidence = "storage-nas", 0.75
    elif vh == "voip" or (VOIP_PORTS & open_ports):
        host.category, host.confidence = "voip", 0.75
    # AI inference host: an unambiguous AI port, OR a shared web port plus an
    # AI keyword in the banner/NSE/probe text (or an AI keyword anywhere).
    elif (AI_PORTS_STRONG & open_ports) or \
         ((AI_PORTS_SHARED & open_ports) and any(k in text for k in AI_KEYWORDS)) or \
         any(k in text for k in AI_KEYWORDS):
        host.category, host.confidence = "ai-inference-host", 0.8
    elif DB_PORTS & open_ports:
        host.category, host.confidence = "database", 0.7
    elif "linux" in text and (open_ports - WEB_PORTS):
        host.category, host.confidence = "linux-server", 0.65
    elif WEB_PORTS & open_ports:
        host.category, host.confidence = "web-server", 0.55
    elif vh == "iot-device" or any(k in text for k in ("embedded", "busybox", "lighttpd", "boa/")):
        host.category, host.confidence = "iot-device", 0.55
    elif not open_ports:
        # alive but nothing in our port set → log as clean
        host.category, host.confidence = "clean", 0.4
    else:
        host.category, host.confidence = "unknown", 0.25

    host.category_source = "rules"


def _looks_workstation(text: str) -> bool:
    return any(k in text for k in ("windows 10", "windows 11", "windows 8", "workstation"))


def analyze_smb_ntlm(host: Host) -> tuple[int, list[str]]:
    """Inspect SMB/NTLM NSE output. Returns (score_delta, reason_flags).

    Decides the real Windows-priority signals:
      * SMBv1 dialect enabled        -> EternalBlue / legacy exposure (critical)
      * SMB signing not required     -> NTLM relay opportunity (high)
      * NTLM info leak               -> internal domain/FQDN/OS recon value
    Also backfills os_guess from smb-os-discovery when OS detection was blank.
    """
    delta = 0
    flags: list[str] = []
    for p in host.ports:
        for sid, out in p.scripts.items():
            low = out.lower()

            if sid == "smb-protocols":
                if "smbv1" in low or "nt lm 0.12" in low:
                    delta += 25
                    flags.append("SMBv1 enabled (EternalBlue / legacy)")

            if sid in ("smb-security-mode", "smb2-security-mode"):
                if "not required" in low or ("signing" in low and "disabled" in low):
                    delta += 18
                    flags.append("SMB signing not required (NTLM relay)")
                elif "enabled and required" in low or "required" in low:
                    flags.append("SMB signing enforced")

            if sid == "smb-os-discovery":
                if not host.os_guess:
                    for line in out.splitlines():
                        if line.strip().lower().startswith("os:"):
                            host.os_guess = line.split(":", 1)[1].strip()
                for key in ("domain", "forest", "fqdn", "computer name"):
                    for line in out.splitlines():
                        if line.strip().lower().startswith(key):
                            flags.append(line.strip())
                            break

            if sid.endswith("ntlm-info"):
                delta += 6
                for line in out.splitlines():
                    ls = line.strip()
                    if any(ls.startswith(k) for k in
                           ("Target_Name", "NetBIOS_Domain_Name", "DNS_Domain_Name",
                            "DNS_Computer_Name", "Product_Version", "DNS_Tree_Name")):
                        flags.append(f"NTLM: {ls}")
    return delta, list(dict.fromkeys(flags))


def score_priority(host: Host) -> None:
    """Compute host.priority_score / priority_level / reasons in place."""
    open_ports = {p.port for p in host.open_ports()}
    text = _haystack(host)
    score = 0
    reasons: list[str] = []

    # SMB/NTLM posture — the decisive Windows-priority signals
    smb_delta, smb_flags = analyze_smb_ntlm(host)
    score += smb_delta
    reasons.extend(smb_flags)

    # category base weights
    cat_weight = {
        "domain-controller": 40,
        "database": 18,
        "hypervisor": 22,
        "windows-server": 16,
        "storage-nas": 16,
        "router-firewall": 20,
        "network-switch": 12,
        "windows-workstation": 8,
        "linux-server": 10,
        "web-server": 8,
        "ai-inference-host": 16,
        "ip-camera": 6,
        "voip": 5,
        "printer": 4,
        "iot-device": 6,
        "unknown": 3,
        "clean": 0,
    }
    score += cat_weight.get(host.category, 3)
    if host.category == "domain-controller":
        reasons.append("Domain Controller — auth keys to the realm")
    if host.category == "ai-inference-host":
        reasons.append("Local AI/LLM inference server (shadow-AI / data-exfil surface)")
        if 11434 in open_ports or 11435 in open_ports:
            reasons.append("Ollama API exposed (11434) — often unauthenticated")
    if "ai-probe" in text and "unauthenticated" in text:
        score += 14
        reasons.append("AI inference API answered WITHOUT auth (exfil / abuse)")

    # juicy ports
    for port in open_ports:
        if port in JUICY_PORTS:
            label, weight = JUICY_PORTS[port]
            score += weight
            reasons.append(f"{label} open ({port})")

    # risky versions
    for marker, label in RISKY_VERSION_MARKERS:
        if marker in text:
            score += 15
            reasons.append(f"Risky: {label}")

    # NSE vuln script hits are strong signals
    for p in host.ports:
        for sid, out in p.scripts.items():
            low = out.lower()
            if sid.startswith("vuln") or "vulners" in sid or "CVE-" in out or "VULNERABLE" in out:
                if "VULNERABLE" in out or "cve-" in low:
                    score += 20
                    reasons.append(f"NSE flagged vuln on {p.port}/{sid}")

    # cleartext / default-cred-prone exposure
    if 23 in open_ports:
        reasons.append("Cleartext Telnet exposed")
    if {512, 513, 514} & open_ports:
        reasons.append("Legacy r-services exposed")

    # web admin surfaces
    if any(k in text for k in ("login", "admin", "phpmyadmin", "tomcat", "jenkins", "grafana", "kibana")):
        score += 6
        reasons.append("Web admin/login surface")

    host.priority_score = score
    host.reasons = reasons

    if host.category == "clean":
        host.priority_level = "clean"
    elif score >= 45:
        host.priority_level = "critical"
    elif score >= 25:
        host.priority_level = "high"
    elif score >= 12:
        host.priority_level = "medium"
    else:
        host.priority_level = "low"


def needs_llm(host: Host) -> bool:
    """Hand to qwen3 when rules are unsure, or when it's high-value enough to
    deserve a written priority story."""
    if host.category == "clean":
        return False
    if host.confidence < 0.6:
        return True
    if host.priority_level in ("critical", "high"):
        return True
    return False
