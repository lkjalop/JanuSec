"""Domain-specific tool and log recommendations for SOC investigations."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List
import yaml
try:
    from src.analysis.playbook_db import get_playbook_for_mitre  # type: ignore
except Exception:
    try:
        from .playbook_db import get_playbook_for_mitre  # type: ignore
    except Exception:
        get_playbook_for_mitre = None  # type: ignore

MEMORY_FACTOR_HINTS = {
    'memory:suspicious_injection',
    'memory:credential_dump',
    'memory:reflective_loader',
    'process_injection',
    'credential_dumping',
    'lsass_access',
}
MEMORY_MITRE_IDS = {'T1003', 'T1055', 'T1112'}


@lru_cache(maxsize=1)
def _memory_template() -> Dict[str, Any] | None:
    path = Path(__file__).resolve().parents[2] / 'playbooks' / 'templates' / 'forensics_memory.yml'
    if not path.exists():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding='utf-8')) or {}
        return data if isinstance(data, dict) else None
    except Exception:
        return None

# Canonical tool recommendations per investigation domain
DOMAIN_TOOLS: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
    "network": {
        "packet_capture": [
            {
                "name": "Wireshark",
                "purpose": "Deep packet inspection",
                "command": "tshark -i eth0 -w capture.pcap host {src_ip}",
                "output_format": "PCAP",
                "when_to_use": "Detailed protocol analysis needed",
            },
            {
                "name": "tcpdump",
                "purpose": "Lightweight packet capture",
                "command": (
                    "tcpdump -i any -s 0 -w evidence.pcap "
                    "host {src_ip} or host {dst_ip}"
                ),
                "output_format": "PCAP",
                "when_to_use": "Quick capture on Linux servers",
            },
        ],
        "flow_analysis": [
            {
                "name": "Zeek",
                "purpose": "Network metadata extraction",
                "command": "zeek -r capture.pcap",
                "output_format": "conn.log, dns.log, http.log",
                "when_to_use": "Protocol-specific behavior analysis",
            },
            {
                "name": "Suricata",
                "purpose": "IDS alerts and flow logs",
                "command": "suricata -r capture.pcap -l output/",
                "output_format": "eve.json",
                "when_to_use": "Signature detections plus flow metadata",
            },
        ],
        "dns_analysis": [
            {
                "name": "Windows DNS Client Logs",
                "purpose": "Domain resolution tracking",
                "command": (
                    'Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" '
                    "| Where-Object Id -eq 3008"
                ),
                "output_format": "Event logs",
                "when_to_use": "Command-and-control domain detection",
            }
        ],
        "firewall_logs": [
            {
                "name": "Windows Firewall",
                "purpose": "Connection allow and block events",
                "command": (
                    'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=5156,5157}'
                ),
                "output_format": "Event 5156/5157",
                "when_to_use": "Verify blocked or permitted connections",
            }
        ],
    },
    "endpoint": {
        "registry": [
            {
                "name": "KAPE",
                "purpose": "Fast forensic artifact collection",
                "command": (
                    "kape.exe --tsource C: --tdest D:\\Evidence "
                    "--module RegistryASEPs,RegistryHives"
                ),
                "output_format": "Registry hives and parsed data",
                "when_to_use": "Comprehensive registry collection",
            },
            {
                "name": "RegRipper",
                "purpose": "Registry hive parsing",
                "command": "rip.exe -r NTUSER.DAT -p userassist",
                "output_format": "Text report",
                "when_to_use": "Analyze specific registry keys",
            },
            {
                "name": "Registry Explorer",
                "purpose": "GUI registry browsing",
                "command": "RegistryExplorer.exe",
                "output_format": "Interactive view",
                "when_to_use": "Manual hive inspection",
            },
        ],
        "memory": [
            {
                "name": "Volatility 3",
                "purpose": "Memory forensics",
                "command": "vol.py -f memdump.raw windows.pslist",
                "output_format": "Text or JSON",
                "when_to_use": "Process injection or credential theft",
            }
        ],
        "disk": [
            {
                "name": "FTK Imager",
                "purpose": "Disk imaging",
                "command": "ftkimager.exe --source PhysicalDrive0 --dest D:\\image.dd",
                "output_format": "DD or E01",
                "when_to_use": "Full disk preservation",
            }
        ],
        "process_logs": [
            {
                "name": "Sysmon",
                "purpose": "Detailed process telemetry",
                "command": (
                    'Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" '
                    "| Where-Object Id -in 1,3,10,13"
                ),
                "output_format": "Event 1, 3, 10, 13",
                "when_to_use": "Always for endpoint investigations",
            },
            {
                "name": "Event 4688",
                "purpose": "Process creation",
                "command": (
                    'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4688} '
                    '| Where-Object {$_.Message -like "*{process_name}*"}'
                ),
                "output_format": "Security Event Log",
                "when_to_use": "Parent and child process lineage",
            },
            {
                "name": "PowerShell 4104",
                "purpose": "Script block logging",
                "command": (
                    'Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" '
                    "| Where-Object Id -eq 4104"
                ),
                "output_format": "PowerShell event log",
                "when_to_use": "PowerShell script content analysis",
            },
        ],
        "autoruns": [
            {
                "name": "Autoruns",
                "purpose": "Persistence mechanism enumeration",
                "command": "autorunsc.exe -a * -c -nobanner",
                "output_format": "CSV",
                "when_to_use": "Locate registry, service, or scheduled task persistence",
            }
        ],
    },
}

# Mapping of MITRE techniques to log sources analysts should collect
MITRE_TO_LOGS: Dict[str, Dict[str, Any]] = {
    "T1055": {
        "name": "Process Injection",
        "logs": [
            "Sysmon Event 10 (Process Access)",
            "Sysmon Event 8 (CreateRemoteThread)",
            "Event 4688 (Process Creation with command line)",
            "EDR process telemetry",
        ],
        "why": "Process injection requires opening a target process handle and creating remote threads.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "logs": [
            "Event 4688 (Process Creation)",
            "PowerShell 4104 (Script Block)",
            "Sysmon Event 1 (Process Creation)",
            "Shell history logs",
        ],
        "why": "Script execution leaves process and script block telemetry.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "logs": [
            "PowerShell 4104 (Script Block Logging)",
            "PowerShell 4103 (Module Logging)",
            "Event 4688 (powershell.exe creation)",
            "Sysmon Event 1 (powershell.exe)",
        ],
        "why": "PowerShell has dedicated telemetry that captures script content.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "logs": [
            "Event 4624 (Logon)",
            "Event 4625 (Failed Logon)",
            "Event 4672 (Special Privileges Assigned)",
            "Event 4768/4769 (Kerberos TGT/TGS)",
        ],
        "why": "Credential use generates authentication telemetry across identity providers.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "logs": [
            "Firewall logs (5156/5157)",
            "Proxy logs",
            "DNS query logs (Event 3008)",
            "Sysmon Event 3 (Network Connection)",
            "Zeek or Suricata flow logs",
        ],
        "why": "Command-and-control traffic requires egress captured in firewall, proxy, or DNS logs.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "logs": [
            "Sysmon Event 10 (LSASS access)",
            "Event 4688 (tools such as mimikatz or procdump)",
            "Event 4656/4663 (SAM/SECURITY hive access)",
            "EDR memory protection alerts",
        ],
        "why": "Credential dumping touches LSASS memory or registry hives.",
    },
    "T1053": {
        "name": "Scheduled Task or Job",
        "logs": [
            "Event 4698 (Scheduled Task Created)",
            "Event 106 (Task Scheduler operational log)",
            "Sysmon Event 1 (schtasks.exe)",
            "Event 4688 (schtasks.exe creation)",
        ],
        "why": "Scheduled task creation produces scheduler and process events.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "logs": [
            "Sysmon Event 13 (Registry value set)",
            "Event 4657 (Registry modification)",
            "Autoruns output",
            "Registry hive forensics",
        ],
        "why": "Autostart persistence modifies Run keys and other monitored registry paths.",
    },
}


def get_tools_for_domain(domain: str, category: str | None = None) -> List[Dict[str, Any]]:
    """Return recommended tools for the given domain."""
    domain = (domain or "").lower()
    if domain not in DOMAIN_TOOLS:
        return []

    if category:
        return list(DOMAIN_TOOLS[domain].get(category, []))

    flattened: List[Dict[str, Any]] = []
    for cat_tools in DOMAIN_TOOLS[domain].values():
        flattened.extend(cat_tools)
    return flattened


def get_logs_for_mitre(mitre_id: str) -> Dict[str, Any]:
    """Return recommended logs for a MITRE ATT&CK technique."""
    default = {
        "name": "Unknown Technique",
        "logs": ["Event 4688 (Process Creation)", "Sysmon Event 1"],
        "why": "Generic process telemetry captures execution context.",
    }
    if not mitre_id:
        return default
    return MITRE_TO_LOGS.get(mitre_id, default)


def build_collection_playbook(
    domain: str,
    mitre_tags: List[str],
    artifact_context: Dict[str, Any],
) -> str:
    """Assemble a markdown playbook summarizing tools and log requirements."""

    def _format_command(template: str) -> str:
        cmd = template
        for key, val in artifact_context.items():
            cmd = cmd.replace("{" + key + "}", str(val or ""))
        return cmd

    lines: List[str] = []
    dom = domain.lower() if domain else "endpoint"
    selections = get_tools_for_domain(dom)
    factors = {
        str(f).lower()
        for f in (artifact_context.get("factors") or [])
        if isinstance(f, str) and f
    }
    memory_requested = bool(
        factors.intersection(MEMORY_FACTOR_HINTS)
        or any(str(mid).upper() in MEMORY_MITRE_IDS for mid in (mitre_tags or []))
    )

    lines.append(f"# Collection Playbook - {dom.upper()}")
    lines.append("")
    lines.append("## Recommended Tools")
    lines.append("")

    for tool in selections[:5]:
        lines.append(f"### {tool['name']}")
        lines.append(f"Purpose: {tool['purpose']}")
        lines.append("")
        lines.append("```bash")
        lines.append(_format_command(tool["command"]))
        lines.append("```")
        lines.append("")
        lines.append(f"Output: {tool['output_format']}")
        lines.append(f"When to use: {tool['when_to_use']}")
        lines.append("")

    if memory_requested:
        template = _memory_template()
        if template:
            lines.append("## Memory Acquisition Playbook")
            lines.append("")
            summary = template.get("summary") or template.get("title")
            if summary:
                lines.append(summary)
                lines.append("")
            artifacts = template.get("artifacts") or []
            if artifacts:
                lines.append("Required Memory Artifacts:")
                for art in artifacts:
                    desc = art.get("description") or art.get("key")
                    if desc:
                        lines.append(f"- {desc}")
                lines.append("")
            for idx, step in enumerate(template.get("steps") or [], 1):
                name = step.get("name") or step.get("title") or f"Step {idx}"
                lines.append(f"### Step {idx}: {name}")
                if step.get("desc"):
                    lines.append(step["desc"])
                    lines.append("")
                for command in step.get("commands") or []:
                    cmd = command.get("command") or ""
                    if cmd:
                        formatted = _format_command(cmd)
                        tool = command.get("tool") or "Command"
                        lines.append(f"- {tool}: `{formatted}`")
                        if command.get("notes"):
                            lines.append(f"  - Notes: {command['notes']}")
                for check in step.get("checks") or []:
                    lines.append(f"- {check}")
                lines.append("")

    lines.append("## Required Logs (based on MITRE techniques)")
    lines.append("")
    for mid in (mitre_tags or [])[:3]:
        # Prefer canonical playbook DB entries when available
        pb = None
        try:
            if get_playbook_for_mitre:
                pb = get_playbook_for_mitre(mid.upper())
        except Exception:
            pb = None
        if pb and isinstance(pb, dict) and pb.get('playbook'):
            p = pb['playbook']
            lines.append(f"### {mid}: {pb.get('name') or p.get('description','')}")
            lines.append("")
            lines.append("Playbook guidance:")
            if p.get('description'):
                lines.append(p.get('description'))
            lines.append("")
            lines.append("Logs/Commands to collect:")
            for req in p.get('required_logs', []):
                cmd = req.get('command') or ''
                try:
                    for key, val in artifact_context.items():
                        cmd = cmd.replace('{' + key + '}', str(val or ''))
                except Exception:
                    pass
                lines.append(f"- Source: {req.get('source')} - Command: {cmd} - Why: {req.get('why')}")
            if p.get('optional'):
                lines.append("")
                lines.append("Optional:")
                for opt in p.get('optional'):
                    lines.append(f"- {opt.get('source') or opt.get('note')}")
            lines.append("")
        else:
            info = get_logs_for_mitre(mid)
            lines.append(f"### {mid}: {info['name']}")
            lines.append(f"Why: {info['why']}")
            lines.append("")
            lines.append("Logs to collect:")
            for log in info["logs"]:
                lines.append(f"- {log}")
            lines.append("")

    return "\n".join(lines).strip()


__all__ = [
    "DOMAIN_TOOLS",
    "MITRE_TO_LOGS",
    "build_collection_playbook",
    "get_logs_for_mitre",
    "get_tools_for_domain",
]
