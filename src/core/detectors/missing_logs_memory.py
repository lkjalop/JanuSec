from __future__ import annotations

from typing import Any, Dict, List, Sequence

MEMORY_FACTOR_HINTS = {
    "memory:suspicious_injection",
    "memory:credential_dump",
    "memory:reflective_loader",
    "process_injection",
    "credential_dumping",
    "lsass_access",
    "lsass_dump",
    "suspicious_parent_child_pair",
}

REQUIRED_ARTIFACTS: Sequence[Dict[str, str]] = (
    {
        "key": "memory_dump",
        "source": "memory_capture",
        "reason": "No physical memory dump attached for suspected injection/credential theft.",
        "how": "Use WinPMem (Windows) or AVML/LiME (Linux) to capture RAM and upload to the memory pipeline.",
    },
    {
        "key": "pslist",
        "source": "volatility_pslist",
        "reason": "Process list from Volatility missing; cannot validate rogue PIDs.",
        "how": "Run `vol.py windows.pslist --output=json` against the dump and attach the results.",
    },
    {
        "key": "dlllist",
        "source": "volatility_dlllist",
        "reason": "DLL map absent for suspicious PID; cannot confirm injected modules.",
        "how": "Run `vol.py windows.dlllist -p <pid>` and collect JSON/CSV output.",
    },
    {
        "key": "malfind",
        "source": "volatility_malfind",
        "reason": "Malfind output missing; unable to extract injected code regions.",
        "how": "Run `vol.py windows.malfind --dump` and upload dumps plus JSON listing.",
    },
)


def _normalize_artifacts(memory_meta: Dict[str, Any]) -> set[str]:
    collected: set[str] = set()
    for key in ("artifacts", "collected", "available"):
        val = memory_meta.get(key)
        if isinstance(val, list):
            for item in val:
                if item:
                    collected.add(str(item).lower())
        elif isinstance(val, dict):
            for name, present in val.items():
                if present:
                    collected.add(str(name).lower())
    for alias in ("dump_id", "last_dump", "memory_id"):
        if memory_meta.get(alias):
            collected.add("memory_dump")
    if memory_meta.get("pslist"):
        collected.add("pslist")
    if memory_meta.get("dlllist"):
        collected.add("dlllist")
    if memory_meta.get("malfind"):
        collected.add("malfind")
    return collected


def detect_memory_artifact_gaps(metadata: Dict[str, Any] | None, factors: Sequence[str] | None) -> List[Dict[str, Any]]:
    """Return missing log entries when memory artifacts are required but absent."""
    if not metadata:
        metadata = {}
    facs = {str(f).lower() for f in (factors or []) if f}
    requires_memory = any(f in facs or f.startswith("memory:") for f in facs)
    if not requires_memory:
        return []

    enrichment = metadata.get("enrichment") or {}
    forensic_meta = enrichment.get("forensics") if isinstance(enrichment, dict) else {}
    if not isinstance(forensic_meta, dict):
        forensic_meta = {}
    memory_meta = forensic_meta.get("memory") or {}
    if not isinstance(memory_meta, dict):
        memory_meta = {}

    collected = _normalize_artifacts(memory_meta)
    missing: List[Dict[str, Any]] = []

    for artifact in REQUIRED_ARTIFACTS:
        if artifact["key"] in collected:
            continue
        missing.append(
            {
                "source": artifact["source"],
                "reason": artifact["reason"],
                "requested_artifacts": artifact["how"],
            }
        )

    return missing


__all__ = ["detect_memory_artifact_gaps"]
