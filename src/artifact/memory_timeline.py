from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


def build_timeline(
    job: Any,
    volatility_results: Dict[str, Any],
    rekall_results: Optional[Dict[str, Any]] = None,
    *,
    platform: Optional[str] = None,
    sandbox_policy: Optional[str] = None,
    registry_entries: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    base_ts = getattr(job, 'created_at', time.time())
    platform_hint = (platform or _infer_platform(volatility_results)).lower()
    _append_pslist(
        entries,
        volatility_results.get('windows.pslist') or volatility_results.get('pslist'),
        base_ts,
        platform=_platform_label(platform_hint, 'windows'),
    )
    _append_malfind(
        entries,
        volatility_results.get('windows.malfind') or volatility_results.get('malfind'),
        base_ts,
        platform=_platform_label(platform_hint, 'windows'),
    )
    _append_netscan(
        entries,
        volatility_results.get('windows.netscan') or volatility_results.get('netscan'),
        base_ts,
        platform=_platform_label(platform_hint, 'windows'),
    )
    _append_linux_pslist(entries, volatility_results.get('linux.pslist'), base_ts)
    _append_linux_lsof(entries, volatility_results.get('linux.lsof'), base_ts)
    _append_macos_tasks(entries, volatility_results.get('mac.tasks'), base_ts)
    if rekall_results:
        _append_pslist(
            entries,
            rekall_results.get('pslist'),
            base_ts,
            source='rekall',
            platform=_platform_label(platform_hint, 'windows'),
        )
    if registry_entries:
        for entry in registry_entries[:10]:
            entry = dict(entry)
            entry.setdefault('platform', platform_hint or 'windows')
            entry.setdefault('source', entry.get('source') or 'registry')
            entry.setdefault('ts', base_ts)
            entry.setdefault('kind', 'registry')
            entries.append(entry)
    entries.sort(key=lambda e: e.get('ts', base_ts))
    if sandbox_policy:
        entries.append(
            {
                'ts': base_ts,
                'kind': 'policy',
                'platform': platform_hint or 'windows',
                'source': 'sandbox',
                'summary': f"Sandbox policy {sandbox_policy} executed for memory job",
            }
        )
    return entries[:50]


def _append_pslist(
    entries: List[Dict[str, Any]],
    pslist: Any,
    base_ts: float,
    *,
    source: str = 'volatility',
    platform: str = 'windows',
) -> None:
    if not isinstance(pslist, list):
        return
    for proc in pslist[:20]:
        image = str(proc.get('ImageFileName') or proc.get('image') or proc.get('name') or '').lower()
        pid = proc.get('PID') or proc.get('pid')
        if not image:
            continue
        entries.append({
            'ts': base_ts,
            'kind': 'process',
            'source': source,
            'platform': platform,
            'summary': f"Process {image} (PID {pid}) present in memory",
        })


def _append_malfind(entries: List[Dict[str, Any]], malfind: Any, base_ts: float, *, platform: str = 'windows') -> None:
    if not isinstance(malfind, list):
        return
    for idx, hit in enumerate(malfind[:10]):
        proc = hit.get('Process') or hit.get('image') or 'unknown'
        entries.append({
            'ts': base_ts + idx,
            'kind': 'injection',
            'source': 'volatility',
            'platform': platform,
            'summary': f"Malfind hit in {proc} (PID {hit.get('PID') or hit.get('pid')})",
        })


def _append_netscan(entries: List[Dict[str, Any]], netscan: Any, base_ts: float, *, platform: str = 'windows') -> None:
    if not isinstance(netscan, list):
        return
    for idx, row in enumerate(netscan[:10]):
        dst = row.get('ForeignAddr') or row.get('dst') or 'unknown'
        proc = row.get('Process') or row.get('image') or 'unknown'
        entries.append({
            'ts': base_ts + (idx * 0.5),
            'kind': 'network',
            'source': 'volatility',
            'platform': platform,
            'summary': f"Process {proc} communicating with {dst}",
        })


def _append_linux_pslist(entries: List[Dict[str, Any]], pslist: Any, base_ts: float) -> None:
    if not isinstance(pslist, list):
        return
    for proc in pslist[:15]:
        name = proc.get('comm') or proc.get('name')
        pid = proc.get('pid')
        if not name:
            continue
        entries.append(
            {
                'ts': base_ts,
                'kind': 'process',
                'source': 'linux.pslist',
                'platform': 'linux',
                'summary': f"Linux process {name} (PID {pid}) present in dump",
            }
        )


def _append_linux_lsof(entries: List[Dict[str, Any]], lsof: Any, base_ts: float) -> None:
    if not isinstance(lsof, list):
        return
    for idx, row in enumerate(lsof[:10]):
        proc = row.get('process') or row.get('comm') or 'unknown'
        fd = row.get('fd') or '?'
        path = row.get('path') or row.get('name') or 'unknown'
        entries.append(
            {
                'ts': base_ts + (idx * 0.25),
                'kind': 'file',
                'source': 'linux.lsof',
                'platform': 'linux',
                'summary': f"{proc} holds {path} via fd {fd}",
            }
        )


def _append_macos_tasks(entries: List[Dict[str, Any]], tasks: Any, base_ts: float) -> None:
    if not isinstance(tasks, list):
        return
    for proc in tasks[:10]:
        name = proc.get('name') or proc.get('command') or 'unknown'
        pid = proc.get('pid')
        entries.append(
            {
                'ts': base_ts,
                'kind': 'process',
                'source': 'mac.tasks',
                'platform': 'macos',
                'summary': f"macOS task {name} (PID {pid}) observed in dump",
            }
        )


def _infer_platform(results: Dict[str, Any]) -> str:
    if any(k.startswith('linux.') for k in results.keys()):
        return 'linux'
    if any(k.startswith('mac.') for k in results.keys()) or any(k.startswith('darwin.') for k in results.keys()):
        return 'macos'
    return 'windows'


def _platform_label(preferred: str, fallback: str) -> str:
    return preferred or fallback


__all__ = ['build_timeline']
