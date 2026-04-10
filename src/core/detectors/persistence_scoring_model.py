"""PersistenceScoringModel — endpoint persistence mechanism detection and scoring.

Covers Windows and Linux persistence vectors:
    endpoint:persistence_novel        — New persistence mechanism deviating from host profile
    endpoint:persistence_burst        — Multiple persistence mechanisms in a short time window
    endpoint:persistence_reg_run      — Registry Run/RunOnce key write
    endpoint:persistence_service_new  — New service installation (Windows: sc create / Linux: systemctl enable)
    endpoint:persistence_task_new     — Scheduled task / cron job creation
    endpoint:persistence_startup_lnk  — File written to Startup folder
    endpoint:persistence_wmi_sub      — WMI event subscription creation (T1546.003)
    endpoint:persistence_ifeo         — Image File Execution Options debugger hijack (T1546.012)
    endpoint:persistence_dll_search   — DLL search order hijacking indicator (T1574.001)
    endpoint:persistence_bootkit      — MBR / VBR / bootloader modification indicators

Linux-specific:
    endpoint:persistence_cron_novel   — New cron entry on non-standard schedule
    endpoint:persistence_ld_preload   — LD_PRELOAD / /etc/ld.so.preload modification
    endpoint:persistence_profile_mod  — Shell profile (.bashrc/.profile/.zshrc) write by non-user process
    endpoint:persistence_systemd_drop — New systemd unit file dropped in /etc/systemd/system/

HopGraph wiring: add edge (process:<pid>, host:<hostname>, 'installed_persistence', weight=score)
                 add edge (host:<hostname>, 'persistence_mechanism:<type>', 'has_persistence', weight=score)

Baseline: per-tenant set of known-good persistence artifacts (loaded from data/persistence_baseline.json).
           EWMA burst detection on persistence event rate per host.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

try:
    from src.detectors.ewma_adaptive import AdaptiveEWMA
    _PERS_EWMA: Optional[Any] = AdaptiveEWMA(base_alpha=0.15, min_alpha=0.02, max_alpha=0.6)
except Exception:
    _PERS_EWMA = None

# ---------------------------------------------------------------------------
# Persistence baseline — known-good persistence artifacts per tenant
# ---------------------------------------------------------------------------
_BASELINE_PATH = os.getenv('PERSISTENCE_BASELINE_PATH', 'data/persistence_baseline.json')
_BASELINE_LOCK = threading.RLock()
# tenant → set of (artifact_type, artifact_key) tuples
_KNOWN_PERSISTENCE: Dict[str, Set[tuple]] = defaultdict(set)
_BASELINE_DIRTY = False

# Burst detection: how many persistence events per host within this window = suspicious
_BURST_WINDOW_SECONDS = int(os.getenv('PERSISTENCE_BURST_WINDOW', '300'))  # 5 minutes
_BURST_THRESHOLD       = int(os.getenv('PERSISTENCE_BURST_THRESHOLD', '3'))

# Per-host recent persistence event timestamps (in-memory sliding window)
_HOST_PERS_TIMES: Dict[str, List[float]] = defaultdict(list)
_HOST_PERS_LOCK  = threading.RLock()


def _load_baseline() -> None:
    try:
        if os.path.exists(_BASELINE_PATH):
            with open(_BASELINE_PATH, 'r', encoding='utf-8') as fh:
                raw = json.load(fh)
            for tenant, entries in raw.get('tenants', {}).items():
                _KNOWN_PERSISTENCE[tenant] = {tuple(e) for e in entries}
    except Exception:
        pass


def _save_baseline() -> None:
    global _BASELINE_DIRTY
    try:
        os.makedirs(os.path.dirname(_BASELINE_PATH) or '.', exist_ok=True)
        serializable = {
            'tenants': {
                tenant: [list(e) for e in entries]
                for tenant, entries in _KNOWN_PERSISTENCE.items()
            },
            'saved_at': time.time(),
        }
        with open(_BASELINE_PATH, 'w', encoding='utf-8') as fh:
            json.dump(serializable, fh)
        _BASELINE_DIRTY = False
    except Exception:
        pass


_load_baseline()

# ---------------------------------------------------------------------------
# Registry run key patterns
# ---------------------------------------------------------------------------
_REG_RUN_PATTERNS = re.compile(
    r'(?:'
    r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS)|HKLM|HKCU|HKU'
    r').*?(?:'
    r'\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once|Services|ServicesOnce)?'
    r'|\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
    r'|\\System\\CurrentControlSet\\Services'
    r'|\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders'
    r'|\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'
    r'|\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\(?:AppInit_DLLs|KnownDLLs)'
    r')',
    re.IGNORECASE,
)

_IFEO_PATTERN = re.compile(
    r'Image File Execution Options[\\\/](\S+)[\\\/]Debugger',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Scheduled task / cron patterns
# ---------------------------------------------------------------------------
_SCHTASK_PATTERNS = re.compile(
    r'(?:schtasks\.exe|at\.exe|taskschd\.msc)',
    re.IGNORECASE,
)
_SCHTASK_CREATE = re.compile(
    r'/create|--create|-l\s+\d+|crontab\s+-[le]|echo.*crontab|/etc/cron\.',
    re.IGNORECASE,
)
_CRON_NONSTANDARD = re.compile(
    r'(?:@reboot|@hourly|@daily|@weekly|@monthly|\*/\d+\s+\*/\d+)',
    re.IGNORECASE,
)

# Startup folder paths
_STARTUP_PATHS = re.compile(
    r'(?:'
    r'\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
    r'|\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
    r'|/etc/init\.d/'
    r'|/etc/rc(?:\d|\.local)'
    r'|/etc/xdg/autostart/'
    r')',
    re.IGNORECASE,
)

# WMI event subscription
_WMI_SUB_PATTERNS = re.compile(
    r'(?:'
    r'wmic.*(?:eventfilter|eventconsumer|filtertoconsumerbinding).*create'
    r'|Subscribe-WmiEvent'
    r'|New-CimInstance.*EventFilter'
    r'|__EventConsumer|__EventFilter|__FilterToConsumerBinding'
    r')',
    re.IGNORECASE,
)

# DLL search order hijacking indicators
_DLL_HIJACK_PATTERNS = re.compile(
    r'(?:'
    r'[A-Za-z]:\\(?:temp|tmp|appdata|programdata|users\\public)\\[^\\]+\.dll'
    r'|/tmp/[^/]+\.so'
    r'|/dev/shm/[^/]+\.so'
    r')',
    re.IGNORECASE,
)

# Service creation (Windows)
_SERVICE_CREATE_PATTERNS = re.compile(
    r'(?:sc\.exe|sc\s+create|New-Service|nssm\.exe\s+install|'
    r'systemctl\s+(?:enable|daemon-reload)|'
    r'/etc/systemd/system/[^/\s]+\.service)',
    re.IGNORECASE,
)

# Bootkit indicators
_BOOTKIT_PATTERNS = re.compile(
    r'(?:'
    r'bootrec\.exe.*(?:/fixmbr|/fixboot|/rebuildbcd)'
    r'|dd\s+(?:if|of)=\/dev\/(?:sda|hda|vda|xvda)'
    r'|bcdedit\s+/set.*(?:testsigning|nointegritychecks|recoveryenabled)\s+(?:yes|no|on|off)'
    r'|diskpart.*clean'
    r')',
    re.IGNORECASE,
)

# Linux LD_PRELOAD
_LD_PRELOAD_PATTERNS = re.compile(
    r'(?:'
    r'LD_PRELOAD\s*='
    r'|/etc/ld\.so\.preload'
    r')',
    re.IGNORECASE,
)

# Shell profile modification by a non-shell process
_SHELL_PROFILE_PATHS = re.compile(
    r'(?:'
    r'/home/[^/]+/\.(?:bashrc|bash_profile|zshrc|profile|bash_logout|xinitrc|xsession)'
    r'|/root/\.(?:bashrc|bash_profile|zshrc|profile)'
    r'|/etc/profile(?:\.d/[^/]+\.sh)?'
    r'|/etc/bash\.bashrc'
    r')',
    re.IGNORECASE,
)

# Systemd unit drop paths
_SYSTEMD_DROP = re.compile(
    r'(?:/etc/systemd/system/|/usr/lib/systemd/system/)[^/\s]+\.(?:service|timer|socket)',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_cmdline_and_path(ev: Dict[str, Any]) -> tuple:
    """Return (cmdline, file_path, process_name) from an event."""
    cmdline = str(ev.get('cmdline') or ev.get('command_line') or ev.get('process_cmdline') or '')
    file_path = str(ev.get('file_path') or ev.get('target_file') or ev.get('registry_key') or '')
    process_name = str(ev.get('process') or ev.get('image') or ev.get('process_name') or '')
    return cmdline, file_path, process_name


def _is_endpoint_event(ev: Dict[str, Any]) -> bool:
    etype = str(ev.get('event_type') or ev.get('type') or '').lower()
    src   = str(ev.get('source_platform') or ev.get('source') or '').lower()
    return (
        any(k in etype for k in ('process', 'registry', 'file', 'service', 'scheduled', 'wmi', 'endpoint'))
        or 'endpoint' in src
        or 'sysmon' in src
        or 'auditd' in src
        or 'ebpf' in src
    )


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_persistence(
    events: List[Dict[str, Any]],
    tenant_id: str = 'default',
    event_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Analyze endpoint events for persistence mechanism installation.

    Args:
        events:    List of normalized endpoint events.
        tenant_id: Tenant for baseline isolation.
        event_id:  Optional event ID for factor dedup.

    Returns:
        List of factor dicts.
    """
    global _BASELINE_DIRTY
    factors: List[Dict[str, Any]] = []

    endpoint_events = [ev for ev in events if _is_endpoint_event(ev)]
    if not endpoint_events:
        return factors

    for ev in endpoint_events:
        try:
            cmdline, file_path, proc_name = _extract_cmdline_and_path(ev)
            hostname = str(ev.get('host') or ev.get('hostname') or ev.get('computer') or '')
            pid      = str(ev.get('pid') or '')
            ts       = float(ev.get('timestamp') or ev.get('ts') or time.time())
            combined = cmdline + ' ' + file_path  # search surface

            # ------------------------------------------------------------------
            # Registry Run keys
            # ------------------------------------------------------------------
            if _REG_RUN_PATTERNS.search(combined):
                artifact_key = ('reg_run', cmdline[:120].lower())
                is_novel = _register_artifact(tenant_id, artifact_key)
                factors.append({
                    'factor': 'endpoint:persistence_reg_run',
                    'score': 0.80 if is_novel else 0.45,
                    'reason': f'Registry Run key write detected by "{proc_name}"',
                    'novel': is_novel,
                    'registry_path': file_path[:200] or _extract_reg_path(combined),
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1547.001', 'STRIDE:elevation'],
                })
                if is_novel:
                    _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # IFEO Debugger hijack
            # ------------------------------------------------------------------
            ifeo_match = _IFEO_PATTERN.search(combined)
            if ifeo_match:
                target_binary = ifeo_match.group(1)
                artifact_key = ('ifeo', target_binary.lower())
                is_novel = _register_artifact(tenant_id, artifact_key)
                factors.append({
                    'factor': 'endpoint:persistence_ifeo',
                    'score': 0.90 if is_novel else 0.55,
                    'reason': f'Image File Execution Options Debugger key set for "{target_binary}"',
                    'novel': is_novel,
                    'target_binary': target_binary,
                    'process': proc_name,
                    'hostname': hostname,
                    'tags': ['ATTACK:T1546.012', 'STRIDE:elevation'],
                })
                if is_novel:
                    _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # Scheduled task / cron creation
            # ------------------------------------------------------------------
            has_schtask = _SCHTASK_PATTERNS.search(proc_name) or _SCHTASK_PATTERNS.search(cmdline)
            has_create  = _SCHTASK_CREATE.search(cmdline)
            if has_schtask and has_create:
                artifact_key = ('schtask', cmdline[:120].lower())
                is_novel = _register_artifact(tenant_id, artifact_key)
                has_nonstandard = bool(_CRON_NONSTANDARD.search(cmdline))
                factors.append({
                    'factor': 'endpoint:persistence_task_new',
                    'score': (0.78 if is_novel else 0.40) + (0.10 if has_nonstandard else 0.0),
                    'reason': f'Scheduled task/cron creation by "{proc_name}"' + (' (non-standard schedule)' if has_nonstandard else ''),
                    'novel': is_novel,
                    'nonstandard_schedule': has_nonstandard,
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1053.005', 'STRIDE:elevation'],
                })
                if is_novel:
                    _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # Startup folder LNK / script drop
            # ------------------------------------------------------------------
            if _STARTUP_PATHS.search(file_path) or _STARTUP_PATHS.search(cmdline):
                artifact_key = ('startup', file_path[:120].lower() or cmdline[:120].lower())
                is_novel = _register_artifact(tenant_id, artifact_key)
                factors.append({
                    'factor': 'endpoint:persistence_startup_lnk',
                    'score': 0.75 if is_novel else 0.38,
                    'reason': f'File written to Startup folder by "{proc_name}"',
                    'novel': is_novel,
                    'file_path': file_path[:200],
                    'process': proc_name,
                    'hostname': hostname,
                    'tags': ['ATTACK:T1547.009', 'STRIDE:elevation'],
                })
                if is_novel:
                    _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # New service
            # ------------------------------------------------------------------
            if _SERVICE_CREATE_PATTERNS.search(combined):
                artifact_key = ('service', cmdline[:120].lower())
                is_novel = _register_artifact(tenant_id, artifact_key)
                factors.append({
                    'factor': 'endpoint:persistence_service_new',
                    'score': 0.77 if is_novel else 0.40,
                    'reason': f'New service installed by "{proc_name}"',
                    'novel': is_novel,
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1543.003', 'STRIDE:elevation'],
                })
                if is_novel:
                    _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # WMI event subscription
            # ------------------------------------------------------------------
            if _WMI_SUB_PATTERNS.search(combined):
                artifact_key = ('wmi_sub', cmdline[:120].lower())
                is_novel = _register_artifact(tenant_id, artifact_key)
                factors.append({
                    'factor': 'endpoint:persistence_wmi_sub',
                    'score': 0.85 if is_novel else 0.55,
                    'reason': f'WMI event subscription creation by "{proc_name}"',
                    'novel': is_novel,
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1546.003', 'STRIDE:elevation'],
                })
                if is_novel:
                    _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # DLL search order hijacking
            # ------------------------------------------------------------------
            if _DLL_HIJACK_PATTERNS.search(file_path) or _DLL_HIJACK_PATTERNS.search(cmdline):
                artifact_key = ('dll_hijack', file_path[:120].lower() or cmdline[:120].lower())
                is_novel = _register_artifact(tenant_id, artifact_key)
                factors.append({
                    'factor': 'endpoint:persistence_dll_search',
                    'score': 0.82 if is_novel else 0.48,
                    'reason': f'DLL drop in writable path consistent with search order hijacking by "{proc_name}"',
                    'novel': is_novel,
                    'file_path': file_path[:200],
                    'process': proc_name,
                    'hostname': hostname,
                    'tags': ['ATTACK:T1574.001', 'STRIDE:elevation'],
                })
                if is_novel:
                    _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # Bootkit
            # ------------------------------------------------------------------
            if _BOOTKIT_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:persistence_bootkit',
                    'score': 0.93,
                    'reason': f'Bootloader / MBR modification command by "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1542.003', 'DREAD:damage', 'STRIDE:tampering'],
                })
                _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # Linux: LD_PRELOAD
            # ------------------------------------------------------------------
            if _LD_PRELOAD_PATTERNS.search(combined):
                artifact_key = ('ld_preload', cmdline[:120].lower())
                is_novel = _register_artifact(tenant_id, artifact_key)
                factors.append({
                    'factor': 'endpoint:persistence_ld_preload',
                    'score': 0.88 if is_novel else 0.55,
                    'reason': f'LD_PRELOAD or /etc/ld.so.preload modification by "{proc_name}"',
                    'novel': is_novel,
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1574.006', 'STRIDE:elevation'],
                })
                if is_novel:
                    _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # Linux: Shell profile modification by non-shell process
            # ------------------------------------------------------------------
            if _SHELL_PROFILE_PATHS.search(file_path):
                shell_proc = proc_name.lower() in {'bash', 'sh', 'zsh', 'dash', 'ksh', 'fish'}
                if not shell_proc:
                    artifact_key = ('profile_mod', file_path[:120].lower())
                    is_novel = _register_artifact(tenant_id, artifact_key)
                    factors.append({
                        'factor': 'endpoint:persistence_profile_mod',
                        'score': 0.80 if is_novel else 0.45,
                        'reason': f'Shell profile "{file_path}" modified by non-shell process "{proc_name}"',
                        'novel': is_novel,
                        'file_path': file_path[:200],
                        'process': proc_name,
                        'hostname': hostname,
                        'tags': ['ATTACK:T1546.004', 'STRIDE:elevation'],
                    })
                    if is_novel:
                        _record_pers_event(hostname, ts)

            # ------------------------------------------------------------------
            # Linux: systemd unit file drop
            # ------------------------------------------------------------------
            if _SYSTEMD_DROP.search(file_path) or _SYSTEMD_DROP.search(cmdline):
                artifact_key = ('systemd_drop', file_path[:120].lower() or cmdline[:120].lower())
                is_novel = _register_artifact(tenant_id, artifact_key)
                factors.append({
                    'factor': 'endpoint:persistence_systemd_drop',
                    'score': 0.75 if is_novel else 0.38,
                    'reason': f'New systemd unit file created by "{proc_name}"',
                    'novel': is_novel,
                    'file_path': file_path[:200] or _extract_systemd_path(cmdline),
                    'process': proc_name,
                    'hostname': hostname,
                    'tags': ['ATTACK:T1543.002', 'STRIDE:elevation'],
                })
                if is_novel:
                    _record_pers_event(hostname, ts)

        except Exception:
            continue

    # ------------------------------------------------------------------
    # Burst detection (across all events in this batch, per host)
    # ------------------------------------------------------------------
    factors.extend(_check_persistence_burst(tenant_id))

    # Lazy save
    if _BASELINE_DIRTY:
        try:
            with _BASELINE_LOCK:
                _save_baseline()
        except Exception:
            pass

    return _dedup_highest_score(factors)


def _register_artifact(tenant_id: str, artifact_key: tuple) -> bool:
    """Return True if this is a novel artifact (first time seen for tenant)."""
    global _BASELINE_DIRTY
    with _BASELINE_LOCK:
        if artifact_key in _KNOWN_PERSISTENCE[tenant_id]:
            return False
        _KNOWN_PERSISTENCE[tenant_id].add(artifact_key)
        _BASELINE_DIRTY = True
        return True


def _record_pers_event(hostname: str, ts: float) -> None:
    with _HOST_PERS_LOCK:
        times = _HOST_PERS_TIMES[hostname]
        times.append(ts)
        # Trim to window
        cutoff = ts - _BURST_WINDOW_SECONDS
        _HOST_PERS_TIMES[hostname] = [t for t in times if t >= cutoff]


def _check_persistence_burst(tenant_id: str) -> List[Dict[str, Any]]:
    """Check for burst of persistence events across hosts."""
    factors = []
    now = time.time()
    with _HOST_PERS_LOCK:
        for hostname, times in _HOST_PERS_TIMES.items():
            recent = [t for t in times if t >= now - _BURST_WINDOW_SECONDS]
            if len(recent) >= _BURST_THRESHOLD:
                factors.append({
                    'factor': 'endpoint:persistence_burst',
                    'score': min(0.65 + 0.05 * (len(recent) - _BURST_THRESHOLD), 0.92),
                    'reason': (
                        f'{len(recent)} persistence events on host "{hostname}" within '
                        f'{_BURST_WINDOW_SECONDS}s (threshold: {_BURST_THRESHOLD})'
                    ),
                    'hostname': hostname,
                    'event_count': len(recent),
                    'window_seconds': _BURST_WINDOW_SECONDS,
                    'tags': ['ATTACK:T1547', 'ATTACK:T1053', 'DREAD:damage', 'STRIDE:elevation'],
                })
    return factors


def _extract_reg_path(text: str) -> str:
    m = re.search(r'HK(?:LM|CU|U|CR|CC)\\\S+', text, re.IGNORECASE)
    return m.group(0)[:200] if m else ''


def _extract_systemd_path(text: str) -> str:
    m = _SYSTEMD_DROP.search(text)
    return m.group(0)[:200] if m else ''


def _dedup_highest_score(factors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[tuple, Dict[str, Any]] = {}
    for f in factors:
        key = (f.get('factor', ''), f.get('hostname', ''), f.get('file_path', f.get('registry_path', ''))[:60])
        existing = seen.get(key)
        if existing is None or f.get('score', 0) > existing.get('score', 0):
            seen[key] = f
    return list(seen.values())


def detect_persistence_signals(runtime, tenant_id: str = 'default', event_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Runtime adapter matching the existing detector call pattern."""
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []
    return detect_persistence(events, tenant_id=tenant_id, event_id=event_id)


__all__ = ['detect_persistence', 'detect_persistence_signals']
