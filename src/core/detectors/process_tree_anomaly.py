"""ProcessTreeAnomalyDetector — endpoint process lineage and command-line rarity scoring.

Emits factors:
    endpoint:process_tree_anomaly  — Parent→child relationship outside normal baseline (IF score or rarity)
    endpoint:cmdline_rarity_high   — Command-line tokens with high TF-IDF rarity vs. host profile
    endpoint:orphan_process        — Process with no parent in telemetry (PPID missing or ghost)
    endpoint:process_depth_spike   — Unusual process tree depth (deeply nested spawning)
    endpoint:lolbin_child_unusual  — LOLBin binary spawned by an unusual parent
    endpoint:process_masquerade    — Process executable path inconsistent with system location for that name

Windows and Linux coverage:
    - Windows: PPID chain from Event ID 4688 / Sysmon Event 1
    - Linux: /proc/pid/status-style events, auditd records

HopGraph wiring: add edge (process:<pid>, process:<ppid>, 'spawned_by', weight=score)
                 add edge (process:<pid>, host:<hostname>, 'ran_on', weight=1.0)

IsolationForest: Optional. Uses existing src/ml/isolation_model.py wrapper.
                 Falls back to rarity heuristics if ML unavailable.
"""
from __future__ import annotations

import math
import os
import re
import threading
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional ML dependency
# ---------------------------------------------------------------------------
try:
    from src.ml.isolation_model import IsolationWrapper
    _ISO_MODEL: Optional[Any] = IsolationWrapper()
except Exception:
    _ISO_MODEL = None

try:
    from src.detectors.ewma_adaptive import AdaptiveEWMA
    _TREE_EWMA: Optional[Any] = AdaptiveEWMA(base_alpha=0.25)
except Exception:
    _TREE_EWMA = None

# ---------------------------------------------------------------------------
# LOLBin process names (Windows) — canonical system names abused by attackers
# ---------------------------------------------------------------------------
_LOLBIN_NAMES = {
    'certutil.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe',
    'cscript.exe', 'bitsadmin.exe', 'msiexec.exe', 'wmic.exe', 'odbcconf.exe',
    'cmstp.exe', 'installutil.exe', 'msbuild.exe', 'ieexec.exe', 'pcalua.exe',
    'appsyncpublishdav.exe', 'syncappvpublishingserver.exe', 'diskshadow.exe',
    'esentutl.exe', 'expand.exe', 'forfiles.exe', 'infdefaultinstall.exe',
    'makecab.exe', 'msdeploy.exe', 'msdt.exe', 'msiexec.exe', 'presentationhost.exe',
    'regasm.exe', 'regsvcs.exe', 'replace.exe', 'rpcping.exe', 'runscripthelper.exe',
    'scriptrunner.exe', 'squirrel.exe', 'syncappvpublishingserver.ps1',
    # Linux LOLBins
    'curl', 'wget', 'python', 'python3', 'perl', 'ruby', 'php', 'nc', 'netcat',
    'ncat', 'openssl', 'bash', 'sh', 'dash', 'zsh', 'awk', 'sed', 'dd',
    'socat', 'telnet', 'xterm', 'xxd', 'base64', 'env', 'find',
}

# Expected parent→child pairs (whitelist of common benign combos)
# Format: frozenset({parent_name, child_name}) — order-independent
_BENIGN_PAIRS: set[frozenset] = {
    frozenset({'explorer.exe', 'chrome.exe'}),
    frozenset({'explorer.exe', 'firefox.exe'}),
    frozenset({'explorer.exe', 'notepad.exe'}),
    frozenset({'services.exe', 'svchost.exe'}),
    frozenset({'wininit.exe', 'services.exe'}),
    frozenset({'winlogon.exe', 'userinit.exe'}),
    frozenset({'svchost.exe', 'taskhostw.exe'}),
    frozenset({'taskeng.exe', 'svchost.exe'}),
    frozenset({'bash', 'python3'}),
    frozenset({'bash', 'python'}),
    frozenset({'bash', 'sh'}),
    frozenset({'sshd', 'bash'}),
    frozenset({'sshd', 'sh'}),
    frozenset({'systemd', 'bash'}),
    frozenset({'init', 'bash'}),
}

# High-risk parent→child combinations
_HIGH_RISK_PAIRS: Dict[str, set] = {
    # Office apps spawning shells
    'winword.exe':  {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe'},
    'excel.exe':    {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'},
    'powerpnt.exe': {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'},
    'outlook.exe':  {'cmd.exe', 'powershell.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe'},
    # Browser spawning shells
    'chrome.exe':   {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'},
    'firefox.exe':  {'cmd.exe', 'powershell.exe', 'mshta.exe'},
    # PDF readers
    'acrord32.exe': {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'},
    # Compression tools spawning executables
    '7z.exe':       {'cmd.exe', 'powershell.exe'},
    'winrar.exe':   {'cmd.exe', 'powershell.exe', 'mshta.exe'},
    # Linux: script interpreters spawning network tools
    'python':       {'nc', 'ncat', 'socat', 'curl', 'wget'},
    'python3':      {'nc', 'ncat', 'socat', 'curl', 'wget'},
    'php':          {'bash', 'sh', 'nc', 'ncat'},
    'perl':         {'bash', 'sh', 'nc', 'ncat'},
}

# Process names that should only live in specific paths
_SYSTEM_PROCESS_PATHS: Dict[str, List[str]] = {
    'svchost.exe':  [r'c:\windows\system32\\', r'c:\windows\syswow64\\'],
    'lsass.exe':    [r'c:\windows\system32\\'],
    'services.exe': [r'c:\windows\system32\\'],
    'winlogon.exe': [r'c:\windows\system32\\'],
    'csrss.exe':    [r'c:\windows\system32\\'],
    'smss.exe':     [r'c:\windows\system32\\'],
    'wininit.exe':  [r'c:\windows\system32\\'],
}

# Maximum expected process tree depth before flagging
_MAX_NORMAL_DEPTH = 8

# ---------------------------------------------------------------------------
# In-memory host process baseline (per-tenant, ring-buffer style)
# ---------------------------------------------------------------------------
_BASELINE_LOCK = threading.RLock()
# tenant → Counter of (parent_name, child_name) pairs seen
_PAIR_BASELINE: Dict[str, Counter] = defaultdict(Counter)
# tenant → Counter of cmdline tokens
_CMDLINE_BASELINE: Dict[str, Counter] = defaultdict(Counter)
_BASELINE_TOTAL: Dict[str, int] = defaultdict(int)
_MAX_BASELINE_ENTRIES = int(os.getenv('PROCESS_BASELINE_MAX', '50000'))


def _norm_proc_name(path: str) -> str:
    """Extract lowercase basename from a process path."""
    name = os.path.basename(path or '').lower().strip()
    # Remove trailing null bytes or whitespace
    return name.rstrip('\x00 ')


def _tokenize_cmdline(cmdline: str) -> List[str]:
    """Split command line into meaningful tokens for TF-IDF baseline."""
    if not cmdline:
        return []
    # Remove common noise: absolute paths (keep basename), quotes
    cmdline = re.sub(r'"([^"]*)"', lambda m: m.group(1), cmdline)
    cmdline = re.sub(r"'([^']*)'", lambda m: m.group(1), cmdline)
    # Split on whitespace and common delimiters
    raw_tokens = re.split(r'[\s,;|&]+', cmdline)
    tokens = []
    for tok in raw_tokens:
        tok = tok.strip().lower()
        if not tok:
            continue
        # Keep basenames of paths
        if os.sep in tok or '/' in tok or '\\' in tok:
            tok = os.path.basename(tok)
        # Skip very short tokens and pure numbers
        if len(tok) < 3 or tok.isdigit():
            continue
        tokens.append(tok)
    return tokens


def _compute_token_rarity(tokens: List[str], baseline: Counter, total: int) -> float:
    """Return average inverse frequency of tokens vs. baseline (simplified TF-IDF rarity)."""
    if not tokens or total < 10:
        return 0.0
    scores = []
    for tok in tokens:
        count = baseline.get(tok, 0)
        if count == 0:
            # Completely novel token — max rarity
            scores.append(1.0)
        else:
            # Inverse document frequency proxy: log(N/count)
            idf = math.log((total + 1) / (count + 1))
            # Normalize to 0..1 range (log scale, max ~log(N))
            max_idf = math.log(total + 1) if total > 0 else 1.0
            scores.append(min(idf / max(max_idf, 1.0), 1.0))
    return sum(scores) / len(scores) if scores else 0.0


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_process_tree_anomaly(
    events: List[Dict[str, Any]],
    tenant_id: str = 'default',
    event_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Analyze process events for tree anomalies and command-line rarity.

    Args:
        events:    List of normalized endpoint events from sanitized_events.
        tenant_id: Tenant for baseline isolation.
        event_id:  Optional event ID for factor dedup.

    Returns:
        List of factor dicts.
    """
    factors: List[Dict[str, Any]] = []
    process_events = []

    # Filter to process-related events
    for ev in events:
        try:
            etype = str(ev.get('event_type') or ev.get('type') or '').lower()
            src   = str(ev.get('source_platform') or ev.get('source') or '').lower()
            if any(k in etype for k in ('process', 'exec', 'spawn', 'fork')) or 'endpoint' in src:
                process_events.append(ev)
            elif ev.get('parent_process') or ev.get('ppid') or ev.get('process_name'):
                process_events.append(ev)
        except Exception:
            continue

    if not process_events:
        return factors

    with _BASELINE_LOCK:
        pair_baseline   = _PAIR_BASELINE[tenant_id]
        cmdline_baseline = _CMDLINE_BASELINE[tenant_id]
        baseline_total  = _BASELINE_TOTAL[tenant_id]

        for ev in process_events:
            try:
                proc_path   = str(ev.get('process') or ev.get('image') or ev.get('process_name') or '')
                parent_path = str(ev.get('parent_process') or ev.get('parent_image') or ev.get('ppid_name') or '')
                cmdline     = str(ev.get('cmdline') or ev.get('command_line') or '')
                hostname    = str(ev.get('host') or ev.get('hostname') or ev.get('computer') or '')
                pid         = str(ev.get('pid') or '')
                ppid        = str(ev.get('ppid') or '')
                depth       = int(ev.get('process_depth') or ev.get('tree_depth') or 0)
                ts          = float(ev.get('timestamp') or ev.get('ts') or time.time())

                proc_name   = _norm_proc_name(proc_path)
                parent_name = _norm_proc_name(parent_path)

                # ----------------------------------------------------------------
                # A. Update baseline (unsupervised learning on observed pairs)
                # ----------------------------------------------------------------
                if proc_name and parent_name:
                    pair_key = f'{parent_name}→{proc_name}'
                    pair_baseline[pair_key] += 1
                    baseline_total += 1
                    # Trim if too large
                    if baseline_total > _MAX_BASELINE_ENTRIES:
                        # Drop the least-common 10% of pairs
                        threshold = sorted(pair_baseline.values())[len(pair_baseline) // 10]
                        for k in list(pair_baseline.keys()):
                            if pair_baseline[k] <= threshold:
                                del pair_baseline[k]

                tokens = _tokenize_cmdline(cmdline)
                for tok in tokens:
                    cmdline_baseline[tok] += 1

                _BASELINE_TOTAL[tenant_id] = baseline_total

                # ----------------------------------------------------------------
                # B. High-risk parent→child pair check
                # ----------------------------------------------------------------
                if parent_name and proc_name:
                    high_risk_children = _HIGH_RISK_PAIRS.get(parent_name, set())
                    if proc_name in high_risk_children:
                        factors.append({
                            'factor': 'endpoint:process_tree_anomaly',
                            'score': 0.87,
                            'reason': f'High-risk process spawn: "{parent_name}" → "{proc_name}" (document/browser spawning shell)',
                            'parent': parent_name,
                            'child': proc_name,
                            'cmdline': cmdline[:300],
                            'hostname': hostname,
                            'pid': pid,
                            'ppid': ppid,
                            'tags': ['ATTACK:T1059', 'ATTACK:T1566.001', 'ATTACK:T1204.002', 'STRIDE:elevation'],
                        })
                    elif pair_key in pair_baseline and pair_baseline[pair_key] == 1 and baseline_total > 100:
                        # First-ever observation of this pair in baseline
                        factors.append({
                            'factor': 'endpoint:process_tree_anomaly',
                            'score': 0.55,
                            'reason': f'Novel parent→child pair "{parent_name}" → "{proc_name}" never seen in baseline ({baseline_total} observations)',
                            'parent': parent_name,
                            'child': proc_name,
                            'hostname': hostname,
                            'tags': ['ATTACK:T1059', 'ATTACK:T1036', 'STRIDE:elevation'],
                        })

                # ----------------------------------------------------------------
                # C. Orphan process (no parent telemetry)
                # ----------------------------------------------------------------
                if pid and not ppid and not parent_name:
                    if proc_name not in {'system', 'init', 'systemd', 'launchd', 'kernel'}:
                        factors.append({
                            'factor': 'endpoint:orphan_process',
                            'score': 0.62,
                            'reason': f'Process "{proc_name}" (PID {pid}) has no parent in telemetry — possible log gap or injection',
                            'process': proc_name,
                            'pid': pid,
                            'hostname': hostname,
                            'tags': ['ATTACK:T1055', 'ATTACK:T1036', 'STRIDE:elevation'],
                        })

                # ----------------------------------------------------------------
                # D. Process tree depth spike
                # ----------------------------------------------------------------
                if depth > _MAX_NORMAL_DEPTH:
                    factors.append({
                        'factor': 'endpoint:process_depth_spike',
                        'score': min(0.50 + 0.04 * (depth - _MAX_NORMAL_DEPTH), 0.80),
                        'reason': f'Process tree depth {depth} exceeds normal threshold {_MAX_NORMAL_DEPTH}',
                        'depth': depth,
                        'process': proc_name,
                        'hostname': hostname,
                        'tags': ['ATTACK:T1055', 'ATTACK:T1059', 'STRIDE:elevation'],
                    })

                # ----------------------------------------------------------------
                # E. LOLBin spawned by unusual parent
                # ----------------------------------------------------------------
                if proc_name in _LOLBIN_NAMES and parent_name:
                    pair = frozenset({parent_name, proc_name})
                    if pair not in _BENIGN_PAIRS:
                        known_risk = parent_name in _HIGH_RISK_PAIRS
                        factors.append({
                            'factor': 'endpoint:lolbin_child_unusual',
                            'score': 0.80 if known_risk else 0.65,
                            'reason': f'LOLBin "{proc_name}" spawned by "{parent_name}" — unusual parent',
                            'lolbin': proc_name,
                            'parent': parent_name,
                            'cmdline': cmdline[:300],
                            'hostname': hostname,
                            'tags': ['ATTACK:T1218', 'ATTACK:T1059', 'STRIDE:elevation'],
                        })

                # ----------------------------------------------------------------
                # F. Process masquerade (wrong path for system process name)
                # ----------------------------------------------------------------
                if proc_name in _SYSTEM_PROCESS_PATHS and proc_path:
                    expected_paths = _SYSTEM_PROCESS_PATHS[proc_name]
                    path_lower = proc_path.lower().replace('/', '\\')
                    if not any(path_lower.startswith(ep) for ep in expected_paths):
                        factors.append({
                            'factor': 'endpoint:process_masquerade',
                            'score': 0.90,
                            'reason': f'"{proc_name}" running from unexpected path "{proc_path}" (expected: {expected_paths})',
                            'process': proc_name,
                            'actual_path': proc_path,
                            'expected_paths': expected_paths,
                            'hostname': hostname,
                            'tags': ['ATTACK:T1036.005', 'ATTACK:T1055', 'STRIDE:elevation'],
                        })

                # ----------------------------------------------------------------
                # G. Command-line rarity scoring
                # ----------------------------------------------------------------
                if tokens and baseline_total >= 50:
                    rarity = _compute_token_rarity(tokens, cmdline_baseline, baseline_total)
                    if rarity >= 0.70:
                        factors.append({
                            'factor': 'endpoint:cmdline_rarity_high',
                            'score': min(0.45 + 0.5 * rarity, 0.85),
                            'reason': f'Command-line token rarity score {rarity:.2f} vs. host baseline ({baseline_total} observations)',
                            'rarity_score': round(rarity, 3),
                            'process': proc_name,
                            'cmdline': cmdline[:300],
                            'hostname': hostname,
                            'novel_tokens': [t for t in tokens if cmdline_baseline.get(t, 0) == 0][:10],
                            'tags': ['ATTACK:T1059', 'ATTACK:T1027', 'STRIDE:elevation'],
                        })

                # ----------------------------------------------------------------
                # H. IsolationForest scoring (when available)
                # ----------------------------------------------------------------
                if _ISO_MODEL is not None and proc_name and parent_name:
                    try:
                        features = [
                            float(len(proc_name)),
                            float(len(parent_name)),
                            float(depth),
                            float(len(cmdline)),
                            float(len(tokens)),
                            float(pair_baseline.get(f'{parent_name}→{proc_name}', 0)),
                        ]
                        iso_score = _ISO_MODEL.score(features)
                        if iso_score >= 0.75:
                            factors.append({
                                'factor': 'endpoint:process_tree_anomaly',
                                'score': min(0.50 + 0.40 * iso_score, 0.80),
                                'reason': f'IsolationForest anomaly score {iso_score:.2f} for process pair "{parent_name}" → "{proc_name}"',
                                'iso_score': round(iso_score, 3),
                                'parent': parent_name,
                                'child': proc_name,
                                'hostname': hostname,
                                'source': 'isolation_forest',
                                'tags': ['ATTACK:T1059', 'ATTACK:T1036', 'STRIDE:elevation'],
                            })
                    except Exception:
                        pass

            except Exception:
                continue

    return _dedup_highest_score(factors)


def _dedup_highest_score(factors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep highest-score entry per (factor, process, parent)."""
    seen: Dict[tuple, Dict[str, Any]] = {}
    for f in factors:
        key = (f.get('factor', ''), f.get('process', ''), f.get('parent', ''))
        existing = seen.get(key)
        if existing is None or f.get('score', 0) > existing.get('score', 0):
            seen[key] = f
    return list(seen.values())


def detect_process_tree_anomalies(runtime, tenant_id: str = 'default', event_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Runtime adapter matching the existing detector call pattern."""
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []
    return detect_process_tree_anomaly(events, tenant_id=tenant_id, event_id=event_id)


__all__ = ['detect_process_tree_anomaly', 'detect_process_tree_anomalies']
