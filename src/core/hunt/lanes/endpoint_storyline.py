"""Endpoint Storyline Lane — SentinelOne Storyline equivalent

Maintains per-host stateful process→network→file event correlation within
a rolling session window.  Detects chains that individually look benign but
together indicate exfiltration or lateral movement.

Built-in stories:
  1. RDP Launch → File Access → Network Upload  (SentinelOne: "Endpoint Exfil")
     mstsc.exe launch on host A → access to sensitive file → outbound large transfer
  2. Office Process → Encoded Script → Network Connect  (macro dropper chain)
  3. Scheduled Task / Service → Large File → External Upload  (persistence + exfil)
  4. Process Injection → Network → File Write  (in-memory → persistence)

Event field contract:
  host — endpoint hostname (key for state)
  process_name / proc / image — process that generated the event
  event_type — 'process'|'network'|'file'|'script'
  file_path / file_name — file involved
  dst_ip / dest_ip, dst_port — network destination
  bytes_sent / transfer_bytes — data volume
  operation / http_method — network/file operation verb
  cmdline — process command line
  timestamp / ts — ISO 8601 or unix float
"""
from __future__ import annotations

import asyncio
import re
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from ..evidence_envelope import EvidenceEnvelope

_WINDOW_SECONDS = 600          # 10-minute storyline window per host
_MAX_EVENTS_PER_HOST = 150
_LARGE_TRANSFER_BYTES = 5_000_000   # 5 MB triggers exfil flag

_OFFICE_PROCS = frozenset({
    'winword.exe', 'excel.exe', 'outlook.exe', 'powerpnt.exe', 'onenote.exe',
})
_SCRIPT_PROCS = frozenset({
    'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
})
_LATERAL_PROCS = frozenset({
    'mstsc.exe', 'psexec.exe', 'psexec64.exe', 'wmic.exe', 'winrs.exe',
})
_INJECTION_INDICATORS = frozenset({
    'virtualalloc', 'writeprocessmemory', 'createremotethread',
    'ntmapviewofsection', 'queueuserapc',
})

_SENSITIVE_FILE_PATTERNS = re.compile(
    r'(?i)(payroll|salary|compensation|bonus|w.?2|1099'
    r'|m.?(?:and|&).?a|merger|acquisition|deal.sheet'
    r'|legal|contract|nda|settlement'
    r'|ssn|social.security|passport|dob|date.of.birth'
    r'|password|credential|secret|api.?key|private.?key)',
)


def _parse_ts(val: Any) -> Optional[float]:
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        try:
            return float(val)
        except ValueError:
            pass
        m = re.match(r'(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})', val)
        if m:
            import calendar, datetime as _dt
            dt = _dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                              int(m.group(4)), int(m.group(5)), int(m.group(6)),
                              tzinfo=_dt.timezone.utc)
            return float(calendar.timegm(dt.timetuple()))
    return None


class _HostStory:
    """Rolling event buffer for one host."""

    def __init__(self, window: int, max_events: int):
        self._window = window
        self._buf: Deque[Tuple[float, str, Dict]] = deque(maxlen=max_events)

    def add(self, ts: float, etype: str, ev: Dict) -> None:
        self._buf.append((ts, etype, ev))

    def trim(self, now: float) -> None:
        cutoff = now - self._window
        while self._buf and self._buf[0][0] < cutoff:
            self._buf.popleft()

    def events(self) -> List[Tuple[float, str, Dict]]:
        return list(self._buf)


class EndpointStorylineLane:
    """Per-host stateful process→network→file chain correlator.

    Equivalent to SentinelOne Storyline: correlates mstsc.exe launch →
    file access → network upload in one storyline without analyst intervention.
    """

    name = 'endpoint_storyline'

    def __init__(self, window_seconds: int = _WINDOW_SECONDS,
                 max_per_host: int = _MAX_EVENTS_PER_HOST):
        self._window = window_seconds
        self._max = max_per_host
        self._stories: Dict[str, _HostStory] = defaultdict(
            lambda: _HostStory(self._window, self._max)
        )

    async def run(self, envelope: EvidenceEnvelope, ctx) -> None:
        ev: Dict[str, Any] = getattr(envelope, 'event', {}) or {}
        factors: List[str] = []

        host = (ev.get('host') or ev.get('hostname') or ev.get('src_host') or '').lower()
        if not host:
            await asyncio.sleep(0)
            return

        ts_raw = ev.get('timestamp') or ev.get('ts') or time.time()
        ts = _parse_ts(ts_raw) or time.time()
        etype = (ev.get('event_type') or ev.get('log_source') or '').lower()

        story = self._stories[host]
        story.trim(ts)
        story.add(ts, etype, ev)
        window_events = story.events()

        if len(window_events) < 2:
            await asyncio.sleep(0)
            return

        factors.extend(self._check_rdp_exfil_story(window_events))
        factors.extend(self._check_office_macro_dropper(window_events))
        factors.extend(self._check_schtask_exfil(window_events))
        factors.extend(self._check_injection_chain(window_events))
        factors.extend(self._check_sensitive_file_access_upload(window_events))

        if factors:
            envelope.add_emission(self.name, factors,
                                  notes='endpoint-storyline', latency_ms=ctx.elapsed_ms())
        await asyncio.sleep(0)

    # ── Story 1: RDP Launch → File Access → Network Upload ─────────────────────────────
    def _check_rdp_exfil_story(self, events: List[Tuple[float, str, Dict]]) -> List[str]:
        """mstsc.exe launched → file read → large outbound transfer."""
        factors: List[str] = []
        try:
            saw_mstsc = False
            saw_file_read = False
            saw_network_upload = False
            for _ts, _etype, se in events:
                proc = (se.get('process_name') or se.get('proc') or se.get('image') or '').lower()
                if proc == 'mstsc.exe':
                    saw_mstsc = True
                if saw_mstsc:
                    # File access after mstsc launch
                    if 'file' in _etype or se.get('file_path') or se.get('file_name'):
                        op = (se.get('operation') or '').lower()
                        if op in ('read', 'open', 'access', 'download', '') or not op:
                            saw_file_read = True
                    # Network upload after mstsc
                    if 'network' in _etype or se.get('dst_ip') or se.get('dest_ip'):
                        sent = se.get('bytes_sent') or se.get('transfer_bytes') or 0
                        if isinstance(sent, (int, float)) and sent >= _LARGE_TRANSFER_BYTES:
                            saw_network_upload = True
                        # Even without bytes_sent, external upload operation counts
                        op = (se.get('operation') or se.get('http_method') or '').upper()
                        if op in ('PUT', 'POST', 'UPLOAD'):
                            saw_network_upload = True

            if saw_mstsc and saw_file_read and saw_network_upload:
                factors.append('storyline:rdp_launch_file_access_upload')
                factors.append('storyline:T1021.001_plus_T1041')
            elif saw_mstsc and saw_network_upload:
                factors.append('storyline:rdp_launch_then_upload')
        except Exception:
            pass
        return factors

    # ── Story 2: Office Process → Encoded Script → Network Connection ──────────────────
    def _check_office_macro_dropper(self, events: List[Tuple[float, str, Dict]]) -> List[str]:
        """winword/excel → powershell (encoded) → external network."""
        factors: List[str] = []
        try:
            saw_office = False
            saw_encoded_script = False
            saw_external_network = False
            for _ts, _etype, se in events:
                proc = (se.get('process_name') or se.get('proc') or se.get('image') or '').lower()
                cmd = se.get('cmdline') or ''
                if proc in _OFFICE_PROCS:
                    saw_office = True
                if saw_office and proc in _SCRIPT_PROCS:
                    if re.search(r'-enc\s+[A-Za-z0-9+/=]{8,}', cmd, re.I):
                        saw_encoded_script = True
                    elif not cmd:  # launched without cmdline is also suspicious
                        saw_encoded_script = True
                if saw_office and (se.get('dst_ip') or se.get('dest_ip')):
                    dst_int = se.get('dst_internal') or se.get('is_internal')
                    if not dst_int:
                        saw_external_network = True
            if saw_office and saw_encoded_script and saw_external_network:
                factors.append('storyline:office_macro_dropper_chain')
                factors.append('storyline:T1566.001_plus_T1059.001')
        except Exception:
            pass
        return factors

    # ── Story 3: Scheduled Task / Service → Large File → External Upload ───────────────
    def _check_schtask_exfil(self, events: List[Tuple[float, str, Dict]]) -> List[str]:
        """Scheduled task creates large file then uploads externally."""
        factors: List[str] = []
        try:
            saw_schtask = False
            large_file_created = False
            saw_external_upload = False
            for _ts, _etype, se in events:
                proc = (se.get('process_name') or se.get('proc') or '').lower()
                if proc in ('schtasks.exe', 'taskeng.exe', 'taskhost.exe', 'at.exe'):
                    saw_schtask = True
                if saw_schtask:
                    size = se.get('file_size') or se.get('bytes_written') or 0
                    if isinstance(size, (int, float)) and size >= _LARGE_TRANSFER_BYTES:
                        large_file_created = True
                    sent = se.get('bytes_sent') or se.get('transfer_bytes') or 0
                    if isinstance(sent, (int, float)) and sent >= _LARGE_TRANSFER_BYTES:
                        if not se.get('dst_internal'):
                            saw_external_upload = True
            if saw_schtask and (large_file_created or saw_external_upload):
                factors.append('storyline:schtask_large_transfer')
                factors.append('storyline:T1053_plus_T1041')
        except Exception:
            pass
        return factors

    # ── Story 4: Process Injection Indicator → Network → File Write ────────────────────
    def _check_injection_chain(self, events: List[Tuple[float, str, Dict]]) -> List[str]:
        """API call indicating injection → external network → file persistence."""
        factors: List[str] = []
        try:
            saw_injection = False
            saw_network = False
            saw_file_write = False
            for _ts, _etype, se in events:
                # Injection: API call name or factor tag
                api = (se.get('api_call') or se.get('syscall') or '').lower()
                factor_tags = se.get('factors') or se.get('tags') or []
                if api in _INJECTION_INDICATORS or any(
                    'inject' in str(f).lower() for f in factor_tags
                ):
                    saw_injection = True
                if saw_injection:
                    if se.get('dst_ip') or se.get('dest_ip'):
                        saw_network = True
                    op = (se.get('file_operation') or se.get('operation') or '').lower()
                    if op in ('write', 'create', 'modify') and (se.get('file_path') or se.get('file_name')):
                        saw_file_write = True
            if saw_injection and saw_network and saw_file_write:
                factors.append('storyline:injection_network_persistence_chain')
                factors.append('storyline:T1055_plus_T1041')
        except Exception:
            pass
        return factors

    # ── Story 5: Sensitive File Access → Upload ─────────────────────────────────────────
    def _check_sensitive_file_access_upload(self, events: List[Tuple[float, str, Dict]]) -> List[str]:
        """Any process accesses a sensitive file then uploads externally."""
        factors: List[str] = []
        try:
            sensitive_files_accessed: List[str] = []
            saw_external_upload = False
            for _ts, _etype, se in events:
                fp = se.get('file_path') or se.get('file_name') or ''
                if fp and _SENSITIVE_FILE_PATTERNS.search(str(fp)):
                    sensitive_files_accessed.append(fp)
                sent = se.get('bytes_sent') or se.get('transfer_bytes') or 0
                if isinstance(sent, (int, float)) and sent >= _LARGE_TRANSFER_BYTES:
                    if not se.get('dst_internal'):
                        saw_external_upload = True
            if sensitive_files_accessed and saw_external_upload:
                factors.append('storyline:sensitive_file_access_then_upload')
                # Tag file sensitivity category hint
                combined = ' '.join(sensitive_files_accessed).lower()
                if re.search(r'payroll|salary|bonus|w.?2|1099', combined):
                    factors.append('storyline:sensitive_file_payroll')
                if re.search(r'm.?(?:and|&).?a|merger|acquisition', combined):
                    factors.append('storyline:sensitive_file_ma')
                if re.search(r'ssn|social.security|passport|dob', combined):
                    factors.append('storyline:sensitive_file_pii')
        except Exception:
            pass
        return factors


LANE = EndpointStorylineLane()
