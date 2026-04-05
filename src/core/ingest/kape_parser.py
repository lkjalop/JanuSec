"""KAPE artifact parser: lightweight, heuristic-based normalization for common artifacts.

Parsers implemented (heuristic):
- Prefetch (exe name, last_run_ts, run_count)
- AmCache (program entries -> file path, publisher, timestamp)
- ShimCache (path, last_mod)
- MFT excerpt lines (filename, mft_entry, ts)
- Registry Run/RunOnce entries (value, data)

These parsers produce normalized event dicts with canonical keys used by the
ingestion pipeline: `type`, `host`, `user`, `file_path`, `file_hash`,
`timestamp`, `evidence`, `service`, `other`.
"""
from __future__ import annotations

from typing import Iterable, Dict, Any, List, Optional
import re
import time
import os
import json
from datetime import datetime


def _extract_hashes(s: str) -> Dict[str, str]:
    """Extract common hash types from a text line (md5, sha1, sha256)."""
    out = {}
    try:
        m = re.search(r"\b([a-fA-F0-9]{32})\b", s)
        if m:
            out['md5'] = m.group(1).lower()
        m = re.search(r"\b([a-fA-F0-9]{40})\b", s)
        if m:
            out['sha1'] = m.group(1).lower()
        m = re.search(r"\b([a-fA-F0-9]{64})\b", s)
        if m:
            out['sha256'] = m.group(1).lower()
    except Exception:
        return {}
    return out


def _load_sidecar_hashes_for_path(basepath: str) -> Dict[str, Dict[str, str]]:
    """If a JSON sidecar next to `basepath` exists (base.json), load mapping of filename->hashes.

    Returns a mapping {basename: {hash_type: value, ...}}
    """
    out: Dict[str, Dict[str, str]] = {}
    try:
        sidecar = f"{basepath}.json"
        if not os.path.exists(sidecar):
            return out
        with open(sidecar, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            # tolerate formats: {"files": [{"name":..., "md5":...}, ...]} or {"basename": {..}}
            if 'files' in data and isinstance(data['files'], list):
                for it in data['files']:
                    name = it.get('name') or it.get('filename')
                    if not name:
                        continue
                    hmap = {k: v for k, v in it.items() if k.lower() in ('md5', 'sha1', 'sha256') and isinstance(v, str)}
                    if hmap:
                        out[name] = hmap
            else:
                # assume mapping
                for k, v in data.items():
                    if isinstance(v, dict):
                        out[k] = {kk: str(vv) for kk, vv in v.items() if kk.lower() in ('md5', 'sha1', 'sha256')}
    except Exception:
        pass
    return out


def _parse_userassist_line(s: str) -> Dict[str, Any] | None:
    """Parse a UserAssist-style line into normalized event.

    Expected to find a key name and a run count or timestamp. This is a
    heuristic fallback that extracts program path, count and last_run_ts when
    available.
    """
    try:
        # Example patterns: "{GUID}\Count\MyApp.exe -> Count=5; LastRun=2024-01-01T12:00:00"
        # Accept either full paths (C:\Path\to\app.exe) or bare exe names (MyApp.exe)
        m = re.search(r"([A-Za-z]:\\[\w\\.\-\s]+\.exe|[\w\-. ]+\.exe)", s)
        if not m:
            return None
        path = m.group(1)
        count = None
        last_ts = None
        mc = re.search(r"Count[:=]\s*(\d+)", s, re.I)
        if mc:
            try:
                count = int(mc.group(1))
            except Exception:
                count = None
        mt = re.search(r"LastRun[:=]\s*([0-9T:\-\s]+)", s, re.I)
        if mt:
            try:
                last_ts = datetime.fromisoformat(mt.group(1).strip()).timestamp()
            except Exception:
                try:
                    last_ts = datetime.strptime(mt.group(1).strip(), "%Y-%m-%d %H:%M:%S").timestamp()
                except Exception:
                    last_ts = None
        ev = {
            'type': 'kape.userassist',
            'file_path': path,
            'timestamp': last_ts or time.time(),
            'evidence': {'raw': s}
        }
        if count is not None:
            ev['run_count'] = count
        return ev
    except Exception:
        return None


def _parse_mru_line(s: str) -> Dict[str, Any] | None:
    """Parse MRU (Most Recently Used) entries into artifact events."""
    try:
        # MRU entries often contain a filename/path and an index or timestamp
        m = re.search(r"([A-Za-z]:\\[\w\\.\-\s]+[\\/][^,;\n]+)", s)
        if not m:
            return None
        path = m.group(1).strip().strip('"')
        ts = None
        mt = re.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", s)
        if mt:
            try:
                ts = datetime.strptime(mt.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
            except Exception:
                try:
                    ts = datetime.fromisoformat(mt.group(1)).timestamp()
                except Exception:
                    ts = None
        ev = {'type': 'kape.mru', 'file_path': path, 'timestamp': ts or time.time(), 'evidence': {'raw': s}}
        return ev
    except Exception:
        return None


def _parse_filetime_token(tok: str) -> Optional[float]:
    """Parse Windows FILETIME integer or common timestamp strings into epoch seconds.

    Accepts large FILETIME ints (100ns since 1601), ISO strings, and YYYY-MM-DD timestamps.
    """
    if not tok:
        return None
    tok = tok.strip()
    # FILETIME large integer (>=1e16)
    m = re.match(r"^(1\d{15,})$", tok)
    if m:
        try:
            ft = int(m.group(1))
            seconds = ft / 10_000_000.0
            epoch_delta = 11644473600
            return seconds - epoch_delta
        except Exception:
            return None
    # ISO datetime
    try:
        try:
            return datetime.fromisoformat(tok).timestamp()
        except Exception:
            return datetime.strptime(tok, "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        # try parsing as numeric seconds
        try:
            return float(tok)
        except Exception:
            return None


def parse_kape_lines(lines: Iterable[str]) -> Iterable[Dict[str, Any]]:
    """Detect artifact type heuristically and yield normalized events."""
    for l in lines:
        s = l.strip()
        if not s:
            continue
        # Prefetch: looks like "<exe>-<hash>.pf -> LastRun: 2023-... Count: N"
        if s.lower().endswith('.pf') or ('lastrun' in s.lower() and 'count' in s.lower()):
            ev = _parse_prefetch_line(s)
            if ev:
                yield ev
                continue

        # AmCache program entries: often contain 'Program ID', 'File' or 'FilePath'
        if 'amcache' in s.lower() or ('program' in s.lower() and ('file' in s.lower() or '\\' in s)):
            ev = _parse_amcache_line(s)
            if ev:
                yield ev
                continue

        # ShimCache lines often look like a path followed by a timestamp
        if '\\' in s and ('shimcache' in s.lower() or re.search(r'\d{4}-\d{2}-\d{2}', s)):
            ev = _parse_shimcache_line(s)
            if ev:
                yield ev
                continue

        # UserAssist entries
        if 'userassist' in s.lower() or 'count=' in s.lower():
            ev = _parse_userassist_line(s)
            if ev:
                yield ev
                continue

        # MFT excerpt: usually contains 'MFT' or is a tab-separated filename with
        # an entry token or a large FILETIME integer. Accept lines even if the
        # literal 'mft' is missing.
        if 'mft' in s.lower() or ('\t' in s and ('entry' in s.lower() or re.search(r'\d{14,}', s))):
            ev = _parse_mft_line(s)
            if ev:
                yield ev
                continue

        # MRU-like entries
        if 'mru' in s.lower() or s.lower().startswith('recent') or ('Most Recently Used' in s):
            ev = _parse_mru_line(s)
            if ev:
                yield ev
                continue

        # Registry run keys: looks like 'Run:' or 'RunOnce:' key/value
        if s.lower().startswith('run:') or s.lower().startswith('runonce:') or '\\software\\microsoft\\windows\\currentversion\\run' in s.lower():
            ev = _parse_run_key_line(s)
            if ev:
                yield ev
                continue

        # Generic fallback: produce a generic artifact event including any hashes found
        hv = _extract_hashes(s)
        ev = {'type': 'kape.artifact', 'raw': s, 'timestamp': time.time()}
        if hv:
            ev['hashes'] = hv
        yield ev


def _parse_prefetch_line(s: str) -> Dict[str, Any] | None:
    # try common patterns
    try:
        # example: "chrome.exe-12345678.pf - LastRun: 2024-01-01 12:00:00 - Count: 5"
        m = re.search(r"(?P<exe>[^\s]+\.exe)[-_]?[0-9a-fA-F]{4,}\.?pf\b", s, re.I)
        if not m:
            m = re.search(r"(?P<exe>[^\s]+\.exe).*LastRun[:=]\s*(?P<ts>[0-9T:\-\s]+).*Count[:=]\s*(?P<count>\d+)", s, re.I)
        if m:
            exe = m.group('exe')
            ev = {'type': 'kape.prefetch', 'file_path': exe, 'timestamp': time.time(), 'evidence': {'raw': s}}
            return ev
    except Exception:
        return None
    return None


def _parse_amcache_line(s: str) -> Dict[str, Any] | None:
    try:
        # heuristics: look for a path and maybe 'Publisher' or 'Company'
        m = re.search(r"([A-Za-z]:\\[\w\\.\-\s]+\.exe)", s)
        if m:
            path = m.group(1)
            # publisher / company
            pub = None
            mm = re.search(r"(Publisher|Company)[:=]\s*([^;\n]+)", s, re.I)
            if mm:
                pub = mm.group(2).strip()
            # try to find file size
            size = None
            ms = re.search(r"(Size|FileSize)[:=]\s*(\d+)", s, re.I)
            if ms:
                try:
                    size = int(ms.group(2))
                except Exception:
                    size = None
            # try to capture file version
            version = None
            mv = re.search(r"FileVersion[:=]\s*([^;\n]+)", s, re.I)
            if mv:
                version = mv.group(1).strip()
            # extract hashes if present
            hv = _extract_hashes(s)
            ev = {
                'type': 'kape.amcache',
                'file_path': path,
                'publisher': pub,
                'timestamp': time.time(),
                'evidence': {'raw': s}
            }
            if size:
                ev['file_size'] = size
            if version:
                ev['file_version'] = version
            if hv:
                ev['hashes'] = hv
            return ev
    except Exception:
        return None
    return None


def _parse_shimcache_line(s: str) -> Dict[str, Any] | None:
    try:
        # capture path and optional timestamp and flags
        m = re.search(r"([A-Za-z]:\\[\w\\.\-\s]+\.exe)(?:\s+([0-9]{4}-[0-9]{2}-[0-9]{2}[ T]?\d{0,8}:?\d{0,8}:?\d{0,8}))?(?:\s+Flags[:=]?\s*([0-9]+))?", s)
        if m:
            path = m.group(1)
            tsraw = m.group(2)
            shim_ts = None
            try:
                shim_ts = datetime.strptime(tsraw.strip(), "%Y-%m-%d %H:%M:%S").timestamp()
            except Exception:
                try:
                    shim_ts = datetime.strptime(tsraw.strip(), "%Y-%m-%dT%H:%M:%S").timestamp()
                except Exception:
                    shim_ts = None
            flags = None
            try:
                flags = int(m.group(3)) if m.group(3) else None
            except Exception:
                flags = None
            ev = {
                'type': 'kape.shimcache',
                'file_path': path,
                'timestamp': shim_ts or time.time(),
                'evidence': {'raw': s, 'shim_ts': tsraw}
            }
            if flags is not None:
                ev['flags'] = flags
            # include hashes if any
            hv = _extract_hashes(s)
            if hv:
                ev['hashes'] = hv
            return ev
    except Exception:
        return None
    return None


def _parse_mft_line(s: str) -> Dict[str, Any] | None:
    try:
        # simplistic: filename TAB entry
        parts = s.split('\t')
        if len(parts) >= 2:
            filename = parts[0].strip().strip('"')
            # normalize slashes
            filename = filename.replace('/', '\\')
            entry = parts[1].strip()
            # attempt to parse an ISO-like timestamp in the entry
            ts = None
            m_ts = re.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", entry)
            if m_ts:
                try:
                    dt = datetime.strptime(m_ts.group(1), "%Y-%m-%d %H:%M:%S")
                    ts = dt.timestamp()
                except Exception:
                    try:
                        dt = datetime.strptime(m_ts.group(1), "%Y-%m-%dT%H:%M:%S")
                        ts = dt.timestamp()
                    except Exception:
                        ts = None
            # Attempt to detect NTFS FILETIME (large int > 1e16)
            if ts is None:
                m_filet = re.search(r"(1\d{16,})", entry)
                if m_filet:
                    try:
                        # FILETIME is 100-ns intervals since Jan 1 1601
                        ft = int(m_filet.group(1))
                        # convert to seconds
                        seconds = ft / 10_000_000.0
                        # epoch delta between 1601 and 1970
                        epoch_delta = 11644473600
                        ts = seconds - epoch_delta
                    except Exception:
                        ts = None
            # attempt to extract MFT entry id (hex) if present in entry
            m_entry = re.search(r"\b0x([0-9A-Fa-f]+)\b", entry)
            mft_id = None
            if m_entry:
                try:
                    mft_id = int(m_entry.group(1), 16)
                except Exception:
                    mft_id = None
            ev = {'type': 'kape.mft', 'file_path': filename, 'mft_entry': entry, 'timestamp': ts or time.time(), 'evidence': {'raw': s}}
            if mft_id is not None:
                ev['mft_entry_id'] = mft_id
            return ev
        # fallback: find filename and any timestamp-like token
        m = re.search(r"([^\\/]+\.[A-Za-z0-9]{1,5})", s)
        if m:
            filename = m.group(1).strip('"')
            filename = filename.replace('/', '\\')
            m_ts = re.search(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", s)
            ts = None
            if m_ts:
                try:
                    dt = datetime.strptime(m_ts.group(1), "%Y-%m-%d %H:%M:%S")
                    ts = dt.timestamp()
                except Exception:
                    try:
                        dt = datetime.strptime(m_ts.group(1), "%Y-%m-%dT%H:%M:%S")
                        ts = dt.timestamp()
                    except Exception:
                        ts = None
            ev = {'type': 'kape.mft', 'file_path': filename, 'timestamp': ts or time.time(), 'evidence': {'raw': s}}
            return ev
    except Exception:
        return None
    return None


def _parse_run_key_line(s: str) -> Dict[str, Any] | None:
    try:
        # lines like "Run: MyApp = C:\\Path\\to\\app.exe /arg"
        m = re.search(r"Run(?:Once)?[:\s]+(?P<name>[^=:\n]+)[:=]?\s*(?P<data>.+)$", s, re.I)
        if m:
            name = m.group('name').strip()
            data = m.group('data').strip()
            ev = {'type': 'kape.registry.run', 'value_name': name, 'data': data, 'timestamp': time.time(), 'evidence': {'raw': s}}
            return ev
        # fallback: key path contains run path
        if '\\software\\microsoft\\windows\\currentversion\\run' in s.lower():
            # try capturing quoted values
            m2 = re.search(r'"([A-Za-z]:\\[^"]+)"', s)
            if m2:
                ev = {'type': 'kape.registry.run', 'data': m2.group(1), 'timestamp': time.time(), 'evidence': {'raw': s}}
                return ev
    except Exception:
        return None
    return None


def normalize_kape_stream(lines: Iterable[str]) -> List[Dict[str, Any]]:
    return list(parse_kape_lines(lines))
