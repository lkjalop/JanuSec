"""
XDR Excel Classifier
Reads the two Eclipse.XDR spreadsheets in dump/ using their native columns,
classifies each row as good/bad, scrubs PII on output, and writes one CSV
report per input file under reports/.

Inputs (defaults):
  - dump/cybstash csv1.xlsx
  - dump/Cyberstash_csv2.xlsx

Output:
  - reports/cybstash_csv1_report.csv
  - reports/cyberstash_csv2_report.csv

Classification rules:
  - For Cyberstash_csv2.xlsx: use columns present in the sheet.
    Mark row bad if any of these are true (case-insensitive where strings):
      * malicious == True
      * suspicious == True
      * threatScore > 0
      * avPositives > 0
      * threatName contains "malicious" or "suspicious"
    Otherwise good.
  - For cybstash csv1.xlsx: only path column is expected. Heuristics:
      * Good if path is under Windows system paths or Program Files, or if
        it contains known OS update artifacts (e.g., SoftwareDistribution\\Download, mpam).
      * Bad if path resides in Temp/AppData temp-like locations and not whitelisted.
      * Otherwise good.

PII scrubbing (Option B):
  - Applies core.redaction.scrub_record (emails, phone, SSN, IPs) and
    a local Windows path redaction pattern on string fields.

Run:
  python -m scripts.xdr_excel_classify
"""
from __future__ import annotations

import os
import re
from pathlib import Path
import hashlib
from typing import Any, Dict, List

import pandas as pd

# Reuse platform redaction utilities for PII scrubbing
try:
    from src.core.redaction import scrub_record as _scrub_record
except Exception:  # pragma: no cover - fallback if relative import differs
    from core.redaction import scrub_record as _scrub_record  # type: ignore


_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\r\n\t<>:\\|?*]+")


def _scrub_windows_paths(data: Dict[str, Any]) -> Dict[str, Any]:
    """Additional PII scrub for Windows file paths inside string fields."""
    out: Dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            out[k] = _WIN_PATH_RE.sub('[path]', v)
        else:
            out[k] = v
    return out


def _classify_cyberstash2_row(row: pd.Series) -> tuple[str, str]:
    """Return (verdict, reason) using native columns when present."""
    malicious = bool(row.get('malicious')) if 'malicious' in row else False
    suspicious = bool(row.get('suspicious')) if 'suspicious' in row else False
    threat_score = float(row.get('threatScore') or 0.0) if 'threatScore' in row else 0.0
    av_pos = float(row.get('avPositives') or 0.0) if 'avPositives' in row else 0.0
    tname = str(row.get('threatName') or '')
    tname_lc = tname.lower()

    if malicious:
        return 'bad', 'malicious=true'
    if suspicious:
        return 'bad', 'suspicious=true'
    if threat_score and threat_score > 0:
        return 'bad', f'threatScore={threat_score}'
    if av_pos and av_pos > 0:
        return 'bad', f'avPositives={av_pos}'
    if 'malicious' in tname_lc or 'suspicious' in tname_lc:
        return 'bad', f'threatName={tname}'
    return 'good', 'clean_indicators'


_GOOD_PATH_HINTS = (
    '\\windows\\system32',
    '\\program files\\',
    '\\program files (x86)\\',
    '\\softwaredistribution\\download\\',
)
_GOOD_KEYWORDS = (
    'mpam',  # Microsoft Defender pattern
    'am_delta_patch',  # Defender delta updates
)
_TEMP_HINTS_BAD = (
    '\\appdata\\',
    '\\temp\\',
    '\\tmp\\',
)


def _classify_cyberstash1_path(path_str: str) -> tuple[str, str]:
    p = path_str.lower()
    if any(h in p for h in _GOOD_PATH_HINTS) or any(k in p for k in _GOOD_KEYWORDS):
        return 'good', 'system_or_update_artifact'
    if any(t in p for t in _TEMP_HINTS_BAD):
        # Allowlist common update artifacts even in temp
        if any(k in p for k in _GOOD_KEYWORDS):
            return 'good', 'update_artifact_temp'
        return 'bad', 'temp_location_executable'
    # Default benign unless clear bad hints exist
    return 'good', 'default_allow'


def _ensure_reports_dir() -> Path:
    out_dir = Path('reports')
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def process_cyberstash2(path: Path, out_dir: Path) -> Path:
    df = pd.read_excel(path)
    columns: List[str] = list(df.columns)
    verdicts: List[str] = []
    reasons: List[str] = []
    rows_out: List[Dict[str, Any]] = []

    for _, row in df.iterrows():
        verdict, reason = _classify_cyberstash2_row(row)
        verdicts.append(verdict)
        reasons.append(reason)
        row_dict = {col: row.get(col) for col in columns}
        # Stable record_id for audit/writeback
        prefer = None
        for key in ('sha256','md5','id'):
            v = row.get(key)
            if isinstance(v, str) and v.strip():
                prefer = v.strip()
                break
        if not prefer:
            sig_parts = [str(row.get(k) or '') for k in ('name','path','sha1','sha256','md5')]
            sig = '|'.join(p.strip().lower() for p in sig_parts)
            prefer = hashlib.sha256(sig.encode('utf-8')).hexdigest()
        row_dict['record_id'] = prefer
        row_dict['verdict'] = verdict
        row_dict['reason'] = reason
        # PII scrub on output record
        row_dict = _scrub_record(row_dict)
        row_dict = _scrub_windows_paths(row_dict)
        rows_out.append(row_dict)

    out_df = pd.DataFrame(rows_out, columns=columns + ['record_id', 'verdict', 'reason'])
    out_path = out_dir / 'cyberstash_csv2_report.csv'
    out_df.to_csv(out_path, index=False)
    return out_path


def process_cyberstash1(path: Path, out_dir: Path) -> Path:
    df = pd.read_excel(path)
    # Expect at least a 'path' column; if the sheet is one-column unnamed, coerce name
    if len(df.columns) == 1 and df.columns[0] != 'path':
        df = df.rename(columns={df.columns[0]: 'path'})
    if 'path' not in df.columns:
        raise ValueError('cybstash csv1.xlsx must contain a path column')

    columns: List[str] = list(df.columns)
    rows_out: List[Dict[str, Any]] = []
    for _, row in df.iterrows():
        p = str(row.get('path') or '')
        verdict, reason = _classify_cyberstash1_path(p)
        row_dict = {col: row.get(col) for col in columns}
        # Stable record_id from path
        sig = p.strip().lower()
        row_dict['record_id'] = hashlib.sha256(sig.encode('utf-8')).hexdigest() if sig else ''
        row_dict['verdict'] = verdict
        row_dict['reason'] = reason
        # PII scrub on output record
        row_dict = _scrub_record(row_dict)
        row_dict = _scrub_windows_paths(row_dict)
        rows_out.append(row_dict)

    out_df = pd.DataFrame(rows_out, columns=columns + ['record_id', 'verdict', 'reason'])
    out_path = out_dir / 'cybstash_csv1_report.csv'
    out_df.to_csv(out_path, index=False)
    return out_path


def main() -> None:
    base = Path('dump')
    f1 = base / 'cybstash csv1.xlsx'
    f2 = base / 'Cyberstash_csv2.xlsx'
    out_dir = _ensure_reports_dir()

    results: List[str] = []
    if f2.exists():
        p = process_cyberstash2(f2, out_dir)
        results.append(str(p))
    else:
        print(f"[warn] Missing file: {f2}")
    if f1.exists():
        p = process_cyberstash1(f1, out_dir)
        results.append(str(p))
    else:
        print(f"[warn] Missing file: {f1}")

    if results:
        print('Reports written:')
        for r in results:
            print(f"  - {r}")
    else:
        print('No reports written. Ensure input files exist under dump/.')


if __name__ == '__main__':
    main()
