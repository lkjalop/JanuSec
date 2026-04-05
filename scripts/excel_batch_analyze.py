#!/usr/bin/env python
"""Excel/XLSX Artifact Batch Uploader

Reads one or more Excel (XLSX) or CSV files, normalizes columns, and submits
artifacts to the sidecar batch analyze API. Designed for quick Eclipse XDR → Sidecar bridging.

Usage:
  python scripts/excel_batch_analyze.py --input dump/cybstash\ csv1.xlsx dump/Cyberstash_csv2.xlsx \
      --api http://localhost:8000/api --token $TOKEN \
      --include-business-summary

Dependencies: pandas, requests, openpyxl (for .xlsx)
Install: pip install pandas openpyxl requests
"""
from __future__ import annotations
import argparse
import time
import hashlib
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

try:
    import pandas as pd  # type: ignore
except ImportError as e:
    print("pandas is required. Install with: pip install pandas openpyxl", file=sys.stderr)
    raise

import requests

REQUIRED_MIN = ["artifact_name"]
ALT_KEYS = ["path", "hash_sha256"]

COLUMN_ALIASES = {
    # Extended source -> normalized mapping
    "file_name": "artifact_name",
    "filename": "artifact_name",
    "name": "artifact_name",
    "image": "artifact_name",
    "process_name": "artifact_name",
    "process": "artifact_name",
    "exe": "artifact_name",
    "binary": "artifact_name",
    "file_path": "path",
    "full_path": "path",
    "filepath": "path",
    "path_name": "path",
    "path": "path",
    "commandline": "command_line",
    "command_line": "command_line",
    "sha256": "hash_sha256",
    "sha_256": "hash_sha256",
    "sha256_hash": "hash_sha256",
    "hash": "hash_sha256",
    "hash_value": "hash_sha256",
    "host_identifier": "host_id",
    "hostname": "host_id",
    "host": "host_id",
    "signed_status": "signed",
    "signature_status": "signed",
    "timestamp_first_seen": "first_seen",
    "first_seen_timestamp": "first_seen",
    "first_seen": "first_seen",
}

SUPPORTED_ARTIFACT_TYPES = {"EXECUTABLE","SCRIPT","MACRO","DOWNLOAD","LIBRARY","SERVICE"}
SCRIPT_EXT = {"ps1","vbs","js","sh","py","rb"}
MACRO_EXT = {"docm","dotm","xlsm","pptm"}


def infer_artifact_type(row: Dict[str, Any]) -> str:
    atype = row.get("artifact_type")
    if atype and atype.upper() in SUPPORTED_ARTIFACT_TYPES:
        return atype.upper()
    path = (row.get("path") or "").lower()
    name = (row.get("artifact_name") or "").lower()
    target = path or name
    if any(target.endswith(f".{ext}") for ext in SCRIPT_EXT):
        return "SCRIPT"
    if any(target.endswith(f".{ext}") for ext in MACRO_EXT):
        return "MACRO"
    if "/downloads/" in target or "\\downloads\\" in target:
        return "DOWNLOAD"
    if target.endswith(".dll") or target.endswith(".so"):
        return "LIBRARY"
    return "EXECUTABLE"


def normalize_df(df: pd.DataFrame, debug: bool = False) -> List[Dict[str, Any]]:
    # Standardize column names (strip spaces, lowercase) before alias mapping
    orig_cols = list(df.columns)
    df.columns = [str(c).strip() for c in df.columns]
    # Apply alias remapping (case-insensitive)
    rename_map = {}
    for c in df.columns:
        key = c.lower()
        if key in COLUMN_ALIASES:
            rename_map[c] = COLUMN_ALIASES[key]
    if rename_map:
        df = df.rename(columns=rename_map)
    records: List[Dict[str, Any]] = []
    dropped_no_name = 0
    dropped_no_alt = 0
    sample_no_name = []
    sample_no_alt = []
    for _, row in df.iterrows():
        rec = {k: (None if pd.isna(v) else v) for k, v in row.items()}
        # Derive artifact_name if missing using path basename or hash prefix
        if not rec.get("artifact_name"):
            p = rec.get("path")
            if isinstance(p, str) and p.strip():
                rec["artifact_name"] = p.replace("\\", "/").split("/")[-1]
        if not rec.get("artifact_name") and rec.get("hash_sha256"):
            rec["artifact_name"] = str(rec["hash_sha256"])[:12]
        if not rec.get("artifact_name"):
            dropped_no_name += 1
            if len(sample_no_name) < 5:
                sample_no_name.append({k: rec.get(k) for k in ('path','hash_sha256','artifact_type')})
            continue
        # Generate hash if missing and path provided
        if not rec.get("hash_sha256") and rec.get("path"):
            rec["hash_sha256"] = hashlib.sha256(str(rec["path"]).encode("utf-8")).hexdigest()
        # Need at least one of ALT_KEYS
        if not any(rec.get(k) for k in ALT_KEYS):
            dropped_no_alt += 1
            if len(sample_no_alt) < 5:
                sample_no_alt.append({k: rec.get(k) for k in ('artifact_name','path','hash_sha256')})
            continue
        rec["artifact_type"] = infer_artifact_type(rec)
        if "signed" in rec and isinstance(rec["signed"], str):
            sval = rec["signed"].strip().lower()
            rec["signed"] = sval in {"true","1","yes","y","signed","valid"}
        records.append(rec)
    if debug:
        print(f"[debug] input_columns={orig_cols}")
        print(f"[debug] rows_in={len(df)} accepted={len(records)} dropped_no_name={dropped_no_name} dropped_no_alt={dropped_no_alt}")
        if sample_no_name:
            print(f"[debug] sample_no_name={sample_no_name}")
        if sample_no_alt:
            print(f"[debug] sample_no_alt={sample_no_alt}")
    return records


def load_file(path: Path, sheet: str | None = None, debug: bool = False) -> List[Dict[str, Any]]:
    ext = path.suffix.lower()
    if ext in {".xlsx", ".xls"}:
        if sheet:
            df = pd.read_excel(path, sheet_name=sheet)
        else:
            df = pd.read_excel(path)
    elif ext == ".csv":
        df = pd.read_csv(path)
    else:
        raise ValueError(f"Unsupported file extension: {ext}")
    return normalize_df(df, debug=debug)


def chunk(items: List[Any], size: int):
    for i in range(0, len(items), size):
        yield items[i:i+size]


def submit_batch(api_base: str, token: str, artifacts: List[Dict[str, Any]], include_business: bool, batch_id: str | None = None) -> str:
    # Endpoint expects { items: [...] } for /api/v1/artifacts/analyze_batch
    url = f"{api_base.rstrip('/')}/artifacts/analyze_batch"
    payload: Dict[str, Any] = {"items": artifacts}
    if batch_id:
        payload["batch_id"] = batch_id
    resp = requests.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(payload))
    if resp.status_code >= 300:
        raise RuntimeError(f"Batch submit failed {resp.status_code}: {resp.text}")
    try:
        data = resp.json()
    except Exception:
        return "UNKNOWN"
    # Response returns batch_meta in current implementation
    meta = data.get('batch_meta') or {}
    return meta.get('batch_id') or meta.get('id') or 'UNKNOWN'


def main():
    ap = argparse.ArgumentParser(description="Upload Excel/CSV artifacts to sidecar batch_analyze endpoint")
    ap.add_argument("--input", nargs="+", required=True, help="Input XLSX/CSV file(s)")
    ap.add_argument("--api", required=True, help="Base API URL (e.g. http://localhost:8000/api")
    ap.add_argument("--token", required=True, help="Bearer token for auth")
    ap.add_argument("--include-business-summary", action="store_true", help="Request business impact summary")
    ap.add_argument("--max-chunk", type=int, default=5000, help="Chunk size for submit")
    ap.add_argument("--sheet", help="Specific Excel sheet name to parse (optional)")
    ap.add_argument("--list-sheets", action="store_true", help="List sheet names for each Excel then exit")
    ap.add_argument("--debug-drop", action="store_true", help="Print diagnostics on dropped rows")
    args = ap.parse_args()

    if args.list_sheets:
        for p in args.input:
            path = Path(p)
            if not path.exists():
                print(f"[sheets] MISSING {path}")
                continue
            if path.suffix.lower() not in {'.xlsx','.xls'}:
                print(f"[sheets] {path} (not Excel)")
                continue
            try:
                import pandas as pd  # type: ignore
                from pandas import ExcelFile
                xf = ExcelFile(path)
                print(f"[sheets] {path}: {xf.sheet_names}")
            except Exception as e:
                print(f"[sheets] ERROR {path}: {e}")
        return

    all_records: List[Dict[str, Any]] = []
    for p in args.input:
        path = Path(p)
        if not path.exists():
            print(f"WARN: File not found: {path}", file=sys.stderr)
            continue
        try:
            recs = load_file(path, sheet=args.sheet, debug=args.debug_drop)
            print(f"Loaded {len(recs)} artifacts from {path}")
            all_records.extend(recs)
        except Exception as e:
            print(f"ERROR reading {path}: {e}", file=sys.stderr)

    if not all_records:
        print("No artifacts collected; exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"Total artifacts prepared: {len(all_records)}")
    batch_ids = []
    base_batch_id = f"INGEST-{int(time.time())}"  # simplistic batch id root
    for idx, ch in enumerate(chunk(all_records, args.max_chunk), start=1):
        part_id = f"{base_batch_id}-p{idx}" if len(all_records) > args.max_chunk else base_batch_id
        print(f"Submitting chunk {idx} with {len(ch)} artifacts (batch_id={part_id})...")
        batch_id = submit_batch(args.api, args.token, ch, args.include_business_summary, batch_id=part_id)
        print(f"Chunk {idx} accepted batch_id={batch_id}")
        batch_ids.append(batch_id)

    print("Submission complete. Batch IDs:")
    for b in batch_ids:
        print(f"  - {b}")

if __name__ == "__main__":
    main()
