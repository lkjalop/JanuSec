"""Restore legacy snapshot ownership from the ingest job DB, with backups.

Default is read-only inventory. --apply changes only unambiguous records.
Directory names, filenames and the invoking user's tenant are never evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def migrate(root: Path, database: Path, backup: Path, *, apply: bool = False, case_metadata: bool = False) -> dict:
    import duckdb
    root, database, backup = root.resolve(), database.resolve(), backup.resolve()
    if not root.is_dir() or not database.is_file():
        raise ValueError("existing_snapshot_root_and_job_database_required")
    if backup == root or root in backup.parents:
        raise ValueError("backup_must_be_outside_snapshot_root")
    conn = duckdb.connect(str(database), read_only=True)
    try:
        jobs = dict(conn.execute("SELECT id, org FROM assessment_jobs").fetchall())
    finally:
        conn.close()
    candidates = []
    for path in sorted(root.rglob("*.json")):
        if not path.resolve().is_relative_to(root):
            continue
        try:
            original = path.read_bytes()
            data = json.loads(original)
        except (ValueError, OSError):
            candidates.append({"path": str(path.relative_to(root)), "status": "invalid_json"})
            continue
        if not isinstance(data, dict) or not data.get("assessment_id"):
            continue
        aid = str(data["assessment_id"])
        owners = {str(data[k]).strip() for k in ("org", "tenant_id") if data.get(k)}
        owner = str(jobs.get(aid) or "").strip()
        if owner.lower() in {"", "unknown", "unassigned", "none"}:
            status = "no_authoritative_owner"
        elif owners and owners != {owner}:
            status = "owner_conflict"
        elif owners == {owner}:
            status = "already_owned"
        else:
            status = "eligible"
        if status in {"eligible", "already_owned"} and case_metadata:
            from src.core.ingest.legacy_case_metadata import reconcile_case_metadata
            data, metadata_counts = reconcile_case_metadata(data, owner)
            if status == "already_owned" and metadata_counts["bound"]:
                status = "eligible_metadata"
        else:
            metadata_counts = {}
        candidates.append({"path": str(path.relative_to(root)), "assessment_id": aid,
                           "status": status, "source_hash": hashlib.sha256(original).hexdigest(),
                           "case_metadata": metadata_counts,
                           "_data": data if status.startswith("eligible") else None,
                           "_bytes": original if status.startswith("eligible") else None, "_owner": owner})
    counts = Counter(c["assessment_id"] for c in candidates if c.get("assessment_id"))
    for item in candidates:
        if item["status"].startswith("eligible") and counts[item["assessment_id"]] > 1:
            item["status"] = "duplicate_assessment_requires_review"
        if not item["status"].startswith("eligible") or not apply:
            continue
        path = root / item["path"]
        if path.read_bytes() != item["_bytes"]:
            item["status"] = "changed_during_inventory"
            continue
        # Content-addressed original survives repeated runs; no overwrite.
        backup.mkdir(parents=True, exist_ok=True)
        saved = backup / (item["source_hash"] + ".json")
        if not saved.exists():
            with saved.open("xb") as handle:
                handle.write(item["_bytes"])
        elif saved.read_bytes() != item["_bytes"]:
            raise ValueError("backup_integrity_failure")
        data = item["_data"]
        data["org"] = data["tenant_id"] = item["_owner"]
        data["ownership_migration"] = {
            "schema_version": "janusec.ownership-migration/v1",
            "source": "assessment_jobs", "source_database": str(database),
            "assessment_id": item["assessment_id"], "owner": item["_owner"],
            "original_sha256": item["source_hash"], "backup_path": str(saved),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        from src.api.persist_utils import atomic_write_json
        atomic_write_json(str(path), data)
        item["status"] = "migrated"
    return {"apply": apply, "counts": dict(Counter(c["status"] for c in candidates)),
            "records": [{k: v for k, v in c.items() if not k.startswith("_")} for c in candidates]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--case-metadata", action="store_true")
    args = parser.parse_args()
    result = migrate(args.root, args.database, args.backup, apply=args.apply, case_metadata=args.case_metadata)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result["counts"]))
