from __future__ import annotations

import argparse
import json
import time
import os
from pathlib import Path
from typing import Any, Dict, List

from src.artifact.memory_acquisition import MemoryAcquisitionGuide


def _default_artifact_dir() -> Path:
    return Path(os.getenv("API_STAGE_ARTIFACT_DIR", "logs/perf/api_stage/artifacts"))


def _load_tenants(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        tenants = data.get("tenants") or data.get("entries")
        if isinstance(tenants, list):
            return [t for t in tenants if isinstance(t, dict)]
    if isinstance(data, list):
        return [t for t in data if isinstance(t, dict)]
    raise ValueError(f"Unrecognized tenant config schema in {path}")


def _artifact_path(base: Path, attestation_id: str) -> Path:
    return base / "courier" / f"{attestation_id}.json"


def run_soak(tenant_file: Path, artifact_dir: Path) -> None:
    guide = MemoryAcquisitionGuide()
    manifest: List[Dict[str, Any]] = []
    tenants = _load_tenants(tenant_file)
    now = time.time()

    for entry in tenants:
        tenant_id = entry.get("tenant_id") or entry.get("id") or entry.get("name") or "tenant"
        os_family = entry.get("os_family") or "windows"
        host = entry.get("host") or f"{tenant_id}-mem"
        plan = guide.issue_plan(
            host=host,
            os_family=os_family,
            case_id=entry.get("case_id") or f"{tenant_id}-case",
            tenant_id=tenant_id,
            courier_profile=entry.get("courier_profile"),
        )
        guide.record_event(plan.attestation_id, event="uploaded", metadata={"tenant": tenant_id})
        guide.record_event(plan.attestation_id, event="analysis_complete", metadata={"tenant": tenant_id})

        art_path = _artifact_path(artifact_dir, plan.attestation_id)
        manifest.append(
            {
                "tenant_id": tenant_id,
                "attestation_id": plan.attestation_id,
                "status": plan.status,
                "expires_at": plan.expires_at,
                "sla_breach": plan.sla_breach,
                "revoked": plan.revoked,
                "artifact_path": str(art_path),
                "ttl_seconds": int(plan.expires_at - now),
            }
        )

    manifest_path = artifact_dir / "courier_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({"entries": manifest}, indent=2), encoding="utf-8")
    print(f"Courier soak manifest written to {manifest_path}")  # noqa: T201


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate courier SLA artefacts for all tenants.")
    parser.add_argument("--tenants", required=True, help="Path to api_stage_tenants JSON file.")
    parser.add_argument(
        "--artifact-dir",
        default=str(_default_artifact_dir()),
        help="Base directory for perf artefacts (default: API_STAGE_ARTIFACT_DIR).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    tenant_file = Path(args.tenants)
    artifact_dir = Path(args.artifact_dir)
    run_soak(tenant_file, artifact_dir)


if __name__ == "__main__":
    main()
