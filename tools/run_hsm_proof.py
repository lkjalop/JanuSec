from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from src.security.hsm_attestor import HardwareAttestorClient, get_latest_attestor


def _default_artifact_dir() -> Path:
    base = os.getenv("API_STAGE_ARTIFACT_DIR", "logs/perf/api_stage/artifacts")
    return Path(base) / "memory" / "hsm"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _copy_alert_log(destination: Path) -> None:
    source = Path("data/memory_jobs/hsm_alerts.log")
    if source.exists():
        shutil.copyfile(source, destination / "hsm_alerts.log")


def run_proof(tenant: str, simulate_tamper: bool, artifact_dir: Path) -> None:
    attestor = get_latest_attestor() or HardwareAttestorClient()
    result = attestor.run_health_check()
    snapshot = attestor.health_snapshot()

    tenant_dir = artifact_dir / tenant
    tenant_dir.mkdir(parents=True, exist_ok=True)
    _write_json(tenant_dir / "health_snapshot.json", {"result": result, "snapshot": snapshot})
    _copy_alert_log(tenant_dir)

    if simulate_tamper:
        tamper_snapshot = attestor.simulate_tamper("managed_hsm_proof")
        _write_json(tenant_dir / "tamper_snapshot.json", tamper_snapshot)
        _copy_alert_log(tenant_dir)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Managed-HSM proof capture for memory pipeline evidence.")
    parser.add_argument("--tenant", required=True, help="Tenant identifier used for artifact directory naming.")
    parser.add_argument(
        "--artifact-dir",
        default=str(_default_artifact_dir()),
        help="Base directory for storing proof artefacts (default: API_STAGE_ARTIFACT_DIR/memory/hsm).",
    )
    parser.add_argument(
        "--simulate-tamper",
        action="store_true",
        help="Trigger a synthetic tamper alert after the healthy run to capture red-state evidence.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    artifact_dir = Path(args.artifact_dir)
    run_proof(args.tenant, args.simulate_tamper, artifact_dir)
    print(f"HSM proof artifacts written to {artifact_dir / args.tenant}")  # noqa: T201


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
