#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import requests
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.offline_replay_harness import _load_rows


AWS_CONNECTORS = ("cloudtrail", "guardduty", "securityhub", "vpcflow")
AZURE_CONNECTORS = ("eventhub", "entra_signin", "entra_audit", "defender_cloud")


def _headers(api_key: str, tenant_id: str) -> Dict[str, str]:
    return {
        "x-api-key": api_key,
        "x-tenant-id": tenant_id,
        "Content-Type": "application/json",
    }


def _get_json(url: str, headers: Dict[str, str], timeout: int = 20) -> Dict[str, Any]:
    resp = requests.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _post_json(url: str, headers: Dict[str, str], payload: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _get_recent_decisions(base: str, headers: Dict[str, str], limit: int = 20, timeout: int = 20) -> List[Dict[str, Any]]:
    payload = _get_json(f"{base}/api/v1/decisions/recent?limit={limit}", headers, timeout=timeout)
    return list(payload.get("items") or payload.get("decisions") or [])


def _dashboard_status(base: str, headers: Dict[str, str], timeout: int = 20) -> Dict[str, Any]:
    return _get_json(f"{base}/api/v1/dashboard/status", headers, timeout=timeout)


def _validate_status_shape(status: Dict[str, Any]) -> List[str]:
    failures: List[str] = []
    if not isinstance(status, dict):
        return ["status_not_dict"]
    for field in ("status", "healthy", "runtime_state", "checkpoint"):
        if field not in status:
            failures.append(f"missing:{field}")
    return failures


def _checkpoint_advanced(before: Any, after: Any) -> bool:
    """Return True if the checkpoint cursor moved forward after a poll."""
    if before == after:
        return False
    if before is None:
        # Checkpoint was empty before — any non-None value after counts as advanced
        return after is not None and after != {}
    if isinstance(before, dict) and isinstance(after, dict):
        # Any key that changed (or new key added) counts as advancement
        for k, v in after.items():
            if before.get(k) != v:
                return True
        return False
    return str(before) != str(after)


def _connector_sequence(
    *,
    base: str,
    tenant_id: str,
    provider: str,
    connector: str,
    headers: Dict[str, str],
    since_ts: float | None,
    limit: int,
    timeout: int,
) -> Dict[str, Any]:
    root = f"{base}/api/v1/connectors/{tenant_id}/{provider}/{connector}"
    config = _get_json(f"{root}/config", headers, timeout=timeout)
    before = _get_json(f"{root}/status", headers, timeout=timeout).get("status") or {}
    checkpoint_before = _get_json(f"{root}/checkpoint", headers, timeout=timeout).get("checkpoint") or {}
    payload = {
        "since_ts": since_ts,
        "limit": limit,
        "dry_run": False,
    }
    started = time.time()
    poll = _post_json(f"{root}/poll", headers, payload, timeout=timeout)
    elapsed_ms = int((time.time() - started) * 1000)
    after = _get_json(f"{root}/status", headers, timeout=timeout).get("status") or {}
    checkpoint_after = _get_json(f"{root}/checkpoint", headers, timeout=timeout).get("checkpoint") or {}
    runtime_state = poll.get("runtime_state") or after.get("runtime_state") or {}

    failures: List[str] = []
    failures.extend(_validate_status_shape(after))

    if poll.get("ok") is not True:
        failures.append("poll_not_ok")
    if "ingested" not in poll and "dry_run" not in poll:
        failures.append("missing_ingested")
    if after.get("healthy") is False:
        failures.append("connector_unhealthy")
    if runtime_state.get("circuit_open_until"):
        failures.append("circuit_open")

    # Warn if poll returned events but checkpoint did not advance
    poll_ingested = poll.get("ingested", 0)
    advanced = _checkpoint_advanced(checkpoint_before, checkpoint_after)
    if isinstance(poll_ingested, int) and poll_ingested > 0 and not advanced:
        failures.append("checkpoint_did_not_advance")

    return {
        "provider": provider,
        "connector": connector,
        "config": config.get("config") or {},
        "status_before": before,
        "status_after": after,
        "checkpoint_before": checkpoint_before,
        "checkpoint_after": checkpoint_after,
        "checkpoint_advanced": advanced,
        "poll": poll,
        "elapsed_ms": elapsed_ms,
        "failures": failures,
    }


def _iter_targets(scope: str) -> Iterable[Tuple[str, str]]:
    lowered = scope.lower()
    if lowered in {"aws", "all"}:
        for connector in AWS_CONNECTORS:
            yield "aws", connector
    if lowered in {"azure", "all"}:
        for connector in AZURE_CONNECTORS:
            yield "azure", connector


def _run_export_replay(
    *,
    base: str,
    tenant_id: str,
    headers: Dict[str, str],
    pack_paths: List[str],
    timeout: int,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for raw in pack_paths:
        path = Path(raw)
        rows = _load_rows(path)
        started = time.time()
        assessment = _post_json(
            f"{base}/api/v1/csv/deep_analyze",
            headers,
            {"org": tenant_id, "rows": rows, "options": {"auto_llm": True}},
            timeout=max(timeout, 120),
        )
        persona = _post_json(
            f"{base}/api/v1/reports/persona_view?persona=soc_analyst&disclosure_level=2&top_n=5",
            headers,
            assessment,
            timeout=max(timeout, 120),
        )
        tier2_payload: Dict[str, Any]
        try:
            tier2_payload = _post_json(
                f"{base}/api/v1/csv/tier2_summarize",
                headers,
                {"org": tenant_id, "assessment_id": assessment.get("assessment_id"), "rows": rows[:25]},
                timeout=max(timeout, 120),
            )
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            tier2_payload = {
                "available": False,
                "status_code": status_code,
                "note": "tier2_unavailable_or_disabled",
            }
        recent = _get_recent_decisions(base, headers, timeout=timeout)
        results.append(
            {
                "pack": path.name,
                "path": str(path),
                "row_count": len(rows),
                "elapsed_ms": int((time.time() - started) * 1000),
                "verdict": assessment.get("verdict") or {},
                "risk_quantification": assessment.get("risk_quantification") or {},
                "semantic_top_factors": assessment.get("verdict", {}).get("semantic_top_factors") or [],
                "supporting_model_factors": assessment.get("verdict", {}).get("supporting_model_factors") or [],
                "hopgraph_context": assessment.get("decision_record", {}).get("hopgraph_context") or {},
                "persona_headline": persona.get("headline"),
                "persona_corroboration_targets": persona.get("corroboration_targets") or [],
                "tier2": tier2_payload,
                "tier2_chunks": len(tier2_payload.get("chunks") or []),
                "recent_decisions_count": len(recent),
            }
        )
    return results


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Validate live connector control-plane behavior against configured tenants."
    )
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--api-key", default="devkey123")
    ap.add_argument("--tenant-id", required=True)
    ap.add_argument("--scope", choices=["aws", "azure", "all"], default="all")
    ap.add_argument("--since-seconds", type=int, default=900)
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=60,
                    help="HTTP request timeout in seconds (default: 60)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--azure-export-pack", action="append", default=[], help="Path to exported Azure replay pack directory or file.")
    ap.add_argument("--aws-export-pack", action="append", default=[], help="Path to exported AWS replay pack directory or file.")
    args = ap.parse_args(argv)

    base = args.base.rstrip("/")
    headers = _headers(args.api_key, args.tenant_id)
    since_ts = time.time() - max(0, int(args.since_seconds))

    report: Dict[str, Any] = {
        "tenant_id": args.tenant_id,
        "base": base,
        "scope": args.scope,
        "started_ts": int(time.time()),
        "results": [],
    }
    exit_code = 0
    for provider, connector in _iter_targets(args.scope):
        try:
            result = _connector_sequence(
                base=base,
                tenant_id=args.tenant_id,
                provider=provider,
                connector=connector,
                headers=headers,
                since_ts=since_ts,
                limit=args.limit,
                timeout=args.timeout,
            )
        except Exception as exc:
            exit_code = 1
            result = {
                "provider": provider,
                "connector": connector,
                "failures": [f"exception:{exc}"],
                "checkpoint_advanced": False,
            }
        if result.get("failures"):
            exit_code = 1
        report["results"].append(result)

    export_packs = {
        "azure": list(args.azure_export_pack or []),
        "aws": list(args.aws_export_pack or []),
    }
    export_results = {}
    for provider, packs in export_packs.items():
        if not packs:
            continue
        try:
            export_results[provider] = _run_export_replay(
                base=base,
                tenant_id=args.tenant_id,
                headers=headers,
                pack_paths=packs,
                timeout=args.timeout,
            )
        except Exception as exc:
            exit_code = 1
            export_results[provider] = [{"failures": [f"replay_exception:{exc}"]}]
    if export_results:
        report["export_replay"] = export_results
        try:
            report["dashboard_status"] = _dashboard_status(base, headers, timeout=args.timeout)
        except Exception as exc:
            report["dashboard_status_error"] = str(exc)
        try:
            report["recent_decisions"] = _get_recent_decisions(base, headers, timeout=args.timeout)
        except Exception as exc:
            report["recent_decisions_error"] = str(exc)

    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)

    # Human-readable summary
    print("\n--- Connector Validation Summary ---", file=sys.stderr)
    total = len(report["results"])
    passed = 0
    for r in report["results"]:
        label = f"{r.get('provider','?')}/{r.get('connector','?')}"
        failures = r.get("failures") or []
        advanced = r.get("checkpoint_advanced", False)
        if failures:
            print(f"  FAIL  {label}  failures={failures}", file=sys.stderr)
        else:
            passed += 1
            ck_note = " checkpoint_advanced=True" if advanced else " (no events ingested)"
            print(f"  PASS  {label}{ck_note}", file=sys.stderr)
    overall = "PASS" if exit_code == 0 else "FAIL"
    for provider, entries in (report.get("export_replay") or {}).items():
        for entry in entries:
            if entry.get("failures"):
                print(f"  FAIL  replay/{provider}  failures={entry.get('failures')}", file=sys.stderr)
                continue
            verdict = (entry.get("verdict") or {}).get("final_verdict")
            confidence = (entry.get("verdict") or {}).get("final_confidence")
            pack = entry.get("pack") or "pack"
            print(f"  REPLAY {provider}/{pack} verdict={verdict} confidence={confidence}", file=sys.stderr)
    print(f"\n[{overall}] {passed}/{total} connectors passed", file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
