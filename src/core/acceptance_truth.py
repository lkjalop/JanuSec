"""Immutable, explicitly scoped acceptance-truth evaluation.

Ground-truth fixtures grade the assessment input presented to a model.  They do
not grade prose quality, so their metrics are kept separate from citation and
calibration metrics produced by ``model_evaluation``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any


_FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "ground_truth"
_CONFIRMED = {"VALIDATED_BREACH", "CONFIRMED_INTRUSION", "CONFIRMED_BREACH"}
_SCENARIO_FILE_SIGNATURES = {
    "vesper": {
        "janusec_cloud_identity_v3.json", "janusec_endpoint_lolbins_v3.ndjson",
        "janusec_identity_kerberos_v3.ndjson", "janusec_network_v3.csv",
    },
    "meridian": {
        "janusec_cloud_identity_v2.json", "janusec_email_exchange_v2.ndjson",
        "janusec_email_gmail_v2.ndjson", "janusec_endpoint_k8s_v2.ndjson",
        "janusec_network_v2.csv",
    },
}


def load_truth_fixture(scenario: str, *, caller_requested: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load an allow-listed repository fixture and return its immutable receipt."""

    name = str(scenario or "").strip().lower()
    if not name or not name.replace("_", "").replace("-", "").isalnum():
        raise ValueError("invalid_truth_scenario")
    path = (_FIXTURE_ROOT / f"{name}.json").resolve()
    if path.parent != _FIXTURE_ROOT.resolve() or not path.is_file():
        raise ValueError("unknown_truth_scenario")
    raw = path.read_bytes()
    fixture = json.loads(raw.decode("utf-8"))
    return fixture, {
        "schema_version": "janusec.acceptance-truth-receipt/v1",
        "scenario": name,
        "fixture": f"tests/fixtures/ground_truth/{path.name}",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "metric_scope": "assessment_input",
        "caller_requested": caller_requested,
        "attachment_mode": "explicit" if caller_requested else "source_signature",
    }


def infer_truth_scenario(assessment: dict[str, Any]) -> str | None:
    """Recognize a complete acceptance corpus; partial uploads never inherit truth."""

    names: set[str] = set()
    source_counts = assessment.get("source_counts")
    if isinstance(source_counts, dict):
        names.update(str(value).replace("\\", "/").rsplit("/", 1)[-1].lower() for value in source_counts)
    policy = assessment.get("evidence_policy") if isinstance(assessment.get("evidence_policy"), dict) else {}
    names.update(
        str(value).replace("\\", "/").rsplit("/", 1)[-1].lower()
        for value in (policy.get("telemetry_inputs") or [])
    )
    for scenario, signature in _SCENARIO_FILE_SIGNATURES.items():
        if signature <= names:
            return scenario
    return None


def _entities(partition: dict[str, Any], role: str | None = None) -> set[str]:
    values: set[str] = set()
    for item in partition.get("roles") or partition.get("entity_roles") or []:
        if not isinstance(item, dict) or (role and str(item.get("role") or "").lower() != role):
            continue
        value = str(item.get("entity") or item.get("entity_id") or "").lower()
        if value:
            values.add(value)
    return values


def _matches(partition: dict[str, Any], selector: dict[str, Any]) -> bool:
    actor = str(selector.get("actor") or "").lower()
    ip = str(selector.get("ip") or "").lower()
    actors = _entities(partition, "actor")
    all_entities = _entities(partition)
    return (not actor or actor in actors) and (not ip or ip in all_entities)


def evaluate_assessment_truth(
    partitions: list[dict[str, Any]], fixture: dict[str, Any]
) -> dict[str, Any]:
    """Grade case detection/separation/suppression without attributing it to prose."""

    active = [item for item in partitions if item.get("status") != "background"]
    detect_results = []
    for assertion in fixture.get("must_detect") or []:
        hits = [
            item for item in active
            if _matches(item, assertion) and str(item.get("verdict") or "").upper() in _CONFIRMED
        ]
        required_phases = {str(value) for value in assertion.get("phases_present_any") or []}
        passed = any(
            not required_phases or bool(required_phases & {str(value) for value in item.get("phase_ids") or []})
            for item in hits
        )
        detect_results.append({"id": assertion.get("id"), "passed": passed})

    separate_results = []
    for assertion in fixture.get("must_separate") or []:
        selectors = assertion.get("selectors") or []
        merged = any(sum(1 for selector in selectors if _matches(item, selector)) > 1 for item in active)
        individually_present = all(any(_matches(item, selector) for item in active) for selector in selectors)
        separate_results.append({
            "id": assertion.get("id"),
            "passed": individually_present and not merged,
        })

    suppress_results = []
    for assertion in fixture.get("must_suppress") or []:
        entity = str(assertion.get("entity") or "").lower()
        # Suppression assertions describe entities that must not become breach
        # actors/cases. An entity may legitimately occur as a victim or target
        # inside a confirmed case (for example an AS-REP roast target).
        breached = any(
            str(item.get("verdict") or "").upper() not in {
                "", "NO_VALIDATED_BREACH", "BENIGN", "BENIGN_EXPECTED",
                "AUTHORIZED_ACTIVITY", "AUTHORIZED_CHANGE", "FALSE_POSITIVE", "NONE",
            }
            and entity in _entities(item, "actor")
            for item in active
        )
        suppress_results.append({"entity": entity, "passed": not breached})

    role_results = []
    for assertion in fixture.get("role_assertions") or []:
        entity = str(assertion.get("entity") or "").lower()
        role = str(assertion.get("role") or "").lower()
        passed = any(entity in _entities(item, role) for item in active)
        role_results.append({"entity": entity, "role": role, "passed": passed})

    def ratio(results: list[dict[str, Any]]) -> float | None:
        return round(sum(bool(item["passed"]) for item in results) / len(results), 6) if results else None

    return {
        "metric_scope": "assessment_input",
        "must_detect": ratio(detect_results),
        "must_separate": ratio(separate_results),
        "must_suppress": ratio(suppress_results),
        "role_attribution": ratio(role_results),
        "details": {
            "must_detect": detect_results,
            "must_separate": separate_results,
            "must_suppress": suppress_results,
            "role_assertions": role_results,
        },
    }


def resolve_evidence_labels(
    fixture: dict[str, Any], evidence_rows: list[dict[str, Any]], *,
    scenario: str, fixture_sha256: str,
) -> tuple[list[str], dict[str, Any]]:
    """Bind curated stable row anchors to run-specific evidence IDs."""

    labels = [item for item in fixture.get("evidence_labels") or [] if isinstance(item, dict)]
    resolved: list[dict[str, Any]] = []
    unresolved: list[str] = []
    for label in labels:
        anchor = label.get("row_index")
        matches = [
            row for row in evidence_rows if isinstance(row, dict)
            and str((row.get("raw") or {}).get("row_index")) == str(anchor)
            and row.get("id")
        ]
        if len(matches) != 1:
            unresolved.append(str(label.get("id") or anchor))
            continue
        resolved.append({
            "label_id": str(label.get("id") or anchor),
            "evidence_id": str(matches[0]["id"]),
            "expected_role": str(label.get("expected_role") or "support"),
            "row_index": anchor,
        })
    content = {
        "schema_version": "janusec.acceptance-evidence-truth/v1",
        "scenario": scenario,
        "fixture_sha256": fixture_sha256,
        "labels": sorted(resolved, key=lambda item: item["label_id"]),
        "unresolved_label_ids": sorted(unresolved),
    }
    content_hash = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    key = os.getenv("JANUSEC_ACCEPTANCE_TRUTH_HMAC_KEY")
    signature = hmac.new(key.encode(), content_hash.encode(), hashlib.sha256).hexdigest() if key else None
    receipt = {
        **content, "content_hash": content_hash,
        "signature_algorithm": "hmac-sha256" if signature else None,
        "signature": signature,
        "signature_status": "signed" if signature else "unsigned",
    }
    return [item["evidence_id"] for item in resolved], receipt


__all__ = [
    "evaluate_assessment_truth", "infer_truth_scenario", "load_truth_fixture",
    "resolve_evidence_labels",
]
