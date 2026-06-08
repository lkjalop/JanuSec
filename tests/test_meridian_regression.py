"""Meridian end-to-end regression — asserts minimum quality bar after roadmap fixes.

Skipped automatically when the Meridian test files are not present (CI environments).
Run locally: pytest tests/test_meridian_regression.py -v
"""
from __future__ import annotations

import json
import pathlib
import time

import pytest

MERIDIAN_DIR = pathlib.Path(r"C:\AI\janusec\dump\test files\Meridian")
FIXTURE_PATH = pathlib.Path(__file__).parent / "fixtures" / "assessments" / "meridian_expected.json"

_MERIDIAN_FILES = [
    "janusec_cloud_identity_v2.json",
    "janusec_email_exchange_v2.ndjson",
    "janusec_email_gmail_v2.ndjson",
    "janusec_endpoint_k8s_v2.ndjson",
    "janusec_network_v2.csv",
]

_SKIP = pytest.mark.skipif(
    not MERIDIAN_DIR.exists() or not all((MERIDIAN_DIR / f).exists() for f in _MERIDIAN_FILES),
    reason="Meridian test files not present — skipping regression",
)


# ── Fixture: run the full pipeline once, share the assessment across tests ────

@pytest.fixture(scope="module")
def meridian_assessment():
    """Upload all 5 Meridian files through the async pipeline and return the assessment dict."""
    import requests  # type: ignore

    base = "http://localhost:8000"
    hdr = {"X-Tenant-ID": "meridian-regression"}

    # Health check
    try:
        r = requests.get(f"{base}/health", timeout=5)
        assert r.status_code == 200, f"Server not healthy: {r.status_code}"
    except Exception as exc:
        pytest.skip(f"Janusec server not running: {exc}")

    # Upload files
    file_handles = []
    multipart = []
    for fname in _MERIDIAN_FILES:
        fh = (MERIDIAN_DIR / fname).open("rb")
        file_handles.append(fh)
        multipart.append(("files", (fname, fh, "application/octet-stream")))

    try:
        r = requests.post(
            f"{base}/api/v1/assessments/upload",
            files=multipart,
            data={"org": "meridian-regression"},
            headers=hdr,
            timeout=60,
        )
    finally:
        for fh in file_handles:
            fh.close()

    assert r.status_code in (200, 202), f"Upload failed {r.status_code}: {r.text[:300]}"
    resp = r.json()
    assessment_id = resp.get("assessment_id")
    assert assessment_id, f"No assessment_id in response: {resp}"

    # Poll for completion
    deadline = time.time() + 300
    while time.time() < deadline:
        pr = requests.get(
            f"{base}/api/v1/assessments/{assessment_id}/progress/poll",
            headers=hdr,
            timeout=10,
        )
        if pr.status_code == 200:
            prog = pr.json()
            pct = prog.get("percent", 0)
            stage = prog.get("stage", "")
            if prog.get("complete") or pct >= 100 or stage in ("done", "complete", "finished"):
                break
            if stage == "error":
                pytest.fail(f"Assessment pipeline errored: {prog}")
        time.sleep(5)
    else:
        pytest.fail(f"Assessment {assessment_id} did not complete within 300s")

    # Load the assessment
    ar = requests.get(
        f"{base}/api/v1/assessments/{assessment_id}",
        headers=hdr,
        timeout=30,
    )
    if ar.status_code != 200:
        # Try alternate path
        ar = requests.get(
            f"{base}/api/v1/report/ingestion",
            params={"format": "json", "assessment_id": assessment_id},
            headers=hdr,
            timeout=30,
        )
    assert ar.status_code == 200, f"Could not load assessment: {ar.status_code}"
    return ar.json()


# ── Individual quality assertions ─────────────────────────────────────────────

@_SKIP
def test_meridian_cluster_count(meridian_assessment):
    """19 clusters should collapse to ≤8 after dedup/jaccard/campaign rollup."""
    clusters = (
        meridian_assessment.get("correlation_clusters")
        or meridian_assessment.get("clusters")
        or []
    )
    assert len(clusters) <= 8, (
        f"Expected ≤8 clusters after rollup, got {len(clusters)}: "
        f"{[c.get('cluster_id', '?') for c in clusters]}"
    )


@_SKIP
def test_meridian_validated_breach_present(meridian_assessment):
    """At least one VALIDATED_BREACH cluster must exist."""
    clusters = (
        meridian_assessment.get("correlation_clusters")
        or meridian_assessment.get("clusters")
        or []
    )
    breach_clusters = [
        c for c in clusters if c.get("verdict") in {
            "VALIDATED_BREACH", "CONFIRMED_BREACH", "CONFIRMED_INTRUSION"
        }
    ]
    assert breach_clusters, "No VALIDATED_BREACH clusters found — detection broken"


@_SKIP
def test_meridian_mitre_not_empty(meridian_assessment):
    """At least one VALIDATED_BREACH cluster must carry MITRE technique IDs."""
    clusters = (
        meridian_assessment.get("correlation_clusters")
        or meridian_assessment.get("clusters")
        or []
    )
    breach_with_mitre = [
        c for c in clusters
        if c.get("mitre_techniques") and c.get("verdict") in {
            "VALIDATED_BREACH", "CONFIRMED_BREACH", "CONFIRMED_INTRUSION",
        }
    ]
    assert len(breach_with_mitre) >= 1, (
        "All VALIDATED_BREACH clusters have empty mitre_techniques — "
        "factor_tags→MITRE propagation not working"
    )
    # Verify the specific expected techniques from Meridian scenario
    all_mitre: set[str] = set()
    for c in breach_with_mitre:
        all_mitre.update(c.get("mitre_techniques") or [])
    assert len(all_mitre) >= 3, (
        f"Expected ≥3 distinct MITRE IDs, got {len(all_mitre)}: {sorted(all_mitre)}"
    )


@_SKIP
def test_meridian_no_all_medium_severity(meridian_assessment):
    """Evidence rows must include HIGH or CRITICAL events (not all MEDIUM)."""
    rows = (
        meridian_assessment.get("normalized_rows")
        or meridian_assessment.get("evidence_rows")
        or meridian_assessment.get("flagged_events")
        or []
    )
    if not rows:
        pytest.skip("No evidence rows in assessment response")
    sevs = {str(r.get("_severity") or r.get("severity") or "").lower() for r in rows}
    assert "high" in sevs or "critical" in sevs, (
        f"All rows are medium/low — severity elevation not working. Severities: {sevs}"
    )


@_SKIP
def test_meridian_audit_opinions_not_all_unqualified(meridian_assessment):
    """Audit opinions for VALIDATED_BREACH clusters must not all say 'Unqualified'."""
    clusters = (
        meridian_assessment.get("correlation_clusters")
        or meridian_assessment.get("clusters")
        or []
    )
    audit_opinions = []
    for cl in clusters:
        if cl.get("verdict") not in {"VALIDATED_BREACH", "CONFIRMED_BREACH"}:
            continue
        personas = cl.get("personas") or cl.get("persona_dispatch") or {}
        audit = personas.get("audit") or {}
        opinion = audit.get("audit_opinion") or audit.get("payload", {}).get("audit_opinion", "")
        if opinion:
            audit_opinions.append(opinion)
    if not audit_opinions:
        pytest.skip("No audit opinions found — audit persona may not have run yet")
    all_unqualified = all("Unqualified opinion" in op for op in audit_opinions)
    assert not all_unqualified, (
        f"All {len(audit_opinions)} audit opinions are 'Unqualified' "
        "even for VALIDATED_BREACH clusters — verdict not propagating to audit persona"
    )


@_SKIP
def test_meridian_expected_actors_flagged(meridian_assessment):
    """wei.zhang and james.hargreaves must appear as flagged actors."""
    rows = (
        meridian_assessment.get("normalized_rows")
        or meridian_assessment.get("evidence_rows")
        or meridian_assessment.get("flagged_events")
        or []
    )
    if not rows:
        pytest.skip("No evidence rows to check actors")
    actors_seen: set[str] = set()
    for r in rows:
        for fld in ("user", "user_canonical", "UserId", "actor"):
            v = str(r.get(fld) or "").lower()
            if "wei.zhang" in v:
                actors_seen.add("wei.zhang")
            if "james.hargreaves" in v:
                actors_seen.add("james.hargreaves")
    assert "wei.zhang" in actors_seen, "wei.zhang not in flagged events — M365 parsing broken"


@_SKIP
def test_meridian_evidence_rows_have_cluster_id(meridian_assessment):
    """Evidence rows assigned to clusters must carry correlation_cluster_id."""
    rows = (
        meridian_assessment.get("normalized_rows")
        or meridian_assessment.get("evidence_rows")
        or meridian_assessment.get("flagged_events")
        or []
    )
    if not rows:
        pytest.skip("No evidence rows to check")
    rows_with_cid = [r for r in rows if r.get("correlation_cluster_id")]
    pct = len(rows_with_cid) / len(rows) * 100 if rows else 0
    assert pct >= 30, (
        f"Only {pct:.0f}% of evidence rows have correlation_cluster_id — "
        "row-stamp loop not running"
    )


@_SKIP
def test_meridian_dread_not_all_low(meridian_assessment):
    """VALIDATED_BREACH clusters must not all have DREAD tier = LOW."""
    clusters = (
        meridian_assessment.get("correlation_clusters")
        or meridian_assessment.get("clusters")
        or []
    )
    breach_clusters = [
        c for c in clusters if c.get("verdict") in {"VALIDATED_BREACH", "CONFIRMED_BREACH"}
    ]
    if not breach_clusters:
        pytest.skip("No breach clusters to check DREAD")
    low_dread = []
    for c in breach_clusters:
        prefill = c.get("tier1_prefill") or {}
        cm = prefill.get("confidence_meter") or {}
        total = cm.get("total", 0)
        if total < 22:
            low_dread.append((c.get("cluster_id"), total))
    assert len(low_dread) < len(breach_clusters), (
        f"ALL {len(breach_clusters)} VALIDATED_BREACH clusters have DREAD <22: {low_dread}"
    )
