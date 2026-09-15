from __future__ import annotations
from typing import List, Dict, Any
from src.core.heartbeat import detect_missing_sources, get_actual_volume_last_hour
from src.core.collector_telemetry import read_last_collector_status
from src.core.evidence_model import EvidenceItem, BayesianFusion


def analyze_root_causes(tenant_id: str, expected_sources: List[str]) -> List[Dict[str, Any]]:
    """Build hypotheses for missing sources and score them using simple evidence fusion."""
    anomalies = detect_missing_sources(tenant_id, expected_sources)
    results = []
    bf = BayesianFusion()

    for source, anomaly in anomalies.items():
        # Build evidence items
        evidence = []
        if anomaly["status"] == "no_logs":
            evidence.append(EvidenceItem(kind="heartbeat_zero", score=2.0, meta={"expected": anomaly["expected"]}))
        elif anomaly["status"] == "volume_drop":
            evidence.append(EvidenceItem(kind="volume_drop", score=1.0, meta={"expected": anomaly["expected"], "actual": anomaly["actual"]}))

        # collector telemetry (best-effort)
        # assume collector id matches source name for simple setups
        col = read_last_collector_status(source)
        if col:
            payload = col.get("payload", {})
            status = payload.get("status")
            if status == "crashed":
                evidence.append(EvidenceItem(kind="collector_crash", score=3.0, meta=payload))
            elif status == "auth_failed":
                evidence.append(EvidenceItem(kind="auth_failed", score=2.5, meta=payload))
            elif status == "rate_limited":
                evidence.append(EvidenceItem(kind="rate_limited", score=1.5, meta=payload))

        # Score hypotheses: collector_failure, authentication_issue, rate_limiting, source_disabled, network_issue
        hypotheses = ["collector_failure", "authentication_issue", "rate_limiting", "source_disabled"]

        scored = []
        for h in hypotheses:
            hs = bf.score(h, evidence)
            scored.append(hs)

        # pick top hypothesis
        scored_sorted = sorted(scored, key=lambda s: s.probability, reverse=True)
        top = scored_sorted[0]

        results.append({
            "source": source,
            "anomaly": anomaly,
            "top_hypothesis": top.hypothesis,
            "confidence": top.probability,
            "evidence": [e.to_dict() for e in top.evidence],
        })

    return results
