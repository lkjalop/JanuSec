"""Offline evaluation of reviewed, tenant-specific agent behavior baselines.

Evaluation never trains on incoming traffic. Descriptor drift is a signal for
review; it does not establish that a tool or agent has been compromised.
"""
from copy import deepcopy
import math
from statistics import mean, pvariance
from src.core.evidence_contract.records import canonical_hash

METRICS = ("tool_calls", "unique_tools", "write_calls", "external_destinations")


def _metrics(event):
    result = {}
    for key in METRICS:
        value = event.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("complete_nonnegative_agent_metrics_required")
        result[key] = float(value)
    return result


def build_reviewed_baseline(*, tenant_id, agent_id, samples, descriptors, review_receipt):
    if not tenant_id or not agent_id or not review_receipt:
        raise ValueError("reviewed_agent_baseline_scope_required")
    if len(samples) < 20:
        raise ValueError("agent_baseline_cold_start")
    if any(s.get("tenant_id") != tenant_id or s.get("agent_id") != agent_id for s in samples):
        raise ValueError("agent_baseline_tenant_or_agent_mismatch")
    values = [_metrics(s) for s in samples]
    baseline = {"schema_version": "janusec.agent-baseline/v1", "tenant_id": tenant_id, "agent_id": agent_id,
        "review_receipt": review_receipt, "sample_count": len(samples), "sample_hash": canonical_hash(samples),
        "metrics": {key: {"mean": mean(v[key] for v in values), "variance": pvariance(v[key] for v in values)} for key in METRICS},
        "tool_descriptors": {name: canonical_hash(descriptor) for name, descriptor in descriptors.items()}}
    baseline["content_hash"] = canonical_hash(baseline)
    return baseline


def evaluate_agent_event(event, baseline, *, descriptors):
    metrics = _metrics(event)
    if baseline is None:
        return {"status": "baseline_unavailable", "assertion_status": "unmapped", "signals": []}
    verified = deepcopy(baseline)
    supplied = verified.pop("content_hash", None)
    if supplied != canonical_hash(verified):
        raise ValueError("agent_baseline_integrity_failure")
    if event.get("tenant_id") != baseline["tenant_id"] or event.get("agent_id") != baseline["agent_id"]:
        raise ValueError("agent_baseline_tenant_or_agent_mismatch")
    signals = []
    for key, value in metrics.items():
        prior = baseline["metrics"][key]
        # A variance floor prevents a constant reviewed sample from making any
        # tiny increase anomalous. Thresholds remain provisional until labeled eval.
        threshold = prior["mean"] + 4 * math.sqrt(max(prior["variance"], 1))
        if value > threshold:
            signals.append({"factor": "agent:" + key + "_spike", "observed": value, "threshold": threshold})
    enrolled = baseline["tool_descriptors"]
    for name, descriptor in descriptors.items():
        digest = canonical_hash(descriptor)
        if name not in enrolled:
            signals.append({"factor": "agent:unenrolled_tool", "tool": name})
        elif digest != enrolled[name]:
            signals.append({"factor": "agent:tool_descriptor_drift", "tool": name,
                            "expected_hash": enrolled[name], "observed_hash": digest})
    return {"status": "review_required" if signals else "within_reviewed_baseline",
            "assertion_status": "candidate", "baseline_hash": supplied, "signals": signals,
            "baseline_updated": False}
