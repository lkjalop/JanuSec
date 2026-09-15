"""Evidence coverage contracts for emerging multi-stage threat classes.

These profiles do not detect or label attacks. They describe the independent
telemetry needed to investigate a hypothesis without turning absence into fact.
"""

from __future__ import annotations

from typing import Any, Mapping


THREAT_COVERAGE_PROFILES: dict[str, dict[str, Any]] = {
    "software_or_ai_supply_chain": {
        "required_capabilities": {
            "artifact_identity": {"artifact_digest", "sbom", "model_digest"},
            "build_provenance": {"slsa_provenance", "build_attestation", "builder_identity"},
            "publisher_trust": {"signature_verification", "signer_identity", "registry_audit"},
            "runtime_lineage": {"process_lineage", "workload_audit", "package_install"},
        },
        "questions": (
            "Was the deployed artifact the artifact that was reviewed and approved?",
            "Which builder, inputs, dependencies, model weights and data produced it?",
            "Did execution diverge from the signed artifact or approved deployment?",
        ),
    },
    "ai_model_or_agent_compromise": {
        "required_capabilities": {
            "model_identity": {"model_digest", "provider_model_id", "deployment_revision"},
            "interaction_audit": {"prompt_audit", "model_response_audit", "retrieval_trace"},
            "tool_boundary": {"tool_invocation", "authorization_decision", "sandbox_audit"},
            "data_boundary": {"data_access_audit", "egress_audit", "secret_access"},
        },
        "questions": (
            "Did untrusted input influence model instructions or retrieved context?",
            "Did a model or agent cross an authorization, tenant, tool or sandbox boundary?",
            "Were weights, adapters, prompts, embeddings or evaluation data poisoned or replaced?",
            "Was confidential data or model behavior extracted through repeated queries?",
        ),
    },
    "ransomware_and_extortion": {
        "required_capabilities": {
            "entry_and_identity": {"identity_audit", "email_audit", "remote_access_audit"},
            "execution_and_spread": {"process_lineage", "network_flow", "authentication_audit"},
            "file_impact": {"file_activity", "volume_snapshot", "encryption_telemetry"},
            "recovery_impact": {"backup_audit", "recovery_test", "inhibit_recovery_audit"},
            "extortion": {"egress_audit", "object_access", "dlp_audit"},
        },
        "questions": (
            "Was data encrypted, destroyed, merely renamed, or made unavailable by another cause?",
            "Were backups or recovery controls reached, changed or tested?",
            "Did data leave the environment before destructive impact?",
        ),
    },
    "steganographic_delivery_or_exfiltration": {
        "required_capabilities": {
            "carrier_provenance": {"file_digest", "mime_metadata", "content_provenance"},
            "content_analysis": {"steganalysis", "archive_analysis", "entropy_analysis"},
            "decoder_lineage": {"process_lineage", "script_audit", "memory_execution"},
            "transfer_path": {"network_flow", "dns_audit", "proxy_audit", "email_audit"},
        },
        "questions": (
            "Was hidden content present, or is the carrier merely unusual?",
            "Which decoder or loader extracted it and what executed next?",
            "Was steganography used for delivery, command-and-control or exfiltration?",
        ),
    },
}


def assess_threat_coverage(records: list[dict[str, Any]], profile_id: str) -> dict[str, Any]:
    profile = THREAT_COVERAGE_PROFILES.get(profile_id)
    if profile is None:
        raise ValueError("unknown_threat_coverage_profile")
    observed: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            continue
        for value in record.get("capabilities") or []:
            observed.add(str(value).strip().lower())
        for key in ("evidence_type", "source_type", "record_type", "sensor_capability"):
            if record.get(key):
                observed.add(str(record[key]).strip().lower())
    capabilities: list[dict[str, Any]] = []
    for name, alternatives in profile["required_capabilities"].items():
        matched = sorted(observed & set(alternatives))
        capabilities.append({
            "capability": name,
            "status": "covered" if matched else "missing",
            "matched": matched,
            "acceptable_evidence": sorted(alternatives),
        })
    return {
        "profile_id": profile_id,
        "status": "sufficient_for_investigation" if all(item["status"] == "covered" for item in capabilities) else "coverage_gaps",
        "capabilities": capabilities,
        "questions": list(profile["questions"]),
        "warning": "Coverage is not a detection verdict and missing telemetry is not evidence that activity did not occur.",
    }


__all__ = ["THREAT_COVERAGE_PROFILES", "assess_threat_coverage"]
