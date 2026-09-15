"""Evidence-gated maker/checker/critic loop for provider-neutral assessments."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .agent_harness import SessionLog
from .evidence_contract.records import canonical_hash


@dataclass(frozen=True, slots=True)
class LoopResult:
    claim: dict[str, Any]
    verification: dict[str, Any]
    iterations: int
    stop_reason: str
    receipt_hash: str


class AccuracyLoop:
    """Run bounded reasoning while evidence ownership remains outside the model.

    ``maker`` proposes claims from an immutable pack; ``checker`` returns typed
    support/contradiction/gaps; ``critic`` may refine the query or hypothesis.
    The loop stops on verifier acceptance, no evidence gain, or budget—not when a
    model merely repeats a high confidence number.
    """

    def __init__(self, session_log: SessionLog, *, max_iterations: int = 3) -> None:
        if not 1 <= max_iterations <= 8:
            raise ValueError("accuracy_loop_iteration_budget_out_of_range")
        self.log = session_log
        self.max_iterations = max_iterations

    def run(
        self,
        *,
        tenant_id: str,
        case_id: str,
        session_id: str,
        evidence_pack: dict[str, Any],
        maker: Callable[[dict[str, Any], dict[str, Any] | None], dict[str, Any]],
        checker: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
        critic: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> LoopResult:
        pack_hash = str(evidence_pack.get("content_hash") or canonical_hash(evidence_pack))
        self.log.append(
            tenant_id=tenant_id,
            case_id=case_id,
            session_id=session_id,
            event_type="evidence_pack_bound",
            payload={"pack_hash": pack_hash, "pack_id": evidence_pack.get("pack_id")},
        )
        feedback: dict[str, Any] | None = None
        previous_basis: str | None = None
        claim: dict[str, Any] = {}
        verification: dict[str, Any] = {}
        stop_reason = "iteration_budget"
        iterations = 0
        for iteration in range(1, self.max_iterations + 1):
            iterations = iteration
            claim = maker(evidence_pack, feedback)
            self.log.append(tenant_id=tenant_id, case_id=case_id, session_id=session_id, event_type="claim_proposed", payload={"iteration": iteration, "claim": claim, "pack_hash": pack_hash})
            verification = checker(claim, evidence_pack)
            basis_hash = canonical_hash(
                {
                    "support": verification.get("support_ids") or [],
                    "contradictions": verification.get("contradiction_ids") or [],
                    "gaps": verification.get("gaps") or [],
                }
            )
            self.log.append(tenant_id=tenant_id, case_id=case_id, session_id=session_id, event_type="claim_checked", payload={"iteration": iteration, "verification": verification, "basis_hash": basis_hash})
            if verification.get("action") == "accept":
                stop_reason = "verified"
                break
            if basis_hash == previous_basis:
                stop_reason = "no_evidence_gain"
                break
            previous_basis = basis_hash
            feedback = critic(claim, verification)
            self.log.append(tenant_id=tenant_id, case_id=case_id, session_id=session_id, event_type="counter_hypothesis", payload={"iteration": iteration, "feedback": feedback})

        receipt = {
            "tenant_id": tenant_id,
            "case_id": case_id,
            "session_id": session_id,
            "pack_hash": pack_hash,
            "iterations": iterations,
            "stop_reason": stop_reason,
            "claim_hash": canonical_hash(claim),
            "verification_hash": canonical_hash(verification),
        }
        receipt_hash = canonical_hash(receipt)
        self.log.append(tenant_id=tenant_id, case_id=case_id, session_id=session_id, event_type="loop_completed", payload={**receipt, "receipt_hash": receipt_hash})
        return LoopResult(claim, verification, iterations, stop_reason, receipt_hash)


__all__ = ["AccuracyLoop", "LoopResult"]
