"""Deterministic grounding validation for LLM-generated narratives.

Checks that every Claim in a ClusterNarrative traces back to actual evidence
row IDs from the cluster's scope. Rejects or flags ungrounded claims.
"""
from __future__ import annotations

import logging
from typing import Set

from .schemas import Claim, ClusterNarrative

logger = logging.getLogger(__name__)


def validate_claims(
    narrative: ClusterNarrative,
    valid_row_ids: Set[int],
) -> ClusterNarrative:
    """Validate each claim's evidence_row_ids against the cluster's row set.

    Marks each claim as grounded=True/False. Returns the narrative with
    updated claim ground-truth flags.
    """
    grounded_claims: list[Claim] = []
    ungrounded_count = 0

    for claim in narrative.claims:
        if not claim.evidence_row_ids:
            # No citation provided — mark ungrounded
            claim.grounded = False
            ungrounded_count += 1
        elif all(rid in valid_row_ids for rid in claim.evidence_row_ids):
            claim.grounded = True
        else:
            # Some cited rows don't belong to this cluster
            invalid = [rid for rid in claim.evidence_row_ids if rid not in valid_row_ids]
            logger.debug(
                'grounding: cluster %s claim cites invalid rows %s',
                narrative.cluster_id, invalid,
            )
            claim.grounded = False
            ungrounded_count += 1
        grounded_claims.append(claim)

    if ungrounded_count:
        logger.info(
            'grounding: cluster %s — %d/%d claims ungrounded',
            narrative.cluster_id, ungrounded_count, len(grounded_claims),
        )

    narrative.claims = grounded_claims
    return narrative


def narrative_is_trustworthy(narrative: ClusterNarrative) -> bool:
    """Return True if all claims (if any) are grounded."""
    if not narrative.claims:
        return True  # No structured claims — deterministic narrative
    return all(c.grounded for c in narrative.claims)
