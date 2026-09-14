"""Registry coverage guard: every breach detector should be mapped in the single phase
registry, so a new detector that lands unmapped is caught here (and via the audit
pack's coverage_gaps) rather than silently producing generic GRC output."""
import pytest

from src.core.ingest.cluster_merge import PHASE_DETECTORS
from src.core.grc import phase_registry as reg

pytestmark = pytest.mark.acceptance

# Phases that are intentionally NOT full control-mapped (benign / sanctioned context).
_INTENTIONALLY_PARTIAL = {"pentest_escalation"}


def test_all_detectors_present_in_registry():
    detectors = {d.phase_id for d in PHASE_DETECTORS}
    missing = sorted(detectors - reg.known_phases())
    assert missing == [], f"detectors unmapped in phase_registry: {missing}"


def test_detectors_have_core_dimensions():
    detectors = {d.phase_id for d in PHASE_DETECTORS} - _INTENTIONALLY_PARTIAL
    unmapped = {}
    for p in sorted(detectors):
        gaps = reg.coverage([p])["unmapped_by_dimension"]
        # controls + remediation + dread + kc are the load-bearing GRC dimensions.
        core = {d for d in gaps if d in ("controls", "remediation", "dread", "kc")}
        if core:
            unmapped[p] = sorted(core)
    assert not unmapped, f"detectors missing core GRC dimensions: {unmapped}"


def test_new_detector_would_be_flagged_by_coverage():
    # A hypothetical unmapped phase must surface in coverage(), not silently default.
    cov = reg.coverage(["totally_new_detector_xyz"])
    assert "totally_new_detector_xyz" in cov["unmapped_phases"]
