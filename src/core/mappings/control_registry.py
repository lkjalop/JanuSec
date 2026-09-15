"""Exact factor lookup across the maintained registries, with visible gaps.

Entries are citations requiring review, not attestations. No domain-prefix or
control-family expansion is permitted at this boundary.
"""
from collections import defaultdict

REGISTRY_VERSION = "2026-09-12.2"


def factor_control_record(factor: str) -> dict:
    from src.core.mappings.factor_to_compliance import FACTOR_TO_COMPLIANCE
    from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP
    from src.core.grc.phase_registry import PHASE_KNOWLEDGE
    citations = defaultdict(set)
    sources = []
    for source, entry in (("factor_to_compliance", FACTOR_TO_COMPLIANCE.get(factor)),
                          ("phase_registry", (PHASE_KNOWLEDGE.get(factor) or {}).get("controls"))):
        if entry:
            sources.append(source)
            for framework, controls in entry.items():
                citations[framework].update(controls)
    taxonomy = _FACTOR_MAP.get(factor)
    if taxonomy:
        sources.append("factor_taxonomy")
        for control in taxonomy.get("controls", []):
            prefix, separator, cid = control.partition(":")
            framework = {"NIST": "nist_800_53", "ISO27001": "iso27001", "SOC2": "soc2"}.get(prefix)
            if separator and framework:
                citations[framework].add(cid)
    from src.core.mappings.catalog_validation import validate_citation
    validation = [validate_citation(fw, cid) for fw, values in sorted(citations.items()) for cid in sorted(values)]
    eligible = defaultdict(list)
    for item in validation:
        if item["catalog_status"] not in {"invalid_id", "withdrawn"}:
            eligible[item["framework"]].append(item["control_id"])
    return {"factor": factor, "registry_version": REGISTRY_VERSION,
            "tag_grade": "inferred" if eligible else "unmapped",
            "assertion_status": "candidate", "sources": sources,
            "controls": dict(eligible), "catalog_validation": validation}


def registry_snapshot() -> dict:
    from src.core.mappings.factor_to_compliance import FACTOR_TO_COMPLIANCE
    from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP
    from src.core.grc.phase_registry import PHASE_KNOWLEDGE
    keys = sorted(set(FACTOR_TO_COMPLIANCE) | set(_FACTOR_MAP) | set(PHASE_KNOWLEDGE))
    records = [factor_control_record(key) for key in keys]
    return {"registry_version": REGISTRY_VERSION, "factors": records,
            "unmapped_count": sum(r["tag_grade"] == "unmapped" for r in records)}
