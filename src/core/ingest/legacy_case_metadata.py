"""Recover a case identifier only from an unambiguous evidence partition."""
from copy import deepcopy


def reconcile_case_metadata(snapshot: dict, tenant_id: str) -> tuple[dict, dict]:
    result = deepcopy(snapshot)
    partitions = [p for p in result.get("case_partitions", []) if isinstance(p, dict)
                  and p.get("tenant_id") == tenant_id
                  and p.get("assessment_id") == snapshot.get("assessment_id")
                  and p.get("case_id") and p.get("status") != "background"]
    counts = {"bound": 0, "ambiguous": 0, "already_bound": 0, "conflict": 0}
    for key in ("corrective_actions", "approved_actions", "analyst_decisions", "grc_workflow"):
        for item in result.get(key) or []:
            if not isinstance(item, dict):
                continue
            refs = {str(v) for field in ("evidence_ids", "supporting_evidence_ids", "contradicting_evidence_ids")
                    for v in item.get(field) or []}
            row_refs = {str(v) for v in item.get("row_refs") or []}
            candidates = {p["case_id"] for p in partitions
                          if (refs or row_refs)
                          and (not refs or refs <= {str(v) for v in p.get("evidence_ids") or []})
                          and (not row_refs or row_refs <= {str(v) for v in p.get("row_refs") or []})}
            if len(candidates) != 1:
                counts["ambiguous"] += 1
                continue
            case_id = next(iter(candidates))
            if item.get("case_id"):
                counts["already_bound" if item["case_id"] == case_id else "conflict"] += 1
                continue
            item["case_id"] = case_id
            item["case_binding_provenance"] = {"method": "exact_evidence_partition", "version": "1"}
            counts["bound"] += 1
    return result, counts
