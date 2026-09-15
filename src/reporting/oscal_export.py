"""Customer-scoped OSCAL evidence exchange, without invented control findings."""
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid

from src.core.evidence_contract.records import canonical_hash
from src.core.mappings.catalog_validation import catalog_index, validate_citation

ROOT = Path(__file__).resolve().parents[2]


def validate_oscal(document: dict) -> None:
    from jsonschema import Draft7Validator, FormatChecker, ValidationError, validators
    import regex
    path = ROOT / "config/oscal/oscal_assessment-results_schema.json"
    raw = path.read_bytes()
    source = json.loads(path.with_suffix(".source.json").read_text(encoding="utf-8"))
    if hashlib.sha256(raw).hexdigest() != source["sha256"]:
        raise ValueError("oscal_schema_integrity_failure")
    # NIST patterns use Unicode properties (\p{L}), unsupported by stdlib re.
    # Keep the official schema intact and use a Unicode-capable pattern engine.
    def pattern(validator, expression, instance, schema):
        if validator.is_type(instance, "string") and regex.search(expression, instance) is None:
            yield ValidationError(f"{instance!r} does not match {expression!r}")
    validator_type = validators.extend(Draft7Validator, {"pattern": pattern})
    validator_type(json.loads(raw), format_checker=FormatChecker()).validate(document)


def export_case_evidence(view: dict, profile: dict, *, tenant_id: str) -> dict:
    case = view.get("case") or {}
    if not tenant_id or case.get("tenant_id") != tenant_id or profile.get("tenant_id") != tenant_id:
        raise ValueError("oscal_customer_scope_mismatch")
    catalog = catalog_index()
    if profile.get("framework") != "nist_800_53" or profile.get("catalog_version") != catalog["metadata"]["version"]:
        raise ValueError("oscal_catalog_version_not_supported")
    controls = profile.get("control_ids")
    if not isinstance(controls, list) or not controls or any(
        validate_citation("nist_800_53", cid)["catalog_status"] != "active" for cid in controls
    ):
        raise ValueError("oscal_explicit_active_control_scope_required")
    plan = profile.get("assessment_plan_href")
    if not isinstance(plan, str) or not plan.strip():
        raise ValueError("oscal_customer_assessment_plan_required")
    now = datetime.now(timezone.utc).isoformat()
    view_hash = canonical_hash(view)
    profile_hash = canonical_hash(profile)
    def uid(value):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"janusec:{tenant_id}:{case['id']}:{view_hash}:{value}"))
    def prop(name, value):
        return {"name": name, "ns": "https://janusec.local/ns/evidence", "value": str(value)}
    resource_id = uid("evidence-pack")
    observations = []
    for impact in view.get("control_impacts") or []:
        check = validate_citation(impact.get("framework", ""), impact.get("control_id", ""))
        selected = {validate_citation("nist_800_53", cid)["canonical_id"] for cid in controls}
        if check.get("canonical_id") not in selected:
            continue
        observations.append({"uuid": uid("control:" + str(impact.get("id"))),
            "description": f"Candidate evidence association for {impact['control_id']}; control effectiveness requires a separate reviewed test.",
            "methods": ["EXAMINE"], "collected": now,
            "props": [prop("assertion-status", "candidate"), prop("control-id", check["canonical_id"])],
            "relevant-evidence": [{"href": "#" + resource_id, "description": "Immutable case projection containing the cited evidence references."}]})
    if not observations:
        observations.append({"uuid": uid("coverage"), "description": "No candidate control associations in the selected customer scope.",
                             "methods": ["EXAMINE"], "collected": now})
    result = {"assessment-results": {
        "uuid": uid(profile_hash),
        "metadata": {"title": "JanuSec case evidence exchange", "last-modified": now,
            "version": "1", "oscal-version": "1.1.2",
            "props": [prop("tenant-id", tenant_id), prop("case-id", case["id"]),
                      prop("customer-profile-hash", profile_hash), prop("evidence-pack-hash", view_hash),
                      prop("catalog-source-sha256", catalog["source_sha256"]),
                      prop("selected-controls", ",".join(controls)), prop("assessment-status", "evidence-only")]},
        "import-ap": {"href": plan},
        "results": [{"uuid": uid("result"), "title": "Candidate evidence review",
            "description": "Evidence exchange only. No control effectiveness, formal nonconformity, or audit opinion is asserted.",
            "start": now,
            "reviewed-controls": {"control-selections": [{"description": "No control effectiveness tests are asserted by this export."}]},
            "observations": observations}],
        "back-matter": {"resources": [{"uuid": resource_id, "title": "Case evidence projection",
            "props": [prop("sha256", view_hash)],
            "base64": {"filename": "case-evidence.json", "media-type": "application/json",
                       "value": base64.b64encode(json.dumps(view, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).decode()}}]},
    }}
    validate_oscal(result)
    return result
