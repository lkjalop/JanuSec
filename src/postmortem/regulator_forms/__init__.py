"""AU regulator form pre-fill modules.

Each module exports ``prefill(document, tenant_config) -> dict`` matching
the corresponding schema in ``data_shapes/regulator_forms/``.

NEVER auto-submits. Always returns ``human_review_required: true`` and a
field-by-field ``field_provenance`` map back to the postmortem sections.
"""
from __future__ import annotations

from . import au_ndb, au_apra_cps234, au_soci, au_cyber_security_act


def prefill_for_regulator(
    *,
    regulator_id: str,
    document: dict,
    tenant_config: dict,
) -> dict:
    """Dispatch a pre-fill call to the right module."""
    rid = (regulator_id or "").lower()
    if rid in ("au_ndb", "ndb_privacy_act"):
        return au_ndb.prefill(document=document, tenant_config=tenant_config)
    if rid in ("au_apra_cps234", "apra_cps234"):
        return au_apra_cps234.prefill(document=document, tenant_config=tenant_config)
    if rid in ("au_soci", "soci_act"):
        return au_soci.prefill(document=document, tenant_config=tenant_config)
    if rid in ("au_cyber_security_act", "csa_ransomware", "cyber_security_act"):
        return au_cyber_security_act.prefill(document=document, tenant_config=tenant_config)
    return {"success": False, "error": f"unknown regulator: {regulator_id}"}


__all__ = ["prefill_for_regulator"]
