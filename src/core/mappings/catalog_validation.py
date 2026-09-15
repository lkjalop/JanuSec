"""Catalog membership is separate from mapping relevance and control testing."""
from functools import lru_cache
import json
from pathlib import Path


@lru_cache(maxsize=1)
def catalog_index() -> dict:
    path = Path(__file__).resolve().parents[3] / "config/control_catalogs/nist_800_53.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    aliases = {}
    for cid, item in catalog["controls"].items():
        aliases[cid.casefold()] = cid
        for label in item["labels"]:
            aliases[label.casefold()] = cid
    return {**catalog, "aliases": aliases}


def validate_citation(framework: str, control_id: str) -> dict:
    result = {"framework": framework, "control_id": control_id,
              "mapping_review": "unreviewed", "applicability": "not_assessed"}
    if framework != "nist_800_53":
        return {**result, "catalog_status": "catalog_not_loaded", "catalog_version": None}
    catalog = catalog_index()
    cid = catalog["aliases"].get(control_id.strip().casefold())
    return {**result, "canonical_id": cid,
            "catalog_status": catalog["controls"][cid]["status"] if cid else "invalid_id",
            "catalog_version": catalog["metadata"]["version"],
            "catalog_source_sha256": catalog["source_sha256"]}
