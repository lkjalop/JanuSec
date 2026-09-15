"""Build a compact identifier index from an explicitly pinned NIST OSCAL commit."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request


def refresh(commit: str, output: Path) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("full_commit_sha_required")
    url = f"https://raw.githubusercontent.com/usnistgov/oscal-content/{commit}/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    with urllib.request.urlopen(url, timeout=45) as response:
        raw = response.read()
    catalog = json.loads(raw)["catalog"]
    controls = {}

    def walk(node):
        for control in node.get("controls", []):
            props = control.get("props", [])
            controls[control["id"]] = {
                "labels": sorted({p["value"] for p in props if p.get("name") == "label"}),
                "status": "withdrawn" if any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in props) else "active",
            }
            walk(control)
        for group in node.get("groups", []):
            walk(group)

    walk(catalog)
    result = {"framework": "nist_800_53", "source_url": url, "source_commit": commit,
              "source_sha256": hashlib.sha256(raw).hexdigest(), "metadata": catalog["metadata"],
              "controls": controls}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return {"controls": len(controls), "version": catalog["metadata"]["version"], "source_sha256": result["source_sha256"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, default=Path("config/control_catalogs/nist_800_53.json"))
    args = parser.parse_args()
    print(json.dumps(refresh(args.commit, args.output)))
