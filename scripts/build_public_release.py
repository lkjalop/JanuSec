"""Copy a reviewed source selection into an empty directory; never copy .git.

Run from the source checkout. Review the resulting tree and run its tests before
publishing. This path policy complements secret scanning; it does not replace it.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCS = {"README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE"}
PRIVATE_TERMS = ("career", "resume", "email_to_", "pitch", "jalop", "disr_",
                 "cyberstash_project_assessment", "claim_defensibility",
                 "demonstrated_skillsets", "deep_assessment_and_research")


def exclusion(path):
    p = Path(path)
    low = path.lower()
    if low.startswith(("logs/", "tmp/", "artifacts/")) or any(
        part in {"__pycache__", ".pytest_cache", "test-results"} for part in p.parts
    ):
        return "generated-runtime-output"
    if p.suffix.lower() in {".pyc", ".pyo"}:
        return "compiled-output"
    if any(part.lower().startswith(("tmp_", "_tmp", "~$")) for part in p.parts):
        return "scratch"
    if low.startswith(("data/", "src/data/", "dump/", "resumes/", "sultry_prd/",
                       "gridverdict_prd_package/", "frontend/static/data/")):
        return "runtime-or-private"
    if p.suffix.lower() in {".key", ".enc", ".pdf", ".docx", ".pid", ".bak", ".db", ".sqlite", ".duckdb", ".log"}:
        return "private-or-generated-format"
    if any(part.startswith("tfplan") or ".tfstate" in part or part.endswith(".egg-info") for part in p.parts):
        return "generated"
    if low.endswith(".tfvars") or (p.name.startswith(".env") and not low.endswith((".example", ".sample", ".template"))):
        return "deployment-configuration"
    if p.suffix.lower() == ".md" and len(p.parts) == 1 and path not in ROOT_DOCS:
        return "unreviewed-root-notes"
    if p.suffix.lower() == ".md" and any(term in low for term in PRIVATE_TERMS):
        return "private-notes"
    if low.startswith("docs/janusec_") and "2026" in low:
        return "internal-security-inventory"
    if len(p.parts) == 1 and (p.name.startswith("_") or p.name in {"-", "'", "# Pseudocode phases.sh"}):
        return "scratch"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination == ROOT or ROOT in destination.parents:
        parser.error("Destination must be outside the source checkout")
    if destination.exists() and any(destination.iterdir()):
        parser.error("Destination must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    paths = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    manifest = {"included": [], "excluded": {}}
    for name in sorted(set(paths) - {""}):
        source = ROOT / name
        reason = exclusion(name)
        if reason:
            manifest["excluded"][name] = reason
        elif source.is_file() and not source.is_symlink():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            manifest["included"].append(name)
    args.manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"included": len(manifest["included"]), "excluded": len(manifest["excluded"])}))


if __name__ == "__main__":
    main()
