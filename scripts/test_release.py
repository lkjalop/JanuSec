"""Run the explicit preview trust suite, without implying full-suite coverage."""
import json
import hashlib
from pathlib import Path
import runpy
import sys
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
files = json.loads((root / "config/release_test_files.json").read_text())
corpora = root / "tests/fixtures/telemetry_corpora"
for item in json.loads((corpora / "manifest.json").read_text()):
    path = corpora / item["path"]
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
        raise SystemExit("Preview corpus missing or changed: " + item["path"])
sys.argv = ["run_preview.py", "pytest", *files, "--tb=short", "--maxfail=0",
            "--junitxml=tmp_preview/release-tests.xml", *sys.argv[1:]]
try:
    runpy.run_path(str(root / "scripts/run_preview.py"), run_name="__main__")
except SystemExit as exc:
    if exc.code:
        raise
    report = ET.parse(root / "tmp_preview/release-tests.xml")
    if list(report.iter("skipped")):
        raise SystemExit("Preview gate failed: selected checks were skipped")
    raise
