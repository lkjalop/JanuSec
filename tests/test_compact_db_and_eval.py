import subprocess
import sys
from pathlib import Path
import os


def test_compact_script_runs(tmp_path):
    db = tmp_path / 't.db'
    db.write_text('')
    p = subprocess.run([sys.executable, 'scripts/compact_hopgraph_db.py', str(db)], capture_output=True, text=True)
    # script should exit 0 even if DB empty
    assert p.returncode == 0


def test_evaluate_gray_tier_runs():
    p = subprocess.run([sys.executable, 'scripts/evaluate_gray_tier_recall.py'], capture_output=True, text=True)
    # script prints status lines; ensure it ran
    assert 'Loaded' in p.stdout or 'Warning' in p.stdout
