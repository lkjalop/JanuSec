from __future__ import annotations
import subprocess
import sys
from pathlib import Path


def test_export_only_runs(tmp_path):
    # run the script with --export-only to ensure it can write output
    out_dir = tmp_path / 'out'
    cmd = [sys.executable, 'scripts/train_isolation.py', '--export-only', '--export-dir', str(out_dir)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # script should exit 0 even if no data available
    assert proc.returncode == 0
    # out dir should exist
    assert out_dir.exists()
    