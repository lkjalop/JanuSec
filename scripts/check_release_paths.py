"""Reject tracked private/runtime files before publication."""
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_public_release import exclusion

paths = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
rejected = [(p, exclusion(p)) for p in paths if p and exclusion(p)]
for name, reason in rejected:
    print(f"Forbidden publication path ({reason}): {name}")
raise SystemExit(bool(rejected))
