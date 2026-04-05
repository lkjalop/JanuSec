import os
import sys
import time
import subprocess
import threading

DEFAULT_TIMEOUT = float(os.getenv('TEST_PER_FILE_TIMEOUT_SEC', '40'))  # configurable per test timeout
TWO_PASS = os.getenv('TEST_TWO_PASS','1') not in ('0','false','False')
from pathlib import Path

"""Sequential test runner to surface order-dependent issues.

Runs each pytest file (test_*.py) individually in lexical order, halting on first
non-zero exit. Prints concise progress lines.

Usage (PowerShell):
  python scripts/run_tests_sequential.py

Optional env vars:
  TEST_GLOB   Override glob pattern (default 'tests/test_*.py')
  TEST_LIMIT  Integer; run only first N files (debugging)
"""

def _run_files(files, enable_async: bool) -> int:
  """Run provided test files sequentially. If enable_async True, allow plugin autoload or explicitly load async plugin."""
  if enable_async:
    disable_plugins = False
  else:
    disable_plugins = True
  glob_pat = os.getenv('TEST_GLOB', 'tests/test_*.py')
  limit = os.getenv('TEST_LIMIT')
  limit_n = int(limit) if limit and limit.isdigit() else None
  # If caller already passed explicit list (discovery pass), skip re-glob; else glob
  discovered = sorted(Path('.').glob(glob_pat)) if not files else files
  files = discovered
  if limit_n:
    files = files[:limit_n]
  if not files:
    print('No test files matched pattern', glob_pat)
    return 0
  start_all = time.time()
  for idx, f in enumerate(files, 1):
    t0 = time.time()
    print(f"\n[RUN {idx}/{len(files)}] {f}")
    cmd = [sys.executable, '-m', 'pytest', '-q', str(f)]
    env = os.environ.copy()
    if disable_plugins:
      env.setdefault('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
    else:
      # Allow async plugin only; still disable global autoload then explicitly add plugin
      env.setdefault('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
      cmd = [sys.executable, '-m', 'pytest', '-q', '-p', 'pytest_asyncio', str(f)]
    proc = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr, env=env)
    while True:
      try:
        rc = proc.wait(timeout=1.0)
        break
      except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        if elapsed > DEFAULT_TIMEOUT:
          print(f"[TIMEOUT] {f} exceeded {DEFAULT_TIMEOUT:.1f}s; terminating...")
          try:
            proc.kill()
          except Exception:
            pass
          rc = proc.wait(timeout=5)
          print(f"[TIMEOUT REPORT] Last test file: {f} elapsed={elapsed:.2f}s rc={rc}")
          return 124
    dt = time.time() - t0
    if rc != 0:
      print(f"[FAIL HALT] {f} exit={rc} duration={dt:.2f}s")
      return rc
    else:
      print(f"[PASS] {f} ({dt:.2f}s)")
  elapsed = time.time() - start_all
  print(f"All {len(files)} test files passed sequentially in {elapsed:.2f}s (async={'on' if enable_async else 'off'})")
  return 0

def main():
  # Pass 1: fast (plugins disabled) to catch most failures quickly
  files = []
  rc = _run_files(files, enable_async=False)
  if rc != 0 or not TWO_PASS:
    return rc
  # Identify async tests (contain '@pytest.mark.asyncio' or 'async def test_')
  async_files = []
  for path in sorted(Path('tests').glob('test_*.py')):
    try:
      text = path.read_text(encoding='utf-8')
      if '@pytest.mark.asyncio' in text or 'async def test_' in text:
        async_files.append(path)
    except Exception:
      pass
  if not async_files:
    print('No async tests detected for second pass.')
    return 0
  print(f"\n[SECOND PASS] Running {len(async_files)} async test file(s) with pytest-asyncio plugin...")
  return _run_files(async_files, enable_async=True)

if __name__ == '__main__':
  sys.exit(main())