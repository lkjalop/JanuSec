import os, sys, subprocess, time
from pathlib import Path

"""Run only async-marked test files with pytest-asyncio plugin explicitly loaded.

Discovery: scans test_*.py for '@pytest.mark.asyncio' OR 'async def test_'.
Env:
  TEST_PER_FILE_TIMEOUT_SEC  Per-file timeout (default 60)
Usage:
  python scripts/run_tests_async_only.py
"""

TIMEOUT = float(os.getenv('TEST_PER_FILE_TIMEOUT_SEC','60'))

def discover_async_files():
    out = []
    for p in sorted(Path('tests').glob('test_*.py')):
        try:
            txt = p.read_text(encoding='utf-8')
            if '@pytest.mark.asyncio' in txt or 'async def test_' in txt:
                out.append(p)
        except Exception:
            pass
    return out

def run():
    files = discover_async_files()
    if not files:
        print('No async tests detected.')
        return 0
    print(f"Discovered {len(files)} async test file(s). Running with pytest-asyncio plugin.")
    for idx, f in enumerate(files, 1):
        print(f"\n[ASYNC {idx}/{len(files)}] {f}")
        cmd = [sys.executable, '-m', 'pytest', '-q', '-p', 'pytest_asyncio', str(f)]
        env = os.environ.copy()
        # Avoid loading unrelated heavy plugins
        env.setdefault('PYTEST_DISABLE_PLUGIN_AUTOLOAD','1')
        start = time.time()
        proc = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr, env=env)
        while True:
            try:
                rc = proc.wait(timeout=1.0)
                break
            except subprocess.TimeoutExpired:
                if (time.time() - start) > TIMEOUT:
                    print(f"[TIMEOUT] {f} exceeded {TIMEOUT}s; killing...")
                    try: proc.kill()
                    except Exception: pass
                    rc = proc.wait(timeout=5)
                    print(f"[TIMEOUT REPORT] file={f} rc={rc}")
                    return 124
        dur = time.time() - start
        if rc != 0:
            print(f"[FAIL HALT] {f} rc={rc} dur={dur:.2f}s")
            return rc
        print(f"[PASS] {f} ({dur:.2f}s)")
    print('All async tests passed.')
    return 0

if __name__ == '__main__':
    sys.exit(run())
