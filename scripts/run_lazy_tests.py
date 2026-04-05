"""Run the lazy-runner tests directly without pytest collection.

Usage: python scripts/run_lazy_tests.py
"""
import asyncio
import importlib
import sys
from pathlib import Path

# Ensure repo root on sys.path so 'tests' package is importable
_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))


async def _run():
    failures = []
    try:
        mod = importlib.import_module('tests.test_lazy_runner')
    except Exception as exc:
        print('Failed to import tests.test_lazy_runner:', exc)
        raise

    for name in dir(mod):
        if name.startswith('test_'):
            func = getattr(mod, name)
            print('Running', name)
            try:
                if asyncio.iscoroutinefunction(func):
                    await func()
                else:
                    func()
            except AssertionError as ae:
                print('Assertion failed in', name, ae)
                failures.append((name, str(ae)))
            except Exception as e:
                print('Error running', name, e)
                failures.append((name, str(e)))

    if failures:
        print('\nFailures:')
        for n, msg in failures:
            print(n, msg)
        raise SystemExit(1)
    print('\nAll tests passed')


if __name__ == '__main__':
    asyncio.run(_run())
