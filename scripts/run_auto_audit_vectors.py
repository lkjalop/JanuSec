import json
import sys
import os
from pathlib import Path


def main():
    # Provide a minimal Windows environment when invoked with an empty env
    # (pytest spawns this script with env={}). Missing SystemRoot/Path can
    # break imports that touch networking libraries.
    if os.name == 'nt':
        sysroot = os.environ.get('SystemRoot') or os.environ.get('SYSTEMROOT') or r'C:\Windows'
        os.environ.setdefault('SystemRoot', sysroot)
        os.environ.setdefault('SYSTEMROOT', sysroot)
        os.environ.setdefault('WINDIR', sysroot)
        os.environ.setdefault('COMSPEC', os.path.join(sysroot, 'System32', 'cmd.exe'))
        os.environ.setdefault('PATH', os.path.join(sysroot, 'System32'))
    # Ensure fast/test mode is enabled to avoid expensive rule discovery
    os.environ.setdefault('FAST_TEST_MODE', '1')
    # Lite/test helpers reduce external dependencies in CI runs
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    # ensure project root is on path so `src` package imports work
    sys.path.insert(0, '')
    try:
        from src.core.correlation.rules.registry import CORRELATION_RULES
    except Exception as e:
        print('Failed to import CORRELATION_RULES:', e)
        return 1

    DATA_DIR = Path('tests') / 'data' / 'auto_audit'
    vectors = sorted([p.name for p in DATA_DIR.iterdir() if p.suffix == '.json'])

    for v in vectors:
        p = DATA_DIR / v
        try:
            payload = json.loads(p.read_text(encoding='utf-8'))
        except Exception as e:
            print(f"{v} -> JSON load error: {e}")
            continue
        try:
            fired = CORRELATION_RULES.evaluate(payload)
            print(f"{v} -> fired: {[r.name for r in fired]}")
        except Exception as e:
            print(f"{v} -> evaluation error: {e}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
