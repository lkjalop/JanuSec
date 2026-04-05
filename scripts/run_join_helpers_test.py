import sys
import importlib.util
from pathlib import Path


def _load_test_module():
    root = Path(__file__).parent.parent.resolve()
    # Ensure project root is on sys.path for imports like `src.*`
    import sys
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    mods = []
    for fn in ('test_join_helpers.py', 'test_join_helpers_edgecases.py'):
        p = root / 'tests' / fn
        spec = importlib.util.spec_from_file_location(fn.replace('.py',''), str(p))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mods.append(mod)
    return mods


def main():
    try:
        mods = _load_test_module()
        # run simple named test functions if present
        for m in mods:
            for attr in dir(m):
                if attr.startswith('test_') and callable(getattr(m, attr)):
                    getattr(m, attr)()
    except AssertionError as e:
        print('TEST FAILED:', e)
        return 2
    except Exception as e:
        print('ERROR running test:', type(e).__name__, e)
        return 3
    print('OK')
    return 0

if __name__ == '__main__':
    sys.exit(main())
