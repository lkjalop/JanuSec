import os
import sys
from pathlib import Path

# Ensure heavy server scan is skipped if any import paths reference it
os.environ.setdefault('SKIP_ISMS_SCAN', '1')

# Ensure project root is on sys.path so `src` package imports work
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main():
    from src.rules import executor
    e = {'message': 'failed login from 1.2.3.4', 'history': [{'type': 'failed_login', 'user': 'alice'}, {'type': 'failed_login', 'user': 'alice'}]}
    print('Loaded executor module:', executor.__name__)
    print('Evaluate with no rules:', executor.evaluate_event(e, []))


if __name__ == '__main__':
    main()
