"""
Run pytest with test helper env variables set (avoids PowerShell quoting issues).
Usage: python scripts/run_pytest_env.py [pytest args...]
"""
import os
import sys
import subprocess

def main(argv):
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    os.environ['PLATFORM_LITE_INIT'] = '1'
    os.environ['DISABLE_DB'] = '1'
    # Preserve any existing PYTEST_ADDOPTS
    cmd = [sys.executable, '-m', 'pytest', '-q'] + argv
    print('Running:', ' '.join(cmd))
    rc = subprocess.call(cmd)
    raise SystemExit(rc)

if __name__ == '__main__':
    main(sys.argv[1:])
