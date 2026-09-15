#!/usr/bin/env python3
"""Run pytest in an isolated, test-friendly environment.

Sets FAST_TEST_MODE=1 and CONNECTOR_CHECKPOINTS_PATH to a temporary
directory, removes persistent checkpoint file if present, runs pytest
with a configurable timeout, and writes full output to tmp/pytest_output.txt.
"""
import os
import sys
import shutil
import tempfile
import subprocess
from pathlib import Path


def main(timeout_seconds: int = 600):
    here = Path(__file__).resolve().parent.parent
    tmpdir = Path(tempfile.mkdtemp(prefix='pytest_checkpoints_'))
    outdir = here / 'tmp'
    outdir.mkdir(exist_ok=True)
    outpath = outdir / 'pytest_output.txt'

    env = os.environ.copy()
    env['FAST_TEST_MODE'] = '1'
    env['CONNECTOR_CHECKPOINTS_PATH'] = str(tmpdir)

    # Remove global checkpoints.json if present to avoid stale state
    cp = here / 'data' / 'checkpoints.json'
    try:
        if cp.exists():
            cp.unlink()
    except Exception:
        pass

    cmd = [sys.executable, '-m', 'pytest', '-q']
    print('Running:', ' '.join(cmd))
    print('FAST_TEST_MODE=1', 'CONNECTOR_CHECKPOINTS_PATH=', tmpdir)

    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout_seconds)
        rc = proc.returncode
        out = proc.stdout
        err = proc.stderr
    except subprocess.TimeoutExpired as e:
        rc = 124
        out = getattr(e, 'output', '') or ''
        err = getattr(e, 'stderr', '') or ''
        out += '\n\n=== TIMEOUT (pytest exceeded %s seconds) ===\n' % timeout_seconds

    # Save full output
    with open(outpath, 'w', encoding='utf-8') as fh:
        fh.write('=== STDOUT ===\n')
        fh.write(out or '')
        fh.write('\n=== STDERR ===\n')
        fh.write(err or '')

    print('\n=== Summary ===')
    print('Output file:', outpath)
    print('Return code:', rc)
    # Print a short tail to console for quick triage
    tail = (out + '\n' + err).strip().splitlines()[-60:]
    print('\n'.join(tail))

    # cleanup left tmpdir to avoid disk leaks (keep for debugging if RC != 0)
    if rc == 0:
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

    sys.exit(rc)


if __name__ == '__main__':
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument('--timeout', '-t', type=int, default=600, help='Timeout seconds for pytest')
    args = p.parse_args()
    main(args.timeout)
