#!/usr/bin/env python3
"""Run pytest in chunks to avoid long monolithic runs and to help isolate failures/stalls.
Usage: python scripts/run_pytest_chunks.py [--chunk-size N] [--start 0] [--pattern tests]
By default skips tests under 'tests/integration' and 'tests/playwright'.
"""
import os
import sys
import subprocess
from pathlib import Path
import argparse
import logging

def gather_tests(root: Path, exclude_dirs=None):
    if exclude_dirs is None:
        exclude_dirs = {'integration', 'playwright'}
    tests = []
    for p in sorted(root.rglob('test_*.py')):
        # skip files in excluded directories
        parts = {str(x) for x in p.parts}
        if any(ex in str(p) for ex in exclude_dirs):
            continue
        tests.append(str(p))
    return tests


def chunked(it, size):
    for i in range(0, len(it), size):
        yield it[i:i+size]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--chunk-size', type=int, default=80)
    ap.add_argument('--start', type=int, default=0)
    ap.add_argument('--pattern', type=str, default='tests')
    args = ap.parse_args()

    root = Path(args.pattern)
    if not root.exists():
        logger = logging.getLogger(__name__)
        logger.error('Test root not found: %s', root)
        sys.exit(2)
    tests = gather_tests(root)
    if not tests:
        logging.getLogger(__name__).info('No test files found under %s', root)
        sys.exit(0)
    logging.getLogger(__name__).info('Found %s test files, running in chunks of %s (starting at chunk %s)', len(tests), args.chunk_size, args.start)

    all_failures = []
    chunk_idx = 0
    for chunk in chunked(tests, args.chunk_size):
        if chunk_idx < args.start:
            chunk_idx += 1
            continue
        logging.getLogger(__name__).info('Running chunk %s with %s files', chunk_idx, len(chunk))
        cmd = [sys.executable, '-m', 'pytest', '-q', '--maxfail=0', '-r', 'a'] + chunk
        env = dict(os.environ)
        env['JANUSEC_TEST_MODE'] = '1'
        try:
            proc = subprocess.run(cmd, env=env)
        except KeyboardInterrupt:
            logging.getLogger(__name__).warning('Interrupted by user')
            break
        except Exception as e:
            logging.getLogger(__name__).exception('Failed to run pytest: %s', e)
            all_failures.append((chunk_idx, 'run_error', str(e)))
            chunk_idx += 1
            continue
        if proc.returncode != 0:
            logging.getLogger(__name__).error('Chunk %s returned non-zero exit %s (see output above)', chunk_idx, proc.returncode)
            all_failures.append((chunk_idx, proc.returncode, chunk))
        else:
            logging.getLogger(__name__).info('Chunk %s passed', chunk_idx)
        chunk_idx += 1
    logging.getLogger(__name__).info('==== Summary ====')
    logging.getLogger(__name__).info('Total chunks: %s', chunk_idx)
    logging.getLogger(__name__).info('Failures: %s', len(all_failures))
    for f in all_failures:
        logging.getLogger(__name__).info(' - %s', f)
    if all_failures:
        sys.exit(1)

if __name__ == '__main__':
    main()
