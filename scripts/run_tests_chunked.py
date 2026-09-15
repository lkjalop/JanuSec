"""Run ordered tests in small chunks and detect hangs.

Usage (from repo root):
  python scripts/run_tests_chunked.py START END [--chunk-size N] [--timeout S]

Example:
  python scripts/run_tests_chunked.py 143 242 --chunk-size 10 --timeout 300

This script reads `batch_order.txt`, selects the requested (1-based inclusive)
range, divides it into chunks and runs pytest on each chunk sequentially.
If a chunk run exceeds the timeout (seconds) the script will abort that chunk
and report which chunk (and files in it) caused the hang. It writes per-chunk
logs under `tests/chunk_logs/` for later inspection.

This helps triage stalls by bisecting the ordered range into smaller groups.
"""
from __future__ import annotations
import argparse
import pathlib
import subprocess
import sys
import os
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
ORDER_F = ROOT / 'batch_order.txt'
LOG_DIR = ROOT / 'tests' / 'chunk_logs'


def load_order(path: pathlib.Path) -> list[str]:
    raw = path.read_bytes()
    for enc in ('utf-8-sig', 'utf-8', 'utf-16', 'utf-16-le', 'utf-16-be'):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            text = None
    if text is None:
        text = raw.decode('latin1')
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith('=')]
    items = []
    for l in lines:
        if ':' in l:
            p = l.split(':', 1)[0].strip()
            items.append(p)
    return items


def ensure_log_dir():
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def run_chunk(chunk_files: list[str], chunk_idx: int, timeout: int) -> tuple[int, str]:
    ensure_log_dir()
    logf = LOG_DIR / f'chunk_{chunk_idx:03d}.log'
    args = [sys.executable, '-m', 'pytest', '-q', '--maxfail=1'] + chunk_files
    start = time.time()
    try:
        with open(logf, 'wb') as fh:
            proc = subprocess.run(args, stdout=fh, stderr=subprocess.STDOUT, timeout=timeout, cwd=str(ROOT))
        elapsed = time.time() - start
        return proc.returncode, f'OK (rc={proc.returncode}, time={int(elapsed)}s) -> log: {logf}'
    except subprocess.TimeoutExpired as exc:
        # write partial output if available
        try:
            with open(logf, 'ab') as fh:
                if exc.stdout:
                    fh.write(exc.stdout)
                if exc.stderr:
                    fh.write(exc.stderr)
        except Exception:
            pass
        return 124, f'TIMEOUT after {timeout}s -> log: {logf} (chunk files: {chunk_files})'
    except Exception as exc:
        return 1, f'ERROR {exc} -> log: {logf}'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('start', type=int)
    p.add_argument('end', type=int)
    p.add_argument('--chunk-size', type=int, default=10)
    p.add_argument('--timeout', type=int, default=300)
    p.add_argument('--show-logs', action='store_true', help='Print per-chunk logs to stdout on completion')
    args = p.parse_args()

    if not ORDER_F.exists():
        print('batch_order.txt not found at', ORDER_F)
        return 2
    items = load_order(ORDER_F)
    if args.start < 1 or args.end > len(items) or args.start > args.end:
        print('Invalid range', args.start, args.end, 'items available', len(items))
        return 2
    subset = items[args.start-1:args.end]
    # run in chunks
    total = len(subset)
    print(f'Running {total} files in chunk-size {args.chunk_size} with timeout {args.timeout}s per chunk')
    ensure_log_dir()

    chunk_idx = 0
    for i in range(0, total, args.chunk_size):
        chunk_idx += 1
        chunk_files = subset[i:i+args.chunk_size]
        print(f'[{chunk_idx}] Running files {i+1}-{i+len(chunk_files)}: {chunk_files[0]} ... {chunk_files[-1]}')
        rc, msg = run_chunk(chunk_files, chunk_idx, args.timeout)
        print(f'[{chunk_idx}] Result: {msg}')
        # if timeout, suggest finer-grained run
        if rc == 124:
            print(f'Chunk {chunk_idx} timed out. To localize, re-run with --chunk-size=1 for this slice or run the log: {LOG_DIR / f"chunk_{chunk_idx:03d}.log"}')
            return 124
        # if non-zero rc, keep going but report so user can triage
        if rc != 0:
            print(f'Chunk {chunk_idx} had pytest failures (rc={rc}). Inspect log {LOG_DIR / f"chunk_{chunk_idx:03d}.log"}');
    print('All chunks completed (no timeouts).')
    if args.show_logs:
        print('--- Per-chunk logs ---')
        for f in sorted(LOG_DIR.glob('chunk_*.log')):
            print('\n' + '='*20 + f' {f.name} ' + '='*20)
            try:
                print(f.read_text(encoding='utf-8', errors='replace'))
            except Exception:
                pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
