#!/usr/bin/env python3
"""Backup and prune integrity-logged artifacts (alerts/evidence JSONL + hash chains).

Features:
- Copies source directory (default data/) selectable via --src to a target snapshot dir (default backups/DATE_HHMMSS)
- Optionally gzip large JSONL files (--gzip-threshold N MB) and produce .gz in snapshot
- Generates SHA256 manifest.json with per-file hashes and total bytes
- Verifies (hash compare) optionally when --verify
- Prunes old snapshots keeping N most recent (--retain N)
- Dry-run mode (--dry-run) prints planned actions

Intended to run via cron or scheduled task.
"""
from __future__ import annotations
import argparse, os, sys, shutil, hashlib, json, time, gzip
from datetime import datetime
from pathlib import Path

def sha256_file(path: Path, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            b = f.read(chunk)
            if not b: break
            h.update(b)
    return h.hexdigest()

def copy_tree(src: Path, dst: Path, gzip_threshold_mb: float | None, dry: bool, log):
    manifest = { 'files': [], 'generated': time.time() }
    total = 0
    for root, _dirs, files in os.walk(src):
        for name in files:
            sp = Path(root)/name
            rel = sp.relative_to(src)
            dp = dst/rel
            dp.parent.mkdir(parents=True, exist_ok=True)
            size_mb = sp.stat().st_size / (1024*1024)
            do_gzip = gzip_threshold_mb is not None and size_mb >= gzip_threshold_mb and sp.suffix in ('.jsonl','.log')
            out_path = dp
            if do_gzip:
                out_path = dp.with_suffix(dp.suffix + '.gz')
            if dry:
                log(f"COPY {sp} -> {out_path} ({'gzip' if do_gzip else 'plain'})")
            else:
                if do_gzip:
                    with sp.open('rb') as fin, gzip.open(out_path,'wb', compresslevel=6) as fout:
                        shutil.copyfileobj(fin, fout)
                else:
                    shutil.copy2(sp, out_path)
            h = 'DRY' if dry else sha256_file(out_path)
            entry = { 'path': str(rel) + ('.gz' if do_gzip else ''), 'sha256': h, 'size': sp.stat().st_size }
            manifest['files'].append(entry)
            total += sp.stat().st_size
    manifest['total_bytes'] = total
    if not dry:
        (dst/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest

def verify_snapshot(snapshot: Path, log):
    mf = snapshot/'manifest.json'
    if not mf.exists():
        raise SystemExit('manifest.json missing for snapshot')
    data = json.loads(mf.read_text(encoding='utf-8'))
    mismatches = []
    for f in data.get('files', []):
        p = snapshot/f['path']
        if not p.exists():
            mismatches.append((f['path'],'missing'))
            continue
        calc = sha256_file(p)
        if calc != f['sha256']:
            mismatches.append((f['path'],'hash_mismatch'))
    return mismatches

def prune_backups(base: Path, retain: int, dry: bool, log):
    snaps = [p for p in base.iterdir() if p.is_dir()]
    snaps.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for s in snaps[retain:]:
        if dry:
            log(f"PRUNE {s}")
        else:
            shutil.rmtree(s, ignore_errors=True)

def main():
    ap = argparse.ArgumentParser(description='Backup detection artifacts with integrity manifest.')
    ap.add_argument('--src','--source', dest='src', default='data', help='Source data directory (default data)')
    ap.add_argument('--dest', default='backups', help='Destination base directory')
    ap.add_argument('--gzip-threshold', type=float, default=None, help='Gzip files >= threshold MB (only jsonl/log)')
    ap.add_argument('--retain', type=int, default=7, help='Number of recent snapshots to retain')
    ap.add_argument('--verify','--verify-chain', dest='verify', action='store_true', help='Verify hashes after write')
    ap.add_argument('--dry-run', action='store_true', help='Print planned actions only')
    ap.add_argument('--quiet', action='store_true', help='Minimal output')
    args = ap.parse_args()
    def log(msg: str):
        if not args.quiet:
            print(msg, file=sys.stderr)
    src = Path(args.src)
    if not src.exists():
        log(f"Source {src} missing")
        return 1
    base = Path(args.dest)
    base.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    snapshot = base/ts
    if snapshot.exists():
        log('Snapshot path already exists, aborting')
        return 2
    if not args.dry_run:
        snapshot.mkdir(parents=True, exist_ok=False)
    log(f"Creating snapshot at {snapshot}")
    manifest = copy_tree(src, snapshot, args.gzip_threshold, args.dry_run, log)
    if args.verify and not args.dry_run:
        mismatches = verify_snapshot(snapshot, log)
        if mismatches:
            log(f"Verification mismatches: {mismatches}")
            return 3
        log('Verification OK')
    prune_backups(base, args.retain, args.dry_run, log)
    if not args.quiet:
        print(json.dumps({'snapshot': str(snapshot), 'file_count': len(manifest['files']), 'total_bytes': manifest['total_bytes']}))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
