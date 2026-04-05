import json
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple

FEEDBACK_BATCH_DIR = Path(os.getenv('FEEDBACK_BATCH_DIR', 'data/feedback'))
FEEDBACK_ARCHIVE_DIR = FEEDBACK_BATCH_DIR / 'archive'
PRIORS_PATH = Path(os.getenv('FACTOR_PRIORS_PATH', 'data/priors.json'))
AUDIT_LOG = Path(os.getenv('FEEDBACK_AUDIT_LOG', 'data/feedback_audit.log'))


def _ensure_dirs():
    FEEDBACK_BATCH_DIR.mkdir(parents=True, exist_ok=True)
    FEEDBACK_ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    PRIORS_PATH.parent.mkdir(parents=True, exist_ok=True)


def _load_priors() -> Dict[str, Any]:
    if not PRIORS_PATH.exists():
        return {}
    try:
        with open(PRIORS_PATH, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_priors(p: Dict[str, Any]):
    with open(PRIORS_PATH, 'w', encoding='utf-8') as fh:
        json.dump(p, fh, indent=2)


def _append_audit(line: str):
    try:
        with open(AUDIT_LOG, 'a', encoding='utf-8') as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def _process_feedback_record(rec: Dict[str, Any], priors: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Apply a single feedback record to priors in-memory and return a proposal list.

    Supported feedback shapes (demo):
    - {'type':'weight_adjust','factor':'factor_name','delta':0.02}
    - {'type':'add_rule','rule':{...}}
    - {'type':'set_weight','factor':'f','value':0.12}
    Returns updated priors (in-memory) and a list of proposals applied.
    """
    proposals = []
    t = rec.get('type')
    if t == 'weight_adjust':
        f = rec.get('factor')
        d = float(rec.get('delta', 0.0))
        cur = float(priors.get('weights', {}).get(f, 0.0))
        new = max(0.0, min(1.0, cur + d))
        priors.setdefault('weights', {})[f] = new
        proposals.append({'action': 'weight_adjust', 'factor': f, 'from': cur, 'to': new})
    elif t == 'set_weight':
        f = rec.get('factor')
        v = float(rec.get('value', 0.0))
        cur = float(priors.get('weights', {}).get(f, 0.0))
        new = max(0.0, min(1.0, v))
        priors.setdefault('weights', {})[f] = new
        proposals.append({'action': 'set_weight', 'factor': f, 'from': cur, 'to': new})
    elif t == 'add_rule':
        rule = rec.get('rule') or {}
        repo = priors.setdefault('proposed_rules', [])
        repo.append(rule)
        proposals.append({'action': 'add_rule', 'rule_id': rule.get('meta', {}).get('id')})
    else:
        proposals.append({'action': 'noop', 'reason': 'unknown_feedback_type'})
    return priors, proposals


def process_batches(dry_run: bool = True) -> Dict[str, Any]:
    """Scan FEEDBACK_BATCH_DIR for .jsonl files, aggregate, and apply proposals.

    Returns a summary dict with counts and proposals. If dry_run, no priors file is written; only audit log updated.
    """
    _ensure_dirs()
    priors = _load_priors()
    summary = {'processed_files': [], 'records': 0, 'proposals': []}
    for p in sorted(FEEDBACK_BATCH_DIR.glob('*.jsonl')):
        if p.is_dir():
            continue
        processed = 0
        try:
            with open(p, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        _append_audit(f"{time.time()}: invalid_json_line in {p}: {line}")
                        continue
                    priors, proposals = _process_feedback_record(rec, priors)
                    processed += 1
                    summary['records'] += 1
                    summary['proposals'].extend(proposals)
                    _append_audit(f"{time.time()}: processed record from {p.name}: {proposals}")
        except Exception as e:
            _append_audit(f"{time.time()}: error reading {p}: {e}")
            continue
        summary['processed_files'].append({'file': str(p), 'records': processed})
        # Move processed file to archive with timestamp
        try:
            dst = FEEDBACK_ARCHIVE_DIR / f"{p.stem}.{int(time.time())}.jsonl"
            p.replace(dst)
        except Exception:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass

    if not dry_run:
        _save_priors(priors)
        _append_audit(f"{time.time()}: priors updated and saved with {len(summary['proposals'])} proposals")
    else:
        _append_audit(f"{time.time()}: dry_run processed {summary['records']} records; proposals: {len(summary['proposals'])}")

    return summary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Process feedback batches and apply proposals to priors')
    parser.add_argument('--apply', action='store_true', help='Apply proposals to priors (writes priors file)')
    parser.add_argument('--dir', type=str, default=None, help='Feedback batch dir')
    args = parser.parse_args()
    if args.dir:
        FEEDBACK_BATCH_DIR = Path(args.dir)
    summary = process_batches(dry_run=not args.apply)
    print('Summary:', json.dumps(summary, indent=2))
