import json
import os
import sys

METRICS_PATH = os.environ.get('TFIDF_METRICS_PATH', 'data/tfidf_metrics.json')
MIN_PRECISION = float(os.environ.get('TFIDF_MIN_PRECISION', '0.6'))
MIN_RECALL = float(os.environ.get('TFIDF_MIN_RECALL', '0.35'))
FAIL_ON_MISSING = os.environ.get('TFIDF_FAIL_ON_MISSING', '0').lower() in {'1','true','yes'}

def main():
    if not os.path.exists(METRICS_PATH):
        msg = f'No metrics file found at {METRICS_PATH}'
        if FAIL_ON_MISSING:
            print(msg + ' — failing as configured')
            return 2
        print(msg + ' - skipping gating (no model trained)')
        return 0
    try:
        j = json.loads(open(METRICS_PATH, 'r', encoding='utf-8').read() or '{}')
    except Exception as e:
        print('Failed to read metrics:', e)
        return 2
    precision = j.get('precision')
    recall = j.get('recall')
    print('Loaded TF-IDF metrics:', j)
    # If metrics missing, treat as informational
    if precision is None or recall is None:
        print('Metrics incomplete (precision/recall missing) — skipping hard gate')
        return 0
    try:
        precision = float(precision)
        recall = float(recall)
    except Exception:
        print('Precision/recall not numeric — skipping hard gate')
        return 0

    failed = False
    if precision < MIN_PRECISION:
        print(f'Precision {precision:.3f} < required {MIN_PRECISION:.3f} — FAIL')
        failed = True
    else:
        print(f'Precision {precision:.3f} >= required {MIN_PRECISION:.3f} — OK')

    if recall < MIN_RECALL:
        print(f'Recall {recall:.3f} < required {MIN_RECALL:.3f} — FAIL')
        failed = True
    else:
        print(f'Recall {recall:.3f} >= required {MIN_RECALL:.3f} — OK')

    return 2 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
