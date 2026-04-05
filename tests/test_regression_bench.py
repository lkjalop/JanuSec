import json
from pathlib import Path


def test_benchmark_regression():
    baseline = Path('data/benchmarking/results/baseline_v3_metrics.json')
    current = Path('data/benchmarking/results/v3_10000_aligned_top10_d8_bw20_gtseq_v4.json')
    if not baseline.exists():
        # No baseline stored; create a placeholder and skip the test
        print('No baseline found; skipping regression test. To enable, provide baseline_v3_metrics.json')
        return
    if not current.exists():
        raise AssertionError('Current metrics not found; run evaluation before CI')
    b = json.loads(baseline.read_text(encoding='utf-8'))
    c = json.loads(current.read_text(encoding='utf-8'))
    # tolerances
    assert c.get('recall_mean', 0) >= b.get('recall_mean', 0) - 0.02, f"Recall dropped below tolerance: {c.get('recall_mean')} vs {b.get('recall_mean')}"
    assert c.get('sequence_score_mean', 0) >= b.get('sequence_score_mean', 0) - 0.04, f"Sequence score dropped below tolerance: {c.get('sequence_score_mean')} vs {b.get('sequence_score_mean')}"
