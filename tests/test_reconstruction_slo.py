"""Regression SLO test for attack reconstruction metrics.

Reads a previously generated evaluation JSON (path via EVAL_RESULT_PATH env or default) and asserts
minimum recall / sequence_score thresholds defined in environment or settings module.
"""
from __future__ import annotations
import os, json, pytest
from pathlib import Path

MIN_RECALL = float(os.getenv('HOPGRAPH_MIN_RECALL','0.35'))
MIN_SEQUENCE = float(os.getenv('HOPGRAPH_MIN_SEQUENCE_SCORE','0.24'))
RESULT_PATH = Path(os.getenv('EVAL_RESULT_PATH','data/benchmarking/latest_eval.json'))

@pytest.mark.skipif(not RESULT_PATH.exists(), reason='evaluation result file missing')
def test_reconstruction_slo():
    data = json.loads(RESULT_PATH.read_text(encoding='utf-8'))
    recall = float(data.get('recall_mean') or 0.0)
    seq = float(data.get('sequence_score_mean') or 0.0)
    assert recall >= MIN_RECALL, f"Recall {recall:.3f} below minimum {MIN_RECALL:.3f}"
    assert seq >= MIN_SEQUENCE, f"Sequence score {seq:.3f} below minimum {MIN_SEQUENCE:.3f}"
