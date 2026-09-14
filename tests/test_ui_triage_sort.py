import pytest

from pathlib import Path
import json

# This test validates the triage-based sort decision used by the frontend logic.
# It's a pure-Python logic check that mimics the compare used in csv_analyzer.js

def triage_key(record):
    # emulate the JS behavior: prefer record.triage_score then _pipeline_row.triage_score then 0
    if record is None:
        return 0
    if isinstance(record.get('triage_score'), (int, float)):
        return float(record.get('triage_score'))
    pr = record.get('_pipeline_row') or {}
    if isinstance(pr.get('triage_score'), (int, float)):
        return float(pr.get('triage_score'))
    return 0.0


def test_triasge_sort_orders_by_triage():
    rows = [
        {'row_index': 0, 'triage_score': 0.2},
        {'row_index': 1, 'triage_score': 0.9},
        {'row_index': 2, '_pipeline_row': {'triage_score': 0.5}},
        {'row_index': 3},
        {'row_index': 4, 'triage_score': 0.9},
    ]
    # expected order: 1 and 4 (0.9) first (preserve relative order among equal scores), then 2 (0.5), then 0 (0.2), then 3 (0)
    sorted_rows = sorted(rows, key=lambda r: (-triage_key(r), r.get('row_index')))
    expected = [1, 4, 2, 0, 3]
    assert [r['row_index'] for r in sorted_rows] == expected