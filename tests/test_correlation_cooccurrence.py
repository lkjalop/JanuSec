from __future__ import annotations
import os

from src.correlation.cooccurrence import CooccurrenceCorrelator


def test_cooccurrence_high_pmi_positive(monkeypatch):
    # Configure environment (must happen before instance use if relying on env vars)
    monkeypatch.setenv('COOCC_PMI_THRESHOLD','0.8')
    monkeypatch.setenv('COOCC_MIN_COUNT','3')
    c = CooccurrenceCorrelator()
    events = []
    # Event ordering crafted so that by the 3rd pair occurrence there are already 4 noise events,
    # producing PMI > 0.8 (k=3, noise=4 => ln((3*(7))/(3*3)) ~= 0.847)
    events.append(['alpha','beta'])  # pair 1
    for i in range(4):  # 4 noise events not containing alpha/beta
        events.append([f'noise{i}'])
    events.append(['alpha','beta'])  # pair 2
    events.append(['alpha','beta'])  # pair 3 -> should emit here
    emitted = 0
    total_delta = 0.0
    for idx, facs in enumerate(events):
        nf, d = c.ingest({'id': idx}, facs.copy())
        if nf:
            emitted += 1
            total_delta += d
    assert emitted == 1, f"Expected exactly one emission, got {emitted}"
    assert 0.0 < total_delta < 0.05  # sanity bound


def test_cooccurrence_high_pmi_negative(monkeypatch):
    monkeypatch.setenv('COOCC_PMI_THRESHOLD','0.8')
    monkeypatch.setenv('COOCC_MIN_COUNT','3')
    c = CooccurrenceCorrelator()
    events = []
    # Pair appears 3 times
    for i in range(3):
        events.append(['alpha','beta'])
    # Alpha alone 4 times
    for i in range(4):
        events.append(['alpha'])
    # Beta alone 4 times
    for i in range(4):
        events.append(['beta'])
    emitted = 0
    for idx, facs in enumerate(events):
        nf, d = c.ingest({'id': idx}, facs.copy())
        if nf:
            emitted += 1
    assert emitted == 0, "Did not expect high PMI emission in negative scenario"
