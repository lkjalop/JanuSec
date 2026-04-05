#!/usr/bin/env python3
from __future__ import annotations

"""Daily predictive LM risk generator (TFT-lite scaffold).

Reads recent alerts ring dump (when present) and produces per-entity
predictions under artifacts/predictive/lm_daily.jsonl for the dashboard.

Usage: python scripts/tft_lm_daily.py [--input path] [--output path]
"""

import argparse
import json
import os
from typing import Iterable

from src.analytics.tft_lm import compute_predictive_risk, write_predictions


def _read_events(input_path: str) -> Iterable[dict]:
    if not os.path.exists(input_path):
        return []
    with open(input_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default=os.getenv('PREDICTIVE_INPUT', 'artifacts/alerts/alerts.jsonl'))
    parser.add_argument('--output', default=os.getenv('PREDICTIVE_OUTPUT', 'artifacts/predictive/lm_daily.jsonl'))
    args = parser.parse_args()
    events = list(_read_events(args.input))
    risk = compute_predictive_risk(events)
    write_predictions(risk, args.output)
    print(f"Wrote {len(risk)} predictions to {args.output}")


if __name__ == '__main__':
    main()

