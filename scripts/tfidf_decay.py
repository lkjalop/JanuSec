#!/usr/bin/env python3
"""One-shot TF-IDF decay runner for cron/systemd.

Usage: python scripts/tfidf_decay.py --decay 0.95 --max-terms 3000
"""
from __future__ import annotations
import argparse
import os
from src.ml.tfidf_profile import GLOBAL_TFIDF_MANAGER


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--decay', type=float, default=None)
    p.add_argument('--max-terms', type=int, default=None)
    args = p.parse_args()
    GLOBAL_TFIDF_MANAGER.decay_and_persist_all(args.decay, args.max_terms)
    print('decay run complete')


if __name__ == '__main__':
    main()
