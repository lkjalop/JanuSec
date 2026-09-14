"""CLI to trigger feedback quality recompute and print metadata."""
from __future__ import annotations
import os
import sys
from src.feedback.store import GLOBAL_FEEDBACK_STORE

def main():
    print('Triggering feedback quality recompute...')
    try:
        GLOBAL_FEEDBACK_STORE.recompute_quality()
        meta = GLOBAL_FEEDBACK_STORE.quality_metadata()
        print('Recompute done:')
        for k,v in meta.items():
            print(f'  {k}: {v}')
        return 0
    except Exception as exc:
        print('Recompute failed:', exc)
        return 2

if __name__ == '__main__':
    sys.exit(main())
