from __future__ import annotations
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict

async def compute_and_dump(window_days: int = 7):
    try:
        from src.repositories import decision_labels_repo
    except Exception:
        return False
    end_dt = datetime.utcnow()
    start_dt = end_dt - timedelta(days=window_days)
    try:
        agg = await decision_labels_repo.aggregate_daily(None, start_dt.isoformat(), end_dt.isoformat())
    except Exception:
        agg = []
    # Compute simple precision/recall from agg
    tp = sum(r.get('tp', 0) for r in agg)
    fp = sum(r.get('fp', 0) for r in agg)
    fn = sum(r.get('fn', 0) for r in agg)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else None
    out: Dict = {'window_days': window_days, 'tp': tp, 'fp': fp, 'fn': fn, 'precision': precision, 'recall': recall, 'as_of': end_dt.isoformat()}
    try:
        with open('data/metrics_labels.json', 'w', encoding='utf-8') as fh:
            json.dump(out, fh, indent=2)
    except Exception:
        pass
    return out

if __name__ == '__main__':
    asyncio.run(compute_and_dump())
