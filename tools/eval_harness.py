#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

# Minimal evaluation harness scaffold
# - Reads fixtures from tools/fixtures/{pos,neg,gray}
# - Sends events through hunters/pipeline (simplified call path) and computes FP/1k, Recall, Gray Recall

FIXTURE_ROOT = Path(__file__).parent / 'fixtures'
OUT_DIR = Path(__file__).parent / 'out'


def _load_events(dir_name: str) -> List[dict]:
    d = FIXTURE_ROOT / dir_name
    if not d.exists():
        return []
    out: List[dict] = []
    for p in sorted(d.glob('*.json')):
        try:
            out.append(json.loads(p.read_text(encoding='utf-8')))
        except Exception:
            pass
    return out


def _score_event(evt: dict) -> Dict[str, Any]:
    # Simplified scoring: run network/endpoint hunters and aggregate confidence
    try:
        from src.modules.network_hunter import NetworkThreatHunter
        from src.modules.endpoint_hunter import EndpointHunter
    except Exception:
        return {'factors': [], 'confidence_delta': 0.0}
    nh = NetworkThreatHunter({})
    eh = EndpointHunter({})
    # Note: in the full pipeline there are more stages; this is a minimal proxy
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        nres = loop.run_until_complete(nh.analyze_event(dict(evt)))
        eres = loop.run_until_complete(eh.analyze_event(dict(evt)))
    finally:
        loop.close()
    factors = list(set((nres.get('factors') or []) + (eres.get('factors') or [])))
    conf = float(nres.get('confidence_delta') or 0.0) + float(eres.get('confidence_delta') or 0.0)
    return {'factors': factors, 'confidence_delta': conf}


def main():
    pos = _load_events('pos')
    neg = _load_events('neg')
    gray = _load_events('gray')
    scored = {
        'pos': [_score_event(e) for e in pos],
        'neg': [_score_event(e) for e in neg],
        'gray': [_score_event(e) for e in gray],
    }
    # Simple thresholds for metrics
    THRESH = float(os.getenv('EVAL_THRESHOLD', '0.5'))
    tp = sum(1 for r in scored['pos'] if (r.get('confidence_delta') or 0.0) >= THRESH)
    fn = len(scored['pos']) - tp
    fp = sum(1 for r in scored['neg'] if (r.get('confidence_delta') or 0.0) >= THRESH)
    tn = len(scored['neg']) - fp
    gp = sum(1 for r in scored['gray'] if (r.get('confidence_delta') or 0.0) >= THRESH)
    # Metrics
    recall = tp / max(1, (tp + fn))
    fp_per_1k = (fp / max(1, len(scored['neg']))) * 1000.0
    gray_recall = gp / max(1, len(scored['gray']))
    out = {
        'ts': time.time(),
        'counts': {'pos': len(pos), 'neg': len(neg), 'gray': len(gray)},
        'metrics': {'recall': recall, 'fp_per_1k': fp_per_1k, 'gray_recall': gray_recall},
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / 'eval_snapshot.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
    # Optional: Prometheus counters (best-effort)
    try:
        from src.api.metrics_init import REGISTRY
        from prometheus_client import Gauge
        g_recall = Gauge('eval_recall', 'Evaluation recall', registry=REGISTRY)
        g_fp1k = Gauge('eval_fp_per_1k', 'Evaluation false positives per 1000', registry=REGISTRY)
        g_gray = Gauge('eval_gray_recall', 'Evaluation gray recall', registry=REGISTRY)
        g_recall.set(recall); g_fp1k.set(fp_per_1k); g_gray.set(gray_recall)
    except Exception:
        pass
    print(json.dumps(out))


if __name__ == '__main__':
    main()
