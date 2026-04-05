import sys
from pathlib import Path as _Path
sys.path.append(str(_Path('src').resolve()))

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

os.environ.setdefault('ENABLE_DB_FALLBACK', '1')
os.environ.setdefault('DB_FALLBACK_PATH', 'data/cache/dev_fallback.sqlite')

from src.main import SecurityOrchestrator

BENIGN_THRESHOLD_DEFAULT = 0.1


def row_to_event(row: pd.Series, idx: int) -> Dict[str, Any]:
    event: Dict[str, Any] = {}
    sha256 = row.get('sha256')
    md5 = row.get('md5')
    raw_id = row.get('id')
    event_id = None
    for candidate in (sha256, md5, raw_id):
        if isinstance(candidate, str) and candidate.strip():
            event_id = candidate.strip()
            break
    if not event_id:
        event_id = f"cybstash2-{idx}"
    event['id'] = event_id
    name = row.get('name')
    if isinstance(name, str) and name.strip():
        event['process_name'] = name.strip()
    path = row.get('path')
    if isinstance(path, str) and path.strip():
        event['path'] = path.strip()
        if 'process_name' not in event:
            event['process_name'] = Path(path.strip()).name
    signed = row.get('signed')
    if pd.notna(signed):
        try:
            event['signed'] = bool(int(signed))
            event['signature_valid'] = bool(int(signed))
        except Exception:
            event['signed'] = bool(signed)
            event['signature_valid'] = bool(signed)
    event['threat_score'] = float(row.get('threatScore') or 0.0)
    event['threat_weight'] = float(row.get('threatWeight') or 0.0)
    event['flag_name'] = row.get('flagName')
    event['flag_color'] = row.get('flagColor')
    event['flag_weight'] = row.get('flagWeight')
    event['av_hits'] = int(row.get('avPositives') or 0)
    event['av_total'] = int(row.get('avTotal') or 0)
    suspicious = bool(row.get('suspicious'))
    event['expected_verdict'] = 'malicious' if suspicious else 'benign'
    event['source_dataset'] = 'cyberstash_csv2'
    return event


def path_row_to_event(path_value: Any, idx: int) -> Dict[str, Any]:
    path_str = str(path_value).strip()
    event_id = f"cybstash1-{idx}"
    event: Dict[str, Any] = {
        'id': event_id,
        'path': path_str,
        'process_name': Path(path_str).name,
        'source_dataset': 'cyberstash_csv1'
    }
    return event


def summarize_metrics(metrics: Dict[str, int]) -> Dict[str, Any]:
    tp = metrics.get('tp', 0)
    fp = metrics.get('fp', 0)
    fn = metrics.get('fn', 0)
    tn = metrics.get('tn', 0)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    return {
        'counts': metrics,
        'precision': precision,
        'recall': recall,
        'false_positive_rate': fpr,
    }


async def evaluate() -> Dict[str, Any]:
    orchestrator = SecurityOrchestrator()
    await orchestrator.initialize()
    pipeline = orchestrator.event_pipeline
    decision_engine = orchestrator.decision_engine
    config_confidence = orchestrator.config.get('confidence', {}) if hasattr(orchestrator.config, 'get') else {}
    if hasattr(config_confidence, 'benign_threshold'):
        benign_threshold = float(getattr(config_confidence, 'benign_threshold', BENIGN_THRESHOLD_DEFAULT))
    else:
        benign_threshold = float(config_confidence.get('benign_threshold', BENIGN_THRESHOLD_DEFAULT))

    dataset2 = pd.read_excel('dump/Cyberstash_csv2.xlsx')
    results2: List[Dict[str, Any]] = []
    metrics = {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0}

    for idx, row in dataset2.iterrows():
        event = row_to_event(row, idx)
        pipe_result = await pipeline.process_event(event)
        decision = await decision_engine.make_decision(pipe_result)
        flagged = pipe_result.confidence > benign_threshold
        expected = event.get('expected_verdict')
        if expected == 'malicious':
            if flagged:
                metrics['tp'] += 1
            else:
                metrics['fn'] += 1
        elif expected == 'benign':
            if flagged:
                metrics['fp'] += 1
            else:
                metrics['tn'] += 1
        results2.append({
            'id': pipe_result.event_id,
            'name': event.get('process_name'),
            'path': event.get('path'),
            'confidence': pipe_result.confidence,
            'verdict': decision.verdict,
            'decision_path': decision.path,
            'factors': pipe_result.factors[:12],
            'expected': expected,
            'threat_score': event.get('threat_score'),
        })

    dataset1 = pd.read_excel('dump/cybstash csv1.xlsx')
    results1: List[Dict[str, Any]] = []
    for idx, row in dataset1.iterrows():
        path_value = row.get('path') if isinstance(row, pd.Series) else row
        event = path_row_to_event(path_value, idx)
        pipe_result = await pipeline.process_event(event)
        decision = await decision_engine.make_decision(pipe_result)
        results1.append({
            'id': pipe_result.event_id,
            'path': event.get('path'),
            'name': event.get('process_name'),
            'confidence': pipe_result.confidence,
            'verdict': decision.verdict,
            'decision_path': decision.path,
            'factors': pipe_result.factors[:10],
        })

    allowlist_metrics: Dict[str, float] = {}
    try:
        counter = pipeline.__class__.allowlist_hits
        families = counter.collect()
        if families:
            for sample in families[0].samples:
                label = sample.labels.get('category', 'total')
                allowlist_metrics[label] = sample.value
    except Exception:
        pass

    await orchestrator.shutdown()

    summary = {
        'dataset2': {
            'total': len(results2),
            'metrics': summarize_metrics(metrics),
            'top_results': sorted(results2, key=lambda r: r['confidence'], reverse=True)[:20],
        },
        'dataset1': {
            'total': len(results1),
            'top_results': sorted(results1, key=lambda r: r['confidence'], reverse=True)[:20],
        },
        'allowlist_metrics': allowlist_metrics,
        'benign_threshold': benign_threshold,
    }
    return summary


if __name__ == '__main__':
    summary = asyncio.run(evaluate())
    print(json.dumps(summary, indent=2))
