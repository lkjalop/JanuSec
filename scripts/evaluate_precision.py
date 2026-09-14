"""Evaluate precision/recall/F1 using labeled events and in-process orchestrator.

Usage:
  python scripts/evaluate_precision.py --file tests/fixtures/labeled_events.jsonl --threshold 0.6
"""
from __future__ import annotations
import argparse, json, asyncio, statistics
from typing import List, Dict, Any

async def evaluate(path: str, threshold: float, persist: bool):
    from main import SecurityOrchestrator
    orch = SecurityOrchestrator()
    await orch.initialize()
    y_true: List[int] = []
    y_pred: List[int] = []
    with open(path,'r',encoding='utf-8') as f:
        for line in f:
            line=line.strip()
            if not line: continue
            ev = json.loads(line)
            label = 1 if ev.get('label')=='malicious' else 0
            # Remove label before processing
            proc_event = {k:v for k,v in ev.items() if k!='label'}
            res = await orch.process_event(proc_event)
            pred = 1 if res.confidence >= threshold else 0
            y_true.append(label); y_pred.append(pred)
    await orch.shutdown()
    tp = sum(1 for t,p in zip(y_true,y_pred) if t==1 and p==1)
    fp = sum(1 for t,p in zip(y_true,y_pred) if t==0 and p==1)
    fn = sum(1 for t,p in zip(y_true,y_pred) if t==1 and p==0)
    tn = sum(1 for t,p in zip(y_true,y_pred) if t==0 and p==0)
    precision = tp / (tp+fp) if (tp+fp)>0 else 0.0
    recall = tp / (tp+fn) if (tp+fn)>0 else 0.0
    f1 = 2*precision*recall/(precision+recall) if (precision+recall)>0 else 0.0
    result = {
        'threshold': threshold,
        'counts': {'tp':tp,'fp':fp,'tn':tn,'fn':fn},
        'precision': precision,
        'recall': recall,
        'f1': f1
    }
    if persist:
        try:
            from repositories import precision_runs_repo
            result['source_file'] = path
            await precision_runs_repo.insert_run(result)
        except Exception:
            pass
    return result

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', default='tests/fixtures/labeled_events.jsonl')
    ap.add_argument('--threshold', type=float, default=0.6)
    ap.add_argument('--persist', action='store_true')
    args = ap.parse_args()
    res = await evaluate(args.file, args.threshold, args.persist)
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    asyncio.run(main())
