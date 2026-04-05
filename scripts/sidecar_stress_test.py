"""Sidecar Stress Test Harness

Generates permutations of hunt sessions to exercise:
- Windows: [3,24,72,120]
- model_enabled: [False, True]
- async_run: [False, True]
- replay after completion
- budget gating rejection paths
Captures basic metrics snapshot deltas (if Prometheus /metrics endpoint reachable).

Usage:
  python -m scripts.sidecar_stress_test --base-url http://localhost:8000 --runs 2
"""
from __future__ import annotations
import argparse, time, itertools, json, random, sys
from urllib import request, parse

DEF_WINDOWS = [3,24,72,120]

def _post_json(base_url, path, payload):
    data = json.dumps(payload).encode('utf-8')
    req = request.Request(base_url+path, data=data, headers={'Content-Type':'application/json'})
    with request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode('utf-8'))

def _get_json(base_url, path):
    with request.urlopen(base_url+path, timeout=30) as r:
        ct = r.read().decode('utf-8')
        try:
            return json.loads(ct)
        except Exception:
            return ct

def run(base_url: str, runs: int):
    summary = []
    combos = list(itertools.product(DEF_WINDOWS, [False, True], [False, True]))
    random.shuffle(combos)
    combos = combos[: max(1, min(len(combos), runs*4))]
    for idx,(win, model_flag, async_flag) in enumerate(combos):
        sid = f"stress_{idx}_{win}_{int(time.time())}"
        payload = { 'session_id': sid, 'window_hours': win, 'model_enabled': model_flag, 'async_run': async_flag }
        print('START', payload)
        resp = _post_json(base_url, '/hunts/start', payload)
        if async_flag:
            # Poll progress
            for _ in range(20):
                prog = _get_json(base_url, f'/hunts/session/{sid}/progress')
                if prog.get('status') == 'COMPLETE':
                    break
                time.sleep(0.2)
        rep = _get_json(base_url, f'/hunts/report/{sid}')
        # Replay
        replay_resp = _post_json(base_url, f'/hunts/replay/{sid}', {})
        rsid = replay_resp['session_id']
        rrep = _get_json(base_url, f'/hunts/report/{rsid}')
        summary.append({
            'session': sid,
            'window': win,
            'model': model_flag,
            'async': async_flag,
            'delta_pct': rep['report']['delta_pct'] if isinstance(rep, dict) else None,
            'replay_of': rrep.get('report',{}).get('replay_of') if isinstance(rrep, dict) else None
        })
    # Gating test (very small budget)
    try:
        _post_json(base_url, '/hunts/start', {
            'session_id': 'gating_fail','window_hours':24,'model_enabled':False,'budget_cap_units':0.01
        })
    except Exception:
        summary.append({'gating':'rejected'})
    # Accuracy history & overview
    acc = _get_json(base_url,'/finops/accuracy')
    ov = _get_json(base_url,'/finops/overview')
    out = {'summary': summary, 'accuracy_history': acc, 'overview': ov}
    print(json.dumps(out, indent=2))
    return out

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--base-url', default='http://localhost:8000')
    ap.add_argument('--runs', type=int, default=2)
    args = ap.parse_args()
    run(args.base_url.rstrip('/'), args.runs)
