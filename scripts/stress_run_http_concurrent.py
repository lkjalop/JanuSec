"""Concurrent end-to-end HTTP stress runner with APT injection and reconstruction checks.

Usage: python scripts/stress_run_http_concurrent.py --batches 800 --batch-size 300 --concurrency 6 --apt-per-10k 4
"""
import os
import sys
import time
import json
import hmac
import hashlib
import threading
import queue
from random import randint

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from src.api.app import app
from src.graph.hopgraph import GLOBAL_HOPGRAPH

# XDR queue lives in integrations_endpoints
try:
    from src.api.integrations_endpoints import _XDR_EVENT_QUEUE
except Exception:
    _XDR_EVENT_QUEUE = None
def make_event(i, host=None, attack_id=None, step=None):
    ev = {'id': f'evt-{i}', 'timestamp': time.time()}
    if host:
        ev['src_host'] = host
    # Add some realistic fields
    ev['process'] = f'proc-{i%500}'
    ev['pid'] = i % 65535
    ev['src_ip'] = f'10.1.{i%255}.{i%255}'
    ev['dst_ip'] = f'10.2.{(i+7)%255}.{(i+13)%255}'
    if attack_id is not None:
        ev['attack_id'] = attack_id
        ev['attack_step'] = step
    return ev


def hmac_sig(secret: str, body: bytes, ts: str) -> str:
    return hmac.new(secret.encode('utf-8'), msg=ts.encode('utf-8') + b'.' + body, digestmod=hashlib.sha256).hexdigest()


class PosterThread(threading.Thread):
    def __init__(self, task_q, out_q, secret, integrator_id):
        super().__init__(daemon=True)
        self.task_q = task_q
        self.out_q = out_q
        self.secret = secret
        self.integrator_id = integrator_id

    def run(self):
        client = TestClient(app)
        while True:
            try:
                batch_idx, body = self.task_q.get(timeout=1.0)
            except queue.Empty:
                return
            ts = str(int(time.time()))
            sig = hmac_sig(self.secret, body, ts)
            headers = {
                'X-Integrator-ID': self.integrator_id,
                'X-Signature': sig,
                'X-Timestamp': ts,
                'Content-Type': 'application/json'
            }
            try:
                r = client.post('/api/v1/integrations/xdr/webhook', data=body, headers=headers)
                self.out_q.put((batch_idx, r.status_code, r.text))
            except Exception as e:
                self.out_q.put((batch_idx, 0, str(e)))
            finally:
                self.task_q.task_done()


def drain_xdr_queue_to_hopgraph(limit=None):
    if _XDR_EVENT_QUEUE is None:
        return 0
    # Diagnostic: report qsize before attempting to drain so we can tell
    # whether items still sit in the queue or were consumed by a worker.
    try:
        qsize = _XDR_EVENT_QUEUE.qsize()
    except Exception:
        qsize = None
    print(f"DEBUG: _XDR_EVENT_QUEUE.qsize() before drain: {qsize}")
    drained = 0
    while True:
        try:
            item = _XDR_EVENT_QUEUE.get_nowait()
        except Exception:
            break
        # item expected to be {'integrator_id':..., 'events': [...]}
        for ev in item.get('events', []) if isinstance(item.get('events'), list) else []:
            try:
                GLOBAL_HOPGRAPH.ingest_event(ev, source='xdr')
            except Exception:
                pass
        drained += 1
        if limit and drained >= limit:
            break
    return drained


def reconstruct_check(apt_hosts):
    results = {}
    for host, meta in apt_hosts.items():
        start = f'host:{host}'
        try:
            ex = GLOBAL_HOPGRAPH.explain_chain(start=start, max_depth=6, beam_width=8, top_k=3)
            # simple check: any chain containing nodes with attack_id in node attrs
            found = False
            for ch in ex.get('chains', []):
                for hop in ch.get('hops', []):
                    if hop.get('dst') and str(meta['attack_id']) in str(hop.get('dst')):
                        found = True
            results[host] = {'found': found, 'explain': ex}
        except Exception as e:
            results[host] = {'found': False, 'error': str(e)}
    return results


def ewma_summary(apt_timestamps, total_steps, alpha=0.3, thresh=0.5, cooldown=10):
    # Construct per-step binary sequence (1 if attack occurred during that step)
    seq = [0] * total_steps
    for ts in apt_timestamps:
        if ts < total_steps:
            seq[ts] = 1
    prev = 0.0
    last_alert = -9999
    tp = fp = fn = tn = 0
    for i, v in enumerate(seq):
        prev = (1-alpha) * prev + alpha * v
        alerted = False
        if prev >= thresh and (i - last_alert) >= cooldown:
            alerted = True
            last_alert = i
        if alerted and v == 1:
            tp += 1
        elif alerted and v == 0:
            fp += 1
        elif (not alerted) and v == 1:
            fn += 1
        else:
            tn += 1
    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn}


def main(batches=800, batch_size=300, concurrency=6, apt_per_10k=4, apt_chain_len=6):
    total_events = batches * batch_size
    print('HTTP concurrent stress: batches', batches, 'batch_size', batch_size, 'concurrency', concurrency, 'total_events', total_events)

    # Register integrator
    client = TestClient(app)
    integrator_id = f'stress-{int(time.time())}'
    r = client.post(f'/api/v1/integrations/xdr/register?integrator_id={integrator_id}')
    if r.status_code != 200:
        print('register failed', r.status_code, r.text); return
    secret = r.json().get('secret')
    # NOTE: do not prevent the XDR worker from starting; allow normal worker path
    # so that ingestion follows production-like flow (the worker will now also
    # ingest into GLOBAL_HOPGRAPH via integrations_endpoints._xdr_worker).

    # Build batch tasks with APT injection
    task_q = queue.Queue()
    out_q = queue.Queue()
    apt_hosts = {}  # host -> {attack_id, batch_idx, ts_step}
    apt_timestamps = []
    step = 0
    attack_counter = 0
    for b in range(batches):
        events = []
        # Determine whether this batch will carry APT injections
        # compute how many 10k groups passed so far
        tenk_group = (b * batch_size) // 10000
        # probability or deterministic distribution: place apt_per_10k per 10k evenly
        # we'll inject when (b*batch_size) % 10000 crosses thresholds
        base_idx = b * batch_size
        # generate normal events
        for i in range(batch_size):
            events.append(make_event(base_idx + i))
        # APT injection: if this batch spans a multiple of 10k, inject apt_per_10k chains
        # compute how many apt chains should be injected for this batch
        inject_count = 0
        # If the batch contains any index where (index % 10000) < batch_size and index//10000 changed
        # simpler: evenly distribute approximate total apt count
        total_apt_expected = max(1, (total_events // 10000) * apt_per_10k)
        # spread them across batches: inject when attack_counter < total_apt_expected and when b % max(1, batches//total_apt_expected)==0
        spacing = max(1, batches // max(1, total_apt_expected))
        if (b % spacing == 0) and attack_counter < total_apt_expected:
            inject_count = min(apt_per_10k, total_apt_expected - attack_counter)
        # inject chains
        for j in range(inject_count):
            attack_id = f'apt-{int(time.time())}-{attack_counter}'
            root_host = f'host:apt-{attack_counter}'
            # build multi-step chain events and append to events (order preserved)
            for s in range(apt_chain_len):
                ev = make_event(base_idx + len(events) + s, host=f'apt-{attack_counter}', attack_id=attack_id, step=s)
                events.append(ev)
            apt_hosts[root_host] = {'attack_id': attack_id, 'batch_idx': b}
            apt_timestamps.append(b)  # coarse timestamp per batch index
            attack_counter += 1

        body = json.dumps({'events': events}).encode('utf-8')
        task_q.put((b, body))

    # Start posters
    threads = []
    for _ in range(concurrency):
        t = PosterThread(task_q, out_q, secret, integrator_id)
        t.start()
        threads.append(t)

    start = time.time()
    task_q.join()
    duration = time.time() - start
    print('Posting complete in', duration, 's')

    # collect results
    statuses = []
    while not out_q.empty():
        statuses.append(out_q.get())

    # Drain the XDR async queue into HopGraph
    drained = drain_xdr_queue_to_hopgraph()
    print('Drained XDR queued batches into HopGraph:', drained)

    # Reconstruction checks
    recon = reconstruct_check(apt_hosts)
    recon_pass = sum(1 for v in recon.values() if v.get('found'))
    recon_fail = len(recon) - recon_pass

    # EWMA summary using batch-level timestamps
    ewma = ewma_summary(apt_timestamps, total_steps=batches, alpha=0.3, thresh=0.5, cooldown=10)

    artifacts_dir = 'artifacts'
    os.makedirs(artifacts_dir, exist_ok=True)
    with open(os.path.join(artifacts_dir, 'stress_http_log.json'), 'w', encoding='utf-8') as fh:
        json.dump({'statuses': statuses}, fh)
    with open(os.path.join(artifacts_dir, 'apt_reconstructions.json'), 'w', encoding='utf-8') as fh:
        json.dump({'recon': recon, 'pass': recon_pass, 'fail': recon_fail}, fh)
    with open(os.path.join(artifacts_dir, 'ewma_summary.json'), 'w', encoding='utf-8') as fh:
        json.dump(ewma, fh)

    print('Recon pass/fail:', recon_pass, recon_fail)
    print('EWMA summary:', ewma)


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--batches', type=int, default=800)
    p.add_argument('--batch-size', type=int, default=300)
    p.add_argument('--concurrency', type=int, default=6)
    p.add_argument('--apt-per-10k', type=int, default=4)
    args = p.parse_args()
    main(batches=args.batches, batch_size=args.batch_size, concurrency=args.concurrency, apt_per_10k=args.apt_per_10k)
