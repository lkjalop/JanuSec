"""Generate synthetic benchmark datasets at scale and optional ground-truth incidents.

Creates datasets under `data/benchmarking/benchmarks/<name>/events.jsonl` and an optional `ground_truth.json` describing known chains.

Usage:
  python -m scripts.generate_synthetic_benchmarks --out-prefix benchmark_campaign_large --sizes 1000 10000 --with-ground-truth
"""
from __future__ import annotations
import argparse, json, random, time
from pathlib import Path

def gen_event(ts, host, process, src_ip, dst_ip, domain, file_hash):
    return {
        'timestamp': ts,
        'host': host,
        'process': process,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'domain': domain,
        'file_hash': file_hash
    }

def random_ip(octet_base=10):
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def gen_dataset(path: Path, n: int, seed: int = 42, with_ground_truth: bool = False, clustering: bool = False):
    random.seed(seed)
    path.mkdir(parents=True, exist_ok=True)
    ev_file = path / 'events.jsonl'
    gt = []
    hosts = [f'host{i}' for i in range(1, 201)]
    processes = ['powershell.exe','rundll32.exe','mshta.exe','cmd.exe','explorer.exe','python.exe','bash']
    domains = ['malicious.example','phish.example','benign.example','cdn.example']
    with ev_file.open('w', encoding='utf-8') as f:
        t0 = int(time.time())
        if clustering:
            # create temporal clusters: pick a subset of hosts and create bursts
            cluster_centers = random.sample(hosts, k=20)
            for i in range(n):
                ts = t0 + int(i/10)  # faster bursts
                if random.random() < 0.6:
                    host = random.choice(cluster_centers)
                else:
                    host = random.choice(hosts)
                proc = random.choice(processes)
                sip = random_ip()
                dip = random_ip(198)
                # correlated domain for cluster hosts
                domain = 'malicious.example' if host in cluster_centers and random.random() < 0.4 else random.choice(domains)
                # correlated file hashes across cluster to simulate staging
                if host in cluster_centers and random.random() < 0.3:
                    fh = f"clusterhash{random.choice(cluster_centers)}"
                else:
                    fh = f"hash{random.randint(100000,999999)}"
                ev = gen_event(ts, host, proc, sip, dip, domain, fh)
                f.write(json.dumps(ev) + '\n')
        else:
            for i in range(n):
                ts = t0 + i
                host = random.choice(hosts)
                proc = random.choice(processes)
                sip = random_ip()
                dip = random_ip(198)
                domain = random.choice(domains)
                fh = f"hash{random.randint(100000,999999)}"
                ev = gen_event(ts, host, proc, sip, dip, domain, fh)
                f.write(json.dumps(ev) + '\n')

        # optionally inject ground-truth incident chains (a small number)
        if with_ground_truth:
            # create 5 incidents spanning multiple events
            for incident_id in range(1,6):
                chain_hosts = random.sample(hosts, 4)
                chain_nodes = []
                for idx, h in enumerate(chain_hosts):
                    ts = t0 + n + incident_id*100 + idx
                    proc = random.choice(processes)
                    sip = random_ip()
                    dip = random_ip()
                    dom = 'malicious.example'
                    fh = f"gt{incident_id}-{idx}"
                    ev = gen_event(ts, h, proc, sip, dip, dom, fh)
                    f.write(json.dumps(ev) + '\n')
                    chain_nodes.append({'host': h, 'process': proc, 'timestamp': ts, 'file_hash': fh})
                gt.append({'incident_id': incident_id, 'chain': chain_nodes})

    if with_ground_truth:
        gt_file = path / 'ground_truth.json'
        gt_file.write_text(json.dumps(gt, indent=2), encoding='utf-8')
    print(f"Wrote dataset {path} (n={n}, gt={with_ground_truth})")


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out-prefix', default='benchmark_campaign_large')
    p.add_argument('--sizes', nargs='+', type=int, default=[1000,10000])
    p.add_argument('--seed', type=int, default=42)
    p.add_argument('--with-ground-truth', action='store_true')
    p.add_argument('--clustering', action='store_true', help='Enable temporal clustering and correlated events')
    args = p.parse_args()
    base = Path('data/benchmarking/benchmarks')
    for s in args.sizes:
        name = f"{args.out_prefix}_{s}"
        path = base / name
        gen_dataset(path, s, seed=args.seed, with_ground_truth=args.with_ground_truth, clustering=args.clustering)

if __name__ == '__main__':
    main()
