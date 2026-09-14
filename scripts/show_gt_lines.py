from pathlib import Path
p = Path('data/benchmarking/benchmarks/benchmark_campaign_v3_10000_aligned/events.jsonl')
lines = p.read_text(encoding='utf-8').splitlines()
for idx, ln in enumerate(lines):
    if 'gt0-0' in ln:
        print('line', idx+1, ln)
