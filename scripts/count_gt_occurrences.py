from pathlib import Path
p = Path('data/benchmarking/benchmarks/benchmark_campaign_v3_10000_aligned/events.jsonl')
text = p.read_text(encoding='utf-8')
for i in range(5):
    for j in range(2):
        h = f'gt{i}-{j}'
        cnt = text.count(h)
        print(h, cnt)
# print a few lines around first gt occurrence
for h in ['gt0-0','gt0-1']:
    idx = text.find(h)
    if idx!=-1:
        start = max(0, idx-200)
        print('\n--- snippet for', h)
        print(text[start:idx+200])
