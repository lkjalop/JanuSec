from collections import Counter
import re
p = r'd:\AI\Threat_thy_sniffer\batch_order.txt'
with open(p, 'rb') as f:
    raw = f.read()
text = raw.decode('utf-8', 'ignore')
counts = Counter()
for line in text.splitlines():
    line = line.strip()
    if not line:
        continue
    m = re.search(r':\s*(\d+)\s*$', line)
    if m:
        bid = int(m.group(1))
        counts[bid] += 1
# print sorted by count desc
items = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
print('batch_id,file_count')
for bid, cnt in items:
    print(f'{bid},{cnt}')
print('\nTotal batches:', len(counts))
print('Total files:', sum(counts.values()))
