import sys, time, os
src_path = os.path.abspath('d:/AI/Threat_thy_sniffer/src')
print('DEBUG: src_path exists?', os.path.exists(src_path), 'src_path=', src_path)
sys.path.append(src_path)
print('DEBUG: sys.path last entries:', sys.path[-3:])
from src.correlation.temporal import TemporalCorrelator

c = TemporalCorrelator()
c.cooldown_seconds = 30
base = time.time()

def e(h, ts):
    return {'host': h, 'ts': ts}

nf1, d1 = c.ingest(e('h2', base), ['endpoint:rare_lineage'])
nf2, d2 = c.ingest(e('h2', base + 1), ['endpoint:lsass_access'])
nf3, d3 = c.ingest(e('h2', base + 2), ['net:beacon_periodic'])
print('1:', nf1, d1, '2:', nf2, d2, '3:', nf3, d3)

c.ingest(e('h2', base + 3), ['endpoint:rare_lineage'])
c.ingest(e('h2', base + 4), ['endpoint:lsass_access'])
nf4, d4 = c.ingest(e('h2', base + 5), ['net:beacon_periodic'])
print('4:', nf4, d4)

c.ingest(e('h2', base + 40), ['endpoint:rare_lineage'])
c.ingest(e('h2', base + 41), ['endpoint:lsass_access'])
nf5, d5 = c.ingest(e('h2', base + 42), ['net:beacon_periodic'])
print('5:', nf5, d5)
print('last_emit:', c.last_emit)
