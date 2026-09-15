import sys, time, os
sys.path.append(os.path.abspath('d:/AI/Threat_thy_sniffer/src'))
from src.correlation.temporal import TemporalCorrelator

c = TemporalCorrelator()
c.cooldown_seconds = 30
base = time.time()

def e(h, ts, factors):
    return {'host': h, 'ts': ts}, factors

def dump(ent):
    dq = c.events[ent]
    print('DQ len:', len(dq))
    for t, fs in dq:
        print('  ts=', round(t,2), 'factors=', fs)
    print('last_emit for', ent, '=', c.last_emit.get(ent))

ent = 'h2'

print('--- first sequence ---')
for i, (ev_f) in enumerate([e(ent, base, ['endpoint:rare_lineage']), e(ent, base+1, ['endpoint:lsass_access']), e(ent, base+2, ['net:beacon_periodic'])]):
    ev, factors = ev_f
    print('\nINGEST', i+1, 'ts=', ev['ts'], 'factors=', factors)
    nf, d = c.ingest(ev, factors)
    print('  returned nf,d=', nf, d)
    dump(ent)

print('\n--- repeated within cooldown ---')
for i, (ev_f) in enumerate([e(ent, base+3, ['endpoint:rare_lineage']), e(ent, base+4, ['endpoint:lsass_access']), e(ent, base+5, ['net:beacon_periodic'])]):
    ev, factors = ev_f
    print('\nINGEST', i+1, 'ts=', ev['ts'], 'factors=', factors)
    nf, d = c.ingest(ev, factors)
    print('  returned nf,d=', nf, d)
    dump(ent)

print('\n--- after cooldown ---')
for i, (ev_f) in enumerate([e(ent, base+40, ['endpoint:rare_lineage']), e(ent, base+41, ['endpoint:lsass_access']), e(ent, base+42, ['net:beacon_periodic'])]):
    ev, factors = ev_f
    print('\nINGEST', i+1, 'ts=', ev['ts'], 'factors=', factors)
    nf, d = c.ingest(ev, factors)
    print('  returned nf,d=', nf, d)
    dump(ent)
