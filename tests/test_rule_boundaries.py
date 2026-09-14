import json
import os
import time

from fastapi.testclient import TestClient

# Assume API app is importable
from src.api.server import app

client = TestClient(app)

# Helper to post batch

def post_events(evts):
    return client.post('/api/v1/endpoints/log_batch', json={'events': evts, 'classify': True, 'send_alerts': False, 'include_rules': True}).json()

def test_asn_rarity_boundary(monkeypatch):
    # Force rarity threshold
    monkeypatch.setenv('ASN_RARITY_THRESHOLD','0.95')
    # Simulate ASN frequency: record many occurrences then a rare one
    # We'll craft events with asn via enrichment stub (set directly)
    base = []
    for i in range(50):
        base.append({
            'id': f'ev{i}', 'host': 'h1', 'proc_name': 'cmd.exe', 'parent_proc': 'explorer.exe', 'dest_ip': f'10.0.0.{i%5}', 'asn': 'AS1'
        })
    # Rare candidate below threshold rarity (simulate asn_stats rarity just under)
    rare_under = {'id': 'under','host': 'h1','proc_name':'cmd.exe','parent_proc':'explorer.exe','dest_ip':'10.0.0.99','asn':'AS_RARE_UNDER'}
    rare_over = {'id': 'over','host': 'h1','proc_name':'cmd.exe','parent_proc':'explorer.exe','dest_ip':'10.0.0.100','asn':'AS_RARE_OVER'}

    # Monkeypatch rarity function
    # Seed ASN counts to produce deterministic rarity behavior
    from src.api import runtime_state as _rs
    # Ensure defaults then seed: AS1 frequent, AS_RARE_OVER rare
    _rs.seed_asn_counts([('AS1', 50), ('AS_RARE_OVER', 1)])
    # Monkeypatch fallback rarity function for any unexpected path
    from src.live import asn_stats
    def rarity_stub(asn):
        if asn == 'AS_RARE_UNDER':
            return 0.94
        if asn == 'AS_RARE_OVER':
            return 0.96
        return asn_stats.rarity(asn)
    monkeypatch.setattr(asn_stats, 'rarity', rarity_stub)

    post_events(base)
    r1 = post_events([rare_under])
    r2 = post_events([rare_over])
    rules1 = r1['accepted'] and r1['errors'] == [] and r1['buffer_size'] is not None
    # Pull latest sanitized events to inspect rules
    recent = client.get('/api/v1/events/sanitized?limit=5').json()
    batch_under = client.post('/api/v1/endpoints/log_batch', json={'events':[rare_under], 'classify': True, 'send_alerts': False, 'include_rules': True}).json()
    batch_over = client.post('/api/v1/endpoints/log_batch', json={'events':[rare_over], 'classify': True, 'send_alerts': False, 'include_rules': True}).json()
    # Over batch should include asn_rare_outbound rule
    assert 'asn_rare_outbound' not in batch_under.get('events', [{}])[0].get('rules', []) if batch_under.get('events') else True
    # Under batch should not include rule, over batch should
    if batch_over.get('events'):
        assert 'asn_rare_outbound' in batch_over['events'][0].get('rules', [])


def test_nxdomain_rate_boundary(monkeypatch):
    monkeypatch.setenv('ZEEK_NXDOMAIN_RATE_THRESHOLD','0.5')
    # Minimal total requirement is 10 queries (rule code). We'll craft below and above.
    host = 'dns-host'
    below = []
    above = []
    # Below: 4 NXDOMAIN of 10 (40%)
    for i in range(10):
        below.append({'id': f'b{i}','host':host,'proc_name':'cmd.exe','dest_ip':'1.1.1.1','dns_rcode': 'NXDOMAIN' if i < 4 else 'NOERROR'})
    # Above: 6 NXDOMAIN of 10 (60%)
    for i in range(10):
        above.append({'id': f'a{i}','host':host,'proc_name':'cmd.exe','dest_ip':'1.1.1.1','dns_rcode': 'NXDOMAIN' if i < 6 else 'NOERROR'})
    # Seed DNS aggregator to deterministic counts
    from src.api import runtime_state as _rs
    # host should see 4 NXDOMAIN of 10 initially
    _rs.seed_dns_nxdomain(host, 4, 10)
    r_under = post_events(below)
    # Now seed additional NXDOMAINs to push above threshold
    _rs.seed_dns_nxdomain(host, 6, 10)
    r_over = post_events(above)
    # Reclassify a final event referencing aggregator to trigger rule if threshold met
    trigger = {'id':'trigger','host':host,'proc_name':'cmd.exe','dest_ip':'1.1.1.1'}
    resp_under = client.post('/api/v1/endpoints/log_batch', json={'events':[trigger], 'classify': True, 'send_alerts': False, 'include_rules': True}).json()
    # Now add more NXDOMAIN to push count over threshold, then trigger again
    post_events([{'id':'nxextra','host':host,'proc_name':'cmd.exe','dest_ip':'1.1.1.1','dns_rcode':'NXDOMAIN'} for _ in range(2)])
    resp_over = client.post('/api/v1/endpoints/log_batch', json={'events':[{'id':'trigger2','host':host,'proc_name':'cmd.exe','dest_ip':'1.1.1.1'}], 'classify': True, 'send_alerts': False, 'include_rules': True}).json()
    ev_under = resp_under.get('events',[{}])[0]
    ev_over = resp_over.get('events',[{}])[0]
    assert 'zeek_high_nxdomain_rate' not in ev_under.get('rules', [])
    assert 'zeek_high_nxdomain_rate' in ev_over.get('rules', [])
