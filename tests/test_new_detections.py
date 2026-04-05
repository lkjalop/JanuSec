import asyncio
import time

from core.event_pipeline import EventPipeline
from repositories.sbom_exec_repo import get_sbom_exec_repo
from repositories.sbom_repo import SBOMComponent, get_sbom_repo


class DummyConfig(dict):
    pass

def run_evt(pipeline, evt):
    return asyncio.run(pipeline.process_event(evt))

def test_non_sbom_and_hash_drift():
    cfg = DummyConfig()
    p = EventPipeline(cfg)
    # Register one SBOM component with known hash
    sbom_repo = get_sbom_repo(); exec_repo = get_sbom_exec_repo()
    comp = SBOMComponent(name='acmeagent', version='1.0', purl=None, hashes={'sha-256':'KNOWNHASH'}, licenses=[], first_seen=time.time(), last_seen=time.time())
    sbom_repo.upsert_components('default', [comp])
    exec_repo.register_sbom_component('default','acmeagent','1.0', {'sha-256':'KNOWNHASH'})
    # Event with different hash -> drift
    evt = {'id':'d1','process_hash':'DIFFHASH','process':{'name':'acmeagent.exe'}}
    res = run_evt(p, evt)
    assert any('component_hash_drift' == f for f in res.factors)


def test_egress_spike_and_domain_novelty_and_rare_tokens():
    cfg = DummyConfig()
    p = EventPipeline(cfg)
    # Warm up egress baseline
    for i in range(5):
        run_evt(p, {'id':f'e{i}','host_id':'h1','bytes_out':100})
    # Spike
    spike = run_evt(p, {'id':'spike','host_id':'h1','bytes_out':5000,'domain':'newdomain.test','cmdline':'powershell.exe -enc JABXABcdQ== --VeryRareConstructX --AnotherWeirdTokenY'})
    factors = spike.factors
    assert any(f=='egress_volume_spike' for f in factors)
    assert any(f=='new_domain_seen' for f in factors)
    assert any(f.startswith('cmd_rare_token_ratio') for f in factors)

