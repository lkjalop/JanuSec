import pytest
from src.correlation.ingestion_orchestrator import ingest_records

NEW_FACTORS = [
    'persistence_registry_change', 'new_autorun_entry', 'beaconing_interval_regular',
    'sudden_c2_domain_contact', 'inactive_role_reactivation', 'compression_before_transfer',
    'auth_token_reuse_across_ips', 'data_staging_then_exfil', 'data_staging_phase', 'exfil_after_staging'
]

def factor_names(result):
    return {f.get('name') for f in result['factors']}

def test_endpoint_persistence_and_autorun():
    recs = [
        {'source_type':'endpoint','timestamp':i,'host':'h1','process':'rundll32.exe','user':'u','raw':{'registry_change':'Run\\Key','autorun_entry':True}}
        for i in range(3)
    ]
    res = ingest_records(recs)
    names = factor_names(res)
    assert 'persistence_registry_change' in names
    assert 'new_autorun_entry' in names

def test_network_beacon_and_c2_domain():
    # Regular intervals for beaconing + many contacts to same domain
    recs = []
    for i in range(5):
        recs.append({'source_type':'network','timestamp':i*10.0,'src_ip':'1.1.1.1','dst_ip':'9.9.9.9'})
    for i in range(8):
        recs.append({'source_type':'network','timestamp':100+i,'src_ip':'2.2.2.2','dst_ip':'8.8.8.8','domain':'c2.example'})
    res = ingest_records(recs)
    names = factor_names(res)
    assert 'beaconing_interval_regular' in names
    assert 'sudden_c2_domain_contact' in names

def test_iam_inactive_role_reactivation():
    recs = [
        {'source_type':'iam','timestamp':1,'actor':'userA','action':'reactivate_account','prev_role':'inactive','new_role':'admin'}
    ]
    res = ingest_records(recs)
    assert 'inactive_role_reactivation' in factor_names(res)

def test_data_compression_and_staging_exfil():
    recs = [
        {'source_type':'data','timestamp':1,'user':'u','repository':'repo1','direction':'internal','data_volume_bytes':100},
        {'source_type':'data','timestamp':2,'user':'u','repository':'repo2','direction':'internal','data_volume_bytes':200,'raw':{'note':'file.zip'}},
        {'source_type':'data','timestamp':3,'user':'u','repository':'repo2','direction':'outbound','data_volume_bytes':6_000_000,'raw':{'archive':'data.gz'}},
    ]
    res = ingest_records(recs)
    names = factor_names(res)
    assert 'compression_before_transfer' in names
    assert 'data_staging_phase' in names
    assert 'data_staging_then_exfil' in names
    assert 'exfil_after_staging' in names

def test_api_token_reuse_across_ips():
    recs = []
    for ip in ['10.0.0.1','10.0.0.2','10.0.0.3']:
        recs.append({'source_type':'api','timestamp':len(recs)+1,'user':'apiUser','endpoint':'/files/list','status':'200','raw':{'auth_token':'ABC123'}, 'src_ip':ip})
    res = ingest_records(recs)
    assert 'auth_token_reuse_across_ips' in factor_names(res)

@pytest.mark.parametrize('factor', NEW_FACTORS)
def test_factor_confidence_present(factor):
    if factor in {'persistence_registry_change','new_autorun_entry'}:
        recs = [{'source_type':'endpoint','timestamp':1,'host':'h','process':'rundll32.exe','user':'u','raw':{'registry_change':'Run\\Key','autorun_entry':True}}]
    elif factor == 'beaconing_interval_regular':
        recs = [{'source_type':'network','timestamp':i,'src_ip':'s','dst_ip':'d'} for i in [0,10,20,30,40,50]]
    elif factor == 'sudden_c2_domain_contact':
        recs = [{'source_type':'network','timestamp':i,'src_ip':'x','dst_ip':'y','domain':'burst.c2'} for i in range(8)]
    elif factor == 'inactive_role_reactivation':
        recs = [{'source_type':'iam','timestamp':1,'actor':'u','action':'reactivate','prev_role':'inactive','new_role':'admin'}]
    elif factor == 'compression_before_transfer':
        recs = [{'source_type':'data','timestamp':1,'user':'u','repository':'r1','direction':'outbound','data_volume_bytes':6_500_000,'raw':{'file':'archive.zip'}}]
    elif factor == 'auth_token_reuse_across_ips':
        recs = [{'source_type':'api','timestamp':i,'user':'u','endpoint':'/dl','status':'200','raw':{'auth_token':'ZZZ'}, 'src_ip':f'10.0.0.{i}'} for i in range(1,4)]
    elif factor in {'data_staging_then_exfil','data_staging_phase','exfil_after_staging'}:
        recs = [
            {'source_type':'data','timestamp':1,'user':'u','repository':'r1','direction':'internal','data_volume_bytes':100},
            {'source_type':'data','timestamp':2,'user':'u','repository':'r2','direction':'internal','data_volume_bytes':200},
            {'source_type':'data','timestamp':3,'user':'u','repository':'r2','direction':'outbound','data_volume_bytes':7_000_000}
        ]
    else:
        pytest.skip('Unknown factor mapping for parameterized confidence test')
    res = ingest_records(recs)
    names = factor_names(res)
    assert factor in names
    fobj = [f for f in res['factors'] if f.get('name') == factor][0]
    assert fobj.get('confidence', 0) > 0