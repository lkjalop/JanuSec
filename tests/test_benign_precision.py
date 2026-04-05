from src.correlation.ingestion_orchestrator import ingest_records

BENIGN_RECORDS = [
    {'source_type':'endpoint','timestamp':1,'host':'h1','process':'explorer.exe','user':'u'},
    {'source_type':'endpoint','timestamp':2,'host':'h1','process':'chrome.exe','user':'u'},
    {'source_type':'network','timestamp':1,'src_ip':'1.1.1.1','dst_ip':'8.8.8.8'},
    {'source_type':'network','timestamp':7,'src_ip':'1.1.1.1','dst_ip':'8.8.4.4'},
    {'source_type':'network','timestamp':23,'src_ip':'1.1.1.1','dst_ip':'9.9.9.9'},
    {'source_type':'iam','timestamp':1,'actor':'userA','action':'login','prev_role':'user','new_role':'user'},
    {'source_type':'data','timestamp':1,'user':'u','repository':'repo1','direction':'internal','data_volume_bytes':5000},
    {'source_type':'data','timestamp':2,'user':'u','repository':'repo1','direction':'internal','data_volume_bytes':8000},
    {'source_type':'api','timestamp':1,'user':'u','endpoint':'/files/list','status':'200','raw':{'auth_token':'T1'}, 'src_ip':'10.0.0.1'},
    {'source_type':'api','timestamp':2,'user':'u','endpoint':'/files/list','status':'200','raw':{'auth_token':'T1'}, 'src_ip':'10.0.0.1'},
]

NEW_FACTORS = {
    'persistence_registry_change','new_autorun_entry','beaconing_interval_regular','sudden_c2_domain_contact',
    'inactive_role_reactivation','compression_before_transfer','auth_token_reuse_across_ips','data_staging_then_exfil',
    'data_staging_phase','exfil_after_staging'
}

def test_benign_does_not_trigger_new_high_signal_factors():
    res = ingest_records(BENIGN_RECORDS)
    names = {f.get('name') for f in res['factors']}
    assert names.isdisjoint(NEW_FACTORS), f"Benign set incorrectly triggered: {names & NEW_FACTORS}"