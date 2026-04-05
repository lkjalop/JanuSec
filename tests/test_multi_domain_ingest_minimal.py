from src.correlation.ingestion_orchestrator import ingest_records

def test_multi_domain_minimal_ingest():
    # Synthetic mixed domain records
    records = [
        {'timestamp': 1000.0, 'tenant': 't1', 'source_type': 'email', 'From': 'attacker@mail.ru', 'Subject': 'Offer bit.ly/abc', 'Message-ID': 'm1', 'Attachment-Type': 'docm', 'Attachment-Hash': 'h1', 'mailbox': 'userA', 'threat_tags': ['spf_fail','forward_rule_added']},
        {'timestamp': 1001.0, 'tenant': 't1', 'source_type': 'network', 'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.6', 'domain': 'phish.invalid', 'proto': 'tcp'},
        {'timestamp': 1002.0, 'tenant': 't1', 'source_type': 'network', 'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.7', 'domain': 'phish.invalid', 'proto': 'tcp'},
        {'timestamp': 1003.0, 'tenant': 't1', 'source_type': 'network', 'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.8', 'domain': 'phish.invalid', 'proto': 'tcp'},
    ]
    result = ingest_records(records)
    assert result['events_count'] == 4
    factor_names = {f['name'] for f in result['factors']}
    # Expect at least these email factors
    assert 'suspicious_sender_domain' in factor_names
    assert 'attachment_macro' in factor_names
    assert 'url_shortener_risk' in factor_names
    assert 'SPF_fail' in factor_names
    assert 'mailbox_forward_rule_added' in factor_names
    # Expect at least one network factor
    assert 'dns_nxdomain_spike' in factor_names
    # Kill chain should include Delivery stage from email factors
    stages = [kc['stage'] for kc in result['kill_chain']]
    assert 'Delivery' in stages
    # Recon from dns_nxdomain_spike mapping
    assert 'Recon' in stages
