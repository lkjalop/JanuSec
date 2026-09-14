from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model

def test_stride_placeholders_appear_when_emitted():
    model = aggregate_threat_model(['auth:token_anomaly','log:tamper_suspected','net:flow_flood'])
    cats = set(model['stride']['categories'])
    # Ensure placeholder categories surface
    assert 'spoofing' in cats
    assert 'repudiation' in cats or 'tampering' in cats
    assert 'denial' in cats
