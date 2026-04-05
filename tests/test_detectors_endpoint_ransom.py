from src.core.detectors.endpoint_ransom import detect_rare_parent_child, detect_file_encryption_wave, detect_unsigned_network_launch

def test_detect_rare_parent_child_empty():
    res = detect_rare_parent_child({'process_events':[]})
    assert isinstance(res, list)

def test_detect_file_encryption_wave():
    runtime = {'file_events':[{'host':'h1','path':'/tmp/a.encrypted'}]*60}
    res = detect_file_encryption_wave(runtime)
    assert any(r.get('factor')=='file_encryption_wave' for r in res)

def test_detect_unsigned_network_launch():
    runtime = {'network_events':[{'host':'h1','exe':'/tmp/x','binary_signed':False,'outbound':True}]}
    res = detect_unsigned_network_launch(runtime)
    assert any(r.get('factor')=='unsigned_binary_network_launch' for r in res)
