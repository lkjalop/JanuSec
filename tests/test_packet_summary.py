from core.network.packet_summary import summarize_packet_event


def test_packet_summary_exfil_and_beacon():
    # Simulate outbound flows every ~30s with large volume
    base_ts = 1_700_000_000
    flows = []
    for i in range(6):
        flows.append({'direction':'outbound','bytes':900000,'dst_port':443,'timestamp': base_ts + i*30,'proto':'tcp'})
    # Add some DNS with long label
    flows.append({'proto':'dns','direction':'outbound','bytes':120,'timestamp':base_ts + 5,'domain':'aaaaa.' + 'b'*35 + '.com'})
    event = {'details': {'network': flows}}
    factors = summarize_packet_event(event)
    assert 'exfil_volume_high' in factors
    assert any(f.startswith('beacon_') for f in factors)
    assert 'dns_tunnel_pattern' in factors


def test_packet_summary_unusual_port_cluster():
    base_ts = 1_700_000_000
    ports = [1024,20000,30000,40000,50000,60000]
    flows = [{'direction':'outbound','bytes':100,'dst_port':p,'timestamp':base_ts + i,'proto':'tcp'} for i,p in enumerate(ports)]
    event = {'details': {'network': flows}}
    factors = summarize_packet_event(event)
    assert 'unusual_port_cluster' in factors
