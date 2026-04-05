from src.core.ingest.zeek_parser import parse_zeek_tsv_lines
from src.core.ingest.netflow_parser import parse_netflow_csv_lines
from src.core.ingest.ingest_worker import process_event_batch


def test_parse_simple_zeek_lines():
    lines = [
        '#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto',
        '1622471123.123	C1	10.0.0.1	12345	10.0.0.2	22	tcp',
    ]
    evs = list(parse_zeek_tsv_lines(lines))
    assert len(evs) == 1
    ev = evs[0]
    assert ev['type'] == 'zeek.conn'
    assert ev['src_ip'] == '10.0.0.1'
    assert ev['dst_port'] == 22


def test_parse_netflow_csv():
    lines = [
        'srcaddr,dstaddr,srcport,dstport,protocol,packets,bytes',
        '10.0.0.1,10.0.0.2,12345,80,tcp,10,1000',
    ]
    evs = list(parse_netflow_csv_lines(lines))
    assert len(evs) == 1
    ev = evs[0]
    assert ev['type'] == 'netflow.record'
    assert ev['src_ip'] == '10.0.0.1'
    assert ev['dst_port'] == 80


def test_integration_parsers_to_worker(monkeypatch, tmp_path):
    # run both parser outputs through the worker and ensure sessions created
    import os
    monkeypatch.chdir(tmp_path)

    z_lines = [
        '#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto',
        '1622471123.123	C1	10.0.0.1	12345	10.0.0.2	22	tcp',
    ]
    n_lines = [
        'srcaddr,dstaddr,srcport,dstport,protocol,packets,bytes',
        '10.0.0.1,10.0.0.3,54321,443,tcp,2,200',
    ]

    zeek_events = list(parse_zeek_tsv_lines(z_lines))
    netflow_events = list(parse_netflow_csv_lines(n_lines))

    res1 = process_event_batch(zeek_events, correlate=True)
    res2 = process_event_batch(netflow_events, correlate=True)

    assert res1['processed'] == 1
    assert res2['processed'] == 1
    # sessions lists should exist
    assert isinstance(res1['sessions'], list)
    assert isinstance(res2['sessions'], list)
