from live.zeek_adapter import parse_zeek_line


def test_parse_dns_minimal():
    line = '{"ts": 1700000000, "id.orig_h": "10.0.0.1", "id.resp_h": "1.1.1.1", "query": "a.example.com"}'
    ev = parse_zeek_line('dns', line)
    assert ev['event_type'] == 'dns'
    assert ev['dns_query'] == 'a.example.com'


def test_parse_http_user_agent():
    line = '{"ts": 1700000001, "id.orig_h":"10.0.0.1", "id.resp_h":"2.2.2.2", "id.resp_p": 443, "method":"GET", "host":"ex.com", "uri":"/", "user_agent":"UA"}'
    ev = parse_zeek_line('http', line)
    assert ev['event_type'] == 'http'
    assert ev['http_user_agent'] == 'UA'


def test_parse_ssl_ja3():
    line = '{"ts": 1700000002, "id.orig_h":"10.0.0.2", "id.resp_h":"3.3.3.3", "id.resp_p": 443, "ja3":"abcd", "ja3s":"efgh"}'
    ev = parse_zeek_line('ssl', line)
    assert ev['event_type'] == 'ssl'
    assert ev['ja3'] == 'abcd'
