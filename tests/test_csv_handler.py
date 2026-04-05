from src.api.csv_handler import parse_csv_bytes, forward_rows


def test_parse_csv_bytes_basic():
    b = b"src_ip,user,dest_host,dest_port,protocol\n1.2.3.4,alice,host1,443,vpn\n"
    rows = parse_csv_bytes(b)
    assert len(rows) == 1
    assert rows[0]['src_ip'] == '1.2.3.4'


def test_forward_rows_calls_post_func():
    rows = [{'src_ip': '1.1.1.1', 'user': 'bob', 'dest_host': 'vm'}]
    called = []
    def fake_post(path, json=None):
        called.append((path, json))
        class R:
            status_code = 200
            text = ''
        return R()
    summary = forward_rows(rows, 'remote_access', fake_post)
    # forward_rows now returns a summary dict
    assert isinstance(summary, dict)
    assert summary.get('forwarded', 0) == 1
    assert called and called[0][0].endswith('/remote_access/ingest')
