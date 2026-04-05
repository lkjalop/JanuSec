from src.live.zeek_adapter import parse_conn
line='{"ts":"2025-01-07T00:00:00Z","id.orig_h":"10.0.0.1","id.resp_h":"8.8.8.8","proto":"tcp","service":"http","id.resp_p":80}'
ev=parse_conn(line)
print(type(ev), ev.get('dest_ip'))
