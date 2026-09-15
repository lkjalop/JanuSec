# Minimal shim for syslog_rfc5424_parser used in tests
# Only implements SyslogMessage.parse for the simple test cases in this repo.
from __future__ import annotations
import re
from datetime import datetime

_rfc5424_re = re.compile(r"^<(?P<pri>\d+)>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) (?P<msg>.*)$")

class SyslogMessage:
    def __init__(self, timestamp=None, hostname=None, msg=None, app_name=None, pri=None):
        self.timestamp = timestamp
        self.hostname = hostname
        self.msg = msg
        self.app_name = app_name
        self.pri = pri

    @staticmethod
    def parse(line: str):
        m = _rfc5424_re.match(line)
        if not m:
            raise RuntimeError('unable to parse')
        ts_raw = m.group('ts')
        ts = None
        try:
            # Accept ISO8601-ish timestamps
            ts = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
        except Exception:
            ts = None
        host = m.group('host')
        msg = m.group('msg')
        pri = int(m.group('pri')) if m.group('pri') else None
        return SyslogMessage(timestamp=ts, hostname=host, msg=msg, app_name=m.group('app'), pri=pri)
