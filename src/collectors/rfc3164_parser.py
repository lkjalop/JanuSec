from lark import Lark, Transformer, Token, v_args
from datetime import datetime
from dataclasses import asdict, dataclass

RFC3164_GRAMMAR = r"""
start: PRI? timestamp hostname appname pid? msg
PRI: "<" INT ">"
timestamp: MONTH DAY TIME
MONTH: /[A-Z][a-z]{2}/
DAY: /\d{1,2}/
TIME: /\d{2}:\d{2}:\d{2}/
hostname: /[^<\s]+/
appname: /[^\s:\[]+/
pid: "[" INT "]"
msg: /.+/
%import common.INT
%import common.WS
%ignore WS
"""


@dataclass
class RFC3164Message:
    pri: int | None
    timestamp: datetime | None
    hostname: str | None
    appname: str | None
    pid: int | None
    msg: str | None


@v_args(inline=True)
class RFC3164Transformer(Transformer):
    def PRI(self, token: Token):
        txt = token.value
        return int(txt.strip("<>") or 0)

    def timestamp(self, month, day, time_tok):
        month = month.value
        day = int(day.value)
        t = time_tok.value
        month_map = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
        hour, minute, second = map(int, t.split(":"))
        now = datetime.utcnow()
        return datetime(now.year, month_map.get(month, 1), day, hour, minute, second)

    def hostname(self, token):
        return token.value

    def appname(self, token):
        return token.value

    def pid(self, token):
        try:
            return int(token.value)
        except Exception:
            return None

    def msg(self, token):
        return token.value

    def start(self, *items):
        pri = None
        ts = None
        hostname = None
        appname = None
        pid = None
        msg = None
        from lark import Token
        for it in items:
            if isinstance(it, Token):
                if it.type == 'PRI':
                    try:
                        pri = int(it.value.strip('<>'))
                    except Exception:
                        pri = None
                    continue
                else:
                    # treat other tokens as strings
                    it = it.value

            if isinstance(it, int):
                pri = it
            elif isinstance(it, datetime):
                ts = it
            elif isinstance(it, str):
                if not hostname:
                    hostname = it
                elif not appname:
                    appname = it
                else:
                    msg = it
            elif isinstance(it, (list, tuple)):
                pass
        return RFC3164Message(pri=pri, timestamp=ts, hostname=hostname, appname=appname, pid=pid, msg=msg)


class RFC3164Parser:
    def __init__(self):
        self._parser = Lark(RFC3164_GRAMMAR, start="start", parser="lalr")
        self._transformer = RFC3164Transformer()

    def parse_line(self, line: str) -> RFC3164Message:
        try:
            tree = self._parser.parse(line)
            return self._transformer.transform(tree)
        except Exception:
            # best-effort fallback using simple heuristic
            # try to split into PRI, timestamp, hostname, rest
            try:
                parts = line.split(None, 4)
                pri = None
                if parts and parts[0].startswith("<") and parts[0].endswith(">"):
                    pri = int(parts[0].strip('<>'))
                    parts = parts[1:]
                ts = None
                if len(parts) >= 3:
                    ts = datetime.utcnow()
                    hostname = parts[2]
                    appname = parts[3] if len(parts) > 3 else None
                    msg = parts[4] if len(parts) > 4 else None
                else:
                    hostname = parts[0] if parts else None
                    appname = None
                    msg = None
                return RFC3164Message(pri=pri, timestamp=ts, hostname=hostname, appname=appname, pid=None, msg=msg)
            except Exception:
                return RFC3164Message(pri=None, timestamp=None, hostname=None, appname=None, pid=None, msg=line)

    def to_canonical(self, parsed: RFC3164Message) -> dict:
        """Convert parsed RFC3164Message into a CanonicalNetworkEvent-like dict."""
        return {
            "ts": parsed.timestamp,
            "source": None,
            "tenant_id": None,
            "device_vendor": None,
            "device_product": None,
            "device_version": None,
            "message": parsed.msg,
            "raw": {"pri": parsed.pri, "appname": parsed.appname, "pid": parsed.pid},
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "proto": None,
            "bytes": None,
            "packets": None,
            "flow_start": None,
            "flow_end": None,
            "sampling_ratio": None,
        }
