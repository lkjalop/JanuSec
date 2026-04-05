import asyncio
import logging
try:
    import structlog
    logger = structlog.get_logger(__name__)
except Exception:
    import logging as _logging
    logger = _logging.getLogger(__name__)
try:
    from opentelemetry import trace
except Exception:
    # lightweight tracer stub for test environments without opentelemetry
    class _NoopSpan:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False

    class _NoopTracerImpl:
        def start_as_current_span(self, name):
            return _NoopSpan()

    class _NoopTraceModule:
        def get_tracer(self, name=None):
            return _NoopTracerImpl()

    trace = _NoopTraceModule()
import ssl
import ipaddress
import yaml
import time
from typing import Optional, Dict

from prometheus_client import Counter, Gauge
try:
    from syslog_rfc5424_parser import SyslogMessage
except Exception:
    # Minimal shim for test environments where parser isn't installed.
    class SyslogMessage:
        @staticmethod
        def parse(s: str):
            # naive fallback: raise so callers can fallback to other parsers
            raise RuntimeError('syslog_rfc5424_parser not installed')
from .structured_parsers import is_cef, parse_cef, is_leef, parse_leef
from .rate_limit_config import load_rate_limits
from lark import UnexpectedInput
from .rfc3164_parser import RFC3164Parser
from datetime import datetime

from .models import CanonicalNetworkEvent
from .redis_producer import RedisStreamProducer

tracer = trace.get_tracer(__name__)

# Prometheus metrics
METRIC_RECEIVED = Counter("collectors_syslog_received_total", "Total syslog messages received", ["proto"])
METRIC_PARSED = Counter("collectors_syslog_parsed_total", "Total syslog messages parsed", ["proto"])
METRIC_DROPPED = Counter("collectors_syslog_dropped_total", "Total syslog messages dropped", ["proto", "reason"])
METRIC_BACKLOG = Gauge("collectors_redis_backlog", "Approx Redis stream backlog length")


class SyslogCollector:
    def __init__(self, redis_url: str, stream_name: str = "collectors:syslog", loop: Optional[asyncio.AbstractEventLoop] = None):
        self.loop = loop or asyncio.get_event_loop()
        self.redis = RedisStreamProducer(redis_url)
        self.stream_name = stream_name
        self._udp_transport = None
        self._tcp_server = None
        self.device_map: Dict[str, Dict] = {}
        self.subnet_map = []
        self._rate_buckets = {}  # source -> (tokens, last_ts)
        self._rate_limit_per_sec = 50
        self._configured_limits = {}
        self._rb_parser = RFC3164Parser()
        self._configured_limits = {}

    def load_device_map(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            for k, v in (data or {}).items():
                if k == "subnets":
                    for s, meta in v.items():
                        self.subnet_map.append((ipaddress.ip_network(s), meta))
                else:
                    self.device_map[k] = v
        except FileNotFoundError:
            logger.info("Device map not found: %s", path)
        except Exception:
            logger.exception("Failed to load device map %s", path)

    def load_rate_limit_config(self, path: str):
        try:
            self._configured_limits = load_rate_limits(path)
        except Exception:
            logger.exception("Failed to load rate limit config %s", path)

    def _allow_emit(self, source_ip: str) -> bool:
        # simple token bucket implementation
        now = time.time()
        tokens, last = self._rate_buckets.get(source_ip, (self._rate_limit_per_sec, now))
        # replenish
        delta = now - last
        tokens = min(self._rate_limit_per_sec, tokens + delta * self._rate_limit_per_sec)
        if tokens < 1:
            self._rate_buckets[source_ip] = (tokens, now)
            return False
        tokens -= 1
        self._rate_buckets[source_ip] = (tokens, now)
        return True

    async def start(self, udp_port: int = 514, tcp_port: int = 5140, tls: bool = False, tls_context: Optional[ssl.SSLContext] = None, device_map_path: Optional[str] = None):
        await self.redis.connect()
        if device_map_path:
            self.load_device_map(device_map_path)
        # UDP
        listen = self.loop.create_datagram_endpoint(lambda: _UDPProtocol(self), local_addr=("0.0.0.0", udp_port))
        self._udp_transport, _ = await listen
        logger.info("SyslogCollector listening UDP on %d", udp_port)

        # TCP
        if tls and tls_context:
            server = await asyncio.start_server(self._handle_tcp, host="0.0.0.0", port=tcp_port, ssl=tls_context)
        else:
            server = await asyncio.start_server(self._handle_tcp, host="0.0.0.0", port=tcp_port)
        self._tcp_server = server
        logger.info("SyslogCollector listening TCP on %d (tls=%s)", tcp_port, bool(tls))

    async def stop(self):
        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        await self.redis.close()

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        proto = "tcp"
        try:
            # support RFC6587 octet-count framing and non-framed lines
            buffer = b""
            while not reader.at_eof():
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buffer += chunk
                # octet-count framing: lines prefixed with <len> text
                while True:
                    # try octet-count
                    if b" " in buffer:
                        try:
                            sp = buffer.split(b" ", 1)
                            count = int(sp[0])
                            if len(sp[1]) >= count:
                                frame = sp[1][:count]
                                buffer = sp[1][count:]
                                await self._process_line(frame.decode(errors="ignore").strip(), proto, peer)
                                continue
                        except Exception:
                            pass
                    # fallback to newline-delimited
                    if b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        await self._process_line(line.decode(errors="ignore").strip(), proto, peer)
                        continue
                    break
        except Exception:
            logger.exception("Error handling TCP connection %s", peer)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_line(self, line: str, proto: str, peer):
        METRIC_RECEIVED.labels(proto=proto).inc()
        # structured detection
        if is_cef(line):
            cef = parse_cef(line)
            # attach structured info
            msg.msg = cef.get("name") or msg.msg
            event_meta = cef.get("extension", {})
        elif is_leef(line):
            leef = parse_leef(line)
            msg.msg = leef.get("raw") or msg.msg

        # choose parser: try RFC5424 first, fallback to RFC3164 Lark parser
        msg = None
        parsed_via_rfc3164 = False
        with tracer.start_as_current_span("parse_syslog"):
            try:
                msg = SyslogMessage.parse(line)
                METRIC_PARSED.labels(proto=proto).inc()
            except Exception:
                try:
                    parsed = self._rb_parser.parse_line(line)
                    parsed_via_rfc3164 = True
                except Exception:
                    METRIC_DROPPED.labels(proto=proto, reason="parse_error").inc()
                    logger.debug("Failed to parse syslog line", line=line)
                    return

        # map exporter by peer IP
        peer_ip = None
        try:
            peer_ip = peer[0]
        except Exception:
            peer_ip = str(peer)

        device_info = self.device_map.get(peer_ip)
        if not device_info:
            for net, meta in self.subnet_map:
                try:
                    if ipaddress.ip_address(peer_ip) in net:
                        device_info = meta
                        break
                except Exception:
                    continue

        if parsed_via_rfc3164:
            ts = parsed.timestamp
            message_text = parsed.msg or line
            appname = parsed.appname
        else:
            ts = getattr(msg, "timestamp", None)
            message_text = getattr(msg, "msg", None) or line
            appname = getattr(msg, "app_name", None) or getattr(msg, "procid", None)

        event = CanonicalNetworkEvent(
            ts=ts or datetime.utcnow(),
            source=peer_ip or str(peer),
            tenant_id=(device_info.get("tenant_id") if device_info else None),
            device_vendor=(device_info.get("vendor") if device_info else None),
            device_product=(device_info.get("product") if device_info else None),
            device_version=None,
            message=message_text,
            raw={"message": line, "app": appname},
        )

        # rate limiting per source (token bucket)
        # consult configured per-source limit if present
        per_src = self._configured_limits.get(peer_ip)
        capacity = int(per_src) if per_src else self._rate_limit_per_sec
        # use redis-backed token bucket if available
        acquired = True
        try:
            acquired = await self.redis.try_acquire_token(f"rate:{peer_ip}", capacity, float(capacity))
        except Exception:
            acquired = self._allow_emit(peer_ip)

        if not acquired:
            METRIC_DROPPED.labels(proto=proto, reason="rate_limited").inc()
            logger.info("rate_limited", peer=peer_ip, proto=proto)
            return

        await self.redis.push(self.stream_name, event.model_dump())
        logger.info("event_emitted", peer=peer_ip, stream=self.stream_name)


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: SyslogCollector):
        self.collector = collector

    def datagram_received(self, data: bytes, addr):
        line = data.decode(errors="ignore").strip()
        asyncio.ensure_future(self.collector._process_line(line, "udp", addr))

