from __future__ import annotations

import asyncio
import logging
import os
import re
import ssl
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from src.core.rate_limit import BucketRegistry
from src.services.network_config import TenantSourceRegistry, load_network_config

logger = logging.getLogger(__name__)

SyslogCallback = Callable[[str, str, Dict[str, Any], Dict[str, Any]], None]
HealthCallback = Callable[[str, str, int], None]

TENANT_PATTERN = re.compile(r'(?:tenant|tenant_id|x-tenant-id)=([A-Za-z0-9_\-]+)', re.IGNORECASE)
SECRET_PATTERN = re.compile(r'(?:secret|shared_secret)=([A-Za-z0-9_\-]+)', re.IGNORECASE)


def _extract_token(pattern: re.Pattern[str], text: str) -> Optional[str]:
    match = pattern.search(text)
    if match:
        return match.group(1)
    return None


def parse_syslog_message(data: bytes) -> Dict[str, Any]:
    text = data.decode('utf-8', 'ignore').strip()
    pri = None
    facility = None
    severity = None
    if text.startswith('<'):
        end = text.find('>')
        if end > 1:
            try:
                pri = int(text[1:end])
                facility = pri // 8
                severity = pri % 8
            except Exception:
                pri = None
            text = text[end + 1 :].lstrip()
    timestamp = None
    host = None
    app = None
    remainder = text
    parts = text.split()
    if len(parts) >= 3:
        timestamp = ' '.join(parts[:3])
        remainder = ' '.join(parts[3:])
    fields = remainder.split(None, 1)
    if fields:
        host = fields[0]
        if len(fields) > 1:
            remainder = fields[1]
    if ':' in remainder:
        left, message = remainder.split(':', 1)
        app = left.strip()
        remainder = message.strip()
    tenant_hint = _extract_token(TENANT_PATTERN, text)
    shared_secret = _extract_token(SECRET_PATTERN, text)
    structured = {}
    # naive structured data extraction [id key="value"]
    for block in re.findall(r'\[([^\]]+)\]', text):
        kv = {}
        for kv_pair in re.findall(r'(\S+)="([^"]*)"', block):
            kv[kv_pair[0]] = kv_pair[1]
        if kv:
            structured.setdefault('blocks', []).append(kv)
    return {
        'raw': text,
        'tenant': tenant_hint,
        'shared_secret': shared_secret,
        'facility': facility,
        'severity': severity,
        'host': host,
        'app': app,
        'timestamp': timestamp,
        'message': remainder,
        'structured': structured,
    }


@dataclass
class ListenerBinding:
    protocol: str
    host: str
    port: int
    ssl_context: Optional[ssl.SSLContext]


class SyslogDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, listener: 'SyslogListener') -> None:
        self.listener = listener

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:  # pragma: no cover - exercised indirectly
        asyncio.create_task(self.listener.process_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        logger.warning('Syslog UDP error: %s', exc)


class SyslogListener:
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        *,
        event_callback: Optional[SyslogCallback] = None,
        health_callback: Optional[HealthCallback] = None,
        force_enable: bool = False,
    ) -> None:
        cfg = config or load_network_config().get('syslog', {})
        self.enabled = force_enable or os.getenv('ENABLE_SYSLOG_LISTENER', '0').lower() in {'1', 'true', 'yes'}
        self.registry = TenantSourceRegistry(cfg.get('sources') or [], default_connector='syslog_udp')
        self.event_callback = event_callback
        self.health_callback = health_callback
        self._udp_transports: List[asyncio.BaseTransport] = []
        self._tcp_servers: List[asyncio.AbstractServer] = []
        self._bucket_registry = BucketRegistry()
        self._bindings = self._build_bindings(cfg.get('listeners') or [])
        self._started = False

    def _build_bindings(self, listeners: List[Dict[str, Any]]) -> List[ListenerBinding]:
        bindings: List[ListenerBinding] = []
        for entry in listeners:
            protocol = (entry.get('protocol') or 'udp').lower()
            host = entry.get('host') or '0.0.0.0'
            port = int(entry.get('port') or (6514 if protocol.endswith('tls') else 514))
            ctx = None
            if protocol == 'tcp_tls':
                cert = entry.get('certfile') or os.getenv('SYSLOG_TLS_CERT')
                key = entry.get('keyfile') or os.getenv('SYSLOG_TLS_KEY')
                if cert and key and os.path.exists(cert) and os.path.exists(key):
                    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ctx.load_cert_chain(cert, key)
                    if entry.get('require_client_cert'):
                        ctx.verify_mode = ssl.CERT_REQUIRED
                        ca_path = entry.get('ca_file') or os.getenv('SYSLOG_TLS_CA')
                        if ca_path and os.path.exists(ca_path):
                            ctx.load_verify_locations(ca_path)
                else:
                    logger.warning('Syslog TLS binding missing cert/key; falling back to plain TCP on %s:%s', host, port)
                    protocol = 'tcp'
            bindings.append(ListenerBinding(protocol=protocol, host=host, port=port, ssl_context=ctx))
        if not bindings:
            bindings.append(ListenerBinding(protocol='udp', host='0.0.0.0', port=514, ssl_context=None))
        return bindings

    async def start(self) -> bool:
        if not self.enabled or self._started:
            return False
        loop = asyncio.get_running_loop()
        for binding in self._bindings:
            try:
                if binding.protocol == 'udp':
                    transport, _ = await loop.create_datagram_endpoint(lambda: SyslogDatagramProtocol(self), local_addr=(binding.host, binding.port))
                    self._udp_transports.append(transport)
                    logger.info('Syslog UDP listener on %s:%s', binding.host, binding.port)
                else:
                    server = await asyncio.start_server(self._handle_tcp_client, binding.host, binding.port, ssl=binding.ssl_context)
                    self._tcp_servers.append(server)
                    logger.info('Syslog %s listener on %s:%s', 'TLS' if binding.ssl_context else 'TCP', binding.host, binding.port)
            except Exception:
                logger.exception('Failed to bind syslog listener on %s:%s', binding.host, binding.port)
        self._started = True
        return True

    async def stop(self) -> None:
        for transport in self._udp_transports:
            try:
                transport.close()
            except Exception:
                pass
        self._udp_transports.clear()
        for server in self._tcp_servers:
            try:
                server.close()
                await server.wait_closed()
            except Exception:
                pass
        self._tcp_servers.clear()
        self._started = False

    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:  # pragma: no cover - exercised by integration tests only
        addr = writer.transport.get_extra_info('peername')
        ip = addr[0] if isinstance(addr, tuple) else '0.0.0.0'
        try:
            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break
                await self.process_datagram(line, (ip, addr[1] if isinstance(addr, tuple) else 0))
        except Exception:
            logger.exception('Syslog TCP client error from %s', ip)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def process_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        if not data:
            return
        parsed = parse_syslog_message(data)
        tenant_entry = self.registry.match(addr[0])
        tenant = parsed.get('tenant') or tenant_entry.tenant
        connector = tenant_entry.connector_id
        shared_secret = parsed.get('shared_secret')
        if tenant_entry.shared_secret and shared_secret != tenant_entry.shared_secret:
            logger.warning('Syslog secret mismatch for tenant=%s ip=%s', tenant, addr[0])
            return
        bucket = self._bucket_registry.get(tenant, connector, tenant_entry.burst, tenant_entry.eps_limit)
        if not bucket.try_consume():
            logger.debug('Syslog rate limited tenant=%s connector=%s', tenant, connector)
            return
        normalized = {
            'ts': time.time(),
            'facility': parsed.get('facility'),
            'severity': parsed.get('severity'),
            'host': parsed.get('host'),
            'app': parsed.get('app'),
            'message': parsed.get('message'),
            'structured': parsed.get('structured'),
            'source_ip': addr[0],
        }
        raw = {'raw': parsed.get('raw')}
        if self.event_callback:
            try:
                self.event_callback(tenant, connector, normalized, raw)
            except Exception:
                logger.exception('Syslog event callback failed')
        if self.health_callback:
            try:
                self.health_callback(tenant, connector, 1)
            except Exception:
                logger.exception('Syslog health callback failed')


__all__ = ['SyslogListener', 'parse_syslog_message']
