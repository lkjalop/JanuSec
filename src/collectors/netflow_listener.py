from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import struct
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.core.rate_limit import BucketRegistry
from src.services.network_config import TenantSourceRegistry, load_network_config

logger = logging.getLogger(__name__)

FlowCallback = Callable[[str, str, List[Dict[str, Any]], Dict[str, Any]], None]
HealthCallback = Callable[[str, str, int], None]


class NetFlowDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, listener: 'NetFlowListener') -> None:
        self.listener = listener

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:  # pragma: no cover - integration path
        asyncio.create_task(self.listener.process_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        logger.warning('NetFlow UDP error: %s', exc)


def parse_netflow_v5(data: bytes) -> List[Dict[str, Any]]:
    if len(data) < 24:
        return []
    header = struct.unpack('!HHIIIIHH', data[:24])
    version, count = header[0], header[1]
    if version != 5:
        return []
    unix_secs = header[2]
    sampling = header[-1] & 0x3FFF
    flows: List[Dict[str, Any]] = []
    offset = 24
    rec_len = 48
    for _ in range(min(count, (len(data) - offset) // rec_len)):
        rec = data[offset : offset + rec_len]
        offset += rec_len
        fields = struct.unpack('!IIIHHIIIIHHBBBBHHBBH', rec)
        src_ip = str(ipaddress.ip_address(fields[0]))
        dst_ip = str(ipaddress.ip_address(fields[1]))
        flow = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': fields[9],
            'dst_port': fields[10],
            'packets': fields[5],
            'bytes': fields[6],
            'start_uptime_ms': fields[7],
            'end_uptime_ms': fields[8],
            'tcp_flags': fields[12],
            'proto': fields[13],
            'tos': fields[14],
            'src_as': fields[15],
            'dst_as': fields[16],
            'src_mask': fields[17],
            'dst_mask': fields[18],
            'timestamp': unix_secs,
            'sampling_rate': sampling or None,
        }
        flows.append(flow)
    return flows


class NetFlowListener:
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        *,
        event_callback: Optional[FlowCallback] = None,
        health_callback: Optional[HealthCallback] = None,
        force_enable: bool = False,
    ) -> None:
        cfg = config or load_network_config().get('netflow', {})
        self.enabled = force_enable or os.getenv('ENABLE_NETFLOW_LISTENER', '0').lower() in {'1', 'true', 'yes'}
        self.registry = TenantSourceRegistry(cfg.get('sources') or [], default_connector='netflow')
        self.event_callback = event_callback
        self.health_callback = health_callback
        self._bucket_registry = BucketRegistry()
        self._listeners = cfg.get('listeners') or [{'host': '0.0.0.0', 'port': 2055}]
        self._transport: Optional[asyncio.BaseTransport] = None
        self._started = False

    async def start(self) -> bool:
        if not self.enabled or self._started:
            return False
        loop = asyncio.get_running_loop()
        try:
            bind = self._listeners[0]
            host = bind.get('host') or '0.0.0.0'
            port = int(bind.get('port') or 2055)
            transport, _ = await loop.create_datagram_endpoint(lambda: NetFlowDatagramProtocol(self), local_addr=(host, port))
            self._transport = transport
            logger.info('NetFlow UDP listener on %s:%s', host, port)
        except Exception:
            logger.exception('Failed to bind NetFlow listener')
            return False
        self._started = True
        return True

    async def stop(self) -> None:
        if self._transport:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None
        self._started = False

    async def process_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        flows = parse_netflow_v5(data)
        if not flows:
            return
        entry = self.registry.match(addr[0])
        tenant = entry.tenant
        connector = entry.connector_id
        bucket = self._bucket_registry.get(tenant, connector, entry.burst, entry.eps_limit)
        tokens_needed = len(flows)
        if not bucket.try_consume(tokens_needed):
            logger.debug('NetFlow rate limited tenant=%s connector=%s', tenant, connector)
            return
        normalized = []
        for flow in flows:
            copy = dict(flow)
            copy['exporter_ip'] = addr[0]
            normalized.append(copy)
        raw_meta = {'exporter_ip': addr[0], 'exporter_port': addr[1], 'flow_count': len(flows)}
        if self.event_callback:
            try:
                self.event_callback(tenant, connector, normalized, raw_meta)
            except Exception:
                logger.exception('NetFlow event callback failed')
        if self.health_callback:
            try:
                self.health_callback(tenant, connector, len(flows))
            except Exception:
                logger.exception('NetFlow health callback failed')


__all__ = ['NetFlowListener', 'parse_netflow_v5']
