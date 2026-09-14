"""Asyncio-based IPFIX UDP intake worker.

This module provides a simple UDP listener that batches received packets and
forwards them to the IPFIX parsing adapter and ingestion worker. It is
designed to be optional and controlled via environment variables.
"""
from __future__ import annotations

import asyncio
import os
import logging
from typing import Iterable

from src.core.ingest.ipfix_adapter import parse_ipfix_stream
from src.core.ingest.ingest_worker import process_event_batch

logger = logging.getLogger(__name__)


async def process_queue(queue: asyncio.Queue, batch_size: int = 50, batch_timeout: float = 1.0, stop_after_batches: int | None = None) -> None:
    """Consume bytes from `queue`, batch them, parse and forward to ingestion.

    If `stop_after_batches` is provided, the function returns after that many
    batches (useful for tests). Otherwise it runs forever.
    """
    batches_done = 0
    while True:
        batch = []
        try:
            # wait for at least one packet
            item = await asyncio.wait_for(queue.get(), timeout=batch_timeout)
            batch.append(item)
        except asyncio.TimeoutError:
            # nothing arrived during timeout
            if stop_after_batches is not None and batches_done >= stop_after_batches:
                return
            if not batch:
                continue

        # gather more items up to batch_size without waiting
        while len(batch) < batch_size:
            try:
                item = queue.get_nowait()
                batch.append(item)
            except asyncio.QueueEmpty:
                break

        if not batch:
            continue

        try:
            # Each queued item may be a tuple (data, (ip,port)) or raw bytes.
            # Normalize to (data, exporter) pairs for parsing.
            normalized = []
            exporters = []
            for item in batch:
                if isinstance(item, tuple) and len(item) == 2:
                    data, addr = item
                    ip, port = addr[0], addr[1]
                    normalized.append(data)
                    exporters.append({'ip': ip, 'port': port})
                else:
                    # addr unknown
                    normalized.append(item)
                    exporters.append(None)

            # Parse the batch into flow records
            records = list(parse_ipfix_stream(normalized))

            # attach exporter metadata to records in a round-robin fashion if available
            out_records = []
            for i, r in enumerate(records):
                rec = dict(r)
                # pick exporter corresponding to the packet index if possible
                exporter = exporters[i] if i < len(exporters) else None
                if exporter:
                    rec['exporter'] = exporter
                out_records.append(rec)

            if out_records:
                # forward to ingestion worker (correlation enabled)
                process_event_batch(out_records, correlate=True)
        except Exception:
            logger.exception('failed processing ipfix batch')

        batches_done += 1
        if stop_after_batches is not None and batches_done >= stop_after_batches:
            return


class IPFIXProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    def datagram_received(self, data: bytes, addr):
        try:
            # push raw bytes into queue for processing
            self.queue.put_nowait(data)
        except Exception:
            logger.exception('failed enqueuing datagram')


async def start_ipfix_udp_listener(host: str = '0.0.0.0', port: int = 4739, batch_size: int = 50, batch_timeout: float = 1.0) -> tuple:
    """Start UDP listener and processing task. Returns (transport, protocol, task, queue).

    The returned `task` should be cancelled to stop processing; the transport
    should be closed to stop listening.
    """
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    protocol = IPFIXProtocol(queue)
    transport, proto = await loop.create_datagram_endpoint(lambda: protocol, local_addr=(host, port))
    task = asyncio.create_task(process_queue(queue, batch_size=batch_size, batch_timeout=batch_timeout))
    logger.info('ipfix udp listener started on %s:%d', host, port)
    return transport, protocol, task, queue


def start_listener_from_env() -> tuple | None:
    """Convenience helper to start listener based on environment variables.

    Environment variables:
      IPFIX_LISTENER_ENABLED (1|0)
      IPFIX_LISTENER_HOST
      IPFIX_LISTENER_PORT
      IPFIX_BATCH_SIZE
      IPFIX_BATCH_TIMEOUT
    """
    enabled = os.environ.get('IPFIX_LISTENER_ENABLED', '0') in ('1', 'true', 'True')
    if not enabled:
        logger.info('IPFIX listener disabled by env')
        return None
    host = os.environ.get('IPFIX_LISTENER_HOST', '0.0.0.0')
    port = int(os.environ.get('IPFIX_LISTENER_PORT', '4739'))
    batch_size = int(os.environ.get('IPFIX_BATCH_SIZE', '50'))
    batch_timeout = float(os.environ.get('IPFIX_BATCH_TIMEOUT', '1.0'))

    # Note: this is a convenience synchronous wrapper that spawns the listener
    # in the current event loop. Callers must be running an asyncio loop.
    coro = start_ipfix_udp_listener(host=host, port=port, batch_size=batch_size, batch_timeout=batch_timeout)
    return coro
