from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Iterable, List, Optional

from .base import AzureConnectorConfig, load_checkpoint, save_checkpoint, azure_envelope
from .normalizer import normalize_event_hub_event

logger = logging.getLogger(__name__)

try:
    from azure.eventhub import EventHubConsumerClient as _EventHubConsumerClient
    _EVENTHUB_SDK = True
except ImportError:
    _EventHubConsumerClient = None  # type: ignore[assignment,misc]
    _EVENTHUB_SDK = False


class EventHubConnector:
    def __init__(self, cfg: AzureConnectorConfig, consumer_factory: Optional[Callable[[], Any]] = None):
        self.cfg = cfg
        self.name = 'eventhub'
        self.ck = load_checkpoint(self.name, cfg)
        # consumer_factory is kept for test injection only.
        # In production the real azure-eventhub SDK is used when SDK is available
        # and eventhub_connection_string + eventhub_name are configured.
        self._consumer_factory = consumer_factory

    def fetch_events(self, limit: int = 100) -> Iterable[Dict[str, Any]]:
        if _EVENTHUB_SDK and self.cfg.eventhub_connection_string and self.cfg.eventhub_name:
            yield from self._fetch_via_sdk(limit)
        elif self._consumer_factory is not None:
            yield from self._fetch_via_factory(limit)
        else:
            missing = []
            if not _EVENTHUB_SDK:
                missing.append('azure-eventhub SDK (pip install azure-eventhub)')
            if not self.cfg.eventhub_connection_string:
                missing.append('eventhub_connection_string')
            if not self.cfg.eventhub_name:
                missing.append('eventhub_name')
            logger.error('EventHubConnector: cannot fetch — missing: %s', ', '.join(missing))

    def _fetch_via_sdk(self, limit: int) -> Iterable[Dict[str, Any]]:
        """Fetch events using the real azure-eventhub SDK."""
        collected: List[Dict[str, Any]] = []
        updated_offsets: Dict[str, Any] = {}

        def _on_batch(partition_context: Any, events: List[Any]) -> None:
            pid = partition_context.partition_id
            for event in events:
                try:
                    body = event.body_as_json()
                except Exception:
                    try:
                        body = {'data': event.body_as_str(encoding='utf-8')}
                    except Exception:
                        body = {}
                normalized = normalize_event_hub_event(body, self.cfg.tenant_id)
                env = azure_envelope(
                    normalized,
                    'azure_eventhub',
                    tenant_id=self.cfg.tenant_id,
                    subscription_id=normalized.get('subscription_id'),
                )
                env.update(normalized)
                env['_eventhub_partition'] = pid
                env['_eventhub_offset'] = event.offset
                env['_eventhub_seq'] = event.sequence_number
                collected.append(env)
                updated_offsets[f'offset_{pid}'] = event.offset
            # Checkpoint after each partition batch so progress survives
            # a crash mid-fetch. Errors here are non-fatal.
            try:
                partition_context.update_checkpoint()
            except Exception:
                pass

        # Build per-partition starting positions from stored checkpoint
        stored = {k: v for k, v in self.ck.items() if k.startswith('offset_')}
        if stored:
            # Map "offset_{pid}" → offset value
            starting_position: Any = {k[len('offset_'):]: v for k, v in stored.items()}
        else:
            starting_position = '@latest'

        try:
            client = _EventHubConsumerClient.from_connection_string(
                self.cfg.eventhub_connection_string,
                consumer_group=self.cfg.eventhub_consumer_group or '$Default',
                eventhub_name=self.cfg.eventhub_name,
            )
            with client:
                client.receive_batch(
                    on_event_batch=_on_batch,
                    max_batch_size=limit,
                    max_wait_time=5.0,
                    starting_position=starting_position,
                )
        except Exception:
            logger.exception('EventHub SDK fetch failed')
            return

        if updated_offsets:
            self.ck.update(updated_offsets)
            save_checkpoint(self.name, self.cfg, self.ck)

        yield from collected

    def _fetch_via_factory(self, limit: int) -> Iterable[Dict[str, Any]]:
        """Fetch using injected consumer_factory (test path)."""
        consumer = self._consumer_factory()
        count = 0
        for event in consumer.receive(limit=limit, checkpoint=self.ck.get('offset')):
            if not isinstance(event, dict):
                continue
            normalized = normalize_event_hub_event(event, self.cfg.tenant_id)
            env = azure_envelope(
                normalized,
                'azure_eventhub',
                tenant_id=self.cfg.tenant_id,
                subscription_id=normalized.get('subscription_id'),
            )
            env.update(normalized)
            count += 1
            yield env
            self.ck['offset'] = event.get('offset') or self.ck.get('offset')
        if count:
            save_checkpoint(self.name, self.cfg, self.ck)
