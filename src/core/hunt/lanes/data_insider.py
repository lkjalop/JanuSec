from __future__ import annotations

import asyncio
from typing import Any

from ..evidence_envelope import EvidenceEnvelope


class DataInsiderLane:
    name = 'data_insider'

    async def run(self, envelope: EvidenceEnvelope, ctx) -> None:
        ev = getattr(envelope, 'event', {}) or {}
        factors: list[str] = []

        # privileged db export hint
        if ev.get('user_role') in ('db_admin', 'dba') and ev.get('db_export'):
            factors.append('data:privileged_db_export')

        # scheduled task performing large transfers
        if ev.get('scheduled_task') and (ev.get('transfer_size') or 0) > 5_000_000:
            factors.append('data:scheduled_task_data_exfil')

        # suspicious host->cloud sync ratio
        host_sync = ev.get('host_cloud_sync_ratio') or 0.0
        if isinstance(host_sync, (int, float)) and host_sync > 2.5:
            factors.append('data:host_to_cloud_sync_ratio_anomaly')

        if factors:
            envelope.add_emission(self.name, factors, notes='auto-detect-batch4', latency_ms=ctx.elapsed_ms())
        await asyncio.sleep(0)


LANE = DataInsiderLane()
