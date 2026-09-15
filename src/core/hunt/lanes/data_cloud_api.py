from __future__ import annotations

import asyncio
from typing import Any

from ..evidence_envelope import EvidenceEnvelope


class DataCloudApiLane:
    name = 'data_cloud_api'

    async def run(self, envelope: EvidenceEnvelope, ctx) -> None:
        ev = getattr(envelope, 'event', {}) or {}
        factors: list[str] = []

        # detect unapproved rclone use via user-agent or process hints
        ua = (ev.get('user_agent') or '').lower()
        if 'rclone' in ua or 'rclone' in (ev.get('process') or '').lower():
            factors.append('data:unapproved_rclone_use')

        # streaming large data via API: repeated chunked responses or content-length high
        cl = ev.get('content_length') or ev.get('bytes') or 0
        if isinstance(cl, (int, float)) and cl >= 5_000_000:
            factors.append('data:streaming_large_data_via_api')

        # service account access spikes
        if ev.get('service_account') and (ev.get('access_count_last_hour') or 0) > 50:
            factors.append('data:service_account_data_access_spike')

        if factors:
            envelope.add_emission(self.name, factors, notes='auto-detect-batch3', latency_ms=ctx.elapsed_ms())
        await asyncio.sleep(0)


LANE = DataCloudApiLane()
