from __future__ import annotations

import asyncio
from typing import Any

from ..evidence_envelope import EvidenceEnvelope


class DataExfiltrationLane:
    name = 'data_exfiltration'

    async def run(self, envelope: EvidenceEnvelope, ctx) -> None:
        ev = getattr(envelope, 'event', {}) or {}
        factors: list[str] = []

        # volume-based heuristics: large outbound bytes or many outbound files
        out_bytes = ev.get('outbound_bytes') or ev.get('bytes_sent') or 0
        if isinstance(out_bytes, (int, float)) and out_bytes >= 10_000_000:
            factors.append('data:mass_upload_to_cloud_service')

        # unusual S3 put/delete patterns (method flags)
        http_method = (ev.get('http_method') or '').upper()
        path = (ev.get('path') or '').lower()
        if http_method in ('PUT','DELETE') and 's3' in (ev.get('service') or '').lower():
            if http_method == 'PUT':
                factors.append('data:unusual_s3_put_pattern')
            elif http_method == 'DELETE':
                factors.append('data:unusual_aws_s3_delete')

        # tor / proxy usage hint
        if (ev.get('network') or {}).get('tor_exit', False) or ev.get('tor_detected'):
            factors.append('data:tor_usage')

        # FTP/SFTP uploads to external hosts
        proto = (ev.get('protocol') or '').lower()
        if proto in ('ftp','sftp') and ev.get('dst_ip') and not ev.get('dst_internal'):
            factors.append('data:ftp_upload_unusual')

        if factors:
            envelope.add_emission(self.name, factors, notes='auto-detect-batch2', latency_ms=ctx.elapsed_ms())
        await asyncio.sleep(0)


LANE = DataExfiltrationLane()
