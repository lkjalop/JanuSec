from __future__ import annotations

import asyncio
import re
from typing import Any

from ..evidence_envelope import EvidenceEnvelope


class DataDiscoveryLane:
    name = 'data_discovery'

    async def run(self, envelope: EvidenceEnvelope, ctx) -> None:
        # More realistic heuristics using normalized event fields where available.
        ev = getattr(envelope, 'event', {}) or {}
        factors: list[str] = []

        # Prefer normalized fields, fall back to raw keys
        paths = ev.get('path_list') or ev.get('file_list') or ev.get('files') or []

        # detector: automated file enumeration (many file accesses in a single event)
        try:
            if isinstance(paths, (list, tuple)) and len(paths) >= 10:
                factors.append('data:automated_file_enumeration')
        except Exception:
            pass

        # detector: database schema enumeration (INFORMATION_SCHEMA, SHOW TABLES, PRAGMA table_info)
        query = str(ev.get('query') or ev.get('sql') or '')
        qlow = query.lower()
        if any(tok in qlow for tok in ('information_schema', 'show tables', 'pragma table_info')):
            factors.append('data:database_schema_enumeration')

        # detector: search_keyword_sensitive (search form inputs, query_text, or request body)
        text = ' '.join([str(ev.get(k, '') or '') for k in ('search', 'query_text', 'body', 'payload')])
        text_low = text.lower()
        if any(k in text_low for k in ('ssn', 'social security', 'credit card', 'card number', 'dob', 'date of birth')):
            factors.append('data:search_keyword_sensitive')

        # detector: sensitive_file_listing (sensitive extensions, keywords in filenames)
        try:
            for p in (paths or [])[:200]:
                if not isinstance(p, str):
                    continue
                pl = p.lower()
                if pl.endswith(('.pem', '.key', '.csv', '.xls', '.xlsx', '.db')) or any(x in pl for x in ('secret', 'credentials', 'passwords', 'ssn')):
                    factors.append('data:sensitive_file_listing')
                    break
        except Exception:
            pass

        # detector: database_export_command (presence of SELECT INTO OUTFILE, COPY TO, or db export commands)
        if re.search(r'\b(select\s+into\s+outfile|copy\s+to\s+file|\bpg_dump\b|mysqldump)\b', qlow, flags=re.IGNORECASE):
            factors.append('data:database_export_command')

        # emit if any factors found
        if factors:
            envelope.add_emission(self.name, factors, notes='auto-detect-batch1', latency_ms=ctx.elapsed_ms())
        await asyncio.sleep(0)


LANE = DataDiscoveryLane()
