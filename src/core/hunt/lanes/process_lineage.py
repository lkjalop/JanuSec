"""Process Lineage Lane

Advisory heuristics:
- Suspicious parent-child combinations (e.g., office spawning script interpreters, explorer launching powershell with encoded command)
- Orphan processes (no parent metadata) when parent normally present
- Signed -> unsigned transition in short interval (if fields available)

Expected event fields (best-effort):
 event['process_name'], event['parent_process_name'], event.get('cmdline'), event.get('parent_cmdline')

Adds factors prefixed automatically by envelope as lane_process_lineage:*
"""
from __future__ import annotations

import re
from typing import List


class ProcessLineageLane:
    name = 'process_lineage'

    SUSPICIOUS_PARENTS = {
        ('winword.exe','powershell.exe'): 'office_macro_spawn_powershell',
        ('excel.exe','powershell.exe'): 'office_macro_spawn_powershell',
        ('winword.exe','cmd.exe'): 'office_macro_spawn_cmd',
        ('powershell.exe','rundll32.exe'): 'ps_spawn_rundll32',
        ('wscript.exe','powershell.exe'): 'script_host_to_ps'
    }

    ENCODED_PATTERN = re.compile(r"-enc\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE)

    async def run(self, envelope, context):
        e = envelope.event
        proc = (e.get('process_name') or '').lower()
        parent = (e.get('parent_process_name') or '').lower()
        cmd = (e.get('cmdline') or '')
        (e.get('parent_cmdline') or '')
        factors: list[str] = []

        key = (parent, proc)
        if key in self.SUSPICIOUS_PARENTS:
            factors.append(self.SUSPICIOUS_PARENTS[key])

        if proc in ('powershell.exe','pwsh.exe') and self.ENCODED_PATTERN.search(cmd):
            factors.append('powershell_encoded_command')

        if not parent and proc and proc not in ('system','idle'):
            factors.append('orphan_process_without_parent_metadata')

        # Signed -> unsigned rapid spawn (placeholder; requires fields)
        child_signed = e.get('process_signed')
        parent_signed = e.get('parent_process_signed')
        if parent_signed is True and child_signed is False:
            factors.append('signed_to_unsigned_transition')

        if factors:
            envelope.add_emission(self.name, factors, notes=None, latency_ms=0.0)

# Factory helper
def build():
    return ProcessLineageLane()
