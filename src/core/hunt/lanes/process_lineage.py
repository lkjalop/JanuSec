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
        ('wscript.exe','powershell.exe'): 'script_host_to_ps',
        # CrowdStrike Falcon / Lateral Tool Transfer (T1021.001, T1570)
        # mstsc.exe is the Windows RDP client; unusual parents indicate programmatic launch
        ('powershell.exe','mstsc.exe'): 'rdp_lateral_ps_spawn',
        ('cmd.exe','mstsc.exe'): 'rdp_lateral_cmd_spawn',
        ('wscript.exe','mstsc.exe'): 'rdp_lateral_script_spawn',
        ('winword.exe','mstsc.exe'): 'rdp_lateral_office_spawn',
        ('excel.exe','mstsc.exe'): 'rdp_lateral_office_spawn',
        # mstsc spawning a shell or data tool → post-RDP execution
        ('mstsc.exe','powershell.exe'): 'rdp_post_lateral_ps',
        ('mstsc.exe','cmd.exe'): 'rdp_post_lateral_cmd',
        ('mstsc.exe','mstsc.exe'): 'rdp_nested_lateral',
    }

    # Processes whose unexpected launch from unusual parents indicates lateral movement
    LATERAL_TOOLS = {'mstsc.exe', 'psexec.exe', 'psexec64.exe', 'wmic.exe', 'winrs.exe'}

    # Typical benign parents for mstsc (explorer or terminal services only)
    MSTSC_BENIGN_PARENTS = {'explorer.exe', 'taskmgr.exe', 'rdpclip.exe', ''}

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
            factors.append(self.SUSPICIOUS_PAIRS[key] if key in getattr(self, 'SUSPICIOUS_PAIRS', {}) else self.SUSPICIOUS_PARENTS[key])

        # mstsc.exe from any parent not in benign list = lateral movement indicator
        # (CrowdStrike Falcon: tracks mstsc spawn context, classifies as Lateral Tool Transfer)
        if proc == 'mstsc.exe' and parent not in self.MSTSC_BENIGN_PARENTS:
            if key not in self.SUSPICIOUS_PARENTS:  # avoid double-emit
                factors.append('rdp_lateral_unusual_parent')
            factors.append('lateral:T1021.001_rdp_client_launch')

        # Any lateral tool launched by a script/office parent gets extra T1570 tag
        if proc in self.LATERAL_TOOLS and parent in {
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'winword.exe', 'excel.exe', 'outlook.exe',
        }:
            factors.append('lateral:T1570_lateral_tool_transfer')

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
