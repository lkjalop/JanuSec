from __future__ import annotations

import re
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


def _query_hopgraph_for_related_events(event_id: str, depth: int = 2) -> List[Dict]:
    """Attempt to query HopGraph for related events. If HopGraph module
    is not available, return an empty list (safe fallback for test-mode).
    """
    try:
        from ...graph.hopgraph_lite import HopGraphLite

        hg = HopGraphLite()  # lightweight constructor
        return hg.query_related(event_id, depth=depth)
    except Exception:
        logger.debug('HopGraphLite not available or query failed, falling back')
        return []


def office_macro_spawn_powershell(event: Dict) -> Optional[Dict]:
    """Hardened rule: detect Office macro spawning PowerShell with contextual scoring.

    Expects event to contain fields: event_id, process_name, command_line, user, host, factors
    Returns: dict with rule_name, score, contributing_factors, recommendation
    """
    process_name = (event.get('process_name') or '').lower()
    cmd = event.get('command_line') or ''
    user = event.get('user') or ''
    event_id = event.get('event_id')

    # Basic pattern: office process (winword/excel/outlook) spawns powershell
    office_re = re.compile(r'\b(winword|excel|outlook)\.exe\b', re.IGNORECASE)
    ps_re = re.compile(r'\b(powershell(?:\.exe)?|pwsh(?:\.exe)?)\b', re.IGNORECASE)

    if not (office_re.search(process_name) or office_re.search(cmd)):
        return None

    if not ps_re.search(cmd):
        return None

    # Score components
    score = 0.2
    contributing = []

    # Suspicious command-line patterns: encoded command, bypass AMSI, download and execute
    if re.search(r'(-enc(oded)?|--encodedcommand|base64)', cmd, re.IGNORECASE):
        score += 0.25
        contributing.append('encoded_command')

    if re.search(r'Am/is?i|AmsiUtils', cmd, re.IGNORECASE):
        score += 0.15
        contributing.append('amsi_bypass')

    if re.search(r'curl\s+.*\|\s*bash|Invoke-Expression|IEX\s+', cmd, re.IGNORECASE):
        score += 0.20
        contributing.append('download_and_exec')

    # Investigate user role if provided (admin users higher risk)
    role = event.get('user_role')
    if role and role.lower() in ('admin', 'administrator', 'root'):
        score += 0.10
        contributing.append('admin_user')

    # HopGraph correlation: look for related suspicious events within 2 hops
    if event_id:
        related = _query_hopgraph_for_related_events(event_id, depth=2)
        if related:
            # Each related suspicious event increases confidence
            score += min(0.05 * len(related), 0.25)
            contributing.append('hopgraph_context')

    # Time-of-day abnormality (off-hours increases risk)
    ts = event.get('ts')
    if ts:
        try:
            from datetime import datetime

            hour = datetime.utcfromtimestamp(int(ts)).hour
            if hour < 6 or hour > 22:
                score += 0.05
                contributing.append('off_hours')
        except Exception:
            pass

    score = min(score, 0.95)

    # Build explanation
    explanation = {
        'rule_name': 'office_macro_spawn_powershell',
        'score': round(score, 3),
        'contributing_factors': contributing,
        'recommendation': 'Investigate Office document chain and PowerShell child process; collect macro sample and network artifacts',
    }

    return explanation
import re
from typing import Dict, Any
from ..registry import register_rule


# DUPLICATE_DISABLED decorator for rule exec_office_macro_chain in src\core\correlation\rules\week1\office_macro_chain.py
@register_rule(name='exec_office_macro_chain', mitre=['T1566.001'], factors_required=['parent_process','child_process'], window_seconds=3600, severity='high', confidence_boost=0.45)
def exec_office_macro_chain(event: Dict[str, Any]) -> bool:
    parent = str(event.get('parent_process') or '').lower()
    child = str(event.get('child_process') or '').lower()
    if any(x in parent for x in ('winword','excel','outlook')) and any(x in child for x in ('powershell','cmd','cscript','wscript')):
        return True
    return False


"""Correlation rules for Office macro chains (week1).

Contains heuristics to detect Office macro -> payload -> LOLBin/Powershell chains.
"""


@register_rule(name='office_macro_spawn_powershell', mitre=['T1204','T1059.001'], factors_required=['file','process','cmdline'], window_seconds=600, severity='high', confidence_boost=0.4)
@register_rule(name='corr_office_macro_ps', mitre=['T1204','T1059.001'], factors_required=['file','process','cmdline'], window_seconds=600, severity='high', confidence_boost=0.4)
def office_macro_spawn_powershell(event: Dict[str, Any]) -> bool:
    """Detect chain: Office macro -> dropped/loaded payload -> powershell execution.

    Heuristics:
    - event.source indicates office macro or office document with macros
    - neighbor process or subsequent process shows powershell with encoded/obfuscated command
    - commandline contains common encoded indicators (Base64, -EncodedCommand, -e)
    - prefer evidence where user/account is high-privilege or off-hours (score adjusted elsewhere)
    """
    try:
        src = str(event.get('event.source') or event.get('source') or '')
        if not src:
            return False

        # quick indicator: office macro artifact or vbaProject.bin
        if re.search(r'(office|docm|vbaProject|vba)', src, re.IGNORECASE):
            # check for process lineage hints
            proc = str(event.get('process') or '')
            cmd = str(event.get('cmdline') or event.get('command_line') or '')

            # direct powershell spawn
            if 'powershell' in proc.lower() or 'pwsh' in proc.lower():
                # check for encoded or obfuscated execution
                if re.search(r'-EncodedCommand|-e\s|base64', cmd, re.IGNORECASE) or len(cmd) > 200:
                    return True

            # sometimes evidence encoded in neighbors/children
            children = event.get('children') or []
            for c in children:
                try:
                    cname = str(c.get('process') or '')
                    ccmd = str(c.get('cmdline') or c.get('command_line') or '')
                    if 'powershell' in cname.lower() or 'pwsh' in cname.lower():
                        if re.search(r'-EncodedCommand|-e\s|base64', ccmd, re.IGNORECASE) or len(ccmd) > 200:
                            return True
                except Exception:
                    continue

            # fallback: check command lines in event for known LOLBin patterns executed after doc open
            if re.search(r'cmd\.exe|wscript|cscript|mshta', proc, re.IGNORECASE) and re.search(r'\.(docm|doc|xlsm|pptm)\b', src, re.IGNORECASE):
                return True
    except Exception:
        return False
    return False


SUSPICIOUS_OFFICE_PARENTS = ('winword', 'excel', 'powerpnt', 'outlook')


@register_rule(name='office_macro_external_c2_chain', mitre=['T1566.001'], factors_required=['parent_process','child_process','network_outbound_domains'], window_seconds=1800, severity='high', confidence_boost=0.45)
def office_macro_chain(event: Dict[str, Any]) -> bool:
    parent = str(event.get('parent_process') or '').lower()
    child = str(event.get('child_process') or '').lower()
    if not parent or not child:
        return False
    if any(p in parent for p in SUSPICIOUS_OFFICE_PARENTS):
        if 'powershell' in child or 'wscript' in child or 'mshta' in child:
            # minimal network enrichment: outbound domain count
            domains = event.get('network_outbound_domains') or []
            if isinstance(domains, list) and len(domains) >= 1:
                return True
    return False


__all__ = ["office_macro_chain", "office_macro_spawn_powershell"]
