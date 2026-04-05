"""Privilege Misuse Lane

Heuristics (lightweight, advisory factors):
 - Admin/session on unusual host for the user/team
 - Service account misuse outside expected scope
 - Use of admin tools by non-admin role

Expected event fields (best-effort):
 event['user'], event['host'], event.get('role'), event.get('is_admin'),
 event.get('tool'), event.get('service_account'), event.get('action')

Factors emitted are prefixed by lane registry as lane_privilege_misuse:*
"""
from __future__ import annotations

from typing import Dict, Set


class PrivilegeMisuseLane:
    name = 'privilege_misuse'

    ADMIN_TOOLS = {
        'psexec', 'wmic', 'wmi', 'winrm', 'schtasks', 'sc', 'net use',
        'powershell remoting', 'remote registry', 'nslookup -type=all'
    }

    def __init__(self):
        # Minimal rolling memory (per-process lifetime) for first-time detections
        self._user_admin_hosts: Dict[str, Set[str]] = {}
        self._service_accounts: Set[str] = set()

    async def run(self, envelope, context):
        e = envelope.event
        user = (e.get('user') or '').lower()
        host = (e.get('host') or '').lower()
        role = (e.get('role') or '').lower()
        is_admin = bool(e.get('is_admin'))
        svc = (e.get('service_account') or '').lower()
        tool = (e.get('tool') or e.get('process_name') or e.get('proc') or '').lower()
        action = (e.get('action') or '').lower()

        factors: list[str] = []

        # Admin session on unusual host
        if is_admin and user and host:
            seen = self._user_admin_hosts.setdefault(user, set())
            if host not in seen and len(seen) >= 1:
                factors.append('admin_session_unusual_host')
            seen.add(host)

        # Service account misuse (service account used interactively or for lateral tools)
        if svc:
            self._service_accounts.add(svc)
            if action in {'logon', 'interactive_logon'} or any(k in tool for k in ('psexec', 'wmic', 'winrm')):
                factors.append('service_account_interactive_use')

        # Non-admin using admin tools
        if role not in ('admin','administrator','secops') and any(tool.startswith(t) or t in tool for t in self.ADMIN_TOOLS):
            factors.append('non_admin_admin_tool_use')

        if factors:
            envelope.add_emission(self.name, factors, notes=None, latency_ms=0.0)


def build():
    return PrivilegeMisuseLane()

