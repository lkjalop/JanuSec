"""Per-persona dispatch generator for JanuSec.

Produces rich, evidence-backed payloads for each stakeholder's dispatch
preview pane. Replaces the static roleDef.desc/actions strings.

PERSONA KEYS (match breach.js _STAKEHOLDER_ROLES):
   soc_analyst | ciso | executive | threat_hunter | forensics |
   compliance | mssp | audit
"""
from __future__ import annotations

import logging
from typing import Any

from src.analysis.framework_mapper import (
    get_cve_context_for_techniques,
    get_crosswalk_for_controls,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Bounded autonomy tier model
# ─────────────────────────────────────────────────────────────────────────────

ACTION_TIERS = {
    1: {
        'name': 'auto_execute_log_only',
        'description': 'Reversible, low-blast-radius, high-confidence. '
                       'Auto-executed via customer EDR/IAM API; human notified.',
        'examples': ['Network containment of actively-exfiltrating endpoint',
                     'Block known-malicious hash in EDR allow-list',
                     'Block IOC IP at proxy if not on enterprise allow-list',
                     'Quarantine specific file already detected by EDR'],
    },
    2: {
        'name': 'one_click_human_approval',
        'description': 'Reversible, scoped to a specific entity. Pre-templated '
                       'API call shown to operator; one-click approve.',
        'examples': ['Disable Okta session for specific user',
                     'Revoke specific AWS access key',
                     'Kill specific scheduled task on contained host',
                     'Freeze specific Snowflake user',
                     'Isolate specific k8s pod'],
    },
    3: {
        'name': 'cab_change_management',
        'description': 'Higher blast radius or partial irreversibility. '
                       'Requires CAB review before execution.',
        'examples': ['Privilege role removal',
                     'Mass account disable (>5 users)',
                     'Network segmentation change',
                     'Cloud resource deletion',
                     'IdP configuration change'],
    },
    4: {
        'name': 'human_only_no_automation',
        'description': 'Cannot be automated. Human judgement required.',
        'examples': ['Regulatory disclosure decision',
                     'Customer notification content',
                     'Public statement',
                     'Legal hold initiation',
                     'Law enforcement engagement',
                     'Attribution claim'],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  Action library
# ─────────────────────────────────────────────────────────────────────────────

def _action_disable_okta_session(user: str) -> dict:
    return {
        'action_id': f'okta_disable_session::{user}',
        'description': f'Expire all Okta sessions for {user}',
        'tier': 2,
        'tool_command': (f'curl -X DELETE -H "Authorization: SSWS $OKTA_API_TOKEN" '
                         f'"$OKTA_ORG_URL/api/v1/users/{user}/sessions"'),
        'rollback_command': '(no rollback — user re-authenticates with MFA)',
        'auto_executable': False,
        'cab_required': False,
        'persona_relevance': ['soc_analyst'],
    }


def _action_revoke_aws_key(access_key_id: str, account: str = '?') -> dict:
    return {
        'action_id': f'aws_revoke_key::{access_key_id}',
        'description': f'Inactivate AWS access key {access_key_id} (account {account})',
        'tier': 2,
        'tool_command': (f'aws iam update-access-key '
                         f'--access-key-id {access_key_id} --status Inactive'),
        'rollback_command': (f'aws iam update-access-key '
                             f'--access-key-id {access_key_id} --status Active'),
        'auto_executable': False,
        'cab_required': False,
        'persona_relevance': ['soc_analyst', 'forensics'],
    }


def _action_kill_scheduled_task(host: str, task_name: str) -> dict:
    return {
        'action_id': f'edr_kill_schtask::{host}::{task_name}',
        'description': f"Delete scheduled task '{task_name}' on {host}",
        'tier': 2,
        'tool_command': (f'CrowdStrike RTR session on {host}: '
                         f'schtasks /Delete /TN "{task_name}" /F'),
        'rollback_command': '(reverse via change-management; document task XML before delete)',
        'auto_executable': False,
        'cab_required': False,
        'persona_relevance': ['soc_analyst', 'forensics'],
    }


def _action_isolate_endpoint(host: str) -> dict:
    return {
        'action_id': f'edr_isolate::{host}',
        'description': f'Network-contain {host} via EDR',
        'tier': 1,
        'tool_command': (f'CrowdStrike: POST /devices/entities/devices-actions/v2 '
                         f'?action_name=contain&ids={host}'),
        'rollback_command': (f'POST /devices/entities/devices-actions/v2 '
                             f'?action_name=lift_containment&ids={host}'),
        'auto_executable': True,
        'cab_required': False,
        'persona_relevance': ['soc_analyst', 'forensics'],
    }


def _action_freeze_snowflake_user(user: str) -> dict:
    return {
        'action_id': f'snowflake_disable_user::{user}',
        'description': f'Disable Snowflake user {user}',
        'tier': 2,
        'tool_command': f'ALTER USER {user} SET DISABLED = TRUE;',
        'rollback_command': f'ALTER USER {user} SET DISABLED = FALSE;',
        'auto_executable': False,
        'cab_required': False,
        'persona_relevance': ['soc_analyst'],
    }


def _action_block_ioc_ip(ip: str) -> dict:
    return {
        'action_id': f'firewall_block_ip::{ip}',
        'description': f'Block egress and ingress for IOC IP {ip}',
        'tier': 1,
        'tool_command': (f'Update perimeter deny-list to include {ip}/32 '
                         f'(check enterprise allow-list first)'),
        'rollback_command': f'Remove {ip}/32 from deny-list',
        'auto_executable': True,
        'cab_required': False,
        'persona_relevance': ['soc_analyst', 'threat_hunter'],
    }


def _action_collect_volatile_artifacts(host: str) -> dict:
    return {
        'action_id': f'forensic_acquire::{host}',
        'description': f'Acquire volatile artifacts from {host} (memory -> disk -> network)',
        'tier': 2,
        'tool_command': (f'CrowdStrike RTR memdump -> KAPE target KapeTriage -> '
                         f'flow log export. Host: {host}'),
        'rollback_command': '(read-only operation, no rollback needed)',
        'auto_executable': False,
        'cab_required': False,
        'persona_relevance': ['forensics'],
    }


def _action_preserve_cloud_logs(scope: str) -> dict:
    return {
        'action_id': f'cloud_log_preservation::{scope}',
        'description': f'Snapshot and legal-hold cloud audit logs for {scope}',
        'tier': 2,
        'tool_command': (f'aws s3 cp s3://<cloudtrail-bucket>/{scope}/ '
                         f's3://<legal-hold-bucket>/case-{{caseid}}/ --recursive; '
                         f'export Snowflake INFORMATION_SCHEMA.QUERY_HISTORY for affected user'),
        'rollback_command': '(no rollback — preservation is additive)',
        'auto_executable': False,
        'cab_required': False,
        'persona_relevance': ['forensics', 'compliance'],
    }


def _action_rotate_service_credential(svc: str) -> dict:
    return {
        'action_id': f'rotate_service_creds::{svc}',
        'description': f'Rotate credential for service account {svc}',
        'tier': 3,
        'tool_command': (f'Coordinate with service owner. Snowflake: ALTER USER {svc} RESET PASSWORD. '
                         f'AWS federated: rotate trust policy and ExternalId.'),
        'rollback_command': '(stage credential rotation in maintenance window)',
        'auto_executable': False,
        'cab_required': True,
        'persona_relevance': ['soc_analyst', 'compliance'],
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Per-persona payload builders
# ─────────────────────────────────────────────────────────────────────────────

def _hostname_from_principals(principals: dict) -> list[str]:
    return list(principals.get('hosts') or [])


def _user_list(principals: dict) -> list[str]:
    return list(principals.get('users') or [])


def _svc_list(principals: dict) -> list[str]:
    return list(principals.get('service_accounts') or [])


def _ips(infra: dict) -> list[str]:
    return list(infra.get('external_ips') or [])


def _build_soc_actions(narrative: dict) -> list[dict]:
    principals = narrative.get('affected_principals') or {}
    infra = narrative.get('attacker_infrastructure') or {}
    actions: list[dict] = []

    for h in _hostname_from_principals(principals):
        actions.append(_action_isolate_endpoint(h))

    for u in _user_list(principals):
        actions.append(_action_disable_okta_session(u))

    # Revoke each AWS access key actually observed in CloudTrail evidence
    # (reads from userIdentity.accessKeyId, not ARN string match)
    for akid in (principals.get('cloud_access_keys') or []):
        actions.append(_action_revoke_aws_key(akid))

    for stage in (infra.get('staging_resources') or []):
        if stage.startswith('scheduled_task:'):
            tn = stage.split(':', 1)[1]
            for h in _hostname_from_principals(principals):
                actions.append(_action_kill_scheduled_task(h, tn))

    for s in _svc_list(principals):
        actions.append(_action_freeze_snowflake_user(s))

    for ip in _ips(infra)[:5]:
        actions.append(_action_block_ioc_ip(ip))

    return actions


def _build_forensics_actions(narrative: dict) -> list[dict]:
    principals = narrative.get('affected_principals') or {}
    actions: list[dict] = []
    for h in _hostname_from_principals(principals):
        actions.append(_action_collect_volatile_artifacts(h))
    if (narrative.get('affected_data') or {}).get('tables'):
        actions.append(_action_preserve_cloud_logs('snowflake_query_history'))
    if narrative.get('attacker_infrastructure', {}).get('external_ips'):
        actions.append(_action_preserve_cloud_logs('aws_cloudtrail'))
    return actions


def _build_threat_hunter_hypotheses(narrative: dict) -> list[dict]:
    hypotheses: list[dict] = []
    infra = narrative.get('attacker_infrastructure') or {}
    principals = narrative.get('affected_principals') or {}

    for ip in (infra.get('external_ips') or [])[:3]:
        hypotheses.append({
            'hypothesis': f'Operator at {ip} reused infrastructure across the org',
            'pivot_query_kql': (
                f'union SigninLogs, AADNonInteractiveUserSignInLogs '
                f'| where IPAddress == "{ip}" '
                f'| project TimeGenerated, UserPrincipalName, Status, RiskState'
            ),
            'pivot_query_splunk': (
                f'index=okta sourcetype=okta:system_log src_ip="{ip}" '
                f'OR index=aws sourcetype=cloudtrail sourceIPAddress="{ip}" '
                f'| stats count by user'
            ),
            'lookback_days': 60,
        })
    for asn in (infra.get('asns') or [])[:2]:
        hypotheses.append({
            'hypothesis': f'Operator group reuses {asn} infrastructure across phases',
            'pivot_query_kql': (
                f'SigninLogs | where AutonomousSystemNumber == "{asn}" '
                f'| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn'
            ),
            'lookback_days': 180,
        })
    if principals.get('service_accounts'):
        for s in principals['service_accounts'][:2]:
            hypotheses.append({
                'hypothesis': f'Federated service account {s} has been misused before',
                'pivot_query_snowflake': (
                    f'SELECT START_TIME, USER_NAME, ROLE_NAME, CLIENT_IP, '
                    f'QUERY_TYPE, BYTES_SCANNED, ROWS_PRODUCED '
                    f'FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY '
                    f"WHERE USER_NAME = '{s}' "
                    f"AND START_TIME >= DATEADD(day, -90, CURRENT_TIMESTAMP())"
                ),
                'lookback_days': 90,
            })
    return hypotheses


def _build_persona_payload(persona_key: str,
                           narrative: dict,
                           register: dict | None,
                           cluster_id: str = '?') -> dict:
    register = register or {}
    affected = narrative.get('affected_data') or {}
    infra = narrative.get('attacker_infrastructure') or {}
    principals = narrative.get('affected_principals') or {}
    discovery = narrative.get('discovery') or {}

    payload: dict[str, Any] = {
        'persona': persona_key,
        'cluster_id': cluster_id,
        'verdict': narrative.get('verdict'),
        'confidence': narrative.get('confidence'),
    }

    if persona_key == 'soc_analyst':
        actions = _build_soc_actions(narrative)
        payload['headline'] = (
            f"{len(actions)} containment actions across "
            f"{len(principals.get('hosts') or [])} hosts and "
            f"{len(principals.get('users') or [])} accounts. "
            f"Top IOC: {(infra.get('external_ips') or ['—'])[0]}"
        )
        payload['required_actions'] = actions
        payload['context_blocks'] = [
            {'label': 'Contained hosts', 'value': principals.get('hosts') or []},
            {'label': 'Compromised accounts', 'value': principals.get('users') or []},
            {'label': 'Service accounts in scope', 'value': principals.get('service_accounts') or []},
            {'label': 'IOC IPs', 'value': infra.get('external_ips') or []},
            {'label': 'Persistence artifacts', 'value': infra.get('staging_resources') or []},
            {'label': 'Exfil destinations', 'value': infra.get('exfil_destinations') or []},
        ]
        payload['evidence_pinned'] = narrative.get('evidence_refs') or []

    elif persona_key == 'threat_hunter':
        # Prefer explicit narrative techniques; fall back to register's inferred set
        _th_mitre = (narrative.get('mitre_techniques') or []) or (register.get('mitre_techniques') or [])
        payload['headline'] = (
            f"Hunt seeds: {len(infra.get('external_ips') or [])} IPs, "
            f"{len(infra.get('asns') or [])} ASNs, "
            f"{len(_th_mitre)} techniques"
        )
        # Back-fill narrative so _build_threat_hunter_hypotheses sees techniques
        if _th_mitre and not narrative.get('mitre_techniques'):
            narrative = dict(narrative)
            narrative['mitre_techniques'] = _th_mitre
        payload['hypotheses'] = _build_threat_hunter_hypotheses(narrative)
        payload['mitre_techniques'] = _th_mitre
        payload['kill_chain_stage'] = narrative.get('kill_chain_stage')
        payload['context_blocks'] = [
            {'label': 'Operator infrastructure', 'value': infra.get('external_ips') or []},
            {'label': 'ASNs', 'value': infra.get('asns') or []},
            {'label': 'Geolocation', 'value': infra.get('countries') or []},
        ]
        payload['visibility_gaps'] = _derive_visibility_gaps(narrative)

    elif persona_key == 'forensics':
        actions = _build_forensics_actions(narrative)
        payload['headline'] = (
            f"Acquire from {len(principals.get('hosts') or [])} host(s); "
            f"snapshot cloud logs before retention rolls "
            f"({_retention_warning(narrative)})"
        )
        payload['required_actions'] = actions
        payload['acquisition_order'] = _acquisition_order_per_host(narrative)
        payload['evidence_pinned'] = narrative.get('evidence_refs') or []
        payload['context_blocks'] = [
            {'label': 'Hosts in scope', 'value': principals.get('hosts') or []},
            {'label': 'Cloud sources to preserve',
             'value': ['aws_cloudtrail', 'snowflake_query_history',
                       'okta_system_log', 'm365_unified_audit']},
            {'label': 'Discovery source', 'value': [discovery.get('source') or 'unknown']},
        ]

    elif persona_key == 'ciso':
        triggers = register.get('regulatory_triggers') or []
        payload['headline'] = (
            f"{len(triggers)} regulatory regime(s) triggered. "
            f"Tightest clock: {register.get('tightest_clock_seconds', 0)//3600}h"
        )
        payload['regulatory_clocks'] = triggers
        payload['data_exposure'] = {
            'classes': affected.get('classes') or [],
            'sensitivity': affected.get('sensitivity'),
            'crown_jewel_touched': affected.get('crown_jewel_touched'),
            'tables': affected.get('tables') or [],
            'record_count_estimate': affected.get('record_count_estimate'),
        }
        payload['executive_decisions_today'] = _ciso_decisions(narrative, register)
        payload['context_blocks'] = [
            {'label': 'Compromised principals', 'value': principals.get('users') or []},
            {'label': 'Data classes exposed', 'value': affected.get('classes') or []},
            {'label': 'Discovery', 'value': [
                f"{discovery.get('source','unknown')} at {discovery.get('when','unknown')}"]},
        ]

    elif persona_key == 'executive':
        payload['headline'] = _executive_one_liner(narrative)
        payload['plain_english'] = _executive_plain_english(narrative, register)
        payload['decisions_required_today'] = _exec_decisions_today(narrative, register)
        payload['containment_status'] = _containment_summary(narrative)
        payload['context_blocks'] = []

    elif persona_key == 'compliance':
        cf = register.get('control_failures_by_framework') or {}
        n_frameworks = len([k for k in cf if k != 'unmapped_techniques'])
        n_failed = register.get('failed_control_count', 0)
        n_critical = register.get('critical_control_count', 0)
        payload['headline'] = (
            f"{n_failed} failed controls across {n_frameworks} frameworks; "
            f"{n_critical} critical"
        )
        payload['control_failure_register'] = cf
        payload['regulatory_triggers'] = register.get('regulatory_triggers') or []
        payload['unmapped_techniques'] = cf.get('unmapped_techniques') or []
        risk_entries = _build_risk_register_entries(narrative, register)
        payload['risk_register_entries'] = risk_entries
        payload['evidence_link_count'] = register.get('evidence_link_count', 0)

        # Flat list for the JS dispatch preview renderer (expects control_failures[])
        _sev_order = {'critical': 0, 'high': 1, 'moderate': 2, 'low': 3}
        flat_controls: list[dict] = []
        for fw, recs in cf.items():
            if fw == 'unmapped_techniques':
                continue
            for r in recs:
                flat_controls.append({
                    'control_id': r.get('control_id', ''),
                    'control_name': r.get('control_name', ''),
                    'framework': fw,
                    'failure': r.get('failure_type', ''),
                    'severity': r.get('severity', ''),
                    'remediation_priority': r.get('remediation_priority', ''),
                    'triggered_by': r.get('triggered_by') or [],
                })
        flat_controls.sort(key=lambda x: _sev_order.get(x['severity'], 99))
        payload['control_failures'] = flat_controls

        # ISMS / CRQ summary block for compliance officers
        affected = narrative.get('affected_data') or {}
        discovery = narrative.get('discovery') or {}
        reg_triggers = register.get('regulatory_triggers') or []
        tightest_h = (register.get('tightest_clock_seconds', 0) or 0) // 3600
        payload['isms_summary'] = {
            'data_sensitivity': affected.get('sensitivity', 'unknown'),
            'crown_jewel_touched': affected.get('crown_jewel_touched', False),
            'data_classes': affected.get('classes') or [],
            'affected_tables': affected.get('tables') or [],
            'record_count_estimate': affected.get('record_count_estimate'),
            'tightest_notification_clock_hours': tightest_h if tightest_h > 0 else None,
            'regulatory_regime_count': len(reg_triggers),
            'discovery_source': discovery.get('source'),
            'p1_control_count': sum(1 for c in flat_controls if c.get('remediation_priority') == 'P1'),
        }

        # CVE / threat-intelligence enrichment from framework_mapper
        techniques = narrative.get('mitre_techniques') or []
        cve_ctx = get_cve_context_for_techniques(techniques)
        iso_ctrl_ids = [c['control_id'] for c in flat_controls if c['framework'] == 'iso27001']
        crosswalk = get_crosswalk_for_controls(iso_ctrl_ids)

        auditor_asks: list[str] = []
        seen_asks: set[str] = set()
        for ctx in cve_ctx.values():
            for ask in (ctx.get('auditor_asks') or []):
                if ask not in seen_asks:
                    auditor_asks.append(ask)
                    seen_asks.add(ask)

        impact_notes = sorted(
            [
                {
                    'technique': tid,
                    'cves': ctx.get('cves') or [],
                    'breach_analogues': ctx.get('breach_analogues') or [],
                    'impact_usd': ctx.get('business_impact_usd', 0),
                    'impact_note': ctx.get('business_impact_note', ''),
                }
                for tid, ctx in cve_ctx.items()
                if ctx.get('business_impact_usd')
            ],
            key=lambda x: x['impact_usd'],
            reverse=True,
        )

        payload['cve_context'] = cve_ctx
        payload['cross_framework_evidence'] = crosswalk
        payload['auditor_insights'] = auditor_asks
        payload['remediation_roadmap'] = {
            tid: ctx['remediation_roadmap']
            for tid, ctx in cve_ctx.items()
            if ctx.get('remediation_roadmap')
        }
        payload['total_business_impact_usd'] = sum(
            ctx.get('business_impact_usd', 0) for ctx in cve_ctx.values()
        )
        payload['impact_notes'] = impact_notes

    elif persona_key == 'mssp':
        _mssp_mitre = (narrative.get('mitre_techniques') or []) or (register.get('mitre_techniques') or [])
        payload['headline'] = (
            f"Tenant: {narrative.get('tenant_id', 'unknown')} — "
            f"{narrative.get('verdict', 'UNKNOWN')} — "
            f"{len(_mssp_mitre)} techniques observed"
        )
        payload['client_comms_draft_technical'] = _mssp_client_comms(narrative, level='technical')
        payload['client_comms_draft_executive'] = _mssp_client_comms(narrative, level='executive')
        payload['sla_status'] = _evaluate_sla(narrative)
        payload['tenant_tuning_recommendations'] = _tuning_recommendations(narrative)

    elif persona_key == 'audit':
        cf = register.get('control_failures_by_framework') or {}
        n_failed = register.get('failed_control_count', 0)
        n_critical = register.get('critical_control_count', 0)
        ev_refs = narrative.get('evidence_refs') or []
        payload['headline'] = (
            f"{n_failed} nonconformities identified ({n_critical} critical). "
            f"Chain-of-custody: {len(ev_refs)} evidence items logged."
        )
        payload['nonconformity_register'] = cf
        payload['evidence_completeness'] = _evidence_completeness_check(narrative, register)
        payload['required_actions'] = _build_audit_actions(narrative, register)
        payload['evidence_pinned'] = ev_refs
        payload['context_blocks'] = [
            {'label': 'Control frameworks breached', 'value': [fw for fw in cf if fw != 'unmapped_techniques']},
            {'label': 'Critical nonconformities', 'value': [
                f"{c.get('control_id', '')} — {c.get('control_name', '')}"
                for fw_recs in cf.values() if isinstance(fw_recs, list)
                for c in fw_recs if isinstance(c, dict) and c.get('severity') == 'critical'
            ][:6]},
            {'label': 'Evidence items logged', 'value': [str(r) for r in ev_refs[:10]]},
        ]
        # ISO 19011 audit standard references
        payload['audit_standard'] = 'ISO 19011:2018'
        payload['audit_opinion'] = _build_audit_opinion(narrative, register)

    else:
        logger.warning('Unknown persona key: %s', persona_key)
        payload['headline'] = 'Unknown persona'
        payload['required_actions'] = []

    return payload


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _evidence_completeness_check(narrative: dict, register: dict) -> dict:
    """ISO 19011 evidence completeness check for the audit persona."""
    ev_refs = narrative.get('evidence_refs') or []
    mitre = narrative.get('mitre_techniques') or []
    cf = register.get('control_failures_by_framework') or {}
    total_controls = sum(
        len(recs) for fw, recs in cf.items()
        if fw != 'unmapped_techniques' and isinstance(recs, list)
    )
    linked_controls = register.get('evidence_link_count', 0)
    completeness_pct = round(linked_controls / total_controls * 100, 1) if total_controls else 0.0
    return {
        'evidence_items': len(ev_refs),
        'techniques_documented': len(mitre),
        'controls_with_evidence': linked_controls,
        'total_controls_failed': total_controls,
        'completeness_percent': completeness_pct,
        'gaps': [] if completeness_pct >= 80 else [
            'Some failed controls lack linked evidence rows — auditor must request supplementary evidence'
        ],
    }


def _build_audit_actions(narrative: dict, register: dict) -> list[dict]:
    """ISO 19011 audit actions: evidence preservation, nonconformity records, corrective actions."""
    actions: list[dict] = []
    cf = register.get('control_failures_by_framework') or {}
    principals = (narrative.get('affected_principals') or {}).get('users') or []
    p1_controls = [
        c for fw_recs in cf.values() if isinstance(fw_recs, list)
        for c in fw_recs if isinstance(c, dict) and c.get('remediation_priority') == 'P1'
    ]
    if p1_controls:
        actions.append({
            'action_id': 'audit::raise_ncr_p1',
            'description': f"Raise Nonconformity Report for {len(p1_controls)} critical control failures",
            'tier': 3,
            'tool_command': 'Create NCR in GRC system; reference cluster_id and evidence_pinned row indices',
            'cab_required': False,
            'auto_executable': False,
        })
    if narrative.get('evidence_refs'):
        actions.append({
            'action_id': 'audit::preserve_evidence_chain',
            'description': 'Lock evidence rows against modification; start chain-of-custody log',
            'tier': 2,
            'tool_command': 'Tag assessment as audit_hold=true via /api/v1/assessments/{aid}/hold',
            'cab_required': False,
            'auto_executable': False,
        })
    if principals:
        actions.append({
            'action_id': 'audit::schedule_corrective_interviews',
            'description': f"Schedule corrective-action interviews with {', '.join(principals[:3])}",
            'tier': 4,
            'tool_command': '(Human action — coordinate with HR and legal)',
            'cab_required': False,
            'auto_executable': False,
        })
    actions.append({
        'action_id': 'audit::corrective_action_plan',
        'description': 'Issue Corrective Action Plan (CAP) with 30-day remediation deadline for P1 controls',
        'tier': 3,
        'tool_command': 'Reference ISO 19011 §6.6 for CAP template; distribute to control owners',
        'cab_required': False,
        'auto_executable': False,
    })
    return actions


def _build_audit_opinion(narrative: dict, register: dict) -> str:
    """Single-sentence ISO 19011 audit opinion."""
    verdict = str(narrative.get('verdict') or 'REQUIRES_INVESTIGATION').upper()
    n_critical = register.get('critical_control_count', 0)
    if verdict in {'VALIDATED_BREACH', 'CONFIRMED_BREACH'}:
        return (
            f"Adverse opinion: evidence substantiates a confirmed security breach with "
            f"{n_critical} critical control failures — material nonconformity against applicable frameworks."
        )
    if verdict in {'SUSPECTED_BREACH', 'LIKELY_BREACH'}:
        return (
            f"Qualified opinion: evidence indicates probable compromise with "
            f"{n_critical} critical control failures — further investigation required before closure."
        )
    return (
        "Unqualified opinion: no confirmed breach; "
        f"{n_critical} control deficiencies identified requiring corrective action."
    )


def _retention_warning(narrative: dict) -> str:
    sources = set()
    for r in (narrative.get('evidence_rows_meta') or []):
        s = r.get('_source') or ''
        if s:
            sources.add(s)
    warnings = []
    if any('snowflake' in s for s in sources):
        warnings.append('Snowflake QUERY_HISTORY default 7d / 90d')
    if any('okta' in s for s in sources):
        warnings.append('Okta system log default 90d')
    if any('cloudtrail' in s for s in sources):
        warnings.append('CloudTrail default 90d')
    return '; '.join(warnings) or 'check tenant retention'


def _acquisition_order_per_host(narrative: dict) -> list[dict]:
    principals = narrative.get('affected_principals') or {}
    out: list[dict] = []
    for h in (principals.get('hosts') or []):
        out.append({
            'host': h,
            'order': [
                {'priority': 1, 'artifact': 'Live memory image',
                 'tool': 'CrowdStrike RTR memdump or WinPmem'},
                {'priority': 2, 'artifact': 'Volatile network state',
                 'tool': 'netstat -anob, DnsCache, ARP'},
                {'priority': 3, 'artifact': 'Triage image',
                 'tool': 'KAPE target KapeTriage'},
                {'priority': 4, 'artifact': 'Defender quarantine + EDR raw events',
                 'tool': 'CS Falcon raw events export, MDE timeline export'},
                {'priority': 5, 'artifact': 'Persistence-specific artifacts',
                 'tool': 'Scheduled task XML, Registry Run keys, WMI subscriptions'},
            ],
        })
    return out


def _derive_visibility_gaps(narrative: dict) -> list[str]:
    gaps: list[str] = []
    affected = narrative.get('affected_data') or {}
    techs = set(narrative.get('mitre_techniques') or [])
    if 'T1537' in techs and 'snowflake_dlp' not in (narrative.get('controls_present') or []):
        gaps.append('No DLP on Snowflake COPY INTO @stage; only CloudTrail PutObject visibility')
    if 'T1611' in techs:
        gaps.append('Pod admission control / OPA Gatekeeper not enforcing privileged=false')
    if 'T1621' in techs:
        gaps.append('Push-fatigue resistant MFA (number-matching) not enforced')
    if affected.get('crown_jewel_touched'):
        gaps.append('No row-level access policy or just-in-time access on crown-jewel tables')
    return gaps


def _ciso_decisions(narrative: dict, register: dict) -> list[dict]:
    triggers = register.get('regulatory_triggers') or []
    decs: list[dict] = []
    for t in triggers:
        decs.append({
            'decision': f"Trigger {t['name']} notification?",
            'clock_remaining_seconds': t['clock_seconds'],
            'rationale': t['rationale'],
            'tier': 4,
        })
    affected = narrative.get('affected_data') or {}
    if affected.get('crown_jewel_touched'):
        decs.append({
            'decision': 'Engage external IR firm + outside counsel',
            'rationale': 'Crown-jewel data touched',
            'tier': 4,
        })
        decs.append({
            'decision': 'Initiate legal hold on affected systems',
            'rationale': 'Likely litigation / regulatory examination',
            'tier': 4,
        })
    return decs


def _executive_one_liner(narrative: dict) -> str:
    affected = narrative.get('affected_data') or {}
    principals = narrative.get('affected_principals') or {}
    n_users = len(principals.get('users') or [])
    classes = affected.get('classes') or []
    rec = affected.get('record_count_estimate')
    rec_text = f"{rec:,} records" if rec else "an unknown record volume"
    cls_text = ', '.join(classes) if classes else 'data of undetermined class'
    crown = ' (including crown-jewel data)' if affected.get('crown_jewel_touched') else ''
    return (f"{n_users} employee account(s) compromised; "
            f"{rec_text} of {cls_text}{crown} taken to attacker-controlled storage.")


def _executive_plain_english(narrative: dict, register: dict) -> str:
    triggers = register.get('regulatory_triggers') or []
    discovery = narrative.get('discovery') or {}
    src = discovery.get('source', 'unknown')
    src_h = {
        'external_pentest': 'an external red team',
        'edr_detection': 'our endpoint protection',
        'analyst': 'our SOC analyst',
        'deterministic_pipeline': 'our automated pipeline',
        'unknown': 'an unspecified source',
    }.get(src, src)
    parts = [
        f"What happened: {_executive_one_liner(narrative)}",
        f"How we found out: {src_h}.",
        f"What we have done: contained the affected machines and accounts.",
    ]
    if triggers:
        clocks = ', '.join(f"{t['name']} ({t['clock_human']})" for t in triggers)
        parts.append(f"What the law requires: {clocks}.")
    return ' '.join(parts)


def _exec_decisions_today(narrative: dict, register: dict) -> list[str]:
    decs: list[str] = []
    triggers = register.get('regulatory_triggers') or []
    if triggers:
        decs.append('Approve regulatory notification timeline')
    if (narrative.get('affected_data') or {}).get('crown_jewel_touched'):
        decs.append('Authorise external IR firm engagement')
        decs.append('Brief board chair within 24h')
    decs.append('Approve customer communications position')
    return decs


def _containment_summary(narrative: dict) -> str:
    principals = narrative.get('affected_principals') or {}
    return (f"Contained: {len(principals.get('hosts') or [])} hosts, "
            f"{len(principals.get('users') or [])} accounts, "
            f"{len(principals.get('service_accounts') or [])} service accounts.")


def _build_risk_register_entries(narrative: dict, register: dict) -> list[dict]:
    entries: list[dict] = []
    cf = register.get('control_failures_by_framework') or {}
    for fw, recs in cf.items():
        if fw == 'unmapped_techniques':
            continue
        for r in recs:
            entries.append({
                'risk_id': f"R-{fw}-{r['control_id']}",
                'description': f"{fw.upper()} {r['control_id']} ({r['control_name']}) — {r['failure_type']}",
                'severity': r['severity'],
                'remediation_priority': r['remediation_priority'],
                'evidence_refs': r.get('evidence_refs') or [],
                'triggered_by_techniques': r.get('triggered_by') or [],
            })
    return entries


def _mssp_client_comms(narrative: dict, level: str = 'technical') -> str:
    affected = narrative.get('affected_data') or {}
    principals = narrative.get('affected_principals') or {}
    if level == 'executive':
        return (f"We have detected and contained a security incident affecting "
                f"{len(principals.get('users') or [])} of your accounts. "
                f"Initial assessment indicates "
                f"{'crown-jewel' if affected.get('crown_jewel_touched') else 'business'} "
                f"data was accessed. Containment is complete; full investigation continues. "
                f"We will provide a 24-hour update.")
    return (f"Incident summary: verdict={narrative.get('verdict')}, "
            f"confidence={narrative.get('confidence')}, "
            f"techniques={narrative.get('mitre_techniques')}, "
            f"kill_chain_stage={narrative.get('kill_chain_stage')}. "
            f"Affected hosts: {principals.get('hosts')}. "
            f"Containment actions issued through your existing EDR and IAM consoles.")


def _evaluate_sla(narrative: dict) -> dict:
    discovery = narrative.get('discovery') or {}
    lag = discovery.get('lag_seconds_from_first_evidence') or 0
    breach = lag > (24 * 3600)
    return {
        'first_evidence_to_detection_seconds': lag,
        'sla_threshold_seconds': 24 * 3600,
        'sla_breached': breach,
    }


def _tuning_recommendations(narrative: dict) -> list[str]:
    recs: list[str] = []
    techs = set(narrative.get('mitre_techniques') or [])
    if 'T1621' in techs:
        recs.append('Enforce number-matching MFA at IdP for this tenant')
    if 'T1611' in techs:
        recs.append('Enable PSP / OPA Gatekeeper to block privileged=true pods')
    if 'T1537' in techs:
        recs.append('Restrict Snowflake CREATE STAGE on EXTERNAL URLs to allow-list')
    return recs


# ─────────────────────────────────────────────────────────────────────────────
#  Public entry points
# ─────────────────────────────────────────────────────────────────────────────

def build_persona_dispatch(persona_key: str,
                           cluster_narrative: dict,
                           register: dict | None = None,
                           evidence_rows: list[dict] | None = None,
                           cluster_id: str = '?',
                           rag_provider: Any = None) -> dict:
    """Build one persona's dispatch payload.

    Args:
        persona_key: one of soc_analyst, ciso, executive, threat_hunter,
                     forensics, compliance, mssp
        cluster_narrative: post-enrich_narrative() narrative dict
        register: build_control_failure_register() output
        evidence_rows: rows used in the narrative
        cluster_id: cluster identifier for traceability
        rag_provider: optional TemporalRAGProvider for prior-decision retrieval
    """
    if not isinstance(cluster_narrative, dict):
        raise ValueError('cluster_narrative must be a dict')

    if evidence_rows:
        cluster_narrative = dict(cluster_narrative)
        cluster_narrative['evidence_rows_meta'] = [
            {'_source': r.get('_source') or r.get('source')} for r in evidence_rows[:50]
        ]

    payload = _build_persona_payload(persona_key, cluster_narrative,
                                     register or {}, cluster_id=cluster_id)

    # Enrich with TemporalRAG + IdentityGraph + ChronoGraph silos
    _principal_src = cluster_narrative.get('affected_principals') or cluster_narrative.get('shared_accounts') or []
    if isinstance(_principal_src, dict):
        _principal_src = (
            _principal_src.get('users') or
            _principal_src.get('accounts') or
            _principal_src.get('service_accounts') or []
        )
    principals = list({str(a) for a in _principal_src if a})[:4]
    hosts = list({
        str(h) for h in (
            cluster_narrative.get('shared_hosts') or
            cluster_narrative.get('affected_hosts') or []
        ) if h
    })[:4]

    if rag_provider is not None:
        try:
            payload['prior_decisions'] = rag_provider.retrieve_prior_decisions(
                cluster_narrative.get('mitre_techniques') or [],
                persona_key,
                k=5,
            )
        except Exception:
            payload['prior_decisions'] = []
        try:
            payload['similar_incidents'] = rag_provider.retrieve_similar_incidents(
                cluster_narrative,
                k=5,
                lookback_days=90,
            )
        except Exception:
            payload['similar_incidents'] = []
        # IdentityGraph — lateral movement paths for this cluster's principals
        try:
            payload['identity_paths'] = rag_provider.retrieve_identity_context(
                principals, depth=3, path_limit=5,
            )
        except Exception:
            payload['identity_paths'] = []
        # ChronoGraph — long-horizon volume anomalies for principals and hosts
        try:
            payload['chrono_anomalies'] = rag_provider.retrieve_chrono_anomalies(
                principals, hosts, window_seconds=86400 * 7,
            )
        except Exception:
            payload['chrono_anomalies'] = []
        # ML anomaly history — prior ISO/EWMA signals for these principals
        try:
            payload['prior_ml_anomalies'] = rag_provider.retrieve_prior_ml_anomalies(
                principals, k=5,
            )
        except Exception:
            payload['prior_ml_anomalies'] = []
    else:
        payload['prior_decisions'] = []
        payload['similar_incidents'] = []
        payload['identity_paths'] = []
        payload['chrono_anomalies'] = []
        payload['prior_ml_anomalies'] = []

    # Compliance violations — pass through from cluster if pre-computed by Stage 5k
    payload['compliance_violations'] = cluster_narrative.get('compliance_violations') or {}

    return payload


def build_all_personas(cluster_narrative: dict,
                       register: dict | None = None,
                       evidence_rows: list[dict] | None = None,
                       cluster_id: str = '?',
                       rag_provider: Any = None) -> dict[str, dict]:
    """Build all personas at once."""
    return {
        p: build_persona_dispatch(p, cluster_narrative, register,
                                  evidence_rows, cluster_id,
                                  rag_provider=rag_provider)
        for p in ('soc_analyst', 'ciso', 'executive', 'threat_hunter',
                  'forensics', 'compliance', 'mssp', 'audit')
    }


__all__ = [
    'build_persona_dispatch',
    'build_all_personas',
    'ACTION_TIERS',
]
