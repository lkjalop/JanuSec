"""Row-normalisation enrichment pipeline.

Extracted from src.api.deep_analyze_endpoints during Phase A-3b.
All functions operate on plain dicts and carry no FastAPI/router state.
"""
from __future__ import annotations
import datetime
import ipaddress
import json
import logging
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from src.api.deep_analyze.helpers import _safe_text, _nested_get, _collect_strings_from_row
from src.api.deep_analyze.verdict_seed import _derive_human_validation_required

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Timestamp / description / entity field name tuples
# ---------------------------------------------------------------------------

_TS_FIELDS = (
    'timestamp', 'Timestamp', 'ts', 'time', 'created', 'created_at', 'event_time',
    'event_ts', 'last_seen', 'first_seen', 'TimeGenerated', 'ActivityDateTime',
    'eventTime', '@timestamp', 'datetime', 'date_time', 'startTime', 'endTime',
    'log_timestamp', 'detection_time', 'observed_at',
)
_DESC_FIELDS = (
    'analyst_notes', 'notes', 'description', 'Description', 'result_description',
    'defender_alert', 'alert_name', 'event_name', 'eventName', 'operation_name',
    'operationName', 'activityDisplayName', 'riskEventType', 'subject',
    'threat_category', 'category'
)
_ACCOUNT_FIELDS = (
    'user_principal_name', 'userPrincipalName', 'username', 'user', 'account',
    'caller_upn', 'caller', 'requestor', 'actor', 'actor_email', 'mailbox_owner',
    'identity', 'principal', 'principal_name', 'upn',
    # CloudTrail nested: userIdentity.userName / userIdentity.arn
    'userName', 'user_name', 'arn',
    # Okta nested: actor.alternateId / actor.displayName
    'alternateId', 'displayName',
    # M365 / Exchange: UserId / UserKey / SendingUserSmtp
    'UserId', 'UserKey', 'SendingUserSmtp',
    # Entra / AAD: UserPrincipalName variation
    'UPN', 'ObjectId',
)
# Nested dotted-path lookups for identity fields that live inside sub-objects.
# Format: tuple of (dotted_path, list_index_or_None) pairs.
# These fire after the flat-field scan and before email regex fallback.
_ACCOUNT_NESTED_PATHS = (
    # CloudTrail: {"userIdentity": {"userName": "...", "arn": "..."}}
    'userIdentity.userName',
    'userIdentity.arn',
    'userIdentity.principalId',
    # Okta: {"actor": {"alternateId": "...", "displayName": "..."}}
    'actor.alternateId',
    'actor.displayName',
    # Entra / AAD audit: {"initiatedBy": {"user": {"userPrincipalName": "..."}}}
    'initiatedBy.user.userPrincipalName',
    'initiatedBy.user.id',
    # Entra sign-in: {"userDisplayName": "..."} (already flat but keep path form for uniformity)
    'properties.userPrincipalName',
    'properties.userId',
    # SailPoint: {"actor": {"name": "..."}}
    'actor.name',
    # Generic nested target principal
    'target.userPrincipalName',
    'target.id',
)
_HOST_NESTED_PATHS = (
    # CloudTrail: requestParameters.instanceId
    'requestParameters.instanceId',
    # Defender/Sentinel: {"DeviceName": ...} (flat, but also sometimes nested)
    'entities.0.HostName',
    'entities.0.DeviceName',
    # Okta target device
    'target.0.displayName',
    'debugContext.debugData.requestUri',
)
_IP_NESTED_PATHS = (
    # CloudTrail: sourceIPAddress lives at top level but sometimes under requestParameters
    'requestParameters.sourceIPAddress',
    # Okta: {"client": {"ipAddress": "..."}}
    'client.ipAddress',
    # Entra: {"ipAddress": "..."} inside properties
    'properties.ipAddress',
    # AWS GuardDuty: service.action.networkConnectionAction.remoteIpDetails.ipAddressV4
    'service.action.networkConnectionAction.remoteIpDetails.ipAddressV4',
    'service.action.awsApiCallAction.remoteIpDetails.ipAddressV4',
)
_HOST_FIELDS = (
    'hostname', 'host', 'device_id', 'device_name', 'asset_name', 'computer',
    'computer_name', 'endpoint', 'instance_id', 'vm_name'
)
_IP_FIELDS = (
    'src_ip', 'source_ip', 'sourceIPAddress', 'ipAddress', 'ip', 'internal_ip',
    'dst_ip', 'destination_ip', 'public_ip', 'remote_ip', 'client_ip'
)
_RESOURCE_FIELDS = (
    'target_resource', 'resource_arn', 'file_name', 'attachment_name', 'path',
    'object_key', 'bucket', 'vault', 'app', 'application', 'service', 'database'
)
_EMAIL_RE = re.compile(r'\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b', re.I)
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_MITRE_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.I)
_SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
_LOW_VALUE_ACCOUNT_PIVOTS = {
    '-', 'n/a', 'na', 'none', 'null', 'unknown',
    'system', 'root', 'local service', 'network service',
    'nt authority\\system', 'nt authority\\local service', 'nt authority\\network service',
    'anonymous logon',
}

# Known CDN, SaaS, and major cloud egress CIDR prefixes that should never be
# classified as attacker infrastructure without explicit IOC context.
# These are /8 or /16 prefixes — intentionally coarse to avoid false positives
# while keeping the list short and auditable.
_VENDOR_EGRESS_PREFIXES: tuple = (
    # Cloudflare
    '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.',
    '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.',
    '162.158.', '198.41.128.', '198.41.129.',
    # Akamai
    '23.32.', '23.33.', '23.64.', '23.65.', '23.192.',
    # Fastly
    '151.101.', '199.232.',
    # AWS CloudFront / global accelerator
    '13.32.', '13.33.', '13.35.', '13.224.', '13.225.', '13.226.', '13.227.',
    '205.251.', '204.246.',
    # Google / GCP / Workspace
    '142.250.', '142.251.', '172.217.', '172.253.',
    '74.125.',
    # Microsoft / Azure / M365
    '13.104.', '13.105.', '13.106.', '13.107.',
    '13.64.', '13.65.', '13.66.', '13.67.', '13.68.', '13.69.', '13.70.',
    '40.64.', '40.65.', '40.66.', '40.67.', '40.68.', '40.69.', '40.70.',
    '52.224.', '52.225.', '52.226.', '52.227.',
    # Okta
    '23.246.',
    # Zscaler (common egress)
    '165.225.',
    # Proofpoint
    '148.163.',
    # Mimecast
    '91.220.42.',
    # Salesforce
    '136.146.',
    # Zoom
    '3.7.', '3.21.', '3.22.', '3.25.',
)

# ---------------------------------------------------------------------------
# Core helper functions
# ---------------------------------------------------------------------------


def _flatten_row_payload(row: dict | None, fallback_index: int) -> dict:
    """Merge top-level CSV row structure with nested raw payload."""
    if not isinstance(row, dict):
        return {'row_index': fallback_index}
    merged: dict[str, Any] = {}
    raw = row.get('raw')
    if isinstance(raw, dict):
        merged.update(raw)
    for key, value in row.items():
        if key == 'raw':
            continue
        merged[key] = value  # outer wrapper fields win (row_index must be global, not per-file)
    row_index_value = merged.get('row_index', fallback_index)
    try:
        if isinstance(row_index_value, int):
            merged['row_index'] = str(row_index_value)
        else:
            merged['row_index'] = row_index_value
    except Exception:
        merged['row_index'] = fallback_index
    return merged


def _safe_identity_text(value: Any) -> str:
    """Return scalar identity text only.

    Dict/list payloads must be handled through explicit nested extractors so
    raw provider objects do not become account pivots.
    """
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ''
    return str(value).strip()


def _is_low_value_account_pivot(value: Any) -> bool:
    text = _safe_identity_text(value).lower()
    if not text:
        return True
    return text in _LOW_VALUE_ACCOUNT_PIVOTS or text.endswith('\\system')


def _extract_first_value(row: dict, keys: Tuple[str, ...]) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ''):
            return _safe_text(value)
    return ''


def _parse_backend_timestamp(value: Any) -> float | None:
    if value in (None, ''):
        return None
    try:
        if isinstance(value, (int, float)):
            raw = float(value)
            return raw / 1000.0 if raw > 10_000_000_000 else raw
        text = _safe_text(value)
        if not text:
            return None
        if text.endswith('Z'):
            text = text[:-1] + '+00:00'
        text = text.replace('/', '-')
        try:
            return datetime.datetime.fromisoformat(text).timestamp()
        except Exception as _exc:
            logger.debug('silent_swallow at %s:%d: %s', __file__, 1874, _exc)
        for fmt in (
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
        ):
            try:
                return datetime.datetime.strptime(text, fmt).timestamp()
            except Exception:
                continue
    except Exception:
        return None
    return None


def _is_private_ip_text(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except Exception:
        return False


def _extract_from_typed_array(arr: Any, type_field: str = 'type', type_values: tuple = ('User', 'user'),
                               value_fields: tuple = ('alternateId', 'displayName', 'id', 'login')) -> List[str]:
    """Scan an array of typed objects (e.g. Okta target[]) and extract identity values.

    Avoids the `target.0.alternateId` trap that only sees the first element.
    Returns all unique non-empty values found across matching entries.
    """
    results: List[str] = []
    if not isinstance(arr, list):
        return results
    for entry in arr:
        if not isinstance(entry, dict):
            continue
        entry_type = _safe_text(entry.get(type_field))
        if type_values and entry_type.lower() not in {t.lower() for t in type_values}:
            continue
        for field in value_fields:
            val = _safe_text(entry.get(field))
            if val and val not in results:
                results.append(val)
    return results


def _account_fallback_text(row: dict) -> str:
    """Collect only account-bearing text for final email fallback.

    This intentionally avoids scanning non-user Okta target entries, because a
    group/application email in target[] is not an account pivot.
    """
    parts: List[str] = []
    for field in _ACCOUNT_FIELDS:
        value = _safe_identity_text(row.get(field))
        if value:
            parts.append(value)
    for path in _ACCOUNT_NESTED_PATHS:
        value = _safe_identity_text(_nested_get(row, path))
        if value:
            parts.append(value)
    for arr_field in ('target', 'targets', 'actor_targets'):
        parts.extend(_extract_from_typed_array(row.get(arr_field), type_values=('User', 'user', 'AppUser', 'SystemUser')))
    raw = row.get('raw')
    if isinstance(raw, dict):
        for field in _ACCOUNT_FIELDS:
            value = _safe_identity_text(raw.get(field))
            if value:
                parts.append(value)
        for path in _ACCOUNT_NESTED_PATHS:
            value = _safe_identity_text(_nested_get(raw, path))
            if value:
                parts.append(value)
        for arr_field in ('target', 'targets', 'actor_targets'):
            parts.extend(_extract_from_typed_array(raw.get(arr_field), type_values=('User', 'user', 'AppUser', 'SystemUser')))
    return ' '.join(parts)


def _extract_accounts_backend(row: dict) -> List[str]:
    values: List[str] = []
    for field in _ACCOUNT_FIELDS:
        value = _safe_identity_text(row.get(field))
        if value and value not in values:
            values.append(value)
    # Deep nested extraction (CloudTrail userIdentity, Okta actor, Entra initiatedBy, etc.)
    for path in _ACCOUNT_NESTED_PATHS:
        value = _safe_identity_text(_nested_get(row, path))
        if value and value not in values:
            values.append(value)
    # Okta / SailPoint typed-array targets — scan ALL entries, not just index 0
    for arr_field in ('target', 'targets', 'actor_targets'):
        arr = row.get(arr_field)
        for val in _extract_from_typed_array(arr, type_values=('User', 'user', 'AppUser', 'SystemUser')):
            if val not in values:
                values.append(val)
    # Also handle nested raw.target for events where original payload is wrapped
    raw = row.get('raw')
    if isinstance(raw, dict):
        for arr_field in ('target', 'targets'):
            arr = raw.get(arr_field)
            for val in _extract_from_typed_array(arr, type_values=('User', 'user', 'AppUser', 'SystemUser')):
                if val not in values:
                    values.append(val)
    for match in _EMAIL_RE.findall(_account_fallback_text(row)):
        if match not in values:
            values.append(match)
    return values[:8]


def _extract_hosts_backend(row: dict) -> List[str]:
    values: List[str] = []
    for field in _HOST_FIELDS:
        value = _safe_text(row.get(field))
        if value and value not in values:
            values.append(value)
    for path in _HOST_NESTED_PATHS:
        value = _safe_text(_nested_get(row, path))
        if value and value not in values:
            values.append(value)
    return values[:8]


def _extract_ips_backend(row: dict) -> List[str]:
    values: List[str] = []
    for field in _IP_FIELDS:
        value = _safe_text(row.get(field))
        if value and value not in values:
            values.append(value)
    for path in _IP_NESTED_PATHS:
        value = _safe_text(_nested_get(row, path))
        if value and value not in values and _IP_RE.match(value):
            values.append(value)
    for match in _IP_RE.findall(_collect_strings_from_row(row)):
        if match not in values:
            values.append(match)
    return values[:10]


def _extract_resources_backend(row: dict) -> List[str]:
    values: List[str] = []
    for field in _RESOURCE_FIELDS:
        value = _safe_text(row.get(field))
        if value and value not in values:
            values.append(value)
    return values[:8]


def _extract_tags_backend(row: dict, assessment: dict | None) -> Dict[str, List[str]]:
    tags: Dict[str, List[str]] = {'mitre': [], 'atlas': [], 'owasp_llm': []}

    def _add(bucket: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, list):
            for item in value:
                _add(bucket, item)
            return
        if isinstance(value, dict):
            for key in ('id', 'technique_id', 'technique', 'name'):
                if value.get(key):
                    _add(bucket, value.get(key))
            return
        text = _safe_text(value)
        if text and text not in tags[bucket]:
            tags[bucket].append(text)

    for source in (assessment or {}, row):
        _add('mitre', source.get('mitre'))
        _add('mitre', source.get('mitre_tags'))
        _add('mitre', source.get('techniques'))
        _add('atlas', source.get('atlas'))
        _add('owasp_llm', source.get('owasp_llm'))
        mappings = source.get('mapping_tags') or source.get('mappings') or {}
        if isinstance(mappings, dict):
            _add('mitre', mappings.get('mitre'))
            _add('atlas', mappings.get('atlas'))
            _add('owasp_llm', mappings.get('owasp_llm'))
        for entry in source.get('framework_mappings') or []:
            if not isinstance(entry, dict):
                continue
            framework = _safe_text(entry.get('framework')).lower()
            if framework == 'mitre_attack':
                _add('mitre', entry.get('id') or entry.get('name'))

    blob = _collect_strings_from_row(row)
    for item in _MITRE_RE.findall(blob):
        _add('mitre', item)
    # Lazy import: map_factors_to_tags is optional and lives in the parent package
    try:
        from src.analysis.explain_mapping import map_factors_to_tags as _mftt  # noqa: PLC0415
    except Exception:
        _mftt = None  # type: ignore
    if _mftt is not None:
        try:
            factor_tags = _mftt(row.get('factors') or [])
            if isinstance(factor_tags, dict):
                _add('mitre', factor_tags.get('mitre'))
                _add('atlas', factor_tags.get('atlas'))
                _add('owasp_llm', factor_tags.get('owasp_llm'))
        except Exception as _exc:
            logger.debug('silent_swallow at %s:%d: %s', __file__, 2076, _exc)
    for bucket in tags:
        tags[bucket] = tags[bucket][:8]
    return tags


def _classify_backend_severity(row: dict) -> str:
    for key in ('severity', 'alert_severity', 'risk_rating', 'review_state'):
        value = _safe_text(row.get(key)).lower()
        if value in _SEV_RANK:
            return value
    text = _collect_strings_from_row(row).lower()
    if any(token in text for token in ('global administrator', 'confirmed_malicious', 'cloudtrail logging disabled', 'lsass', 'exfil', 'ransomware')):
        return 'critical'
    if any(token in text for token in ('tor exit', 'mailbox rule', 'legacy auth', 'impossible travel', 'powershell', 'stager', 'c2', 'beacon')):
        return 'high'
    if any(token in text for token in ('suspicious', 'anomal', 'review', 'investigate')):
        return 'medium'
    return 'low'


def _severity_label_for_rows(rows: List[dict]) -> str:
    if not rows:
        return 'low'
    return sorted((_classify_backend_severity(row) for row in rows), key=lambda item: _SEV_RANK.get(item, 0), reverse=True)[0]


def _infer_cloud_provider(row: dict, assessment: dict | None = None) -> str:
    explicit = _safe_text(
        row.get('cloud_provider')
        or row.get('_provider_profile')
        or row.get('provider')
        or row.get('provider_profile')
    ).lower()
    if explicit in {'aws', 'azure', 'gcp', 'oci', 'multi_cloud', 'vmware', 'nutanix', 'openstack', 'okta', 'active_directory', 'email'}:
        return explicit
    source_sheet = _safe_text(row.get('_sheet') or row.get('sheet') or row.get('source') or '').lower()
    text = _collect_strings_from_row(row).lower()
    if 'cloud_aws' in source_sheet or any(token in text for token in ('aws', 'cloudtrail', 'guardduty', 'iam user', 'arn:aws')):
        return 'aws'
    if 'cloud_azure' in source_sheet or any(token in text for token in ('azure', 'entra', 'microsoft graph', 'subscription id')):
        return 'azure'
    if any(token in text for token in ('okta', 'okta verify', 'okta system log', 'okta fastpass')):
        return 'okta'
    if any(token in text for token in ('active directory', 'kerberos', 'ldap bind', 'domain controller', 'adfs', 'windows security')):
        return 'active_directory'
    if any(token in text for token in ('gcp', 'google cloud', 'gcloud', 'project id')):
        return 'gcp'
    if any(token in text for token in ('oracle cloud', 'oci', 'compartment ocid', 'tenancy ocid')):
        return 'oci'
    if any(token in text for token in ('vmware', 'vcenter', 'esxi')):
        return 'vmware'
    if any(token in text for token in ('nutanix', 'prism central')):
        return 'nutanix'
    if any(token in text for token in ('openstack', 'keystone', 'nova', 'neutron')):
        return 'openstack'
    if any(token in text for token in ('mailbox rule', 'message trace', 'exchange online', 'mail flow', 'proofpoint', 'mimecast', 'business email compromise', 'bec')):
        return 'email'
    return 'generic'


def _infer_plane(row: dict) -> str:
    text = _collect_strings_from_row(row).lower()
    if any(token in text for token in ('signin', 'login', 'role', 'sts', 'entra', 'iam', 'policy', 'control plane', 'admin')):
        return 'control_plane'
    if any(token in text for token in ('s3', 'blob', 'object', 'query', 'dataset', 'db', 'download', 'egress', 'data plane')):
        return 'data_plane'
    return 'unknown'


def _extract_cloud_context(row: dict, assessment: dict | None = None) -> dict:
    provider = _infer_cloud_provider(row, assessment)
    account_id = _extract_first_value(row, ['account_id', 'aws_account_id', 'account', 'recipientAccountId'])
    subscription_id = _extract_first_value(row, ['subscription_id', 'azure_subscription_id'])
    project_id = _extract_first_value(row, ['project_id', 'gcp_project_id', 'project'])
    compartment_id = _extract_first_value(row, ['compartment_id', 'compartment_ocid'])
    org_id = _extract_first_value(row, ['organization_id', 'org_id', 'tenant_id', 'azure_tenant_id'])
    region = _extract_first_value(row, ['region', 'awsRegion', 'location', 'azure_region'])
    resource_id = _extract_first_value(row, ['resource_id', 'resource_arn', 'target_resource', 'resource'])
    resource_type = _extract_first_value(row, ['resource_type', 'target_resource_type', 'serviceName', 'service'])
    return {
        'provider': provider,
        'org_id': org_id,
        'account_id': account_id,
        'subscription_id': subscription_id,
        'project_id': project_id,
        'compartment_id': compartment_id,
        'region': region,
        'resource_id': resource_id,
        'resource_type': resource_type,
        'control_plane': _infer_plane(row) == 'control_plane',
        'data_plane': _infer_plane(row) == 'data_plane',
        'plane': _infer_plane(row),
    }


def _extract_identity_context(row: dict) -> dict:
    text = _collect_strings_from_row(row).lower()
    role = _extract_first_value(row, ['identity_role', 'role', 'role_name', 'assigned_role', 'user_role'])
    session_id = _extract_first_value(row, ['session_id', 'sessionId', 'correlation_id', 'correlationId'])
    auth_strength = _extract_first_value(row, ['auth_strength', 'authentication_requirement', 'mfa_detail', 'authenticationMethodsUsed'])
    privilege_type = 'standing'
    privilege_state = 'normal'
    privilege_source = ''
    if any(token in text for token in ('just in time', 'jit', 'pim activated', 'temporary elevated', 'temporary privilege')):
        privilege_type = 'temporary'
        privilege_state = 'elevated'
        privilege_source = 'jit_or_pim'
    elif any(token in text for token in ('global administrator', 'privileged role administrator', 'role assigned', 'elevation', 'assume role', 'sts:assumerole')):
        privilege_type = 'escalated'
        privilege_state = 'elevated'
        privilege_source = 'role_change'
    elif any(token in text for token in ('token reuse', 'refresh token', 'session replay', 'legacy auth')):
        privilege_type = 'session_reuse'
        privilege_state = 'suspicious'
        privilege_source = 'session_anomaly'
    impossible_travel = any(token in text for token in ('impossible travel', 'atypical travel', 'geo-velocity', 'geovelocity'))
    if impossible_travel and privilege_state == 'normal':
        privilege_state = 'suspicious'
    return {
        'principal': _extract_first_value(row, ['user_principal_name', 'userPrincipalName', 'user', 'username', 'caller_upn', 'caller', 'requestor']),
        'user_id': _extract_first_value(row, ['user_id', 'actor_id', 'principal_id', 'userIdentity.arn']),
        'role': role,
        'privilege_state': privilege_state,
        'privilege_type': privilege_type,
        'privilege_source': privilege_source,
        'session_id': session_id,
        'auth_strength': auth_strength,
        'impossible_travel': impossible_travel,
    }


def _extract_network_context(row: dict) -> dict:
    src_ip = _extract_first_value(row, ['src_ip', 'source_ip', 'sourceIPAddress', 'ipAddress', 'internal_ip'])
    dst_ip = _extract_first_value(row, ['dst_ip', 'destination_ip', 'server_ip', 'target_ip'])
    subnet = _extract_first_value(row, ['subnet', 'subnet_id', 'vpc_subnet', 'network_subnet'])
    return {'src_ip': src_ip, 'dst_ip': dst_ip, 'subnet': subnet}


def _extract_policy_change_context(row: dict) -> dict:
    text = _collect_strings_from_row(row).lower()
    signals = []
    if any(token in text for token in ('policy drift', 'iam policy', 'attachrolepolicy', 'putrolepolicy', 'inline policy')):
        signals.append('iam_policy')
    if any(token in text for token in ('security group', 'sg-', 'nsg', 'firewall rule', 'subnet route', 'route table')):
        signals.append('network_policy')
    if any(token in text for token in ('config drift', 'terraform', 'opa', 'rego', 'policy as code', 'guardrail')):
        signals.append('config_guardrail')
    negated = any(token in text for token in ('without cab', 'without approval', 'no cab', 'not approved', 'unapproved'))
    approved = (not negated) and any(token in text for token in ('approved', 'cab', 'change ticket', 'service request', 'terraform apply by pipeline', 'maintenance window'))
    suspicious = bool(signals) and not approved
    if not signals:
        return {}
    return {
        'kind': 'policy_change',
        'signals': signals,
        'approved_change': approved,
        'suspicious_drift': suspicious,
        'summary': 'Approved policy change detected.' if approved else 'Policy drift or permission expansion requires corroboration.',
    }


def _extract_guest_onboarding_context(row: dict) -> dict:
    text = _collect_strings_from_row(row).lower()
    onboarding_markers = (
        'inviteexternaluser',
        'invited user',
        'external user',
        'b2b invite',
        'guest onboarding',
        'access package',
        'sponsor',
        'temporary guest',
        'guest access',
        'onboarding',
    )
    if not any(token in text for token in onboarding_markers):
        return {}
    approved = any(token in text for token in ('approved', 'ticket', 'manager approved', 'sponsor', 'mfa registered', 'access package'))
    suspicious = any(token in text for token in ('unexpected geo', 'asn rare', 'legacy auth', 'impossible travel', 'beacon', 'data exfil', 'privilege escalation'))
    category = 'benign_onboarding' if approved and not suspicious else 'needs_review'
    return {
        'kind': 'guest_onboarding',
        'category': category,
        'approved': approved,
        'suspicious': suspicious,
        'summary': 'Temporary guest onboarding appears approved and should remain benign unless corroborated.'
        if category == 'benign_onboarding'
        else 'Guest onboarding exists, but surrounding telemetry needs confirm/deny review before escalation.',
    }


def _extract_security_posture_context(row: dict) -> dict:
    text = _collect_strings_from_row(row).lower()
    vendors: List[str] = []
    if any(token in text for token in ('check point', 'checkpoint', 'gaia gateway', 'cp-gateway')):
        vendors.append('checkpoint')
    if any(token in text for token in ('palo alto', 'pan-os', 'panw', 'panorama', 'cortex data lake')):
        vendors.append('palo_alto')
    cdn_present = any(token in text for token in ('cloudfront', 'cdn', 'edge cache', 'fastly', 'akamai'))
    no_firewall = any(token in text for token in ('zero firewall', 'no firewall', 'without firewall', 'perimeter absent', 'no perimeter firewall'))
    benign_mfa = any(token in text for token in ('mfa registered', 'fido2 success', 'phishing-resistant mfa', 'approved mfa challenge', 'webauthn success'))
    compromised_mfa = any(token in text for token in ('mfa fatigue', 'push accepted from suspicious', 'compromised mfa', 'mfa bypass', 'sim swap', 'prompt bombing'))
    if not vendors and not cdn_present and not no_firewall and not benign_mfa and not compromised_mfa:
        return {}
    if no_firewall:
        perimeter_mode = 'none'
    elif len(vendors) >= 2:
        perimeter_mode = 'dual_firewall'
    elif len(vendors) == 1:
        perimeter_mode = 'single_firewall'
    else:
        perimeter_mode = 'edge_only' if cdn_present else 'unspecified'
    return {
        'kind': 'security_posture',
        'vendors': vendors,
        'cdn_present': cdn_present,
        'perimeter_mode': perimeter_mode,
        'benign_mfa': benign_mfa,
        'compromised_mfa': compromised_mfa,
        'summary': (
            'No perimeter firewall telemetry is present; rely on cloud-native logs and east-west flow evidence.'
            if perimeter_mode == 'none'
            else 'Layered perimeter telemetry is available to confirm or deny ingress and egress hypotheses.'
            if perimeter_mode == 'dual_firewall'
            else 'Partial perimeter telemetry is available and should be cross-checked with cloud-native logs.'
        ),
    }


def _extract_event_context(row: dict) -> dict:
    return {
        'action': _extract_first_value(row, ['eventName', 'event_name', 'operationName', 'operation_name', 'activityDisplayName', 'action']),
        'service': _extract_first_value(row, ['serviceName', 'service', 'service_name']),
        'method': _extract_first_value(row, ['http_method', 'method', 'request_method']),
    }


def _build_bitemporal_trace(timestamp_text: str | None, assessment: dict | None = None) -> dict:
    event_ts = _parse_backend_timestamp(timestamp_text)
    decision_raw = None
    if isinstance(assessment, dict):
        decision_raw = assessment.get('updated_at') or assessment.get('generated_at') or assessment.get('created_at')
    if isinstance(decision_raw, (int, float)):
        decision_ts = float(decision_raw)
    else:
        decision_ts = time.time()
    lag = int(max(0.0, decision_ts - event_ts)) if event_ts is not None else None
    return {
        'event_time': timestamp_text,
        'event_epoch': event_ts,
        'decision_time': datetime.datetime.utcfromtimestamp(decision_ts).isoformat() + 'Z',
        'decision_epoch': decision_ts,
        'observed_lag_seconds': lag,
    }


def _extract_evidence_mode(row: dict, assessment: dict | None = None) -> str:
    mode = _safe_text(row.get('_intake_mode') or row.get('intake_mode') or row.get('source_kind')).lower()
    if not mode and isinstance(assessment, dict):
        options = assessment.get('options') or {}
        mode = _safe_text(options.get('intake_mode') or assessment.get('intake_mode')).lower()
    if mode in {'live', 'stream'}:
        return 'live'
    if mode in {'merged', 'hybrid'}:
        return 'merged'
    return 'snapshot'


def _extract_freshness(ts_epoch: float | None) -> dict:
    if ts_epoch is None:
        return {'freshness_ts': None, 'freshness_age_seconds': None, 'freshness_state': 'unknown'}
    age = max(0.0, time.time() - float(ts_epoch))
    if age <= 3600:
        state = 'fresh'
    elif age <= 86400:
        state = 'recent'
    else:
        state = 'historical'
    return {'freshness_ts': ts_epoch, 'freshness_age_seconds': int(age), 'freshness_state': state}


def _normalize_assessment_rows(assessment: dict) -> List[dict]:
    # Lazy import to avoid circular dependency while _compute_triage_score
    # remains in deep_analyze_endpoints pending a future extract phase
    from src.api.deep_analyze_endpoints import _compute_triage_score  # noqa: PLC0415
    source_rows = assessment.get('rows') or []
    llm_by_index: Dict[int, dict] = {}
    for entry in assessment.get('llm_rows') or []:
        try:
            llm_by_index[int(entry.get('row_index'))] = entry
        except Exception:
            continue

    normalized: List[dict] = []
    for idx, source in enumerate(source_rows):
        flat = _flatten_row_payload(source, idx)
        try:
            row_index = int(flat.get('row_index') or idx)
        except Exception:
            row_index = idx
        llm_row = llm_by_index.get(row_index) or {}
        merged = {**flat, **llm_row}
        ts_text = _extract_first_value(merged, _TS_FIELDS)
        accounts = _extract_accounts_backend(merged)
        hosts = _extract_hosts_backend(merged)
        ips = _extract_ips_backend(merged)
        resources = _extract_resources_backend(merged)
        tags = _extract_tags_backend(merged, assessment)
        triage = float(merged.get('triage_score') or _compute_triage_score(merged) or 0.0)
        cloud = _extract_cloud_context(merged, assessment)
        identity = _extract_identity_context(merged)
        network = _extract_network_context(merged)
        policy_ctx = _extract_policy_change_context(merged)
        guest_ctx = _extract_guest_onboarding_context(merged)
        security_posture = _extract_security_posture_context(merged)
        event_ctx = _extract_event_context(merged)
        bitemporal = _build_bitemporal_trace(ts_text, assessment)
        evidence_mode = _extract_evidence_mode(merged, assessment)
        freshness = _extract_freshness(_parse_backend_timestamp(ts_text))
        human_validation_required = _derive_human_validation_required(merged, policy_ctx, guest_ctx)
        normalized.append({
            **merged,
            'row_index': row_index,
            'timestamp': ts_text,
            'timestamp_epoch': _parse_backend_timestamp(ts_text),
            'source_sheet': _safe_text(merged.get('_sheet') or merged.get('sheet') or merged.get('source') or merged.get('_source') or 'unknown'),
            'entity': _extract_first_value(merged, _ACCOUNT_FIELDS + _HOST_FIELDS + _IP_FIELDS + _RESOURCE_FIELDS) or '-',
            'description': _extract_first_value(merged, _DESC_FIELDS),
            'severity': _classify_backend_severity(merged),
            'triage_score': triage,
            'accounts': accounts,
            'hosts': hosts,
            'ips': ips,
            'external_ips': [
                ip for ip in ips
                if not _is_private_ip_text(ip)
                and (_is_ioc_confirmed(ip) or not _is_vendor_egress_ip(ip))
            ],
            'resources': resources,
            'mitre': tags['mitre'],
            'atlas': tags['atlas'],
            'owasp_llm': tags['owasp_llm'],
            'cloud': cloud,
            'identity': identity,
            'network': network,
            'event': event_ctx,
            'policy_change_context': policy_ctx,
            'guest_onboarding_context': guest_ctx,
            'security_posture_context': security_posture,
            'evidence_mode': evidence_mode,
            'bitemporal_trace': bitemporal,
            **freshness,
            'provider_profile': cloud.get('provider'),
            'cloud_boundary': (
                cloud.get('account_id')
                or cloud.get('subscription_id')
                or cloud.get('project_id')
                or cloud.get('compartment_id')
                or cloud.get('org_id')
            ),
            'privilege_state': identity.get('privilege_state'),
            'privilege_type': identity.get('privilege_type'),
            'session_id': identity.get('session_id'),
            'impossible_travel': bool(identity.get('impossible_travel')),
            'human_validation_required': human_validation_required,
        })
    return normalized


def _is_vendor_egress_ip(ip: str) -> bool:
    """Return True if ip looks like CDN/SaaS/cloud egress that shouldn't be attacker infra."""
    for prefix in _VENDOR_EGRESS_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _is_ioc_confirmed(ip: str) -> bool:
    """Return True if the threat intel store has an active IOC entry for this IP.

    IOC hits always override the vendor allowlist — a Cloudflare IP appearing in
    an active feed is a legitimate threat indicator (e.g. proxy abuse, malicious CDN node).
    Fails silently so a degraded TI client never breaks clustering.
    """
    try:
        from src.integrations.threat_intel_client import CLIENT as _TI  # noqa: PLC0415
        return bool(_TI.is_malicious_ip(ip))
    except Exception:
        return False


def _extract_attacker_ips(row: dict) -> frozenset:
    """IPs most likely to represent attacker-controlled infrastructure (source/initiator side).

    Excludes RFC1918 addresses AND known CDN/SaaS/cloud egress ranges to avoid
    misclassifying customer VPNs, cloud service IPs, and SaaS providers as C2.
    Exception: if the TI store has an active IOC for the IP it is always included,
    even if it falls in a vendor prefix range (e.g. abused CDN node, compromised SaaS egress).
    """
    result = set()
    for field in ('src_ip', 'source_ip', 'remote_ip', 'origin_ip', 'originating_ip',
                  'attacker_ip', 'c2_ip', 'client_ip', 'initiator_ip'):
        v = str(row.get(field) or '').strip()
        if not v or v in ('-', 'N/A', '', '0.0.0.0'):
            continue
        if _is_private_ip_text(v):
            continue
        # IOC-confirmed IPs bypass the vendor allowlist
        if _is_ioc_confirmed(v) or not _is_vendor_egress_ip(v):
            result.add(v)
    return frozenset(result)
