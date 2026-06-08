"""IAM Phases 3 and 4 detectors (Kerberos & persistence; Azure AD/OAuth/PIM).

All functions are feature-flagged using the same flags as earlier phases.
They return (factors, attributions) with (node_id, factor) pairs to attach
to HopGraph when available.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


# ---------------- Phase 3: Kerberos & Persistence (Identity-side) ----------------
def detect_identity_phase3(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    attrs: List[Tuple[str, str]] = []
    # Accept VESPER NDJSON field names (account_name, windows_event_id) alongside normalised names
    user = str(
        payload.get('user') or payload.get('user_canonical') or
        payload.get('actor') or payload.get('account_name') or ''
    )
    etype = str(
        payload.get('event_type') or payload.get('operation') or payload.get('action') or
        payload.get('event_name') or payload.get('activityDisplayName') or ''
    ).lower()
    obj = str(payload.get('object') or payload.get('dn') or payload.get('path') or '').lower()

    # Windows Event ID field — accept both VESPER and XML/normalised names
    win_eid = str(
        payload.get('windows_event_id') or payload.get('event_id') or payload.get('EventID') or ''
    ).strip()
    pre_auth = str(payload.get('pre_auth_type') or payload.get('PreAuthType') or '').strip()
    enc_type = str(
        payload.get('ticket_encryption') or payload.get('ticket_encryption_type')
        or payload.get('TicketEncryptionType') or ''
    ).strip()
    ticket_opts = str(payload.get('ticket_options') or payload.get('TicketOptions') or '').strip()

    # AS-REP roasting: pre-authentication disabled (EventID 4768, PreAuthType 0)
    if (('as-rep' in etype) or ('asrep' in etype) or ('preauth disabled' in obj)
            or (win_eid == '4768' and pre_auth in ('0', '0x0'))):
        f = 'iam:as_rep_roasting'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # Kerberoasting: RC4-downgraded TGS (EventID 4769, etype 0x17)
    if win_eid == '4769' and enc_type in ('0x17', '0x18', '23', '18'):
        _target_svc = str(
            payload.get('service_name') or payload.get('target_service_name') or
            payload.get('target_user_name') or payload.get('ServiceName') or ''
        ).strip().lower()
        _requester = str(payload.get('account_name') or payload.get('user') or payload.get('user_canonical') or '').strip().lower()
        _exclude_svcs = {
            s.strip().lower() for s in
            os.getenv('KERBEROAST_EXCLUDE_SERVICES', '').split(',') if s.strip()
        }
        if not (_exclude_svcs and (_target_svc in _exclude_svcs or _requester in _exclude_svcs)):
            f = 'iam:kerberoasting'
            factors.append(f)
            if user:
                attrs.append((f'user:{user}', f))

    # Golden Ticket: forged TGT with anomalous ticket options
    if win_eid == '4769' and enc_type in ('0x17', '0x18') and ticket_opts in (
        '0x60a10000', '0x40a10000', '0x60810000', '0x60a00000',
    ):
        f = 'iam:golden_ticket'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # Kerberos delegation abuse (unconstrained or constrained abuse)
    if ('delegation' in etype) or ('trustedfordelegation' in obj) or ('msds-allowedtodelegateto' in obj):
        f = 'iam:kerberos_delegation_abuse'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # SID History injection
    if ('sidhistory' in obj) and any(k in etype for k in ('add','modify','change','update')):
        f = 'iam:sid_history_injection'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    return factors, attrs


# ---------------- Phase 3: Persistence (Endpoint-side) ----------------
def detect_endpoint_phase3(event: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    attrs: List[Tuple[str, str]] = []
    host = str(event.get('host') or '')
    proc = ''
    try:
        p = event.get('process') or {}
        proc = (p.get('name') or '')
    except Exception:
        proc = ''
    cmd = str((event.get('process') or {}).get('command') or event.get('command') or '')
    file_path = str(event.get('file') or event.get('path') or '')
    reg_path = str(event.get('registry_path') or event.get('reg') or '')
    low_cmd = cmd.lower()
    low_file = file_path.lower()
    low_reg = reg_path.lower()

    # SSP DLL into LSASS
    if ('lsass' in low_cmd or 'lsass.exe' in low_cmd or 'lsass' in proc.lower()) and ('ssp' in low_cmd or 'ssp' in low_file):
        f = 'iam:security_support_provider_dll'
        factors.append(f)
        if host:
            attrs.append((f'host:{host}', f))
        if proc:
            attrs.append((f'process:{proc}', f))

    # Authentication Packages registry modification (LSA/Winlogon)
    if ('authentication packages' in low_reg) or ('lsa\\authentication packages' in low_cmd) or ('winlogon' in low_reg and 'authentication packages' in low_reg):
        f = 'iam:authentication_package_modification'
        factors.append(f)
        if host:
            attrs.append((f'host:{host}', f))
        if proc:
            attrs.append((f'process:{proc}', f))

    return factors, attrs


# ---------------- Phase 4: Azure AD / OAuth / PIM (Identity-side) ----------------
def detect_cloud_identity_phase4(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    attrs: List[Tuple[str, str]] = []
    user = str(
        payload.get('user') or payload.get('user_canonical') or payload.get('actor') or
        payload.get('userPrincipalName') or payload.get('user_principal_name') or ''
    )
    etype = str(
        payload.get('event_type') or payload.get('operation') or payload.get('action') or
        payload.get('event_name') or payload.get('activityDisplayName') or ''
    ).lower()
    app = str(
        payload.get('app') or payload.get('application') or payload.get('appId') or
        payload.get('app_id') or payload.get('client_id') or payload.get('service_principal') or ''
    )
    raw = dict(payload.get('raw') or {})
    signals = dict(raw.get('signals') or {})

    # Device code phishing: extremely rapid approval or explicit signal
    try:
        dt = float(raw.get('device_code_approval_seconds') or 0.0)
    except Exception:
        dt = 0.0
    if (dt and dt < 10.0) or ('device_code_phishing' in etype) or signals.get('device_code_phishing'):
        f = 'iam:azure_device_code_phishing'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # OAuth consent to suspicious app
    publisher = str(raw.get('app_publisher') or payload.get('app_publisher') or payload.get('publisher') or '')
    verified = str(raw.get('app_verified') or payload.get('app_verified') or payload.get('verifiedPublisher') or '').lower() in {'1','true','yes'}
    scopes = str(payload.get('scopes') or payload.get('oauth_scope') or payload.get('consent_scopes') or raw.get('scopes') or '').lower()
    if not scopes:
        for target in payload.get('targetResources') or []:
            if not isinstance(target, dict):
                continue
            for prop in target.get('modifiedProperties') or []:
                if not isinstance(prop, dict):
                    continue
                name = str(prop.get('displayName') or '').lower()
                if 'permission' in name or 'scope' in name:
                    scopes += ' ' + str(prop.get('newValue') or '').lower()
    excessive = any(scope in scopes for scope in ('mail.read', 'files.read.all', 'user.read.all', 'offline_access'))
    if ('oauth_consent' in etype or 'consent' in etype or 'grant' in etype) and (not verified or 'unknown' in publisher.lower() or excessive):
        f = 'iam:oauth_consent_grant_suspicious_app'
        factors.append(f)
        if app:
            attrs.append((f'app:{app}', f))
        if user:
            attrs.append((f'user:{user}', f))

    # Legacy auth usage
    if ('legacy_auth' in etype) or signals.get('legacy_auth') is True:
        f = 'iam:azure_legacy_auth'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # Conditional access bypass
    if ('conditional_access' in etype and 'bypass' in etype) or signals.get('conditional_access_bypass') is True:
        f = 'iam:conditional_access_bypass'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # PIM activation anomaly
    if ('pim' in etype and 'activate' in etype) or signals.get('pim_activation_anomaly') is True:
        f = 'iam:azure_privileged_role_activation_unusual'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # Risky sign-in (AAD Identity Protection)
    if ('risky_sign_in' in etype) or signals.get('risky_sign_in') is True or payload.get('risky') is True:
        f = 'iam:entra_id_risky_sign_in'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # Service principal credential add (AAD addKey/addPassword — persistence indicator)
    target_text = str(payload.get('targetResources') or '').lower()
    if any(k in etype for k in ('addkey', 'addpassword', 'add key credential', 'add password credential', 'certificate', 'secret')) or any(k in target_text for k in ('asymmetricx509cert', 'keydescription', 'keyidentifier')):
        f = 'iam:service_principal_credential_add'
        factors.append(f)
        if app:
            attrs.append((f'app:{app}', f))
        if user:
            attrs.append((f'user:{user}', f))

    return factors, attrs
