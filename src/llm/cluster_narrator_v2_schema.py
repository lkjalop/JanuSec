"""Cluster narrator v2 schema additions — tenant-agnostic.

REPLACES v1 hardcoded tokens. Sensitivity now comes from (priority order):

  1. Tenant DataClassificationConfig — explicit table → sensitivity map
  2. Data-catalog tag lookup — Snowflake/AWS Glue/Unity Catalog
  3. Generic schema-naming conventions (RESTRICTED, VAULT, CONFIDENTIAL, etc.)
  4. PII pattern detection on query text — generic regex

If none resolve, sensitivity is 'unknown' (NOT 'low') so analysts
see that the platform doesn't know rather than getting a false-low.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any, Protocol


# ── Generic conventions only (industry-standard, not tenant-specific) ────────

_GENERIC_RESTRICTED_SCHEMA_TOKENS = (
    'RESTRICTED', 'VAULT', 'CONFIDENTIAL', 'SECRET', 'PRIVATE',
    'PII', 'PHI', 'CARDHOLDER', 'CHD', 'GDPR', 'CLASSIFIED',
)

_PII_COLUMN_PATTERNS = (
    re.compile(r'\b(email|email_addr|email_address)\b', re.I),
    re.compile(r'\b(ssn|social_security|tfn|nino|sin)\b', re.I),
    re.compile(r'\b(date_of_birth|dob|birthdate)\b', re.I),
    re.compile(r'\b(passport|driver_license|driving_licence|drivers_license)\b', re.I),
    re.compile(r'\b(credit_card|card_number|pan|ccnum)\b', re.I),
    re.compile(r'\b(phone|mobile|telephone)_?(number|num)?\b', re.I),
    re.compile(r'\b(home_address|residential_address|postal_code|zipcode|zip_code|postcode)\b', re.I),
    re.compile(r'\b(medicare|medicaid|nhs_number|health_record)\b', re.I),
    re.compile(r'\b(bank_account|iban|bsb|routing_number|account_number)\b', re.I),
)

_CREDENTIAL_TOKENS = (
    'lsass', 'secret', 'access_key', 'access_token',
    'refresh_token', 'private_key', 'oauth_token',
    'api_key', 'service_account_key',
)

# Bulletproof hosting / high-abuse ASNs (Spamhaus DROP / AbuseIPDB consensus).
# Tenant config can extend or override via 'known_bad_asns' key.
_KNOWN_BPH_ASNS: dict[str, str] = {
    'AS44477': 'Stark Industries Solutions — BPH provider',
    'AS202425': 'IP Volume Inc — BPH reseller',
    'AS209588': 'Flyservers SA — BPH provider',
    'AS60068': 'DATACAMP Ltd — BPH/botnet hosting',
    'AS35830': 'FOZZY-NET — abuse-prone',
    'AS57588': 'Hayat for Internet & Communication',
    'AS206485': 'Serverius Holding B.V. — Spamhaus listed',
    'AS196695': 'RootLayer Web Services',
    'AS59711': 'HZ Hosting — BPH',
    'AS9009': 'M247 Ltd — abuse-prone',
    'AS24961': 'MYLOC Managed IT — bulk abuse reports',
    'AS8100': 'QuadraNet Enterprises — abuse-prone',
    'AS29073': 'Quasi Networks (Novogara) — BPH',
    'AS48721': 'Flynet — BPH provider',
    'AS203557': 'CIKTEL — abuse-prone',
}

# High-risk country codes: OFAC-sanctioned + high APT-activity (public sources).
_HIGH_RISK_COUNTRY_CODES: frozenset[str] = frozenset({
    'RU', 'BY', 'KP', 'IR', 'CN', 'SY', 'CU', 'VE', 'MM', 'SD',
    'SO', 'LY', 'IQ', 'NG',
})


# ── Tenant configuration interfaces ──────────────────────────────────────────

class CatalogTagProvider(Protocol):
    """Pluggable interface for fetching data-catalog tags."""
    def get_table_sensitivity(self, fully_qualified_name: str) -> str | None: ...
    def get_table_classes(self, fully_qualified_name: str) -> list[str]: ...


class TenantDataClassification:
    """Tenant-supplied classification config loaded from per-tenant YAML/JSON."""

    def __init__(self, config: dict | None = None):
        config = config or {}
        self.sensitivity_by_table: dict[str, str] = {
            k.upper(): v.lower() for k, v in (config.get('sensitivity_by_table') or {}).items()
        }
        self.classes_by_table: dict[str, list[str]] = {
            k.upper(): list(v) for k, v in (config.get('classes_by_table') or {}).items()
        }
        self.extra_pii_patterns: list[re.Pattern] = [
            re.compile(p, re.I) for p in (config.get('extra_pii_patterns') or [])
        ]
        self.extra_restricted_schemas: tuple[str, ...] = tuple(
            s.upper() for s in (config.get('extra_restricted_schemas') or [])
        )
        # Tenant-supplied override for known-bad ASNs (merged with builtin list).
        self.known_bad_asns: dict[str, str] = {
            k.upper() if k.upper().startswith('AS') else f'AS{k}'.upper(): v
            for k, v in (config.get('known_bad_asns') or {}).items()
        }
        # Tenant-supplied trusted IP allowlist (for compromised-allowlist detection).
        self.allowlist_ips: frozenset[str] = frozenset(config.get('allowlist_ips') or [])

    def lookup_table_sensitivity(self, fqn: str) -> str | None:
        return self.sensitivity_by_table.get(fqn.upper())

    def lookup_table_classes(self, fqn: str) -> list[str]:
        return list(self.classes_by_table.get(fqn.upper()) or [])

    def restricted_schema_tokens(self) -> tuple[str, ...]:
        return _GENERIC_RESTRICTED_SCHEMA_TOKENS + self.extra_restricted_schemas

    def pii_patterns(self) -> list[re.Pattern]:
        return list(_PII_COLUMN_PATTERNS) + self.extra_pii_patterns


# ── Network / principal extraction ───────────────────────────────────────────

_RFC1918_PREFIXES = (
    '10.', '192.168.',
    '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
    '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
)


def _is_rfc1918(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    if ip.startswith(_RFC1918_PREFIXES):
        return True
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def _extract_external_ips(rows: list[dict]) -> Counter:
    c: Counter = Counter()
    for r in rows:
        for f in ('src_ip', 'dst_ip', 'remote_address', 'sourceIPAddress',
                  'ClientIP', 'client_ip', 'ip', 'ipAddress'):
            ip = r.get(f)
            if isinstance(ip, str) and ip and not _is_rfc1918(ip):
                c[ip] += 1
        cli = r.get('client') or {}
        if isinstance(cli, dict):
            ip = cli.get('ipAddress')
            if isinstance(ip, str) and ip and not _is_rfc1918(ip):
                c[ip] += 1
    return c


def _extract_geo_asn(rows: list[dict]) -> tuple[set[str], set[str]]:
    countries: set[str] = set()
    asns: set[str] = set()
    for r in rows:
        for f in ('geo_country', 'country', 'src_country', 'dst_country'):
            v = r.get(f)
            if isinstance(v, str) and v:
                countries.add(v)
        for f in ('asn', 'src_asn', 'dst_asn', 'asn_name'):
            v = r.get(f)
            if isinstance(v, (str, int)) and v:
                asns.add(str(v))
        geo = r.get('geo') or {}
        if isinstance(geo, dict):
            for sub in geo.values():
                if isinstance(sub, dict):
                    if sub.get('country'):
                        countries.add(str(sub['country']))
                    if sub.get('asn'):
                        asns.add(str(sub['asn']))
        dbg = (r.get('debugContext') or {}).get('debugData') or {}
        reason = str(dbg.get('reason') or '')
        m = re.search(r'AS\d{1,7}', reason)
        if m:
            asns.add(m.group(0))
    return countries, asns


def _augment_principals_from_cloud_idp(
        rows: list[dict],
        users: set[str],
        svc_accts: set[str],
        cloud_roles: set[str],
        cloud_access_keys: set[str],
        idp_sources: set[str],
) -> None:
    """Augment principal sets from Entra ID, GCP, Google Workspace, SailPoint, Oracle Cloud.

    Modifies all passed sets in-place; records detected IDP source names in idp_sources.
    """
    for r in rows:
        # ── Azure / Entra ID sign-in & activity logs ──────────────────────
        props = r.get('properties') or {}
        if isinstance(props, dict):
            upn = props.get('userPrincipalName')
            if isinstance(upn, str) and upn:
                users.add(upn)
                idp_sources.add('entra_id')
            sp_id = props.get('servicePrincipalId') or props.get('appId')
            if isinstance(sp_id, str) and sp_id:
                svc_accts.add(f'azure_sp:{sp_id}')
                idp_sources.add('entra_id')
            mi = props.get('managedIdentityObjectId')
            if isinstance(mi, str) and mi:
                cloud_roles.add(f'azure_managed_identity:{mi}')
                idp_sources.add('azure')
            # Token/session hint
            if props.get('authenticationDetails') or props.get('conditionalAccessStatus'):
                idp_sources.add('entra_id')
        # Azure activity log: operationName + callerIpAddress pattern
        if r.get('operationName') and r.get('callerIpAddress'):
            caller = r.get('callerIpAddress') or ''
            if isinstance(caller, str) and caller:
                idp_sources.add('azure_activity')

        # ── GCP Cloud Audit Logs ──────────────────────────────────────────
        proto_payload = r.get('protoPayload') or {}
        if isinstance(proto_payload, dict):
            auth_info = proto_payload.get('authenticationInfo') or {}
            if isinstance(auth_info, dict):
                principal = (auth_info.get('principalEmail')
                             or auth_info.get('principalSubject'))
                if isinstance(principal, str) and principal:
                    if principal.endswith('.iam.gserviceaccount.com'):
                        svc_accts.add(principal)
                    else:
                        users.add(principal)
                    idp_sources.add('gcp')
                # Service account delegation chain
                for d in (auth_info.get('serviceAccountDelegationInfo') or []):
                    if isinstance(d, dict):
                        sa_raw = (d.get('principalSubject')
                                  or (d.get('firstPartyPrincipal') or {}).get('principalEmail'))
                        if isinstance(sa_raw, str) and sa_raw:
                            # Strip IAM resource type prefix (serviceAccount:, user:, group:)
                            sa = sa_raw.split(':', 1)[-1] if ':' in sa_raw else sa_raw
                            svc_accts.add(sa)
                            idp_sources.add('gcp')
            method = proto_payload.get('methodName') or ''
            service = proto_payload.get('serviceName') or ''
            if service and method:
                cloud_roles.add(f'gcp:{service}:{method}')
                idp_sources.add('gcp')

        # ── Google Workspace / Gmail audit logs ───────────────────────────
        actor = r.get('actor') or {}
        if isinstance(actor, dict):
            email = actor.get('email')
            if isinstance(email, str) and email:
                users.add(email)
                idp_sources.add('google_workspace')
            key = actor.get('key')   # OAuth2 client ID
            if isinstance(key, str) and key and key != email:
                svc_accts.add(f'gws_oauth:{key}')
                idp_sources.add('google_workspace')
            # SailPoint: actor has explicit 'type' field
            actor_type = actor.get('type') or ''
            if actor_type in ('IDENTITY', 'SOURCE', 'RULE', 'SYSTEM'):
                name = actor.get('name')
                if isinstance(name, str) and name:
                    if actor_type == 'IDENTITY':
                        users.add(name)
                    else:
                        svc_accts.add(f'sailpoint:{name}')
                    idp_sources.add('sailpoint')

        # ── SailPoint IIQ / IdentityNow — target object ───────────────────
        sp_target = r.get('target') or {}
        if isinstance(sp_target, dict):
            tname = sp_target.get('name')
            ttype = (sp_target.get('type') or '').upper()
            if isinstance(tname, str) and tname and 'APP' in ttype:
                svc_accts.add(f'sailpoint_app:{tname}')
                idp_sources.add('sailpoint')

        # ── Oracle Cloud Infrastructure audit logs ────────────────────────
        data_block = r.get('data') or {}
        if isinstance(data_block, dict):
            pname = data_block.get('principalName')
            if isinstance(pname, str) and pname:
                if pname.startswith('ocid1.'):
                    cloud_roles.add(pname)
                else:
                    users.add(pname)
                idp_sources.add('oracle_cloud')
            pid = data_block.get('principalId')
            if isinstance(pid, str) and pid and pid.startswith('ocid'):
                cloud_access_keys.add(pid)
                idp_sources.add('oracle_cloud')
        # OCI event type hint
        oci_type = r.get('type') or ''
        if isinstance(oci_type, str) and oci_type.startswith('com.oraclecloud.'):
            idp_sources.add('oracle_cloud')


def _extract_principals(rows: list[dict]) -> dict:
    """Extract human users, service accounts, hosts, cloud roles, and AWS
    access keys from proper source fields (not heuristics on ARNs)."""
    users: set[str] = set()
    svc_accts: set[str] = set()
    hosts: set[str] = set()
    cloud_roles: set[str] = set()
    cloud_access_keys: set[str] = set()
    idp_sources: set[str] = set()

    for r in rows:
        for f in ('user', 'user_name', 'userName', 'username',
                  'user_principal_name', 'UserId', 'actor_id'):
            v = r.get(f)
            if isinstance(v, str) and v and v.lower() not in ('-', 'n/a', 'system'):
                low = v.lower()
                if (low.startswith(('svc_', 'service_', 'sa-', 'svc-'))
                        or low.endswith(('_service', '_svc', '_sa'))
                        or '$' in v):
                    svc_accts.add(v)
                else:
                    users.add(v)
        actor = r.get('actor') or {}
        if isinstance(actor, dict):
            aid = actor.get('alternateId') or actor.get('displayName')
            if isinstance(aid, str) and aid:
                users.add(aid)
        ui = r.get('userIdentity') or {}
        if isinstance(ui, dict):
            uname = ui.get('userName')
            if isinstance(uname, str) and uname:
                users.add(uname)
            arn = ui.get('arn') or ''
            if 'assumed-role/' in arn:
                cloud_roles.add(arn)
            akid = ui.get('accessKeyId')
            if isinstance(akid, str) and akid:
                cloud_access_keys.add(akid)
        for f in ('device_id', 'host', 'hostname', 'agent_id', 'ComputerName'):
            v = r.get(f)
            if isinstance(v, str) and v:
                hosts.add(v)
        kuser = (r.get('user') or {}).get('username') if isinstance(r.get('user'), dict) else None
        if isinstance(kuser, str) and kuser.startswith('system:serviceaccount:'):
            svc_accts.add(kuser)

    # Augment with multi-cloud IDP sources (Entra/GCP/GWS/SailPoint/Oracle)
    _augment_principals_from_cloud_idp(
        rows, users, svc_accts, cloud_roles, cloud_access_keys, idp_sources,
    )

    return {
        'users': sorted(users),
        'service_accounts': sorted(svc_accts),
        'hosts': sorted(hosts),
        'cloud_roles': sorted(cloud_roles),
        'cloud_access_keys': sorted(cloud_access_keys),
        'idp_sources': sorted(idp_sources),
    }


# ── Schema-driven sensitivity / data-class detection ─────────────────────────

_TABLE_FQN_RE = re.compile(
    r'(?:FROM|INTO|UPDATE|DESC\s+TABLE|TABLE|JOIN)\s+'
    r'([A-Z_][A-Z0-9_]*\.[A-Z_][A-Z0-9_]*\.[A-Z_][A-Z0-9_]*'
    r'|[A-Z_][A-Z0-9_]*\.[A-Z_][A-Z0-9_]*)',
    re.IGNORECASE,
)


def _detect_table_sensitivity(fqn: str,
                              tenant_class: TenantDataClassification | None,
                              catalog_tags: CatalogTagProvider | None) -> str | None:
    fqn_u = fqn.upper()

    if tenant_class:
        s = tenant_class.lookup_table_sensitivity(fqn_u)
        if s:
            return s

    if catalog_tags:
        try:
            s = catalog_tags.get_table_sensitivity(fqn_u)
            if s:
                return s
        except Exception:
            pass

    schema_tokens = (
        tenant_class.restricted_schema_tokens()
        if tenant_class else _GENERIC_RESTRICTED_SCHEMA_TOKENS
    )
    parts = fqn_u.split('.')
    if any(tok in p for p in parts for tok in schema_tokens):
        return 'high'

    return None


def _detect_table_classes(fqn: str,
                          query_text: str,
                          tenant_class: TenantDataClassification | None,
                          catalog_tags: CatalogTagProvider | None) -> set[str]:
    out: set[str] = set()
    fqn_u = fqn.upper()

    if tenant_class:
        out.update(tenant_class.lookup_table_classes(fqn_u))

    if catalog_tags:
        try:
            out.update(catalog_tags.get_table_classes(fqn_u) or [])
        except Exception:
            pass

    patterns = (tenant_class.pii_patterns()
                if tenant_class else list(_PII_COLUMN_PATTERNS))
    if any(p.search(query_text) for p in patterns):
        out.add('customer_pii')

    return out


def _extract_affected_data(rows: list[dict],
                           tenant_class: TenantDataClassification | None,
                           catalog_tags: CatalogTagProvider | None) -> dict:
    tables: set[str] = set()
    classes: set[str] = set()
    record_count = 0
    crown_jewel = False
    sensitivities: list[str] = []

    for r in rows:
        qt = r.get('query_text') or r.get('command_line') or ''
        if not isinstance(qt, str) or not qt:
            qt = ''

        for m in _TABLE_FQN_RE.finditer(qt):
            fqn = m.group(1).upper()
            tables.add(fqn)
            sens = _detect_table_sensitivity(fqn, tenant_class, catalog_tags)
            if sens:
                sensitivities.append(sens)
                if sens == 'crown_jewel':
                    crown_jewel = True
            cls = _detect_table_classes(fqn, qt, tenant_class, catalog_tags)
            classes.update(cls)

        cl = r.get('command_line') or r.get('file_path') or ''
        if isinstance(cl, str):
            low = cl.lower()
            if any(tok in low for tok in _CREDENTIAL_TOKENS):
                classes.add('credentials')

        rp = r.get('rows_produced')
        if isinstance(rp, (int, float)) and rp > 0:
            record_count += int(rp)
            for fqn_match in re.findall(_TABLE_FQN_RE, qt):
                if isinstance(fqn_match, str):
                    fqn_u = fqn_match.upper()
                    schema_tokens = (
                        tenant_class.restricted_schema_tokens()
                        if tenant_class else _GENERIC_RESTRICTED_SCHEMA_TOKENS
                    )
                    if any(tok in fqn_u for tok in schema_tokens) and rp > 100_000:
                        crown_jewel = True

        op = r.get('Operation') or ''
        if isinstance(op, str) and op in (
            'FileDownloaded', 'FileAccessed', 'FileSyncDownloadedFull',
            'FileExported', 'FileMalwareDetected',
        ):
            classes.add('cloud_files_unclassified')

    if crown_jewel:
        top_sens = 'crown_jewel'
    elif 'high' in sensitivities or 'customer_pii' in classes or 'credentials' in classes:
        top_sens = 'high'
    elif 'moderate' in sensitivities or classes:
        top_sens = 'moderate'
    elif sensitivities:
        # We have explicit sensitivity determinations (from tenant config,
        # catalog tags, or schema convention) — use the lowest one.
        top_sens = 'low'
    else:
        # Tables may be observed but nothing resolved their sensitivity.
        # Report 'unknown' — false-low is worse than no-answer.
        top_sens = 'unknown'

    return {
        'tables': sorted(tables),
        'record_count_estimate': record_count if record_count > 0 else None,
        'classes': sorted(classes),
        'sensitivity': top_sens,
        'crown_jewel_touched': crown_jewel,
        'sensitivity_evidence_source': _evidence_source_summary(
            tenant_class, catalog_tags, len(tables) > 0
        ),
    }


def _evidence_source_summary(tenant_class, catalog_tags, has_tables) -> str:
    if not has_tables:
        return 'no_tables_observed'
    sources: list[str] = []
    if tenant_class:
        sources.append('tenant_config')
    if catalog_tags:
        sources.append('catalog_tags')
    sources.append('schema_naming_convention')
    sources.append('pii_column_patterns')
    return '+'.join(sources)


# ── Attacker infrastructure / discovery ──────────────────────────────────────

_STAGE_PATTERNS = [
    re.compile(r"CREATE\s+(?:OR\s+REPLACE\s+)?STAGE\s+\S+\s+URL\s*=\s*'([^']+)'", re.I),
    re.compile(r"COPY\s+INTO\s+(@\S+)", re.I),
]
_FILE_STAGE_PATTERNS = [
    re.compile(r'(C:\\Users\\Public\\[^\s"]+)', re.I),
    re.compile(r'(/tmp/[^\s"]+\.(?:7z|tar|zip|gz))', re.I),
    re.compile(r'\barchive_\d+\.(?:7z|tar|zip|gz)', re.I),
]
_EXFIL_PATTERNS = [
    re.compile(r'\b(mega\.nz|mega\.io|backblaze|rclone:\S+|dropbox\.com'
               r'|wetransfer\.com|filebin\.net|anonfiles\.com|gofile\.io)\b', re.I),
    re.compile(r'\bs3://[\w\-\.]+', re.I),
]


def _extract_attacker_infra(rows: list[dict],
                            ext_ips: Counter) -> dict:
    staging: set[str] = set()
    exfil: set[str] = set()

    for r in rows:
        for f in ('query_text', 'command_line', 'requestURI'):
            v = r.get(f) or ''
            if not isinstance(v, str) or not v:
                continue
            for p in _STAGE_PATTERNS + _FILE_STAGE_PATTERNS:
                for m in p.finditer(v):
                    staging.add(m.group(0).strip())
            for p in _EXFIL_PATTERNS:
                for m in p.finditer(v):
                    exfil.add(m.group(0).strip())
        notes = r.get('notes') or ''
        if isinstance(notes, str):
            for p in _EXFIL_PATTERNS:
                for m in p.finditer(notes):
                    exfil.add(m.group(0).strip())
        cl = r.get('command_line') or ''
        if isinstance(cl, str) and 'schtasks' in cl.lower() and '/Create' in cl:
            tn_m = re.search(r'/TN\s+"?([^"\s/]+)"?', cl)
            if tn_m:
                staging.add(f'scheduled_task:{tn_m.group(1)}')

    countries, asns = _extract_geo_asn(rows)

    return {
        'external_ips': [ip for ip, _ in ext_ips.most_common(8)],
        'asns': sorted(asns),
        'countries': sorted(countries),
        'staging_resources': sorted(staging)[:10],
        'exfil_destinations': sorted(exfil)[:10],
    }


def _extract_discovery(rows: list[dict], cluster: dict) -> dict:
    pentest_ref = None
    edr_detect = None
    rtr_op = None
    first_ts = None
    detect_ts = None

    for r in rows:
        ts = (r.get('timestamp') or r.get('eventTime') or
              r.get('published') or r.get('CreationTime'))
        if isinstance(ts, str):
            if first_ts is None or ts < first_ts:
                first_ts = ts
        if r.get('_pentest_ref'):
            pentest_ref = str(r['_pentest_ref'])
            detect_ts = ts
        if r.get('event_simpleName') == 'DetectionSummaryEvent':
            edr_detect = r.get('detect_id')
            if not detect_ts:
                detect_ts = ts
        if r.get('event_simpleName') == 'RtrExecutedCommand' and not rtr_op:
            rtr_op = r.get('operator')

    if pentest_ref:
        source, who = 'external_pentest', pentest_ref
    elif edr_detect:
        source, who = 'edr_detection', edr_detect
    elif rtr_op:
        source, who = 'analyst', rtr_op
    else:
        source, who = 'deterministic_pipeline', cluster.get('cluster_id', 'unknown')

    lag = None
    if first_ts and detect_ts and first_ts < detect_ts:
        try:
            from datetime import datetime
            f = datetime.fromisoformat(first_ts.replace('Z', '+00:00'))
            d = datetime.fromisoformat(detect_ts.replace('Z', '+00:00'))
            lag = int((d - f).total_seconds())
        except (ValueError, TypeError):
            pass

    return {
        'source': source,
        'who': who,
        'when': detect_ts or first_ts,
        'first_evidence_at': first_ts,
        'lag_seconds_from_first_evidence': lag,
    }


# ── Network / security log signal extraction ─────────────────────────────────

def _extract_network_signals(rows: list[dict]) -> dict:
    """Extract structured signals from network and security log sources.

    Handles: Zeek conn/dns/ssl/http logs, Suricata alerts, Palo Alto NGFW,
    generic firewall deny logs, Wazuh rule alerts, CDN/WAF blocks.
    """
    ids_alerts: list[dict] = []
    firewall_blocks: list[dict] = []
    wazuh_alerts: list[dict] = []
    cdn_waf_blocks: list[dict] = []
    zeek_dst_ips: set[str] = set()
    zeek_protocols: set[str] = set()
    zeek_long_conns: int = 0
    zeek_dns_queries: set[str] = set()
    seen_alert_keys: set[str] = set()

    for r in rows:
        # ── Suricata EVE JSON ─────────────────────────────────────────────
        if r.get('event_type') == 'alert' and isinstance(r.get('alert'), dict):
            a = r['alert']
            sig = a.get('signature') or ''
            key = f"suricata:{sig}:{r.get('src_ip')}:{r.get('dest_ip')}"
            if key not in seen_alert_keys:
                seen_alert_keys.add(key)
                mitre = []
                for t in ((a.get('metadata') or {}).get('mitre_technique_id') or []):
                    if isinstance(t, str):
                        mitre.append(t)
                ids_alerts.append({
                    'source': 'suricata',
                    'signature': sig,
                    'category': a.get('category') or '',
                    'severity': a.get('severity'),
                    'src_ip': r.get('src_ip'),
                    'dst_ip': r.get('dest_ip'),
                    'proto': r.get('proto'),
                    'mitre_techniques': mitre,
                })

        # ── Zeek conn.log ─────────────────────────────────────────────────
        id_block = r.get('id') or {}
        if isinstance(id_block, dict) and id_block.get('resp_h'):
            dst = id_block['resp_h']
            if not _is_rfc1918(str(dst)):
                zeek_dst_ips.add(str(dst))
            proto = r.get('proto') or r.get('service') or ''
            if proto:
                zeek_protocols.add(str(proto))
            dur = r.get('duration')
            if isinstance(dur, (int, float)) and dur > 3600:
                zeek_long_conns += 1

        # ── Zeek dns.log ──────────────────────────────────────────────────
        q = r.get('query')
        if isinstance(q, str) and q and r.get('rcode_name') is not None:
            zeek_dns_queries.add(q)

        # ── Zeek ssl.log ──────────────────────────────────────────────────
        if r.get('server_name') and r.get('validation_status') is not None:
            zeek_protocols.add('tls')

        # ── Palo Alto NGFW (CSV syslog export) ───────────────────────────
        threat_id = (r.get('threat_id') or r.get('Threat/Content Name') or
                     r.get('ThreatID') or '')
        pa_type = (r.get('type') or r.get('log_type') or '').upper()
        pa_action = r.get('action') or r.get('Action') or ''
        if (str(threat_id) or pa_type in ('THREAT',)) and pa_action:
            src_ip = (r.get('src') or r.get('Source address') or
                      r.get('src_ip') or r.get('Src IP') or '')
            dst_ip = (r.get('dst') or r.get('Destination address') or
                      r.get('dst_ip') or r.get('Dst IP') or '')
            key = f"paloalto:{threat_id}:{src_ip}:{dst_ip}"
            if key not in seen_alert_keys:
                seen_alert_keys.add(key)
                ids_alerts.append({
                    'source': 'paloalto',
                    'signature': str(threat_id),
                    'category': (r.get('category') or r.get('Category') or
                                 r.get('Threat Category') or ''),
                    'severity': r.get('severity') or r.get('Severity') or '',
                    'src_ip': str(src_ip),
                    'dst_ip': str(dst_ip),
                    'rule': r.get('rule') or r.get('Rule') or '',
                    'app': r.get('app') or r.get('Application') or '',
                    'action': str(pa_action),
                    'mitre_techniques': [],
                })

        # ── Generic firewall deny (not Palo Alto) ─────────────────────────
        fw_action = str(r.get('action') or r.get('fw_action') or '').upper()
        if fw_action in ('DENY', 'DROP', 'REJECT', 'BLOCK') and pa_type not in ('THREAT',):
            src_ip = str(r.get('src_ip') or r.get('src') or r.get('source_ip') or '')
            dst_ip = str(r.get('dst_ip') or r.get('dst') or r.get('dest_ip') or '')
            if src_ip and dst_ip and not _is_rfc1918(src_ip):
                firewall_blocks.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'rule': str(r.get('rule') or r.get('policy') or ''),
                    'port': str(r.get('dst_port') or r.get('dport') or ''),
                    'proto': str(r.get('proto') or r.get('protocol') or ''),
                })

        # ── Wazuh alerts ──────────────────────────────────────────────────
        rule_block = r.get('rule') or {}
        agent_block = r.get('agent') or {}
        if isinstance(rule_block, dict) and rule_block.get('id'):
            level = rule_block.get('level') or 0
            try:
                level = int(level)
            except (TypeError, ValueError):
                level = 0
            if level >= 7:   # only medium+ severity
                mitre_block = rule_block.get('mitre') or {}
                mitre_techniques = []
                if isinstance(mitre_block, dict):
                    for t in (mitre_block.get('technique') or []):
                        if isinstance(t, str):
                            mitre_techniques.append(t)
                wazuh_alerts.append({
                    'rule_id': rule_block.get('id'),
                    'description': rule_block.get('description') or '',
                    'level': level,
                    'groups': list(rule_block.get('groups') or []),
                    'mitre_techniques': mitre_techniques,
                    'agent_name': (agent_block.get('name')
                                   if isinstance(agent_block, dict) else None),
                    'agent_ip': (agent_block.get('ip')
                                 if isinstance(agent_block, dict) else None),
                })

        # ── CDN / WAF (Cloudflare, Akamai, Fastly) ───────────────────────
        waf_action = str(
            r.get('WAFAction') or r.get('waf_action') or
            r.get('EdgeWAFAction') or r.get('WAFRuleAction') or ''
        ).upper()
        if waf_action in ('BLOCK', 'CHALLENGE', 'DROP', 'MANAGED_CHALLENGE'):
            cdn_waf_blocks.append({
                'client_ip': str(
                    r.get('ClientIP') or r.get('client_ip') or
                    r.get('OriginatingIP') or ''
                ),
                'waf_action': waf_action,
                'uri': str(
                    r.get('ClientRequestURI') or r.get('cs-uri-stem') or
                    r.get('uri') or r.get('request_uri') or ''
                ),
                'status': str(r.get('EdgeResponseStatus') or r.get('sc-status') or ''),
                'country': str(r.get('ClientCountry') or r.get('country') or ''),
                'rule_id': str(r.get('WAFRuleID') or r.get('waf_rule_id') or ''),
            })

    return {
        'ids_alerts': ids_alerts[:25],
        'firewall_blocks': firewall_blocks[:20],
        'wazuh_alerts': wazuh_alerts[:20],
        'cdn_waf_blocks': cdn_waf_blocks[:15],
        'zeek_summary': {
            'unique_external_dst_count': len(zeek_dst_ips),
            'protocols_seen': sorted(zeek_protocols),
            'long_duration_conn_count': zeek_long_conns,
            'unique_dns_queries': len(zeek_dns_queries),
        },
        'log_sources_detected': _detect_log_sources(
            ids_alerts, firewall_blocks, wazuh_alerts,
            cdn_waf_blocks, zeek_dst_ips,
        ),
    }


def _detect_log_sources(ids_alerts, firewall_blocks, wazuh_alerts,
                        cdn_waf_blocks, zeek_dst_ips) -> list[str]:
    """Return a sorted list of log source types that contributed signals."""
    sources: set[str] = set()
    for a in ids_alerts:
        sources.add(a.get('source') or 'ids_unknown')
    if firewall_blocks:
        sources.add('firewall')
    if wazuh_alerts:
        sources.add('wazuh')
    if cdn_waf_blocks:
        sources.add('cdn_waf')
    if zeek_dst_ips:
        sources.add('zeek')
    return sorted(sources)


# ── Threat intelligence cross-reference ──────────────────────────────────────

def _extract_threat_intel_flags(
        ext_ips: Counter,
        countries: set[str],
        asns: set[str],
        tenant_class: TenantDataClassification | None,
) -> dict:
    """Cross-reference network observables against public threat intelligence baselines.

    Detects:
      - IPs/ASNs in known bulletproof hosting / high-abuse autonomous systems
      - Connections from OFAC-sanctioned or high-APT-activity countries
      - Tenant trusted allowlist IPs that appear in live external traffic
        (possible compromised trusted entry-point or allow-rule bypass)
    """
    # Build effective BPH lookup: builtins + tenant overrides
    bph_lookup = dict(_KNOWN_BPH_ASNS)
    if tenant_class:
        bph_lookup.update(tenant_class.known_bad_asns)

    allowlist_ips: frozenset[str] = (
        tenant_class.allowlist_ips if tenant_class else frozenset()
    )

    def _norm_asn(a: str) -> str:
        s = str(a).strip().upper()
        return s if s.startswith('AS') else f'AS{s}'

    flagged_asns: list[dict] = []
    for asn_raw in asns:
        norm = _norm_asn(asn_raw)
        if norm in bph_lookup:
            flagged_asns.append({
                'asn': norm,
                'flag': 'bulletproof_hosting_or_abuse_prone',
                'description': bph_lookup[norm],
                'source': 'public_bph_list',
            })

    geo_risk_hits = sorted(_HIGH_RISK_COUNTRY_CODES & countries)

    # Compromised allowlist: external IPs observed in live traffic that are
    # also in the tenant's trusted IP allowlist — possible trusted-path abuse.
    compromised_allowlist: list[dict] = []
    for ip, count in ext_ips.most_common():
        if ip in allowlist_ips:
            compromised_allowlist.append({
                'ip': ip,
                'observation_count': count,
                'note': (
                    'IP is in tenant trusted allowlist but observed in '
                    'external attacker-correlated traffic — possible '
                    'compromised trusted entry-point or allowlist bypass'
                ),
            })
        if len(compromised_allowlist) >= 10:
            break

    return {
        'flagged_asns': flagged_asns,
        'high_risk_countries': geo_risk_hits,
        'compromised_allowlist_hits': compromised_allowlist,
        'bph_asn_count': len(flagged_asns),
        'geo_risk_country_count': len(geo_risk_hits),
    }


# ── Public entry point ───────────────────────────────────────────────────────

def enrich_narrative(narrative: dict,
                     cluster: dict,
                     evidence: list[dict],
                     *,
                     tenant_classification: TenantDataClassification | None = None,
                     catalog_tags: CatalogTagProvider | None = None) -> dict:
    """Add deterministic structured blocks to an LLM narrative.

    Tenant-agnostic by default. Pass tenant_classification and
    catalog_tags to get higher-fidelity sensitivity detection.

    Blocks added (all use setdefault — won't overwrite LLM-generated values):
      attacker_infrastructure  — IPs, ASNs, staging, exfil destinations
      affected_principals      — users, service accounts, hosts, cloud roles,
                                 access keys, idp_sources (which IDPs seen)
      affected_data            — tables, sensitivity, PII classes, crown jewel
      discovery                — source, who, when, dwell-time lag
      network_signals          — IDS alerts, firewall blocks, Wazuh, CDN WAF,
                                 Zeek stats (Suricata/PAN/generic/Wazuh/CDN)
      threat_intel_flags       — BPH ASNs, geo-risk countries,
                                 compromised allowlist hits
    """
    if not isinstance(narrative, dict):
        narrative = {}

    ext_ips = _extract_external_ips(evidence)
    principals = _extract_principals(evidence)
    attacker_infra = _extract_attacker_infra(evidence, ext_ips)
    affected_data = _extract_affected_data(evidence, tenant_classification, catalog_tags)
    discovery = _extract_discovery(evidence, cluster)
    network_signals = _extract_network_signals(evidence)

    # Threat intel cross-reference needs countries + ASNs from attacker_infra
    countries = set(attacker_infra.get('countries') or [])
    asns = set(attacker_infra.get('asns') or [])
    threat_flags = _extract_threat_intel_flags(
        ext_ips, countries, asns, tenant_classification,
    )

    narrative.setdefault('attacker_infrastructure', attacker_infra)
    narrative.setdefault('affected_principals', principals)
    narrative.setdefault('affected_data', affected_data)
    narrative.setdefault('discovery', discovery)
    narrative.setdefault('network_signals', network_signals)
    narrative.setdefault('threat_intel_flags', threat_flags)

    return narrative


__all__ = [
    'enrich_narrative',
    'TenantDataClassification',
    'CatalogTagProvider',
]
