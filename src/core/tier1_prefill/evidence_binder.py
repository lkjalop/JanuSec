"""Evidence binder — row resolution and entity-set helpers for Tier-1 prefill."""
from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


def _row_ref(row: dict) -> int | None:
    for key in ('row_index', 'row_number'):
        value = row.get(key)
        try:
            return int(value)
        except Exception:
            continue
    return None


def _field_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, dict):
        if value.get('username'):
            return str(value.get('username'))
        if value.get('resource') or value.get('namespace') or value.get('subresource'):
            return '/'.join(
                str(value.get(k))
                for k in ('resource', 'subresource', 'namespace', 'name')
                if value.get(k)
            )
        try:
            return json.dumps(value, sort_keys=True)
        except Exception:
            return str(value)
    return str(value)


def _row_actor(row: dict) -> str:
    for key in ('user_principal_name', 'username', 'user_name', 'UserId', 'user', 'account', 'actor', 'hostname', 'host'):
        value = row.get(key)
        if value not in (None, ''):
            return _field_text(value)
    return 'affected entity'


def _detect_row_source(row: dict) -> str:
    """Identify the data source for a row based on characteristic fields."""
    explicit = str(row.get('_source') or row.get('source') or '').lower()
    if explicit:
        for token in ('okta', 'entra', 'azure_ad', 'aad'):
            if token in explicit:
                return 'okta'
        for token in ('m365', 'sharepoint', 'teams', 'exchange', 'o365', 'office365'):
            if token in explicit:
                return 'm365'
        for token in ('proofpoint', 'mimecast', 'email', 'mail'):
            if token in explicit:
                return 'email'
        for token in ('zeek', 'network', 'bro', 'netflow', 'pcap'):
            if token in explicit:
                return 'network'
        for token in ('crowdstrike', 'falcon', 'edr', 'endpoint'):
            if token in explicit:
                return 'edr'
        for token in ('cloudtrail', 'aws', 'guardduty'):
            if token in explicit:
                return 'aws'
        for token in ('snowflake', 'database', 'query_history'):
            if token in explicit:
                return 'data'
        for token in ('sailpoint', 'iam'):
            if token in explicit:
                return 'iam'

    # Heuristic: characteristic field presence
    if row.get('displayName') or row.get('activityDisplayName') or row.get('userPrincipalName'):
        return 'okta'
    if row.get('Workload') or row.get('Operation') or row.get('ClientIP') or row.get('SiteUrl'):
        return 'm365'
    if row.get('email_from') or row.get('sender') or row.get('email_subject') or row.get('dkim_result'):
        return 'email'
    if row.get('proto') or row.get('ja3') or row.get('ja4') or row.get('orig_bytes') or row.get('ts') and row.get('id.orig_h'):
        return 'network'
    if row.get('event_simpleName') or row.get('CommandLine') or row.get('SHA256HashData'):
        return 'edr'
    if row.get('eventName') or row.get('awsRegion') or row.get('userIdentity'):
        return 'aws'
    if row.get('query_text') or row.get('query_type') or row.get('warehouse_name') or row.get('database_name'):
        return 'data'
    return 'generic'


def _row_action_text(row: dict) -> str:
    """Produce a human-readable sentence describing what this row represents.

    Source-aware: extracts the most meaningful fields per data source so that
    the attack timeline reads as specific observations, not generic boilerplate.
    """
    src = _detect_row_source(row)

    def _s(v) -> str:
        return _field_text(v).strip() if v not in (None, '') else ''

    def _trunc(s: str, n: int = 120) -> str:
        s = re.sub(r'\s+', ' ', s).strip()
        return s[:n] + '…' if len(s) > n else s

    # ── Okta / Entra ID / Azure AD ───────────────────────────────────────────
    if src == 'okta':
        event = _s(row.get('activityDisplayName') or row.get('displayName') or row.get('event_type') or '')
        user = _s(row.get('user_principal_name') or row.get('userPrincipalName') or row.get('username') or '')
        result = _s(row.get('outcome_result') or row.get('result') or row.get('outcome') or '')
        ip = _s(row.get('source_ip') or row.get('client_ip') or row.get('ipAddress') or '')
        device = _s(row.get('device_name') or row.get('deviceDetail_displayName') or '')
        geo = row.get('_geo') or {}
        location = _s(geo.get('city') or geo.get('country') or '')
        geo_ctx = row.get('context') or {}
        if isinstance(geo_ctx, dict):
            g = geo_ctx.get('geographicalContext') or {}
            if isinstance(g, dict):
                location = location or _s(g.get('city') or g.get('country') or '')

        parts = []
        if event:
            parts.append(event)
        if user:
            parts.append(f"user: {user}")
        if result:
            parts.append(f"result: {result.upper()}")
        if ip:
            parts.append(f"from: {ip}")
        if location:
            parts.append(f"({location})")
        if device:
            parts.append(f"device: {device}")
        if parts:
            return _trunc(' · '.join(parts))
        return 'Okta authentication event.'

    # ── Microsoft 365 (SharePoint, Teams, Exchange, OneDrive) ────────────────
    if src == 'm365':
        operation = _s(row.get('Operation') or row.get('operation') or row.get('activityDisplayName') or '')
        user = _s(row.get('UserId') or row.get('user_principal_name') or '')
        workload = _s(row.get('Workload') or row.get('workload') or '')
        obj = _s(row.get('ObjectId') or row.get('object_id') or row.get('SiteUrl') or '')
        client_ip = _s(row.get('ClientIP') or row.get('client_ip') or '')
        target = _s(row.get('TargetUserOrGroupName') or '')

        parts = []
        if workload:
            parts.append(f"[{workload}]")
        if operation:
            parts.append(operation)
        if obj:
            leaf = obj.split('/')[-1] or obj
            parts.append(f"→ {_trunc(leaf, 60)}")
        if user:
            parts.append(f"user: {user}")
        if target:
            parts.append(f"target: {target}")
        if client_ip:
            parts.append(f"from: {client_ip}")
        if parts:
            return _trunc(' '.join(parts))
        return 'Microsoft 365 activity event.'

    # ── Email (Proofpoint, Mimecast) ─────────────────────────────────────────
    if src == 'email':
        sender = _s(row.get('email_from') or row.get('sender') or row.get('from_address') or '')
        recipient = _s(row.get('email_to') or row.get('recipient') or row.get('to_address') or '')
        subject = _s(row.get('email_subject') or row.get('subject') or '')
        disposition = _s(row.get('disposition') or row.get('action') or row.get('verdict') or '')
        domain = _s(row.get('sender_domain') or '')
        url = _s(row.get('url_clicked') or row.get('threat_url') or '')

        parts = []
        if disposition:
            parts.append(f"[{disposition.upper()}]")
        if sender:
            parts.append(f"from: {sender}")
        elif domain:
            parts.append(f"domain: {domain}")
        if recipient:
            parts.append(f"to: {recipient}")
        if subject:
            parts.append(f"subject: \"{_trunc(subject, 60)}\"")
        if url:
            parts.append(f"url: {_trunc(url, 60)}")
        if parts:
            return _trunc(' · '.join(parts))
        return 'Email event.'

    # ── Network (Zeek/Bro, Netflow, PCAP) ───────────────────────────────────
    if src == 'network':
        proto = _s(row.get('proto') or row.get('protocol') or '')
        src_ip = _s(row.get('id.orig_h') or row.get('src_ip') or row.get('source_ip') or '')
        dst_ip = _s(row.get('id.resp_h') or row.get('dst_ip') or row.get('dest_ip') or row.get('remote_address') or '')
        dst_port = str(row.get('id.resp_p') or row.get('dst_port') or row.get('dest_port') or '')
        ja3 = _s(row.get('ja3') or row.get('ja3s') or '')
        ja4 = _s(row.get('ja4') or '')
        bytes_out = row.get('orig_bytes') or row.get('bytes_sent') or row.get('bytes') or 0
        sni = _s(row.get('server_name') or row.get('sni') or '')

        parts = []
        if proto:
            parts.append(proto.upper())
        if src_ip:
            parts.append(f"{src_ip}")
        if dst_ip:
            dst_str = dst_ip + (f":{dst_port}" if dst_port else '')
            parts.append(f"→ {dst_str}")
        if sni:
            parts.append(f"SNI: {sni}")
        if ja3:
            parts.append(f"JA3: {ja3[:16]}…" if len(ja3) > 16 else f"JA3: {ja3}")
        elif ja4:
            parts.append(f"JA4: {ja4[:16]}…" if len(ja4) > 16 else f"JA4: {ja4}")
        try:
            b = int(bytes_out)
            if b > 1_000_000_000:
                parts.append(f"{b / 1e9:.1f}GB out")
            elif b > 1_000_000:
                parts.append(f"{b / 1e6:.1f}MB out")
            elif b > 0:
                parts.append(f"{b:,}B out")
        except Exception:
            pass
        if parts:
            return _trunc(' · '.join(parts))
        return 'Network connection event.'

    # ── EDR (CrowdStrike Falcon, SentinelOne) ────────────────────────────────
    if src == 'edr':
        event_name = _s(row.get('event_simpleName') or row.get('EventType') or '')
        process = _s(row.get('FileName') or row.get('process_name') or row.get('ImageFileName') or '')
        cmdline = _s(row.get('CommandLine') or row.get('command_line') or '')
        host = _s(row.get('ComputerName') or row.get('hostname') or row.get('host') or '')
        user = _s(row.get('UserName') or row.get('username') or '')
        sha = _s(row.get('SHA256HashData') or row.get('sha256') or '')

        parts = []
        if event_name:
            parts.append(event_name)
        if process:
            parts.append(f"process: {process}")
        if user:
            parts.append(f"user: {user}")
        if host:
            parts.append(f"host: {host}")
        if cmdline:
            parts.append(f"cmd: {_trunc(cmdline, 80)}")
        if sha:
            parts.append(f"sha256: {sha[:16]}…")
        if parts:
            return _trunc(' · '.join(parts))
        return 'Endpoint detection event.'

    # ── AWS CloudTrail ───────────────────────────────────────────────────────
    if src == 'aws':
        event = _s(row.get('eventName') or '')
        service = _s(row.get('eventSource') or '')
        region = _s(row.get('awsRegion') or '')
        identity = row.get('userIdentity') or {}
        principal = _s(identity.get('principalId') or identity.get('arn') or '' if isinstance(identity, dict) else '')
        src_ip = _s(row.get('sourceIPAddress') or '')
        error = _s(row.get('errorCode') or '')

        parts = []
        if service:
            parts.append(f"[{service.replace('.amazonaws.com', '')}]")
        if event:
            parts.append(event)
        if error:
            parts.append(f"ERROR: {error}")
        if principal:
            parts.append(f"principal: {_trunc(principal, 50)}")
        if region:
            parts.append(f"region: {region}")
        if src_ip:
            parts.append(f"from: {src_ip}")
        if parts:
            return _trunc(' · '.join(parts))
        return 'AWS CloudTrail event.'

    if src == 'data':
        qtype = _s(row.get('query_type') or row.get('operation') or '')
        user = _s(row.get('user_name') or row.get('user') or row.get('username') or '')
        db = _s(row.get('database_name') or row.get('schema_name') or '')
        app = _s(row.get('client_application_id') or '')
        ip = _s(row.get('client_ip') or row.get('source_ip') or '')
        query = _s(row.get('query_text') or '')
        rows_out = _s(row.get('rows_produced') or '')
        bytes_scanned = _s(row.get('bytes_scanned') or '')

        parts = []
        if qtype:
            parts.append(qtype.upper())
        if user:
            parts.append(f"user: {user}")
        if db:
            parts.append(f"db: {db}")
        if query:
            parts.append(f"query: {_trunc(query, 80)}")
        if rows_out:
            parts.append(f"rows: {rows_out}")
        if bytes_scanned:
            parts.append(f"bytes scanned: {bytes_scanned}")
        if ip:
            parts.append(f"from: {ip}")
        if app:
            parts.append(f"app: {_trunc(app, 40)}")
        if parts:
            return _trunc(' · '.join(parts))
        return 'Data platform query event.'

    # ── Generic fallback — still better than a fixed string ──────────────────
    for key in (
        'description', 'summary', 'email_body_summary',
        'event_type', 'activityDisplayName', 'eventName', 'operationName',
        'event_simpleName', 'process_name', 'query_text', 'dns_query', 'notes',
    ):
        value = row.get(key)
        if value not in (None, ''):
            text = _field_text(value).strip()
            if text:
                return _trunc(text)
    # Last resort: build something from whatever entity fields exist
    actor = _row_actor(row)
    src_ip = _s(row.get('src_ip') or row.get('source_ip') or row.get('remote_address') or '')
    event_type = _s(row.get('event_type') or row.get('type') or '')
    parts = [p for p in [event_type or 'Security event', f"actor: {actor}" if actor != 'affected entity' else '', f"from: {src_ip}" if src_ip else ''] if p]
    return _trunc(' · '.join(parts)) if parts else 'Security telemetry event.'


def _get_rows_for_cluster(cluster: dict, assessment: dict) -> list[dict]:
    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    refs: set[int] = {int(v) for v in (cluster.get('row_refs') or []) if str(v).lstrip('-').isdigit()}
    if not refs:
        return list(cluster.get('evidence_preview') or [])
    matched = [r for r in all_rows
               if r.get('row_index') in refs or r.get('row_number') in refs]
    preview = [r for r in (cluster.get('evidence_preview') or []) if isinstance(r, dict)]
    if matched:
        if preview and len({
            _row_ref(r) for r in matched if _row_ref(r) is not None
        }) < min(len(refs), len(preview)):
            seen = {_row_ref(r) for r in matched if _row_ref(r) is not None}
            merged = list(matched)
            for row in preview:
                ref = _row_ref(row)
                if ref is not None and ref in seen:
                    continue
                if ref is not None:
                    seen.add(ref)
                merged.append(row)
            return merged
        logger.info(
            'tier1_prefill row_attribution: cluster=%s refs=%d matched=%d',
            cluster.get('cluster_id'), len(refs), len(matched),
        )
        return matched
    logger.info(
        'tier1_prefill row_attribution: cluster=%s refs=%d matched=0 preview_fallback=True',
        cluster.get('cluster_id'), len(refs),
    )
    return preview


def _extract_entity_set(cluster: dict, rows: list[dict]) -> set[str]:
    """Build the bounded entity set allowed for this cluster."""
    entities: set[str] = set()
    for r in rows:
        for f in ('user', 'user_principal_name', 'username', 'account', 'entity',
                  'src_ip', 'source_ip', 'dst_ip', 'destination_ip',
                  'hostname', 'host', 'src_host', 'device_name'):
            v = str(r.get(f) or '').strip().lower()
            if v and v not in ('-', 'n/a', ''):
                entities.add(v)
        for f in ('mitre_technique', 'mitre', 'technique_id'):
            v = r.get(f)
            if isinstance(v, list):
                entities.update(str(x).lower() for x in v if x)
            elif v:
                entities.add(str(v).lower())
    # Add cluster ID itself
    entities.add(str(cluster.get('cluster_id') or '').lower())
    return entities


def _build_entity_cluster_index(clusters: list[dict], assessment: dict) -> dict[str, list[str]]:
    """Map entity_value → [cluster_ids that contain that entity]."""
    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    row_by_index: dict[int, dict] = {
        (r['row_index'] if 'row_index' in r else r.get('row_number', -1)): r
        for r in all_rows
    }

    index: dict[str, list[str]] = {}  # entity_lower → [cluster_id, ...]
    for cluster in clusters:
        cid = cluster.get('cluster_id', '')
        for ref in (cluster.get('row_refs') or []):
            row = row_by_index.get(ref, {})
            for f in ('user', 'user_principal_name', 'username', 'account',
                      'src_ip', 'source_ip', 'hostname', 'host'):
                v = str(row.get(f) or '').strip().lower()
                if v and v not in ('-', 'n/a', '', 'none'):
                    index.setdefault(v, [])
                    if cid not in index[v]:
                        index[v].append(cid)
    return index


def _compute_cross_cluster_links(
    cluster: dict,
    entity_index: dict[str, list[str]],
    clusters: list[dict],
) -> list[dict]:
    """Return list of {entity, also_in_cluster_id, also_in_incident_name} for shared entities."""
    cid = cluster.get('cluster_id', '')
    links: list[dict] = []
    seen: set[str] = set()

    # Build incident name lookup from tier1_prefill if available
    incident_by_cid: dict[str, str] = {}
    for c in clusters:
        p = c.get('tier1_prefill') or {}
        incident_by_cid[c.get('cluster_id', '')] = p.get('incident_name') or c.get('cluster_id', '')

    for entity, cluster_ids in entity_index.items():
        if cid not in cluster_ids:
            continue
        other_ids = [c for c in cluster_ids if c != cid]
        for other_id in other_ids:
            key = f"{entity}::{other_id}"
            if key not in seen:
                seen.add(key)
                links.append({
                    'entity': entity,
                    'also_in_cluster_id': other_id,
                    'also_in_incident_name': incident_by_cid.get(other_id, other_id),
                })

    return links[:10]  # cap at 10 to avoid overwhelming the card
