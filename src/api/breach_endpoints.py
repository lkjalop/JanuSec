"""Breach Assessment API endpoints.

Routes:
  POST /api/v1/assessments/{aid}/tier1-prefill
      Run Tier-1 prefill on top-N clusters (auto-called after pipeline).

  POST /api/v1/assessments/{aid}/clusters/{cid}/tier1-summary
      On-demand Tier-1 for a single cluster (clusters 4+).

  POST /api/v1/assessments/{aid}/executive-summary
      Hybrid deterministic + LLM colour sentence for the home page.

  POST /api/v1/assessments/{aid}/clusters/{cid}/sign-off
      Analyst sign-off with notes + timeline confirmation.

  POST /api/v1/assessments/{aid}/clusters/{cid}/further-tasks
      Generate further investigation tasks grounded in uncovered evidence.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/assessments', tags=['breach'])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_tenant(request: Request) -> str:
    return (request.headers.get('X-Tenant-ID') or
            request.headers.get('x-tenant-id') or 'default')


def _get_assessment(assessment_id: str) -> Optional[dict]:
    try:
        from src.api.deep_analyze_endpoints import _get_assessment_cached
        result = _get_assessment_cached(assessment_id)
        if result:
            _repair_assessment_runtime_fields(result)
            return result
    except Exception:
        pass
    try:
        from src.api.deep_analyze_endpoints import REPORT_STORE
        result = REPORT_STORE.get(assessment_id)
        if result:
            _repair_assessment_runtime_fields(result)
        return result
    except Exception:
        return None


def _persist(assessment_id: str, assessment: dict) -> None:
    try:
        from src.api.deep_analyze_endpoints import _persist_assessment_state
        _persist_assessment_state(assessment_id, assessment)
    except Exception:
        pass


def _get_llm(model: str = 'qwen2.5:14b'):
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT
        return DEFAULT_CLIENT
    except Exception:
        return None


def _safe_text(v: Any) -> str:
    if v is None:
        return ''
    if isinstance(v, dict):
        if v.get('username'):
            return str(v.get('username'))
        if v.get('resource') or v.get('namespace') or v.get('subresource'):
            return '/'.join(
                str(v.get(k))
                for k in ('resource', 'subresource', 'namespace', 'name')
                if v.get(k)
            )
        try:
            return json.dumps(v, sort_keys=True)
        except Exception:
            return str(v)
    return str(v)


_VERDICT_RANK = {
    'VALIDATED_BREACH': 60,
    'CONFIRMED_INTRUSION': 50,
    'LIKELY_COMPROMISE': 40,
    'SUSPICIOUS_ACTIVITY': 30,
    'INSUFFICIENT_TELEMETRY': 20,
    'BENIGN_EXPECTED': 10,
}


def _cluster_rank(cluster: dict) -> tuple[int, int, float]:
    verdict = str(cluster.get('verdict') or cluster.get('final_verdict') or '').upper()
    sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(
        str(cluster.get('severity') or '').lower(),
        0,
    )
    try:
        conf = float(cluster.get('verdict_confidence') or cluster.get('confidence') or 0.0)
    except Exception:
        conf = 0.0
    return (_VERDICT_RANK.get(verdict, 0), sev_rank, conf)


def _cluster_rows(cluster: dict, assessment: dict) -> list[dict]:
    rows = (
        assessment.get('normalized_rows')
        or assessment.get('evidence_rows')
        or assessment.get('rows')
        or []
    )
    refs = {int(v) for v in (cluster.get('row_refs') or []) if str(v).lstrip('-').isdigit()}
    if not refs:
        return list(cluster.get('evidence_preview') or [])
    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ('row_index', 'row_number'):
            try:
                if int(row.get(key)) in refs:
                    result.append(row)
                    break
            except Exception:
                continue
    preview = [row for row in (cluster.get('evidence_preview') or []) if isinstance(row, dict)]
    if result:
        def _idx(row: dict) -> int | None:
            for key in ('row_index', 'row_number'):
                try:
                    value = row.get(key)
                    if value is not None:
                        return int(value)
                except Exception:
                    continue
            return None

        if preview and len({idx for row in result for idx in [_idx(row)] if idx is not None}) < min(len(refs), len(preview)):
            seen = set()
            merged = []
            for row in result + preview:
                idx = _idx(row)
                if idx is not None and idx in seen:
                    continue
                if idx is not None:
                    seen.add(idx)
                merged.append(row)
            return merged
        return result
    # normalized_rows/evidence_rows may not overlap with this cluster's row_refs —
    # fall back to evidence_preview which is pre-sampled against the actual refs.
    return preview


_NOISY_INCIDENT_NAME_PREFIXES = (
    'day ', 'shared ', 'same ', 'identity compromise or ', 'external infrastructure ',
)


def _cluster_text(cluster: dict, rows: list[dict]) -> str:
    parts: list[str] = [
        _safe_text(cluster.get('incident_name')),
        _safe_text(cluster.get('lead_description')),
        _safe_text(cluster.get('reason_summary')),
        _safe_text(cluster.get('business_significance')),
    ]
    for row in rows[:80]:
        for key in (
            'incident_id', 'threat_actor', 'analyst_notes', 'event_type',
            'email_subject', 'email_body_summary', 'dns_query', 'sni',
            'process_name', 'event_simpleName', 'rule_name', 'rule_destination',
            'mitre_technique', 'notes', 'objectRef', 'user', 'src_ip', 'dst_ip',
            'remote_address', 'ja3', 'ja4',
        ):
            if row.get(key) not in (None, ''):
                parts.append(_safe_text(row.get(key)))
    return ' '.join(parts).lower()


def _clean_incident_name(value: Any) -> str:
    name = _safe_text(value).strip()
    if not name:
        return ''
    lowered = name.lower()
    if lowered.startswith(_NOISY_INCIDENT_NAME_PREFIXES):
        return ''
    if lowered in {'correlated incident', 'no validated breach'}:
        return ''
    if re.match(r'^unknown(?:[-_\s]*\d{4})?(?:[-_\s]*[a-z])?\s*breach$', name, re.I):
        return ''
    if lowered.startswith('day ') or ' — ' in lowered[:30] or len(name) > 72:
        return ''
    if 'cluster-' in lowered or lowered.count(';') >= 2:
        return ''
    return name


def _derive_incident_name(cluster: dict, rows: list[dict]) -> str:
    prefill = cluster.get('tier1_prefill') or {}
    clean = (
        _clean_incident_name(prefill.get('incident_name'))
        or _clean_incident_name(cluster.get('incident_name'))
    )
    if clean:
        return clean

    # Substring-match fallback removed. LLM Tier-1 prefill is the only
    # legitimate source of incident_name. If it's missing or rejected,
    # return a neutral placeholder so the gap is visible in the UI.
    logger.warning(
        'incident_name_fallback cluster_id=%s verdict=%s — LLM prefill missing/rejected',
        cluster.get('cluster_id'), cluster.get('verdict'),
    )
    verdict = (cluster.get('verdict') or 'UNCERTAIN').upper()
    row_count = len(cluster.get('row_refs') or [])
    return f'UNNAMED {verdict} CLUSTER ({row_count} ROWS)'


def _derive_incident_subtitle(cluster: dict, rows: list[dict]) -> str:
    cues = _evidence_cues(cluster, {'rows': rows})
    if cues:
        return 'Evidence: ' + ', '.join(cues)
    summary = _safe_text(cluster.get('reason_summary')).strip()
    if summary and len(summary) <= 140:
        return summary
    return f"{len(cluster.get('row_refs') or [])} correlated evidence rows"


def _repair_assessment_runtime_fields(assessment: dict) -> None:
    """Repair cached assessments that pre-date verdict gates, v2 stories, or top_links."""
    if not isinstance(assessment, dict):
        return
    clusters = assessment.get('correlation_clusters') or []
    if not isinstance(clusters, list):
        return

    try:
        from src.core.verdict_engine.verdict_rules import backfill_cluster_verdicts
        backfill_cluster_verdicts(assessment)
    except Exception:
        pass

    try:
        from src.api.deep_analyze_endpoints import _apply_hvr_gating
        for cluster in clusters:
            if isinstance(cluster, dict):
                _apply_hvr_gating(cluster)
    except Exception:
        pass

    try:
        from src.core.tier1_prefill.prefill_engine import _ensure_v2_prefill_fields
        for cluster in clusters:
            prefill = cluster.get('tier1_prefill') if isinstance(cluster, dict) else None
            if isinstance(cluster, dict) and not isinstance(prefill, dict):
                cluster_rows = _cluster_rows(cluster, assessment)
                prefill = {
                    'incident_name': _derive_incident_name(cluster, cluster_rows),
                    'headline_subtitle': _derive_incident_subtitle(cluster, cluster_rows),
                    'short_narrative': cluster.get('business_significance') or cluster.get('reason_summary') or '',
                    'top_actions': [
                        'Validate the correlated evidence rows and containment scope.',
                        'Collect the recommended missing logs before closing the incident.',
                    ],
                    'mitre_techniques': cluster.get('top_mitre') or [],
                    'confidence_meter': cluster.get('confidence_meter'),
                    '_fallback_generated': True,
                }
                cluster['tier1_prefill'] = prefill
            if isinstance(prefill, dict) and prefill.get('incident_name'):
                _ensure_v2_prefill_fields(prefill, cluster, _cluster_rows(cluster, assessment))
    except Exception:
        pass

    if any(isinstance(c, dict) and c.get('top_links') for c in clusters):
        return

    try:
        from src.api.deep_analyze_endpoints import _build_correlation_clusters, _normalize_assessment_rows
        rebuilt, _adj = _build_correlation_clusters(_normalize_assessment_rows(assessment))
    except Exception:
        return
    by_exact = {
        tuple(sorted(int(v) for v in (c.get('row_refs') or []))): c
        for c in rebuilt
        if isinstance(c, dict) and c.get('top_links')
    }
    for cluster in clusters:
        if not isinstance(cluster, dict) or cluster.get('top_links'):
            continue
        refs = tuple(sorted(int(v) for v in (cluster.get('row_refs') or []) if str(v).lstrip('-').isdigit()))
        match = by_exact.get(refs)
        if match is None and refs:
            ref_set = set(refs)
            best = None
            best_overlap = 0
            for candidate in rebuilt:
                cand_refs = set(int(v) for v in (candidate.get('row_refs') or []) if str(v).lstrip('-').isdigit())
                overlap = len(ref_set & cand_refs)
                if overlap > best_overlap:
                    best = candidate
                    best_overlap = overlap
            if best_overlap >= 2:
                match = best
        if match:
            cluster['top_links'] = match.get('top_links') or []
            if not cluster.get('reason_summary'):
                cluster['reason_summary'] = match.get('reason_summary') or ''


# ── Geo-location helpers ──────────────────────────────────────────────────────

# Approximate great-circle distances (km) between country centroids.
# Used for velocity-based impossible-travel detection.
_COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    'AU': (-25.3, 133.8), 'NZ': (-40.9, 174.9),
    'SG': (1.4, 103.8),   'JP': (36.2, 138.3),   'KR': (35.9, 127.8),
    'CN': (35.9, 104.2),  'IN': (20.6, 78.9),     'HK': (22.3, 114.2),
    'MY': (4.2, 101.9),   'TH': (15.9, 100.9),    'ID': (-2.5, 118.0),
    'PH': (12.9, 121.8),  'VN': (14.1, 108.3),
    'US': (38.9, -77.0),  'CA': (56.1, -106.3),   'MX': (23.6, -102.5),
    'GB': (55.4, -3.4),   'DE': (51.2, 10.5),      'FR': (46.2, 2.2),
    'NL': (52.1, 5.3),    'SE': (60.1, 18.6),      'NO': (60.5, 8.5),
    'RU': (61.5, 105.3),  'UA': (48.4, 31.2),      'PL': (51.9, 19.1),
    'BR': (-14.2, -51.9), 'AR': (-38.4, -63.6),
    'ZA': (-28.5, 24.7),  'NG': (9.1, 8.7),
    'AE': (23.4, 53.8),   'SA': (23.9, 45.1),      'IL': (31.0, 34.9),
}


# Full country name lookup — keeps UI readable for non-technical executives
_COUNTRY_NAMES: dict[str, str] = {
    'AU': 'Australia',   'NZ': 'New Zealand',
    'SG': 'Singapore',   'JP': 'Japan',         'KR': 'South Korea',
    'CN': 'China',       'IN': 'India',          'HK': 'Hong Kong',
    'MY': 'Malaysia',    'TH': 'Thailand',       'ID': 'Indonesia',
    'PH': 'Philippines', 'VN': 'Vietnam',        'TW': 'Taiwan',
    'US': 'United States', 'CA': 'Canada',       'MX': 'Mexico',
    'GB': 'United Kingdom', 'DE': 'Germany',     'FR': 'France',
    'NL': 'Netherlands', 'SE': 'Sweden',         'NO': 'Norway',
    'FI': 'Finland',     'DK': 'Denmark',        'CH': 'Switzerland',
    'AT': 'Austria',     'BE': 'Belgium',        'IT': 'Italy',
    'ES': 'Spain',       'PT': 'Portugal',       'PL': 'Poland',
    'RU': 'Russia',      'UA': 'Ukraine',        'RO': 'Romania',
    'CZ': 'Czech Republic', 'HU': 'Hungary',     'SK': 'Slovakia',
    'BR': 'Brazil',      'AR': 'Argentina',      'CO': 'Colombia',
    'CL': 'Chile',       'PE': 'Peru',
    'ZA': 'South Africa','NG': 'Nigeria',        'KE': 'Kenya',
    'EG': 'Egypt',       'MA': 'Morocco',
    'AE': 'UAE',         'SA': 'Saudi Arabia',   'IL': 'Israel',
    'TR': 'Turkey',      'IR': 'Iran',           'PK': 'Pakistan',
    'BD': 'Bangladesh',
}


def _format_geo_location(ip: str, city: str, country: str, country_code: str, asn_org: str) -> str:
    """Format a human-readable location string including technical detail in brackets.

    Example output:
      "Melbourne, Australia (203.134.12.5 · Telstra · AU)"
      "Singapore (175.41.2.8 · Singtel · SG)"
      "Romania (185.220.101.3 · M247 Europe SRL · RO)"
    """
    cc = (country_code or '').upper()
    country_full = _COUNTRY_NAMES.get(cc) or country or cc or 'Unknown'
    city_part = city.strip() if city else ''
    location = f"{city_part}, {country_full}" if city_part else country_full

    detail_parts = [p for p in [ip, asn_org, cc] if p]
    detail = ' · '.join(detail_parts)
    return f"{location} ({detail})" if detail else location


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    import math
    r = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _extract_geo_from_row(row: dict) -> dict:
    """Pull geo context from whatever the event already carries.

    Handles Okta's context.geographicalContext, M365 ClientIP enrichment,
    and generic geo_country / country_code / asn fields from other sources.
    """
    geo: dict = {}

    # Okta: event.context.geographicalContext
    ctx = row.get('context') or row.get('event_context') or {}
    if isinstance(ctx, dict):
        geo_ctx = ctx.get('geographicalContext') or ctx.get('geo') or {}
        if isinstance(geo_ctx, dict):
            if geo_ctx.get('country'):
                geo['country'] = str(geo_ctx['country']).strip()
            if geo_ctx.get('city'):
                geo['city'] = str(geo_ctx['city']).strip()
            if geo_ctx.get('countryCode') or geo_ctx.get('country_code'):
                geo['country_code'] = str(geo_ctx.get('countryCode') or geo_ctx.get('country_code')).strip().upper()
            if geo_ctx.get('geolocation'):
                loc = geo_ctx['geolocation']
                if isinstance(loc, dict):
                    try:
                        geo['lat'] = float(loc.get('lat', 0))
                        geo['lon'] = float(loc.get('lon', 0))
                    except Exception:
                        pass

    # Okta: context.ipChain[0].geographicalContext
    ip_chain = ctx.get('ipChain') or []
    if isinstance(ip_chain, list) and ip_chain and isinstance(ip_chain[0], dict):
        chain_geo = ip_chain[0].get('geographicalContext') or {}
        if isinstance(chain_geo, dict) and not geo.get('country'):
            if chain_geo.get('country'):
                geo['country'] = str(chain_geo['country']).strip()
            if chain_geo.get('city'):
                geo['city'] = str(chain_geo['city']).strip()

    # Generic field scan — common across connectors
    for field in ('geo_country', 'country_name', 'country', 'geoip_country_name', 'geo_location_country'):
        val = row.get(field)
        if val and isinstance(val, str) and len(val) > 1 and not geo.get('country'):
            geo['country'] = val.strip()
            break
    for field in ('country_code', 'geo_country_code', 'geoip_country_code', 'countryCode'):
        val = row.get(field)
        if val and isinstance(val, str) and 2 <= len(val) <= 3 and not geo.get('country_code'):
            geo['country_code'] = val.strip().upper()
            break
    for field in ('geo_city', 'city', 'geoip_city_name'):
        val = row.get(field)
        if val and isinstance(val, str) and not geo.get('city'):
            geo['city'] = val.strip()
            break
    for field in ('asn', 'as_number', 'asn_number', 'geo_asn', 'autonomous_system_number'):
        val = row.get(field)
        if val is not None and not geo.get('asn'):
            geo['asn'] = str(val).strip()
            break
    for field in ('as_org', 'asn_org', 'asn_organization', 'isp', 'geo_isp', 'autonomous_system_organization'):
        val = row.get(field)
        if val and isinstance(val, str) and not geo.get('asn_org'):
            geo['asn_org'] = val.strip()
            break

    # Source IP
    for field in ('source_ip', 'src_ip', 'client_ip', 'ClientIP', 'remote_address', 'sourceIPAddress', 'ip_address'):
        val = row.get(field)
        if val and isinstance(val, str) and not geo.get('ip'):
            geo['ip'] = val.strip()
            break

    # If we have a country_code but no lat/lon, look up centroid
    if not geo.get('lat') and geo.get('country_code'):
        centroid = _COUNTRY_CENTROIDS.get(geo['country_code'].upper())
        if centroid:
            geo['lat'], geo['lon'] = centroid

    return geo


def _detect_impossible_travel(rows: list[dict]) -> list[dict]:
    """Per-user impossible travel analysis across all rows.

    Returns a list of flags: each flag describes a pair of consecutive logins
    for the same user that are geographically anomalous.

    Velocity thresholds:
      > 900 km/hr  → IMPOSSIBLE (faster than commercial flight)
      > 400 km/hr  → SUSPICIOUS (jet speed, but no airport boarding time)
      <= 400 km/hr → PLAUSIBLE (could be business travel)
    """
    import math
    from datetime import datetime, timezone

    def _parse_ts(row: dict):
        for f in (
            'timestamp_utc', 'timestamp', '@timestamp', 'ts', 'event_ts',
            'event_time', 'start_time', 'end_time', 'time', 'published', 'created',
        ):
            v = row.get(f)
            if not v:
                continue
            try:
                s = str(v).replace('Z', '+00:00')
                return datetime.fromisoformat(s)
            except Exception:
                pass
        return None

    def _user_key(row: dict) -> str:
        for f in ('user_principal_name', 'userPrincipalName', 'username', 'user_name',
                  'actor', 'user', 'initiator', 'email'):
            v = row.get(f)
            if v and isinstance(v, str) and '@' in v or (v and isinstance(v, str) and len(v) > 2):
                return str(v).lower().strip()
            if isinstance(v, dict):
                inner = v.get('alternateId') or v.get('login') or v.get('id') or ''
                if inner:
                    return str(inner).lower().strip()
        return ''

    # Group login events by user
    user_events: dict[str, list[dict]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        user = _user_key(row)
        if not user:
            continue
        geo = row.get('_geo') or _extract_geo_from_row(row)
        if not geo.get('country') and not geo.get('country_code'):
            continue  # no geo signal — skip
        ts = _parse_ts(row)
        if not ts:
            continue
        row['_geo'] = geo
        row['_parsed_ts'] = ts
        user_events.setdefault(user, []).append(row)

    flags: list[dict] = []
    for user, events in user_events.items():
        events_sorted = sorted(events, key=lambda r: r['_parsed_ts'])
        for i in range(len(events_sorted) - 1):
            e1, e2 = events_sorted[i], events_sorted[i + 1]
            g1, g2 = e1.get('_geo', {}), e2.get('_geo', {})
            cc1 = (g1.get('country_code') or '').upper()
            cc2 = (g2.get('country_code') or '').upper()
            c1 = g1.get('country', cc1)
            c2 = g2.get('country', cc2)
            if not c1 or not c2 or c1 == c2:
                continue

            # Time delta
            dt = (e2['_parsed_ts'] - e1['_parsed_ts']).total_seconds()
            if dt <= 0:
                # Simultaneous logins from different countries — impossible
                verdict = 'CONCURRENT_IMPOSSIBLE'
                km, km_hr = 0.0, float('inf')
            else:
                hours = dt / 3600.0
                # Distance
                lat1, lon1 = g1.get('lat', 0.0), g1.get('lon', 0.0)
                lat2, lon2 = g2.get('lat', 0.0), g2.get('lon', 0.0)
                if lat1 and lat2:
                    km = _haversine_km(lat1, lon1, lat2, lon2)
                    km_hr = km / hours if hours > 0 else float('inf')
                else:
                    # No coordinates — classify by time alone
                    km, km_hr = -1.0, -1.0

                if km_hr == float('inf') or km_hr > 900:
                    verdict = 'IMPOSSIBLE'
                elif km_hr > 400:
                    verdict = 'SUSPICIOUS'
                else:
                    verdict = 'PLAUSIBLE_TRAVEL'

            from_city = g1.get('city', '')
            to_city = g2.get('city', '')
            from_ip = g1.get('ip', '')
            to_ip = g2.get('ip', '')
            from_asn = g1.get('asn_org', '') or g1.get('asn', '')
            to_asn = g2.get('asn_org', '') or g2.get('asn', '')

            # Approximate min flight hours between these countries (for human context)
            _APPROX_FLIGHT: dict[tuple[str, str], float] = {
                ('AU', 'SG'): 8, ('SG', 'AU'): 8,
                ('AU', 'GB'): 22, ('GB', 'AU'): 22,
                ('AU', 'US'): 17, ('US', 'AU'): 17,
                ('AU', 'JP'): 10, ('JP', 'AU'): 10,
                ('AU', 'NZ'): 3, ('NZ', 'AU'): 3,
                ('SG', 'GB'): 13, ('GB', 'SG'): 13,
                ('US', 'GB'): 8, ('GB', 'US'): 8,
                ('US', 'RO'): 11, ('RO', 'US'): 11,
                ('AU', 'RO'): 24, ('RO', 'AU'): 24,
            }
            flight_hrs = _APPROX_FLIGHT.get((cc1, cc2)) or _APPROX_FLIGHT.get((cc2, cc1))

            flags.append({
                'user': user,
                # Raw fields
                'from_country': c1,
                'from_country_code': cc1,
                'from_city': from_city,
                'from_ip': from_ip,
                'from_asn_org': from_asn,
                'from_ts': e1['_parsed_ts'].isoformat(),
                'to_country': c2,
                'to_country_code': cc2,
                'to_city': to_city,
                'to_ip': to_ip,
                'to_asn_org': to_asn,
                'to_ts': e2['_parsed_ts'].isoformat(),
                'hours_between': round(dt / 3600, 2) if dt > 0 else 0,
                'km': round(km, 0) if km >= 0 else None,
                'km_hr': round(km_hr, 0) if 0 <= km_hr < 10000 else None,
                'verdict': verdict,
                'min_flight_hours': flight_hrs,
                'row_index_from': e1.get('row_index', e1.get('row_number')),
                'row_index_to': e2.get('row_index', e2.get('row_number')),
                # Human-readable formatted labels (city, Country · IP · ASN · CC)
                'from_label': _format_geo_location(from_ip, from_city, c1, cc1, from_asn),
                'to_label': _format_geo_location(to_ip, to_city, c2, cc2, to_asn),
            })

    return flags


def _geo_enrich_cluster(cluster: dict, assessment: dict) -> dict:
    """Compute geo summary for a cluster: countries, impossible travel, IAM playbook."""
    rows = _cluster_rows(cluster, assessment)
    if not rows:
        return {}

    # Attach _geo to each row
    for row in rows:
        if '_geo' not in row:
            geo = _extract_geo_from_row(row)
            if geo:
                row['_geo'] = geo

    # Unique countries seen
    countries: dict[str, int] = {}
    for row in rows:
        geo = row.get('_geo') or {}
        c = geo.get('country') or geo.get('country_code')
        if c:
            countries[c] = countries.get(c, 0) + 1

    # ASNs
    asns: dict[str, int] = {}
    for row in rows:
        geo = row.get('_geo') or {}
        if geo.get('asn_org'):
            asns[geo['asn_org']] = asns.get(geo['asn_org'], 0) + 1
        elif geo.get('asn'):
            asns[geo['asn']] = asns.get(geo['asn'], 0) + 1

    # Impossible travel
    travel_flags = _detect_impossible_travel(rows)
    impossible = [f for f in travel_flags if f['verdict'] in ('IMPOSSIBLE', 'CONCURRENT_IMPOSSIBLE')]
    suspicious = [f for f in travel_flags if f['verdict'] == 'SUSPICIOUS']
    plausible = [f for f in travel_flags if f['verdict'] == 'PLAUSIBLE_TRAVEL']

    # Derive a travel verdict for the cluster
    if impossible:
        travel_verdict = 'IMPOSSIBLE_TRAVEL'
    elif suspicious:
        travel_verdict = 'SUSPICIOUS_TRAVEL'
    elif plausible and len(countries) > 1:
        travel_verdict = 'PLAUSIBLE_TRAVEL'
    elif countries:
        travel_verdict = 'LOCAL' if len(countries) == 1 else 'MULTI_COUNTRY'
    else:
        travel_verdict = 'UNKNOWN'

    # IAM playbook: generate when travel is flagged
    iam_playbook: list[str] = []
    affected_users = list({f['user'] for f in travel_flags if f.get('user')})[:3]
    if impossible or suspicious:
        for flag in (impossible or suspicious)[:2]:
            user = flag.get('user', 'affected user')
            c1, c2 = flag.get('from_country', '?'), flag.get('to_country', '?')
            hrs = flag.get('hours_between', 0)
            iam_playbook.append(
                f"Prompt {user} via Okta/Entra step-up MFA to confirm {c2} access"
                f" ({hrs}h after {c1} login). If unconfirmed within 30 min → terminate session."
            )
    elif plausible:
        for flag in plausible[:2]:
            user = flag.get('user', 'affected user')
            c2 = flag.get('to_country', '?')
            iam_playbook.append(
                f"Verify {user} travel to {c2} is approved (check HR/calendar). "
                f"If unplanned, escalate to identity team."
            )

    return {
        'geo_countries': countries,
        'geo_asns': dict(list(asns.items())[:5]),
        'travel_flags': travel_flags[:10],
        'impossible_travel': impossible,
        'suspicious_travel': suspicious,
        'plausible_travel': plausible,
        'travel_verdict': travel_verdict,
        'geo_affected_users': affected_users,
        'iam_playbook': iam_playbook,
    }


def _verdict_bucket(verdict: str) -> str:
    v = str(verdict or '').upper()
    if v == 'VALIDATED_BREACH':
        return 'validated'
    if v == 'CONFIRMED_INTRUSION' or 'CONFIRMED' in v:
        return 'confirmed'
    if v == 'LIKELY_COMPROMISE' or 'LIKELY' in v:
        return 'likely'
    if v == 'SUSPICIOUS_ACTIVITY':
        return 'suspicious'
    if v == 'INSUFFICIENT_TELEMETRY' or 'UNCERTAIN' in v:
        return 'insufficient telemetry'
    if v == 'BENIGN_EXPECTED':
        return 'benign'
    return 'unclassified'


def _cluster_name(cluster: dict) -> str:
    prefill = cluster.get('tier1_prefill') or {}
    clean = (
        _clean_incident_name(prefill.get('incident_name'))
        or _clean_incident_name(cluster.get('incident_name'))
    )
    if clean:
        return clean
    return _derive_incident_name(cluster, [])


def _cluster_subtitle(cluster: dict) -> str:
    prefill = cluster.get('tier1_prefill') or {}
    return (
        _safe_text(prefill.get('headline_subtitle')).strip()
        or _safe_text(prefill.get('root_cause')).strip()
        or _safe_text(cluster.get('reason_summary')).strip()
        or _derive_incident_subtitle(cluster, [])
    )


def _evidence_cues(cluster: dict, assessment: dict) -> list[str]:
    rows = _cluster_rows(cluster, assessment)
    joined = ' '.join(
        _safe_text(row.get(k))
        for row in rows
        for k in (
            'analyst_notes', 'email_subject', 'email_body_summary', 'event_type',
            'rule_name', 'rule_destination', 'source_ip', 'mitre_technique',
            'wire_transfer_amount_aud', 'notes', 'objectRef', 'user', 'src_ip',
            'dst_ip', 'remote_address', 'ja3', 'ja4',
        )
        if row.get(k) not in (None, '')
    ).lower()
    cues: list[str] = []
    if any(t in joined for t in ('k8s.audit', 'kubernetes', 'daemonsets', 'pods/exec')):
        cues.append('Kubernetes privileged workload activity')
    if any(t in joined for t in ('anomalous ja3', 'ja3', 'c2', 'beacon', 'command-and-control')):
        cues.append('C2 or beaconing traffic')
    if any(t in joined for t in ('mfa fatigue', 'push', 't1621')):
        cues.append('MFA fatigue')
    if any(t in joined for t in ('bcc', 'forward', 'imap', 'mailbox')):
        cues.append('mailbox rule or legacy-mail access')
    if any(t in joined for t in ('bec', 'wire', 'payment', 'finance officer')):
        cues.append('business email compromise')
    amounts = sorted({
        _safe_text(row.get('wire_transfer_amount_aud')).strip()
        for row in rows
        if row.get('wire_transfer_amount_aud') not in (None, '')
    })
    if amounts:
        cues.append('AUD ' + ', AUD '.join(amounts[:2]) + ' payment exposure')
    if any(t in joined for t in ('dns', 'beacon', 'c2', 'command and control')):
        cues.append('C2 or DNS beaconing')
    return cues[:4]


# ── Request / Response models ─────────────────────────────────────────────────

class PrefillRequest(BaseModel):
    model: str = 'qwen3:14b'
    top_n: int = Field(default=3, ge=1, le=10)
    force: bool = False


class SingleSummaryRequest(BaseModel):
    model: str = 'qwen3:14b'
    force: bool = False


class ExecSummaryRequest(BaseModel):
    model: str = 'qwen3:14b'
    regenerate: bool = False


class SignOffRequest(BaseModel):
    analyst_id: str = ''
    notes: str = ''
    timeline_confirmed: bool = False


class FurtherTasksRequest(BaseModel):
    completed_evidence_refs: List[int] = Field(default_factory=list)
    completed_task_titles: List[str] = Field(default_factory=list)
    model: str = 'qwen3:30b'


class NotesRequest(BaseModel):
    notes: str = ''
    analyst_id: str = ''


# ── E9: Kill-chain phase lookup (deterministic, zero LLM) ─────────────────────

_MITRE_PHASE: dict[str, str] = {
    # Reconnaissance
    'T1595': 'Reconnaissance', 'T1592': 'Reconnaissance', 'T1589': 'Reconnaissance',
    'T1590': 'Reconnaissance', 'T1591': 'Reconnaissance', 'T1598': 'Reconnaissance',
    'T1596': 'Reconnaissance', 'T1593': 'Reconnaissance',
    # Resource Development
    'T1583': 'Resource Development', 'T1584': 'Resource Development',
    'T1585': 'Resource Development', 'T1586': 'Resource Development',
    'T1587': 'Resource Development', 'T1588': 'Resource Development',
    # Initial Access
    'T1189': 'Initial Access', 'T1190': 'Initial Access', 'T1133': 'Initial Access',
    'T1566': 'Initial Access', 'T1195': 'Initial Access', 'T1199': 'Initial Access',
    'T1078': 'Initial Access',
    # Execution
    'T1059': 'Execution', 'T1203': 'Execution', 'T1106': 'Execution',
    'T1053': 'Execution', 'T1569': 'Execution', 'T1204': 'Execution', 'T1047': 'Execution',
    # Persistence
    'T1098': 'Persistence', 'T1547': 'Persistence', 'T1136': 'Persistence',
    'T1543': 'Persistence', 'T1546': 'Persistence', 'T1574': 'Persistence',
    'T1505': 'Persistence', 'T1525': 'Persistence', 'T1556': 'Persistence',
    # Privilege Escalation
    'T1548': 'Privilege Escalation', 'T1134': 'Privilege Escalation',
    'T1484': 'Privilege Escalation', 'T1611': 'Privilege Escalation',
    'T1068': 'Privilege Escalation',
    # Defense Evasion
    'T1140': 'Defense Evasion', 'T1564': 'Defense Evasion', 'T1562': 'Defense Evasion',
    'T1070': 'Defense Evasion', 'T1036': 'Defense Evasion', 'T1027': 'Defense Evasion',
    'T1578': 'Defense Evasion', 'T1112': 'Defense Evasion',
    # Credential Access
    'T1110': 'Credential Access', 'T1003': 'Credential Access', 'T1606': 'Credential Access',
    'T1056': 'Credential Access', 'T1557': 'Credential Access', 'T1621': 'Credential Access',
    'T1539': 'Credential Access', 'T1558': 'Credential Access', 'T1552': 'Credential Access',
    # Discovery
    'T1087': 'Discovery', 'T1482': 'Discovery', 'T1083': 'Discovery',
    'T1046': 'Discovery', 'T1135': 'Discovery', 'T1069': 'Discovery',
    'T1057': 'Discovery', 'T1082': 'Discovery', 'T1016': 'Discovery',
    'T1049': 'Discovery', 'T1033': 'Discovery', 'T1518': 'Discovery',
    'T1124': 'Discovery', 'T1526': 'Discovery', 'T1538': 'Discovery',
    # Lateral Movement
    'T1210': 'Lateral Movement', 'T1534': 'Lateral Movement', 'T1570': 'Lateral Movement',
    'T1563': 'Lateral Movement', 'T1021': 'Lateral Movement', 'T1550': 'Lateral Movement',
    # Collection
    'T1560': 'Collection', 'T1119': 'Collection', 'T1530': 'Collection',
    'T1213': 'Collection', 'T1005': 'Collection', 'T1074': 'Collection',
    'T1114': 'Collection', 'T1113': 'Collection',
    # Command & Control
    'T1071': 'Command & Control', 'T1132': 'Command & Control', 'T1573': 'Command & Control',
    'T1008': 'Command & Control', 'T1105': 'Command & Control', 'T1095': 'Command & Control',
    'T1571': 'Command & Control', 'T1572': 'Command & Control', 'T1090': 'Command & Control',
    'T1219': 'Command & Control', 'T1102': 'Command & Control',
    # Exfiltration
    'T1020': 'Exfiltration', 'T1048': 'Exfiltration', 'T1041': 'Exfiltration',
    'T1567': 'Exfiltration', 'T1537': 'Exfiltration',
    # Impact
    'T1485': 'Impact', 'T1486': 'Impact', 'T1491': 'Impact', 'T1499': 'Impact',
    'T1490': 'Impact', 'T1498': 'Impact', 'T1496': 'Impact', 'T1489': 'Impact',
}

_PHASE_ORDER = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command & Control',
    'Exfiltration', 'Impact',
]


def tag_kill_chain_phase(row: dict) -> str:
    """Return the kill-chain phase string for a row, or 'Unknown'."""
    for f in ('mitre_technique', 'mitre', 'technique_id', 'mitre_id'):
        val = row.get(f)
        if not val:
            continue
        techs = val if isinstance(val, list) else [val]
        for t in techs:
            t_str = str(t).strip().upper()
            # Match on base technique T1234 (strip sub-technique .001 etc.)
            base = t_str.split('.')[0]
            if base in _MITRE_PHASE:
                return _MITRE_PHASE[base]
    return 'Unknown'


def _extract_iocs(cluster: dict, rows: list[dict]) -> dict:
    """Extract all unique IOC entities from cluster rows."""
    users: set[str] = set()
    ips: set[str] = set()
    hosts: set[str] = set()
    for r in rows:
        for f in ('user', 'user_principal_name', 'username', 'account', 'entity'):
            v = str(r.get(f) or '').strip()
            if v and v not in ('-', 'N/A', 'n/a', ''):
                users.add(v)
        for f in ('src_ip', 'source_ip', 'dst_ip', 'destination_ip'):
            v = str(r.get(f) or '').strip()
            if v and v not in ('-', 'N/A', ''):
                ips.add(v)
        for f in ('hostname', 'host', 'src_host', 'device_name'):
            v = str(r.get(f) or '').strip()
            if v and v not in ('-', 'N/A', ''):
                hosts.add(v)
    return {
        'users': sorted(users),
        'ips': sorted(ips),
        'hosts': sorted(hosts),
        'cluster_id': cluster.get('cluster_id', ''),
        'severity': cluster.get('severity', ''),
        'verdict': cluster.get('verdict') or cluster.get('final_verdict', ''),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post('/{assessment_id}/tier1-prefill')
async def trigger_tier1_prefill(
    assessment_id: str,
    body: PrefillRequest,
    request: Request,
) -> JSONResponse:
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    tenant_id = _get_tenant(request)

    try:
        from src.core.tier1_prefill.prefill_engine import run_prefill
    except ImportError:
        from core.tier1_prefill.prefill_engine import run_prefill  # type: ignore

    result = await asyncio.to_thread(
        run_prefill,
        assessment,
        body.top_n,
        body.model,
        tenant_id,
    )
    _persist(assessment_id, assessment)

    return JSONResponse({
        'assessment_id': assessment_id,
        **result,
    })


@router.post('/{assessment_id}/clusters/{cluster_id}/tier1-summary')
async def tier1_single_summary(
    assessment_id: str,
    cluster_id: str,
    body: SingleSummaryRequest,
    request: Request,
) -> JSONResponse:
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    tenant_id = _get_tenant(request)

    try:
        from src.core.tier1_prefill.prefill_engine import run_single_cluster_prefill
    except ImportError:
        from core.tier1_prefill.prefill_engine import run_single_cluster_prefill  # type: ignore

    result = await asyncio.to_thread(
        run_single_cluster_prefill,
        assessment,
        cluster_id,
        body.model,
        tenant_id,
        body.force,
    )
    _persist(assessment_id, assessment)

    if result.get('status') == 'not_found':
        raise HTTPException(status_code=404, detail='cluster_not_found')

    return JSONResponse({'assessment_id': assessment_id, **result})


@router.post('/{assessment_id}/executive-summary')
async def get_executive_summary(
    assessment_id: str,
    body: ExecSummaryRequest,
    request: Request,
) -> JSONResponse:
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    # Return cached unless regenerate=True
    cached = assessment.get('exec_summary_llm')
    if cached and not body.regenerate:
        return JSONResponse({
            'assessment_id': assessment_id,
            **cached,
            'from_cache': True,
        })

    clusters = assessment.get('correlation_clusters') or []
    # Prefer the DuckDB-backed row count (Phase 2 ingest) over the sampled in-memory rows
    evidence_store = assessment.get('evidence_store') or {}
    total_rows = (
        evidence_store.get('row_count')
        or assessment.get('rows_processed')
        or len(assessment.get('normalized_rows') or assessment.get('evidence_rows') or assessment.get('rows') or [])
    )
    total_sources = (
        len(evidence_store.get('source_counts') or {})
        or len(set(
            str(r.get('_source') or r.get('source') or '')
            for r in (assessment.get('normalized_rows') or assessment.get('rows') or [])
            if r.get('_source') or r.get('source')
        ))
    )

    # Deterministic backbone. This must be correct without the LLM: the CEO
    # view should answer "was there a breach?" before giving extra color.
    verdict_counts: dict[str, int] = {}
    for c in clusters:
        v = str(c.get('verdict') or c.get('final_verdict') or 'UNCERTAIN').upper()
        label = _verdict_bucket(v)
        verdict_counts[label] = verdict_counts.get(label, 0) + 1

    sorted_clusters = sorted(clusters, key=_cluster_rank, reverse=True)
    lead = sorted_clusters[0] if sorted_clusters else {}
    lead_verdict = str(lead.get('verdict') or lead.get('final_verdict') or 'UNCERTAIN').upper()
    lead_name = _cluster_name(lead) if lead else 'No lead incident'
    lead_subtitle = _cluster_subtitle(lead) if lead else ''
    lead_rows = len(lead.get('row_refs') or []) if lead else 0
    lead_cluster_rows = _cluster_rows(lead, assessment) if lead else []
    lead_cues = _evidence_cues(lead, assessment) if lead else []

    def _uniq(values: list[Any], limit: int) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for value in values:
            text = _safe_text(value).strip()
            if not text or text in {'-', 'N/A', 'n/a'}:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(text)
            if len(out) >= limit:
                break
        return out

    row_accounts = _uniq([
        row.get(k)
        for row in lead_cluster_rows
        for k in ('user_principal_name', 'userPrincipalName', 'username', 'user_name', 'UserId', 'user', 'account', 'actor', 'email')
    ], 5)
    row_ips = _uniq([
        row.get(k)
        for row in lead_cluster_rows
        for k in ('source_ip', 'src_ip', 'client_ip', 'ClientIP', 'remote_address', 'sourceIPAddress', 'dst_ip', 'destination_ip')
    ], 5)
    row_assets = _uniq([
        row.get(k)
        for row in lead_cluster_rows
        for k in ('hostname', 'host', 'device_name', 'ComputerName', 'database_name', 'warehouse_name')
    ], 5)
    row_times = sorted(_uniq([
        row.get(k)
        for row in lead_cluster_rows
        for k in ('timestamp_utc', 'timestamp', '@timestamp', 'event_ts', 'event_time', 'start_time', 'end_time', 'time', 'ts')
    ], 200))
    entity_context = ''
    if row_accounts or row_assets or row_ips:
        bits = []
        if row_accounts:
            bits.append('accounts ' + ', '.join(row_accounts[:3]))
        if row_assets:
            bits.append('assets ' + ', '.join(row_assets[:3]))
        if row_ips:
            bits.append('IPs ' + ', '.join(row_ips[:3]))
        entity_context = '; '.join(bits)

    # Geo enrichment for lead cluster (compute once, reuse in both deterministic + LLM paths)
    lead_geo: dict = {}
    if lead:
        try:
            lead_geo = _geo_enrich_cluster(lead, assessment)
            lead['_geo_summary'] = lead_geo  # cache on cluster for UI access
        except Exception as _geo_err:
            logger.debug('geo_enrich_failed: %s', _geo_err)
    counts_text = ', '.join(
        f"{count} {label}"
        for label, count in sorted(verdict_counts.items(), key=lambda x: (-x[1], x[0]))
    ) or '0 findings'
    # Geo addendum for deterministic text
    geo_travel = lead_geo.get('travel_verdict', '')
    geo_countries = lead_geo.get('geo_countries') or {}
    geo_impossible = lead_geo.get('impossible_travel') or []
    geo_suspicious = lead_geo.get('suspicious_travel') or []
    geo_plausible = lead_geo.get('plausible_travel') or []
    geo_addendum = ''
    if geo_impossible:
        f0 = geo_impossible[0]
        from_lbl = f0.get('from_label') or f0.get('from_country', '?')
        to_lbl = f0.get('to_label') or f0.get('to_country', '?')
        hrs = f0.get('hours_between')
        flight = f0.get('min_flight_hours')
        geo_addendum = (
            f" Impossible travel: {f0.get('user', 'the affected user')} logged in from"
            f" {from_lbl}, then {to_lbl}"
            + (f" — only {hrs}h apart" if hrs is not None else '')
            + (f" (minimum flight time: {flight}h)" if flight else '')
            + '. This is a strong indicator of stolen credentials.'
        )
    elif geo_suspicious:
        f0 = geo_suspicious[0]
        from_lbl = f0.get('from_label') or f0.get('from_country', '?')
        to_lbl = f0.get('to_label') or f0.get('to_country', '?')
        hrs = f0.get('hours_between')
        geo_addendum = (
            f" Suspicious travel: {f0.get('user', 'the affected user')} accessed from"
            f" {from_lbl}, then {to_lbl}"
            + (f" ({hrs}h apart — high velocity)" if hrs is not None else '')
            + '.'
        )
    elif geo_plausible and geo_countries:
        f0 = geo_plausible[0]
        from_lbl = f0.get('from_label') or f0.get('from_country', '?')
        to_lbl = f0.get('to_label') or f0.get('to_country', '?')
        hrs = f0.get('hours_between')
        flight = f0.get('min_flight_hours')
        geo_addendum = (
            f" Overseas access: {f0.get('user', 'the affected user')} logged in from"
            f" {to_lbl}"
            + (f", {hrs}h after their login from {from_lbl}" if hrs is not None else f" (previously accessed from {from_lbl})")
            + (f". A direct flight takes approximately {flight}h — consistent with business travel." if flight else '. Geographically plausible — verify with HR or travel calendar.')
        )

    if lead and lead_verdict == 'VALIDATED_BREACH':
        headline = f"Validated breach: {lead_name}"
        subline = (
            f"{lead_rows} evidence rows"
            + (f" across {total_sources} sources" if total_sources else '')
            + (f" link {', '.join(lead_cues)}" if lead_cues else ' support the lead incident')
        )
        executive_summary = (
            f"JanuSec found observed attacker action against a protected business process. "
            f"The lead threat case is {lead_name}. "
            + (f"Evidence names {entity_context}. " if entity_context else '')
            + (f"Evidence links {', '.join(lead_cues)}. " if lead_cues else '')
            + f"Overall, {len(clusters)} threat cases were grouped from {total_rows} rows: {counts_text}."
            + geo_addendum
        )
    elif lead:
        headline = f"Highest finding: {lead_verdict} for {lead_name}"
        subline = (
            f"{lead_rows} evidence rows"
            + (f" across {total_sources} sources" if total_sources else '')
            + " require investigation before breach validation."
        )
        executive_summary = (
            f"JanuSec grouped {len(clusters)} threat cases from {total_rows} rows"
            + (f" across {total_sources} sources" if total_sources else '')
            + f": {counts_text}. "
            + (f"The lead finding is {lead_name} ({lead_subtitle})." if lead_subtitle else f"The lead finding is {lead_name}.")
            + geo_addendum
        )
    else:
        headline = 'No validated breach found'
        subline = f'No correlated incident clusters were found in {total_rows} rows.'
        executive_summary = subline
    deterministic = '\n'.join([headline, subline, executive_summary])

    # Attempt LLM narrative for the executive_summary body (non-blocking; falls back to deterministic)
    llm_color: Optional[str] = None
    if lead and body.regenerate:
        try:
            llm = _get_llm(body.model)
            lead_prefill = lead.get('tier1_prefill') or {}
            mitre_tags = lead_prefill.get('mitre_techniques') or lead.get('mitre_tags') or []
            mitre_str = ', '.join(mitre_tags[:4]) if mitre_tags else ''

            # Gather entity context — accounts, IPs, assets, time range, attack chain
            raw_accounts = (
                lead_prefill.get('affected_users')
                or lead.get('shared_accounts')
                or lead.get('affected_accounts')
                or row_accounts
            )
            accounts_str = ', '.join([str(a) for a in raw_accounts[:4] if a]) or ''

            raw_ips = (
                lead.get('shared_external_ips')
                or lead.get('external_ips')
                or lead_prefill.get('source_ips')
                or row_ips
            )
            ips_str = ', '.join([str(ip) for ip in raw_ips[:4] if ip]) or ''

            raw_assets = (
                lead.get('shared_hosts')
                or lead.get('affected_assets')
                or lead_prefill.get('affected_assets')
                or row_assets
            )
            assets_str = ', '.join([str(a) for a in raw_assets[:3] if a]) or ''

            # Time range from evidence chain or cluster timestamps
            chain_steps = lead_prefill.get('evidence_chain') or []
            ts_list = [s.get('timestamp') or s.get('ts') for s in chain_steps if s.get('timestamp') or s.get('ts')]
            if not ts_list:
                ts_list = row_times
            ts_list = sorted([str(t) for t in ts_list if t])
            time_range_str = f"{ts_list[0]} to {ts_list[-1]}" if len(ts_list) >= 2 else ''

            # Attack chain summary from evidence_chain steps
            chain_summary = ''
            if chain_steps:
                chain_summary = ' → '.join(
                    str(s.get('what') or s.get('event') or s.get('description') or '')
                    for s in chain_steps[:5] if s.get('what') or s.get('event') or s.get('description')
                )

            business_context = (
                lead_prefill.get('business_significance')
                or lead.get('business_significance')
                or ''
            )

            # Build context block — only include populated fields
            context_parts = [f"Assessment verdict: {lead_verdict}. Incident: {lead_name}."]
            context_parts.append(f"Evidence: {lead_rows} rows across {total_sources} sources.")
            if accounts_str:
                context_parts.append(f"Affected accounts: {accounts_str}.")
            if ips_str:
                context_parts.append(f"Attacker IPs: {ips_str}.")
            if assets_str:
                context_parts.append(f"Affected assets: {assets_str}.")
            if time_range_str:
                context_parts.append(f"Time range: {time_range_str}.")
            if chain_summary:
                context_parts.append(f"Attack chain: {chain_summary}.")
            if mitre_str:
                context_parts.append(f"MITRE techniques: {mitre_str}.")
            if business_context:
                context_parts.append(f"Business impact context: {business_context}.")
            if lead_cues:
                context_parts.append(f"Key indicators: {', '.join(lead_cues)}.")

            # Geo context for LLM — use formatted human-readable labels
            if geo_impossible:
                f0 = geo_impossible[0]
                from_lbl = f0.get('from_label') or f0.get('from_country', '?')
                to_lbl = f0.get('to_label') or f0.get('to_country', '?')
                hrs = f0.get('hours_between')
                flight = f0.get('min_flight_hours')
                context_parts.append(
                    f"CRITICAL — Impossible travel: {f0.get('user')} logged in from"
                    f" {from_lbl}, then {to_lbl}"
                    + (f" — only {hrs}h apart" if hrs is not None else '')
                    + (f" (min flight: {flight}h)" if flight else '')
                    + ". This indicates stolen credentials used by a remote attacker."
                )
            elif geo_suspicious:
                f0 = geo_suspicious[0]
                from_lbl = f0.get('from_label') or f0.get('from_country', '?')
                to_lbl = f0.get('to_label') or f0.get('to_country', '?')
                context_parts.append(
                    f"Suspicious travel: {f0.get('user')} accessed from {from_lbl},"
                    f" then {to_lbl}"
                    + (f" ({f0.get('hours_between')}h apart — high velocity)." if f0.get('hours_between') is not None else '.')
                )
            elif geo_plausible:
                f0 = geo_plausible[0]
                from_lbl = f0.get('from_label') or f0.get('from_country', '?')
                to_lbl = f0.get('to_label') or f0.get('to_country', '?')
                hrs = f0.get('hours_between')
                flight = f0.get('min_flight_hours')
                context_parts.append(
                    f"Overseas access (likely business travel): {f0.get('user')} logged in from"
                    f" {to_lbl}, {hrs}h after login from {from_lbl}."
                    + (f" A direct flight takes ~{flight}h — geographically consistent." if flight else " Travel is geographically plausible.")
                    + " Recommend verifying with HR or travel calendar before escalating."
                )
            if geo_countries and len(geo_countries) > 1:
                formatted_countries = [
                    _COUNTRY_NAMES.get(cc.upper(), cc) + f" ({cc})"
                    for cc in list(geo_countries.keys())[:5]
                ]
                context_parts.append(
                    f"Logins observed from {len(geo_countries)} countries: {', '.join(formatted_countries)}."
                )

            prompt = (
                "You are a security analyst writing a concise executive briefing for a non-technical audience.\n"
                + "\n".join(context_parts)
                + "\n\nWrite 2-3 sentences in plain English describing: (1) what the attacker did, naming specific "
                "accounts or IPs if provided, (2) the business impact. "
                "No bullet points, no jargon, no repeated incident name, do not start with 'The'."
            )
            resp = await asyncio.to_thread(llm.generate, prompt, 220)
            llm_text = (resp.get('text') or '').strip()
            if llm_text and len(llm_text) > 30 and not llm_text.startswith('{'):
                executive_summary = llm_text
        except Exception:
            pass  # keep deterministic fallback

    cluster_headlines = []
    for c in sorted_clusters[:3]:
        prefill = c.get('tier1_prefill') or {}
        cluster_headlines.append({
            'verdict': c.get('verdict') or c.get('final_verdict') or 'UNCERTAIN',
            'incident_name': prefill.get('incident_name') or _cluster_name(c),
            'headline_subtitle': prefill.get('headline_subtitle') or _cluster_subtitle(c),
        })

    result = {
        'headline': headline,
        'subline': subline,
        'executive_summary': executive_summary,
        'deterministic': deterministic,
        'llm_color': llm_color,
        'model_used': body.model,
        'generated_at': int(time.time()),
        'from_cache': False,
        # Geo signals surfaced to the UI
        'geo_travel_verdict': lead_geo.get('travel_verdict', ''),
        'geo_countries': lead_geo.get('geo_countries', {}),
        'geo_impossible_travel': lead_geo.get('impossible_travel', []),
        'geo_suspicious_travel': lead_geo.get('suspicious_travel', []),
        'geo_plausible_travel': lead_geo.get('plausible_travel', []),
        'iam_playbook': lead_geo.get('iam_playbook', []),
    }
    assessment['exec_summary_llm'] = result
    _persist(assessment_id, assessment)

    return JSONResponse({'assessment_id': assessment_id, **result})


@router.post('/{assessment_id}/clusters/{cluster_id}/sign-off')
async def cluster_sign_off(
    assessment_id: str,
    cluster_id: str,
    body: SignOffRequest,
    request: Request,
) -> JSONResponse:
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    signed_at = int(time.time())
    cluster['sign_off'] = {
        'analyst_id': body.analyst_id,
        'notes': body.notes,
        'timeline_confirmed': body.timeline_confirmed,
        'signed_off_at': signed_at,
        'status': 'signed_off',
    }
    _persist(assessment_id, assessment)

    return JSONResponse({
        'status': 'ok',
        'cluster_id': cluster_id,
        'signed_off_at': signed_at,
        'report_url': None,  # PDF export: v2
    })


@router.post('/{assessment_id}/clusters/{cluster_id}/further-tasks')
async def generate_further_tasks(
    assessment_id: str,
    cluster_id: str,
    body: FurtherTasksRequest,
    request: Request,
) -> JSONResponse:
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    tenant_id = _get_tenant(request)

    # Gather all rows for this cluster
    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    row_refs = set(cluster.get('row_refs') or [])
    cluster_rows = [r for r in all_rows
                    if r.get('row_index') in row_refs or r.get('row_number') in row_refs]

    # Uncovered = cluster rows whose index is not in completed_evidence_refs
    completed = set(body.completed_evidence_refs)
    uncovered = [
        r for r in cluster_rows
        if (r.get('row_index') not in completed and
            r.get('row_number') not in completed)
    ]

    # Missing sources from existing evidence quality field or derive from cluster
    missing_sources: list[str] = (
        cluster.get('missing_sources') or
        cluster.get('evidence_gaps') or
        assessment.get('missing_sources') or
        []
    )

    # Entity extraction for entity-pinning
    users, ips, hosts = set(), set(), set()
    for r in cluster_rows:
        for f in ('user', 'user_principal_name', 'username', 'account'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in ('-', 'N/A', ''):
                users.add(v)
        for f in ('src_ip', 'source_ip', 'dst_ip'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in ('-', 'N/A', ''):
                ips.add(v)
        for f in ('hostname', 'host', 'device_name'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in ('-', 'N/A', ''):
                hosts.add(v)

    entities_allowed = {
        'users': sorted(users)[:8],
        'ips': sorted(ips)[:6],
        'hosts': sorted(hosts)[:6],
    }

    try:
        from src.prompts.tier1_cluster_prefill import build_further_tasks_prompt
    except ImportError:
        from prompts.tier1_cluster_prefill import build_further_tasks_prompt  # type: ignore

    cluster_sources = sorted({str(r.get('_source') or r.get('source') or '') for r in cluster_rows if r.get('_source') or r.get('source')})
    prompt = build_further_tasks_prompt(
        cluster=cluster,
        uncovered_rows=uncovered,
        missing_sources=missing_sources,
        completed_task_titles=body.completed_task_titles,
        entities_allowed=entities_allowed,
        cluster_sources=cluster_sources,
    )

    llm = _get_llm(body.model)
    if not llm:
        return JSONResponse({
            'status': 'no_llm',
            'further_tasks': [],
            'uncovered_row_count': len(uncovered),
        })

    further_tasks: list[dict] = []
    try:
        resp = llm.generate(
            prompt=prompt,
            max_tokens=512,
            tenant_id=tenant_id,
            overrides={'timeout': 20},
            model=body.model,
        )
        raw = (resp.get('text') or resp.get('response') or
               resp.get('content') or '') if isinstance(resp, dict) else str(resp)
        raw = raw.strip()
        if raw.startswith('```'):
            raw = '\n'.join(l for l in raw.split('\n') if not l.strip().startswith('```'))
        parsed = json.loads(raw)
        candidate_tasks = parsed.get('further_tasks') or []

        # Validate grounding: each task must cite real uncovered rows or missing sources
        uncovered_indices = {
            r.get('row_index') for r in uncovered
            if r.get('row_index') is not None
        } | {
            r.get('row_number') for r in uncovered
            if r.get('row_number') is not None
        }
        missing_lower = {s.lower() for s in missing_sources}

        for task in candidate_tasks:
            refs = [r for r in (task.get('evidence_refs') or [])
                    if r in uncovered_indices]
            ms = task.get('missing_source') or ''
            grounded_by_missing = ms and ms.lower() in missing_lower

            if refs or grounded_by_missing:
                task['evidence_refs'] = refs  # strip any hallucinated refs
                further_tasks.append(task)
            else:
                logger.debug(
                    'further_tasks: dropped ungrounded task "%s" for cluster %s',
                    task.get('title', '?'), cluster_id,
                )

    except Exception as exc:
        logger.warning('further_tasks LLM failed for %s/%s: %s',
                       assessment_id, cluster_id, exc)
        return JSONResponse({
            'status': 'llm_error',
            'error': str(exc),
            'further_tasks': [],
        })

    return JSONResponse({
        'status': 'ok',
        'cluster_id': cluster_id,
        'further_tasks': further_tasks,
        'uncovered_row_count': len(uncovered),
        'grounded_count': len(further_tasks),
    })


# ── E9: Kill-chain phase timeline ─────────────────────────────────────────────

@router.get('/{assessment_id}/clusters/{cluster_id}/timeline')
async def get_cluster_timeline(
    assessment_id: str,
    cluster_id: str,
) -> JSONResponse:
    """Return rows for this cluster tagged with kill-chain phase, sorted by timestamp."""
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    refs = set(cluster.get('row_refs') or [])
    cluster_rows = [r for r in all_rows
                    if (r.get('row_index') in refs or r.get('row_number') in refs)]

    # Tag kill-chain phase and extract timestamp for sort
    _TS_FIELDS = (
        'timestamp_utc', 'date_utc', 'timestamp_iso', 'source_time',
        'ts', 'timestamp', 'eventTime', 'time', 'createdDateTime',
        'activityDateTime', 'TimeGenerated', 'start', 'date',
        'datetime', '@timestamp', 'event_time', 'UpdatedDateTime',
    )
    tagged: list[dict] = []
    for r in cluster_rows:
        ts_val = None
        for tf in _TS_FIELDS:
            v = r.get(tf)
            if v is not None:
                ts_val = v
                break
        tagged.append({
            'row_index': r.get('row_index') if 'row_index' in r else r.get('row_number'),
            'severity': r.get('severity') or r.get('risk_level') or 'info',
            'source': r.get('_source') or r.get('source') or '',
            'description': str(r.get('description') or r.get('activityDisplayName') or
                               r.get('operationName') or r.get('analyst_notes') or '')[:200],
            'mitre_technique': r.get('mitre_technique') or r.get('technique_id') or '',
            'kill_chain_phase': tag_kill_chain_phase(r),
            'user': r.get('user') or r.get('user_principal_name') or '',
            'src_ip': r.get('src_ip') or r.get('source_ip') or '',
            'hostname': r.get('hostname') or r.get('host') or '',
            'timestamp_raw': ts_val,
            'country': str(r.get('country') or r.get('geo_country') or r.get('src_country') or ''),
            'asn': str(r.get('asn') or r.get('src_asn') or r.get('as_org') or ''),
        })

    # Sort: rows with timestamps first (ascending), then un-timestamped
    def _ts_sort_key(row: dict):
        v = row['timestamp_raw']
        if v is None:
            return (1, 0)
        if isinstance(v, (int, float)):
            return (0, float(v) * 1000 if v < 1e12 else float(v))
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(str(v).replace('Z', '+00:00'))
            return (0, dt.timestamp() * 1000)
        except Exception:
            return (1, 0)

    tagged.sort(key=_ts_sort_key)

    # Annotate rows where the ASN appears in 2+ distinct kill-chain phases
    _asn_phase_sets: dict[str, set[str]] = {}
    for row in tagged:
        asn = row.get('asn', '')
        if asn:
            _asn_phase_sets.setdefault(asn, set()).add(row['kill_chain_phase'])
    _reused_asns = {asn for asn, ps in _asn_phase_sets.items() if len(ps) >= 2}
    for row in tagged:
        row['_asn_reused'] = bool(row.get('asn') and row['asn'] in _reused_asns)

    # Group by kill-chain phase in order
    phases: dict[str, list] = {}
    for row in tagged:
        phase = row['kill_chain_phase']
        phases.setdefault(phase, []).append(row)

    ordered_phases = []
    for phase in _PHASE_ORDER + ['Unknown']:
        if phase in phases:
            ordered_phases.append({'phase': phase, 'rows': phases[phase]})

    return JSONResponse({
        'assessment_id': assessment_id,
        'cluster_id': cluster_id,
        'rows': tagged,
        'phases': ordered_phases,
        'total': len(tagged),
    })


# ── E10: Analyst sticky notes ──────────────────────────────────────────────────

@router.patch('/{assessment_id}/clusters/{cluster_id}/notes')
async def patch_cluster_notes(
    assessment_id: str,
    cluster_id: str,
    body: NotesRequest,
) -> JSONResponse:
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    cluster['analyst_notes'] = {
        'text': body.notes,
        'analyst_id': body.analyst_id,
        'updated_at': int(time.time()),
    }
    _persist(assessment_id, assessment)

    return JSONResponse({
        'status': 'ok',
        'cluster_id': cluster_id,
        'updated_at': cluster['analyst_notes']['updated_at'],
    })


# ── E11: IOC bundle (served; client can also build this locally) ───────────────

@router.get('/{assessment_id}/clusters/{cluster_id}/iocs')
async def get_cluster_iocs(
    assessment_id: str,
    cluster_id: str,
) -> JSONResponse:
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    refs = set(cluster.get('row_refs') or [])
    cluster_rows = [r for r in all_rows
                    if (r.get('row_index') in refs or r.get('row_number') in refs)]

    iocs = _extract_iocs(cluster, cluster_rows)
    iocs['exported_at'] = int(time.time())
    return JSONResponse(iocs)


# ── E12: Repeat entity detection ──────────────────────────────────────────────

@router.get('/{assessment_id}/clusters/{cluster_id}/repeat-entities')
async def get_repeat_entities(
    assessment_id: str,
    cluster_id: str,
) -> JSONResponse:
    """Scan all stored assessments for clusters sharing entities with this cluster."""
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    refs = set(cluster.get('row_refs') or [])
    cluster_rows = [r for r in all_rows
                    if (r.get('row_index') in refs or r.get('row_number') in refs)]

    current_iocs = _extract_iocs(cluster, cluster_rows)
    current_entities: set[str] = set(
        current_iocs['users'] + current_iocs['ips'] + current_iocs['hosts']
    )

    if not current_entities:
        return JSONResponse({'matches': [], 'current_entity_count': 0})

    matches: list[dict] = []
    try:
        from src.api.deep_analyze_endpoints import REPORT_STORE
        for past_aid, past_assessment in list(REPORT_STORE.items()):
            if past_aid == assessment_id:
                continue
            past_clusters = past_assessment.get('correlation_clusters') or []
            past_rows = (past_assessment.get('normalized_rows') or
                         past_assessment.get('rows') or [])
            for pc in past_clusters:
                pc_refs = set(pc.get('row_refs') or [])
                pc_rows = [r for r in past_rows
                           if (r.get('row_index') in pc_refs or r.get('row_number') in pc_refs)]
                pc_iocs = _extract_iocs(pc, pc_rows)
                past_entities: set[str] = set(
                    pc_iocs['users'] + pc_iocs['ips'] + pc_iocs['hosts']
                )
                shared = current_entities & past_entities
                if shared:
                    matches.append({
                        'past_assessment_id': past_aid,
                        'past_cluster_id': pc.get('cluster_id', ''),
                        'past_verdict': pc.get('verdict') or pc.get('final_verdict', ''),
                        'past_severity': pc.get('severity', ''),
                        'shared_entities': sorted(shared)[:10],
                        'shared_count': len(shared),
                    })
    except Exception as exc:
        logger.debug('repeat_entities scan failed: %s', exc)

    matches.sort(key=lambda m: m['shared_count'], reverse=True)
    return JSONResponse({
        'cluster_id': cluster_id,
        'current_entity_count': len(current_entities),
        'matches': matches[:10],
        'match_count': len(matches),
    })
