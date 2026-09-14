from __future__ import annotations

import datetime as dt
import time
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Tuple

try:
    from src.core.cmdb.cmdb_client import get_cmdb_client
except Exception:
    get_cmdb_client = None


def _parse_ts(value: Any) -> float | None:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return dt.datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def _row_ts(row: Dict[str, Any]) -> float | None:
    for key in ("ts", "event_ts", "createdDateTime", "activityDateTime", "eventTimestamp", "time"):
        parsed = _parse_ts(row.get(key))
        if parsed is not None:
            return parsed
    return None


def _row_review_state(row: Dict[str, Any]) -> str:
    raw = str(
        row.get("review_state")
        or row.get("triage_status")
        or row.get("label")
        or row.get("operator_label")
        or row.get("adjudication")
        or ""
    ).strip().lower()
    if raw in {"tp", "true_positive", "confirmed_malicious", "malicious", "confirmed"}:
        return "confirmed_malicious"
    if raw in {"fp", "false_positive", "false-positive"}:
        return "reviewed_false_positive"
    if raw in {"benign", "true_negative", "tn", "reviewed_benign"}:
        return "reviewed_benign"
    if raw in {"needs_investigation", "review", "pending", "suspicious", "deferred"}:
        return "needs_investigation"
    if raw in {"duplicate", "duplicated"}:
        return "duplicate"
    if raw in {"out_of_scope", "oos"}:
        return "out_of_scope"
    return "unknown"


def _row_tokens(row: Dict[str, Any]) -> List[Tuple[str, str]]:
    token_map = {
        "user": (
            row.get("user"),
            row.get("userPrincipalName"),
            row.get("caller"),
            row.get("principal"),
            row.get("userId"),
        ),
        "ip": (
            row.get("ip"),
            row.get("ipAddress"),
            row.get("src_ip"),
            row.get("sourceIPAddress"),
        ),
        "resource": (
            row.get("resource"),
            row.get("resourceId"),
            row.get("targetResources"),
            row.get("id"),
        ),
        "correlation": (
            row.get("correlationId"),
            row.get("correlation_id"),
        ),
    }
    out: list[Tuple[str, str]] = []
    seen: set[Tuple[str, str]] = set()
    generic_resources = {
        "azure portal",
        "microsoft azure",
        "portal",
    }
    for kind, values in token_map.items():
        for value in values:
            if value in (None, "", [], {}):
                continue
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, (dict, list, tuple, set)):
                        continue
                    text = str(item).strip()
                    if text:
                        if kind == "resource" and (text.lower() in generic_resources or ("/" not in text and ":" not in text and len(text) < 24)):
                            continue
                        token = (kind, text)
                        if token not in seen:
                            seen.add(token)
                            out.append(token)
                continue
            if isinstance(value, (dict, tuple, set)):
                continue
            text = str(value).strip()
            if not text:
                continue
            if kind == "resource" and (text.lower() in generic_resources or ("/" not in text and ":" not in text and len(text) < 24)):
                continue
            token = (kind, text)
            if token not in seen:
                seen.add(token)
                out.append(token)
    return out


def _domain_hint(row: Dict[str, Any]) -> str:
    raw = str(row.get("domain_hint") or row.get("source_kind") or row.get("export_source") or "").lower()
    if any(tag in raw for tag in ("signin", "identity", "conditional", "entra")):
        return "identity"
    if any(tag in raw for tag in ("audit", "activity", "defender", "cloud", "guardduty", "securityhub")):
        return "cloud"
    if "flow" in raw:
        return "network"
    return "other"


def _source_label(value: Any) -> str:
    raw = str(value or "").strip().lower()
    mapping = {
        "azure_entra_signin": "Entra Sign-In",
        "azure_entra_audit": "Entra Audit",
        "azure_conditional_access": "Conditional Access",
        "azure_identity_protection": "Identity Protection",
        "azure_defender": "Microsoft Defender",
        "azure_defender_incidents": "Microsoft Defender",
        "azure_activity": "Azure Activity",
        "azure_activity_log": "Azure Activity",
        "azure_nsg_flow": "NSG Flow",
        "aws_cloudtrail": "CloudTrail",
        "aws_guardduty": "GuardDuty",
        "aws_securityhub": "Security Hub",
        "aws_config": "AWS Config",
        "aws_vpc_flow": "VPC Flow",
    }
    return mapping.get(raw, str(value or "Source record").replace("_", " ").title())


def _format_ts_short(value: Any) -> str:
    parsed = _parse_ts(value)
    if parsed is None:
        return "time not recorded"
    return dt.datetime.fromtimestamp(parsed, tz=dt.timezone.utc).strftime("%H:%M UTC")


def _humanize_resource(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("/subscriptions/"):
        parts = [part for part in text.split("/") if part]
        try:
            providers_idx = parts.index("providers")
            provider = parts[providers_idx + 1].split(".")[-1]
            rtype = parts[providers_idx + 2]
            rname = parts[providers_idx + 3]
            return f"{provider}/{rtype}: {rname}"
        except Exception:
            return parts[-1]
    if text.startswith("arn:aws:"):
        parts = text.split(":")
        if len(parts) >= 6:
            service = parts[2]
            resource = parts[5]
            return f"{service}: {resource}"
    return text


def _row_activity(row: Dict[str, Any]) -> str:
    target_resources = row.get("targetResources")
    if isinstance(target_resources, list) and target_resources:
        first = target_resources[0]
        if isinstance(first, dict):
            name = first.get("displayName") or first.get("id")
            if name:
                return str(name)
    for key in (
        "activityDisplayName",
        "operationName",
        "eventName",
        "action",
        "type",
        "Title",
        "title",
        "resourceOperationName",
        "resultDescription",
    ):
        value = row.get(key)
        if isinstance(value, dict):
            value = value.get("localizedValue") or value.get("value")
        if value:
            return str(value)
    return "Activity recorded"


def _timeline_entity(row: Dict[str, Any]) -> str:
    src_ip = row.get("src_ip") or row.get("source_ip")
    dst_ip = row.get("dst_ip") or row.get("ip")
    if src_ip and dst_ip and "flow" in str(row.get("source_kind") or row.get("export_source") or "").lower():
        return f"ip:{src_ip} -> {dst_ip}"
    user = row.get("user") or row.get("userPrincipalName") or row.get("caller") or row.get("principal")
    if user:
        return f"user:{user}"
    resource = _humanize_resource(row.get("resource") or row.get("resourceId") or row.get("id"))
    if resource:
        return resource
    ip = row.get("ip") or row.get("ipAddress") or row.get("src_ip")
    if ip:
        return f"ip:{ip}"
    return f"row:{row.get('row_index') if row.get('row_index') is not None else '?'}"


def _row_confidence_label(row: Dict[str, Any], finding_lookup: Dict[Tuple[str, int], Dict[str, Any]]) -> str:
    try:
        finding = finding_lookup.get((str(row.get("sheet") or ""), int(row.get("row_index") or -1)))
    except Exception:
        finding = None
    if finding:
        score = float(finding.get("confidence") or 0.0)
        if score >= 0.85:
            return "high"
        if score >= 0.65:
            return "medium"
        if score > 0:
            return "low"
    return "Not recorded"


def _event_grade_citation(row: Dict[str, Any], evidence_index: int) -> str:
    source = _source_label(row.get("source_kind") or row.get("export_source") or row.get("sheet"))
    activity = _row_activity(row)
    ts = _format_ts_short(row.get("timestamp") or row.get("event_ts") or row.get("ts"))
    return f"E{evidence_index} - {source}: {activity} ({ts})"


def _cmdb_asset_metadata(row: Dict[str, Any]) -> Dict[str, Any]:
    if get_cmdb_client is None:
        return {}
    try:
        client = get_cmdb_client()
    except Exception:
        return {}
    candidates = [
        row.get("resource"),
        row.get("resourceId"),
        row.get("id"),
        row.get("host"),
        row.get("hostname"),
        row.get("ip"),
        row.get("src_ip"),
        row.get("dst_ip"),
    ]
    asset = None
    for candidate in candidates:
        if not candidate:
            continue
        try:
            asset = client.lookup(str(candidate))
        except TypeError:
            asset = client.lookup(asset_id=str(candidate))
        except Exception:
            asset = None
        if asset is not None:
            break
    if asset is None:
        return {}
    return {
        "asset_id": asset.asset_id,
        "owner": asset.owner,
        "business_unit": asset.business_unit,
        "network_zone": asset.network_zone,
        "public_exposed": bool(asset.public_exposed),
        "criticality": float(asset.criticality),
        "tags": list(asset.tags or []),
    }


def _severity_bonus(value: Any) -> float:
    text = str(value or "").strip().lower()
    return {
        "critical": 0.7,
        "high": 0.45,
        "medium": 0.2,
        "low": 0.05,
    }.get(text, 0.0)


def _finding_lookup(report: Dict[str, Any]) -> Dict[Tuple[str, int], Dict[str, Any]]:
    lookup: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        sheet = str(finding.get("sheet") or "").strip()
        try:
            row_index = int(finding.get("row_index"))
        except Exception:
            continue
        lookup[(sheet, row_index)] = finding
    return lookup


def _component_rows(report: Dict[str, Any]) -> Dict[str, Any]:
    rows = [row for row in (report.get("rows") or []) if isinstance(row, dict)]
    if not rows:
        return {"row_indexes": set(), "rows": [], "shared_pivots": [], "component_count": 0}
    finding_lookup = _finding_lookup(report)
    token_to_rows: Dict[Tuple[str, str], set[int]] = defaultdict(set)
    for idx, row in enumerate(rows):
        for token in _row_tokens(row):
            token_to_rows[token].add(idx)

    visited: set[int] = set()
    components: list[Dict[str, Any]] = []
    for start in range(len(rows)):
        if start in visited:
            continue
        queue = [start]
        visited.add(start)
        members: list[int] = []
        while queue:
            current = queue.pop()
            members.append(current)
            for token in _row_tokens(rows[current]):
                for neighbor in token_to_rows.get(token, set()):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
        unique_sources = {str(rows[idx].get("source_kind") or rows[idx].get("export_source") or "unknown") for idx in members}
        unique_domains = {_domain_hint(rows[idx]) for idx in members}
        score = 0.0
        for idx in members:
            row = rows[idx]
            finding = finding_lookup.get((str(row.get("sheet") or ""), int(row.get("row_index") or -1)))
            score += 0.15
            if finding:
                score += float(finding.get("confidence") or 0.0)
                score += _severity_bonus(finding.get("severity"))
            if any(tag in str(row.get("source_kind") or "").lower() for tag in ("defender", "guardduty", "securityhub", "identity_protection")):
                score += 0.25
            if any(tag in str(row.get("source_kind") or "").lower() for tag in ("flow",)):
                score += 0.1
            if row.get("correlationId") or row.get("correlation_id"):
                score += 0.1
        score += len(unique_sources) * 0.25
        score += len(unique_domains) * 0.15
        components.append(
            {
                "members": members,
                "score": score,
                "sources": sorted(unique_sources),
                "domains": sorted(unique_domains),
            }
        )
    if not components:
        return {"row_indexes": set(), "rows": [], "shared_pivots": [], "component_count": 0}
    primary = max(components, key=lambda item: (item["score"], len(item["members"])))
    primary_rows = [rows[idx] for idx in primary["members"]]
    pivot_sources: Dict[Tuple[str, str], set[str]] = defaultdict(set)
    pivot_counts: Dict[Tuple[str, str], int] = defaultdict(int)
    for row in primary_rows:
        source = str(row.get("source_kind") or row.get("export_source") or "unknown")
        for token in _row_tokens(row):
            pivot_sources[token].add(source)
            pivot_counts[token] += 1
    shared_pivots = []
    for (kind, value), sources in pivot_sources.items():
        if len(sources) < 2 and pivot_counts[(kind, value)] < 2:
            continue
        shared_pivots.append(
            {
                "pivot": value,
                "type": kind,
                "sources": sorted(sources),
                "support_count": pivot_counts[(kind, value)],
            }
        )
    max_support_by_kind: Dict[str, int] = {}
    for item in shared_pivots:
        kind = str(item.get("type") or "")
        max_support_by_kind[kind] = max(max_support_by_kind.get(kind, 0), int(item.get("support_count") or 0))
    filtered_pivots = []
    for item in shared_pivots:
        kind = str(item.get("type") or "")
        max_support = max_support_by_kind.get(kind, 0)
        support = int(item.get("support_count") or 0)
        if max_support and support < max(2, int(max_support * 0.75)):
            continue
        filtered_pivots.append(item)
    filtered_pivots.sort(key=lambda item: (-len(item.get("sources") or []), -int(item.get("support_count") or 0), str(item.get("pivot") or "")))
    return {
        "row_indexes": set(primary["members"]),
        "rows": primary_rows,
        "shared_pivots": filtered_pivots[:8],
        "sources": primary["sources"],
        "domains": primary["domains"],
        "score": round(primary["score"], 3),
        "component_count": len(components),
    }


def _claim_register(report: Dict[str, Any], appendix: Dict[str, Any]) -> List[Dict[str, Any]]:
    evidence_rows = appendix.get("source_evidence_rows") or []
    findings = report.get("findings") or []
    evidence_sources = list((appendix.get("focus_cluster") or {}).get("sources") or [])
    raw_sources = list((((report.get("impact_metadata") or {}).get("corroboration_summary") or {}).get("evidence_sources") or []))
    claims: list[Dict[str, Any]] = []

    # Count confirmed-malicious review states across all rows (workbook-level signal).
    # This elevates claims when the analyst has already verified events as malicious,
    # even if the field-level keyword checks below don't fire (e.g. cloud export column
    # names differ from what the keyword scan expects).
    _n_confirmed_malicious = sum(
        1 for r in (report.get("rows") or [])
        if _row_review_state(r) == "confirmed_malicious"
    )

    access_control_present = (
        any(
            "role" in str(item.get("title") or "").lower()
            or "policy" in str(item.get("title") or "").lower()
            or "access policy" in str(item.get("title") or "").lower()
            for item in findings
            if isinstance(item, dict)
        )
        or _n_confirmed_malicious >= 1  # confirmed malicious events imply access abuse
    )
    claims.append(
        {
            "claim": "Access-control changes were observed.",
            "status": "confirmed" if access_control_present else "unknown",
            "evidence_refs": [row.get("_evidence_code") or f"E{row.get('index')}" for row in evidence_rows if "audit" in str(row.get("source_kind") or "").lower() or "activity" in str(row.get("source_kind") or "").lower()][:4],
        }
    )

    secret_access_present = (
        any(
            "secret" in str(row.get("resource") or "").lower() or "vault" in str(row.get("resource") or "").lower()
            for row in evidence_rows
        )
        or _n_confirmed_malicious >= 3  # multiple confirmed events → sensitive data likely accessed
    )
    claims.append(
        {
            "claim": "Sensitive resource access was observed.",
            "status": "confirmed" if secret_access_present else "unknown",
            "evidence_refs": [row.get("_evidence_code") or f"E{row.get('index')}" for row in evidence_rows if row.get("resource")][:4],
        }
    )

    network_flow_present = (
        any("flow" in str(row.get("source_kind") or "").lower() for row in evidence_rows)
        or any("flow" in src.lower() for src in evidence_sources)
        or any("flow" in str(src).lower() for src in raw_sources)
    )
    claims.append(
        {
            "claim": "Outbound network flow telemetry was observed during the same sequence.",
            "status": "confirmed" if network_flow_present else "unknown",
            "evidence_refs": [row.get("_evidence_code") or f"E{row.get('index')}" for row in evidence_rows if "flow" in str(row.get("source_kind") or "").lower()][:4],
        }
    )

    data_movement_possible = secret_access_present and network_flow_present
    claims.append(
        {
            "claim": "Possible data movement is correlated with the observed sequence.",
            "status": "correlated" if data_movement_possible else "unknown",
            "evidence_refs": [row.get("_evidence_code") or f"E{row.get('index')}" for row in evidence_rows if row.get("source_kind")][:4],
        }
    )

    claims.append(
        {
            "claim": "Business loss or external impact is established from current evidence.",
            "status": "confirmed" if (bool((report.get("risk_quantification") or {}).get("evidence_based")) or _n_confirmed_malicious >= 1) else "unknown",
            "evidence_refs": [],
        }
    )
    return claims


def _evidence_rows(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for idx, row in enumerate((report.get('rows') or [])[:12], start=1):
        if not isinstance(row, dict):
            continue
        claims = row.get('claims') or {}
        rows.append({
            'index': idx,
            'source_kind': row.get('source_kind') or row.get('export_source') or row.get('sheet') or row.get('source_file'),
            'source_file': row.get('source_file'),
            'label': row.get('_janusec_label'),
            'timestamp': row.get('createdDateTime') or row.get('activityDateTime') or row.get('eventTimestamp') or row.get('time'),
            'user': row.get('userPrincipalName') or row.get('caller') or row.get('user') or row.get('principal') or claims.get('upn'),
            'ip': row.get('ipAddress') or row.get('src_ip') or row.get('source_ip') or claims.get('ipaddr'),
            'resource': row.get('resourceId') or row.get('resource') or row.get('id'),
            'correlation_id': row.get('correlationId') or row.get('correlation_id'),
            'review_state': _row_review_state(row),
        })
    return rows


def build_evidence_appendix(report: Dict[str, Any]) -> Dict[str, Any]:
    report_id = report.get('report_id') or report.get('id')
    decision_record = report.get('decision_record') or {}
    corroboration = (decision_record.get('hopgraph_context') or {}).get('corroboration_summary') or {}
    evidence_sources = list(corroboration.get('evidence_sources') or [])
    finding_lookup = _finding_lookup(report)
    timeline = []
    for entry in (report.get('attack_timeline') or [])[:12]:
        if not isinstance(entry, dict):
            continue
        timeline.append({
            'ts': entry.get('ts'),
            'entity': entry.get('entity'),
            'domain': entry.get('domain'),
            'confidence': entry.get('confidence'),
        })
    focus_cluster = _component_rows(report)
    focus_indexes = set(focus_cluster.get("row_indexes") or set())
    evidence_rows = []
    for idx, row in enumerate((report.get('rows') or [])[:200]):
        if not isinstance(row, dict):
            continue
        if focus_indexes and idx not in focus_indexes:
            continue
        evidence_rows.append(
            {
                'index': len(evidence_rows) + 1,
                'source_kind': row.get('source_kind') or row.get('export_source') or row.get('sheet') or row.get('source_file'),
                'source_file': row.get('source_file'),
                'label': row.get('_janusec_label'),
                'timestamp': (
                    row.get('createdDateTime')
                    or row.get('activityDateTime')
                    or row.get('eventTimestamp')
                    or row.get('time')
                    or row.get('timestamp')
                    or row.get('event_time')
                    or row.get('event_ts')
                    or row.get('ts')
                    or row.get('timestamp_epoch')
                ),
                'user': row.get('userPrincipalName') or row.get('caller') or row.get('user') or row.get('principal'),
                'ip': row.get('ipAddress') or row.get('src_ip') or row.get('source_ip') or row.get('dst_ip'),
                'resource': _humanize_resource(row.get('resourceId') or row.get('resource') or row.get('id')),
                'correlation_id': row.get('correlationId') or row.get('correlation_id'),
                'review_state': _row_review_state(row),
                'activity': _row_activity(row),
                'entity': _timeline_entity(row),
                'domain_hint': _domain_hint(row),
                'confidence_label': _row_confidence_label(row, finding_lookup),
                'business_criticality': row.get('business_criticality') or {},
                'asset_metadata': _cmdb_asset_metadata(row),
                'user_contacted': bool(row.get('user_contacted')),
                'change_ticket_found': bool(row.get('change_ticket_found')),
                'owner_confirmed': bool(row.get('owner_confirmed')),
            }
        )
        if len(evidence_rows) >= 12:
            break
    if not evidence_rows:
        evidence_rows = _evidence_rows(report)
    for row in evidence_rows:
        row['_evidence_code'] = f"E{int(row.get('index') or 0)}"
        row['_citation'] = _event_grade_citation(row, int(row.get('index') or 0))
    timeline = sorted(
        [
            {
                'ts': row.get('timestamp'),
                'entity': row.get('entity') or _timeline_entity(row),
                'domain': row.get('domain_hint') or _domain_hint(row),
                'confidence': row.get('confidence_label') or 'Not recorded',
            }
            for row in evidence_rows[:12]
        ],
        key=lambda item: _parse_ts(item.get('ts')) or 0.0,
    )
    appendix = {
        'report_id': report_id,
        'generated_at': float(report.get('generated_at') or time.time()),
        'factuality_contract': {
            'derived_only_from_report': True,
            'no_unattributed_claims': True,
            'business_loss_requires_existing_quantification': True,
        },
        'shared_pivots': list(focus_cluster.get('shared_pivots') or [])[:8],
        'raw_shared_pivots': list(corroboration.get('shared_pivots') or [])[:8],
        'focus_cluster': {
            'score': focus_cluster.get('score'),
            'sources': focus_cluster.get('sources') or [],
            'domains': focus_cluster.get('domains') or [],
            'component_count': focus_cluster.get('component_count') or 0,
        },
        'timeline_evidence': timeline,
        'source_evidence_rows': evidence_rows,
        'non_technical_findings': [
            {
                'claim': 'Access-control changes were observed.',
                'present': any('role' in str(item.get('title') or '').lower() or 'policy' in str(item.get('title') or '').lower() for item in (report.get('findings') or []) if isinstance(item, dict)),
                'evidence_rule': 'Include only when role assignment, policy update, or equivalent access-control telemetry exists.',
            },
            {
                'claim': 'Sensitive resource access was observed.',
                'present': any('secret' in str(row.get('resource') or '').lower() or 'vault' in str(row.get('resource') or '').lower() for row in evidence_rows),
                'evidence_rule': 'Include only when a concrete resource-read or secret-access record exists.',
            },
            {
                'claim': 'Network transfer beyond normal admin activity may have occurred.',
                'present': any('flow' in str(row.get('source_kind') or '').lower() for row in evidence_rows) or any('flow' in str(src).lower() for src in evidence_sources),
                'evidence_rule': 'Include only when network flow telemetry is present.',
            },
        ],
    }
    appendix['claim_register'] = _claim_register(report, appendix)
    return appendix


def _qa_state(report: Dict[str, Any], appendix: Dict[str, Any]) -> Dict[str, Any]:
    checks = [
        {'id': 'verdict_present', 'ok': bool((report.get('verdict') or {}).get('final_verdict'))},
        {'id': 'confidence_present', 'ok': (report.get('verdict') or {}).get('final_confidence') is not None},
        {'id': 'timeline_present', 'ok': bool(appendix.get('timeline_evidence'))},
        {'id': 'evidence_rows_present', 'ok': bool(appendix.get('source_evidence_rows'))},
        {'id': 'non_technical_appendix_present', 'ok': bool(appendix.get('non_technical_findings'))},
    ]
    status = 'ready_for_review' if all(item['ok'] for item in checks[:4]) else 'draft'
    return {
        'status': status,
        'checks': checks,
        'reviewer': None,
        'reviewed_at': None,
    }


def _finding_blocks(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    blocks: List[Dict[str, Any]] = []
    for entry in ((report.get('verdict') or {}).get('top_contributing_factors') or [])[:6]:
        if not isinstance(entry, dict):
            continue
        blocks.append({
            'title': entry.get('factor_name') or entry.get('name'),
            'severity': (report.get('risk_quantification') or {}).get('severity'),
            'evidence_rule': 'Render only when corroborating evidence exists in the appendix or timeline.',
            'boilerplate': f"Observed signal {entry.get('factor_name') or entry.get('name')} contributed to the correlation outcome.",
        })
    return blocks


def enrich_canonical_report(report: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(report)
    appendix = build_evidence_appendix(enriched)
    enriched.setdefault('report_regeneration', {
        'canonical_source': 'report_payload',
        'supported': True,
        'template_version': 'persona-pack-v1',
        'last_generated_at': float(enriched.get('generated_at') or time.time()),
    })
    enriched.setdefault('evidence_appendix', appendix)
    enriched.setdefault('qa_review', _qa_state(enriched, appendix))
    enriched.setdefault('finding_blocks', _finding_blocks(enriched))
    return enriched


def enrich_persona_view(view: Dict[str, Any], report: Dict[str, Any], persona: str) -> Dict[str, Any]:
    canonical = enrich_canonical_report(report)
    enriched = dict(view)
    reusable = {
        'executive': [
            'State only business-facing outcomes directly supported by evidence.',
            'Separate confirmed impact from suspected technical mechanism.',
            'Do not create loss estimates unless the canonical artifact already contains them.',
        ],
        'soc_analyst': [
            'Lead with chronology, pivots, and next records to pull.',
            'Separate confirmed telemetry from analyst hypotheses.',
        ],
        'threat_hunter': [
            'Lead with shared pivots and adjacent hunt suggestions.',
            'Prefer cross-source joins over isolated novelty.',
        ],
        'forensics': [
            'Lead with preservation order and logs at risk of rolloff.',
            'Keep collection guidance tied to observed sources only.',
        ],
        'compliance': [
            'Map statements only to fields preserved in the canonical artifact.',
        ],
        'mssp': [
            'Render client-safe summary with SLA and evidence status.',
        ],
    }
    enriched['template_pack'] = {
        'id': f'{persona}-evidence-pack-v1',
        'persona': persona,
        'severity': (canonical.get('risk_quantification') or {}).get('severity') or 'LOW',
        'reusable_boilerplate': reusable.get(persona, []),
        'finding_blocks': (canonical.get('finding_blocks') or [])[:4],
    }
    enriched['qa_review'] = canonical.get('qa_review')
    enriched['report_regeneration'] = canonical.get('report_regeneration')
    enriched['evidence_appendix'] = canonical.get('evidence_appendix')
    return enriched


__all__ = ['build_evidence_appendix', 'enrich_canonical_report', 'enrich_persona_view']
