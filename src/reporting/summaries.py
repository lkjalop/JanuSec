from typing import Dict, Any, List


def _top_n(items: List[Any], n: int = 5) -> List[Any]:
    return items[:n] if items else []


def top5_risk_drivers(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return top 5 risk drivers from report.risk_quantification and factors.
    Expects keys like 'verdict' with 'top_contributing_factors' and 'risk_quantification'.
    """
    drivers: List[Dict[str, Any]] = []
    rq = report.get("risk_quantification", {})
    for k in [
        "damage_potential",
        "reproducibility",
        "exploitability",
        "affected_users",
        "discoverability",
    ]:
        if k in rq:
            drivers.append({"driver": k, "value": rq[k]})
    # Blend top factors by contribution_score
    factors = report.get("verdict", {}).get("top_contributing_factors", [])
    sorted_factors = sorted(
        factors,
        key=lambda f: f.get("contribution_score", 0.0) if isinstance(f, dict) else 0.0,
        reverse=True,
    )
    for f in sorted_factors:
        if isinstance(f, dict):
            drivers.append(
                {
                    "driver": f.get("factor_name", "factor"),
                    "value": f.get("contribution_score", 0.0),
                    "category": f.get("factor_category"),
                }
            )
        else:
            drivers.append({"driver": str(f), "value": 0.0, "category": None})
    return _top_n(drivers, 5)


def top5_factors(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    factors = report.get("verdict", {}).get("all_factors", [])
    sorted_factors = sorted(
        factors,
        key=lambda f: f.get("contribution_score", 0.0) if isinstance(f, dict) else 0.0,
        reverse=True,
    )
    result = []
    for f in sorted_factors:
        if isinstance(f, dict):
            result.append({
                "name": f.get("factor_name"),
                "score": f.get("contribution_score", 0.0),
                "evidence_count": f.get("evidence_count", 0),
                "category": f.get("factor_category"),
            })
        else:
            result.append({"name": str(f), "score": 0.0, "evidence_count": 0, "category": None})
    return _top_n(result, 5)


def top5_iocs(report: Dict[str, Any]) -> Dict[str, List[str]]:
    """Aggregate IOCs from evidence items, rows, and raw events. Returns top 5 per type."""
    import re as _re
    evidence = report.get("evidence_items", [])
    out: Dict[str, List[str]] = {"ip": [], "domain": [], "hash": [], "email": []}
    seen: Dict[str, set] = {k: set() for k in out.keys()}

    def _add(t: str, v: str) -> None:
        v = str(v).strip()
        if v and v not in seen[t]:
            seen[t].add(v)
            out[t].append(v)

    # --- 1. legacy evidence_items path ---
    for ev in evidence:
        iocs = ev.get("extracted_iocs", {})
        for t, vals in iocs.items():
            if t in out:
                for v in vals:
                    _add(t, v)

    # --- 2. extract from scored rows (deep_analyze / lite assessment rows) ---
    _IP_RE = _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _HASH_RE = _re.compile(r'\b[0-9a-fA-F]{32,64}\b')
    _EMAIL_RE = _re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')

    _FACTOR_IP_FIELDS = ('src_ip', 'dst_ip', 'ip', 'source_ip', 'dest_ip', 'remote_ip', 'c2_ip')
    _FACTOR_HASH_FIELDS = ('sha256', 'sha1', 'md5', 'file_hash', 'hash', 'process_hash')
    _FACTOR_DOMAIN_FIELDS = ('domain', 'fqdn', 'hostname', 'dns_query', 'dest_domain', 'url')
    _FACTOR_EMAIL_FIELDS = ('sender', 'from', 'email', 'recipient', 'envelope_from', 'mail_from')

    rows = report.get("rows") or report.get("llm_rows") or []
    for row in rows:
        if not isinstance(row, dict):
            continue
        # structured fields
        for f in _FACTOR_IP_FIELDS:
            v = row.get(f)
            if v:
                for m in _IP_RE.findall(str(v)):
                    _add('ip', m)
        for f in _FACTOR_HASH_FIELDS:
            v = row.get(f)
            if v:
                for m in _HASH_RE.findall(str(v)):
                    _add('hash', m)
        for f in _FACTOR_DOMAIN_FIELDS:
            v = row.get(f)
            if v:
                _add('domain', str(v).split('/')[0].split('?')[0][:100])
        for f in _FACTOR_EMAIL_FIELDS:
            v = row.get(f)
            if v:
                for m in _EMAIL_RE.findall(str(v)):
                    _add('email', m)
        # scan LLM summary text for IPs and hashes
        summary = str(row.get('llm_summary') or '')
        for m in _IP_RE.findall(summary):
            if not m.startswith('0.') and not m.startswith('127.'):
                _add('ip', m)
        for m in _HASH_RE.findall(summary):
            if len(m) in (32, 40, 64):
                _add('hash', m)
        for m in _EMAIL_RE.findall(summary):
            _add('email', m)

    # --- 3. also check top-level verdict / findings ---
    verdict = report.get('verdict') or {}
    for field in ('c2_ips', 'malicious_ips', 'suspicious_ips'):
        for v in (verdict.get(field) or []):
            for m in _IP_RE.findall(str(v)):
                _add('ip', m)
    for finding in (report.get('findings') or []):
        if not isinstance(finding, dict):
            continue
        for t, field in [('ip', 'src_ip'), ('ip', 'dst_ip'), ('hash', 'hash'), ('domain', 'domain')]:
            v = finding.get(field)
            if v:
                _add(t, str(v))

    return {k: _top_n(v, 5) for k, v in out.items()}


def top5_impacted_entities(report: Dict[str, Any]) -> List[str]:
    timeline = report.get("attack_timeline", [])
    entities: List[str] = []
    seen = set()
    for evt in timeline:
        entity = evt.get("entity")
        if entity and entity not in seen:
            seen.add(entity)
            entities.append(entity)
    return _top_n(entities, 5)


def top5_recommended_actions(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions = report.get("recommended_actions", [])
    # Prefer urgency order: immediate > urgent > normal > low
    urgency_rank = {"immediate": 0, "urgent": 1, "normal": 2, "low": 3}
    sorted_actions = sorted(
        actions,
        key=lambda a: urgency_rank.get(str(a.get("urgency", "low")).lower(), 99),
    )
    result = _top_n(
        [
            {
                "action": a.get("primary_action"),
                "urgency": a.get("urgency"),
                "persona": a.get("persona"),
            }
            for a in sorted_actions
        ],
        5,
    )
    # Anti-pattern fix: never return an empty list — always show at least one action
    if not result:
        result = [{"action": "Continue monitoring — no action required at this time.", "urgency": "low", "persona": None}]
    return result
