import hashlib
import inspect
import json
import os
import time
from typing import Dict, Any, List
try:
    from src.explain.dread import aggregate  # type: ignore
except Exception:
    aggregate = None

SIGNAL_HINTS = {
    'novel_global': 'Hash not seen across enterprise baseline.',
    'novel_local': 'New artifact on this host.',
    'temp_execution': 'Executed from temporary directory.',
    'naming_mimicry': 'Filename mimics trusted tooling.',
    'orphan_process': 'Parent process missing from telemetry.',
    'unsigned_executable': 'Binary lacks vendor signature.',
    'lolbin': 'Executed via living-off-the-land binary.',
    'network_beacon': 'Periodic outbound connections detected.',
    'credential_access': 'Touched credential stores.',
}


def _resolve_model_for_tier(tier: str, context: Dict[str, Any] | None = None) -> str:
    """Return preferred model name for a tier, honoring context and env vars.

    Defaults: T1=llama3.2:3b (fast per-row), T2=llama3.1:8b (quality narrative).
    Override with T1_MODEL / T2_MODEL env vars.
    """
    env_key = 'T1_MODEL' if tier == 'tier1' else 'T2_MODEL'
    # Ollama-first defaults (better quality, local, no cost)
    ollama_fallback = 'llama3.2:3b' if tier == 'tier1' else 'llama3.1:8b'
    try:
        if context and context.get('model'):
            return context.get('model')
    except Exception:
        pass
    return os.getenv(env_key) or ollama_fallback


def _resolve_token_limit(tier: str) -> int:
    return 1024 if tier == 'tier1' else 2048


def _estimate_tier_cost(tier: str) -> float:
    if tier == 'tier2':
        return float(os.getenv('T2_COST_PER_ROW', os.getenv('LLM_COST_PER_ROW', '0.015')))
    return float(os.getenv('LLM_COST_PER_ROW', '0.003'))


def _estimate_row_severity(row: Dict[str, Any]) -> float:
    """Refined severity blending dread, correlation, triage score (if present) and verdict weight.

    Formula (bounded 0..1): 0.35*dread_norm + 0.25*corr_norm + 0.25*triage_score + 0.15*verdict_weight
    """
    try:
        dread = row.get('_dread') or row.get('dread') or {}
        if isinstance(dread, dict):
            dread = dread.get('score', 0)
        dread_score = float(dread or 0) / 10.0
    except Exception:
        dread_score = 0.0
    try:
        corr = row.get('correlation_score') or (row.get('_correlation') or {}).get('score') or 0.0
        corr = float(corr) if corr is not None else 0.0
    except Exception:
        corr = 0.0
    triage = 0.0
    try:
        triage = float(row.get('triage_score') or 0.0)
    except Exception:
        triage = 0.0
    verdict = (row.get('verdict') or '').upper()
    verdict_weight = 1.0 if verdict in {'CRITICAL','HIGH','MALICIOUS'} else (0.6 if verdict == 'SUSPICIOUS' else 0.25)
    score = (dread_score * 0.35) + (corr * 0.25) + (triage * 0.25) + (verdict_weight * 0.15)
    return max(0.0, min(1.0, score))


def _build_signal_context(row: Dict[str, Any], pipeline: Dict[str, Any]) -> List[Dict[str, Any]]:
    factors = row.get('factors') or []
    host_stats = {}
    fleet_stats = {}
    try:
        host_stats = pipeline.get('host_factor_counts') or row.get('host_factor_counts') or {}
    except Exception:
        host_stats = {}
    try:
        fleet_stats = pipeline.get('global_factor_counts') or row.get('global_factor_counts') or {}
    except Exception:
        fleet_stats = {}
    context = []
    for factor in factors[:8]:
        entry = {'signal': factor, 'explanation': SIGNAL_HINTS.get(str(factor).lower(), 'Pipeline flagged this indicator.')}
        if isinstance(host_stats, dict) and factor in host_stats:
            entry['host_recent_occurrences'] = host_stats.get(factor)
        if isinstance(fleet_stats, dict) and factor in fleet_stats:
            entry['enterprise_occurrences'] = fleet_stats.get(factor)
        context.append(entry)
    if not context:
        context.append({'signal': 'none', 'explanation': 'No pipeline signals provided.'})
    return context


def _build_baseline_context(row: Dict[str, Any], pipeline: Dict[str, Any]) -> Dict[str, Any]:
    baseline = {}
    try:
        baseline['host_recent_alerts'] = row.get('host_recent_alerts') or pipeline.get('host_recent_alerts')
        baseline['user_recent_alerts'] = row.get('user_recent_alerts') or pipeline.get('user_recent_alerts')
        baseline['historical_context'] = pipeline.get('historical_context') or row.get('historical_context')
    except Exception:
        baseline = {}
    return baseline or {'message': 'No baseline context attached to this row.'}


def _build_threat_intel_context(row: Dict[str, Any], pipeline: Dict[str, Any]) -> Dict[str, Any]:
    context: Dict[str, Any] = {}
    ti = row.get('ti_hits') or pipeline.get('ti_hits') or row.get('threat_intel') or {}
    if isinstance(ti, dict):
        context.update(ti)
    vt = row.get('vt') or row.get('virustotal')
    if vt:
        context['virustotal'] = vt
    sigma = row.get('sigma_matches') or pipeline.get('sigma_matches')
    if sigma:
        context['sigma_matches'] = sigma
    intel_tags = row.get('intel_tags') or pipeline.get('intel_tags')
    if intel_tags:
        context['intel_tags'] = intel_tags
    if not context:
        context['note'] = 'No external threat intel hits.'
    return context


def _build_tier2_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    host = row.get('host') or row.get('hostname') or 'unknown host'
    user = row.get('user') or row.get('username') or 'unknown user'
    process = row.get('process_name') or row.get('file_path') or 'artifact'
    verdict = (row.get('verdict') or 'suspicious').upper()
    timestamp = row.get('timestamp') or row.get('ts') or row.get('time')
    payload = {
        'executive_summary': {
            'one_liner': f'{process} on {host} flagged as {verdict}',
            'threat_level': 'HIGH' if verdict in {'CRITICAL', 'HIGH'} else 'MEDIUM',
            'recommended_action': 'Isolate host and collect volatile evidence.'
        },
        'ai_reasoning': {
            'primary_hypothesis': 'Potential malware execution from suspicious location.',
            'supporting_evidence': [
                {'observation': f'{process} ran on {host}', 'significance': 'Unexpected execution path.', 'confidence': 0.6}
            ],
            'alternative_hypotheses': [
                {'hypothesis': 'Admin testing or troubleshooting', 'probability': 0.2, 'evidence_needed': 'Confirm with host owner.'}
            ],
            'knowledge_gaps': ['Parent process unknown', 'Network telemetry unavailable'],
            'confidence_level': 'MEDIUM',
            'reasoning_caveats': 'Host baseline not provided.'
        },
        'investigation_tasks': [
            {'task': 'Capture memory image', 'tool': 'Velociraptor', 'priority': 'critical'},
            {'task': 'Collect Sysmon process tree', 'tool': 'SIEM query', 'priority': 'high'}
        ],
        'siem_queries': [
            {'name': 'Hash prevalence', 'query': f'process.hash.sha256:{row.get("sha256") or "*"}', 'platform': 'elastic'}
        ],
        'mitre_mapping': {
            'techniques': (row.get('mitre_tags') or [])[:5],
            'tactics': [],
            'kill_chain_phase': row.get('kill_chain') or 'Execution'
        },
        'evidence_timeline': {'events': [{'timestamp': timestamp or 'unknown', 'event_type': 'process_start', 'description': f'{process} executed', 'severity': 'high'}]},
        'entity_graph': {
            'primary_entity': {'type': 'process', 'identifier': process, 'properties': {'host': host, 'user': user}},
            'related_entities': [{'type': 'host', 'identifier': host, 'relationship': 'executed_on'}]
        },
        'analyst_notes': {'notes': [], 'tags': []}
    }
    return payload


def _enforce_tier2_payload(raw_text: str, row: Dict[str, Any]) -> Dict[str, Any]:
    payload = _build_tier2_payload(row)
    try:
        parsed = json.loads(raw_text)
        if isinstance(parsed, dict):
            payload.update(parsed)
    except Exception:
        pass
    return payload


def build_llm_prompt(row: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Build a 30-45 line structured prompt for SOC triage based on the artifact row and pipeline context.
    """
    try:
        import json
        pipeline = context.get('pipeline_context') or context.get('assessment') or {}
        include_missing = False
        try:
            include_missing = should_include_missing_logs(row, pipeline)
        except Exception:
            include_missing = False

        domain_hint = context.get('gated_domain') or context.get('domain')

        prompt = (
            "You are a SOC analyst performing FAST TRIAGE. Analyze the artifact and provide a concise 30-45 line summary.\n"
            "Include the following sections exactly:\n"
            "WHAT IS IT? (2-3 lines)\n"
            "EXPLOITABILITY (3-4 lines)\n"
            "WHAT TO DO? (3-4 lines)\n"
            "CONCISE PLAYBOOK (5-8 lines - include copy-paste commands)\n"
        )
        if domain_hint:
            prompt += f"\nDetected domain: {domain_hint.upper()}. Tailor the analysis to {domain_hint} telemetry and evidence."
        if include_missing:
            prompt += "MISSING LOGS (3-5 lines) - only include when pipeline evidence suggests gaps\n"

        prompt += "\nARTIFACT JSON:\n" + json.dumps(row, indent=2, default=str) + "\n\n"
        # include compact pipeline context when present
        try:
            ctx_snip = {
                'dread': pipeline.get('dread') or pipeline.get('dread_score') if isinstance(pipeline, dict) else None,
                'mitre': pipeline.get('mitre_tags') or pipeline.get('mitre') if isinstance(pipeline, dict) else None,
                'correlation': (pipeline.get('correlation') or {}).get('score') if isinstance(pipeline.get('correlation', {}), dict) else pipeline.get('correlation') if isinstance(pipeline, dict) else None,
                'attack_patterns': pipeline.get('attack_patterns') if isinstance(pipeline, dict) else None,
            }
            prompt += "PIPELINE CONTEXT:\n" + json.dumps(ctx_snip, default=str) + "\n\n"
        except Exception:
            pass
        try:
            enrichments = pipeline.get('enrichment') if isinstance(pipeline, dict) else {}
            api_sec = (enrichments or {}).get('api_security') or {}
            alerts = api_sec.get('alerts') or []
            if alerts:
                prompt += "API SECURITY FINDINGS:\n"
                for alert in alerts[:5]:
                    prompt += f"- {alert.get('factor')}: {alert.get('note')} (severity={alert.get('severity')})\n"
                prompt += "\n"
            timeline = api_sec.get('forensics') or []
            if timeline:
                prompt += "API TIMELINE (most recent events):\n"
                for record in timeline[:5]:
                    prompt += f"- {record.get('ts')}: {record.get('method')} {record.get('uri')} status={record.get('status')} user={record.get('user')}\n"
                prompt += "\n"
        except Exception:
            pass
        try:
            status_ctx = {}
            snapshot = context.get('pipeline_snapshot')
            if snapshot:
                status_ctx['pipeline_snapshot'] = snapshot
            breaker = context.get('breaker_signal')
            if breaker:
                status_ctx['breaker'] = breaker
            mapping_ctx = context.get('mapping_semantics')
            if mapping_ctx:
                status_ctx['mapping_semantics'] = mapping_ctx
            binary_ctx = context.get('binary_context')
            if binary_ctx:
                status_ctx['binary'] = binary_ctx
            kill_chain = context.get('kill_chain')
            if kill_chain:
                status_ctx['kill_chain'] = kill_chain
            hopgraph_ctx = context.get('hopgraph_context')
            if hopgraph_ctx:
                status_ctx['hopgraph'] = hopgraph_ctx
            if status_ctx:
                prompt += "STATUS CONTEXT:\n" + json.dumps(status_ctx, default=str, indent=2) + "\n\n"
        except Exception:
            pass
        try:
            signal_ctx = _build_signal_context(row, pipeline if isinstance(pipeline, dict) else {})
            prompt += "SIGNAL DICTIONARY:\n" + json.dumps(signal_ctx, default=str, indent=2) + "\n\n"
        except Exception:
            pass
        try:
            baseline_ctx = _build_baseline_context(row, pipeline if isinstance(pipeline, dict) else {})
            prompt += "BASELINE CONTEXT:\n" + json.dumps(baseline_ctx, default=str, indent=2) + "\n\n"
        except Exception:
            pass
        try:
            ti_ctx = _build_threat_intel_context(row, pipeline if isinstance(pipeline, dict) else {})
            prompt += "THREAT INTEL HITS:\n" + json.dumps(ti_ctx, default=str, indent=2) + "\n\n"
        except Exception:
            pass

        prompt += (
            "RULES:\n- Keep output between 30 and 45 lines.\n- Be concise and factual; do not hallucinate beyond provided data.\n"
            "- Use bullet points, include explicit commands in PLAYBOOK.\n- If data is missing, state what logs are required in MISSING LOGS.\n"
        )
        return prompt
    except Exception:
        return f"Summarize row: {str(row)}"


def detect_domain_with_confidence(row: Dict[str, Any]) -> tuple[str, float]:
    """
    Detect investigation domain (network vs endpoint vs generic) with confidence score.

    Returns:
        tuple: (domain_name, confidence_score)
        - domain_name: 'network', 'endpoint', or 'generic'
        - confidence_score: 0.0 to 1.0
    """
    factors = set(row.get('factors', []))

    # Network-specific high-confidence indicators
    network_high = {
        'port_scan', 'beaconing', 'dns_tunneling', 'c2_communication',
        'lateral_movement_smb', 'lateral_movement_rdp', 'data_exfiltration',
        'suspicious_dns', 'dga_domain', 'rare_port', 'uncommon_protocol',
        'outbound_connection', 'malicious_ip', 'tor_exit_node'
    }

    # Endpoint-specific high-confidence indicators
    endpoint_high = {
        'process_injection', 'dll_hijack', 'registry_persistence',
        'scheduled_task', 'service_creation', 'unsigned_binary',
        'memory_manipulation', 'credential_dumping', 'lsass_access',
        'privilege_escalation', 'parent_child_anomaly', 'hollowing',
        'reflective_dll_injection', 'token_impersonation'
    }

    # Medium confidence indicators (could be either)
    network_medium = {
        'unusual_traffic', 'high_volume', 'connection_spike',
        'remote_connection', 'external_ip'
    }

    endpoint_medium = {
        'suspicious_process', 'rare_binary', 'suspicious_path',
        'cmdline_obfuscation', 'encoded_command', 'script_execution'
    }

    # Calculate scores
    network_score = 0.0
    endpoint_score = 0.0

    # High confidence matches (0.3 per match, max 0.9)
    network_high_matches = factors.intersection(network_high)
    endpoint_high_matches = factors.intersection(endpoint_high)
    network_score += min(0.9, len(network_high_matches) * 0.3)
    endpoint_score += min(0.9, len(endpoint_high_matches) * 0.3)

    # Medium confidence matches (0.15 per match, max 0.45)
    network_med_matches = factors.intersection(network_medium)
    endpoint_med_matches = factors.intersection(endpoint_medium)
    network_score += min(0.45, len(network_med_matches) * 0.15)
    endpoint_score += min(0.45, len(endpoint_med_matches) * 0.15)

    # Attribute-based boosting
    has_network_attrs = any([
        row.get('src_ip'), row.get('dst_ip'), row.get('dst_port'),
        row.get('domain'), row.get('url'), row.get('protocol')
    ])
    has_endpoint_attrs = any([
        row.get('process_name'), row.get('file_path'), row.get('sha256'),
        row.get('registry_key'), row.get('parent_process')
    ])

    if has_network_attrs:
        network_score += 0.1
    if has_endpoint_attrs:
        endpoint_score += 0.1

    # Clamp scores to [0, 1]
    network_score = min(1.0, network_score)
    endpoint_score = min(1.0, endpoint_score)

    # Decision logic with confidence threshold
    CONFIDENCE_THRESHOLD = 0.5

    if network_score >= CONFIDENCE_THRESHOLD and network_score > endpoint_score:
        return ('network', network_score)
    elif endpoint_score >= CONFIDENCE_THRESHOLD and endpoint_score > network_score:
        return ('endpoint', endpoint_score)
    elif network_score == endpoint_score and network_score >= CONFIDENCE_THRESHOLD:
        # Tie-breaker: prefer endpoint if has process info
        if has_endpoint_attrs:
            return ('endpoint', endpoint_score)
        elif has_network_attrs:
            return ('network', network_score)
        else:
            return ('generic', 0.5)
    else:
        # Low confidence for both, return generic with max of the two scores
        return ('generic', max(network_score, endpoint_score, 0.3))


def build_tier2_prompt(row: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Build a 60-100 line deep investigation prompt with historical context,
    domain-specific playbooks, and correlation enrichment.

    This is the Tier 2 prompt for "Investigate Further" workflows.
    """
    import json

    # Extract pipeline context
    pipeline = context.get('pipeline_context') or context.get('assessment') or {}

    # Step 1: Detect domain
    domain, confidence = detect_domain_with_confidence(row)
    gated_domain = context.get('gated_domain') or domain
    try:
        confidence = float(context.get('domain_confidence') or confidence or 0.0)
    except Exception:
        confidence = confidence or 0.0

    # Step 2: Query historical incidents (best-effort)
    historical_context = []
    try:
        from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo
        repo = HistoricalIncidentsRepo()
        similar = repo.query_similar_incidents(row, lookback_days=90, limit=3)
        historical_context = similar
    except Exception:
        # Historical repo unavailable - graceful degradation
        historical_context = []
    if not historical_context:
        try:
            from src.services.historical_context import load_host_history  # type: ignore
            host_history = load_host_history(row.get('host') or row.get('hostname') or '')
            if host_history:
                historical_context = host_history
        except Exception:
            pass

    # Step 3: Enrich correlation context
    attack_scenarios = []
    try:
        from src.analysis.correlation_context import enrich_correlation_context
        enriched = enrich_correlation_context(row, pipeline)
        attack_scenarios = enriched.get('scenarios', [])
    except Exception:
        attack_scenarios = []

    # Step 4: Get domain-specific tools and logs
    tools_info = []
    logs_info = {}  # Changed to dict since get_logs_for_mitre returns dict per technique
    try:
        from src.analysis.domain_tools import get_tools_for_domain, get_logs_for_mitre

        # Get tools for detected domain
        domain_for_tools = gated_domain if gated_domain != 'generic' else domain
        if domain_for_tools != 'generic':
            tools_info = get_tools_for_domain(domain_for_tools)  # Returns flat list of dicts

        # Get logs for MITRE techniques
        mitre_tags = pipeline.get('mitre_tags') or pipeline.get('mitre') or row.get('mitre_tags') or []
        if mitre_tags:
            for tag in mitre_tags[:3]:  # Limit to first 3 MITRE tags
                technique_id = tag if isinstance(tag, str) else tag.get('id', '')
                if technique_id:
                    logs_info[technique_id] = get_logs_for_mitre(technique_id)  # Returns dict
    except Exception:
        tools_info = []
        logs_info = {}

    # Build Tier 2 prompt (60-100 lines)
    prompt_lines = []
    prompt_lines.append("You are a THREAT HUNTER performing DEEP INVESTIGATION.")
    prompt_lines.append("Analyze this artifact with full context and provide a comprehensive 60-100 line report.")
    prompt_lines.append("")
    prompt_lines.append("DOMAIN-SPECIFIC EXPECTATIONS:")
    if gated_domain == 'endpoint':
        prompt_lines.append("- Highlight process lineage, persistence techniques, credential access, and host-isolation actions.")
        prompt_lines.append("- Provide EDR, memory, and registry collection steps plus host-based detection queries.")
    elif gated_domain == 'network':
        prompt_lines.append("- Emphasize beaconing cadence, suspicious flows, DNS/HTTP indicators, and containment of IPs/domains.")
        prompt_lines.append("- Provide packet capture/IDS/proxy log pivots and segmentation/ACL changes for containment.")
    else:
        prompt_lines.append("- Cover both endpoint and network view plus any cloud/identity telemetry required to close gaps.")
    prompt_lines.append("")
    status_lines: list[str] = []
    snapshot = context.get('pipeline_snapshot')
    if snapshot:
        status_lines.append(f"Pipeline rank: {snapshot.get('rank_label')} (completed: {', '.join(snapshot.get('completed_stages') or [])})")
        pending = snapshot.get('pending_stages') or []
        if pending:
            status_lines.append("Upcoming stages: " + ', '.join(pending[:5]))
    breaker = context.get('breaker_signal')
    if breaker:
        parts = []
        if breaker.get('queue_depth') is not None:
            parts.append(f"queue_depth={breaker.get('queue_depth')}")
        if breaker.get('congested'):
            parts.append('circuit_breaker=OPEN')
        status_lines.append("Breaker state: " + (' '.join(parts) if parts else str(breaker)))
    mapping_ctx = context.get('mapping_semantics')
    if mapping_ctx:
        score = mapping_ctx.get('score')
        status_lines.append(f"Mapping semantics score: {score}")
    binary_ctx = context.get('binary_context')
    if binary_ctx:
        if binary_ctx.get('binary_entropy') is not None:
            status_lines.append(f"Binary entropy: {binary_ctx['binary_entropy']}")
        if binary_ctx.get('import_risk') is not None:
            status_lines.append(f"Import count: {binary_ctx['import_risk']}")
        if binary_ctx.get('network_anomaly_tags'):
            status_lines.append("Network tags: " + ', '.join(binary_ctx['network_anomaly_tags']))
        if binary_ctx.get('supply_chain_tags'):
            status_lines.append("Supply-chain tags: " + ', '.join(binary_ctx['supply_chain_tags']))
    kill_chain = context.get('kill_chain')
    if kill_chain:
        status_lines.append("Kill-chain phases: " + ', '.join(kill_chain.get('phases', [])))
    hopgraph_ctx = context.get('hopgraph_context')
    if hopgraph_ctx:
        status_lines.append("HopGraph snippet: " + json.dumps(hopgraph_ctx, default=str)[:260])
    if status_lines:
        prompt_lines.append("PIPELINE / ENRICHMENT STATUS:")
        prompt_lines.extend(status_lines)
        prompt_lines.append("")

        try:
            enrichments = pipeline.get('enrichment') if isinstance(pipeline, dict) else {}
            api_sec = (enrichments or {}).get('api_security') or {}
            api_alerts = api_sec.get('alerts') or []
            if api_alerts:
                prompt_lines.append("API SECURITY CONTEXT:")
                for alert in api_alerts[:8]:
                    note = alert.get('note') or ''
                    severity = alert.get('severity') or 'n/a'
                    prompt_lines.append(f"- {alert.get('factor')} (severity {severity}): {note}")
                prompt_lines.append("")
            timeline = api_sec.get('forensics') or []
            if timeline:
                prompt_lines.append("API ATTACK TIMELINE:")
                for record in timeline[:8]:
                    prompt_lines.append(
                        f"- {record.get('ts')}: {record.get('method')} {record.get('uri')} status={record.get('status')} user={record.get('user')}"
                    )
                prompt_lines.append("")
        except Exception:
            pass

    # SECTION 1: WHAT IS IT? WHY SUSPICIOUS?
    prompt_lines.append("=" * 70)
    prompt_lines.append("SECTION 1: WHAT IS IT? WHY SUSPICIOUS?")
    prompt_lines.append("=" * 70)
    prompt_lines.append(f"Domain: {gated_domain.upper()} (confidence: {confidence:.2f})")
    prompt_lines.append("")
    proc = row.get('process_name') or row.get('process') or row.get('file_path') or 'Unknown'
    prompt_lines.append(f"Artifact: {proc}")
    prompt_lines.append(f"Host: {row.get('host') or 'Unknown'}")
    prompt_lines.append(f"User: {row.get('user') or 'Unknown'}")
    if row.get('sha256'):
        prompt_lines.append(f"SHA256: {row.get('sha256')[:16]}...")
    prompt_lines.append("")
    prompt_lines.append("Key Suspicion Factors:")
    factors = row.get('factors', [])
    for i, factor in enumerate(factors[:5], 1):
        prompt_lines.append(f"  {i}. {factor}")
    prompt_lines.append("")

    # SECTION 2: HISTORICAL CONTEXT
    prompt_lines.append("=" * 70)
    prompt_lines.append("SECTION 2: HISTORICAL CONTEXT (CRITICAL!)")
    prompt_lines.append("=" * 70)
    if historical_context:
        prompt_lines.append("⚠️ WARNING: Similar incidents detected in past 90 days:")
        prompt_lines.append("")
        for idx, incident in enumerate(historical_context[:3], 1):
            days_ago = 0
            try:
                from datetime import datetime
                updated = incident.get('updated_at', '')
                if updated:
                    delta = datetime.utcnow() - datetime.fromisoformat(updated)
                    days_ago = delta.days
            except Exception:
                days_ago = 0

            outcome = incident.get('outcome', 'unknown')
            prompt_lines.append(f"  Incident #{idx} ({days_ago} days ago):")
            prompt_lines.append(f"    - Outcome: {outcome.upper()}")
            prompt_lines.append(f"    - Process: {incident.get('process_name', 'N/A')}")
            prompt_lines.append(f"    - Host: {incident.get('host', 'N/A')}")
            if incident.get('analyst_notes'):
                notes = str(incident.get('analyst_notes', ''))[:100]
                prompt_lines.append(f"    - Notes: {notes}")
            prompt_lines.append("")

        prompt_lines.append("DECISION IMPACT:")
        if any(inc.get('outcome') in ['confirmed_malicious', 'ransomware', 'malware'] for inc in historical_context):
            prompt_lines.append("  ⛔ CRITICAL: Previous instance was CONFIRMED MALICIOUS")
            prompt_lines.append("  ⛔ Recommendation: Auto-escalate to Tier 3, isolate host immediately")
        elif any(inc.get('outcome') == 'false_positive' for inc in historical_context):
            prompt_lines.append("  ✓ Previous instance was false positive - exercise caution")
        else:
            prompt_lines.append("  ℹ️ Review historical notes before deciding")
        prompt_lines.append("")
    else:
        prompt_lines.append("No similar incidents recorded in the last 90 days.")
        prompt_lines.append("Treat this as a potentially novel technique and capture findings for future historical baselines.")
        prompt_lines.append("Escalate if new telemetry confirms persistence or C2 overlap.")
        prompt_lines.append("")

    # SECTION 3: ATTACK SCENARIO
    prompt_lines.append("=" * 70)
    prompt_lines.append("SECTION 3: ATTACK SCENARIO & BUSINESS IMPACT")
    prompt_lines.append("=" * 70)
    if attack_scenarios:
        for scenario in attack_scenarios[:3]:
            prompt_lines.append(f"Attack Stage: {scenario.get('factor', 'Unknown').replace('_', ' ').title()}")
            prompt_lines.append(f"  Description: {scenario.get('description', 'N/A')}")
            prompt_lines.append(f"  Techniques: {', '.join(scenario.get('techniques', []))}")
            prompt_lines.append(f"  Business Impact: {scenario.get('business_impact', 'N/A')}")
            prompt_lines.append(f"  Urgency: {scenario.get('urgency', 'MEDIUM')}")
            prompt_lines.append("")
    else:
        prompt_lines.append("Attack scenario analysis: Limited data available")
        prompt_lines.append("Recommend manual correlation with MITRE ATT&CK framework")
        prompt_lines.append("")

    # SECTION 4: COLLECTION PLAYBOOK
    prompt_lines.append("=" * 70)
    prompt_lines.append("SECTION 4: STEP-BY-STEP FORENSIC COLLECTION PLAYBOOK")
    prompt_lines.append("=" * 70)
    prompt_lines.append(f"Domain: {domain.upper()} - Tools optimized for this investigation type")
    prompt_lines.append("")

    if tools_info:
        # tools_info is a flat list of dicts
        for tool in tools_info[:5]:  # Limit to first 5 tools
            prompt_lines.append(f"  • {tool.get('name', 'Unknown')}")
            prompt_lines.append(f"    Purpose: {tool.get('purpose', 'N/A')}")
            if tool.get('command'):
                cmd = str(tool['command'])
                # Template variable substitution hints
                cmd = cmd.replace('{src_ip}', row.get('src_ip', '<SRC_IP>'))
                cmd = cmd.replace('{dst_ip}', row.get('dst_ip', '<DST_IP>'))
                cmd = cmd.replace('{process_name}', proc)
                prompt_lines.append(f"    Command: {cmd}")
            prompt_lines.append("")
    else:
        prompt_lines.append("Generic collection steps:")
        prompt_lines.append("  1. Collect system memory dump")
        prompt_lines.append("  2. Collect process memory (if process still running)")
        prompt_lines.append("  3. Collect registry hives")
        prompt_lines.append("  4. Collect event logs (Security, System, Application)")
        prompt_lines.append("  5. Network packet capture if suspicious connections active")
        prompt_lines.append("")

    # SECTION 5: REQUIRED LOGS
    if logs_info:
        prompt_lines.append("=" * 70)
        prompt_lines.append("SECTION 5: REQUIRED LOGS (MITRE-Mapped)")
        prompt_lines.append("=" * 70)
        # logs_info is a dict: {technique_id: {name, logs, why}}
        for technique_id, log_data in logs_info.items():
            prompt_lines.append(f"MITRE {technique_id}: {log_data.get('name', 'Unknown')}")
            prompt_lines.append(f"  Why: {log_data.get('why', 'N/A')}")
            logs_list = log_data.get('logs', [])
            if logs_list:
                prompt_lines.append("  Required Logs:")
                for log_source in logs_list[:5]:  # Limit to first 5
                    prompt_lines.append(f"    • {log_source}")
            prompt_lines.append("")

    # SECTION 6: DECISION CRITERIA
    prompt_lines.append("=" * 70)
    prompt_lines.append("SECTION 6: DECISION CRITERIA")
    prompt_lines.append("=" * 70)
    dread = pipeline.get('dread_score') or pipeline.get('dread') or 0.0
    if isinstance(dread, dict):
        dread = dread.get('score', 0.0)
    prompt_lines.append(f"DREAD Score: {dread:.1f}/10")
    prompt_lines.append("")
    prompt_lines.append("ALLOWLIST if ALL of:")
    prompt_lines.append("  - Signed by trusted publisher")
    prompt_lines.append("  - No historical malicious outcomes")
    prompt_lines.append("  - DREAD < 4.0")
    prompt_lines.append("  - Known legitimate process path")
    prompt_lines.append("")
    prompt_lines.append("ESCALATE to Tier 3 if ANY of:")
    prompt_lines.append("  - Historical confirmed malicious match")
    prompt_lines.append("  - DREAD >= 7.0")
    prompt_lines.append("  - Credential dumping or lateral movement indicators")
    prompt_lines.append("  - Active C2 communication")
    prompt_lines.append("")

    # SECTION 7: ARTIFACT DATA
    prompt_lines.append("=" * 70)
    prompt_lines.append("SECTION 7: FULL ARTIFACT DATA")
    prompt_lines.append("=" * 70)
    prompt_lines.append(json.dumps(row, indent=2, default=str))
    prompt_lines.append("")

    # SECTION 8: PIPELINE CONTEXT
    if pipeline:
        prompt_lines.append("=" * 70)
        prompt_lines.append("SECTION 8: PIPELINE ENRICHMENT")
        prompt_lines.append("=" * 70)
        ctx_snip = {
            'dread': pipeline.get('dread') or pipeline.get('dread_score'),
            'mitre': pipeline.get('mitre_tags') or pipeline.get('mitre'),
            'correlation': (pipeline.get('correlation') or {}).get('score') if isinstance(pipeline.get('correlation', {}), dict) else pipeline.get('correlation'),
            'attack_patterns': pipeline.get('attack_patterns'),
        }
        prompt_lines.append(json.dumps(ctx_snip, indent=2, default=str))
        prompt_lines.append("")
        prompt_lines.append("SIGNAL DICTIONARY:")
        prompt_lines.append(json.dumps(_build_signal_context(row, pipeline if isinstance(pipeline, dict) else {}), indent=2, default=str))
        prompt_lines.append("")
        prompt_lines.append("BASELINE CONTEXT:")
        prompt_lines.append(json.dumps(_build_baseline_context(row, pipeline if isinstance(pipeline, dict) else {}), indent=2, default=str))
        prompt_lines.append("")
        prompt_lines.append("THREAT INTEL HITS:")
        prompt_lines.append(json.dumps(_build_threat_intel_context(row, pipeline if isinstance(pipeline, dict) else {}), indent=2, default=str))
        prompt_lines.append("")

    # FINAL INSTRUCTIONS
    prompt_lines.append("=" * 70)
    prompt_lines.append("INSTRUCTIONS")
    prompt_lines.append("=" * 70)
    prompt_lines.append("Based on ALL context above, provide:")
    prompt_lines.append("  1. Verdict: INVESTIGATE / ESCALATE / SHELF / BENIGN")
    prompt_lines.append("  2. Confidence: 0-100%")
    prompt_lines.append("  3. Reasoning: 2-3 sentences explaining decision")
    prompt_lines.append("  4. Next Steps: 3-5 specific actions for analyst")
    prompt_lines.append("  5. Hunt Query: KQL/SPL to find similar artifacts")
    prompt_lines.append("")
    prompt_lines.append("CRITICAL:")
    prompt_lines.append("  - Do NOT hallucinate - only use provided data")
    prompt_lines.append("  - Do NOT re-derive MITRE/DREAD - already calculated")
    prompt_lines.append("  - Do reference historical outcomes if present")
    prompt_lines.append("  - Do provide copy-paste commands from playbook")
    prompt_lines.append("")

    return '\n'.join(prompt_lines)


_PROMPT_VERSION_CACHE: dict[str, str] = {}


def _compute_prompt_source_hash(fn: Any) -> str:
    """Hash the source code of a prompt builder for version tracking."""
    try:
        source = inspect.getsource(fn)
    except Exception:
        source = getattr(fn, '__name__', 'unknown_prompt')
    digest = hashlib.sha1(source.encode('utf-8')).hexdigest()[:10]
    return digest


def _resolve_prompt_version(tier: str) -> str:
    """Return semantic version for Tier1/Tier2 prompts with optional overrides."""
    key = 'tier2' if tier == 'tier2' else 'tier1'
    override = os.getenv(f'{key.upper()}_PROMPT_VERSION')
    if override:
        _PROMPT_VERSION_CACHE[key] = override
        return override
    cached = _PROMPT_VERSION_CACHE.get(key)
    if cached:
        return cached
    builder = build_tier2_prompt if key == 'tier2' else build_llm_prompt
    digest = _compute_prompt_source_hash(builder)
    commit = os.getenv('PROMPT_VERSION_COMMIT') or os.getenv('GIT_COMMIT') or os.getenv('SOURCE_VERSION')
    version = f'{key}-sha{digest}'
    if commit:
        version = f'{version}+{commit[:7]}'
    _PROMPT_VERSION_CACHE[key] = version
    return version


class LLMAssessmentClient:
    def __init__(self):
        # Lightweight shim that delegates to the central LLM client for
        # provider selection, timeouts, retries, and mock handling.
        try:
            from src.integrations.llm_client import DEFAULT_CLIENT
            self._client = DEFAULT_CLIENT
        except Exception:
            self._client = None

    def summarize_row(self, row: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        # Build structured prompt based on tier mode
        # Tier 1: 30-45 line fast triage (default)
        # Tier 2: 60-100 line deep investigation
        ctx = dict(context or {})
        tier = ctx.get('tier', 'tier1')
        prompt_version = _resolve_prompt_version(tier)
        # propagate domain hints so prompts can gate expectations
        try:
            if not ctx.get('gated_domain'):
                domain_hint, domain_conf = detect_domain_with_confidence(row)
                ctx['gated_domain'] = domain_hint
                ctx['domain_confidence'] = domain_conf
        except Exception:
            pass
        try:
            severity = _estimate_row_severity(row)
            ctx['severity_score'] = severity
            escalate_model = os.getenv('T2_HIGH_CONF_MODEL')
            threshold = float(os.getenv('T2_HIGH_CONF_THRESHOLD', '0.75'))
            if tier == 'tier2' and escalate_model and severity >= threshold:
                ctx['model'] = escalate_model
                ctx['escalated_model'] = True
        except Exception:
            pass
        try:
            if tier == 'tier2':
                user_prompt = build_tier2_prompt(row, ctx)
            else:
                user_prompt = build_llm_prompt(row, ctx)
        except Exception:
            user_prompt = f"Summarize for triage: {str(row)}"

        # Call central LLM client if available
        payload: Dict[str, Any] | None = None
        try:
            if self._client:
                try:
                    # forward per-call overrides (e.g., ollama_host, ollama_model, provider)
                    overrides = None
                    try:
                        overrides = ctx.get('overrides')
                    except Exception:
                        overrides = None
                    model_name = _resolve_model_for_tier(tier, ctx)
                    token_cap = _resolve_token_limit(tier)
                    # Pre-check prompt for prompt-injection patterns
                    try:
                        from src.core.detectors.prompt_injection import detect_prompt_injection
                        inj = detect_prompt_injection(user_prompt)
                        if inj and tier == 'tier2':
                            # Block or flag risky tier2 prompts
                            return {'text': 'Prompt blocked due to detected prompt-injection patterns', 'model': 'blocked', 'meta': {'injection': inj}, 'payload': None}
                    except Exception:
                        pass
                    if overrides:
                        resp = self._client.generate(user_prompt, model=model_name, max_tokens=token_cap, tenant_id=ctx.get('org'), overrides=overrides)
                    else:
                        resp = self._client.generate(user_prompt, model=model_name, max_tokens=token_cap, tenant_id=ctx.get('org'))
                except Exception:
                    resp = None
                if isinstance(resp, dict):
                    # normalize various possible shapes
                    text = resp.get('text') or (resp.get('meta') or {}).get('text') or (resp.get('choices') and resp.get('choices')[0].get('text')) if isinstance(resp.get('choices'), list) else ''
                    meta = resp.get('meta') or {}
                    # some providers put tokens under usage
                    if not meta and isinstance(resp.get('usage'), dict):
                        meta = resp.get('usage')
                    model_name = resp.get('model') or meta.get('model') or ctx.get('model') or 'unknown'
                elif isinstance(resp, str):
                    text = resp
                    meta = {}
                    model_name = ctx.get('model') or 'unknown'
                else:
                    text = ''
                    meta = {}
                    model_name = ctx.get('model') or 'unknown'

                meta.setdefault('prompt_version', prompt_version)

                # sanitize and enforce structured sections
                try:
                    content = text or ''
                    if tier == 'tier2':
                        payload = _enforce_tier2_payload(content, row)
                        text = json.dumps(payload, indent=2)
                    else:
                        include_missing = False
                        try:
                            pipeline_ctx = ctx.get('pipeline_context') or ctx.get('assessment') or {}
                            include_missing = should_include_missing_logs(row, pipeline_ctx)
                        except Exception:
                            include_missing = False
                        text = _enforce_tier1_schema(content, row, include_missing)
                    try:
                        max_chars = int(ctx.get('max_chars')) if ctx.get('max_chars') else None
                    except Exception:
                        max_chars = None
                    if max_chars is not None and len(text) > max_chars:
                        text = self._semantic_truncate(text, max_chars)
                except Exception:
                    text = text or ''

                if not (text or '').strip():
                    raise RuntimeError('empty_llm_response')

                # ensure meta has safe defaults
                try:
                    meta.setdefault('input_tokens', int(meta.get('input_tokens') or meta.get('prompt_tokens') or 0))
                except Exception:
                    meta['input_tokens'] = 0
                try:
                    meta.setdefault('output_tokens', int(meta.get('output_tokens') or meta.get('completion_tokens') or 0))
                except Exception:
                    meta['output_tokens'] = 0
                    meta.setdefault('estimated_cost', float(meta.get('estimated_cost') or meta.get('cost') or 0.0) or _estimate_tier_cost(tier))
                    meta.setdefault('confidence', float(meta.get('confidence') or 0.9))

                # Track cost/tokens if tracker available (best-effort)
                try:
                    from src.analysis.cost_tracker import EXTERNAL_TRACKER, LOCAL_TRACKER
                    it = int(meta.get('input_tokens') or 0)
                    ot = int(meta.get('output_tokens') or 0)
                    est_cost = float(meta.get('estimated_cost') or 0.0)
                    if est_cost and EXTERNAL_TRACKER:
                        EXTERNAL_TRACKER.track_call(int(row.get('row_index') or -1), model_name or 'unknown', it, ot, est_cost)
                    else:
                        if LOCAL_TRACKER:
                            LOCAL_TRACKER.track_call(int(row.get('row_index') or -1), model_name or 'unknown', it, ot, int(meta.get('gpu_time_ms') or 0))
                except Exception:
                    pass

                # ensure metadata is attached back to row for persistence
                try:
                    row['_llm_processed'] = True
                    row['_llm_timestamp'] = int(time.time())
                    row['_llm_model'] = model_name
                    row['_llm_cost'] = float(meta.get('estimated_cost') or meta.get('cost') or _estimate_tier_cost(tier))
                    row['_llm_tier'] = tier
                    row['llm_meta'] = meta
                    row['_llm_prompt_version'] = prompt_version
                except Exception:
                    pass

                return {'text': text, 'model': model_name or 'unknown', 'meta': meta, 'payload': payload}
        except Exception:
            pass

        # Fallback deterministic templated summary
        try:
            tier = ctx.get('tier', 'tier1')
            meta = {'prompt_version': prompt_version}
            if tier == 'tier2':
                fallback_payload = _build_tier2_payload(row)
                text = json.dumps(fallback_payload, indent=2)
                return {'text': text, 'model': 'fallback-tier2', 'meta': meta, 'payload': fallback_payload}
            text = _build_tier1_fallback(row)
            return {'text': text, 'model': 'fallback-tier1', 'meta': meta}
        except Exception:
            return {'text': 'LLM not available', 'model': 'none', 'meta': {'prompt_version': prompt_version}}

    def _semantic_truncate(self, text: str, max_chars: int) -> str:
        """Truncate `text` to `max_chars` preserving high-priority sections.

        Priority order (highest to lowest): WHAT IS IT, WHAT TO DO, EXPLOITABILITY,
        CONCISE PLAYBOOK, MISSING LOGS, remaining bullets. If needed, truncate
        within sections, removing lines from lower-priority sections first.
        """
        try:
            sections = {}
            current = 'PREAMBLE'
            for ln in text.splitlines():
                up = ln.strip().upper()
                if up.startswith('WHAT IS IT'):
                    current = 'WHAT'
                    sections.setdefault(current, []).append(ln)
                elif up.startswith('WHAT TO DO'):
                    current = 'TO_DO'
                    sections.setdefault(current, []).append(ln)
                elif up.startswith('EXPLOITABILITY'):
                    current = 'EXPLOITABILITY'
                    sections.setdefault(current, []).append(ln)
                elif up.startswith('CONCISE PLAYBOOK') or up.startswith('PLAYBOOK'):
                    current = 'PLAYBOOK'
                    sections.setdefault(current, []).append(ln)
                elif up.startswith('MISSING LOGS'):
                    current = 'MISSING'
                    sections.setdefault(current, []).append(ln)
                else:
                    sections.setdefault(current, []).append(ln)

            # Reconstruct preserving priority
            priority = ['WHAT', 'TO_DO', 'EXPLOITABILITY', 'PLAYBOOK', 'MISSING', 'PREAMBLE']
            out_lines = []
            for key in priority:
                for ln in sections.get(key, []):
                    out_lines.append(ln)
                    if len('\n'.join(out_lines)) >= max_chars:
                        # truncate the current line if needed
                        joined = '\n'.join(out_lines)
                        return joined[:max_chars]

            # If still too long, progressively drop lower-priority lines
            if len('\n'.join(out_lines)) <= max_chars:
                return '\n'.join(out_lines)

            # As a last resort, trim to max_chars
            return '\n'.join(out_lines)[:max_chars]
        except Exception:
            return text[:max_chars]


def build_llm_row(row: Dict[str, Any], context: Dict[str, Any], assessment: Dict[str, Any] | None = None) -> Dict[str, Any]:
    # Collect fields
    proc = row.get('process_name') or row.get('process') or ''
    path = row.get('file_path') or row.get('path') or ''
    sha = row.get('file_hash') or row.get('hash_sha256') or row.get('hash') or ''
    publisher = 'unknown'
    if row.get('signed') is True:
        publisher = 'signed'
    elif row.get('signed') is False:
        publisher = 'unsigned'

    # DREAD numeric via aggregator if available
    numeric = 0.0
    try:
        if aggregate:
            dra = aggregate({'row': row})
            numeric = float((dra.get('damage',0.0) + dra.get('exploit',0.0) + dra.get('repro',0.0)) / 3.0 * 10.0)
        else:
            raise RuntimeError('no_aggregator')
    except Exception:
        numeric = float(min(10.0, max(0.0, 2.0 * len((row.get('factors') or [])))))

    # Map factors to MITRE using simple heuristics if available
    mitre: List[Dict[str, Any]] = []
    try:
        from src.core.mappings.factor_to_mitre import map_factors  # type: ignore
        mitre = map_factors(list(row.get('factors') or []))
    except Exception:
        # heuristic mapping
        facs = list(row.get('factors') or [])
        for f in facs[:3]:
            mitre.append({'id': 'T1055', 'why': f'Associated factor {f}'})

    # deterministic fingerprint: use canonical columns only (sha, process, host, user)
    parts = [str(sha or ''), str(proc or ''), str(row.get('host') or ''), str(row.get('user') or '')]
    fp = hashlib.sha256('|'.join(parts).encode()).hexdigest()
    generated_at = int(time.time())
    # Map numeric score to human-friendly risk label using configurable thresholds
    try:
        high_th = float(os.getenv('LLM_RISK_HIGH', '7'))
        med_th = float(os.getenv('LLM_RISK_MED', '4'))
    except Exception:
        high_th = 7.0
        med_th = 4.0
    risk_label = 'High' if numeric >= high_th else 'Medium' if numeric >= med_th else 'Low'

    rec = {
        'process_name': proc,
        'file_path': path,
        'publisher_signing': publisher,
        'hash_sha256': sha,
        'what_it_does': f"Performs actions related to {', '.join((row.get('factors') or [])[:3])}",
        'can_attackers_use': 'yes - mock rationale' if numeric > 4 else 'no - low impact',
        'mitre_techniques': mitre,
        'classification': row.get('classification') or 'Unknown',
        'risk_level': {'label': risk_label, 'numeric': numeric, 'rationale': 'Derived from DREAD-like scoring'},
        'fingerprint': fp,
        'recommendation': {'action': 'Quarantine' if numeric >= 7 else 'Investigate', 'playbook': '04_isolate_host' if numeric >= 7 else '01_collect_evidence'},
        'source': 'llm' if (context.get('auto_llm') or False) else 'heuristic',
        'comments': [{'by': 'system', 'text': 'auto-generated row', 'timestamp': generated_at}],
        'generated_at': generated_at
    }
    # Attach LLM summary when auto_llm requested
    rec.setdefault('llm_meta', {})
    rec.setdefault('llm_summary', '')
    try:
        client = LLMAssessmentClient()
        if context.get('auto_llm') and client:
            # provide assessment context to summarizer so missing-logs decision can use pipeline evidence
            summary_ctx = dict(context or {})
            summary_ctx.setdefault('tier', summary_ctx.get('tier') or 'tier1')
            summary_ctx.setdefault('assessment', assessment)
            llm_out = client.summarize_row(row, summary_ctx)
            # normalize llm output shape
            if isinstance(llm_out, dict):
                rec['llm_summary'] = llm_out.get('text') or llm_out.get('summary') or ''
                meta = dict(llm_out.get('meta') or {})
                model_name = llm_out.get('model') or meta.get('model') or context.get('model')
                meta['model'] = model_name
                rec['llm_meta'] = meta
                # metadata for bookkeeping
                try:
                    rec['_llm_processed'] = True
                    rec['_llm_timestamp'] = int(time.time())
                    rec['_llm_model'] = model_name
                    # estimated cost placeholder; client may provide meta.estimated_cost
                    rec['_llm_cost'] = float(meta.get('estimated_cost') or meta.get('cost') or 0.003)
                except Exception:
                    pass
            # decide missing logs heuristics using assessment if available
            try:
                if assessment:
                    if should_include_missing_logs(rec, assessment):
                        rec.setdefault('missing_logs', ['inferred: network', 'inferred: auth'])
                else:
                    if should_include_missing_logs(rec, {}):
                        rec.setdefault('missing_logs', ['inferred: network', 'inferred: auth'])
            except Exception:
                pass
            else:
                rec['llm_summary'] = str(llm_out)
                rec['llm_meta'] = {}
            rec['source'] = 'llm'
    except Exception:
        pass
    # Ensure required minimal schema fields for persisted llm_rows
    try:
        provenance = {
            'assessment_id': context.get('assessment_id') if isinstance(context, dict) else None,
            'session_id': context.get('session_id') if isinstance(context, dict) else None,
            'org': context.get('org') if isinstance(context, dict) else None,
            'source': rec.get('source'),
            'generated_at': rec.get('generated_at'),
            'model': (rec.get('llm_meta') or {}).get('model'),
        }
    except Exception:
        provenance = {}

    recommendation = rec.get('recommendation') or {}
    recommendations = [recommendation] if recommendation else []

    raw_index = row.get('row_index')
    if raw_index is None:
        raw_index = row.get('index')
    try:
        row_index_value = int(raw_index)
    except Exception:
        row_index_value = -1
    llm_row = {
        'row_index': row_index_value,
        'fingerprint': rec.get('fingerprint'),
        'hash_sha256': rec.get('hash_sha256'),
        'process_name': rec.get('process_name'),
        'host': row.get('host') or row.get('hostname') or None,
        'user': row.get('user') or None,
        'verdict': row.get('verdict') or row.get('decision') or rec.get('classification') or '',
        'factors': list(row.get('factors') or []),
        'what_it_does': rec.get('what_it_does'),
        'can_attackers_use': rec.get('can_attackers_use'),
        'llm_summary': rec.get('llm_summary') or '',
        'llm_meta': rec.get('llm_meta') or {},
        'risk_level': rec.get('risk_level') or {'label': 'Unknown', 'numeric': 0},
        'risk_label': risk_label,
        'recommendation': rec.get('recommendation') or {},
        'recommendations': recommendations,
        'source': rec.get('source'),
        'comments': rec.get('comments') or [],
        'generated_at': rec.get('generated_at') or int(time.time()),
        'mitre_tags': mitre,
        'provenance': provenance,
        'classification': rec.get('classification') or 'Unknown',
    }
    return llm_row
def should_include_missing_logs(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> bool:
    """Decide whether to include the Missing Logs section based on pipeline context.
    Uses simple heuristics: correlation score, attack patterns, and LLM confidence.
    """
    try:
        corr = float((pipeline_context.get('correlation') or {}).get('score') or pipeline_context.get('correlation_score') or 0.0)
        if corr > 0.5:
            return True
    except Exception:
        pass
    try:
        patterns = pipeline_context.get('attack_patterns') or pipeline_context.get('attack_pattern') or []
        for p in patterns:
            if p and str(p).lower() in {'c2','lateral_movement','persistence','credential_access','exfiltration'}:
                return True
    except Exception:
        pass
    try:
        conf = float((row.get('llm_meta') or {}).get('confidence') or 1.0)
        if conf < 0.8:
            return True
    except Exception:
        pass
    try:
        enrichment = pipeline_context.get('enrichment') if isinstance(pipeline_context, dict) else None
        missing = (enrichment or {}).get('missing_logs') if enrichment else None
        api_missing = ((enrichment or {}).get('api_security') or {}).get('missing_logs') if enrichment else None
        all_missing = []
        if isinstance(missing, list):
            all_missing.extend(missing)
        if isinstance(api_missing, list):
            all_missing.extend(api_missing)
        if all_missing:
            return True
    except Exception:
        pass
    # check factor-based telemetry gaps
    try:
        tele_gaps = {'no_network_logs','no_parent_process','no_registry_data','no_auth_logs'}
        if set(row.get('factors') or []).intersection(tele_gaps):
            return True
    except Exception:
        pass
    return False


def _enforce_tier1_schema(raw_text: str, row: Dict[str, Any], include_missing: bool) -> str:
    """Ensure tier1 summaries always contain canonical sections and 30-45 lines."""
    headings = ['WHAT IS IT?', 'EXPLOITABILITY', 'WHAT TO DO?', 'CONCISE PLAYBOOK']
    if include_missing and 'MISSING LOGS' not in headings:
        headings.append('MISSING LOGS')
    sections: Dict[str, List[str]] = {title: [] for title in headings}
    current = None
    for line in (raw_text or '').splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()
        matched = next((h for h in headings if upper.startswith(h)), None)
        if matched:
            current = matched
            content = stripped[len(matched):].strip(': ') if len(stripped) > len(matched) else ''
            if content:
                sections[matched].append(content)
            continue
        if current:
            sections[current].append(stripped)
    def _fallback_lines(title: str) -> List[str]:
        host = row.get('host') or row.get('hostname') or 'unknown host'
        proc = row.get('process_name') or row.get('process') or row.get('file_path') or 'artifact'
        verdict = row.get('verdict') or row.get('classification') or 'UNKNOWN'
        factors = ', '.join((row.get('factors') or [])[:3]) or 'no high-signal factors provided'
        if title == 'WHAT IS IT?':
            return [f"{proc} on {host} flagged as {verdict}.", f"Top factors: {factors}."]
        if title == 'EXPLOITABILITY':
            return [f"Exploitability driven by {factors}.", "Review execution context and parent processes."]
        if title == 'WHAT TO DO?':
            return ["Collect EDR + Sysmon events.", "Correlate with identity and network telemetry to confirm scope."]
        if title == 'CONCISE PLAYBOOK':
            return [
                "1) Isolate affected host or container.",
                "2) Capture memory + relevant logs.",
                "3) Pivot to correlated alerts and confirm persistence.",
                "4) Contain credentials/networks as needed."
            ]
        if title == 'MISSING LOGS':
            return ["Identify absent network/auth logs.", "Request EDR/NetFlow/Identity telemetry to close gaps."]
        return []
    for heading in headings:
        if not sections.get(heading):
            sections[heading] = _fallback_lines(heading)
    lines: List[str] = []
    for heading in headings:
        lines.append(f"{heading}")
        lines.extend(sections.get(heading, []))
    # Ensure 30-45 lines by padding with evidence bullets
    if len(lines) < 30:
        evidence = [
            f"- Host: {row.get('host') or 'n/a'}",
            f"- User: {row.get('user') or 'n/a'}",
            f"- Path: {row.get('file_path') or row.get('path') or 'n/a'}",
            f"- Hash: {row.get('hash_sha256') or row.get('sha256') or 'n/a'}",
            f"- DREAD: {(row.get('_dread') or {}).get('score') or 0}"
        ]
        idx = 0
        while len(lines) < 30:
            lines.append(evidence[idx % len(evidence)])
            idx += 1
    if len(lines) > 45:
        lines = lines[:45]
    return '\n'.join(lines)


def _build_tier1_fallback(row: Dict[str, Any]) -> str:
    """Deterministic Tier 1 summary when LLM is unavailable."""
    proc = row.get('process_name') or row.get('process') or row.get('file_path') or 'artifact'
    host = row.get('host') or 'unknown host'
    verdict = row.get('verdict') or row.get('classification') or 'UNKNOWN'
    factors = ', '.join((row.get('factors') or [])[:4]) or 'no high-signal factors provided'
    lines = [
        f"WHAT IS IT?: {proc} on {host} flagged as {verdict}",
        f"EXPLOITABILITY: Driven by {factors}",
        "WHAT TO DO?:",
        "- Collect EDR + Sysmon telemetry",
        "- Verify parent/child process lineage",
        "- Capture memory if process still running",
        "CONCISE PLAYBOOK:",
        "1) Get system info: systeminfo > C:\\temp\\sys.txt",
        "2) Dump process: procdump -ma <PID> C:\\temp\\proc.dmp",
        "3) Capture netstat: netstat -ano | findstr <PID>",
        "4) Query autoruns: autorunsc.exe -accepteula",
    ]
    while len(lines) < 30:
        lines.append(f"- Evidence: host={host} user={row.get('user') or 'n/a'} process={proc}")
    if len(lines) > 45:
        lines = lines[:45]
    return '\n'.join(lines)


def _build_tier2_fallback(row: Dict[str, Any], context: Dict[str, Any]) -> str:
    """Structured Tier 2 fallback (60-100 lines)."""
    domain, confidence = detect_domain_with_confidence(row)
    gated_domain = context.get('gated_domain') or domain
    try:
        confidence = float(context.get('domain_confidence') or confidence or 0.0)
    except Exception:
        confidence = confidence or 0.0
    lines: List[str] = []

    def add_section(title: str):
        lines.append("=" * 70)
        lines.append(title)
        lines.append("=" * 70)

    add_section("SECTION 1: WHAT IS IT? WHY SUSPICIOUS?")
    lines.append(f"Domain: {gated_domain.upper()} (confidence: {confidence:.2f})")
    lines.append(f"Process: {row.get('process_name') or row.get('process') or row.get('file_path') or 'unknown'}")
    lines.append(f"Host: {row.get('host') or 'unknown'}  User: {row.get('user') or 'unknown'}")
    lines.append(f"Verdict: {row.get('verdict') or row.get('classification') or 'UNKNOWN'}")
    lines.append("Suspicion Factors:")
    for idx, factor in enumerate((row.get('factors') or [])[:5], 1):
        lines.append(f"  {idx}. {factor}")
    lines.append("")

    add_section("SECTION 2: HISTORICAL CONTEXT (CRITICAL!)")
    lines.append("No historical repository available in fallback mode.")
    lines.append("Treat as a potentially novel technique; document findings for future runs.")
    lines.append("")

    add_section("SECTION 3: ATTACK SCENARIO & BUSINESS IMPACT")
    lines.append("Likely Scenario: Credential access / execution abuse based on observed factors.")
    lines.append("Business Impact: Potential lateral movement, C2 beaconing, or data staging.")
    lines.append("Recommended Hunt Focus:")
    lines.append("  - Review parent processes and recent logon sessions.")
    lines.append("  - Inspect network connections tied to the process PID.")
    lines.append("  - Cross-check identity telemetry for unusual MFA/SSO events.")
    lines.append("")

    add_section("SECTION 4: STEP-BY-STEP FORENSIC COLLECTION PLAYBOOK")
    if gated_domain == 'network':
        lines.extend([
            "1. Capture packet data for src/dst pairs observed.",
            "2. Pull firewall/proxy logs for matching indicators.",
            "3. Review NetFlow for sustained beacon cadence.",
            "4. Contain suspicious IPs via ACL/network segmentation.",
        ])
    else:
        lines.extend([
            "1. Acquire memory image (e.g., winpmem) for the host.",
            "2. Dump suspect process memory (procdump -ma <PID>).",
            "3. Collect autoruns + scheduled tasks for persistence.",
            "4. Gather registry hives and relevant event logs.",
            "5. Capture timeline (MFTECmd, $MFT) for staging evidence.",
        ])
    lines.append("")

    add_section("SECTION 5: REQUIRED LOGS")
    lines.extend([
        "Minimum telemetry required to validate findings:",
        "  - Sysmon (Event IDs 1,3,7,10,11)",
        "  - Security Event Log (4624/4625/4672/4688)",
        "  - EDR alerts for process injection/persistence",
        "  - DNS/Proxy logs for outbound indicators",
        "  - Authentication logs (Azure AD/Okta) for correlated activity",
        "",
    ])

    add_section("SECTION 6: DECISION CRITERIA")
    dread = 0.0
    try:
        dread = float((row.get('_dread') or {}).get('score') or (row.get('dread') or {}).get('score') or 0.0)
    except Exception:
        dread = 0.0
    lines.append(f"DREAD Score (approx): {dread:.1f}/10")
    lines.append("Escalate if:")
    lines.append("  - DREAD >= 7 or factors include credential_dumping/lateral movement")
    lines.append("  - Network indicators confirm beaconing or exfiltration")
    lines.append("  - Host shows persistence or multiple privileged logons")
    lines.append("Allowlist if:")
    lines.append("  - Signed, known-good binary with benign parent lineage")
    lines.append("  - No external communications or privilege changes detected")
    lines.append("")

    while len(lines) < 60:
        lines.append(f"- Evidence: host={row.get('host') or 'n/a'} user={row.get('user') or 'n/a'} process={row.get('process_name') or 'n/a'}")
    if len(lines) > 100:
        lines = lines[:100]
    return '\n'.join(lines)
