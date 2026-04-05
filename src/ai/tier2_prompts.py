from typing import Dict, Any, List

SECTIONS = [
    'verdict', 'actions', 'evidence', 'reasoning', 'timeline', 'threat_intel',
    'graph_context', 'business_impact', 'recommendations', 'controls', 'mitre', 'next_steps'
]

def _sample_evidence_item(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'row_index': row.get('row_index'),
        'summary': row.get('summary') or '',
        'top_factors': row.get('factors') or [],
        'confidence': float(row.get('triage_score') or row.get('confidence') or 0.0),
    }

def build_tier2_prompt_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build a structured prompt context for the 12-section Tier 2 LLM.

    The returned object contains a list of sections and a `context` object
    with rich fields the model can consume. Keep the structure explicit so
    unit tests and prompt templating can reference named fields.
    """
    rows = payload.get('rows') or []
    sample_rows = [r for r in rows[:5]]

    context: Dict[str, Any] = {
        'assessment_id': payload.get('assessment_id'),
        'org': payload.get('org') or payload.get('tenant'),
        'rows_count': len(rows),
        'sample_evidence': [_sample_evidence_item(r) for r in sample_rows],
        'recent_iocs': payload.get('iocs') or [],
        'pipeline_summary': payload.get('pipeline_summary') or {},
        'graph_summary': payload.get('graph_summary') or {},
        'threat_intel': payload.get('threat_intel') or {},
        'time_generated': payload.get('time_generated'),
    }

    # Per-section guidance templates: short descriptions to steer the model
    section_templates: Dict[str, Dict[str, str]] = {}
    section_templates['verdict'] = {
        'prompt': 'One-sentence conclusion about whether this is malicious, suspicious, or benign.',
        'fields': 'verdict_label, score(0-1), top_reason'
    }
    section_templates['actions'] = {
        'prompt': 'High-level recommended actions (triage priority, isolate, block, investigate).',
        'fields': 'action_list, priority, estimated_time'
    }
    section_templates['evidence'] = {
        'prompt': 'Concise evidence list (source, timestamp, snippet, associated IOC).',
        'fields': 'evidence_items[]'
    }
    section_templates['reasoning'] = {
        'prompt': 'Explain why the verdict was reached, referencing evidence items and scoring.',
        'fields': 'rationale_text, uncertainty_reasons'
    }
    section_templates['timeline'] = {
        'prompt': 'Ordered timeline of key events (earliest->latest) with timestamps and actors.',
        'fields': 'timeline[]'
    }
    section_templates['threat_intel'] = {
        'prompt': 'Matches to external intel (MISP/OpenCTI), confidence and relevance.',
        'fields': 'iocs_matches[]'
    }
    section_templates['graph_context'] = {
        'prompt': 'HopGraph summary: key nodes, top path(s), centrality scores and connected assets.',
        'fields': 'nodes[], top_paths[]'
    }
    section_templates['business_impact'] = {
        'prompt': 'Estimate business impact (data types, systems affected, estimated records/volume).',
        'fields': 'impact_estimate, impacted_assets'
    }
    section_templates['recommendations'] = {
        'prompt': 'Concrete remediation and investigation steps, mapping to playbook IDs.',
        'fields': 'playbook_ids[], step_list[]'
    }
    section_templates['controls'] = {
        'prompt': 'Relevant security controls to enable or check (EPP, NAC, WAF, IAM).',
        'fields': 'controls[]'
    }
    section_templates['mitre'] = {
        'prompt': 'Mapped MITRE techniques and tactics with short rationale for each mapping.',
        'fields': 'techniques[]'
    }
    section_templates['next_steps'] = {
        'prompt': 'Checklist for analysts with estimated effort and who should act next.',
        'fields': 'tasks[]'
    }

    # Few-shot guidance: simple example to nudge structured JSON outputs
    few_shot_examples = [
        {
            'input': {
                'sample_evidence': [
                    {'row_index': 1, 'summary': 'NXDOMAIN spike to malicious.example.com', 'top_factors': ['nxdomain_spike'], 'confidence': 0.8}
                ],
                'pipeline_summary': {'note': 'NXDOMAIN + ASN rarity'}
            },
            'output': {
                'verdict': {'summary': 'Likely suspicious', 'confidence': 0.8},
                'evidence': {'items': [{'type': 'domain', 'value': 'malicious.example.com', 'confidence': 0.9}]},
                'actions': {'action_list': ['Block DNS','Collect full pcap'], 'priority': 'high'}
            }
        }
    ]

    # Add a couple more few-shot examples for other section shapes
    few_shot_examples.append({
        'input': {
            'sample_evidence': [
                {'row_index': 2, 'summary': 'Process spawn suspicious binary C:\\Temp\\evil.exe', 'top_factors': ['suspicious_process'], 'confidence': 0.7}
            ]
        },
        'output': {
            'verdict': {'summary': 'Suspicious - possible malware execution', 'confidence': 0.7},
            'evidence': {'items': [{'type': 'process', 'value': 'C:\\Temp\\evil.exe', 'confidence': 0.8}]},
            'actions': {'action_list': ['Isolate host', 'Collect EDR trace'], 'priority': 'high'}
        }
    })

    few_shot_examples.append({
        'input': {
            'sample_evidence': [
                {'row_index': 3, 'summary': 'Suspicious outbound to rare ASN', 'top_factors': ['asn_rarity'], 'confidence': 0.5}
            ]
        },
        'output': {
            'verdict': {'summary': 'Potential exfiltration or C2', 'confidence': 0.6},
            'evidence': {'items': [{'type': 'ip', 'value': '203.0.113.12', 'confidence': 0.6}]},
            'actions': {'action_list': ['Block IP', 'Monitor egress'], 'priority': 'medium'}
        }
    })

    # Missing logs heuristic: suggest what logs would help to raise confidence
    missing = []
    for item in context.get('sample_evidence', []):
        if 'dns' in (item.get('summary') or '').lower() and 'edr' not in context.get('pipeline_summary', {}):
            missing.append('EDR process telemetry (process tree, cmdline, parent PID)')
        if 'nxdomain' in (item.get('summary') or '').lower():
            missing.append('Full DNS query logs and resolver logs including response codes')
    if not missing:
        missing = ['Authentication logs', 'Proxy/Web gateway logs', 'Endpoint EDR telemetry']

    return {
        'sections': SECTIONS,
        'context': context,
        'templates': section_templates,
        'few_shot_examples': few_shot_examples,
        'missing_logs_suggestions': list(dict.fromkeys(missing)),
    }


