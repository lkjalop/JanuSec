from __future__ import annotations
from typing import List, Dict, Any
import time, os, json
from collections import Counter
from .models import ArtifactObservation

REPORT_DIR = os.path.join('dump','artifact_reports')
os.makedirs(REPORT_DIR, exist_ok=True)

LATEST_REPORT_PATH = os.path.join(REPORT_DIR,'latest.json')

SECTION_FACTORS_OF_INTEREST = ['lolbin_misuse','tunneling_utility','macro_autoexec','script_obfuscation_high','fresh_download','rapid_multi_host_appearance','malicious_neighbor']

def build_report(artifacts: List[ArtifactObservation], batch_meta: Dict[str,Any]) -> Dict[str,Any]:
    totals = Counter(a.verdict.value for a in artifacts)
    factor_counts = Counter(f for a in artifacts for f in a.factors)
    lolbin_items = [a for a in artifacts if 'lolbin_misuse' in a.factors or 'tunneling_utility' in a.factors][:25]
    macro_items = [a for a in artifacts if any(f.startswith('macro_') for f in a.factors)][:25]
    fresh_downloads = [a for a in artifacts if 'fresh_download' in a.factors][:25]
    graph_impacted = [a for a in artifacts if a.graph_context]
    top_risky = sorted(artifacts, key=lambda x: x.final_risk, reverse=True)[:20]
    # Technique coverage
    mitre_counts = Counter(t for a in artifacts for t in getattr(a,'mitre',[]) or [])
    stride_counts = Counter()
    for a in artifacts:
        stride_meta = a.factor_details.get('stride',{}) if a.factor_details else {}
        for s in stride_meta.get('categories',[]) or []:
            stride_counts[s]+=1
    prev = None
    try:
        if os.path.exists(LATEST_REPORT_PATH):
            with open(LATEST_REPORT_PATH,'r',encoding='utf-8') as fh:
                prev = json.load(fh)
    except Exception:
        prev = None
    rep = {
        'generated_at': time.time(),
        'batch_meta': batch_meta,
        'verdict_totals': dict(totals),
        'factor_top': factor_counts.most_common(30),
        'top_risky': [serialize_artifact(a) for a in top_risky],
        # NOTE: If artifact volume grows >5000 consider pagination endpoint instead of bundling all
        'all_artifacts': [serialize_artifact(a) for a in artifacts],
        'lolbin_examples': [serialize_artifact(a) for a in lolbin_items],
        'macro_examples': [serialize_artifact(a) for a in macro_items],
        'fresh_downloads': [serialize_artifact(a) for a in fresh_downloads],
        'graph_impact_count': len(graph_impacted),
        'graph_examples': [serialize_artifact(a) for a in graph_impacted[:25]],
        'cost_estimate': batch_meta.get('cost_estimate'),
        'mitre_coverage': mitre_counts.most_common(40),
        'stride_coverage': stride_counts.most_common(),
    }
    # Narrative summary (simple keyword frequency)
    narratives = [a.narrative for a in artifacts if a.narrative]
    if narratives:
        from collections import Counter as _C
        import re
        tokens = []
        for n in narratives:
            tokens.extend([t.lower() for t in re.findall(r"[A-Za-z]{4,}", n)])
        stop = {'with','this','that','from','between','likely','potential','using','execution','artifact','binary','script','macro','persistence','credential'}
        freq = _C(t for t in tokens if t not in stop)
        rep['narrative_summary'] = {
            'count': len(narratives),
            'top_terms': freq.most_common(15),
            'samples': narratives[:5]
        }
    if prev:
        try:
            prev_m = {k:v for k,v in prev.get('mitre_coverage',[])}
            curr_m = {k:v for k,v in rep['mitre_coverage']}
            mitre_delta = []
            for k,v in curr_m.items():
                pv = prev_m.get(k,0)
                if v != pv:
                    mitre_delta.append({'technique': k,'prev': pv,'current': v,'delta': v-pv})
            rep['mitre_delta'] = sorted(mitre_delta, key=lambda x: -abs(x['delta']))[:40]
            prev_s = {k:v for k,v in prev.get('stride_coverage',[])}
            curr_s = {k:v for k,v in rep['stride_coverage']}
            stride_delta = []
            for k,v in curr_s.items():
                pv = prev_s.get(k,0)
                if v!=pv:
                    stride_delta.append({'category': k,'prev': pv,'current': v,'delta': v-pv})
            rep['stride_delta'] = sorted(stride_delta, key=lambda x: -abs(x['delta']))[:20]
        except Exception:
            pass
    try:
        with open(LATEST_REPORT_PATH,'w',encoding='utf-8') as fh:
            json.dump(rep, fh, indent=2)
    except Exception:
        pass
    return rep


def serialize_artifact(a: ArtifactObservation) -> Dict[str,Any]:
    # Extended serialization: include optional sha256, host_count, rarity if available.
    # If the ArtifactObservation model does not yet define these, they will appear as None
    # allowing the frontend to degrade gracefully while we iteratively enrich the pipeline.
    sha256 = getattr(a, 'sha256', None) or getattr(a, 'hash', None)
    # host_count: prefer explicit attribute, else infer from graph_context if it stores host list
    host_count = getattr(a, 'host_count', None)
    if host_count is None and getattr(a, 'graph_context', None):
        try:
            gc = a.graph_context
            # Heuristic: if graph_context contains 'hosts' list or 'host_set'
            if isinstance(gc, dict):
                if 'hosts' in gc and isinstance(gc['hosts'], list):
                    host_count = len(gc['hosts'])
                elif 'host_set' in gc and isinstance(gc['host_set'], (list,set)):
                    host_count = len(gc['host_set'])
        except Exception:
            pass
    rarity = getattr(a, 'rarity', None)  # expected values: RARE|EMERGING|COMMON or None
    return {
        'artifact_id': a.artifact_id,
        'type': a.artifact_type.value,
        'path': a.path,
        'name': a.name,
        'host': a.host,
        'host_count': host_count,
        'sha256': sha256,
        'rarity': rarity,
        'risk': round(a.final_risk,3),
        'verdict': a.verdict.value,
        'factors': a.factors,
        'factor_contributions': a.factor_contributions,
        'mitre': a.mitre,
        'graph': a.graph_context,
        'cluster_id': a.cluster_id,
        'cluster_stats': a.cluster_stats,
        'narrative': a.narrative
        , 'risk_confidence': getattr(a,'risk_confidence', None)
        , 'ambiguity': getattr(a,'ambiguity', None)
        , 'escalation_trace': getattr(a,'escalation_trace', None)
        , 'escalation_status': getattr(a,'escalation_status', None)
    }


def markdown_summary(rep: Dict[str,Any]) -> str:
    t = rep['verdict_totals']
    lines = [f"# Artifact Risk Report {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(rep['generated_at']))}"]
    lines.append("\n## Verdict Totals")
    for k,v in t.items():
        lines.append(f"- {k}: {v}")
    lines.append("\n## Top Risky")
    for item in rep['top_risky'][:10]:
        lines.append(f"* {item['path']} ({item['risk']}) {item['verdict']} factors: {','.join(item['factors'])}")
    lines.append("\n## LOLBin / Tunneling Examples")
    for item in rep['lolbin_examples'][:5]:
        lines.append(f"* {item['path']} {item['factors']}")
    lines.append("\n## Macro / Script Examples")
    for item in rep['macro_examples'][:5]:
        lines.append(f"* {item['path']} {item['factors']}")
    lines.append("\n## Fresh Downloads")
    for item in rep['fresh_downloads'][:5]:
        lines.append(f"* {item['path']} {item['risk']}")
    lines.append("\n## Graph Impact")
    lines.append(f"Graph impacted artifacts: {rep['graph_impact_count']}")
    if rep.get('mitre_coverage'):
        lines.append("\n## MITRE Techniques")
        for t,c in rep['mitre_coverage'][:15]:
            lines.append(f"- {t}: {c}")
    if rep.get('stride_coverage'):
        lines.append("\n## STRIDE Categories")
        for s,c in rep['stride_coverage'][:10]:
            lines.append(f"- {s}: {c}")
    return '\n'.join(lines)
