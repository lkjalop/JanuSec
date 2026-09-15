"""
XDR Excel Summary Report
Aggregates the two per-file classifier reports and produces a single
Janusec summary with cross-mapping to STRIDE, DREAD, MAESTRO, and PASTA.

Input reports (created by scripts/xdr_excel_classify.py):
  - reports/cybstash_csv1_report.csv
  - reports/cyberstash_csv2_report.csv

Output:
  - reports/janusec_summary.json

Mapping approach:
  - For each flagged (verdict == 'bad') row, derive a small set of heuristic
    pipeline-like factors from available fields to support taxonomy mapping.
  - Feed union of factors into core.threat_modeling.factor_taxonomy.aggregate_threat_model
    to derive STRIDE categories, DREAD components, and MAESTRO phases.
  - PASTA scenarios are matched if their required_factors are a subset of the
    derived factor set; counts are summarized.

Run:
  python -m scripts.xdr_excel_summary
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
import argparse
import os
import requests

import pandas as pd

from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model
from src.core.threat_modeling.pasta_scenarios import SCENARIOS


def _derive_factors_from_row(row: Dict[str, Any], source: str) -> List[str]:
    """Heuristic factor derivation for taxonomy mapping.

    source: 'csv2' or 'csv1'
    """
    factors: List[str] = []
    reason = str(row.get('reason') or '').lower()
    if source == 'csv2':
        # Suspicious/malicious or AV hits indicate anomaly clusters
        if 'malicious=true' in reason or 'suspicious=true' in reason:
            factors.append('corr_multisurface_anomaly')
        if 'avpositives=' in reason:
            factors.append('endpoint:exec_burst')
        if 'threatscore=' in reason:
            factors.append('corr_beacon_rare_ua')  # generic anomaly indicator
        if 'threatname=' in reason and 'suspicious' in reason:
            factors.append('corr_anomalous_user_agent_chain')
    else:
        # csv1 is path-only; temp executables suggest persistence/execution chains
        if 'temp_location_executable' in reason:
            factors.extend(['endpoint:rare_lineage', 'endpoint:persistence_candidate', 'endpoint:exec_burst'])
        else:
            # default: no strong signal
            pass
    # Deduplicate
    return sorted(set(factors))


def _load_reports() -> Tuple[pd.DataFrame, pd.DataFrame]:
    p1 = Path('reports/cybstash_csv1_report.csv')
    p2 = Path('reports/cyberstash_csv2_report.csv')
    if not p1.exists() or not p2.exists():
        raise FileNotFoundError('Expected reports missing. Run scripts/xdr_excel_classify first.')
    return pd.read_csv(p1), pd.read_csv(p2)


def _summarize(df: pd.DataFrame, source: str) -> Dict[str, Any]:
    total = len(df)
    good = int((df['verdict'] == 'good').sum()) if 'verdict' in df else 0
    bad = int((df['verdict'] == 'bad').sum()) if 'verdict' in df else 0
    factors_all: List[str] = []
    flagged_samples: List[Dict[str, Any]] = []
    if 'verdict' in df:
        flagged_df = df[df['verdict'] == 'bad']
        for _, row in flagged_df.iterrows():
            rowd = row.to_dict()
            f = _derive_factors_from_row(rowd, source)
            factors_all.extend(f)
            # Keep a small sample record
            sample = {k: rowd.get(k) for k in list(rowd.keys())[:8]}
            sample['factors'] = f
            flagged_samples.append(sample)
    # Aggregate taxonomy
    model = aggregate_threat_model(factors_all)
    # PASTA scenarios
    pasta_hits: Dict[str, int] = {}
    fset = set(factors_all)
    for scn in SCENARIOS:
        if scn.required_factors and scn.required_factors.issubset(fset):
            pasta_hits[scn.id] = pasta_hits.get(scn.id, 0) + 1
    return {
        'counts': {'total': total, 'good': good, 'bad': bad},
        'taxonomy': model,
        'pasta': {
            'matched': [{'id': sid, 'count': c} for sid, c in sorted(pasta_hits.items(), key=lambda x: (-x[1], x[0]))]
        },
        'flagged_samples': flagged_samples[:20],
    }


def _notify_services(services: List[str], summary: Dict[str, Any], api_url: str, api_key: str | None) -> None:
    overall = summary['summary']['overall']
    stride = summary['summary']['csv2']['taxonomy']['stride']['categories'] if summary['summary']['csv2']['taxonomy'] else []
    maestro = summary['summary']['csv2']['taxonomy']['maestro']['phases'] if summary['summary']['csv2']['taxonomy'] else []
    stride_str = ', '.join(stride[:4]) if isinstance(stride, list) else ''
    maestro_str = ', '.join([p[0] for p in maestro[:3]]) if isinstance(maestro, list) else ''
    text = (
        f"JanuSec Excel Summary: total={overall['total']} good={overall['good']} bad={overall['bad']}\n"
        f"Top STRIDE (csv2): {stride_str}\nTop MAESTRO phases (csv2): {maestro_str}"
    )
    headers = {'x-api-key': api_key} if api_key else {}

    for svc in services:
        svc = svc.lower()
        try:
            if svc in ('slack','teams','whatsapp'):
                # POST /api/v1/webhooks/test with service param and text in body
                url = f"{api_url.rstrip('/')}/api/v1/webhooks/test?service={svc}"
                resp = requests.post(url, json={'service': svc, 'text': text}, headers=headers, timeout=6)
                print(f"notify[{svc}]: {resp.status_code} {resp.text[:120]}")
            elif svc == 'jira':
                # Fetch Jira webhook_url from integrations status, then post text
                st = requests.get(f"{api_url.rstrip('/')}/api/v1/integrations/status", headers=headers, timeout=6)
                webhook = None
                if st.ok:
                    data = st.json()
                    webhook = ((data or {}).get('jira') or {}).get('webhook_url')
                if not webhook:
                    print('notify[jira]: no_webhook_configured')
                    continue
                jr = requests.post(webhook, json={'summary': 'JanuSec Excel Summary', 'text': text}, timeout=8)
                print(f"notify[jira]: {jr.status_code}")
            else:
                print(f"notify[{svc}]: unsupported service")
        except Exception as e:
            print(f"notify[{svc}]: error {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description='Aggregate Excel classification reports and optionally notify.')
    parser.add_argument('--notify', nargs='*', help='Services to notify: slack teams jira whatsapp')
    parser.add_argument('--api-url', default=os.getenv('JANUSEC_API_URL', 'http://localhost:8080'), help='Base API URL for integrations')
    parser.add_argument('--api-key', default=os.getenv('JANUSEC_API_KEY', os.getenv('API_KEY')), help='x-api-key for API calls')
    args = parser.parse_args()

    df1, df2 = _load_reports()
    s1 = _summarize(df1, 'csv1')
    s2 = _summarize(df2, 'csv2')

    out = {
        'source_reports': ['reports/cybstash_csv1_report.csv', 'reports/cyberstash_csv2_report.csv'],
        'summary': {
            'csv1': s1,
            'csv2': s2,
            'overall': {
                'total': s1['counts']['total'] + s2['counts']['total'],
                'good': s1['counts']['good'] + s2['counts']['good'],
                'bad': s1['counts']['bad'] + s2['counts']['bad'],
            }
        },
        'audit': [
            {'action': 'classified', 'source': 'cybstash_csv1', 'counts': s1['counts']},
            {'action': 'classified', 'source': 'cyberstash_csv2', 'counts': s2['counts']},
        ],
        'egress_options': ['slack', 'teams', 'whatsapp', 'jira', 'webhook'],
        'note': 'Use API /integrations/webhooks/test or /integrations/{name}/config to configure and dispatch notifications.'
    }

    out_path = Path('reports/janusec_summary.json')
    out_path.write_text(json.dumps(out, indent=2))
    print(f'Wrote {out_path}')

    if args.notify:
        _notify_services(args.notify, out, args.api_url, args.api_key)


if __name__ == '__main__':
    main()
