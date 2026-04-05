"""Generate coverage matrices from rules metadata.

Produces JSON and Markdown outputs summarizing MITRE tactic coverage and (optional)
STRIDE mapping when present in rule metadata.
"""
from __future__ import annotations
import json
import os
from collections import defaultdict
from typing import Dict, Any

HERE = os.path.dirname(__file__)
REGISTRY = os.path.join(HERE, '..', 'core', 'correlation', 'rules', 'rules_metadata.json')


def load_metadata(path: str = REGISTRY) -> list:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def generate_coverage(meta: list) -> Dict[str, Any]:
    tactic_counts = defaultdict(int)
    technique_map = defaultdict(set)
    stride_counts = defaultdict(int)
    rule_map = defaultdict(list)
    hopgraph_rules = []

    for r in meta:
        mitre = r.get('mitre') or {}
        tactic = mitre.get('tactic') or 'Unknown'
        technique = mitre.get('technique_id') or ''
        tactic_counts[tactic] += 1
        if technique:
            technique_map[tactic].add(technique)
        rid = r.get('id')
        rule_map[tactic].append(rid)

        # identify hopgraph-related rules by factor usage
        factors = r.get('factors') or []
        if any(str(f).startswith('graph_') for f in factors):
            hopgraph_rules.append(rid)

        # optional STRIDE mapping in metadata (some rules may include it)
        stride = r.get('stride')
        if stride:
            # stride may be list or string
            if isinstance(stride, (list, tuple)):
                for s in stride:
                    stride_counts[s] += 1
            else:
                stride_counts[stride] += 1

    return {
        'tactic_counts': dict(tactic_counts),
        'technique_map': {k: sorted(list(v)) for k, v in technique_map.items()},
        'stride_counts': dict(stride_counts),
        'rules_by_tactic': dict(rule_map),
        'hopgraph_rules': sorted(hopgraph_rules)
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = []
    lines.append('# Rules Coverage Matrix')
    lines.append('')
    lines.append('## Tactic Counts')
    lines.append('')
    lines.append('| MITRE Tactic | Rule Count |')
    lines.append('|---:|---:|')
    for t, c in sorted(report['tactic_counts'].items(), key=lambda x: -x[1]):
        lines.append(f'| {t} | {c} |')

    if report.get('stride_counts'):
        lines.append('')
        lines.append('## STRIDE Counts (optional)')
        lines.append('')
        lines.append('| STRIDE | Count |')
        lines.append('|---:|---:|')
        for s, c in sorted(report['stride_counts'].items(), key=lambda x: -x[1]):
            lines.append(f'| {s} | {c} |')

    lines.append('')
    lines.append('## Techniques per Tactic (sample)')
    lines.append('')
    for t, techs in report['technique_map'].items():
        lines.append(f'### {t} ({len(techs)} techniques)')
        if techs:
            lines.append('')
            lines.append(', '.join(techs))
        lines.append('')

    return '\n'.join(lines)


def main(out_json: str = None, out_md: str = None):
    meta = load_metadata()
    report = generate_coverage(meta)
    if out_json:
        with open(out_json, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
    if out_md:
        md = render_markdown(report)
        with open(out_md, 'w', encoding='utf-8') as f:
            f.write(md)
    return report


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--json', help='Output JSON file path')
    p.add_argument('--md', help='Output Markdown file path')
    args = p.parse_args()
    main(args.json, args.md)
