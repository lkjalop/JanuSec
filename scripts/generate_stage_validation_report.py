"""
Generate a Markdown validation report for pipeline stages 13–21 and key threat
categories by running a curated subset of pytest tests and parsing JUnit XML.

Usage examples:
  python scripts/generate_stage_validation_report.py --preset smoke --out artifacts/pipeline_13_21_validation_results.md
  python scripts/generate_stage_validation_report.py --preset full  --out artifacts/pipeline_13_21_validation_results.md

If you already have a JUnit XML from a prior pytest run, you can pass it with
  --junit artifacts/test-results.xml  (test discovery still used for coverage buckets)
"""
from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from glob import glob
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import pytest  # type: ignore
except Exception:
    pytest = None  # type: ignore


# Stage names and their test file patterns (globs)
STAGE_GLOBS: dict[str, list[str]] = {
    'beacon': [
        'tests/test_beacon_*.py',
        'tests/test_c2_*beacon*.py',
        'tests/test_network_hunter.py',
    ],
    'egress': [
        'tests/test_network_header_and_portscan.py',
        'tests/test_detection_metrics.py',
    ],
    'domain_novelty': [
        'tests/test_network_hunter.py',
        'tests/test_dns*.py',
        'tests/test_geoip_enrichment.py',
    ],
    'rare_token': [
        'tests/test_lolbin_tfidf_*.py',
        'tests/test_week1_rules.py',
        'tests/test_week2_rules.py',
    ],
    'hunt_lanes': [
        'tests/test_lane_*.py',
        'tests/test_graph_enrichment_pipeline.py',
    ],
    'correlation': [
        'tests/test_correlation_*.py',
        'tests/test_week1_rules.py',
        'tests/test_week2_rules.py',
        'tests/week1/test_week1_rule_evals.py',
        'tests/week1/test_week1_vectors.py',
        'tests/test_campaign_correlation.py',
    ],
    'quality_filter': [
        'tests/test_fp_metrics.py',
        'tests/test_detection_metrics.py',
    ],
    'mapping': [
        'tests/test_explain_mapping.py',
        'tests/test_report_mitre_tags.py',
        'tests/test_report_mitre_styles.py',
    ],
    'cluster_dedupe': [
        'tests/test_detection_metrics.py',  # indirect coverage/markers
        'tests/test_correlation_rules*.py',
    ],
}

# Threat categories and patterns
THREAT_GLOBS: dict[str, list[str]] = {
    'APT_multistage': [
        'tests/test_correlation_rules*.py',
        'tests/test_campaign_correlation.py',
        'tests/test_incident_aggregator.py',
    ],
    'LOLbins': [
        'tests/test_week1_rules.py',
        'tests/test_week2_rules.py',
        'tests/test_lolbin_tfidf_*.py',
        'tests/test_report_mitre_tags.py',
    ],
    'Credentials': [
        'tests/test_week2_rules.py',
        'tests/test_t1078_t1133_rules.py',
        'tests/test_auth_smoke.py',
    ],
    'HopGraph': [
        'tests/test_hopgraph_*.py',
        'tests/test_graph_explain_api.py',
        'tests/test_graph_trace_endpoints.py',
        'tests/test_graph_enrichment_pipeline.py',
    ],
    'Cost_FinOps': [
        'tests/test_finops_*.py',
        'tests/test_metrics_guard.py',
        'tests/test_server_metrics.py',
    ],
}

# Presets for quick vs full runs
PRESETS: dict[str, list[str]] = {
    'smoke': [
        # focus on stages 13–21
        *STAGE_GLOBS['beacon'],
        *STAGE_GLOBS['hunt_lanes'],
        *STAGE_GLOBS['correlation'],
        *STAGE_GLOBS['mapping'],
        # essential hopgraph + finops
        *THREAT_GLOBS['HopGraph'],
        *THREAT_GLOBS['Cost_FinOps'],
    ],
    'full': [
        # all stage globs
        *[g for gl in STAGE_GLOBS.values() for g in gl],
        # all threat globs
        *[g for gl in THREAT_GLOBS.values() for g in gl],
        # additional high-signal groups
        'tests/test_incident_aggregator.py',
        'tests/test_beacon_detection.py',
        'tests/test_beacon_multiscale.py',
        'tests/test_beacon_jitter_metrics.py',
        'tests/test_beacon_lomb_error_path.py',
        'tests/test_network_hunter.py',
    ],
}


def expand_globs(patterns: list[str]) -> list[str]:
    files: list[str] = []
    for pat in patterns:
        files.extend(sorted(glob(pat)))
    # Drop Playwright/e2e JS tests; keep Python unit/integration tests only
    files = [f for f in files if f.endswith('.py') and f.startswith('tests/')]
    # Deduplicate while preserving order
    seen = set()
    out: list[str] = []
    for f in files:
        if f not in seen:
            out.append(f)
            seen.add(f)
    return out


def run_pytest_collect(files: list[str], junit_path: str) -> int:
    if not files:
        print('No test files matched. Aborting.', file=sys.stderr)
        return 2
    if pytest is None:
        print('pytest is not available in this environment', file=sys.stderr)
        return 2
    args = files + [
        '-q', '--maxfail=1', f'--junitxml={junit_path}'
    ]
    print('Running pytest with', len(files), 'files...')
    rc = pytest.main(args)
    return int(rc)


def parse_junit(path: str) -> list[tuple[str, str, str]]:
    """Return list of (file, testname, status) where status in {passed,failed,error,skipped}.
    """
    results: list[tuple[str, str, str]] = []
    if not os.path.exists(path):
        return results
    tree = ET.parse(path)
    root = tree.getroot()
    # JUnit formats vary; handle either <testsuite><testcase> or nested
    for tc in root.iter('testcase'):
        classname = tc.attrib.get('classname', '')
        name = tc.attrib.get('name', '')
        # Some runners put file on classname, others as attribute
        file_attr = tc.attrib.get('file') or classname.replace('.', '/') + '.py'
        status = 'passed'
        if tc.find('failure') is not None:
            status = 'failed'
        elif tc.find('error') is not None:
            status = 'error'
        elif tc.find('skipped') is not None:
            status = 'skipped'
        results.append((file_attr, name, status))
    return results


def bucketize(results: list[tuple[str, str, str]], buckets: dict[str, list[str]]) -> dict[str, dict[str, int]]:
    """Aggregate pass/fail/error/skip counts per logical bucket (stage or threat).
    Matches by file glob membership.
    """
    out: dict[str, dict[str, int]] = {k: {'passed': 0, 'failed': 0, 'error': 0, 'skipped': 0, 'total': 0} for k in buckets}
    for file_path, _name, status in results:
        # Normalize path
        file_norm = file_path.replace('\\', '/').replace('./', '')
        for bucket, patterns in buckets.items():
            for pat in patterns:
                # manual glob-ish match: endswith filename portion
                if pat.endswith('*.py'):
                    prefix = pat[:-4]  # drop *.py
                    if file_norm.startswith(prefix[:-1]):  # drop trailing *
                        out[bucket]['total'] += 1
                        out[bucket][status] += 1
                        break
                else:
                    if file_norm.endswith(pat.replace('tests/', '')) or file_norm.endswith(pat):
                        out[bucket]['total'] += 1
                        out[bucket][status] += 1
                        break
    return out


def write_markdown(out_path: str,
                   stage_stats: dict[str, dict[str, int]],
                   threat_stats: dict[str, dict[str, int]],
                   all_results: list[tuple[str, str, str]],
                   exit_code: int) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    total = len(all_results)
    passed = sum(1 for _f, _n, s in all_results if s == 'passed')
    failed = sum(1 for _f, _n, s in all_results if s == 'failed')
    errors = sum(1 for _f, _n, s in all_results if s == 'error')
    skipped = sum(1 for _f, _n, s in all_results if s == 'skipped')

    lines: list[str] = []
    lines.append('# JanuSec Pipeline 13–21 Validation Results')
    lines.append('')
    lines.append(f'- Summary: {passed} passed, {failed} failed, {errors} errors, {skipped} skipped (total {total})')
    lines.append(f'- Overall status code: {exit_code}')
    lines.append('')
    lines.append('## Stage Coverage (13–21)')
    for stage in ['beacon','egress','domain_novelty','rare_token','hunt_lanes','correlation','quality_filter','mapping','cluster_dedupe']:
        s = stage_stats.get(stage, {'total': 0, 'passed': 0, 'failed': 0, 'error': 0, 'skipped': 0})
        lines.append(f'- {stage}: {s["passed"]}/{s["total"]} passed, {s["failed"]} failed, {s["error"]} errors, {s["skipped"]} skipped')
    lines.append('')
    lines.append('## Threat Coverage')
    for k in ['APT_multistage','LOLbins','Credentials','HopGraph','Cost_FinOps']:
        s = threat_stats.get(k, {'total': 0, 'passed': 0, 'failed': 0, 'error': 0, 'skipped': 0})
        lines.append(f'- {k}: {s["passed"]}/{s["total"]} passed, {s["failed"]} failed, {s["error"]} errors, {s["skipped"]} skipped')
    lines.append('')
    if failed or errors:
        lines.append('## Failing/Errored Tests')
        for f, n, s in all_results:
            if s in ('failed','error'):
                lines.append(f'- {f} :: {n} [{s}]')
        lines.append('')

    lines.append('## Next Steps')
    if any(s['total'] == 0 for s in stage_stats.values()):
        lines.append('- Expand test globs for uncovered stages in `scripts/generate_stage_validation_report.py`.')
    if failed or errors:
        lines.append('- Investigate failures; start with associated modules per stage (see docs/VALIDATION_13_21_STAGES.md).')
    lines.append('- Optionally add `--include-metrics` support to embed live `/metrics` stage latency snapshots.')
    lines.append('- Present results alongside LIVE console demo: beacons, correlation explain, hopgraph paths, FinOps summaries.')

    p.write_text('\n'.join(lines), encoding='utf-8')
    print('Wrote', out_path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--preset', choices=sorted(PRESETS.keys()), default='smoke')
    ap.add_argument('--out', required=True, help='Path to write Markdown report')
    ap.add_argument('--junit', help='Optional existing JUnit XML to parse instead of running pytest')
    args = ap.parse_args()

    test_files = expand_globs(PRESETS[args.preset])
    junit_path = args.junit or 'artifacts/test-results.xml'
    exit_code = 0
    if not args.junit:
        exit_code = run_pytest_collect(test_files, junit_path)

    results = parse_junit(junit_path)
    # Bucketize by stages and threats for coverage views
    stage_stats = bucketize(results, STAGE_GLOBS)
    threat_stats = bucketize(results, THREAT_GLOBS)
    write_markdown(args.out, stage_stats, threat_stats, results, exit_code)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())

