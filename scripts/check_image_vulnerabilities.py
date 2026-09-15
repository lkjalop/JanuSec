"""Gate critical and fixable high image findings; retain unfixed findings."""
import argparse
import collections
import json
from pathlib import Path


def assess(report):
    if report.get('ArtifactType') != 'container_image' or not report.get('Results'):
        raise ValueError('A nonempty Trivy container image report is required')
    findings = [v for result in report['Results'] for v in result.get('Vulnerabilities', [])]
    blocking = [v for v in findings if v['Severity'] == 'CRITICAL'
                or (v['Severity'] == 'HIGH' and v.get('FixedVersion'))]
    return {
        'severity_counts': dict(collections.Counter(v['Severity'] for v in findings)),
        'blocking': [{'id': v['VulnerabilityID'], 'package': v['PkgName'],
                      'severity': v['Severity'], 'fix': v.get('FixedVersion', '')} for v in blocking],
        'unfixed_high_ids': sorted({v['VulnerabilityID'] for v in findings
                                   if v['Severity'] == 'HIGH' and not v.get('FixedVersion')}),
        'production_approval': False,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    summary = assess(json.loads(args.report.read_text(encoding='utf-8')))
    print(json.dumps(summary, indent=2))
    raise SystemExit(bool(summary['blocking']))
