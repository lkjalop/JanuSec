from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


DEFAULT_STEPS = [
    [
        sys.executable,
        '-m',
        'pytest',
        '-q',
        'tests/test_kafka_assessment_queue.py',
        'tests/test_kafka_assessment_worker.py',
        'tests/test_kafka_assessment_soak.py',
        'tests/test_aws_pressure_gate.py',
        'tests/test_multicloud_pressure_gate.py',
        'tests/test_queue_backpressure_replay.py',
        'tests/test_investigate_semantics_backend.py',
    ],
    [
        'npx',
        'playwright',
        'test',
        'tests/playwright/investigate_architecture.spec.js',
        'tests/playwright/investigate_persona_semantics.spec.js',
        'tests/playwright/platform_visual_smoke.spec.js',
        '--config=playwright.config.js',
    ],
    [
        sys.executable,
        'scripts/kafka_assessment_soak.py',
        '--employees',
        '200',
        '--iterations',
        '2',
        '--workers',
        '3',
        '--out',
        'test-results/kafka_assessment_soak_report.json',
    ],
]


def main() -> int:
    parser = argparse.ArgumentParser(description='Run the Janusec release-candidate wringer.')
    parser.add_argument('--out', default='test-results/release_candidate_wringer_report.json')
    args = parser.parse_args()

    results = []
    exit_code = 0
    for step in DEFAULT_STEPS:
        started = time.time()
        run_kwargs = {'capture_output': True, 'text': True}
        if os.name == 'nt' and step and step[0].lower() == 'npx':
            proc = subprocess.run(' '.join(step), shell=True, **run_kwargs)
        else:
            proc = subprocess.run(step, **run_kwargs)
        duration = round(time.time() - started, 2)
        result = {
            'command': step,
            'returncode': proc.returncode,
            'duration_seconds': duration,
            'stdout_tail': (proc.stdout or '')[-4000:],
            'stderr_tail': (proc.stderr or '')[-4000:],
        }
        results.append(result)
        if proc.returncode != 0:
            exit_code = proc.returncode
            break

    report = {
        'generated_at': int(time.time()),
        'steps': results,
        'status': 'pass' if exit_code == 0 else 'fail',
        'next_actions': [
            'Run 12-24h soak with durable queue metrics before any customer-facing beta claim.',
            'Run disposable live validations only with approved credentials for Okta/AWS/Azure and AD/VMware-or-Nutanix/Exchange-M365.',
            'Freeze scope after wringer pass and treat new features as post-beta backlog.',
        ],
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
