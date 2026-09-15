#!/usr/bin/env python3
"""Automated Audit Runner

Runs a suite of static & lightweight dynamic checks and produces a JSON summary
for governance + regression tracking.

Phases:
 1. Dependency import resolution scan
 2. (Optional) Ruff lint (if installed)
 3. (Optional) Bandit security scan (if installed)
 4. (Optional) Mypy type check (if installed)
 5. Replay determinism check (if sample file provided)
 6. Metrics endpoint scrape (if URL provided)
 7. (Optional) Test coverage collection (pytest --cov) if pytest & coverage installed
 8. Dependency usage diff (unused requirements)
 9. Suppression precision regression guard (if provided baseline & current)
 10. Aggregate summary -> audit_results.json

Usage:
    python scripts/audit_runner.py --output audit_results.json \
            --metrics-url http://localhost:8000/metrics \
            --replay-input sample_events.jsonl

All optional tools are best-effort; absence does not cause failure unless
--strict flag is used.
"""
from __future__ import annotations
import argparse, subprocess, sys, json, importlib.util, time, hashlib, os, difflib, http.client, urllib.parse, ast, re
from pathlib import Path
from typing import Dict, Any, List

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / 'src'


def run_cmd(cmd: List[str], timeout: int = 60) -> tuple[int, str]:
    """Run a subprocess command safely.

    Args:
        cmd: Command list to execute.
        timeout: Seconds before force termination (default 60).
    Returns:
        (return_code, combined_output)
        127 if binary not found.
        124 if timeout reached.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
        return proc.returncode, (proc.stdout + '\n' + proc.stderr).strip()
    except FileNotFoundError:
        return 127, 'NOT_FOUND'
    except subprocess.TimeoutExpired as e:
        return 124, f'TIMEOUT after {timeout}s: ' + (e.stdout or '') + (e.stderr or '')


def tool_available(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def scan_unresolved_imports(base: Path) -> List[str]:
    unresolved: List[str] = []
    for py in base.rglob('*.py'):
        if '.venv' in py.parts:
            continue
        try:
            text = py.read_text(encoding='utf-8')
        except Exception:
            continue
        for line in text.splitlines():
            line_strip = line.strip()
            if line_strip.startswith('import ') or line_strip.startswith('from '):
                # heuristic: skip relative imports
                if 'prometheus_client' in line_strip:
                    if not tool_available('prometheus_client'):
                        unresolved.append(f"{py}: prometheus_client (missing runtime module)")
    return unresolved

def collect_imported_top_level_modules(base: Path) -> List[str]:
    modules: set[str] = set()
    for py in base.rglob('*.py'):
        if '.venv' in py.parts:
            continue
        try:
            tree = ast.parse(py.read_text(encoding='utf-8'))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    root = n.name.split('.')[0]
                    if root and root not in ('__future__','typing'):
                        modules.add(root)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root = node.module.split('.')[0]
                    if root and root not in ('__future__','typing'):
                        modules.add(root)
    return sorted(modules)

def parse_requirements(req_file: Path) -> List[str]:
    if not req_file.exists():
        return []
    reqs: List[str] = []
    for line in req_file.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Simple parse: grab up to version spec
        name = re.split(r'[<>= ]', line)[0]
        if name:
            reqs.append(name.lower())
    return reqs

def map_requirement_to_import(req: str) -> str:
    # Heuristic mapping for common mismatches
    mapping = {
        'prometheus-client': 'prometheus_client',
        'pyyaml': 'yaml',
        'scikit-learn': 'sklearn',
    }
    return mapping.get(req, req.replace('-', '_'))

def compute_rubric(metrics_path: str) -> Dict[str, Any]:
    """Compute readiness rubric from supplied metrics JSON.

    Expected metrics JSON schema (fields optional, defaults applied if missing):
      {
        "benign_suppression_precision": float,
        "gray_tier_recall": float,
        "high_tier_recall": float,
        "correlation_lift": float,
        "parallel_speedup": float,
        "false_positive_rate_per_1k": int,
        "batch_latency_p95_ms": float
      }

    Scoring Weights (sum=1.0):
      detection = 0.25 (gray + high recall averaged, weighted heavier on high)
      suppression = 0.15 (benign precision)
      correlation = 0.15 (lift)
      performance = 0.10 (latency + speedup)
      efficiency = 0.10 (fp rate)
      resilience = 0.15 (implicit: speedup + absence of regression placeholder)
      governance = 0.10 (placeholder -> if precision present & lift >1)
    """
    try:
        data = json.loads(Path(metrics_path).read_text(encoding='utf-8'))
    except Exception as e:
        return {"error": f"Failed to load metrics: {e}"}

    # Extract with defaults
    benign_prec = float(data.get('benign_suppression_precision', 0.0))
    gray_recall = float(data.get('gray_tier_recall', 0.0))
    high_recall = float(data.get('high_tier_recall', 0.0))
    lift = float(data.get('correlation_lift', 0.0))
    speedup = float(data.get('parallel_speedup', 0.0))
    latency_p95 = float(data.get('batch_latency_p95_ms', 9999))
    fp_per_1k = float(data.get('false_positive_rate_per_1k', 9999))

    # Normalize metrics to 0..1 scores
    def clamp(v: float) -> float: return max(0.0, min(1.0, v))

    high_recall_score = clamp((high_recall - 0.9) / 0.08)  # 0.90->0, 0.98->1
    gray_recall_score = clamp((gray_recall - 0.75) / 0.15)  # 0.75->0, 0.90->1
    benign_prec_score = clamp((benign_prec - 0.95) / 0.03)  # 0.95->0, 0.98->1
    lift_score = clamp((lift - 1.0) / 0.4)  # 1.0->0, 1.4->1
    speedup_score = clamp((speedup - 1.1) / 0.5)  # 1.1->0, 1.6->1
    latency_score = clamp((800 - latency_p95) / 400)  # 800ms->0, 400ms->1
    fp_score = clamp((50 - fp_per_1k) / 40)  # 50->0, 10->1

    detection_score = (0.6 * high_recall_score + 0.4 * gray_recall_score)
    suppression_score = benign_prec_score
    correlation_score = lift_score
    performance_score = 0.5 * latency_score + 0.5 * speedup_score
    efficiency_score = fp_score
    resilience_score = 0.5 * speedup_score + 0.5 * correlation_score
    governance_score = 1.0 if (benign_prec > 0 and lift > 1.0) else 0.5

    weights = {
        'detection': 0.25,
        'suppression': 0.15,
        'correlation': 0.15,
        'performance': 0.10,
        'efficiency': 0.10,
        'resilience': 0.15,
        'governance': 0.10,
    }
    components = {
        'detection': detection_score,
        'suppression': suppression_score,
        'correlation': correlation_score,
        'performance': performance_score,
        'efficiency': efficiency_score,
        'resilience': resilience_score,
        'governance': governance_score,
    }
    overall = sum(components[k] * weights[k] for k in weights)
    return {
        'component_scores': components,
        'weights': weights,
        'overall_score': round(overall, 4)
    }


def replay_determinism(sample: Path, outdir: Path) -> Dict[str, Any]:
    if not sample.exists():
        return {"skipped": True, "reason": "sample file not found"}
    outdir.mkdir(parents=True, exist_ok=True)
    r1 = outdir / 'replay_run1.jsonl'
    r2 = outdir / 'replay_run2.jsonl'
    cmd = [sys.executable, str(ROOT / 'scripts' / 'replay_harness.py'), '--input', str(sample), '--output', str(r1)]
    c1, o1 = run_cmd(cmd)
    c2, o2 = run_cmd(cmd[:-2] + [str(r2)])
    diff_info = {'return_code_1': c1, 'return_code_2': c2}
    if c1 == 0 and c2 == 0:
        t1 = r1.read_text(encoding='utf-8').splitlines()
        t2 = r2.read_text(encoding='utf-8').splitlines()
        if t1 == t2:
            diff_info['deterministic'] = True
        else:
            diff = list(difflib.unified_diff(t1, t2, lineterm=''))[:200]
            diff_info['deterministic'] = False
            diff_info['diff_excerpt'] = diff
    else:
        diff_info['deterministic'] = False
        diff_info['error_output'] = {'run1': o1, 'run2': o2}
    return diff_info


def metrics_scrape(url: str) -> Dict[str, Any]:
    try:
        parsed = urllib.parse.urlparse(url)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=3)
        path = parsed.path or '/'
        conn.request('GET', path)
        resp = conn.getresponse()
        body = resp.read().decode('utf-8', errors='replace')
        # minimal parse: count metric families of interest
        families = {}
        for line in body.splitlines():
            if line.startswith('#'):
                continue
            if line.startswith('hunt_'):
                name = line.split()[0]
                families[name] = families.get(name, 0) + 1
        return {"reachable": True, "families": families, "count": len(families)}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', default='audit_results.json')
    ap.add_argument('--metrics-url', help='Prometheus metrics endpoint URL')
    ap.add_argument('--replay-input', help='Sample events file for determinism test')
    ap.add_argument('--strict', action='store_true', help='Fail on any missing optional tool')
    ap.add_argument('--coverage', action='store_true', help='Collect pytest coverage if pytest present')
    ap.add_argument('--precision-baseline', type=float, help='Baseline suppression precision (0-1)')
    ap.add_argument('--precision-current', type=float, help='Current suppression precision (0-1)')
    ap.add_argument('--precision-regression-threshold', type=float, default=0.01, help='Max allowed regression (absolute) before fail')
    ap.add_argument('--metrics-json', help='Path to validation metrics JSON for rubric scoring')
    ap.add_argument('--rubric-output', help='Optional path to write rubric score JSON')
    ap.add_argument('--previous-metrics', help='Path to prior run metrics JSON for delta computation')
    ap.add_argument('--delta-output', help='Optional JSON file to write metric deltas')
    ap.add_argument('--delta-markdown', help='Optional Markdown snippet output (for AUTO-DELTA insertion)')
    ap.add_argument('--metrics-history-dir', help='Directory to store rubric history JSON snapshots for variance stats')
    args = ap.parse_args()

    summary: Dict[str, Any] = {"timestamp": time.time(), "phases": {}}

    # Phase 1: Unresolved imports
    unresolved = scan_unresolved_imports(SRC)
    summary['phases']['imports'] = {"unresolved": unresolved, "status": 'pass' if not unresolved else 'warn'}

    # Phase 2: Dependency usage diff
    reqs = parse_requirements(ROOT / 'requirements.txt')
    imported = collect_imported_top_level_modules(SRC)
    imported_set = set(imported)
    unused = []
    for r in reqs:
        imp_name = map_requirement_to_import(r)
        if imp_name not in imported_set and not imp_name.startswith(('torch','transformers')):  # allow optional heavy deps
            unused.append(r)
    summary['phases']['dependency_usage'] = {"unused_requirements": unused, "status": 'pass' if not unused else 'warn'}

    # Optional tools
    optional_tools = {
        'ruff': ['ruff', 'check', '.'],
        'bandit': ['bandit', '-q', '-r', 'src'],
        'mypy': ['mypy', 'src/core/correlation/hunt_correlation.py'],
    }
    for tool, cmd in optional_tools.items():
        rc, out = run_cmd(cmd)
        phase_record = {"rc": rc, "output_excerpt": out.splitlines()[-25:]}
        status = 'pass'
        if rc == 127:
            status = 'skipped'
            if args.strict:
                status = 'fail'
        elif rc != 0:
            status = 'warn'
        # Special parsing for bandit to escalate high severity
        if tool == 'bandit' and rc != 127:
            high_findings = []
            for line in out.splitlines():
                if 'Severity: HIGH' in line:
                    high_findings.append(line.strip())
            if high_findings:
                status = 'fail'
                phase_record['high_findings'] = high_findings[:20]
        phase_record['status'] = status
        summary['phases'][tool] = phase_record

    # Replay determinism
    if args.replay_input:
        rep = replay_determinism(Path(args.replay_input), ROOT / 'audit_artifacts')
        summary['phases']['replay'] = rep
    else:
        summary['phases']['replay'] = {"skipped": True, "reason": 'no input provided'}

    # Metrics
    if args.metrics_url:
        summary['phases']['metrics'] = metrics_scrape(args.metrics_url)
    else:
        summary['phases']['metrics'] = {"skipped": True}

    # Coverage collection (optional)
    if args.coverage:
        rc_cov, out_cov = run_cmd([sys.executable, '-m', 'pytest', '--maxfail=1', '--disable-warnings', '-q', '--cov=src', '--cov-report=term-missing'])
        cov_phase = {"rc": rc_cov, "status": 'pass' if rc_cov == 0 else 'fail'}
        tail = out_cov.splitlines()[-50:]
        cov_phase['output_excerpt'] = tail
        # try to extract total coverage
        for line in tail:
            if 'TOTAL' in line and '%' in line:
                cov_phase['total_line'] = line.strip()
                break
        summary['phases']['coverage'] = cov_phase
    else:
        summary['phases']['coverage'] = {"skipped": True}

    # Suppression precision regression guard
    if args.precision_baseline is not None and args.precision_current is not None:
        baseline = args.precision_baseline
        current = args.precision_current
        delta = baseline - current
        status = 'pass'
        if delta > args.precision_regression_threshold:
            status = 'fail'
        summary['phases']['suppression_precision'] = {
            'baseline': baseline,
            'current': current,
            'delta': delta,
            'threshold': args.precision_regression_threshold,
            'status': status
        }
    else:
        summary['phases']['suppression_precision'] = {"skipped": True}

    # Rubric scoring (optional)
    if args.metrics_json:
        rubric = compute_rubric(args.metrics_json)
        summary['phases']['rubric'] = rubric
        if args.rubric_output:
            try:
                Path(args.rubric_output).write_text(json.dumps(rubric, indent=2), encoding='utf-8')
            except Exception as e:
                print(f"Failed to write rubric output: {e}")
        # If rubric overall below threshold mark warn
        target_min = 0.75
        if rubric.get('overall_score', 0) < target_min:
            summary['phases']['rubric']['status'] = 'warn'
        else:
            summary['phases']['rubric']['status'] = 'pass'

        # Historical variance statistics
        if args.metrics_history_dir:
            hist_dir = Path(args.metrics_history_dir)
            hist_dir.mkdir(parents=True, exist_ok=True)
            # Write current snapshot with timestamp-based filename
            ts_name = f"rubric_{int(summary['timestamp'])}.json"
            try:
                (hist_dir / ts_name).write_text(json.dumps(rubric, indent=2), encoding='utf-8')
            except Exception as e:
                print(f"Failed to persist rubric snapshot: {e}")
            # Load all snapshots and compute mean/std dev
            comps_accum: dict[str, list[float]] = {}
            overall_list: list[float] = []
            for snap in hist_dir.glob('rubric_*.json'):
                try:
                    data = json.loads(snap.read_text(encoding='utf-8'))
                except Exception:
                    continue
                comp_scores = data.get('component_scores', {})
                for k, v in comp_scores.items():
                    if isinstance(v, (int, float)):
                        comps_accum.setdefault(k, []).append(float(v))
                ov = data.get('overall_score')
                if isinstance(ov, (int, float)):
                    overall_list.append(float(ov))
            import math
            def stats(values: list[float]) -> dict[str, float]:
                if not values:
                    return {'count': 0}
                n = len(values)
                mean = sum(values) / n
                var = sum((x - mean) ** 2 for x in values) / n if n > 1 else 0.0
                return {'count': n, 'mean': round(mean, 4), 'stddev': round(math.sqrt(var), 4)}
            history_stats = {k: stats(vs) for k, vs in comps_accum.items()}
            history_stats['overall'] = stats(overall_list)
            summary['phases']['rubric']['history_stats'] = history_stats
    else:
        summary['phases']['rubric'] = {"skipped": True}

    # Metrics delta computation (optional)
    if args.metrics_json and args.previous_metrics:
        try:
            current_metrics = json.loads(Path(args.metrics_json).read_text(encoding='utf-8'))
            previous_metrics = json.loads(Path(args.previous_metrics).read_text(encoding='utf-8'))
            tracked_keys = [
                'benign_suppression_precision',
                'gray_tier_recall',
                'high_tier_recall',
                'correlation_lift',
                'parallel_speedup',
                'batch_latency_p95_ms',
                'false_positive_rate_per_1k'
            ]
            deltas = {}
            markdown_rows = []
            for k in tracked_keys:
                prev = previous_metrics.get(k)
                curr = current_metrics.get(k)
                if prev is None or curr is None:
                    continue
                try:
                    delta = curr - prev
                except Exception:
                    continue
                deltas[k] = {
                    'previous': prev,
                    'current': curr,
                    'delta': delta
                }
                # Formatting for markdown table
                if isinstance(prev, (int, float)) and isinstance(curr, (int, float)):
                    if abs(prev) > 0 and k != 'false_positive_rate_per_1k':
                        pct = (delta / prev) * 100.0
                        pct_str = f"{pct:+.2f}%"
                    else:
                        pct_str = ''
                    markdown_rows.append(f"| {k} | {prev} | {curr} | {delta:+.4f} | {pct_str} |")
            summary['phases']['metric_deltas'] = {'deltas': deltas, 'status': 'pass'}
            if args.delta_output:
                try:
                    Path(args.delta_output).write_text(json.dumps(deltas, indent=2), encoding='utf-8')
                except Exception as e:
                    print(f"Failed to write delta output: {e}")
            if args.delta_markdown and markdown_rows:
                header = "| metric | previous | current | delta | % change |\n|--------|----------|---------|-------|----------|\n"
                try:
                    Path(args.delta_markdown).write_text(header + "\n".join(markdown_rows) + "\n", encoding='utf-8')
                except Exception as e:
                    print(f"Failed to write delta markdown: {e}")
        except Exception as e:
            summary['phases']['metric_deltas'] = {'error': str(e), 'status': 'warn'}
    else:
        summary['phases']['metric_deltas'] = {"skipped": True}

    # Hash key scripts for provenance
    key_files = [ROOT / 'src' / 'core' / 'correlation' / 'hunt_correlation.py', ROOT / 'src' / 'core' / 'hunt' / 'lane_registry.py']
    hashes = {str(p): hash_file(p) for p in key_files if p.exists()}
    summary['hashes'] = hashes

    # Overall status heuristic
    overall = 'pass'
    if unresolved:
        overall = 'warn'
    if any(phase.get('status') == 'fail' for phase in summary['phases'].values() if isinstance(phase, dict)):
        overall = 'fail'
    summary['overall'] = overall

    Path(args.output).write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(f"Wrote audit summary to {args.output} (overall={overall})")

if __name__ == '__main__':
    main()
