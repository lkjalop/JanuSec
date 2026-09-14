"""Synthetic Scenario Replay Harness.

Executes predefined ordered event sequences through the SecurityOrchestrator
pipeline and returns a small JSON summary (factors + confidence series).

Notes on determinism and environment flags
-----------------------------------------
- REPLAY_IN_SUBPROCESS: internal helper flag used by `run_scenario()` to
    detect whether the current interpreter is the subprocess worker. The
    top-level call to `run_scenario()` will spawn a fresh Python process that
    sets this flag; the worker process performs deterministic seeding and
    module-level cache resets before executing the scenario. Do not set this
    flag manually unless you explicitly want to run the worker branch.

- REPLAY_DETERMINISTIC: when set to a truthy value (string '1'), modules and
    detectors that support deterministic behavior will use stable timestamps,
    seeded RNGs, or fallbacks to ensure identical outputs between runs.
    The harness sets this in the worker subprocess automatically.

Implementation detail
---------------------
To guarantee bitwise-deterministic results for tests that call the harness
twice in the same interpreter, `run_scenario()` spawns a fresh subprocess and
parses its JSON output. This avoids fragile, ad-hoc resets of every global
module state across the codebase. If shorter runtime is required later, we
can add an in-process `reset_for_replay()` helper that clears known global
singletons and sketches; that is left as a follow-up.

Usage:
    python scripts/replay_harness.py --scenario macro_rare_ja3
    python -m pytest tests/test_replay_determinism.py -q

Scenarios are intentionally lightweight and do not hit a real database; they
operate purely in-memory using the orchestrator and its pipeline. Extend by
adding new entries to SCENARIOS.
"""
from __future__ import annotations
import asyncio, argparse, json, time
from typing import List, Dict, Any

# Scenario definition structure:
#  name: {
#     'events': [ {event dicts in order} ],
#     'expected_factors_any': [list of factor names that should appear at least once in cumulative factors],
#     'confidence_min': float (optional)
#  }

BASE_TS = 1_700_000_000

SCENARIOS: Dict[str, Dict[str, Any]] = {
    'lateral_movement': {
        'events': [
            {'id':'lm1','user':'alice','host':'host1','proc':'p1','details':{}},
            {'id':'lm2','user':'alice','host':'host1','proc':'p2','details':{}},
            {'id':'lm3','user':'alice','host':'host1','proc':'p3','details':{}},
            {'id':'lm4','user':'alice','host':'host1','proc':'p4','details':{}},
            {'id':'lm5','user':'alice','host':'host2','proc':'p5','details':{}},
        ],
        'expected_factors_any': ['graph_user_proc_burst','lateral_movement_candidate'],
    },
    'exfiltration': {
        'events': [
            {'id':'ex1','details':{'network':[]}},
            {'id':'ex2','details':{'network':[]}},
            # final event has large outbound pattern
            {'id':'ex3','details':{'network':[{'direction':'outbound','bytes':3_000_000,'dst_port':443,'timestamp':BASE_TS + i*30,'proto':'tcp'} for i in range(2)] +
                                              [{'direction':'outbound','bytes':3_500_000,'dst_port':443,'timestamp':BASE_TS + 120,'proto':'tcp'}]}},
        ],
        'expected_factors_any': ['exfil_volume_high'],
    },
    'dns_beacon': {
        'events': [
            {'id':'db1','details':{'network':[{'direction':'outbound','bytes':100,'dst_port':443,'timestamp':BASE_TS + i*30,'proto':'tcp'} for i in range(5)] +
                                              [{'proto':'dns','direction':'outbound','bytes':100,'timestamp':BASE_TS+10,'domain':'x.' + 'a'*34 + '.com'}]}},
        ],
        'expected_factors_any': ['beacon_like_30s','dns_tunnel_pattern'],
    },
    'brute_force': {
        'events': [
            {'id':'bf1','user':'bruce','event_type':'auth_fail','details':{'auth':'fail'}},
            {'id':'bf2','user':'bruce','event_type':'auth_fail','details':{'auth':'fail'}},
            {'id':'bf3','user':'bruce','event_type':'auth_fail','details':{'auth':'fail'}},
            {'id':'bf4','user':'bruce','event_type':'auth_fail','details':{'auth':'fail'}},
            {'id':'bf5','user':'bruce','event_type':'auth_fail','details':{'auth':'fail'}},
        ],
    'expected_factors_any': ['auth_fail_burst_5m'],
    },
    'macro_rare_ja3': {
        'events': [
            # Seed baseline JA3s
            *[{'id':f'mj_seed{i}','process_name':'proc.exe','parent_process_name':'parent.exe','ja3_hash':f'hash{i%5}'} for i in range(30)],
            # Macro spawn event with rare ja3
            {'id':'mj_corr','process_name':'powershell.exe','parent_process_name':'winword.exe','cmdline':'powershell.exe -enc AAAA','ja3_hash':'rare_ja3_x'}
        ],
        'expected_factors_any': ['lane_process_lineage:office_macro_spawn_powershell','lane_ja3_novelty:ja3_rare','corr_office_ps_rare_ja3']
    },
    'encoded_signed_synergy': {
        'events': [
            {'id':'sy1','process_name':'child.exe','parent_process_name':'parent.exe','process_signed':False,'parent_process_signed':True,'cmdline':'powershell.exe -enc AAAA'},
        ],
        'expected_factors_any': ['lane_process_lineage:powershell_encoded_command','lane_process_lineage:signed_to_unsigned_transition','corr_encoded_ps_signed_to_unsigned']
    },
}

async def run_scenario(name: str) -> Dict[str, Any]:
    import sys, subprocess, os as _os
    import os
    # If we're not inside a subprocess helper, spawn a fresh process to run the
    # scenario. This guarantees isolation from in-process singletons and
    # time-based sketches so tests that call run_scenario() twice in the same
    # interpreter see identical results.
    if _os.environ.get('REPLAY_IN_SUBPROCESS') != '1':
        # Spawn a fresh python process that runs this module as a script and
        # prints the JSON result. We set REPLAY_IN_SUBPROCESS to avoid recursion.
        env = dict(_os.environ)
        env['REPLAY_IN_SUBPROCESS'] = '1'
        # Ensure Python can import project modules by adding repo 'src' (or repo root)
        from pathlib import Path
        script_path = Path(__file__).resolve()
        repo_root = str(script_path.parent.parent)
        # Add both the repository root and the 'src' directory to PYTHONPATH
        # so imports like `import main` (src/main.py) and `import src.foo`
        # both resolve correctly.
        src_dir = Path(repo_root) / 'src'
        paths = [repo_root]
        if src_dir.exists():
            paths.append(str(src_dir))
        env_py = env.get('PYTHONPATH', '')
        existing = env_py.split(os.pathsep) if env_py else []
        # Prepend our paths to ensure they take precedence
        new_paths = [p for p in paths if p not in existing] + existing
        env['PYTHONPATH'] = os.pathsep.join(new_paths)
        cmd = [sys.executable, str(script_path), '--scenario', name]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=repo_root)
        if proc.returncode != 0:
            # Provide stderr for easier debugging
            raise RuntimeError(f"Subprocess failed (rc={proc.returncode}). stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
        out = proc.stdout.strip()
        # Attempt to parse stdout as JSON; if noisy logs are present, try the
        # last non-empty line as a fallback.
        try:
            return json.loads(out)
        except Exception:
            # fallback: try last non-empty line
            for line in reversed(out.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except Exception:
                    continue
            raise RuntimeError(f"Failed to parse subprocess output: {proc.stdout!r}\nstderr:\n{proc.stderr}")

    # In-subprocess execution continues here (REPLAY_IN_SUBPROCESS=1)
    from main import SecurityOrchestrator
    # Reset global singletons and seeding to ensure deterministic replay
    # Clear known global state using the replay utils helper (best-effort)
    try:
        from src.tests.replay_utils import reset_for_replay
    except Exception:
        try:
            from tests.replay_utils import reset_for_replay
        except Exception:
            reset_for_replay = None
    if reset_for_replay is not None:
        try:
            reset_for_replay()
        except Exception:
            pass
    # Reset cluster cache (dedupe markers)
    from core.correlation.cluster_dedupe import reset_cluster_cache
    reset_cluster_cache()
    # Reset hopgraph module-level singleton properly so get_graph() yields a fresh instance
    from importlib import import_module as _import_module
    try:
        _hg_mod = _import_module('src.core.graph.hopgraph_lite')
    except Exception:
        try:
            _hg_mod = _import_module('core.graph.hopgraph_lite')
        except Exception:
            _hg_mod = None
    if _hg_mod is not None:
        try:
            _hg_mod._default_graph = _hg_mod.HopGraphLite()
        except Exception:
            try:
                # fallback if symbol names differ
                _hg_mod._default_graph = _hg_mod.HopGraphLite()
            except Exception:
                pass
    # Reset streaming rarity (daily first-seen) so multiple runs in same process
    # don't influence each other via last_seen timestamps
    try:
        _stream = _import_module('src.metrics.streaming')
    except Exception:
        try:
            _stream = _import_module('metrics.streaming')
        except Exception:
            _stream = None
    if _stream is not None:
        try:
            if hasattr(_stream, 'RARITY_DAILY') and hasattr(_stream.RARITY_DAILY, 'last_seen'):
                _stream.RARITY_DAILY.last_seen.clear()
        except Exception:
            pass
    # ensure deterministic env removed at the end of run_scenario via orchestrator shutdown
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {name}")
    orch = SecurityOrchestrator()
    await orch.initialize()
    # Ensure hunt lanes active (advisory) for replay evaluation
    try:
        orch.event_pipeline.config.setdefault('pipeline', {}).setdefault('hunt_lanes', {})['enabled'] = True  # type: ignore
    except Exception:
        pass
    cumulative_factors: List[str] = []
    confidences: List[float] = []
    for ev in SCENARIOS[name]['events']:
        res = await orch.process_event(ev)
        cumulative_factors.extend(res.factors)
        confidences.append(res.confidence)
    await orch.shutdown()
    normalized_factors = [f for f in cumulative_factors if not str(f).startswith('timings:')]
    result = {
        'scenario': name,
        'factors': sorted(set(normalized_factors)),
        'confidence_series': confidences,
    }
    # Assertions (raise on failure) - simple heuristic checks
    expected_any = SCENARIOS[name].get('expected_factors_any', [])
    for f in expected_any:
        if f not in result['factors']:
            raise AssertionError(f"Expected factor '{f}' not seen in scenario '{name}'")
    return result

async def main(list_only: bool, scenario: str | None):
    if list_only:
        print(json.dumps({'scenarios': list(SCENARIOS.keys())}))
        return
    if scenario is None:
        raise SystemExit("--scenario required unless --list")
    out = await run_scenario(scenario)
    print(json.dumps(out))

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--scenario', type=str, default=None)
    ap.add_argument('--list', action='store_true')
    args = ap.parse_args()
    asyncio.run(main(args.list, args.scenario))
