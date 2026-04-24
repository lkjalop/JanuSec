import os
import time
import json
import threading
import sqlite3
from typing import Dict, Any, List, Optional

from src.integrations.llm_client import LLMClient
from src.analysis.deep_analyze_utils import (
    build_canonical_signals,
    map_to_mitre,
    map_to_stride,
    map_to_controls,
    map_to_dread,
    map_to_pasa,
    map_to_maestro,
    map_to_diamond,
)

_SESSION_ROOT = os.getenv('SESSION_PERSIST_DIR') or 'data/sessions'
DEFAULT_PIPELINE_DIR = os.getenv('DEEP_PIPELINE_DIR') or os.path.join(_SESSION_ROOT, 'deep_pipeline')
SESSION_DB = os.getenv('DEEP_PIPELINE_DB') or os.path.join(DEFAULT_PIPELINE_DIR, 'sessions.db')

ALLOWED_RISK_LABELS = {'High', 'Medium', 'Low', 'Unknown'}


def _sanitize_llm_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Validate and normalize persisted LLM rows."""
    try:
        idx = int(row.get('row_index', -1))
        if idx < 0:
            return None
        row['row_index'] = idx
    except Exception:
        return None

    risk_level = row.get('risk_level') or {}
    label = str(risk_level.get('label') or row.get('risk_label') or 'Unknown')
    if label not in ALLOWED_RISK_LABELS:
        label = 'Unknown'
    risk_level['label'] = label
    row['risk_level'] = risk_level
    row['risk_label'] = label

    source = str(row.get('source') or 'unknown').lower()
    if source not in {'llm', 'heuristic', 'unknown'}:
        source = 'unknown'
    row['source'] = source

    if not isinstance(row.get('factors'), list):
        row['factors'] = []
    if not isinstance(row.get('comments'), list):
        row['comments'] = []
    if not isinstance(row.get('recommendations'), list):
        rec = row.get('recommendation')
        row['recommendations'] = [rec] if rec else []

    try:
        row['generated_at'] = int(row.get('generated_at') or time.time())
    except Exception:
        row['generated_at'] = int(time.time())

    row.setdefault('fingerprint', '')
    row.setdefault('process_name', '')
    row.setdefault('verdict', '')
    row.setdefault('classification', 'Unknown')

    return row


def _init_session_db():
    os.makedirs(os.path.dirname(SESSION_DB), exist_ok=True)
    conn = sqlite3.connect(SESSION_DB)
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, json TEXT, status TEXT, updated_at REAL)''')
    conn.commit(); conn.close()

_init_session_db()


def _ensure_session_dir(session_id: str) -> str:
    path = os.path.join(DEFAULT_PIPELINE_DIR, session_id)
    os.makedirs(path, exist_ok=True)
    return path


def _save_session_db(session_id: str, payload: Dict[str, Any], status: str):
    try:
        conn = sqlite3.connect(SESSION_DB)
        cur = conn.cursor()
        cur.execute('INSERT OR REPLACE INTO sessions(id,json,status,updated_at) VALUES(?,?,?,?)', (session_id, json.dumps(payload), status, time.time()))
        conn.commit(); conn.close()
    except Exception:
        pass


def _load_session_db(session_id: str) -> Optional[Dict[str, Any]]:
    try:
        conn = sqlite3.connect(SESSION_DB)
        cur = conn.cursor()
        cur.execute('SELECT json,status,updated_at FROM sessions WHERE id=?', (session_id,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return {'payload': json.loads(row[0]), 'status': row[1], 'updated_at': row[2]}
    except Exception:
        return None


class PipelineStep:
    def __init__(self, idx: int, name: str, timeout: float = 30.0):
        self.idx = idx
        self.name = name
        self.timeout = timeout


# Define a 21-step Deep Analyze pipeline spec (names are illustrative)
PIPELINE_SPEC: List[PipelineStep] = [
    PipelineStep(1, 'ingest_logs'),
    PipelineStep(2, 'parse_events'),
    PipelineStep(3, 'normalize_fields'),
    PipelineStep(4, 'enrich_ip_whois'),
    PipelineStep(5, 'enrich_asn'),
    PipelineStep(6, 'enrich_reputation'),
    PipelineStep(7, 'cluster_sessions'),
    PipelineStep(8, 'identify_hosts'),
    PipelineStep(9, 'identify_users'),
    PipelineStep(10, 'process_binaries'),
    PipelineStep(11, 'extract_indicators'),
    PipelineStep(12, 'correlate_indicators'),
    PipelineStep(13, 'score_paths'),
    PipelineStep(14, 'build_hop_graph'),
    PipelineStep(15, 'entropy_analysis'),
    PipelineStep(16, 'temporal_correlation'),
    PipelineStep(17, 'anomaly_detection'),
    PipelineStep(18, 'generate_findings'),
    PipelineStep(19, 'prioritize_findings'),
    PipelineStep(20, 'prepare_summary_inputs'),
    PipelineStep(21, 'llm_summarize', timeout=120.0)
]


class DeepAnalyzeWorker:
    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._llm = LLMClient()

    def start_session(self, session_id: str, payload: Dict[str, Any]):
        with self._lock:
            if session_id in self._sessions:
                raise RuntimeError('session_exists')
            now = time.time()
            self._sessions[session_id] = {
                'status': 'queued',
                'current': 0,
                'started': now,
                'payload': payload,
                'stage_history': [],
                'stage_outputs': [],
                'telemetry': {'queued_at': now},
            }
            # persist initial session info
            _save_session_db(session_id, payload, 'queued')
        t = threading.Thread(target=self._run, args=(session_id,), daemon=True)
        t.start()
        return self._sessions[session_id]

    def _run(self, session_id: str):
        sess = self._sessions.get(session_id)
        if not sess:
            return
        sess['status'] = 'running'
        session_dir = _ensure_session_dir(session_id)
        sess.setdefault('telemetry', {})['started_at'] = time.time()
        stage_history: List[Dict[str, Any]] = sess.setdefault('stage_history', [])
        stage_outputs: List[Dict[str, Any]] = sess.setdefault('stage_outputs', [])

        for step in PIPELINE_SPEC:
            sess['current'] = step.idx
            sess['step_name'] = step.name
            step_file = os.path.join(session_dir, f'step_{step.idx}_{step.name}.json')
            # simulate step work; in production these would be real calls
            try:
                stage_start = time.time()
                stage_entry = {'idx': step.idx, 'name': step.name, 'status': 'running', 'started_at': stage_start}
                stage_history.append(stage_entry)
                # load previous results if present
                if os.path.exists(step_file):
                    with open(step_file, 'r', encoding='utf-8') as fh:
                        result = json.load(fh)
                else:
                    # run real step implementations for selected steps
                    if step.idx == 1:
                        result = self._step_ingest(payload=sess.get('payload'), session_dir=session_dir)
                    elif step.idx == 2:
                        result = self._step_parse(session_dir=session_dir)
                    elif step.idx == 3:
                        result = self._step_normalize_fields(session_dir=session_dir)
                    elif step.idx == 4:
                        result = self._step_enrich_ip_whois(session_dir=session_dir)
                    elif step.idx == 5:
                        result = self._step_enrich_asn(session_dir=session_dir)
                    elif step.idx == 6:
                        result = self._step_enrich_reputation(session_dir=session_dir)
                    elif step.idx == 7:
                        result = self._step_cluster_sessions(session_dir=session_dir)
                    elif step.idx == 8:
                        result = self._step_identify_hosts(session_dir=session_dir)
                    elif step.idx == 9:
                        result = self._step_identify_users(session_dir=session_dir)
                    elif step.idx == 10:
                        result = self._step_process_binaries(session_dir=session_dir)
                    elif step.idx == 11:
                        result = self._step_extract_indicators(session_dir=session_dir)
                    elif step.idx == 12:
                        result = self._step_correlate_indicators(session_dir=session_dir)
                    elif step.idx == 13:
                        result = self._step_score_paths(session_dir=session_dir)
                    elif step.idx == 14:
                        result = self._step_build_hop_graph(session_dir=session_dir)
                    elif step.idx == 15:
                        result = self._step_entropy_analysis(session_dir=session_dir)
                    elif step.idx == 16:
                        result = self._step_temporal_correlation(session_dir=session_dir)
                    elif step.idx == 17:
                        result = self._step_anomaly_detection(session_dir=session_dir)
                    elif step.idx == 18:
                        result = self._step_generate_findings(session_dir=session_dir)
                    elif step.idx == 19:
                        result = self._step_prioritize_findings(session_dir=session_dir)
                    elif step.idx == 20:
                        result = self._step_prepare_summary_inputs(session_dir=session_dir)
                    else:
                        result = {'step': step.name, 'status': 'ok', 'data': {'notes': f'auto-generated for {step.name}'}}
                    with open(step_file + '.tmp', 'w', encoding='utf-8') as fh:
                        fh.write(json.dumps(result))
                    os.replace(step_file + '.tmp', step_file)
                stage_entry['status'] = 'completed'
                stage_entry['elapsed_ms'] = (time.time() - stage_start) * 1000.0
                stage_outputs.append({'stage': step.name, 'result': result})
                # small sleep to emulate work (non-blocking)
                time.sleep(min(0.01, step.timeout))
            except Exception as e:
                stage_entry['status'] = 'failed'
                stage_entry['error'] = str(e)
                sess['status'] = 'failed'
                sess['error'] = str(e)
                _save_session_db(session_id, sess.get('payload') or {}, 'failed')
                return

        # after all steps run, persist a placeholder summary and assessment (fast)
        # then mark the session completed so status polling sees the final state.
        try:
            payload = sess.get('payload') or {}
            assessment_id = payload.get('assessment_id') or payload.get('session_id') or None
            org = payload.get('org') or 'unknown'

            # write a lightweight placeholder summary for quick visibility
            summary = {'text': 'summary_pending', 'provenance': {'placeholder': True, 'timestamp': time.time()}}
            try:
                with open(os.path.join(session_dir, 'summary.json'), 'w', encoding='utf-8') as fh:
                    fh.write(json.dumps(summary))
            except Exception:
                pass

            # If an assessment_id is present, attempt to persist an assessment JSON (best-effort)
            if assessment_id:
                try:
                    repo_root = os.getcwd()
                    datepart = time.strftime('%Y-%m-%d', time.gmtime(time.time()))
                    env_base = os.getenv('SESSION_PERSIST_DIR')
                    bases = [env_base] if env_base else []
                    bases.append(os.path.join(repo_root, 'data', 'assessments'))

                    # build a minimal assessment payload with current pipeline outputs
                    canonical = build_canonical_signals(stage_outputs, payload)
                    mappings = {
                        'mitre': map_to_mitre(canonical),
                        'stride': map_to_stride(canonical),
                        'controls': map_to_controls(canonical),
                        'dread': map_to_dread(canonical),
                        'pasa': map_to_pasa(canonical),
                        'maestro': map_to_maestro(canonical),
                        'diamond': map_to_diamond(canonical),
                    }
                    telemetry = sess.get('telemetry', {})
                    telemetry['completed_at'] = time.time()
                    telemetry['duration_ms'] = int((telemetry.get('completed_at', 0) - telemetry.get('started_at', telemetry.get('queued_at', time.time()))) * 1000)
                    out = {
                        'assessment_id': assessment_id,
                        'session_id': session_id,
                        'org': org,
                        'summary': summary,
                        'llm_rows': [],
                        'canonical': canonical,
                        'mappings': mappings,
                        'pipeline_stages': stage_history,
                        'stage_status': stage_outputs,
                        'telemetry': telemetry,
                    }

                    wrote = False
                    last_exc = None
                    for base in bases:
                        try:
                            dest = os.path.join(base, org, datepart)
                            os.makedirs(dest, exist_ok=True)
                            path = os.path.join(dest, f"{assessment_id}.json")
                            # Merge into existing file to preserve correlation_clusters, evidence_rows etc.
                            merged = {}
                            if os.path.exists(path):
                                try:
                                    with open(path, 'r', encoding='utf-8') as _fh:
                                        merged = json.load(_fh)
                                except Exception:
                                    merged = {}
                            merged.update(out)
                            with open(path + '.tmp', 'w', encoding='utf-8') as fh:
                                fh.write(json.dumps(merged))
                            os.replace(path + '.tmp', path)
                            wrote = True
                            break
                        except Exception as e:
                            last_exc = e
                            continue
                    if not wrote and last_exc is not None:
                        # best-effort persistence failure; continue
                        pass
                except Exception:
                    pass

            # mark completed and persist session DB so status polls see completion
            sess['status'] = 'completed'
            sess['summary'] = summary
            _save_session_db(session_id, sess.get('payload') or {}, 'completed')
        except Exception as e:
            sess['status'] = 'failed'
            sess['error'] = str(e)
            _save_session_db(session_id, sess.get('payload') or {}, 'failed')

        # Spawn a background finalizer to compute the real summary and update persisted files
        def _finalizer():
            try:
                # In test-mode skip expensive external LLM calls to avoid network hangs
                if os.getenv('TEST_HELPERS_ENABLED','0').lower() in {'1','true','yes'} or os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'}:
                    real_summary = {'text': 'summary_skipped_in_test_mode', 'provenance': {'test_mode': True, 'timestamp': time.time()}}
                else:
                    real_summary = self._run_summarizer(session_id, session_dir)
                try:
                    with open(os.path.join(session_dir, 'summary.json'), 'w', encoding='utf-8') as fh:
                        fh.write(json.dumps(real_summary))
                except Exception:
                    pass

                try:
                    if assessment_id:
                        datepart = time.strftime('%Y-%m-%d', time.gmtime(time.time()))
                        bases = [os.getenv('SESSION_PERSIST_DIR')] if os.getenv('SESSION_PERSIST_DIR') else []
                        bases.append(os.path.join(os.getcwd(), 'data', 'assessments'))
                        for base in bases:
                            if not base:
                                continue
                            dest = os.path.join(base, org, datepart)
                            path = os.path.join(dest, f"{assessment_id}.json")
                            if os.path.exists(path):
                                try:
                                    with open(path, 'r', encoding='utf-8') as fh:
                                        j = json.load(fh)
                                    j['summary'] = real_summary
                                    with open(path + '.tmp', 'w', encoding='utf-8') as fh:
                                        fh.write(json.dumps(j))
                                    os.replace(path + '.tmp', path)
                                except Exception:
                                    continue
                except Exception:
                    pass
            except Exception:
                pass

        th = threading.Thread(target=_finalizer, daemon=True)
        th.start()

    def _run_summarizer(self, session_id: str, session_dir: str) -> Dict[str, Any]:
        # gather artifacts to build a safe prompt
        parts = []
        for step in PIPELINE_SPEC[:-1]:
            p = os.path.join(session_dir, f'step_{step.idx}_{step.name}.json')
            if os.path.exists(p):
                try:
                    with open(p, 'r', encoding='utf-8') as fh:
                        j = json.load(fh)
                        parts.append(f"{step.name}: {j.get('data',{}).get('notes','')}")
                except Exception:
                    continue
        prompt = "\n".join(parts[-10:])
        prompt = "Summarize the following findings:\n" + prompt
        # honor overrides provided to the session payload or pipeline
        _overrides = None
        try:
            p = sess.get('payload') or {}
            _overrides = p.get('overrides') if isinstance(p, dict) else None
        except Exception:
            _overrides = None
        try:
            if _overrides:
                resp = self._llm.generate(prompt, max_tokens=256, model='gpt-like', overrides=_overrides)
            else:
                resp = self._llm.generate(prompt, max_tokens=256, model='gpt-like')
            provenance = {'model': resp.get('model'), 'meta': resp.get('meta'), 'timestamp': time.time()}
            return {'text': resp.get('text'), 'provenance': provenance}
        except Exception as exc:
            return {
                'text': f"Auto-LLM summary unavailable: {exc}",
                'provenance': {'error': str(exc), 'timestamp': time.time()},
            }

    # Real step implementations (simple, pluggable)
    def _step_ingest(self, payload: Dict[str, Any], session_dir: str) -> Dict[str, Any]:
        # Accept a small inline payload or a URL/file reference
        data = payload.get('data') if payload else {'source':'inline','records': ['r1','r2']}
        out = {'step': 'ingest', 'status': 'ok', 'data': {'records': data}}
        return out

    def _step_parse(self, session_dir: str) -> Dict[str, Any]:
        # Very small parse: read ingest artifact if present
        p = os.path.join(session_dir, 'step_1_ingest.json')
        records = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    records = j.get('data', {}).get('records', [])
            except Exception:
                records = []
        parsed = [{'parsed': str(r)} for r in records]
        return {'step': 'parse', 'status': 'ok', 'data': {'parsed': parsed}}

    def _step_normalize_fields(self, session_dir: str) -> Dict[str, Any]:
        # use header inference to suggest canonical mapping for parsed records
        try:
            from src.core.mapping.header_inference import infer_headers
        except Exception:
            infer_headers = None
        p = os.path.join(session_dir, 'step_2_parse.json')
        parsed = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    parsed = j.get('data', {}).get('parsed', [])
            except Exception:
                parsed = []
        samples = []
        for r in parsed:
            if isinstance(r, dict):
                samples.append(r)
            else:
                # attempt to recover simple string -> dict
                samples.append({'value': r})
        mapping = infer_headers(samples) if infer_headers else {}
        return {'step': 'normalize_fields', 'status': 'ok', 'data': {'mapping': mapping, 'samples': samples[:10]}}

    def _step_enrich_ip_whois(self, session_dir: str) -> Dict[str, Any]:
        # enrich parsed records with geoip-based data
        try:
            from src.enrichment.geoip import enrich_event
        except Exception:
            enrich_event = None
        p = os.path.join(session_dir, 'step_2_parse.json')
        parsed = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    parsed = j.get('data', {}).get('parsed', [])
            except Exception:
                parsed = []
        enriched = []
        for r in parsed:
            ev = r.copy() if isinstance(r, dict) else {'parsed': r}
            try:
                if enrich_event:
                    enrich_event(ev)
            except Exception:
                pass
            enriched.append(ev)
        return {'step': 'enrich_ip_whois', 'status': 'ok', 'data': {'enriched': enriched}}

    def _step_enrich_asn(self, session_dir: str) -> Dict[str, Any]:
        try:
            from src.live.asn_lookup import lookup_asn
        except Exception:
            lookup_asn = None
        p = os.path.join(session_dir, 'step_4_enrich_ip_whois.json')
        enriched = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    enriched = j.get('data', {}).get('enriched', [])
            except Exception:
                enriched = []
        out = []
        for e in enriched:
            ev = e.copy() if isinstance(e, dict) else {'record': e}
            ip = None
            for key in ('dst_ip','src_ip','ip'):
                v = ev.get(key)
                if isinstance(v, str):
                    ip = v; break
            try:
                if lookup_asn and ip:
                    asn = lookup_asn(ip)
                    if asn:
                        ev.setdefault('asn', asn)
            except Exception:
                pass
            out.append(ev)
        return {'step': 'enrich_asn', 'status': 'ok', 'data': {'enriched': out}}

    def _step_enrich_reputation(self, session_dir: str) -> Dict[str, Any]:
        try:
            from src.core.reputation.wrappers import geoip_lookup, mx_is_free_provider
        except Exception:
            geoip_lookup = None; mx_is_free_provider = None
        p = os.path.join(session_dir, 'step_5_enrich_asn.json')
        records = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    records = j.get('data', {}).get('enriched', [])
            except Exception:
                records = []
        out = []
        for r in records:
            ev = r.copy() if isinstance(r, dict) else {'record': r}
            rep = {}
            try:
                ip = ev.get('ip') or ev.get('src_ip') or ev.get('dst_ip')
                if geoip_lookup and ip:
                    info = geoip_lookup(str(ip))
                    if info:
                        rep['geoip'] = info
            except Exception:
                pass
            try:
                domain = ev.get('domain') or ev.get('host')
                if mx_is_free_provider and domain:
                    rep['mx_free'] = mx_is_free_provider(str(domain))
            except Exception:
                pass
            ev['reputation'] = rep
            out.append(ev)
        return {'step': 'enrich_reputation', 'status': 'ok', 'data': {'records': out}}

    def _step_extract_indicators(self, session_dir: str) -> Dict[str, Any]:
        # extract simple indicators like hashes, urls, domains from records
        p = os.path.join(session_dir, 'step_6_enrich_reputation.json')
        records = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    records = j.get('data', {}).get('records', [])
            except Exception:
                records = []
        inds = []
        for r in records:
            ev = r if isinstance(r, dict) else {'record': r}
            cand = {}
            for k,v in ev.items():
                if k.lower().endswith('hash') or k.lower() in ('sha256','md5'):
                    cand.setdefault('hashes', []).append(v)
                if isinstance(v, str) and ('http://' in v or 'https://' in v):
                    cand.setdefault('urls', []).append(v)
                if k.lower() in ('domain','host') and isinstance(v, str):
                    cand.setdefault('domains', []).append(v)
            if cand:
                inds.append({'source': ev, 'indicators': cand})
        return {'step': 'extract_indicators', 'status': 'ok', 'data': {'indicators': inds}}

    def _step_correlate_indicators(self, session_dir: str) -> Dict[str, Any]:
        p = os.path.join(session_dir, 'step_11_extract_indicators.json')
        inds = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    inds = j.get('data', {}).get('indicators', [])
            except Exception:
                inds = []
        # simple correlation: group by indicator fingerprint
        groups = {}
        for entry in inds:
            for t,v in entry.get('indicators', {}).items():
                for val in v:
                    key = f"{t}:{val}"
                    groups.setdefault(key, []).append(entry.get('source'))
        return {'step': 'correlate_indicators', 'status': 'ok', 'data': {'groups_count': len(groups), 'groups': list(groups.keys())[:50]}}

    def _step_score_paths(self, session_dir: str) -> Dict[str, Any]:
        # lightweight scoring: count indicator groups and mark severity
        p = os.path.join(session_dir, 'step_12_correlate_indicators.json')
        groups = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    groups = j.get('data', {}).get('groups', [])
            except Exception:
                groups = []
        severity = 'low'
        if len(groups) > 20:
            severity = 'high'
        elif len(groups) > 5:
            severity = 'medium'
        return {'step': 'score_paths', 'status': 'ok', 'data': {'groups': len(groups), 'severity': severity}}

    def _step_build_hop_graph(self, session_dir: str) -> Dict[str, Any]:
        # minimal hop graph builder: nodes = unique domains/ips seen
        nodes = set()
        edges = []
        p = os.path.join(session_dir, 'step_11_extract_indicators.json')
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    inds = j.get('data', {}).get('indicators', [])
            except Exception:
                inds = []
        else:
            inds = []
        for e in inds:
            src = e.get('source', {})
            doms = []
            for k,v in e.get('indicators', {}).items():
                if k == 'domains':
                    doms.extend(v)
            src_id = str(src.get('parsed') or src.get('record') or str(src))
            for d in doms:
                nodes.add(src_id)
                nodes.add(d)
                edges.append({'from': src_id, 'to': d})
        return {'step': 'build_hop_graph', 'status': 'ok', 'data': {'nodes': list(nodes)[:200], 'edges': edges[:200]}}

    def _step_enrich_asn_whois(self, session_dir: str) -> Dict[str, Any]:
        # Lightweight enrichment: fake ASN/whois enrichment for parsed records
        p = os.path.join(session_dir, 'step_2_parse.json')
        parsed = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                    parsed = j.get('data', {}).get('parsed', [])
            except Exception:
                parsed = []
        enriched = [{'record': r, 'asn': 'AS12345', 'whois': 'example.net'} for r in parsed]
        return {'step': 'enrich_asn_whois', 'status': 'ok', 'data': {'enriched': enriched}}

    def _step_prepare_summary_inputs(self, session_dir: str) -> Dict[str, Any]:
        # Aggregate key artifacts to a compact summary input
        summary_bits = []
        for idx in (2,4,18):
            p = os.path.join(session_dir, f'step_{idx}_' )
            matches = [f for f in os.listdir(session_dir) if f.startswith(f'step_{idx}_')]
            for m in matches:
                try:
                    with open(os.path.join(session_dir, m), 'r', encoding='utf-8') as fh:
                        j = json.load(fh)
                        summary_bits.append(str(j.get('data',{})))
                except Exception:
                    continue
        return {'step': 'prepare_summary_inputs', 'status': 'ok', 'data': {'summary_inputs': summary_bits}}

    def _step_prepare_summary_inputs(self, session_dir: str) -> Dict[str, Any]:
        # Aggregate key artifacts to a compact summary input
        summary_bits = []
        for idx in (2,4,18):
            p = os.path.join(session_dir, f'step_{idx}_' )
            matches = [f for f in os.listdir(session_dir) if f.startswith(f'step_{idx}_')]
            for m in matches:
                try:
                    with open(os.path.join(session_dir, m), 'r', encoding='utf-8') as fh:
                        j = json.load(fh)
                        summary_bits.append(str(j.get('data',{})))
                except Exception:
                    continue
        return {'step': 'prepare_summary_inputs', 'status': 'ok', 'data': {'summary_inputs': summary_bits}}

    # ── Gap 7: Implement previously stub steps 7-10, 15-19 ─────────────────

    def _load_step(self, session_dir: str, idx: int) -> dict:
        """Load output of a prior step by index (best-effort)."""
        matches = [f for f in os.listdir(session_dir) if f.startswith(f'step_{idx}_')]
        for m in sorted(matches):
            try:
                with open(os.path.join(session_dir, m), 'r', encoding='utf-8') as fh:
                    return json.load(fh)
            except Exception:
                pass
        return {}

    def _get_rows(self, session_dir: str) -> list:
        """Best-effort row retrieval from step outputs or payload."""
        # Try step 6 (enriched records), step 3 (normalized), step 2 (parsed)
        for idx in (6, 5, 4, 3, 2, 1):
            j = self._load_step(session_dir, idx)
            d = j.get('data', {})
            for key in ('records', 'enriched', 'parsed', 'normalized'):
                rows = d.get(key)
                if rows and isinstance(rows, list):
                    return rows
        return []

    def _step_cluster_sessions(self, session_dir: str) -> Dict[str, Any]:
        """Group rows by src_ip + 5-minute time window (Gap 7: step 7)."""
        rows = self._get_rows(session_dir)
        clusters: dict[str, list] = {}
        for row in rows:
            r = row if isinstance(row, dict) else {}
            src = str(r.get('src_ip') or r.get('ip') or r.get('host') or 'unknown')
            try:
                ts = int(float(r.get('ts') or r.get('timestamp') or 0))
                window = ts // 300  # 5-min buckets
            except Exception:
                window = 0
            key = f"{src}:{window}"
            clusters.setdefault(key, []).append(r)
        summary = [{'key': k, 'count': len(v), 'first_src': k.split(':')[0]} for k, v in clusters.items()]
        return {
            'step': 'cluster_sessions', 'status': 'ok',
            'data': {'cluster_count': len(clusters), 'clusters': summary[:50]}
        }

    def _step_identify_hosts(self, session_dir: str) -> Dict[str, Any]:
        """Collect unique hosts and IPs from all rows (Gap 7: step 8)."""
        rows = self._get_rows(session_dir)
        hosts: set[str] = set()
        ips: set[str] = set()
        for row in rows:
            r = row if isinstance(row, dict) else {}
            for k in ('host', 'hostname', 'computer'):
                v = r.get(k)
                if v:
                    hosts.add(str(v))
            for k in ('src_ip', 'dst_ip', 'ip'):
                v = r.get(k)
                if v:
                    ips.add(str(v))
        return {
            'step': 'identify_hosts', 'status': 'ok',
            'data': {'host_count': len(hosts), 'ip_count': len(ips),
                     'hosts': sorted(hosts)[:100], 'ips': sorted(ips)[:100]}
        }

    def _step_identify_users(self, session_dir: str) -> Dict[str, Any]:
        """Collect unique user identities from all rows (Gap 7: step 9)."""
        rows = self._get_rows(session_dir)
        users: set[str] = set()
        email_addrs: set[str] = set()
        for row in rows:
            r = row if isinstance(row, dict) else {}
            for k in ('user', 'username', 'account', 'principal'):
                v = r.get(k)
                if v:
                    users.add(str(v))
            for k in ('from', 'to', 'email', 'sender', 'recipient'):
                v = r.get(k)
                if v:
                    email_addrs.add(str(v))
        return {
            'step': 'identify_users', 'status': 'ok',
            'data': {'user_count': len(users), 'email_count': len(email_addrs),
                     'users': sorted(users)[:100], 'emails': sorted(email_addrs)[:100]}
        }

    def _step_process_binaries(self, session_dir: str) -> Dict[str, Any]:
        """Check process names and hashes against LOLBin/known-bad lists (Gap 7: step 10)."""
        from src.api.csv_handler import extract_factors_from_raw_row  # type: ignore
        rows = self._get_rows(session_dir)
        flagged: list[dict] = []
        for row in rows:
            r = row if isinstance(row, dict) else {}
            factors = extract_factors_from_raw_row(r)
            suspicious = [f for f in factors if f not in ('windows_update',)]
            if suspicious:
                flagged.append({
                    'process': r.get('process') or r.get('process_name', ''),
                    'path': r.get('path') or r.get('file_path', ''),
                    'sha256': r.get('sha256') or r.get('hash', ''),
                    'factors': suspicious,
                })
        return {
            'step': 'process_binaries', 'status': 'ok',
            'data': {'flagged_count': len(flagged), 'flagged': flagged[:50]}
        }

    def _step_entropy_analysis(self, session_dir: str) -> Dict[str, Any]:
        """Detect beaconing by computing stddev of inter-event ts deltas (Gap 7: step 15)."""
        import math
        rows = self._get_rows(session_dir)
        # Group timestamps by src_ip
        ts_by_src: dict[str, list[float]] = {}
        for row in rows:
            r = row if isinstance(row, dict) else {}
            src = str(r.get('src_ip') or r.get('host') or 'unknown')
            try:
                ts_by_src.setdefault(src, []).append(float(r.get('ts') or r.get('timestamp') or 0))
            except Exception:
                pass
        beaconing: list[dict] = []
        for src, tss in ts_by_src.items():
            if len(tss) < 3:
                continue
            tss_sorted = sorted(tss)
            deltas = [tss_sorted[i+1] - tss_sorted[i] for i in range(len(tss_sorted)-1)]
            mean = sum(deltas) / len(deltas)
            variance = sum((d - mean)**2 for d in deltas) / len(deltas)
            stddev = math.sqrt(variance)
            # Low stddev + regular interval → beaconing
            cv = stddev / mean if mean > 0 else 1.0
            if cv < 0.15 and mean < 120:  # tight cadence, short interval
                beaconing.append({'src': src, 'interval_mean_s': round(mean, 2),
                                  'interval_stddev_s': round(stddev, 2), 'cv': round(cv, 4),
                                  'event_count': len(tss)})
        return {
            'step': 'entropy_analysis', 'status': 'ok',
            'data': {'beaconing_candidates': beaconing, 'sources_analyzed': len(ts_by_src)}
        }

    def _step_temporal_correlation(self, session_dir: str) -> Dict[str, Any]:
        """Cross-domain event timing: find events within 60s window (Gap 7: step 16).

        For CSV2: email at ts=1700000000, then evilproc at ts=1700000020 (+20s),
        then C2 at ts=1700000045 (+45s).  This chains them.
        """
        rows = self._get_rows(session_dir)
        # Also look in payload rows if present
        try:
            payload = self._load_step(session_dir, 1).get('data', {}).get('records') or []
            if isinstance(payload, list) and payload:
                rows = rows + [r for r in payload if isinstance(r, dict) and r not in rows]
        except Exception:
            pass

        # Sort events by ts
        timed: list[tuple[float, dict]] = []
        for row in rows:
            r = row if isinstance(row, dict) else {}
            try:
                ts = float(r.get('ts') or r.get('timestamp') or 0)
                if ts > 0:
                    timed.append((ts, r))
            except Exception:
                pass
        timed.sort(key=lambda x: x[0])

        chains: list[dict] = []
        window = 60.0  # seconds
        for i, (ts_a, ev_a) in enumerate(timed):
            for ts_b, ev_b in timed[i+1:]:
                delta = ts_b - ts_a
                if delta > window:
                    break
                # Events from different sheets/domains within window = chain hit
                sheet_a = ev_a.get('_sheet_source') or ev_a.get('_sheet') or ''
                sheet_b = ev_b.get('_sheet_source') or ev_b.get('_sheet') or ''
                if sheet_a and sheet_b and sheet_a != sheet_b:
                    chains.append({
                        'ts_a': ts_a, 'sheet_a': sheet_a,
                        'ts_b': ts_b, 'sheet_b': sheet_b,
                        'delta_s': round(delta, 2),
                        'event_a': str(list(ev_a.values())[:3])[:80],
                        'event_b': str(list(ev_b.values())[:3])[:80],
                    })
                # Also match same IP across different domain layers
                ip_a = ev_a.get('src_ip') or ev_a.get('dst_ip') or ''
                ip_b = ev_b.get('src_ip') or ev_b.get('dst_ip') or ''
                if ip_a and ip_b and ip_a == ip_b and sheet_a != sheet_b:
                    chains.append({
                        'ts_a': ts_a, 'sheet_a': sheet_a,
                        'ts_b': ts_b, 'sheet_b': sheet_b,
                        'delta_s': round(delta, 2),
                        'shared_ip': ip_a,
                        'chain_type': 'ip_correlation',
                    })
        # Deduplicate
        seen_chains: set[str] = set()
        uniq: list[dict] = []
        for c in chains:
            key = f"{c.get('ts_a')}-{c.get('ts_b')}-{c.get('sheet_a')}-{c.get('sheet_b')}"
            if key not in seen_chains:
                seen_chains.add(key)
                uniq.append(c)
        return {
            'step': 'temporal_correlation', 'status': 'ok',
            'data': {'chain_count': len(uniq), 'chains': uniq[:50],
                     'events_with_ts': len(timed)}
        }

    def _step_anomaly_detection(self, session_dir: str) -> Dict[str, Any]:
        """Z-score anomaly on dst_port and payload_len (Gap 7: step 17)."""
        import math
        rows = self._get_rows(session_dir)
        port_vals: list[float] = []
        len_vals: list[float] = []
        for row in rows:
            r = row if isinstance(row, dict) else {}
            try:
                p = float(r.get('dst_port') or 0)
                if p > 0:
                    port_vals.append(p)
            except Exception:
                pass
            try:
                pl = float(r.get('payload_len') or 0)
                if pl > 0:
                    len_vals.append(pl)
            except Exception:
                pass

        def _zscore_outliers(vals: list[float], threshold=2.5) -> list[float]:
            if len(vals) < 3:
                return []
            mean = sum(vals) / len(vals)
            var = sum((v - mean)**2 for v in vals) / len(vals)
            std = math.sqrt(var) or 1.0
            return [v for v in vals if abs(v - mean) / std > threshold]

        port_outliers = _zscore_outliers(port_vals)
        len_outliers = _zscore_outliers(len_vals)
        return {
            'step': 'anomaly_detection', 'status': 'ok',
            'data': {
                'port_outliers': port_outliers[:20],
                'payload_len_outliers': len_outliers[:20],
                'total_analyzed': len(rows),
            }
        }

    def _step_generate_findings(self, session_dir: str) -> Dict[str, Any]:
        """Collect substantive outputs from prior steps into a findings list (Gap 7: step 18)."""
        findings: list[dict] = []
        step_sources = {
            10: ('flagged', 'process_binary_hit'),
            15: ('beaconing_candidates', 'beaconing_detected'),
            16: ('chains', 'temporal_chain'),
            17: ('port_outliers', 'anomalous_port'),
        }
        for idx, (data_key, finding_type) in step_sources.items():
            j = self._load_step(session_dir, idx)
            items = j.get('data', {}).get(data_key, [])
            if items:
                for item in (items if isinstance(items, list) else [items]):
                    findings.append({'type': finding_type, 'detail': item, 'source_step': idx})
        # Also collect flagged binaries as HIGH findings
        bin_j = self._load_step(session_dir, 10)
        for item in bin_j.get('data', {}).get('flagged', []):
            if not any(f.get('type') == 'process_binary_hit' and f.get('detail') == item for f in findings):
                findings.append({'type': 'process_binary_hit', 'detail': item,
                                 'source_step': 10, 'severity': 'HIGH'})
        return {
            'step': 'generate_findings', 'status': 'ok',
            'data': {'finding_count': len(findings), 'findings': findings[:100]}
        }

    def _step_prioritize_findings(self, session_dir: str) -> Dict[str, Any]:
        """Sort findings by severity (DREAD composite or label) (Gap 7: step 19)."""
        j = self._load_step(session_dir, 18)
        findings = j.get('data', {}).get('findings', [])
        # Assign numeric priority to severity labels
        _SEV_ORDER = {'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}

        def _sev(f: dict) -> int:
            detail = f.get('detail') or {}
            if isinstance(detail, dict):
                factors = detail.get('factors') or []
                sev = 'HIGH' if len(factors) >= 3 else ('MEDIUM' if factors else 'LOW')
            else:
                sev = f.get('severity', 'UNKNOWN')
            return _SEV_ORDER.get(sev, 4)

        prioritized = sorted(findings, key=_sev)
        for i, f in enumerate(prioritized):
            f['priority_rank'] = i + 1
        return {
            'step': 'prioritize_findings', 'status': 'ok',
            'data': {'prioritized_count': len(prioritized), 'top_findings': prioritized[:20]}
        }

    def status(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self._sessions.get(session_id)

    def cancel(self, session_id: str) -> bool:
        with self._lock:
            s = self._sessions.get(session_id)
            if not s or s.get('status') in {'completed','failed'}:
                return False
            s['status'] = 'cancelled'
            return True


DEFAULT_WORKER = DeepAnalyzeWorker()
