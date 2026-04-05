from __future__ import annotations
import yaml, os, time, json
from typing import Dict, Any, List
import psycopg2

_FACTORS_SPEC_PATH = os.getenv('FACTOR_SPECS_PATH', 'factor_specs/new_factors.yaml')
DB_DSN = os.getenv('JNS_DB_DSN', 'postgresql://postgres:postgres@localhost:5432/janusec')


def _get_conn():
    return psycopg2.connect(DB_DSN)

# DSL & temporal imports
try:
    from src.rules.dsl_parser import parse_rule, evaluate as _eval_simple
except Exception:
    parse_rule = None
    _eval_simple = None

try:
    from src.rules.temporal_executor import execute_sequence, execute_absence, evaluate_rate, evaluate_zscore
except Exception:
    execute_sequence = None
    execute_absence = None
    evaluate_rate = None
    evaluate_zscore = None

try:
    from src.enrichment.lookup_registry import lookup_func
except Exception:
    lookup_func = None


def _get_field(event: Dict[str, Any], path: str):
    parts = path.split('.')
    cur = event
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
        if cur is None:
            return None
    return cur


def _eval_compare(event: Dict[str, Any], expr: str) -> bool:
    # supports simple comparisons like metrics.delta_bytes > 100 and tag presence
    import re
    m = re.match(r"^([a-zA-Z0-9_\.]+)\s*(>=|<=|==|!=|>|<)\s*(.+)$", expr.strip())
    if not m:
        # presence check
        val = _get_field(event, expr.strip())
        return bool(val)
    fld, op, rhs = m.group(1), m.group(2), m.group(3)
    lhs_val = _get_field(event, fld)
    # try to coerce rhs to number
    try:
        rhs_val = float(rhs)
    except Exception:
        rhs_val = rhs.strip().strip('"\'')
    try:
        lhs_num = float(lhs_val)
    except Exception:
        lhs_num = None
    if lhs_num is not None and isinstance(rhs_val, (int,float)):
        if op == '>': return lhs_num > rhs_val
        if op == '<': return lhs_num < rhs_val
        if op == '>=': return lhs_num >= rhs_val
        if op == '<=': return lhs_num <= rhs_val
        if op == '==': return lhs_num == rhs_val
        if op == '!=': return lhs_num != rhs_val
    else:
        # string compare
        l = str(lhs_val or '')
        r = str(rhs_val)
        if op == '==': return l == r
        if op == '!=': return l != r
    return False


def _eval_dsl(event: Dict[str, Any], expr: str, spec: Dict[str, Any]) -> bool:
    """Evaluate a DSL expression. Uses parse_rule -> AST and delegates temporal/statistical nodes to temporal_executor.

    Returns True if the rule matches.
    """
    if not parse_rule:
        # fallback to legacy compare patterns
        try:
            return _eval_compare(event, expr)
        except Exception:
            return False
    try:
        ast = parse_rule(expr)
    except Exception:
        # parse failed; fallback
        return _eval_compare(event, expr)
    # Walk AST and handle temporal/statistical nodes
    # For simple comparisons & logical, use _eval_simple evaluator
    try:
        if _eval_simple:
            # _eval_simple handles Comparison and Exists and logical operators
            if _eval_simple(ast, event):
                return True
        # sequence
        from src.rules.dsl_parser import Sequence, Absence, RateExpr, ZScoreExpr, LookupExpr
        if isinstance(ast, Sequence) and execute_sequence:
            # convert window to seconds
            mul = {'s':1,'m':60,'h':3600,'d':86400}.get(ast.unit,'s')
            return execute_sequence(ast.steps, int(ast.window*mul), event.get('tenant_id','default'))
        if isinstance(ast, Absence) and execute_absence:
            mul = {'s':1,'m':60,'h':3600,'d':86400}.get(ast.unit,'s')
            return execute_absence(ast.predicate, int(ast.window*mul), event.get('tenant_id','default'))
        if isinstance(ast, RateExpr) and evaluate_rate:
            mul = {'s':1,'m':60,'h':3600,'d':86400}.get(ast.unit,'s')
            return evaluate_rate(ast.field, int(ast.window*mul), ast.op, ast.threshold, event.get('tenant_id','default'))
        if isinstance(ast, ZScoreExpr) and evaluate_zscore:
            mul = {'s':1,'m':60,'h':3600,'d':86400}.get(ast.unit,'s')
            return evaluate_zscore(ast.field, int(ast.window*mul), ast.op, ast.threshold, event.get('tenant_id','default'))
        if isinstance(ast, LookupExpr) and lookup_func:
            # call enrichment function (e.g., asn_rarity)
            val = lookup_func(ast.func, event, ast.field)
            return _eval_compare({'v': val}, f'v {ast.op} {ast.value}')
    except Exception:
        return False
    return False


def _eval_seq_within(event: Dict[str, Any], spec: Dict[str, Any], expr: str) -> bool:
    # expr like SEQ[mfa_disable, role_grant] WITHIN 15m
    import re
    m = re.match(r"SEQ\[(.+)\]\s+WITHIN\s+(\d+)(m|h)", expr.strip(), flags=re.IGNORECASE)
    if not m:
        return False
    seq_list = [s.strip() for s in m.group(1).split(',') if s.strip()]
    num = int(m.group(2))
    unit = m.group(3)
    minutes = num if unit.lower() == 'm' else num*60
    principal = (event.get('actor') or {}).get('principal_id')
    if not principal:
        return False
    # Query recent events for this principal from events table
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT raw->>'changeType' as changeType, ts FROM events WHERE (raw->>'actor') IS NOT NULL AND (raw->>'actor') LIKE %s AND ts >= now() - interval '%s minutes' ORDER BY ts ASC", (f"%{principal}%", minutes))
            rows = cur.fetchall()
        conn.close()
    except Exception:
        return False
    # flatten changeType list
    observed = [r[0] for r in rows if r and r[0]]
    # check if seq_list appears in order in observed
    idx = 0
    for o in observed:
        if idx < len(seq_list) and seq_list[idx] in o:
            idx += 1
    return idx >= len(seq_list)



def load_factors_spec(path: str | None = None) -> Dict[str, Any]:
    p = path or _FACTORS_SPEC_PATH
    with open(p, 'r', encoding='utf-8') as fh:
        data = yaml.safe_load(fh)
    # Return mapping by id
    out = {}
    for f in data.get('factors', []):
        out[f['id']] = f
    return out


class FactorEngine:
    def __init__(self, spec_path: str | None = None):
        self.specs = load_factors_spec(spec_path)
        # Prometheus counters (lazy import to avoid heavy deps during tests)
        try:
            from prometheus_client import Counter
            self._counter = Counter('janusec_factor_matches_total', 'Total factor matches', ['factor_id'])
        except Exception:
            self._counter = None

    def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate event against loaded factor specs and return list of matched factor dicts
        with 'id' and 'score' keys.
        """
        matches: List[Dict[str, Any]] = []
        for fid, spec in self.specs.items():
            try:
                det = spec.get('detection_logic') or ''
                # If detection_logic contains temporal/statistical nodes, prefer offloading to temporal_tasks
                if det and ('SEQ' in det or 'ABSENCE' in det or 'RATE' in det or 'ZSCORE' in det or 'LOOKUP' in det):
                    # enqueue a temporal task for async evaluation
                    try:
                        conn = _get_conn()
                        with conn.cursor() as cur:
                            cur.execute("INSERT INTO temporal_tasks(tenant_id,factor_id,event_id,rule_expr,ast) VALUES (%s,%s,%s,%s,%s)", (event.get('tenant_id','default'), fid, event.get('event_id'), det, None))
                        conn.commit(); conn.close()
                    except Exception:
                        pass
                    # Defer matching to worker; use heuristic local match attempt
                    matched = False
                elif det:
                    matched = _eval_dsl(event, det, spec)
                else:
                    matched = self._match_spec(event, spec)
                if matched:
                    score = float(spec.get('severity_weight') or 0.5)
                    matches.append({'id': fid, 'score': score})
                    # persist to DB
                    try:
                        conn = _get_conn()
                        with conn.cursor() as cur:
                            cur.execute("INSERT INTO event_factors(event_id, factor_id, score) VALUES (%s,%s,%s)", (event.get('event_id'), fid, score))
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass
                    # prometheus
                    try:
                        if self._counter:
                            self._counter.labels(factor_id=fid).inc()
                    except Exception:
                        pass
                    # Incident automation: check aggregate threshold
                    try:
                        inc_cfg = spec.get('incident', {})
                        if inc_cfg:
                            # Example: inc_cfg = {'aggregate_count': 5, 'window_minutes': 60, 'title': 'Multiple X', 'severity':'HIGH'}
                            agg = int(inc_cfg.get('aggregate_count') or 0)
                            win = int(inc_cfg.get('window_minutes') or 60)
                            if agg > 0:
                                # count event_factors entries for this factor in window
                                try:
                                    conn = _get_conn()
                                    with conn.cursor() as cur:
                                        cur.execute("SELECT count(*) FROM event_factors ef JOIN events e ON ef.event_id = e.event_id WHERE ef.factor_id=%s AND e.ts >= now() - interval '%s minutes'", (fid, win))
                                        row = cur.fetchone()
                                    conn.close()
                                    cnt = int(row[0]) if row and row[0] else 0
                                    if cnt >= agg:
                                        # create incident if not exists for recent window
                                        key = f"auto:{fid}:{int(time.time()//(win*60))}"
                                        try:
                                            conn = _get_conn()
                                            with conn.cursor() as cur:
                                                cur.execute("INSERT INTO incidents(tenant_id,incident_key,title,description,severity,metadata) VALUES (%s,%s,%s,%s,%s,%s)", (event.get('tenant_id','default'), key, inc_cfg.get('title') or f'Auto:{fid}', inc_cfg.get('description') or '', inc_cfg.get('severity') or 'MEDIUM', json.dumps({'factor':fid,'count':cnt})))
                                            conn.commit(); conn.close()
                                        except Exception:
                                            pass
                                except Exception:
                                    pass
                    except Exception:
                        pass
            except Exception:
                continue
        return matches

    def _match_spec(self, event: Dict[str, Any], spec: Dict[str, Any]) -> bool:
        # Handle a few types of detection_logic heuristics from YAML: sequence windows, threshold comparisons
        det = spec.get('detection_logic','') or ''
        # Simple mapping of some known spec ids to heuristics
        fid = spec.get('id','')
        if fid == 'iam:privilege_chain_escalation':
            iam = event.get('iam') or {}
            val = (iam.get('privilege_delta_count') or 0)
            thresh = (spec.get('thresholds',{}).get('cumulative_privilege_delta') or 20)
            if val >= thresh:
                return True
            # fallback: check recent events for cumulative delta for this principal
            principal = (event.get('actor') or {}).get('principal_id')
            window = spec.get('thresholds',{}).get('window_minutes') or 120
            try:
                conn = _get_conn()
                with conn.cursor() as cur:
                    cur.execute("SELECT SUM((raw->>'privilegeDelta')::int) FROM events WHERE actor_principal = %s AND ts >= now() - interval '%s minutes'", (principal, window))
                    row = cur.fetchone()
                    if row and row[0] and int(row[0]) >= thresh:
                        conn.close()
                        return True
                conn.close()
            except Exception:
                pass
            return False
        if fid == 'api:rare_method_combo':
            # Presence added by normalizer as heuristic
            return 'api:rare_method_combo' in (event.get('factors') or [])
        if fid == 'email:forward_rule_new_external':
            return 'email:forward_rule_new_external' in (event.get('factors') or [])
        if fid == 'data:staging_volume_spike':
            # If metrics.delta_bytes in event
            m = event.get('metrics') or {}
            return (m.get('delta_bytes') or 0) >= (spec.get('thresholds',{}).get('delta_bytes') or 0)
        # Default: match if factor id present in event factors
        return fid in (event.get('factors') or [])


__all__ = ['FactorEngine', 'load_factors_spec']
