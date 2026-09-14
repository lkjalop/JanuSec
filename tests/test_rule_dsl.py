from src.rules.dsl_engine import parse_rule, evaluate_rule
import time

def _mk(ts_offset: int, **fields):
    e = {'ts': time.time() + ts_offset}
    e.update(fields)
    return e

def test_simple_comparison():
    ast = parse_rule("user = alice")
    ev = {'user': 'alice'}
    assert evaluate_rule(ast, ev, [ev]) is True
    ev2 = {'user': 'bob'}
    assert evaluate_rule(ast, ev2, [ev, ev2]) is False

def test_regex():
    ast = parse_rule("proc_name ~ evil")
    ev = {'proc_name': 'run-evil.exe'}
    assert evaluate_rule(ast, ev, [ev]) is True

def test_and_or_not():
    ast = parse_rule("user = alice AND NOT role = admin")
    ev = {'user': 'alice', 'role': 'user'}
    assert evaluate_rule(ast, ev, [ev])
    ev2 = {'user': 'alice', 'role': 'admin'}
    assert not evaluate_rule(ast, ev2, [ev, ev2])

def test_count_within():
    ast = parse_rule("COUNT(ip) > 2 WITHIN 1m")
    now_events = [_mk(-10, ip='1.1.1.1'), _mk(-5, ip='2.2.2.2'), _mk(-1, ip='3.3.3.3')]
    assert evaluate_rule(ast, now_events[-1], now_events)

def test_seq_within():
    ast = parse_rule("user = alice SEQ_WITHIN 30s role = admin")
    e1 = _mk(-20, user='alice')
    e2 = _mk(-5, role='admin')
    assert evaluate_rule(ast, e2, [e1, e2])

def test_within_single():
    ast = parse_rule("(user = alice) WITHIN 30s")
    e1 = _mk(-10, user='alice')
    current = _mk(0, user='bob')
    assert evaluate_rule(ast, current, [e1, current])