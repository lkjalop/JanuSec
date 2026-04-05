from src.rules.dsl_parser import parse_rule, evaluate, Comparison, Logical, Not, Exists

def test_simple_comparison_parse():
    ast = parse_rule('user.id == "alice"')
    assert isinstance(ast, Comparison)
    assert ast.field == ['user','id']
    assert ast.op == '=='
    assert ast.value == 'alice'
    assert evaluate(ast, {'user':{'id':'alice'}}) is True


def test_logical_and_or():
    ast = parse_rule('(user.id == "alice" AND action == "login") OR EXISTS meta.trace')
    assert isinstance(ast, Logical)


def test_sequence_parses():
    ast = parse_rule('SEQ[user.id == "alice", action == "priv_escalate"] WITHIN 5m')
    from src.rules.dsl_parser import Sequence
    assert isinstance(ast, Sequence)
    assert ast.window == 5
    assert ast.unit == 'm'


def test_lookup_parses():
    ast = parse_rule('LOOKUP.asn_rarity(src.ip) > 0.8')
    from src.rules.dsl_parser import LookupExpr
    assert isinstance(ast, LookupExpr)
    assert ast.func == 'asn_rarity'


def test_rate_parses():
    ast = parse_rule('RATE(user.id,5m) > 10')
    from src.rules.dsl_parser import RateExpr
    assert isinstance(ast, RateExpr)
    assert ast.window == 5
    assert ast.unit == 'm'


def test_absence_parses():
    ast = parse_rule('ABSENCE[action == "logout"] WITHIN 10m')
    from src.rules.dsl_parser import Absence
    assert isinstance(ast, Absence)
    assert ast.window == 10
    assert ast.unit == 'm'
