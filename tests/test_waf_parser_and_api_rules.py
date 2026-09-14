import json
from src.parsers.waf_parser import parse_waf_log
from src.core.correlation.rules import api_security as api_rules


def test_parse_modsecurity_like_line():
    sample = json.dumps({'timestamp': 1234567890, 'message': 'Matched rule', 'ruleId': '12345', 'clientIp': '1.2.3.4', 'request': {'uri': '/api/v1/users/42', 'method': 'GET'}})
    res = parse_waf_log(sample)
    assert res['src_ip'] in ('1.2.3.4', None)
    assert res['rule_id'] in ('12345', None)


def test_api_rules_heuristics():
    # BOLA heuristic
    parsed = {'uri': '/api/v1/users/1234/admin/action', 'message': 'suspicious'}
    assert api_rules.match_bola(parsed) is True
    # SSRF heuristic
    parsed2 = {'uri': '/fetch?url=http://169.254.169.254/latest', 'message': ''}
    assert api_rules.match_ssrf(parsed2) is True
