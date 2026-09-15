def verdict_pass_fail(v, rec=None):
    try:
        s = (v or '').upper().strip()
        if (not s or not len(s)) and rec:
            s = (rec.get('verdict') or '').upper()
        if not s:
            return 'NEUTRAL'
        if 'GOOD' in s or 'BENIGN' in s or 'CONTROLLED' in s:
            return 'PASS'
        if 'MALICIOUS' in s or 'SUSPICIOUS' in s or 'THREAT' in s:
            return 'FAIL'
        return 'NEUTRAL'
    except Exception:
        return 'NEUTRAL'


def collect_suspicious_rows(limit, rows):
    out = []
    for r in rows:
        if verdict_pass_fail(None, r) == 'FAIL':
            out.append(r)
            if limit and len(out) >= limit:
                break
    return out


def test_verdict_pass_fail_basic():
    assert verdict_pass_fail('MALICIOUS') == 'FAIL'
    assert verdict_pass_fail('suspicious') == 'FAIL'
    assert verdict_pass_fail('good') == 'PASS'


def test_collect_suspicious_rows_logic():
    rows = [
        {'row_index': 0, 'verdict': 'GOOD'},
        {'row_index': 1, 'verdict': 'SUSPICIOUS'},
        {'row_index': 2, 'verdict': 'MALICIOUS'},
        {'row_index': 3, 'verdict': ''},
    ]
    out = collect_suspicious_rows(100, rows)
    idxs = [r['row_index'] for r in out]
    assert 1 in idxs and 2 in idxs
