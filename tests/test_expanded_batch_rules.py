import json
import pathlib

from src.core.correlation.rules.registry import CORRELATION_RULES

DATA = pathlib.Path(__file__).parent / 'data' / 'auto_audit'


def load(name):
    p = DATA / name
    with p.open('r', encoding='utf-8') as f:
        return json.load(f)


def test_ca_lsass_access_seq_matches_vector():
    evt = load('ca_lsass_access_seq.json')
    fired = CORRELATION_RULES.evaluate(evt)
    assert any(r.name == 'ca_lsass_access_seq' for r in fired)


def test_pe_token_theft_combo_matches_vector():
    evt = load('pe_token_theft_combo.json')
    fired = CORRELATION_RULES.evaluate(evt)
    assert any(r.name == 'pe_token_theft_combo' for r in fired)


def test_cred_dump_lsass_trace_matches_vector():
    evt = load('cred_dump_lsass_trace.json')
    fired = CORRELATION_RULES.evaluate(evt)
    assert any(r.name in ('cred_dump_lsass_trace','cred_lsass_openprocess') for r in fired)


def test_filesystem_encryption_trigger_matches_vector():
    evt = load('filesystem_encryption_trigger.json')
    fired = CORRELATION_RULES.evaluate(evt)
    assert any(r.name == 'filesystem_encryption_trigger' for r in fired)
