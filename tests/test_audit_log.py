import json, os, tempfile
from src.audit import logger as audit_logger


def test_audit_writes(tmp_path):
    p = tmp_path / 'audit.log'
    # Point the module at our temp file
    audit_logger.AUDIT_PATH = p
    # call audit
    audit_logger.audit('unit_test_event', who='tester', value=123)
    # read back
    with open(p, 'r', encoding='utf-8') as fh:
        lines = [l.strip() for l in fh.readlines() if l.strip()]
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec.get('event') == 'unit_test_event'
    assert rec.get('who') == 'tester'
    assert rec.get('value') == 123
