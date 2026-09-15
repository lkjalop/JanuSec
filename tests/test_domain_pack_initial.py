import json
import os
import pytest

from src.core.correlation.rules import registry as reg

# Ensure modules are imported so register_rule decorators run
try:
    from src.core.correlation.rules.weekX import expanded_batch  # type: ignore
    from src.core.correlation.rules.batch_more import additional_30  # type: ignore
except Exception:
    pass

DOMAIN_VECTORS = [
    # Email (SMTP exfil)
    ('exfil_smtp_large_attachment', 'tests/data/exfil_smtp_large_attachment_event.json'),
    # IAM / Cloud
    ('cloud_role_escalation_from_vm', 'tests/data/cloud_role_escalation_from_vm_event.json'),
    # Exfil
    ('exfil_multipart_http_chunking', 'tests/data/exfil_multipart_http_chunking_event.json'),
    # Ransomware / Impact
    ('filesystem_encryption_trigger', 'tests/data/filesystem_encryption_trigger_event.json'),
]


@pytest.mark.parametrize('rule_id,vector_path', DOMAIN_VECTORS)
def test_domain_pack_initial(rule_id, vector_path):
    full_path = os.path.join(os.getcwd(), vector_path)
    assert os.path.exists(full_path), f"Missing vector {vector_path}"
    with open(full_path, 'r', encoding='utf-8') as fh:
        payload = json.load(fh)
    hits = reg.CORRELATION_RULES.evaluate(payload)
    hit_names = set()
    for h in hits:
        if hasattr(h, 'rule'):
            hit_names.add(getattr(h, 'rule'))
        elif hasattr(h, 'name'):
            hit_names.add(getattr(h, 'name'))
    assert rule_id in hit_names, f"Rule {rule_id} did not fire; hits={hit_names}"
