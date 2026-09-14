import json
import os
import pytest

from src.core.correlation.rules import registry as reg

try:
    from src.core.correlation.rules.weekX import expanded_batch  # type: ignore
    from src.core.correlation.rules.batch_more import additional_30  # type: ignore
except Exception:
    pass

ADDITIONAL_VECTORS = [
    ('imp_shadowcopy_delete', 'tests/data/imp_shadowcopy_delete_event.json'),
    ('imp_stop_security_services', 'tests/data/imp_stop_security_services_event.json'),
    ('exfil_stealth_cloud_metadata', 'tests/data/exfil_stealth_cloud_metadata_event.json'),
    ('exfil_dns_txt_chunks', 'tests/data/exfil_dns_txt_chunks_event.json'),
    ('exfil_large_https_rare_asn', 'tests/data/exfil_large_https_rare_asn_event.json'),
]


@pytest.mark.parametrize('rule_id,vector_path', ADDITIONAL_VECTORS)
def test_domain_pack_additional(rule_id, vector_path):
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
