import json
import os
import pytest

from src.core.correlation.rules import registry as reg

# Ensure rule modules loaded
try:
    from src.core.correlation.rules.email import bec_impersonation_enriched  # type: ignore
    from src.core.correlation.rules.email import dkim_dmarc_failure_enriched  # type: ignore
except Exception:
    pass

EMAIL_VECTORS = [
    ('email_bec_impersonation_enriched', 'tests/data/email_bec_impersonation_event.json'),
    ('email_dkim_dmarc_failure_enriched', 'tests/data/email_dkim_dmarc_failure_event.json'),
    ('email_header_spoof_enriched', 'tests/data/email_header_spoof_event.json'),
    ('email_to_lolbin_chain_enriched', 'tests/data/email_to_lolbin_chain_event.json'),
    ('email_display_name_fuzzy_enriched', 'tests/data/email_display_name_fuzzy_event.json'),
    ('bec_chain_enriched', 'tests/data/email_bec_chain_event.json'),
    ('bec_reply_chain_enriched', 'tests/data/email_bec_reply_chain_event.json'),
    ('bec_vendor_spoof_chain_enriched', 'tests/data/email_bec_vendor_spoof_chain_event.json'),
    ('bec_invoice_fraud_pattern_enriched', 'tests/data/email_bec_invoice_fraud_event.json'),
    ('bec_supplier_portal_takeover_enriched', 'tests/data/email_supplier_portal_takeover_event.json'),
    ('bec_brand_oauth_spoof_enriched', 'tests/data/email_brand_oauth_spoof_event.json'),
    ('bec_supplier_replyto_freemail_enriched', 'tests/data/email_supplier_replyto_freemail_event.json'),
    ('bec_payment_change_dkim_pass_domain_flip_enriched', 'tests/data/email_payment_change_dkim_pass_domain_flip_event.json'),
        ('email_oauth_brand_spoof_enriched', 'tests/data/email_oauth_brand_spoof_event.json'),
        ('bec_supplier_portal_free_reply_enriched', 'tests/data/email_supplier_portal_free_reply_event.json'),
        ('bec_payment_change_dkim_flip_enriched', 'tests/data/email_payment_change_dkim_flip_event.json'),
]


@pytest.mark.parametrize('rule_id,vector_path', EMAIL_VECTORS)
def test_email_pack(rule_id, vector_path):
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


def test_email_supplier_portal_edgecase():
    full_path = os.path.join(os.getcwd(), 'tests/data/email_supplier_portal_takeover_edgecase.json')
    assert os.path.exists(full_path), "Missing edgecase vector"
    with open(full_path, 'r', encoding='utf-8') as fh:
        payload = json.load(fh)
    hits = reg.CORRELATION_RULES.evaluate(payload)
    names = {getattr(h, 'rule', getattr(h, 'name', None)) for h in hits}
    assert 'bec_supplier_portal_takeover_enriched' in names
