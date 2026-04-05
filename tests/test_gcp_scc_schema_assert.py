import json
from scripts.gcp_scc_to_posture import build_payloads


def test_gcp_scc_mapping_public_bucket_and_source_ts():
    doc = {
        "findings": [
            {
                "category": "Public Access to Storage Bucket",
                "severity": "MEDIUM",
                "resourceName": "//storage.googleapis.com/projects/_/buckets/my-bucket",
                "eventTime": "2025-12-01T12:34:56Z"
            },
            {
                "category": "Open firewall 0.0.0.0/0",
                "severity": "HIGH",
                "resourceName": "//compute.googleapis.com/projects/p/regions/r/firewalls/fw-1",
                "eventTime": "2025-12-01T12:35:10Z"
            }
        ]
    }
    posture, assets = build_payloads(doc, tenant="t1")
    fs = posture.get('findings', [])
    types = {f['type'] for f in fs}
    assert 'cloud:public_bucket' in types
    assert 'cloud:sg_open_0_0_0_0' in types
    # source_ts propagated
    assert any('source_ts' in f for f in fs)
    # assets captured
    assert assets['assets']


def test_gcp_scc_mapping_iam_over_permission_and_cmek_missing_and_vuln_image():
    doc = {
        "findings": [
            {
                "category": "IAM Overly Permissive Binding",
                "severity": "LOW",
                "resourceName": "//cloudresourcemanager.googleapis.com/projects/p",
                "eventTime": "2025-12-01T13:00:00Z"
            },
            {
                "category": "CMEK missing on storage",
                "severity": "MEDIUM",
                "resourceName": "//storage.googleapis.com/projects/_/buckets/b",
                "eventTime": "2025-12-01T13:05:00Z"
            },
            {
                "category": "Container vulnerability: vulnerable image",
                "severity": "HIGH",
                "resourceName": "//container.googleapis.com/projects/p/locations/r/**",
                "eventTime": "2025-12-01T13:10:00Z"
            }
        ]
    }
    posture, assets = build_payloads(doc, tenant="t1")
    fs = posture.get('findings', [])
    types = {f['type'] for f in fs}
    assert 'cloud:iam_over_permission' in types
    assert 'cloud:cmek_missing' in types
    assert 'cloud:image_vulnerable' in types
    assert all('source_ts' in f for f in fs)
