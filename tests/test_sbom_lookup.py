from __future__ import annotations

from src.integrations.sbom import SBOMLookup


def test_sbom_lookup_empty(tmp_path):
    p = tmp_path / 'sbom.json'
    # write a simple cache entry
    content = {
        'abcd1234deadbeef': {
            'components': [{'name': 'libfoo', 'version': '1.2.3'}],
            'cves': [{'cve': 'CVE-2023-0001', 'cvss': 7.5, 'kev': True, 'epss': 0.12}]
        }
    }
    p.write_text(__import__('json').dumps(content))
    s = SBOMLookup(str(p))
    res = s.lookup_binary('abcd1234deadbeef')
    assert isinstance(res, dict)
    assert len(res.get('components', [])) == 1
    assert len(res.get('cves', [])) == 1
