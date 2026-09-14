"""Network-focused feature extractor for Sultry.

Provides small, dependency-free helpers to summarize network signals useful
for correlation and scoring (ASN counts, NXDOMAIN rate, port distribution).
"""
from collections import Counter
from typing import List, Dict, Any


def summarize_network(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize a list of network records (each record is a dict).

    Expects records to include optional keys: `asn`, `dst_port`, `domain`, `response_code`.
    """
    total = len(records)
    asns = [r.get('asn') for r in records if r.get('asn')]
    ports = [r.get('dst_port') for r in records if r.get('dst_port') is not None]
    domains = [r.get('domain') for r in records if r.get('domain')]
    # NXDOMAIN-ish heuristic: response_code 3 or domain == 'NXDOMAIN'
    nxdomain_count = sum(1 for r in records if str(r.get('response_code','')).lower() in ('3','nxdomain'))

    return {
        'total_records': total,
        'unique_asns': len(set(asns)),
        'top_ports': Counter(ports).most_common(6),
        'domain_count': len(set(domains)),
        'nxdomain_rate': (nxdomain_count / total) if total else 0.0,
    }
