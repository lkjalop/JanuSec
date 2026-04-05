"""Evidence-based DREAD scorer (production-grade).

DREAD Components (Microsoft SDL, 1-10 scale):
  - Damage Potential:   How severe is the harm if the attack succeeds
                        (data/system destruction, ransomware, exfil).
  - Reproducibility:   How consistently the attack can be repeated
                        (scripted tools, no human prerequisites).
  - Exploitability:    How much skill/effort is required to launch the attack
                        (public PoC, automated toolkits vs. novel technique).
  - Affected Users:    Breadth of users, systems, or data impacted
                        (domain-wide vs. single host).
  - Discoverability:   How easy it is for an attacker to find this vector
                        (public CVE, exposed service, insider knowledge).

Each dimension returns:
  - score_10:   raw 1-10 integer
  - score_01:   normalised 0.0-1.0 float (score_10 / 10)
  - rationale:  short human-readable justification string
  - evidence:   list of factor keys that contributed to this dimension

composite returns the arithmetic mean on the 1-10 scale.

Usage::

    out = score_dread({'impact:ransomware': 1.0, 'exfiltration:c2_channel': 0.5})
    # out['damage']['score_10'] -> int 1-10
    # out['composite'] -> float 1.0-10.0
    # Legacy keys 'damage','reproducibility','exploitability','affected_users',
    # 'discoverability' are also available as normalised 0-1 floats for backward
    # compatibility with existing callers.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple


# ---------------------------------------------------------------------------
# Dimension contribution tables
# Each entry: (substring_match, partial_match_ok, dimension_delta, rationale)
# Deltas on the 1-10 scale; capped per dimension.
# ---------------------------------------------------------------------------

_DAMAGE_TABLE: List[Tuple[str, int, str]] = [
    ('impact:ransomware',        9, 'Ransomware causes full data encryption / business disruption'),
    ('impact:wiper',             10,'Wiper destroys data irreversibly'),
    ('impact:data_destruction',  9, 'Irreversible data destruction'),
    ('exfiltration:pii',         8, 'Bulk PII exfiltration violates privacy and triggers regulatory damage'),
    ('exfiltration:credentials', 8, 'Credential exfiltration enables follow-on compromise'),
    ('exfiltration:ip',          8, 'Intellectual property theft has long-term strategic damage'),
    ('exfil',                    7, 'Data exfiltration confirmed'),
    ('impact:privilege_escalation', 7, 'Privilege escalation enables lateral movement and persistent access'),
    ('impact:lateral_movement',  7, 'Lateral movement amplifies blast radius across systems'),
    ('ransomware',               9, 'Ransomware payload detected'),
    ('data:large_extract',       7, 'Large-scale data extraction confirmed'),
    ('cloud:public_bucket',      6, 'Public cloud bucket exposes data at scale'),
    ('endpoint:unsigned_exec',   6, 'Unsigned executable can run arbitrary payloads'),
    ('sandbox:malicious',        7, 'Sandbox detonation confirmed malicious behaviour'),
    ('yara:match',               6, 'YARA match indicates known malware family'),
    ('impact:denial_of_service', 6, 'DoS disrupts availability of services'),
    ('impact:',                  5, 'Generic impact factor detected'),
]

_REPRO_TABLE: List[Tuple[str, int, str]] = [
    ('api:',                     8, 'API-accessible; scriptable and highly reproducible'),
    ('net:beacon_periodic',      8, 'Periodic beaconing is fully automated and repeatable'),
    ('identity:credential_stuffing', 9, 'Credential stuffing is fully scripted with public toolkits'),
    ('remote:no_mfa',            8, 'No MFA; brute-force or replay is trivially repeatable'),
    ('network:port_scan',        9, 'Port scanning is fully automated'),
    ('port_scan',                9, 'Port scanning is fully automated'),
    ('cloud:',                   7, 'Cloud misconfigurations are reproducible via SDK/CLI'),
    ('exfiltration:c2_channel',  7, 'Established C2 channel enables repeatable command execution'),
    ('yara:match',               6, 'Known malware family implies tooling exists for repro'),
    ('endpoint:dll_sideload',    7, 'DLL sideloading is scriptable given known path'),
    ('identity:mfa_fatigue',     7, 'MFA fatigue attack is easily automated via repeated push loop'),
    ('email:domain_homograph',   6, 'Homograph campaign infrastructure is reusable'),
    ('email:',                   5, 'Email-based attack requires some sender infrastructure setup'),
    ('identity:',                6, 'Identity attacks often reproducible with available credential data'),
]

_EXPLOIT_TABLE: List[Tuple[str, int, str]] = [
    ('identity:credential_stuffing', 9, 'Credential stuffing: public toolkits, minimal skill required'),
    ('remote:no_mfa',            9, 'No MFA: trivial to exploit with any valid credential'),
    ('cloud:public_bucket',      9, 'Public bucket: zero-skill read access'),
    ('network:port_scan',        8, 'Port scanning: free tools, no prior access needed'),
    ('port_scan',                8, 'Port scanning: free tools, no prior access needed'),
    ('api:',                     8, 'Public API surface: documented, low skill barrier'),
    ('sandbox:malicious',        7, 'Malicious file: requires delivery but no active skill'),
    ('exfiltration:c2_channel',  7, 'C2 established: attacker already inside, easy to exploit'),
    ('endpoint:unsigned_exec',   7, 'Unsigned exec: requires local access but no advanced skill'),
    ('identity:kerberos',        8, 'Kerberos abuse: toolkits (Rubeus, Impacket) freely available'),
    ('remote:rdp_chain',         7, 'RDP lateral movement: tools widely available'),
    ('endpoint:dll_sideload',    7, 'DLL sideloading: public PoC for many apps'),
    ('yara:match',               6, 'Known malware family with available sample/tooling'),
    ('identity:role_mutation',   6, 'Role mutation: requires cloud API knowledge'),
    ('cloud:cross_account',      6, 'Cross-account trust chain: requires IAM expertise'),
    ('dns:tunnel_suspected',     6, 'DNS tunnelling: tools available but detection-aware setup needed'),
    ('net:tls_cert_chain',       5, 'Custom TLS cert: moderate skill to set up infrastructure'),
    ('impact:ransomware',        6, 'Ransomware: obtainable as-a-service; moderate skill'),
    ('exfiltration:pii',         6, 'Exfil of PII: depends on access method complexity'),
    ('identity:conditional_access_drift', 5, 'CA drift: requires admin-level cloud knowledge'),
    ('endpoint:persistence_surface', 6, 'Persistence: various techniques, tools available'),
]

_AFFECTED_TABLE: List[Tuple[str, int, str]] = [
    ('impact:ransomware',        9, 'Ransomware typically encrypts all accessible shares/hosts'),
    ('exfiltration:pii',         8, 'PII exfiltration affects all data subjects in scope'),
    ('identity:credential_stuffing', 8, 'Credential stuffing targets all accounts in the corpus'),
    ('remote:no_mfa',            7, 'No-MFA gap applies to all users missing enforcement'),
    ('cloud:public_bucket',      8, 'Public cloud bucket exposes all objects to anyone'),
    ('cloud:cross_account',      8, 'Cross-account trust can pivot to all tenants in the org'),
    ('network:port_scan',        7, 'Horizontal scan targets all hosts in the scanned range'),
    ('port_scan_horizontal',     7, 'Horizontal scan targets all hosts in the scanned range'),
    ('net:beacon_periodic',      5, 'C2 beacon is typically per-host; blast radius = 1 host initially'),
    ('remote:rdp_chain',         6, 'RDP lateral movement progressively expands affected hosts'),
    ('api:',                     6, 'API abuse affects all consumers of the targeted service'),
    ('email:',                   5, 'Email campaign targets distribution list recipients'),
    ('sandbox:malicious',        4, 'Malicious file initially affects executing user/host'),
    ('endpoint:',                4, 'Endpoint compromise initially limited to single host'),
    ('data:large_extract',       7, 'Large extraction implies broad dataset in scope'),
    ('cloud:kms_secrets',        7, 'KMS/secrets access exposes all encrypted data under those keys'),
]

_DISCO_TABLE: List[Tuple[str, int, str]] = [
    ('cloud:public_bucket',      10,'Bucket is public: discoverable without authentication'),
    ('network:port_scan',        9, 'Open port discovered via internet-wide scanning tools'),
    ('port_scan',                9, 'Open port discovered via internet-wide scanning tools'),
    ('remote:no_mfa',            8, 'Missing MFA visible in authentication headers / public services'),
    ('identity:credential_stuffing', 8, 'Credential stuffing targets login pages visible from internet'),
    ('email:domain_homograph',   8, 'Homograph domain discoverable via WHOIS / passive DNS'),
    ('dns:tunnel_suspected',     7, 'DNS tunnelling visible to passive DNS watchers'),
    ('api:',                     7, 'Public API: discoverable via Shodan, GitHub, or docs'),
    ('cloud:serverless_trigger', 7, 'Serverless endpoints often exposed via public invoke URLs'),
    ('net:beacon_periodic',      6, 'Periodic beacon: discoverable via NetFlow analysis'),
    ('net:sni_dns_nx_spike',     7, 'NXDOMAIN spike: anomaly visible in DNS telemetry'),
    ('yara:match',               5, 'Known malware: discoverable via AV/sandboxes but requires sample'),
    ('sandbox:malicious',        5, 'Malicious file: discoverable in routing/email analytics'),
    ('endpoint:unsigned_exec',   5, 'Unsigned exec: requires code-signing audit to find'),
    ('identity:kerberos',        5, 'Kerberos abuse: discoverable in DC event logs (4769/4768)'),
    ('exfiltration:pii',         4, 'Internal exfil discovered via DLP or UEBA; not public'),
    ('exfiltration:credentials', 5, 'Credential exfil: discoverable in auth logs'),
    ('remote:rdp_chain',         5, 'RDP lateral movement: visible in security event viewer logs'),
]


def _score_dimension(
    factors: Dict[str, float],
    table: List[Tuple[str, int, str]],
    base: int = 1,
) -> Dict[str, Any]:
    """Apply contribution table to factors, returning dimension detail."""
    best_delta = 0
    best_rationale = 'No matching evidence signals'
    evidence: List[str] = []

    for factor_key, weight in factors.items():
        fk = factor_key.lower()
        for prefix, delta, rationale in table:
            if fk.startswith(prefix) or prefix in fk:
                adj = max(1, round(delta * float(weight)))
                if adj > best_delta:
                    best_delta = adj
                    best_rationale = rationale
                if factor_key not in evidence:
                    evidence.append(factor_key)
                break

    raw = min(10, max(1, base + best_delta - 1))  # ensure 1-10
    return {
        'score_10': raw,
        'score_01': round(raw / 10.0, 3),
        'rationale': best_rationale,
        'evidence': evidence[:5],
    }


def score_dread(factors: Dict[str, float]) -> Dict[str, Any]:
    """Compute evidence-based DREAD scores from a dict of factor weights (0.0-1.0).

    Args:
        factors: Mapping of factor_key -> weight, e.g.
                 {'impact:ransomware': 1.0, 'exfiltration:c2_channel': 0.5}

    Returns:
        Full DREAD breakdown dict with per-dimension detail plus composite.
        Legacy 0-1 float keys are also present for backward compatibility.

    Example output::

        {
          'damage':        {'score_10': 9, 'score_01': 0.9, 'rationale': '...', 'evidence': [...]},
          'reproducibility': {...},
          'exploitability':  {...},
          'affected_users':  {...},
          'discoverability': {...},
          'composite':     8.4,        # arithmetic mean on 1-10 scale
          'composite_01':  0.84,       # same normalised 0-1
          'risk_tier':     'CRITICAL', # CRITICAL/HIGH/MEDIUM/LOW
          # Legacy aliases (0-1 floats) kept for backward compat:
          '_damage_01': 0.9,
          '_reproducibility_01': 0.7,
          '_exploitability_01': 0.8,
          '_affected_users_01': 0.9,
          '_discoverability_01': 0.8,
        }
    """
    factors = factors or {}

    dmg = _score_dimension(factors, _DAMAGE_TABLE)
    rep = _score_dimension(factors, _REPRO_TABLE)
    expl = _score_dimension(factors, _EXPLOIT_TABLE)
    aff = _score_dimension(factors, _AFFECTED_TABLE)
    disc = _score_dimension(factors, _DISCO_TABLE)

    dims = [dmg, rep, expl, aff, disc]
    composite_10 = round(sum(d['score_10'] for d in dims) / len(dims), 2)
    composite_01 = round(composite_10 / 10.0, 3)

    if composite_10 >= 8.0:
        risk_tier = 'CRITICAL'
    elif composite_10 >= 6.0:
        risk_tier = 'HIGH'
    elif composite_10 >= 4.0:
        risk_tier = 'MEDIUM'
    else:
        risk_tier = 'LOW'

    return {
        'damage':           dmg,
        'reproducibility':  rep,
        'exploitability':   expl,
        'affected_users':   aff,
        'discoverability':  disc,
        'composite':        composite_10,
        'composite_01':     composite_01,
        'risk_tier':        risk_tier,
        # Legacy 0-1 float aliases for backward compatibility
        '_damage_01':         dmg['score_01'],
        '_reproducibility_01': rep['score_01'],
        '_exploitability_01':  expl['score_01'],
        '_affected_users_01':  aff['score_01'],
        '_discoverability_01': disc['score_01'],
    }

