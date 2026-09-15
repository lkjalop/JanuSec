import json
import os
from typing import Dict, Any, List, Optional

try:
    # avoid hard dependency; import lazily in tests
    from src.core.cmdb.client import BaseCMDBClient
except Exception:
    BaseCMDBClient = object


def _safe_get_factor(factors: List[Dict[str, Any]], key: str):
    for f in factors:
        if f.get('name') == key or f.get('type') == key:
            return f.get('value')
    return None


# ---------------------------------------------------------------------------
# Cloud-native factor → DREAD dimension deltas
# Each entry: (damage, reproducibility, exploitability, affected, discoverability)
# ---------------------------------------------------------------------------
_CLOUD_FACTOR_DELTAS: Dict[str, tuple] = {
    # CloudTrail / AWS IAM
    'cloud:admin_role_assumed':        (5, 3, 4, 5, 3),
    'cloud:privilege_escalation':      (6, 3, 5, 5, 2),
    'cloud:iam_policy_change':         (4, 4, 3, 4, 3),
    'cloud:root_account_used':         (7, 2, 3, 7, 2),
    'cloud:access_key_created':        (4, 5, 4, 4, 4),
    'cloud:mfa_disabled':              (5, 4, 5, 5, 3),
    'cloud:detective_findings_group':  (5, 3, 4, 4, 3),
    'cloud:provider_detection':        (4, 3, 3, 4, 3),
    # Macie / data exposure
    'data:pci_sensitive':              (7, 2, 3, 6, 4),
    'data:phi_exposure':               (8, 2, 2, 7, 3),
    'data:pii_exposure':               (6, 2, 2, 5, 3),
    'data:credential_exposure':        (8, 4, 6, 7, 4),
    # GuardDuty / SecurityHub
    'cloud:guardduty_high':            (6, 3, 4, 5, 3),
    'cloud:guardduty_critical':        (8, 3, 5, 7, 3),
    'cloud:securityhub_critical':      (7, 3, 5, 6, 3),
    'cloud:vpcflow_recon':             (3, 5, 3, 3, 5),
    # Azure-specific
    'cloud:azure_nsg':                 (3, 4, 3, 3, 4),
    'cloud:privileged_operation':      (5, 3, 4, 5, 3),
    'cloud:sentinel_alert':            (5, 3, 4, 5, 3),
    'cloud:entra_risky_signin':        (5, 4, 4, 5, 3),
    'cloud:defender_alert':            (6, 3, 4, 5, 3),
    # Endpoint / process
    'credential_access':               (7, 4, 5, 6, 3),
    'lolbin':                          (5, 6, 5, 4, 3),
    'orphan_process':                  (5, 4, 5, 4, 2),
    'temp_execution':                  (4, 5, 5, 3, 3),
    'unsigned_executable':             (4, 4, 4, 3, 3),
    'naming_mimicry':                  (5, 4, 4, 4, 2),
    'novel_global':                    (5, 2, 3, 4, 2),
    # Network
    'network_beacon':                  (5, 7, 5, 4, 4),
    'network:adaptive_ewma_regular_cadence': (5, 8, 5, 4, 4),
    'network:port_scan_horizontal':    (2, 8, 3, 2, 7),
    'network:dns_recon_spike':         (2, 6, 3, 2, 6),
    'network:lateral_movement_port':   (5, 5, 4, 5, 3),
    # Email
    'email:phishing_lure':             (4, 5, 4, 4, 5),
    'attachment:macro_enabled_office': (5, 5, 5, 4, 4),
}

# Default dimension weights (configurable via DREAD_WEIGHTS_JSON)
_DEFAULT_DIM_WEIGHTS = {
    'damage': 0.30,
    'reproducibility': 0.15,
    'exploitability': 0.25,
    'affected': 0.20,
    'discoverability': 0.10,
}


def _load_dim_weights() -> Dict[str, float]:
    try:
        raw = os.getenv('DREAD_WEIGHTS_JSON')
        if raw:
            w = json.loads(raw)
            if isinstance(w, dict):
                merged = {}
                total = 0.0
                for k in _DEFAULT_DIM_WEIGHTS:
                    v = float(w.get(k, _DEFAULT_DIM_WEIGHTS[k]))
                    merged[k] = v
                    total += v
                if total > 0:
                    return {k: v / total for k, v in merged.items()}
    except Exception:
        pass
    return _DEFAULT_DIM_WEIGHTS


class DREADScoringEngine:
    """Evidence-driven DREAD scoring engine with cloud-native factor support.

    Inputs:
      - artifact: dict with fields like 'source_ip','destination_ports','business_tier',
                  'factors' (list of factor strings from the pipeline)
      - factors: list of structured factor dicts (tool_fingerprint, vuln_matches, etc.)

    Factor strings (e.g. 'cloud:admin_role_assumed', 'credential_access') are mapped
    to per-dimension deltas so every pipeline source — including CloudTrail, GuardDuty,
    Azure Activity Log, Macie, and email — contributes evidence to each dimension.

    Returns dict: damage, reproducibility, exploitability, affected, discoverability,
                  composite (weighted), evidence (per-dim rationale strings).
    """

    CRITICAL_PORTS = {22, 23, 445, 3389, 1433, 3306}

    def __init__(self, config: Dict[str, Any] | None = None, cmdb_client: Optional[BaseCMDBClient] = None):
        self.config = config or {}
        self.cmdb = cmdb_client

    def score(self, artifact: Dict[str, Any], factors: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        if factors is None:
            factors = []

        # ---- Collect factor strings from both pipeline formats ----
        # Format A: list of dicts with 'name'/'type' keys (structured pipeline)
        # Format B: list of raw strings (factor_taxonomy / insights_endpoints path)
        factor_strings: List[str] = []
        for f in (artifact.get('factors') or []):
            if isinstance(f, str):
                factor_strings.append(f.lower())
        for f in factors:
            if isinstance(f, str):
                factor_strings.append(f.lower())
            elif isinstance(f, dict):
                name = f.get('name') or f.get('type') or ''
                if name:
                    factor_strings.append(str(name).lower())
        factor_str_set = set(factor_strings)

        # Per-dimension accumulators: (score, evidence_list)
        dmg_pts, rep_pts, exp_pts, aff_pts, dis_pts = 1, 1, 1, 1, 1
        evidence: Dict[str, List[str]] = {k: [] for k in ('damage', 'reproducibility', 'exploitability', 'affected', 'discoverability')}

        # ---- Cloud-native factor deltas ----
        for factor_key, deltas in _CLOUD_FACTOR_DELTAS.items():
            # Support both exact match and factor strings containing the key
            matched = factor_key in factor_str_set or any(factor_key in fs for fs in factor_strings)
            if matched:
                d, r, e, a, di = deltas
                dmg_pts = min(10, dmg_pts + d)
                rep_pts = min(10, rep_pts + r)
                exp_pts = min(10, exp_pts + e)
                aff_pts = min(10, aff_pts + a)
                dis_pts = min(10, dis_pts + di)
                label = factor_key.replace('_', ' ').replace(':', ': ')
                if d >= 4:
                    evidence['damage'].append(label)
                if a >= 4:
                    evidence['affected'].append(label)
                if e >= 4:
                    evidence['exploitability'].append(label)

        # ---- Network / infrastructure evidence ----
        ports = set(artifact.get('destination_ports') or [])
        if ports & self.CRITICAL_PORTS:
            dmg_pts = min(10, dmg_pts + 4)
            evidence['damage'].append(f'critical ports: {sorted(ports & self.CRITICAL_PORTS)}')

        biz = (artifact.get('business_tier') or '').lower()
        highest_asset_criticality = None
        if self.cmdb and artifact.get('destination_ips'):
            for ip in (artifact.get('destination_ips') or []):
                try:
                    rec = None
                    try:
                        rec = self.cmdb.lookup(ip=ip)  # type: ignore
                    except TypeError:
                        rec = self.cmdb.lookup(ip)
                    if rec and getattr(rec, 'criticality', None) is not None:
                        c = float(getattr(rec, 'criticality'))
                        if highest_asset_criticality is None or c > highest_asset_criticality:
                            highest_asset_criticality = c
                            if c >= 8.0:
                                biz = 'critical'
                            elif c >= 6.0:
                                biz = 'high'
                            elif c >= 4.0:
                                biz = 'medium'
                except Exception:
                    pass
        if biz in ('high', 'critical'):
            dmg_pts = min(10, dmg_pts + 3)
            aff_pts = min(10, aff_pts + 3)
            evidence['damage'].append(f'asset tier: {biz}')
            evidence['affected'].append(f'asset tier: {biz}')
        if highest_asset_criticality is not None:
            extra = int(min(3, max(0, (highest_asset_criticality - 5.0) / 1.5)))
            dmg_pts = min(10, dmg_pts + extra)
            evidence['damage'].append(f'CMDB criticality {highest_asset_criticality:.1f}/10')

        # ---- CVE / vuln evidence ----
        vuln_matches = _safe_get_factor(factors, 'vulnerability_matches') or []
        if vuln_matches:
            high_cves = [v for v in vuln_matches if (v.get('cvss') or 0) >= 7.0]
            if high_cves:
                dmg_pts = min(10, dmg_pts + min(3, len(high_cves)))
                cve_ids = ', '.join(v.get('cve_id', 'CVE-??') for v in high_cves[:3])
                evidence['damage'].append(f'{len(high_cves)} high-CVSS CVE(s): {cve_ids}')
            exploit_avail = any(v.get('exploit_available') for v in vuln_matches)
            if exploit_avail:
                exp_pts = min(10, exp_pts + 5)
                evidence['exploitability'].append('public exploit available')
            avg_cvss = sum((v.get('cvss') or 0) for v in vuln_matches) / max(1, len(vuln_matches))
            if avg_cvss >= 7.0:
                exp_pts = min(10, exp_pts + 3)
                evidence['exploitability'].append(f'avg CVSS {avg_cvss:.1f}')
        if _safe_get_factor(factors, 'prior_exploit_count'):
            exp_pts = min(10, exp_pts + 2)
            evidence['exploitability'].append('prior exploitation observed')

        # ---- Reproducibility evidence ----
        asn_cat = _safe_get_factor(factors, 'asn_category') or _safe_get_factor(factors, 'asn') or ''
        if asn_cat in ('residential', 'static'):
            rep_pts = min(10, rep_pts + 3)
            evidence['reproducibility'].append(f'source ASN: {asn_cat}')
        tool = _safe_get_factor(factors, 'tool_fingerprint') or ''
        if tool and 'masscan' in str(tool).lower():
            rep_pts = min(10, rep_pts + 2)
            evidence['reproducibility'].append('masscan fingerprint')

        # ---- Affected users evidence ----
        hosts = artifact.get('destination_ips') or []
        if len(hosts) > 50:
            aff_pts = min(10, aff_pts + 4)
            evidence['affected'].append(f'{len(hosts)} destination hosts')
        elif len(hosts) > 10:
            aff_pts = min(10, aff_pts + 2)
            evidence['affected'].append(f'{len(hosts)} destination hosts')
        if highest_asset_criticality is not None and highest_asset_criticality >= 8.0:
            aff_pts = min(10, aff_pts + 2)
            evidence['affected'].append('high-criticality asset')

        # ---- Discoverability evidence ----
        if _safe_get_factor(factors, 'public_dns'):
            dis_pts = min(10, dis_pts + 3)
            evidence['discoverability'].append('public DNS record')
        if _safe_get_factor(factors, 'public_facing'):
            dis_pts = min(10, dis_pts + 3)
            evidence['discoverability'].append('externally reachable')
        scan_pattern = _safe_get_factor(factors, 'scan_pattern') or ''
        if 'sequential' in str(scan_pattern).lower():
            dis_pts = min(10, dis_pts + 2)
            evidence['discoverability'].append('sequential scan pattern')

        # ---- Weighted composite ----
        w = _load_dim_weights()
        composite = round(
            dmg_pts * w['damage']
            + rep_pts * w['reproducibility']
            + exp_pts * w['exploitability']
            + aff_pts * w['affected']
            + dis_pts * w['discoverability'],
            2,
        )

        return {
            'damage': dmg_pts,
            'reproducibility': rep_pts,
            'exploitability': exp_pts,
            'affected': aff_pts,
            'discoverability': dis_pts,
            'composite': composite,
            'weights': w,
            'evidence': {k: v for k, v in evidence.items() if v},
        }


def compute_dread(artifact: Dict[str, Any], factors: List[Dict[str, Any]] | None = None, cmdb_client: Optional[BaseCMDBClient] = None) -> Dict[str, Any]:
    engine = DREADScoringEngine(cmdb_client=cmdb_client)
    return engine.score(artifact, factors)


def severity_from_dread(composite: float, thresholds: Dict[str, float] | None = None) -> str:
    """Map composite DREAD score to severity label.

    thresholds example: {'critical':8.0,'high':6.0,'medium':4.0}
    """
    if thresholds is None:
        thresholds = {
            'critical': float(os.getenv('DREAD_CRITICAL_THRESHOLD','8.0')),
            'high': float(os.getenv('DREAD_HIGH_THRESHOLD','6.0')),
            'medium': float(os.getenv('DREAD_MEDIUM_THRESHOLD','4.0')),
        }
    try:
        if composite >= thresholds.get('critical', 8.0):
            return 'critical'
        if composite >= thresholds.get('high', 6.0):
            return 'high'
        if composite >= thresholds.get('medium', 4.0):
            return 'medium'
    except Exception:
        pass
    return 'low'
