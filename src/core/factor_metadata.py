"""Canonical mapping from factor keys to metadata (MITRE, STRIDE, CVSS/KEV tags, playbook hints).

This module provides a curated set of factor definitions used by the HopGraph
frontend and scoring engine. Each entry attempts to map the factor to known
frameworks (MITRE, STRIDE) and provides operational playbook hints.
"""
from typing import Dict, Any, List

# Canonical domain taxonomy (9-domain canonical mapping)
DOMAIN_TAXONOMY: List[str] = [
    'identity', 'endpoint', 'network', 'data', 'cloud', 'email', 'application', 'remote', 'api/app'
]

FACTOR_METADATA: Dict[str, Dict[str, Any]] = {
    # Network domain
    'net_beaconing_periodic': {
        'name': 'Network Beaconing (Periodic)',
        'domain': 'network',
        'weight': 0.85,
        'mitre': ['T1071.001', 'T1095'],
        'stride': ['availability', 'repudiation'],
        'cvss': None,
        'dread': {'damage': 8, 'repro': 6, 'exploit': 7, 'affected': 6, 'discoverability': 7},
        'maestro': ['C2.Beaconing'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:AC-19','CIS:5.2'],
        'tags': ['c2','network','beaconing'],
        'playbook_hints': ['investigate outbound connections', 'correlate with known C2 domains', 'collect pcap for session analysis'],
        'description': 'Periodic or regular connections to external hosts indicative of C2 beaconing.'
    },
    'nxdomain_rate_high': {
        'name': 'High NXDOMAIN Rate',
        'domain': 'network',
        'weight': 0.7,
        'mitre': ['T1566'],
        'stride': ['information_disclosure'],
        'cvss': None,
        'dread': {'damage': 6,'repro':5,'exploit':5,'affected':4,'discoverability':6},
        'maestro': ['Exfil.DNS'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:SI-4'],
        'tags': ['dns','exfil','nxdomain'],
        'playbook_hints': ['check for data exfiltration via DNS', 'inspect length/patterns of queries'],
        'description': 'A spike in NXDOMAIN responses which can indicate DNS-based exfiltration or misconfiguration.'
    },
    'dns_exfil': {
        'name': 'DNS Exfiltration Signature',
        'domain': 'network',
        'weight': 0.9,
        'mitre': ['T1041'],
        'stride': ['confidentiality'],
        'cvss': None,
        'dread': {'damage':9,'repro':5,'exploit':7,'affected':8,'discoverability':6},
        'maestro': ['Exfil.DNS'],
        'pasta': [],
        'epss': None,
        'kev': None,
        'mapped_controls': ['NIST:AC-4'],
        'tags': ['dns','exfil'],
        'playbook_hints': ['extract DNS payload patterns', 'cross-check with user data access patterns'],
        'description': 'Indicators consistent with data being exfiltrated over DNS channels.'
    },

    # Endpoint domain
    'file_hash_rarity': {
        'name': 'Rare File Hash',
        'domain': 'endpoint',
        'weight': 0.6,
        'mitre': ['T1204'],
        'stride': ['repudiation'],
        'cvss': None,
        'dread': {'damage':5,'repro':5,'exploit':4,'affected':3,'discoverability':5},
        'maestro': ['File.Rarity'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['CIS:2.3'],
        'tags': ['file','rarity'],
        'playbook_hints': ['verify file origin', 'query threat intel for hash'],
        'description': 'A file hash not seen previously in the environment or common repositories.'
    },
    'file_signature_mismatch': {
        'name': 'File Signature Mismatch',
        'domain': 'endpoint',
        'weight': 0.8,
        'mitre': ['T1036'],
        'stride': ['tampering'],
        'cvss': None,
        'dread': {'damage':7,'repro':6,'exploit':6,'affected':5,'discoverability':6},
        'maestro': ['File.SignatureMismatch'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:SI-7'],
        'tags': ['file','signature','tampering'],
        'playbook_hints': ['check code signing cert chain', 'verify vendor presence'],
        'description': 'Executable or library signature does not match expected vendor signature.'
    },
    'file_high_entropy': {
        'name': 'High Entropy File',
        'domain': 'endpoint',
        'weight': 0.65,
        'mitre': ['T1005'],
        'stride': ['confidentiality'],
        'cvss': None,
        'dread': {'damage':6,'repro':4,'exploit':5,'affected':4,'discoverability':5},
        'maestro': ['File.EncodedPayload'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['CIS:3.4'],
        'tags': ['file','entropy'],
        'playbook_hints': ['examine file for packing/encryption', 'run sandbox analysis'],
        'description': 'File contents exhibit high entropy suggesting packing or embedded encrypted payloads.'
    },
    'suspicious_process_spawn': {
        'name': 'Suspicious Process Spawn',
        'domain': 'endpoint',
        'weight': 0.7,
        'mitre': ['T1055','T1543'],
        'stride': ['tampering'],
        'cvss': None,
        'dread': {'damage':7,'repro':6,'exploit':6,'affected':5,'discoverability':6},
        'maestro': ['Process.SuspiciousSpawn'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:CM-7'],
        'tags': ['process','behavior'],
        'playbook_hints': ['capture parent/child chain', 'collect command line and binary'],
        'description': 'Child process spawned in unusual context or by uncommon parent process.'
    },

    # Identity domain
    'privilege_change': {
        'name': 'Privilege Change / Escalation',
        'domain': 'identity',
        'weight': 0.9,
        'mitre': ['T1078','T1098'],
        'stride': ['elevation'],
        'cvss': None,
        'dread': {'damage':9,'repro':6,'exploit':7,'affected':8,'discoverability':6},
        'maestro': ['Identity.PrivilegeEscalation'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:AC-2','CIS:5.1'],
        'tags': ['privilege','iam'],
        'playbook_hints': ['audit recent privilege grants', 'check for service account misuse'],
        'description': 'Changes to account privileges or role assignments outside expected workflows.'
    },
    'time_of_day_anomaly': {
        'name': 'Anomalous Time-of-Day Activity',
        'domain': 'identity',
        'weight': 0.5,
        'mitre': [],
        'stride': ['repudiation'],
        'cvss': None,
        'dread': {'damage':5,'repro':4,'exploit':4,'affected':3,'discoverability':5},
        'maestro': ['Behavior.TimeAnomaly'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:AU-6'],
        'tags': ['temporal','behavior'],
        'playbook_hints': ['correlate with user travel/status', 'verify MFA history'],
        'description': 'Activity observed at unusual hours for a user or system account.'
    },

    # Data domain
    'mapping_semantics': {
        'name': 'Mapping Semantics Coverage',
        'domain': 'data',
        'weight': 0.45,
        'mitre': [],
        'mapped_mitre': [],
        'mapped_controls': ['CIS:1.1','NIST:AC-2'],
        'stride': ['information_disclosure'],
        'tags': ['mapping','data_quality','coverage'],
        'playbook_hints': ['verify canonical mappings','validate user/host/file_hash coverage','enrich missing fields via enrichment pipeline'],
        'description': 'Represents richness and coverage of canonical field mapping across ingested batches.'
    },
    'data_exfil_size_large': {
        'name': 'Large Data Exfiltration Volume',
        'domain': 'data',
        'weight': 0.85,
        'mitre': ['T1041'],
        'stride': ['confidentiality','privacy'],
        'cvss': None,
        'dread': {'damage':9,'repro':5,'exploit':6,'affected':8,'discoverability':6},
        'maestro': ['Exfil.Volume'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:SI-4'],
        'tags': ['exfil','volume','data'],
        'playbook_hints': ['identify sensitive files involved', 'audit recipients/destinations'],
        'description': 'Large transfers of data that may indicate bulk exfiltration.'
    },

    # Cloud domain
    'cloud_metadata_anomaly': {
        'name': 'Cloud Metadata Anomaly',
        'domain': 'cloud',
        'weight': 0.75,
        'mitre': ['T1078'],
        'stride': ['repudiation'],
        'cvss': None,
        'dread': {'damage':7,'repro':5,'exploit':6,'affected':6,'discoverability':5},
        'maestro': ['Cloud.ConfigAnomaly'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['CIS:5.6','NIST:CM-6'],
        'tags': ['cloud','config','iam'],
        'playbook_hints': ['check recent IAM changes','verify instance metadata access patterns'],
        'description': 'Suspicious or unexpected metadata access or configuration changes in cloud resources.'
    },
    'container_escape_suspicious': {
        'name': 'Container Escape / Host Access',
        'domain': 'cloud',
        'weight': 0.9,
        'mitre': ['T1610'],
        'stride': ['tampering'],
        'cvss': None,
        'dread': {'damage':9,'repro':7,'exploit':7,'affected':8,'discoverability':6},
        'maestro': ['Container.Escape'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:SC-7'],
        'tags': ['container','escape','cloud'],
        'playbook_hints': ['isolate node','inspect kernel logs','review container runtime configs'],
        'description': 'Evidence that a containerized workload attempted to access host-level resources.'
    },

    # Email domain
    'suspicious_email_attachment': {
        'name': 'Suspicious Email Attachment',
        'domain': 'email',
        'weight': 0.7,
        'mitre': ['T1566.001'],
        'stride': ['information_disclosure'],
        'cvss': None,
        'dread': {'damage':6,'repro':5,'exploit':6,'affected':5,'discoverability':5},
        'maestro': ['Email.MaliciousAttachment'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:SC-8'],
        'tags': ['email','phishing','attachment'],
        'playbook_hints': ['quarantine attachment','scan with multiple engines','contact recipient for verification'],
        'description': 'Attachments with executable content or suspicious macros arriving via email.'
    },

    # Application / API domain
    'api_abuse_rate': {
        'name': 'API Abuse / High Error Rate',
        'domain': 'api/app',
        'weight': 0.8,
        'mitre': [],
        'stride': ['availability'],
        'cvss': None,
        'dread': {'damage':7,'repro':7,'exploit':8,'affected':6,'discoverability':7},
        'maestro': ['API.Abuse'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:SC-5'],
        'tags': ['api','abuse','rate'],
        'playbook_hints': ['check client auth patterns','rate-limit offenders','inspect request payloads'],
        'description': 'High rate of errors or abusive patterns against an API endpoint indicating automated abuse.'
    },
    'credential_stuffing': {
        'name': 'Credential Stuffing / Brute Force',
        'domain': 'remote',
        'weight': 0.85,
        'mitre': ['T1110'],
        'stride': ['repudiation','elevation'],
        'cvss': None,
        'dread': {'damage':8,'repro':8,'exploit':8,'affected':7,'discoverability':7},
        'maestro': ['Auth.BruteForce'],
        'pasta': [],
        'epss': None,
        'kev': None,
            'pasta_score': None,
            'epss_score': None,
            'kev_tag': None,
        'mapped_controls': ['NIST:IA-5','CIS:4.1'],
        'tags': ['auth','bruteforce','credential_stuffing'],
        'playbook_hints': ['block offending IPs','force password resets for affected accounts','enable MFA'],
        'description': 'Repeated login attempts across accounts or from distributed sources indicating credential stuffing.'
    },
    # IAM
    'iam_impossible_travel': {
        'name': 'Impossible Travel Login',
        'domain': 'identity',
        'weight': 0.8,
        'mitre': ['T1078'],
        'stride': ['spoofing'],
        'cvss': None,
        'dread': {'damage':7,'repro':6,'exploit':6,'affected':6,'discoverability':6},
        'maestro': ['Identity.ImpossibleTravel'],
        'pasta': [],
        'epss': None,
        'kev': None,
        'mapped_controls': ['NIST:AC-2','CIS:16.3'],
        'tags': ['iam','geo','travel'],
        'playbook_hints': ['verify user travel and device posture','enforce step-up MFA','investigate source IP reputation'],
        'description': 'Back-to-back logins from distant geographies requiring unrealistic travel speed.'
    },
    'iam_mfa_bypass': {
        'name': 'MFA Disabled → Login',
        'domain': 'identity',
        'weight': 0.85,
        'mitre': ['T1556'],
        'stride': ['elevation'],
        'cvss': None,
        'dread': {'damage':8,'repro':6,'exploit':7,'affected':7,'discoverability':6},
        'maestro': ['Identity.MFABypass'],
        'pasta': [],
        'epss': None,
        'kev': None,
        'mapped_controls': ['NIST:IA-2','CIS:16.11'],
        'tags': ['iam','mfa','bypass'],
        'playbook_hints': ['re-enable MFA','lock account pending verification','audit recent role grants'],
        'description': 'Observed MFA disable followed by login success in short window.'
    },
    # Email BEC
    'email_bec_auth_fail': {
        'name': 'Email Auth Failures (SPF/DMARC/DKIM)',
        'domain': 'email',
        'weight': 0.6,
        'mitre': ['T1566.003'],
        'stride': ['spoofing'],
        'cvss': None,
        'dread': {'damage':6,'repro':5,'exploit':6,'affected':5,'discoverability':6},
        'maestro': ['Email.AuthFailures'],
        'pasta': [],
        'epss': None,
        'kev': None,
        'mapped_controls': ['NIST:SC-8'],
        'tags': ['email','auth','dmarc','spf','dkim'],
        'playbook_hints': ['quarantine message','validate sender identity','check DMARC policy'],
        'description': 'Message failed one or more authentication checks.'
    },
    'email_bec_lookalike': {
        'name': 'Lookalike Sender Domain',
        'domain': 'email',
        'weight': 0.7,
        'mitre': ['T1566.003'],
        'stride': ['spoofing'],
        'cvss': None,
        'dread': {'damage':7,'repro':5,'exploit':6,'affected':6,'discoverability':6},
        'maestro': ['Email.LookalikeDomain'],
        'pasta': [],
        'epss': None,
        'kev': None,
        'mapped_controls': ['NIST:SC-8'],
        'tags': ['email','lookalike','homoglyph'],
        'playbook_hints': ['contact sender via trusted channel','block domain if malicious','check thread hijack indicators'],
        'description': 'Sender domain top-label closely resembles a known brand — potential impersonation.'
    },
    'email_bec_payroll_change': {
        'name': 'Payroll/Vendor Account Change Intent',
        'domain': 'email',
        'weight': 0.75,
        'mitre': ['T1566.003'],
        'stride': ['spoofing','tampering'],
        'cvss': None,
        'dread': {'damage':8,'repro':6,'exploit':6,'affected':7,'discoverability':6},
        'maestro': ['Email.BECPayroll'],
        'pasta': [],
        'epss': None,
        'kev': None,
        'mapped_controls': ['NIST:SC-8','CIS:8.1'],
        'tags': ['email','bec','financial'],
        'playbook_hints': ['require out-of-band validation','freeze account changes','notify finance team'],
        'description': 'Message content suggests changing bank/routing/payroll details.'
    },
    # Endpoint LOLBins (metainfo for existing signals)
    'endpoint:lolbin_certutil_suspicious': {
        'name': 'Certutil Suspicious Use',
        'domain': 'endpoint',
        'weight': 0.6,
        'mitre': ['T1218'],
        'stride': ['tampering'],
        'cvss': None,
        'dread': {'damage':6,'repro':6,'exploit':6,'affected':5,'discoverability':6},
        'maestro': ['Process.LOLBin'],
        'pasta': [],
        'epss': None,
        'kev': None,
        'mapped_controls': ['NIST:CM-7'],
        'tags': ['lolbin','certutil'],
        'playbook_hints': ['capture command line','check network destinations','block if malicious'],
        'description': 'Certutil used in patterns associated with download/encode operations.'
    },
    'endpoint:lolbin_mshta_remote': {
        'name': 'MSHTA Remote Execution',
        'domain': 'endpoint',
        'weight': 0.65,
        'mitre': ['T1218'],
        'stride': ['tampering'],
        'cvss': None,
        'dread': {'damage':7,'repro':6,'exploit':6,'affected':6,'discoverability':6},
        'maestro': ['Process.LOLBin'],
        'pasta': [],
        'epss': None,
        'kev': None,
        'mapped_controls': ['NIST:CM-7'],
        'tags': ['lolbin','mshta'],
        'playbook_hints': ['collect HTA payload','block URL if malicious'],
        'description': 'MSHTA invoked with remote content indicative of execution via HTA.'
    },
    'endpoint:lolbin_rundll32_inline': {
        'name': 'Rundll32 Inline DLL Execution',
        'domain': 'endpoint',
        'weight': 0.6,
        'mitre': ['T1218'],
        'stride': ['tampering'],
        'cvss': None,
        'dread': {'damage':6,'repro':6,'exploit':6,'affected':5,'discoverability':6},
        'maestro': ['Process.LOLBin'],
        'pasta': [],
        'epss': None,
        'kev': None,
        'mapped_controls': ['NIST:CM-7'],
        'tags': ['lolbin','rundll32'],
        'playbook_hints': ['collect DLL','analyze export function usage'],
        'description': 'Rundll32 executing DLL inline or with suspicious parameters.'
    },
}


def get_metadata_for_factor(name: str) -> Dict[str, Any]:
    if not name:
        return {}
    return FACTOR_METADATA.get(name) or FACTOR_METADATA.get(str(name)) or {}


def list_all_factors() -> Dict[str, Any]:
    """Return an export-friendly copy of the factor taxonomy and metadata."""
    out = []
    for k, v in FACTOR_METADATA.items():
        entry = dict(v)
        entry['id'] = k
        # ensure domain present
        entry.setdefault('domain', 'unknown')
        out.append(entry)
    return {'domains': DOMAIN_TAXONOMY, 'factors': out}


def get_metadata(name: str) -> Dict[str, Any]:
    """Alias for external modules expecting a generic metadata lookup."""
    return get_metadata_for_factor(name)
