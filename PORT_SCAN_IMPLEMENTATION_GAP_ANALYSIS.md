# JanuSec Port Scanning Enhancement - Gap Analysis
## What Exists vs. What's Needed for Production

**Assessment Date:** December 21, 2025
**Reference Document:** janusec-port-scanning-detection-enhancement.md
**Codebase Version:** 0.9.0-pre

---

## EXECUTIVE SUMMARY

The port scanning enhancement document outlines **sophisticated threat correlation capabilities**. Based on codebase analysis, JanuSec has:

- ✅ **Strong foundation:** HopGraph, event pipeline, MITRE mapping, correlation engine
- 🟡 **Partial implementation:** Some threat frameworks, basic scoring, LLM summaries
- ❌ **Missing:** DREAD/PASTA/Diamond Model, automated playbooks, advanced log gap analysis

**Overall Implementation Status: ~40% Complete**

**Critical Gaps for Production:**
1. Multi-framework threat scoring (DREAD, PASTA, Diamond Model)
2. Automated playbook orchestration (SOAR integration)
3. Forensic log gap detection and alerting
4. Enhanced LLM context with kill chain progression
5. Port scan-specific HopGraph schemas

---

## 1. EXISTING CAPABILITIES (What JanuSec Already Has)

### ✅ 1.1 HopGraph Attack Reconstruction (IMPLEMENTED)

**Files:**
- `src/core/graph/hopgraph_lite.py` - Lightweight temporal graph
- `src/core/hunt/hopgraph_light.py` - Hunt sidecar graph
- `src/api/graph_session_endpoints.py` - Session management API

**What's Working:**
```python
# Existing HopGraph node types (from codebase)
NODE_TYPES = [
    "asset",      # ✅ Already exists
    "user",       # ✅ Already exists
    "process",    # ✅ Already exists
    "conn",       # ✅ Network connections
    "technique",  # ✅ MITRE techniques
    "risk"        # ✅ Risk nodes
]

# Existing edge types
EDGE_TYPES = [
    "lateral",    # ✅ Lateral movement
    "exec",       # ✅ Execution chains
    "connects",   # ✅ Network connections
    "invokes",    # ✅ Process invocations
    "maps",       # ✅ Technique mapping
    "relates"     # ✅ General relationships
]
```

**What's Missing (from enhancement doc Section 4):**
```yaml
# NEW node types needed for port scanning
MISSING_NODE_TYPES:
  - PortScanEvent              # ❌ Not implemented
  - ScanSourceInfrastructure   # ❌ Not implemented
  - DiscoveredService          # ❌ Not implemented
  - VulnerabilityMatch         # ❌ Not implemented
  - ExploitationAttempt        # ❌ Not implemented
  - ThreatActor                # ❌ Not implemented

# NEW edge types needed
MISSING_EDGE_TYPES:
  - ORIGINATED_FROM            # ❌ Not implemented
  - TARGETED                   # ❌ Not implemented
  - DISCOVERED                 # ❌ Not implemented
  - HAS_VULNERABILITY          # ❌ Not implemented
  - PRECEDED                   # ❌ Not implemented (key for scan→exploit chains!)
  - ATTRIBUTED_TO              # ❌ Not implemented
  - PART_OF_CAMPAIGN           # ❌ Not implemented
```

**Implementation Gap:**
- **Existing:** Generic graph structure supports custom node/edge types
- **Missing:** Port scan-specific schemas and queries (Section 4.3)
- **Effort:** 2-3 weeks to add schemas + indexing + query optimization

---

### ✅ 1.2 MITRE ATT&CK Mapping (PARTIALLY IMPLEMENTED)

**Files:**
- `src/core/mappings/mitre_stride.py` - MITRE/STRIDE mapping
- `src/artifact/technique_mapping.py` - Technique extraction
- `src/live/rules_engine.py` - Rule-based technique tagging

**What's Working:**
```python
# Existing MITRE techniques mapped (from codebase)
IMPLEMENTED_TECHNIQUES = {
    # Initial Access
    "T1078": "Valid Accounts",
    "T1190": "Exploit Public-Facing Application",

    # Execution
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",

    # Persistence
    "T1547.001": "Registry Run Keys",
    "T1543.003": "Windows Service",

    # Lateral Movement
    "T1021": "Remote Services",

    # (20+ more techniques...)
}
```

**What's Missing (from enhancement doc Section 2.4):**
```yaml
# Port scan-specific MITRE techniques NOT MAPPED
MISSING_TECHNIQUES:
  T1595_active_scanning:
    T1595_001_scanning_ip_blocks:        # ❌ Not implemented
      detection_logic: "Horizontal scan pattern"
      confidence_boosters: ["sequential IPs", "no prior history"]

    T1595_002_vulnerability_scanning:    # ❌ Not implemented
      detection_logic: "Service banner grabbing"
      confidence_boosters: ["HTTP OPTIONS", "known scanner sigs"]

    T1595_003_wordlist_scanning:         # ❌ Not implemented
      detection_logic: "Path enumeration"
      confidence_boosters: ["High 404 rate", "common paths"]

  T1592_gather_victim_host_information:  # ❌ Not implemented
  T1590_gather_victim_network_information: # ❌ Not implemented
```

**Implementation Gap:**
- **Existing:** Generic technique mapping framework
- **Missing:** Reconnaissance-phase techniques (T1595.*)
- **Missing:** Confidence boosters and chain indicators
- **Effort:** 1-2 weeks to add recon techniques + detection logic

---

### ✅ 1.3 Event Pipeline (21 Stages) - MATURE

**Files:**
- `src/core/event_pipeline/pipeline.py` - Main pipeline orchestration
- `src/core/event_pipeline/stages/*.py` - Individual stage implementations

**Existing Pipeline Stages:**
```python
# From codebase analysis
IMPLEMENTED_STAGES = [
    1: "ingestion",               # ✅ Raw event intake
    2: "normalization",           # ✅ Schema standardization
    3: "protocol_decode",         # ✅ Protocol parsing
    4: "enrichment",              # ✅ Basic enrichment
    5: "threat_intel",            # ✅ IP/domain reputation
    6: "deduplication",           # ✅ Event deduplication
    7: "baseline_comparison",     # ✅ Behavioral baseline
    8: "factor_extraction",       # ✅ Detection factors
    9: "confidence_scoring",      # ✅ Confidence calculation
    10: "allowlist_filtering",    # ✅ Whitelist/allowlist
    11: "correlation_engine",     # ✅ Multi-event correlation
    12: "cluster_deduplication",  # ✅ Event clustering
    13: "mitre_mapping",          # ✅ Technique attribution
    14: "risk_scoring",           # ✅ Risk calculation
    15: "decision_routing",       # ✅ Benign/malicious/deep
    16: "factor_synthesis",       # ✅ Factor aggregation
    17: "hopgraph_integration",   # ✅ Graph construction
    18: "llm_triage",             # 🟡 Conditional (needs config)
    19: "playbook_trigger",       # ❌ Stub only
    20: "metrics_emission",       # ✅ Prometheus metrics
    21: "analyst_presentation"    # ✅ Alert formatting
]
```

**Integration Points for Port Scanning (from doc Section 3):**

| Pipeline Stage | Current State | Enhancement Needed |
|----------------|---------------|-------------------|
| **Stage 3: Protocol Decode** | ✅ Working | ⚠️ Add TCP flag analysis (SYN-only, NULL, FIN, XMAS) |
| **Stage 5: Threat Intel** | ✅ Working | ⚠️ Add Diamond Model clustering |
| **Stage 7: Baseline** | ✅ Working | ⚠️ Add legitimate scanner whitelist (Qualys, Tenable) |
| **Stage 11: Correlation** | ✅ Working | ⚠️ Add scan→exploit temporal correlation |
| **Stage 14: Risk Scoring** | ✅ Working | ❌ Add DREAD scoring (completely missing) |
| **Stage 17: HopGraph** | ✅ Working | ❌ Add port scan schemas (Section 4) |
| **Stage 19: Playbooks** | ❌ Stub | ❌ Implement automated playbooks (Section 6) |

**Implementation Gap:**
- **Existing:** Full 21-stage pipeline operational
- **Missing:** Port scan-specific enhancements at key stages
- **Effort:** 3-4 weeks to enhance stages 3, 5, 7, 11, 14, 17, 19

---

### 🟡 1.4 LLM Tier 1/2 Summaries (FRAMEWORK EXISTS, STUBS USED)

**Files:**
- `src/api/llm_tier1.py` - Tier 1 fast summaries
- `src/api/tier2_endpoints.py` - Tier 2 deep analysis
- `src/artifact/llm_refine.py` - LLM refinement logic

**What's Working:**
```python
# Existing LLM framework (from codebase)
class LLMTriage:
    def __init__(self):
        self.enabled = os.getenv("ENABLE_ARTIFACT_LLM", "0") == "1"
        self.endpoint = os.getenv("ARTIFACT_LLM_ENDPOINT")

    async def tier1_summary(self, artifact, factors):
        """Fast 30-second summary"""
        if not self.enabled:
            # ⚠️ Returns deterministic stub
            return self._generate_stub_summary(artifact)

        # ✅ Real LLM call (if configured)
        prompt = self._build_tier1_prompt(artifact, factors)
        return await self._call_llm(prompt)

    async def tier2_analysis(self, artifact, factors, hopgraph_context):
        """Deep 60-90 second analysis"""
        if not self.enabled:
            # ⚠️ Returns template-based analysis
            return self._generate_template_analysis(artifact)

        # ✅ Real LLM call (if configured)
        prompt = self._build_tier2_prompt(artifact, factors, hopgraph_context)
        return await self._call_llm(prompt)
```

**What's Missing for Port Scan Enhancement:**

**Tier 1 Summary Context (Currently Missing):**
```yaml
# From enhancement doc Section 2.4 (Kill Chain Progression)
MISSING_T1_CONTEXT:
  kill_chain_phase:
    current: "Generic threat description"
    needed: "Reconnaissance phase indicator with progression tracking"

  dread_score:
    current: "Not included in prompt"
    needed: "DREAD composite score (D+R+E+A+D)/5 with breakdown"

  diamond_model_cluster:
    current: "Not included"
    needed: "Adversary cluster ID and campaign attribution"

  scan_pattern_motivation:
    current: "Not included"
    needed: "Inferred attacker motivation (ransomware, APT, botnet, etc.)"
```

**Example Current Tier 1 Output (Stub):**
```
"Port scanning activity detected from 203.0.113.5 targeting
multiple internal hosts on common service ports. Risk score: 0.75"
```

**Example Enhanced Tier 1 Output (Needed):**
```
"CRITICAL: Targeted reconnaissance (Kill Chain: Phase 1) from
bulletproof hosting ASN (DREAD: 8.2/10). Attacker scanned 45 hosts
for SMB/RDP (445, 3389), likely ransomware operator based on
pattern matching (confidence: 0.85). Clustered with Campaign #1247
(15 prior scans from same infrastructure). IMMEDIATE ACTION: Block
source ASN, audit exposed services, check for follow-on exploitation."
```

**Tier 2 Deep Analysis Context (Currently Missing):**
```yaml
MISSING_T2_CONTEXT:
  pasta_threat_modeling:
    current: "Not included"
    needed: "Business impact assessment, asset criticality, trust boundaries"

  vulnerability_correlation:
    current: "Basic factor analysis"
    needed: "CVSS-contextualized vuln list for discovered services"

  kill_chain_progression_tracking:
    current: "Not included"
    needed: "Temporal correlation with subsequent attack phases (scan → exploit → install)"

  forensic_log_gaps:
    current: "Not included"
    needed: "Identify missing telemetry for investigation"

  playbook_recommendations:
    current: "Generic recommendations"
    needed: "Specific automated playbook suggestions with confidence"
```

**Implementation Gap:**
- **Existing:** LLM framework operational, multi-provider support
- **Missing:** Context enrichment with kill chain, DREAD, Diamond Model, PASTA
- **Missing:** Prompt engineering for port scan-specific narratives
- **Effort:** 2-3 weeks to enhance prompts + context building

---

### ❌ 1.5 Multi-Framework Threat Scoring (NOT IMPLEMENTED)

**Current State:**
JanuSec has a **basic risk scoring system** but lacks multi-framework integration.

**File:** `src/artifact/risk.py`

**Existing Risk Scoring:**
```python
# Simplified from codebase
def calculate_risk_score(artifact, factors):
    """Basic risk calculation"""
    base_risk = 0.0

    # Factor weighting (simple)
    for factor in factors:
        base_risk += factor.weight * factor.confidence

    # Normalize to 0-1
    return min(base_risk / len(factors), 1.0)
```

**What's Completely Missing (from enhancement doc Section 2):**

#### ❌ DREAD Scoring (Section 2.1)
```yaml
MISSING_DREAD_IMPLEMENTATION:
  damage_potential:
    logic: "Score 1-10 based on critical ports (445, 3389, 22, 1433, 3306)"
    implementation_status: ❌ NOT IMPLEMENTED

  reproducibility:
    logic: "Score based on source IP type (residential proxy, cloud, static)"
    implementation_status: ❌ NOT IMPLEMENTED

  exploitability:
    logic: "Match discovered services to CVE database"
    implementation_status: ❌ NOT IMPLEMENTED

  affected_users:
    logic: "Scope based on asset business tier (DMZ, internal, isolated)"
    implementation_status: ❌ NOT IMPLEMENTED

  discoverability:
    logic: "How easily attacker found target (cert transparency, public DNS)"
    implementation_status: ❌ NOT IMPLEMENTED

  composite_calculation:
    formula: "(D + R + E + A + D) / 5"
    implementation_status: ❌ NOT IMPLEMENTED
```

**Effort to Implement:** 2 weeks (configurable rules engine + CMDB integration)

#### ❌ PASTA Threat Modeling (Section 2.2)
```yaml
MISSING_PASTA_IMPLEMENTATION:
  stage_1_business_objectives:
    task: "Map scanned assets to business criticality tiers"
    current_status: ❌ NOT IMPLEMENTED
    dependency: "CMDB/asset inventory integration"

  stage_2_technical_scope:
    task: "Identify shadow IT (scanned but unknown assets)"
    current_status: ❌ NOT IMPLEMENTED
    query_needed: "MATCH (scan)-[:TARGETED]->(ip) WHERE NOT EXISTS((ip)<-[:OWNS]-(:Asset))"

  stage_3_application_decomposition:
    task: "Map service → application → business process"
    current_status: ❌ NOT IMPLEMENTED
    dependency: "Service dependency mapping database"

  stage_4_threat_analysis:
    task: "Infer attacker motivation from scan patterns"
    current_status: ❌ NOT IMPLEMENTED
    patterns_needed:
      - horizontal_scan_445_3389: "Ransomware operator"
      - vertical_scan_web_db: "Data exfiltration"
      - slow_comprehensive: "APT reconnaissance"
      - iot_ports_scan: "Botnet recruitment"

  stage_5_vulnerability_analysis:
    task: "Match discovered services to vuln database"
    current_status: 🟡 PARTIAL (basic CVE lookup exists)
    missing: "CVSS temporal/environmental scoring"

  stage_6_attack_modeling:
    task: "Build attack trees from scan → exploit → objective"
    current_status: 🟡 PARTIAL (HopGraph exists, needs scan schemas)

  stage_7_risk_mitigation:
    task: "Response priority matrix (DREAD + motivation)"
    current_status: ❌ NOT IMPLEMENTED
```

**Effort to Implement:** 4-6 weeks (requires CMDB integration, service mapping, motivation inference ML)

#### ❌ Diamond Model Adversary Profiling (Section 2.3)
```yaml
MISSING_DIAMOND_MODEL_IMPLEMENTATION:
  adversary_vertex:
    attribution_signals:
      - "ASN ownership patterns"                    # ❌ NOT IMPLEMENTED
      - "Historical IP reputation"                   # 🟡 PARTIAL (basic threat intel)
      - "Scan timing patterns (timezone inference)"  # ❌ NOT IMPLEMENTED
    clustering_features:
      - asn_category: ["bulletproof", "cloud", "research"]  # ❌ NOT IMPLEMENTED
      - historical_threat_intel: ["known_apt", "ransomware"]  # ❌ NOT IMPLEMENTED
      - operational_timezone: "utc_offset_inferred"  # ❌ NOT IMPLEMENTED

  capability_vertex:
    scan_sophistication_indicators:
      low: "Sequential IP, default nmap timing"      # ❌ NOT IMPLEMENTED
      medium: "Randomized ports, distributed sources"  # ❌ NOT IMPLEMENTED
      high: "Slow-and-low, decoy injection, fragmented"  # ❌ NOT IMPLEMENTED

  infrastructure_vertex:
    source_infrastructure_profiling:
      enrichment_sources:
        - "MaxMind/IP2Location"                      # 🟡 PARTIAL (basic geo)
        - "Shodan/Censys characterization"           # ❌ NOT IMPLEMENTED
        - "Passive DNS associations"                 # ❌ NOT IMPLEMENTED
        - "TOR exit node lists"                      # ❌ NOT IMPLEMENTED
        - "Proxy/VPN provider ranges"                # ❌ NOT IMPLEMENTED

  campaign_clustering:
    algorithm: "DBSCAN on feature vectors"           # ❌ NOT IMPLEMENTED
    features: ["asn_category", "scan_pattern", "target_industry", "timing"]
    output: "campaign_id for correlated scans"       # ❌ NOT IMPLEMENTED
```

**Effort to Implement:** 6-8 weeks (ML clustering, extensive enrichment, pattern analysis)

#### 🟡 CVSS Contextualization (Section 2.5) - PARTIAL
```yaml
CVSS_IMPLEMENTATION_STATUS:
  step_1_service_identification:
    status: 🟡 PARTIAL
    current: "Basic port → service mapping exists"
    missing: "Banner grabbing and version detection"

  step_2_vulnerability_lookup:
    status: 🟡 PARTIAL
    current: "CVE lookup via NVD API exists"
    missing: "Batch querying, caching, performance optimization"

  step_3_cvss_enrichment:
    base_score: ✅ IMPLEMENTED (from NVD)
    temporal_score:
      exploit_code_maturity: ❌ NOT IMPLEMENTED
      remediation_level: ❌ NOT IMPLEMENTED
    environmental_score:
      asset_criticality: ❌ NOT IMPLEMENTED (needs CMDB)
      exposure_context: ❌ NOT IMPLEMENTED

  prioritization_formula:
    composite: ❌ NOT IMPLEMENTED
    needed: "priority = cvss_base*0.4 + temporal*0.3 + environmental*0.2 + dread*0.1"
```

**Effort to Implement:** 3-4 weeks (temporal/environmental scoring + CMDB integration)

#### ❌ Cyber Kill Chain Correlation (Section 2.6)
```yaml
KILL_CHAIN_CORRELATION_STATUS:
  reconnaissance:
    detection_sources: ✅ IMPLEMENTED (firewall, netflow, IDS)
    correlation_signals: ❌ NOT IMPLEMENTED
      - "OSINT domain enumeration → port scan timing"
      - "Cert transparency hits → scan targeting new subdomains"
    hopgraph_node_type: ❌ "ReconEvent" not created

  weaponization:
    proxy_indicators: ❌ NOT IMPLEMENTED
      - "Lookalike domain registration post-scan"
      - "Phishing infrastructure setup"

  delivery:
    correlation_logic: ❌ NOT IMPLEMENTED
      - "Scan discovered email server → phishing campaign"
      - "Scan discovered VPN → credential spray"
    time_window: "24h-30d post-scan" (not tracked)

  exploitation:
    correlation_logic: 🟡 PARTIAL
      same_source: ✅ Can correlate same IP
      same_asn: ❌ NOT IMPLEMENTED
      same_target: ✅ Can correlate same service
    hopgraph_edge: ❌ "ENABLES_EXPLOITATION" not created

  full_chain_tracking:
    path: "(scan)-[:PRECEDES]->(exploit)-[:LEADS_TO]->(install)"
    status: ❌ NOT IMPLEMENTED (needs PRECEDED edge type)
```

**Effort to Implement:** 4-5 weeks (temporal correlation, edge types, time-bounded queries)

---

### ❌ 1.6 Automated Playbook Orchestration (STUB ONLY)

**File:** `src/api/playbook_executor.py`, `src/soar/playbook_engine.py`

**Current State:**
```python
# From codebase - playbook executor is a stub
class PlaybookExecutor:
    async def execute_playbook(self, playbook_id, context):
        """
        Execute automated response playbook.

        TODO: Implement SOAR integration
        """
        logger.info(f"Playbook {playbook_id} triggered (not implemented)")
        return {"status": "stub", "message": "Playbook execution not implemented"}
```

**What's Missing (from enhancement doc Section 6):**

#### ❌ External Port Scan Playbook (Section 6.1)
```yaml
PLAYBOOK_IMPLEMENTATION_STATUS:
  stage_1_initial_triage:
    automated_actions:
      - enrich_source_ip:           ❌ NOT AUTOMATED
      - calculate_dread_score:      ❌ NOT IMPLEMENTED
      - diamond_model_cluster:      ❌ NOT IMPLEMENTED
      - check_whitelist:            ✅ IMPLEMENTED (manual)
    decision_logic:
      - escalate_based_on_dread:    ❌ NOT IMPLEMENTED

  stage_2_correlation:
    automated_actions:
      - search_historical_scans:    🟡 MANUAL QUERY POSSIBLE
      - check_subsequent_activity:  ❌ NOT AUTOMATED
      - identify_discovered_services: ❌ NOT AUTOMATED
      - vulnerability_correlation:  🟡 PARTIAL
      - build_hopgraph:             🟡 HAPPENS, NOT PLAYBOOK-DRIVEN

  stage_3_response:
    automated_actions:
      - create_block_recommendation: ❌ NOT IMPLEMENTED
      - notify_asset_owners:         ❌ NOT IMPLEMENTED
      - create_patch_ticket:         ❌ NOT IMPLEMENTED
      - update_mitre_navigator:      ❌ NOT IMPLEMENTED

  stage_4_closure:
    automated_actions:
      - document_investigation:      ❌ NOT AUTOMATED
      - update_threat_intel:         ❌ NOT IMPLEMENTED
      - calculate_metrics:           🟡 PARTIAL (manual)
```

**SOAR Integration Missing:**
- No integration with PagerDuty, Tines, Cortex XSOAR, Phantom
- No webhook/API clients for external ticketing systems
- No approval workflow engine
- No playbook state machine

**Effort to Implement:** 6-8 weeks (SOAR integration framework + playbook engine)

---

### ❌ 1.7 Forensic Log Gap Analysis (NOT IMPLEMENTED)

**Current State:**
JanuSec has **coverage tracking** but not **gap detection and alerting**.

**File:** `src/core/coverage_tracker.py`

**What Exists:**
```python
# From codebase
class CoverageTracker:
    """Tracks which alert types have been seen at least once."""

    def __init__(self):
        self.seen_alert_types = set()

    def record_coverage(self, alert_type):
        """Mark alert type as seen."""
        self.seen_alert_types.add(alert_type)

    def get_coverage_ratio(self):
        """Calculate ratio of seen vs. expected alert types."""
        expected = len(TARGET_ALERT_TYPES)
        seen = len(self.seen_alert_types)
        return seen / expected
```

**What's Missing (from enhancement doc Section 5):**

#### ❌ Required Log Sources Matrix (Section 5.1)
```yaml
LOG_GAP_DETECTION_MISSING:
  tier_1_essential:
    firewall_logs:
      status: ✅ Can ingest (if provided)
      gap_detection: ❌ NOT IMPLEMENTED
      alerting: ❌ "No firewall logs in 1 hour" alert missing

    dns_query_logs:
      status: ✅ Can ingest
      gap_detection: ❌ NOT IMPLEMENTED

    netflow_ipfix:
      status: ✅ Can ingest
      gap_detection: ❌ NOT IMPLEMENTED

  tier_2_enhanced:
    ids_ips_alerts:
      status: ✅ Can ingest (Suricata/Snort)
      gap_detection: ❌ NOT IMPLEMENTED

    web_server_access_logs:
      status: ✅ Can ingest
      gap_detection: ❌ NOT IMPLEMENTED

  gap_alerting_framework:
    heartbeat_monitoring: ❌ NOT IMPLEMENTED
      - "Detect when expected log source stops sending"
      - "Alert after configurable time window (e.g., no DNS logs in 1 hour)"

    coverage_gap_dashboard: ❌ NOT IMPLEMENTED
      - "Visual dashboard showing missing log sources"
      - "Per-tenant gap tracking"

    soar_integration: ❌ NOT IMPLEMENTED
      - "Auto-create ticket when critical log source missing"
```

**What's Needed:**
```python
# Proposed implementation
class ForensicLogGapDetector:
    """Detect and alert on missing log sources."""

    EXPECTED_SOURCES = {
        "tier_1_essential": [
            {"name": "firewall_logs", "max_gap_seconds": 3600, "severity": "critical"},
            {"name": "dns_query_logs", "max_gap_seconds": 3600, "severity": "critical"},
            {"name": "netflow", "max_gap_seconds": 1800, "severity": "high"}
        ],
        "tier_2_enhanced": [
            {"name": "ids_alerts", "max_gap_seconds": 7200, "severity": "medium"},
            {"name": "web_access_logs", "max_gap_seconds": 3600, "severity": "medium"}
        ]
    }

    async def check_log_gaps(self, tenant_id):
        """Check for missing log sources and generate alerts."""
        gaps = []

        for source in self.EXPECTED_SOURCES["tier_1_essential"]:
            last_seen = await self._get_last_log_time(tenant_id, source["name"])
            time_since = (datetime.utcnow() - last_seen).total_seconds()

            if time_since > source["max_gap_seconds"]:
                gaps.append({
                    "source": source["name"],
                    "severity": source["severity"],
                    "time_since_last_log": time_since,
                    "impact": self._get_gap_impact(source["name"])
                })

        if gaps:
            await self._generate_gap_alerts(gaps)

        return gaps

    def _get_gap_impact(self, source_name):
        """Return impact statement for missing log source."""
        IMPACTS = {
            "firewall_logs": "Cannot detect external reconnaissance or port scanning",
            "dns_query_logs": "Miss pre-scan DNS enumeration and C2 communication",
            "netflow": "Cannot detect slow-and-low scans or distributed attacks"
        }
        return IMPACTS.get(source_name, "Unknown impact")
```

**Effort to Implement:** 2-3 weeks (heartbeat monitoring + alerting + dashboard)

---

## 2. IMPLEMENTATION PRIORITY MATRIX

### 🎯 Critical for Port Scan Detection (Phase 1: 4-6 Weeks)

| Feature | Current Status | Effort | Priority | Files to Create/Modify |
|---------|---------------|--------|----------|------------------------|
| **HopGraph Port Scan Schemas** | ❌ Missing | 2 weeks | P0 | `src/core/graph/schemas/port_scan.py` |
| **DREAD Scoring Engine** | ❌ Missing | 2 weeks | P0 | `src/core/scoring/dread_engine.py` |
| **MITRE T1595.* Techniques** | ❌ Missing | 1 week | P0 | `src/core/mappings/mitre_recon.py` |
| **Kill Chain Phase Tracking** | ❌ Missing | 2 weeks | P0 | `src/core/kill_chain/phase_tracker.py` |
| **Scan→Exploit Correlation** | 🟡 Partial | 2 weeks | P0 | `src/core/correlation/scan_exploit_chain.py` |

**Phase 1 Deliverables:**
- Port scans create proper HopGraph nodes/edges
- DREAD score displayed on all scan alerts
- MITRE reconnaissance techniques auto-tagged
- Kill chain phase indicator in alerts
- Scan→exploit chains automatically detected

---

### 🔧 Important for Enhanced Detection (Phase 2: 6-8 Weeks)

| Feature | Current Status | Effort | Priority | Files to Create/Modify |
|---------|---------------|--------|----------|------------------------|
| **Diamond Model Clustering** | ❌ Missing | 4 weeks | P1 | `src/analytics/diamond_model_clustering.py` |
| **PASTA Threat Modeling** | ❌ Missing | 4 weeks | P1 | `src/core/threat_modeling/pasta_engine.py` |
| **CVSS Contextualization** | 🟡 Partial | 3 weeks | P1 | `src/integrations/cvss_enrichment.py` |
| **Enhanced LLM Context** | 🟡 Partial | 2 weeks | P1 | `src/ai/llm_prompts.py` (enhance) |
| **Forensic Log Gap Detection** | ❌ Missing | 3 weeks | P1 | `src/monitoring/log_gap_detector.py` |

**Phase 2 Deliverables:**
- Scan campaigns clustered by adversary infrastructure
- Business impact assessment for scanned assets
- Vulnerability prioritization with CVSS composite scores
- LLM summaries include kill chain, DREAD, motivation
- Alerts when critical log sources go silent

---

### 🚀 Advanced Capabilities (Phase 3: 6-8 Weeks)

| Feature | Current Status | Effort | Priority | Files to Create/Modify |
|---------|---------------|--------|----------|------------------------|
| **Automated Playbook Engine** | ❌ Stub | 6 weeks | P2 | `src/soar/playbook_executor.py` (rewrite) |
| **SOAR Integrations** | ❌ Missing | 4 weeks | P2 | `src/integrations/soar/*.py` |
| **Scan Tool Fingerprinting** | ❌ Missing | 3 weeks | P2 | `src/analytics/scan_tool_fingerprint.py` |
| **Certificate Transparency Monitoring** | ❌ Missing | 2 weeks | P2 | `src/collectors/cert_transparency.py` |
| **Honeypot Integration** | ❌ Missing | 3 weeks | P2 | `src/integrations/honeypot_client.py` |

**Phase 3 Deliverables:**
- Automated response workflows (block, notify, ticket creation)
- Integration with PagerDuty, Tines, Cortex XSOAR
- Detection of nmap vs. Nessus vs. Masscan vs. custom tools
- Early warning from CT log new cert registrations
- High-confidence targeting from honeypot hits

---

## 3. ENHANCED LLM SUMMARY IMPLEMENTATION

### Current LLM Prompt (Simplified from Codebase)

```python
# src/artifact/llm_refine.py (current)
def build_tier1_prompt(artifact, factors):
    """Build basic Tier 1 prompt."""

    factor_summary = "\n".join([
        f"- {f['name']}: {f.get('value', 'N/A')} (confidence: {f.get('confidence', 0):.2f})"
        for f in factors[:5]
    ])

    prompt = f"""You are a cybersecurity analyst. Provide a 2-3 sentence summary.

Artifact Type: {artifact.get('type')}
Risk Score: {artifact.get('risk_score', 0):.2f}
Verdict: {artifact.get('verdict', 'UNKNOWN')}

Top Factors:
{factor_summary}

Task: Explain what was detected, why it's suspicious, and recommended action.
Keep under 100 words.
"""
    return prompt
```

### Enhanced Tier 1 Prompt (Port Scan-Specific)

```python
# src/ai/llm_prompts.py (ENHANCED VERSION NEEDED)
class EnhancedPortScanPromptBuilder:
    """Build context-rich prompts for port scan analysis."""

    @staticmethod
    def build_tier1_port_scan_prompt(
        scan_event,
        factors,
        dread_score,           # ← NEW
        kill_chain_phase,      # ← NEW
        diamond_cluster,       # ← NEW
        inferred_motivation,   # ← NEW
        subsequent_activity    # ← NEW
    ):
        """Build enhanced Tier 1 prompt with kill chain context."""

        # Format DREAD breakdown
        dread_breakdown = f"""
DREAD Score: {dread_score['composite']:.1f}/10
  - Damage Potential: {dread_score['damage']}/10 ({dread_score['damage_rationale']})
  - Reproducibility: {dread_score['reproducibility']}/10
  - Exploitability: {dread_score['exploitability']}/10
  - Affected Users: {dread_score['affected']}/10
  - Discoverability: {dread_score['discoverability']}/10
"""

        # Format kill chain context
        kill_chain_context = f"""
Cyber Kill Chain Phase: {kill_chain_phase} (Reconnaissance)
Progression Indicators:
  - Scan detected at: {scan_event['detection_time']}
  - Subsequent activity: {subsequent_activity.get('summary', 'None detected yet')}
  - Time to exploitation (if any): {subsequent_activity.get('time_to_exploit', 'N/A')}
"""

        # Format adversary context
        adversary_context = f"""
Adversary Profiling (Diamond Model):
  - Source Infrastructure: {diamond_cluster['infrastructure_type']} ({diamond_cluster['asn_name']})
  - Adversary Cluster: {diamond_cluster['cluster_id']} ({diamond_cluster['cluster_size']} related scans)
  - Inferred Motivation: {inferred_motivation['primary']} (confidence: {inferred_motivation['confidence']:.0%})
  - Sophistication: {diamond_cluster['sophistication_level']}
"""

        # Format threat intel
        threat_intel = scan_event.get('threat_intel_tags', [])
        threat_context = f"Threat Intel: {', '.join(threat_intel) if threat_intel else 'No matches'}"

        # Format target context
        target_context = f"""
Target Analysis:
  - Hosts scanned: {len(scan_event['destination_ips'])}
  - Ports targeted: {len(scan_event['destination_ports'])} ({', '.join(map(str, scan_event['destination_ports'][:10]))})
  - Business Impact: {scan_event.get('business_tier', 'Unknown')} tier assets
  - Critical services exposed: {scan_event.get('critical_services_found', 'None')}
"""

        prompt = f"""You are a senior SOC analyst providing a CRITICAL ALERT SUMMARY for Tier 1 triage.

PORT SCAN DETECTION:

{dread_breakdown}

{kill_chain_context}

{adversary_context}

{threat_context}

{target_context}

TASK: Provide a 3-4 sentence summary covering:
1. SEVERITY: Why this is critical/high/medium (reference DREAD score)
2. THREAT: What type of attacker this likely is (reference motivation)
3. RISK: What could happen next (reference kill chain phase)
4. ACTION: Immediate recommended response (specific, actionable)

Write for a Tier 1 analyst who needs to decide: escalate immediately, investigate further, or close as benign.
Keep under 150 words. Use CLEAR, DIRECT language.
"""
        return prompt
```

### Enhanced Tier 2 Prompt (Deep Analysis)

```python
@staticmethod
def build_tier2_port_scan_prompt(
    scan_event,
    all_factors,
    hopgraph_chains,
    vulnerability_matches,
    pasta_business_context,    # ← NEW
    kill_chain_full_analysis,  # ← NEW
    forensic_log_gaps          # ← NEW
):
    """Build comprehensive Tier 2 deep analysis prompt."""

    # ... (similar structure but with much more context)

    prompt = f"""You are a Tier 3 threat analyst conducting IN-DEPTH investigation.

INCIDENT OVERVIEW:
{scan_summary}

COMPLETE DREAD ANALYSIS:
{dread_full_breakdown}

PASTA THREAT MODELING:
Stage 1 - Business Objectives:
  - Assets scanned: {pasta_business_context['asset_criticality']}
  - Revenue impact if compromised: {pasta_business_context['revenue_impact']}

Stage 2 - Technical Scope:
  - Known assets: {pasta_business_context['known_assets']}
  - Shadow IT detected: {pasta_business_context['shadow_it']}

Stage 3 - Application Decomposition:
  - Service dependencies: {pasta_business_context['service_map']}
  - Trust boundaries at risk: {pasta_business_context['trust_boundaries']}

Stage 4 - Threat Analysis:
  {inferred_threat_analysis}

Stage 5 - Vulnerability Analysis:
  {vulnerability_correlation_analysis}

Stage 6 - Attack Modeling:
  {attack_tree_from_hopgraph}

Stage 7 - Risk Mitigation Priority:
  {mitigation_recommendations}

FULL KILL CHAIN ANALYSIS:
{kill_chain_detailed}

HOPGRAPH ATTACK CHAINS:
{hopgraph_visualizations}

FORENSIC LOG ANALYSIS:
Available Evidence:
  {available_logs_summary}

Log Gaps Identified:
  {forensic_log_gaps}
  ^ These gaps limit investigation scope

TASK: Provide a 400-500 word comprehensive analysis covering:

1. ATTACK NARRATIVE: Tell the complete story from reconnaissance to current state
2. TECHNICAL EVIDENCE: Reference specific factors, HopGraph chains, and vulnerability matches
3. THREAT ACTOR ASSESSMENT: Analyze sophistication, motivation, likely next steps
4. BUSINESS IMPACT: Explain potential damage in business terms (not just technical)
5. INVESTIGATION GAPS: Call out missing logs and how they limit visibility
6. RECOMMENDED RESPONSE: Prioritized action plan with specific steps and timeline
7. LESSONS LEARNED: What could have detected this earlier or prevented it

Write for a technical audience (Tier 2/3 analyst or incident responder).
Reference specific MITRE techniques, CVE IDs, and HopGraph nodes.
Be thorough but precise - every sentence should add value to the investigation.
"""
    return prompt
```

**Implementation Effort:** 2-3 weeks to enhance prompt building + context aggregation

---

## 4. MISSING LOG DETECTION - SPECIFIC IMPLEMENTATION

### Current Coverage Tracking (Limited)

```python
# From src/core/coverage_tracker.py (current)
class CoverageTracker:
    """Tracks seen alert types."""

    TARGET_ALERT_TYPES = [
        "process_create",
        "network_connection",
        "file_write",
        "registry_set",
        # ... etc
    ]

    def get_coverage_ratio(self):
        """Calculate % of expected alerts seen."""
        return len(self.seen_alert_types) / len(self.TARGET_ALERT_TYPES)
```

### Enhanced Log Gap Detection (Needed)

```python
# src/monitoring/forensic_log_gap_detector.py (NEW FILE NEEDED)

from typing import Dict, List, Any
from datetime import datetime, timedelta
import asyncio
import logging

logger = logging.getLogger(__name__)


class ForensicLogGapDetector:
    """
    Detect and alert on missing forensic log sources critical for port scan investigation.

    Based on enhancement doc Section 5.1-5.2.
    """

    # From enhancement doc Section 5.1
    TIER_1_ESSENTIAL_SOURCES = {
        "firewall_logs": {
            "max_gap_seconds": 3600,  # 1 hour
            "severity": "critical",
            "required_fields": ["timestamp", "source_ip", "dest_ip", "dest_port", "action"],
            "gap_impact": "Cannot detect external reconnaissance or port scanning",
            "ask_for": "Firewall connection logs with 5-tuple and action (allow/deny)"
        },
        "dns_query_logs": {
            "max_gap_seconds": 3600,
            "severity": "critical",
            "required_fields": ["timestamp", "client_ip", "query_name", "response_code"],
            "gap_impact": "Miss pre-scan DNS enumeration",
            "ask_for": "DNS resolver query logs with client IP and queried domain"
        },
        "netflow_ipfix": {
            "max_gap_seconds": 1800,  # 30 minutes
            "severity": "high",
            "required_fields": ["timestamp", "source_ip", "dest_ip", "dest_port", "packets", "bytes"],
            "gap_impact": "Cannot detect slow-and-low scans or distributed attacks",
            "ask_for": "NetFlow/IPFIX from core routers with flow metadata"
        }
    }

    TIER_2_ENHANCED_SOURCES = {
        "ids_ips_alerts": {
            "max_gap_seconds": 7200,  # 2 hours
            "severity": "medium",
            "gap_impact": "Miss scan pattern classification and tool fingerprints"
        },
        "web_server_access_logs": {
            "max_gap_seconds": 3600,
            "severity": "medium",
            "gap_impact": "Miss web reconnaissance and path enumeration (404 spikes)"
        },
        "authentication_logs": {
            "max_gap_seconds": 3600,
            "severity": "high",
            "gap_impact": "Cannot correlate scan → credential spray chains"
        }
    }

    def __init__(self, db, alert_manager):
        self.db = db
        self.alert_manager = alert_manager
        self._last_check_time = {}

    async def check_all_tenants(self):
        """Periodic check for all tenants."""
        tenants = await self._get_active_tenants()

        for tenant_id in tenants:
            gaps = await self.detect_log_gaps(tenant_id)
            if gaps:
                await self._handle_log_gaps(tenant_id, gaps)

    async def detect_log_gaps(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Detect missing log sources for a tenant.

        Returns list of gap dictionaries with source, severity, time_since, impact.
        """
        gaps = []
        now = datetime.utcnow()

        # Check Tier 1 essential sources
        for source_name, config in self.TIER_1_ESSENTIAL_SOURCES.items():
            last_seen = await self._get_last_log_time(tenant_id, source_name)

            if last_seen is None:
                # Never seen this log source
                gaps.append({
                    "source": source_name,
                    "severity": config["severity"],
                    "status": "never_seen",
                    "impact": config["gap_impact"],
                    "ask_for": config.get("ask_for", ""),
                    "tier": 1
                })
            else:
                time_since = (now - last_seen).total_seconds()

                if time_since > config["max_gap_seconds"]:
                    gaps.append({
                        "source": source_name,
                        "severity": config["severity"],
                        "status": "missing",
                        "time_since_seconds": time_since,
                        "time_since_human": self._format_duration(time_since),
                        "last_seen": last_seen.isoformat(),
                        "impact": config["gap_impact"],
                        "ask_for": config.get("ask_for", ""),
                        "tier": 1
                    })

        # Check Tier 2 enhanced sources (less critical)
        for source_name, config in self.TIER_2_ENHANCED_SOURCES.items():
            last_seen = await self._get_last_log_time(tenant_id, source_name)

            if last_seen:
                time_since = (now - last_seen).total_seconds()

                if time_since > config["max_gap_seconds"]:
                    gaps.append({
                        "source": source_name,
                        "severity": config["severity"],
                        "status": "missing",
                        "time_since_seconds": time_since,
                        "time_since_human": self._format_duration(time_since),
                        "last_seen": last_seen.isoformat(),
                        "impact": config["gap_impact"],
                        "tier": 2
                    })

        return gaps

    async def _get_last_log_time(self, tenant_id: str, source_type: str) -> datetime | None:
        """Query database for last log timestamp from source."""

        # Map source types to event types in database
        SOURCE_TO_EVENT_TYPE = {
            "firewall_logs": "firewall_connection",
            "dns_query_logs": "dns_query",
            "netflow_ipfix": "netflow",
            "ids_ips_alerts": "ids_alert",
            "web_server_access_logs": "web_access",
            "authentication_logs": "auth_event"
        }

        event_type = SOURCE_TO_EVENT_TYPE.get(source_type)
        if not event_type:
            return None

        async with self.db.get_connection() as conn:
            row = await conn.fetchrow("""
                SELECT MAX(timestamp) as last_seen
                FROM events
                WHERE tenant_id = $1
                  AND event_type = $2
                  AND timestamp > NOW() - INTERVAL '7 days'
            """, tenant_id, event_type)

            return row["last_seen"] if row else None

    async def _handle_log_gaps(self, tenant_id: str, gaps: List[Dict[str, Any]]):
        """Generate alerts and take action on log gaps."""

        # Separate by severity
        critical_gaps = [g for g in gaps if g["severity"] == "critical"]
        high_gaps = [g for g in gaps if g["severity"] == "high"]
        medium_gaps = [g for g in gaps if g["severity"] == "medium"]

        # Critical gaps: immediate alert
        if critical_gaps:
            await self._send_critical_gap_alert(tenant_id, critical_gaps)

        # High gaps: daily summary
        if high_gaps:
            await self._send_gap_summary(tenant_id, high_gaps, "high")

        # Log all gaps for dashboard
        await self._log_gaps_for_dashboard(tenant_id, gaps)

    async def _send_critical_gap_alert(self, tenant_id: str, gaps: List[Dict[str, Any]]):
        """Send immediate alert for critical log source gaps."""

        gap_summary = "\n".join([
            f"- {g['source']}: {g.get('time_since_human', 'Never seen')} "
            f"(Impact: {g['impact']})"
            for g in gaps
        ])

        alert = {
            "title": f"CRITICAL: Missing Essential Log Sources for Port Scan Detection",
            "severity": "critical",
            "tenant_id": tenant_id,
            "description": f"""
One or more critical log sources required for port scan detection are missing.

Missing Sources:
{gap_summary}

IMMEDIATE ACTION REQUIRED:
{self._generate_remediation_steps(gaps)}

Without these logs, JanuSec cannot detect:
- External port scanning and reconnaissance
- Slow-and-low distributed attacks
- Pre-attack DNS enumeration

This significantly reduces detection coverage and may allow attacks to go unnoticed.
""",
            "metadata": {
                "gaps": gaps,
                "detection_type": "log_gap",
                "playbook": "log_gap_remediation"
            }
        }

        await self.alert_manager.send_alert(alert)

        # If SOAR integration exists, create ticket
        if self._soar_enabled():
            await self._create_gap_remediation_ticket(tenant_id, gaps)

    def _generate_remediation_steps(self, gaps: List[Dict[str, Any]]) -> str:
        """Generate specific remediation steps for log gaps."""

        steps = []
        for i, gap in enumerate(gaps, 1):
            ask_for = gap.get("ask_for", "Contact security team")
            steps.append(f"{i}. {gap['source']}: {ask_for}")

        return "\n".join(steps)

    async def _log_gaps_for_dashboard(self, tenant_id: str, gaps: List[Dict[str, Any]]):
        """Store gap data for dashboard visualization."""

        async with self.db.get_connection() as conn:
            for gap in gaps:
                await conn.execute("""
                    INSERT INTO log_gap_events (
                        tenant_id, source_type, severity, status,
                        time_since_seconds, impact, detected_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, NOW())
                """,
                    tenant_id,
                    gap["source"],
                    gap["severity"],
                    gap["status"],
                    gap.get("time_since_seconds", 0),
                    gap["impact"]
                )

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        else:
            return f"{int(seconds / 86400)} days"

    async def _get_active_tenants(self) -> List[str]:
        """Get list of active tenants."""
        async with self.db.get_connection() as conn:
            rows = await conn.fetch("SELECT DISTINCT tenant_id FROM events WHERE timestamp > NOW() - INTERVAL '1 day'")
            return [row["tenant_id"] for row in rows]

    def _soar_enabled(self) -> bool:
        """Check if SOAR integration is available."""
        # TODO: Implement when SOAR integration exists
        return False

    async def _create_gap_remediation_ticket(self, tenant_id: str, gaps: List[Dict[str, Any]]):
        """Create ticket in SOAR platform for gap remediation."""
        # TODO: Implement when SOAR integration exists
        pass


# Background service to run periodic checks
async def run_log_gap_monitor():
    """Background task to check for log gaps every 15 minutes."""

    detector = ForensicLogGapDetector(db=get_db(), alert_manager=get_alert_manager())

    while True:
        try:
            logger.info("Running log gap detection check...")
            await detector.check_all_tenants()
            logger.info("Log gap check complete")

        except Exception as e:
            logger.error(f"Log gap detection failed: {e}")

        # Check every 15 minutes
        await asyncio.sleep(900)
```

**Database Migration for Log Gap Tracking:**

```sql
-- migrations/023_log_gap_tracking.sql

CREATE TABLE IF NOT EXISTS log_gap_events (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    source_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- critical, high, medium
    status VARCHAR(20) NOT NULL,    -- never_seen, missing
    time_since_seconds INTEGER,
    impact TEXT,
    detected_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,

    INDEX idx_log_gaps_tenant (tenant_id),
    INDEX idx_log_gaps_severity (severity),
    INDEX idx_log_gaps_detected (detected_at)
);

CREATE MATERIALIZED VIEW log_gap_dashboard AS
SELECT
    tenant_id,
    source_type,
    severity,
    COUNT(*) as gap_count,
    MAX(detected_at) as last_detected,
    AVG(time_since_seconds) as avg_gap_duration
FROM log_gap_events
WHERE resolved_at IS NULL
GROUP BY tenant_id, source_type, severity;

COMMENT ON TABLE log_gap_events IS 'Tracks detected gaps in forensic log sources';
```

**Implementation Effort:** 3 weeks (detector + database + dashboard + alerting)

---

## 5. FINAL RECOMMENDATIONS

### Immediate Actions (Week 1-2)

1. **✅ Implement HopGraph Port Scan Schemas**
   - Create `PortScanEvent`, `ScanSourceInfrastructure`, `DiscoveredService` nodes
   - Add `ORIGINATED_FROM`, `TARGETED`, `DISCOVERED`, `PRECEDED` edges
   - Test with example scan → exploit chains

2. **✅ Add DREAD Scoring**
   - Implement configurable DREAD engine
   - Integrate with existing risk scoring
   - Display DREAD breakdown in alerts

3. **✅ Map MITRE T1595.* Techniques**
   - Add reconnaissance-phase techniques
   - Update technique mapping logic
   - Tag all port scan events with T1595.001/002/003

### Short-Term (Week 3-6)

4. **✅ Enhance LLM Prompts**
   - Add kill chain context to Tier 1 summaries
   - Add DREAD, Diamond Model, PASTA to Tier 2
   - Implement motivation inference

5. **✅ Implement Log Gap Detection**
   - Build ForensicLogGapDetector class
   - Add heartbeat monitoring per log source
   - Generate alerts for missing critical sources

6. **✅ Build Scan→Exploit Correlation**
   - Temporal correlation within 24-72 hour window
   - Same source/ASN/target matching
   - Create `PRECEDED` edges in HopGraph

### Medium-Term (Week 7-12)

7. **✅ Diamond Model Clustering**
   - ASN categorization (bulletproof, cloud, research)
   - Scan sophistication scoring (low/medium/high)
   - Campaign clustering with DBSCAN

8. **✅ PASTA Threat Modeling**
   - CMDB integration for business criticality
   - Shadow IT detection (scanned but unknown assets)
   - Service dependency mapping

9. **✅ Basic Playbook Automation**
   - Implement Stage 1 (triage) automation
   - Auto-escalation based on DREAD
   - Email notifications to asset owners

### Long-Term (Week 13+)

10. **✅ Full SOAR Integration**
    - PagerDuty, Tines, Cortex XSOAR connectors
    - Complete playbook automation (Stages 1-4)
    - Approval workflows

11. **✅ Advanced Analytics**
    - Scan tool fingerprinting (nmap vs. Masscan)
    - Certificate Transparency monitoring
    - Honeypot integration

---

## 6. CONCLUSION

**Current Implementation Status: ~40% Complete**

JanuSec has a **strong foundation** with:
- ✅ Full 21-stage event pipeline
- ✅ HopGraph attack reconstruction framework
- ✅ Basic MITRE ATT&CK mapping
- ✅ LLM summary framework (needs enhanced prompts)
- ✅ Coverage tracking (needs gap detection)

**Critical Gaps for Port Scan Enhancement:**
- ❌ Port scan-specific HopGraph schemas
- ❌ DREAD/PASTA/Diamond Model scoring
- ❌ Kill chain phase tracking and correlation
- ❌ Enhanced LLM context (kill chain, motivation, business impact)
- ❌ Forensic log gap detection and alerting
- ❌ Automated playbook orchestration

**Estimated Effort for Full Implementation:**
- Phase 1 (Critical): 4-6 weeks
- Phase 2 (Important): 6-8 weeks
- Phase 3 (Advanced): 6-8 weeks
- **Total: 16-22 weeks** (4-5.5 months) with 2-3 engineers

**Recommended Approach:**
1. Start with Phase 1 (HopGraph schemas, DREAD, MITRE T1595, scan→exploit correlation)
2. This unlocks immediate value for port scan detection
3. Phase 2 and 3 can be developed in parallel or based on customer demand

The platform is **well-architected** and adding these enhancements will elevate port scanning from basic detection to **comprehensive threat intelligence and automated response**.
