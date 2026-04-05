# JanuSec Port Scanning Detection Enhancement
## Threat Framework Correlation, HopGraph Reconstruction & Forensic Gap Analysis

**Version**: 1.0  
**Classification**: Technical Architecture Document  
**Audience**: Coding Agents, Detection Engineers, SOC Analysts

---

## Executive Summary

This document extends port scanning detection capabilities for JanuSec by providing:
1. Multi-framework threat correlation (DREAD, PASTA, Diamond Model, MITRE ATT&CK, CVSS, Cyber Kill Chain)
2. HopGraph attack reconstruction schemas for recon-phase activities
3. Forensic log gap analysis and collection requirements
4. Automated playbook templates for detection-to-response workflows

---

## 1. Gap Analysis: What ChatGPT Missed

The provided ChatGPT response covered detection telemetry well but had significant gaps:

| Missing Element | Impact |
|-----------------|--------|
| DREAD scoring for port scan severity | Cannot prioritize scan alerts by business risk |
| PASTA threat modeling integration | No attacker motivation/objective mapping |
| Diamond Model adversary profiling | Cannot cluster scan campaigns by actor |
| CVSS contextualization | Missing vulnerability correlation post-scan |
| HopGraph schemas | No attack chain reconstruction capability |
| Playbook automation triggers | Detection without response workflow |
| Forensic log gap matrix | Unknown blind spots in investigation |

---

## 2. Multi-Framework Threat Correlation

### 2.1 DREAD Scoring for Port Scanning Events

DREAD provides risk-based prioritization for detected scan activity.

```yaml
# DREAD Scoring Schema for Port Scan Events
dread_port_scan_scoring:
  damage_potential:
    criteria: "What could attacker gain from discovered services?"
    scoring_logic:
      - condition: "scan_targets CONTAINS ['445', '3389', '22', '1433', '3306']"
        score: 9
        rationale: "Critical infrastructure services exposed"
      - condition: "scan_targets CONTAINS ['80', '443', '8080']"
        score: 6
        rationale: "Web services - attack surface dependent on app security"
      - condition: "scan_targets CONTAINS high_ports_only"
        score: 3
        rationale: "Non-standard ports - lower immediate impact"

  reproducibility:
    criteria: "How easily can this scan be repeated?"
    scoring_logic:
      - condition: "source_ip_type == 'residential_proxy' OR 'tor_exit'"
        score: 10
        rationale: "Easily rotatable, repeatable infrastructure"
      - condition: "source_ip_type == 'cloud_provider'"
        score: 8
        rationale: "Ephemeral compute, likely automated"
      - condition: "source_ip_type == 'static_hosting'"
        score: 5
        rationale: "Traceable but repeatable"

  exploitability:
    criteria: "Given scan results, how exploitable are findings?"
    scoring_logic:
      - condition: "discovered_services MATCH known_cve_vulnerable"
        score: 10
        rationale: "Direct path to exploitation exists"
      - condition: "discovered_services MATCH default_credentials_common"
        score: 8
        rationale: "Credential spray likely follow-up"
      - condition: "discovered_services MATCH current_patch_level"
        score: 3
        rationale: "Limited immediate exploitation path"

  affected_users:
    criteria: "Scope of potential impact"
    scoring_logic:
      - condition: "scan_target_type == 'dmz_perimeter'"
        score: 10
        rationale: "Customer-facing, broad impact"
      - condition: "scan_target_type == 'internal_segment'"
        score: 7
        rationale: "Internal users affected if breached"
      - condition: "scan_target_type == 'isolated_test'"
        score: 2
        rationale: "Limited blast radius"

  discoverability:
    criteria: "How easily attacker found this target"
    scoring_logic:
      - condition: "target_in_certificate_transparency OR public_dns"
        score: 9
        rationale: "Publicly discoverable infrastructure"
      - condition: "target_ip_sequential_scan"
        score: 5
        rationale: "Opportunistic discovery"
      - condition: "target_requires_prior_knowledge"
        score: 2
        rationale: "Suggests targeted reconnaissance"

  # Composite calculation
  composite_score:
    formula: "(D + R + E + A + D) / 5"
    thresholds:
      critical: ">= 8.0"
      high: ">= 6.0"
      medium: ">= 4.0"
      low: "< 4.0"
```

### 2.2 PASTA (Process for Attack Simulation and Threat Analysis)

PASTA provides attacker-centric threat modeling aligned to business objectives.

```yaml
# PASTA Stage Mapping for Port Scanning Intelligence
pasta_port_scan_integration:
  
  stage_1_define_objectives:
    business_context:
      - "Map scanned assets to business criticality tiers"
      - "Identify revenue-generating vs support infrastructure"
    janusec_enrichment:
      - query: "MATCH (a:Asset) WHERE a.ip IN $scanned_ips RETURN a.business_tier, a.data_classification"
      - output: "business_impact_score"

  stage_2_define_technical_scope:
    asset_inventory_correlation:
      - "Cross-reference scan targets with CMDB"
      - "Identify shadow IT (scanned but unknown assets)"
    janusec_enrichment:
      - query: "MATCH (scan:PortScan)-[:TARGETED]->(ip:IP) WHERE NOT EXISTS((ip)<-[:OWNS]-(:Asset)) RETURN ip"
      - output: "shadow_it_candidates"

  stage_3_application_decomposition:
    service_dependency_mapping:
      - "For each discovered port, map service → application → business process"
      - "Identify trust boundaries crossed if service compromised"
    janusec_enrichment:
      - query: |
          MATCH (p:Port {number: $port})-[:RUNS]->(s:Service)-[:SUPPORTS]->(a:Application)
          RETURN a.name, a.trust_boundary, a.dependencies

  stage_4_threat_analysis:
    attacker_motivation_inference:
      scan_pattern_to_motivation:
        - pattern: "horizontal_scan_445_3389"
          motivation: "Ransomware operator seeking lateral movement vectors"
          confidence: 0.85
        - pattern: "vertical_scan_web_ports_plus_db"
          motivation: "Data exfiltration / web app compromise"
          confidence: 0.80
        - pattern: "slow_comprehensive_all_ports"
          motivation: "APT-style reconnaissance for persistence"
          confidence: 0.75
        - pattern: "iot_ports_scan_23_8443_554"
          motivation: "Botnet recruitment / IoT exploitation"
          confidence: 0.70

  stage_5_vulnerability_analysis:
    post_scan_correlation:
      - "Match discovered services to vulnerability database"
      - "Prioritize by CVSS + exploitability"
    janusec_query:
      - query: |
          MATCH (scan:PortScan)-[:DISCOVERED]->(s:Service)
          MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
          WHERE v.cvss_score >= 7.0 AND v.exploit_available = true
          RETURN s, v ORDER BY v.cvss_score DESC

  stage_6_attack_modeling:
    hopgraph_integration:
      - "Build attack trees from scan → exploit → objective"
      - "Reference Section 4 for HopGraph schemas"

  stage_7_risk_mitigation:
    response_priority_matrix:
      - "High DREAD + APT motivation → Immediate block + hunt"
      - "High DREAD + commodity motivation → Block + patch sprint"
      - "Low DREAD + any → Monitor + scheduled remediation"
```

### 2.3 Diamond Model Adversary Profiling

Diamond Model enables clustering scan campaigns by adversary infrastructure and capabilities.

```yaml
# Diamond Model Schema for Port Scan Attribution
diamond_model_port_scan:
  
  adversary_vertex:
    attribution_signals:
      - "ASN ownership patterns (bulletproof hosting, research institutions, cloud)"
      - "Historical IP reputation (prior campaigns, malware C2, scanning history)"
      - "Scan timing patterns (business hours in specific timezone)"
    clustering_features:
      - feature: "asn_category"
        values: ["bulletproof", "residential_proxy", "cloud_ephemeral", "research", "unknown"]
      - feature: "historical_threat_intel"
        values: ["known_apt", "known_ransomware", "known_scanner", "clean", "unknown"]
      - feature: "operational_timezone"
        values: ["utc_offset_inferred_from_timing"]

  capability_vertex:
    scan_sophistication_indicators:
      low_sophistication:
        - "Sequential IP scanning"
        - "Default nmap timing templates"
        - "No evasion techniques"
        - "Single source IP"
      medium_sophistication:
        - "Randomized port ordering"
        - "Distributed source IPs (same ASN)"
        - "Timing variation (T2-T3 templates)"
      high_sophistication:
        - "Slow-and-low (days/weeks)"
        - "Decoy packet injection"
        - "Source IP rotation across ASNs"
        - "Fragmented probes"
        - "Application-layer service detection"

  infrastructure_vertex:
    source_infrastructure_profiling:
      enrichment_sources:
        - "MaxMind/IP2Location for geo + ASN"
        - "Shodan/Censys for source host characterization"
        - "Passive DNS for domain associations"
        - "TOR exit node lists"
        - "Known proxy/VPN provider ranges"
      janusec_schema:
        node_type: "ScanInfrastructure"
        properties:
          - ip_address
          - asn
          - asn_name
          - geo_country
          - geo_city
          - hosting_type  # cloud, residential, datacenter
          - proxy_probability
          - tor_exit_flag
          - historical_scan_count
          - first_seen
          - last_seen

  victim_vertex:
    target_characterization:
      - "Business criticality tier"
      - "Internet exposure duration"
      - "Patch cadence"
      - "Previous targeting history"

  meta_features:
    socio_political_context:
      - "Correlate scan timing with geopolitical events"
      - "Industry-specific targeting patterns"
      - "Seasonal patterns (quarter-end, holidays)"
    
    technology_context:
      - "Vulnerability disclosure timing correlation"
      - "Exploit release date proximity"
      - "Vendor patch cycle alignment"

  # Campaign clustering algorithm
  campaign_clustering:
    algorithm: "DBSCAN on feature vectors"
    features:
      - source_asn_category
      - scan_pattern_type
      - target_industry
      - timing_profile
      - capability_score
    output: "campaign_id assignment for correlated scans"
```

### 2.4 MITRE ATT&CK Mapping (Extended)

```yaml
# MITRE ATT&CK Detailed Mapping for Port Scanning
mitre_attack_mapping:
  
  reconnaissance:
    T1595_active_scanning:
      T1595_001_scanning_ip_blocks:
        detection_logic: "Source IP → multiple destination IPs, same port"
        janusec_correlation: "horizontal_scan_pattern"
        confidence_boosters:
          - "Sequential or near-sequential IP targeting"
          - "No prior communication history with targets"
          
      T1595_002_vulnerability_scanning:
        detection_logic: "Service banner grabbing, version probing payloads"
        janusec_correlation: "vuln_scan_pattern"
        confidence_boosters:
          - "HTTP OPTIONS/HEAD requests post-port discovery"
          - "Known scanner signatures (Nessus, OpenVAS, Nuclei)"
          
      T1595_003_wordlist_scanning:
        detection_logic: "Path enumeration on discovered web services"
        janusec_correlation: "web_recon_pattern"
        confidence_boosters:
          - "High 404 rate from single source"
          - "Common path patterns (/admin, /.git, /wp-admin)"

    T1592_gather_victim_host_information:
      chain_indicator: "Port scan → OS fingerprinting → service enumeration"
      
    T1590_gather_victim_network_information:
      chain_indicator: "DNS enumeration → port scan → network mapping"

  initial_access_correlation:
    T1190_exploit_public_facing:
      pre_indicator: "Port scan discovering vulnerable service"
      timing_correlation: "Exploit attempt within 24-72 hours of scan"
      
    T1133_external_remote_services:
      pre_indicator: "Port scan on 22/3389/5900/3283"
      timing_correlation: "Brute force attempts following discovery"

  # Kill chain progression tracking
  kill_chain_progression:
    recon_to_delivery_indicators:
      - "Same source IP/ASN transitions from scanning to exploitation"
      - "Time-bound correlation (scan → exploit < 7 days typically)"
      - "Target overlap between scan and subsequent attack phases"
```

### 2.5 CVSS Contextualization

```yaml
# CVSS Integration for Post-Scan Vulnerability Correlation
cvss_port_scan_integration:
  
  discovery_to_vulnerability_pipeline:
    step_1_service_identification:
      input: "port_scan_results"
      process: "Map port → service → version (via banner/probe)"
      output: "service_inventory"
      
    step_2_vulnerability_lookup:
      input: "service_inventory"
      process: "Query NVD/CVE databases for known vulnerabilities"
      output: "vulnerability_list_per_service"
      
    step_3_cvss_enrichment:
      for_each_vulnerability:
        base_score: "From NVD"
        temporal_score:
          exploit_code_maturity:
            - condition: "exploit_db_available"
              modifier: "+1.0"
            - condition: "metasploit_module_exists"
              modifier: "+1.5"
          remediation_level:
            - condition: "vendor_patch_available"
              modifier: "-0.5"
            - condition: "no_patch_available"
              modifier: "+0.5"
        environmental_score:
          asset_criticality:
            - condition: "business_tier == 'critical'"
              modifier: "+1.0"
            - condition: "business_tier == 'standard'"
              modifier: "0"
          exposure_context:
            - condition: "internet_facing"
              modifier: "+0.5"
            - condition: "internal_only"
              modifier: "-0.5"

  prioritization_formula:
    composite: |
      priority_score = (
        cvss_base * 0.4 +
        temporal_modifier * 0.3 +
        environmental_modifier * 0.2 +
        dread_score * 0.1
      )
    
  janusec_query_example: |
    MATCH (scan:PortScan)-[:DISCOVERED]->(s:Service)-[:RUNS_ON]->(a:Asset)
    MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
    WITH scan, s, a, v,
         v.cvss_base * 0.4 + 
         CASE WHEN v.exploit_available THEN 1.5 ELSE 0 END * 0.3 +
         CASE a.business_tier WHEN 'critical' THEN 1.0 ELSE 0 END * 0.2
         AS priority_score
    RETURN a.hostname, s.name, v.cve_id, v.cvss_base, priority_score
    ORDER BY priority_score DESC
    LIMIT 20
```

### 2.6 Cyber Kill Chain Correlation Matrix

```yaml
# Cyber Kill Chain Phase Correlation for Port Scanning
cyber_kill_chain_correlation:
  
  reconnaissance:
    port_scan_role: "Primary indicator"
    detection_sources:
      - firewall_deny_logs
      - netflow_analysis
      - ids_scan_alerts
      - honeypot_triggers
    correlation_signals:
      - "OSINT domain enumeration → port scan timing"
      - "Certificate transparency hits → scan targeting new subdomains"
    hopgraph_node_type: "ReconEvent"
    
  weaponization:
    port_scan_role: "Intelligence input for payload selection"
    defender_visibility: "Low - occurs off-network"
    proxy_indicators:
      - "Lookalike domain registration post-scan"
      - "Phishing infrastructure setup"
    hopgraph_edge: "INFORMS_WEAPONIZATION"
    
  delivery:
    port_scan_role: "Target selection for delivery vector"
    correlation_logic:
      - "Scan discovered email server → phishing campaign"
      - "Scan discovered VPN endpoint → credential spray"
      - "Scan discovered web app → exploit delivery"
    time_window: "24 hours to 30 days post-scan"
    hopgraph_edge: "PRECEDES_DELIVERY"
    
  exploitation:
    port_scan_role: "Identified attack surface"
    correlation_logic:
      same_source:
        condition: "exploit_source_ip IN scan_source_ips"
        confidence: 0.90
      same_asn:
        condition: "exploit_source_asn == scan_source_asn"
        confidence: 0.70
      same_target:
        condition: "exploit_target_service IN scan_discovered_services"
        confidence: 0.85
    hopgraph_edge: "ENABLES_EXPLOITATION"
    
  installation:
    port_scan_role: "Indirect - enabled initial access"
    correlation: "Chain from scan → exploit → persistence"
    hopgraph_path: "(scan)-[:PRECEDES]->(exploit)-[:LEADS_TO]->(install)"
    
  command_and_control:
    port_scan_role: "May scan for C2 egress paths internally"
    internal_scan_indicators:
      - "Post-compromise internal port scanning"
      - "Lateral movement reconnaissance"
    hopgraph_node_type: "InternalReconEvent"
    
  actions_on_objectives:
    port_scan_role: "Indirect - full chain enabler"
    impact_attribution: "Trace back through HopGraph to originating scan"
```

---

## 3. JanuSec 21-Stage Pipeline Integration Points

Map port scanning detection to specific JanuSec pipeline stages:

```yaml
janusec_pipeline_integration:
  
  stage_3_protocol_decode:
    relevance: "Identify scan protocol characteristics"
    enhancements:
      - "Detect TCP flag anomalies (SYN-only, NULL, FIN, XMAS)"
      - "Identify ICMP echo patterns preceding port scans"
      - "Decode application-layer probes in service detection"
    
  stage_5_threat_intel_enrichment:
    relevance: "Correlate scan sources with known threat actors"
    enhancements:
      - "Real-time lookup against threat intel feeds"
      - "Historical scan source reputation scoring"
      - "Diamond Model adversary clustering"
    
  stage_7_behavioral_baseline:
    relevance: "Distinguish normal network discovery from malicious"
    enhancements:
      - "Baseline legitimate scanner IPs (Qualys, Tenable, cloud health checks)"
      - "Detect deviation from normal connection patterns"
      - "Time-series anomaly detection on port diversity metrics"
    
  stage_11_correlation_engine:
    relevance: "Chain port scans with subsequent attack phases"
    enhancements:
      - "Temporal correlation: scan → exploit within window"
      - "Entity correlation: same source/target across phases"
      - "Behavioral correlation: scan pattern → attack pattern matching"
    
  stage_14_risk_scoring:
    relevance: "Apply DREAD + CVSS composite scoring"
    enhancements:
      - "Dynamic DREAD calculation based on scan characteristics"
      - "CVSS contextualization for discovered vulnerabilities"
      - "Business impact multiplier from asset criticality"
    
  stage_17_hopgraph_construction:
    relevance: "Build attack reconstruction graph"
    enhancements:
      - "See Section 4 for detailed HopGraph schemas"
    
  stage_19_playbook_trigger:
    relevance: "Automated response orchestration"
    enhancements:
      - "See Section 5 for playbook templates"
    
  stage_21_analyst_presentation:
    relevance: "Contextualized alert with full threat framework mapping"
    enhancements:
      - "MITRE ATT&CK navigator visualization"
      - "Kill chain phase indicator"
      - "DREAD/CVSS scores prominently displayed"
```

---

## 4. HopGraph Attack Reconstruction Schemas

### 4.1 Core Node Types

```yaml
hopgraph_node_schemas:
  
  PortScanEvent:
    description: "Individual or aggregated port scan detection"
    properties:
      - event_id: "string (UUID)"
      - detection_time: "datetime"
      - source_ip: "string"
      - source_port: "integer (if applicable)"
      - destination_ips: "array[string]"
      - destination_ports: "array[integer]"
      - scan_type: "enum[vertical, horizontal, block, slow_low, vuln_scan]"
      - protocol: "enum[tcp, udp, icmp]"
      - tcp_flags: "string (SYN, FIN, NULL, etc.)"
      - packet_count: "integer"
      - bytes_total: "integer"
      - duration_seconds: "float"
      - detection_source: "enum[firewall, ids, netflow, honeypot, edr]"
      - raw_log_refs: "array[string] (log source references)"
    indexes:
      - source_ip
      - detection_time
      - scan_type
      
  ScanSourceInfrastructure:
    description: "Enriched source IP context"
    properties:
      - ip_address: "string"
      - asn: "integer"
      - asn_name: "string"
      - geo_country: "string"
      - geo_city: "string"
      - hosting_type: "enum[cloud, residential, datacenter, unknown]"
      - is_tor_exit: "boolean"
      - is_known_proxy: "boolean"
      - threat_intel_tags: "array[string]"
      - first_seen: "datetime"
      - last_seen: "datetime"
      - total_scan_events: "integer"
      - diamond_adversary_cluster: "string (nullable)"
    indexes:
      - ip_address
      - asn
      - diamond_adversary_cluster
      
  DiscoveredService:
    description: "Service discovered through scanning"
    properties:
      - service_id: "string (UUID)"
      - host_ip: "string"
      - port: "integer"
      - protocol: "enum[tcp, udp]"
      - service_name: "string (ssh, http, smb, etc.)"
      - service_version: "string (nullable)"
      - banner: "string (nullable)"
      - discovery_time: "datetime"
      - discovery_method: "enum[port_open, banner_grab, service_probe]"
    indexes:
      - host_ip
      - port
      - service_name
      
  VulnerabilityMatch:
    description: "Vulnerability correlated to discovered service"
    properties:
      - vuln_id: "string (UUID)"
      - cve_id: "string"
      - cvss_base: "float"
      - cvss_temporal: "float (nullable)"
      - cvss_environmental: "float (nullable)"
      - exploit_available: "boolean"
      - exploit_source: "string (nullable) (metasploit, exploit-db, etc.)"
      - patch_available: "boolean"
      - vendor_advisory_url: "string (nullable)"
    indexes:
      - cve_id
      - cvss_base
      
  ExploitationAttempt:
    description: "Detected exploitation following scan"
    properties:
      - exploit_id: "string (UUID)"
      - detection_time: "datetime"
      - source_ip: "string"
      - target_ip: "string"
      - target_port: "integer"
      - exploit_type: "string"
      - cve_targeted: "string (nullable)"
      - success_indicator: "enum[succeeded, failed, unknown]"
      - detection_source: "enum[ids, waf, edr, honeypot]"
    indexes:
      - source_ip
      - target_ip
      - detection_time
      
  Asset:
    description: "Target asset from CMDB/inventory"
    properties:
      - asset_id: "string (UUID)"
      - hostname: "string"
      - ip_addresses: "array[string]"
      - business_tier: "enum[critical, high, standard, low]"
      - data_classification: "enum[public, internal, confidential, restricted]"
      - owner_team: "string"
      - environment: "enum[production, staging, development, test]"
      - last_patch_date: "datetime"
      - os_type: "string"
      - os_version: "string"
    indexes:
      - asset_id
      - ip_addresses
      - business_tier

  ThreatActor:
    description: "Attributed or hypothesized threat actor"
    properties:
      - actor_id: "string (UUID)"
      - actor_name: "string (nullable)"
      - actor_type: "enum[apt, criminal, hacktivist, insider, unknown]"
      - motivation: "array[string] (financial, espionage, disruption, etc.)"
      - ttps: "array[string] (MITRE ATT&CK technique IDs)"
      - confidence: "float (0.0-1.0)"
      - diamond_cluster_id: "string"
    indexes:
      - actor_id
      - actor_type
```

### 4.2 Edge Types (Relationships)

```yaml
hopgraph_edge_schemas:
  
  ORIGINATED_FROM:
    source: "PortScanEvent"
    target: "ScanSourceInfrastructure"
    properties:
      - enrichment_time: "datetime"
      
  TARGETED:
    source: "PortScanEvent"
    target: "Asset"
    properties:
      - ports_scanned: "array[integer]"
      - services_found: "array[string]"
      
  DISCOVERED:
    source: "PortScanEvent"
    target: "DiscoveredService"
    properties:
      - discovery_confidence: "float"
      - banner_captured: "boolean"
      
  HAS_VULNERABILITY:
    source: "DiscoveredService"
    target: "VulnerabilityMatch"
    properties:
      - match_confidence: "float"
      - version_confirmed: "boolean"
      
  PRECEDED:
    source: "PortScanEvent"
    target: "ExploitationAttempt"
    properties:
      - time_delta_seconds: "integer"
      - same_source: "boolean"
      - same_target: "boolean"
      - correlation_confidence: "float"
      
  ATTRIBUTED_TO:
    source: "PortScanEvent | ExploitationAttempt"
    target: "ThreatActor"
    properties:
      - attribution_method: "enum[ip_reputation, ttp_match, diamond_cluster, manual]"
      - confidence: "float"
      
  PART_OF_CAMPAIGN:
    source: "PortScanEvent"
    target: "Campaign"
    properties:
      - cluster_algorithm: "string"
      - cluster_timestamp: "datetime"

  RUNS_ON:
    source: "DiscoveredService"
    target: "Asset"
    properties: []
      
  ESCALATED_TO:
    source: "PortScanEvent"
    target: "Incident"
    properties:
      - escalation_time: "datetime"
      - escalation_reason: "string"
      - dread_score: "float"
```

### 4.3 Example HopGraph Queries

```cypher
// Query 1: Full attack chain from scan to exploitation
MATCH path = (scan:PortScanEvent)-[:ORIGINATED_FROM]->(infra:ScanSourceInfrastructure)
MATCH (scan)-[:DISCOVERED]->(svc:DiscoveredService)-[:HAS_VULNERABILITY]->(vuln:VulnerabilityMatch)
MATCH (scan)-[:PRECEDED]->(exploit:ExploitationAttempt)
WHERE exploit.detection_time > scan.detection_time
  AND exploit.detection_time < scan.detection_time + duration('P7D')
RETURN path, svc, vuln, exploit
ORDER BY vuln.cvss_base DESC

// Query 2: Cluster scans by adversary infrastructure
MATCH (scan:PortScanEvent)-[:ORIGINATED_FROM]->(infra:ScanSourceInfrastructure)
WHERE infra.threat_intel_tags IS NOT NULL
WITH infra.diamond_adversary_cluster AS cluster, 
     collect(scan) AS scans,
     count(DISTINCT scan.destination_ips) AS unique_targets
RETURN cluster, size(scans) AS scan_count, unique_targets
ORDER BY scan_count DESC

// Query 3: High-value targets scanned with exploitable vulns
MATCH (scan:PortScanEvent)-[:TARGETED]->(asset:Asset)
MATCH (scan)-[:DISCOVERED]->(svc:DiscoveredService)-[:HAS_VULNERABILITY]->(vuln:VulnerabilityMatch)
WHERE asset.business_tier = 'critical'
  AND vuln.exploit_available = true
  AND vuln.cvss_base >= 7.0
RETURN asset.hostname, svc.service_name, svc.port, vuln.cve_id, vuln.cvss_base
ORDER BY vuln.cvss_base DESC

// Query 4: Timeline reconstruction for incident investigation
MATCH (scan:PortScanEvent)-[:PRECEDED]->(exploit:ExploitationAttempt)
WHERE scan.source_ip = $incident_source_ip
OPTIONAL MATCH (exploit)-[:LED_TO]->(persistence:PersistenceEvent)
OPTIONAL MATCH (persistence)-[:LED_TO]->(lateral:LateralMovementEvent)
RETURN scan, exploit, persistence, lateral
ORDER BY scan.detection_time ASC

// Query 5: DREAD-scored scan prioritization
MATCH (scan:PortScanEvent)-[:TARGETED]->(asset:Asset)
MATCH (scan)-[:ORIGINATED_FROM]->(infra:ScanSourceInfrastructure)
WITH scan, asset, infra,
     // Damage potential
     CASE WHEN 445 IN scan.destination_ports OR 3389 IN scan.destination_ports THEN 9
          WHEN 80 IN scan.destination_ports OR 443 IN scan.destination_ports THEN 6
          ELSE 3 END AS damage,
     // Reproducibility
     CASE infra.hosting_type WHEN 'residential' THEN 10 WHEN 'cloud' THEN 8 ELSE 5 END AS repro,
     // Affected users (from asset tier)
     CASE asset.business_tier WHEN 'critical' THEN 10 WHEN 'high' THEN 7 ELSE 4 END AS affected,
     // Discoverability
     CASE WHEN asset.environment = 'production' THEN 9 ELSE 5 END AS discover
WITH scan, asset, (damage + repro + affected + discover) / 4.0 AS dread_score
WHERE dread_score >= 7.0
RETURN scan.event_id, asset.hostname, dread_score
ORDER BY dread_score DESC
```

---

## 5. Forensic Log Gap Analysis

### 5.1 Required Log Sources Matrix

```yaml
forensic_log_requirements:
  
  tier_1_essential:
    description: "Minimum viable detection - must have"
    
    firewall_logs:
      log_type: "Connection logs (allow/deny)"
      required_fields:
        - timestamp
        - source_ip
        - source_port
        - destination_ip
        - destination_port
        - protocol
        - action (allow/deny)
        - bytes_sent
        - bytes_received
        - session_duration
      retention: "90 days minimum"
      gap_impact: "Cannot detect external reconnaissance"
      ask_for: |
        "We need firewall connection logs with timestamp, 5-tuple (src/dst IP, src/dst port, protocol),
        action taken, and byte counts. Can you export logs from [Palo Alto/Fortinet/Cisco ASA]?"
        
    dns_query_logs:
      log_type: "DNS resolution requests"
      required_fields:
        - timestamp
        - client_ip
        - query_name
        - query_type
        - response_code
        - resolved_ips
      retention: "90 days minimum"
      gap_impact: "Miss pre-scan DNS enumeration"
      ask_for: |
        "Do you have DNS query logs from your resolvers? We need client IP, queried domain,
        query type, and response. This helps us see if attackers enumerated your domains before scanning."
        
    netflow_ipfix:
      log_type: "Network flow metadata"
      required_fields:
        - timestamp
        - source_ip
        - source_port
        - destination_ip
        - destination_port
        - protocol
        - packets
        - bytes
        - tcp_flags
        - flow_duration
      retention: "30 days minimum"
      gap_impact: "Cannot detect slow-and-low scans, miss flow patterns"
      ask_for: |
        "Are you exporting NetFlow/IPFIX from your core routers and switches?
        We need this to detect distributed and slow scanning patterns that evade firewall rules."

  tier_2_enhanced:
    description: "Significantly improves detection fidelity"
    
    ids_ips_alerts:
      log_type: "Intrusion detection alerts"
      required_fields:
        - timestamp
        - signature_id
        - signature_name
        - source_ip
        - destination_ip
        - destination_port
        - severity
        - raw_payload_sample
      gap_impact: "Miss scan pattern classification"
      ask_for: |
        "Can you forward IDS/IPS alerts from [Snort/Suricata/Zeek]? 
        We specifically need scan-related signatures and any payload samples."
        
    web_server_access_logs:
      log_type: "HTTP/HTTPS access logs"
      required_fields:
        - timestamp
        - client_ip
        - request_method
        - request_uri
        - response_code
        - user_agent
        - referrer
        - response_size
      gap_impact: "Miss web reconnaissance and path enumeration"
      ask_for: |
        "Do you have Apache/Nginx/IIS access logs? We need these to correlate web scanning
        (404 spikes, path enumeration) with port scan activity."
        
    authentication_logs:
      log_type: "Auth success/failure events"
      required_fields:
        - timestamp
        - username
        - source_ip
        - auth_method
        - success_flag
        - failure_reason
        - target_service
      sources: ["SSH", "RDP", "VPN", "SSO", "AD"]
      gap_impact: "Cannot correlate scan → credential spray chains"
      ask_for: |
        "We need authentication logs from VPN, SSH, RDP, and your SSO provider.
        This lets us see if scanning leads to brute force attempts."

  tier_3_advanced:
    description: "Enables sophisticated correlation and attribution"
    
    packet_capture:
      log_type: "Full or sampled PCAP"
      use_case: "Deep inspection of suspicious traffic"
      retention: "7 days rolling or on-demand"
      gap_impact: "Cannot confirm scan tool fingerprints"
      ask_for: |
        "Can you enable selective PCAP on internet-facing segments? 
        Even sampled capture helps us fingerprint scan tools and confirm detections."
        
    endpoint_connection_logs:
      log_type: "EDR network connection telemetry"
      required_fields:
        - timestamp
        - endpoint_hostname
        - process_name
        - process_hash
        - local_port
        - remote_ip
        - remote_port
        - direction
      gap_impact: "Miss endpoint-view of inbound scan attempts"
      ask_for: |
        "Does your EDR [CrowdStrike/Defender/SentinelOne] export network connection events?
        This gives us endpoint perspective on what's actually reaching hosts."
        
    certificate_transparency:
      log_type: "CT log monitoring alerts"
      required_fields:
        - timestamp
        - domain
        - certificate_issuer
        - certificate_validity_start
      gap_impact: "Miss early warning of attacker infrastructure setup"
      ask_for: |
        "Are you monitoring Certificate Transparency logs for your domains?
        New unexpected certs often precede targeted scanning campaigns."
        
    honeypot_logs:
      log_type: "Deception system events"
      required_fields:
        - timestamp
        - source_ip
        - decoy_ip
        - decoy_port
        - interaction_type
      gap_impact: "Miss high-confidence targeting indicators"
      ask_for: |
        "Do you have any honeypots or canary tokens deployed?
        Any hit on these is high-signal since legitimate traffic shouldn't touch them."

  tier_4_threat_intel:
    description: "External context enrichment"
    
    threat_intel_feeds:
      data_type: "IP reputation, IOC feeds"
      required_fields:
        - indicator_type
        - indicator_value
        - threat_type
        - confidence
        - first_seen
        - last_seen
        - source
      gap_impact: "Cannot attribute scans to known actors"
      ask_for: |
        "What threat intel feeds do you subscribe to? We can integrate them for
        real-time scan source reputation checking."
        
    shodan_censys_exports:
      data_type: "Attack surface snapshots"
      use_case: "Understand attacker's view of your infrastructure"
      gap_impact: "Cannot assess what attackers see before they scan you"
      ask_for: |
        "Have you run Shodan/Censys searches on your own IP ranges?
        This shows what's visible to attackers doing OSINT before active scanning."
```

### 5.2 Log Gap Assessment Questions

```yaml
log_gap_assessment_questionnaire:
  
  network_visibility:
    questions:
      - "What percentage of your egress/ingress traffic flows through monitored firewalls?"
      - "Do you have visibility into cloud VPC flow logs (AWS VPC Flow, Azure NSG, GCP Flow)?"
      - "Are east-west (internal) traffic flows logged?"
      - "Do you have NetFlow/IPFIX from core network devices?"
    red_flags:
      - "Direct internet access bypassing firewall"
      - "Cloud workloads without flow logging enabled"
      - "No internal network flow visibility"
      
  endpoint_visibility:
    questions:
      - "What percentage of endpoints have EDR deployed?"
      - "Are EDR network connection events being exported to SIEM?"
      - "Do you have sysmon or equivalent on Windows hosts?"
      - "Are Linux hosts running auditd with network connection logging?"
    red_flags:
      - "EDR coverage < 90%"
      - "EDR data not centralized"
      - "No host-level network logging"
      
  application_visibility:
    questions:
      - "Are web server access logs centralized?"
      - "Do you have WAF logs with request details?"
      - "Are authentication logs from all services centralized?"
      - "Do you log API gateway requests?"
    red_flags:
      - "Web servers logging locally only"
      - "WAF in detect-only without logging"
      - "Auth logs fragmented across systems"
      
  retention_and_freshness:
    questions:
      - "What is your log retention period for each source?"
      - "What is the typical latency from event to SIEM ingestion?"
      - "Can you retrieve historical logs beyond retention if needed?"
    red_flags:
      - "Retention < 30 days for network logs"
      - "Ingestion latency > 15 minutes"
      - "No archive/cold storage option"
```

---

## 6. Automated Playbook Templates

### 6.1 Detection-to-Response Playbook: External Port Scan

```yaml
playbook_external_port_scan:
  name: "External Port Scan Detection and Response"
  version: "1.0"
  trigger:
    event_type: "PortScanEvent"
    conditions:
      - scan_type: ["vertical", "horizontal", "block"]
      - source_ip_internal: false
      - unique_ports_threshold: ">= 20 OR unique_destinations >= 10"
      
  stages:
    
    stage_1_initial_triage:
      timeout_minutes: 5
      automated_actions:
        - action: "enrich_source_ip"
          data_sources: ["maxmind", "shodan", "threat_intel_feeds", "tor_exit_list"]
          output: "source_enrichment"
          
        - action: "calculate_dread_score"
          inputs: ["scan_event", "source_enrichment", "target_assets"]
          output: "dread_score"
          
        - action: "diamond_model_cluster"
          inputs: ["source_enrichment", "scan_pattern"]
          output: "adversary_cluster"
          
        - action: "check_whitelist"
          inputs: ["source_ip", "scanner_whitelist"]
          output: "is_whitelisted"
          
      decision_logic:
        - condition: "is_whitelisted == true"
          action: "close_as_benign"
          
        - condition: "dread_score >= 8.0"
          action: "escalate_to_stage_2_urgent"
          
        - condition: "dread_score >= 5.0"
          action: "escalate_to_stage_2_normal"
          
        - condition: "dread_score < 5.0"
          action: "log_and_monitor"
          
    stage_2_correlation:
      timeout_minutes: 15
      automated_actions:
        - action: "search_historical_scans"
          query: "Same source IP/ASN in past 30 days"
          output: "historical_context"
          
        - action: "check_subsequent_activity"
          query: "Same source → any exploit/auth attempts within 24 hours"
          output: "kill_chain_progression"
          
        - action: "identify_discovered_services"
          query: "What services responded during scan?"
          output: "exposed_services"
          
        - action: "vulnerability_correlation"
          inputs: ["exposed_services"]
          output: "potential_vulnerabilities"
          
        - action: "build_hopgraph"
          inputs: ["scan_event", "source_enrichment", "exposed_services", "potential_vulnerabilities"]
          output: "hopgraph_subgraph"
          
      decision_logic:
        - condition: "kill_chain_progression.exploit_detected == true"
          action: "escalate_to_incident"
          priority: "P1"
          
        - condition: "potential_vulnerabilities.critical_count > 0"
          action: "escalate_to_stage_3"
          priority: "P2"
          
        - condition: "historical_context.repeat_scanner == true"
          action: "consider_blocking"
          
    stage_3_response:
      automated_actions:
        - action: "create_block_recommendation"
          inputs: ["source_ip", "source_asn", "confidence"]
          output: "block_ticket"
          approval_required: true
          
        - action: "notify_asset_owners"
          inputs: ["exposed_services", "potential_vulnerabilities"]
          template: "scan_notification_email"
          
        - action: "create_patch_ticket"
          condition: "potential_vulnerabilities.patch_available == true"
          inputs: ["potential_vulnerabilities"]
          output: "patch_tickets"
          
        - action: "update_mitre_navigator"
          techniques: ["T1595.001", "T1595.002"]
          
    stage_4_closure:
      automated_actions:
        - action: "document_investigation"
          inputs: ["hopgraph_subgraph", "actions_taken", "decisions"]
          output: "investigation_report"
          
        - action: "update_threat_intel"
          condition: "adversary_cluster.new_attribution == true"
          inputs: ["source_enrichment", "adversary_cluster"]
          
        - action: "calculate_metrics"
          outputs: ["time_to_detect", "time_to_respond", "false_positive_flag"]
```

### 6.2 Honeypot Hit Playbook

```yaml
playbook_honeypot_hit:
  name: "Honeypot/Canary Triggered - High Confidence Targeting"
  version: "1.0"
  trigger:
    event_type: "HoneypotEvent"
    conditions:
      - any_hit: true  # Any honeypot interaction is significant
      
  stages:
    stage_1_immediate:
      timeout_minutes: 2
      automated_actions:
        - action: "enrich_source_ip"
          priority: "high"
          
        - action: "check_internal_vs_external"
          output: "source_location"
          
        - action: "correlate_with_port_scans"
          query: "Same source in last 24 hours"
          output: "scan_correlation"
          
      decision_logic:
        - condition: "source_location == 'internal'"
          action: "escalate_immediately"
          priority: "P1"
          rationale: "Internal honeypot hit indicates compromise or insider"
          
        - condition: "source_location == 'external' AND scan_correlation.exists == true"
          action: "escalate"
          priority: "P2"
          rationale: "Targeted reconnaissance in progress"
          
    stage_2_investigation:
      automated_actions:
        - action: "full_source_profiling"
          # Extensive lookup since honeypot hits are high-signal
          
        - action: "check_all_assets_from_source"
          query: "All connections from source IP in past 7 days"
          
        - action: "build_attack_timeline"
          
    stage_3_containment:
      condition: "source_location == 'internal'"
      actions:
        - "isolate_source_endpoint"
        - "preserve_evidence"
        - "notify_ir_team"
```

### 6.3 Scan-to-Exploit Chain Playbook

```yaml
playbook_scan_exploit_chain:
  name: "Scan Followed by Exploitation Attempt"
  version: "1.0"
  trigger:
    event_type: "CorrelatedEvent"
    conditions:
      - scan_event: "exists"
      - exploit_event: "exists"
      - time_delta: "<= 72 hours"
      - target_overlap: true
      
  priority: "P1"
  
  stages:
    stage_1_confirm_correlation:
      automated_actions:
        - action: "verify_source_relationship"
          checks:
            - same_ip
            - same_asn
            - same_diamond_cluster
          output: "correlation_confidence"
          
        - action: "assess_exploit_success"
          inputs: ["exploit_event"]
          output: "exploit_outcome"
          
    stage_2_impact_assessment:
      condition: "exploit_outcome.success_indicator != 'failed'"
      actions:
        - action: "check_for_post_exploit_activity"
          indicators:
            - persistence_mechanisms
            - lateral_movement
            - data_access
            
        - action: "scope_potential_compromise"
          
    stage_3_containment_and_eradication:
      condition: "exploit_outcome.success_indicator == 'succeeded'"
      actions:
        - "initiate_incident_response"
        - "isolate_affected_systems"
        - "preserve_forensic_evidence"
        - "engage_ir_team"
```

---

## 7. Implementation Recommendations

### 7.1 Priority Implementation Order

```yaml
implementation_priority:
  
  phase_1_foundation:
    duration: "2-4 weeks"
    deliverables:
      - "HopGraph schema implementation (Section 4)"
      - "DREAD scoring engine integration (Section 2.1)"
      - "Basic scan detection rules with framework tagging"
    success_criteria:
      - "Port scans automatically scored with DREAD"
      - "HopGraph nodes created for scan events"
      - "MITRE ATT&CK technique tagged on alerts"
      
  phase_2_correlation:
    duration: "4-6 weeks"
    deliverables:
      - "Diamond Model clustering implementation"
      - "Temporal scan→exploit correlation"
      - "PASTA threat modeling integration"
      - "Playbook Stage 1-2 automation"
    success_criteria:
      - "Scan campaigns clustered by adversary"
      - "Automatic escalation on scan→exploit chains"
      - "Business context enrichment working"
      
  phase_3_advanced:
    duration: "6-8 weeks"
    deliverables:
      - "Full playbook automation"
      - "CVSS contextualization pipeline"
      - "Forensic gap monitoring dashboard"
      - "Analyst workflow integration"
    success_criteria:
      - "End-to-end automated response for common scenarios"
      - "Vulnerability prioritization integrated"
      - "Log gap alerts functioning"
```

### 7.2 Coding Agent Integration Notes

```yaml
coding_agent_notes:
  
  data_models:
    - "HopGraph schemas in Section 4 are Neo4j/Cypher compatible"
    - "YAML structures can be converted to JSON schemas for validation"
    - "DREAD scoring logic should be implemented as configurable rules engine"
    
  api_requirements:
    external_enrichment:
      - "MaxMind GeoIP API"
      - "Shodan API"
      - "Threat intel feed APIs (configurable)"
      - "CVE/NVD API for vulnerability correlation"
      
    internal_integration:
      - "CMDB/asset inventory API for business tier lookup"
      - "SIEM query API for historical correlation"
      - "Ticketing system API for playbook actions"
      
  testing_considerations:
    - "Unit tests for DREAD scoring edge cases"
    - "Integration tests for HopGraph query performance"
    - "Playbook tests with synthetic scan→exploit chains"
    - "Load testing for high-volume scan environments"
    
  performance_targets:
    - "DREAD scoring: < 50ms per event"
    - "HopGraph query for single scan: < 200ms"
    - "Playbook Stage 1 completion: < 5 minutes"
    - "Diamond clustering batch: < 30 seconds for 1000 events"
```

---

## 8. Appendix: Framework Quick Reference

### DREAD Score Interpretation
| Score Range | Severity | Response SLA |
|-------------|----------|--------------|
| 8.0 - 10.0 | Critical | 15 minutes |
| 6.0 - 7.9 | High | 1 hour |
| 4.0 - 5.9 | Medium | 4 hours |
| 0.0 - 3.9 | Low | 24 hours |

### Kill Chain Phase Mapping
| Phase | Port Scan Role | Detection Priority |
|-------|----------------|-------------------|
| Reconnaissance | Primary | High |
| Weaponization | Intel input | Low (off-network) |
| Delivery | Target selection | Medium |
| Exploitation | Attack surface | Critical |
| Installation | Indirect | Low |
| C2 | Internal scans | High |
| Actions | Chain enabler | Attribution |

### Diamond Model Vertex Priorities
| Vertex | Enrichment Priority | Data Sources |
|--------|---------------------|--------------|
| Adversary | High | Threat intel, ASN rep |
| Capability | Medium | Scan pattern analysis |
| Infrastructure | High | IP enrichment, passive DNS |
| Victim | Context | CMDB, asset inventory |

---

*Document generated for JanuSec development team. Designed for parsing by automated coding agents.*
