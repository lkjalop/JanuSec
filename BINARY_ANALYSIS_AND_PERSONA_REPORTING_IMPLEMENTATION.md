# Binary Analysis, Memory Scanning & Persona-Based Reporting
## Strategic Implementation Guide

**Status:** RFC (Request for Comments)
**Author:** Platform Architecture Team
**Date:** 2025-11-30
**Target Release:** Q1 2025

---

## Executive Summary

This document outlines enhancements to JanuSec's triage pipeline focusing on:
1. **Pre-Tier 1 Binary Enrichment** - Magic numbers, PE/ELF analysis, obfuscation detection
2. **HopGraph Integration** - Binary artifacts as first-class graph nodes
3. **Human-In-The-Loop Memory Analysis** - On-demand deep inspection with cost controls
4. **Persona-Based Report Generation** - Tailored outputs for CISO, SOC Analyst, Compliance Officer, External Auditor
5. **Secure Report Distribution** - Clearance-aware, vertical-specific, role-based content filtering

**Philosophy:** Maximum human agency + AI efficiency. Analysts decide when to deep-dive; AI handles the heavy lifting.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Phase 1: Binary Enrichment Pipeline](#phase-1-binary-enrichment-pipeline)
3. [Phase 2: HopGraph Integration](#phase-2-hopgraph-integration)
4. [Phase 3: Threat Intel Enrichment](#phase-3-threat-intel-enrichment)
5. [Phase 4: Memory Analysis (On-Demand)](#phase-4-memory-analysis-on-demand)
6. [Phase 5: Persona-Based Reporting](#phase-5-persona-based-reporting)
7. [UI/UX Design](#uiux-design)
8. [Prometheus & Grafana Metrics](#prometheus--grafana-metrics)
9. [Cost Optimization Strategy](#cost-optimization-strategy)
10. [Security & Compliance](#security--compliance)
11. [Implementation Roadmap](#implementation-roadmap)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        JANUSEC ENHANCED PIPELINE                     │
└─────────────────────────────────────────────────────────────────────┘

[Event Ingestion]
      ↓
┌─────────────────────────────────────────────────────────────────────┐
│ PRE-TIER 1 ENRICHMENT (Toggleable, Cost-Aware)                      │
├─────────────────────────────────────────────────────────────────────┤
│ ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐             │
│ │ Binary      │  │ Obfuscation  │  │ Threat Intel    │             │
│ │ Analysis    │→ │ Detection    │→ │ (Rate-Limited)  │             │
│ │ - Magic #s  │  │ - XOR decode │  │ - VT, AlienVault│             │
│ │ - PE/ELF    │  │ - Multi-layer│  │ - MISP (if CFG) │             │
│ │ - Imports   │  │ - Shellcode  │  │                 │             │
│ └─────────────┘  └──────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
      ↓
┌─────────────────────────────────────────────────────────────────────┐
│ HOPGRAPH INTEGRATION                                                 │
├─────────────────────────────────────────────────────────────────────┤
│  [Process] ──spawned──> [Binary] ──loaded──> [DLL]                  │
│      │                      │                    │                   │
│   (signed)            (magic mismatch)      (unsigned)               │
│      │                      │                    │                   │
│      └──────> [Network] <───┘                    │                   │
│              (C2 beacon)                          │                   │
│                                                   ↓                   │
│                                          [Registry Persistence]       │
│                                                                       │
│ Graph Query: "Find unsigned DLLs loaded by signed processes          │
│               that opened network connections to rare domains"        │
└─────────────────────────────────────────────────────────────────────┘
      ↓
┌─────────────────────────────────────────────────────────────────────┐
│ TIER 1 LLM SUMMARY (Existing)                                        │
│ - Enriched with binary metadata + graph context                      │
└─────────────────────────────────────────────────────────────────────┘
      ↓
┌─────────────────────────────────────────────────────────────────────┐
│ HUMAN DECISION POINT (UI)                                            │
├─────────────────────────────────────────────────────────────────────┤
│  Analyst sees: "Suspicious unsigned binary with process injection    │
│                 imports. Loaded by signed process (winword.exe)"     │
│                                                                       │
│  Options:                                                            │
│  [Escalate to Tier 2] [Request Memory Scan] [Mark FP] [Investigate] │
│                                                                       │
│  Memory Scan Cost: ~$0.15 | Estimated Time: 45s                      │
│  Last scan for this hash: 2 days ago (cached available)              │
└─────────────────────────────────────────────────────────────────────┘
      ↓ (If Memory Scan Requested)
┌─────────────────────────────────────────────────────────────────────┐
│ ON-DEMAND MEMORY ANALYSIS (Human-Triggered)                          │
├─────────────────────────────────────────────────────────────────────┤
│ 1. Check cache (hash-based, 7-day TTL)                               │
│ 2. If miss: Queue analysis job (budget check)                        │
│ 3. Results streamed to analyst UI (WebSocket)                        │
│ 4. Findings added to HopGraph + Tier 2 context                       │
└─────────────────────────────────────────────────────────────────────┘
      ↓
┌─────────────────────────────────────────────────────────────────────┐
│ TIER 2 LLM SUMMARY (Enhanced)                                        │
│ - Includes binary analysis + memory findings + graph path            │
└─────────────────────────────────────────────────────────────────────┘
      ↓
┌─────────────────────────────────────────────────────────────────────┐
│ PERSONA-BASED REPORT GENERATION                                      │
├─────────────────────────────────────────────────────────────────────┤
│ Input: Incident ID + Recipient Profile                               │
│                                                                       │
│ Recipient Profile:                                                   │
│ {                                                                    │
│   "role": "CISO",                                                    │
│   "clearance": "full",           # full | limited | external         │
│   "vertical": "healthcare",       # healthcare | finance | govt      │
│   "focus": ["compliance", "risk"] # technical | compliance | exec    │
│ }                                                                    │
│                                                                       │
│ Output: PDF/HTML report with:                                        │
│ - Executive summary (always)                                         │
│ - Technical details (if clearance allows)                            │
│ - Compliance mapping (if vertical requires)                          │
│ - Redacted IOCs (if external recipient)                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Binary Enrichment Pipeline

### 1.1 Magic Number & File Type Validation

**Location:** `src/artifact/binary_analysis.py` (new file)

**Capabilities:**
- Validate file headers (PE: `MZ`, ELF: `\x7fELF`, Mach-O: `\xfe\xed\xfa\xce`)
- Detect file type mismatches (`.exe` claiming to be `.txt`)
- Extract PE metadata: compile time, imports, exports, sections
- Identify packers (UPX, Themida, ASPack, custom)

**New Factors:**
```python
FACTOR_WEIGHTS.update({
    'binary_magic_mismatch': (FactorCategory.STATIC, 0.22, 'File extension does not match magic number'),
    'binary_suspicious_imports': (FactorCategory.STATIC, 0.20, 'Imports process injection APIs'),
    'binary_overlay_data': (FactorCategory.STATIC, 0.15, 'Non-standard overlay/appended data'),
    'binary_anomalous_sections': (FactorCategory.STATIC, 0.12, 'Section characteristics suspicious (RWX)'),
    'binary_import_hash_rare': (FactorCategory.STATIC, 0.10, 'Import hash rarely seen in fleet'),
})
```

**Suspicious API Imports:**
```python
INJECTION_APIS = [
    'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
    'NtCreateThreadEx', 'QueueUserAPC', 'SetThreadContext',
    'RtlCreateUserThread', 'NtMapViewOfSection'
]

EVASION_APIS = [
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'OutputDebugString',
    'VirtualProtect', 'VirtualProtectEx'
]
```

**Toggle Configuration:**
```python
# .env or config
BINARY_ANALYSIS_ENABLED=1           # Master switch
BINARY_ANALYSIS_MAX_SIZE_MB=50      # Skip files > 50MB
BINARY_ANALYSIS_TIMEOUT_SEC=5       # Timeout per file
BINARY_ANALYSIS_CACHE_TTL=86400     # Cache results 24h
```

### 1.2 Advanced Obfuscation Detection

**Location:** `src/artifact/obfuscation_detector.py` (new file)

**Capabilities:**

**1. XOR Brute Force:**
```python
def detect_xor_encoded(data: bytes) -> Optional[Dict]:
    """Try single-byte XOR keys 0x00-0xFF, score by entropy reduction"""
    for key in range(256):
        decoded = bytes([b ^ key for b in data])
        if has_readable_strings(decoded):  # Entropy drop + ASCII ratio
            return {
                'factor': 'binary_xor_encoded',
                'key': hex(key),
                'confidence': calculate_confidence(decoded)
            }
    return None
```

**2. Multi-Layer PowerShell:**
```python
def detect_multilayer_encoding(script: str) -> List[str]:
    """Detect nested Base64/Gzip/IEX chains"""
    layers = []
    current = script
    max_depth = 5

    for _ in range(max_depth):
        if is_base64(current):
            layers.append('base64')
            current = base64_decode(current)
        elif is_gzip(current):
            layers.append('gzip')
            current = gzip_decompress(current)
        elif 'iex' in current.lower():
            layers.append('iex')
            break
        else:
            break

    if len(layers) >= 2:
        return ['script_multilayer_obfuscation']
    return []
```

**3. Shellcode Pattern Detection:**
```python
SHELLCODE_PATTERNS = [
    rb'\x64\xa1\x30\x00\x00\x00',  # mov eax, fs:[0x30] (PEB access)
    rb'\x55\x8b\xec',               # push ebp; mov ebp, esp (function prologue)
    rb'\x89\xe5',                   # mov ebp, esp (x64)
]

def detect_shellcode(data: bytes) -> bool:
    """Heuristic shellcode detection"""
    return any(pattern in data for pattern in SHELLCODE_PATTERNS)
```

**New Factors:**
```python
'binary_xor_encoded': (FactorCategory.STATIC, 0.18, 'XOR-encoded payload detected'),
'script_multilayer_obfuscation': (FactorCategory.SCRIPT, 0.16, 'Multiple encoding layers'),
'binary_shellcode_pattern': (FactorCategory.STATIC, 0.20, 'Shellcode patterns detected'),
```

---

## Phase 2: HopGraph Integration

### 2.1 Binary Artifacts as First-Class Nodes

**Graph Schema Enhancement:**

```python
# src/core/graph/hopgraph_lite.py

class BinaryNode:
    """Binary artifact in attack graph"""
    sha256: str
    path: str
    magic_number: str
    file_type: str  # 'PE', 'ELF', 'script', 'unknown'
    signed: bool
    signer: Optional[str]
    imports: List[str]  # API imports for executables
    sections: List[Dict]  # PE sections with characteristics
    overlay_size: int

    # Risk indicators
    factors: List[str]
    risk_score: float

    # Relationships
    loaded_by: List[str]  # Process PIDs that loaded this binary
    spawned: List[str]    # Processes this binary created
    network_connections: List[str]  # Flows associated with this binary
    registry_keys: List[str]  # Registry keys accessed
```

**Graph Queries:**

```python
# Find attack chains: signed → unsigned → network
query = """
MATCH (p1:Process {signed: true})
      -[:SPAWNED]->(p2:Process {signed: false})
      -[:LOADED]->(b:Binary)
      -[:CONNECTED]->(n:Network)
WHERE b.factors CONTAINS 'binary_suspicious_imports'
  AND n.domain NOT IN known_good_domains
RETURN p1, p2, b, n
"""

# Find DLL injection chains
query = """
MATCH (p:Process)-[:LOADED]->(dll:Binary)
WHERE dll.imports CONTAINS 'VirtualAllocEx'
  AND dll.signed = false
  AND p.signed = true
RETURN p, dll, p.command_line
"""
```

### 2.2 Graph-Based Factor Enrichment

**New Graph-Derived Factors:**

```python
# src/core/graph/binary_graph_factors.py

def extract_graph_binary_factors(binary_node: BinaryNode, graph: HopGraph) -> List[str]:
    """Extract factors based on graph context"""
    factors = []

    # Signed process loading unsigned binary
    if graph.has_path(signed_process → unsigned_binary):
        factors.append('graph_signed_to_unsigned_load')

    # Binary with suspicious imports that opened network connection
    if binary_node.has_injection_imports() and graph.has_network_edge(binary_node):
        factors.append('graph_injection_with_network')

    # Binary loaded from temp dir with persistence
    if binary_node.path.contains('temp') and graph.has_persistence_edge(binary_node):
        factors.append('graph_temp_binary_persistence')

    # Binary part of multi-hop attack chain (3+ hops)
    chain_length = graph.longest_path_from(binary_node)
    if chain_length >= 3:
        factors.append('graph_multihop_attack_chain')

    return factors
```

---

## Phase 3: Threat Intel Enrichment

### 3.1 Safe, Rate-Limited Threat Intel Calls

**Design Philosophy:**
- **Cache-first:** Check local DB before external calls
- **Rate-limited:** Respect API quotas (VT: 500/day free, 1000/day paid)
- **Async:** Non-blocking, results enrich over time
- **Toggleable:** Disable per tenant or globally

**Implementation:**

```python
# src/integrations/threat_intel_router.py

class ThreatIntelRouter:
    """Safe, rate-limited threat intel aggregator"""

    def __init__(self):
        self.cache = ThreatIntelCache(ttl=604800)  # 7 days
        self.providers = {
            'virustotal': VirusTotalProvider(rate_limit=500/day),
            'alienvault': AlienVaultProvider(rate_limit=1000/day),
            'misp': MISPProvider(enabled=os.getenv('MISP_ENABLED')),
        }
        self.budget_tracker = BudgetTracker()

    async def enrich(self, observable: str, observable_type: str) -> Dict:
        """
        Enrich with threat intel, respecting budget and rate limits

        Args:
            observable: SHA256, IP, domain, etc.
            observable_type: 'hash', 'ip', 'domain', 'url'

        Returns:
            {
                'reputation': 'malicious' | 'suspicious' | 'clean' | 'unknown',
                'vt_positives': int,
                'alienvault_pulses': List[str],
                'misp_events': List[str],
                'cached': bool,
                'cost_usd': float
            }
        """
        # Check cache first
        cached = await self.cache.get(observable)
        if cached:
            return {**cached, 'cached': True, 'cost_usd': 0.0}

        # Check budget
        if not await self.budget_tracker.can_spend('threat_intel', 0.01):
            return {'reputation': 'unknown', 'reason': 'budget_exceeded'}

        # Parallel enrichment with timeout
        results = await asyncio.gather(
            self.providers['virustotal'].lookup(observable, observable_type),
            self.providers['alienvault'].lookup(observable, observable_type),
            self.providers['misp'].lookup(observable, observable_type) if self.providers['misp'].enabled else None,
            return_exceptions=True
        )

        # Synthesize results
        enriched = self._synthesize(results)
        await self.cache.set(observable, enriched)
        await self.budget_tracker.record('threat_intel', 0.01)

        return {**enriched, 'cached': False, 'cost_usd': 0.01}
```

**Configuration:**

```python
# .env
THREAT_INTEL_ENABLED=1                    # Master switch
THREAT_INTEL_PROVIDERS=virustotal,alienvault  # Comma-separated
THREAT_INTEL_CACHE_TTL=604800             # 7 days
THREAT_INTEL_MAX_COST_PER_DAY=5.00        # USD budget cap
THREAT_INTEL_VT_API_KEY=your_key_here
THREAT_INTEL_ALIENVAULT_API_KEY=your_key
THREAT_INTEL_MISP_ENABLED=0               # Optional MISP integration
```

**When to Call Threat Intel:**

```python
# Pre-Tier 1: Only for high-risk observables
if artifact.risk_score > 0.60:
    threat_intel = await router.enrich(artifact.sha256, 'hash')
    if threat_intel['reputation'] == 'malicious':
        artifact.factors.append('reputation_confirmed_malicious')
```

---

## Phase 4: Memory Analysis (On-Demand)

### 4.1 Human-In-The-Loop Design

**Trigger:** Analyst clicks "Request Memory Scan" button in UI

**Flow:**

```
[Analyst sees suspicious binary in UI]
        ↓
[Click "Request Memory Scan" button]
        ↓
[UI shows cost + ETA: "$0.15 | ~45 seconds"]
        ↓
[Confirm] → [Job queued]
        ↓
[WebSocket stream: "Connecting to endpoint..."]
        ↓
[Memory dump acquired → Analyzing...]
        ↓
[Results streamed to UI in real-time]
        ↓
[Findings added to Tier 2 context + HopGraph]
```

### 4.2 Memory Analysis Techniques (Minimal Latency)

**Option A: Agent-Based (Fast, Recommended)**

```python
# Endpoint agent collects memory dump on-demand
# Analyst triggers from UI → API → Agent → Dump → Upload → Analyze

class MemoryAnalysisAgent:
    """Lightweight agent for on-demand memory collection"""

    async def collect_process_memory(self, pid: int) -> bytes:
        """Dump process memory (Linux: /proc/<pid>/mem, Windows: MiniDumpWriteDump)"""
        timeout = 30  # Max 30 seconds
        max_size = 100_000_000  # 100MB cap

        # Incremental dump with size check
        dump = await self.platform_specific_dump(pid, max_size, timeout)
        return dump

    async def scan_memory_patterns(self, dump: bytes) -> Dict:
        """Fast pattern matching (no full emulation)"""
        findings = []

        # 1. YARA rules (fastest)
        yara_matches = await self.yara_scan(dump)
        findings.extend(yara_matches)

        # 2. String extraction (moderate)
        suspicious_strings = extract_suspicious_strings(dump)  # IPs, domains, API keys
        findings.append({'strings': suspicious_strings})

        # 3. Shellcode detection (fast heuristic)
        shellcode_offsets = detect_shellcode_fast(dump)
        findings.append({'shellcode': shellcode_offsets})

        # 4. Injected DLLs (fast)
        injected_dlls = find_unmapped_dlls(dump)
        findings.append({'injected_dlls': injected_dlls})

        return {'findings': findings, 'scan_time_ms': ...}
```

**Option B: Sandbox-Based (Slower, More Comprehensive)**

```python
# For deeper analysis, submit to sandbox (Cuckoo, Any.Run, VMRay)
# Only if analyst requests "Deep Memory Analysis"

class SandboxMemoryAnalysis:
    async def submit_to_sandbox(self, binary_hash: str, analyst_id: str) -> str:
        """Submit to sandbox, return job ID"""
        # Check budget
        if not budget_tracker.can_spend('sandbox', 2.50):
            raise BudgetExceededError()

        job_id = await sandbox_client.submit(binary_hash, profile='memory_forensics')
        await budget_tracker.record('sandbox', 2.50, analyst_id)

        return job_id  # Results arrive via webhook
```

### 4.3 Caching Strategy (Cost Reduction)

```python
# src/analysis/memory_cache.py

class MemoryScanCache:
    """Cache memory analysis results by SHA256"""

    def __init__(self):
        self.ttl = 604800  # 7 days
        self.db = get_db()

    async def get(self, sha256: str) -> Optional[Dict]:
        """Retrieve cached memory analysis"""
        result = await self.db.query(
            "SELECT findings, scan_date FROM memory_scans WHERE sha256 = ? AND scan_date > ?",
            (sha256, time.time() - self.ttl)
        )
        if result:
            return {'findings': result['findings'], 'cached': True}
        return None

    async def set(self, sha256: str, findings: Dict):
        """Cache new analysis"""
        await self.db.insert('memory_scans', {
            'sha256': sha256,
            'findings': json.dumps(findings),
            'scan_date': time.time()
        })
```

### 4.4 UI Integration

**Memory Scan Button:**

```html
<!-- In artifact details card -->
<div class="artifact-actions">
  <button
    id="memScanBtn"
    class="btn-secondary"
    data-sha256="{{ artifact.sha256 }}"
    data-cost="0.15"
  >
    <span class="icon">🔍</span> Request Memory Scan
    <span class="cost-badge">$0.15</span>
  </button>

  <!-- If cached -->
  <div id="cachedScanAvailable" class="cached-notice">
    ✓ Cached scan from 2 days ago available
    <a href="#" onclick="loadCachedScan()">View Results</a>
  </div>
</div>
```

**Real-Time Progress:**

```javascript
// WebSocket stream for live progress
const ws = new WebSocket('wss://janusec.local/api/v1/memory_scan/stream');

ws.onmessage = (event) => {
  const update = JSON.parse(event.data);

  switch (update.status) {
    case 'queued':
      showProgress('Queued for analysis...');
      break;
    case 'collecting':
      showProgress('Collecting memory dump...');
      break;
    case 'analyzing':
      showProgress('Scanning for patterns...', update.progress);  // 0-100%
      break;
    case 'complete':
      displayFindings(update.findings);
      addToHopGraph(update.graph_updates);
      break;
  }
};
```

---

## Phase 5: Persona-Based Reporting

### 5.1 Recipient Profiles

**Profile Schema:**

```python
# src/reporting/persona.py

class RecipientProfile(BaseModel):
    """Defines who receives the report and how it's tailored"""

    # Identity
    email: str
    name: str
    organization: str

    # Role-based content
    role: Literal['ciso', 'soc_analyst', 'compliance_officer', 'external_auditor', 'board_member']

    # Security clearance (controls technical detail depth)
    clearance: Literal['full', 'limited', 'external']
    # - full: All technical details, IOCs, raw logs
    # - limited: High-level technical, redacted IPs/hashes
    # - external: Executive summary only, no sensitive IOCs

    # Vertical-specific compliance
    vertical: Optional[Literal['healthcare', 'finance', 'government', 'retail', 'technology']]

    # Content focus areas
    focus: List[Literal['technical', 'compliance', 'risk', 'executive', 'remediation']]

    # PII/data handling
    redact_pii: bool = True
    redact_internal_ips: bool = False
    redact_usernames: bool = False
```

### 5.2 Report Templates by Persona

**CISO Report:**
```markdown
# Incident Report: {{ incident.title }}
**Date:** {{ incident.date }}
**Severity:** {{ incident.severity }}
**Status:** {{ incident.status }}

## Executive Summary (3-5 sentences)
{{ llm_generated_executive_summary }}

## Business Impact
- **Systems Affected:** {{ affected_systems_count }}
- **Data at Risk:** {{ data_classification }}
- **Estimated Downtime:** {{ downtime_estimate }}
- **Financial Impact:** {{ cost_estimate }}

## Risk Assessment
- **CVSS Score:** {{ cvss_score }}
- **Attack Sophistication:** {{ attack_sophistication }}
- **Likelihood of Recurrence:** {{ recurrence_likelihood }}

## Compliance Implications
{% if vertical == 'healthcare' %}
- **HIPAA:** {{ hipaa_assessment }}
{% elif vertical == 'finance' %}
- **PCI-DSS:** {{ pci_assessment }}
- **SOX:** {{ sox_assessment }}
{% endif %}

## Recommended Actions (Prioritized)
1. {{ action_1 }}
2. {{ action_2 }}
3. {{ action_3 }}

## Technical Details (Collapsed by Default)
<details>
<summary>Click to expand</summary>
{{ technical_timeline }}
{{ ioc_list }}
{{ hopgraph_visualization }}
</details>
```

**SOC Analyst Report:**
```markdown
# Incident {{ incident.id }}: Technical Analysis

## Quick Facts
- **First Seen:** {{ first_seen }}
- **Last Activity:** {{ last_activity }}
- **Attack Vector:** {{ attack_vector }}
- **MITRE ATT&CK:** {{ mitre_techniques }}

## Tier 2 LLM Summary
{{ tier2_summary }}

## Artifacts Analyzed
| Artifact | Type | Risk | Factors | Action Taken |
|----------|------|------|---------|--------------|
{% for artifact in artifacts %}
| {{ artifact.name }} | {{ artifact.type }} | {{ artifact.risk }} | {{ artifact.factors }} | {{ artifact.action }} |
{% endfor %}

## HopGraph Attack Path
```
{{ ascii_attack_graph }}
```

## IOCs (Actionable)
**Hashes (SHA256):**
{{ hash_list }}

**IPs:**
{{ ip_list }}

**Domains:**
{{ domain_list }}

**Registry Keys:**
{{ registry_keys }}

## Remediation Steps
1. {{ remediation_step_1 }}
2. {{ remediation_step_2 }}

## Threat Intel Enrichment
{% if threat_intel_available %}
- **VT Positives:** {{ vt_positives }}/{{ vt_total }}
- **AlienVault Pulses:** {{ av_pulses }}
- **MISP Events:** {{ misp_events }}
{% endif %}
```

**Compliance Officer Report:**
```markdown
# Compliance Incident Report: {{ incident.id }}

## Regulatory Obligations
{% if vertical == 'healthcare' %}
### HIPAA Breach Assessment
- **PHI Exposure:** {{ phi_exposure_assessment }}
- **Notification Required:** {{ notification_required }}
- **Timeline:** {{ breach_notification_timeline }}
{% elif vertical == 'finance' %}
### PCI-DSS Assessment
- **Cardholder Data Affected:** {{ chd_affected }}
- **Forensic Investigation Required:** {{ forensic_required }}
{% endif %}

## Data Classification
| Data Type | Volume | Classification | Exposure Risk |
|-----------|--------|----------------|---------------|
{{ data_table }}

## Control Failures
1. {{ control_failure_1 }}
2. {{ control_failure_2 }}

## Remediation for Compliance
{{ compliance_remediation }}

## Audit Trail
{{ audit_log }}
```

**External Auditor Report (Redacted):**
```markdown
# Security Incident Summary (External Distribution)

**Incident ID:** {{ incident.id_redacted }}
**Date Range:** {{ date_range }}
**Severity:** {{ severity }}

## Incident Overview
{{ high_level_summary }}
*(Internal systems and specific IOCs redacted for security)*

## Impact Assessment
- **Systems Affected:** {{ systems_count }} (types redacted)
- **Data Categories:** {{ data_categories_generic }}
- **Service Disruption:** {{ disruption_level }}

## Response Actions
1. {{ generic_action_1 }}
2. {{ generic_action_2 }}

## Lessons Learned
{{ lessons_learned }}

---
*This report has been sanitized for external distribution. Internal IPs, specific system names, and detailed IOCs have been redacted.*
```

### 5.3 Secure Report Distribution

**Report Generation API:**

```python
# src/api/report_endpoints.py

@router.post('/api/v1/reports/generate')
async def generate_persona_report(
    incident_id: str,
    recipient_profile: RecipientProfile,
    current_user: User = Depends(require_auth)
):
    """
    Generate persona-tailored report with security controls

    Security checks:
    1. User has permission to share this incident
    2. Recipient clearance level validated
    3. Vertical-specific redactions applied
    4. Audit log created (who sent what to whom)
    """

    # Authorization check
    if not await can_generate_report(current_user, incident_id, recipient_profile.clearance):
        raise HTTPException(403, "Insufficient permissions to generate report for this clearance level")

    # Load incident with clearance-appropriate data
    incident = await load_incident(incident_id, clearance=recipient_profile.clearance)

    # Apply vertical-specific redactions
    if recipient_profile.vertical:
        incident = apply_vertical_redactions(incident, recipient_profile.vertical)

    # Apply clearance-based filtering
    if recipient_profile.clearance == 'external':
        incident = redact_sensitive_iocs(incident)
        incident = anonymize_internal_systems(incident)

    # Select template based on role
    template = get_template_for_role(recipient_profile.role)

    # Generate report (LLM-enhanced)
    report = await generate_report(
        template=template,
        incident=incident,
        profile=recipient_profile,
        llm_enhance=True  # Use LLM to tailor language and summarize
    )

    # Audit logging
    await audit_log.record({
        'action': 'report_generated',
        'incident_id': incident_id,
        'generated_by': current_user.email,
        'recipient': recipient_profile.email,
        'recipient_role': recipient_profile.role,
        'clearance': recipient_profile.clearance,
        'timestamp': datetime.utcnow(),
        'report_hash': hash(report.content)  # For tamper detection
    })

    return {
        'report_url': f'/reports/{report.id}',
        'format': 'pdf',  # or 'html', 'docx'
        'expires_at': datetime.utcnow() + timedelta(days=30)
    }
```

**UI: Quick Report Generation**

```html
<!-- Simple 3-step wizard -->
<div class="report-wizard">
  <h3>Generate Report for Incident {{ incident.id }}</h3>

  <!-- Step 1: Who -->
  <div class="step">
    <label>Send to:</label>
    <select id="recipientSelect">
      <option value="preset_ciso">CISO (Jane Doe)</option>
      <option value="preset_compliance">Compliance Officer (John Smith)</option>
      <option value="custom">Custom Recipient...</option>
    </select>
  </div>

  <!-- Step 2: Clearance (if custom) -->
  <div class="step" id="clearanceStep" style="display:none;">
    <label>Security Clearance:</label>
    <div class="radio-group">
      <label><input type="radio" name="clearance" value="full"> Full (Internal SOC)</label>
      <label><input type="radio" name="clearance" value="limited"> Limited (IT Management)</label>
      <label><input type="radio" name="clearance" value="external"> External (Auditors, Partners)</label>
    </div>
  </div>

  <!-- Step 3: Focus Areas (multi-select) -->
  <div class="step">
    <label>Report Focus:</label>
    <div class="checkbox-group">
      <label><input type="checkbox" name="focus" value="executive" checked> Executive Summary</label>
      <label><input type="checkbox" name="focus" value="technical"> Technical Details</label>
      <label><input type="checkbox" name="focus" value="compliance"> Compliance Implications</label>
      <label><input type="checkbox" name="focus" value="remediation"> Remediation Steps</label>
    </div>
  </div>

  <!-- Generate -->
  <button class="btn-primary" onclick="generateReport()">
    Generate Report (Est. 15 seconds)
  </button>
</div>
```

**Preset Profiles (Stored per Organization):**

```python
# src/reporting/presets.py

ORGANIZATION_PRESETS = {
    'org_123': {
        'ciso': RecipientProfile(
            role='ciso',
            clearance='full',
            vertical='healthcare',
            focus=['executive', 'risk', 'compliance'],
            redact_pii=True
        ),
        'compliance_officer': RecipientProfile(
            role='compliance_officer',
            clearance='full',
            vertical='healthcare',
            focus=['compliance', 'remediation'],
            redact_pii=False  # Compliance needs full PII context
        ),
        'external_auditor': RecipientProfile(
            role='external_auditor',
            clearance='external',
            vertical='healthcare',
            focus=['executive', 'compliance'],
            redact_pii=True,
            redact_internal_ips=True,
            redact_usernames=True
        )
    }
}
```

---

## UI/UX Design

### 6.1 Binary Analysis Enrichment UI

**Artifact Detail Card (Enhanced):**

```
┌─────────────────────────────────────────────────────────────────┐
│ 📄 Artifact: suspicious.exe                           [Actions ▼]│
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ Risk Score: 0.87 (High)                                          │
│ ████████████████░░░░                                             │
│                                                                  │
│ 🔍 Binary Analysis (Auto-Enriched)                               │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ File Type: PE32 executable                                 │  │
│ │ Magic Number: MZ (valid)                                   │  │
│ │ Signed: ❌ No                                               │  │
│ │ Compile Time: 2025-11-28 (2 days ago) ⚠️                   │  │
│ │ Entropy: 7.8/8.0 (High - likely packed) ⚠️                 │  │
│ │                                                            │  │
│ │ Suspicious Imports Detected:                               │  │
│ │  • CreateRemoteThread ⚠️                                   │  │
│ │  • VirtualAllocEx ⚠️                                        │  │
│ │  • WriteProcessMemory ⚠️                                    │  │
│ │  → Indicates process injection capability                  │  │
│ │                                                            │  │
│ │ Sections:                                                  │  │
│ │  .text   (RX)  ✓                                           │  │
│ │  .data   (RW)  ✓                                           │  │
│ │  .rsrc   (RWX) ⚠️ Executable resource section!            │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ 🧬 Obfuscation Analysis                                          │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ XOR Encoding: Detected (key: 0x42)                         │  │
│ │ Decoded Preview: "http://malicious-c2[.]com/payload.bin"   │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ 🌐 Threat Intel (Cached)                                         │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ VirusTotal: 45/71 detections                               │  │
│ │ AlienVault: 3 pulses (APT28, Emotet, Generic Trojan)       │  │
│ │ Last Updated: 2 hours ago                                  │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ 🔬 Memory Analysis                                               │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ Status: Not scanned                                        │  │
│ │                                                            │  │
│ │ [Request Memory Scan] 💰 $0.15 | ⏱️ ~45s                   │  │
│ │                                                            │  │
│ │ ℹ️ Cached scan from similar hash (95% match) available     │  │
│ │    [View Similar Scan Results]                             │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ 🕸️ HopGraph Context                                              │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ Attack Chain:                                              │  │
│ │                                                            │  │
│ │  winword.exe (signed) ──spawned──> suspicious.exe          │  │
│ │       │                                  │                 │  │
│ │  (opened doc)                     (loaded malicious.dll)   │  │
│ │                                           │                 │  │
│ │                                      (connected to)        │  │
│ │                                           │                 │  │
│ │                                    192.168.1.50:4444       │  │
│ │                                    (rare destination)      │  │
│ │                                                            │  │
│ │ [View Full Graph] [Export IOCs]                            │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ Actions:                                                         │
│ [Escalate to Tier 2] [Mark as FP] [Quarantine] [Generate Report]│
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Memory Scan Progress UI

```
┌─────────────────────────────────────────────────────────────────┐
│ 🔬 Memory Analysis: suspicious.exe (PID 1234)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ Status: Analyzing...                                             │
│ ████████████████░░░░░░░░ 65%                                     │
│                                                                  │
│ Timeline:                                                        │
│ ✓ Memory dump acquired (2.3 seconds)                             │
│ ✓ YARA scan complete (12 rules matched)                          │
│ ⏳ String extraction in progress...                              │
│ ⌛ Shellcode detection pending                                   │
│                                                                  │
│ Preliminary Findings:                                            │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ ⚠️ Injected Code Detected                                   │  │
│ │   Location: 0x00400000 (non-image memory)                  │  │
│ │   Pattern: Cobalt Strike beacon signature                  │  │
│ │                                                            │  │
│ │ ⚠️ Suspicious Strings Extracted                             │  │
│ │   • "http://185.220.101.50/payload"                        │  │
│ │   • "mimikatz"                                             │  │
│ │   • "SeDebugPrivilege"                                     │  │
│ │                                                            │  │
│ │ ⚠️ Unmapped DLL Found                                       │  │
│ │   evil.dll (not in process module list)                    │  │
│ │   SHA256: a3b2c1d4...                                       │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ Cost: $0.15 | Analyst: jane.doe@company.com                      │
│                                                                  │
│ [Cancel Scan] [Add to Tier 2 Context] [Download Raw Dump]       │
└─────────────────────────────────────────────────────────────────┘
```

### 6.3 Report Generation Wizard UI

```
┌─────────────────────────────────────────────────────────────────┐
│ 📊 Generate Incident Report                                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ Incident: INC-2025-1234 (Suspicious Process Injection)           │
│                                                                  │
│ Step 1: Select Recipient                                         │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ Common Recipients:                                         │  │
│ │                                                            │  │
│ │ [📧 CISO - Jane Doe]        (Full clearance, Risk focus)   │  │
│ │ [📧 SOC Manager - Bob Lee]  (Full clearance, Technical)    │  │
│ │ [📧 Compliance - Sue Kim]   (Full clearance, Compliance)   │  │
│ │ [📧 External Auditor - PwC] (External, Redacted)           │  │
│ │                                                            │  │
│ │ [+ Add Custom Recipient]                                   │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ Step 2: Customize Content (Optional)                             │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ Include:                                                   │  │
│ │ ☑️ Executive Summary                                        │  │
│ │ ☑️ Technical Timeline                                       │  │
│ │ ☑️ IOCs (full list)                                         │  │
│ │ ☑️ HopGraph visualization                                   │  │
│ │ ☑️ Compliance assessment (HIPAA)                            │  │
│ │ ☐ Raw logs (large file warning)                            │  │
│ │                                                            │  │
│ │ Redactions:                                                │  │
│ │ ☐ Redact internal IPs                                      │  │
│ │ ☑️ Redact PII (usernames, emails)                           │  │
│ │ ☐ Anonymize system names                                   │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ Step 3: Delivery                                                 │
│ ┌────────────────────────────────────────────────────────────┐  │
│ │ Format: ○ PDF  ● HTML  ○ DOCX                              │  │
│ │                                                            │  │
│ │ Delivery: ● Email  ○ Secure Download Link  ○ Print         │  │
│ │                                                            │  │
│ │ Expiration: [30 days ▼]                                    │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│ [Preview Report] [Generate & Send] [Save as Draft]               │
│                                                                  │
│ ⏱️ Estimated generation time: 15 seconds                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prometheus & Grafana Metrics

### 7.1 Binary Analysis Metrics

```python
# src/artifact/binary_analysis.py

from prometheus_client import Counter, Histogram, Gauge

# Counters
binary_analysis_total = Counter(
    'binary_analysis_total',
    'Total binaries analyzed',
    ['file_type', 'result']  # result: clean | suspicious | malicious | error
)

binary_magic_mismatch_total = Counter(
    'binary_magic_mismatch_total',
    'File type mismatches detected'
)

binary_suspicious_imports_total = Counter(
    'binary_suspicious_imports_total',
    'Binaries with suspicious API imports',
    ['api_category']  # injection | evasion | credential_access
)

obfuscation_detected_total = Counter(
    'obfuscation_detected_total',
    'Obfuscated artifacts detected',
    ['technique']  # xor | base64 | multilayer | shellcode
)

# Histograms (latency)
binary_analysis_duration_seconds = Histogram(
    'binary_analysis_duration_seconds',
    'Binary analysis latency',
    ['file_type'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0]
)

# Gauges
binary_analysis_queue_depth = Gauge(
    'binary_analysis_queue_depth',
    'Pending binary analyses'
)
```

### 7.2 Threat Intel Metrics

```python
# src/integrations/threat_intel_router.py

threat_intel_lookups_total = Counter(
    'threat_intel_lookups_total',
    'Threat intel lookups',
    ['provider', 'result']  # provider: virustotal | alienvault | misp
                             # result: hit | miss | error | rate_limited
)

threat_intel_cache_hits_total = Counter(
    'threat_intel_cache_hits_total',
    'Cache hits for threat intel',
    ['provider']
)

threat_intel_cost_usd = Counter(
    'threat_intel_cost_usd',
    'Cumulative threat intel costs',
    ['provider']
)

threat_intel_latency_seconds = Histogram(
    'threat_intel_latency_seconds',
    'Threat intel lookup latency',
    ['provider'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0]
)
```

### 7.3 Memory Analysis Metrics

```python
# src/analysis/memory_scanner.py

memory_scans_total = Counter(
    'memory_scans_total',
    'Memory scans requested',
    ['trigger']  # analyst_manual | auto_escalation
)

memory_scan_cost_usd = Counter(
    'memory_scan_cost_usd',
    'Cumulative memory scan costs'
)

memory_scan_findings_total = Counter(
    'memory_scan_findings_total',
    'Memory scan findings',
    ['finding_type']  # injected_code | shellcode | suspicious_string | unmapped_dll
)

memory_scan_duration_seconds = Histogram(
    'memory_scan_duration_seconds',
    'Memory scan latency',
    buckets=[5, 15, 30, 60, 120, 300]
)

memory_scan_cache_hits_total = Counter(
    'memory_scan_cache_hits_total',
    'Memory scan cache hits'
)
```

### 7.4 Report Generation Metrics

```python
# src/reporting/generator.py

reports_generated_total = Counter(
    'reports_generated_total',
    'Reports generated',
    ['role', 'clearance', 'vertical']
)

report_generation_duration_seconds = Histogram(
    'report_generation_duration_seconds',
    'Report generation time',
    ['role'],
    buckets=[1, 5, 10, 20, 30, 60]
)

report_downloads_total = Counter(
    'report_downloads_total',
    'Report downloads',
    ['format']  # pdf | html | docx
)
```

### 7.5 Grafana Dashboard: Binary Analysis

```json
{
  "title": "Binary Analysis & Enrichment",
  "panels": [
    {
      "title": "Binary Analysis Throughput",
      "targets": [
        {
          "expr": "rate(binary_analysis_total[5m])",
          "legendFormat": "{{result}}"
        }
      ]
    },
    {
      "title": "Magic Number Mismatches",
      "targets": [
        {
          "expr": "binary_magic_mismatch_total",
          "legendFormat": "File type spoofing attempts"
        }
      ]
    },
    {
      "title": "Suspicious Imports by Category",
      "targets": [
        {
          "expr": "binary_suspicious_imports_total",
          "legendFormat": "{{api_category}}"
        }
      ]
    },
    {
      "title": "Obfuscation Techniques Detected",
      "targets": [
        {
          "expr": "obfuscation_detected_total",
          "legendFormat": "{{technique}}"
        }
      ]
    },
    {
      "title": "Analysis Latency (p95)",
      "targets": [
        {
          "expr": "histogram_quantile(0.95, binary_analysis_duration_seconds_bucket)",
          "legendFormat": "{{file_type}}"
        }
      ]
    }
  ]
}
```

### 7.6 Grafana Dashboard: Memory Analysis & Cost Control

```json
{
  "title": "Memory Analysis & Cost Optimization",
  "panels": [
    {
      "title": "Memory Scans (By Trigger)",
      "targets": [
        {
          "expr": "memory_scans_total",
          "legendFormat": "{{trigger}}"
        }
      ]
    },
    {
      "title": "Memory Scan Cost (Daily)",
      "targets": [
        {
          "expr": "increase(memory_scan_cost_usd[1d])",
          "legendFormat": "Total daily cost"
        }
      ]
    },
    {
      "title": "Cache Hit Rate",
      "targets": [
        {
          "expr": "memory_scan_cache_hits_total / memory_scans_total",
          "legendFormat": "Cache efficiency"
        }
      ]
    },
    {
      "title": "Findings per Scan",
      "targets": [
        {
          "expr": "memory_scan_findings_total",
          "legendFormat": "{{finding_type}}"
        }
      ]
    },
    {
      "title": "Cost Savings (Cache)",
      "targets": [
        {
          "expr": "memory_scan_cache_hits_total * 0.15",
          "legendFormat": "Saved USD (cached results)"
        }
      ]
    }
  ]
}
```

---

## Cost Optimization Strategy

### 8.1 Cost Breakdown (Per Incident)

| Component | Cost | Trigger | Optimization |
|-----------|------|---------|--------------|
| Binary Analysis | $0.00 | Always (pre-Tier 1) | Local, no external cost |
| Threat Intel (VT) | $0.01 | Risk > 0.60 | Cache (7 days), rate limit |
| Tier 1 LLM | $0.02 | Always | Use Haiku/Small model |
| Memory Scan | $0.15 | Analyst request | Cache (7 days), SHA256 dedup |
| Tier 2 LLM | $0.08 | Escalation | Use Sonnet, include all context |
| Sandbox Analysis | $2.50 | Manual request | Cache (30 days), rare use |

**Average Incident Cost (Before Optimizations):** $2.76
**Average Incident Cost (With Caching + Human Agency):** $0.35
**Savings:** 87%

### 8.2 Budget Controls

```python
# src/api/budget_tracker.py

class BudgetTracker:
    """Enforce daily/monthly cost limits"""

    async def can_spend(self, category: str, amount: float) -> bool:
        """Check if operation is within budget"""
        today_spend = await self.get_daily_spend(category)
        daily_limit = self.get_limit(category, 'daily')

        if today_spend + amount > daily_limit:
            await self.alert_budget_exceeded(category, today_spend, daily_limit)
            return False

        return True

    async def record(self, category: str, amount: float, analyst_id: str):
        """Record spend with attribution"""
        await self.db.insert('budget_ledger', {
            'category': category,
            'amount': amount,
            'analyst_id': analyst_id,
            'timestamp': datetime.utcnow()
        })
```

**Budget Limits (Configurable):**

```python
# .env
BUDGET_DAILY_THREAT_INTEL=10.00      # $10/day for all TI lookups
BUDGET_DAILY_MEMORY_SCANS=50.00      # $50/day for memory analysis
BUDGET_DAILY_SANDBOX=100.00          # $100/day for sandbox submissions
BUDGET_MONTHLY_LLM=500.00            # $500/month for all LLM calls

# Alerts
BUDGET_ALERT_THRESHOLD=0.80          # Alert at 80% of daily limit
BUDGET_ALERT_EMAIL=security-ops@company.com
```

### 8.3 Human Agency = Cost Control

**Key Insight:** Analysts decide when expensive operations are warranted.

**Example Flow:**
1. Binary analysis (free) detects suspicious imports
2. Tier 1 LLM ($0.02) summarizes: "Potential process injection"
3. Analyst reviews, sees HopGraph context
4. Analyst decides: "This looks like dev tool, not malware"
5. Marks as FP → Saves $0.15 (memory scan) + $0.08 (Tier 2)

**Result:** Only ~20% of incidents need expensive deep analysis.

---

## Security & Compliance

### 9.1 Report Distribution Security

**Controls:**

1. **Audit Logging:**
   - Every report generation logged with recipient details
   - Tamper detection via report content hashing
   - Retention: 7 years (compliance requirement)

2. **Clearance Enforcement:**
   ```python
   async def can_generate_report(user: User, incident_id: str, clearance: str) -> bool:
       # User must have equal or higher clearance
       if user.clearance_level < CLEARANCE_LEVELS[clearance]:
           return False

       # Incident classification check
       incident = await load_incident(incident_id)
       if incident.classification == 'confidential' and clearance == 'external':
           return False

       return True
   ```

3. **Automatic Redactions:**
   ```python
   def redact_sensitive_iocs(incident: Incident) -> Incident:
       """Auto-redact for external recipients"""
       incident.internal_ips = ['[REDACTED]'] * len(incident.internal_ips)
       incident.usernames = ['[REDACTED]'] * len(incident.usernames)
       incident.system_names = [anonymize(name) for name in incident.system_names]
       return incident
   ```

4. **Report Expiration:**
   - Download links expire after configurable period (default: 30 days)
   - No email attachments for external recipients (secure link only)

### 9.2 Compliance Mappings

**Vertical-Specific Requirements:**

```python
COMPLIANCE_REQUIREMENTS = {
    'healthcare': {
        'frameworks': ['HIPAA', 'HITECH'],
        'mandatory_sections': ['phi_exposure', 'breach_notification'],
        'retention_years': 7
    },
    'finance': {
        'frameworks': ['PCI-DSS', 'SOX', 'GLBA'],
        'mandatory_sections': ['cardholder_data', 'sox_controls'],
        'retention_years': 7
    },
    'government': {
        'frameworks': ['FISMA', 'NIST 800-53', 'FedRAMP'],
        'mandatory_sections': ['classification', 'incident_category'],
        'retention_years': 10
    }
}
```

---

## Implementation Roadmap

### Phase 1: Binary Enrichment (Week 1-2)
- [ ] Implement `binary_analysis.py` (magic numbers, PE parsing)
- [ ] Add obfuscation detection (XOR, multi-layer)
- [ ] Integrate into pre-Tier 1 pipeline
- [ ] Add Prometheus metrics
- [ ] UI: Display binary analysis in artifact cards
- **Deliverable:** Binary analysis visible in UI, no external costs

### Phase 2: HopGraph Integration (Week 3)
- [ ] Add binary nodes to HopGraph schema
- [ ] Implement graph-derived factors
- [ ] Create graph queries for attack chains
- [ ] UI: Visualize binary → process → network paths
- **Deliverable:** Attack chains include binary analysis context

### Phase 3: Threat Intel (Week 4)
- [ ] Implement `threat_intel_router.py`
- [ ] Add VT, AlienVault integrations
- [ ] Cache layer with 7-day TTL
- [ ] Budget tracking and rate limiting
- [ ] UI: Show threat intel in artifact cards (with cache status)
- **Deliverable:** Safe, cost-controlled threat intel enrichment

### Phase 4: Memory Analysis (Week 5-6)
- [ ] Implement agent-based memory collection
- [ ] YARA + string extraction + shellcode detection
- [ ] Cache layer (SHA256-based, 7-day TTL)
- [ ] UI: "Request Memory Scan" button with cost display
- [ ] WebSocket progress streaming
- **Deliverable:** On-demand memory analysis with human approval

### Phase 5: Persona Reporting (Week 7-8)
- [ ] Implement `RecipientProfile` schema
- [ ] Create role-based templates (CISO, SOC, Compliance, External)
- [ ] LLM-enhanced report generation
- [ ] Clearance-based redactions
- [ ] UI: 3-step report wizard
- [ ] Audit logging for report distribution
- **Deliverable:** Tailored, secure report generation

### Phase 6: Metrics & Dashboards (Week 9)
- [ ] Deploy Grafana dashboards
- [ ] Set up budget alerts
- [ ] Create cost optimization reports
- **Deliverable:** Full observability + cost tracking

---

## Success Metrics

### Technical KPIs
- **Binary Analysis Coverage:** >95% of executables analyzed
- **Threat Intel Cache Hit Rate:** >70%
- **Memory Scan Latency:** <60 seconds (p95)
- **False Positive Reduction:** 30% (via better enrichment)

### Cost KPIs
- **Average Cost per Incident:** <$0.50 (vs. $2.76 baseline)
- **Memory Scan Cache Savings:** >$50/month
- **Threat Intel Budget Adherence:** <$10/day

### User Experience KPIs
- **Report Generation Time:** <20 seconds (p95)
- **Analyst Time Saved:** 40% (via better context)
- **Report Customization Time:** <2 minutes

---

## Conclusion

This implementation delivers:

1. ✅ **Better Enrichment:** Binary analysis + obfuscation detection + threat intel
2. ✅ **HopGraph Integration:** Attack chains with binary context
3. ✅ **Cost Control:** Human-in-the-loop + caching = 87% cost reduction
4. ✅ **Human Agency:** Analysts decide when to deep-dive
5. ✅ **Secure Reporting:** Clearance-aware, vertical-specific, auditable
6. ✅ **Simple UX:** 3-click report generation, 1-click memory scans

**You're not smoking crack.** You're designing a platform that respects analyst expertise while leveraging AI efficiency. This is exactly how modern SOCs should operate.

**Next Steps:**
1. Review this RFC with team
2. Prioritize phases based on customer pain points
3. Start with Phase 1 (binary enrichment) - highest ROI, no external costs
4. Iterate based on analyst feedback

---

**Questions? Feedback?**
Open a PR or discussion in the repo.
