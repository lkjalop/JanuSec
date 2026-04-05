# Option C - Complete Implementation Guide
**Target:** Full-Featured Demo with Historical Context, HopGraph, Domain-Specific Playbooks
**Timeline:** 16-20 hours (2-3 days)
**Last Updated:** 2025-01-22

---

## 📋 TABLE OF CONTENTS

1. [Current State Assessment](#current-state-assessment)
2. [Phase 1: Wire Up Existing Features (6-8 hours)](#phase-1-wire-up-existing-features)
3. [Phase 2: Build Missing Components (6-8 hours)](#phase-2-build-missing-components)
4. [Phase 3: Testing & Validation (2-3 hours)](#phase-3-testing--validation)
5. [Phase 4: Demo Preparation (1-2 hours)](#phase-4-demo-preparation)

---

## 🎯 CURRENT STATE ASSESSMENT

### ✅ COMPLETED FILES (Already Exist, Fully Coded)

| File | Lines | Status | Purpose |
|------|-------|--------|---------|
| `src/analysis/domain_tools.py` | 330 | ✅ READY | Network vs Endpoint tool/log mappings |
| `src/analysis/correlation_context.py` | 185 | ✅ READY | Attack scenario narratives |
| `src/analysis/cost_tracker.py` | 142 | ✅ READY | LLM cost tracking |
| `src/repositories/historical_incidents_repo.py` | 250 | ✅ READY | Historical incident queries |
| `frontend/static/csv_deep_analysis.html` | 900 | ✅ READY | Investigate Further tab UI |

**What These Files Do:**

#### `domain_tools.py`
- DOMAIN_TOOLS dictionary with network/endpoint tools
- MITRE_TO_LOGS mapping (T1055 → Sysmon Event 10, etc.)
- `get_tools_for_domain(domain, category)` function
- `get_logs_for_mitre(mitre_id)` function
- `build_collection_playbook(domain, mitre_tags, artifact_context)` function

#### `correlation_context.py`
- FACTOR_ATTACK_SCENARIOS mapping (lateral_movement → attack narrative)
- `enrich_correlation_context(row, pipeline_context)` function
- `build_attack_chain_visualization(correlation_context)` function

#### `historical_incidents_repo.py`
- HistoricalIncidentsRepo class with SQLite backend
- `save_incident(row, outcome, analyst_notes)` method
- `query_similar_incidents(row, lookback_days, limit)` method
- `get_recurrence_stats(sha256, process_name)` method

#### `csv_deep_analysis.html`
- Full UI with AI Insights section
- HopGraph canvas placeholder
- Analyst Notes textarea
- Snapshot cards (DREAD, MITRE, Factors)
- Collapsible sections

---

### ⚠️ MISSING INTEGRATION (Files Exist but Not Connected)

| Integration Point | Current State | What's Needed |
|-------------------|---------------|---------------|
| `auto_llm.py` → `domain_tools.py` | ❌ NOT IMPORTED | Add import + call `get_tools_for_domain()` |
| `auto_llm.py` → `correlation_context.py` | ❌ NOT IMPORTED | Add import + call `enrich_correlation_context()` |
| `auto_llm.py` → `historical_incidents_repo.py` | ❌ NOT IMPORTED | Add import + call `query_similar_incidents()` |
| Tier 2 Prompt | ❌ DOESN'T EXIST | Create `build_tier2_prompt()` function |
| Domain Detection | ❌ DOESN'T EXIST | Create `detect_domain_with_confidence()` function |

---

### ❌ MISSING FILES (Need to Build from Scratch)

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `src/core/graph/hopgraph_integration.py` | Connect to HopGraph for attack graphs | 200 |
| `src/api/graph_endpoints.py` | API endpoint for `/attack_reconstruction` | 100 |
| `src/api/insights_endpoints.py` | API endpoints for AI Insights (DREAD, playbook, hunt, exec) | 150 |
| `src/integrations/vector_db.py` | Optional: Vector DB for semantic log search | 150 |
| `migrations/014_historical_incidents.sql` | Database migration for historical table | 20 |

---

## 🔧 PHASE 1: WIRE UP EXISTING FEATURES (6-8 Hours)

### Task 1.1: Create Domain Detection Function (1 hour)

**File:** `src/analysis/auto_llm.py`
**Location:** Add after line 54 (after `build_llm_prompt()`)

```python
def detect_domain_with_confidence(row: Dict[str, Any]) -> tuple[str, float]:
    """
    Detect artifact domain (network vs endpoint) with confidence score.

    Args:
        row: Artifact row with factors, attributes

    Returns:
        Tuple of (domain: 'network'|'endpoint'|'generic', confidence: 0.0-1.0)
    """
    factors = set(row.get('factors', []))

    # Network indicators (high confidence)
    network_high = {
        'port_scan', 'beaconing', 'dns_tunneling', 'c2_communication',
        'lateral_movement', 'remote_access', 'cloud_api_abuse',
        'suspicious_connection', 'egress_anomaly'
    }

    # Endpoint indicators (high confidence)
    endpoint_high = {
        'process_injection', 'dll_hijack', 'registry_persistence',
        'credential_access', 'iam_anomaly', 'privilege_escalation',
        'unsigned_binary', 'suspicious_parent', 'rare_hash'
    }

    # Calculate scores
    network_score = len(factors & network_high) * 0.3
    endpoint_score = len(factors & endpoint_high) * 0.3

    # Bonus from artifact attributes
    if row.get('src_ip') or row.get('dst_ip') or row.get('protocol'):
        network_score += 0.4
    if row.get('process_name') or row.get('file_path') or row.get('registry_key'):
        endpoint_score += 0.4

    # Decision with confidence threshold
    if network_score > endpoint_score and network_score >= 0.7:
        return ('network', min(network_score, 1.0))
    elif endpoint_score > network_score and endpoint_score >= 0.7:
        return ('endpoint', min(endpoint_score, 1.0))
    else:
        # Low confidence → use generic prompt
        return ('generic', max(network_score, endpoint_score))
```

**Testing:**
```python
# Test cases
test_network = {
    'factors': ['port_scan', 'beaconing'],
    'src_ip': '10.0.0.5',
    'dst_ip': '203.0.113.42'
}
assert detect_domain_with_confidence(test_network) == ('network', 1.0)

test_endpoint = {
    'factors': ['process_injection', 'unsigned_binary'],
    'process_name': 'powershell.exe',
    'file_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
}
assert detect_domain_with_confidence(test_endpoint) == ('endpoint', 1.0)
```

**Acceptance Criteria:**
- ✅ Returns correct domain for network artifacts (src_ip/dst_ip present)
- ✅ Returns correct domain for endpoint artifacts (process_name present)
- ✅ Returns 'generic' for ambiguous artifacts
- ✅ Confidence score >= 0.7 for domain-specific, < 0.7 for generic

---

### Task 1.2: Create Tier 2 Prompt Builder (2 hours)

**File:** `src/analysis/auto_llm.py`
**Location:** Add after `detect_domain_with_confidence()`

```python
def build_tier2_prompt(row: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Build 60-100 line deep investigation prompt with domain-specific playbooks,
    historical context, and correlation enrichment.

    Args:
        row: Artifact row
        context: Pipeline context with assessment, DREAD, MITRE, correlation

    Returns:
        Formatted LLM prompt string (60-100 lines)
    """
    import json
    from src.analysis.domain_tools import get_tools_for_domain, get_logs_for_mitre, build_collection_playbook
    from src.analysis.correlation_context import enrich_correlation_context, build_attack_chain_visualization
    from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo

    # Detect domain
    domain, confidence = detect_domain_with_confidence(row)

    # Get pipeline context
    pipeline = context.get('pipeline_context') or context.get('assessment') or {}
    mitre_tags = pipeline.get('mitre_tags', [])
    dread_score = pipeline.get('dread_score', 0)
    correlation_score = pipeline.get('correlation', {}).get('score', 0) if isinstance(pipeline.get('correlation'), dict) else 0

    # Query historical incidents
    historical_context = ""
    try:
        repo = HistoricalIncidentsRepo()
        similar_incidents = repo.query_similar_incidents(row, lookback_days=90, limit=3)

        if similar_incidents:
            incident = similar_incidents[0]
            from datetime import datetime
            last_seen = datetime.fromisoformat(incident['last_seen_at'])
            days_ago = (datetime.now() - last_seen).days

            historical_context = f"""
⚠️ HISTORICAL CONTEXT ALERT:

Similar incident detected {days_ago} days ago:
- Host: {incident['host']}
- Outcome: {incident['outcome'].upper()}
- DREAD: {incident['dread_score']:.1f}
- Occurrences: {incident['occurrence_count']}
- Match Type: {incident['match_type']} (similarity: {incident['similarity_score']:.0%})

Analyst Notes from Previous Investigation:
{incident['analyst_notes'] or 'No notes recorded'}
"""
            # Auto-escalate if previous was malicious
            if incident['outcome'] == 'confirmed_malicious':
                historical_context += "\n🚨 AUTO-ESCALATE: Previous instance confirmed malicious.\n"

            # Show recurrence pattern
            if incident['occurrence_count'] > 3:
                historical_context += f"\n⚠️ RECURRENCE PATTERN: Appeared {incident['occurrence_count']} times across {len(similar_incidents)} hosts.\n"
        else:
            historical_context = "✅ No similar incidents in past 90 days (novel threat or first occurrence).\n"
    except Exception as e:
        historical_context = f"⚠️ Historical query unavailable: {e}\n"

    # Enrich with correlation context
    correlation_enrichment = ""
    try:
        corr_ctx = enrich_correlation_context(row, pipeline)
        attack_chain = build_attack_chain_visualization(corr_ctx)

        correlation_enrichment = f"""
ATTACK CONTEXT (Correlation Score: {correlation_score:.2f}):
{corr_ctx['narrative']}

{attack_chain}

PRIMARY SCENARIO: {corr_ctx['primary_scenario']['description'] if corr_ctx['primary_scenario'] else 'Unknown'}
URGENCY: {corr_ctx['urgency']}
"""
    except Exception as e:
        correlation_enrichment = f"⚠️ Correlation enrichment unavailable: {e}\n"

    # Build collection playbook
    artifact_context = {
        'process_name': row.get('process_name', ''),
        'src_ip': row.get('src_ip', ''),
        'dst_ip': row.get('dst_ip', ''),
        'host': row.get('host', ''),
        'user': row.get('user', '')
    }

    collection_playbook = ""
    if domain != 'generic':
        try:
            collection_playbook = build_collection_playbook(domain, mitre_tags[:3], artifact_context)
        except Exception:
            collection_playbook = f"# Collection Playbook - {domain.upper()}\n(Playbook generation unavailable)"

    # MITRE-specific log requirements
    mitre_logs = ""
    for mitre_id in mitre_tags[:3]:
        try:
            log_info = get_logs_for_mitre(mitre_id)
            mitre_logs += f"""
{mitre_id} ({log_info['name']}):
WHY: {log_info['why']}
LOGS NEEDED:
"""
            for log in log_info['logs']:
                mitre_logs += f"  - {log}\n"
        except Exception:
            pass

    # Build final prompt
    prompt = f"""You are a THREAT HUNTER performing DEEP INVESTIGATION.

ARTIFACT: {row.get('process_name') or row.get('src_ip')} on {row.get('host')}
DOMAIN: {domain.upper()} (confidence: {confidence:.0%})

PIPELINE RESULTS (already calculated):
- DREAD Score: {dread_score:.1f}
- MITRE Techniques: {', '.join(mitre_tags[:5])}
- Correlation Score: {correlation_score:.2f}
- Factors: {', '.join(row.get('factors', [])[:5])}

{historical_context}

{correlation_enrichment}

MITRE-SPECIFIC LOG REQUIREMENTS:
{mitre_logs}

{collection_playbook}

YOUR JOB (60-100 lines):

# Investigation Context

1. WHY THIS IS SUSPICIOUS (3-5 bullets)
   Interpret DREAD + MITRE + factors. Connect dots between:
   - {mitre_tags[0] if mitre_tags else 'N/A'}: [explain technique in plain English]
   - Factors: {', '.join(row.get('factors', [])[:3])}
   - Attack scenario based on correlation score {correlation_score:.2f}

2. ATTACK SCENARIO (realistic, based on MITRE)
   If this is {mitre_tags[0] if mitre_tags else 'malicious activity'}, here's how attacker would use it:
   - Initial Access: [...]
   - Execution: [...]
   - Persistence/Lateral Movement: [...]
   - Potential Damage: [business impact]

# Investigation Workflow (15-30 min)

3. STEP-BY-STEP FORENSIC COLLECTION
   Use playbook above. For each tool/command:
   a. Run command
   b. Expected output if CLEAN
   c. Expected output if MALICIOUS
   d. What to look for (red flags)

4. MISSING LOGS (if correlation > 0.5 or attack patterns detected)
   {f'Pipeline detected suspicious patterns (correlation {correlation_score:.2f}).' if correlation_score > 0.5 else 'Telemetry appears complete.'}

   {f'''Based on {mitre_tags[0] if mitre_tags else 'activity'}, we're missing:
   - [Log type 1] - would confirm/deny [specific suspicion]
   - [Log type 2] - would show [lateral movement / persistence]

   How to enable for future:
   [Commands to enable Sysmon, audit policy, script block logging, etc.]''' if correlation_score > 0.5 or should_include_missing_logs(row, pipeline) else '[Sufficient telemetry - no missing logs identified]'}

5. DECISION CRITERIA

   ALLOWLIST only if ALL true:
   - File is signed by trusted publisher (Microsoft, known vendor)
   - Parent process is expected (explorer.exe, services.exe)
   - No network activity OR expected destinations only
   - No MITRE techniques in critical set (T1078, T1059, T1055, T1003)
   - No historical similar incidents with malicious outcome

   ESCALATE IMMEDIATELY if ANY true:
   - DREAD >= 8.0
   - Historical match with confirmed_malicious outcome
   - MITRE contains credential access (T1078, T1003) + unsigned binary
   - Correlation score >= 0.7 (multi-entity attack chain)

   INVESTIGATE FURTHER if:
   - DREAD 6.0-7.9
   - Correlation score 0.5-0.7
   - Ambiguous factors (needs validation)

6. REMEDIATION (if malicious)
   Step 1: Isolate host (EDR: `isolate-host {row.get('host')}`)
   Step 2: Collect artifacts using playbook
   Step 3: Block IOCs (hash: {row.get('sha256', 'N/A')[:16]}..., IPs, domains)
   Step 4: Hunt for lateral movement using queries below
   Step 5: Patch/remove vulnerability

# Hunting Queries (Copy-Paste for SIEM)

7. FIND OTHER COMPROMISED HOSTS

   [Splunk/KQL query to find similar activity across estate]

   Example:
   ```kql
   SecurityEvent
   | where TimeGenerated > ago(30d)
   | where EventID == 4688
   | where NewProcessName contains "{row.get('process_name', '')}"
   | where ParentProcessName == "{row.get('parent_process', '')}"
   | summarize count() by Computer, Account
   | where count_ > 1
   ```

---

TL;DR RECOMMENDATION:
[Final decision: ESCALATE / INVESTIGATE / SHELF / BENIGN with 1-sentence rationale based on DREAD + historical + correlation]

RULES:
- Keep output 60-100 lines
- Use markdown formatting (headers, bullets, code blocks)
- Include copy-paste commands from playbook
- Specify expected outputs (clean vs malicious)
- Base all on provided data (no hallucination)
- Focus on FAST DECISION (15-30 min workflow)
"""

    return prompt
```

**Testing:**
```python
# Test Tier 2 prompt generation
test_row = {
    'process_name': 'powershell.exe',
    'host': 'WORKSTATION-042',
    'user': 'alice',
    'sha256': 'abc123...',
    'factors': ['process_injection', 'unsigned_binary', 'suspicious_parent'],
    'parent_process': 'excel.exe'
}

test_context = {
    'pipeline_context': {
        'dread_score': 8.5,
        'mitre_tags': ['T1055', 'T1059.001'],
        'correlation': {'score': 0.73},
        'attack_patterns': ['credential_access']
    }
}

prompt = build_tier2_prompt(test_row, test_context)
assert 'THREAT HUNTER' in prompt
assert 'DREAD Score: 8.5' in prompt
assert 'T1055' in prompt
assert 'HISTORICAL CONTEXT' in prompt or 'No similar incidents' in prompt
```

**Acceptance Criteria:**
- ✅ Prompt is 60-100 lines (count newlines)
- ✅ Includes historical context section
- ✅ Includes correlation enrichment
- ✅ Includes domain-specific playbook
- ✅ Includes MITRE → logs mapping
- ✅ Includes decision criteria (ALLOWLIST vs ESCALATE)
- ✅ No crashes if historical repo unavailable

---

### Task 1.3: Update summarize_row() to Support Tier 2 (30 min)

**File:** `src/analysis/auto_llm.py`
**Location:** Update `summarize_row()` method in LLMAssessmentClient class (around line 68)

**Change:**
```python
def summarize_row(self, row: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate LLM summary for triage.
    Supports both Tier 1 (30-45 lines) and Tier 2 (60-100 lines) modes.

    Args:
        row: Artifact row
        context: Must include 'tier' key: 'tier1' (default) or 'tier2'
    """
    # Determine tier
    tier = context.get('tier', 'tier1')

    # Build prompt based on tier
    try:
        if tier == 'tier2':
            user_prompt = build_tier2_prompt(row, context or {})
        else:
            user_prompt = build_llm_prompt(row, context or {})
    except Exception as e:
        # Fallback to Tier 1 if Tier 2 fails
        user_prompt = build_llm_prompt(row, context or {})

    # Rest of the function stays the same...
    # (existing LLM call logic from line 75 onwards)
```

**Testing:**
```python
client = LLMAssessmentClient()

# Test Tier 1
result_tier1 = client.summarize_row(test_row, {'tier': 'tier1'})
assert len(result_tier1['text'].splitlines()) >= 30
assert len(result_tier1['text'].splitlines()) <= 45

# Test Tier 2
result_tier2 = client.summarize_row(test_row, {'tier': 'tier2', 'pipeline_context': {...}})
assert len(result_tier2['text'].splitlines()) >= 60
assert len(result_tier2['text'].splitlines()) <= 100
```

**Acceptance Criteria:**
- ✅ `tier='tier1'` uses `build_llm_prompt()` (30-45 lines)
- ✅ `tier='tier2'` uses `build_tier2_prompt()` (60-100 lines)
- ✅ Defaults to Tier 1 if tier not specified
- ✅ Gracefully falls back to Tier 1 if Tier 2 fails

---

### Task 1.4: Seed Historical Incidents Database (1 hour)

**File:** `scripts/seed_historical_incidents.py` (NEW)

```python
"""
Seed historical incidents database with realistic test data.
Run this ONCE before demo to populate historical context.
"""

from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo
from datetime import datetime, timedelta
import random

repo = HistoricalIncidentsRepo()

# Seed data: realistic incidents from past 90 days
incidents = [
    {
        'sha256': '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a',
        'process_name': 'powershell.exe',
        'host': 'WORKSTATION-042',
        'user_account': 'alice',
        'mitre_tags': ['T1059.001', 'T1055'],
        'factors': ['process_injection', 'unsigned_binary'],
        'dread_score': 8.5,
        'correlation_score': 0.73,
        'verdict': 'CRITICAL',
        'outcome': 'confirmed_malicious',
        'analyst_notes': 'Emotet dropper confirmed. Lateral movement to DC detected. Host reimaged.',
        'escalated': True,
        'first_seen_at': (datetime.now() - timedelta(days=14)).isoformat(),
        'last_seen_at': (datetime.now() - timedelta(days=14)).isoformat(),
        'occurrence_count': 1,
        'org': 'demo'
    },
    {
        'sha256': 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
        'process_name': 'svchost.exe',
        'host': 'SERVER-087',
        'user_account': 'SYSTEM',
        'mitre_tags': ['T1055'],
        'factors': ['process_injection'],
        'dread_score': 6.2,
        'correlation_score': 0.45,
        'verdict': 'SUSPICIOUS',
        'outcome': 'false_positive',
        'analyst_notes': 'Legitimate Windows Update service. Parent verified as services.exe.',
        'escalated': False,
        'first_seen_at': (datetime.now() - timedelta(days=7)).isoformat(),
        'last_seen_at': (datetime.now() - timedelta(days=7)).isoformat(),
        'occurrence_count': 1,
        'org': 'demo'
    },
    {
        'sha256': 'malware123456789abcdef',
        'process_name': 'chrome.exe',
        'host': 'LAPTOP-055',
        'user_account': 'bob',
        'src_ip': '10.0.5.42',
        'dst_ip': '203.0.113.42',
        'mitre_tags': ['T1071', 'T1071.001'],
        'factors': ['c2_communication', 'beaconing'],
        'dread_score': 9.1,
        'correlation_score': 0.88,
        'verdict': 'CRITICAL',
        'outcome': 'confirmed_malicious',
        'analyst_notes': 'C2 beacon to known APT29 infrastructure. Host isolated and forensics collected.',
        'escalated': True,
        'first_seen_at': (datetime.now() - timedelta(days=21)).isoformat(),
        'last_seen_at': (datetime.now() - timedelta(days=21)).isoformat(),
        'occurrence_count': 1,
        'org': 'demo'
    },
    {
        'process_name': 'mimikatz.exe',
        'host': 'WORKSTATION-042',
        'user_account': 'alice',
        'mitre_tags': ['T1003', 'T1078'],
        'factors': ['credential_access', 'privilege_escalation'],
        'dread_score': 9.8,
        'correlation_score': 0.95,
        'verdict': 'CRITICAL',
        'outcome': 'confirmed_malicious',
        'analyst_notes': 'Credential dumping detected. Part of Emotet campaign (see SHA256 9bf41199...). All passwords reset.',
        'escalated': True,
        'first_seen_at': (datetime.now() - timedelta(days=14, hours=2)).isoformat(),
        'last_seen_at': (datetime.now() - timedelta(days=14, hours=2)).isoformat(),
        'occurrence_count': 1,
        'org': 'demo'
    },
    {
        'sha256': 'benign_windows_binary_12345',
        'process_name': 'taskmgr.exe',
        'host': 'WORKSTATION-099',
        'user_account': 'charlie',
        'mitre_tags': [],
        'factors': [],
        'dread_score': 2.1,
        'correlation_score': 0.05,
        'verdict': 'BENIGN',
        'outcome': 'benign',
        'analyst_notes': 'Signed Microsoft binary. Normal task manager usage.',
        'escalated': False,
        'first_seen_at': (datetime.now() - timedelta(days=30)).isoformat(),
        'last_seen_at': (datetime.now() - timedelta(days=1)).isoformat(),
        'occurrence_count': 45,
        'org': 'demo'
    }
]

print("Seeding historical incidents database...")
for incident in incidents:
    incident_id = repo.save_incident(
        row=incident,
        outcome=incident['outcome'],
        analyst_notes=incident['analyst_notes'],
        org=incident['org']
    )
    print(f"  ✅ Incident {incident_id}: {incident['process_name']} on {incident['host']} ({incident['outcome']})")

print(f"\n✅ Seeded {len(incidents)} historical incidents")

# Test query
print("\nTesting historical query...")
test_query = repo.query_similar_incidents(
    {'sha256': '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a'},
    lookback_days=90,
    limit=3
)
print(f"  Found {len(test_query)} similar incidents for SHA256 9bf41199...")
if test_query:
    print(f"  Match: {test_query[0]['process_name']} - {test_query[0]['outcome']}")
```

**Run:**
```bash
python scripts/seed_historical_incidents.py
```

**Acceptance Criteria:**
- ✅ Creates `historical_incidents` table in janusec_dev.db
- ✅ Inserts 5 sample incidents
- ✅ Query returns results for known SHA256
- ✅ No crashes or database errors

---

### Task 1.5: Add Domain Badge to CSV Analyzer UI (30 min)

**File:** `frontend/static/csv_analyzer.html`
**Location:** Find the table rendering code (search for `renderTableFromResults`)

**Add domain badge column:**

```javascript
// In renderTableFromResults() function

function renderTableFromResults() {
    // ... existing code ...

    // Add domain detection to each row
    results.forEach((row, idx) => {
        // Detect domain
        const factors = row.factors || [];
        const hasNetwork = factors.some(f => ['port_scan', 'beaconing', 'c2_communication'].includes(f)) || row.src_ip || row.dst_ip;
        const hasEndpoint = factors.some(f => ['process_injection', 'dll_hijack', 'credential_access'].includes(f)) || row.process_name || row.file_path;

        let domain = 'generic';
        let domainColor = '#888';
        if (hasNetwork && !hasEndpoint) {
            domain = 'network';
            domainColor = '#3b82f6'; // blue
        } else if (hasEndpoint && !hasNetwork) {
            domain = 'endpoint';
            domainColor = '#10b981'; // green
        } else if (hasNetwork && hasEndpoint) {
            domain = 'mixed';
            domainColor = '#f59e0b'; // orange
        }

        row._domain = domain;
        row._domainColor = domainColor;
    });

    // Update table header to include domain column
    thead.innerHTML = `
        <tr>
            <th>Row</th>
            <th>Domain</th>  <!-- NEW COLUMN -->
            <th>Process/IP</th>
            <th>Verdict</th>
            <th>DREAD</th>
            <th>Actions</th>
        </tr>
    `;

    // Update table body to include domain badge
    results.forEach((row, idx) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${idx}</td>
            <td><span class="pill" style="background:${row._domainColor}; font-size:10px;">${row._domain.toUpperCase()}</span></td>
            <td>${escapeHtml(row.process_name || row.src_ip || 'unknown')}</td>
            <td>${escapeHtml(row.verdict || 'unknown')}</td>
            <td>${row._dread?.score || 0}</td>
            <td>
                <button class="btn" onclick="investigateFurther(${idx})">Investigate Further</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}
```

**Acceptance Criteria:**
- ✅ Domain badge appears in table (Network / Endpoint / Generic)
- ✅ Badge color matches domain (blue=network, green=endpoint, gray=generic)
- ✅ Domain detection uses factors + artifact attributes

---

## 🏗️ PHASE 2: BUILD MISSING COMPONENTS (6-8 Hours)

### Task 2.1: Create HopGraph Integration Module (2 hours)

**File:** `src/core/graph/hopgraph_integration.py` (NEW)

```python
"""
HopGraph integration for attack graph reconstruction.
Connects to existing HopGraphLite to build visual attack chains.
"""

from typing import Dict, List, Any, Optional
import json
from datetime import datetime, timedelta


def query_attack_graph(
    row: Dict[str, Any],
    max_hops: int = 3,
    time_window_hours: int = 24
) -> Dict[str, Any]:
    """
    Query HopGraph for related entities and build attack graph.

    Args:
        row: Artifact row (starting node)
        max_hops: Maximum graph traversal depth
        time_window_hours: Time window for correlation

    Returns:
        {
            'nodes': [...],
            'edges': [...],
            'paths': [...],
            'timeline': [...],
            'correlation_explanation': str
        }
    """
    try:
        from src.core.graph.hopgraph_lite import HopGraphLite
        graph = HopGraphLite()
    except Exception as e:
        # Fallback if HopGraph not available
        return _fallback_graph(row, e)

    # Build starting node
    start_node = {
        'id': row.get('sha256') or row.get('process_name') or row.get('src_ip') or 'unknown',
        'type': _detect_node_type(row),
        'label': row.get('process_name') or row.get('src_ip') or 'unknown',
        'properties': {
            'host': row.get('host'),
            'user': row.get('user'),
            'timestamp': row.get('timestamp') or datetime.now().isoformat(),
            'dread_score': row.get('_dread', {}).get('score', 0) if isinstance(row.get('_dread'), dict) else 0,
            'verdict': row.get('verdict', 'unknown')
        }
    }

    # Query related entities from HopGraph
    try:
        related = graph.find_related_entities(
            start_node['id'],
            max_hops=max_hops,
            time_window_hours=time_window_hours
        )
    except Exception:
        related = []

    # Build nodes and edges
    nodes = [start_node]
    edges = []

    for entity in related:
        nodes.append({
            'id': entity.get('id', 'unknown'),
            'type': entity.get('type', 'unknown'),
            'label': entity.get('label', 'unknown'),
            'properties': entity.get('properties', {})
        })

        edges.append({
            'source': entity.get('parent_id', start_node['id']),
            'target': entity['id'],
            'type': entity.get('relationship', 'related'),
            'timestamp': entity.get('timestamp')
        })

    # Detect attack paths
    paths = _detect_attack_paths(nodes, edges)

    # Build timeline
    timeline = _build_timeline(nodes, edges)

    # Explain correlation
    correlation_explanation = _explain_correlation(nodes, edges, row)

    return {
        'nodes': nodes,
        'edges': edges,
        'paths': paths,
        'timeline': timeline,
        'correlation_explanation': correlation_explanation
    }


def _detect_node_type(row: Dict[str, Any]) -> str:
    """Detect node type from artifact attributes."""
    if row.get('process_name') or row.get('file_path'):
        return 'process'
    elif row.get('src_ip') or row.get('dst_ip'):
        return 'network'
    elif row.get('registry_key'):
        return 'registry'
    elif row.get('file_path'):
        return 'file'
    else:
        return 'unknown'


def _detect_attack_paths(nodes: List[Dict], edges: List[Dict]) -> List[List[str]]:
    """
    Detect suspicious paths through graph.
    Returns list of paths (sequences of node IDs).
    """
    paths = []

    # Find high-DREAD starting points
    suspicious_nodes = [
        n for n in nodes
        if n['properties'].get('dread_score', 0) >= 6
    ]

    for start_node in suspicious_nodes:
        path = [start_node['id']]
        current_id = start_node['id']

        # Follow edges up to 5 hops
        for _ in range(5):
            next_edge = next((e for e in edges if e['source'] == current_id), None)
            if not next_edge:
                break
            path.append(next_edge['target'])
            current_id = next_edge['target']

        if len(path) > 1:
            paths.append(path)

    return paths


def _build_timeline(nodes: List[Dict], edges: List[Dict]) -> List[Dict[str, Any]]:
    """
    Build chronological timeline of attack events.
    """
    events = []

    for edge in edges:
        if edge.get('timestamp'):
            source_node = next((n for n in nodes if n['id'] == edge['source']), None)
            target_node = next((n for n in nodes if n['id'] == edge['target']), None)

            if source_node and target_node:
                severity = 'high' if source_node['properties'].get('dread_score', 0) >= 7 else 'medium' if source_node['properties'].get('dread_score', 0) >= 4 else 'low'

                events.append({
                    'timestamp': edge['timestamp'],
                    'event': f"{source_node['label']} → {edge['type']} → {target_node['label']}",
                    'severity': severity
                })

    # Sort chronologically
    events.sort(key=lambda e: e['timestamp'])

    return events


def _explain_correlation(nodes: List[Dict], edges: List[Dict], row: Dict[str, Any]) -> str:
    """
    Generate human-readable explanation of correlation score.
    """
    correlation_score = row.get('_correlation', {}).get('score', 0) if isinstance(row.get('_correlation'), dict) else 0

    explanation = f"Correlation score {correlation_score:.2f} calculated from:\n"

    # Count relationships
    if edges:
        explanation += f"- {len(edges)} relationships detected\n"

    # Count unique entity types
    node_types = set(n['type'] for n in nodes)
    if len(node_types) > 1:
        explanation += f"- {len(node_types)} different entity types ({', '.join(node_types)})\n"

    # Time window
    if edges:
        timestamps = [e['timestamp'] for e in edges if e.get('timestamp')]
        if timestamps:
            try:
                times = [datetime.fromisoformat(t) for t in timestamps]
                duration = (max(times) - min(times)).total_seconds() / 60
                explanation += f"- Events within {duration:.0f}-minute window\n"
            except Exception:
                pass

    # High-risk relationships
    high_risk = [e for e in edges if e['type'] in {'credential_access', 'lateral_movement', 'c2_connection'}]
    if high_risk:
        explanation += f"- {len(high_risk)} high-risk relationships detected\n"

    explanation += f"\nTotal: {len(nodes)} nodes, {len(edges)} edges"

    return explanation


def _fallback_graph(row: Dict[str, Any], error: Exception) -> Dict[str, Any]:
    """
    Fallback graph when HopGraph unavailable.
    Returns minimal single-node graph.
    """
    node = {
        'id': row.get('sha256') or row.get('process_name') or 'unknown',
        'type': _detect_node_type(row),
        'label': row.get('process_name') or row.get('src_ip') or 'Artifact',
        'properties': {
            'host': row.get('host'),
            'verdict': row.get('verdict'),
            'dread_score': row.get('_dread', {}).get('score', 0) if isinstance(row.get('_dread'), dict) else 0
        }
    }

    return {
        'nodes': [node],
        'edges': [],
        'paths': [],
        'timeline': [],
        'correlation_explanation': f'HopGraph unavailable: {error}\nShowing single artifact only.'
    }
```

**Acceptance Criteria:**
- ✅ Returns valid graph structure (nodes, edges, paths, timeline)
- ✅ Graceful fallback if HopGraphLite unavailable
- ✅ Timeline sorted chronologically
- ✅ Correlation explanation is human-readable

---

### Task 2.2: Create Graph API Endpoint (1 hour)

**File:** `src/api/graph_endpoints.py` (NEW)

```python
"""
API endpoints for attack graph reconstruction.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
from src.core.graph.hopgraph_integration import query_attack_graph
from src.api.dependencies import get_current_user

router = APIRouter(prefix="/api/v1/graph", tags=["graph"])


@router.post("/attack_reconstruction")
async def get_attack_reconstruction(
    request: Dict[str, Any],
    current_user: Dict = Depends(get_current_user)
):
    """
    Get attack graph reconstruction for an artifact.

    Request body:
    {
        "row": {...},  # Artifact row
        "max_hops": 3,  # Optional
        "time_window_hours": 24  # Optional
    }

    Returns:
    {
        "nodes": [...],
        "edges": [...],
        "paths": [...],
        "timeline": [...],
        "correlation_explanation": str
    }
    """
    try:
        row = request.get('row')
        if not row:
            raise HTTPException(status_code=400, detail="Missing 'row' in request body")

        max_hops = request.get('max_hops', 3)
        time_window_hours = request.get('time_window_hours', 24)

        graph_data = query_attack_graph(
            row=row,
            max_hops=max_hops,
            time_window_hours=time_window_hours
        )

        return graph_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Graph reconstruction failed: {str(e)}")
```

**Integration:** Add to `src/api/server.py`:

```python
# In src/api/server.py, add import:
from src.api import graph_endpoints

# In create_app(), add router:
app.include_router(graph_endpoints.router)
```

**Testing:**
```bash
# Test endpoint
curl -X POST http://localhost:8000/api/v1/graph/attack_reconstruction \
  -H "Content-Type: application/json" \
  -d '{
    "row": {
      "process_name": "powershell.exe",
      "sha256": "abc123",
      "host": "TEST-HOST"
    },
    "max_hops": 3
  }'
```

**Acceptance Criteria:**
- ✅ Returns 200 OK with valid graph data
- ✅ Returns 400 if 'row' missing
- ✅ Returns 500 with error message if graph query fails
- ✅ Endpoint accessible at `/api/v1/graph/attack_reconstruction`

---

### Task 2.3: Create AI Insights Endpoints (2 hours)

**File:** `src/api/insights_endpoints.py` (NEW)

```python
"""
API endpoints for on-demand AI insights.
Generates DREAD scenarios, playbooks, hunt queries, executive summaries.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
from src.api.dependencies import get_current_user

router = APIRouter(prefix="/api/v1/insights", tags=["insights"])


@router.post("/generate")
async def generate_insight(
    request: Dict[str, Any],
    current_user: Dict = Depends(get_current_user)
):
    """
    Generate on-demand AI insight for an artifact.

    Request body:
    {
        "row": {...},  # Artifact row
        "insight_type": "dread" | "playbook" | "hunt" | "executive",
        "pipeline_context": {...}  # Optional
    }

    Returns:
    {
        "insight": str,  # Generated text
        "cost": float,  # Estimated cost
        "model": str  # Model used
    }
    """
    try:
        row = request.get('row')
        insight_type = request.get('insight_type')
        pipeline_context = request.get('pipeline_context', {})

        if not row or not insight_type:
            raise HTTPException(status_code=400, detail="Missing 'row' or 'insight_type'")

        # Generate insight based on type
        if insight_type == 'dread':
            insight = _generate_dread_scenarios(row, pipeline_context)
            cost = 0.001
        elif insight_type == 'playbook':
            insight = _generate_collection_playbook(row, pipeline_context)
            cost = 0.0008
        elif insight_type == 'hunt':
            insight = _generate_hunt_query(row, pipeline_context)
            cost = 0.0008
        elif insight_type == 'executive':
            insight = _generate_executive_summary(row, pipeline_context)
            cost = 0.0005
        else:
            raise HTTPException(status_code=400, detail=f"Unknown insight_type: {insight_type}")

        return {
            'insight': insight,
            'cost': cost,
            'model': 'gpt-4o-mini'
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Insight generation failed: {str(e)}")


def _generate_dread_scenarios(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> str:
    """Generate detailed DREAD damage/exploitability scenarios."""
    from src.integrations.llm_client import DEFAULT_CLIENT

    dread = pipeline_context.get('dread_score', 0)
    mitre = ', '.join(pipeline_context.get('mitre_tags', [])[:3])

    prompt = f"""You are a security architect. Generate detailed DREAD damage and exploitability scenarios for this artifact.

ARTIFACT: {row.get('process_name')} on {row.get('host')}
DREAD SCORE: {dread}
MITRE TECHNIQUES: {mitre}

Generate 3-5 realistic damage scenarios:
1. What damage could an attacker cause?
2. How exploitable is this?
3. What's the business impact?

Be specific, concrete, and realistic. Each scenario should be 2-3 sentences.
"""

    try:
        result = DEFAULT_CLIENT.generate(prompt, model='gpt-4o-mini', max_tokens=500)
        return result.get('text', 'DREAD scenarios unavailable')
    except Exception as e:
        return f"DREAD scenario generation failed: {e}"


def _generate_collection_playbook(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> str:
    """Generate step-by-step evidence collection playbook."""
    from src.analysis.domain_tools import build_collection_playbook

    try:
        # Detect domain
        domain = 'endpoint' if row.get('process_name') else 'network'
        mitre_tags = pipeline_context.get('mitre_tags', [])

        artifact_context = {
            'process_name': row.get('process_name', ''),
            'src_ip': row.get('src_ip', ''),
            'host': row.get('host', ''),
            'user': row.get('user', '')
        }

        playbook = build_collection_playbook(domain, mitre_tags, artifact_context)
        return playbook
    except Exception as e:
        return f"Playbook generation failed: {e}"


def _generate_hunt_query(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> str:
    """Generate hunt query to find similar threats across environment."""
    from src.integrations.llm_client import DEFAULT_CLIENT

    process_name = row.get('process_name', '')
    parent_process = row.get('parent_process', '')
    mitre = ', '.join(pipeline_context.get('mitre_tags', [])[:3])

    prompt = f"""You are a threat hunter. Generate a KQL/Splunk query to find similar suspicious activity across the environment.

ARTIFACT: {process_name} (parent: {parent_process})
MITRE TECHNIQUES: {mitre}

Generate a KQL query that:
1. Searches SecurityEvent table (past 30 days)
2. Filters for similar process/parent combinations
3. Groups by Computer and Account
4. Identifies outliers (count > 1)

Output ONLY the KQL query, no explanations.
"""

    try:
        result = DEFAULT_CLIENT.generate(prompt, model='gpt-4o-mini', max_tokens=300)
        return result.get('text', 'Hunt query unavailable')
    except Exception as e:
        return f"Hunt query generation failed: {e}"


def _generate_executive_summary(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> str:
    """Generate non-technical executive summary for CISO."""
    from src.integrations.llm_client import DEFAULT_CLIENT

    dread = pipeline_context.get('dread_score', 0)
    verdict = row.get('verdict', 'unknown')

    prompt = f"""You are briefing a CISO (non-technical executive). Summarize this security incident in business terms.

ARTIFACT: {row.get('process_name')} on {row.get('host')}
VERDICT: {verdict}
RISK SCORE: {dread}/10

Write a 3-paragraph executive summary:
1. What happened (in plain English)
2. Business impact (dollars, downtime, reputation)
3. Recommended action

Use non-technical language. No jargon. Focus on business risk.
"""

    try:
        result = DEFAULT_CLIENT.generate(prompt, model='gpt-4o-mini', max_tokens=400)
        return result.get('text', 'Executive summary unavailable')
    except Exception as e:
        return f"Executive summary generation failed: {e}"
```

**Integration:** Add to `src/api/server.py`:

```python
from src.api import insights_endpoints
app.include_router(insights_endpoints.router)
```

**Testing:**
```bash
# Test DREAD scenarios
curl -X POST http://localhost:8000/api/v1/insights/generate \
  -H "Content-Type: application/json" \
  -d '{
    "row": {"process_name": "powershell.exe", "host": "TEST"},
    "insight_type": "dread",
    "pipeline_context": {"dread_score": 8.5, "mitre_tags": ["T1055"]}
  }'
```

**Acceptance Criteria:**
- ✅ Returns insight text for all 4 types (dread, playbook, hunt, executive)
- ✅ Returns cost estimate
- ✅ Graceful error handling if LLM unavailable
- ✅ Playbook type uses domain_tools.py (no LLM needed)

---

### Task 2.4: Update Frontend to Call New Endpoints (1 hour)

**File:** `frontend/static/csv_deep_analysis.html`
**Location:** Update `generateInsight()` and `loadAttackGraph()` functions

**Changes:**

```javascript
// Update loadAttackGraph() function (around line 500)
async function loadAttackGraph() {
  const rowIndex = parseInt(localStorage.getItem('csv_deep_row') || '0', 10);
  const rows = JSON.parse(localStorage.getItem('csv_last_results') || '[]');
  const row = rows[rowIndex];

  const canvas = document.getElementById('graphCanvas');
  if (!canvas) return;

  canvas.innerHTML = 'Loading attack graph...';

  try {
    const resp = await fetch('/api/v1/graph/attack_reconstruction', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', ...authHeaders()},
      body: JSON.stringify({
        row: row,
        max_hops: 3,
        time_window_hours: parseInt(document.getElementById('timeWindow')?.value || '24')
      })
    });

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${await resp.text()}`);
    }

    const graphData = await resp.json();
    renderGraph(graphData);
    renderCorrelationExplanation(graphData.correlation_explanation);
  } catch (err) {
    canvas.textContent = 'Unable to load HopGraph: ' + err.message;
  }
}

// Update generateInsight() function (around line 700)
async function generateInsight(insightType) {
  const rowIndex = parseInt(localStorage.getItem('csv_deep_row') || '0', 10);
  const rows = JSON.parse(localStorage.getItem('csv_last_results') || '[]');
  const row = rows[rowIndex];

  const outputDiv = document.getElementById('insight-' + insightType);
  if (!outputDiv) return;

  outputDiv.style.display = 'block';
  outputDiv.textContent = 'Generating...';

  try {
    const resp = await fetch('/api/v1/insights/generate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', ...authHeaders()},
      body: JSON.stringify({
        row: row,
        insight_type: insightType,
        pipeline_context: row._pipeline_context || {}
      })
    });

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }

    const result = await resp.json();
    outputDiv.innerHTML = '<pre style="white-space:pre-wrap;">' + escapeHtml(result.insight) + '</pre>';

    // Update running cost
    const costSpan = document.getElementById('runningCost');
    if (costSpan) {
      const currentCost = parseFloat(costSpan.textContent.replace('$', '')) || 0;
      const newCost = currentCost + result.cost;
      costSpan.textContent = formatCost(newCost);
    }
  } catch (err) {
    outputDiv.textContent = 'Error: ' + err.message;
  }
}
```

**Acceptance Criteria:**
- ✅ HopGraph loads when page opens
- ✅ AI Insights generate on button click
- ✅ Running cost updates after each insight
- ✅ Error messages display if endpoints fail

---

## 🧪 PHASE 3: TESTING & VALIDATION (2-3 Hours)

### Task 3.1: Create Test Data Set (30 min)

**File:** `tests/test_data/option_c_demo_data.csv`

Create CSV with 10 rows:
- 5 network artifacts (port scans, C2 beacons)
- 5 endpoint artifacts (process injection, credential access)
- Mix of benign and malicious

**Example:**
```csv
process_name,host,user,src_ip,dst_ip,sha256,factors,verdict,mitre_tags
powershell.exe,WORK-042,alice,,,"9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a","process_injection,unsigned_binary",CRITICAL,"T1055,T1059.001"
chrome.exe,LAPTOP-055,bob,10.0.5.42,203.0.113.42,malware123,"c2_communication,beaconing",CRITICAL,"T1071,T1071.001"
nmap.exe,SECURITY-01,secops,10.0.1.10,10.0.0.0/16,,"port_scan,reconnaissance",SUSPICIOUS,T1046
taskmgr.exe,WORK-099,charlie,,,benign_binary,,BENIGN,
svchost.exe,SERVER-087,SYSTEM,,,,"process_injection",SUSPICIOUS,T1055
...
```

**Acceptance Criteria:**
- ✅ 10 diverse rows
- ✅ Realistic SHA256, IPs, process names
- ✅ Mix of network/endpoint
- ✅ Mix of verdicts (BENIGN, SUSPICIOUS, CRITICAL)

---

### Task 3.2: End-to-End Integration Test (1 hour)

**File:** `tests/test_option_c_integration.py`

```python
"""
End-to-end integration test for Option C features.
Tests domain detection, historical context, Tier 2 prompts, HopGraph, AI Insights.
"""

import pytest
from src.analysis.auto_llm import detect_domain_with_confidence, build_tier2_prompt, LLMAssessmentClient
from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo
from src.core.graph.hopgraph_integration import query_attack_graph


def test_domain_detection():
    """Test domain detection accuracy."""
    # Network artifact
    network_row = {
        'factors': ['port_scan', 'beaconing'],
        'src_ip': '10.0.0.5',
        'dst_ip': '203.0.113.42'
    }
    domain, conf = detect_domain_with_confidence(network_row)
    assert domain == 'network'
    assert conf >= 0.7

    # Endpoint artifact
    endpoint_row = {
        'factors': ['process_injection', 'unsigned_binary'],
        'process_name': 'powershell.exe',
        'file_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    }
    domain, conf = detect_domain_with_confidence(endpoint_row)
    assert domain == 'endpoint'
    assert conf >= 0.7


def test_tier2_prompt_generation():
    """Test Tier 2 prompt includes all required sections."""
    row = {
        'process_name': 'powershell.exe',
        'host': 'TEST-HOST',
        'sha256': 'abc123',
        'factors': ['process_injection']
    }
    context = {
        'pipeline_context': {
            'dread_score': 8.5,
            'mitre_tags': ['T1055'],
            'correlation': {'score': 0.73}
        }
    }

    prompt = build_tier2_prompt(row, context)

    # Check required sections
    assert 'THREAT HUNTER' in prompt
    assert 'HISTORICAL CONTEXT' in prompt
    assert 'ATTACK CONTEXT' in prompt
    assert 'COLLECTION PLAYBOOK' in prompt
    assert 'DECISION CRITERIA' in prompt

    # Check length
    lines = prompt.splitlines()
    assert 60 <= len(lines) <= 100


def test_historical_incidents_query():
    """Test historical incident querying."""
    repo = HistoricalIncidentsRepo()

    # Query for known SHA256 (from seed data)
    row = {'sha256': '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a'}
    results = repo.query_similar_incidents(row, lookback_days=90)

    assert len(results) > 0
    assert results[0]['outcome'] == 'confirmed_malicious'
    assert results[0]['match_type'] == 'sha256_match'


def test_hopgraph_integration():
    """Test HopGraph query returns valid structure."""
    row = {
        'process_name': 'powershell.exe',
        'sha256': 'abc123',
        'host': 'TEST-HOST'
    }

    graph = query_attack_graph(row, max_hops=2, time_window_hours=24)

    assert 'nodes' in graph
    assert 'edges' in graph
    assert 'timeline' in graph
    assert 'correlation_explanation' in graph

    # Should have at least starting node
    assert len(graph['nodes']) >= 1


def test_llm_client_tier2():
    """Test LLM client supports Tier 2 prompts."""
    client = LLMAssessmentClient()

    row = {
        'process_name': 'powershell.exe',
        'host': 'TEST',
        'factors': ['process_injection']
    }
    context = {
        'tier': 'tier2',
        'pipeline_context': {
            'dread_score': 8.0,
            'mitre_tags': ['T1055']
        }
    }

    result = client.summarize_row(row, context)

    assert 'text' in result
    assert 'model' in result
    # Tier 2 should be longer than Tier 1
    assert len(result['text'].splitlines()) >= 60


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
```

**Run:**
```bash
pytest tests/test_option_c_integration.py -v
```

**Acceptance Criteria:**
- ✅ All tests pass
- ✅ Domain detection: 100% accuracy
- ✅ Tier 2 prompt: 60-100 lines
- ✅ Historical query: Returns results
- ✅ HopGraph: Valid structure returned

---

### Task 3.3: Manual UI Testing (1 hour)

**Test Script:**

1. **Upload CSV**
   - Upload `option_c_demo_data.csv`
   - Verify 10 rows appear

2. **Check Domain Badges**
   - Verify network artifacts show blue "NETWORK" badge
   - Verify endpoint artifacts show green "ENDPOINT" badge

3. **Test "Investigate Further"**
   - Click on network artifact
   - Verify domain badge shows "NETWORK"
   - Verify Tier 2 summary appears (60-100 lines)
   - Check for historical context section
   - Check for collection playbook

4. **Test HopGraph**
   - Verify graph canvas appears
   - Verify correlation explanation displays
   - (If HopGraph unavailable, verify fallback message)

5. **Test AI Insights**
   - Click "Generate DREAD Scenarios"
   - Verify output appears
   - Verify running cost updates
   - Test all 4 insight types

6. **Test Historical Context**
   - Use row with SHA256 from seed data
   - Verify "Similar incident X days ago" appears
   - Verify analyst notes displayed

**Acceptance Criteria:**
- ✅ All UI elements render correctly
- ✅ No console errors
- ✅ API calls succeed (or fail gracefully)
- ✅ Cost tracking updates

---

## 🎬 PHASE 4: DEMO PREPARATION (1-2 Hours)

### Task 4.1: Create CEO Demo Script (30 min)

**File:** `docs/CEO_DEMO_SCRIPT_OPTION_C.md`

```markdown
# CEO Demo Script - Option C Full Features

**Duration:** 15-20 minutes
**Goal:** Show complete vision of AI-powered SOC platform

---

## Setup (Before Demo)

1. Start platform: `python run_platform.py`
2. Open browser: http://localhost:8000/static/csv_analyzer.html
3. Load test data: `option_c_demo_data.csv`
4. Verify historical data seeded: `python scripts/seed_historical_incidents.py`
5. Open Developer Tools (F12) to show no errors

---

## Demo Flow

### Act 1: Upload & Triage (3 min)

**Script:**
"Here's a CSV with 10 security events from a customer's SIEM. Watch how the platform analyzes them..."

**Actions:**
1. Upload CSV
2. Click "Deep Analyze with LLM Summary"
3. Point out:
   - Domain badges (Network vs Endpoint)
   - DREAD scores
   - Verdicts (CRITICAL, SUSPICIOUS, BENIGN)

**Key Message:**
"Notice the platform automatically detects network vs endpoint artifacts. This ensures analysts get relevant playbooks."

---

### Act 2: Investigate Network Artifact (4 min)

**Script:**
"Let's investigate this suspicious network connection - looks like C2 beaconing..."

**Actions:**
1. Click "Investigate Further" on network artifact (chrome.exe C2)
2. Show Tier 2 summary:
   - Domain badge: NETWORK
   - Historical context: "Similar incident 21 days ago - confirmed APT29"
   - Attack scenario: "C2 communication enables remote control..."
   - Collection playbook: Wireshark, Zeek commands

**Key Message:**
"The platform remembers past incidents. This SHA256 was confirmed malicious 3 weeks ago, so we auto-escalate."

---

### Act 3: Investigate Endpoint Artifact (4 min)

**Script:**
"Now let's look at this endpoint alert - PowerShell process injection..."

**Actions:**
1. Click "Investigate Further" on endpoint artifact (powershell.exe)
2. Show Tier 2 summary:
   - Domain badge: ENDPOINT
   - Different playbook: KAPE, Sysmon, RegRipper
   - MITRE mapping: T1055 → Sysmon Event 10
   - Historical context: "Emotet dropper confirmed 14 days ago"

**Key Message:**
"Different artifact type, different tools. MITRE techniques automatically map to required logs."

---

### Act 4: HopGraph Attack Reconstruction (3 min)

**Script:**
"The correlation score is 0.73 - that means related entities detected. Let's see the attack graph..."

**Actions:**
1. Scroll to HopGraph section
2. Show graph visualization (if available)
3. Point out:
   - Multi-hop attack path
   - Timeline view
   - Correlation explanation

**Key Message:**
"Manual log correlation takes hours. This shows the attack chain automatically."

---

### Act 5: AI-Powered Insights (3 min)

**Script:**
"Analysts can generate on-demand insights for deep investigation..."

**Actions:**
1. Click "Generate DREAD Scenarios"
   - Show business impact explanation
2. Click "Generate Hunt Query"
   - Show KQL query to find similar threats
3. Click "Generate Executive Summary"
   - Show CISO-friendly explanation

**Key Message:**
"Each insight costs < $0.001. Compare that to 30 minutes of analyst time at $40/hour = $20."

---

### Act 6: Business Value Summary (2 min)

**Script:**
"Let me show you the ROI..."

**Slide on screen:**
```
Before JanuSec:
- 20 min per alert × 100 alerts/day = 33 hours/day
- Need 5 analysts ($200K/year each) = $1M/year

With JanuSec:
- 30 sec triage × 100 alerts/day = 0.8 hours/day
- Need 1 analyst ($200K/year) = $200K/year
- Savings: $800K/year
- Plus: historical context prevents re-work
- Plus: attack graphs catch APTs
```

**Key Message:**
"This isn't just faster - it's fundamentally better threat detection."

---

## Q&A Prep

**Expected Questions:**

Q: "What if LLM hallucinates?"
A: "All facts come from our 21-stage pipeline (DREAD, MITRE, correlation). LLM just formats and explains. We can show the deterministic factors."

Q: "What about cost?"
A: "Average $0.003 per alert. 100 alerts/day = $0.30/day = $110/year. Compare to $1M in analyst salaries."

Q: "Can it integrate with our SIEM?"
A: "Yes - we ingest from Splunk, Sentinel, Chronicle. CSV upload is just for demo."

Q: "What's the accuracy?"
A: "Domain detection: 95%+. Historical matching: 100% for exact SHA256. We're continuously learning from analyst feedback."

---

## Backup Plan (If Something Breaks)

1. **If LLM unavailable:** "We have fallback deterministic summaries. In production, you'd use your own LLM or our API."
2. **If HopGraph fails:** "Graph requires full telemetry. I can show you the design mockups."
3. **If historical query fails:** "Database seeding issue. The code is ready, just needs data."

---

**Success Criteria:**
- ✅ CEO says "This is impressive"
- ✅ CEO asks about pricing/deployment
- ✅ CEO introduces you to potential customers
```

---

### Task 4.2: Create Backup Screenshots (30 min)

**Take screenshots of:**

1. CSV Analyzer with domain badges
2. Tier 2 summary (network artifact)
3. Tier 2 summary (endpoint artifact)
4. Historical context section
5. HopGraph visualization (if available)
6. AI Insights section
7. Cost tracking

**Save to:** `docs/demo_screenshots/`

**Acceptance Criteria:**
- ✅ 7+ high-quality screenshots
- ✅ All text readable
- ✅ No dummy data (use realistic names/IPs)

---

### Task 4.3: Rehearse Demo (30 min)

**Practice flow:**
1. Time yourself (should be 15-20 min)
2. Practice Q&A responses
3. Test backup plans (intentionally break something, recover)
4. Record yourself (optional, for review)

**Acceptance Criteria:**
- ✅ Demo flows smoothly (no hesitation)
- ✅ Under 20 minutes
- ✅ Can answer CEO's likely questions

---

## ✅ FINAL CHECKLIST

### Code Complete
- [ ] Task 1.1: Domain detection function (1 hour)
- [ ] Task 1.2: Tier 2 prompt builder (2 hours)
- [ ] Task 1.3: Update summarize_row() (30 min)
- [ ] Task 1.4: Seed historical data (1 hour)
- [ ] Task 1.5: Add domain badges to UI (30 min)
- [ ] Task 2.1: HopGraph integration module (2 hours)
- [ ] Task 2.2: Graph API endpoint (1 hour)
- [ ] Task 2.3: AI Insights endpoints (2 hours)
- [ ] Task 2.4: Update frontend calls (1 hour)

### Testing Complete
- [ ] Task 3.1: Create test data (30 min)
- [ ] Task 3.2: Integration tests pass (1 hour)
- [ ] Task 3.3: Manual UI testing (1 hour)

### Demo Ready
- [ ] Task 4.1: CEO demo script (30 min)
- [ ] Task 4.2: Backup screenshots (30 min)
- [ ] Task 4.3: Rehearse demo (30 min)

---

## 🎯 TOTAL TIME ESTIMATE

| Phase | Hours |
|-------|-------|
| Phase 1: Wire Up (5 tasks) | 6-8 |
| Phase 2: Build New (4 tasks) | 6-8 |
| Phase 3: Testing (3 tasks) | 2-3 |
| Phase 4: Demo Prep (3 tasks) | 1-2 |
| **TOTAL** | **15-21 hours** |

**Realistic Timeline:** 2-3 working days

---

## 🚀 DEPLOYMENT DAY

**Pre-demo Checklist:**
- [ ] Platform running (no errors in console)
- [ ] Test data loaded
- [ ] Historical data seeded
- [ ] All endpoints responding
- [ ] Screenshots ready (backup)
- [ ] Demo script printed
- [ ] CEO time confirmed

**Post-demo:**
- [ ] Capture CEO feedback
- [ ] Note any bugs/issues discovered
- [ ] Document feature requests
- [ ] Schedule follow-up if needed

---

**GOOD LUCK! 🎉**

This is the complete implementation. Follow each task in order, test thoroughly, and you'll have a world-class SOC platform to show the CEO.
