# Report Generation & Batch Processing Strategy

**Date:** 2025-01-22
**For:** Large-Scale CSV Analysis (50-135+ Rows)

---

## 📋 EXECUTIVE SUMMARY

### What You Asked:
> "how is the progress on the report generation how does that work. do you select the top suspicious files/rows/threats. what if there is more than 50 or even 135+ rows do you send 135+ rows? how to best triage what is worth reporting and how much to send to which persona?"

### Answers:

**1. Report Generation Status:**
✅ **ALREADY IMPLEMENTED** - `src/api/report_endpoints.py` exists with full HTML/PDF generation

**2. Top Suspicious Selection:**
✅ **YES** - Prioritize by DREAD score, verdict, factor count (see strategy below)

**3. Handling 135+ Rows:**
❌ **NO** - Don't send all rows to LLM. Use **smart batching with Top-N prioritization**

**4. Persona-Based Reporting:**
✅ **RECOMMENDED** - Different detail levels for SOC Analyst vs CISO vs Security Engineer

---

## 🎯 CURRENT REPORT GENERATION (What Exists)

### Existing Implementation

**File:** `src/api/report_endpoints.py`

**Endpoints:**
```python
POST /api/v1/report/generate          # Generate HTML/JSON report
POST /api/v1/report/generate_pdf      # Generate PDF report
```

**Current Flow:**
1. Frontend sends JSON payload with analyzed rows
2. `build_report_html(payload)` generates comprehensive HTML
3. Optional: `include_model=true` adds LLM executive summary
4. Returns HTML or PDF (via WeasyPrint if installed)

**What's Included:**
- All rows from CSV analysis
- Summary statistics (total, malicious, suspicious, benign)
- MITRE ATT&CK coverage
- DREAD distribution
- No prioritization or filtering (sends ALL rows)

---

## ⚠️ THE PROBLEM: Sending 135+ Rows

### Cost Explosion Example

**Scenario:** Security team uploads 135-row CSV with mixed alerts

**Option A: Process All Rows (Current Naive Approach)**
```
135 rows × $0.003/row = $0.40 per upload
10 uploads/day × $0.40 = $4.00/day
$4/day × 30 days = $120/month
```

**Option B: Smart Prioritization (Top 25)**
```
25 rows × $0.003/row = $0.075 per upload
10 uploads/day × $0.075 = $0.75/day
$0.75/day × 30 days = $22.50/month

SAVINGS: $97.50/month (81% cost reduction)
```

**Option C: Tiered Processing**
```
Top 10 (High Priority) → Tier 2 deep analysis: 10 × $0.003 = $0.03
Next 15 (Medium Priority) → Tier 1 fast triage: 15 × $0.0005 = $0.0075
Bottom 110 (Low Priority) → Pipeline only (no LLM): $0

Total: $0.0375 per upload
10 uploads/day × $0.0375 = $0.375/day
$0.375 × 30 days = $11.25/month

SAVINGS: $108.75/month (91% cost reduction)
```

---

## ✅ RECOMMENDED SOLUTION: Smart Batch Processing

### Strategy Overview

**Philosophy:**
> "Don't waste LLM budget on benign or low-priority alerts. Focus expensive analysis on the threats that matter."

**Approach:**
1. **Classify all rows** using existing 21-stage pipeline (free, fast)
2. **Prioritize** by DREAD score, verdict, factor count
3. **Select Top-N** based on context (report type, budget, persona)
4. **Apply Tier 1 or Tier 2** based on severity
5. **Generate report** with full context but focused LLM summaries

---

## 🔢 PRIORITIZATION ALGORITHM

### Step 1: Calculate Priority Score

**Formula:**
```python
priority_score = (
    verdict_weight * 40 +      # 0-40 points
    dread_score * 3 +           # 0-30 points (DREAD is 0-10)
    factor_count * 2 +          # 0-20 points (assuming max 10 factors)
    historical_match * 10       # 0-10 points (bonus for known threats)
)
# Max score: 100 points
```

**Verdict Weights:**
```python
verdict_weight = {
    'malicious': 1.0,      # 40 points
    'suspicious': 0.7,     # 28 points
    'anomalous': 0.5,      # 20 points
    'benign': 0.1,         # 4 points
    'unknown': 0.3         # 12 points
}
```

**Example Calculation:**
```python
# Row: PowerShell with process_injection, cmdline_obfuscation
row = {
    'verdict': 'suspicious',
    'dread_score': 8.5,
    'factors': ['process_injection', 'cmdline_obfuscation', 'unsigned_binary'],
    'sha256': '9bf41199...'  # matches historical incident
}

priority_score = (
    0.7 * 40 +        # verdict: suspicious → 28 points
    8.5 * 3 +         # DREAD 8.5 → 25.5 points
    3 * 2 +           # 3 factors → 6 points
    1 * 10            # historical match → 10 points
) = 69.5 points
```

---

### Step 2: Sort and Bucket

**Sort by Priority Score (Descending):**
```python
sorted_rows = sorted(rows, key=lambda r: calculate_priority_score(r), reverse=True)
```

**Create Buckets:**
```python
# High Priority: Top 10% or score >= 60
high_priority = [r for r in sorted_rows if r['priority_score'] >= 60][:max_high]

# Medium Priority: Next 20% or score 40-59
medium_priority = [r for r in sorted_rows if 40 <= r['priority_score'] < 60][:max_medium]

# Low Priority: Bottom 70% or score < 40
low_priority = [r for r in sorted_rows if r['priority_score'] < 40]

# Benign/Noise: Verdict = benign and score < 20
benign = [r for r in sorted_rows if r['verdict'] == 'benign' and r['priority_score'] < 20]
```

---

### Step 3: Apply Tier-Based Processing

**High Priority (Top 10):**
- **Processing:** Tier 2 deep analysis (60-100 line prompts)
- **LLM Cost:** $0.003/row
- **AI Insights:** All 4 types (DREAD, playbook, hunt, executive)
- **Historical Context:** Full lookback (90 days)
- **Report Detail:** Full section with HopGraph

**Medium Priority (Next 15):**
- **Processing:** Tier 1 fast triage (30-45 line prompts)
- **LLM Cost:** $0.0005/row
- **AI Insights:** Playbook only (free, instant)
- **Historical Context:** Basic (14 days)
- **Report Detail:** Summary table only

**Low Priority (Bottom 110):**
- **Processing:** Pipeline only (no LLM)
- **LLM Cost:** $0/row
- **AI Insights:** None
- **Historical Context:** None
- **Report Detail:** Raw data table with verdict/DREAD

**Benign/Noise:**
- **Processing:** Count only (don't include in report)
- **LLM Cost:** $0
- **AI Insights:** None
- **Report Detail:** "135 rows analyzed, 25 threats detected, 110 benign"

---

## 👥 PERSONA-BASED REPORTING

### Different Audiences Need Different Detail

**Persona 1: SOC Analyst (Tier 1)**
- **Goal:** Quick triage and escalation decisions
- **Needs:**
  - Top 25 threats with Tier 1 summaries
  - Playbook steps (copy-paste commands)
  - Clear verdict (Investigate/Shelf/Dismiss)
- **Report Format:** HTML table with expandable details
- **LLM Budget:** Low ($0.02/report)

**Persona 2: Threat Hunter (Tier 2)**
- **Goal:** Deep investigation of high-priority threats
- **Needs:**
  - Top 10 threats with Tier 2 deep analysis
  - HopGraph attack chains
  - Hunt queries (KQL, SPL, Sigma)
  - Historical context
- **Report Format:** Detailed sections per artifact
- **LLM Budget:** Medium ($0.05/report)

**Persona 3: CISO / Executive**
- **Goal:** Business impact and risk overview
- **Needs:**
  - Executive summary (5 sentences)
  - Risk heatmap (high/medium/low counts)
  - Compliance impact (MITRE coverage gaps)
  - Cost savings metrics
- **Report Format:** 1-page PDF with charts
- **LLM Budget:** Very Low ($0.005/report)

**Persona 4: Security Engineer (Remediation)**
- **Goal:** Fix vulnerabilities and harden defenses
- **Needs:**
  - Top 15 threats grouped by attack pattern
  - Remediation playbooks
  - Detection rules (Sigma/YARA)
  - Policy recommendations
- **Report Format:** Technical detail with code snippets
- **LLM Budget:** Medium ($0.04/report)

---

## 🛠️ IMPLEMENTATION GUIDE

### New Endpoint: `/api/v1/report/generate_prioritized`

**Request:**
```json
POST /api/v1/report/generate_prioritized
{
  "rows": [...],  // All 135 rows
  "persona": "soc_analyst",  // or "threat_hunter", "executive", "security_engineer"
  "max_high_priority": 10,
  "max_medium_priority": 15,
  "include_llm": true,
  "include_benign_count": true
}
```

**Response:**
```json
{
  "report_id": "rpt_20250122_001",
  "total_rows": 135,
  "high_priority_count": 10,
  "medium_priority_count": 15,
  "low_priority_count": 80,
  "benign_count": 30,
  "high_priority_rows": [
    {
      "row": {...},
      "priority_score": 85.5,
      "tier2_summary": "THREAT HUNTER DEEP ANALYSIS: ...",
      "ai_insights": {
        "dread": "...",
        "playbook": "...",
        "hunt": "...",
        "executive": "..."
      },
      "hopgraph": {...}
    }
  ],
  "medium_priority_rows": [
    {
      "row": {...},
      "priority_score": 52.0,
      "tier1_summary": "FAST TRIAGE: ...",
      "playbook": "..."
    }
  ],
  "low_priority_rows": [
    {"row": {...}, "priority_score": 22.0}
  ],
  "llm_cost": 0.0375,
  "processing_time_ms": 12450
}
```

---

### Implementation Code

**File:** `src/api/report_endpoints.py`

**Add new function:**
```python
from typing import List, Dict, Any

def calculate_priority_score(row: Dict[str, Any]) -> float:
    """Calculate priority score for a row (0-100)."""
    verdict_weights = {
        'malicious': 1.0,
        'suspicious': 0.7,
        'anomalous': 0.5,
        'benign': 0.1,
        'unknown': 0.3
    }

    verdict = row.get('verdict', 'unknown').lower()
    dread_score = row.get('dread_score') or row.get('_dread', {}).get('score', 5.0)
    factors = row.get('factors', [])
    factor_count = len(factors) if isinstance(factors, list) else 0

    # Check for historical match
    sha256 = row.get('sha256', '')
    historical_match = 0
    if sha256:
        try:
            from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo
            repo = HistoricalIncidentsRepo()
            matches = repo.query_similar_incidents(row, lookback_days=90, limit=1)
            if matches:
                historical_match = 1
        except Exception:
            pass

    score = (
        verdict_weights.get(verdict, 0.3) * 40 +
        float(dread_score) * 3 +
        min(factor_count, 10) * 2 +
        historical_match * 10
    )

    return min(score, 100.0)


def prioritize_rows(
    rows: List[Dict[str, Any]],
    max_high: int = 10,
    max_medium: int = 15,
    high_threshold: float = 60.0,
    medium_threshold: float = 40.0
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Prioritize rows into high/medium/low buckets based on priority score.

    Returns:
        {
            'high_priority': [...],
            'medium_priority': [...],
            'low_priority': [...],
            'benign': [...]
        }
    """
    # Calculate priority scores
    for row in rows:
        row['priority_score'] = calculate_priority_score(row)

    # Sort by priority (descending)
    sorted_rows = sorted(rows, key=lambda r: r['priority_score'], reverse=True)

    # Bucket
    high_priority = [r for r in sorted_rows if r['priority_score'] >= high_threshold][:max_high]
    remaining = [r for r in sorted_rows if r not in high_priority]

    medium_priority = [r for r in remaining if r['priority_score'] >= medium_threshold][:max_medium]
    remaining = [r for r in remaining if r not in medium_priority]

    benign = [r for r in remaining if r.get('verdict', '').lower() == 'benign' and r['priority_score'] < 20]
    low_priority = [r for r in remaining if r not in benign]

    return {
        'high_priority': high_priority,
        'medium_priority': medium_priority,
        'low_priority': low_priority,
        'benign': benign
    }


@router.post('/api/v1/report/generate_prioritized')
async def generate_prioritized_report(req: Request):
    """
    Generate a prioritized report with smart batch processing.

    Only processes top-priority rows with LLM to save costs.
    """
    payload = await req.json()
    rows = payload.get('rows', [])
    persona = payload.get('persona', 'soc_analyst')
    max_high = payload.get('max_high_priority', 10)
    max_medium = payload.get('max_medium_priority', 15)
    include_llm = payload.get('include_llm', True)

    # Prioritize rows
    buckets = prioritize_rows(rows, max_high=max_high, max_medium=max_medium)

    result = {
        'report_id': f"rpt_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        'total_rows': len(rows),
        'high_priority_count': len(buckets['high_priority']),
        'medium_priority_count': len(buckets['medium_priority']),
        'low_priority_count': len(buckets['low_priority']),
        'benign_count': len(buckets['benign']),
        'high_priority_rows': [],
        'medium_priority_rows': [],
        'low_priority_rows': buckets['low_priority'],
        'llm_cost': 0.0,
        'processing_time_ms': 0
    }

    if not include_llm:
        # Skip LLM processing, return prioritized raw data
        result['high_priority_rows'] = buckets['high_priority']
        result['medium_priority_rows'] = buckets['medium_priority']
        return JSONResponse(result)

    # Process high priority with Tier 2
    from src.analysis.auto_llm import AutoLLM
    llm = AutoLLM()

    start_time = time.time()

    for row in buckets['high_priority']:
        try:
            # Tier 2 deep analysis
            context = {'tier': 'tier2', 'persona': persona}
            tier2_summary = llm.summarize_row(row, context)

            # AI Insights (all 4 types)
            from src.api.insights_endpoints import _generate_all_insights
            insights = _generate_all_insights(row, context)

            # HopGraph
            from src.core.graph.hopgraph_integration import query_attack_graph
            hopgraph = query_attack_graph(row, max_hops=3)

            result['high_priority_rows'].append({
                'row': row,
                'priority_score': row['priority_score'],
                'tier2_summary': tier2_summary.get('text', ''),
                'ai_insights': insights,
                'hopgraph': hopgraph
            })

            result['llm_cost'] += 0.003  # Tier 2 cost

        except Exception as e:
            # Graceful degradation
            result['high_priority_rows'].append({
                'row': row,
                'priority_score': row['priority_score'],
                'error': str(e)
            })

    # Process medium priority with Tier 1
    for row in buckets['medium_priority']:
        try:
            # Tier 1 fast triage
            context = {'tier': 'tier1', 'persona': persona}
            tier1_summary = llm.summarize_row(row, context)

            # Playbook only (free)
            from src.analysis.domain_tools import get_tools_for_domain
            from src.analysis.auto_llm import detect_domain_with_confidence
            domain, _ = detect_domain_with_confidence(row)
            tools = get_tools_for_domain(domain)

            result['medium_priority_rows'].append({
                'row': row,
                'priority_score': row['priority_score'],
                'tier1_summary': tier1_summary.get('text', ''),
                'playbook': {'domain': domain, 'tools': tools[:5]}
            })

            result['llm_cost'] += 0.0005  # Tier 1 cost

        except Exception as e:
            result['medium_priority_rows'].append({
                'row': row,
                'priority_score': row['priority_score'],
                'error': str(e)
            })

    result['processing_time_ms'] = int((time.time() - start_time) * 1000)

    return JSONResponse(result)
```

---

## 📊 DECISION MATRIX: When to Use What

### Based on Row Count

| Row Count | Strategy | Max LLM Rows | Estimated Cost | Estimated Time |
|-----------|----------|--------------|----------------|----------------|
| **1-10** | Process all with Tier 1 | 10 | $0.005 | 10-20 sec |
| **11-25** | Top 10 Tier 2, rest Tier 1 | 25 | $0.04 | 30-60 sec |
| **26-50** | Top 10 Tier 2, next 15 Tier 1 | 25 | $0.0375 | 30-60 sec |
| **51-100** | Top 10 Tier 2, next 15 Tier 1 | 25 | $0.0375 | 30-60 sec |
| **101-200** | Top 15 Tier 2, next 20 Tier 1 | 35 | $0.055 | 60-90 sec |
| **200+** | Top 20 Tier 2, next 30 Tier 1 | 50 | $0.075 | 90-120 sec |

---

### Based on Persona

| Persona | High Priority | Medium Priority | Total LLM Rows | Report Type |
|---------|--------------|----------------|----------------|-------------|
| **SOC Analyst** | 10 (Tier 1) | 15 (Tier 1) | 25 | HTML table |
| **Threat Hunter** | 10 (Tier 2) | 10 (Tier 1) | 20 | Detailed sections |
| **CISO** | 5 (Executive summary only) | 0 | 5 | PDF executive brief |
| **Security Engineer** | 15 (Tier 2) | 20 (Tier 1) | 35 | Technical playbook |

---

### Based on Budget

| Monthly Budget | Rows/Upload | Uploads/Day | Strategy |
|---------------|-------------|-------------|----------|
| **$10/month** | Top 10 Tier 1 | 50 | Fast triage only |
| **$25/month** | Top 10 Tier 2, 15 Tier 1 | 20 | Balanced |
| **$50/month** | Top 15 Tier 2, 20 Tier 1 | 25 | Comprehensive |
| **$100/month** | Top 25 Tier 2 | 100 | Deep analysis all high-priority |

---

## 🎯 RECOMMENDED DEFAULTS

### For 135-Row CSV Upload

**Default Configuration:**
```python
{
  "max_high_priority": 10,      # Tier 2 deep analysis
  "max_medium_priority": 15,    # Tier 1 fast triage
  "persona": "soc_analyst",
  "include_llm": true,
  "include_benign_count": true,
  "high_threshold": 60.0,
  "medium_threshold": 40.0
}
```

**Result:**
- **High Priority (10 rows):** Full Tier 2 analysis, HopGraph, all AI insights
- **Medium Priority (15 rows):** Tier 1 triage, playbook only
- **Low Priority (80 rows):** Pipeline data only, no LLM
- **Benign (30 rows):** Counted but not included in report

**Cost:** $0.0375 per upload (vs $0.40 for all 135 rows)
**Time:** 30-60 seconds (vs 10-15 minutes for all rows)
**Coverage:** All threats analyzed, benign noise filtered out

---

## ✅ SUCCESS CRITERIA

Smart batch processing is working if:

- ✅ Top 10 threats get Tier 2 deep analysis
- ✅ Medium threats get Tier 1 fast triage
- ✅ Low-priority and benign rows are counted but not sent to LLM
- ✅ Cost per upload < $0.05 (vs $0.40 without prioritization)
- ✅ Processing time < 90 seconds (vs 10+ minutes)
- ✅ Report includes all rows but focuses detail on high-priority

---

## 🚀 NEXT STEPS

### Immediate (Next 2 Hours):
1. **Implement `calculate_priority_score()`** in `src/api/report_endpoints.py`
2. **Implement `prioritize_rows()`** function
3. **Add `/api/v1/report/generate_prioritized` endpoint**
4. **Test with 135-row CSV**

### Short Term (Next 2 Days):
1. **Add persona-based templates** (SOC analyst, CISO, etc.)
2. **Add frontend UI** for selecting persona and max rows
3. **Add cost estimator** before processing ("This will cost ~$0.04")
4. **Create visual priority heatmap** in report

### Before CEO Demo:
1. **Test with realistic data** (100+ row CSV)
2. **Show cost comparison** (naive vs smart batching)
3. **Demonstrate persona switching** (analyst vs CISO view)
4. **Rehearse walkthrough**

---

**Ready to implement smart batch processing?**
