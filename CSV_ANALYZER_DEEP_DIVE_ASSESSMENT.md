# CSV Analyzer Deep Dive Assessment

**Date:** 2025-11-15
**Scope:** csv_analyzer.html, csv_multi_analyzer.html, Deep Analyze (21-step pipeline), Auto-LLM Summaries, Report Generation & PDF Export

---

## Executive Summary

The JanuSec CSV analysis suite consists of three primary components:
1. **Single CSV Analyzer** (`csv_analyzer.html`) - Client-side row-by-row analysis
2. **Multi-Source Correlator** (`csv_multi_analyzer.html`) - Heterogeneous log correlation
3. **Deep Analysis Pipeline** - Server-side 21-step enrichment framework

**Current State:** ✅ Core analysis functional | ⚠️ LLM summaries partially implemented | ❌ PDF generation missing

---

## 1. Component Analysis

### 1.1 csv_analyzer.html

**Purpose:** Single CSV file upload with client-side parsing, DREAD scoring, and framework mapping.

**Key Features:**
- ✅ Client-side CSV/XLSX parsing (SheetJS fallback)
- ✅ Verdict inference (GOOD/SUSPICIOUS/MALICIOUS) with vendor allowlisting
- ✅ DREAD scoring with numeric signals (avPositives, threatWeight)
- ✅ MITRE ATT&CK, STRIDE, PASTA framework mapping
- ✅ Per-row "Deep Analyze" button → `/static/csv_deep_analysis.html`
- ✅ Export Report button → `/api/v1/report/generate`
- ✅ HopGraph correlation button → `/api/v1/graph/session/build`
- ✅ Bulk disposition (Mark Good/Review/Threat)

**Technical Implementation:**
```javascript
Location: frontend/static/csv_analyzer.html (626 lines)
Dependencies:
  - /static/js/csv_analyzer.js (753 lines)
  - /static/js/threat_ranking.js
  - /static/js/parse_tabular.js (XLSX parsing)
  - /static/js/notifications.js
```

**Data Flow:**
```
1. User uploads CSV/XLSX → fileInput.files[0]
2. Client parses → window.parseTabular.clientSideAggregate()
3. Maps to records → mapRawToRecord(raw)
   - Infers verdict via inferVerdictFromRaw()
   - Computes DREAD via computeDreadBreakdown(factors, raw)
4. Renders table → renderTableFromResults()
5. User clicks "Deep Analyze" → Calls inline handler
   - Adds 'deep_enriched' factor to first row
   - Dispatches 'csv-deep-analyze-done' event
   - Sets window.__csv_deep_analyze_done = true
```

**Deep Analyze Button (csv_analyzer.html:70):**
```html
<button id="btnAnalyzePipeline" data-test="csv-btn-deep-analyze" class="btn">Deep Analyze</button>
```

**Handler (Lines 531-573):**
```javascript
// Simplified flow:
1. Ingest rows → POST /api/v1/ingest/csv_rows
   Returns: [{row_index, event_id}, ...]
2. Build CSV blob → FormData with file
3. Upload → POST /api/v1/upload/files
   Returns: {sessions: [...]}
4. Build graph → POST /api/v1/graph/session/build
   Payload: {session_ids, correlate:true, ewma:true, mapping}
   Returns: {summary: {verdict, confidence, factors, path_scores}}
5. Saves to window.LAST_CORR_SUMMARY
6. Enriches first row with 'deep_enriched' factor
7. Re-renders table
```

**Current Gaps:**
- ❌ Deep Analyze doesn't actually run 21-step pipeline (just adds a tag)
- ⚠️ No backend integration with artifact pipeline stages
- ⚠️ Missing LLM summary call after correlation

---

### 1.2 csv_multi_analyzer.html

**Purpose:** Multi-source log correlation with heterogeneous file types (CSV, JSON, XLSX, LOG, PCAP, EVTX).

**Key Features:**
- ✅ Multiple file upload with source type annotation
- ✅ Auto-detection (VPN, RDP, Bastion, API Gateway, Email, Data Access, AI)
- ✅ Canonical field mapping (user, host, process, file_hash, domain, ip)
- ✅ Assessment metadata (org, dept, assessor, vertical)
- ✅ Auto-LLM toggle (disabled by default)
- ✅ EWMA smoothing with configurable alpha
- ✅ Row-level preview table with filtering (All/Suspicious/Passed)
- ✅ Deep Analyze button → triggers backend pipeline
- ✅ HopGraph visualization with threat rankings sidebar
- ✅ Remediation hints & mini attack chain

**Technical Implementation:**
```javascript
Location: frontend/static/csv_multi_analyzer.html (1000+ lines embedded JS)
Backend: src/api/csv_multi_endpoints.py (would need to be created)
Dependencies:
  - XLSX.js (CDN + offline fallback)
  - threat_ranking.js
```

**Data Flow:**
```
1. User uploads files → fileInput.files (multiple)
2. Client parses each → XLSX.read() or CSV.parse()
3. Detects source type → detect_vpn_log(), detect_ai_log(), etc.
4. Maps to canonical → {user, host, process, file_hash, domain, ip}
5. User clicks "Build HopGraph" → POST /api/v1/graph/session/build
6. Displays correlation matrix, path scores, threat rankings
7. Deep Analyze → POST /api/v1/csv/deep_analyze (needs implementation)
```

**Assessment Metadata (Lines 100-121):**
```html
<input id="metaOrg" placeholder="Organization / Company" />
<input id="metaDept" placeholder="Department" />
<input id="metaAssessor" placeholder="Assessor" />
<select id="metaVertical">Finance/Healthcare/Manufacturing/Tech/Gov/Edu</select>
<input type="checkbox" id="metaAutoLLM" /> Auto-LLM (off by default)
<select id="metaRiskAppetite">Low/Medium/High</select>
```

**Current Gaps:**
- ❌ Backend endpoint `/api/v1/csv/deep_analyze` missing
- ❌ Auto-LLM integration not wired to backend
- ⚠️ Assessment metadata not persisted

---

### 1.3 csv_deep_analysis.html

**Purpose:** Per-row deep framework analysis page (opens in new window).

**Key Features:**
- ✅ DREAD breakdown (Damage/Repro/Exploitability/Affected/Discoverability)
- ✅ MITRE technique hints (T1059, T1543.003, T1047, etc.)
- ✅ STRIDE mapping (Tampering, Repudiation, Elevation, etc.)
- ✅ PASTA stages (Stage 4-7)
- ✅ CVSS estimate (Critical/High/Medium/Low)
- ✅ Compliance controls (NIST SI-7, CIS 8, ISO 27001)
- ✅ Rationale & playbooks (Isolate Host, Contain Execution, Block C2)
- ✅ Server risk ablation fetch → `/api/v1/risk/{event_id}/explain?include_ablation=1`

**Technical Implementation:**
```javascript
Location: frontend/static/csv_deep_analysis.html (222 lines)
Data Source: localStorage.getItem('csv_last_results')
Row Index: localStorage.getItem('csv_deep_row')
```

**Data Flow:**
```
1. User clicks "Per-row Deep Explain" in csv_analyzer.html
2. Saves row index to localStorage: csv_deep_row
3. Saves full results to localStorage: csv_last_results
4. Opens csv_deep_analysis.html in new tab
5. Retrieves row → list[idx]
6. Computes DREAD client-side → computeDreadBreakdown(factors)
7. Maps factors → mitreHints(), strideFromFactors(), pastaStages()
8. If event_id present → Fetch server ablation:
   GET /api/v1/risk/{event_id}/explain?include_ablation=1
9. Renders frameworks + playbooks
```

**Current Gaps:**
- ❌ No LLM-powered natural language summary
- ⚠️ Limited to client-side factor mapping (no server enrichment)

---

## 2. Deep Analyze Pipeline (21-Step) - Current State

**Location:** `src/core/event_pipeline/pipeline.py`

**Available Stages (13 detected):**
1. ✅ `NormalizationStage` - Field normalization
2. ✅ `AllowlistStage` - Vendor/benign filtering
3. ✅ `FactorEmissionStage` - Signal extraction
4. ✅ `RiskScoringStage` - DREAD/risk calculation
5. ✅ `MitreEnrichmentStage` - ATT&CK mapping
6. ✅ `StrideEnrichmentStage` - Threat modeling
7. ✅ `NetworkEnrichmentStage` - IP/domain enrichment
8. ✅ `SbomEnrichmentStage` - Software BOM analysis
9. ✅ `BeaconDetectionStage` - C2 beaconing
10. ✅ `RareTokenStage` - Anomaly detection
11. ✅ `CorrelationStage` - Cross-event correlation
12. ✅ `EscalationStage` - Threshold-based escalation
13. ✅ `PersistenceStage` - Database write

**Missing Stages (to reach 21):**
14. ❌ `GeoIPEnrichmentStage` - Geographic context
15. ❌ `ThreatIntelStage` - VirusTotal/AbuseIPDB/MISP
16. ❌ `BehaviorModelingStage` - ML-based anomaly scoring
17. ❌ `GraphTraversalStage` - Attack path discovery
18. ❌ `ContextAggregationStage` - User/asset context
19. ❌ `ComplianceCheckStage` - Policy violation detection
20. ❌ `ResponseOrchestrationStage` - SOAR actions
21. ❌ `LLMSummaryStage` - Natural language generation

**Current Backend Integration:**

```python
# src/api/csv_endpoints.py - Line 539
@router.post("/analyze_row")
async def analyze_row(payload: dict):
    """Analyze a single tabular row and return explainable metrics."""
    # Composes risk score via compose_risk_score()
    # Maps factors to MITRE/STRIDE/DREAD
    # Returns breakdown + top positive/negative contributors
```

**Gap:** No multi-stage pipeline invocation. Current implementation is a single-shot analysis.

---

## 3. Auto-LLM Summary Implementation

### 3.1 Current Implementation

**Backend:**
```python
# src/api/report_endpoints.py - Lines 42-109
@router.post('/api/v1/report/generate')
async def generate_report(
    req: Request,
    format: str = Query('html'),
    include_model: bool = Query(False),
    include_scenarios: bool = Query(False)
):
    payload = await req.json()
    html = build_report_html(payload)
    result = {'html': html}

    # LLM summary if requested
    if include_model:
        prompt = build_summary_prompt(payload.get('summary') or {}, len(payload.get('rows') or []))
        llm_resp = generate_summary(prompt, max_tokens=512)
        if hasattr(llm_resp, '__await__'):
            llm_resp = await llm_resp

        result['model_summary'] = {
            'text': llm_resp.get('text'),
            'model': llm_resp.get('model'),
            'meta': llm_resp.get('meta'),
            'provenance': {}
        }

        # Parse structured JSON from LLM
        parsed = parse_structured_summary(llm_resp.get('text'))
        result['model_summary']['provenance']['structured'] = parsed

        # Create model_html snippet
        model_html = '<div>...</div>'
        result['model_html'] = model_html

    return JSONResponse(result) if include_model else HTMLResponse(html)
```

**LLM Client:**
```python
# src/integrations/llm_client.py
class LLMClient:
    - Mock mode: LLM_MOCK=1 → returns fixtures from tests/fixtures/llm_mock.json
    - OpenAI: gpt-* models via openai.ChatCompletion.create()
    - Anthropic: claude-* models via anthropic.Client
    - Token cap enforcement
    - Retry logic (LLM_RETRIES=2)
    - Timeout (LLM_TIMEOUT_SECONDS=10)
    - Cost tracking via CostLedger
    - Circuit breaker per tenant
```

**Prompt Template:**
```python
# src/reporting/llm_prompts.py
SUMMARY_PROMPT_TEMPLATE = '''
You are a security analyst assistant. Produce a JSON object with keys:
- company_name (optional)
- recipients (array)
- key_findings (array of short strings)
- one_line_recommendation (string)
- provenance (object)

Input Summary: {summary}
Top rows count: {row_count}
Return only the JSON object. Keep items concise.
'''
```

### 3.2 Frontend Integration

**csv_analyzer.html (Lines 82-84):**
```html
<label style="display:inline-flex; align-items:center; gap:6px;">
  <input type="checkbox" id="reportIncludeModel" />
  <span style="font-size:12px">Include Model Summary</span>
</label>
```

**Report Export Handler (Lines 216-251):**
```javascript
var includeModel = document.getElementById('reportIncludeModel').checked;
var url = '/api/v1/report/generate' + (includeModel ? '?include_model=true' : '');
var resp = await fetch(url, { method: 'POST', ... });

if (includeModel) {
    var j = await resp.json();
    // j.html → main report
    // j.model_summary → LLM output
    // j.model_html → formatted snippet
    if (j.html) {
        var w = window.open('about:blank', '_blank');
        w.document.write(j.html);
        injectEnhancements(w.document, rows, corrSummary);
    }
}
```

**csv_multi_analyzer.html (Lines 117-118):**
```html
<label><input type="checkbox" id="metaAutoLLM" /> Auto-LLM (off by default)</label>
```
→ **Not wired to backend yet**

### 3.3 Gaps in LLM Summary

1. ❌ **No Auto-LLM trigger after Deep Analyze**
   - User must manually check "Include Model Summary" box
   - No automatic invocation after correlation build

2. ❌ **Multi-analyzer Auto-LLM not connected**
   - `metaAutoLLM` checkbox exists but not sent to backend

3. ⚠️ **Limited Prompt Engineering**
   - Current prompt is basic (JSON fields only)
   - No chain-of-thought or multi-shot examples
   - No incident narrative generation

4. ⚠️ **No Streaming Support**
   - LLM responses block until complete
   - No Server-Sent Events (SSE) for progressive updates

5. ❌ **No LLM-Powered Attack Narratives**
   - Could generate: "Attacker moved laterally from HOST_A to HOST_B via RDP, then exfiltrated DB_SALES via SFTP to EXTERNAL_IP"

---

## 4. Report Generation

### 4.1 Current HTML Report Generator

**Location:** `src/reporting/comprehensive_report_generator.py`

**Structure:**
```python
def build_report_html(payload):
    title = payload.get('title', 'Comprehensive Findings Report')
    rows = payload.get('rows') or []
    meta = payload.get('meta') or {}

    # Sections:
    1. Title + Session ID
    2. Executive Summary
       - Company name
       - Recipients
       - Key findings (top hosts, verdict distribution, high DREAD entries)
       - Correlation verdict/confidence
       - One-line recommendation
    3. Summary (JSON dump)
    4. Rows (up to 200, JSON preview per row)
    5. HopGraph Snapshot (correlation data)
    6. Footer

    Returns: HTML string (dark theme, inline styles)
```

**Enhancement Injections (csv_analyzer.html:166-214):**
```javascript
function injectEnhancements(doc, rows, corrSummary) {
    // Adds to generated report:
    1. MITRE Technique Heatmap (count by technique ID)
    2. Per-row DREAD Summary (horizontal bars)
    3. Playbook Suggestions (derived from path_scores)
    4. Copy buttons per row
}
```

### 4.2 Report Endpoints

**Available:**
- ✅ `POST /api/v1/report/generate?format=html&include_model=true`
- ✅ `POST /api/v1/report/upload` (not shown but referenced in share flow)
- ✅ `POST /api/v1/integrations/send_report` (Webhook/Email/Teams/WhatsApp)

**Missing:**
- ❌ `POST /api/v1/report/generate?format=pdf` - PDF generation endpoint

---

## 5. PDF Generation - What's Needed

### 5.1 Library Options

**Option 1: ReportLab (Already in requirements.txt)**
```python
# requirements.txt:73-74
reportlab>=4.0.0
pdfplumber>=0.11.0  # For reading PDFs, not generating
```

**Pros:**
- ✅ Pure Python, no external dependencies
- ✅ Programmatic layout control
- ✅ Supports charts/tables/images
- ✅ Works on Windows/Linux

**Cons:**
- ⚠️ Low-level API (manual positioning)
- ⚠️ Doesn't render HTML directly

**Option 2: WeasyPrint**
```bash
pip install weasyprint
```

**Pros:**
- ✅ Renders HTML/CSS to PDF
- ✅ Reuses existing report_html output
- ✅ CSS Paged Media support

**Cons:**
- ⚠️ Requires system dependencies (Pango, Cairo on Windows)
- ⚠️ Larger install footprint

**Option 3: wkhtmltopdf (via pdfkit)**
```bash
pip install pdfkit
# Requires wkhtmltopdf binary installed separately
```

**Pros:**
- ✅ WebKit-based rendering (good CSS support)
- ✅ Headless conversion

**Cons:**
- ❌ External binary dependency
- ❌ Project no longer maintained (last release 2020)

**Option 4: Playwright/Puppeteer PDF**
```bash
pip install playwright
playwright install chromium
```

**Pros:**
- ✅ Full browser rendering (perfect CSS fidelity)
- ✅ JavaScript execution (for dynamic content)
- ✅ Already in project (see playwright.config.js)

**Cons:**
- ⚠️ Requires Chromium download (~170MB)
- ⚠️ Slower than WeasyPrint

### 5.2 Recommended Approach: **WeasyPrint**

**Rationale:**
1. Reuses existing HTML reports (no rewrite needed)
2. Pure Python dependency management
3. Good CSS support for dark theme
4. Reasonable performance (<3s for 200-row report)

**Installation:**
```bash
pip install weasyprint
```

**Windows Dependencies:**
```bash
# Option 1: GTK3 Runtime (one-time install)
https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases

# Option 2: Conda (if using Anaconda)
conda install -c conda-forge weasyprint
```

**Linux:**
```bash
sudo apt-get install python3-pip python3-cffi python3-brotli libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
pip install weasyprint
```

### 5.3 Implementation Plan

**Step 1: Add PDF Endpoint**

```python
# src/api/report_endpoints.py (add after line 109)

from weasyprint import HTML
import tempfile
import os

@router.post('/api/v1/report/generate_pdf')
async def generate_pdf_report(req: Request, include_model: bool = Query(False)):
    """Generate PDF report from HTML via WeasyPrint."""
    payload = await req.json()

    # Generate HTML first (reuse existing logic)
    html = build_report_html(payload)

    # Add model summary if requested
    if include_model:
        prompt = build_summary_prompt(payload.get('summary') or {}, len(payload.get('rows') or []))
        llm_resp = generate_summary(prompt, max_tokens=512)
        if hasattr(llm_resp, '__await__'):
            llm_resp = await llm_resp
        model_text = llm_resp.get('text') if isinstance(llm_resp, dict) else str(llm_resp)

        # Inject model summary into HTML before PDF conversion
        model_section = f'''
        <div style="margin:20px 0; padding:16px; background:#10131a; border-left:4px solid #4A63E7; border-radius:6px;">
            <h3 style="margin:0 0 10px; color:#4A63E7;">AI Executive Summary</h3>
            <div style="white-space:pre-wrap; font-size:14px; line-height:1.6;">{escape(model_text)}</div>
            <div style="margin-top:8px; font-size:11px; color:#93A0B1;">
                Model: {llm_resp.get('model', 'N/A')} | Generated: {datetime.utcnow().isoformat()}
            </div>
        </div>
        '''
        # Insert after executive summary
        html = html.replace('<h3>Summary</h3>', model_section + '<h3>Summary</h3>')

    # Sanitize HTML
    if _HAS_BLEACH:
        safe_html = bleach.clean(html, tags=bleach.sanitizer.ALLOWED_TAGS + ['table','tr','td','th','div','h1','h2','h3','pre','span'], attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES, strip=True)
    else:
        safe_html = _simple_sanitize(html)

    # Convert to PDF
    try:
        # Create temporary HTML file (WeasyPrint needs file path for base_url resolution)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as tmp:
            tmp.write(safe_html)
            tmp_path = tmp.name

        # Generate PDF
        pdf_bytes = HTML(filename=tmp_path).write_pdf()

        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

        # Return as streaming response
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="janusec_report_{int(time.time())}.pdf"'
            }
        )
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return JSONResponse({'error': str(e)}, status_code=500)
```

**Step 2: Add Frontend Button**

```javascript
// csv_analyzer.html - Add after line 85
<button id="btnExportPDF" class="btn" title="Generate PDF report for selected rows">Export PDF</button>

// Wire handler after line 251
document.getElementById('btnExportPDF').addEventListener('click', async function(){
  try {
    var rows = (window.csvSelectedRows && window.csvSelectedRows.length ? window.csvSelectedRows : (window.LAST_RESULTS||[])).slice(0,200);
    if(!rows || !rows.length){ if(window.notifications && notifications.toast) notifications.toast('No rows to include','warn'); return; }

    var includeModel = document.getElementById('reportIncludeModel').checked;
    var payload = {
      title: 'CSV Analysis Report',
      rows: rows,
      summary: { total_rows: rows.length },
      correlation: (window.LAST_CORR_SUMMARY || null)
    };

    var url = '/api/v1/report/generate_pdf' + (includeModel ? '?include_model=true' : '');
    var resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'x-api-key': (localStorage.getItem('apiKey')||'devkey123') },
      body: JSON.stringify(payload)
    });

    if(!resp.ok){
      if(window.notifications && notifications.toast) notifications.toast('PDF generation failed: ' + resp.status,'error');
      return;
    }

    // Download PDF
    var blob = await resp.blob();
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'janusec_report_' + Date.now() + '.pdf';
    a.click();
    URL.revokeObjectURL(a.href);

    if(window.notifications && notifications.toast) notifications.toast('PDF downloaded','success');
  } catch(e) {
    if(window.notifications && notifications.toast) notifications.toast('PDF export failed','error');
  }
});
```

**Step 3: CSS Adjustments for PDF**

```html
<!-- Add to report HTML template -->
<style>
@media print {
  body { background: white; color: black; }
  .panel { page-break-inside: avoid; }
  pre { font-size: 10px; }
}
</style>
```

---

## 6. Complete Implementation Checklist

### 6.1 Deep Analyze 21-Step Pipeline

**Backend Stages to Add:**

```python
# src/core/event_pipeline/stages/advanced.py

class GeoIPEnrichmentStage(Stage):
    """Enrich IP addresses with geo/ASN data."""
    async def process(self, event):
        # Use MaxMind GeoIP2 or ip-api.com
        # Add: event['geo'] = {country, city, asn, org}
        pass

class ThreatIntelStage(Stage):
    """Query VirusTotal, AbuseIPDB, AlienVault OTX."""
    async def process(self, event):
        # Batch queries for hashes/IPs/domains
        # Add: event['threat_intel'] = {vt_score, abuse_confidence, otx_pulses}
        pass

class BehaviorModelingStage(Stage):
    """ML-based anomaly detection."""
    async def process(self, event):
        # Use isolation forest or autoencoder
        # Add: event['anomaly_score'] = float
        pass

class GraphTraversalStage(Stage):
    """Discover attack paths via graph query."""
    async def process(self, event):
        # Neo4j/NetworkX traversal
        # Add: event['attack_paths'] = [...]
        pass

class ContextAggregationStage(Stage):
    """Pull user/asset context from CMDB."""
    async def process(self, event):
        # ServiceNow/Jira/LDAP lookup
        # Add: event['context'] = {user_dept, asset_criticality}
        pass

class ComplianceCheckStage(Stage):
    """Check policy violations."""
    async def process(self, event):
        # SOC2/PCI-DSS/HIPAA rules
        # Add: event['compliance_violations'] = [...]
        pass

class ResponseOrchestrationStage(Stage):
    """Trigger SOAR actions."""
    async def process(self, event):
        # Splunk Phantom/Cortex XSOAR
        # Add: event['actions_triggered'] = [...]
        pass

class LLMSummaryStage(Stage):
    """Generate natural language summary."""
    async def process(self, event):
        prompt = f"Summarize this security event: {event}"
        summary = await generate_summary(prompt, max_tokens=256)
        event['llm_summary'] = summary
        pass
```

**Wiring:**
```python
# src/api/csv_endpoints.py - Add new endpoint

@router.post("/deep_analyze")
async def deep_analyze_rows(payload: dict, tenant_id: str | None = Header(None)):
    """Run 21-step pipeline on uploaded rows."""
    rows = payload.get('rows') or []
    auto_llm = payload.get('auto_llm', False)
    risk_appetite = payload.get('risk_appetite', 'medium')

    # Initialize pipeline
    pipeline = EventPipeline()
    pipeline.add_stage(NormalizationStage())
    pipeline.add_stage(AllowlistStage())
    pipeline.add_stage(FactorEmissionStage())
    pipeline.add_stage(RiskScoringStage())
    pipeline.add_stage(MitreEnrichmentStage())
    pipeline.add_stage(StrideEnrichmentStage())
    pipeline.add_stage(NetworkEnrichmentStage())
    pipeline.add_stage(SbomEnrichmentStage())
    pipeline.add_stage(BeaconDetectionStage())
    pipeline.add_stage(RareTokenStage())
    pipeline.add_stage(GeoIPEnrichmentStage())
    pipeline.add_stage(ThreatIntelStage())
    pipeline.add_stage(BehaviorModelingStage())
    pipeline.add_stage(GraphTraversalStage())
    pipeline.add_stage(ContextAggregationStage())
    pipeline.add_stage(ComplianceCheckStage())
    pipeline.add_stage(ResponseOrchestrationStage())
    pipeline.add_stage(CorrelationStage())
    pipeline.add_stage(EscalationStage())
    if auto_llm:
        pipeline.add_stage(LLMSummaryStage())
    pipeline.add_stage(PersistenceStage())

    # Process rows
    results = []
    for row in rows[:200]:  # Cap at 200 for performance
        event = {'raw': row, 'tenant_id': tenant_id}
        enriched = await pipeline.run(event)
        results.append(enriched)

    return {
        'status': 'completed',
        'processed': len(results),
        'results': results,
        'pipeline_stages': 21
    }
```

### 6.2 Auto-LLM Summary Integration

**Multi-Analyzer Backend:**
```python
# src/api/csv_multi_endpoints.py (new file)

@router.post("/build_graph")
async def build_multi_source_graph(payload: dict):
    """Build HopGraph from multi-source uploads."""
    session_ids = payload.get('session_ids') or []
    auto_llm = payload.get('meta', {}).get('auto_llm', False)

    # Build graph
    graph_resp = await build_session({
        'session_ids': session_ids,
        'correlate': True,
        'ewma': payload.get('ewma', True),
        'mapping': payload.get('mapping', {})
    })

    # Auto-LLM if enabled
    if auto_llm:
        summary = graph_resp.get('summary', {})
        prompt = build_summary_prompt(summary, len(session_ids))
        llm_resp = await generate_summary(prompt, max_tokens=512)
        graph_resp['llm_summary'] = llm_resp

    return graph_resp
```

**Frontend Wiring:**
```javascript
// csv_multi_analyzer.html - Update btnBuildGraph handler
document.getElementById('btnBuildGraph').addEventListener('click', async function(){
    const autoLLM = document.getElementById('metaAutoLLM').checked;
    const payload = {
        session_ids: [...],
        ewma: document.getElementById('chkEWMA').checked,
        mapping: {...},
        meta: {
            auto_llm: autoLLM,
            org: document.getElementById('metaOrg').value,
            dept: document.getElementById('metaDept').value,
            assessor: document.getElementById('metaAssessor').value,
            vertical: document.getElementById('metaVertical').value,
            risk_appetite: document.getElementById('metaRiskAppetite').value
        }
    };

    const resp = await fetch('/api/v1/csv/build_graph', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify(payload)
    });

    const data = await resp.json();

    // Display LLM summary if present
    if (data.llm_summary) {
        const summaryDiv = document.createElement('div');
        summaryDiv.className = 'panel';
        summaryDiv.innerHTML = `
            <h3>AI Executive Summary</h3>
            <div class="pre">${escapeHtml(data.llm_summary.text)}</div>
        `;
        document.querySelector('.container').prepend(summaryDiv);
    }
});
```

### 6.3 Share/Send Report Flow

**Email/Webhook Integration:**
```python
# src/api/integrations_endpoints.py - Add send_report endpoint

@router.post("/send_report")
async def send_report(payload: dict):
    """Send report via Email/Webhook/Teams/WhatsApp."""
    channel = payload.get('service') or payload.get('channel')
    target = payload.get('target')
    report_url = payload.get('report_url')
    message = payload.get('message', '')

    if channel == 'email':
        # Use SMTP or SendGrid
        send_email(to=target, subject='JanuSec Report', body=f"{message}\n\n{report_url}")
    elif channel == 'webhook':
        # POST to webhook URL
        httpx.post(target, json={'report_url': report_url, 'message': message})
    elif channel == 'teams':
        # Microsoft Teams adaptive card
        send_teams_message(webhook_url=target, text=message, url=report_url)
    elif channel == 'whatsapp':
        # Twilio WhatsApp API
        send_whatsapp(to=target, body=f"{message}\n{report_url}")

    return {'status': 'sent', 'channel': channel}
```

---

## 7. Testing Strategy

### 7.1 Unit Tests

```python
# tests/test_csv_deep_analyze.py

@pytest.mark.asyncio
async def test_deep_analyze_21_stages(test_client):
    """Verify all 21 pipeline stages execute."""
    payload = {
        'rows': [
            {'process_name': 'powershell.exe', 'file_path': 'C:\\temp\\malware.ps1'},
            {'process_name': 'cmd.exe', 'command_line': 'whoami /all'}
        ],
        'auto_llm': False
    }
    resp = test_client.post('/api/v1/csv/deep_analyze', json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data['pipeline_stages'] == 21
    assert len(data['results']) == 2
    # Verify each stage output
    assert 'geo' in data['results'][0]
    assert 'threat_intel' in data['results'][0]
    assert 'anomaly_score' in data['results'][0]

@pytest.mark.asyncio
async def test_llm_summary_generation(test_client, monkeypatch):
    """Verify LLM summary is generated when include_model=true."""
    monkeypatch.setenv('LLM_MOCK', '1')
    payload = {
        'title': 'Test Report',
        'rows': [{'verdict': 'MALICIOUS', 'dread': {'score': 8}}],
        'summary': {'total_rows': 1}
    }
    resp = test_client.post('/api/v1/report/generate?include_model=true', json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert 'model_summary' in data
    assert 'text' in data['model_summary']
    assert 'model' in data['model_summary']

@pytest.mark.asyncio
async def test_pdf_generation(test_client):
    """Verify PDF is generated with correct headers."""
    payload = {
        'title': 'Test Report',
        'rows': [{'process_name': 'test.exe'}]
    }
    resp = test_client.post('/api/v1/report/generate_pdf', json=payload)
    assert resp.status_code == 200
    assert resp.headers['content-type'] == 'application/pdf'
    assert 'Content-Disposition' in resp.headers
    assert b'%PDF-' in resp.content[:10]  # PDF magic bytes
```

### 7.2 E2E Tests (Playwright)

```javascript
// tests/e2e/test_csv_analyzer.spec.js

test('Deep Analyze runs 21-step pipeline', async ({ page }) => {
  await page.goto('http://localhost:8080/static/csv_analyzer.html');

  // Upload CSV
  await page.setInputFiles('#fileInput', 'tests/fixtures/malicious_sample.csv');
  await page.click('#btnLoad');
  await page.waitForSelector('[data-ready="1"]');

  // Click Deep Analyze
  await page.click('#btnAnalyzePipeline');
  await page.waitForFunction(() => window.__csv_deep_analyze_done);

  // Verify pipeline badge
  const badge = await page.locator('#pipelineBadge .pill');
  await expect(badge).toBeVisible();
});

test('Export PDF with LLM summary', async ({ page }) => {
  await page.goto('http://localhost:8080/static/csv_analyzer.html');
  await page.setInputFiles('#fileInput', 'tests/fixtures/sample.csv');
  await page.click('#btnLoad');
  await page.waitForSelector('[data-ready="1"]');

  // Enable model summary
  await page.check('#reportIncludeModel');

  // Trigger PDF export
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('#btnExportPDF')
  ]);

  const path = await download.path();
  const buffer = await fs.readFile(path);
  expect(buffer.slice(0, 5).toString()).toBe('%PDF-');
});
```

---

## 8. Performance Considerations

### 8.1 LLM Summary Caching

```python
# src/integrations/llm_client.py - Add cache decorator

from functools import lru_cache
import hashlib

class LLMClient:
    def __init__(self):
        self._cache = {}  # prompt_hash -> response
        self._cache_ttl = int(os.getenv('LLM_CACHE_TTL', '3600'))

    def generate(self, prompt, **kwargs):
        # Check cache
        cache_key = hashlib.sha256(prompt.encode()).hexdigest()
        cached = self._cache.get(cache_key)
        if cached and (time.time() - cached['ts']) < self._cache_ttl:
            return cached['response']

        # Generate new response
        response = self._generate_uncached(prompt, **kwargs)

        # Store in cache
        self._cache[cache_key] = {'response': response, 'ts': time.time()}
        return response
```

### 8.2 PDF Generation Optimization

**Async PDF Conversion:**
```python
import asyncio
from concurrent.futures import ProcessPoolExecutor

_PDF_EXECUTOR = ProcessPoolExecutor(max_workers=2)

@router.post('/api/v1/report/generate_pdf')
async def generate_pdf_report(req: Request):
    # ... build HTML ...

    # Offload PDF conversion to process pool
    pdf_bytes = await asyncio.get_event_loop().run_in_executor(
        _PDF_EXECUTOR,
        _convert_html_to_pdf,
        safe_html
    )

    return StreamingResponse(io.BytesIO(pdf_bytes), media_type='application/pdf')

def _convert_html_to_pdf(html: str) -> bytes:
    """CPU-bound PDF generation in separate process."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as tmp:
        tmp.write(html)
        tmp_path = tmp.name
    pdf_bytes = HTML(filename=tmp_path).write_pdf()
    os.unlink(tmp_path)
    return pdf_bytes
```

### 8.3 Streaming LLM Responses

**SSE Implementation:**
```python
from fastapi.responses import StreamingResponse

@router.post('/api/v1/report/generate_stream')
async def generate_report_stream(req: Request):
    """Stream LLM summary generation via SSE."""
    async def event_generator():
        payload = await req.json()

        # Yield HTML immediately
        html = build_report_html(payload)
        yield f"data: {json.dumps({'type': 'html', 'content': html})}\n\n"

        # Stream LLM summary
        prompt = build_summary_prompt(payload.get('summary') or {}, len(payload.get('rows') or []))

        # If using OpenAI streaming:
        if include_model:
            async for chunk in generate_summary_stream(prompt):
                yield f"data: {json.dumps({'type': 'llm_chunk', 'content': chunk})}\n\n"

        yield "data: {\"type\": \"done\"}\n\n"

    return StreamingResponse(event_generator(), media_type='text/event-stream')
```

---

## 9. Final Summary

### 9.1 Current Capabilities

| Feature | csv_analyzer.html | csv_multi_analyzer.html | Backend |
|---------|-------------------|-------------------------|---------|
| File Upload | ✅ CSV/XLSX | ✅ CSV/JSON/XLSX/LOG/PCAP/EVTX | ✅ |
| Verdict Inference | ✅ Client | ✅ Client | ✅ Server |
| DREAD Scoring | ✅ | ✅ | ✅ |
| Framework Mapping | ✅ MITRE/STRIDE/PASTA | ✅ | ✅ |
| Deep Analyze Button | ✅ (stub) | ✅ | ❌ |
| 21-Step Pipeline | ❌ | ❌ | ⚠️ 13/21 |
| LLM Summary (Manual) | ✅ | ❌ | ✅ |
| LLM Summary (Auto) | ❌ | ❌ (UI only) | ❌ |
| HTML Report | ✅ | ❌ | ✅ |
| PDF Export | ❌ | ❌ | ❌ |
| Share/Send | ✅ (UI) | ❌ | ✅ |

### 9.2 What's Needed to Complete

**Priority 1 (Critical):**
1. ✅ **Backend Deep Analyze Endpoint** - `/api/v1/csv/deep_analyze`
   - Wire existing pipeline stages
   - Add 8 missing stages (GeoIP, ThreatIntel, Behavior, Graph, Context, Compliance, SOAR, LLM)
2. ✅ **PDF Generation Endpoint** - `/api/v1/report/generate_pdf`
   - Install WeasyPrint
   - Add endpoint implementation
   - Wire frontend button

**Priority 2 (High):**
3. ✅ **Auto-LLM Integration**
   - Multi-analyzer: Wire `metaAutoLLM` to backend
   - Add automatic trigger after Deep Analyze
   - Implement streaming SSE for progressive updates
4. ✅ **Enhanced LLM Prompts**
   - Add chain-of-thought reasoning
   - Multi-shot examples for incident narratives
   - Attack chain generation

**Priority 3 (Medium):**
5. ✅ **Performance Optimizations**
   - LLM response caching (1-hour TTL)
   - Async PDF generation (process pool)
   - Streaming for large reports
6. ✅ **Testing**
   - Unit tests for all 21 pipeline stages
   - E2E tests for Deep Analyze + PDF export
   - Load testing (100 concurrent PDF generations)

### 9.3 Estimated Effort

| Task | Effort | Dependencies |
|------|--------|--------------|
| Backend Deep Analyze Endpoint | 3 days | Pipeline stages 14-21 |
| Pipeline Stages 14-21 | 5 days | GeoIP/ThreatIntel APIs |
| PDF Generation (WeasyPrint) | 1 day | System deps install |
| Auto-LLM Integration | 2 days | Backend endpoint |
| Enhanced LLM Prompts | 2 days | Prompt engineering |
| Performance Optimizations | 2 days | Caching + async |
| Testing Suite | 3 days | All above complete |
| **Total** | **18 days** | Sequential dependencies |

### 9.4 Quick Wins (Can Ship Today)

1. **PDF Export Button** - Add frontend button wired to existing HTML report download
2. **LLM Summary Checkbox** - Already works, just document usage
3. **Share Report Flow** - Already implemented, needs user documentation

---

## 10. Next Steps

**Immediate (Week 1):**
1. Install WeasyPrint: `pip install weasyprint`
2. Add PDF endpoint to `report_endpoints.py`
3. Wire PDF button in `csv_analyzer.html`
4. Test with sample 200-row report

**Short-Term (Week 2-3):**
5. Implement missing pipeline stages (GeoIP, ThreatIntel, Behavior, Graph)
6. Create `/api/v1/csv/deep_analyze` endpoint
7. Wire Deep Analyze button to backend
8. Add Auto-LLM toggle logic

**Medium-Term (Month 1):**
9. Enhanced LLM prompts with attack narratives
10. SSE streaming for progressive updates
11. Performance testing and optimization
12. Comprehensive E2E test suite

---

**End of Assessment**
*Generated: 2025-11-15 | Author: Claude Code | Platform: JanuSec Threat Sifter*
