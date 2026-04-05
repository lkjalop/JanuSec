# auto_llm.py - BEFORE vs AFTER Comparison

**Critical Change:** Line 24 in `src/analysis/auto_llm.py`

---

## ❌ BEFORE (Current Implementation)

**File:** `src/analysis/auto_llm.py`
**Lines:** 20-28

```python
def summarize_row(self, row: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    # Compose a compact prompt describing the row for triage summarization
    try:
        import json as _json
        system = 'You are a concise security analyst. Summarize this single row for triage.'
        user_prompt = f"{system}\nRow: {_json.dumps(row, default=str)}"
    except Exception:
        user_prompt = f"Summarize row: {str(row)}"
```

**Output Example:**
```
Mock summary for solarwinds tftp server.exe: likely suspicious based on hashes and factors.
```

**Problems:**
- ❌ Vague, unstructured
- ❌ No actionable playbook
- ❌ No exploitability context
- ❌ Analyst spends 20 minutes investigating

---

## ✅ AFTER (Proposed Implementation)

**File:** `src/analysis/auto_llm.py`
**Lines:** 20-120 (expanded)

```python
def should_include_missing_logs(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> bool:
    """
    Only include missing logs if 21-stage pipeline flagged something

    Args:
        row: The artifact row
        pipeline_context: Results from 21-stage deep analyze pipeline

    Returns:
        bool: True if missing logs section should be included
    """
    # Check correlation score from graph/correlation stage
    correlation_score = pipeline_context.get('correlation', {}).get('score', 0)
    if correlation_score > 0.5:
        return True

    # Check if high-risk attack patterns detected
    attack_patterns = pipeline_context.get('attack_patterns', [])
    high_risk_patterns = ['c2', 'lateral_movement', 'persistence', 'credential_access', 'exfiltration']
    if any(pattern in attack_patterns for pattern in high_risk_patterns):
        return True

    # Check if LLM confidence is low (needs more data)
    llm_confidence = pipeline_context.get('llm_confidence', 1.0)
    if llm_confidence < 0.8:
        return True

    # Check if factors suggest missing critical telemetry
    factors = row.get('factors', [])
    telemetry_gaps = ['no_network_logs', 'no_parent_process', 'no_user_context', 'no_registry_data']
    if any(gap in factors for gap in telemetry_gaps):
        return True

    # Otherwise, skip missing logs section
    return False


def build_llm_prompt(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> str:
    """
    Build 30-45 line LLM summary prompt for fast SOC triage

    Args:
        row: The artifact row
        pipeline_context: Results from 21-stage deep analyze pipeline

    Returns:
        str: Formatted prompt for LLM
    """
    import json

    prompt = f"""You are a SOC analyst performing FAST TRIAGE. Analyze this artifact and provide a concise 30-45 line summary.

ARTIFACT:
{json.dumps(row, indent=2, default=str)}

21-STAGE PIPELINE CONTEXT:
- DREAD Score: {pipeline_context.get('dread_score', 'N/A')}
- MITRE Techniques: {pipeline_context.get('mitre_tags', [])}
- Suspicious Factors: {pipeline_context.get('factors', [])}
- Graph Correlation Score: {pipeline_context.get('correlation', {}).get('score', 0)}
- Attack Patterns Detected: {pipeline_context.get('attack_patterns', [])}
- Threat Intel Hits: {pipeline_context.get('threat_intel', 'None')}

OUTPUT FORMAT (30-45 lines max):

📌 WHAT IS IT? (2-3 lines)
[Brief context: what process, what behavior, what attack pattern]

💥 EXPLOITABILITY (3-4 lines)
Attacker can use this to:
• [Damage scenario 1]
• [Damage scenario 2]
• [Damage scenario 3]

⚡ WHAT TO DO? (3-4 lines)
[Immediate action - 3 steps max, be specific]

📋 CONCISE PLAYBOOK (5-8 lines)
Step 1: [PowerShell/CLI command with context]
Step 2: [PowerShell/CLI command with context]
Step 3: [PowerShell/CLI command with context]
Step 4: [PowerShell/CLI command with context]
...
"""

    # CONDITIONAL: Only add missing logs if pipeline flagged something
    if should_include_missing_logs(row, pipeline_context):
        prompt += """
⚠️ MISSING LOGS (3-5 lines):
The 21-stage pipeline detected correlation/attack patterns but lacks complete telemetry.
Identify what logs would help CONFIRM or DENY if this is a real attack:
• [Missing log 1] - would confirm/deny [specific suspicion]
• [Missing log 2] - would confirm/deny [specific suspicion]
• [Missing log 3] - would confirm/deny [specific suspicion]
"""
    else:
        prompt += """
[Sufficient telemetry available - no missing logs section needed]
"""

    prompt += """
RULES:
- Keep total output to 30-45 lines
- Be concise but actionable
- Use bullet points for readability
- Include copy-paste commands in playbook
- Base all analysis on provided context (no hallucination)
- If binary is signed by Microsoft/Apple and in System32, likely benign
- Focus on HIGH-IMPACT findings that require immediate action
"""

    return prompt


def summarize_row(self, row: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate 30-45 line LLM summary for fast triage

    Args:
        row: The artifact row
        context: Pipeline context with DREAD, MITRE, correlation, etc.

    Returns:
        dict: {'text': summary, 'model': model_name, 'meta': {...}}
    """
    try:
        # Build structured prompt
        pipeline_context = context.get('pipeline_context', {})
        user_prompt = build_llm_prompt(row, pipeline_context)

    except Exception as e:
        # Fallback to basic prompt if structured prompt fails
        import json as _json
        system = 'You are a concise security analyst. Summarize this single row for triage.'
        user_prompt = f"{system}\nRow: {_json.dumps(row, default=str)}"

    # If we have a central LLM client, use it
    try:
        if self._client:
            resp = self._client.generate(user_prompt, model='gpt-4o-mini', max_tokens=1024, tenant_id=context.get('org'))

            # Standardize response shape
            if isinstance(resp, dict):
                summary_text = resp.get('text') or ''

                # Add metadata tracking
                result = {
                    'text': summary_text,
                    'model': resp.get('model') or 'gpt-4o-mini',
                    'meta': {
                        '_llm_processed': True,
                        '_llm_timestamp': datetime.utcnow().isoformat(),
                        '_llm_model': resp.get('model') or 'gpt-4o-mini',
                        '_llm_cost': context.get('llm_cost', 0.003),  # Default $0.003 per summary
                        '_llm_tokens': {
                            'input': resp.get('meta', {}).get('input_tokens', 0),
                            'output': resp.get('meta', {}).get('output_tokens', 0)
                        }
                    }
                }

                # Update row with metadata
                row['_llm_processed'] = True
                row['_llm_timestamp'] = result['meta']['_llm_timestamp']
                row['_llm_model'] = result['meta']['_llm_model']
                row['_llm_cost'] = result['meta']['_llm_cost']

                return result

    except Exception as e:
        # Log error but continue with fallback
        print(f"LLM call failed: {e}")
        pass

    # Fallback deterministic response
    try:
        proc = row.get('process_name') or row.get('process') or row.get('file_path') or 'row'
        text = f"Mock summary for {proc}: likely suspicious based on hashes and factors."
        return {
            'text': text,
            'model': 'fallback-mock',
            'meta': {
                '_llm_processed': False,
                '_llm_timestamp': datetime.utcnow().isoformat(),
                '_llm_model': 'fallback-mock',
                '_llm_cost': 0.0
            }
        }
    except Exception:
        return {
            'text': 'LLM not available',
            'model': 'none',
            'meta': {
                '_llm_processed': False,
                '_llm_timestamp': datetime.utcnow().isoformat(),
                '_llm_model': 'none',
                '_llm_cost': 0.0
            }
        }
```

**Output Example:**
```
╔═══════════════════════════════════════════════════════════════════╗
║ Row 3: solarwinds tftp server.exe (DREAD 8.7) - HIGH RISK        ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║ 📌 WHAT IS IT?                                                    ║
║ SolarWinds TFTP Server (Trivial File Transfer Protocol daemon).  ║
║ Unsigned binary. Company involved in 2020 SUNBURST supply chain  ║
║ attack. ThreatScore=4 + 1 AV detection warrants investigation.   ║
║                                                                   ║
║ 💥 EXPLOITABILITY                                                 ║
║ Attacker can use this to:                                        ║
║ • Exfiltrate files via TFTP (UDP port 69, often bypasses FW)     ║
║ • Upload malicious payloads to other network devices             ║
║ • Supply chain risk: If compromised variant, C2 communication    ║
║                                                                   ║
║ ⚡ WHAT TO DO?                                                    ║
║ 1. URGENT: Verify SHA256 against SolarWinds official hash        ║
║ 2. Check network logs for TFTP traffic (UDP 69) to external IPs  ║
║ 3. Review process lineage: Who installed? When? Authorized?      ║
║ 4. If unverified, isolate host + forensic analysis               ║
║                                                                   ║
║ 📋 CONCISE PLAYBOOK                                               ║
║ Step 1: Get-FileHash -Algorithm SHA256 "C:\...\tftp server.exe"  ║
║         Compare to: https://support.solarwinds.com/sha256-hashes ║
║ Step 2: Get-WinEvent -FilterHashtable @{LogName='Security';      ║
║         Id=4688} | Where {$_.Message -like '*solarwinds*'}       ║
║ Step 3: netstat -ano | findstr :69  # Check if TFTP port active  ║
║ Step 4: If hash mismatch OR unexpected network activity →        ║
║         Isolate host + escalate to IR team                       ║
║                                                                   ║
║ ⚠️ MISSING LOGS                                                   ║
║ [21-stage pipeline detected supply chain risk + threatScore=4]   ║
║ • No EDR/Sysmon logs - can't see parent process or install time  ║
║ • No firewall logs - can't confirm if TFTP is actively used      ║
║ • No hash validation baseline - can't auto-confirm legitimacy    ║
║ Collecting these would CONFIRM/DENY if backdoored or legit.      ║
║                                                                   ║
║ [🔍 Investigate Further - Open New Tab]                          ║
╚═══════════════════════════════════════════════════════════════════╝
```

**Benefits:**
- ✅ Structured, actionable
- ✅ Copy-paste playbook commands
- ✅ Exploitability context (business impact)
- ✅ Missing logs (conditional, only when needed)
- ✅ Analyst spends 30 seconds (glance → decide)

---

## 🔧 Implementation Steps

### Step 1: Add imports (top of file)
```python
from datetime import datetime
```

### Step 2: Add helper functions (before `summarize_row()`)
```python
def should_include_missing_logs(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> bool:
    # [See code above]
    pass

def build_llm_prompt(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> str:
    # [See code above]
    pass
```

### Step 3: Replace `summarize_row()` method (lines 20-46)
```python
def summarize_row(self, row: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    # [See code above]
    pass
```

### Step 4: Test with 3 suspicious rows
```bash
python
>>> from src.analysis.auto_llm import LLMAssessmentClient
>>> client = LLMAssessmentClient()
>>> row = {
...     "name": "solarwinds tftp server.exe",
...     "path": "c:\\program files (x86)\\solarwinds\\tftp server\\solarwinds tftp server.exe",
...     "sha256": "9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a",
...     "suspicious": True,
...     "threatScore": 4,
...     "avPositives": 1,
...     "factors": ["unsigned_binary", "supply_chain_risk", "network_service"]
... }
>>> context = {
...     "pipeline_context": {
...         "dread_score": 8.7,
...         "mitre_tags": ["T1072"],
...         "factors": ["unsigned_binary", "supply_chain_risk"],
...         "correlation": {"score": 0.73},
...         "attack_patterns": ["c2", "exfiltration"]
...     }
... }
>>> result = client.summarize_row(row, context)
>>> print(result['text'])
```

---

## 📊 Expected Diff

**Lines Changed:** ~100 lines
**Files Modified:** 1 (`src/analysis/auto_llm.py`)
**Time Estimate:** 1-2 hours
**Testing Time:** 30 minutes (3 test rows)

---

## ✅ Success Criteria

1. **30-45 line output:** Summary should be 30-45 lines (not 1 line, not 200 lines)
2. **Structured sections:** Must have WHAT IS IT / EXPLOITABILITY / WHAT TO DO / PLAYBOOK / MISSING LOGS (conditional)
3. **No hallucinations:** All facts must come from `row` or `pipeline_context` data
4. **Copy-paste commands:** Playbook must have actual PowerShell/CLI commands
5. **Metadata tracking:** `_llm_processed`, `_llm_timestamp`, `_llm_model`, `_llm_cost` added to row
6. **Conditional missing logs:** Only show if correlation > 0.5 or attack patterns detected

---

## 🚀 GitHub Copilot Prompt (Ready to Use)

```
Update src/analysis/auto_llm.py to implement 30-45 line structured LLM triage summary.

CHANGES:
1. Add import at top: from datetime import datetime

2. Add helper function should_include_missing_logs(row, pipeline_context):
   - Check correlation_score > 0.5
   - Check attack_patterns for ['c2', 'lateral_movement', 'persistence']
   - Check llm_confidence < 0.8
   - Check factors for ['no_network_logs', 'no_parent_process', 'no_user_context']
   - Return bool

3. Add helper function build_llm_prompt(row, pipeline_context):
   - Build structured prompt with sections:
     * 📌 WHAT IS IT? (2-3 lines)
     * 💥 EXPLOITABILITY (3-4 lines)
     * ⚡ WHAT TO DO? (3-4 lines)
     * 📋 CONCISE PLAYBOOK (5-8 lines)
     * ⚠️ MISSING LOGS (3-5 lines - IF suspected, call should_include_missing_logs())
   - Include ARTIFACT and 21-STAGE PIPELINE CONTEXT in prompt
   - Add RULES: 30-45 lines max, no hallucination, copy-paste commands

4. Update summarize_row() method:
   - Call build_llm_prompt() instead of basic prompt
   - Increase max_tokens to 1024 (from 512)
   - Add metadata tracking after LLM call:
     * row['_llm_processed'] = True
     * row['_llm_timestamp'] = datetime.utcnow().isoformat()
     * row['_llm_model'] = model_name
     * row['_llm_cost'] = 0.003 (or 0 for local GPU)
   - Return dict with 'text', 'model', 'meta' (includes tracking fields)

IMPORTANT:
- Keep fallback logic for errors (existing code)
- Don't break existing API (summarize_row() signature stays same)
- Add metadata to 'meta' dict in return value
```

---

## 📝 Next Steps

1. ✅ Review this BEFORE/AFTER comparison
2. ⏭️ Copy GitHub Copilot prompt above
3. ⏭️ Paste into GitHub Copilot / Cursor AI
4. ⏭️ Review generated code
5. ⏭️ Test with 3 suspicious rows from Cyberstash
6. ⏭️ Verify output quality (30-45 lines, structured, actionable)
7. ⏭️ Get CEO approval: "Is this what you wanted?"

---

**File:** `src/analysis/auto_llm.py`
**Priority:** CRITICAL (Phase 1 - Foundation)
**Time:** 1-2 hours implementation + 30 min testing
**Impact:** 40x faster triage (20 min → 30 sec per alert)
