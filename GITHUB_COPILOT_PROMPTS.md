# GitHub Copilot Implementation Prompts

**Purpose:** Step-by-step prompts to implement enhanced LLM triage schema
**Use Case:** Copy-paste these into GitHub Copilot chat to make changes

---

## 📚 Required Reading for Copilot

Before starting, tell Copilot to read these files:

```
@workspace Read these files for context:
- ENHANCED_LLM_TRIAGE_SCHEMA.md (target schema design)
- SAMPLE_ENHANCED_OUTPUTS.md (example outputs)
- CLAUDE_CODE_SESSION_CONTEXT.md (architecture overview)
- src/analysis/auto_llm.py (current implementation)
```

---

## 🔧 Prompt 1: Update `auto_llm.py` - Add Enhanced Schema

**File:** `src/analysis/auto_llm.py`
**Lines:** 88-152 (the `build_llm_row()` function)

**Copilot Prompt:**

```
@workspace In src/analysis/auto_llm.py, I need to enhance the build_llm_row() function
to return a richer schema for security triage. Read ENHANCED_LLM_TRIAGE_SCHEMA.md for
the target structure.

Currently build_llm_row() returns a basic schema with:
- process_name, file_path, hash_sha256
- risk_level (just label + numeric)
- recommendation (just action + playbook)
- llm_summary (simple text string)

I need to expand this to include:

1. "triage" object with:
   - verdict (string)
   - confidence (0.0-1.0)
   - priority (P0/P1/P2)
   - whats_suspicious (array of {signal, severity, context, why_matters})
   - dread_breakdown (object with damage, reproducibility, exploitability, affected_users, discoverability - each has score + explanation + scenarios)
   - how_compromise_occurs (attack_chain array + mitre_mapping array)

2. "fast_decision_tree" object with:
   - estimated_time (string)
   - urgency (string)
   - steps (array of {step, title, priority, commands, decision_gate})

3. "missing_telemetry" object with:
   - identified_gaps (array of {gap, why_critical, how_to_get, what_to_query, urgency})
   - recommended_collection (object with immediate, high_priority, medium_priority arrays)
   - analyst_guidance (string)

4. "allowlist_criteria" object
5. "remediation_steps" object with prioritized actions
6. "extra_validation" object
7. "tldr_recommendation" object
8. "analyst_next_steps" object
9. "context_sources" object with confidence scoring

Keep existing fields (process_name, hash_sha256, etc.) and ADD these new sections.

The function should:
- Call a NEW helper function identify_telemetry_gaps(row, canonical_signals) to detect missing logs
- Call a NEW helper function build_dread_scenarios(row, dread_numeric) to generate damage explanations
- Call a NEW helper function build_decision_tree(row) to generate triage commands
- Maintain backwards compatibility (old fields still present)

Show me the updated build_llm_row() function structure with these new sections.
```

---

## 🔧 Prompt 2: Create `identify_telemetry_gaps()` Helper

**File:** `src/analysis/auto_llm.py`
**Insert Location:** After line 47 (after LLMAssessmentClient class)

**Copilot Prompt:**

```
@workspace In src/analysis/auto_llm.py, add a new function identify_telemetry_gaps(row, canonical_signals)
after the LLMAssessmentClient class definition (around line 47).

This function should analyze the input row and identify what telemetry is MISSING for proper triage.

Logic rules:
1. If process_name contains 'powershell' and command_line has '-e' or '-enc' (encoded):
   → Gap: "No PowerShell script block logging (Event 4104)"
   → how_to_get: "Enable via GPO: Windows PowerShell → Script Block Logging"
   → urgency: "HIGH"

2. If command_line contains 'reg add', 'New-ItemProperty', 'Set-ItemProperty', or registry modifications:
   → Gap: "No registry persistence check"
   → how_to_get: "Run KAPE with --target RegistryASEPs or use AutoRuns"
   → urgency: "HIGH"

3. If command_line contains 'http://', 'https://', 'ftp://', or network URLs:
   → Gap: "No network traffic logs"
   → how_to_get: "Query firewall, proxy, or Zeek/Suricata for host connections"
   → urgency: "CRITICAL"

4. If parent_process is in ['excel.exe', 'winword.exe', 'outlook.exe', 'powerpnt.exe', 'rundll32.exe', 'regsvr32.exe']:
   → Gap: "No full process tree (EDR timeline)"
   → how_to_get: "Pull from CrowdStrike/SentinelOne/Defender ATP process timeline"
   → urgency: "CRITICAL"

5. If user field exists and command_line suggests credential access:
   → Gap: "No AD/IAM logs (credential theft check)"
   → how_to_get: "Query Active Directory Event 4624/4768 or Okta for user login history"
   → urgency: "CRITICAL"

6. If process creates scheduled tasks (schtasks, Register-ScheduledTask):
   → Gap: "No scheduled task inventory"
   → how_to_get: "Export scheduled tasks: schtasks /query /fo LIST /v"
   → urgency: "HIGH"

Return a dict with:
{
  "identified_gaps": [list of gap objects],
  "recommended_collection": {
    "immediate": [array of strings],
    "high_priority": [array of strings],
    "medium_priority": [array of strings]
  },
  "analyst_guidance": "Summary of what's provided and what's needed"
}

Use defensive coding (handle None values, missing fields gracefully).
```

---

## 🔧 Prompt 3: Create `build_dread_scenarios()` Helper

**File:** `src/analysis/auto_llm.py`
**Insert Location:** After `identify_telemetry_gaps()` function

**Copilot Prompt:**

```
@workspace In src/analysis/auto_llm.py, add a new function build_dread_scenarios(row, dread_numeric, factors)
that generates detailed DREAD breakdown with realistic damage scenarios.

Inputs:
- row: dict with process_name, file_path, command_line, etc.
- dread_numeric: float (0.0-10.0)
- factors: list of factor strings (e.g., ['unsigned_binary', 'rare_parent'])

This function should:
1. Analyze the row context (what process, what command, what parent)
2. Generate realistic damage scenarios based on:
   - If powershell.exe → credential theft, lateral movement, ransomware deployment
   - If regsvr32.exe → fileless malware, C2 beacon, persistence
   - If bitsadmin.exe → malware download, backdoor installation
   - If unsigned binary in System32 → trojanized system file, rootkit potential
   - If suspicious parent (Excel/Word) → phishing macro, initial access

3. Return a dict with:
{
  "overall_score": float (calculated from existing DREAD or passed in),
  "damage": {
    "score": int (1-10),
    "explanation": "What attacker can do if this is malicious",
    "scenarios": [
      "Specific damage scenario 1",
      "Specific damage scenario 2",
      ...
    ],
    "business_impact": "High-level business risk"
  },
  "reproducibility": {
    "score": int,
    "explanation": "How easy to reproduce this attack",
    "attack_prerequisites": [list of requirements]
  },
  "exploitability": {
    "score": int,
    "explanation": "Attack vectors",
    "attack_vectors": [list of methods]
  },
  "affected_users": {
    "score": int,
    "explanation": "Scope of impact"
  },
  "discoverability": {
    "score": int,
    "explanation": "Detection challenges",
    "detection_challenges": [list of why this is hard/easy to detect]
  }
}

Use heuristics based on process names and command line patterns.
Don't hallucinate - base scenarios on REAL capabilities of the process/technique.
```

---

## 🔧 Prompt 4: Create `build_decision_tree()` Helper

**File:** `src/analysis/auto_llm.py`
**Insert Location:** After `build_dread_scenarios()` function

**Copilot Prompt:**

```
@workspace In src/analysis/auto_llm.py, add a new function build_decision_tree(row, dread_score)
that generates a fast triage decision tree with PowerShell/cmd commands.

This function should return step-by-step triage commands based on the artifact type:

Rules:
1. If powershell.exe with encoded command (-e, -enc, -EncodedCommand):
   Step 1: Decode Base64 command
   Step 2: Check parent process lineage
   Step 3: Look for network connections
   Step 4: Check persistence (registry, scheduled tasks)

2. If regsvr32.exe with /i: flag (Squiblydoo):
   Step 1: Isolate host + block remote URL
   Step 2: Attempt to retrieve payload (in sandbox)
   Step 3: Check network logs for successful download
   Step 4: Check for persistence

3. If bitsadmin.exe with /transfer:
   Step 1: Check if downloaded file executed
   Step 2: Quarantine downloaded file
   Step 3: Hash and submit to VirusTotal
   Step 4: Check persistence

4. If unsigned binary in System32:
   Step 1: Verify signature (Get-AuthenticodeSignature)
   Step 2: Run SFC /scannow to check integrity
   Step 3: Check file hash against known-good baseline
   Step 4: Look for DLL hijacking

Return structure:
{
  "estimated_time": "5-10 minutes",
  "urgency": "🔴 CRITICAL" or "🟠 HIGH" or "🟡 MEDIUM",
  "steps": [
    {
      "step": 1,
      "title": "Step title",
      "priority": "P0" or "P1" or "P2",
      "commands": [
        {
          "shell": "powershell" or "cmd" or "EDR Console",
          "command": "Actual command to run",
          "purpose": "What this command checks",
          "expected_output": "What good/bad looks like",
          "interpretation": {
            "if_valid": "What to do if check passes",
            "if_invalid": "What to do if check fails"
          }
        }
      ],
      "decision_gate": "If X then Y, else Z"
    }
  ]
}

Only use REAL Windows/PowerShell commands (Get-AuthenticodeSignature, Get-FileHash, sfc, etc.).
DO NOT invent commands.
```

---

## 🔧 Prompt 5: Update LLM Prompt in `LLMAssessmentClient.summarize_row()`

**File:** `src/analysis/auto_llm.py`
**Lines:** 20-46 (LLMAssessmentClient class)

**Copilot Prompt:**

```
@workspace In src/analysis/auto_llm.py, update the LLMAssessmentClient.summarize_row() method
to use a more structured prompt that generates the enhanced triage output.

Current prompt (line 24):
"You are a concise security analyst. Summarize this single row for triage."

New prompt should be:
"You are an expert security analyst performing alert triage. Analyze this artifact and provide:

INPUT CONTEXT:
- Process: {process_name}
- Path: {file_path}
- Hash: {hash_sha256}
- Command: {command_line}
- Parent: {parent_process}
- User: {user}
- Host: {host}
- Factors: {factors}
- DREAD Score: {dread_numeric}

YOUR TASK:
1. Explain WHY this is suspicious (what signals indicate malicious behavior?)
2. Explain HOW an attacker could use this (damage scenarios, not generic)
3. Provide specific triage commands (PowerShell/cmd - use REAL commands only)
4. Identify what telemetry is MISSING to complete the investigation

RULES:
- DO NOT hallucinate file paths, commands, or MITRE techniques not in the input
- Base damage scenarios on ACTUAL artifact attributes (signed status, path, parent process)
- Only suggest standard Windows commands (Get-AuthenticodeSignature, Get-FileHash, etc.)
- If you don't have enough context, say 'Insufficient data - recommend manual review'
- For commands, provide expected output and interpretation

OUTPUT (JSON):
{
  \"whats_suspicious\": [...],
  \"how_compromise_occurs\": {...},
  \"fast_decision_tree\": {...},
  \"missing_telemetry\": {...}
}
"

The prompt should inject actual values from the row dict.
Max tokens should be increased to 2048 (from current 512) to accommodate detailed output.
```

---

## 🔧 Prompt 6: Update `deep_analyze_endpoints.py` to Use New Schema

**File:** `src/api/deep_analyze_endpoints.py`
**Lines:** 303-317 (where `build_llm_row()` is called)

**Copilot Prompt:**

```
@workspace In src/api/deep_analyze_endpoints.py around line 303, where build_llm_row() is called
in the auto LLM section, ensure the function is called with the correct parameters.

Current call (line 303):
built = build_llm_row(rr, {'auto_llm': auto, 'org': org, 'assessment_id': assessment_id, 'session_id': session_id})

The enhanced build_llm_row() now also needs:
- canonical_signals (from the build_canonical_signals call on line 242)
- factors (from the row's factors field if it exists)

Update the call to:
built = build_llm_row(
    rr,
    {
        'auto_llm': auto,
        'org': org,
        'assessment_id': assessment_id,
        'session_id': session_id,
        'canonical_signals': canonical,  # from line 242
        'factors': rr.get('factors', [])
    }
)

Also ensure _sanitize_llm_row() on line 312 can handle the new nested structure
(triage, missing_telemetry, fast_decision_tree fields).

If _sanitize_llm_row() is too aggressive and strips new fields, update it to preserve:
- triage
- missing_telemetry
- fast_decision_tree
- allowlist_criteria
- remediation_steps
- tldr_recommendation
```

---

## 🔧 Prompt 7: Update Frontend `csv_analyzer.js` to Render New Schema

**File:** `frontend/static/js/csv_analyzer.js`
**Lines:** 1364-1374 (hunter persona renderer)

**Copilot Prompt:**

```
@workspace In frontend/static/js/csv_analyzer.js, the hunter persona renderer (around line 1364)
currently displays basic LLM summaries.

Update it to render the enhanced schema with collapsible sections:

1. Show "What's Suspicious" bullets (from triage.whats_suspicious)
2. Show DREAD breakdown (expandable section showing damage scenarios)
3. Show "Fast Decision Tree" with copy-paste command buttons
4. Show "Missing Telemetry" recommendations in a highlighted box
5. Show TL;DR recommendation prominently

HTML structure should be:
<div class="deep-row-card">
  <h4>{process_name} - {verdict} (DREAD {score})</h4>

  <div class="suspicious-section">
    <strong>🔴 What's Suspicious:</strong>
    <ul>
      <!-- Loop through whats_suspicious array -->
    </ul>
  </div>

  <button onclick="toggleDread()">Show DREAD Breakdown</button>
  <div id="dread-{idx}" style="display:none">
    <!-- DREAD damage scenarios -->
  </div>

  <div class="missing-telemetry-box" style="border:1px solid orange; padding:8px; background:rgba(255,165,0,0.1)">
    <strong>⚠️ Missing Telemetry to Collect:</strong>
    <ul>
      <!-- Loop through missing_telemetry.recommended_collection.immediate -->
    </ul>
  </div>

  <button onclick="copyCommands()">📋 Copy Triage Commands</button>
</div>

Use escapeHtml() for all user-provided text to prevent XSS.
Add copy-to-clipboard functionality for commands.
```

---

## 🔧 Prompt 8: Update Prompt Template in New File

**File:** Create `src/analysis/llm_prompts.py`

**Copilot Prompt:**

```
@workspace Create a new file src/analysis/llm_prompts.py to centralize LLM prompt templates.

This file should contain:

1. ENHANCED_TRIAGE_PROMPT template (string with placeholders)
2. build_enhanced_prompt(row, context) function that injects row data into template
3. Validation helpers to check prompt doesn't exceed token limits

The prompt template should match the structure described in ENHANCED_LLM_TRIAGE_SCHEMA.md.

Include:
- Clear instructions for the LLM
- Anti-hallucination rules
- JSON schema definition
- Examples of good vs bad outputs

Export:
- ENHANCED_TRIAGE_PROMPT (constant)
- build_enhanced_prompt() (function)

Then update auto_llm.py to import and use this prompt instead of inline strings.
```

---

## 📋 Summary Checklist for Copilot

Use these prompts in order:

1. ✅ Prompt 1: Update `auto_llm.py` - Expand `build_llm_row()` structure
2. ✅ Prompt 2: Add `identify_telemetry_gaps()` helper
3. ✅ Prompt 3: Add `build_dread_scenarios()` helper
4. ✅ Prompt 4: Add `build_decision_tree()` helper
5. ✅ Prompt 5: Update `LLMAssessmentClient.summarize_row()` prompt
6. ✅ Prompt 6: Update `deep_analyze_endpoints.py` to pass canonical_signals
7. ✅ Prompt 7: Update frontend `csv_analyzer.js` hunter renderer
8. ✅ Prompt 8: Create `src/analysis/llm_prompts.py` for centralized prompts

---

## 🧪 Testing After Implementation

After Copilot makes changes, test with:

```python
# Quick test in Python console
from src.analysis.auto_llm import build_llm_row

test_row = {
    'process_name': 'powershell.exe',
    'file_path': 'C:\\Users\\user\\AppData\\Local\\Temp\\ps.exe',
    'hash_sha256': 'badbadbad...',
    'command_line': 'powershell.exe -NoProfile -ExecutionPolicy Bypass -e JABjAGw...',
    'parent_process': 'excel.exe',
    'user': 'user1',
    'host': 'INFECTED-01',
    'factors': ['encoded_powershell', 'suspicious_parent']
}

result = build_llm_row(test_row, {'auto_llm': True, 'org': 'test'})
print(json.dumps(result, indent=2))
```

Expected output should match structure in `SAMPLE_ENHANCED_OUTPUTS.md`.

---

## 🚨 Common Copilot Issues & Fixes

**Issue:** Copilot generates incomplete code
**Fix:** Re-prompt with: "Complete the function, showing all fields from ENHANCED_LLM_TRIAGE_SCHEMA.md"

**Issue:** Copilot hallucinates new dependencies
**Fix:** "Only use existing imports (typing, hashlib, time). Do not add new dependencies."

**Issue:** Copilot changes existing working code
**Fix:** "Preserve all existing fields in build_llm_row(). ONLY ADD new fields, don't remove old ones."

**Issue:** Copilot doesn't follow anti-hallucination rules
**Fix:** "Add validation that checks: if file_path not in row, return 'Unknown' - do not invent paths."

---

**End of Copilot Prompts Guide**
