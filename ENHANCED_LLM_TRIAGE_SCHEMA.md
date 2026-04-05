# Enhanced LLM Triage Schema - CEO Requirements

## What the CEO Wants

**Problem Statement:**
When an analyst sees an alert, they need to understand:
1. **WHY** it was flagged (what's suspicious)
2. **HOW** it can compromise the environment (DREAD-based risk)
3. **WHAT** to do about it (fast decision tree)
4. **WHERE** to get more context (no hallucinations, real data)

**Current State:**
- `llm_summary`: "Response for prompt (len 274)." ❌ Too vague
- Risk level: Just "High/Medium/Low" ❌ No explanation
- Recommendation: Just "Quarantine" ❌ No steps

**Target State (ChatGPT Example):**
- ✅ Clear "What's suspicious here" section
- ✅ Fast decision tree with PowerShell commands
- ✅ Allowlist vs Investigate criteria
- ✅ Remediation steps
- ✅ Extra validation checks
- ✅ TL;DR recommendation

---

## Proposed Enhanced Schema

### Schema Structure (JSON)

```json
{
  "row_index": 42,
  "artifact": {
    "process_name": "SnippingTool.exe",
    "file_path": "C:\\Windows\\System32\\SnippingTool.exe",
    "hash_sha256": "abc123...",
    "host": "WORKSTATION-01",
    "user": "john.doe",
    "signed": false,
    "publisher": "unsigned"
  },

  "triage": {
    "verdict": "Suspicious",
    "confidence": 0.85,
    "priority": "High",

    "whats_suspicious": [
      {
        "signal": "unsigned_system_binary",
        "severity": "high",
        "context": "System32 binary reported unsigned → legit SnippingTool.exe is Microsoft-signed",
        "why_matters": "Unsigned system binaries indicate potential trojanization or DLL hijacking"
      },
      {
        "signal": "novel_global",
        "severity": "medium",
        "context": "New/rare hash in your estate (0 other hosts)",
        "why_matters": "Treats as untrusted until proven clean - could be recent malware deployment"
      },
      {
        "signal": "dread_score_7",
        "severity": "medium",
        "context": "DREAD 7 → medium-high risk; worth verification before allowlisting",
        "why_matters": "Falls into 'investigate first' tier per risk appetite policy"
      }
    ],

    "dread_breakdown": {
      "overall_score": 7.0,
      "damage": {
        "score": 8,
        "explanation": "System32 replacement grants SYSTEM-level execution. Attacker can:",
        "scenarios": [
          "Execute arbitrary code at NT AUTHORITY\\SYSTEM level",
          "Bypass UAC via trusted path hijacking",
          "Persist via Windows UI hooks (snipping tool launched from PrintScreen)",
          "Exfiltrate screenshots containing sensitive data (credentials, PII)"
        ]
      },
      "reproducibility": {
        "score": 7,
        "explanation": "Medium-high - requires admin/TrustedInstaller to replace System32 binary",
        "attack_prerequisites": [
          "Attacker needs Administrator or SYSTEM privileges initially",
          "May require disabling Windows File Protection (WFP/WRP)",
          "Could leverage vulnerable driver (CVE) for file overwrite"
        ]
      },
      "exploitability": {
        "score": 6,
        "explanation": "Medium - LOLbin abuse via trusted Windows utility",
        "attack_vectors": [
          "DLL search-order hijacking (place malicious DLL in %ProgramData%)",
          "Binary replacement during unpatched window (compromised update)",
          "Hard link manipulation to bypass integrity checks"
        ]
      },
      "affected_users": {
        "score": 8,
        "explanation": "All users on host - Snipping Tool accessible to standard users",
        "impact_scope": "Single host but high blast radius if pivoted laterally"
      },
      "discoverability": {
        "score": 6,
        "explanation": "Medium - requires signature validation or integrity check to detect",
        "detection_challenges": [
          "File still in trusted System32 path",
          "Filename matches legitimate binary",
          "May have valid-looking metadata (version info spoofed)"
        ]
      }
    },

    "how_compromise_occurs": {
      "attack_chain": [
        "Initial access: Phishing with admin-prompt malware OR vulnerable driver exploit",
        "Privilege escalation: Gain SYSTEM via token manipulation or service abuse",
        "Defense evasion: Disable WRP via registry (KnownDLLs manipulation)",
        "Persistence: Replace SnippingTool.exe with backdoor maintaining original filename",
        "Execution: User presses PrintScreen → malicious binary runs as user (but with SYSTEM capabilities if needed)",
        "Impact: Keylogging, screenshot exfil, lateral movement via captured credentials"
      ],
      "mitre_mapping": [
        {"id": "T1574.002", "name": "DLL Side-Loading", "confidence": 0.7},
        {"id": "T1036.005", "name": "Match Legitimate Name/Location", "confidence": 0.9},
        {"id": "T1055", "name": "Process Injection", "confidence": 0.5},
        {"id": "T1543.003", "name": "Windows Service", "confidence": 0.3}
      ]
    }
  },

  "fast_decision_tree": {
    "estimated_time": "10-15 minutes",
    "steps": [
      {
        "step": 1,
        "title": "Signature + Hash Sanity",
        "commands": [
          {
            "shell": "powershell",
            "command": "Get-AuthenticodeSignature 'C:\\Windows\\System32\\SnippingTool.exe' | fl *",
            "expected_output": "Status = Valid, SignerCertificate.Subject = CN=Microsoft Windows",
            "interpretation": {
              "if_valid": "Proceed to step 3 (lineage/behavior) before allowlisting",
              "if_invalid": "Skip to Remediate - likely trojanized"
            }
          },
          {
            "shell": "powershell",
            "command": "Get-FileHash 'C:\\Windows\\System32\\SnippingTool.exe' -Algorithm SHA256",
            "expected_output": "Hash matches known-good Microsoft baseline",
            "interpretation": {
              "if_match": "Cross-check with VirusTotal for recent detections",
              "if_mismatch": "High confidence malicious - isolate immediately"
            }
          }
        ],
        "decision_gate": "If NOT signed OR invalid → skip to Remediate"
      },
      {
        "step": 2,
        "title": "Tamper Checks (Quick Integrity)",
        "commands": [
          {
            "shell": "cmd",
            "command": "sfc /scannow",
            "purpose": "Repairs replaced system files",
            "expected_duration": "5-10 min"
          },
          {
            "shell": "cmd",
            "command": "dir C:\\Windows\\System32\\SnippingTool.exe /r",
            "purpose": "Check for alternate data streams (ADS)",
            "red_flags": ["Any ADS with size > 0", "Zone.Identifier with ZoneId=0 (local bypass)"]
          },
          {
            "shell": "cmd",
            "command": "icacls C:\\Windows\\System32\\SnippingTool.exe",
            "purpose": "Check file permissions",
            "red_flags": ["Non-standard ACLs", "Everyone:(F)", "Writable by standard users"]
          }
        ]
      },
      {
        "step": 3,
        "title": "Parent Lineage & Runtime Behavior",
        "commands": [
          {
            "shell": "powershell",
            "command": "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-1)} | Where-Object {$_.Message -like '*SnippingTool.exe*'} | Select-Object -First 5 | % {$_.Message}",
            "purpose": "Pull process creation lineage (requires audit policy)",
            "expected_parents": ["explorer.exe", "ShellExperienceHost.exe", "Settings UI"],
            "red_flags": ["cmd.exe", "powershell.exe", "wscript.exe", "suspicious service"]
          },
          {
            "shell": "powershell",
            "command": "$pid=(Get-Process SnippingTool -ErrorAction SilentlyContinue).Id; if($pid){ netstat -ano | findstr $pid }",
            "purpose": "Check network connections",
            "expected_output": "No connections (Snipping Tool is offline utility)",
            "red_flags": ["Any outbound connections", "Listening ports"]
          }
        ]
      },
      {
        "step": 4,
        "title": "Estate Prevalence",
        "query": "Check if hash exists on other hosts in your SIEM/EDR",
        "interpretation": {
          "single_host": "Supports suspicious replacement theory",
          "widespread_and_signed": "Likely legit Windows update"
        }
      }
    ]
  },

  "allowlist_criteria": {
    "safe_to_allowlist_if_all_true": [
      "File is Microsoft-signed (valid)",
      "Lineage normal (spawned by shell/UI), no network",
      "No tamper (no ADS/odd ACL/hardlink), SFC/DISM clean",
      "Hash shows low/no detections in your intel/VT"
    ],
    "recommendation": "DO NOT ALLOWLIST YET - verify signature + lineage + network first"
  },

  "remediation_steps": {
    "if_suspicious": [
      {
        "priority": "IMMEDIATE",
        "action": "Isolate host in EDR",
        "details": "Prevent lateral movement while preserving forensic state"
      },
      {
        "priority": "IMMEDIATE",
        "action": "Collect artifacts",
        "artifacts": [
          "Get-FileHash output",
          "Get-AuthenticodeSignature output",
          "4688 process creation chain",
          "5156 firewall events (if available)",
          "Sysmon Event ID 1, 3, 7 (process, network, module load)"
        ]
      },
      {
        "priority": "HIGH",
        "action": "Replace the binary",
        "commands": [
          "sfc /scannow",
          "DISM /Online /Cleanup-Image /RestoreHealth"
        ],
        "alternative": "Pull clean copy from WinSxS (same build) - advanced users only"
      },
      {
        "priority": "HIGH",
        "action": "Block execution until verified",
        "methods": [
          "AppLocker/SRP deny for SHA256",
          "EDR hash block (quarantine)",
          "WDAC policy (allow-list mode)"
        ]
      },
      {
        "priority": "MEDIUM",
        "action": "Hunt for adjacent tampering",
        "hunt_queries": [
          "reg query \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SnippingTool.exe\" /s",
          "schtasks /Query /FO LIST /V | findstr /i \"snip\"",
          "Check %ProgramData%, System32 for DLL side-loading candidates",
          "Review IFEO debuggers, AppInit_DLLs, KnownDLLs registry keys"
        ]
      }
    ],
    "user_impact": "Snipping Tool is non-critical—safe to disable temporarily",
    "estimated_remediation_time": "30-45 minutes for full hunt + repair"
  },

  "extra_validation": {
    "nice_to_check": [
      {
        "check": "Compile timestamp",
        "red_flag": "Far from OS build date (e.g., 2015 timestamp on Win11 system)",
        "command": "PowerShell: (Get-Item C:\\Windows\\System32\\SnippingTool.exe).VersionInfo"
      },
      {
        "check": "File size",
        "red_flag": "Drastically different from gold image (e.g., 50KB vs expected 200KB)",
        "baseline": "Check known-good Win10/11 baseline or MSFT security baseline"
      },
      {
        "check": "Unexpected persistence",
        "red_flag": "Autoruns shows SnippingTool.exe at logon",
        "command": "Sysinternals Autoruns or reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      }
    ]
  },

  "tldr_recommendation": {
    "summary": "DO NOT ALLOWLIST YET. First verify signature + lineage + network.",
    "if_signed_and_clean": "Allowlist this hash in tooling (document rationale)",
    "if_unsigned_or_suspicious": "Isolate host, repair system files, block hash, hunt for DLL hijack/persistence"
  },

  "context_sources": {
    "canonical_signals": ["unsigned_system_binary", "novel_global", "rare_parent_lineage"],
    "enrichment_sources": [
      "VirusTotal hash lookup (last checked: 2025-01-21 14:32 UTC)",
      "Internal baseline comparison (gold image: Win11-22H2-baseline.wim)",
      "SIEM prevalence query (0/1543 hosts have this hash)",
      "Threat intel: No known association with malware families"
    ],
    "confidence_score": 0.85,
    "confidence_rationale": "High confidence due to unsigned + novel_global combo; medium due to lack of network IOCs"
  },

  "analyst_next_steps": {
    "immediate": "Run Step 1 commands (signature check) - paste output back for instant verdict",
    "if_need_help": {
      "internal_runbook": "https://confluence.company.com/SOC/Runbooks/System32-Tampering-RB-042",
      "escalation": "Tier 2 SOC (Slack: #soc-tier2-escalations)",
      "vendor_support": "Contact Microsoft Support with CBS.log if SFC fails"
    },
    "learning_resources": [
      "MITRE ATT&CK T1574.002: DLL Side-Loading techniques",
      "LOLBAS Project: Living-off-the-land binaries abuse",
      "SANS FOR508: Advanced Incident Response for Windows"
    ]
  },

  "provenance": {
    "assessment_id": "assessment-1763628207-c3f035a1",
    "model": "gpt-4o",
    "generated_at": 1763628207,
    "prompt_version": "v2.1-dread-triage",
    "latency_ms": 1847,
    "cost_estimate_usd": 0.0023
  }
}
```

---

## Implementation Strategy

### 1. LLM Provider Recommendations

#### Option A: **OpenAI GPT-4o** (Recommended for Production)
**Pros:**
- ✅ Best reasoning quality for complex security context
- ✅ Structured output support (JSON mode)
- ✅ Low latency (500-2000ms for this prompt)
- ✅ Strong security domain knowledge

**Cons:**
- ❌ Cost: ~$0.002-0.005 per alert (acceptable for high-value triage)
- ❌ External API dependency (mitigate with circuit breakers)

**Use when:**
- High-stakes alerts (DREAD ≥ 7)
- Executive/customer-facing reports
- Budget allows ($50-200/mo for 10k-50k alerts)

---

#### Option B: **Anthropic Claude 3.5 Sonnet** (Best Balance)
**Pros:**
- ✅ Excellent reasoning and nuanced explanations
- ✅ Better at avoiding hallucinations vs GPT-4
- ✅ Larger context window (200K) - great for correlation
- ✅ Cost-effective ($0.003 per 1K input tokens)

**Cons:**
- ❌ Slightly slower than GPT-4o (1-3s)
- ❌ Less structured output than GPT-4 JSON mode

**Use when:**
- Need high-quality explanations without OpenAI pricing
- Complex multi-artifact correlation (HopGraph + LLM)
- Compliance/audit scenarios (Claude better at citing sources)

---

#### Option C: **Ollama + Llama 3.1 70B** (Cost-Optimized)
**Pros:**
- ✅ Zero API costs (self-hosted)
- ✅ Data privacy (on-prem)
- ✅ No rate limits

**Cons:**
- ❌ Requires GPU (A100 80GB or 2x 4090 for 70B)
- ❌ Slower (3-8s per response)
- ❌ Lower quality reasoning vs GPT-4/Claude
- ❌ More hallucinations (needs strict prompt engineering)

**Use when:**
- Budget constraints
- Air-gapped environments
- High alert volume (>100k/day) where API cost prohibitive

**Setup:**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull Llama 3.1 70B (best open-source reasoning)
ollama pull llama3.1:70b-instruct-q4_K_M

# Test
ollama run llama3.1:70b-instruct-q4_K_M "Explain DREAD scoring for unsigned system binary"
```

---

#### Option D: **Hybrid Approach** (Smart Routing)
```python
def route_llm_request(row, risk_level, auto_llm_mode):
    """
    Route to best LLM based on risk and cost constraints
    """
    dread = row.get('dread', {}).get('score', 0)

    # High-stakes: Use best model
    if dread >= 8 or risk_level == 'critical':
        return 'gpt-4o'  # $0.005/alert but best quality

    # Medium: Use Claude (best balance)
    elif dread >= 5:
        return 'claude-3.5-sonnet'  # $0.003/alert

    # Low-risk: Use Ollama (free but slower)
    elif dread < 5:
        return 'ollama-llama3.1'  # Free but 3-8s latency

    # Fallback for circuit breaker trips
    else:
        return 'heuristic-fallback'  # No LLM, just templated output
```

**Cost Estimate (Hybrid):**
- 10,000 alerts/day
- 20% high-risk (GPT-4o): 2K × $0.005 = $10/day
- 40% medium (Claude): 4K × $0.003 = $12/day
- 40% low (Ollama): Free
- **Total: $22/day = $660/mo** (vs $1500/mo all GPT-4o)

---

### 2. Latency Management

#### Problem: LLM calls add 1-3s per row

**Solutions:**

##### A. **Async Batch Processing** (Recommended)
```python
async def process_deep_analyze_batch(rows):
    """
    Process rows in parallel, return immediately with assessment_id
    """
    assessment_id = create_assessment(rows)

    # Return immediately to UI
    response = {
        'assessment_id': assessment_id,
        'status': 'processing',
        'estimated_completion': '2-5 minutes'
    }

    # Process LLM calls in background
    asyncio.create_task(
        generate_llm_summaries_background(assessment_id, rows)
    )

    return response

# UI polls /api/v1/assessments/{id}/status every 2s
# Shows progress: "3/135 rows analyzed (2%)"
```

**User Experience:**
1. Click "Deep Analyze" → instant response
2. Modal shows progress bar: "Analyzing 135 rows... 3% complete"
3. Rows populate incrementally (show results as they arrive)
4. Full analysis done in 2-5 min (vs 3-8 min sequential)

---

##### B. **Tiered Analysis** (Show Fast Results First)
```python
def deep_analyze_tiered(rows):
    """
    Show heuristic results immediately, enrich with LLM over time
    """
    # Phase 1: Instant (0-100ms)
    heuristic_results = [
        build_heuristic_summary(row) for row in rows
    ]
    yield {'phase': 'heuristic', 'results': heuristic_results}

    # Phase 2: Fast signals (200-500ms)
    threat_intel = batch_lookup_virustotal(rows)
    yield {'phase': 'threat_intel', 'results': threat_intel}

    # Phase 3: LLM enrichment (1-3s per row, async)
    for row in rows:
        llm_result = await generate_llm_summary(row)
        yield {'phase': 'llm', 'row_index': row['index'], 'result': llm_result}
```

**UI Flow:**
```
T+0ms:   Show table with heuristic scores
T+500ms: Add ThreatIntel column (VT detections)
T+2s:    First LLM summary appears (streaming)
T+5min:  All LLM summaries complete
```

---

##### C. **Smart Caching**
```python
# Cache LLM responses by artifact fingerprint
cache_key = hashlib.sha256(
    f"{sha256}|{process_name}|{signed}|{factors}".encode()
).hexdigest()

cached = redis.get(f"llm_summary:{cache_key}")
if cached:
    return json.loads(cached)  # <50ms cache hit
else:
    result = await call_llm(row)
    redis.setex(f"llm_summary:{cache_key}", 86400, json.dumps(result))
    return result
```

**Cache Hit Rate Estimate:**
- Same malware seen across hosts: 60-80% hit rate
- Benign software (Chrome, Office): 90%+ hit rate
- **Effective latency: 500ms avg** (vs 2s uncached)

---

### 3. Where to Point Users for Deep Dives

#### In-App "Learn More" Links

```json
"analyst_next_steps": {
  "if_need_help": {
    "internal_runbook": "https://confluence.company.com/SOC/RB-042",
    "escalation": "Slack: #soc-tier2-escalations",
    "mitre_context": "https://attack.mitre.org/techniques/T1574/002/",
    "vendor_kb": "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/wdac-and-applocker-overview"
  }
}
```

#### Contextual UI Buttons
```html
<div class="llm-summary-card">
  <h4>SnippingTool.exe - Suspicious (DREAD 7)</h4>
  <p>Unsigned system binary detected...</p>

  <div class="action-buttons">
    <button onclick="showDetailedTriage()">📋 Full Triage Guide</button>
    <button onclick="showMitreContext()">🎯 MITRE Context</button>
    <button onclick="showRemediationSteps()">🛠️ Remediation</button>
    <button onclick="showSimilarAlerts()">🔍 Similar Alerts</button>
  </div>
</div>
```

#### Progressive Disclosure
```
[Initial View]
  → SnippingTool.exe - Suspicious
  → DREAD 7: Unsigned system binary
  → [Show Why] button

[Click "Show Why"]
  → Expands to show:
    - What's Suspicious (3 bullets)
    - DREAD Breakdown (damage scenarios)
    - [Run Triage Commands] button

[Click "Run Triage Commands"]
  → Opens drawer with copy-paste PowerShell commands
  → "Paste results here for instant analysis" textbox
  → Auto-analyzes output, updates verdict
```

---

### 4. Preventing Hallucinations

#### Strict Prompt Engineering
```python
SYSTEM_PROMPT = """
You are a security analyst assistant. Follow these rules STRICTLY:

1. ONLY cite signals present in the input context
2. If a signal is missing, say "Not available in telemetry"
3. DO NOT invent file paths, registry keys, or commands
4. When suggesting commands, ONLY use standard Windows/PowerShell tools
5. If you don't know, say "Insufficient data - recommend manual review"
6. For DREAD scenarios, base on ACTUAL artifact attributes (signed, path, parent)

Input Context:
{context}

Output MUST be valid JSON matching this schema:
{schema}
"""
```

#### Confidence Scoring
```python
def calculate_confidence(llm_output, canonical_signals):
    """
    Validate LLM output against ground truth
    """
    confidence = 1.0

    # Penalize if LLM cites signals not in canonical
    for signal in llm_output.get('whats_suspicious', []):
        if signal['signal'] not in canonical_signals:
            confidence -= 0.2  # Hallucinated signal

    # Penalize if LLM gives generic response
    if 'mock summary' in llm_output.get('tldr', '').lower():
        confidence -= 0.3

    # Boost if LLM cites specific context values
    if canonical_signals.get('file_path') in str(llm_output):
        confidence += 0.1

    return max(0.0, min(1.0, confidence))
```

---

## Recommended Implementation Phases

### Phase 1: Proof of Concept (Week 1-2)
- [ ] Update `build_llm_row()` in `src/analysis/auto_llm.py` to use new schema
- [ ] Create `src/analysis/triage_prompt_builder.py` with DREAD-focused prompts
- [ ] Test with GPT-4o API (10 sample alerts)
- [ ] Validate: No hallucinations, all commands are real

### Phase 2: Backend Integration (Week 3-4)
- [ ] Update `deep_analyze_endpoints.py` to call new schema builder
- [ ] Add async background processing for LLM calls
- [ ] Implement smart routing (hybrid model selection)
- [ ] Add caching layer (Redis or in-memory)

### Phase 3: Frontend UI (Week 5-6)
- [ ] Update `csv_analyzer.html` to render new schema
- [ ] Add "Show Triage Guide" expandable sections
- [ ] Add "Copy PowerShell Commands" buttons
- [ ] Implement progressive disclosure UI

### Phase 4: Ollama Fallback (Week 7)
- [ ] Set up Ollama with Llama 3.1 70B
- [ ] Create prompt adapter for Llama (different format than GPT-4)
- [ ] A/B test quality vs GPT-4o on 100 alerts
- [ ] Decision: Keep Ollama for low-risk only, or expand?

### Phase 5: Production Hardening (Week 8)
- [ ] Add circuit breakers for API failures
- [ ] Implement cost tracking per tenant
- [ ] Add "LLM used: GPT-4o" badge in UI for transparency
- [ ] Create analyst feedback loop ("Was this helpful? Y/N")

---

## Cost Projections

### Scenario: 50,000 alerts/month

| Model | Alerts Routed | Cost per Alert | Monthly Cost |
|-------|---------------|----------------|--------------|
| GPT-4o | 10K (high-risk) | $0.005 | $50 |
| Claude 3.5 | 20K (medium) | $0.003 | $60 |
| Ollama Llama 3.1 | 20K (low-risk) | $0 | $0 |
| **Total** | **50K** | **avg $0.0022** | **$110/mo** |

**vs. All GPT-4o:** 50K × $0.005 = $250/mo

**Savings: $140/mo (56% reduction)**

---

## Success Metrics

### CEO/Analyst Satisfaction
- [ ] Analyst feedback: "Was this triage helpful?" → Target: 85% Yes
- [ ] Time to triage decision: Reduce from 20 min → 5 min (75% reduction)
- [ ] Allowlist accuracy: Reduce false positives by 40%

### Technical KPIs
- [ ] LLM latency P50: <2s, P99: <5s
- [ ] Cache hit rate: >70%
- [ ] Hallucination rate: <5% (validated by QA spot checks)
- [ ] Cost per alert: <$0.003 avg

---

## Next Steps

1. **Review this doc with CEO** - confirm schema meets expectations
2. **Choose LLM provider** - recommend hybrid (GPT-4o + Claude + Ollama)
3. **Build prompt** - I can write the full prompt template
4. **Test on 10 real alerts** - paste back results for validation
5. **Iterate** - refine prompt based on feedback

**ETA to Production: 6-8 weeks** with dedicated eng + QA resource.
