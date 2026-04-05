# LLM Triage Implementation - My Response & Recommendations

**Date:** 2025-01-21
**For:** CEO Requirements - Enhanced Alert Triage

---

## 📋 What I Understood

### The Problem
Your analysts see alerts like:
```
SnippingTool.exe - Suspicious (DREAD 7)
LLM Summary: "Response for prompt (len 274)."
```

**This tells them NOTHING actionable.**

### What You Want (Based on ChatGPT Example)
An analyst needs to see:

```
╔═══════════════════════════════════════════════════════════════════╗
║ SnippingTool.exe - SUSPICIOUS (DREAD 7)                          ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║ 🔴 WHAT'S SUSPICIOUS HERE                                        ║
║ • System32 binary reported "unsigned" → legit version IS signed  ║
║ • Novel hash (new/rare in your estate) → untrusted until proven  ║
║ • DREAD 7 → medium-high; worth verification before allowlisting  ║
║                                                                   ║
║ 💥 HOW THIS CAN DAMAGE YOU                                       ║
║ If this is malicious, attacker can:                              ║
║ • Execute code at SYSTEM level (8/10 damage)                     ║
║ • Bypass UAC via trusted path hijacking                          ║
║ • Persist via Windows UI hooks (PrintScreen launches backdoor)   ║
║ • Exfiltrate screenshots with credentials/PII                    ║
║                                                                   ║
║ Exploitability: MEDIUM (6/10)                                    ║
║ • Requires admin privileges to replace System32 file             ║
║ • Could leverage DLL search-order hijacking                      ║
║ • May exploit vulnerable driver for file overwrite               ║
║                                                                   ║
║ 🎯 FAST DECISION TREE (10-15 min)                                ║
║                                                                   ║
║ Step 1: Verify Signature                                         ║
║ ┌─────────────────────────────────────────────────────────────┐  ║
║ │ Get-AuthenticodeSignature C:\Windows\System32\...          │  ║
║ │ Get-FileHash C:\Windows\System32\SnippingTool.exe -Algo... │  ║
║ └─────────────────────────────────────────────────────────────┘  ║
║ [Copy Commands] button                                           ║
║                                                                   ║
║ ✅ If VALID signature → Proceed to Step 2                        ║
║ ❌ If INVALID/missing → Skip to Remediation                      ║
║                                                                   ║
║ Step 2: Check for Tampering                                      ║
║ ┌─────────────────────────────────────────────────────────────┐  ║
║ │ sfc /scannow                                                │  ║
║ │ dir C:\Windows\System32\SnippingTool.exe /r  (check ADS)   │  ║
║ └─────────────────────────────────────────────────────────────┘  ║
║                                                                   ║
║ 🛠️ IF SUSPICIOUS → REMEDIATE                                     ║
║ 1. Isolate host in EDR                                           ║
║ 2. Collect: FileHash, 4688 logs, 5156 firewall events           ║
║ 3. Replace binary: sfc /scannow + DISM restore                  ║
║ 4. Block hash: AppLocker/SRP deny rule                           ║
║ 5. Hunt for DLL hijack in %ProgramData%, scheduled tasks        ║
║                                                                   ║
║ 📌 TL;DR RECOMMENDATION                                          ║
║ DO NOT ALLOWLIST YET. Run signature check first.                ║
║ If unsigned → isolate, repair, hunt.                             ║
║ If signed and clean → safe to allowlist (document why).          ║
║                                                                   ║
║ [Show Full Remediation] [Similar Alerts] [MITRE Context]         ║
╚═══════════════════════════════════════════════════════════════════╝
```

---

## ✅ My Understanding - Key Requirements

### 1. **WHY Flagged** (Context-Driven)
- Not just "unsigned" - explain **what that means** (System32 should be signed)
- Not just "novel hash" - explain **why that matters** (untrusted until proven)
- Tie to **DREAD score** - "Score 7 means medium-high, investigate before allowlist"

### 2. **HOW Compromise Occurs** (DREAD Breakdown)
- **Damage (D):** What can attacker do? (SYSTEM execution, UAC bypass, exfil)
- **Reproducibility (R):** How easy to trigger? (Requires admin, but DLL hijack possible)
- **Exploitability (E):** Attack vectors (binary replacement, DLL side-load, driver exploit)
- **Affected Users (A):** Scope (all users on host, single host impact)
- **Discoverability (D):** Detection challenges (still in System32, filename matches legit)

### 3. **WHAT to Do** (Fast Decision Tree)
- **Step-by-step commands** (PowerShell, not vague "check signature")
- **Decision gates** ("If valid → Step 2, else → Remediate")
- **Copy-paste ready** (One-click copy commands)
- **Time estimates** ("10-15 min" for triage)

### 4. **WHERE to Learn More** (No Hallucinations)
- **Context sources:** "VirusTotal last checked 2025-01-21 14:32 UTC"
- **Baseline comparison:** "Gold image: Win11-22H2-baseline.wim"
- **Prevalence:** "0/1543 hosts have this hash"
- **Confidence score:** "85% confident (high due to unsigned+novel, medium due to no network IOCs)"

---

## 🎯 My Proposed Solution

I've created **two detailed documents**:

### 1. `ENHANCED_LLM_TRIAGE_SCHEMA.md`
**Full JSON schema** for the new LLM output structure.

Key sections:
- `triage.whats_suspicious` - Array of signals with context
- `triage.dread_breakdown` - Damage/Repro/Exploit/Affected/Discoverability scenarios
- `triage.how_compromise_occurs` - Attack chain + MITRE mapping
- `fast_decision_tree` - Step-by-step with PowerShell commands
- `remediation_steps` - Prioritized actions (IMMEDIATE, HIGH, MEDIUM)
- `tldr_recommendation` - One-line verdict

**Example output size:** ~3-5KB per row (vs current 50 bytes)

---

### 2. `CLAUDE_CODE_SESSION_CONTEXT.md`
**Context document** for future Claude Code sessions.

Includes:
- Current architecture overview
- Implementation status (what's done, in progress, not started)
- LLM provider strategy (hybrid routing)
- Prompt engineering guidelines
- Development workflow
- Known issues & workarounds

**Purpose:** So when you ask Claude Code to implement this, it has full context.

---

## 🤖 LLM Provider Recommendations

### My Recommendation: **Hybrid Model Routing**

```python
def route_llm(row):
    dread = row['dread']['score']

    if dread >= 8:
        return 'gpt-4o'  # High-stakes: Best quality ($0.005)
    elif dread >= 5:
        return 'claude-3.5-sonnet'  # Medium: Great balance ($0.003)
    else:
        return 'ollama-llama-3.1-70b'  # Low-risk: Free (3-8s latency)
```

### Cost Comparison (50,000 alerts/month)

| Strategy | Cost/Month | Pros | Cons |
|----------|------------|------|------|
| **All GPT-4o** | $250 | Best quality, fast | Expensive |
| **All Claude** | $150 | Good quality, cheaper | Slower than GPT-4o |
| **All Ollama** | $0 | Free, private | Needs GPU, more hallucinations |
| **🏆 Hybrid** | **$110** | Best ROI, smart | Complexity |

**My Pick:** Hybrid saves $140/mo (56%) vs all-GPT-4o, with minimal quality tradeoff.

---

## ⚡ Latency Management Strategies

### Problem
LLM calls add 1-3s per row. For 135 rows → 3-8 minutes wait.

### Solution 1: **Async Background Processing** ✅ BEST
```
User clicks "Deep Analyze"
  ↓
Backend returns immediately: {"assessment_id": "abc123", "status": "processing"}
  ↓
UI polls every 2s: "3/135 rows analyzed (2%)"
  ↓
Results populate incrementally (streaming)
  ↓
Full analysis done in 2-5 min
```

**User Experience:**
- ✅ Instant feedback (not waiting 8 min staring at blank screen)
- ✅ See results as they arrive (first 10 rows in 20s)
- ✅ Can cancel if taking too long

---

### Solution 2: **Tiered Analysis** ⚡ FAST RESULTS FIRST
```
T+0ms:   Show heuristic results (DREAD, factors)
T+500ms: Add ThreatIntel (VT lookups)
T+2s:    First LLM summary appears
T+5min:  All LLM summaries complete
```

**Benefit:** Analyst can start triaging IMMEDIATELY, not wait for LLM.

---

### Solution 3: **Smart Caching** 💾 70% FASTER
```python
# Cache by artifact fingerprint
key = hash(sha256 + process + signed + factors)
cached = redis.get(f"llm:{key}")

if cached:
    return cached  # <50ms
else:
    result = await call_llm(row)  # 2s
    redis.setex(f"llm:{key}", 86400, result)
    return result
```

**Cache Hit Rate:**
- Same malware across hosts: 70-80%
- Benign apps (Chrome): 90%+
- **Effective latency: 500ms avg** (vs 2s uncached)

---

## 🎓 Where to Point Users for Deep Dives

### In the UI, every alert should have:

```
┌─────────────────────────────────────────────────────────────┐
│ SnippingTool.exe - Suspicious (DREAD 7)                    │
│                                                             │
│ [📋 Copy Triage Commands]  [🎯 MITRE Context]              │
│ [🛠️ Full Remediation]      [🔍 Similar Alerts]             │
│ [📚 Internal Runbook]       [💬 Escalate to Tier 2]        │
└─────────────────────────────────────────────────────────────┘
```

### Button Actions:

**📋 Copy Triage Commands**
→ Copies PowerShell to clipboard:
```powershell
Get-AuthenticodeSignature C:\Windows\System32\SnippingTool.exe
Get-FileHash C:\Windows\System32\SnippingTool.exe -Algorithm SHA256
```

**🎯 MITRE Context**
→ Opens: `https://attack.mitre.org/techniques/T1574/002/`
→ Shows: DLL Side-Loading technique details

**🛠️ Full Remediation**
→ Expands drawer with:
- Step 1: Isolate (EDR command)
- Step 2: Collect (artifacts list)
- Step 3: Replace (sfc /scannow)
- Step 4: Block (AppLocker rule)
- Step 5: Hunt (registry queries)

**🔍 Similar Alerts**
→ Opens modal: "3 other hosts have similar unsigned System32 files"
→ Shows: Table of related alerts

**📚 Internal Runbook**
→ Links to: `https://confluence.yourcompany.com/SOC/RB-042-System32-Tampering`

**💬 Escalate to Tier 2**
→ Opens Slack: `#soc-tier2-escalations`
→ Pre-fills message: "Need help with SnippingTool.exe alert on WORKSTATION-01. Assessment ID: abc123"

---

## 🚦 Preventing Hallucinations

### Problem
LLMs can invent:
- Fake file paths
- Non-existent registry keys
- Wrong PowerShell syntax
- Made-up MITRE techniques

### My Solutions

#### 1. **Strict Prompt Engineering**
```python
SYSTEM_PROMPT = """
You are a security analyst. Follow these rules STRICTLY:

✅ DO:
- Only cite signals present in INPUT CONTEXT
- Base DREAD scenarios on ACTUAL artifact attributes
- Use standard Windows/PowerShell commands only
- If you don't know, say "Insufficient data"

❌ DO NOT:
- Invent file paths not in context
- Guess registry keys
- Make up commands
- Cite MITRE techniques without evidence

INPUT CONTEXT:
{canonical_signals}

OUTPUT (JSON):
{schema}
"""
```

#### 2. **Confidence Scoring**
```python
def validate_llm_output(llm_response, canonical_signals):
    confidence = 1.0

    # Penalize hallucinated signals
    for signal in llm_response['whats_suspicious']:
        if signal['signal'] not in canonical_signals:
            confidence -= 0.2  # Cited non-existent signal

    # Penalize generic responses
    if 'mock summary' in llm_response['tldr'].lower():
        confidence -= 0.3

    # Boost if cites actual data
    if canonical_signals['file_path'] in str(llm_response):
        confidence += 0.1

    return max(0.0, min(1.0, confidence))
```

**If confidence < 0.6:** Show warning: "⚠️ Low confidence response - manual review recommended"

#### 3. **Post-Processing Validation**
```python
# Check PowerShell commands are valid
for cmd in llm_output['fast_decision_tree']['commands']:
    if not is_valid_powershell(cmd):
        cmd['_warning'] = 'Syntax may be incorrect - verify before running'

# Check MITRE IDs exist
for mitre in llm_output['how_compromise_occurs']['mitre_mapping']:
    if not mitre_id_exists(mitre['id']):
        mitre['_warning'] = 'MITRE ID not found in ATT&CK framework'
```

---

## 📦 Implementation Plan

### Phase 1: POC (Week 1-2)
**Goal:** Prove the schema works with GPT-4o

**Tasks:**
- [ ] Write full prompt template (I can draft this)
- [ ] Update `src/analysis/auto_llm.py` to generate new schema
- [ ] Test with 10 real alerts (manual review)
- [ ] Validate: Zero hallucinations

**Deliverable:** 10 alerts with perfect triage output

---

### Phase 2: Backend (Week 3-4)
**Goal:** Production-ready backend

**Tasks:**
- [ ] Add async background processing (`deep_analyze_endpoints.py`)
- [ ] Implement hybrid model routing (GPT-4o / Claude / Ollama)
- [ ] Add Redis caching layer
- [ ] Add hallucination validation (confidence scoring)

**Deliverable:** `/api/v1/assessments/deep_analyze` returns new schema

---

### Phase 3: Frontend (Week 5-6)
**Goal:** Beautiful UI for new schema

**Tasks:**
- [ ] Update `csv_analyzer.js` to render new fields
- [ ] Add expandable "Show Triage Guide" sections
- [ ] Add "Copy Commands" buttons
- [ ] Add "Similar Alerts" / "MITRE Context" links

**Deliverable:** Full UI matching mockup above

---

### Phase 4: Ollama Testing (Week 7)
**Goal:** Validate open-source fallback

**Tasks:**
- [ ] Install Ollama + Llama 3.1 70B
- [ ] Create Llama-specific prompt (different format)
- [ ] A/B test 100 alerts: Ollama vs GPT-4o
- [ ] Decision: Use Ollama for low-risk only? Or expand?

**Deliverable:** Ollama quality report

---

### Phase 5: Hardening (Week 8)
**Goal:** Production-ready, monitored

**Tasks:**
- [ ] Add circuit breakers (max $500/day spend)
- [ ] Cost tracking dashboard (per tenant)
- [ ] Analyst feedback buttons ("Was this helpful?")
- [ ] Weekly quality spot checks (100 random alerts)

**Deliverable:** Full monitoring + feedback loop

---

## 💰 Cost Estimates

### Scenario: 50,000 alerts/month

**Hybrid Strategy:**
- 10K high-risk (DREAD ≥ 8) → GPT-4o: $50/mo
- 20K medium (DREAD 5-7) → Claude: $60/mo
- 20K low-risk (DREAD < 5) → Ollama: $0/mo

**Total: $110/month**

**Per-alert cost: $0.0022**

**vs. Alternatives:**
- All GPT-4o: $250/mo (2.3x more)
- All Claude: $150/mo (1.4x more)
- All Ollama: $0/mo but needs $5K GPU

---

## ⏱️ Latency Estimates

### Current State (No LLM)
- Upload CSV → Results: **500ms**

### With Enhanced LLM (Sequential)
- Upload CSV → Results: **3-8 minutes** (unusable)

### With Async Processing ✅
- Upload CSV → Heuristic results: **500ms** (instant)
- First LLM result: **2-5s**
- All LLM results: **2-5 min** (background, streaming)

### With Caching (70% hit rate) ✅
- Cached alerts: **50ms** (instant)
- Cache miss: **2s** (acceptable)
- **Effective avg: 500ms** (feels instant)

---

## 🎯 Success Metrics

### Quality
- **Hallucination Rate:** <5% (measure: weekly spot check of 100)
- **Analyst Feedback:** "Was this helpful?" → 85% Yes
- **Command Accuracy:** 100% valid PowerShell (automated check)

### Performance
- **LLM Latency P50:** <2s
- **LLM Latency P99:** <5s
- **Cache Hit Rate:** >70%

### Business
- **Time to Triage:** 20 min → **5 min** (75% reduction)
- **False Positives:** Reduce by **40%**
- **Allowlist Accuracy:** **95%** (alerts allowlisted = actually benign)

---

## 🏆 My Recommendation

### Start with This:

**Phase 1 (Weeks 1-2):**
1. I draft the full prompt template for GPT-4o
2. You update `auto_llm.py` to use new schema
3. We test on 10 real alerts
4. If CEO approves → proceed to Phase 2

**Phase 2 (Weeks 3-4):**
5. Implement async processing
6. Add GPT-4o + Claude hybrid routing
7. Deploy to staging

**Phase 3 (Weeks 5-6):**
8. Update frontend UI
9. Beta test with 3 analysts
10. Iterate based on feedback

**Go-live: End of Week 6**
- With GPT-4o + Claude only (no Ollama yet)
- Cost: ~$150/mo
- Latency: <2s per alert

**Then Phase 4 (Week 7): Add Ollama**
- Test quality vs GPT-4o
- If good enough → route low-risk to Ollama
- Cost drops to $110/mo

---

## 🚀 Next Steps - What Do You Need?

**Option A: I Write the Prompt** (Fastest)
- I draft the full GPT-4o prompt template
- You review, we iterate
- Ready to code in 1-2 days

**Option B: We Build POC Together** (Safest)
- Give me 3-5 real CSV rows
- I generate sample outputs with my prompt
- You validate: "Yes, this is what I want"
- Then we proceed to code

**Option C: You Want Different Approach**
- Tell me what concerns you have
- I'll adjust the plan

---

## 📄 Files Created for You

1. **`ENHANCED_LLM_TRIAGE_SCHEMA.md`**
   - Full JSON schema with all fields
   - Implementation strategy (POC → Production)
   - LLM provider comparison
   - Latency management techniques
   - Cost projections

2. **`CLAUDE_CODE_SESSION_CONTEXT.md`**
   - Context for future Claude Code sessions
   - Current architecture + implementation status
   - Prompt engineering guidelines
   - Known issues & workarounds
   - Success metrics

3. **`LLM_TRIAGE_IMPLEMENTATION_RESPONSE.md`** (this file)
   - My understanding of your requirements
   - Proposed solution summary
   - Recommendations
   - Next steps

---

## ❓ Questions for You

1. **Budget:** Is $110-150/mo acceptable for 50K alerts? Or need lower?
2. **Timeline:** 6-8 weeks realistic? Or need faster MVP?
3. **Quality bar:** 85% analyst approval sufficient? Or need 95%?
4. **Ollama:** Do you have GPU available? (A100 80GB or 2x 4090)
5. **API keys:** Do you already have OpenAI/Anthropic accounts set up?

---

## 🎉 Bottom Line

**I understand exactly what you want:**
- Analysts see **WHY** (context)
- Analysts see **HOW** (DREAD damage scenarios)
- Analysts see **WHAT** (copy-paste commands)
- No hallucinations (cite real data only)

**I have a plan:**
- Enhanced schema (designed ✅)
- Hybrid LLM routing (GPT-4o + Claude + Ollama)
- Async processing (no UI blocking)
- Cost target: $110/mo for 50K alerts
- Timeline: 6-8 weeks to production

**Ready when you are.**

Let me know:
1. Should I draft the prompt template? (1-2 days)
2. Or do you want to see sample outputs first? (give me 3-5 CSV rows)
3. Or do you have questions/concerns about the approach?
