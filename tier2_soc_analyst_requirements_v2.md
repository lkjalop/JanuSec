# Tier 2 Deep Dive: What SOC Analysts Actually Need
## A Practical Guide to LLM-Assisted Investigation Summaries

**Version:** 2.0  
**Date:** November 2025  
**Author:** Analysis for JanuSec Development  
**Purpose:** Transform Tier 2 from "AI output dump" to "analyst decision accelerator"

---

## First: You're Not Talking Trash

Let me be direct: **The concept is solid. The market need is real.** SOC teams are drowning—average analyst sees 500+ alerts/day, burnout is endemic, and most AI tools produce generic garbage that adds cognitive load rather than reducing it.

Your existing improvement document shows sophisticated thinking about:
- Two-phase generation (plan → elaborate)
- Evidence binding with explicit references
- Confidence calibration
- Verification loops

**The problem isn't the architecture—it's that the current output doesn't match how analysts actually think and work.**

What you've built is an engineering solution. What analysts need is a **decision support tool**. Let me bridge that gap.

---

## Part 1: How SOC Analysts Actually Work (Reality Check)

### The Three Personas You're Serving

| Persona | Time Budget | Primary Question | Secondary Questions |
|---------|-------------|------------------|---------------------|
| **Tier 2 SOC Analyst** | 15-30 min | "Is this real, and how bad is it?" | What's the blast radius? Who do I notify? |
| **Threat Hunter** | 1-4 hours | "Is this part of something bigger?" | What else should I look for? What's the adversary's next move? |
| **Forensic Analyst** | Days | "What exactly happened, and can I prove it?" | Chain of custody, timeline reconstruction, evidence preservation |

### What They Do When They See Your Current Output

Based on the screenshot from Image 2, here's the honest assessment:

```
Current State                          Analyst Reaction
─────────────────────────────────────────────────────────────────
Giant JSON dump                   →    "I'm not reading that"
"unknown on unknown host"         →    "Useless without context"
Empty Attack Graph               →    "Why is this even here?"
Generic SIEM queries             →    "I'll write my own"
Wall of AI text                  →    "Skip to find actual IOCs"
```

### The 30-Second Test

When a Tier 2 analyst opens your deep dive, they need to answer these questions in 30 seconds:

1. **What is this?** (One sentence)
2. **How confident should I be?** (With reasoning)
3. **What's the worst case?** (Business impact)
4. **What do I do RIGHT NOW?** (First 3 actions)
5. **What can I copy-paste?** (IOCs, queries, ticket text)

If they can't get these answers without scrolling, the tool has failed.

---

## Part 2: The Core Problem with Current Output

### Problem 1: Information Architecture is Wrong

Your current layout (based on the screenshot):
```
┌─────────────────────────────────────────────┐
│ Header: "unknown on unknown host"           │  ← Immediate trust loss
├─────────────────────────────────────────────┤
│ Decision Snapshot (small, top-right)        │  ← Right info, wrong prominence
├─────────────────────────────────────────────┤
│ AI-Powered Insights (Tier 2 Investigation)  │
│ ┌─────────────────────────────────────────┐ │
│ │ GIANT JSON/TEXT DUMP                    │ │  ← Wall of text = ignored
│ │ ...                                     │ │
│ │ (60-120 lines)                          │ │
│ └─────────────────────────────────────────┘ │
├─────────────────────────────────────────────┤
│ Semantic Log Search                         │  ← Useful but buried
├─────────────────────────────────────────────┤
│ Attack Graph (empty/broken)                 │  ← Erodes trust
├─────────────────────────────────────────────┤
│ Analyst Notes                               │  ← Good but at bottom
└─────────────────────────────────────────────┘
```

**The fix:** Invert the pyramid. Most important info first, details on demand.

### Problem 2: No Clear "So What?"

Current output tells analysts WHAT the AI found. It doesn't tell them:
- **WHY it matters** (business context)
- **HOW CONFIDENT to be** (with reasoning they can validate)
- **WHAT TO DO** (specific, sequenced actions)
- **WHAT COULD GO WRONG** (if they're wrong about the verdict)

### Problem 3: Generic Output Destroys Trust

When analysts see:
- "Review logs for suspicious activity" → They think: "No shit, Sherlock"
- "Correlate with other data sources" → They think: "Which ones? Be specific"
- "Consider escalating" → They think: "Based on what criteria?"

**Trust is built through specificity.** Every recommendation needs to reference THIS alert, not generic IR playbooks.

---

## Part 3: What Each Persona Actually Needs

### Tier 2 SOC Analyst Needs

**Primary workflow:** Validate Tier 1 escalation → Determine scope → Contain or close

| Need | Why | How to Deliver |
|------|-----|----------------|
| **Quick verdict validation** | Confirm/deny Tier 1 assessment | Show evidence that supports AND contradicts the verdict |
| **Blast radius assessment** | Determine who else is affected | Entity graph with "same user," "same host," "same C2" pivots |
| **Containment decision support** | Decide: isolate now or gather more? | Risk matrix: "If malicious + we wait = X. If benign + we isolate = Y" |
| **Escalation justification** | Explain to manager/IR team | Pre-written executive summary they can copy |
| **Time-to-action** | How urgent is this? | Clear SLA recommendation with reasoning |

### Threat Hunter Needs

**Primary workflow:** Pivot from single alert → Find campaign scope → Identify TTPs

| Need | Why | How to Deliver |
|------|-----|----------------|
| **Pivot points** | What to search for next | Highlighted IOCs with "search for this in X system" |
| **TTP mapping** | Understand adversary behavior | Full MITRE chain, not just one technique |
| **Historical correlation** | Has this happened before? | "Similar patterns seen: [dates, hosts, outcomes]" |
| **Hunt hypotheses** | What else might be true? | Alternative attack scenarios to investigate |
| **Campaign indicators** | Is this targeted or commodity? | Threat intel correlation with confidence |

### Forensic Analyst Needs

**Primary workflow:** Preserve evidence → Reconstruct timeline → Document for legal/compliance

| Need | Why | How to Deliver |
|------|-----|----------------|
| **Evidence inventory** | What do we have? | Itemized list with hash, source, acquisition time |
| **Timeline reconstruction** | What happened when? | Visual timeline with causal links |
| **Chain of custody** | Legal defensibility | Metadata: who accessed, when, hash verification |
| **Gaps identification** | What's missing? | "We don't have X, which means we can't prove Y" |
| **Report generation** | Document findings | Export to standard formats (STIX, PDF, DOCX) |

---

## Part 4: Proposed Wireframe Redesign

### Above-the-Fold (No Scrolling Required)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🔬 INVESTIGATION: INV-2024-1127-0493                              [Export ▾]│
│ ═══════════════════════════════════════════════════════════════════════════ │
│                                                                             │
│ ┌─────────────────────────────────────┐  ┌────────────────────────────────┐ │
│ │ 📊 VERDICT                          │  │ ⏱️ RECOMMENDED ACTION          │ │
│ │                                     │  │                                │ │
│ │   ██████████░░ LIKELY MALICIOUS     │  │  🔴 CONTAIN WITHIN 1 HOUR      │ │
│ │   Confidence: 78%                   │  │                                │ │
│ │                                     │  │  Primary: Isolate endpoint     │ │
│ │   DREAD: 8/10  │  CVSS: 7.2        │  │  Secondary: Preserve memory    │ │
│ │                                     │  │  Notify: IR Lead, Asset Owner  │ │
│ └─────────────────────────────────────┘  └────────────────────────────────┘ │
│                                                                             │
│ ┌───────────────────────────────────────────────────────────────────────────┤
│ │ 📝 ONE-LINER (Copy for Ticket)                                    [Copy] │
│ │ ─────────────────────────────────────────────────────────────────────────│
│ │ Unsigned executable mimicking CrowdStrike agent executing from TEMP      │
│ │ directory on WORKSTATION-A1234. No parent process visible. Hash unknown  │
│ │ to threat intel. Likely first-stage loader requiring immediate isolation.│
│ └───────────────────────────────────────────────────────────────────────────┘
│                                                                             │
│ [Tab: Evidence] [Tab: Reasoning] [Tab: Hunt] [Tab: Timeline] [Tab: Actions] │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tab 1: Evidence (Default View)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 📁 KEY EVIDENCE                                                             │
│ ═══════════════════════════════════════════════════════════════════════════ │
│                                                                             │
│ Primary Artifact                                                            │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ Type: Executable                                                        │ │
│ │ Path: c:\windows\temp\fsagentcrashstatusupdater.exe                    │ │
│ │ SHA256: 6307545ad5664c3ba03c417c34471ce738bb...  [Copy] [VT] [Search]  │ │
│ │ Size: 245,760 bytes │ Signed: NO │ First Seen: 2021-07-06 12:44:15     │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Context                                                                     │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ Host: WORKSTATION-A1234 (Desktop, Finance Dept, Asset Criticality: MED)│ │
│ │ User: jsmith@company.com (Standard User, Last Login: 2h ago)           │ │
│ │ Network: 10.1.50.0/24 (Corporate LAN, Segment: Finance)                │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Supporting Evidence (3 items)                                     [Expand] │
│ ┌──────────────────────────────────────────────────────┬──────┬───────────┐ │
│ │ Evidence                                             │ Type │ Confidence│ │
│ ├──────────────────────────────────────────────────────┼──────┼───────────┤ │
│ │ No parent process in telemetry                       │ Gap  │ N/A       │ │
│ │ Filename mimics CrowdStrike naming convention        │ TTP  │ 85%       │ │
│ │ Execution from %TEMP% (common staging location)      │ TTP  │ 90%       │ │
│ └──────────────────────────────────────────────────────┴──────┴───────────┘ │
│                                                                             │
│ ⚠️ EVIDENCE GAPS                                                            │
│ • No network telemetry available (cannot confirm C2)                       │
│ • Parent process unknown (attack vector unclear)                            │
│ • No file creation events (dropper mechanism unknown)                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tab 2: AI Reasoning (Transparency View)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🧠 HOW I REACHED THIS CONCLUSION                                            │
│ ═══════════════════════════════════════════════════════════════════════════ │
│                                                                             │
│ Primary Hypothesis (78% confidence)                                         │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ "This is a malware dropper or first-stage loader using filename        │ │
│ │ masquerading to appear as legitimate security software."               │ │
│ │                                                                         │ │
│ │ Supporting Evidence:                         Confidence Contribution   │ │
│ │ ├─ Unsigned executable                       +25% (CrowdStrike signs)  │ │
│ │ ├─ TEMP directory execution                  +20% (staging behavior)   │ │
│ │ ├─ Name mimics "fsagent" pattern             +18% (evasion technique)  │ │
│ │ ├─ Hash unknown globally                     +15% (novel threat)       │ │
│ │                                                                         │ │
│ │ Weakening Factors:                                                      │ │
│ │ ├─ No observed malicious behavior            -15% (could be benign)    │ │
│ │ ├─ Missing network telemetry                 -10% (can't confirm C2)   │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Alternative Hypotheses                                                      │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ ┌─ 15% Probability ───────────────────────────────────────────────────┐ │ │
│ │ │ Legitimate but misconfigured IT deployment tool                     │ │ │
│ │ │ To confirm: Check IT change management for deployments on this date │ │ │
│ │ │ To disprove: Sandbox execution shows malicious behavior             │ │ │
│ │ └─────────────────────────────────────────────────────────────────────┘ │ │
│ │                                                                         │ │
│ │ ┌─ 7% Probability ────────────────────────────────────────────────────┐ │ │
│ │ │ Developer testing/debugging on wrong machine                        │ │ │
│ │ │ To confirm: User is developer + scheduled dev activity              │ │ │
│ │ │ To disprove: User has no dev role + no change tickets               │ │ │
│ │ └─────────────────────────────────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ What Would Change My Assessment?                                            │
│ ├─ ↑ Confidence: Sandbox shows C2 callback, file drops, or persistence    │
│ ├─ ↑ Confidence: Same hash seen in threat intel as known malware          │
│ ├─ ↓ Confidence: IT confirms authorized deployment                         │
│ ├─ ↓ Confidence: Legitimate vendor confirms this is their crash reporter  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tab 3: Hunt (Threat Hunter View)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🎯 THREAT HUNTING GUIDANCE                                                  │
│ ═══════════════════════════════════════════════════════════════════════════ │
│                                                                             │
│ MITRE ATT&CK Mapping                                                        │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ Kill Chain Position: ██████░░░░ EXECUTION (Stage 3 of 7)               │ │
│ │                                                                         │ │
│ │ Techniques Observed:                                                    │ │
│ │ ├─ T1036.005 │ Masquerading: Match Legitimate Name    │ HIGH confidence│ │
│ │ ├─ T1059     │ Command and Scripting Interpreter      │ MED confidence │ │
│ │                                                                         │ │
│ │ Techniques to Hunt For (likely next steps):                            │ │
│ │ ├─ T1055     │ Process Injection                      │ Check lsass    │ │
│ │ ├─ T1053     │ Scheduled Task/Job                     │ Check tasks    │ │
│ │ ├─ T1071     │ Application Layer Protocol (C2)        │ Check network  │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Pivot Points (Search These)                                        [Copy All│
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ IOC Type    │ Value                              │ Search In            │ │
│ ├─────────────┼────────────────────────────────────┼──────────────────────┤ │
│ │ SHA256      │ 6307545ad5664c3ba03c417c34471...   │ EDR, TI, VT          │ │
│ │ Filename    │ *fsagent*crash*.exe                │ EDR, File events     │ │
│ │ Path        │ *\temp\*updater*.exe               │ EDR, Sysmon          │ │
│ │ Timeframe   │ 2021-07-06 12:00-13:00             │ All sources          │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Hunt Hypotheses                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ IF this is a dropper, THEN look for:                                   │ │
│ │ • Child processes spawned (especially cmd, powershell, rundll32)       │ │
│ │ • Files created in %APPDATA%, %PROGRAMDATA%, or Startup folders       │ │
│ │ • Registry modifications for persistence                               │ │
│ │ • Network connections to non-corporate IPs within 5 min of execution  │ │
│ │                                                                         │ │
│ │ IF this is part of a campaign, THEN look for:                          │ │
│ │ • Same hash on other endpoints (enterprise-wide search)                │ │
│ │ • Similar naming patterns ("*crash*", "*status*", "*updater*")        │ │
│ │ • Same user executing suspicious files on other machines               │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Ready-to-Run Queries                                              [Copy All]│
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ ▾ Splunk: Find all executions of this hash                      [Copy] │ │
│ │   index=edr sourcetype=process_creation                                │ │
│ │   | where SHA256="6307545ad5664c3ba03c417c34471ce738bbc2ebe..."       │ │
│ │                                                                         │ │
│ │ ▾ Elastic: Find similar TEMP executions (±1 hour)               [Copy] │ │
│ │   process.executable:*\\temp\\*.exe AND                                │ │
│ │   @timestamp:[2021-07-06T12:00:00 TO 2021-07-06T13:00:00]             │ │
│ │                                                                         │ │
│ │ ▾ Sentinel: Find child processes from TEMP executables          [Copy] │ │
│ │   DeviceProcessEvents                                                   │ │
│ │   | where InitiatingProcessFolderPath contains "temp"                  │ │
│ │   | where Timestamp between (datetime(2021-07-06)..datetime(2021-07-07)│ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tab 4: Timeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 📅 EVENT TIMELINE                                                           │
│ ═══════════════════════════════════════════════════════════════════════════ │
│                                                                             │
│ Known Events                                                                │
│ ─────────────────────────────────────────────────────────────────────────── │
│                                                                             │
│ 12:44:15 ──●── PROCESS START                                    [Critical] │
│            │   fsagentcrashstatusupdater.exe executed                      │
│            │   Parent: UNKNOWN │ User: UNKNOWN                              │
│            │   Source: EDR Telemetry                                        │
│            │                                                                │
│            ▼                                                                │
│         [GAP]  No events between 12:44:15 and present                      │
│            │   Missing: Network connections, child processes,              │
│            │   file operations, registry changes                           │
│            │                                                                │
│ ─────────────────────────────────────────────────────────────────────────── │
│                                                                             │
│ Timeline Gaps (Data Collection Needed)                                      │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ Gap Type          │ Impact                  │ Collection Method         │ │
│ ├───────────────────┼─────────────────────────┼───────────────────────────┤ │
│ │ No network logs   │ Can't confirm C2        │ Pull NetFlow, DNS logs    │ │
│ │ No file events    │ Can't see what dropped  │ Pull Sysmon Event ID 11   │ │
│ │ No parent process │ Attack vector unknown   │ Check process creation    │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ [Expand Timeline] [Export for Report]                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tab 5: Actions (Decision Support)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ✅ INVESTIGATION ACTIONS                                                    │
│ ═══════════════════════════════════════════════════════════════════════════ │
│                                                                             │
│ Immediate (Do Now)                                                          │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ □ 1. ISOLATE HOST                                    [Auto-Execute]    │ │
│ │      Why: Prevent lateral movement if compromised                       │ │
│ │      How: EDR network isolation or switch port disable                  │ │
│ │      Risk if skipped: Adversary moves to other systems                  │ │
│ │                                                                         │ │
│ │ □ 2. NOTIFY ASSET OWNER                              [Draft Email]     │ │
│ │      Who: jsmith@company.com's manager                                  │ │
│ │      What: Potential compromise, machine being investigated             │ │
│ │                                                                         │ │
│ │ □ 3. PRESERVE VOLATILE EVIDENCE                                        │ │
│ │      What: Memory dump, process list, network connections               │ │
│ │      Tool: Velociraptor or WinPMEM                                      │ │
│ │      Deadline: Before any reboot                                        │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Short-term (Next 4 Hours)                                                   │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ □ 4. COLLECT ADDITIONAL LOGS                         [Auto-Query]      │ │
│ │      • Sysmon (Event IDs 1, 3, 7, 11, 12, 13)                          │ │
│ │      • DNS query logs for this host                                     │ │
│ │      • Authentication logs for jsmith                                   │ │
│ │                                                                         │ │
│ │ □ 5. SUBMIT TO SANDBOX                               [Upload Link]     │ │
│ │      Services: Any.Run, Joe Sandbox, Hybrid Analysis                   │ │
│ │      Goal: Observe runtime behavior, identify C2                        │ │
│ │                                                                         │ │
│ │ □ 6. ENTERPRISE-WIDE HASH SEARCH                                       │ │
│ │      Find other hosts with this file                                    │ │
│ │      Query: [Pre-populated EDR query]                                   │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Decision Points                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ IF sandbox shows C2 callback:                                          │ │
│ │   → Escalate to IR team                                                 │ │
│ │   → Block C2 domain/IP at perimeter                                    │ │
│ │   → Hunt for other infected hosts                                       │ │
│ │                                                                         │ │
│ │ IF sandbox is clean AND IT confirms legitimate:                        │ │
│ │   → Close as false positive                                             │ │
│ │   → Add to allowlist with documentation                                 │ │
│ │   → Remove network isolation                                            │ │
│ │                                                                         │ │
│ │ IF inconclusive after 4 hours:                                          │ │
│ │   → Keep isolated                                                       │ │
│ │   → Escalate to Tier 3 / IR                                            │ │
│ │   → Consider reimaging as precaution                                    │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ [Mark Complete] [Escalate to IR] [Close - True Positive] [Close - FP]       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 5: Improved Schema for LLM Output

Based on your existing schema plus analyst needs, here's the refined version:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Tier2InvestigationSummary",
  "version": "2.0",
  
  "above_the_fold": {
    "_comment": "MUST be answerable in 30 seconds without scrolling",
    
    "verdict": {
      "classification": "LIKELY_MALICIOUS|SUSPICIOUS|LIKELY_BENIGN|INCONCLUSIVE",
      "confidence_percent": 78,
      "confidence_band": "LIKELY",
      "dread_score": 8,
      "cvss_equivalent": 7.2
    },
    
    "recommended_action": {
      "urgency": "IMMEDIATE|WITHIN_1H|WITHIN_4H|WITHIN_24H|MONITOR",
      "primary_action": "Isolate endpoint from network",
      "secondary_action": "Preserve volatile memory",
      "notify": ["IR Lead", "Asset Owner"]
    },
    
    "one_liner": {
      "text": "Unsigned executable mimicking CrowdStrike agent executing from TEMP directory. No parent process visible. Hash unknown to threat intel. Likely first-stage loader.",
      "copyable": true,
      "char_limit": 280
    },
    
    "investigation_id": "INV-2024-1127-0493"
  },
  
  "evidence": {
    "primary_artifact": {
      "type": "file|process|network|user|host",
      "path": "c:\\windows\\temp\\fsagentcrashstatusupdater.exe",
      "hash_sha256": "6307545ad5664c3ba03c417c34471ce738bbc2ebe7940bf76af8045dbd903785",
      "hash_md5": "optional",
      "size_bytes": 245760,
      "signature": {
        "signed": false,
        "signer": null,
        "valid": null
      },
      "first_seen": "2021-07-06T12:44:15Z",
      "source_system": "CrowdStrike Falcon"
    },
    
    "context": {
      "host": {
        "hostname": "WORKSTATION-A1234",
        "type": "desktop|laptop|server|unknown",
        "department": "Finance",
        "criticality": "low|medium|high|critical",
        "os": "Windows 10 21H2",
        "last_patch": "2021-06-15"
      },
      "user": {
        "username": "jsmith@company.com",
        "display_name": "John Smith",
        "role": "Financial Analyst",
        "privileged": false,
        "last_login": "2021-07-06T10:30:00Z"
      },
      "network": {
        "ip": "10.1.50.42",
        "segment": "Corporate LAN - Finance",
        "subnet": "10.1.50.0/24"
      }
    },
    
    "supporting_evidence": [
      {
        "id": "EVID-001",
        "observation": "Execution from %TEMP% directory",
        "significance": "Common malware staging location; legitimate installers clean up",
        "evidence_type": "behavioral|artifact|contextual|absence",
        "confidence": 0.90,
        "source": "EDR Process Events",
        "timestamp": "2021-07-06T12:44:15Z"
      }
    ],
    
    "evidence_gaps": [
      {
        "gap": "No network telemetry",
        "impact": "Cannot confirm C2 communication",
        "collection_method": "Pull NetFlow from firewall for this host IP",
        "priority": "high"
      }
    ]
  },
  
  "reasoning": {
    "_comment": "Show the AI's work so analysts can validate",
    
    "primary_hypothesis": {
      "statement": "Malware dropper using filename masquerading to appear as CrowdStrike crash handler",
      "confidence": 0.78,
      "supporting_factors": [
        {
          "factor": "Unsigned executable",
          "contribution": "+0.25",
          "explanation": "All legitimate CrowdStrike binaries are signed"
        },
        {
          "factor": "TEMP directory execution",
          "contribution": "+0.20",
          "explanation": "Staging behavior consistent with malware"
        }
      ],
      "weakening_factors": [
        {
          "factor": "No observed malicious behavior",
          "contribution": "-0.15",
          "explanation": "File may not have executed fully or been dormant"
        }
      ]
    },
    
    "alternative_hypotheses": [
      {
        "hypothesis": "Legitimate IT deployment tool misconfigured",
        "probability": 0.15,
        "to_confirm": "Check IT change management for deployments on 2021-07-06",
        "to_disprove": "Sandbox shows malicious behavior"
      }
    ],
    
    "confidence_calibration": {
      "band": "LIKELY",
      "band_definition": "65-84% confidence based on available evidence",
      "what_would_increase": [
        "Sandbox confirms malicious behavior (+15%)",
        "Hash found in threat intel as known malware (+10%)"
      ],
      "what_would_decrease": [
        "IT confirms authorized deployment (-40%)",
        "Vendor confirms legitimate crash reporter (-35%)"
      ]
    }
  },
  
  "hunt_guidance": {
    "mitre_mapping": {
      "observed_techniques": [
        {
          "technique_id": "T1036.005",
          "technique_name": "Masquerading: Match Legitimate Name",
          "confidence": "high",
          "evidence_refs": ["EVID-001"]
        }
      ],
      "likely_next_techniques": [
        {
          "technique_id": "T1055",
          "technique_name": "Process Injection",
          "hunt_location": "lsass.exe, explorer.exe memory"
        }
      ],
      "kill_chain_phase": "Execution",
      "kill_chain_progress": "3/7"
    },
    
    "pivot_points": [
      {
        "ioc_type": "sha256",
        "value": "6307545ad5664c3ba03c417c34471ce738bbc2ebe7940bf76af8045dbd903785",
        "search_in": ["EDR", "Threat Intel", "VirusTotal"],
        "copyable": true
      },
      {
        "ioc_type": "filename_pattern",
        "value": "*fsagent*crash*.exe",
        "search_in": ["EDR", "File Events"],
        "copyable": true
      }
    ],
    
    "hunt_hypotheses": [
      {
        "if_true": "This is a dropper",
        "then_look_for": [
          "Child processes (cmd, powershell, rundll32)",
          "Files in %APPDATA%, %PROGRAMDATA%, Startup",
          "Registry persistence keys",
          "Network connections within 5 min of execution"
        ]
      }
    ],
    
    "siem_queries": [
      {
        "name": "Find all executions of this hash",
        "platform": "splunk",
        "query": "index=edr sourcetype=process_creation SHA256=\"6307545ad5664c3ba03c417c34471ce738bbc2ebe7940bf76af8045dbd903785\"",
        "expected_result": "List of hosts with this file",
        "risk_addressed": "Determine blast radius"
      },
      {
        "name": "Find all executions of this hash",
        "platform": "elastic",
        "query": "process.hash.sha256:6307545ad5664c3ba03c417c34471ce738bbc2ebe7940bf76af8045dbd903785",
        "expected_result": "List of hosts with this file",
        "risk_addressed": "Determine blast radius"
      },
      {
        "name": "Find all executions of this hash",
        "platform": "sentinel",
        "query": "DeviceProcessEvents | where SHA256 == \"6307545ad5664c3ba03c417c34471ce738bbc2ebe7940bf76af8045dbd903785\"",
        "expected_result": "List of hosts with this file", 
        "risk_addressed": "Determine blast radius"
      }
    ]
  },
  
  "timeline": {
    "events": [
      {
        "timestamp": "2021-07-06T12:44:15Z",
        "event_type": "process_start",
        "description": "fsagentcrashstatusupdater.exe executed",
        "severity": "critical",
        "source": "EDR Telemetry",
        "is_pivot_point": true,
        "evidence_ref": "EVID-001"
      }
    ],
    "gaps": [
      {
        "start": "2021-07-06T12:44:15Z",
        "end": "present",
        "missing_data": ["Network connections", "Child processes", "File operations"],
        "impact": "Cannot determine post-execution behavior"
      }
    ],
    "temporal_context": {
      "events_1h_before": 0,
      "events_1h_after": 0,
      "business_hours": true,
      "anomaly_score": null
    }
  },
  
  "actions": {
    "immediate": [
      {
        "order": 1,
        "action": "Isolate host from network",
        "why": "Prevent lateral movement if compromised",
        "how": "EDR network isolation or switch port disable",
        "risk_if_skipped": "Adversary moves to other systems",
        "automatable": true,
        "automation_id": "edr_isolate_host"
      }
    ],
    "short_term": [
      {
        "order": 4,
        "action": "Collect Sysmon logs",
        "why": "Understand process tree and file operations",
        "how": "Query SIEM for Event IDs 1, 3, 7, 11, 12, 13",
        "deadline_hours": 4,
        "automatable": true,
        "automation_id": "siem_sysmon_query"
      }
    ],
    "decision_tree": [
      {
        "condition": "Sandbox shows C2 callback",
        "then": [
          "Escalate to IR team",
          "Block C2 domain/IP at perimeter",
          "Hunt for other infected hosts"
        ]
      },
      {
        "condition": "Sandbox clean AND IT confirms legitimate",
        "then": [
          "Close as false positive",
          "Add to allowlist with documentation",
          "Remove network isolation"
        ]
      }
    ]
  },
  
  "threat_intel": {
    "hash_lookups": [
      {
        "source": "VirusTotal",
        "result": "not_found|clean|malicious",
        "detections": "0/70",
        "first_seen": null,
        "link": "https://virustotal.com/..."
      }
    ],
    "behavioral_matches": [
      {
        "pattern": "temp_execution_unsigned",
        "matching_campaigns": ["Generic Dropper Behavior"],
        "confidence": "low"
      }
    ],
    "attribution": {
      "actor": null,
      "campaign": null,
      "confidence": null
    }
  },
  
  "meta": {
    "model": "llama3:8b",
    "model_version": "janusec-tier2-v2",
    "generation_time_ms": 2340,
    "tokens_prompt": 1450,
    "tokens_completion": 2100,
    "cost_usd": 0.0152,
    "cache_hit": false,
    "schema_version": "2.0"
  },
  
  "verification": {
    "evidence_coverage_percent": 78.5,
    "claims_with_evidence_refs": 12,
    "claims_without_evidence_refs": 2,
    "unsupported_statements": [
      "Claim about exfiltration has no supporting evidence"
    ],
    "consistency_score": 0.83,
    "hallucination_flags": []
  }
}
```

---

## Part 6: The Model Problem (Honest Assessment)

### Is llama3:8b the Problem?

**Partially, but not entirely.**

| Issue | Model Problem? | Solution |
|-------|---------------|----------|
| Generic output | Yes - lacks security domain knowledge | Better prompting OR security fine-tuning |
| Missing reasoning | No - prompt doesn't ask for it | Explicit prompt structure |
| Confidence without explanation | No - prompt doesn't require it | Force confidence breakdown |
| Irrelevant playbook steps | Yes - generic IR knowledge only | Few-shot examples of good output |
| JSON parsing issues | Sometimes | Output validation + retry |

### The Real Problem Stack

```
Layer 1: Model (20% of problem)
├─ llama3:8b is general-purpose, not security-trained
├─ 8B params limits complex reasoning chains
└─ No fine-tuning on SOC workflows

Layer 2: Prompting (40% of problem)
├─ Not forcing structured output
├─ Not providing signal definitions
├─ Not including few-shot examples
├─ Not requiring evidence binding
└─ Not constraining to THIS alert's specifics

Layer 3: Context (20% of problem)
├─ Missing enterprise baseline ("what's normal here")
├─ Missing asset criticality
├─ Missing user context
└─ Missing historical patterns

Layer 4: UX (20% of problem)
├─ Information architecture is inverted
├─ No progressive disclosure
├─ Actions not prominent enough
└─ Copy-paste not frictionless
```

### Recommended Approach

**Phase 1: Fix Prompting (Cheap, High Impact)**
- Use the prompt template below
- Force JSON output with schema validation
- Inject signal definitions
- Add 2-3 few-shot examples

**Phase 2: Fix UX (Medium Effort, High Impact)**
- Implement the wireframes above
- Above-the-fold principle
- Tab-based progressive disclosure
- One-click copy for all IOCs/queries

**Phase 3: Model Upgrade (Higher Cost, If Needed)**
- For Tier 2 only (complex reasoning)
- Claude Sonnet 4 or GPT-4o for reasoning transparency
- Keep llama3:8b for Tier 1 classification

---

## Part 7: Improved Prompt Template for Tier 2

```
<system>
You are a Tier 2 SOC analyst assistant generating investigation summaries. Your output will be read by security analysts who need to make fast, accurate decisions.

CRITICAL RULES:
1. EVERY claim must reference specific evidence from the alert data
2. SHOW YOUR REASONING - explain what increased/decreased your confidence
3. Be SPECIFIC to THIS alert - no generic IR advice
4. Quantify uncertainty with confidence bands
5. Provide MULTIPLE hypotheses, not just one

CONFIDENCE BANDS:
- CERTAIN: ≥85% (would bet my job on this)
- LIKELY: 65-84% (strong evidence, some gaps)
- PLAUSIBLE: 45-64% (circumstantial evidence)
- UNCERTAIN: <45% (insufficient evidence)

OUTPUT: Strict JSON matching the provided schema. No markdown, no explanation outside JSON.
</system>

<context>
ENTERPRISE CONTEXT:
- Asset Type: {{host_type}} ({{department}}, Criticality: {{criticality}})
- User Role: {{user_role}} (Privileged: {{is_privileged}})
- Normal baseline: {{baseline_description}}

DETECTION SIGNALS FIRED:
{{#each signals}}
- {{signal_name}}: {{signal_explanation}}
{{/each}}

AVAILABLE TELEMETRY:
- EDR: {{edr_available}}
- Sysmon: {{sysmon_available}}
- Network: {{network_available}}
- Identity: {{identity_available}}
</context>

<alert_data>
{{raw_alert_json}}
</alert_data>

<evidence_items>
{{#each evidence}}
ID: {{id}}
Type: {{type}}
Value: {{value}}
Source: {{source}}
Timestamp: {{timestamp}}
{{/each}}
</evidence_items>

<instructions>
Generate a Tier 2 investigation summary answering:

1. VERDICT: What is this? (classification + confidence + reasoning)
2. SO WHAT: Why does it matter? (business impact, blast radius)
3. NOW WHAT: What should the analyst do? (specific, sequenced actions)
4. WHAT ELSE: What are alternative explanations? (competing hypotheses)
5. WHAT'S MISSING: What evidence gaps affect confidence?

For EVERY conclusion, cite the evidence ID that supports it: [EVID-001]

For SIEM queries, provide actual working syntax for Splunk, Elastic, AND Sentinel.

Output ONLY valid JSON matching the schema. No other text.
</instructions>

<few_shot_example>
{{example_good_output}}
</few_shot_example>

<output_schema>
{{tier2_json_schema}}
</output_schema>
```

---

## Part 8: Validation Checklist

Before shipping, validate against these criteria:

### The 30-Second Test
- [ ] Analyst can determine verdict without scrolling
- [ ] Confidence has visible reasoning
- [ ] First action is immediately clear
- [ ] One-liner is copy-pasteable for tickets

### The "So What" Test
- [ ] Every signal has a plain-English explanation
- [ ] Business impact is stated, not implied
- [ ] Blast radius assessment is present
- [ ] SLA/urgency is explicit

### The Trust Test
- [ ] No claims without evidence references
- [ ] Alternative hypotheses are present
- [ ] Knowledge gaps are explicitly listed
- [ ] Confidence shows what would change it

### The Action Test
- [ ] Actions are specific to THIS alert
- [ ] Actions are sequenced by priority
- [ ] Each action has a "why"
- [ ] Decision tree covers likely outcomes

### The Hunt Test
- [ ] IOCs are copy-pasteable
- [ ] SIEM queries are ready-to-run
- [ ] MITRE mapping is complete
- [ ] Pivot points are identified

---

## Part 9: Implementation Priority

### Week 1 (Highest Impact)
1. [ ] Restructure UI to above-the-fold principle
2. [ ] Add confidence breakdown (not just number)
3. [ ] Format actions as checklist with "why"
4. [ ] Add copy buttons to all IOCs/queries

### Week 2
5. [ ] Implement new prompt template
6. [ ] Add evidence binding (claims → evidence refs)
7. [ ] Create tab-based progressive disclosure
8. [ ] Add SIEM queries for multiple platforms

### Week 3
9. [ ] Add alternative hypotheses section
10. [ ] Implement decision tree
11. [ ] Add timeline visualization
12. [ ] Add hunt guidance section

### Week 4
13. [ ] Add verification/hallucination detection
14. [ ] Implement automation hooks
15. [ ] Add export functionality
16. [ ] User testing with actual SOC analysts

---

## Final Verdict: Are You Wasting Time?

**No. Here's why:**

1. **The market need is real.** SOC analyst burnout is a documented crisis. Tools that reduce cognitive load are valuable.

2. **Your technical foundation is solid.** The schema you've designed, the two-phase generation idea, the verification loop—these are sophisticated approaches.

3. **The gap is UX and specificity.** The current output looks like "AI generated this" rather than "an analyst wrote this." That's fixable.

4. **The concept of triage-as-a-service is valid.** You're not building a replacement for analysts—you're building a force multiplier. That's the right positioning.

**What would make you fail:**
- Shipping generic output that adds cognitive load
- Not getting actual SOC analyst feedback before v1
- Over-engineering the backend while UX stays broken
- Trying to replace analyst judgment instead of augmenting it

**What would make you succeed:**
- Obsessing over the 30-second test
- Making every action specific to THIS alert
- Building trust through reasoning transparency
- Getting one real SOC team to pilot and iterate

You're not an intern who doesn't know what they're talking about. You've built something with genuine architectural sophistication. Now make it usable.

---

*Document version 2.0 - Created for JanuSec Tier 2 improvement*
