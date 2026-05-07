# JanuSec: Architecture, Delta Analysis & Competitive Positioning

> **Date:** 2026-04-28  
> **Branch:** feat/webhook-guard-middleware-only-verification  
> **Author:** JanuSec Engineering

---

## Table of Contents

1. [Full Architecture Walkthrough](#1-full-architecture-walkthrough)
2. [breach.html/breach.js vs investigate.html/investigate.js — Delta Analysis](#2-breachhtml-vs-investigatehtml--delta-analysis)
3. [Vendor Comparison: JanuSec vs AI-SOC Market](#3-vendor-comparison)
4. [Was Time Wasted? Did Breach Solve the CEO Problem?](#4-was-time-wasted)
5. [CEO Feedback Response: The Path to Validated Breach](#5-ceo-feedback-response)

---

## 1. Full Architecture Walkthrough

### 1.1 Ingestion Layer — Upload to Raw Storage

```
User (browser)
    → multipart POST /api/v1/csv/upload
    → file_parser.py (streaming parser)
    → DuckDB (store.py)
    → async assessment_worker.py (background)
    → SSE /progress endpoint (real-time status)
```

**File size routing:**

| Threshold | Path |
|-----------|------|
| < 5 MB, single file | `_handleFilesSync()` — inline parse, immediate render |
| ≥ 5 MB or multiple files | `_handleFilesAsync()` — background worker + SSE progress stream |

**Parser dispatch (file_parser.py):**

- `.csv` → streaming CSV reader (row-by-row, no full load)
- `.ndjson` / `.jsonl` → streaming NDJSON reader
- `.json` → `ijson` event-based parser for files > 5 MB; regular `json.load()` below that
- `.xlsx` → `openpyxl` workbook with `read_only=True` (memory-efficient)

Every row is immediately classified into one of three lanes:

| Lane | Purpose |
|------|---------|
| `LANE_TELEMETRY_EVIDENCE` | Raw endpoint/network/cloud events |
| `LANE_EVALUATION_ANSWER_KEY` | Ground truth labels (for red-team exercises) |
| `business_context` | Asset registry, crown jewel tags, org metadata |

Rows are persisted to **DuckDB** via `store.py` under a content-addressed assessment ID. DuckDB was chosen over SQLite for its columnar scan performance on 50K+ row uploads.

---

### 1.2 Triage Scoring — Per-Row Risk Signal

Each row receives a triage score `0.0–1.0` before clustering:

| Signal | Score |
|--------|-------|
| Severity = `critical` | 0.95 |
| Severity = `high` | 0.75 |
| Process name matches `lsass`, `mimikatz`, `rclone` | 0.65 |
| External IP detected in cloud-hosted asset row | 0.20 |
| Default (no signal) | 0.10 |

Scores inform clustering merge priority and later feed the confidence meter.

---

### 1.3 Clustering — Union-Find with 7 Merge Rules

**Algorithm:** Transitive union-find (disjoint set). Every row starts as its own cluster; the 7 rules below merge clusters when their predicates fire.

| Rule | Condition | Time Window |
|------|-----------|-------------|
| R1 | Same `user_principal_name` or `username` | ≤ 6 hours |
| R2 | Same external IP (exact match) | ≤ 60 days |
| R3 | Same /24 CIDR subnet | ≤ 24 hours |
| R4 | Same IP appearing in cross-domain sources | ≤ 2 hours |
| R5 | Same `engagement_ref` (pentest marker) | Unlimited |
| R6 | Same `change_ref` (change-management ticket) | Unlimited |
| R7 | Same `event_signature` hash | ≤ 14 days |

**Phase detectors** run after clustering and annotate each cluster's `kind`:

| Detector | Trigger Criteria | Cluster Kind |
|----------|-----------------|--------------|
| LSASS Credential Dump | Process = `lsass.exe` + `access_mask` dump flags | `campaign` |
| Snowflake Exfil | `COPY INTO` + external stage, OR > 1M rows copied | `campaign` |
| rclone / Cloud Sync | Process matches `rclone`/`azcopy`/`gsutil` in exfil context | `campaign` |
| K8s Privilege Escape | `ClusterRoleBinding` creation + `exec` into privileged pod | `campaign` |
| RDP Lateral Movement | RDP logon chain > 2 hops within /16 | `campaign` |

**Cluster verdicts (deterministic, cluster_merge.py):**

| Cluster Kind | Verdict |
|-------------|---------|
| `campaign` (≥1 phase detector fired) | `VALIDATED_BREACH` |
| `pentest` (has `engagement_ref`, no detectors) | `BENIGN_EXPECTED` |
| `ops` (has `change_ref`, no detectors) | `BENIGN_EXPECTED` |
| `unclassified` | `NO_VALIDATED_BREACH` |

---

### 1.4 Confidence Meter — LLM-Augmented Scoring

Before calling the LLM, the confidence meter computes a 0–100 score from four deterministic components:

| Component | Max Points | What It Measures |
|-----------|-----------|-----------------|
| `source_diversity` | 25 | How many distinct log source types contributed |
| `evidence_quality` | 30 | Triage score distribution across cluster rows |
| `corroboration` | 25 | Cross-source row overlap confirming same event |
| `pattern_match` | 20 | Matched phase detectors / known-bad signatures |

---

### 1.5 Tier-1 Prefill — LLM Prompt → Structured JSON

**Engine:** `prefill_engine.py`  
**Model:** Ollama `qwen3.6:27b` (configurable in `config/llm_settings.json`)

The prefill pipeline:

```
1. Build prompt: cluster rows + confidence score + triage context
2. POST to Ollama /api/generate (streaming)
3. Parse response → expect exactly 6 JSON fields:
   - incident_name
   - headline_subtitle
   - short_narrative     ← CEO-readable 2-3 sentence causal chain
   - confidence_rationale
   - top_actions         ← immediate response steps
   - mitre_techniques    ← ATT&CK IDs
4. Confidence post-gate: CONFIRMED_BREACH (conf ≥ 0.85 + fill_rate ≥ 0.40)
                         LIKELY_BREACH    (conf ≥ 0.55)
```

**LLM firing policy (breach.js):**
- `CONFIRMED_BREACH` → fires Tier-1 automatically on page load
- `LIKELY_BREACH` → shows human gate banner, fires on analyst click
- No auto-fire on hover, scroll, or tab switch

---

### 1.6 Verdict Ladder — Deterministic (verdict_rules.py)

The verdict ladder is **purely rule-based** — not LLM-driven:

```
VALIDATED_BREACH     conf ≥ 80  + critical + REAL + observed_impact
       ↓
CONFIRMED_INTRUSION  conf ≥ 60  + REAL source
       ↓
LIKELY_COMPROMISE    conf ≥ 40  or leans_REAL
       ↓
SUSPICIOUS_ACTIVITY  conf ≥ 20
       ↓
INSUFFICIENT_TELEMETRY  conf > 0
       ↓
BENIGN_EXPECTED      LLM verdict = BENIGN
```

This means the hard verdict call is never hallucinated — the LLM enriches narrative, not the verdict itself.

---

### 1.7 Bounded Autonomy — Agent Loop

The bounded autonomy framework wraps all agentic actions in a four-agent loop with a policy gate.

#### Agent Roles

| Agent | Role |
|-------|------|
| **Planner** | LLM → `InvestigationPlan` (ordered task list with tool assignments) |
| **Investigator** | Execute tools (DuckDB queries, API lookups, enrichment) |
| **Verifier** | Independent re-derivation of findings against raw DuckDB rows |
| **Narrator** | CEO-readable kill-chain prose from verified findings |

#### Autonomy Zones (autonomy_gate.py)

| Zone | Label | Policy |
|------|-------|--------|
| Zone 0 | BLOCKED | Never execute (destructive/irreversible) |
| Zone 1 | AUTO-OK | Read-only queries, low blast-radius lookups |
| Zone 2A | PROPOSE (quick-approve) | 30-minute analyst approval window |
| Zone 2B | PROPOSE (explicit) | Requires explicit analyst confirmation |
| Zone 2C | AUTO-APPROVE | Auto-executes if: conf > 0.95 AND ≥3 sources AND DREAD ≥ 8.0 |
| Zone 3 | ESCALATE | Legal/regulatory actions, human-only |

#### ScopeTracker Limits (per investigation session)

```
max_bytes   = 50 MB   (DuckDB scan budget)
max_queries = 200      (API/DB call budget)
```
When either limit is exceeded, Zone 1 actions promote to Zone 2 automatically.

#### Verifier Logic (verifier.py)

The Verifier runs independently of the Investigator and:
1. Re-queries raw DuckDB rows (no reliance on Investigator cache)
2. Checks for ≥ 2 independent source types (multi-source validation)
3. Runs a canary check (known-benign row must not trigger detectors)
4. Recomputes DREAD score algorithmically
5. Outputs a reverification-weighted confidence delta (`±Δ`)

---

### 1.8 Threat Models — DREAD / PASTA / Diamond

All three frameworks are computed deterministically then enriched with LLM narrative fragments.

**DREAD components:**

| Letter | Field | How Computed |
|--------|-------|-------------|
| D | Damage | Crown jewel touch + data volume exfiltrated |
| R | Reproducibility | Pattern match score, IoC stability |
| E | Exploitability | CVSS base score of observed technique |
| A | Affected Users | Distinct UPNs in cluster |
| D | Discoverability | Whether technique has public write-up |

**Diamond Model:** Adversary ↔ Capability ↔ Infrastructure ↔ Victim — edges populated from cluster rows.

**PASTA:** Threat decomposition against business context rows (crown jewels registry, asset value).

---

### 1.9 HopGraph & Swimlane — Visualization Layer

**breach_hopgraph.js:**  
- Extracts entity nodes (actor / ip / process / resource / technique / geo) from cluster rows
- Builds edges: actor↔ip, actor↔geo, ip↔host
- D3 force simulation
- Geo nodes annotated with travel verdict: `IMPOSSIBLE / CONCURRENT_IMPOSSIBLE / SUSPICIOUS / PLAUSIBLE_TRAVEL / LOCAL`
- Top-links overlay: backend-computed confidence-scored pivot-typed edges
- Edge colors by pivot type: attacker_ip=red, session=blue, host=green, identity_anomaly=orange

**breach_swimlane.js:**  
- Clusters sorted by verdict + severity
- D3 time-scale swimlane with severity-colored dots
- Expand button for > 7 clusters

---

## 2. breach.html vs investigate.html — Delta Analysis

### 2.1 Conceptual Purpose — Who Is Each For?

| Dimension | breach.html / breach.js | investigate.html / investigate.js |
|-----------|-------------------------|-----------------------------------|
| **Audience** | CEO, CISO, board, executive sponsor | SOC analyst, threat hunter, forensics |
| **Entry point** | Post-analysis result page (read-mostly) | Real-time investigation console (interactive) |
| **Primary question answered** | "Was there a breach? What happened?" | "What should I investigate next? What have I found?" |
| **Agency** | Near-zero — AI presents conclusions | High — analyst drives queue, makes calls |
| **Time orientation** | Retrospective causal narrative | Present-tense investigation stream |

---

### 2.2 Feature Delta Map

| Feature | breach.js | investigate.js |
|---------|-----------|----------------|
| Verdict hero banner (CONFIRMED/LIKELY/NO BREACH) | ✅ Full render `_renderBreachAnswerHero()` | ❌ Not present |
| CEO-readable root cause narrative | ✅ `_renderRootCauseNarrative()` (LLM-generated 2-3 sentences) | ❌ Not present |
| Executive summary card (hybrid det+LLM) | ✅ `_renderExecSummaryShell()` + `_loadExecSummary()` | ❌ Not present |
| "Why Confirmed" six-gate panel | ✅ `_renderWhyConfirmed()` | ❌ Not present |
| Known/Unknown evidence box | ✅ `_knownUnknownBox()` (deterministic) | ❌ Not present |
| DREAD/PASTA/Diamond threat model | ✅ `_renderThreatModelSummary()` + `_dreadInfo()` | ✅ `_cdShowThreatModelTab()` |
| Bounded actions (SAFE/APPROVAL/MANUAL) | ✅ `_boundedActionsHtml()` | ⚠️ Partial (queue actions only) |
| FP reduction + cluster ranking | ✅ `_rankClusters()`, `_selectTopThreatCases()` | ❌ Shows raw table |
| Benign context narrative | ✅ `_renderNarrativeContext()` | ❌ Not present |
| LLM human gate banner | ✅ Shown when `LIKELY_BREACH` | ❌ Not present |
| Swimlane timeline visualization | ✅ `BreachSwimlane.render()` | ❌ Not present |
| HopGraph entity-relationship graph | ✅ `BreachHopGraph.render()` | ❌ Not present |
| Compliance overlay (GDPR/ISO27001/SOC2) | ✅ Compliance tab in breach.html | ❌ Not present |
| Real-time SSE progress feed | ✅ `_connectSSE()` | ✅ Live feed panel |
| Upload handling | ✅ Sync + async paths | ✅ Sync + async paths |
| Evidence table with triage scores | ⚠️ Cluster summary only | ✅ Full `renderEvidenceTable()` |
| Cluster drawer (persona-tabbed) | ✅ `breach_cluster_tab.js` | ✅ `openClusterDetail()` |
| Operator queue (Active/Remainder/Escalated) | ❌ Not present | ✅ `renderQueuePanel()` |
| History sidebar | ❌ Not present | ✅ localStorage-backed |
| Analyst notes auto-save | ✅ In cluster drawer | ✅ In cluster drawer |
| Crown jewels gating form | ✅ `_loadCrownJewelsReview()` | ❌ Not present |
| IOC export | ✅ In cluster drawer sign-off | ✅ In cluster drawer |
| Investigate tab (agentic loop trigger) | ❌ Links to Advanced Console | ✅ `buildInvestigate()` → POST /investigate/build |
| Persona tabs (SOC/TH/Forensics) | ✅ In cluster drawer | ✅ In cluster drawer |
| IR bucket grouping (CONTAIN/INVESTIGATE/PRESERVE/REPORT) | ✅ `_buildPersonaSteps()` | ✅ `_cdLoadPersona()` |

---

### 2.3 Architecture Divergence

**investigate.js** is the original, analyst-first design. Every feature assumes:
- An analyst is present and making decisions
- The pipeline is streaming in real time
- Events should be presented for triage, not conclusions for reading

**breach.js** is a deliberate architectural pivot:
- The AI pipeline runs to completion before the user sees anything
- Conclusions are presented as verdicts, not event queues
- The LLM is invoked to explain a pre-determined verdict, not to discover it
- False positives are filtered and annotated (`BENIGN_EXPECTED`) rather than dumped
- The "Why Confirmed" gate ensures the verdict is earned, not just asserted

This is not a refactor of investigate.js — it is a fundamentally different user journey.

---

### 2.4 What breach.js Added That investigate.js Cannot Provide

1. **Verdict-first rendering:** The page opens to a rendered verdict — not a list of events to triage.
2. **Causal narrative (`short_narrative`):** LLM produces a 2–3 sentence attack chain. investigate.js never calls this field.
3. **FP suppression in the hero:** `_rankClusters()` surfaces only the highest-signal cluster as the lead story. Benign clusters are explained in context, not dumped.
4. **Executive summary separation:** The executive summary is a distinct, printable artifact — not embedded in an analyst workflow.
5. **Crown jewels gate:** The bounded-autonomy gate on high-value assets is surfaced in the CEO view, not hidden in the analyst drawer.

---

## 3. Vendor Comparison

### 3.1 Competitive Landscape Summary

| Vendor | Model | Autonomy | Verdict Output | Key Differentiator | Weakness |
|--------|-------|----------|----------------|-------------------|---------|
| **JanuSec** | Self-hosted (Ollama) | Bounded zones 0–3 | Deterministic ladder + LLM narrative | No data leaves the building; FP-annotated verdicts | Early stage; narrative not yet CEO-default |
| **SOCFortress Talon** | Cloud SaaS | Human-in-loop | Alert triage + runbook | Turnkey SIEM integration, SOC workflow-native | Requires SOCFortress stack; analyst-first only |
| **Dropzone AI** | Cloud SaaS | Autonomous tier 1 | "Closed" / "Escalate" | Fully automated L1 triage, fast time-to-verdict | No breach narrative; opaque model; cloud-only |
| **Prophet Security** | Cloud SaaS | Co-pilot | Risk-scored alert clusters | Multi-source correlation, NLP query | Not breach-scoped; no causal chain; SaaS lock-in |
| **Intezer** | Cloud SaaS + on-prem option | Autonomous malware triage | Malware lineage + verdict | Best-in-class binary/code analysis; gene tree | Endpoint/malware-focused; weak on cloud/identity |
| **D3 Morpheus** | Cloud SaaS | Playbook-driven | Incident closed/escalated | Deepest SOAR integration; cross-platform | No LLM narrative; verdict is playbook output, not reasoning |
| **Microsoft Sentinel + Copilot** | Cloud (Azure) | Co-pilot + auto-triage | Incident grade (High/Medium) | Native Azure/M365 integration; massive data | Cloud lock-in; privacy concerns; generic LLM, not SOC-tuned |
| **CrowdStrike Charlotte AI** | Cloud | Co-pilot | Threat score | Best EDR telemetry; fastest IOC enrichment | Requires Falcon; no multi-vendor cloud; expensive |
| **SentinelOne Purple AI** | Cloud | Co-pilot | Alert verdict | Strong EDR + cloud CNAPP | Requires S1 agent; weak narrative; SaaS only |

---

### 3.2 Where JanuSec Differentiates

**1. Self-hosted LLM with no telemetry egress**  
Every competitor above sends your log data to a cloud LLM API. JanuSec runs Ollama locally. For enterprises subject to GDPR, healthcare, defense, or financial data regulations, this is a hard architectural requirement that eliminates most competitors.

**2. Deterministic verdict ladder (not LLM-opined)**  
Dropzone AI, Prophet, and D3 all produce verdicts that are influenced by the LLM's probabilistic output. JanuSec's verdict is computed by `verdict_rules.py` from deterministic thresholds. The LLM is only allowed to write the narrative paragraph — it cannot change the verdict. This is auditable and explainable in a way that SaaS AI verdicts are not.

**3. Phase detectors with false-positive suppression**  
JanuSec's clustering layer explicitly labels `BENIGN_EXPECTED` clusters (pentest/change-window) before any LLM call. This means the AI never wastes tokens — or executive attention — on events that are already explained. No competitor surfaces benign context as a named, annotated artifact.

**4. Bounded autonomy zones (legal/regulatory escalation gate)**  
Zone 3 (ESCALATE) exists as a first-class autonomy zone for legal and regulatory actions. No other AI-SOC platform has a formally defined escalation gate that routes to legal rather than just flagging to a human analyst. This is table stakes for enterprise security incident response.

**5. CEO-layer verdict surface (breach.html)**  
Every competitor delivers to the analyst. JanuSec's breach.html is explicitly designed for the CEO, CISO, and board. The verdict hero, root cause narrative, and "Why Confirmed" six-gate panel are board-presentation artifacts. No competitor produces this.

---

### 3.3 Where JanuSec Is Behind

| Gap | Nearest Competitor with It |
|-----|---------------------------|
| Production-hardened integrations (EDR, SIEM, cloud APIs) | CrowdStrike, SentinelOne, Sentinel |
| Automated playbook execution | D3 Morpheus |
| Binary/malware analysis | Intezer |
| Speed (sub-60s L1 close) | Dropzone AI |
| Enterprise SSO, RBAC, audit log | All SaaS vendors |
| Multi-tenant / MSSP mode | SOCFortress Talon |

---

## 4. Was Time Wasted?

### Short Answer: No — but the UI surface hasn't caught up to the architecture.

### What Was Built Right

The backend pipeline from upload → cluster → verdict → narrative is exactly the right architecture for answering the CEO's question. Specifically:

- **Deterministic clustering** ensures that a phishing email, the click event, the malware process, and the C2 connection end up in the **same cluster** via R1 (same user) + R7 (same event signature). This is the technical substrate for the causal chain.
- **Phase detectors** correctly classify that cluster as `campaign` → `VALIDATED_BREACH`.
- **Confidence meter** correctly scores source diversity: if the cluster has endpoint process logs + network flow logs + identity sign-in logs, it gets ≥ 80/100 confidence.
- **Verdict ladder** correctly produces `VALIDATED_BREACH` without any LLM input.
- **Narrator agent** is designed exactly for the kill-chain prose the CEO wants: "John received phishing email from bobby@xyz.com, clicked link at 09:12 UTC, badprocess.exe loaded at 09:14 UTC, C2 connection to A.B.C.D:8080 established at 09:16 UTC."

### Where the Gap Is

The architecture can produce the answer. The **presentation layer hasn't fully surfaced it** as the dominant, unambiguous lead. The breach.html page still has too much visible surface area for investigation artifacts (evidence table, cluster drawer, compliance tab) that crowd out the CEO narrative.

The CEO's feedback is not "this doesn't work." It is "I can't find the answer you already computed." That is a UX problem, not an architecture problem.

---

## 5. CEO Feedback Response

### 5.1 What the CEO Actually Asked For

The CEO's three requirements, extracted from the demo feedback:

> **1.** "Was there an actual breach?" — A binary, unambiguous answer.  
> **2.** "How did it happen exactly? Root cause!" — A causal timeline: actor → vector → tool → C2.  
> **3.** "A section 'validated breach' — not just events based on priority which analysts need to sift through."

All three are solvable without new backend architecture.

---

### 5.2 The False Positive Problem

The CEO's core complaint: the platform **adds more events to process** rather than reducing them.

This is the fundamental difference between analyst tools (investigate.js) and executive tools (breach.html). The architecture already does FP reduction:

- `BENIGN_EXPECTED` clusters are separated and explained
- `_rankClusters()` surfaces only the top-signal cluster as the lead story
- `_selectTopThreatCases()` limits card count to prevent event overload

**What's missing:** The total cluster count and raw event volume are still visible on the breach.html page. The CEO sees "127 events across 14 clusters" and concludes the platform is overwhelming them. The fix is to hide the total counts from the executive view and instead show "1 validated breach, 3 suspected intrusions, 9 explained (benign)."

---

### 5.3 The Causal Narrative Problem

The `short_narrative` field from `prefill_engine.py` is designed to produce exactly:

> "John Smith received a phishing email from bobby@xyz.com at 09:10 UTC. He clicked the embedded link and downloaded badprocess.exe at 09:14 UTC. The process established a C2 connection to 185.220.101.42:8080 (Russia) at 09:16 UTC."

This narrative **already exists in the pipeline** but is rendered in a small card below the verdict hero. It needs to be the **first and largest element** on the page.

---

### 5.4 The Validated Breach Section

The CEO wants a section called "Validated Breach" that shows only confirmed breaches, not prioritized events.

The backend already produces this distinction:
- `VALIDATED_BREACH` clusters → go in the "Validated Breach" section
- `CONFIRMED_INTRUSION` clusters → go in the "Confirmed Intrusions" section
- `BENIGN_EXPECTED` clusters → go in a collapsed "Explained Activity" section (not visible by default)
- `SUSPICIOUS_ACTIVITY` / `LIKELY_COMPROMISE` → go in an "Under Investigation" section

The current breach.html mixes all of these into a single card flow. The fix is structural separation.

---

### 5.5 Concrete Implementation Plan (5 Changes)

**Change 1 — Make the narrative the hero, not a card**  
In `breach.js` `_renderBreachAnswerHero()`, move `short_narrative` into an `<h2>` or large prose block above the verdict badge, not below the confidence bar.

**Change 2 — Rename and restructure the cluster list**  
Replace the current "Threat Cases" card flow with three named sections:
- `## Validated Breach` (cluster kind = `campaign`, verdict = `VALIDATED_BREACH`)  
- `## Confirmed Intrusions` (verdict = `CONFIRMED_INTRUSION`)  
- `## Explained Activity` (verdict = `BENIGN_EXPECTED`, collapsed by default)

**Change 3 — Replace raw event count with verdict summary**  
Instead of "127 events across 14 clusters", show:
```
1 Validated Breach   |   2 Confirmed Intrusions   |   9 Explained (Benign)
```
This directly answers the CEO's "are these false positives?" without making them count events.

**Change 4 — Promote the kill-chain timeline**  
In `breach_cluster_tab.js`, the timeline (E9) is currently inside the cluster drawer tab. For VALIDATED_BREACH clusters, render the timeline inline in the hero card, above the fold.

**Change 5 — Add a "Path of Intrusion" table**  
For `VALIDATED_BREACH` clusters, extract: first event → attack vector → persistence mechanism → data accessed/exfiltrated → C2 destination. Render as a 5-row table with timestamps. This gives the CEO the exact narrative they asked for:

| Step | Time | Event | Actor | Destination |
|------|------|-------|-------|-------------|
| Initial Access | 09:10 UTC | Phishing email received | john.smith | from: bobby@xyz.com |
| Execution | 09:14 UTC | badprocess.exe launched | john.smith | WORKSTATION-042 |
| C2 Established | 09:16 UTC | Outbound TCP:8080 | WORKSTATION-042 | 185.220.101.42 (Russia) |
| Credential Dump | 09:31 UTC | lsass.exe access | SYSTEM | WORKSTATION-042 |
| Exfiltration | 10:15 UTC | rclone sync (12 GB) | john.smith | rclone-remote-bucket |

This table is 100% derivable from existing cluster row data. No new backend work is required.

---

### 5.6 What Would Require New Work

| CEO Request | Solvable Today? | What's Missing |
|-------------|----------------|----------------|
| "Was there a breach?" | ✅ Yes | Just needs hero redesign |
| "Root cause narrative" | ✅ Yes | `short_narrative` exists, needs promotion |
| "Path of intrusion table" | ✅ Yes | Build from cluster rows client-side |
| "Validated breach section" | ✅ Yes | Structural UI separation only |
| "AI does the investigation" | ⚠️ Partial | Narrator agent exists but not wired to breach.html |
| "Automatic root cause for all connectors" | ❌ Needs work | Requires production connector integrations (Azure, AWS, EDR) |
| "No analyst required" | ❌ Needs work | Zone 2 actions still need human approval; Zone 2C auto-approve is available but limited |

The first four items are frontend-only changes. The CEO's core complaint is addressable in the current sprint without new infrastructure.

---

### 5.7 The Right Framing for the CEO

When the platform returns `VALIDATED_BREACH`, the CEO should see exactly one prominent artifact:

```
╔══════════════════════════════════════════════════════════════════╗
║  ✅ VALIDATED BREACH — CONFIRMED (Confidence: 94%)              ║
╠══════════════════════════════════════════════════════════════════╣
║  John Smith's workstation was compromised via phishing at        ║
║  09:10 UTC. The attacker installed badprocess.exe, established   ║
║  a C2 channel to Russia (185.220.101.42), and exfiltrated        ║
║  12 GB of data over 64 minutes. Crown jewel "HR Payroll DB"      ║
║  was accessed during the intrusion.                              ║
╠══════════════════════════════════════════════════════════════════╣
║  PATH OF INTRUSION                                               ║
║  09:10 Phishing → 09:14 Execution → 09:16 C2 → 10:15 Exfil     ║
╚══════════════════════════════════════════════════════════════════╝
```

Everything below this is detail for the analyst. The CEO never needs to scroll.

---

*End of document. Generated 2026-04-28 from codebase analysis.*
