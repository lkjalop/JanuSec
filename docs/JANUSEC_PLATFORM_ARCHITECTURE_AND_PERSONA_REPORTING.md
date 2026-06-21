# JanuSec Platform Architecture and Persona Reporting Guide

## Purpose

JanuSec is a breach assessment, correlation, and evidence-to-action platform for security teams that need to answer a difficult operational question quickly:

> Did the supplied telemetry prove a real breach, what evidence supports that conclusion, what controls failed, and what should each stakeholder do next?

The platform combines deterministic security analytics, graph correlation, temporal retrieval, threat modeling, compliance crosswalks, and LLM-assisted narration. The intended operating model is not "ask an LLM if this is bad." JanuSec first builds an evidence-backed deterministic assessment, then uses LLMs to explain, summarize, and adapt the findings for different personas.

This document describes what JanuSec is, what it can do, how the breach assessment architecture works, how `breach.html` and `breach.js` support the user workflow, how persona reports are generated, and how components such as scatter-gather agents, ChronoGraph, TemporalRAG, HopGraph, ISO 27001, ISO 27035, and threat modeling frameworks fit together.

## Target Audience

JanuSec is aimed at organizations and service providers that already have security telemetry but struggle to turn it into a coherent breach answer.

Primary audiences:

- SOC analysts who need fast triage, containment actions, and evidence-backed next steps.
- Threat hunters who need pivots, hypotheses, IOCs, ATT&CK techniques, and cross-source correlation.
- Incident responders and forensics teams who need chain-of-custody aware acquisition plans.
- CISOs, executives, legal, and privacy teams who need business impact, notification posture, decision clocks, and risk framing.
- Compliance and audit teams who need control failure mapping, ISO/NIST/SOC/PCI evidence, and corrective action registers.
- MSSPs who need tenant-ready handoff reports, SLA-aware summaries, and customer-facing updates.
- Product, engineering, and platform teams who need a defensible architecture for AI-assisted security operations.

## Unique Selling Propositions

JanuSec's strongest differentiators are:

- Evidence-first breach verdicts: the deterministic pipeline owns the verdict; the LLM narrates and adapts it.
- Multi-domain correlation: identity, endpoint, network, cloud, email, data, API, and supply-chain signals are stitched into clusters.
- Persona-specific reporting: one incident can produce SOC, CISO, executive, threat hunter, forensics, compliance, audit, and MSSP outputs.
- Explainable control failures: MITRE ATT&CK techniques are crosswalked to ISO 27001, NIST CSF, Essential Eight, ASD ISM, APRA CPS 234, NIST 800-53, PCI DSS, GDPR, SOCI, and related frameworks where configured.
- Time-aware reasoning: ChronoGraph and TemporalRAG add historical anomaly and similar-incident context.
- Graph-native investigation: HopGraph links users, hosts, IPs, domains, processes, cloud resources, hashes, and evidence rows.
- Bounded automation: actions are tiered by blast radius and approval need.
- Air-gap friendly posture: local LLM and deterministic fallbacks allow analysis without sending sensitive evidence to external providers.
- Auditability: evidence refs, dispatch traces, sign-off state, control witnesses, and generated outputs can be persisted and replayed.

## What JanuSec Can Do

JanuSec can currently support these operating capabilities:

- Upload and analyze CSV, XLSX, JSON, NDJSON, logs, and workbook-style evidence packs.
- Normalize heterogeneous telemetry into canonical fields.
- Build breach assessments with correlation clusters, threat cases, verdicts, severity, evidence previews, row references, and pipeline metadata.
- Generate Tier 1 cluster narratives and executive summaries.
- Render an interactive breach assessment UI through `frontend/static/breach.html`.
- Display an evidence table, cluster cards, HopGraph views, swimlane timelines, compliance coverage, threat intel enrichment controls, and postmortem panels.
- Regenerate persona dispatch payloads for individual stakeholders.
- Produce persona-specific handoff content for SOC analyst, CISO, executive, threat hunter, forensics, compliance, audit, and MSSP workflows.
- Map MITRE techniques to compliance and control failures.
- Evaluate regulatory trigger hints and notification clock context where enough evidence exists.
- Attach proposed actions and approval tiers for containment and governance.
- Use TemporalRAG to retrieve similar recent evidence and provide historical context.
- Use ChronoGraph to track long-horizon entity metrics and anomalies.
- Use HopGraph to correlate entities across rows and clusters.
- Export IOC packs, hunt packs, ATT&CK Navigator layers, Sigma-style rules, and evidence manifests from the UI.
- Maintain dispatch state and support sign-off, further-task generation, notes, timelines, IOCs, and repeat-entity checks.

## High-Level Architecture

```text
                                  +-----------------------------+
                                  | Users and Stakeholders      |
                                  | SOC, CISO, Exec, Legal,     |
                                  | Hunter, Forensics, Audit,   |
                                  | Compliance, MSSP            |
                                  +---------------+-------------+
                                                  |
                                                  v
                           +----------------------+----------------------+
                           | Breach Console UI                           |
                           | frontend/static/breach.html                 |
                           | frontend/static/js/breach.js                |
                           | breach_dispatch.js, breach_cluster_tab.js   |
                           | breach_swimlane.js, breach_hopgraph.js      |
                           +----------------------+----------------------+
                                                  |
                                REST, SSE, WebSocket, static assets
                                                  |
                                                  v
+-------------------------+       +---------------+--------------------+       +-------------------------+
| Evidence Inputs         |       | FastAPI API Layer                  |       | Integrations            |
| CSV, XLSX, JSON, NDJSON |------>| src/api/app.py                    |<----->| Slack, Teams, SIEM,     |
| Zeek, Suricata, Sysmon  |       | deep_analyze_endpoints.py         |       | webhooks, EDR/IAM APIs  |
| M365, CloudTrail, EDR   |       | breach_endpoints.py shim          |       | Sentinel, Splunk, etc.  |
| SBOM, email, packs      |       | exec_summary/cluster/dispatch     |       +-------------------------+
+-------------------------+       +---------------+--------------------+
                                                  |
                                                  v
                            +---------------------+---------------------+
                            | Ingestion and Normalization Pipeline      |
                            | file_parser, streaming_ingest,            |
                            | assessment_worker, store, mapping         |
                            +---------------------+---------------------+
                                                  |
                +---------------------------------+----------------------------------+
                |                                                                    |
                v                                                                    v
 +--------------+------------------+                              +------------------+--------------+
 | Deterministic Analytics         |                              | Context Engines                 |
 | scoring, detectors, rules,      |                              | HopGraph, TemporalRAG,          |
 | factor synthesis, clustering,   |                              | ChronoGraph, baseline context,  |
 | DREAD, kill-chain, MITRE        |                              | entity resolution, CMDB         |
 +--------------+------------------+                              +------------------+--------------+
                |                                                                    |
                +---------------------------------+----------------------------------+
                                                  |
                                                  v
                              +-------------------+-------------------+
                              | Assessment Object                      |
                              | normalized_rows, correlation_clusters, |
                              | threat_cases, factor_tags, verdicts,   |
                              | evidence_preview, row_refs, mappings,  |
                              | control_witnesses, proposed_actions    |
                              +-------------------+-------------------+
                                                  |
                      +---------------------------+----------------------------+
                      |                                                        |
                      v                                                        v
      +---------------+----------------+                       +---------------+----------------+
      | LLM-Assisted Narration         |                       | Persona and Report Generation |
      | cluster_narrator, tier1,       |                       | exec_summary orchestrator,    |
      | critic, grounding validator,   |                       | persona_dispatch, compliance, |
      | deterministic fallback         |                       | postmortem, export views      |
      +---------------+----------------+                       +---------------+----------------+
                      |                                                        |
                      +---------------------------+----------------------------+
                                                  |
                                                  v
                            +---------------------+---------------------+
                            | Outputs                                   |
                            | Intrusion answer, cluster narratives,     |
                            | stakeholder dispatch, compliance report,  |
                            | evidence manifest, IOC/hunt packs,        |
                            | postmortem, audit trail, next actions     |
                            +-------------------------------------------+
```

## User Flow Architecture

```text
User opens /
  |
  | if DEFAULT_FRONTEND=breach or root fallback
  v
breach.html loads shell
  |
  v
breach.js initializes
  |
  +-- no assessment query param
  |     |
  |     v
  |   renderUpload()
  |     |
  |     +-- user drops CSV/XLSX/JSON/log files
  |     |
  |     +-- small/workbook path
  |     |     POST /api/v1/upload/workbook_sheets or /api/v1/upload/files
  |     |     GET  /api/v1/upload/tabular/page
  |     |     POST /api/v1/csv/deep_analyze
  |     |
  |     +-- large async path
  |           POST /api/v1/assessments/upload
  |           poll or stream progress
  |
  +-- assessment query param exists
        |
        v
      loadAssessment()
        |
        v
      render selected tab
        |
        +-- Intrusion Assessment
        |     hero verdict, executive summary, dispatch center,
        |     threat cases, evidence views, root cause, agent panel
        |
        +-- Cluster
        |     detailed cluster workbench, DREAD, evidence, actions,
        |     critic challenge, HopGraph, notes, further tasks
        |
        +-- Evidence
        |     sortable/filterable normalized row table
        |
        +-- HopGraph
        |     entity relationship graph for assessment or cluster
        |
        +-- Compliance
        |     GET /api/v1/compliance/coverage
        |     framework coverage and factor-to-control mapping
        |
        +-- Intel
        |     IOC enrichment, MITRE enrichment, actor-attribution gate
        |
        +-- Postmortem
              ISO 27035-style incident report, timeline, corrective actions
```

## How `breach.html` Works

`frontend/static/breach.html` is intentionally a thin static shell. It provides:

- The navigation bar.
- A tab bar container populated by JavaScript.
- A live-feed probe strip for common integrations.
- The main `#br-content` mount point.
- Script loading order for D3, dispatch, API/state/progress helpers, core breach UI, swimlane, cluster tab, postmortem, and HopGraph modules.

The page itself does not contain the business logic. It loads the JavaScript modules that call backend APIs, render tabs, and update the assessment state.

Important loaded modules:

- `breach.js`: core application controller.
- `breach_dispatch.js`: stakeholder dispatch bar and role definitions.
- `breach_api.js`: API wrapper helpers.
- `breach_state.js`: shared state helper.
- `breach_progress.js`: progress helpers.
- `breach_swimlane.js`: D3 swimlane and mini graph.
- `breach_cluster_tab.js`: cluster detail workbench.
- `breach_hopgraph.js`: assessment and cluster entity graph.
- `breach_postmortem.js` and `breach_postmortem_tab.js`: postmortem rendering.
- `breach_threat_cases.js`: threat case cards and repeated card rendering helpers.

## How `breach.js` Works

`frontend/static/js/breach.js` is the main static application controller. It solves the user's problem by turning a raw upload or existing assessment into an actionable investigation workbench.

Main responsibilities:

- Parse URL parameters such as `assessment`, `cluster`, and `tab`.
- Decide whether to show upload mode or assessment mode.
- Upload files through backend endpoints.
- Load persisted assessment data.
- Render the intrusion assessment home view.
- Rank and render clusters.
- Trigger Tier 1 summaries for high-priority clusters.
- Request executive summaries.
- Render evidence, HopGraph, compliance, intel, and postmortem tabs.
- Manage selected LLM model from the tab bar.
- Render stakeholder dispatch and wire action buttons.
- Export IOC, hunt, ATT&CK Navigator, Sigma, and evidence manifest packages.
- Open cluster detail views.
- Call persona dispatch regeneration endpoints.
- Call notification dispatch endpoints.
- Surface evidence gaps, control failures, approval gates, and next actions.

Key user problems solved by `breach.js`:

- "I have files but do not know whether this is a breach."
  - It provides upload, progress, and routes the data into deep analysis.

- "I need the answer in one screen."
  - It renders a clear breach verdict hero, executive summary, top threat cases, evidence views, and action center.

- "I need to brief different stakeholders."
  - It renders the dispatch center and persona previews.

- "I need evidence, not a vague summary."
  - It links cluster cards and summaries back to row refs, evidence chains, HopGraph, and evidence table rows.

- "I need compliance and notification posture."
  - It surfaces ISO/NIST/control mapping, regulatory impact, ISO 27035 lifecycle state, and approval requirements.

- "I need to investigate further."
  - It provides HopGraph, swimlane, IOC enrichment, MITRE enrichment, hunt exports, and further-task generation.

## Backend Route Map For Breach UI

```text
breach.html / breach.js
  |
  +-- Upload and deep analysis
  |     POST /api/v1/assessments/upload
  |     POST /api/v1/upload/workbook_sheets
  |     POST /api/v1/upload/files
  |     GET  /api/v1/upload/tabular/page
  |     POST /api/v1/csv/deep_analyze
  |
  +-- Assessment summaries
  |     POST /api/v1/assessments/{aid}/executive-summary
  |     GET  /api/v1/assessments/{aid}/deep-exec-summary/status/{job_id}
  |     GET  /api/v1/assessments/{aid}/deep-exec-summary/stream/{job_id}
  |
  +-- Cluster narration
  |     POST /api/v1/assessments/{aid}/tier1-prefill
  |     GET  /api/v1/assessments/{aid}/tier1-prefill/status
  |     POST /api/v1/assessments/{aid}/clusters/{cid}/tier1-summary
  |
  +-- Persona dispatch and investigation
  |     POST /api/v1/assessments/{aid}/clusters/{cid}/persona-dispatch
  |     GET  /api/v1/assessments/{aid}/clusters/{cid}/persona-dispatch/stream
  |     POST /api/v1/assessments/{aid}/clusters/{cid}/sign-off
  |     POST /api/v1/assessments/{aid}/clusters/{cid}/further-tasks
  |     GET  /api/v1/assessments/{aid}/clusters/{cid}/timeline
  |     PATCH /api/v1/assessments/{aid}/clusters/{cid}/notes
  |     GET  /api/v1/assessments/{aid}/clusters/{cid}/iocs
  |     GET  /api/v1/assessments/{aid}/clusters/{cid}/repeat-entities
  |
  +-- Compliance, report, and integrations
        GET /api/v1/compliance/coverage
        GET /api/v1/report/ingestion
        POST /api/v1/dispatch/notify
        POST /api/v1/incidents
```

## Core Data Model

A JanuSec assessment is a structured object built from uploaded or live telemetry. Important fields include:

- `assessment_id`: stable identifier for the analysis.
- `normalized_rows`: canonical evidence rows derived from uploaded files or connectors.
- `correlation_clusters`: grouped evidence rows representing possible incidents or threat cases.
- `threat_cases`: UI-friendly cluster summaries.
- `row_refs`: row indices that support each cluster.
- `evidence_preview`: selected evidence rows shown to the narrator and UI.
- `factor_tags`: compact detector outputs such as IAM, endpoint, network, email, exfil, or cloud factors.
- `verdict` or `overall_verdict`: assessment-level classification.
- `final_verdict`: cluster-level deterministic verdict where present.
- `confidence`: deterministic confidence.
- `severity`: cluster severity.
- `tier1_prefill`: fast cluster narrative, DREAD fragments, kill-chain summary, and related context.
- `llm_narrative`: enriched LLM-assisted narrative.
- `persona_dispatch`: per-persona handoff payloads.
- `control_witnesses`: evidence-linked controls that failed or require review.
- `compliance_violations`: framework mappings and violations.
- `proposed_actions`: containment or governance actions requiring approval.
- `hopgraph_summary`: graph context for entity paths.
- `exec_summary_llm`: executive summary and enriched pipeline outputs.

## Scatter-Gather Agents

In JanuSec, "scatter-gather" describes an orchestration pattern rather than a single monolithic model call.

Scatter phase:

- Split the assessment by clusters, entities, domains, or persona needs.
- Send each unit to a specialized deterministic or LLM-assisted worker.
- Examples:
  - Cluster narrative synthesis.
  - Evidence frame retrieval.
  - Persona adaptation.
  - Control failure mapping.
  - Threat hunter pivot generation.
  - Forensic acquisition planning.
  - Executive rollup generation.

Gather phase:

- Collect outputs.
- Validate row references and grounding.
- Merge deterministic verdicts with LLM narration.
- Preserve stronger deterministic verdicts when LLM output is weaker.
- Build rollups, persona reports, and UI-ready dispatch payloads.

Implemented examples:

- `src/exec_summary/orchestrator.py` processes top clusters, builds belief trajectories, retrieves evidence frames, derives verdict reasoning, synthesizes cluster narratives, validates claims, attaches control witnesses, synthesizes rollup, then adapts personas.
- `src/api/dispatch_endpoints.py` can regenerate one persona or stream all persona dispatch payloads.
- `src/core/tier1_prefill/prefill_engine.py` is used by cluster endpoints to generate top-N or single-cluster Tier 1 summaries.

Recommended operating rule:

- Deterministic agents decide "what is true enough to act on."
- LLM agents decide "how to explain it to this stakeholder."
- Validators decide "whether the explanation is grounded."

## HopGraph

HopGraph is the entity relationship layer. It connects observables across rows and clusters so analysts can see how an identity, host, process, IP, domain, cloud resource, or file hash relates to the rest of the case.

Typical nodes:

- Users and service accounts.
- Hosts and devices.
- Source and destination IP addresses.
- Domains and TLS SNI values.
- Processes and command lines.
- File hashes.
- Cloud roles, buckets, resources, and access keys.
- Evidence rows and clusters.

Typical edges:

- User logged in from IP.
- Process executed on host.
- Host connected to domain.
- Cloud principal assumed role.
- Evidence row belongs to cluster.
- Cluster shares infrastructure with another cluster.

How it helps:

- Reveals lateral movement.
- Shows reused infrastructure.
- Links isolated-looking alerts into a single intrusion path.
- Gives threat hunters pivots.
- Gives executives visual scope.
- Gives forensics teams acquisition targets.

UI implementation:

- `breach_hopgraph.js` renders D3 entity graphs.
- `breach_swimlane.js` includes a mini HopGraph option.
- `breach.js` renders a HopGraph tab and mini lead-cluster graph.

Backend implementation:

- Core graph modules live under `src/core/graph/` and `src/graph/`.
- The compatibility shim `src/core/graph/hopgraph.py` imports the global HopGraph implementation.
- Deep analysis can ingest rows into HopGraph context for assessment views.

## ChronoGraph

ChronoGraph is the time-bucketed metrics memory. It tracks entity metrics over time using hourly buckets and configurable lookback windows.

Implemented core:

- `src/core/chrono/sketch_store.py`
- Singleton: `CHRONO`
- Default bucket size: 1 hour.
- Default lookback: 30 days.
- Optional SQLite persistence.

Capabilities:

- Increment metrics for an entity.
- Sum metrics over a time window.
- Compute per-hour means.
- Compute z-scores against historical buckets.
- Return top entities for a metric.
- Expose entity metrics for persona and TemporalRAG context.

Example uses:

- User has unusual outbound byte volume.
- Host has unusual process-launch rate.
- Domain has unusual NXDOMAIN or beaconing pattern.
- Cloud principal has unusual API activity.
- Service account has abnormal data access.

How it improves reports:

- SOC gets "this is 5x normal for this host."
- Threat hunter gets "same ASN appeared across multiple phases over 7 days."
- CISO gets "detection was delayed relative to first anomalous activity."
- Compliance gets "monitoring control failed to detect sustained abnormal behavior."

## TemporalRAG

TemporalRAG is time-windowed retrieval for evidence rows. It indexes recent evidence and retrieves similar or relevant rows before narration.

Implemented core:

- `src/ai/temporal_rag.py`
- `TemporalCorpus`: per-tenant ring buffer.
- `TemporalRAGEngine`: indexes rows and retrieves neighbors.
- Embedding mode can use Ollama or deterministic BM25 fallback.

Why it exists:

- A single row rarely proves a breach.
- Similar recent events often explain whether a row is benign, repeated, escalating, or newly suspicious.
- Persona reports need prior context without asking the LLM to remember it.

Retrieval flow:

```text
Evidence rows arrive
  |
  v
TemporalRAG indexes compact row text
  |
  +-- embedding mode: Ollama embeddings
  |
  +-- fallback mode: BM25 keyword scoring
  |
  v
Narrator or persona builder queries context
  |
  v
TemporalRAG returns recent similar evidence
  |
  v
Prompt includes context block and neighbor summaries
```

How it helps:

- Reduces one-row hallucination.
- Supports bitemporal review and prior-decision retrieval.
- Lets dispatch payloads mention similar incidents, prior decisions, or anomaly history.
- Helps analysts distinguish repeated noise from escalation.

## Bitemporal Review

Bitemporal review separates two time concepts:

- Event time: when the security event happened.
- Transaction time: when JanuSec or an analyst learned, labeled, or changed something.

This matters for regulated incident response. A report should be able to say:

- What the platform believed at the time.
- What evidence later changed that belief.
- Which persona dispatch was active at a given time.
- Whether a decision was superseded.

Implemented pieces:

- `src/analysis/bitemporal_dispatch_trace.py`
- Analyst review endpoint in `src/api/analyst_review_endpoints.py`
- Dispatch decision records with persona, tenant, cluster, transaction time, content hash, and supersession fields.

## Persona-Based Reporting

JanuSec uses a shared evidence backbone and adapts it into persona-specific reports. Each persona receives different emphasis, not different facts.

Core generation path:

```text
Cluster + evidence rows + deterministic verdict
  |
  v
Narrative enrichment
  |
  v
Control failure register
  |
  v
Persona dispatch builder
  |
  v
Persona payload stored on cluster.persona_dispatch
  |
  v
breach.js renders dispatch preview and actions
```

Primary implementation:

- `src/analysis/persona_dispatch.py`
- `src/reporting/prompt_templates.py`
- `src/exec_summary/persona_adapters.py`
- `src/api/dispatch_endpoints.py`
- `frontend/static/js/breach_dispatch.js`
- `frontend/static/js/breach.js`

## Persona Report Matrix

| Persona | Main Question | Receives | Generated From |
| --- | --- | --- | --- |
| SOC Analyst | What do I contain now? | Host/account containment actions, IOCs, commands, evidence refs, urgency | Narrative, affected principals, attacker infrastructure, action library |
| CISO / Legal | What decisions and risks require sign-off? | Regulatory triggers, breach posture, legal review points, P1 approvals, control failures | Control register, affected data, verdict, notification clocks |
| Executive | What happened and what decision is needed? | Plain-English impact, business consequence, scope, decision requests | Executive summary pipeline, top clusters, rollup synthesis |
| Threat Hunter | Where should I pivot? | Hypotheses, KQL/Splunk/Snowflake queries, MITRE techniques, infrastructure pivots | Factor tags, MITRE mappings, IOCs, HopGraph, TemporalRAG |
| Forensics | What evidence must be preserved? | Acquisition order, volatile evidence plan, host list, cloud log preservation, chain-of-custody hints | Affected hosts, evidence refs, timeline, persistence signals |
| Compliance | Which controls failed? | ISO/NIST/PCI/GDPR mappings, control failures, regulatory triggers, remediation priorities | Framework mapper, MITRE techniques, affected data, evidence rows |
| Audit / ISO | Is there auditable evidence and a corrective action plan? | Evidence completeness, nonconformity records, CAP actions, audit opinion | Control register, evidence refs, ISO 19011-style checks |
| MSSP | What do I tell the customer and what SLA applies? | Client-facing summary, SLA posture, next update, tenant actions | Narrative, containment state, SLA evaluation, dispatch status |

## Persona Output Examples

SOC analyst output should include:

- Top containment action.
- Affected hosts and accounts.
- IOCs.
- Command examples where available.
- Evidence refs.
- Action tier and approval requirement.

CISO output should include:

- Breach posture.
- Material business risk.
- Legal/privacy decision points.
- Notification clocks.
- Control failures.
- Which actions require CAB, legal, or executive sign-off.

Executive output should include:

- What happened.
- What was affected.
- What has been contained.
- What remains uncertain.
- What decision is needed today.

Threat hunter output should include:

- Hypotheses.
- ATT&CK techniques.
- Pivot queries.
- Reused infrastructure.
- Similar prior incidents.
- Visibility gaps.

Forensics output should include:

- Acquisition order.
- Evidence to preserve before remediation.
- Host and cloud artifacts.
- Timeline refs.
- Chain-of-custody state.

Compliance output should include:

- Framework control failures.
- Evidence-linked controls.
- Regulatory triggers.
- Remediation priority.
- Notification deadlines where known.

Audit output should include:

- Evidence completeness.
- Corrective action plan.
- Nonconformity register hints.
- Audit opinion.

MSSP output should include:

- Customer-facing summary.
- SLA status.
- Handoff state.
- Tenant-specific next update.

## Executive Summary Pipeline

The enriched executive summary pipeline is implemented in `src/exec_summary/orchestrator.py`.

Flow:

```text
Sorted clusters
  |
  v
Phase 1: belief trajectories, evidence frames, verdict reasoning
  |
  v
Phase 2: per-cluster narrative synthesis
  |
  v
Claim grounding validation
  |
  v
Control witness attachment
  |
  v
Phase 3: assessment rollup
  |
  v
Phase 4: persona adapters
  |
  v
exec_summary_llm response consumed by breach.js
```

The pipeline is designed to degrade gracefully. If LLM calls timeout or fail, deterministic fallbacks are used and failure metadata is returned so the UI can avoid pretending an LLM completed successfully.

## Tiered LLM Model Strategy

JanuSec should treat LLMs as bounded narration and reasoning helpers.

Recommended tiers:

- T0 deterministic: no LLM, used for scoring, verdicts, compliance mapping, and fallback text.
- T1 fast narrator: cluster summaries and analyst-facing prefill.
- T2 quality narrator: executive, legal, compliance, and board-facing reports.
- T3 deep analysis: slower scatter-gather synthesis across many clusters, personas, and counter-hypotheses.

Best practice:

- T1 should be fast, local, and deterministic-verdict anchored.
- T2 should use a stronger model and stricter grounding.
- T3 should run asynchronously with SSE/polling, not block the UI.
- All tiers should preserve deterministic verdicts unless there is concrete false-positive evidence.

## Threat Modeling Frameworks

JanuSec uses threat modeling frameworks to turn technical findings into structured reasoning and next steps.

### MITRE ATT&CK

Purpose:

- Describe attacker behavior using technique IDs.
- Support hunt pivots, kill-chain summaries, and control crosswalks.

How JanuSec uses it:

- Factor tags and narratives are mapped to ATT&CK techniques.
- Techniques drive control mapping in `framework_mapper.py`.
- UI exports can include ATT&CK Navigator-style layers.

### Kill Chain

Purpose:

- Show attack progression from initial access through execution, persistence, credential access, lateral movement, collection, and exfiltration.

How JanuSec uses it:

- Cluster timelines are tagged by phase.
- Swimlane views show when each phase occurred.
- Executive summaries describe the path of intrusion.

### STRIDE

Purpose:

- Classify threat categories:
  - Spoofing.
  - Tampering.
  - Repudiation.
  - Information disclosure.
  - Denial of service.
  - Elevation of privilege.

How JanuSec uses it:

- STRIDE-like categories help explain risk patterns and map them to control families.
- Compliance endpoints expose STRIDE-to-control hints.

### DREAD

Purpose:

- Score risk dimensions:
  - Damage.
  - Reproducibility.
  - Exploitability.
  - Affected users.
  - Discoverability.

How JanuSec uses it:

- DREAD scoring helps rank clusters and explain why something is critical.
- `src/core/scoring/dread_engine.py` maps cloud, endpoint, network, email, CVE, CMDB, and infrastructure factors into dimension scores.
- Persona reports use DREAD fragments to explain severity.

### Diamond Model

Purpose:

- Structure adversary, capability, infrastructure, and victim.

How JanuSec uses it:

- Threat hunter and executive narratives can describe observed infrastructure, affected users, and capabilities.
- Capability text helps infer MITRE techniques when explicit tags are missing.

### PASTA

Purpose:

- Connect business objectives, technical scope, threat analysis, vulnerability analysis, attack modeling, and risk treatment.

How JanuSec uses it:

- Deep analysis helpers expose PASTA-like fields to explain exploitation paths and next risk treatment steps.

### MAESTRO / AI Threat Modeling

Purpose:

- Model AI, agentic, and autonomous workflow risks.

How JanuSec can use it:

- Identify risks in LLM-assisted triage, tool use, prompt injection, data leakage, and automated action execution.
- Inform AI governance reports and approval requirements.

## Compliance Architecture

JanuSec should be understood as a control-evidence mapper, not a legal determination engine. It can surface indicators and control mappings, but final regulatory decisions require human legal and compliance review.

### ISO 27001

ISO 27001 provides the information security management system and control frame.

Relevant mappings in JanuSec include:

- Access control.
- Identity management.
- Secure authentication.
- Privileged access rights.
- Protection against malware.
- Monitoring activities.
- Data leakage prevention.
- Network security.
- Web filtering.
- Cloud service security.
- Vulnerability management.

JanuSec maps ATT&CK techniques and evidence to ISO 27001 controls through `src/analysis/framework_mapper.py` and compliance endpoints.

### ISO 27035

ISO 27035 provides incident management lifecycle framing.

JanuSec uses ISO 27035-style concepts for:

- Preparation.
- Detection and reporting.
- Assessment and decision.
- Response.
- Lessons learned.
- Corrective actions.

The breach UI includes postmortem and lifecycle language that turns evidence into an incident report, timeline narrative, and corrective action register.

### ISO 19011

ISO 19011 is useful for audit evidence and audit-program thinking.

JanuSec uses ISO 19011-style ideas in the audit persona:

- Evidence completeness.
- Audit opinion.
- Nonconformity records.
- Corrective action plans.
- Traceability of evidence refs to controls.

### ISO 27003

ISO 27003 is implementation guidance for establishing an ISMS. It is useful as a roadmap companion to ISO 27001 findings.

How JanuSec can use it:

- Convert repeated ISO 27001 control failures into ISMS implementation tasks.
- Group corrective actions into policy, ownership, risk treatment, monitoring, and continuous improvement workstreams.

### Regulatory Trigger Hints

JanuSec can evaluate trigger hints such as:

- GDPR.
- PCI DSS.
- APRA CPS 234.
- SOCI Act.
- NDB-style notification clocks where configured.
- Sector and data-class based obligations.

These are presented as decision-support indicators, not final legal conclusions.

## Control Failure Register

The control failure register converts technique-level evidence into audit-ready control failures.

Flow:

```text
Narrative + evidence rows + entity context + cluster
  |
  v
Extract or infer MITRE techniques
  |
  v
Map techniques to controls
  |
  v
Evaluate affected data and regulatory triggers
  |
  v
Attach evidence row refs where available
  |
  v
Return failed controls, critical count, clocks, evidence links
```

This register drives compliance, CISO, audit, and executive outputs.

## Action Tier Architecture

JanuSec uses bounded autonomy tiers in `src/analysis/persona_dispatch.py`.

```text
Tier 1: Auto-execute / log-only candidate
  Reversible, low blast radius, high confidence.
  Example: block known malicious IOC, isolate actively exfiltrating endpoint.

Tier 2: One-click human approval
  Reversible and scoped to a specific entity.
  Example: expire user sessions, revoke access key, collect volatile artifacts.

Tier 3: CAB / change management
  Higher blast radius or operational risk.
  Example: privilege role removal, segmentation change, mass account disable.

Tier 4: Human-only
  Legal, regulatory, public, or attribution decisions.
  Example: breach notification, customer notice, legal hold, law enforcement.
```

This lets JanuSec recommend concrete actions without encouraging unsafe automation.

## Evidence Gathering Architecture

Evidence quality determines report quality. JanuSec should gather and preserve:

- Original raw files.
- Parsed normalized rows.
- Row index and source file.
- Event IDs and event names.
- Event type and canonical event summary.
- Timestamp and timezone.
- User, host, IP, domain, process, command line, hash, cloud resource.
- Detection factor tags.
- MITRE technique IDs.
- Control witness links.
- Chain-of-custody metadata.
- LLM prompt version, model, timeout, and response provenance.

Evidence should flow like this:

```text
Raw file or connector event
  |
  v
Parser extracts source-specific fields
  |
  v
Normalizer promotes canonical fields
  |
  v
Store persists full row JSON
  |
  v
Detectors emit factors and scores
  |
  v
Clusterer assigns row_refs
  |
  v
Evidence sampler selects source-balanced rows
  |
  v
Narrator receives event summaries and factor labels
  |
  v
Persona/report builders cite row refs
```

Recommended evidence fields for high-quality narration:

- `row_index`
- `source_file`
- `source_type`
- `event_id`
- `event_type`
- `event_name`
- `event_summary`
- `timestamp`
- `user`
- `host`
- `src_ip`
- `dst_ip`
- `domain`
- `process_name`
- `command_line`
- `service_name`
- `file_hash`
- `bytes_sent`
- `bytes_received`
- `cloud_principal`
- `cloud_resource`
- `mitre_technique`
- `factor_tags`
- `triage_score`
- `correlation_cluster_id`

## Prompt Architecture

Prompts should follow the same hierarchy as the platform:

```text
Deterministic classification
  |
  v
Narrator role
  |
  v
Structured signals
  |
  v
Human-readable factor explanations
  |
  v
Evidence snippets with row refs
  |
  v
Known false-positive or uncertainty signals
  |
  v
Required output schema
  |
  v
Grounding and citation rules
```

Prompt rules:

- Open with the deterministic verdict and confidence.
- Tell the model to explain, not reclassify.
- Allow downgrade only with a concrete false-positive reason.
- Humanize factor tags.
- Include event summaries, not just usernames and timestamps.
- Require row citations.
- Require JSON schema for machine-parsed outputs.
- Include missing-source and uncertainty fields.
- Include persona-specific tone and action requirements only after the facts.

## Report Generation Modes

JanuSec has several report styles:

### Intrusion Assessment

Rendered in the breach home tab. It answers:

- Is this a confirmed breach?
- What is the top threat case?
- What is the path of intrusion?
- What evidence supports it?
- What actions are pending?

### Cluster Report

Rendered in the cluster tab. It answers:

- What happened in this cluster?
- What evidence rows are involved?
- What DREAD and threat model scores apply?
- What does the critic challenge?
- What gaps remain?
- What should the analyst do next?

### Executive Summary

Generated through `/api/v1/assessments/{aid}/executive-summary`.

It combines:

- Deterministic summary.
- Optional LLM color.
- Enriched pipeline outputs.
- TemporalRAG context.
- Belief trajectories.
- Persona summaries.
- Executive story and ISO 27035 lifecycle blocks.

### Persona Dispatch

Generated through `/persona-dispatch` endpoints.

It creates stakeholder-specific payloads from a shared narrative and control register.

### Compliance Report

Generated through compliance endpoints and report exports.

It focuses on:

- Framework coverage.
- Control failures.
- Evidence links.
- Regulatory trigger hints.
- Remediation priorities.

### Postmortem

Rendered through postmortem modules.

It focuses on:

- ISO 27035 incident lifecycle.
- Timeline narrative.
- Root cause.
- Corrective action register.
- Lessons learned.

## Security and Governance Model

JanuSec should enforce these governance principles:

- Evidence minimization: only send necessary context to LLMs.
- Local-first inference: use local LLMs by default for sensitive evidence.
- Redaction: redact secrets, tokens, and PII where feasible.
- Provenance: record model, prompt version, response metadata, and row refs.
- Human approval: require approval for high-blast-radius or legal actions.
- Audit trail: persist dispatch, sign-off, notes, and generated outputs.
- False-positive handling: include benign baselines and suppressions in prompts.
- Reproducibility: preserve raw evidence hashes, fixture versions, and pipeline versions.

## How JanuSec Improves User Outcomes

For SOC teams:

- Reduces alert overload by grouping rows into threat cases.
- Gives concrete containment actions.
- Links every claim back to evidence.

For executives:

- Converts technical telemetry into business risk and decision requests.
- Clarifies what is known, inferred, and still unverified.

For compliance and legal:

- Maps technical activity to control failures and notification posture.
- Helps start the right review early.

For threat hunters:

- Provides pivots, ATT&CK context, infrastructure reuse, and similar incidents.

For forensics:

- Preserves order-of-operations and volatile evidence priorities.

For MSSPs:

- Produces tenant-specific, SLA-aware handoffs and customer-ready summaries.

## Recommended Next Enhancements

To improve quality further:

1. Make evidence previews source-balanced rather than first-N or score-only.
2. Promote canonical `event_id`, `event_type`, and `event_summary` for every row.
3. Centralize factor taxonomy with labels, MITRE mappings, tactics, and report wording.
4. Add row-citation precision tests for all LLM-generated claims.
5. Add prompt ablation benchmarks for verdict anchor, factor humanization, and evidence snippets.
6. Add T1/T2/T3 model routing as explicit configuration.
7. Add persona report quality gates for blank tools, missing evidence refs, and hallucinated entities.
8. Add evidence diagnostics to every persisted assessment.
9. Add source freshness and missing-log severity to persona prompts.
10. Expand ChronoGraph integration into reports for normal-vs-abnormal baselines.
11. Expand TemporalRAG retrieval to include prior analyst decisions and resolved false positives.
12. Expand HopGraph path scoring to highlight identity-to-data and endpoint-to-cloud paths.
13. Add ISO 27035 postmortem export with sign-off and corrective action register.
14. Add ISO 27001 statement-of-applicability style summaries for repeated control failures.
15. Add model/prompt provenance to every export.

## Glossary

- Assessment: a complete analysis object for one upload or case.
- Cluster: a group of related evidence rows.
- Threat case: UI-ready cluster summary.
- Factor tag: detector output used as compact evidence.
- Evidence preview: selected rows shown to the UI or narrator.
- Row ref: stable row index used for citations.
- HopGraph: entity relationship graph.
- ChronoGraph: time-bucketed metric memory.
- TemporalRAG: time-windowed retrieval over recent evidence.
- Persona dispatch: stakeholder-specific report payload.
- Control witness: evidence-linked control failure.
- DREAD: risk scoring model.
- STRIDE: threat category model.
- MITRE ATT&CK: adversary behavior technique framework.
- ISO 27001: ISMS requirements and control framework.
- ISO 27035: incident management lifecycle guidance.
- ISO 19011: audit management guidance.

## Summary

JanuSec is best understood as an evidence-to-decision platform for breach assessment. Its core value is not just detecting suspicious rows, and not just generating summaries. Its value is the full chain:

```text
raw telemetry
  -> normalized evidence
  -> deterministic factors
  -> correlated clusters
  -> graph and temporal context
  -> breach verdict
  -> control failures
  -> persona reports
  -> approved actions
  -> audit-ready postmortem
```

The architecture is strongest when deterministic analytics own truth, graph and temporal systems provide context, and LLMs provide grounded explanation tailored to each stakeholder.
