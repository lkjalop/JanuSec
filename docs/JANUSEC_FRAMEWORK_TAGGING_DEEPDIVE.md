# JanuSec — Current Architecture Deep Dive

*Compiled from direct code inspection of `c:\AI\janusec` (not from memory/notes alone). File:line references point to the actual implementation at time of writing.*

---

## 1. What JanuSec is

A self-hosted SOC/breach-detection + GRC platform. 53 production-ready detectors, telemetry ingest across cloud/endpoint/email/IAM/network/supply-chain, and a two-tier (deterministic + LLM) narration pipeline sitting on top of a bounded-autonomy multi-agent investigation loop.

## 2. Telemetry in

| Category | Sources |
|---|---|
| Cloud | AWS: CloudTrail, CloudTrail-S3, GuardDuty, VPC Flow, Config, Inspector, Macie, SecurityHub, Detective, IAM changes, Kinesis/SQS. Azure: Entra ID, Activity Log, Event Hub, Defender for Cloud, NSG flow, Sentinel Analytics/Workspace. GCP asset adapter (stub, demo-only). |
| Endpoint/EDR | CrowdStrike, SentinelOne, Sysmon/EVTX |
| Network | Zscaler, Netskope (both stub connectors — return `[]` pending live creds), netflow listener, syslog/rfc3164 |
| Email | Mimecast, Proofpoint, Cofense, O365 Graph, Abnormal, Defender, Gmail/O365 adapters |
| IAM | AD, Okta, PingIdentity, OneLogin, SailPoint, Duo, GCP IAM, AWS IAM |
| Supply chain/SBOM | Snyk, Trivy, Grype, Syft |
| Generic | CSV/structured upload — the one fully production-ready path with zero optional-dependency risk |

## 3. Telemetry out

SOC technical narrative with row citations → persona-tailored executive views → GRC audit pack (combined **ISO 19011 + 27035 + 27001** printable HTML→PDF report) → per-incident kill-chain timeline → CSV control-failure register → HopGraph (D3) correlation graph → row-level evidence with SHA-256 custody hash.

## 4. Data normalization

**Canonical schema:** `CanonicalEvent` dataclass (`src/correlation/canonical_event.py`) — ~40 fields: timestamp, tenant, source_type, user, host, src_ip/dst_ip, process, file_hash, auth_method, mfa_result, data_volume_bytes, threat_tags, correlation_ids, raw, plus a dedicated AI-telemetry field group (model, model_provider, prompt, tool, embedding_id, vector_db, rag_index, guardrail, chain, agent) for capturing LLM/agent activity as first-class telemetry.

Azure has its own documented sub-schema (`docs/azure_canonical_event_schema.md`) — required fields `tenant_id/source/event_type/user/ip/resource/action/factors/risk_signals` — that all 4 Azure sources (entra_signin, entra_audit, defender_cloud, eventhub) normalize into before correlation.

**Field reconciliation** happens close to the source. `assessment_worker.py:462-475` aliases vendor-specific fields into canonical ones — e.g. Kerberos `client_address→src_ip`, `account_name→user_canonical`, `workstation→host` — so a Kerberos event and a CrowdStrike event about the same host/user land on the same correlation key.

**Correlation windows** (tuned empirically, per code comments): `HOST_WINDOW=14d` links cross-source events by host; `USER_WINDOW=6h` is deliberately short — a 24h window was tried and reverted because it caused benign-activity/campaign leakage in testing (`test_t5`).

## 5. Multi-agent investigation loop

`src/agents/router.py` runs **Planner → Investigator → Verifier → Narrator**. Every Investigator action is classified by `autonomy_gate.py` into:
- **Zone 0** — blocked (hardcoded deny-list, audit-logged)
- **Zone 1** — auto-execute (read-only/internal, immediate, parallel)
- **Zone 2** — propose, needs human approval (2A quick-timeout, 2B explicit, 2C conditional-auto)
- **Zone 3** — escalate (legal/regulatory; agent can only draft)

**Verifier** runs in a *separate LLM context* specifically to stop prompt-injection propagating from Investigator to Narrator: independent re-derivation from raw DuckDB rows, engagement-scope check, CorrectiveRAG false-positive pattern matching, multi-source corroboration (≥2 independent sources), canary-event checks, and **algorithmic (non-LLM) DREAD scoring**.

## 6. Scatter-gather narration (`src/agents/narrator.py`)

Instead of one LLM call writing the whole incident narrative:

- **Phase 1 — Scatter:** 4 specialist mini-agents run concurrently (`asyncio.gather`) on the same evidence, each with a narrow, length-capped system prompt so it can't drift into another's job:
  - **TimelineMini** — chronological kill-chain arc (Phase | Timestamp | Actor | Action | Evidence ref), flags temporal gaps >2h
  - **AttributionMini** — threat-actor fingerprinting (nation-state/eCrime/insider) with confidence %
  - **ImpactMini** — business/dollar blast radius, regulatory exposure (GDPR/PCI/HIPAA)
  - **ComplianceMini** — control failures (ISO 27001 Annex A / NIST CSF / CIS) with failure type
- **Phase 2 — Gather:** a synthesis agent merges all 4 outputs into one ≤200-word CEO paragraph, explicitly instructed not to invent anything absent from the 4 inputs.
- **Phase 3 — Deepen** (documented, not wired in this module): top-3 DREAD clusters get a second, fuller-context pass (threshold lives in `cluster_narrator.py`).
- `narrate_campaign_arc()` separately stitches multiple per-cluster narratives into one storyline once shared IOCs/techniques are found across clusters.

**Confidence is never LLM-output.** `compute_aggregate_confidence()` is a plain DREAD-weighted average with a gap penalty (each data gap costs ~0.05 confidence, capped at 0.3; per-gap hard caps also apply) — a fluent LLM cannot talk its way to a high confidence number.

## 7. Hallucination control — three real layers

1. **Annotate-only grounding check** (`_validate_ioc_grounding`) flags entity names in the prose absent from evidence, without blocking publication.
2. **Blocking check** (`regenerate_until_grounded`) — if the narrative asserts an entity absent from evidence or swallows a cited row, it force-regenerates once with the specific violation fed back ("do not invent names"); if that still fails, falls back to a deterministic prose template built only from grounded facts, flagging `_integrity_degraded`.
3. **Entity-scrub pass** (`scrub_ungrounded_entities`) — a *structural guarantee*, not detection: any ungrounded entity-shaped token is swapped for the nearest real one or redacted. A fabricated host/IP/user cannot ship, by construction.

Separately, `AdversarialCritic` (`src/agents/critic.py`) runs a low-temperature second pass whose only job is to try to falsify the narrator's verdict; `fp_probability > 0.60` pulls the confidence score down.

## 8. Executive summary composition

Persona-driven, not one-size-fits-all. `persona_views.py:421` lists: **executive, ciso, soc_analyst, compliance, threat_hunter, mssp, forensics**. `exec_summary_endpoints.py` adds: **ir, ciso, board, legal, gc, regulator** — each with distinct framing rules (e.g. ciso/board get "risk framing only, no specific state assertion").

The GRC path (`report_templates.py`) sorts so the **worst-severity incident leads**; every cited row resolves to a real event + SHA-256 custody hash, so the executive narrative traces back to raw telemetry rather than being prose-only.

## 9. LLM plumbing

`src/integrations/llm_client.py` has three tiers:
- `LocalDeterministicClient` — fully offline, zero-LLM fallback (the **T1** tier)
- `LLMClient` — resolves provider via `LLM_PROVIDER` env, defaults to Ollama (`qwen3:14b`), or Anthropic if `ANTHROPIC_API_KEY` is set

Per the original MVP design, **T2** (actual LLM narration) only fires for high-severity/ambiguous/explicitly-requested clusters — everything else gets the T1 deterministic summary with no LLM call at all.

---

# Deeper dive: MITRE, OWASP (API/LLM/Agentic), Diamond Model, MAESTRO, STRIDE, DREAD

## MITRE ATT&CK — how the tags are actually used, not just attached

MITRE technique/tactic IDs are propagated from a single source (`factor_taxonomy.py`'s unified `_FACTOR_MAP`, exposed via `FACTOR_TO_MITRE` in `core/mappings/factor_to_mitre.py`) and then consumed in **four distinct downstream places**:

1. **Narrator prompt** — `build_narrator_prompt()` in `agents/narrator.py:144-160` injects MITRE technique IDs directly next to each kill-chain phase (`MITRE {mitre_str}`), so the LLM's causal narrative is anchored to real technique IDs rather than inventing attack terminology.
2. **Campaign-arc stitching** — `narrate_campaign_arc()` (`agents/narrator.py:412-483`) uses each cluster's `mitre_techniques` list as one of the signals (alongside shared IOCs) for connecting multiple clusters into one attack story, and reports the campaign's overall technique set to the LLM.
3. **Compliance cross-walk** — `analysis/framework_mapper.py` (`map_techniques_to_controls`, `build_control_failure_register`) takes MITRE technique IDs and cross-walks them into **failed controls** across ISO 27001:2022, NIST CSF 2.0, Essential Eight, ASD ISM, APRA CPS 234, NIST 800-53 Rev 5, PCI DSS v4.0, NDB, SOCI Act, GDPR — e.g. T1078 (Valid Accounts) maps to ISO A.5.15/A.5.16/A.8.5, NIST CSF PR.AA-01, Essential Eight E2. This is what actually produces the audit-ready "control failure register."
4. **AI-specific MITRE ATLAS IDs** — for AI/agent-targeting attacks, `factor_to_mitre.py:495-508` maps a distinct set of factors to **MITRE ATLAS** (the AI/ML-specific sibling of ATT&CK) technique IDs: `agent_goal_hijack → ATLAS:AML.T0051/T0054`, `agent_memory_poisoning → ATLAS:AML.T0020`, `agent_tool_misuse → ATLAS:AML.T0057`, `model_extraction → ATLAS:AML.T0030`, `training_data_poisoning → ATLAS:AML.T0020`, etc.

**Known gap:** `GET /api/v1/dashboard/mitre/techniques/{investigation_id}` (`dashboard_endpoints.py:218-254`) is a **stub** — it returns 3 hardcoded technique entries regardless of the `investigation_id` passed in. It is not wired to real per-cluster MITRE data, unlike the four paths above which are all real. Worth knowing if you're relying on that specific endpoint.

## OWASP Top 10 — API, LLM, and "Agentic"

Two explicit OWASP lists are mapped, factor→ID, in `core/mappings/factor_to_compliance.py:599-761`:

- **OWASP LLM Top 10:2025** (`factor_to_mitre.py:513-529`, `factor_to_compliance.py:606-691`) — all 10 categories covered, e.g. `prompt_injection → LLM01:2025`, `sensitive_output_leak → LLM02:2025 + LLM06:2025`, `training_data_poisoning → LLM04:2025`, `vector_db_poisoning → LLM08:2025`, `mcp_tool_injection → LLM01:2025 + LLM06:2025`.
- **OWASP API Top 10:2023** (`factor_to_compliance.py:696-761`) — all 10, e.g. `API1:2023 - BOLA`, `API7:2023 - SSRF`, `API9:2023 - Improper Inventory Management`.
- **No classic web-app OWASP Top 10** (A01–A10:2021) — expected, since JanuSec is breach detection/GRC, not a SAST/DAST scanner.

**"Agentic" is not a separate OWASP list here — it's routed through three existing frameworks instead:**
1. Agent-specific factors map into the **existing** OWASP LLM Top 10 (not a distinct Agentic list): `agent_goal_hijack → LLM01 Prompt Injection`, `agent_memory_poisoning → LLM04 Data/Model Poisoning`, `tool_abuse`/`mcp_tool_injection → LLM06 Excessive Agency`.
2. The same agent factors also map to **MITRE ATLAS** (see above).
3. **MAESTRO** is used as the platform's own agentic-AI *self-governance* framework (see next section) — this is the piece that most directly answers "how does JanuSec threat-model its own agentic behavior."

If you specifically want OWASP's newer standalone "Agentic AI Top 10 / Threats & Mitigations" list mapped as its own taxonomy (distinct from LLM01-10), that does not currently exist in the codebase — it's currently absorbed into LLM Top 10 + ATLAS + MAESTRO.

## Diamond Model of Intrusion Analysis

Computed per-breach-cluster by `_compute_diamond_model()` in `core/tier1_prefill/threat_models.py:319+`, called from `prefill_orchestrator.py:901-906` only for confirmed breaches. Builds the four classic corners **deterministically from evidence**, not via LLM:

- **Adversary** — inferred, not assumed: checks `engagement_refs`/`change_refs` first (authorized pentest/change activity → explicitly labeled as such, suppressing false attribution), otherwise infers from signals: >40% off-hours activity (00:00–07:00 UTC), cloud API abuse without MFA/bastion (`GetSecretValue`/`AssumeRole` patterns), commodity exfil tooling (`rclone`, `mega.nz`) — each signal is named in the output, not just scored.
- **Capability** — tools/techniques from phase detectors + row content.
- **Infrastructure** — external IPs, C2 domains, cloud buckets.
- **Victim** — targeted users, hosts, data assets.

This feeds the exec-summary attribution framing and is exposed at several endpoints (`exec_summary_endpoints.py:642/953/1274/2456`), plus a dedicated Diamond Model LLM-analysis prompt in `tier2_canvas_endpoints.py:3596`.

## MAESTRO — two distinct roles in the codebase, worth not conflating

**Role 1 — kill-chain/campaign phase tagging.** In `factor_taxonomy.py`, each factor carries a `maestro` tag that's really a kill-chain phase label (e.g. `command_and_control`, `initial_access`). `FACTOR_MAESTRO` (`factor_taxonomy.py:2110`) aggregates these into a phase-coverage count, surfaced via a "MAESTRO Maturity Dashboard" (`dashboard_endpoints.py:262-280`) that reports which kill-chain phases the current factor taxonomy actually covers.

**Role 2 — the real OWASP MAESTRO framework (Multi-Agent Environment, Security, Threat, Risk, Outcome), used for self-governance.** `core/grc/ai_governance.py` explicitly documents this as modeling **the platform's own AI decisions** against ISO/IEC 42001, the EU AI Act, and MAESTRO's 7 layers (L1 Foundation Models → L7 Agent Ecosystem). This is deliberately evidence-linked — each control cites the concrete code mechanism, e.g.:

| Control | Mechanism | MAESTRO layer | Status |
|---|---|---|---|
| AIG-1 Human decision authority | Verdict set by deterministic detectors; LLM only narrates, can't upgrade/invent a verdict | L7 Agent ecosystem | implemented |
| AIG-2 Output grounding | Entity-constrained generation + deterministic scrub (the 3-layer hallucination control above) | L2 Data operations | implemented |
| AIG-3 Deterministic technique/verdict correctness | MITRE IDs and DREAD priority come from deterministic maps; wrong LLM T-codes are stripped | L4 Deployment & infra | implemented |
| AIG-4 Provenance & traceability | Every narrative claim carries cited evidence row indices | L6 Security & compliance | implemented |
| AIG-5 Graceful degradation | LLM optional — deterministic render on unavailability/timeout/drift | L5 Evaluation & observability | implemented |
| AIG-6 Prompt-injection defence | Attacker-controlled log fields sanitised before entering the prompt | L1 Foundation models, L2 Data operations | implemented |

This is JanuSec explicitly using MAESTRO to threat-model *itself* as an agentic system, not just to tag external attacker kill-chains — a meaningfully different (and more sophisticated) use of the framework than Role 1.

## STRIDE

Tagged per-factor in the same unified taxonomy (`factor_taxonomy.py`), plus a lighter standalone heuristic version in `enrichment/frameworks.py:47-65` (keyword-matches like `'spoof'`, `'tamper'`, `'exfil'`→information_disclosure, `'dos'`→denial, `'privilege'`→elevation, `'recon'`→discovery). `FACTOR_STRIDE` is consumed by `dashboard_endpoints.py` and `reporting/adapters/csv_adapter.py`. Compared to MITRE and DREAD, STRIDE here functions mainly as a **coverage/tagging dimension** (which category of threat is this) rather than driving its own scoring or compliance cross-walk — it doesn't have a downstream consumer as deep as the MITRE→controls cross-walk or the DREAD blast-radius amplification.

## DREAD — and an important nuance: there are two parallel implementations

You asked specifically about the 5 classic components (Damage, Reproducibility, Exploitability, Affected Users, Discoverability). The codebase actually has **two separate DREAD engines** that aren't fully unified:

**(A) The full classic 5-component evidence-based scorer** — `src/analysis/dread_scorer.py`. This is the one that matches the textbook Microsoft SDL model exactly:
- Each dimension (`damage`, `reproducibility`, `exploitability`, `affected_users`, `discoverability`) has its own **contribution table** of `(factor_prefix, delta, rationale)` tuples — e.g. for Damage: `impact:wiper→10`, `impact:ransomware→9`, `exfiltration:pii→8`; for Discoverability: `cloud:public_bucket→10`, `network:port_scan→9`, `remote:no_mfa→8`.
- Each dimension returns `score_10` (1-10), `score_01` (normalized), a human-readable `rationale`, and the specific `evidence` factor keys that drove the score — so every DREAD number is individually explainable, not a black box.
- `composite` = arithmetic mean of the 5 dimensions on the 1-10 scale → `risk_tier` (CRITICAL ≥8, HIGH ≥6, MEDIUM ≥4, LOW below).
- `score_dread_with_blast_radius()` adds cross-cluster amplification: if a cluster shares factors or entities (users/hosts/IPs) with other clusters in the same assessment (lateral movement, multi-stage compromise), `affected_users` is amplified up to 2× and the composite is recomputed — so a single-host compromise that's actually part of a wider campaign scores its true breadth, not just its own cluster's view.
- **Used by:** `api/artifact_endpoints.py` and `core/ebpf_correlation.py` — a narrower slice of the platform than you might expect.

**(B) A simplified 3-component aggregation + separate heavyweight composite scorer**, used in the main cluster/narrator path:
- `factor_taxonomy.py`'s `aggregate_threat_model()` only tracks `damage`, `exploitability`, `discoverability` (max-aggregated 0-1 floats per factor) — **reproducibility and affected_users are not tracked** in this path.
- `compute_dread_score()` (same file) is a *different* scoring formula entirely — a composite built from keyword-pattern weights + contextual signals (attack-vector metrics, threat metrics, technique-diversity, binary/supply-chain/kill-chain/network bonuses, status boosts, trust adjustments), clamped to 0-10, then multiplied by `asset_criticality × exposure` to get a final 0-1 risk score and CRITICAL/HIGH/MEDIUM/LOW tier. This is the DREAD number that actually reaches most cluster verdicts and the narrator.

There are additionally standalone modules `core/grc/dread.py`, `core/scoring/dread_engine.py`, `explain/dread.py`, `explain/dread_aggregator.py` (plus a `_clean` variant) and `prefill/dread_fragments.py` — suggesting DREAD scoring logic has accreted across several sprints rather than converging on one canonical implementation. If DREAD accuracy/consistency becomes a priority, this cluster of modules is the concrete place to look at consolidating — the full 5-component `dread_scorer.py` is the more rigorous, more explainable implementation and would be the natural one to standardize on if that's ever undertaken.

---

## One correction carried over from the first pass

**"HippoGraph" does not exist in the codebase.** Only **HopGraph** exists (`core/graph/network_hopgraph.py`) — a D3.js force-directed entity/correlation graph. Flagging again so it doesn't get repeated as fact.
