# Minimum Production Readiness Expansion

This document translates the open gaps captured in `DEMO_READINESS_DETAILED_ANALYSIS_2025-12-18.md` into minimum viable work packages required before we can claim "production ready" coverage. Each section references the source paragraphs in the demo analysis and outlines the concrete deliverables, owners, integrations, and validation we need.

## 1. CSPM Collectors and Compliance Logic (Ref. §2.7, lines 417‑436)

**Gap recap**  
Architecture placeholders exist for AWS Config, Azure Security Center, and GCP Security Command Center, but there are no authenticated API calls, compliance rule engines, or drift detection hooks.

**Minimum readiness target**  
Ship authenticated collectors for all three clouds plus a lightweight compliance evaluator so we can demonstrate automated CIS/NIST posture reporting inside the LIVE console.

**Required workstreams**
1. **Collector services** – Implement signed AWS Config `ListDiscoveredResources`/`GetComplianceDetails` polling, Azure Security Center REST with AAD app registration, and GCP SCC `findings` ingestion. Store responses in `data/posture/*.jsonl` partitions tagged per tenant.
2. **Compliance logic** – Build a rule runner that maps Config/SCC findings to CIS 1.1+/NIST 800‑53 controls using the existing `src/compliance/rule_engine.py` scaffolds. Include pass/fail counts, drift deltas, and mitigation hints.
3. **Frontend surfacing** – Extend `frontend/static/janusec-platform-complete-LIVE.html` posture cards plus add a static page (e.g., `frontend/static/cspm.html`) that renders benchmark coverage with `x-api-key` authenticated calls to `/api/v1/cspm/status`.
4. **Testing & ops** – Add unit tests in `tests/collectors/test_cspm_collectors.py` using vcrpy fixtures, plus Prometheus metrics (`cspm_poll_latency_seconds`, `cspm_rule_failures_total`). Provide a runbook for credential rotation stored in Vault/KMS (see §7).

## 2. Network Infrastructure Observability (Ref. §2.8, lines 443‑452)

**Gap recap**  
`src/integrations/bgp_client.py` is scaffolding only; there is no BGP session telemetry, MACsec/IPsec health monitoring, or anomaly detection.

**Minimum readiness target**  
Demonstrate authenticated collectors that ingest BGP route updates, MACsec key status, and IPsec tunnel health into HopGraph plus dashboards that alert on drift/anomalies.

**Required workstreams**
1. **Collector daemons** – Stand up ExaBGP or GoBGP listeners with TLS auth, parse route announcements, and push normalized events into `NetworkAdapter.enqueue`. For MACsec/IPsec, integrate with vendor APIs (Cisco DNAC, Juniper, Azure VWAN) using stored credentials.
2. **Health monitoring** – Emit metrics (`bgp_session_up`, `ipsec_tunnel_latency_ms`, `macsec_rekey_failures_total`). Wire alerts into Prometheus/Alertmanager and expose summary via `/api/v1/network/infra/status`.
3. **Anomaly detection** – Implement BGP prefix hijack heuristics (unexpected ASN changes, path length spikes) and IPsec drop detection (EWMA on packet loss). Surface findings in LIVE console’s Network panel plus persona reports.
4. **Docs & runbooks** – Document onboarding (per-tenant peer IPs, allowed prefixes) and failover testing so ops can validate after upgrades.

## 3. KAPE Forensics Pipeline (Ref. §2.9, lines 461‑466)

**Gap recap**  
KAPE ingestion is not implemented; there is no end-to-end pathway from artifact upload to UI exploration.

**Minimum readiness target**  
Provide a scripted ingestion path (S3/SFTP watch), parsers that MITRE-tag the extracted artifacts, storage with retention controls, and a UI card exposing forensic timelines.

**Required workstreams**
1. **Ingestion path** – Add `src/collectors/kape_ingestor.py` that monitors tenant-specific S3 prefixes or SFTP dropboxes, runs checksum/AV scans, and writes normalized artifacts to `data/kape/{tenant}/{case}`.
2. **Parser + MITRE tagging** – Extend `src/parsers/kape_parser.py` to map registry, shimcache, browser, and jump-list data to TTPs (T1078, T1105, etc.) and emit `hopgraph_event` entries for correlation.
3. **Frontend/UI** – Create `frontend/static/forensics_kape.html` and add sidebar link. Include timeline charts, download controls, and per-artifact retention banners referencing the compliance section.
4. **Retention/Auditing** – Store metadata in PostgreSQL with signed hashes; log access events for auditing (see §7). Provide a purge command respecting tenant TTL.

## 4. LLM Tier2 + Persona Narratives (Ref. §§4.1‑4.2 & §5, lines 521‑610+)

**Gap recap**  
Tier1/Tier2 LLM calls still rely on deterministic placeholders, and persona-specific reporting is 0% complete.

**Minimum readiness target**  
Wire real LLM providers honoring tenant overrides, ensure Tier2 SSE streams deterministic but AI-backed narratives, and expose persona-specific report exports from APIs/UI.

**Required workstreams**
1. **Provider wiring** – Implement `src/integrations/llm_client.py` with OpenAI + Anthropic SDKs, plus Ollama fallback. Respect `DEFAULT_FRONTEND` overrides and LIVE console LLM settings. Add retry, rate-limit, and budget reservation logic.
2. **Tier2 SSE** – Update `src/api/tier2_endpoints.py` to stream actual provider responses, include graph context & threat intel enrichments, and add structured error telemetry.
3. **Persona templates** – Build `src/reports/persona_templates/*.jinja` for Executive, SOC, Compliance, Hunter, MSSP personas with fields outlined in §5. Implement `/api/v1/forwarding/persona` for targeted delivery and augment `/api/v1/report/ingestion` to accept `persona`.
4. **UI surfaces** – Update LIVE console right rail + csv multi-analyzer to select persona narratives, show cost estimates, and display provider health status.

## 5. Network Adapter Completion (Ref. §2.4, lines 257‑314)

**Gap recap**  
The adapter only includes a queue scaffold; there are no Syslog/NetFlow/IPFIX listeners or parsers, and throttling/backpressure features are minimal.

**Minimum readiness target**  
Deliver authenticated listeners with TLS, structured parsers, buffering/backpressure controls, and throttling plus metrics.

**Required workstreams**
1. **Listeners** – Implement UDP/TCP listeners with mTLS and optional DTLS, supporting Syslog RFC5424 and custom header injection for tenant IDs.
2. **Parsers** – Integrate `libparse` or rust-based NetFlow/IPFIX decoders exposed via FFI, mapping flow tuples to canonical schema (src_ip/dst_ip, proto, byte_count). Validate via golden fixtures in `tests/integrations/test_network_adapter.py`.
3. **Throttling & buffering** – Add token-bucket flow control per tenant plus persistent overflow queue (e.g., disk-backed `asyncio.Queue`). Emit `network_adapter_dropped_total` metrics with tenant labels.
4. **Ops** – Provide configuration docs (`config/network_adapter.yaml`) for port bindings, auth secrets (Vault references), and scaling guidance (K8s DaemonSet with nodeSelectors).

## 6. Email & IAM Live Ingestion (Ref. §§2.5‑2.6, lines 318‑401)

**Gap recap**  
Adapters rely on synthetic fixtures; OAuth/MS Graph/Okta integrations are not wired, so production tenants must upload CSVs manually.

**Minimum readiness target**  
Enable live OAuth flows (MSAL/Gmail/Okta/Azure AD), persistent token storage, incremental polling, and enrichment hooks.

**Required workstreams**
1. **OAuth implementation** – Complete MSAL auth for O365, Google Workspace OAuth2, Okta client credentials, and Azure Graph credential flows. Store secrets/refresh tokens in Vault/KMS with rotation policies.
2. **Ingestion loops** – Implement resilient pollers with checkpoint cursors (Graph delta queries, Okta SCIM events) writing to message queues for HopGraph ingest.
3. **Schema + enrichment** – Ensure canonical fields (dkim/spf/dmarc for email, actor/action/resource for IAM) feed into scoring and persona narratives. Add heuristics for BEC detection and risky logins surfaced via `/api/v1/decisions/recent`.
4. **Validation** – Add integration tests hitting mock Graph/Okta servers plus soak tests measuring throughput and latency. Document onboarding steps for tenants in `docs/connectors/email_iam_onboarding.md`.

## 7. Secret Handling & Missing-Log SOAR Loop (Ref. §10.1‑10.2 + scattered notes)

**Gap recap**  
Secret storage strategy is undecided and missing-log automation is not wired into SOAR platforms despite being highlighted in sections 10.1‑10.3.

**Minimum readiness target**  
Adopt a production secret store (Vault, AWS KMS, or Azure Key Vault), migrate connector secrets, implement heartbeat checks per tenant, and trigger SOAR tickets when logs go missing.

**Required workstreams**
1. **Secret store selection** – Choose HashiCorp Vault cluster (preferred) or cloud KMS. Implement secret sync for connectors (Email/IAM/Network/CSPM) and update config loaders to fetch via Vault transit engine.
2. **Heartbeat service** – Extend `/api/v1/correlation/multi-domain/config` to store per-connector heartbeat TTLs. Background job scans ingestion timestamps and raises `missing_log` incidents with severity scaling.
3. **SOAR integration** – Wire missing-log alerts to Cortex XSOAR/Tines/Phantom via webhook templates. Include tenant metadata plus auto-closure when heartbeat recovers.
4. **Auditing** – Log secret fetches, rotations, and heartbeat states; expose compliance summaries for SOC2 evidence.

## 8. Recommended Production Path Execution (Ref. §10.1 lines 1071‑1117, §10.2 lines 1118‑1169)

**P0 focus (Weeks 1‑4)**  
Deliver LLM provider wiring, Email/IAM connectors, and deterministic Tier2 SSE. Track progress via Jira epics `P0-LLM`, `P0-EMAIL`, `P0-IAM`. Define exit criteria (live tenant sending data + persona narratives available in UI).

**P1 follow-up (Weeks 5‑8)**  
Finish Network Adapter plus missing-log SOAR automation. Add weekly readiness demos showing authenticated Syslog ingestion feeding HopGraph and SOAR tickets firing after heartbeat lapses.

**Dependencies**  
All work must land behind feature flags toggled via `/api/v1/admin/scoring/weights` and `/api/v1/admin/autogen/*` so demo envs stay stable while we iterate.

## 9. Persona Reporting & Backlog Analytics (Ref. §5 + persona-forwarding guidance)

**Minimum readiness target**  
Implement persona ranking helper, persona filters across reports, `POST /api/v1/forwarding/persona`, backlog report endpoints, and ensure network artifacts respect persona filters.

**Required workstreams**
1. **Ranking helper** – Build `src/core/persona_ranker.py` scoring incidents per persona weightings (executive risk, SOC actionability, compliance coverage). Store results in `recommendation_catalog`.
2. **Persona filters** – Update API responses (`/api/v1/report/ingestion`, `/api/v1/decisions/recent`) to include persona tags; extend LIVE console & csv analyzer filters.
3. **Forwarding endpoint** – Implement `/api/v1/forwarding/persona` to push filtered payloads to Slack/email/SIEM and log ack status.
4. **Backlog analytics** – Add `/api/v1/backlog/persona_summary` summarizing outstanding actions per persona, surfaced on right rail and exported in persona-specific PDF/HTML.

## 10. Security & Compliance Hardening (Secret store, retention, auditing)

**Minimum readiness target**  
Lock down secrets (see §7), enforce per-tenant heartbeats, document retention/auditing for KAPE and other sensitive artifacts, and ensure SBOM/SOAR flows respect compliance demands.

**Required workstreams**
1. **Retention policies** – Define default retention (e.g., 30 days raw, 365 days metadata) for KAPE artifacts with configurable overrides stored in `/api/v1/correlation/multi-domain/config`. Document purge scripts and legal hold process.
2. **Audit trails** – Instrument every sensitive action (KAPE view/download, persona report export, LLM completion) with audit entries stored in PostgreSQL and exported for SOC2/ISO evidence.
3. **Access controls** – Enforce RBAC for new collectors/pages; update `src/api/app.py` dependencies to require `x-api-key` plus optional JWT for admin operations.
4. **Runbooks** – Provide operator docs covering secret rotation, connector onboarding, artifact retention, and compliance attestations.

## 11. Testing, Metrics, and Operations (Ref. testing notes & final bullets)

**Minimum readiness target**  
Expand automated coverage for persona/forensics endpoints, ensure pytest suite passes (handle `aiosqlite` dependency), and publish metrics/runbooks for every collector.

**Required workstreams**
1. **Automated tests** – Add pytest modules for new APIs (`tests/api/test_persona_forwarding.py`, `tests/api/test_kape_ingest.py`, etc.) plus golden HopGraph session fixtures covering multi-domain ingestion.
2. **Performance harness** – Re-run `pytest -m "not slow"` plus targeted integration suites after each milestone; capture artifacts via `test-results/`.
3. **Observability** – Instrument collectors and adapters with Prometheus counters/gauges, ensure `/metrics` exposes them, and update Grafana dashboards plus runbooks (pager triggers, SLOs from `SLOs.md`).
4. **Runbooks & readiness gates** – Before flipping features on for tenants, run checklists (LLM provider smoke, Email/IAM ingestion, Network adapter throughput, CSPM compliance). Document in `operations/runbooks/production_readiness.md`.

---

Delivering the above elevates each “NOT STARTED/TEST ONLY” area to demo-ready with verifiable traces, ensures persona narratives have real LLM backing, and closes the core security/ops gaps blocking production claims.
