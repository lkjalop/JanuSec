**Domain Correlation Analysis for Janusec**

This document evaluates the pros, cons, and operational repercussions of ingesting and correlating security telemetry across multiple domains (up to eight), and provides architectural, compliance, networking, data engineering, and infrastructure guidance. It includes recommended minimum domain sets, permutations and risk tables, and cost/scale considerations for organizations sized 100, 500, 1,000 and 5,000+ employees.

**Assumptions**
- "Domain" means a logical telemetry domain such as: Network, Endpoint, Email, Identity, Cloud, Application, DNS, and Threat Intelligence (8 domains).
- Janusec will perform live ingestion and correlation (streaming + near-real-time) and support manual log analysis.
- Storage and processing are hosted in cloud or on-prem VM/Kubernetes clusters.
- Compliance requirements (e.g., GDPR, HIPAA, PCI-DSS) vary by customer and data types ingested.

**Quick Executive Summary**
- Correlating 8 domains gives the richest context and highest detection capability but increases complexity, cost, latency, and compliance surface area.
- For most SMB/SME organizations, starting with 2–3 high-value domains (Network, Endpoint, Email) delivers most practical ROI for threat detection and incident investigation.
- Larger orgs (1,000+ employees) benefit from adding Identity and Cloud telemetry early.
- Architect for incremental onboarding: modular ingestion pipelines, per-tenant rate-limiting/partitioning, and strong secrets/token lifecycle management.

**Domains and What They Provide**
- Network: flow logs, proxies, firewall logs — useful for lateral movement, suspicious connections, exfil.
- Endpoint: EDR alerts, process/file telemetry — high-fidelity indicators and containment signals.
- Email: SMTP, MTA/Exchange/Gmail logs — phishing/BEC detection and initial vector evidence.
- Identity: IdP (Okta/AzureAD) logs, SSO events — account takeover, suspicious logins.
- Cloud: Cloud provider logs (AWS CloudTrail/GCP/Azure) — misconfigurations, lateral cloud movement.
- Application: Web server/app logs, API gateways — business logic abuse, exposed endpoints.
- DNS: Resolver logs, recursive queries — command-and-control, tunneling, reconnaissance.
- Threat Intel: Feeds, reputation, YARA, SBOM/vuln scans — enrichments and scoring.

**Architectural Considerations**
- Modular ingestion: each domain should have its own connector/collector service with a canonical normalized output (common event schema). This limits blast radius when a connector fails.
- Canonical event model: define a minimal core schema (timestamp, tenant_id, source_domain, host/ip, user, event_type, attributes, raw) and canonical fields used for correlation (ip, host, user, file_hash, url, domain).
- Partitioning & multitenancy: per-tenant partitioning at ingest (DB partitions, Kafka topic per tenant, or topic with tenant key) to keep queries efficient and allow per-tenant retention policies.
- Storage stratification: hot store for recent events (streaming DB or time-series), warm store for 30–90 days (columnar or cloud object store with Parquet), cold/archival for long-term retention or compliance.
- Enrichment & scoring pipeline: lightweight enrichers (IP->AS, domain->WHOIS, file hash->reputation) should be executed inline or as fast downstream workers depending on latency budget.
- Correlation Graph (HopGraph): ingest artifacts and canonical factors (user, host, ip, file) into a graph DB or in-memory correlator. Graph must be horizontally scalable and TTL-aware for memory control.
- Backpressure & rate limiting: collectors should use adaptive backoff, buffer local queues, and honor tenant quotas to prevent overload.
- Observability: metrics (per-connector ingest rate, lag, error rate), tracing for request flows, and logs for debugging.

**Compliance & Privacy**
- Data minimization: ingest only necessary fields and use hashing/tokenization for PII when possible.
- Consent & Data Residency: support region-specific storage (EU, US, APAC) and allow tenant-configurable retention/locations.
- Access Controls: RBAC for the UI/API, audit logs for who viewed incidents/data, encryption at rest and in transit.
- Sensitive data handling: for PHI/PCI/other regulated data, avoid storing raw payloads or encrypt them with customer-managed keys (CMKs).
- Legal Holds & Deletion Requests: implement per-tenant deletion and legal hold flags that suspend retention pruning.

**Networking and Edge Requirements**
- Bandwidth: estimated based on log volume (see next section). For streaming ingestion, ensure collectors have reliable egress and low latency to processing endpoints.
- Connectivity: collectors in cloud/on-premise must reach API endpoints or message broker over TLS; consider private peering (VPC endpoints) for high-volume customers.
- Ingress endpoints: provision load-balanced, autoscaling ingress (HTTP/gRPC) and optional message queuing (Kafka, Pulsar) for bursts.
- Firewall & NAT: plan for large numbers of source IPs; use TLS client auth or per-tenant API keys.

**Data Engineering & Storage Requirements**
- Normalization: central normalizer service to map diverse logs into canonical schema. Keep mapping metadata versioned.
- Pipelines: use durable streaming (Kafka, Pub/Sub) for high-throughput; use consumer groups for enrichment/partitioning.
- Storage: choose Postgres/Timescale for structured events up to medium scale; use ClickHouse or BigQuery for high query throughput; S3/Blob for raw event archives in Parquet.
- Indexing & Search: elasticsearch/OpenSearch for full-text/fast search; precompute graph adjacency or use purpose-built graph DB for correlation.

**Infrastructure: VM vs Kubernetes**
- Small deployments (proof-of-concept, <100 employees): VMs or a single small Kubernetes cluster (2–3 nodes) are sufficient.
- Medium (100–1,000): Kubernetes recommended for autoscaling collectors, enrichers, and API services. Use 3+ control nodes and multiple worker nodes.
- Large (1,000+ and especially 5,000+): Kubernetes cluster with autoscaling, dedicated data nodes for ingestion, and separate clusters for analytics and infra. Consider managed services (Amazon MSK, GKE, EKS) to reduce ops burden.
- Pod sizing: collectors are lightweight but I/O bound; enrichment/graph processors require more CPU and memory. Provide node pools for different workloads (ingest, processing, analytics).

**Estimated Resource & Cost Guidance (ballpark)**
Note: costs vary by cloud, region, and retention requirements. Estimates assume cloud-managed Kafka/DB and moderate retention (30–90 days).

- 100 employees (small):
  - Log volume: 50–200 MB/day
  - Infra: single small k8s cluster or 2–3 VMs (2 vCPU, 8GB each), Postgres small instance, optional managed Kafka small cluster
  - Monthly infra cost: $200–$1,000

- 500 employees (medium):
  - Log volume: 0.5–2 GB/day
  - Infra: k8s cluster (3–5 nodes, 4–8 vCPU, 16–32GB), managed Kafka/Redis, Postgres medium, optional ClickHouse for analytics
  - Monthly infra cost: $1k–$5k

- 1,000 employees (large):
  - Log volume: 2–8 GB/day
  - Infra: multiple k8s node pools (ingest, processing, analytics), managed Kafka, ClickHouse, Postgres for metadata
  - Monthly infra cost: $5k–$20k

- 5,000+ employees (very large):
  - Log volume: 10–50+ GB/day
  - Infra: distributed processing with autoscaling, dedicated graph cluster, ClickHouse/BigQuery, heavy storage/ingest costs
  - Monthly infra cost: $20k+

These numbers are illustrative. Cost drivers: retention window, raw vs. enriched storage, and graph retention/velocity.

**Minimum Domain Combination to be Useful**
- Minimal useful set for both manual investigation and live ingestion:
  1. Network
  2. Endpoint
  3. Email

Rationale: Network + Endpoint provide the ability to track lateral movement and host-based indicators; Email captures the most common initial vector (phishing/BEC). Together they enable high-value detections and investigations with manageable complexity.

**Optional high-value additions**
- Identity: critical for mid-to-large orgs where cloud/SSO is central.
- Cloud: required if workloads run in cloud or cloud logs are a major source of events.

**Permutations & Risks**
The table below shows permutations of domain sets (subset combinations), their primary detection benefits, operational complexity, and risk/cost implications. Use this as a decision matrix when choosing which domains to onboard first.

| Permutation | Domains Included | Detection Value | Complexity / Ops | Cost Impact | Key Risks |
|---|---:|---|---|---:|---|
| Minimal-high-value | Network, Endpoint, Email | High — covers phishing, endpoint compromise, lateral movement | Low–Medium — 3 connectors, simple schema | Low–Medium | Missed cloud/identity signals, longer time-to-attribute for cloud-only attacks |
| Add Identity | Network, Endpoint, Email, Identity | Very High — ties users to actions; reduces false positives | Medium — IdP connectors + SSO mapping | Medium | PII handling, SSO data sensitivity, storage residency |
| Add Cloud | Network, Endpoint, Email, Cloud | Very High — captures cloud lateral and misconfig | Medium–High | Medium–High | Cloud account compromise missed if absent |
| Full 8 domains | All 8 (Network, Endpoint, Email, Identity, Cloud, App, DNS, TI) | Max detection coverage and forensic fidelity | High — normalization, enrichment, graph scale | High | Cost, operational burden, compliance surface area, high maintenance |
| Network + DNS only | Network, DNS | Medium — network anomalies, C2 | Low | Low | Misses endpoint/user context; harder attribution |
| Endpoint + App | Endpoint, Application | Medium — host and app-layer events | Low–Medium | Low–Medium | Misses initial vector if email not ingested |

**Permutation Risk Matrix by Organization Size**
- Small (100): favor Minimal-high-value. Full 8 domains is likely cost-prohibitive.
- Medium (500): consider Minimal + Identity or Cloud depending on cloud adoption.
- Large (1,000): add Identity early; Cloud and App telemetry recommended.
- Very Large (5,000+): Full multi-domain ingestion feasible and recommended for full coverage but plan for scaled graph and long retention.

**Why pick Network/Endpoint/Email first?**
- They cover common threat narratives: phishing→email, execution/persistence→endpoint, and lateral/exfiltration→network.
- Implementation complexity is modest: connector maturity is high for these domains (EDR vendors, email APIs, firewall logs).
- Early ROI is high — many SOC playbooks and detection rules are already tuned for these sources.

**Options if budget is constrained**
- Start with Network+Email (cheaper than adding EDR) to capture phishing and C2 behavior, then add selective EDR for critical hosts.
- Use sampling / selective retention: ingest full telemetry for high-risk hosts/tenants and sample others.
- Use SaaS-managed analytics for heavy lifting (managed Kafka, ClickHouse, BigQuery) to reduce ops burden.

**Operational & Engineering Checklist (to onboard each domain)**
1. Connector maturity: vendor APIs, rate limits, auth model (OAuth, API key), and token rotation.
2. Normalizer mapping: canonical field mapping and transformation tests.
3. Backpressure: local buffering, retries, dead-letter queues.
4. Enrichment: cache external lookups (ASN, GeoIP, TI) to reduce repeated calls.
5. Graph ingestion: canonical artifacts and TTL management.
6. Security: encrypt secrets, RBAC, and audit trails.
7. Compliance: per-tenant residency, PII handling, deletion/hold flows.

**Concrete Implementation Patterns**
- Use Kafka or a managed streaming service as the durable ingestion buffer; collectors publish to topics by domain and tenant.
- Use stateless collectors in k8s deployments with per-tenant configuration pulled from `TenantStore` (secrets) and `Subscription` metadata.
- Run enrichment workers and graph ingesters in separate worker pools with autoscaling based on queue lag.
- Store raw events in object storage (Parquet) and enriched/normalized events in a fast query store (ClickHouse or Postgres + OpenSearch for search).

**When multi-domain correlation becomes too costly**
- The tipping point is when total ingest volume and graph retention cause either:
  - storage cost for hot/warm indexes to exceed budget, or
  - CPU/memory requirements for the graph engine to exceed operational capacity.

Mitigations:
- Reduce retention in the hot store and rely on cold archives for historical queries.
- Aggregate or summarize low-value telemetry before storing (e.g., flows aggregated per 5–15 minutes).
- Use sampling or tiered collection (full data for critical assets, aggregated for less critical ones).

**Recommendation & Roadmap**
1. Start with the Minimal-high-value set: `Network`, `Endpoint`, `Email`.
2. Add `Identity` for mid-sized and larger orgs as a second phase.
3. Onboard `Cloud` and `Application` next if cloud workloads are substantial.
4. Add `DNS` and `Threat Intelligence` opportunistically for better C2 detection and enrichment.
5. Architect for modular onboarding: per-domain connectors, per-tenant quotas, and a scalable graph service with TTL controls.

**Next Steps & Checklist for Janusec**
- Define canonical schema and mapping repository for each domain.
- Build connector templates and a test harness for ingestion (sample data replay).
- Evaluate an initial infra plan for expected volume (50–200 MB/day to start), and choose managed services for Kafka/DB where possible.
- Implement per-tenant configuration controls in `TenantStore` and ensure secure token rotation.

**Appendix: Permutation Cost Indicator Matrix (quick glance)**
- Legend: Low / Medium / High (relative scale of cost & ops)

| Domains | Cost | Ops Complexity | Detection Coverage |
|---|---:|---:|---:|
| Network, Endpoint, Email | Low–Medium | Low–Medium | High |
| + Identity | Medium | Medium | Very High |
| + Cloud | Medium–High | Medium–High | Very High |
| + App, DNS, TI (full 8) | High | High | Max |

---

If you want, I can:
- produce a downloadable CSV of the permutation table, or
- generate a simple cost estimator script (input: events/day, retention days) to produce a monthly cost forecast, or
- scaffold the canonical schema files and mapping templates for the `Network`, `Endpoint`, and `Email` connectors.

---
Generated: 2025-12-23
