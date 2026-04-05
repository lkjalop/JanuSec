**ASCII Architecture — Janusec Multi‑Tenant Secure Microsegmented Deployment (Azure-focused, cloud-agnostic)**

High-level goals:
- Multi-tenant, least-privilege isolation per tenant
- Microsegmented subnets (network/endpoint/app/data) to limit blast radius
- Minimal cross-tenant data egress, local ingestion preference
- Support multi-domain telemetry ingestion (start with 4 domains)
- Cloud-agnostic patterns but examples and references for Azure

ASCII Diagram (simplified):

                        Internet
                           |
                   +-------+--------+
                   |  Public LB     |  (WAF, TLS termination)
                   +-------+--------+
                           |
                   +-------+--------+
                   |  DMZ Subnet     |  (Ingress proxies, auth)
                   +--+----------+---+
                      |          |
  Tenant-A Ingest --->+          +---> Tenant-B Ingest
                      |          |
                   +--+----------+---+
                   |  App Subnet      |  (API, processing workers)
     +-------------+--+-----+----+--+--------------+
     |                |     |    |                 |
     |                |     |    |                 |
     |       +--------+     |    +--------+        |
     |       |K8s/VMs/Pods  |    | Serverless|       |
     |       |(isolated by  |    |Functions  |       |
     |       |  tenant NSG) |    |(per tenant)|      |
     |       +--------------+    +-----------+      |
     |                                           +--+--+
     |                                           | DB  |
     |                                           |Tier |  (encrypted, per-tenant or shared with row-level encryption)
     |                                           +--+--+
     |                                              |
     +---------------------+------------------------+
                           |
                   +-------+--------+
                   |  Forensic/Blob |  (SSE-KMS, immutability/object-lock)
                   +-------+--------+
                           |
                   +-------+--------+
                   |  Monitoring    |  (Prometheus, Azure Monitor, Log Analytics)
                   +----------------+

Notes on microsegmentation and tenancy
- Subnet breakdown (suggested):
  - DMZ/Ingress: TLS termination, WAF, API Gateways, per-region public endpoints.
  - App/Compute: application workers, k8s nodes, VM scale sets. NSGs restrict egress to only necessary S3/Blob or messaging endpoints.
  - Data/DB: RDBMS, time-series, indices. Strong encryption (SSE-KMS), separate databases per tenant when feasible.
  - Forensic/Archive: immutable blobs and DLQ storage, object-lock, KMS envelope encryption.

- Tenant isolation model options (choose one or hybrid):
  - Strong isolation: separate VNET/subscription per tenant (best isolation, higher cost and ops).
  - Logical isolation: shared VNET with strict NSGs + dedicated subnets + per-tenant namespaces/tenants in DB (balanced cost/ops).
  - Hybrid: heavy customers get dedicated subscription; others use logical isolation.

Telemetry domain reduction (recommended initial four domains)
- Choose the four telemetry domains that cover the widest coverage with lowest duplication and cost:
  1. Network (Netflow, Zeek, DNS, Proxy logs) — high-value for lateral movement and exfil.
  2. Endpoint (EDR, sysmon, osquery, ebpf traces) — critical for host-centric detection.
  3. Identity (Auth logs, SSO, IAM events) — high importance for multi-tenant access control.
  4. Email (Inbound/outbound mail telemetry via Proofpoint/Mimecast or cloud SMTP logs) — phishing/BEC is high-impact.

Rationale: these four domains minimize cross-cloud egress by collecting from data sources closer to their origin (e.g., ingest EDR and email logs near tenant's region or provider). Additional domains (e.g., container runtime, cloud infra logs, application logs) can be added on request.

Multi-tenant considerations
- IAM: central identity provider (Azure AD) with delegated tenant roles. Use service principals with per-tenant scoped RBAC.
- Secrets: use Key Vault (or HashiCorp Vault) with per-tenant keys and KMS policies. Envelope encrypt blobs and DB fields.
- Networking: NSGs + UDRs + Azure Firewall with FQDN tags for egress control. Use private endpoints for storage and DB to avoid public egress.
- Observability: per-tenant metric/trace tagging; metrics aggregated but tenant-separated views in dashboards.
- Billing & Quotas: per-tenant storage buckets and S3 lifecycle policies to limit costs.

Latency & multi-domain ingestion
- Prefer regional ingestion: place ingestion endpoints in the same cloud region as log sources.
- Use compact batching (ingest agents buffer and compress) and use TLS keep-alive + HTTP/2 where possible.
- For cross-region events, prefer async durable queues (SQS/EventHub) with local ingest then cross-region replication for central analytics if needed.
- Use rate-limiting, EWMA-based smoothing, and backpressure signals to avoid spikes.

Security Controls Summary
- Network: Azure Firewall, NSGs, private endpoints, microsegmented subnets
- Data: SSE-KMS (per-tenant keys), object lock, immutable retention for forensic artifacts
- Identity: Azure AD center, conditional access, PIM for admin roles
- Supply chain: signed images for workloads, image scanning in CI (Syft/Grype)
- Operations: central SIEM with role-separated consoles and per-tenant RBAC

Next steps
- Produce Terraform guidance specific to Azure resources (VNETs, subnets, NSGs, private endpoints, KeyVault, storage accounts, EventHub) — see TERRAFORM_GUIDANCE.md.
- Review recommended four telemetry domains and optionally extend with tenant-request flow.
