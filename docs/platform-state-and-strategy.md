# Janusec Platform State, Strategy & Deployment Guide
**Date:** 2026-04-11 | **Audience:** CEO, CTO, Engineering Lead  
**This document is honest. It covers what works, what's missing, why someone should care, and what the legal exposure looks like if things go wrong.**

---

## Table of Contents
1. [Platform State — What Works Today](#1-platform-state)
2. [Blockers to Closed Beta and Production](#2-blockers)
3. [Live Connector Streaming — How It Actually Works](#3-live-connector-streaming)
4. [Cloud Coverage Matrix](#4-cloud-coverage-matrix)
5. [Forensic and On-Demand Ingest](#5-forensic-and-on-demand-ingest)
6. [Registry Attacks and Windows Telemetry](#6-registry-attacks-and-windows-telemetry)
7. [How Janusec Compares to the Market](#7-market-comparison)
8. [Deployment Options](#8-deployment-options)
9. [Single vs Multi-Tenant — The CEO's Decision](#9-single-vs-multi-tenant)
10. [Data Loss: Legal and Compliance Exposure](#10-data-loss-legal-exposure)

---

## 1. Platform State

### What a live company can use right now

| Capability | Status | Notes |
|-----------|--------|-------|
| AWS CloudTrail / GuardDuty / Macie / Detective / VPC Flow | ✅ Production | Full API integration, checkpointing |
| AWS Kinesis (stream) + SQS (long-poll) + EventBridge | ✅ Production | Push + EFO + DLQ retry |
| Azure Activity Log / Entra ID / Sentinel / Defender Cloud | ✅ Production | Full API integration |
| Azure Event Hub streaming + per-partition checkpoint | ✅ Production | Batch streaming with offset persistence |
| Azure Defender for Endpoint (MDE via Graph API) | ✅ Production | Security alerts via /v1.0/security/alerts |
| Sysmon event ingestion (JSON + EVTX) | ✅ Production | WEF + Sysmon normalized adapter |
| PCAP upload + network flow analysis (JA3/JA4/SNI) | ✅ Production | Magic-byte validated, 50MB limit |
| EVTX (Windows Event Log) upload | ✅ Production | Binary parsing via Evtx library |
| KAPE forensic artifact ingest | ✅ Production | Prefetch, AmCache, ShimCache, MFT, UserAssist, MRU, browser history |
| HopGraph multi-hop correlation | ✅ Production | WAL + snapshot + 40+ tests |
| Temporal RAG (BM25 + Ollama) | ✅ Production | Ring-buffer corpus, 2h window |
| Chain of custody T0/T1 | ✅ Production | SHA256-linked JSONL audit trail |
| Proofpoint TAP + Mimecast + Cofense + Abnormal Security | ✅ Production | Real API calls |
| Netskope + Zscaler connectors | ✅ Production | REST API v2 |
| URL risk scoring (entropy, homoglyph, redirect chain, DGA) | ✅ New | src/core/detectors/url_risk_scorer.py |
| Attachment risk (OLE, zip bomb, HTML smuggling, LNK) | ✅ New | src/core/detectors/attachment_risk_analyzer.py |
| BEC advanced scoring (EWMA baseline, reply-to, first-contact) | ✅ New | src/core/detectors/bec_scoring_model.py |
| Process tree anomaly (LOLBin, masquerade, cmdline rarity) | ✅ New | src/core/detectors/process_tree_anomaly.py |
| Persistence scoring (reg, service, task, WMI, LD_PRELOAD) | ✅ New | src/core/detectors/persistence_scoring_model.py |
| Advanced threats (fileless, eBPF, steg, supply chain, macros) | ✅ New | src/core/detectors/advanced_endpoint_threats.py |
| Compliance control matrix (CIS/NIST/ISO/SOC2/PCI/HIPAA) | ✅ New | src/core/mappings/factor_to_compliance.py |
| Registry attack detection (Run keys, IFEO, AppInit) | ✅ Production | 14+ patterns in persistence_scoring_model.py |

### What does NOT work yet

| Gap | Impact | Build time |
|-----|--------|-----------|
| GCP: no direct API connector (file adapter only) | Cannot ingest live GCP telemetry | 2–3 weeks |
| OCI: file adapter only, no API | Cannot ingest live OCI telemetry | 1–2 weeks |
| AWS Inspector: missing entirely | No vulnerability findings | 3 days |
| AWS CloudWatch Logs: stub (27 lines) | No application log ingest | 1 week |
| Azure Monitor: missing | No platform metrics / diagnostic logs | 1 week |
| Okta: no connector | No identity event ingestion from Okta | 1 week |
| CrowdStrike Falcon: missing | No EDR telemetry | 1–2 weeks |
| SentinelOne: missing | No EDR telemetry | 1–2 weeks |
| Splunk/Elastic/QRadar: reference only | No SIEM forwarding or pull | 2 weeks each |
| Persona templates: 5/8 are stubs | CISO/Executive/ThreatHunter/Compliance/MSSP return analyst output | 1–2 days each |
| Bitemporal T2–T8 states: not built | Analyst review loop doesn't close | 1 sprint |
| Graph/Timeline/Compliance UI tabs | Placeholder only | 2–4 weeks |
| Assessment data backup | Data loss if disk fails | 3–5 days |
| Memory dump parsing | No Volatility / raw memory forensics | 2–3 weeks |
| Raw registry hive (.hive) parsing | KAPE output only, not raw hives | 1 week |

---

## 2. Blockers

### Closed Beta (ship this first)

These are the actual blockers — nothing else matters until these are done:

1. **Persona templates** — CISO and Threat Hunter are the two personas a CISO demo will ask for. 1 day each. Do these first.
2. **Analyst review endpoint** (`POST /{assessment_id}/analyst_review`) — Without this, the bitemporal loop never closes. The model updates its assessment after human review; this is the core product differentiator. 3 days.
3. **HopGraph chain narrative in Tier 2 prompt** — `hopgraph_explain_chain()` is already computed, just not passed to the LLM. This is the single highest-ROI change. 1 day.
4. **Assessment backup** — A customer losing all their data in closed beta is a company-ending event. Implement nightly S3/Azure Blob copy of `data/assessments/`. 3 days.
5. **Test API keys** — Remove hardcoded `testkey` fallbacks from production endpoints before any external access.
6. **GCP file adapter → real API** — If any closed beta customers are on GCP, this must ship. 2–3 weeks.

### Production (after closed beta)

1. Okta connector (1 week)
2. CrowdStrike or SentinelOne connector (1–2 weeks)
3. AWS Inspector (3 days)
4. Azure Monitor (1 week)
5. Full D3.js graph tab in investigate.html
6. Compliance report generation (MITRE ATT&CK mapping, PDF export)
7. Playbook execution wiring (not just suggestions — actual remediation)
8. SQLite persistence enabled by default for HopGraph

---

## 3. Live Connector Streaming — How It Actually Works

### Architecture: Hybrid push + poll, all normalized to Redis

```
Cloud Provider Events
    │
    ├── AWS Kinesis (EFO push or poll)        → redis XADD ingest_stream
    ├── AWS SQS (long-poll, 20s, DLQ retry)  → redis XADD ingest_stream
    ├── Azure Event Hub (batch streaming,      → redis XADD ingest_stream
    │     per-partition checkpoint)
    ├── Proofpoint/Mimecast/Cofense API poll  → redis XADD ingest_stream
    └── Sysmon/WEF JSON push                  → redis XADD ingest_stream
         │
         ▼
    Ingest Worker (reads Redis stream)
         │
         ▼
    Event normalization → canonical EventV2 envelope
    (ts, src_ip, dst_ip, port, protocol, ingest_source, tenant_id)
         │
         ├── HopGraph node/edge ingestion (WAL write)
         ├── Temporal RAG corpus update
         ├── DREAD scoring
         ├── ML Pipeline (url_risk, attachment, BEC, process_tree, persistence, advanced)
         └── Tier 1 LLM triage → SSE push to frontend
```

### Durability guarantees per connector

| Connector | Checkpoint mechanism | Failure recovery |
|-----------|---------------------|-----------------|
| Kinesis | Sequence number to `data/kinesis_checkpoints/` | Replay from last checkpoint on restart |
| SQS | Visibility timeout + DLQ after 3 retries | Message returns to queue, DLQ catches persistent failures |
| Azure Event Hub | Per-partition offset in memory + file | Restarts from last offset per partition |
| SQS DLQ | Manual review queue | Ops must drain DLQ periodically |

### What's missing from streaming

- No Kafka consumer (referenced in provisioning code but not implemented)
- No back-pressure signal from HopGraph to ingest worker (fast producer + slow HopGraph = OOM risk under load)
- No Redis persistence config verification at startup (if Redis dies, in-flight events are lost)

---

## 4. Cloud Coverage Matrix

### Honest status

| Cloud | Live streaming | API integrated | File adapter | Missing |
|-------|---------------|----------------|--------------|---------|
| **AWS** | ✅ Kinesis, SQS | ✅ CloudTrail, GuardDuty, SecurityHub, Macie, Detective, VPC Flow, Config, EventBridge | — | Inspector, CloudWatch Logs (stub) |
| **Azure** | ✅ Event Hub | ✅ Activity Log, Entra ID, Sentinel, Defender, NSG Flow, MDE (Graph API) | — | Azure Monitor |
| **GCP** | ❌ | ❌ | ✅ SCC (JSON file poll), Cloud Audit (JSON file poll) | Pub/Sub, Cloud Armor, VPC Flow, Chronicle |
| **OCI** | ❌ | ❌ | ✅ Cloud Guard (JSON file poll) | Everything else |
| **Email security** | Poll | ✅ Proofpoint, Mimecast, Cofense, Abnormal | — | Native Gmail Pub/Sub watcher |
| **SSE/CASB** | Poll | ✅ Netskope, Zscaler | — | Symantec CloudSOC, McAfee MVISION |
| **EDR** | Push (Sysmon/WEF) | ✅ MDE (Graph) | — | CrowdStrike, SentinelOne, Carbon Black, Elastic Defend |
| **SIEM** | ❌ | ❌ | ❌ | Splunk, Elastic, QRadar, Microsoft Sentinel pull |

### What GCP real-time integration needs

GCP currently requires a customer to manually export SCC findings to a JSON directory that Janusec polls. For production:

1. **Pub/Sub subscriber** — subscribe to `projects/{project}/topics/scc-findings` → push to Redis ingest stream. ~1 week.
2. **Cloud Logging sink** → Pub/Sub → Janusec subscriber for Audit Logs and VPC Flow. ~1 week.
3. **Chronicle Forwarder** API — Chronicle feeds pre-normalized events. ~2 weeks.

### What Azure still needs

1. **Azure Monitor Diagnostic Logs** — platform metrics and resource logs not currently ingested. 1 week.
2. **Azure Purview** — currently a stub that falls back to synthetic enrichment. Wire real Purview API for data classification signals. 1 week.

### What VMware / Nutanix / OpenStack would need

These are private cloud, not public cloud. They have no managed security services equivalent to GuardDuty. The integration path is:

| Platform | Integration approach | Data available |
|---------|---------------------|----------------|
| **VMware vSphere** | vCenter REST API (events endpoint) or syslog forwarding via VMware Log Insight | VM power events, admin actions, network events |
| **Nutanix Prism** | Prism Central REST API v3 (audit events, alerts) | Infrastructure events, VM lifecycle, cluster health |
| **OpenStack** | Keystone event notifications via AMQP/RabbitMQ | Identity, compute, network events |
| **Proxmox** | Syslog forwarding + API polling | VM events, resource usage |

None of these exist in Janusec today. 1–2 weeks each. VMware and Nutanix are reasonable for enterprise sales; Proxmox and OpenStack are niche.

---

## 5. Forensic and On-Demand Ingest

### What works today for threat hunters and forensic analysts

| Format | Status | What's extracted |
|--------|--------|-----------------|
| PCAP / PCAPNG | ✅ Production | Flow events, JA3/JA3S/JA4, SNI, src/dst |
| EVTX (Windows Event Log) | ✅ Production | All event IDs, normalized |
| KAPE triage package | ✅ Production | Prefetch, AmCache, ShimCache, MFT, UserAssist, MRU, browser history, registry Run keys |
| JSON / JSONL | ✅ Production | Passthrough normalization |
| CSV / TSV / XLSX | ✅ Production | Multi-header auto-detect |
| ZIP / TAR / GZIP | ✅ Production | Container extraction, routes inner files |
| Sysmon JSON | ✅ Production | WEF + normalized endpoint events |
| Generic .log / .txt | ✅ Production | Pattern-based parsing |

### What forensic analysts need that's missing

| Format | Status | Priority | Build time |
|--------|--------|----------|-----------|
| Wireshark PCAP (already works) | ✅ | — | — |
| KAPE output (already works) | ✅ | — | — |
| Raw registry hive files (.hive) | ❌ | High | 1 week — use python-registry library |
| Windows Defender XML log files | ❌ | Medium | 3 days |
| Memory dump (raw / full) | ❌ | Medium | 2–3 weeks — Volatility integration |
| LNK file forensics | Partial (attachment detector) | Medium | 3 days |
| $MFT raw parse | Partial (KAPE output) | Medium | 1 week |
| Prefetch deep analysis | Partial (KAPE) | Medium | 3 days |
| ETW (Event Tracing for Windows) | ❌ | Low | 2 weeks |
| macOS Unified Logs | ❌ | Low | 2 weeks |

### Forensic workflow today (what works end-to-end)

```
Investigator has a compromised machine image
    │
    ├── Run KAPE on machine → exports triage package
    ├── Upload KAPE package to /api/v1/upload → Janusec ingests
    │     AmCache, ShimCache, Prefetch, UserAssist, MFT, browser history
    │
    ├── Export Windows Event Logs (.evtx) → upload
    │     All event IDs parsed and normalized
    │
    ├── Capture PCAP (Wireshark) → upload
    │     Network flows, JA3, SNI extracted
    │
    └── HopGraph correlates: process → network → identity → persistence
          Temporal RAG searches for LOLBIN/C2/persistence patterns
          Tier 2 LLM generates forensic persona report
```

---

## 6. Registry Attacks and Windows Telemetry

### Registry attack detection coverage

| Attack technique | MITRE | Status | Where detected |
|-----------------|-------|--------|----------------|
| Run/RunOnce key write | T1547.001 | ✅ | persistence_scoring_model.py |
| Image File Execution Options hijack | T1546.012 | ✅ | persistence_scoring_model.py |
| AppInit_DLLs modification | T1546.010 | ✅ | persistence_scoring_model.py |
| KnownDLLs hijacking | T1574.001 | ✅ | persistence_scoring_model.py |
| Session Manager AppInit | T1547 | ✅ | persistence_scoring_model.py |
| Winlogon Userinit hijack | T1547 | ✅ | persistence_scoring_model.py |
| ShimCache unsigned entry | — | ✅ | registry_forensics.py |
| UserAssist spike | — | ✅ | registry_forensics.py |
| Registry-based LOLBIN correlation | T1218 | ✅ | correlation rules (registry_run_keys_enriched.py) |
| Raw .hive file parse | — | ❌ | Not implemented |
| COM object hijacking | T1546.015 | ❌ | Not implemented |
| Accessibility features hijacking | T1546.008 | ❌ | Not implemented |
| Port Monitors DLL | T1547.010 | ❌ | Not implemented |

### Windows EDR telemetry path

```
Windows machine
    │
    ├── Sysmon → JSON events → POST /api/v1/ingest/sysmon
    │     Process creation (Event 1), network (Event 3), file (Event 11),
    │     registry (Event 12/13/14), driver load (Event 6), DNS (Event 22)
    │
    ├── WEF (Windows Event Forwarding) → POST /api/v1/ingest/wef
    │     Security events (4688, 4624, 4625, 4648, 4672, 4698, 4720)
    │
    ├── EVTX upload → parse all event IDs
    │
    └── MDE (Microsoft Defender for Endpoint) → Graph API pull
          Security alerts normalized to NormalizedEmailEvent
```

### What's missing for full Windows coverage

- **COM object hijacking detection** — registry-based, high-value persistence technique
- **WMI repository parsing** — offline forensics for persistent WMI subscriptions
- **Sysmon Event 25** (process tampering) — process hollowing at OS level
- **ETW provider monitoring** — real-time visibility into .NET/CLR execution

---

## 7. How Janusec Compares to the Market

### The honest competitive landscape

| Platform | Type | Strengths | Weaknesses vs. Janusec |
|---------|------|-----------|----------------------|
| **CrowdStrike Falcon** | EDR + XDR | Best-in-class endpoint telemetry, threat intel | Cloud-only, expensive ($150–300/endpoint/yr), no self-hosted, no multi-cloud correlation graph |
| **Microsoft Sentinel** | Cloud SIEM | Native Azure integration, massive rule library, Copilot | Azure-only SIEM, no OSS, expensive at scale ($2–4/GB), no multi-cloud HopGraph |
| **SentinelOne Singularity** | XDR | Strong autonomous response, STAR rules | No open architecture, $70–150/endpoint/yr, no bitemporal reasoning |
| **Palo Alto Cortex XDR** | XDR | Deep packet inspection, ML anomaly | Requires Palo Alto stack, very expensive, closed ecosystem |
| **Splunk Enterprise Security** | SIEM | Best log aggregation, massive ecosystem | $150/GB/day, no native AI correlation, no HopGraph, expensive at any scale |
| **Elastic Security** | SIEM + EDR | Open source, cheap storage | Requires Elastic Defend agent, manual rule tuning, no AI corroboration |
| **Wiz** | Cloud security posture | Agentless cloud scanning, excellent CSPM | No runtime threat detection, no EDR, no email, no SIEM |
| **Lacework** | Cloud-native threat detection | ML-based cloud anomaly | Cloud-only, no on-prem, no email/endpoint, expensive |
| **Vectra AI** | Network + identity AI | Good NDR, Attack Signal Intelligence | NDR-only, $200K+ entry, no self-hosted |

### Why someone should choose Janusec

**1. Self-hosted sovereign deployment**  
Every competitor above is cloud-delivered SaaS. Janusec can run on a customer's GPU box, a private NAS, Nutanix, VMware, or OpenStack. For regulated industries (banking, defence, healthcare) where data cannot leave the building, this is a non-negotiable differentiator.

**2. Multi-cloud correlation in a single graph**  
Competitors specialize by cloud or vector. CrowdStrike sees the endpoint. Sentinel sees Azure. Wiz sees cloud posture. None of them natively connect an AWS CloudTrail event → Azure Entra identity → Sysmon process chain → Proofpoint email lure into a single hop-graph that reasons across all of them simultaneously. Janusec does.

**3. Human review as a signal, not an endpoint**  
Most XDR platforms treat analyst labels as terminal output. Janusec treats them as input to a better second reasoning pass (bitemporal re-evaluation). Over time, per-tenant false positive suppression emerges organically from adjudication history — without manual tuning.

**4. Forensic ingest + live streaming in the same platform**  
Most platforms are either SIEM (live streaming) or forensic tools (KAPE, Autopsy). Janusec does both: live connector streaming + KAPE triage upload + PCAP + EVTX + CSV, all correlated into the same HopGraph.

**5. Cost profile**  
With local models (Ollama + Llama 3.3 70B), zero per-query AI cost. With Groq for correlated clusters, ~$0.001 per analysis. Compare to Splunk at $150/GB/day or Sentinel at $2–4/GB.

**6. Compliance-native**  
Factor → CIS / NIST CSF / ISO 27001 / SOC2 / PCI-DSS / HIPAA / GDPR control matrix is built-in. Most competitors require third-party compliance overlays or manual mapping.

**Where Janusec loses today:**  
- No agent (can't do EDR without Sysmon or MDE integration)  
- No threat intel feed integration (VirusTotal, MISP, TAXII)  
- No autonomous response / SOAR execution  
- GCP/OCI are not production-grade yet  
- Brand recognition is zero (a startup problem, not a product problem)

---

## 8. Deployment Options

### Hardware requirements (minimum / recommended)

| Profile | CPU | RAM | GPU | Storage | Use case |
|---------|-----|-----|-----|---------|----------|
| **Minimum (CPU only)** | 8-core x86 | 32GB | None | 2TB SSD | Demo/dev, small customer, LocalDeterministicClient |
| **Recommended (local LLM)** | 16-core x86 | 64GB | RTX 4090 / A10G (24GB VRAM) | 4TB NVMe | Tier 1/2 with Ollama Llama 3.3 70B |
| **Production (local 70B)** | 32-core | 128GB | 2× A100 80GB or H100 | 8TB NVMe RAID | Full local inference, no cloud AI |
| **Production (cloud AI)** | 8-core | 32GB | None | 2TB SSD | Groq/Claude API for Tier 2/3, local for Tier 1 |

### Deployment targets

#### 1. Single GPU workstation (customer's own machine)
```
Requirements: 64GB RAM, RTX 4090 or better, Ubuntu 22.04 or Windows 11 Pro
Install: pip install -r requirements.txt + docker-compose for Redis + Ollama
LLM: Ollama with llama3.3:70b (local, no cloud API needed)
Connectors: AWS + Azure + local KAPE/EVTX upload
Data: Local SSD, optionally S3 backup
Cost: Hardware one-time, ~$0 ongoing AI cost
```

#### 2. AWS deployment (EC2 + managed services)
```
Recommended instance: g5.4xlarge ($1.62/hr, NVIDIA A10G 24GB) or p3.2xlarge (V100 16GB)
Alternative (no GPU): c7i.8xlarge → Groq API for LLM
Storage: EBS gp3 + S3 for assessment backup
Redis: ElastiCache (t3.medium)
Deploy: docker-compose or ECS Fargate
Connectors: All AWS connectors native, Azure via cross-cloud credentials
Estimated cost: $1,200–2,500/month all-in for a mid-size customer
```

#### 3. Azure deployment (VM + managed services)
```
Recommended instance: NC24ads A100 v4 ($3.67/hr) or Standard_D8s_v3 + Azure OpenAI
Storage: Managed Disk Premium + Azure Blob for backup
Redis: Azure Cache for Redis (C1)
Deploy: Docker Compose or AKS
Connectors: All Azure connectors native
```

#### 4. Private cloud — Nutanix / VMware / OpenStack
```
VM requirements: 64GB RAM, GPU passthrough (NVIDIA), 2TB storage
OS: Ubuntu 22.04 LTS
Deploy: Docker Compose
LLM: Ollama local (no external API)
Connectors: CSV/EVTX/KAPE upload + syslog/Sysmon forwarding
Network: Air-gapped capable (no internet required if using local LLM)
This is the sovereign deployment story for defence/banking
```

#### 5. NAS + GPU workstation (home lab / small business)
```
Example: Synology NAS (RAID for storage) + separate workstation with RTX 4090
NAS: Assessment storage, backups, KAPE uploads via SMB mount
GPU box: Runs Janusec + Ollama
Network: LAN only, no internet exposure required
Cost: ~$3,000 hardware one-time
This is the "security analyst's personal XDR" use case
```

#### 6. Air-gapped deployment
```
Fully offline capable if:
- LLM_PROVIDER=ollama (local model)
- No cloud connectors configured
- Input: KAPE packages, EVTX files, PCAP uploads via local network
- Output: Local assessments, HopGraph, reports
Use case: Classified environments, military, nuclear, critical infrastructure
```

### Docker Compose quick start (any deployment)
```yaml
# docker-compose.yml (conceptual — validate against actual repo)
services:
  janusec:
    build: .
    environment:
      - LLM_PROVIDER=ollama
      - OLLAMA_HOST=http://ollama:11434
      - REDIS_URL=redis://redis:6379
      - DEFAULT_TENANT=customer-001
      - ALLOW_DEFAULT_TENANT=1
    volumes:
      - ./data:/app/data
    ports:
      - "8000:8000"
  
  ollama:
    image: ollama/ollama
    volumes:
      - ollama_models:/root/.ollama
    deploy:
      resources:
        reservations:
          devices:
            - capabilities: [gpu]

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes  # enable persistence
```

---

## 9. Single vs Multi-Tenant — The CEO's Decision

### The CEO's instinct is correct

Multi-tenant SaaS has real legal and operational problems for a security platform:

**Problem 1: Cross-tenant data contamination risk**  
In multi-tenant mode, a bug in tenant isolation code can expose one customer's security events to another. For a security platform, this is existential — not just embarrassing.

**Problem 2: Data sovereignty / residency law**  
Australia's Privacy Act 1988 and the US state privacy laws (CCPA, CPRA, etc.) impose data residency obligations. If a customer's security telemetry is co-mingled on shared infrastructure, determining "where is the data?" becomes legally complex.

**Problem 3: Discovery and subpoena risk**  
If Janusec operates as a multi-tenant SaaS, a subpoena targeting one customer's data could pull the entire platform into legal proceedings affecting other customers.

**Problem 4: Liability for breach of another customer's data**  
If a security event from Customer A causes a data breach that exposes Customer B's telemetry (due to a multi-tenant bug), Janusec is liable to both.

### The single-tenant model is already supported

The codebase has:
- `DEFAULT_TENANT` env var — all data under one tenant
- `ALLOW_DEFAULT_TENANT=1` — no X-Tenant-ID header required
- `data/tenants/{tenant_id}/` — separate directories per tenant (works for single tenant too)

### Recommended go-to-market model

**"Bring your own infrastructure"** — Janusec licenses the software. The customer deploys it in their own AWS account, Azure subscription, GPU box, or private cloud. Janusec never touches the customer's data.

This eliminates:
- Data sovereignty concerns (customer's data never leaves their infrastructure)
- Multi-tenant data contamination risk
- Subpoena exposure for other customers' data
- GDPR/Privacy Act data controller obligations (customer is the controller, Janusec is the vendor)

**Pricing model options:**
- Per-node/connector license (like Elastic)
- Annual software license + support
- Usage-based (per assessment/event) if they want SaaS

---

## 10. Data Loss: Legal and Compliance Exposure

### Scenario: Janusec loses all ingested and analysed data

This section covers what happens legally if the data in `data/assessments/`, `data/chain_of_custody.jsonl`, and `data/hopgraph_wal.log` is destroyed — whether by ransomware, hardware failure, accidental deletion, or a disgruntled employee.

### Australia

**Privacy Act 1988 (Cth) + Australian Privacy Principles (APPs)**

Security events can contain personal information (IP addresses, usernames, email addresses, device names). If Janusec holds this on behalf of a customer and loses it:

- **APP 11 (Security of personal information)**: Must take reasonable steps to protect personal information from loss, interference, and misuse. Data loss due to absence of backup = potential breach of APP 11.
- **Notifiable Data Breaches (NDB) scheme** (Part IIIC): If lost data contains personal information and is likely to result in serious harm (e.g., security event data showing a breach that wasn't remediated because the records were lost), the organisation must notify the Australian Information Commissioner (OAIC) and affected individuals within 30 days.
- **Penalties (post-2022 amendments)**: Up to $50M per breach, or 30% of adjusted turnover for the relevant period, whichever is greater.

**Critical Infrastructure Act 2018 (SOCI Act)**  
If Janusec is deployed by an entity covered by SOCI (banking, energy, water, comms, defence industry), loss of security incident logs may trigger:
- Obligation to notify the Australian Signals Directorate (ASD)
- Potential intervention by ASD or Home Affairs
- Mandatory incident reporting under the cyber security incident reporting requirements

**ASIC regulatory requirements (financial services customers)**  
Financial services entities must retain records for 7 years. Loss of security event records = regulatory breach with ASIC.

**Evidence Act 2011 (Cth)**  
Lost chain of custody data may render Janusec's forensic outputs inadmissible in any criminal or civil proceeding. If a customer is trying to prove a cyber crime occurred and the evidence is gone, Janusec may face negligence claims.

### United States

**GDPR (if EU data subjects involved)**  
If any EU persons' data appears in security events (common in multinational corps), GDPR Article 32 requires appropriate technical measures to ensure data security. Data loss = potential regulatory action by EU supervisory authorities. Fines up to €20M or 4% of global annual turnover.

**HIPAA (healthcare customers, 45 CFR § 164.312)**  
Security event data in healthcare environments may be classified as PHI (Protected Health Information) or ePHI. Loss = potential breach of the HIPAA Security Rule. HHS Office for Civil Rights investigates. Fines: $100–$50,000 per violation, up to $1.9M per calendar year per violation category.

**SEC Cybersecurity Disclosure Rules (Rule 13a-1)**  
Public companies must disclose material cybersecurity incidents within 4 days. If Janusec holds the evidence of an incident and loses it, the company cannot make the required disclosure. Janusec could face civil liability for contributing to a failed disclosure obligation.

**State breach notification laws (all 50 states)**  
California (CCPA/CPRA), New York (SHIELD Act), Texas, etc. all have breach notification obligations. If lost data contained PII from state residents, notification timelines apply (typically 30–72 hours after discovery).

**Computer Fraud and Abuse Act (CFAA) and ECPA**  
Not directly applicable to data loss, but relevant if the loss was caused by a third party accessing Janusec infrastructure.

**SOC 2 Type II obligations**  
If Janusec or its customers are SOC 2 audited, loss of audit logs (chain of custody, assessment history) means the audit evidence for the period is destroyed. This will result in a qualified SOC 2 opinion and potential loss of certifications.

### The minimum viable data protection posture

To avoid most of the above exposure, implement before closed beta:

| Control | What it does | Build time |
|---------|-------------|-----------|
| Nightly backup of `data/assessments/` to S3 or Azure Blob | Protects against disk failure, accidental deletion | 3 days |
| Enable SQLite persistence for HopGraph (`HOPGRAPH_PERSISTENCE_ENABLED=1`) | WAL + SQLite = two independent recovery paths | 1 day (config change) |
| Enable Redis persistence (`appendonly yes`) | In-flight events survive process restart | 1 day (config change) |
| Data retention policy endpoint (`DELETE /api/v1/tenant/{id}/data?retention_days=90`) | Customer controls their own data lifecycle | 3 days |
| Backup integrity verification (daily hash check of backup vs source) | Detect silent corruption | 2 days |
| Chain of custody immutable log (append-only, no delete API) | Preserve forensic evidence integrity | 1 day (remove delete endpoint if one exists) |

### What the BRING YOUR OWN INFRASTRUCTURE model does to liability

If the customer deploys Janusec on their own infrastructure:
- Janusec (the company) is a **data processor** under GDPR, or potentially not a data processor at all if no personal data passes through Janusec's systems
- The customer is the **data controller** — they own the obligation
- Janusec's liability is limited to the software license terms (negligence for defective software vs. data loss is a different legal question)
- This is exactly why the single-tenant BYOI model is the right go-to-market for a startup — it dramatically reduces legal exposure

**The one liability that remains regardless of deployment model:** If Janusec's software has a bug that causes data loss (e.g., a WAL corruption bug), and the customer suffers regulatory penalties as a result, there is potential negligence or product liability exposure. This is addressed by: (a) robust testing, (b) appropriate limitation of liability clauses in the license agreement, and (c) cyber insurance.

---

## Summary

**Platform state:** Closed beta ready for AWS + Azure today. GCP requires 2–3 weeks to make real.

**Biggest risks before beta:** No assessment backup, 5 of 8 persona templates are stubs, analyst review loop not closed.

**Market position:** The only self-hosted, multi-cloud, HopGraph-correlated, forensic-capable XDR with built-in compliance mapping. The sovereign deployment story is genuinely differentiating for regulated industries.

**Deployment recommendation:** BYOI single-tenant. Customer's infrastructure. Janusec never touches the data. Dramatically reduces legal exposure for a startup.

**Data loss legal exposure:** Significant in Australia and US if Janusec is a SaaS multi-tenant platform. Negligible if BYOI model is used and customer controls their own backup posture.
