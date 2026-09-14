# JanuSec — Azure AI Foundry Deployment Architecture

> **Purpose.** How to deploy the JanuSec AI-assisted breach-assessment platform on Azure with **Azure AI Foundry** as the inference + governance layer, in a highly-available, data-sovereign topology suitable for a regulated ANZ client (e.g. a water utility / critical-infrastructure operator).
>
> **Audience.** Solution architect + platform engineering. Doubles as interview-prep reference.
>
> **Status.** Architecture design. JanuSec today runs on local Ollama; this document is the Foundry-target deployment blueprint. Nothing here is deployed to production yet.

---

## 0. TL;DR — the one-paragraph version

JanuSec is **deterministic-first**: an auditable scoring engine owns every verdict and the LLM *only narrates* it. That single design fact is what makes this deployment clean — **Azure AI Foundry is not "the app," it's a swappable inference + governance layer** that slots in exactly where the local Ollama call sits today. The provider abstraction is *already wired* (`azure_openai` is a first-class provider in `src/core/config/tenant_llm_config.py` alongside bedrock/vertex), so switching inference to Foundry is a **configuration + endpoint change, not a re-architecture.** The rest of the platform — FastAPI orchestrator, DuckDB ingest, HopGraph, detectors, aggregation — runs as your own containers on Azure compute. The two hard parts are (1) **externalising the in-process state** (DuckDB/SQLite single-writer files, `REPORT_STORE`, in-proc workers) before you can run more than one node, and (2) **choosing the inference substrate** (managed Azure OpenAI vs open-weight on GPU vs Foundry Local air-gapped) — a data-residency vs cost trade.

---

## 1. What JanuSec actually is (runtime reality)

Before deploying, be honest about the shape of the thing. (Verified against the codebase, not the marketing.)

| Layer | Reality | Deployment consequence |
|---|---|---|
| **API** | One large **FastAPI + Uvicorn monolith** on **:8080** (`src/api/server.py` → `src/api/app.py`, ~150 routers). Route-loading gated by `LOAD_FULL_ROUTES` / `PLATFORM_LITE_INIT`. | Stateless-*ish* front tier — but see in-memory state below. Binds fast (deferred post-startup), so probes work. |
| **Background workers (in-proc)** | Ingest worker (`assessment_worker.py` `_worker_loop`), investigate worker (`deep_analyze_endpoints.py`), SSE flush, schedulers (enrichment/embedding/trainer/backups/hopgraph), cloud pollers — all started in the FastAPI **lifespan**. | These are **singletons**. Running N API replicas would run N copies of each worker → duplicate work. Must be split into a dedicated single-instance worker role. |
| **Separate worker processes** | `python -m src.workers.llm_worker` (RQ + Redis LLM queue), `redis_streams_consumer`, `syslog_collector_runner`, Kafka pipeline workers. | Already designed as separate deployables — good. Map 1:1 to Azure workloads. |
| **LLM inference** | **Local Ollama** (`:11434`), `qwen2.5:14b` (T1 narrator) / `qwen3.6:27b` (T2) / `qwen3:14b` fallback. **Serial** narration (`JANUSEC_NARRATOR_CONCURRENCY=1`) for single-GPU OOM safety. ~15–25 sequential model calls per investigation. Cloud providers (`azure_openai`, openai, anthropic, bedrock, vertex) already wired but dormant. | The GPU workload. This is the piece Foundry replaces/augments. |
| **Durable state** | **Redis** (mandatory for the worker/queue path — `EVENT_QUEUE`, LLM queue, dedup). **Postgres** wired but *optional* with silent SQLite fallback (`.env` currently points at a **Neon** cloud DSN). | Redis + Postgres are your externalised state — good. |
| **Embedded state (the problem)** | **DuckDB** (`data/ingest/assessments.duckdb`) + ~20 **SQLite** files (hopgraph, sessions, decision trace) — all **single-writer, in-process**. Plus in-memory `REPORT_STORE`, `INVESTIGATE_QUEUE`, per-replica rate limits, `ServerRuntime` ring buffers, `GLOBAL_HOPGRAPH`. | **The #1 HA blocker.** These cannot be shared across nodes over NFS/Files — they corrupt. Must be externalised or the roles pinned. |
| **Vector / RAG** | TemporalRAG (in-mem, Ollama `nomic-embed-text` with **BM25 fallback**), optional pgvector (`vector(384)`, best-effort). No neural reranker. | Light. CPU-friendly. Maps to Azure AI Search when you want managed RAG. |
| **Neo4j** | **Dormant** — bridge exists, `NEO4J_URI` never set, not called from the pipeline. The real graph is in-memory HopGraph + SQLite. | Ignore for deployment. Don't provision it. |
| **Existing deploy artifacts** | `Dockerfile` (:8080, non-root, `/health`), `docker-compose.yml` (db/redis/app/worker/ollama/prometheus/grafana + Kafka profile), `k8s/deployment.yaml` (2 replicas, HPA, ingress), **mature `charts/janusec/` Helm chart** (pgbouncer, redis-ha/Sentinel, oauth2-proxy OIDC, jaeger, PDB, NetworkPolicy, ServiceMonitor). | You are **not** starting from zero. The Helm chart is production-shaped and is the fastest path onto AKS. |

**Two red flags to fix before any multi-node deploy** (both real, both in the current tree):
1. `k8s/deployment.yaml` mounts `data/` as a **single `ReadWriteMany` PVC across 2 replicas** — this shares the DuckDB/SQLite files across pods and **will corrupt them**. Must change (externalise state, or pin to one writer).
2. The committed `.env` contains a **live Neon Postgres password** and `SECRET_KEY=dev-secret-key-change-in-production`. **Rotate + move to Key Vault before anything ships.**

---

## 2. Where Azure AI Foundry fits

Foundry is the managed realisation of the pattern JanuSec already implements by hand. It replaces the **Ollama call** and adds the **governance layer** — nothing else.

```
                         ┌─────────────────────────────────────────────┐
   evidence upload ─────▶│  JanuSec FastAPI orchestrator (YOUR code)   │
                         │  parse → cluster → detect → AGGREGATE        │
                         │  ┌───────────────────────────────────────┐  │
                         │  │  Verdict engine — DETERMINISTIC        │  │  ← owns the verdict
                         │  │  (scoring, DREAD, MITRE, ISO mapping)  │  │    (unchanged, no LLM)
                         │  └───────────────────────────────────────┘  │
                         │              │ narrate this cluster          │
                         └──────────────┼───────────────────────────────┘
                                        ▼
                    ╔═══════════════════════════════════════════════╗
                    ║        AZURE AI FOUNDRY (inference + gov)      ║
                    ║  Model catalog / endpoint  ◀── narrator/critic ║
                    ║  Content Safety (I/O guardrails)               ║
                    ║  Evaluations (groundedness, coherence) → CI    ║
                    ║  [Agent Service — optional orchestration]      ║
                    ║  [AI Search — optional managed RAG]            ║
                    ╚═══════════════════════════════════════════════╝
```

### 2.1 The provider swap (already wired)
JanuSec's `LLMClient` / `llm_router.py` / `tenant_llm_config.py` already select provider by config. To point at Foundry:

```
LLM_PROVIDER=azure_openai
AZURE_OPENAI_ENDPOINT=https://<foundry-project>.openai.azure.com/   # or a managed-compute endpoint
AZURE_OPENAI_API_KEY=<from Key Vault / Managed Identity>            # prefer MI over key
LLM_STRICT_PROVIDER=1                                               # already prod default
```

The deterministic fallbacks in every LLM stage (narrator, critic, prefill) mean the pipeline **degrades gracefully** if the endpoint is slow/unavailable — this is a genuine reliability story for the interview.

### 2.2 Model mapping

| JanuSec tier | Local (today) | Foundry option A — **managed** | Foundry option B — **open-weight, sovereign** |
|---|---|---|---|
| **T1 narrator** (fast, clean-JSON) | `qwen2.5:14b` | Azure OpenAI `gpt-4o-mini` | Qwen/Llama-3.1-8B on **Managed Compute** endpoint |
| **T2 quality** (top cluster, conf ≥ 0.88) | `qwen3.6:27b` | `gpt-4o` | Qwen2.5-32B / Llama-3.3-70B on Managed Compute |
| **Critic** (adversarial 2nd pass) | `qwen2.5:14b` | `gpt-4o-mini` | same as T1 pool |
| **Embeddings** (RAG) | `nomic-embed-text` (BM25 fallback) | `text-embedding-3-large` | keep BM25 / all-MiniLM on CPU |

> **Design note for the interview:** keeping the *same open-weight models* on Foundry Managed Compute (Option B) makes the "portable by design" claim literally true and preserves data residency. Option A (Azure OpenAI) is faster to stand up but **sends evidence to a shared managed model** — unacceptable for the air-gap persona. State this trade explicitly; it shows you understand sovereignty, not just deployment.

### 2.3 Governance = your ISO / EU AI Act evidence-by-design
This is JanuSec's whole thesis, and Foundry gives you managed hooks for it:
- **Azure AI Content Safety** on prompt inputs and model outputs → prompt-injection / jailbreak / harmful-content gate. Maps to EU AI Act risk controls.
- **Foundry Evaluations** (groundedness, relevance, coherence) run in **CI** on a golden set → continuous assurance that narration stays grounded in evidence. This is your `pytest -m acceptance` golden harness, promoted to a managed eval.
- **Azure Monitor + tracing** → the audit trail / decision provenance, traceable per ISO 27001 / ISO 42001.
- The **deterministic verdict engine stays in your code** — Foundry never owns the decision. That boundary *is* the auditability guarantee.

---

## 3. Two deployment modes (match JanuSec's two personas)

### Mode A — Cloud sovereign (recommended default)
Everything in **your Azure tenant**, evidence never leaves it. Open-weight models on a **Foundry Managed Compute GPU endpoint** (Option B above). Front-tier + workers on **AKS**. PaaS (Postgres/Redis/AI Search/Foundry) reached over **Private Link** — no public egress.

### Mode B — Air-gapped / on-prem (the sovereignty ace)
For a client that cannot send evidence to any cloud (critical infrastructure, classified data): **Foundry Local** runs the same catalog models **on the customer's own hardware**, fully disconnected. JanuSec's existing air-gap design (BM25 fallback, local deterministic client, no mandatory egress) already fits this. Same governance controls, local execution. **This is the differentiator off-the-shelf SaaS can't offer** — lead with it for a utility client.

---

## 4. Target Azure topology (Mode A — the full picture)

```
 Users / SOC analysts / connectors
             │  HTTPS
             ▼
   ┌───────────────────────┐    global anycast, TLS, caching
   │  Azure Front Door     │    (optional; multi-region)
   └──────────┬────────────┘
              ▼
   ┌───────────────────────┐    L7 WAF (OWASP), regional
   │  Application Gateway   │    session affinity (cookie) ← needed for sticky routing
   │  (WAF v2)             │
   └──────────┬────────────┘
              ▼   private VNet
 ┌────────────────────────────────────────────────────────────────┐
 │  AKS cluster (VNet-integrated, Azure CNI)                       │
 │                                                                 │
 │  ┌──────────────────┐   ┌──────────────────┐  ┌──────────────┐ │
 │  │ api Deployment   │   │ worker Deployment│  │ collector    │ │
 │  │  (N replicas,    │   │  (SINGLE replica │  │ Deployment   │ │
 │  │   stateless)     │   │   — ingest +     │  │ (syslog/     │ │
 │  │  :8080           │   │   investigate)   │  │  Kafka/RQ)   │ │
 │  └────────┬─────────┘   └────────┬─────────┘  └──────┬───────┘ │
 │           │                      │                    │         │
 │  ┌────────┴──────────────────────┴────────────────────┴──────┐ │
 │  │  GPU node pool  →  Foundry Managed Compute endpoint(s)     │ │
 │  │  open-weight Qwen/Llama, scaled by # endpoints (serial     │ │
 │  │  narration ⇒ scale out, not up)                            │ │
 │  └───────────────────────────────────────────────────────────┘ │
 └───────────────┬───────────────┬───────────────┬────────────────┘
     Private     │               │               │  Private Endpoints
     Link  ▼             ▼               ▼
   ┌───────────────┐ ┌──────────────┐ ┌───────────────────┐
   │ Azure DB for  │ │ Azure Cache  │ │ Azure AI Search   │
   │ PostgreSQL    │ │ for Redis    │ │ (managed RAG)     │
   │ (Flexible,    │ │ (HA/zone-    │ └───────────────────┘
   │  zone-redund) │ │  redundant)  │ ┌───────────────────┐
   └───────────────┘ └──────────────┘ │ Blob / Files      │  evidence, reports
                                       │ (evidence store)  │
   ┌───────────────┐ ┌──────────────┐ └───────────────────┘
   │ Key Vault     │ │ Azure Monitor│  audit / tracing / eval telemetry
   │ (secrets, MI) │ │ + Log Analyt.│
   └───────────────┘ └──────────────┘
```

### 4.1 The state-externalisation plan (do this first)
Running >1 API replica is impossible until the embedded state moves. Mapping:

| Embedded today | Move to | Change needed |
|---|---|---|
| DuckDB (`assessments.duckdb`) ingest tables | **Azure DB for PostgreSQL** (already the intended `APP_DB_DSN` path) | Point ingest store at Postgres; DuckDB stays only as a node-local scratch/analytics cache if useful. |
| SQLite hopgraph / sessions / decision-trace | Postgres (state) + **Blob** (snapshots) | HopGraph already snapshots to disk + restores on boot; repoint snapshot dir to Blob/Files, or pin hopgraph to the single worker. |
| `REPORT_STORE` (in-mem `_BoundedDict`) | **Postgres** via the existing `MIGRATE_REPORT_STORE` → `report_store.py` path | Flip the flag; it already has a DB-backed adapter. |
| `EVENT_QUEUE` | **Azure Cache for Redis** (auto-swaps to `RedisStreamsQueue` when `REDIS_URL` set) | Just set `REDIS_URL`. Already HA-friendly. |
| `INVESTIGATE_QUEUE`, in-proc ingest worker | **Single worker Deployment** (role split) | Run the workers as their own 1-replica deployment; API replicas run API-only (`ENABLE_JOB_WORKER=0`). |
| Per-replica rate limits, `ServerRuntime` buffers | Redis-backed limiter, or accept per-replica + **session affinity** | App Gateway cookie affinity is the pragmatic bridge for a first cut. |
| Uploaded evidence (`data/raw/...`) | **Azure Blob / Files** (`azureFile` or CSI Blob) | Repoint `JANUSEC_RAW_DIR` / upload sinks to a mounted share. This share is *file blobs*, not databases — safe to share (unlike the embedded DBs). |

> **The golden rule:** shared file storage is fine for *evidence blobs and JSON reports*; it is **fatal for DuckDB/SQLite**. Never put the embedded DBs on a shared RWX volume. That's the fix for the `k8s/deployment.yaml` red flag.

### 4.2 Role split (from monolith-with-workers → clean deployables)

| Azure workload | From | Replicas | Scales on |
|---|---|---|---|
| **api** | FastAPI, `ENABLE_JOB_WORKER=0`, full routes | N (2+) | HTTP RPS / CPU (HPA) |
| **worker-ingest** | ingest + investigate workers | **1** (singleton) | queue depth (KEDA on Redis) |
| **worker-llm** | `src.workers.llm_worker` (RQ) | N | Redis queue length (KEDA) |
| **collector** | syslog / Kafka consumers | per-source | ingest volume |
| **inference** | Foundry Managed Compute endpoint(s) | M endpoints | # concurrent investigations (serial per endpoint) |

---

## 5. High availability — the "minimum 2 VM or K8s" question

You asked whether to run **≥2 VMs or Kubernetes**. Here's the honest answer, because JanuSec's state model changes the math.

### 5.1 Why you can't just "run 2 replicas"
Naïvely scaling the current monolith to 2 breaks: duplicate ingest/investigate workers, split-brain `REPORT_STORE`, per-replica rate limits, and **corrupted DuckDB/SQLite** on shared storage. HA is a *role-split + state-externalisation* problem first, a *replica-count* problem second. Fix §4.1 and §4.2 and HA becomes trivial.

### 5.2 Option 1 — Two VMs (simplest sovereign; good for a Sydney Water pilot)
```
 App Gateway (WAF, zone-redundant, cookie affinity)
        ├── VM-A (Availability Zone 1)  — Docker Compose: api + worker + collector
        └── VM-B (Availability Zone 2)  — Docker Compose: api + collector (worker DISABLED)
                     │
   externalised:  Azure DB for PostgreSQL (zone-redundant) + Azure Cache for Redis (zone-redundant)
                  + Blob for evidence  + one GPU VM (or Foundry Local) for inference
```
- **Pros:** dead-simple, uses the existing `docker-compose.yml` almost as-is, cheap, easy to reason about, air-gap-friendly (Mode B). Meets "minimum 2" with **AZ spread** for real availability (not just 2 boxes in one datacentre).
- **Cons:** manual role pinning (worker only on VM-A), no auto-scaling, you patch/manage VMs, failover of the singleton worker is manual (or scripted).
- **Verdict:** right for a **pilot / air-gapped POC** and for demonstrating the architecture without AKS overhead. This is what I'd stand up *first*.

### 5.3 Option 2 — AKS (recommended for the real deployment)
Use the **existing `charts/janusec/` Helm chart** — it already ships PDB, HPA, NetworkPolicy, redis-ha, pgbouncer, oauth2-proxy (OIDC), ServiceMonitor. Add:
- **3 AZs**, system + user node pools, **PodDisruptionBudgets**, `topologySpreadConstraints` across zones.
- **GPU node pool** (`NVadsA10 v5` / `NC A100 v4`) tainted for the inference workload only.
- **KEDA** autoscaling on Redis queue depth for the worker/LLM roles.
- **Managed Identity (Workload Identity)** for Key Vault / Postgres / Blob — no secrets in cluster.
- `/health` + `/ready` probes already exist → wire to readiness/liveness.
- **Pros:** true HA, rolling deploys, autoscale, the chart is already production-shaped, single control plane for api/workers/collectors.
- **Cons:** more moving parts, needs the state-externalisation done, GPU node pools cost money even idle (use scale-to-zero + KEDA on the GPU pool where possible).
- **Verdict:** the destination architecture. Start on 2×VM, graduate to this.

### 5.4 Availability targets
| Component | HA mechanism | Realistic SLO |
|---|---|---|
| api tier | N replicas × 3 AZ + App Gateway | 99.95% |
| worker-ingest (singleton) | K8s reschedule + durable Redis/Postgres queue (work resumes on restart — `_recover_queued_jobs`) | brief gap on failover, no data loss |
| Postgres | Flexible Server zone-redundant HA | 99.99% |
| Redis | Premium zone-redundant / redis-ha Sentinel | 99.9%+ |
| inference | ≥2 Foundry endpoints behind the client's global limiter | degrades to deterministic fallback if all down |

---

## 6. GPU sizing — pros / cons (the core cost decision)

Narration + critic are the only GPU-bound work, and they run **serially per node** (`JANUSEC_NARRATOR_CONCURRENCY=1`, global limiter `LLM_MAX_CONCURRENT=4`). So a single investigation needs **one GPU sized for the model tier**, and **throughput scales by adding endpoints, not GPUs-per-node**.

### 6.1 VRAM by model tier
| Model | Params | VRAM (Q4/Q8) | Azure GPU SKU (example) |
|---|---|---|---|
| Qwen/Llama **8B** (T1) | 8B | ~6–10 GB | `NVadsA10 v5` (A10, 24 GB) — comfortable |
| Qwen2.5 **14B** (current T1) | 14B | ~10–12 GB | `NVadsA10 v5` (A10, 24 GB) |
| Qwen2.5 **32B** / `qwen3.6:27b` (T2) | 27–32B | ~18–24 GB | `NC A100 v4` (A100 40/80 GB) or 2×A10 |
| Llama **70B** (max quality T2) | 70B | ~40–48 GB (Q4) | `NC A100 v4` (A100 80 GB) |

### 6.2 The three inference substrates

| | **A. Azure OpenAI (managed)** | **B. Open-weight on Managed Compute** | **C. Foundry Local (on-prem)** |
|---|---|---|---|
| GPU to manage | **None** | Yes — you size + pay for it | Yes — customer hardware |
| Data residency | ❌ evidence → shared managed model | ✅ stays in your tenant | ✅✅ never leaves premises |
| Cost shape | per-token (opex, scales to zero) | GPU-hours (reserve or scale-to-zero via KEDA) | capex (customer owns GPUs) |
| "Same model" story | ❌ different model (gpt-4o) | ✅ literally the same Qwen/Llama | ✅ same |
| Latency | low, elastic | steady, sized | depends on customer HW |
| Best for | non-sensitive tenants, fast start | **the JanuSec sovereign default** | **air-gapped critical infra (Sydney Water)** |

### 6.3 Sizing rule of thumb
- **Concurrency:** because narration is serial, `#GPU endpoints ≈ peak concurrent investigations`. If the SOC runs 4 investigations at once and each holds the model for its narration burst, you want ~4 endpoints (or 1 endpoint + queueing if latency-tolerant — the client's global limiter already caps fan-out at 4).
- **Scale-to-zero:** GPU idle cost is the enemy. Use **KEDA + Managed Compute scale-to-zero** so GPU nodes spin up on queue depth and drop when idle. For a SOC with bursty investigation load this is the right cost posture.
- **Fix the timeout mismatch first:** the ingest stage budget (`JANUSEC_INGEST_NARRATE_TIMEOUT_S`) is inconsistent across code/docstring/compose (50 vs 180 vs 600). On a given GPU, set it to comfortably exceed `N_clusters × (per_call_timeout + critic_timeout)` or clusters past the first fall back to non-LLM narratives. Size the timeout to the GPU, not the reverse.

---

## 7. Networking & traffic (eBGP, summary routes, and what actually applies)

You asked about **eBGP, summary route tables, and how traffic reaches users**. Here's where each actually applies in Azure — and where it doesn't.

### 7.1 North-south (users → app)
This is **L7 load balancing, not BGP**:
```
Azure Front Door (global anycast, TLS, WAF)      ← multi-region / global users
   → Application Gateway (regional L7 WAF, cookie session affinity)   ← the sticky-routing JanuSec needs
      → AKS internal Load Balancer / Service
         → api pods
```
- **Session affinity** (App Gateway cookie) is the pragmatic bridge for the per-replica state (`REPORT_STORE`, rate limits) until you fully externalise §4.1.
- **Front Door** only if you go multi-region; a single-region utility deployment can skip it and front with App Gateway alone.

### 7.2 Where eBGP genuinely belongs — hybrid / on-prem edge
BGP (eBGP) in Azure shows up at the **enterprise/on-prem boundary**, which is exactly the air-gap / hybrid scenario for a utility:
- **ExpressRoute** — private L3 circuit from the client's on-prem SOC/datacentre to Azure, using **eBGP peering** to exchange routes. The customer's on-prem prefixes and Azure VNet prefixes are advertised over BGP. This is how a Sydney-Water-style operator connects an on-prem evidence source (or an air-gapped Foundry Local island) to a cloud control plane **without traversing the public internet**.
- **Azure Route Server** — lets you run BGP between Azure and an NVA (firewall/SD-WAN) in the VNet, so custom routes propagate automatically instead of hand-maintained UDRs.
- **VPN Gateway (BGP mode)** — eBGP over IPsec for a cheaper hybrid link than ExpressRoute.

### 7.3 Summary routes / route aggregation
- Over ExpressRoute/VPN BGP, advertise **summarised (aggregated) prefixes** (e.g. a single `/16` for the on-prem SOC estate) rather than many `/24`s — smaller route tables, cleaner failover. Azure honours received BGP routes; you control what you advertise.
- **Hub-and-spoke + UDR:** in a hub-spoke VNet topology, the hub firewall/NVA holds **User-Defined Routes** that summarise spoke traffic and force it through inspection. JanuSec's spokes (api, data, inference) route east-west via the hub; a **summary route** (`0.0.0.0/0` → firewall, plus specific PaaS prefixes → Private Endpoints) keeps the spoke route tables minimal.

### 7.4 East-west (inside the cluster) — CNI, not BGP
Intra-AKS pod traffic uses **Azure CNI** (pods get VNet IPs) + Kubernetes Services + Ingress. BGP is **not** the pod-routing mechanism here (a common misconception). If you use **Calico** for NetworkPolicy it *can* use BGP internally, but for JanuSec the network policy in `charts/janusec/` is standard K8s NetworkPolicy — no BGP needed inside the cluster.

### 7.5 Private everything (critical for a utility)
- All PaaS (Postgres, Redis, AI Search, Key Vault, Blob, **Foundry endpoint**) reached via **Private Endpoints** — no public IPs, traffic stays on the Microsoft backbone / your VNet.
- **NSGs + firewall egress allow-list** — the deployment should have *no* unrestricted outbound. JanuSec's only mandatory egress is Redis + the inference endpoint (both private) + optional connector integrations (which you allow-list per connector).
- Air-gap mode (B): **zero egress** — Foundry Local + BM25 fallback + local deterministic client mean the platform runs fully disconnected.

---

## 8. Recommended path (ranked)

1. **Pilot — 2×VM (AZ-spread) + Foundry Local**, state on Azure DB for PostgreSQL + Azure Cache for Redis. Proves the sovereign/air-gap story with minimal moving parts. Uses existing `docker-compose.yml`. *(Start here.)*
2. **Production — AKS via the existing `charts/janusec/` Helm chart**, open-weight models on **Foundry Managed Compute GPU pool** (Mode A sovereign), Private Link everywhere, KEDA scale-to-zero on GPU. *(Destination.)*
3. **Burst / non-sensitive tenants — Azure OpenAI (`gpt-4o` family)** for tenants whose data may leave the boundary, selected per-tenant via the existing `tenant_llm_config.py` provider routing. *(Optional add-on; never for air-gap tenants.)*

---

## 9. Pre-requisites / migration checklist

**Must-do before any deploy:**
- [ ] **Rotate the leaked Neon password** and `SECRET_KEY` in the committed `.env`; move all secrets to **Key Vault** + Managed Identity.
- [ ] **Externalise state** (§4.1): repoint ingest store + `REPORT_STORE` to Postgres, set `REDIS_URL`, move evidence to Blob/Files, snapshots off local disk.
- [ ] **Split roles** (§4.2): api replicas with `ENABLE_JOB_WORKER=0`; separate single-replica ingest/investigate worker.
- [ ] **Fix the RWX PVC** in `k8s/deployment.yaml` — never share embedded DBs across pods.
- [ ] **Fix the narrate-timeout mismatch** (`JANUSEC_INGEST_NARRATE_TIMEOUT_S`) to match the provisioned GPU/endpoint latency.

**Foundry setup:**
- [ ] Create an **Azure AI Foundry project** (hub + project).
- [ ] Deploy models: managed (`gpt-4o` / `gpt-4o-mini`) **or** open-weight (Qwen/Llama) to a **Managed Compute** endpoint.
- [ ] Set `LLM_PROVIDER=azure_openai` + endpoint + Managed-Identity auth.
- [ ] Enable **Content Safety** on the endpoint; wire **Evaluations** into CI against the `pytest -m acceptance` golden set.
- [ ] (Air-gap) provision **Foundry Local** on customer hardware; validate BM25/deterministic fallbacks with egress blocked.

**Compute:**
- [ ] Provision Postgres (Flexible, zone-redundant HA), Redis (zone-redundant), Blob, AI Search (if managed RAG), Key Vault, Log Analytics.
- [ ] Stand up 2×VM (pilot) or AKS from `charts/janusec/` (prod) with GPU node pool.
- [ ] Private Endpoints + NSGs + egress allow-list; ExpressRoute/VPN with **summarised BGP advertisement** if hybrid/on-prem.

---

## 10. Governance & compliance mapping (JanuSec's throughline, on Azure)

| Control theme | Azure mechanism | JanuSec artefact |
|---|---|---|
| Decision provenance / auditability | Azure Monitor + Log Analytics tracing | bitemporal decision trace, verdict engine owns verdict |
| AI risk management (EU AI Act, ISO 42001) | Content Safety + Foundry Evaluations | deterministic-first scoring, golden acceptance harness |
| Data sovereignty / residency | Private Link, Foundry Local, in-tenant models | air-gap deployment option |
| Secrets / identity (ISO 27001) | Key Vault + Managed Identity + oauth2-proxy OIDC | existing RBAC (`src/security/auth.py`, roles/rbac) |
| Data protection / retention | Postgres + retention sweeper, Blob lifecycle | `RETENTION_*_DAYS`, `retention_sweeper.py` |
| Network assurance | NSG, WAF, Private Endpoints, NetworkPolicy | `charts/janusec/` NetworkPolicy |

---

## 11. Risks & gotchas (call these out proactively)

1. **State externalisation is the real project.** The Foundry swap is a day; making JanuSec horizontally scalable (§4.1) is the multi-week effort. Don't undersell it.
2. **Serial narration caps throughput.** By design (single-GPU OOM safety). Scale endpoints, not GPUs-per-node; be honest that per-investigation latency is bounded by single-stream token rate.
3. **GPU idle cost.** Without scale-to-zero, a reserved A100 burns money 24/7 for bursty SOC load. KEDA + Managed Compute scale-to-zero is essential.
4. **The committed secret + dev SECRET_KEY** must be rotated — this is a live finding, not hypothetical.
5. **Neo4j is dormant** — don't provision it; the graph is HopGraph/SQLite.
6. **Timeout inconsistency** (50/180/600s) will silently degrade narration quality on slower endpoints. Fix before load-testing.

---

## Appendix — key files (for whoever implements this)

- Inference / provider: `src/integrations/llm_client.py`, `src/integrations/llm_router.py`, `src/core/config/tenant_llm_config.py`, `src/integrations/llm_concurrency.py`
- Narration / critic: `src/core/ingest/cluster_narrator.py`, `src/agents/critic.py`, `src/agents/narrator.py`
- Pipeline: `src/core/ingest/assessment_worker.py` (`run_assessment_pipeline`), `src/core/event_pipeline/pipeline.py`
- State: `src/api/deep_analyze/persistence.py` (`REPORT_STORE`), `src/api/runtime_state.py`, `src/core/ingest/store.py` (DuckDB), `src/core/storage/report_store.py`, `src/graph/hopgraph.py`
- Deploy: `Dockerfile`, `docker-compose.yml`, `k8s/deployment.yaml`, **`charts/janusec/` (values.yaml + values-production.yaml)**, `azure-deployment/`
- Config/secrets: `.env` (⚠ rotate), `src/config/settings.py`, `src/core/config.py`

---

*Prepared as an architecture design for the Azure AI Foundry target deployment. Companion doc available for ShopSquire (lighter — no local model in the hot path). None of this is deployed to production; it is a design blueprint and interview reference.*
