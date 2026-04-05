# JanuSec Platform Deep Dive - Part 2: Core Engines & Analysis

## 1. HopGraph Attack Reconstruction

### 1.1 Architecture Overview

**Verdict: HopGraph WORKS for attack reconstruction** with production-grade implementation.

The system features **dual implementations**:

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| HopGraphLite | `src/core/graph/hopgraph_lite.py` | 1,004 | Real-time sliding window (900s default), in-memory |
| Full HopGraph | `src/graph/hopgraph.py` | 1,600+ | Persistent with WAL, snapshots, configurable TTL |
| SQLite Backend | `src/core/graph/persistence/sqlite_backend.py` | 286 | Durable storage with schema versioning |

### 1.2 Graph Data Model

**Nodes**:
- Types: `user`, `host`, `process`, `package`, `binary`, `infrastructure`, `ip`, `domain`, `hash`, `certfp`, `ja3`
- Metadata: creation timestamp, last seen, factors, chain_len hints

**Edges**:
- Directed with timestamps and provenance
- Types: `auth`, `net`, `proc`, `runs`, `spawns`, `loads_hash`, `connects_to`, `contacts_domain`
- Per-edge metadata: source (sensor, intel_feed), weight (1.0-1.2)
- TTL per type: AUTH=72h, NET=24h, PROC=12h

### 1.3 Core Reconstruction Method

```python
def reconstruct_attack(self, seed_alert, depth=3, ttl_seconds=None) -> dict:
    """
    Reconstructs subgraph around a seed alert.

    Returns:
    {
        'seeds': [...],      # Initial pivot nodes
        'nodes': [...],      # All connected nodes
        'edges': [...],      # Edges with phase labels
        'timeline': {...}    # Start/end timestamps
    }
    """
```

**Algorithm**:
1. Seeds on user/host/process from alert
2. Bidirectional BFS (forward + backward edges)
3. Depth limit (typically 3-4 hops)
4. Labels edges with MITRE phases:
   - `initial_access`: Earliest user→host auth
   - `execution`: User→process edges
   - `lateral`: Host→host or additional user→host
   - `unknown`: Others

### 1.4 Lateral Movement Detection

```python
def detect_lateral_chain(user, max_hops=5, min_hosts=3, within_seconds=None):
    """
    Returns chains like: [host1, host2, host3, ...]

    Algorithm:
    1. Collect all user→host auths in window
    2. Build host→host (net) adjacency
    3. DFS to enumerate unique paths up to max_hops
    4. Return paths >= min_hosts as chains
    """
```

**Test Validation** (from `test_hopgraph_lateral_rule.py`):
```python
g.observe({'edge_type':'auth','user':'bob','host':'h1'})
g.observe({'edge_type':'net','host':'h1','peer':'h2'})
g.observe({'edge_type':'net','host':'h2','peer':'h3'})
res = g.detect_lateral_chain('bob')
assert res['rapid_lateral_movement'] is True
assert len(res['chains'][0]) >= 3  # PASSES
```

### 1.5 Explain Chain (Beam Search Scoring)

The full HopGraph uses **beam search with scoring**:

```python
for depth in range(max_depth):
    for (score, nodes_path, edges_path) in beam:
        for (dst, edge_type, ts, source, weight) in outgoing_edges:
            age_decay = 0.5 ** (age_seconds / 3600)
            contrib = weight * age_decay * preferred_multiplier * gt_boost
            new_score = (old_score * len(path) + contrib) / (len(path) + 1)
```

**Edge Type Multipliers**:
- `loads_hash`: 2.5x (highest for binary analysis)
- `spawns`: 2.0x
- `gt_sequence`: 2.2x (Ground Truth edges)
- `precedes`, `discovers`: 1.2x
- Others: 1.0x

### 1.6 Personalized PageRank (PPR)

```python
def ppr(self, seed=(type, id), alpha=0.15, steps=8, cap=128):
    """
    Localized PPR with short random-walk + restart.
    Returns: [(type, id, score), ...] top-32 ranked nodes
    """
```

Used to find high-centrality nodes (e.g., domain controllers) in attack paths.

### 1.7 Persistence & Storage

**SQLite Schema**:
```sql
CREATE TABLE nodes (id TEXT PRIMARY KEY, type TEXT, label TEXT, last_seen REAL, json_meta TEXT);
CREATE TABLE edges (id TEXT PRIMARY KEY, src TEXT, dst TEXT, etype TEXT, last_seen REAL, json_meta TEXT);
CREATE TABLE wal_events (id INTEGER PRIMARY KEY, ts REAL, tenant TEXT, kind TEXT, payload TEXT);
CREATE TABLE snapshot_meta (snapshot_id TEXT, saved_seq_max INTEGER, ...);
```

**Configuration**:
```bash
HOPGRAPH_PERSISTENCE_ENABLED=1
HOPGRAPH_DB_PATH=/data/hopgraph.db
HOPGRAPH_SNAPSHOT_EDGE_DELTA=1000
HOPGRAPH_WAL_MAX_BYTES=104857600  # 100MB
```

### 1.8 API Endpoints

```
POST /api/v1/graph/reconstruct
  - seed: {user, host, process}
  - depth: 3 (default)
  - ttl_seconds: 3600 (optional)

GET /api/v1/graph/temporal_query
  - time range query

POST /api/v1/graph/multi_merge
  - multi-root merge operation
```

### 1.9 HopGraph Assessment

| Aspect | Status | Notes |
|--------|--------|-------|
| Core reconstruction | **Working** | Multi-domain scenarios tested |
| Lateral detection | **Working** | 3+ hop chains validated |
| Temporal scoring | **Working** | Beam search + decay produces reasonable rankings |
| Persistence | **Working** | WAL recovery, snapshots, SQLite |
| Test coverage | **Good** | 41+ test files |
| Production confidence | **8/10** | Deploy as primary attack reconstruction engine |

---

## 2. Event Pipeline

### 2.1 Architecture

**33 registered stages** in 3 groups: `core`, `heavy`, `external`

```
Event Entry
    ↓
[Circuit Breaker Check] → Memory pressure evaluation
    ↓
[Per-Stage Processing Loop]
    ├─ Confidence Gate: Skip heavy if confidence >= 0.8
    ├─ Under-Load Skip: Selective bypass under memory pressure
    ├─ Process Pool Isolation: Optional worker processes for heavy stages
    ├─ Per-Stage Timeout: Configurable (e.g., 30s for pcap_session)
    └─ Factor Accumulation: Progressive enrichment
    ↓
[Allowlist Application] → Suppress known-good vendors/binaries
    ↓
[Confidence Adjustment] → Trust signals & missing field penalties
    ↓
[Factor Synthesis] → Multi-factor confidence calculation
    ↓
[Decision Engine] → Route: Benign | Deep Analysis | Malicious
```

### 2.2 Stage Groups

**CORE STAGES (17)** - Always enabled, <50ms:
1. `baseline` - Known IOC lookup, allowlist bypass
2. `regex` - Pattern matching (command injection, base64 PS)
3. `parent_child` - Process lineage (winword→powershell)
4. `endpoint` - Endpoint threat detection
5. `email_enrichment` - Domain/content analysis
6. `auth_burst` - CUSUM spike detection
7. `identity` - IAM/OAuth abuse
8. `graph` - Graph correlation/provenance
9. `adaptive_pre` - Preliminary scoring
10. `packet_summary` - Network metadata
11. `threat_intel` - External intel enrichment
12. `supply_chain_npm` - NPM package risks
13. `supply_chain_cicd` - CI/CD pipeline risks
14. `sbom_exec` - SBOM execution context
15. `sbom_vuln` - SBOM vulnerability mapping
16. `ebpf_analysis` - Kernel event analysis
17. `rare_token` - Anomalous token detection

**HEAVY STAGES (6)** - Resource-intensive, gated:
18. `binary_payload` - Deep binary analysis (30+ min timeout)
19. `beacon` - C2 beacon detection
20. `egress` - Data exfil volume spikes
21. `domain_novelty` - New/rare domain discovery
22. `pcap_session` - PCAP analysis (30s timeout)
23. `hunt_lanes` - Multi-lane threat hunting

**CORRELATION & QUALITY (5)**:
24. `correlation` - Multi-factor rule engine
25. `quality_filter` - Factor entropy filtering
26. `mapping` - MITRE ATT&CK mapping
27. `cluster_dedupe` - Event deduplication
28. `coverage_tracker` - Telemetry observability

**EXTERNAL (2)** - Optional dependencies:
29. `cert_analysis` - TLS/X.509 analysis
30. `http_header` - HTTP header security

### 2.3 Correlation Rules

**79 rule files across 8 domains**:

| Domain | Files | Notable Rules |
|--------|-------|---------------|
| **Email** | 20 | BEC chain, payment redirect, domain flip, supplier takeover, OAuth spoof |
| **Process/Binary** | 14 | Office macros, PowerShell encoding, AMSI bypass, LOLbins |
| **Registry/Persistence** | 6 | Run keys, LSASS OpenProcess, WMI persistence |
| **Network** | 3 | Beacon low-frequency, C2 multi-channel, DNS exfil |
| **IAM** | 2 | OAuth consent anomaly, assume role abuse |
| **Supply Chain** | 4 | Package source anomaly, post-install scripts |
| **Binary** | 4 | High entropy sections, PE mismatch, unsigned binaries |
| **eBPF/Container** | 2 | Container escape, syscall patterns |

### 2.4 Robustness Features

**Memory Circuit Breaker**:
- Monitors RSS in real-time
- Configurable threshold (default 4GB)
- Auto-disables correlation under pressure
- Recovery at 80% of limit

**Error Handling**:
- Per-stage exception isolation
- Non-fatal errors continue pipeline
- Timeout enforcement per-stage
- Process pool isolation option

**Allowlist Management**:
```python
# Vendors: Microsoft, Windows Defender, etc.
# Binaries: mpam-d.exe, snippingtool.exe, etc.
# Factor suppression: endpoint:signed_mismatch
# Confidence cap: Allowlisted items ≤ 0.35
```

### 2.5 Confidence Calculation

**Missing Field Penalties**:
```
host: 0.20
user: 0.15
parent_process: 0.20
signer: 0.15
network: 0.20

If penalty >= 0.5: Mark as 'needs_enrichment'
If penalty >= 0.95: Cap at 0.05 confidence
```

**Blending Modes**:
- `add` (default): `confidence += incoming * weight`
- `max`: `confidence = max(current, incoming)`
- `weighted_max`: `confidence = max(current, current + incoming * 0.5)`

### 2.6 Pipeline Metrics (Prometheus)

```
pipeline_stage_latency_ms{stage}
pipeline_heavy_stage_latency_ms{stage}
pipeline_confidence_progress{stage}
pipeline_events_total{terminal}
pipeline_stage_skips_total{reason}
pipeline_allowlist_hits_total
pipeline_breaker_state_gauge
pipeline_worker_task_latency_ms
```

### 2.7 Pipeline Assessment

| Aspect | Status | Grade |
|--------|--------|-------|
| Stage architecture | 33 stages, 3 groups | A |
| Error handling | Isolated, non-fatal | A |
| Memory management | Circuit breaker | A |
| Correlation rules | 67 active rules, 8 domains | A |
| Observability | Comprehensive Prometheus metrics | A |
| Process isolation | Optional worker pools | A |
| Test coverage | 8+ test suites | A |
| **Overall** | **Production-Ready** | **A** |

---

## 3. Deep Analyze & LLM Capabilities

### 3.1 Architecture

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| Deep Analyze API | `deep_analyze_endpoints.py` | 4,784 | 50+ endpoints |
| Auto-LLM | `auto_llm.py` | 1,366 | Tier detection, prompts |
| LLM Client | `llm_client.py` | 917 | Provider abstraction |

### 3.2 LLM Providers

**Supported Providers**:
1. **Ollama** (Default) - Local CPU/GPU, `OLLAMA_HOST`, `OLLAMA_MODEL`
2. **OpenAI** - GPT-4, GPT-4o, GPT-4o-mini via `OPENAI_API_KEY`
3. **Anthropic Claude** - Fallback via `ANTHROPIC_API_KEY`
4. **Local Deterministic** - Offline fallback (`LLM_MOCK=1`)

**Selection Logic**:
```python
if LLM_PROVIDER env set → use it
elif OLLAMA_HOST set or no keys → use ollama
else → use openai
fallback → LocalDeterministicClient
```

### 3.3 Tier-1 vs Tier-2 Summaries

#### Tier-1: Fast Triage
- **Purpose**: 30-45 line structured summaries for rapid SOC triage
- **Latency**: <10 seconds
- **Cost**: ~$0.003 per row
- **Model**: `gpt-4o-mini` or `llama3:8b`
- **Token Limit**: 1,024 tokens

**Tier-1 Prompt Structure**:
```
- WHAT IS IT? (2-3 lines)
- EXPLOITABILITY (3-4 lines)
- WHAT TO DO? (3-4 lines)
- CONCISE PLAYBOOK (5-8 lines)
- [OPTIONAL] MISSING LOGS (3-5 lines)
```

#### Tier-2: Deep Investigation
- **Purpose**: 60-100 line comprehensive analysis
- **Latency**: 30-90 seconds
- **Cost**: ~$0.015 per row
- **Model**: `gpt-4o` (escalates to `gpt-4` for severity ≥0.75)
- **Token Limit**: 2,048 tokens

**Tier-2 Includes**:
- Domain detection (endpoint/network) with confidence
- Historical incident query (90-day lookback)
- Correlation context and attack scenarios
- Step-by-step forensic collection playbook
- Evidence timeline and entity graph
- MITRE mapping with domain-specific tools

### 3.4 Auto-LLM Triage Flow

```
POST /assessments/generate_llm_summaries
    ↓
Rate Limiting (5 req/min per assessment)
    ↓
Row Prioritization
    ├─ Factor count
    ├─ DREAD score
    └─ Verdict (CRITICAL > HIGH > MEDIUM)
    ↓
LLM Generation
    ├─ Select tier based on severity
    ├─ Build tier-specific prompt
    ├─ Call LLM provider
    ├─ Enforce schema (sections, line count)
    └─ Track cost/tokens
    ↓
Output
    ├─ llm_summary (formatted text)
    ├─ llm_meta (provider, model, tokens, cost)
    └─ persona_reports (multi-view)
```

### 3.5 Persona-Based Reports

**Personas Supported**:
1. **executive** - Concise, non-technical, decision-focused
2. **soc_analyst** - Technical, evidence-first, actionable
3. **compliance** - Formal, controls-oriented, remediation timeline

**Output Schema**:
```python
{
  'summary': str,
  'actions': [{'desc': str, 'urgency': 'immediate|urgent|normal'}],
  'evidence_refs': [str],  # Event IDs, SHA256 hashes
  'confidence': float,
  'parsed_from_json': bool
}
```

### 3.6 Cost & Budget Control

```bash
# Per-row costs
LLM_COST_PER_ROW=0.003        # Tier-1
T2_COST_PER_ROW=0.015         # Tier-2

# Budget enforcement
LLM_TENANT_BUDGET=100.0       # Per-tenant limit
LLM_TENANT_SOFT_THRESHOLD=0.9 # Trip at 90%
```

**Features**:
- Per-row and aggregate cost tracking
- Per-tenant budget enforcement
- Circuit breaker at 90% threshold
- Cost ledger with persistence

### 3.7 LLM Assessment

| Feature | Status | Notes |
|---------|--------|-------|
| Multi-provider | **Working** | Ollama, OpenAI, Anthropic |
| Tier-1 summaries | **Working** | 30-45 lines, schema enforced |
| Tier-2 investigation | **Working** | 60-100 lines with playbooks |
| Cost tracking | **Working** | Per-tenant budgets |
| Deterministic fallback | **Working** | Offline capability |
| Persona reports | **Working** | Executive, analyst, compliance |
| Prompt injection defense | **Partial** | Surface patterns only |
| **Overall** | **Production-Capable** | **7/10** |

---

## 4. Live Streaming vs Manual Analysis

### 4.1 Comparison Matrix

| Dimension | Live Streaming | Manual CSV |
|-----------|----------------|------------|
| **Ingestion latency** | <100ms per event | On-demand (batch) |
| **Correlation window** | 15 minutes sliding | Single batch (finite) |
| **Graph context** | Temporal relationships | Static snapshots |
| **Client notification** | SSE push (active) | Request/response pull |
| **Schema discovery** | Fixed (Zeek types) | Heuristic inference |
| **Backpressure** | Token bucket rate limit | File size threshold |
| **Memory model** | Event deques + LRU | Materialized batch |
| **Temporal motifs** | Yes (burst, spiking) | No (aggregate only) |
| **Determinism** | Order-dependent | Same input = same output |

### 4.2 Live Streaming Architecture

```
Zeek Adapter
    ├─ Conn logs (IP:port, protocol, duration, bytes)
    ├─ DNS logs (queries, response codes)
    ├─ HTTP logs (User-Agent, URIs)
    └─ SSL logs (JA3/JA3S fingerprints)
        ↓
Correlation Window (900s sliding)
    ├─ Per-host event deques (5K max)
    ├─ Per-user tracking
    └─ Per-destination IP tracking
        ↓
HopGraph Integration
    ├─ Node registration (user, host, process)
    ├─ Edge registration (auth, net, proc)
    └─ Temporal motif detection
        ↓
SSE Broadcast → All connected clients
```

### 4.3 CSV Batch Architecture

```
CSV Upload
    ↓
Size Detection
    ├─ < 100MB: Materialized batch
    └─ >= 100MB: Streaming (1000-row chunks)
        ↓
Mapping Inference
    ├─ HIGH_VALUE: user, host, process_name, hash, domain
    └─ SUPPORT: command_line, parent_process, ip, email
        ↓
Batch Analysis
    ├─ Risk scoring (processes, paths, encodings)
    ├─ Verdict classification
    └─ Factor extraction
```

### 4.4 Decision Output Differences

**Live Stream Decision**:
```json
{
  "event_id": "zeek:conn:12345",
  "confidence": 0.87,
  "stage_timings": [
    {"name": "baseline", "duration_ms": 45, "confidence_after": 0.65},
    {"name": "correlation", "duration_ms": 12, "confidence_after": 0.72},
    {"name": "graph_context", "duration_ms": 8, "confidence_after": 0.87}
  ],
  "factors": [
    "geo_anomaly (dest_ip from rare ASN)",
    "burst_detection (user:alice 5 conn/min)",
    "temporal_motif (3-hop lateral movement)"
  ]
}
```

**CSV Batch Decision**:
```json
{
  "artifact_id": "csv_row_42",
  "process_name": "powershell.exe",
  "verdict": "SUSPICIOUS",
  "risk_score": 0.65,
  "factors": [
    "powershell_execution",
    "encoded_command",
    "temp_directory_execution"
  ],
  "recommendations": [
    "Monitor process behavior",
    "Check network connections"
  ]
}
```

### 4.5 Use Case Guidance

**Choose Live Streaming When**:
- Multi-step attack detection (lateral movement, recon)
- Behavioral sequences matter (burst patterns, impossible travel)
- Low-latency response critical (<1s)
- High volume sources (Zeek, eBPF, ETW)
- Real-time SOC monitoring dashboards

**Choose Manual CSV When**:
- Bulk historical analysis (forensic review)
- Ad-hoc threat hunting (one-off exports)
- Non-standardized data formats
- Offline analysis (no network)
- Compliance reporting (audit trails)

### 4.6 Performance Characteristics

**Real-Time Path**:
- Throughput: 100-1000 events/sec per instance
- Latency: 50-200ms pipeline + 0-50ms SSE
- Memory: O(5000 events) in correlation window

**Batch Path**:
- Throughput: 1000-10000 rows/second
- Latency: Entire file before response
- Memory: O(batch_size) streaming

---

## 5. Key File References

| Component | Path | Lines |
|-----------|------|-------|
| HopGraphLite | `src/core/graph/hopgraph_lite.py` | 1,004 |
| Full HopGraph | `src/graph/hopgraph.py` | 1,600+ |
| Event Pipeline | `src/core/event_pipeline/pipeline.py` | 2,038 |
| Pipeline Stages | `src/core/event_pipeline/stages/` | 1,993 |
| Deep Analyze API | `src/api/deep_analyze_endpoints.py` | 4,784 |
| LLM Client | `src/integrations/llm_client.py` | 917 |
| Auto-LLM | `src/analysis/auto_llm.py` | 1,366 |
| Correlation Rules | `src/core/correlation/rules/` | 79 files |
| Decision Engine | `src/core/decision_engine.py` | ~500 |
| Zeek Adapter | `src/live/zeek_adapter.py` | ~300 |
| CSV Handler | `src/api/csv_handler.py` | ~800 |
| Decision Stream | `src/api/decisions_stream.py` | ~400 |

---

## Next: Part 3 - Competitive Analysis, USPs, Multi-Domain, FP Reduction
