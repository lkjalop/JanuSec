# HoneyGraph: AI-Powered Honeypot Correlation Engine
## Product Requirements Document (PRD)

**Version:** 0.1 (Draft)
**Status:** Pre-Development
**Target Release:** Q2 2025 (MVP)
**Last Updated:** 2025-01-11

---

## 1. Executive Summary

### 1.1 Vision Statement

**HoneyGraph** is an open-source AI-powered correlation engine that transforms honeypot data into actionable threat intelligence through temporal analysis, graph-based attack reconstruction, and machine learning.

### 1.2 Problem Statement

**Current State:**
- Existing honeypots (Cowrie, T-Pot, Dionaea) generate massive logs but provide minimal analysis
- SOC teams manually correlate attacks across time and infrastructure
- Attack chains are reconstructed manually (time-consuming, error-prone)
- Threat intelligence integration is primitive or non-existent
- No open-source tool applies advanced AI/ML to honeypot data

**Pain Points:**
- 🚨 **Data Overload:** Thousands of log entries, hard to find meaningful patterns
- 🚨 **Manual Correlation:** Analysts spend hours connecting related attacks
- 🚨 **Missed Campaigns:** Multi-stage attacks go undetected
- 🚨 **No Context:** Attacks lack threat intel enrichment
- 🚨 **Poor Visualization:** No graph-based attack chain views

### 1.3 Solution Overview

**HoneyGraph provides:**
- ✅ **Temporal Correlation:** EWMA-based drift detection finds attack campaigns
- ✅ **Attack Chain Graphs:** HopGraph reconstructs multi-stage attacks visually
- ✅ **ML Anomaly Detection:** Isolation Forest identifies novel attacks
- ✅ **Threat Intel RAG:** Semantic search enriches attacks with context
- ✅ **Multi-Framework Mapping:** Automatic MITRE ATT&CK, Kill Chain, STRIDE tagging
- ✅ **Factor-Based Scoring:** Risk prioritization for analyst triage

### 1.4 Success Criteria

**MVP Success (6 months):**
- 100+ GitHub stars
- 10+ active users/organizations
- 3+ community contributions (PRs)
- 1 conference talk accepted (BSides, DEFCON)

**Long-Term Success (12 months):**
- 500+ GitHub stars
- 50+ active deployments
- 1 published research paper (IEEE S&P, NDSS)
- Integration with major honeypot platforms (T-Pot, MHN)

---

## 2. Target Users & Use Cases

### 2.1 Primary Personas

**Persona 1: SOC Analyst (Sarah)**
- **Role:** Threat detection, triage, investigation
- **Pain:** Honeypot logs overwhelm her; she needs prioritized alerts
- **Goal:** Quickly identify high-value attacks and campaigns
- **Use Case:** Deploy HoneyGraph to correlate honeypot data, get ML-ranked alerts

**Persona 2: Security Researcher (Rajiv)**
- **Role:** Threat research, TTP analysis, publishing papers
- **Pain:** Manually analyzing attack patterns from honeypot logs
- **Goal:** Discover novel attack techniques, publish findings
- **Use Case:** Use HoneyGraph's graph analysis and ML to find patterns

**Persona 3: Threat Intel Analyst (Maria)**
- **Role:** Threat intel enrichment, IOC tracking, STIX/TAXII sharing
- **Pain:** Honeypot data is siloed, not enriched with context
- **Goal:** Feed honeypot intel into threat feeds
- **Use Case:** Export HoneyGraph analysis to STIX, enrich with RAG

### 2.2 Use Cases

| Use Case | Description | Priority |
|----------|-------------|----------|
| **Attack Campaign Detection** | Identify coordinated attacks across time/IPs | ✅ Must Have |
| **Attack Chain Reconstruction** | Visualize multi-stage attacks as graphs | ✅ Must Have |
| **Anomaly Detection** | Find novel/zero-day attack attempts | ✅ Must Have |
| **Threat Intel Enrichment** | RAG retrieves context for attacks | ✅ Must Have |
| **MITRE ATT&CK Mapping** | Auto-tag attacks with tactics/techniques | ✅ Must Have |
| **Risk Prioritization** | Score attacks by risk for triage | ✅ Must Have |
| **SIEM Integration** | Export alerts to Splunk/ELK/QRadar | ⚠️ Should Have |
| **STIX/TAXII Export** | Share threat intel in standard format | ⚠️ Should Have |
| **Attacker Profiling** | Cluster attackers by behavior | ⚠️ Nice to Have |
| **Attack Prediction** | Predict next attacker move (LSTM) | ⚠️ Nice to Have |

---

## 3. Technical Architecture

### 3.1 System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         HoneyGraph System                        │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│   Cowrie     │      │    T-Pot     │      │   Dionaea    │
│   Logs       │      │    Logs      │      │   Logs       │
└──────┬───────┘      └──────┬───────┘      └──────┬───────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Log Ingestion  │
                    │  & Normalization│
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
       ┌──────▼──────┐ ┌────▼─────┐ ┌─────▼──────┐
       │  Temporal   │ │ HopGraph │ │  ML Anomaly│
       │  Correlation│ │ Attack   │ │  Detection │
       │  (EWMA)     │ │ Chains   │ │ (IsolForest)│
       └──────┬──────┘ └────┬─────┘ └─────┬──────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │  Threat Intel   │
                    │  RAG Enrichment │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Factor Scoring │
                    │  & Prioritization│
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
       ┌──────▼──────┐ ┌────▼─────┐ ┌─────▼──────┐
       │  Web UI     │ │  REST    │ │  Exports   │
       │  Dashboard  │ │  API     │ │  (JSON/STIX)│
       └─────────────┘ └──────────┘ └────────────┘
```

### 3.2 Core Components (From JanuSec)

#### **Component 1: Temporal Correlation Engine**

**Extract From:**
- `src/live/correlation_window.py`
- `src/analytics/drift_analyzer.py`
- `src/core/detect/beacon_analyzer.py`
- `src/core/detect/domain_tracker.py`

**Adaptation:**
```python
class TemporalCorrelator:
    """
    Identifies attack campaigns using sliding windows and EWMA.

    Input: Stream of honeypot events
    Output: Correlated attack groups with campaign IDs
    """

    def __init__(self, window_size: int = 3600):  # 1 hour default
        self.window = SlidingWindow(window_size)
        self.ewma = AdaptiveEWMA(alpha=0.3)
        self.campaigns = {}

    def process_event(self, event: HoneypotEvent) -> Optional[Campaign]:
        """
        Process single event, return campaign if threshold crossed.
        """
        # Add to sliding window
        self.window.add(event)

        # Calculate drift from baseline
        drift_score = self.ewma.update(event.features)

        # Check for campaign threshold
        if drift_score > self.threshold:
            campaign_id = self._identify_campaign(event)
            return self.campaigns[campaign_id]

        return None
```

**Key Metrics:**
- Campaign detection rate (target: 80%+)
- False positive rate (target: <10%)
- Processing latency (target: <100ms per event)

---

#### **Component 2: HopGraph Attack Chain Reconstructor**

**Extract From:**
- `src/core/graph/hopgraph_lite.py`
- `src/core/graph/network_hopgraph.py`
- Graph traversal/scoring logic

**Adaptation:**
```python
class AttackChainGraph:
    """
    Reconstructs multi-stage attacks as directed graphs.

    Nodes: IPs, commands, files, ports, usernames
    Edges: Relationships (executed, accessed, connected)
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.ttl = 86400  # 24 hours

    def add_event(self, event: HoneypotEvent):
        """
        Add event to graph, creating nodes and edges.
        """
        # Create nodes
        src_node = self._create_node(event.source_ip, "ip")
        cmd_node = self._create_node(event.command, "command")

        # Create edge with timestamp
        self.graph.add_edge(src_node, cmd_node,
                           timestamp=event.timestamp,
                           weight=event.risk_score)

    def get_attack_chain(self, start_node: str, max_hops: int = 3):
        """
        Retrieve multi-hop attack chain from starting node.
        """
        return nx.single_source_shortest_path(self.graph,
                                             start_node,
                                             cutoff=max_hops)

    def prune_old_nodes(self):
        """
        Remove nodes older than TTL.
        """
        current_time = time.time()
        old_nodes = [n for n, data in self.graph.nodes(data=True)
                     if current_time - data['timestamp'] > self.ttl]
        self.graph.remove_nodes_from(old_nodes)
```

**Visualization:**
- Export to Cytoscape.js (web UI)
- Export to DOT (Graphviz)
- Export to JSON (custom tools)

**Key Metrics:**
- Graph build time (target: <500ms per event)
- Multi-hop query time (target: <200ms)
- Memory usage (target: <1GB for 100K nodes)

---

#### **Component 3: ML Anomaly Detector**

**Extract From:**
- `src/ai/model_manager.py` (Isolation Forest section)
- Feature extraction logic

**Adaptation:**
```python
class AnomalyDetector:
    """
    Detects novel attacks using Isolation Forest.

    Features: command frequency, port patterns, timing, sequences
    """

    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.trained = False

    def train(self, historical_events: List[HoneypotEvent]):
        """
        Train on historical honeypot data (unsupervised).
        """
        features = [self._extract_features(e) for e in historical_events]
        features_scaled = self.scaler.fit_transform(features)
        self.model.fit(features_scaled)
        self.trained = True

    def detect(self, event: HoneypotEvent) -> AnomalyScore:
        """
        Return anomaly score (-1 = anomaly, 1 = normal).
        """
        if not self.trained:
            return AnomalyScore(score=0, confidence=0)

        features = self._extract_features(event)
        features_scaled = self.scaler.transform([features])

        prediction = self.model.predict(features_scaled)[0]
        anomaly_score = self.model.decision_function(features_scaled)[0]

        return AnomalyScore(
            score=anomaly_score,
            is_anomaly=(prediction == -1),
            confidence=abs(anomaly_score)
        )

    def _extract_features(self, event: HoneypotEvent) -> np.ndarray:
        """
        Extract numerical features for ML.
        """
        return np.array([
            event.port,
            hash(event.command) % 1000,
            event.session_duration,
            event.bytes_transferred,
            event.num_commands,
            event.hour_of_day,
            event.day_of_week
        ])
```

**Key Metrics:**
- Anomaly detection accuracy (target: 85%+)
- False positive rate (target: <15%)
- Training time (target: <5 min on 100K events)

---

#### **Component 4: Threat Intel RAG**

**Extract From:**
- `src/artifact/embedding.py`
- `src/artifact/llm_refine.py`

**Adaptation:**
```python
class ThreatIntelRAG:
    """
    Enriches attacks with threat intel via RAG.

    Retrieval: Semantic search over past attacks + threat feeds
    Augmentation: Inject context into prompts
    Generation: LLM provides analysis and recommendations
    """

    def __init__(self, vector_store: VectorStore):
        self.vector_store = vector_store
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        self.llm_client = OpenAI()  # or local model

    def enrich_attack(self, event: HoneypotEvent) -> EnrichedAttack:
        """
        Enrich single attack with threat intel context.
        """
        # 1. Embed attack
        query_text = f"{event.source_ip} {event.command} {event.user_agent}"
        query_embedding = self.embedder.encode(query_text)

        # 2. Retrieve similar attacks
        similar = self.vector_store.search(query_embedding, k=5)

        # 3. Retrieve threat intel for IP
        threat_intel = self._get_threat_intel(event.source_ip)

        # 4. Build context
        context = self._build_context(similar, threat_intel)

        # 5. Generate analysis
        analysis = self._generate_analysis(event, context)

        return EnrichedAttack(
            event=event,
            similar_attacks=similar,
            threat_intel=threat_intel,
            llm_analysis=analysis
        )

    def _generate_analysis(self, event: HoneypotEvent, context: str) -> str:
        """
        Use LLM to generate natural language analysis.
        """
        prompt = f"""
        You are a cybersecurity analyst. Analyze this honeypot event:

        Event: {event.to_dict()}

        Context:
        {context}

        Provide:
        1. Attack classification
        2. Likely threat actor type
        3. Recommended actions
        """

        response = self.llm_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=500
        )

        return response.choices[0].message.content
```

**Key Metrics:**
- Retrieval precision (target: 70%+)
- LLM analysis quality (human eval: 4/5+)
- Response time (target: <2s per event)

---

#### **Component 5: Multi-Framework Mapper**

**Extract From:**
- `src/artifact/technique_mapping.py`
- `src/core/mappings/mitre_stride.py`

**Adaptation:**
```python
class ThreatFrameworkMapper:
    """
    Maps attacks to MITRE ATT&CK, Kill Chain, STRIDE.

    Uses rule-based logic + embeddings for fuzzy matching.
    """

    def __init__(self):
        self.mitre_db = self._load_mitre_attack()
        self.kill_chain_stages = ["recon", "weaponization", "delivery",
                                  "exploitation", "installation",
                                  "command_control", "actions_on_objectives"]
        self.stride = ["spoofing", "tampering", "repudiation",
                      "info_disclosure", "dos", "elevation"]

    def map_attack(self, event: HoneypotEvent) -> FrameworkMapping:
        """
        Map single event to multiple frameworks.
        """
        return FrameworkMapping(
            mitre_tactics=self._map_mitre_tactics(event),
            mitre_techniques=self._map_mitre_techniques(event),
            kill_chain_stage=self._map_kill_chain(event),
            stride_categories=self._map_stride(event)
        )

    def _map_mitre_techniques(self, event: HoneypotEvent) -> List[str]:
        """
        Map to MITRE techniques using keywords + embeddings.
        """
        techniques = []

        # Rule-based matching
        if "whoami" in event.command:
            techniques.append("T1033")  # System Owner/User Discovery
        if "cat /etc/passwd" in event.command:
            techniques.append("T1087")  # Account Discovery
        if "wget" in event.command or "curl" in event.command:
            techniques.append("T1105")  # Ingress Tool Transfer

        # Embedding-based fuzzy match
        cmd_embedding = self.embedder.encode(event.command)
        for tid, tech in self.mitre_db.items():
            tech_embedding = self.embedder.encode(tech['description'])
            similarity = cosine_similarity(cmd_embedding, tech_embedding)
            if similarity > 0.75:
                techniques.append(tid)

        return techniques
```

**Key Metrics:**
- MITRE mapping accuracy (target: 80%+)
- Kill Chain mapping accuracy (target: 85%+)
- Mapping latency (target: <50ms per event)

---

#### **Component 6: Factor-Based Risk Scorer**

**Extract From:**
- `src/artifact/factors.py`
- `src/artifact/risk.py`

**Adaptation:**
```python
class RiskScorer:
    """
    Scores attacks using factor-based system.

    Factors: novelty, sophistication, lateral_movement, etc.
    """

    def __init__(self):
        self.factor_weights = {
            "rare_exploit": 0.9,
            "privilege_escalation": 0.85,
            "lateral_movement": 0.8,
            "data_exfiltration": 0.9,
            "persistence": 0.75,
            "credential_access": 0.7,
            "reconnaissance": 0.4,
            "automated_scan": 0.1
        }

    def score_attack(self, event: HoneypotEvent, factors: List[str]) -> RiskScore:
        """
        Calculate risk score from factors.
        """
        score = 0.0
        confidence = 0.0

        for factor in factors:
            weight = self.factor_weights.get(factor, 0.5)
            score += weight
            confidence += 1.0

        # Normalize
        score = min(score / len(factors), 1.0) if factors else 0.0
        confidence = min(confidence / len(factors), 1.0) if factors else 0.0

        return RiskScore(
            score=score,
            confidence=confidence,
            factors=factors,
            severity=self._get_severity(score)
        )

    def _get_severity(self, score: float) -> str:
        if score >= 0.8: return "critical"
        if score >= 0.6: return "high"
        if score >= 0.4: return "medium"
        return "low"
```

**Key Metrics:**
- Risk score correlation with analyst triage (target: 0.7+)
- Prioritization accuracy (target: 85%+)

---

### 3.3 Database Architecture

**Decision: Tiered Approach**

**MVP (Phase 1): SQLite + In-Memory FAISS**

```python
# Schema
attacks_table = """
CREATE TABLE attacks (
    id TEXT PRIMARY KEY,
    timestamp REAL,
    source_ip TEXT,
    source_port INTEGER,
    dest_port INTEGER,
    honeypot_type TEXT,
    command TEXT,
    session_id TEXT,
    raw_log TEXT,
    factors TEXT,  -- JSON array
    risk_score REAL,
    mitre_techniques TEXT,  -- JSON array
    campaign_id TEXT
);

CREATE INDEX idx_timestamp ON attacks(timestamp);
CREATE INDEX idx_source_ip ON attacks(source_ip);
CREATE INDEX idx_campaign ON attacks(campaign_id);
"""

# FAISS for embeddings (in-memory)
vector_index = faiss.IndexFlatL2(384)  # SentenceTransformer dim
```

**Production (Phase 2): PostgreSQL + pgvector**

```sql
CREATE EXTENSION vector;

CREATE TABLE attacks (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ,
    source_ip INET,
    dest_port INTEGER,
    honeypot_type TEXT,
    command TEXT,
    session_id TEXT,
    raw_log JSONB,
    embedding VECTOR(384),
    factors TEXT[],
    risk_score FLOAT,
    mitre_techniques TEXT[],
    campaign_id TEXT
);

CREATE INDEX ON attacks USING ivfflat (embedding vector_cosine_ops);
CREATE INDEX ON attacks USING GIN (factors);
CREATE INDEX ON attacks (timestamp DESC);
```

**Enterprise (Phase 3): Qdrant (Optional)**

```python
# Config flag
storage_backend = os.getenv("STORAGE_BACKEND", "sqlite")  # sqlite|postgres|qdrant

if storage_backend == "qdrant":
    client = QdrantClient(host="localhost", port=6333)
    client.create_collection(
        collection_name="attacks",
        vectors_config=VectorParams(size=384, distance=Distance.COSINE)
    )
```

---

### 3.4 API Design

**REST API Endpoints:**

```python
# Ingestion
POST /api/v1/ingest
    Body: { "source": "cowrie", "log_file": "..." }
    Response: { "events_processed": 1234, "campaigns_detected": 5 }

# Queries
GET /api/v1/attacks?start_time=...&end_time=...&min_risk=0.7
    Response: [ { "id": "...", "timestamp": "...", ... } ]

GET /api/v1/attacks/{id}
    Response: { "id": "...", "enrichment": {...}, "graph": {...} }

GET /api/v1/campaigns/{id}
    Response: { "campaign_id": "...", "attacks": [...], "graph": {...} }

# Graph
GET /api/v1/graph?source_ip=1.2.3.4&max_hops=3
    Response: { "nodes": [...], "edges": [...] }

# RAG Enrichment
POST /api/v1/enrich/{attack_id}
    Response: { "similar_attacks": [...], "threat_intel": {...}, "analysis": "..." }

# Exports
GET /api/v1/export/stix?campaign_id=...
    Response: STIX JSON bundle

GET /api/v1/export/json?start_time=...
    Response: JSON array of attacks
```

---

### 3.5 Web UI Components

**Dashboard Views:**

1. **Overview Dashboard**
   - Real-time attack count (last 24h)
   - Risk score histogram
   - Top source IPs/countries
   - MITRE heatmap

2. **Attack Timeline**
   - Temporal view of attacks
   - Highlighted campaigns
   - Filter by risk/type

3. **Attack Chain Graph**
   - Interactive Cytoscape.js graph
   - Zoom, pan, filter
   - Click node → details panel

4. **Campaign View**
   - List of detected campaigns
   - Attack count, risk, timespan
   - Click → attack chain graph

5. **Attack Details**
   - Full event details
   - Enrichment (RAG)
   - MITRE/Kill Chain mapping
   - Similar attacks

**Tech Stack:**
- Frontend: React + TypeScript
- Visualization: Cytoscape.js (graphs), Recharts (charts)
- API: FastAPI
- Auth: API keys (simple)

---

## 4. Phased Roadmap

### Phase 1: MVP (0-3 months)

**Goal:** Functional prototype with core features

**Scope:**
- ✅ Log ingestion (Cowrie only)
- ✅ Temporal correlation (EWMA)
- ✅ HopGraph attack chains
- ✅ Isolation Forest anomaly detection
- ✅ MITRE ATT&CK mapping
- ✅ Factor-based risk scoring
- ✅ SQLite + FAISS storage
- ✅ REST API
- ✅ Basic web UI (attack list + graph)

**Not Included:**
- ❌ RAG enrichment
- ❌ Advanced ML (LSTM, GNN)
- ❌ STIX export
- ❌ T-Pot/Dionaea support

**Success Metrics:**
- Processes 10K events in <5 minutes
- Detects 3+ real attack campaigns
- Graph visualizes multi-hop chains
- 10+ GitHub stars

**Timeline:**
- Month 1: Core extraction + ingestion
- Month 2: Correlation + graph + ML
- Month 3: API + UI + docs

---

### Phase 2: Production (3-6 months)

**Goal:** Production-ready with RAG and multi-honeypot support

**Scope:**
- ✅ PostgreSQL + pgvector backend
- ✅ RAG threat intel enrichment
- ✅ Multi-honeypot support (Cowrie, T-Pot, Dionaea)
- ✅ STIX/TAXII export
- ✅ Kill Chain + STRIDE mapping
- ✅ SIEM integration (JSON webhooks)
- ✅ Advanced UI (timeline, campaign view)
- ✅ Docker Compose deployment
- ✅ Documentation + tutorials

**Success Metrics:**
- 100+ GitHub stars
- 10+ active users
- 3+ community PRs
- Conference talk accepted (BSides)

**Timeline:**
- Month 4: RAG + multi-honeypot
- Month 5: Exports + SIEM
- Month 6: Docs + polish + launch

---

### Phase 3: Research (6-12 months)

**Goal:** Cutting-edge ML features and research papers

**Scope:**
- ✅ LSTM sequence prediction (next command)
- ✅ Behavioral clustering (attacker profiling)
- ✅ GNN attack path prediction
- ✅ Anomaly ensemble (IsolationForest + SVM + LOF)
- ✅ Qdrant backend option
- ✅ Advanced visualizations
- ✅ Multi-site federation (optional)

**Success Metrics:**
- 500+ GitHub stars
- 50+ active users
- 1 research paper published (IEEE S&P, NDSS)
- Integration with major platform (T-Pot)

**Timeline:**
- Months 7-9: LSTM + GNN + clustering
- Months 10-12: Paper writing + publishing

---

## 5. Components to Extract from JanuSec

### 5.1 Priority Extraction List

**High Priority (MVP):**
1. `src/live/correlation_window.py` → Temporal correlation
2. `src/analytics/drift_analyzer.py` → EWMA
3. `src/core/graph/hopgraph_lite.py` → Attack graphs
4. `src/ai/model_manager.py` → Isolation Forest
5. `src/artifact/technique_mapping.py` → MITRE mapping
6. `src/artifact/factors.py` → Factor detection
7. `src/artifact/risk.py` → Risk scoring

**Medium Priority (Phase 2):**
8. `src/artifact/embedding.py` → RAG embeddings
9. `src/artifact/llm_refine.py` → LLM enrichment
10. `src/core/mappings/mitre_stride.py` → Multi-framework
11. `src/core/detect/beacon_analyzer.py` → Beaconing
12. `src/core/detect/domain_tracker.py` → Domain tracking

**Low Priority (Phase 3):**
13. `src/modules/adaptive_tuner.py` → Adaptive thresholds
14. `src/artifact/feedback.py` → Active learning

### 5.2 Adaptation Guidelines

**For Each Component:**
1. **Rename classes:** `JanuSecCorrelator` → `HoneyGraphCorrelator`
2. **Change data model:** `SecurityEvent` → `HoneypotEvent`
3. **Simplify config:** Remove multi-tenant, compliance features
4. **Add honeypot-specific features:** Parse Cowrie JSON logs
5. **Update tests:** Adapt test data to honeypot format
6. **Document differences:** Comment on JanuSec vs HoneyGraph usage

---

## 6. Data Model

### 6.1 Core Schema

```python
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

@dataclass
class HoneypotEvent:
    """Single honeypot event (attack attempt)."""
    id: str
    timestamp: datetime
    source_ip: str
    source_port: int
    dest_port: int
    honeypot_type: str  # cowrie, dionaea, etc.
    session_id: str
    command: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    user_agent: Optional[str] = None
    bytes_transferred: int = 0
    session_duration: float = 0
    raw_log: dict = None

    # Enrichment (added by HoneyGraph)
    factors: List[str] = None
    risk_score: float = 0.0
    confidence: float = 0.0
    mitre_techniques: List[str] = None
    kill_chain_stage: Optional[str] = None
    campaign_id: Optional[str] = None
    anomaly_score: float = 0.0
    embedding: List[float] = None

@dataclass
class Campaign:
    """Group of related attacks (detected campaign)."""
    id: str
    start_time: datetime
    end_time: datetime
    attack_ids: List[str]
    source_ips: List[str]
    risk_score: float
    size: int  # number of attacks
    description: str

@dataclass
class AttackChain:
    """Graph representation of multi-stage attack."""
    campaign_id: str
    nodes: List[dict]  # [{"id": "...", "type": "ip|command|file", ...}]
    edges: List[dict]  # [{"source": "...", "target": "...", "weight": ...}]
    root_node: str
    depth: int  # max hops
```

---

## 7. Metrics & Observability

### 7.1 System Metrics

**Performance:**
- Events processed per second (target: 100+)
- End-to-end latency (ingest → analysis) (target: <1s)
- Graph query time (target: <200ms)
- RAG enrichment time (target: <2s)
- Memory usage (target: <2GB for 100K events)

**Quality:**
- Campaign detection rate (target: 80%+)
- MITRE mapping accuracy (target: 80%+)
- Anomaly detection F1 score (target: 0.75+)
- Risk score correlation with analyst triage (target: 0.7+)

**Engagement:**
- GitHub stars (target: 100 @ 6 months)
- Active users (target: 10 @ 6 months)
- Community PRs (target: 3 @ 6 months)
- Conference talks (target: 1 @ 9 months)

### 7.2 Monitoring

**Built-in Metrics:**
```python
from prometheus_client import Counter, Histogram, Gauge

events_processed = Counter('honeygraph_events_processed', 'Total events processed')
processing_latency = Histogram('honeygraph_processing_seconds', 'Event processing time')
campaigns_detected = Gauge('honeygraph_active_campaigns', 'Number of active campaigns')
anomalies_detected = Counter('honeygraph_anomalies', 'Novel attacks detected')
```

**Health Checks:**
```python
GET /health
    Response: {
        "status": "healthy",
        "events_processed_24h": 12345,
        "campaigns_active": 7,
        "storage_backend": "postgres",
        "version": "0.1.0"
    }
```

---

## 8. Deployment

### 8.1 Docker Compose (Recommended)

```yaml
version: '3.8'

services:
  honeygraph:
    image: honeygraph/honeygraph:latest
    ports:
      - "8000:8000"  # API
      - "3000:3000"  # Web UI
    environment:
      - STORAGE_BACKEND=postgres
      - POSTGRES_HOST=db
      - ENABLE_RAG=true
      - LLM_PROVIDER=openai
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./logs:/app/logs
      - ./config.yaml:/app/config.yaml
    depends_on:
      - db

  db:
    image: pgvector/pgvector:latest
    environment:
      - POSTGRES_USER=honeygraph
      - POSTGRES_PASSWORD=honeygraph
      - POSTGRES_DB=honeygraph
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

### 8.2 Configuration

```yaml
# config.yaml
honeygraph:
  storage:
    backend: postgres  # sqlite | postgres | qdrant
    postgres:
      host: localhost
      port: 5432
      database: honeygraph
      user: honeygraph
      password: ${POSTGRES_PASSWORD}

  ingestion:
    sources:
      - type: cowrie
        path: /var/log/cowrie/cowrie.json
        batch_size: 100
      - type: tpot
        path: /data/tpot/

  correlation:
    window_size: 3600  # 1 hour
    ewma_alpha: 0.3
    campaign_threshold: 0.75

  ml:
    isolation_forest:
      contamination: 0.1
      n_estimators: 100
    embeddings:
      model: all-MiniLM-L6-v2

  rag:
    enabled: true
    llm_provider: openai  # openai | ollama | none
    openai_api_key: ${OPENAI_API_KEY}
    max_context: 5  # similar attacks to retrieve

  api:
    host: 0.0.0.0
    port: 8000
    auth: api_key
    api_keys:
      - ${API_KEY_1}

  ui:
    port: 3000
    graph_max_nodes: 1000
```

---

## 9. Open Source Strategy

### 9.1 License

**MIT License** (permissive, encourages adoption)

Rationale:
- ✅ Allows commercial use (companies can deploy)
- ✅ Minimal restrictions (easy contribution)
- ✅ Good for portfolio (shows sharing)

### 9.2 Repository Structure

```
honeygraph/
├── README.md
├── LICENSE (MIT)
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── docker-compose.yml
├── config.example.yaml
├── requirements.txt
├── setup.py
├── src/
│   ├── honeygraph/
│   │   ├── __init__.py
│   │   ├── ingestion/
│   │   ├── correlation/
│   │   ├── graph/
│   │   ├── ml/
│   │   ├── rag/
│   │   ├── api/
│   │   └── ui/
├── tests/
├── docs/
│   ├── architecture.md
│   ├── quickstart.md
│   ├── integrations/
│   └── research/
└── examples/
    ├── cowrie_demo.py
    └── sample_data/
```

### 9.3 Community Building

**Launch Strategy:**
1. **Soft Launch:** Post on r/netsec, r/AskNetsec
2. **Blog Post:** Technical deep-dive on personal blog
3. **Conference Talk:** Submit to BSides, DEFCON (Demo Labs)
4. **Twitter/LinkedIn:** Share with hashtags #honeypot #threatintel #opensource
5. **Integration PRs:** Submit to T-Pot, MHN repos

**Engagement:**
- Respond to issues within 48 hours
- Accept quality PRs
- Monthly release cycle
- Quarterly roadmap updates

---

## 10. Success Metrics

### 10.1 MVP Success (3 months)

- [ ] 100+ GitHub stars
- [ ] 10+ active users/orgs
- [ ] 3+ community PRs
- [ ] Processes 100K events without crashing
- [ ] Detects 5+ real campaigns in test data
- [ ] Conference talk submitted (BSides)

### 10.2 Production Success (6 months)

- [ ] 300+ GitHub stars
- [ ] 30+ active deployments
- [ ] 10+ community PRs
- [ ] Integration with T-Pot
- [ ] Conference talk accepted
- [ ] Blog post with 1K+ views

### 10.3 Research Success (12 months)

- [ ] 500+ GitHub stars
- [ ] 50+ active deployments
- [ ] Research paper published (IEEE S&P, NDSS)
- [ ] Cited in academic work
- [ ] Enterprise inquiries (commercial support)

---

## 11. Risks & Mitigation

### 11.1 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Scalability issues** | Medium | High | Optimize early, provide config tuning guide |
| **ML false positives** | High | Medium | Clear confidence scores, human-in-loop |
| **Integration complexity** | Medium | Medium | Support 1-2 honeypots initially, expand later |
| **RAG LLM costs** | Low | Medium | Make RAG optional, support local models |

### 11.2 Market Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Low adoption** | Medium | High | Strong differentiation, good docs, active marketing |
| **Competitor emerges** | Low | Medium | Speed to market, novel features (GNN, RAG) |
| **Maintenance burden** | High | Medium | Clear scope, say no to feature creep |
| **Commercial pressure** | Low | Low | MIT license, open core model if needed later |

---

## 12. Next Steps (Action Items)

### 12.1 Before Starting Development

- [ ] **Confirm IP ownership with Cyberstash CEO**
- [ ] **Create GitHub repo** (public, MIT license)
- [ ] **Set up project structure** (see 9.2)
- [ ] **Extract core components** from JanuSec (see 5.1)
- [ ] **Write architecture doc** (for contributors)

### 12.2 Week 1-2: Foundation

- [ ] Set up dev environment (Python 3.11+, FastAPI)
- [ ] Create data models (HoneypotEvent, Campaign, etc.)
- [ ] Implement log parser (Cowrie JSON)
- [ ] Set up SQLite storage
- [ ] Write basic tests

### 12.3 Week 3-4: Correlation

- [ ] Port temporal correlation (correlation_window.py)
- [ ] Port EWMA drift detection (drift_analyzer.py)
- [ ] Implement campaign detection
- [ ] Test on sample Cowrie data

### 12.4 Week 5-6: Graph

- [ ] Port HopGraph (hopgraph_lite.py)
- [ ] Adapt for honeypot node types
- [ ] Implement TTL pruning
- [ ] Test multi-hop queries

### 12.5 Week 7-8: ML

- [ ] Port Isolation Forest (model_manager.py)
- [ ] Implement feature extraction for honeypot events
- [ ] Train on sample data
- [ ] Evaluate accuracy

### 12.6 Week 9-10: Framework Mapping

- [ ] Port MITRE mapping (technique_mapping.py)
- [ ] Add Kill Chain logic
- [ ] Test mapping accuracy

### 12.7 Week 11-12: API & UI

- [ ] Build REST API (FastAPI)
- [ ] Create basic React UI
- [ ] Implement graph visualization (Cytoscape.js)
- [ ] Write API docs

### 12.8 Month 4: Launch Prep

- [ ] Write README, quickstart, docs
- [ ] Record demo video
- [ ] Test end-to-end on real Cowrie data
- [ ] Launch: Reddit, Twitter, blog post

---

## 13. Conclusion

**Is This Viable?** **YES.**

**Key Strengths:**
- ✅ Real market gap (no AI/ML correlation for honeypots)
- ✅ Novel technical approach (temporal RAG + graphs + ML)
- ✅ Feasible scope (80% code already exists)
- ✅ Clear differentiation (vs T-Pot, Cowrie, etc.)
- ✅ Research potential (multiple publishable papers)
- ✅ Career value (strong portfolio piece)

**Recommendation:**
**Proceed with MVP (3 months), evaluate adoption, then decide on Phase 2.**

**Next Action:**
- Confirm IP ownership with Cyberstash
- Create GitHub repo
- Start Week 1 tasks

---

**Document Version:** 0.1 (Draft)
**Status:** Ready for Review
**Approval Needed:** Cyberstash CEO (IP ownership), Self (time commitment)
**Next Review:** After 3-month MVP

---

*"This is not crack. This is a solid open-source project with real value. Ship it."*
