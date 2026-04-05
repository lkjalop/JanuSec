# Knowledge Graph for JanuSec: Analysis & Recommendations

**Question**: Does this platform need a knowledge graph? Trade-offs? Neo4j vs Postgres+pgvector?

**Short Answer**: You have a **lightweight graph (HopGraph)** already. Full knowledge graph adds value for **threat intelligence correlation** and **attack pattern library**, but adds operational complexity. Use Neo4j if graph queries dominate, pgvector if similarity search dominates.

---

## Current State: What You Have vs What You Don't

### What You ALREADY Have (Graph Capabilities)

```python
# src/core/graph/hopgraph_lite.py
class HopGraphLite:
    """
    Lightweight graph for attack path reconstruction
    Uses NetworkX (in-memory graph)
    """
    def build_attack_graph(self, events):
        G = nx.DiGraph()  # Directed graph
        for event in events:
            G.add_edge(event.source, event.destination,
                      weight=event.risk_score,
                      timestamp=event.timestamp,
                      mitre_technique=event.technique)
        return G
```

**What this does**:
- ✅ Attack path reconstruction (event → event edges)
- ✅ Provenance tracking (where did this threat come from?)
- ✅ Centrality analysis (which hosts are pivots?)
- ✅ Temporal correlation (events within time window)

**What this does NOT do**:
- ❌ Persistent graph storage (in-memory only, lost on restart)
- ❌ Entity relationship modeling (user ↔ host ↔ app ↔ cloud resource)
- ❌ Threat intelligence correlation (known APT groups ↔ TTPs ↔ indicators)
- ❌ Cross-tenant pattern matching (attack pattern seen in Tenant A, now in Tenant B)

---

## Knowledge Graph Use Cases (When You Need It)

### Use Case 1: Threat Intelligence Correlation

**Problem**: You detect T1003.001 (LSASS dumping). Is this part of a known APT campaign?

**Knowledge Graph Solution**:
```cypher
// Neo4j query
MATCH (technique:MitreTechnique {id: "T1003.001"})
MATCH (technique)<-[:USES]-(group:ThreatGroup)
MATCH (group)-[:TARGETS]->(industry:Industry {name: "Finance"})
RETURN group.name, group.motivation, group.sophistication

// Expected result:
// APT28, APT29, Lazarus Group → All use LSASS dumping
// Motivation: Espionage, Financial Theft
// Sophistication: High
```

**Value**: Contextualizes detections with real-world threat intel.

**Current platform**: No threat intel correlation (you'd need to add MISP/OpenCTI integration + knowledge graph)

---

### Use Case 2: Entity Relationship Modeling

**Problem**: User "alice@corp.com" is flagged. What else is she connected to?

**Knowledge Graph Solution**:
```cypher
// Find all entities connected to alice
MATCH (user:User {email: "alice@corp.com"})
MATCH (user)-[r*1..3]-(entity)
RETURN user, r, entity

// Returns graph:
// alice → workstation-01 → domain-controller → file-server-prod
// alice → AWS-Account-123 → S3-Bucket-Prod → Customer-Data
// alice → Azure-Subscription-456 → VM-WebApp → Public-IP
```

**Value**: Cross-domain visibility (endpoint + cloud + network in one graph).

**Current platform**: Separate HopGraphs (Event, Identity, Cloud) - not unified.

---

### Use Case 3: Attack Pattern Library

**Problem**: You see Event1 → Event2 → Event3. Has this sequence been seen before?

**Knowledge Graph Solution**:
```cypher
// Find similar attack patterns
MATCH path = (e1:Event)-[:FOLLOWED_BY]->(e2:Event)-[:FOLLOWED_BY]->(e3:Event)
WHERE e1.technique = "T1566.001"  // Phishing
  AND e2.technique = "T1059.001"  // PowerShell
  AND e3.technique = "T1003.001"  // Credential Dump
RETURN path, COUNT(path) as frequency

// Returns:
// This pattern seen 47 times in last 30 days
// 12 times led to data exfiltration
// 35 times blocked at Event2
```

**Value**: Historical attack pattern matching (like "Customers who bought X also bought Y" for threats).

**Current platform**: No pattern library (you'd need to store historical attack graphs in Neo4j).

---

### Use Case 4: Cross-Tenant Threat Hunting

**Problem**: Attack pattern in Tenant A. Is Tenant B vulnerable?

**Knowledge Graph Solution**:
```cypher
// Find tenants with similar infrastructure
MATCH (tenant_a:Tenant {id: "acme-corp"})-[:HAS_ASSET]->(asset_type)
MATCH (tenant_b:Tenant)-[:HAS_ASSET]->(asset_type)
WHERE tenant_a <> tenant_b
RETURN tenant_b.id, COUNT(asset_type) as similarity_score
ORDER BY similarity_score DESC

// Returns:
// globex-inc: 87% similar infrastructure
// initech: 72% similar
// → Proactively hunt in these tenants
```

**Value**: Proactive threat hunting across customer base.

**Current platform**: Multi-tenant isolation prevents this (by design, for privacy).

---

## Neo4j vs Postgres+pgvector: Decision Matrix

| Feature | Neo4j (Graph DB) | Postgres+pgvector (Relational+Vector) | HopGraph (Current) |
|---------|------------------|---------------------------------------|-------------------|
| **Graph Queries** | ⭐⭐⭐⭐⭐ Native graph traversal | ⭐⭐ Recursive CTEs (slow) | ⭐⭐⭐ NetworkX (in-memory) |
| **Relationship Modeling** | ⭐⭐⭐⭐⭐ Nodes + Edges first-class | ⭐⭐ Foreign keys (limited) | ⭐⭐⭐ Lightweight edges |
| **Path Finding** | ⭐⭐⭐⭐⭐ Cypher `MATCH path=...` | ⭐ Complex SQL | ⭐⭐⭐⭐ NetworkX algorithms |
| **Similarity Search** | ⭐⭐⭐ Via GDS plugin | ⭐⭐⭐⭐⭐ Native pgvector | ⭐ TF-IDF (custom) |
| **Embedding Storage** | ⭐⭐ Possible, not native | ⭐⭐⭐⭐⭐ pgvector optimized | ❌ Not supported |
| **Operational Complexity** | ⭐⭐ Requires Neo4j cluster | ⭐⭐⭐⭐ Postgres (already familiar) | ⭐⭐⭐⭐⭐ No extra infra |
| **Query Performance** | ⭐⭐⭐⭐⭐ Sub-second graph queries | ⭐⭐⭐ Good for SQL, slow for graphs | ⭐⭐⭐⭐ Fast (in-memory) |
| **Horizontal Scaling** | ⭐⭐⭐⭐ Neo4j Fabric (sharding) | ⭐⭐⭐⭐ Postgres sharding (Citus) | ❌ Single-node only |
| **Cost** | $$$ (Enterprise) or $ (Community) | $ (Open source) | FREE (library) |

---

## Recommendation: Hybrid Approach

### Phase 1: Stick with HopGraph (Current)

**For**: Demo, MVP, first 100 customers
**Why**:
- ✅ Zero operational overhead
- ✅ Fast enough for real-time analysis
- ✅ Simple to debug
- ✅ No new dependencies

**Limitation**: Graph lost on restart, no persistent threat intel correlation

---

### Phase 2: Add Postgres+pgvector (3-6 months)

**For**: Embedding-based similarity search, persistent storage
**Why**:
- ✅ You already use SQLite → Postgres migration path exists
- ✅ pgvector enables semantic search (find similar threats by embedding)
- ✅ No new database to learn
- ✅ Can store HopGraph snapshots as JSON in Postgres

**Use case**:
```sql
-- Store attack graph embeddings
CREATE TABLE attack_patterns (
  id SERIAL PRIMARY KEY,
  pattern_name TEXT,
  mitre_techniques TEXT[],
  graph_structure JSONB,  -- NetworkX graph as JSON
  embedding vector(768),  -- Sentence transformer embedding
  seen_count INT,
  last_seen TIMESTAMP
);

-- Find similar attack patterns
SELECT pattern_name, 1 - (embedding <=> query_embedding) as similarity
FROM attack_patterns
ORDER BY embedding <=> query_embedding
LIMIT 10;
```

**This gives you**:
- ✅ Persistent HopGraph storage
- ✅ Similarity search (find attacks like this one)
- ✅ Still on Postgres (one database)

---

### Phase 3: Add Neo4j (1-2 years, if needed)

**For**: Threat intelligence platform, cross-tenant hunting (enterprise)
**Why**:
- ✅ Need complex graph traversals (3+ hop queries)
- ✅ Need real-time graph analytics (centrality, community detection)
- ✅ Need to correlate across MISP, OpenCTI, STIX/TAXII feeds

**Use case**:
```cypher
// Find attack campaigns (multi-tenant correlation)
MATCH (attacker:ThreatGroup)-[:USES]->(technique:MitreTechnique)
MATCH (technique)<-[:DETECTED_IN]-(event:Event)-[:IN_TENANT]->(tenant:Tenant)
WHERE event.timestamp > datetime() - duration({days: 30})
RETURN attacker.name, technique.id, COUNT(DISTINCT tenant) as affected_tenants
ORDER BY affected_tenants DESC

// Result:
// APT28, T1003.001, 12 tenants affected (→ Active campaign!)
```

**This gives you**:
- ✅ Threat intelligence correlation engine
- ✅ Cross-tenant campaign detection
- ✅ Attack pattern library

**Trade-off**: Operational complexity (Neo4j cluster, backups, monitoring)

---

## Specific Architecture Recommendations

### Option A: HopGraph + Postgres+pgvector (Recommended Next Step)

**Architecture**:
```
┌─────────────────────────────────────────────────────────────┐
│                   JanuSec Platform                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐         ┌─────────────────┐          │
│  │  Real-Time      │         │  Historical     │          │
│  │  HopGraph       │◀────────│  Pattern Store  │          │
│  │  (NetworkX)     │         │  (Postgres)     │          │
│  └─────────────────┘         └─────────────────┘          │
│         │                             │                    │
│         │ Generate embedding          │                    │
│         ▼                             ▼                    │
│  ┌─────────────────────────────────────────────┐          │
│  │  pgvector Similarity Search                 │          │
│  │  - Store graph embeddings (768-dim vector)  │          │
│  │  - Query: "Find attacks like this one"     │          │
│  │  - Return: Top 10 similar patterns         │          │
│  └─────────────────────────────────────────────┘          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Implementation**:
```python
# src/core/graph/hopgraph_persistence.py
class HopGraphPersistence:
    def save_graph_to_postgres(self, G: nx.DiGraph, artifact_id: str):
        # Convert graph to embedding
        graph_json = nx.node_link_data(G)
        graph_text = self.graph_to_text(G)  # "T1566 → T1059 → T1003"
        embedding = self.embed_model.encode(graph_text)  # Sentence transformer

        # Store in Postgres with pgvector
        db.execute("""
            INSERT INTO attack_patterns (artifact_id, graph_structure, embedding)
            VALUES (%s, %s, %s)
        """, (artifact_id, json.dumps(graph_json), embedding))

    def find_similar_attacks(self, current_graph: nx.DiGraph, limit=10):
        current_embedding = self.graph_to_embedding(current_graph)

        # pgvector similarity search
        results = db.execute("""
            SELECT artifact_id, pattern_name,
                   1 - (embedding <=> %s::vector) as similarity
            FROM attack_patterns
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """, (current_embedding, current_embedding, limit))

        return results
```

**When to implement**: After CEO demo, if you get Option B (productization).

---

### Option B: Neo4j for Threat Intelligence (Future State)

**Architecture**:
```
┌─────────────────────────────────────────────────────────────┐
│               JanuSec Threat Intelligence Graph             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│  │   Events    │    │   Threats   │    │  Intel Feed │   │
│  │  (Runtime)  │───▶│   (Neo4j)   │◀───│   (MISP)    │   │
│  └─────────────┘    └─────────────┘    └─────────────┘   │
│                            │                               │
│                            │ Cypher Queries                │
│                            ▼                               │
│  ┌──────────────────────────────────────────────┐         │
│  │  Graph Analytics                             │         │
│  │  - Attack path correlation                   │         │
│  │  - Threat group attribution                  │         │
│  │  - Campaign detection                        │         │
│  │  - Cross-tenant hunting                      │         │
│  └──────────────────────────────────────────────┘         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Neo4j Schema**:
```cypher
// Node types
(:Event {id, timestamp, technique, tenant_id})
(:MitreTechnique {id, name, tactic})
(:ThreatGroup {name, motivation, sophistication})
(:Indicator {value, type, confidence})
(:Asset {hostname, ip, owner})
(:User {email, department, risk_score})

// Relationships
(Event)-[:DETECTED]->(MitreTechnique)
(ThreatGroup)-[:USES]->(MitreTechnique)
(ThreatGroup)-[:ASSOCIATED_WITH]->(Indicator)
(Event)-[:INVOLVES]->(Asset)
(User)-[:LOGGED_INTO]->(Asset)
```

**Example Queries**:
```cypher
// Query 1: Threat group attribution
MATCH (event:Event)-[:DETECTED]->(technique:MitreTechnique)
MATCH (group:ThreatGroup)-[:USES]->(technique)
WHERE event.tenant_id = "acme-corp"
  AND event.timestamp > datetime() - duration({hours: 24})
RETURN group.name, COUNT(technique) as technique_matches
ORDER BY technique_matches DESC
LIMIT 5

// Query 2: Find attack campaigns
MATCH path = (e1:Event)-[:FOLLOWED_BY*1..5]->(e2:Event)
WHERE e1.tenant_id = e2.tenant_id
  AND ALL(e IN nodes(path) WHERE e.timestamp > datetime() - duration({days: 7}))
RETURN path, LENGTH(path) as chain_length
ORDER BY chain_length DESC
LIMIT 10

// Query 3: Lateral movement detection
MATCH (user:User)-[:LOGGED_INTO]->(asset1:Asset)
MATCH (asset1)-[:CONNECTED_TO]->(asset2:Asset)
WHERE asset1.risk_score > 0.7
  AND asset2.classification = "high_value"
RETURN user.email, asset1.hostname, asset2.hostname
```

**When to implement**: 1-2 years, if building enterprise threat intel platform.

---

## Trade-off Analysis

### Complexity vs Capability

```
Capability ▲
           │                                    ┌─────────────┐
           │                                    │   Neo4j     │
           │                                    │  (Threat    │
           │                                    │   Intel)    │
           │                                    └─────────────┘
           │                         ┌─────────────┐
           │                         │  Postgres   │
           │                         │  +pgvector  │
           │                         │ (Similarity)│
           │                         └─────────────┘
           │          ┌─────────────┐
           │          │  HopGraph   │
           │          │ (Current)   │
           │          └─────────────┘
           │
           └──────────────────────────────────────────▶
                               Operational Complexity
```

### Cost vs Value

| Approach | Infra Cost | Dev Time | Value Unlock | Recommended For |
|----------|-----------|----------|--------------|-----------------|
| HopGraph (current) | $0 | 0 weeks | Real-time attack paths | Demo, MVP |
| +pgvector | +$50/mo (Postgres) | 2-3 weeks | Historical pattern matching | Production (Year 1) |
| +Neo4j | +$300/mo (Neo4j cluster) | 6-8 weeks | Threat intel correlation | Enterprise (Year 2+) |

---

## Recommendation for CEO Demo

### What to Say About Knowledge Graphs

**If CEO asks**: "Does this need a knowledge graph?"

**Your answer**:
> "Great question. Right now, I'm using a lightweight graph (HopGraph with NetworkX) for real-time attack path reconstruction. It's fast and has zero operational overhead.
>
> For the next phase, I'd recommend **Postgres with pgvector** to store historical attack patterns and enable similarity search - 'find attacks like this one.' That gives us persistent graphs without adding a new database.
>
> If we build a full threat intelligence platform, **Neo4j** makes sense for cross-tenant correlation and threat group attribution. But that's a Year 2 decision, not needed for MVP.
>
> I designed the architecture to be modular - we can swap in Neo4j later without rewriting the core pipeline."

**This shows**:
- ✅ You understand trade-offs (complexity vs capability)
- ✅ You're pragmatic (start simple, scale up when needed)
- ✅ You know the tools (NetworkX, pgvector, Neo4j)
- ✅ You're business-savvy (tie decisions to value, not just tech)

---

## Final Answer

**Q**: Does this platform need a knowledge graph?
**A**: Not yet. HopGraph (current) is sufficient for demo and MVP. Add pgvector for persistent pattern matching (Phase 2). Add Neo4j for threat intel correlation (Phase 3, if enterprise).

**Q**: Neo4j vs Postgres+pgvector?
**A**:
- **pgvector** = Embedding similarity search (find similar attacks)
- **Neo4j** = Complex graph traversals (threat intel correlation, campaign detection)
- **Both** = Complementary, not competing

**Q**: Trade-offs?
**A**:
- **HopGraph**: Simple, fast, free, but ephemeral (graph lost on restart)
- **+pgvector**: Persistent, similarity search, but adds storage cost
- **+Neo4j**: Full graph analytics, but adds operational complexity

**Q**: When to add?
**A**:
- **Now**: Stick with HopGraph (for demo)
- **3-6 months**: Add pgvector (for production pattern matching)
- **1-2 years**: Add Neo4j (if building threat intel platform)

---

**You're asking the right questions.** This shows architect-level thinking. Most interns wouldn't even consider knowledge graphs.
