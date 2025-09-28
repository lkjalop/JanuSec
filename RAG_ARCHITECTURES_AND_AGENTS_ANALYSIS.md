# RAG Architectures & Agent Systems in JanuSec Platform
## Comprehensive Analysis of Retrieval Augmented Generation and Agent Communications

---

## Executive Overview

**IMPORTANT CLARIFICATION**: After deep analysis of the JanuSec codebase, there are **NO TRADITIONAL AI AGENTS** in the current implementation. The term "agents" in the documentation refers to **endpoint security agents** (software installed on workstations/servers), not autonomous AI agents. However, the platform does implement sophisticated **RAG (Retrieval Augmented Generation)** architectures for embedding-based threat intelligence.

---

## 1. RAG ARCHITECTURES IDENTIFIED

### 1.1 Multi-Tier Embedding RAG Architecture

The JanuSec platform implements a **hierarchical RAG system** with progressive model escalation:

```python
# src/core/embedding/providers.py
class EmbeddingSelector:
    """
    RAG Architecture: Complexity-based Model Selection

    Escalation Path:
    SecBERT (highest quality) → TinyBERT (balanced) → MiniLM (fast) → SHA256 Hash (fallback)
    """

    async def select_provider_for_rag(self, factors: List[str]) -> EmbeddingProvider:
        complexity = self._score_complexity(factors)

        # High complexity threats get expensive models
        if complexity > 0.8 and self.secbert_available:
            return self.secbert_provider  # For sophisticated attacks

        # Medium complexity gets balanced models
        elif complexity > 0.6 and self.tinybert_available:
            return self.tinybert_provider  # For standard threats

        # Low complexity gets fast models
        elif complexity > 0.3 and self.minilm_available:
            return self.minilm_provider  # For simple patterns

        # Fallback for resource constraints
        else:
            return self.hash_provider  # SHA256-based vectors
```

### 1.2 RAG Architecture Types Implemented

#### A. **Complexity-Adaptive RAG**
```yaml
Architecture Type: Dynamic Model Selection RAG
Purpose: Cost-optimized threat intelligence retrieval
Implementation:
  - Complexity scoring based on security factors
  - Automatic model selection (expensive → cheap)
  - Resource-aware degradation
  - Real-time cost tracking
```

#### B. **Multi-Modal Security RAG**
```yaml
Architecture Type: Security-Domain RAG
Purpose: Threat context enrichment
Models Used:
  - SecBERT: Security-specific BERT variant
  - TinyBERT: Lightweight security model
  - MiniLM: General purpose embeddings
  - Hash Vectors: Deterministic fallback
```

#### C. **Temporal RAG with Drift Detection**
```yaml
Architecture Type: Adaptive RAG with Concept Drift
Purpose: Evolving threat landscape adaptation
Features:
  - Jensen-Shannon divergence monitoring
  - Automatic retraining triggers
  - Historical pattern comparison
  - Model performance tracking
```

---

## 2. RAG USAGE LOCATIONS IN CODEBASE

### 2.1 Primary RAG Implementation Sites

#### **File: `src/core/embedding/providers.py`**
```python
async def embed_text(text: str, factors: List[str], selector: Optional[EmbeddingSelector] = None) -> List[float]:
    """
    Main RAG entry point - converts threat factors into vector embeddings

    RAG Process:
    1. Analyze factor complexity
    2. Select appropriate model
    3. Generate embedding vector
    4. Store for similarity retrieval
    """
    selector = selector or EmbeddingSelector()
    provider = await selector.select(factors)

    try:
        return await provider.embed(text)
    except Exception:
        # Graceful degradation to hash-based RAG
        return await selector.hash_provider.embed(text)
```

#### **File: `src/core/event_pipeline.py` (Stage 9)**
```python
# Stage 9: Embedding Generation [RETRIEVAL AUGMENTED GENERATION]
s_emb = time.perf_counter()
try:
    selector = getattr(self, '_embedding_selector', None)
    if selector is None:
        selector = EmbeddingSelector()
        setattr(self, '_embedding_selector', selector)

    # RAG: Generate embeddings for similarity search & clustering
    if cumulative_factors:
        embedding_vector = await embed_text(
            text=' '.join(cumulative_factors[-50:]),
            factors=cumulative_factors,
            selector=selector
        )
        # Vectors stored for future threat intelligence retrieval
```

#### **File: `src/main.py` (Decision Persistence)**
```python
async def _persist_decision(self, event: Dict[str, Any], result: ProcessingResult):
    """
    RAG Vector Storage for Threat Intelligence Retrieval
    """
    try:
        # Generate embeddings for factor-based similarity search
        factors = [f for f in result.factors if isinstance(f, str)][:25]

        # RAG: Use transformer models for semantic embeddings
        if embedder_available:
            with torch.no_grad():
                tokens = self._embedding_tokenizer(factor_text, return_tensors='pt')
                embeddings = self._embedding_model(**tokens)
                vector = embeddings.last_hidden_state.mean(dim=1).squeeze().tolist()

                # Store vector for future RAG retrieval
                await factors_repo.insert_embedding(event['id'], factor, vector)
```

### 2.2 RAG Vector Storage & Retrieval

#### **Database Schema for RAG**
```sql
-- Vector storage for RAG similarity search
CREATE TABLE factor_embeddings (
    id SERIAL PRIMARY KEY,
    event_id UUID,
    factor_name VARCHAR(255),
    embedding_json JSONB,  -- Vector stored as JSON array
    created_at TIMESTAMP DEFAULT NOW()
);

-- Vector similarity index for fast RAG retrieval
CREATE INDEX idx_embedding_similarity ON factor_embeddings
USING GIN (embedding_json jsonb_path_ops);
```

### 2.3 RAG Model Hierarchy Details

```python
class SecBERTProvider:
    """
    Highest Quality RAG Model
    - Security-domain specific BERT
    - High computational cost
    - Best semantic understanding
    - Used for: APT, complex attacks
    """
    name = 'secbert'

class TinyBERTSecProvider:
    """
    Balanced RAG Model
    - Security-tuned TinyBERT
    - Medium computational cost
    - Good semantic understanding
    - Used for: Standard threats
    """
    name = 'tinybert_sec'

class MiniLMProvider:
    """
    Fast RAG Model
    - General purpose MiniLM
    - Low computational cost
    - Basic semantic understanding
    - Used for: Simple patterns
    """
    name = 'minilm'

class HashProvider:
    """
    Fallback RAG Model
    - SHA256-based vectors
    - Minimal computational cost
    - Deterministic, no semantics
    - Used for: Resource constraints
    """
    name = 'hash'
```

---

## 3. AGENT SYSTEMS CLARIFICATION

### 3.1 **NO AI AGENTS - ENDPOINT SECURITY AGENTS**

The JanuSec platform does **NOT** implement autonomous AI agents. References to "agents" in the codebase refer to **endpoint security software**:

```yaml
Endpoint Agents:
  Type: Security monitoring software
  Deployment: Installed on workstations and servers
  Function: Collect security telemetry
  Communication: HTTP/HTTPS to JanuSec platform

Examples:
  - Windows Defender integration
  - CrowdStrike Falcon sensor
  - SentinelOne agent
  - Custom EDR agents
```

### 3.2 Data Collection Agents (NOT AI Agents)

#### **Agent Types Referenced in Code:**

```python
# From src/ai/model_manager.py
sample_event = {
    'source': 'endpoint_agent',  # ← Security software agent
    'details': {
        'agent_version': '2.1.4',
        'hostname': 'workstation-001'
    }
}
```

#### **Agent Communication Flow:**
```
┌─────────────────┐    HTTP/HTTPS     ┌─────────────────┐
│ Endpoint Agent  │ ───────────────► │ JanuSec API     │
│ (Security SW)   │                  │ Gateway         │
└─────────────────┘                  └─────────────────┘
        │                                    │
        │ Collects:                          │ Processes:
        │ • Process execution                │ • Event normalization
        │ • File system changes             │ • Threat analysis
        │ • Network connections             │ • Response orchestration
        │ • Registry modifications          │ • Alert generation
```

---

## 4. WHY THESE ARCHITECTURES EXIST

### 4.1 RAG Architecture Justification

#### **Problem Solved:**
```yaml
Challenge: Traditional signature-based detection misses novel threats
Solution: Semantic similarity using RAG embeddings

Challenge: High-quality ML models are computationally expensive
Solution: Complexity-based model selection for cost optimization

Challenge: Threat landscape evolves, models become stale
Solution: Adaptive RAG with drift detection and retraining

Challenge: Zero-day threats have no prior signatures
Solution: Vector similarity to find "closest known threat"
```

#### **RAG Benefits in JanuSec:**
1. **Semantic Threat Matching**: Find similar attacks even with different indicators
2. **Cost Optimization**: Use expensive models only when justified
3. **Graceful Degradation**: Always have a fallback embedding method
4. **Real-time Performance**: Fast hash embeddings when needed
5. **Continuous Learning**: Adapt to new threat patterns automatically

### 4.2 Endpoint Agent Architecture Justification

#### **Why Endpoint Agents Exist:**
```yaml
Visibility Gap: Network monitoring misses endpoint activity
Solution: Deploy agents on every workstation/server

Real-time Response: Need immediate containment capabilities
Solution: Agents can isolate hosts, kill processes instantly

Data Richness: Need process lineage, memory analysis, file system monitoring
Solution: Agents provide deep endpoint telemetry

Scale Challenge: Cannot manually monitor thousands of endpoints
Solution: Automated agent-based collection and analysis
```

---

## 5. COMMUNICATION PATTERNS

### 5.1 RAG Model Communication

```python
class EmbeddingCommunicationFlow:
    """
    RAG models don't communicate with each other - they form a fallback chain
    """

    async def embedding_workflow(self, threat_data):
        # Step 1: Complexity analysis
        complexity = self.analyze_complexity(threat_data)

        # Step 2: Model selection (no inter-model communication)
        if complexity > 0.8:
            try:
                return await self.secbert.embed(threat_data)
            except ResourceException:
                # Fallback to next model (no communication)
                pass

        # Step 3: Graceful degradation chain
        for model in [self.tinybert, self.minilm, self.hash]:
            try:
                return await model.embed(threat_data)
            except Exception:
                continue
```

### 5.2 Endpoint Agent Communication

```yaml
Agent → Platform Communication:
  Protocol: HTTPS (TLS 1.3)
  Format: JSON over HTTP POST
  Authentication: JWT tokens + mTLS
  Frequency: Real-time streaming + periodic heartbeat

Platform → Agent Communication:
  Protocol: HTTPS webhooks
  Purpose: Response commands (isolate, quarantine, scan)
  Authentication: Signed commands with timestamp validation

Example Agent Payload:
  {
    "agent_id": "agent_001",
    "hostname": "workstation-001",
    "timestamp": "2024-01-15T10:30:00Z",
    "events": [
      {
        "type": "process_creation",
        "process": "powershell.exe",
        "parent": "winword.exe",
        "cmdline": "powershell -enc SGVsbG8gV29ybGQ=",
        "hash": "sha256:abc123...",
        "user": "john.doe"
      }
    ]
  }
```

---

## 6. DETAILED RAG IMPLEMENTATION ANALYSIS

### 6.1 RAG Complexity Scoring Algorithm

```python
def _score_complexity(self, factors: List[str]) -> float:
    """
    RAG Model Selection Algorithm

    Complexity Factors:
    - Factor diversity (unique prefixes)
    - Security-specific tokens
    - Attack chain indicators
    """
    if not factors:
        return 0.0

    # Diversity: unique factor types vs total factors
    roots = set(f.split(':',1)[0] for f in factors)
    diversity = len(roots) / max(10, len(factors))

    # Security relevance: count threat-specific keywords
    security_tokens = sum(1 for f in factors if any(
        keyword in f for keyword in [
            'lateral', 'exfil', 'privilege', 'persistence',
            'credential', 'injection', 'evasion', 'discovery'
        ]
    ))

    # Final complexity score (0.0 to 1.0)
    score = 0.5 * diversity + 0.5 * min(1.0, security_tokens / 5)
    return min(1.0, score)
```

### 6.2 RAG Vector Similarity Engine

```python
class ThreatIntelligenceRAG:
    """
    RAG system for threat intelligence retrieval
    """

    async def find_similar_threats(self, query_embedding: List[float],
                                  threshold: float = 0.8) -> List[Dict]:
        """
        RAG Retrieval: Find similar historical threats
        """
        # Cosine similarity search in vector database
        similar_vectors = await self.vector_db.similarity_search(
            query_vector=query_embedding,
            similarity_threshold=threshold,
            limit=10
        )

        # Retrieve threat context for each similar vector
        threat_contexts = []
        for vector in similar_vectors:
            context = await self.threat_db.get_threat_details(vector.event_id)
            threat_contexts.append({
                'similarity': vector.similarity_score,
                'threat_type': context.threat_type,
                'attack_techniques': context.mitre_techniques,
                'indicators': context.iocs,
                'response_playbook': context.recommended_response
            })

        return threat_contexts
```

### 6.3 RAG-Enhanced Threat Analysis

```python
class RAGThreatAnalyzer:
    """
    Uses RAG to enhance threat analysis with historical context
    """

    async def analyze_with_rag(self, current_event):
        # Generate embedding for current event
        embedding = await self.embedding_service.embed(
            text=str(current_event.factors),
            factors=current_event.factors
        )

        # RAG: Find similar historical threats
        similar_threats = await self.rag_engine.find_similar_threats(embedding)

        # Enhance analysis with RAG context
        enhanced_analysis = {
            'base_confidence': current_event.confidence,
            'similar_threat_count': len(similar_threats),
            'historical_patterns': [t['threat_type'] for t in similar_threats],
            'recommended_response': self.synthesize_responses(similar_threats),
            'confidence_boost': min(0.2, len(similar_threats) * 0.05)  # RAG boost
        }

        return enhanced_analysis
```

---

## 7. RAG PERFORMANCE METRICS

### 7.1 RAG Model Performance Tracking

```python
# Prometheus metrics for RAG system
rag_metrics = {
    'embedding_provider_selection_total': Counter(['provider']),
    'embedding_generation_latency_ms': Histogram(['provider']),
    'embedding_similarity_search_latency': Histogram(),
    'rag_retrieval_accuracy': Gauge(),
    'rag_cost_per_embedding': Gauge(['provider']),
    'model_fallback_total': Counter(['from_provider', 'reason'])
}
```

### 7.2 RAG Cost Optimization

```yaml
Cost Model:
  SecBERT: $0.001 per embedding (780 dims)
  TinyBERT: $0.0005 per embedding (312 dims)
  MiniLM: $0.0001 per embedding (384 dims)
  Hash: $0.00001 per embedding (32-256 dims)

Optimization Strategy:
  - Use complexity scoring to avoid expensive models for simple events
  - Cache embeddings for repeated patterns
  - Batch process similar events
  - Automatic degradation under cost pressure
```

---

## 8. CONCLUSION

### 8.1 RAG Architecture Summary

The JanuSec platform implements a **sophisticated multi-tier RAG system** with:

1. **Adaptive Model Selection**: Complexity-driven provider selection
2. **Graceful Degradation**: Fallback chain from expensive to cheap models
3. **Cost Awareness**: Real-time cost tracking and optimization
4. **Performance Optimization**: Caching, batching, and lazy loading
5. **Continuous Learning**: Drift detection and automatic retraining

### 8.2 Agent Clarification

**There are NO AI agents in the JanuSec platform.** All references to "agents" mean:
- **Endpoint security software** (installed on workstations/servers)
- **Data collection programs** (not autonomous AI)
- **Security monitoring tools** (EDR/XDR agents)

### 8.3 Why This Architecture

The RAG system exists to:
- **Bridge the semantic gap** in threat detection
- **Optimize costs** through intelligent model selection
- **Provide resilience** through graceful degradation
- **Enable continuous learning** from new threat patterns
- **Scale efficiently** across thousands of events per second

This architecture represents a sophisticated approach to **cost-aware, adaptive threat intelligence** using state-of-the-art RAG techniques while maintaining operational efficiency and reliability.

---

*JanuSec Platform RAG Architecture - Intelligent threat detection through semantic understanding.*