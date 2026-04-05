# Project Capabilities Matrix - Gen AI Architect Role

**Candidate Portfolio:** JanuSec Platform + Agentic Chatbot College
**Role:** Gen AI Architect | Sydney, NSW, Australia

---

## 📊 Comprehensive Mapping: Job Requirements → Project Evidence

### 1. Design and Develop AI Solutions using Python

| Sub-Requirement | JanuSec Platform | Agentic Chatbot | Combined Evidence |
|-----------------|------------------|-----------------|-------------------|
| **Python proficiency** | ✅✅✅ **50,000+ lines**<br>• Async/await throughout<br>• Type hints (Python 3.11+)<br>• Complex data structures<br>• Multi-module architecture | ✅✅ **5,000+ lines**<br>• Modern Python 3.11+<br>• Type-safe Pydantic models<br>• AsyncPG integration<br>• Clean module separation | **Expert-level Python**<br>Both production-grade and educational-level code quality |
| **Flask** | ⚠️ Not used | ⚠️ Not used | Can learn quickly (FastAPI experience transfers) |
| **Streamlit** | ⚠️ Not used | ⚠️ Not used | Can learn quickly (Python + web frameworks experience) |
| **FastAPI** | ✅✅✅ **Production expert**<br>• 30+ API endpoints<br>• SSE streaming<br>• WebSocket support<br>• Multi-tenant routing<br>• Dependency injection<br>• Async request handling<br>• Custom middleware<br>• Auto-generated OpenAPI docs | ✅✅ **Core implementation**<br>• RESTful API design<br>• Async endpoint patterns<br>• Request/response validation<br>• Auto-generated docs<br>• Error handling<br>• Serverless-compatible | **FastAPI mastery**<br>Production deployment experience, scalability patterns, advanced features |

---

### 2. Architect and Implement Intelligent Agents

| Aspect | JanuSec Platform | Agentic Chatbot | Analysis |
|--------|------------------|-----------------|----------|
| **Agent Count** | ✅✅✅ **4 tiers + specialized modules**<br>• Tier 0: Rule-based (heuristics)<br>• Tier 1: Lightweight ML (IsolationForest, K-means)<br>• Tier 2: External LLM (OpenAI-compatible)<br>• Tier 3: Specialized transformers (RoBERTa, DeBERTa)<br>• Plus: Network Hunter, Endpoint Hunter, Intelligent Router | ✅✅✅ **6-agent hybrid**<br>• 4 Career Track Specialists:<br>  - Data & AI Agent<br>  - Cybersecurity Agent<br>  - Business Analyst Agent<br>  - Full Stack Developer Agent<br>• 2 Support Agents:<br>  - Cultural Support Agent<br>  - Booking/Scheduling Agent | **Multi-agent architecture expertise**<br>Demonstrates both hierarchical (JanuSec) and specialist (Chatbot) patterns |
| **Agent Orchestration** | ✅✅✅ **Model Orchestrator**<br>• Dynamic tier selection based on:<br>  - Event severity<br>  - Confidence scores<br>  - Budget remaining<br>  - Model availability<br>• Auto-escalation on low confidence<br>• Auto-degradation on budget constraints<br>**File:** `src/core/hunt/model_orchestrator.py` | ✅✅✅ **Intent-based routing**<br>• Pattern matching with keywords<br>• Confidence scoring (83.3% accuracy)<br>• Persona detection<br>• Deterministic routing<br>• Transparent decision-making<br>• Real-time "Under the Hood" panel | **Orchestration mastery**<br>Both ML-driven (JanuSec) and rule-based (Chatbot) routing strategies |
| **Agent Communication** | ✅✅✅ **Pipeline stages**<br>• 13-stage event pipeline<br>• Factors passed between stages<br>• State carried through context<br>• Dynamic stage skipping<br>• Confidence blending<br>**File:** `src/core/event_pipeline/pipeline.py` | ✅✅ **Sequential flow**<br>• Intent → Security → Route → Retrieve → Generate → Respond<br>• Session state management<br>• Error propagation<br>• Fallback handling | **Inter-agent coordination**<br>Both synchronous (Chatbot) and complex pipeline (JanuSec) patterns |
| **Agent Autonomy** | ✅✅✅ **Autonomous decision-making**<br>• Self-healing (circuit breakers)<br>• Auto-fallback on failures<br>• Health monitoring<br>• Performance tracking<br>• Budget-aware decisions<br>**File:** `src/ai/model_manager.py:708-757` | ✅✅ **Rule-based autonomy**<br>• Automatic agent selection<br>• Confidence thresholds<br>• Security auto-escalation<br>• Cache hit optimization | **Autonomous agents**<br>Self-monitoring, self-healing, adaptive behavior |
| **Tool Use** | ✅✅✅ **Multiple specialized tools**<br>• VT (VirusTotal) queue<br>• SBOM analyzer<br>• Threat intel cache<br>• Compliance mapper<br>• Artifact analyzer<br>**Files:** `src/artifact/`, `src/modules/` | ✅✅ **Integrated tools**<br>• Vector search (Upstash)<br>• LLM generation (Groq)<br>• Speech recognition (Web Speech API)<br>• TTS synthesis<br>• Twilio integration | **Tool-using agents**<br>External API integration, service orchestration |

---

### 3. Apply RAG Techniques (including GraphRAG)

| RAG Component | JanuSec Platform | Agentic Chatbot | Combined Depth |
|---------------|------------------|-----------------|----------------|
| **Retrieval Strategy** | ✅✅✅ **Hybrid: Vector + Graph**<br>• Initial embedding: SentenceTransformers<br>• Graph traversal: Multi-hop HopGraph<br>• Entity relationship modeling<br>• Temporal correlation<br>**Files:** ~80 graph-related modules | ✅✅ **Semantic vector search**<br>• Upstash Vector DB<br>• MXBAI_EMBED_LARGE_V1 embeddings<br>• Cosine similarity<br>• Metadata filtering<br>• 110 curated Q&As | **Full RAG spectrum**<br>Simple semantic to complex GraphRAG |
| **GraphRAG Implementation** | ✅✅✅ **Production GraphRAG**<br>• **HopGraph**: Custom graph implementation<br>• **5 specialized domains:**<br>  - Network HopGraph (connections, flows)<br>  - Identity HopGraph (users, permissions)<br>  - Cloud HopGraph (resources, dependencies)<br>  - Email HopGraph (senders, recipients)<br>  - API HopGraph (service calls)<br>• Multi-hop traversal (2-3 hops typical)<br>• Entity relationship scoring<br>• Temporal graph evolution<br>• TTL-based pruning<br>**Files:**<br>• `src/core/graph/hopgraph_lite.py`<br>• `src/core/graph/network_hopgraph.py`<br>• `src/core/graph/identity_hopgraph.py`<br>• `src/core/graph/cloud_hopgraph.py`<br>• `src/core/graph/email_hopgraph.py` | ⚠️ **Not implemented**<br>• Vector-only RAG<br>• No graph layer<br>• Relationships not modeled | **GraphRAG expertise from JanuSec**<br>Can explain:<br>• When to use graph vs. vector<br>• Multi-hop traversal algorithms<br>• Graph pruning strategies<br>• Entity relationship scoring<br>• Hybrid retrieval approaches |
| **Augmentation (Context Injection)** | ✅✅✅ **Multi-source context**<br>• Retrieved graph entities → prompt<br>• Factor history → risk analysis<br>• Related events → correlation<br>• Baseline profiles → anomaly detection<br>• Sanitized input (injection prevention)<br>**File:** `src/ai/model_manager.py:613-646` | ✅✅ **Curated context**<br>• Retrieved Q&As → prompt<br>• Persona profile → system message<br>• Student background → recommendations<br>• Security scan results → guardrails<br>• 300-token response cap | **Context engineering**<br>Both retrieved (dynamic) and curated (static) augmentation |
| **Generation** | ✅✅✅ **Multi-tier generation**<br>• External LLM (OpenAI-compatible)<br>• Specialized transformers (local)<br>• Fallback to ML models<br>• Structured JSON responses<br>• Pydantic validation<br>**File:** `src/ai/model_manager.py:648-705` | ✅✅ **Direct LLM generation**<br>• Groq API (Llama models)<br>• Temperature 0.8<br>• Persona-aware prompts<br>• Response capping (300 tokens)<br>• Mobile-optimized | **Generation strategies**<br>Both multi-tier (JanuSec) and focused (Chatbot) approaches |
| **Feedback Loop** | ✅✅✅ **Active learning**<br>• User feedback → factor weights<br>• False positive detection → allowlist<br>• Model performance tracking<br>• Adaptive threshold tuning<br>**Files:**<br>• `src/artifact/feedback.py`<br>• `src/modules/adaptive_tuner.py` | ✅ **Basic feedback**<br>• User satisfaction tracking<br>• Query logging<br>• Performance metrics<br>• Cache optimization | **Closed-loop systems**<br>JanuSec has sophisticated feedback integration |

---

### 4. Engineer Memory and Context-Aware Systems

| Memory Type | JanuSec Platform | Agentic Chatbot | Architecture Depth |
|-------------|------------------|-----------------|-------------------|
| **Short-Term Memory (seconds to minutes)** | ✅✅✅ **Multi-layer caching**<br>• Result cache (5-min TTL)<br>• LRU eviction (10K max entries)<br>• Per-request context object<br>• Stage state propagation<br>• Cache hit tracking<br>**File:** `src/ai/model_manager.py:759-807` | ✅✅ **TTL-based caching**<br>• 10-minute default TTL<br>• 60-80% cache hit rate<br>• Intelligent pre-loading<br>• Session state (Next.js API routes)<br>• Request-scoped memory | **Caching expertise**<br>Both understand TTL strategies, eviction policies, cache warming |
| **Medium-Term Memory (minutes to hours)** | ✅✅✅ **Correlation windows**<br>• Time-bound event grouping<br>• Sliding window analysis<br>• Egress history per host<br>• Domain request tracking<br>• Circuit breaker state (failure counts, cooldown)<br>**Files:**<br>• `src/live/correlation_window.py`<br>• `src/core/event_pipeline/pipeline.py:53` | ✅ **Session memory**<br>• Conversation context (limited)<br>• Single-query focus<br>• State management via API routes<br>• User profile tracking | **Temporal context**<br>JanuSec has sophisticated windowing; Chatbot has basic sessions |
| **Long-Term Memory (days to weeks)** | ✅✅✅ **Behavioral baselines**<br>• Domain baseline tracking<br>• Entity reputation scores<br>• Statistical profiles of "normal"<br>• Graph persistence (SQLite + snapshots)<br>• Factor weight learning<br>**Files:**<br>• `src/live/domain_baseline.py`<br>• `src/modules/baseline.py`<br>• `src/artifact/feedback.py` | ⚠️ **Limited long-term**<br>• User history logging<br>• Performance metrics<br>• No behavioral baselines | **Long-term context from JanuSec**<br>Understands decay functions, incremental updates, baseline modeling |
| **Context Propagation** | ✅✅✅ **Pipeline context object**<br>• `StageContext` passed through 13 stages<br>• Accumulating factors<br>• State dictionary<br>• Registry access<br>• Logger sharing<br>**File:** `src/core/event_pipeline/pipeline.py:84-93` | ✅✅ **Request context**<br>• Intent → Agent selection<br>• Security scan results<br>• Persona profile<br>• Retrieved Q&A context<br>• Error state | **Context threading**<br>Both understand state propagation patterns |
| **Memory Management** | ✅✅✅ **Explicit cleanup**<br>• TTL-based expiration<br>• LRU eviction<br>• Graph pruning (TTL-based)<br>• Cache size limits (10K entries)<br>• Sliding window trimming<br>**Files:** Various, including graph pruning logic | ✅✅ **TTL expiration**<br>• 10-min cache TTL<br>• Automatic cleanup<br>• Session expiration<br>• No unbounded growth | **Memory efficiency**<br>Both prevent memory leaks via explicit limits |

---

### 5. Work with Modern AI Frameworks

| Framework | JanuSec Platform | Agentic Chatbot | Learning Path |
|-----------|------------------|-----------------|---------------|
| **LangChain** | ⚠️ **Not used**<br>**But built equivalent patterns:**<br>• Agent executors → Model orchestrator<br>• Memory classes → Multi-layer memory<br>• Chains → Pipeline stages<br>• Tools → Specialized modules<br>• Callbacks → Metrics tracking | ⚠️ **Deliberately avoided**<br>**Reasoning documented:**<br>• "Adds orchestration overhead"<br>• Direct API for performance<br>• Full control for security<br>• Transparent decision-making | **Strong defense:**<br>"I built what LangChain abstracts, which makes me effective at using and debugging it. I can onboard within 2 weeks because I understand the underlying patterns." |
| **LangGraph** | ⚠️ **Not used**<br>**But built equivalent patterns:**<br>• State machines → Pipeline with dynamic routing<br>• Graph state → HopGraph<br>• Conditional edges → Stage skipping logic<br>• Persistence → Graph snapshots | ⚠️ **Not used**<br>**But built equivalent patterns:**<br>• State management → Session state<br>• Routing logic → Agent selection<br>• Flow control → Intent-based routing | **Can map directly:**<br>JanuSec pipeline IS a state machine; HopGraph IS graph state management |
| **crew.ai** | ⚠️ **Not used**<br>**But built equivalent patterns:**<br>• Crew → Module registry<br>• Agents → Hunters (network, endpoint)<br>• Tasks → Pipeline stages<br>• Process → Sequential/parallel execution | ⚠️ **Not used**<br>**But built equivalent patterns:**<br>• Crew → 6-agent system<br>• Roles → Specialist agents<br>• Delegation → Intent routing | **Parallel architecture:**<br>Multi-agent coordination without framework |
| **Autogen** | ⚠️ **Not used** | ⚠️ **Not used** | **Fastest to learn:**<br>Similar multi-agent patterns already implemented |
| **Direct LLM APIs** | ✅✅✅ **OpenAI-compatible**<br>• Custom endpoint integration<br>• Prompt engineering<br>• Token tracking<br>• Cost management<br>• Error handling<br>• Circuit breakers<br>**File:** `src/ai/model_manager.py:281-365` | ✅✅✅ **Groq API**<br>• Direct REST integration<br>• Persona-aware prompts<br>• Temperature tuning<br>• Response constraints<br>• Error handling | **Direct API mastery**<br>Not framework-dependent; can integrate any LLM provider |
| **Transformers (Hugging Face)** | ✅✅✅ **Production use**<br>• SentenceTransformers for embeddings<br>• RoBERTa for classification<br>• DeBERTa for NLP tasks<br>• Local inference (CPU/CUDA)<br>• Model loading/caching<br>**File:** `src/ai/oss_models.py` | ⚠️ **Not used** | **Transformer expertise from JanuSec**<br>Model selection, inference optimization, resource management |

---

### 6. Contribute to Agent Architectures and MCP Design

| Architecture Aspect | JanuSec Platform | Agentic Chatbot | Design Capability |
|--------------------|------------------|-----------------|-------------------|
| **Multi-Component Pipeline** | ✅✅✅ **13-stage pipeline**<br>**Stages:**<br>1. Allowlist check<br>2. Baseline comparison<br>3. Regex pattern matching<br>4. Parent-child analysis<br>5. SBOM vulnerability mapping<br>6. Beaconing detection<br>7. Egress tracking<br>8. Domain novelty<br>9. Rare token detection<br>10. Threat intel lookup<br>11. Hunt lane analysis<br>12. Compliance mapping<br>13. Final scoring<br><br>**Features:**<br>• Dynamic stage skipping (confidence gates)<br>• Per-tenant configuration<br>• Heavy/light stage optimization<br>• Detailed timing metrics<br>• Failure isolation<br>**File:** `src/core/event_pipeline/pipeline.py` | ✅✅ **6-component flow**<br>**Components:**<br>1. Intent classification<br>2. Security scanning (PII, injection)<br>3. Agent routing<br>4. RAG retrieval<br>5. LLM generation<br>6. Response synthesis<br><br>**Features:**<br>• Sequential execution<br>• Error propagation<br>• Multi-channel (chat, voice)<br>• Under-the-hood transparency<br>• Performance tracking | **Pipeline architecture expertise**<br>Can design:<br>• Stage composition<br>• Orchestration patterns<br>• Conditional execution<br>• Error handling<br>• Performance optimization |
| **Scalability Design** | ✅✅✅ **Enterprise patterns**<br>• Multi-tenant isolation<br>• Per-tenant thresholds<br>• Circuit breakers (prevent cascade failures)<br>• Graceful degradation<br>• Stage parallelization potential<br>• Database connection pooling<br>• Async throughout<br>**File:** `src/core/config/tenant_overrides.py` | ✅✅ **Horizontal scaling**<br>• Stateless API routes<br>• Serverless-compatible<br>• CDN-friendly frontend<br>• Vector DB (managed service)<br>• Caching reduces load<br>• Rate limiting ready | **Scalability understanding**<br>Both vertical (optimization) and horizontal (stateless design) |
| **Observability** | ✅✅✅ **Comprehensive metrics**<br>• Prometheus metrics export<br>• Stage-level timing<br>• Confidence tracking<br>• Cost ledger (per-tenant)<br>• Health check endpoints<br>• Performance history<br>• Circuit breaker status<br>**Files:**<br>• `src/api/metrics_init.py`<br>• `src/core/metrics/cost_ledger.py` | ✅✅ **Basic monitoring**<br>• Response time tracking<br>• Cache hit rates<br>• Routing accuracy<br>• Error logging<br>• "Under the Hood" diagnostics panel | **Observability design**<br>Understands instrumentation, metrics export, debugging tools |
| **Modularity** | ✅✅✅ **Highly modular**<br>• Pluggable stages<br>• Module registry pattern<br>• Dependency injection<br>• Interface-based design<br>• Stage definitions separate from execution<br>**File:** `src/core/event_pipeline/stages/` | ✅✅ **Clean separation**<br>• Agent interfaces<br>• Service abstractions<br>• Database layer isolation<br>• API route modularity<br>• Frontend components | **Modular design mastery**<br>Can architect loosely-coupled systems |

---

## 🎯 Strategic Summary

### What You Have (Strong Evidence)

| Capability | Confidence | Evidence Projects | Interview Strategy |
|------------|-----------|-------------------|-------------------|
| Python Programming | ✅✅✅ 10/10 | Both | Lead with this - it's your foundation |
| FastAPI | ✅✅✅ 10/10 | Both | Demonstrate production expertise |
| Agent Architectures | ✅✅✅ 9/10 | Both (complementary) | Show JanuSec's depth + Chatbot's clarity |
| RAG (Semantic) | ✅✅✅ 9/10 | Both | Chatbot for explanation, JanuSec for production |
| GraphRAG | ✅✅✅ 8/10 | JanuSec only | Lead with HopGraph example, explain when to use |
| Memory/Context | ✅✅✅ 9/10 | JanuSec (sophisticated) | Show multi-layer approach |
| Multi-Component Pipelines | ✅✅✅ 9/10 | Both | JanuSec for complexity, Chatbot for clarity |
| Direct LLM Integration | ✅✅✅ 9/10 | Both | Demonstrate understanding beyond frameworks |

### What You Need to Address (Learning Curve)

| Framework | Current Level | Path to Proficiency | Timeline Estimate |
|-----------|--------------|---------------------|-------------------|
| LangChain | Pattern understanding | Map existing patterns → Learn syntax → Build small project | 1-2 weeks |
| LangGraph | State machine understanding | Study examples → Implement one flow → Extend | 1 week |
| crew.ai | Multi-agent understanding | Read docs → Compare to existing → Try one crew | 3-5 days |
| Autogen | Multi-agent understanding | Similar to crew.ai | 3-5 days |

**Defense:** "I can onboard within 2 weeks because I've already solved the problems these frameworks address."

---

## 💪 Unique Strengths (Differentiation)

| Strength | Evidence | Why It Matters |
|----------|----------|----------------|
| **Built from First Principles** | Both projects avoid frameworks | Deeper understanding; effective at debugging; can extend beyond framework limitations |
| **Production Patterns** | Circuit breakers, cost optimization, multi-tenant, graceful degradation | Most candidates have toy projects; you have enterprise patterns |
| **Security Mindset** | PII detection, injection prevention, threat-aware routing | Rare in Gen AI roles; valuable for safety/governance |
| **Cost Consciousness** | Budget gates, tier optimization, caching, token tracking | Shows business awareness; not just technical |
| **Complementary Projects** | Simple (Chatbot) + Complex (JanuSec) | Can explain at multiple levels; shows range |
| **Honest About Tradeoffs** | Chatbot acknowledges limitations; JanuSec documents decisions | Shows maturity; trustworthy |
| **Graph + Vector RAG** | Both approaches implemented | Rare; most candidates know only one |

---

## 🚀 Interview Positioning

### Opening (30 seconds):
> "I have two AI projects that demonstrate comprehensive Gen AI capabilities: JanuSec with production GraphRAG and 4-tier agents, and an Agentic Chatbot with 6 agents and semantic RAG. While I haven't used LangChain, I've built the underlying patterns - orchestration, memory, RAG, multi-agent coordination. This makes me effective at using frameworks because I understand what's under the hood."

### If Pressed on LangChain (30 seconds):
> "I can map every pattern I've built to LangChain components: my pipeline is SequentialChain, my model orchestrator is AgentExecutor, my memory layers are BufferMemory/WindowMemory, my HopGraph is LangGraph state. The advantage is I can debug and extend beyond framework limitations. I'll onboard within 2 weeks because I already understand the problems LangChain solves."

### Closing (30 seconds):
> "My projects show both depth (JanuSec's GraphRAG and circuit breakers) and pragmatism (Chatbot's focused simplicity). I bring pattern-based understanding that makes me effective with frameworks like LangChain, plus production experience with cost optimization and multi-tenant architectures. I'm excited to apply these skills to your Gen AI challenges."

---

## 📈 Confidence Assessment

**Overall Fit: 8.5/10**

**Breakdown:**
- **Technical Skills (9/10):** Strong Python, FastAPI, agents, RAG, memory systems
- **Framework Experience (6/10):** Haven't used LangChain, but understand patterns deeply
- **Production Readiness (9/10):** Circuit breakers, monitoring, cost optimization
- **Learning Velocity (9/10):** Can onboard to frameworks quickly due to pattern knowledge

**Risk Areas:**
- LangChain/LangGraph syntax learning curve (~2 weeks)
- Need to demonstrate learning agility

**Mitigation:**
- Lead with pattern understanding
- Show equivalent implementations
- Express genuine enthusiasm for learning
- Provide realistic timeline (2 weeks to productivity)

---

## ✅ Final Checklist

**Before Interview:**
- [ ] Review both project READMEs
- [ ] Open key files (model_manager, pipeline, agents)
- [ ] Practice 30-second pitch out loud
- [ ] Prepare "why no LangChain" response
- [ ] Have 3-5 questions for them ready

**During Interview:**
- [ ] Lead with strengths (Python, FastAPI, agents)
- [ ] Use both projects (simple explanations, complex examples)
- [ ] Address LangChain proactively and confidently
- [ ] Show code if possible (model_manager, pipeline)
- [ ] Ask technical questions about their architecture

**After Interview:**
- [ ] Send thank-you email with project links
- [ ] Highlight 1-2 key technical discussions
- [ ] Reiterate 2-week onboarding commitment
- [ ] Express genuine excitement

---

**Document Version:** 1.0
**Last Updated:** 2025-01-11

---

*This matrix provides comprehensive evidence of Gen AI architecture capabilities across two complementary projects. Use it to confidently articulate expertise while honestly addressing framework learning curves.*
