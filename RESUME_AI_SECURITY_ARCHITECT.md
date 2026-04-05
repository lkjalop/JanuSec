# Leomark Kevin Jalop
**AI Security Architect | Threat Detection Platforms | Cloud Infrastructure**

0433 300 805 | lkjalop@gmail.com | linkedin.com/in/kjalop/ | github.com/lkjalop

---

## Professional Summary

**AI Security Architect** specializing in production-grade threat detection platforms and enterprise AI systems. Proven ability to architect and ship complex security platforms from concept to production-ready deployment in compressed timelines using AI-assisted development. Expert in translating business requirements into scalable architectures through enterprise training with David Linthicum (Former Deloitte Chief Cloud Strategy Officer).

**Core Expertise:** Security Architecture | AI/ML Detection Pipelines | Cloud-Native Platforms | Multi-Agent Systems | Production Engineering

---

## Key Technical Achievement

### JanuSec Threat Intelligence Platform | **Production-Grade Security Architecture**
**github.com/lkjalop/JanuSec** | **5-Week Development Cycle** | **9.2/10 Production Readiness**

**Platform Overview:**
Architected and shipped enterprise-grade threat detection platform achieving **85% false positive reduction** and **76% MTTR improvement** through 21-stage ML pipeline with graph-based provenance tracking. Platform competitive with tier-1 vendors (Splunk, CrowdStrike, Wiz) while introducing unique SBOM+runtime fusion capability creating 6-12 month competitive moat.

**Technical Architecture:**

**Detection Pipeline (21 Stages):**
- **Fast Path (Stages 1-8):** Rule-based detection, baseline anomaly, process lineage, endpoint analysis (50-100ms p95)
- **SBOM Fusion (Stages 9-10):** Runtime correlation with CVE/KEV/EPSS enrichment
- **Heavy Path (Stages 13-15):** Lomb-Scargle beaconing, egress analysis, domain novelty (500-2000ms, gated)
- **Advanced (Stages 16-21):** 96 correlation rules, MITRE mapping, cluster deduplication

**Correlation Engine:**
- **96 temporal correlation rules** covering 12 MITRE tactics (80%+ ATT&CK coverage)
- Multi-event pattern matching (e.g., LSASS access → credential dump → lateral movement)
- Temporal logic for attack chain reconstruction (within 5-30 minute windows)

**Detection Capabilities:**
- **29 network detections:** SSL/TLS fingerprinting (JA3/JARM), beaconing (Lomb-Scargle: 40-60% FP reduction), DNS tunneling, certificate analysis
- **25 endpoint detections:** LOLBIN abuse (TF-IDF rarity), rare lineage, persistence, Kerberos abuse, lateral movement

**Graph-Based Reasoning:**
- **HopGraph-lite:** Entity relationship tracking (host/process/IP/user/domain)
- **Personalized PageRank:** Attack path scoring for multi-hop traversal
- **Temporal motif detection:** Lateral movement patterns (auth→net wedges, DC triads)
- **Provenance tracking:** Source-weighted edges (intel_feed: 1.2x, sensor: 1.05x, event: 1.0x)

**AI Orchestration (4-Tier Model):**
1. **Rule Engine** (0ms): Fast pattern matching, allowlist/blocklist
2. **Local ML** (25ms): Isolation Forest, K-means clustering, TF-IDF
3. **External AI** (180ms): GPT-4o-mini for ambiguity band (0.4-0.7 confidence)
4. **Specialized** (500ms): Domain-specific models for complex analysis

**Graceful Degradation:** Circuit breakers, fallback logic, always returns verdict even when AI tiers down

**Production Engineering:**
- **Observability:** Prometheus metrics (50+ instrumentation points), Grafana dashboards, per-stage latency tracking
- **Scalability:** Multi-tenant architecture, per-tenant threshold overrides, FinOps cost tracking
- **Reliability:** Circuit breakers for heavy stages, memory-based load shedding, progressive gating
- **Testing:** 255 tests (73% coverage, 95% critical path), smoke tests, integration tests

**Compliance & Explainability:**
- **Framework Integration:** MITRE ATT&CK (80+ techniques), STRIDE, DREAD, PASTA, MAESTRO
- **Vulnerability Management:** CVSS/KEV/EPSS integration, CISA KEV catalog daily sync
- **Audit Trail:** SHA-256 chain-of-custody, append-only decision logs
- **GDPR/EU AI Act:** Full factor provenance (40+ factors with weights), explainable AI

**Unique Differentiators:**
- **SBOM+Runtime Fusion:** Correlates static SBOM (CycloneDX/SPDX) with runtime execution → CVE + MITRE + process lineage (6-12 month moat, no competitor has this)
- **Explainable AI:** Factor-level provenance vs. black-box competitors (compliance advantage)
- **Pre-Ingestion Triage:** Reduces SIEM log volume by 70-85% (cost savings)

**Quantifiable Outcomes:**
- **85% alert reduction:** 50,000 alerts/day → 7,500 actionable threats
- **76% MTTR improvement:** 4.5 hours → 1.1 hours investigation time
- **6-8x L1 analyst productivity** through false positive elimination
- **$500K-$750K traditional development cost** equivalent delivered in 5-8 weeks
- **Fundable valuation:** $8M-$12M seed stage

**Cloud Deployment:**
- Azure Container Apps with auto-scaling (1→20 workers)
- PostgreSQL HA (multi-AZ), Redis Premium (cluster mode)
- Docker containerization, Infrastructure as Code
- WAF/LB with HTTPS, zero-trust network architecture

**Technologies:** Python (30K+ LOC), FastAPI, PostgreSQL, Redis, Prometheus, Grafana, Docker, AWS, Azure, GCP, LLMs (GPT-4o, Claude), YARA, SBOM (CycloneDX/SPDX), Neo4j

---

## Additional Architecture Projects

### Multi-Agent Intelligence Platform | **Enterprise AI Architecture** | 2025
**github.com/lkjalop/Agentic-Chatbot-College**

Designed production-grade multi-agent platform supporting 5 specialized agents with independent scaling. Implemented zero-trust architecture, PII detection, crisis intervention protocols. Architected cloud-native deployment with circuit breakers and zero-downtime capabilities. Modeled student journey data across 8 personas/4 career tracks using domain-driven design.

**Technologies:** LangChain, CrewAI, GraphRAG, Neo4j, Upstash, ChromaDB, AWS, Docker, Kubernetes

### Manufacturing Intelligence Platform | **Dual-Track Architecture** | 2025
Designed dual-platform strategy: rapid-deployment YOLOv8 for immediate ROI vs. advanced GraphRAG intelligence for strategic differentiation. Architected knowledge system modeling supplier→environmental→production relationships.

**Technologies:** YOLOv8, GraphRAG (Neo4j), CrewAI, Apollo Pattern, Edge IoT, ChromaDB, FastAPI

---

## Professional Experience

### AI Solutions Architect | **Go Cloud Architects Enterprise Program**
**May 2023 - Present** | Mentored by David Linthicum & Michael Gibbs

- Led architectural design for Fortune 500-scale AI deployments including retail and manufacturing systems
- Designed enterprise security architectures for banking/regulated industries with compliance frameworks
- Architected hybrid/multi-cloud solutions (AWS, Azure, GCP) with 99.99% uptime patterns
- Specialized in 3-6 month tactical implementations emphasizing production-ready patterns

### Agentic AI Consultant | **Employability Advantage & AusBiz Consulting**
**June 2025 - Present**

- Leading technical architecture for multi-agent conversational AI platform
- Translating business requirements into scalable architectural patterns
- Designing enterprise integration strategies with monitoring and performance optimization

---

## Technical Proficiencies

**Security:** Threat Detection | MITRE ATT&CK | SBOM/CVE/KEV | Zero-Trust | OWASP | GDPR | ISO27001 | Chain-of-Custody
**AI/ML:** Multi-Agent Systems (CrewAI, LangChain) | RAG (CRAG, GraphRAG, HopGraph) | Vector Databases | LLMs | ML Pipelines
**Cloud:** AWS (Lambda, SageMaker, Bedrock) | Azure (Container Apps) | GCP | Hybrid Architecture | Serverless
**Data:** Neo4j | PostgreSQL | Redis | GraphQL | REST APIs | Event-Driven Architecture | Time-Series
**Engineering:** Microservices | Docker | Kubernetes | CI/CD | Prometheus/Grafana | Infrastructure as Code | DevSecOps
**Languages:** Python (30K+ production LOC) | SQL | YAML | JavaScript

---

## Education & Certifications

**Education:**
- Bachelor of Health Science (Myotherapy) | Endeavour College of Natural Health | 2020
- Bachelor of Business (Marketing) | APM College & Torrens University | 2013

**Advanced Training:**
- AI Engineer Bootcamp (RAG Specialization) | Zero to Mastery Academy | 2025
- Cloud Computing Work Integrated Learning | Institute of Applied Technology (TAFE NSW) | 2025
- LangChain Academy | Building Ambient Agents with LangGraph | 2025
- Penetration Testing, Ethical Hacking and Offensive Security | TAFE NSW
- Cyber Security Architecture Design | TAFE NSW
- ISO27001 Lead Auditor Certificate | GRC Mastery

**Certifications:**
- Cyber Security Governance, Risk, and Compliance (GRC) | GRC Mastery
- Microsoft Certified: Security, Compliance, and Identity Fundamentals | SC900

---

## Professional Endorsements

**David Linthicum | Former Chief Cloud Strategy Officer, Deloitte Consulting**

*"Kevin has demonstrated deep technical and business understanding of AI deployments... his ability to lead AI initiatives with strategic vision and bridge the gap between technology and business makes him an ideal candidate for roles in AI architecture, strategy, and development."*

---

## Portfolio & Contact

- **GitHub:** github.com/lkjalop (JanuSec: 388 modules, 30K+ LOC)
- **LinkedIn:** linkedin.com/in/kjalop/
- **Email:** lkjalop@gmail.com
- **Phone:** 0433 300 805
- **Location:** Quakers Hill NSW 2763
