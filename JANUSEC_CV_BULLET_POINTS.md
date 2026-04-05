# JanuSec — CV / Resume Bullet Points

> Structured the same way as the ShopSquire CV doc. Pick the version closest to the role,
> swap individual bullets between versions as needed. 5 bullets per role.

---

## Recommended 2026 Bullets (Universal / Strong Short Version)

Use these on any resume where JanuSec is featured as a key project.

1. **AI-Powered XDR Triage Platform** — Architected JanuSec, an AI-powered XDR triage platform that cuts SOC alert noise 60-90% without missing a single threat, using a 30-stage progressive detection pipeline combining IsolationForest anomaly detection, HopGraph knowledge-graph correlation, semantic embeddings, and LLM-assisted triage.

2. **HopGraph Threat Correlation Engine** — Designed a proprietary graph-based correlation engine (HopGraph) that reconstructs multi-hop attack chains across endpoints, users, network events, email, and file artifacts — automating detection of lateral movement, persistence, and exfiltration patterns that flat-log SIEM rules cannot correlate.

3. **Multi-Framework Threat Modeling at Ingestion** — Embedded automated MITRE ATT&CK technique mapping, STRIDE, DREAD, MAESTRO, and PASTA threat models directly into the detection pipeline — every event is tagged with TTP classification and risk score at ingestion, not as a post-processing afterthought.

4. **Enterprise AI Governance Architecture** — Designed multi-tenant compliance architecture covering ISO 42001, EU AI Act, NIST AI RMF, ISO 27001, and GDPR with zero-trust tenant isolation, privacy-by-design enforcement, cryptographically-linked audit trails, and full decision provenance satisfying board-level AI governance requirements.

5. **Measured SOC Impact** — Delivered 2-5x analyst capacity improvement and 73% MTTD reduction (sub-15 minute mean time to detect) through LLM-assisted triage, explainable risk scoring, automated false-positive suppression, and adaptive feedback loops — generating 7.3x documented ROI.

### Short Resume Version (3–4 lines for space-constrained layouts)

- Architected JanuSec, an AI-powered XDR triage platform that reduces SOC alert noise 60-90% through a 30-stage pipeline combining HopGraph graph correlation, IsolationForest anomaly detection, and LLM-assisted triage.
- Embedded automated MITRE ATT&CK, STRIDE, DREAD, MAESTRO, and PASTA threat models as first-class platform concerns, with full decision provenance for ISO 42001, EU AI Act, and ISO 27001 compliance.
- Delivered 2-5x analyst capacity improvement, sub-15-minute MTTD, and 7.3x ROI through explainable AI triage, adaptive FP suppression, and multi-tenant zero-trust architecture.

---

## Role 1: AppSec Engineer

1. **OWASP-Mapped API Security Layer** — Hardened a production FastAPI microservices platform against OWASP API Top 10 threats by implementing JWT authentication with RBAC, HMAC-signed webhook verification middleware, tenant-isolated request routing, rate limiting, and dependency-injection-based fail-closed auth guards across all security-sensitive endpoints.

2. **Threat Modeling Embedded in Detection** — Automated MITRE ATT&CK, STRIDE, DREAD, MAESTRO, and PASTA threat classification directly in the event pipeline — every security event exits triage with a structured threat model, kill-chain stage tag, and CVSS-equivalent risk score, turning threat modeling from a periodic exercise into a continuous operational output.

3. **Authentication, Session, and Webhook Hardening** — Implemented multi-layer security controls including HMAC webhook signature verification, tenant isolation middleware, approval-gated high-impact operations, suppression-rule access controls, and audit-logged privilege operations — following OWASP secure coding and zero-trust design principles throughout.

4. **SBOM and Vulnerability Intelligence Pipeline** — Built SBOM ingestion and vulnerability mapping pipelines correlating CVE/CVSS data against discovered software inventory per tenant, prioritising exploitable vulnerabilities by blast radius and observed MITRE technique exposure — directly accelerating AppSec triage and patch-cycle decision-making.

5. **Security Regression and CI/CD Gate** — Designed targeted security regression test packs for authentication routes, webhook validation, tenant boundary enforcement, and privilege-sensitive endpoints — backed by pytest fixtures, Bandit static analysis integration, and an API stage harness that validates security controls before every deployment reaches staging.

---

## Role 2: AI Engineer

1. **30-Stage AI Detection Pipeline** — Engineered a 30-stage progressive enhancement pipeline that transforms raw security events into ranked, explainable threat decisions using IsolationForest anomaly scoring, HopGraph knowledge-graph traversal, semantic embedding similarity, and LLM-assisted triage — achieving 60-90% alert noise reduction while maintaining 100% threat detection fidelity.

2. **HopGraph Knowledge Graph for Threat Correlation** — Designed and implemented HopGraph, a graph-based entity correlation engine that models relationships between IPs, domains, users, file hashes, techniques, and artifacts — enabling automated reconstruction of multi-stage attack chains and behavioural patterns that sequential SIEM rules structurally cannot detect.

3. **TemporalRAG and Embedding Intelligence Layer** — Built a retrieval-augmented generation system with configurable embedding providers (OpenAI, Ollama local inference, Azure OpenAI), vector similarity search across threat evidence corpora, and LLM-generated triage summaries — with deterministic rule-based fallback for air-gapped or offline deployments.

4. **Production LLM Cost and Model Management** — Implemented FinOps-aware AI inference management with per-tenant LLM cost tracking, tiered execution (fast rule-based path → embedding similarity → full LLM), model provider abstraction across cloud and local endpoints, prewarm probes, and graceful degradation — production-grade AI engineering beyond prototype quality.

5. **Explainable AI and Decision Provenance** — Architected a decision trace system recording which detection factors, graph hops, model outputs, rule matches, and confidence scores contributed to every triage decision — satisfying ISO 42001 and EU AI Act explainability requirements and providing the audit evidence SOC analysts need to defend escalation decisions under governance review.

---

## Role 3: AI & Security Architect

1. **JanuSec XDR Platform Architecture** — Architected JanuSec, a production AI-powered XDR triage platform delivering 60-90% SOC alert noise reduction through a 30-stage progressive detection pipeline — integrating anomaly detection, knowledge-graph correlation, semantic retrieval, and LLM reasoning in a single coherent architecture that achieves 2-5x analyst capacity improvement and 7.3x ROI.

2. **HopGraph — Proprietary Threat Intelligence Graph** — Designed HopGraph, a graph-native correlation engine modelling entity relationships and attack chain reconstruction across all telemetry domains (endpoint, network, identity, email, file) — enabling behavioural detection of multi-stage threats, lateral movement, and persistence mechanisms that rule-based SIEM and flat-log correlation cannot surface.

3. **Multi-Framework Threat Modeling Architecture** — Embedded MITRE ATT&CK, STRIDE, DREAD, MAESTRO, and PASTA as first-class architectural concerns — every detection is automatically classified by technique, tactic, threat model, and kill-chain stage at the pipeline ingestion layer, ensuring threat intelligence is produced continuously rather than retroactively during incident response.

4. **AI Governance and Multi-Tenant Compliance Architecture** — Designed enterprise-grade AI governance covering ISO 42001 (AI Management Systems), EU AI Act, NIST AI RMF, ISO 27001, and GDPR — with zero-trust tenant isolation, privacy-by-design data flows, cryptographically-linked decision audit trails, and explainable AI provenance satisfying both regulatory requirements and board-level accountability demands.

5. **Production XDR Stack — Designed for Enterprise SOC Deployment** — Architected the full platform stack (FastAPI, PostgreSQL, Redis, Kubernetes, SOAR integration) with tenant-isolated event pipelines, configurable hunt lanes, adaptive suppression-rule governance, connector health monitoring, FinOps cost controls, and Prometheus-based observability — production-ready for enterprise multi-tenant SOC deployment without re-architecture.

---

## Quick Reference: Which Version for Which Job Title

| Job Title | Primary Version | Steal Bullets From |
|---|---|---|
| AppSec Engineer | Role 1 (AppSec) | Role 3 (SBOM + threat modeling) |
| AI Engineer | Role 2 (AI Engineer) | Role 3 (provenance + explainability) |
| AI Security Engineer | Role 2 + Role 1 | Role 3 (governance) |
| AI Architect | Role 3 (Architect) | Role 2 (HopGraph design) |
| Security Architect | Role 3 | Role 1 (OWASP/hardening) |
| Threat Intelligence Engineer | Role 3 (HopGraph) | Role 2 (RAG + embeddings) |
| Cloud Security Architect | Recommended Bullets | Role 3 (compliance arch) |
| MLOps / AI Platform Engineer | Role 2 | Role 1 (CI/CD gate) |
| SOC Platform Engineer | Recommended Bullets | Role 2 (pipeline) + Role 1 (AppSec) |
| Solutions Architect | Role 3 | Recommended (ROI numbers) |
| GRC / AI Governance | Role 3 (bullet 4) | Recommended (bullet 4) |

---

## Go Cloud Architects — Updated Bullets (Add UAE Hospital)

### Existing Bullets (keep as-is or refine)

- Architected Fortune 500-equivalent security and cloud solutions across retail automation, manufacturing, and automotive IoT sectors, delivering defence-in-depth architectures with 99.99% uptime across banking, retail, and enterprise hybrid cloud environments.
- Designed responsible AI deployment frameworks with compliance protocols for ethical governance, RFI/RFP/RFQ response, and client-facing architecture proposals for enterprise digital transformation engagements.

### NEW Bullet — PrismHealth UAE Robotic Hospital

- **PrismHealth UAE — Robotic Surgery & Hospital Cloud Infrastructure** — Co-architected hybrid cloud and network infrastructure for a 1,000-bed Abu Dhabi hospital enabling <150ms remote robotic surgery across 4-5 concurrent operating theatres via triple-diverse WAN (dual dark fibre + SD-WAN backup); designed a 3-site active/active data centre fabric achieving 99.999% availability, specified zero-trust security architecture with Palo Alto NGFW, CrowdStrike EDR, and CyberArk PAM, and mapped full compliance to UAE OSHAD, UAE Federal Data Protection Law, JCI accreditation, ISO 27001/27017/27018, and HITRUST — with immutable 25-year data retention and <5 minute ransomware isolation.

---

## Why These Bullets Get You Interviews

### The honest assessment of your position

You are NOT a help desk candidate. You are NOT a field technician. Here is what your profile actually represents:

**What you have that most senior candidates don't:**
- A Robotics & Mechatronics engineering degree — hard STEM credential at a time when AI runs on robotics and IoT
- Built JanuSec: a real, production-grade XDR/SIEM-class platform from scratch — most "security architects" maintain vendor products, you built the product
- Built ShopSquire: a real agentic AI security platform with OWASP LLM compliance — barely anyone has done this
- Co-architected a life-critical hospital infrastructure for a 1,000-bed UAE facility — network that fails kills patients, the stakes don't get higher
- ISO 27001 Lead Auditor — not just a practitioner, you can audit and certify
- David Linthicum endorsement — former Chief Cloud Strategy Officer at Deloitte, one of the most cited names in cloud architecture — this is a tier-1 social proof signal
- MITRE ATT&CK, STRIDE, DREAD, MAESTRO, PASTA, OWASP LLM Top 10, ISO 42001, EU AI Act — you speak every language across detection, compliance, and AI governance simultaneously

**The gap you're facing:**
Your employment timeline is unconventional (healthcare career in between, project-based work vs linear corporate progression). Conservative Australian and US enterprise recruiters use ATS keyword matching and "years in role X" as filters. That means **you will be screened out by bots but pass human review**. The strategy is to get to the human.

---

## Roles to Target — Realistic and Strategic

### Tier 1: Apply Immediately (Strong Match)

| Role | Why You Win |
|---|---|
| **AI Security Engineer (Senior)** | JanuSec is exactly this role — you didn't apply for it, you built it |
| **Threat Intelligence Engineer** | HopGraph, TemporalRAG, hunt lanes, MITRE ATT&CK automation |
| **Security Architect** | ISO 27001 Lead Auditor + JanuSec architecture + Linthicum endorsement |
| **AI & Security Architect** | Your current title — the UAE + JanuSec + ShopSquire package is compelling |
| **Cloud Security Architect** | UAE hospital zero-trust design + Go Cloud Architects multi-cloud work |

### Tier 2: Strong Fit With Targeted Positioning

| Role | Angle |
|---|---|
| **AI Platform Engineer / MLOps** | JanuSec AI pipeline — 30 stages, embedding providers, model fallback, FinOps |
| **Solutions Architect (Security)** | ROI numbers (7.3x, 73% MTTD reduction) + enterprise compliance patterns |
| **DevSecOps Engineer** | CI/CD security gates, Bandit, API stage harness, Kubernetes deployment |
| **Healthcare IT Security Architect** | UAE hospital + health science background + ISO 27001 is a rare combination |
| **SOC Platform / Detection Engineer** | JanuSec is literally a SOC platform — hunt lanes, correlation, FP suppression |

### Tier 3: Good Money, Lower Competition in AU

| Role | Why Consider |
|---|---|
| **GRC / AI Governance Consultant** | ISO 42001 + EU AI Act + ISO 27001 Lead Auditor — very few people span both AI and GRC |
| **Security Consulting (Big 4)** | Linthicum's Deloitte connection — use it for a warm intro, not a cold apply |
| **MSSP Threat Intelligence roles** | JanuSec directly demonstrates the day-to-day output they need |

### Do NOT apply for:
- Help Desk / Field Technician / L1 Support — you are overqualified by a decade, they will reject you
- Junior/Mid positions — same issue, and it anchors your salary expectations badly
- Generic "Cloud Engineer" roles without a security angle — you'll compete against people with 5 years of pure infra and lose on YoE metrics

---

## The Strategy That Will Actually Work

1. **Lead with Linthicum.** His quote goes on every resume version, above the fold. "Former Chief Cloud Strategy Officer, Deloitte" is a name any tech hiring manager recognises. Ask him for a direct warm introduction if you haven't already.

2. **Target companies building AI security products** (CrowdStrike, Darktrace, Vectra, Securonix, Abnormal Security, Corelight, Cyera, Wiz) — they are hiring people who already understand the problem. Your JanuSec build IS the product demo.

3. **Target MSSPs and SOC-as-a-service vendors** (Secureworks, Trustwave, Arctic Wolf, Orca Security) — JanuSec solves their core operational problem. Show the ROI numbers upfront.

4. **Healthcare IT security is a niche you own** — Myotherapy background + Robotics degree + UAE hospital infrastructure + ISO 27001 is a combination that barely anyone else has. Target hospital networks, health insurers, and health IT vendors in AU (Telstra Health, Orion Health, Cerner/Oracle Health AU).

5. **UAE / Middle East market is live** — PrismHealth proves you can work at enterprise scale in the UAE. That market pays significantly more than AU for senior tech roles. Pursue it directly.

6. **Don't hide the career change** — the Myotherapy period shows you can manage complex stakeholder relationships, run a client-facing practice, and maintain discipline across multiple disciplines. Frame it as: *"I returned to tech with a full-stack understanding of what AI systems must deliver in high-stakes environments — I've been on both sides of clinical and technical risk."*
