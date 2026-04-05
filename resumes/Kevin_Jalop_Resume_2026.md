# Kevin Jalop — AI & Security Platform Architect

**Contact:** Kevin Jalop  ·  Email: kevin@example.com  ·  Location: [City, Country]  ·  GitHub: github.com/kevinjalop

**Summary**
- **Role:**: AI & Security Platform Architect (solo-built Janusec platform)
- **Specialty:**: Platform design and full-stack implementation of detection, correlation and SBOM pipelines; rapid prototyping to production-ready demos
- **Approach:**: Hands-on owner across architecture, backend, integrations, testing, and product demos; emphasis on reproducible instrumentation and lightweight debuggability

**Core Skills**
- **Languages:**: Python, SQL, Bash, JavaScript
- **Frameworks / Tools:**: FastAPI, pytest, httpx, Prometheus, HopGraph (custom), dpkt/scapy, playbook automation
- **Cloud / Infra:**: Azure Functions (integrations), container workflows, local dev / CI
- **Security Domains:**: eBPF/Falco ingest, host telemetry, network PCAP analysis, SBOM scanning, threat detection rules

**Selected Projects**
- **Janusec — AI Security Platform (Owner / Architect)**
  - **Role:**: Solo architect and developer for Janusec demo platform, responsible for end-to-end design, implementation, and demo readiness.
  - **Responsibilities:**: Backend API (FastAPI), ingestion endpoints (Falco/eBPF, webhook adapters, SBOM upload), event pipeline stages, lightweight HopGraph correlation, and the static LIVE Console demo UI.
  - **Technical highlights:**
    - **Ingest:** Implemented robust Falco/eBPF ingest with normalization, rate guards and hand-off to an EventPipeline for downstream analysis.
    - **Analysis:** Built `ebpf_analysis` stage with decaying syscall baselines, Falco→MITRE mapping, and explainable factor emission.
    - **Correlation:** Designed a lightweight HopGraph publisher for sessions and file/batch evidence linking; created `pcap_session:<id>` nodes and `participates_in` edges.
    - **SBOM & Vulnerability Flow:** Added SBOM upload and lightweight vuln mapping endpoints used by the UI demo.
    - **Testing & Reliability:** Hardened unit tests for ingest endpoints, added site-level test shims and `conftest` fixtures to avoid expensive import-time init and make CI runs deterministic.
    - **UI Integration:** Served a static LIVE Console (frontend/static/janusec-platform-complete-LIVE.html) and added demo static pages for Network/Endpoint/SBOM panels.
  - **Outcomes:**
    - **Demo-focused:** Platform serves a production-feel interactive demo, supports exportable investigation reports, and has endpoint tests covering key ingestion paths.
    - **Ownership:** Position is justifiable to present as “AI & Security Platform Architect” given sole responsibility for platform components (design → code → tests → demo).
  - **Tech stack:**: Python, FastAPI, pytest, dpkt/scapy, Prometheus, simple filesystem persistence for sessions, lightweight JS static UI.

- **PCAP Session Reconstruction**
  - **Work:** Implemented session grouping, initial publication to HopGraph, and unit tests for session builder and hopgraph publish hooks.
  - **Next steps:** Add TCP reassembly, HTTP artifact extraction, and additional integration tests.

- **LOLBins Catalog Expansion**
  - **Work:** Extended the LOLBins catalog, wrote a merge/validation helper, and added ~39 extra entries (catalog now larger).

**Other Experience**
- **Integrations & Connectors:**: Webhooks, SIEM dispatch, Slack/Teams webhook test endpoints, event normalization across sources
- **DevOps:**: CI-focused packaging, light-weight background task guards for test runs, local dev scripts for demo startup

**Education & Certifications**
- **Relevant:**: [Add degrees / certifications here — e.g., MSc Cybersecurity, Certified Cloud Practitioner, etc.]

**Suggested Resume Edits (Janusec-specific & formatting)**
- **Change to dot-form:**: Convert long paragraphs into concise bullets (done in this .md). Bullets improve skimmability for hiring managers.
- **Title clarity:**: Use `AI & Security Platform Architect` for Janusec ownership. It reflects platform design + implementation responsibility.
- **Quantify outcomes:**: Add measurable results where possible (e.g., "reduced demo startup time by X", "added N unit tests", "catalog grew by 39 entries"). If you have metrics (users, demo runs, performance), add them.
- **Focus on impact:**: For each project bullet, add one short line on impact (demo readiness, reliability, detection coverage, or operational lessons).
- **Call out solo ownership:**: Add a short parenthetical like `(solo-engineered)` after Janusec project name to make ownership explicit.
- **Consistency:**: Make sure contact info and GitHub/portfolio links are present and up to date.

**Export / Next Steps**
- **Export to PDF (suggested):**: If you use pandoc, run:

```bash
pandoc "resumes/Kevin_Jalop_Resume_2026.md" -o "Kevin_Jalop_Resume_2026.pdf" --from markdown --template=default
```

- **Optional polish:**: Add a short objective line under Summary tailored to the role you want (platform architect, head of security engineering, etc.).
- **Add links:**: Add links to the Janusec repo or a short 1–2 minute demo GIF for product-context in the header.

---

If you want, I can:
- (a) incorporate specific metrics/numbers you provide into the bullets,
- (b) produce a condensed one-page variant optimized for hiring managers,
- (c) produce a two-column layout flavor for visual PDF rendering.
