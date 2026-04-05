Factors Catalog (split)

Structure:
- `factors_network.json` — network-related factor entries
- `factors_endpoint.json` — endpoint/host-related factor entries
- `factors_deception.json` — honeypot/deception factor entries
- `factors_identity.json` — identity/IAM-related factor entries
- `factors_cloud.json` — cloud-specific factor entries
- `factors_application.json` — application-level factor entries
- `factors_supply_chain.json` — supply-chain factor entries
- `index.json` — manifest with file counts

Fields per factor (concise):
- `name` : short id (snake_case, stable identifier used in rules and UIs)
- `domain` : canonical domain (`network`,`endpoint`,`deception`,`identity`,`cloud`,`application`,`supply_chain`,`temporal`,`operational`,`threatintel`)
- `severity` : 0.0-1.0 heuristic severity (float). Not a final score — used for prioritization and scoring weights.
- `mitre` : (optional) ATT&CK IDs (array of strings)
- `stride` : (optional) STRIDE categories (array)
- `kill_chain` : (optional) Cyber Kill Chain or equivalent stages
- `compliance` : (optional) crosswalk tags (ISO27001, NIST-RMF, GDPR, PCI-DSS, HIPAA, ISO42001, CIS/E8, EU-AI-Act)
- `diamond` : (optional) lightweight Diamond model fields (adversary, capability, infrastructure, victim)
- `dread` : (optional) small object with `damage`, `repro` etc (for heuristic scoring)
- `notes` : (optional) freeform note about detection caveats or tuning

File conventions and CI:
- Keep files under 400 lines to satisfy the repo's CI line-check (see `sultry_prd/scripts/check_max_lines.py`).
- Use `full/factors_catalog_full.json` as the editable, human-reviewed source of truth. Split it into domain files for CI and runtime consumption.

ASCII Architecture (high-level):

 Ingest -> Normalize -> Enrich -> Score -> Correlate -> Alert/Export

	+----------------+    +--------------+    +-----------+    +--------+    +-----------+    +-------------+
	|   Ingestors    | -> |  Normalizer  | -> |  Enricher | -> | Scorer | -> | Correlator | -> |  Outputs    |
	+----------------+    +--------------+    +-----------+    +--------+    +-----------+    +-------------+

	- Ingestors: collectors and connectors that bring telemetry/events into the pipeline.
		- Examples: Zeek/Suricata logs, Zeek conn, syslogs, EDR events, cloud audit logs, honeypot events, package repo scans.
		- Use case solved: centralizing heterogeneous telemetry for unified processing.

	- Normalizer: converts vendor-specific fields into canonical event schema used by Sultry (timestamp, src_ip, dst_ip, user, host, process, file_hash, domain, event_type, raw).
		- Examples: map `src`, `dst`, `saddr` to `src_ip`; normalize timestamps to UTC isoformat; canonicalize user identifiers.
		- Use case solved: downstream rules and models can reference stable fields and reuse factors across sources.

	- Enricher: attaches contextual metadata to events (geoip, ASN, IP reputation, user risk scores, host inventory, MITRE mappings, factor matches from catalog).
		- Examples: query local intel store for IP reputation, add `mitre` tags to suspicious processes, flag events that match deception triggers.
		- Use case solved: improves signal-to-noise for scoring and correlation; enables compliance tagging.

	- Scorer: applies factor catalog logic + heuristic scoring (severity, DREAD adjustments, mapping semantics) to produce a per-event or per-path score vector.
		- Examples: apply `honeypot_interaction` => high base severity; add mapping weight if `user`+`host` co-occurrence; record `score_breakdown`.
		- Use case solved: reduces raw telemetry into prioritized, explainable risk signals.

	- Correlator: links events into multi-step paths (HopGraph), computes overlap matrices, EWMA smoothing, and factors aggregation for session verdicts.
		- Examples: correlate repeated credential use with outbound exfil and C2 beaconing to raise incident confidence.
		- Use case solved: surfaces campaigns and multi-stage threats rather than isolated alerts.

	- Outputs: alerts/incidents, SIEM export, webhook integrations, SBOM/vuln scanners, human investigation UI.
		- Examples: push to Slack via webhook, export incident report HTML, create investigation record in console.
		- Use case solved: delivers high-quality, contextual alerts and reports to analysts and downstream systems.

How the factor catalog integrates:
- During Enrichment, each incoming normalized event is evaluated against factor signatures/patterns in the catalog. Matches annotate the event with `factor:<name>` tags and candidate compliance references.
- During Scoring, matches contribute weighted scores; DREAD/Diamond/STRIDE fields feed scoring explainability and routing (e.g., `EU-AI-Act:HighRisk` may require stricter review paths).
- During Correlation, factor overlaps across sessions help compute path-level confidence and identify pivot points (e.g., credential reuse + atypical process execution + external data transfer).

Examples (quick):
- A honeypot `canary_file_access` event: Ingest -> Normalizer tags `host` and `file` -> Enricher attributes `honeypot=true` -> Factor match -> Scorer assigns high weight -> Correlator links with `credential_reuse_from_honeypot` -> Outputs create a high-confidence incident.
- A suspicious Docker image pull: Ingest cloud logs -> Normalizer -> Enricher attaches `repo` metadata -> Factor `malicious_container_image_pull_2` matched -> Scorer raises supply-chain risk -> Output triggers developer-facing ticket and CI block.

Notes on extending:
- Add new factors to `full/factors_catalog_full.json` and re-run the split process to generate per-domain files with full metadata.
- Consider adding a simple script `scripts/split_full_catalog.py` to automate splitting and ensure CI-safety.

Contact / Maintainers:
- Keep changes scoped to `sultry_prd/` to avoid touching `JanuSec` core assets.

---
This README documents the current catalog format and pipeline orientation. If you'd like, I can also:
- Add a JSON schema and a small Python validation script that ensures each factor has required fields (name, domain, severity).
- Add the `scripts/split_full_catalog.py` automation and wire it into the repo's tasks.

Usage:
- Consumers can read `index.json` to enumerate domain files.
- To add many factors, create new domain files or append to the appropriate file. Keep each file under 400 lines to satisfy CI.

Next steps:
- Optionally rehydrate a human-readable full catalog in `full_catalog/` (ignored by CI) for editing and review.
- If you want, I can split the original expanded 100-entry catalog into these files and add missing fields (diamond/dread/compliance IDs) per factor.
