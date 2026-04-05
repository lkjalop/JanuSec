LLM Summaries & Domain-Log Suggestions

Purpose
- Provide a concise mapping from suspicious factors (signals) and explain outputs to the additional domains/log sources analysts should collect to improve HopGraph correlation and attack reconstruction.
- Offer LLM summary templates and UI text for policy-aware guidance when insider threat or credential compromise is suspected.

How to use
- When the CSV Analyzer or Deep Analyze synthesizes a high-confidence signal (e.g., `deep_enriched`, `lolbin`, `unsigned_sensitive_path`, `multi`), present these suggestions in the modal's "Playbooks / Remediation" or as a small banner: "Recommended additional logs to collect". The UI should respect legal/policy gating: if the suggestion involves user email or content, require a checkbox confirming policy review before enabling automated collection.

Mapping: Signal -> Recommended Logs / Domains
- deep_enriched
  - Why: Client-side enrichment merged external pipeline artifacts with evidence from CSV rows; suggests a correlation candidate.
  - Collect: Correlation session details, full packet capture (if available), endpoint process start/end logs, host EDR timeline, HTTP/HTTPS proxy logs, and authentication logs (IAM). Collect identity mapping (user->host) and recent privileged actions.
  - Priority: High

- lolbin (living-off-the-land binary)
  - Why: Admin utilities abused for execution; may indicate lateral movement or execution of payload via trusted binaries.
  - Collect: Process ancestry from EDR, command-line history, scheduled tasks, WMI logs, PowerShell transcription, Windows Event Logs (Event ID 4688/4689), endpoint network connections, and remote access session logs (RDP/SSH/VPN).
  - Priority: High

- unsigned_sensitive_path
  - Why: Binary located in sensitive path without expected signing; could be dropped by malware or abused installer.
  - Collect: File system access logs, MSI/installer logs, code-signing metadata, EDR file hash evidence, and cloud object storage (S3/GCS/AzureBlob) access for binaries if cloud-backed.
  - Priority: Medium

- multi (seen across multiple batches/sources)
  - Why: Multi-batch occurrence suggests distribution (higher confidence) — expands correlation surface.
  - Collect: Cross-host timeline, central logging (SIEM), DNS logs, proxy logs, network flows, cloud access logs, and internal artifacts (software deployment logs, patching systems) to rule out benign rollout.
  - Priority: High

- suspicious (heuristic/textual matches)
  - Why: Keyword heuristics can produce noise; requires context enrichment.
  - Collect: Application logs where keywords appear, full raw fields (to inspect noise), and any related telemetry to validate pattern (e.g., user agent, headers, referrer).
  - Priority: Low-Medium

- novel_global
  - Why: Artifact not seen in global telemetry; may be new vendor file or targeted sample.
  - Collect: File sample (binary), static/dynamic analysis reports (VirusTotal, JSandbox), sandbox traces, artifact provenance (where downloaded from), and network telemetry where download originated.
  - Priority: Medium

- network anomalies (NXDOMAIN spike, rare ASN, large request volumes)
  - Why: Points to exfiltration, C2, or staged infrastructure.
  - Collect: DNS query logs (including NXDOMAIN counts and timestamps), flow logs (VPC Flow, NetFlow), proxy logs, TLS SNI, and CDN logs. Enrich with ASN lookup history and geolocation.
  - Priority: High

- credential_anomaly / iam (suspicious token usage, privileged API calls)
  - Why: Direct sign of compromised credentials or malicious cloud activity.
  - Collect: Cloud IAM logs (CloudTrail, GCP audit logs, Azure Activity Log), privileged API call history, token issuance/refresh events, service account activity, and session metadata (source IP, geolocation).
  - Priority: Critical

- ai_model_usage / data_api (anomalous AI usage or large data pulls)
  - Why: Indicates potential data exfiltration or model theft; unique in environments with AI services.
  - Collect: Application/API logs for model access endpoints, API key usage logs, request payload sizes, S3/DB download logs, data access audit logs, and model access patterns.
  - Priority: High

Suggested UI text / alerts (short, policy-aware)
- Banner (low-disruption): "Recommended additional logs: IAM logs, endpoint process timeline, and proxy logs. Click to collect or review policy before request."
- Modal suggestion (more context):
  - Title: "Recommended Evidence to Improve Correlation"
  - Body: "This analysis suggests potential credential misuse and unusual execution patterns. To improve HopGraph reconstruction, consider collecting: 1) Cloud IAM logs (CloudTrail), 2) Endpoint process lineage and command-line history, 3) DNS & proxy logs covering the last 24 hours. Collecting email contents or user mailbox data may require policy approval — please confirm authorization."
  - Buttons: `[Request Logs] [Request With Policy Approval] [Dismiss]`
- Policy gating tooltip: "Requests that include user mailbox or content will pause for legal/HR review. Use 'Request With Policy Approval' to continue." 

LLM Summary templates (short & analyst-facing)
- Short template (one-liner):
  "Summary: [VERDICT] on [HOST] — [PROCESS/ARTIFACT]. DREAD: [SCORE]. Key signals: [factors]. Suggested next logs: [list]. Confidence: [XX]% (derived from DREAD + factor counts)."

- Medium template (3–4 sentences):
  "This record is flagged as [VERDICT] on host [HOST] involving [PROCESS/ARTIFACT]. Key signals: [factors]. The synthesized DREAD score is [SCORE], driven by [top contributors]. For improved correlation and path reconstruction, collect [list of domain logs]. If credential compromise is suspected, prioritize `IAM logs` and `session metadata` and escalate following policy." 

- Long template (expanded analyst note):
  "Analyst Summary:
   - Artifact: [PROCESS/ARTIFACT] on [HOST] (sha256: [SHA256])
   - Verdict: [VERDICT], DREAD [SCORE]
   - Signals: [factors]
   - Rationale: [short reason why factors and DREAD indicate this verdict]
   - Recommended evidence: 1) Endpoint process lineage & EDR timeline; 2) Cloud IAM logs & API audit trails; 3) DNS, proxy, and flow logs covering [time window]; 4) File sample for static/dynamic analysis. Note: access to user mailboxes or content requires policy approval; if requested, follow corporate legal/HR escalation procedures."

Policy-aware guidance (how to surface in UI)
- When LLM or explain suggests mailbox/email content, show a prominent policy banner requiring one-click confirmation: "I confirm this request has appropriate authorization (legal/HR)". Record this confirmation in event audit before performing data access.
- For suspected insider or credential compromise, include an immediate recommended action list: "1) Rotate compromised credentials; 2) Block active sessions; 3) Isolate host; 4) Search for lateral movement indicators." Include safe, read-only options (e.g., 'Collect logs for review') vs. active remediation ('Rotate credentials now') with clear audit trails.

Notes and implementation hints
- Expose suggested logs as a list of clickable checkboxes in the modal; clicking `Request Logs` should send a combined request to the server integrations that will enqueue the log collection or call registered collectors (with `x-api-key`) and record that the artifacts were requested.
- The UI should always record what the analyst requested and any policy confirmations in telemetry for audit and later model-training (feedback loop).
- Where possible, avoid automatically fetching sensitive content; prefer a ticketed request (requires policy approval) or dry-run metadata collection (counts, time windows, hashes) before requesting content.

Appendix: Quick factor→priority summary
- Critical: credential_anomaly / iam
- High: deep_enriched, lolbin, multi, network anomalies, ai_model_usage
- Medium: novel_global, unsigned_sensitive_path
- Low-Medium: suspicious

---
Created for the CSV Analyzer / Deep Analyze flows to improve HopGraph correlation and to guide UI/LLM integration.