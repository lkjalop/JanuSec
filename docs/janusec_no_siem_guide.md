# Using Janusec Without A SIEM/XDR

This guide explains how organizations that only have a firewall and an Open Source Active Directory (AD) — but no SIEM or commercial XDR — can still deploy and benefit from Janusec. It covers architectural options, a 30-step data-to-action pipeline tailored for constrained environments, operational advice, and a simple ASCII architecture diagram.

**Assumptions**:
- Small-to-medium organization with limited budget and tooling
- Firewall (logging enabled) and an Open Source AD (e.g., Samba/FreeIPA)
- Basic server(s) to run Janusec (VMs or small cloud instance)
- Network access to forward logs or poll endpoints from the Janusec host

**High-level options (architectural perspectives)**
- Local-only (air-gapped or on-prem): Run Janusec on a local VM/physical server, ingest logs via file drops, syslog, or lightweight forwarders.
- Network-edge aggregator: Use a low-cost collector (rsyslog, nxlog, syslog-ng) on the firewall or a nearby host to normalize logs and send to Janusec.
- Agent-based minimal endpoint telemetry: Deploy a lightweight open-source agent (osquery, Wazuh agent, or custom eBPF probe) to capture endpoint metadata and send periodic snapshots to Janusec.
- Hybrid cloud: Run Janusec in a low-cost cloud instance and use secure tunnels (WireGuard/SSH) to pull logs from on-prem devices.

**Benefits of using Janusec without SIEM/XDR**
- Centralized correlation and investigation UI that works with lightweight inputs
- Lightweight incident creation and triage (Tier1 summaries) using local or mocked LLMs
- Graph-based correlation (HopGraph) to connect identity, endpoint, and network signals
- Extensible integrations to add more telemetry over time (agents, flow logs)

**30-Step Pipeline (from telemetry to protective action)**
The pipeline below shows a practical step-by-step flow Janusec can perform in constrained environments. Each step is actionable and implementable with open-source components and minimal infra.

1. Ingest firewall logs via syslog (rsyslog/syslog-ng) to a collector host.
2. Configure the collector to normalize firewall logs into a common JSON schema.
3. Periodically rsync/secure-copy normalized files to the Janusec `uploads` directory (or push via HTTP to `/api/v1/upload/files`).
4. If available, deploy `osquery` on critical endpoints to capture process, network connections, and loaded modules; export snapshots to the collector.
5. Use simple scripts to convert osquery JSON into Janusec SBOM-like components or event batches and push to Janusec.
6. Configure Janusec's `decisions/recent` and `insights/generate` endpoints for automated analysis and triage.
7. Janusec parses logs and extracts canonical fields: `src_ip`, `dst_ip`, `user`, `host`, `process`, `url`, `sha256`, `domain`.
8. Janusec builds short-lived correlation graphs (HopGraph sessions) from uploaded batches.
9. Compute simple heuristics for high-entropy events: repeated auth failures, unusual port access, NXDOMAIN bursts.
10. Rank suspect entities by simple scoring (frequency, novelty, user risk, unusual ports).
11. For high-priority suspects, Janusec invokes Tier1 summarization (LLM or deterministic templates) to create investigator-friendly notes.
12. Create an incident record in Janusec's incident store for manual or automated follow-up.
13. Enrich with AD context: map usernames to groups, recent AD login times, and host membership using LDAP queries against your Open Source AD.
14. Cross-reference firewall logs with AD login times to find mismatched accesses (e.g., remote access when user logged out).
15. For endpoint snapshots matching a suspect host, pull osquery artifacts (running binaries, open sockets, listening processes).
16. Apply lightweight YARA rules or hash checks against known-bad lists (local or public intel) to detect malicious files.
17. If a suspicious binary is found, compute file hash and check against public feeds (VirusTotal-like APIs) or local blacklists.
18. Score the overall incident using weighted factors (auth anomalies, network anomalies, file detection, AD context).
19. Auto-tag incidents with recommended actions: `investigate`, `isolate_host`, `rotate_creds`, `monitor`.
20. If configured with orchestration hooks (webhook), send recommended action to a ticketing system, Slack, or an SOAR runner.
21. Provide quick-playbooks in Janusec (right-rail actions) for common mitigations: block IP on firewall, disable AD account, isolate VLAN.
22. For firewall-level blocking, generate a minimal firewall rule (IP/CIDR + ports) and present the exact command to the network operator.
23. For AD account remediation, produce the exact LDAP/AD command to disable the account (or PowerShell snippet for Windows AD equivalent).
24. Keep all raw evidence (normalized logs, osquery snapshots, binary samples) attached to the incident for audit.
25. Allow manual triage follow-up: investigator notes, flag as false positive, or escalate.
26. Track incident lifecycle metrics (time-to-detect, time-to-remediate) in Janusec for continuous improvement.
27. Periodic export: create weekly SBOM/vulnerability-like reports to highlight recurring risky assets and users.
28. Automate baseline recalibration: use low-fidelity heuristics to reduce noise over time (e.g., suppress frequent benign flows).
29. Implement simple network segmentation guidance derived from incident patterns (host groups that frequently communicate externally become a segment to audit).
30. Regularly feed improved detection rules back into the collector normalization layer to improve fidelity.

Each step above is intentionally granular so organizations with limited tooling can implement a subset and gradually expand. The pipeline focuses on combining network firewall telemetry and AD context with optional endpoint snapshots to achieve meaningful detection and response.

**Architectural options (detailed)**

- Option 1 — Minimal on-prem (recommended for tight budgets)
  - Components: Firewall -> Syslog collector -> Janusec VM
  - Pros: Low cost, simple to operate
  - Cons: Limited endpoint telemetry, detection is primarily network-driven

- Option 2 — Agent-augmented (best detection ROI)
  - Components: Firewall + Collector + Janusec + osquery/Wazuh agents on critical hosts
  - Pros: Endpoint visibility, better false-positive reduction
  - Cons: Requires deploying agents and managing updates

- Option 3 — Hybrid cloud Janusec (easy scaling)
  - Components: On-prem collector pushes to cloud-hosted Janusec over WireGuard
  - Pros: Easier maintenance, central operations for multiple sites
  - Cons: Requires secure connectivity and compliance considerations

- Option 4 — Pull model / air-gapped
  - Components: Collector writes to removable media or isolated staging host; Janusec ingests via secure import
  - Pros: Works in constrained or highly secure networks
  - Cons: Less real-time, more manual overhead

**Deployment checklist & practical tips**
- Turn on detailed logging on the firewall (connection start/end, NAT translations, application metadata if available).
- Normalize timestamps and timezones in the collector to UTC to make correlation easier.
- Use lightweight compression (gzip) when transferring batched logs to Janusec.
- Start with a shortlist of critical hosts and users for `osquery` snapshots — don't try to protect everything at once.
- Maintain a local blocklist for known-bad IPs and hash values; keep it updated from public intel feeds.
- Document runbooks for the most frequent incident types (e.g., compromised AD account, suspicious outbound connection).

**How to advise companies (concise)**
- Start small: enable firewall logging and get Janusec ingesting those logs first.
- Add AD enrichment quickly — it's low effort and yields big correlation wins.
- Gradually deploy endpoint snapshots (osquery) to your most critical hosts.
- Use Janusec playbooks to convert detection into repeatable response steps — automate only low-risk actions initially (notify, create tickets).
- Measure and iterate: track false positives and reduce noise by adding suppressions and tuning heuristics.

**ASCII architecture (simple)**

```
                     +-------------------------+
                     |       Internet          |
                     +-----------+-------------+
                                 |
                             (Edge FW)
                                 |
                   +-------------+-------------+
                   |  Syslog Collector / Host  |
                   |  (rsyslog / syslog-ng)   |
                   +------+------+-------------+
                          |      |
    optional osquery ->   |      |    SCP/HTTP push
      endpoints push      |      v
  +-------------+    +----+-------------------+    +----------------+
  |  Endpoints   | -> | Janusec Server / VM  | <- | Open Source AD |
  |  (osquery)   |    |  (uploads, graph,    |    | (Samba/FreeIPA) |
  +-------------+    |   LLM/triage, UI)    |    +----------------+
                     +----+------------------+
                          |
                   Actions: block IP / disable AD account / ticket
```

**30-step pipeline mapping to Janusec features**
- Ingestion: upload files endpoint, CSV/JSON parsers
- Correlation: HopGraph session build, EWMA smoothing, mapping editor
- Triage: `insights/generate` (LLM or deterministic templates)
- Enrichment: LDAP lookups, osquery snapshot ingestion
- Response: webhooks, playbooks, firewall rule generation

**Final notes and risk considerations**
- Without XDR, detection will be less precise — rely on combined signals (network + identity + occasional endpoint snapshots) to reduce false positives.
- Prioritize containment over automatic remediation until confidence is high.
- Keep data retention and access controls strict — logs and artifacts may contain sensitive information.

If you want, I will:
- create a short runbook `scripts/run_baseline_setup.sh` to configure rsyslog and a sample Janusec upload flow;
- produce sample `osquery` packs and Janusec upload examples under `examples/`;
- or run through an end-to-end demo with the data you have.
