# Option C – CEO Demo Script

**Duration:** 15–20 minutes  
**Goal:** Show how the platform collapses Tier 1 triage from 20 minutes to 30 seconds and equips junior analysts with Tier 2 playbooks.

---

## Setup (5 minutes prior)

1. Start stack: `python run_platform.py`
2. Browser: http://localhost:8000/static/csv_analyzer.html
3. Load `tests/test_data/option_c_demo.csv`
4. Pre-open “Investigate Further” on the `powershell.exe` row
5. Keep backup screenshots in `docs/screenshots/`

---

## Demo Flow

### Act 1 – The Problem (2 min)

> “Analysts spend 20+ minutes per alert: googling processes, reading MITRE docs, deciding which logs to pull. Our console shrinks that to ~30 seconds with domain-aware AI triage.”

### Act 2 – Tier 1 Fast Triage (3 min)

*Highlight CSV Analyzer table*
- Call out domain badges: NETWORK (blue) on `svchost.exe`, ENDPOINT (green) on `powershell.exe`, GENERIC (gray) on `taskmgr.exe`
- Emphasize workload routing and instant context (“LLM column shows who already has Tier 2 summaries”)

### Act 3 – Tier 2 Deep Dive (5 min)

*Click “Investigate Further” on `powershell.exe`*
- Point to SECTION 2 “Historical Context”: shows “14 days ago – CONFIRMED_MALICIOUS (Emotet dropper)”
- Scroll to SECTION 4 “Collection Playbook”: mention KAPE, Volatility, Sysmon IDs
- Highlight MITRE mapping and automatic recommendations (“Isolate WORKSTATION-042 immediately”)

### Act 4 – AI Insights On-Demand (3 min)

*Stay on deep analysis page*
- Click “Generate Detailed DREAD Scenarios” (cost ~$0.001) and show the structured output
- Click “Generate Collection Playbook” (rule-based, $0) – stress that juniors get expert-grade guidance
- Click “Generate Hunt Query” (KQL/SPL/Sigma) – demonstrates proactive sweep capability
- Mention running cost tracker (“we can show CFOs that a full investigation costs <$0.003 in LLM spend”)

### Act 5 – HopGraph Visualization (2 min)

*Scroll to HopGraph section*
- Show the three-node chain: explorer.exe → powershell.exe → C2 IP
- Mention multi-hop explainability, timeline toggles, and that HopGraphLite is resident even without SIEM backhaul

---

## Closing (2 min)

- Reiterate ROI: 40× faster triage, 6,600× cheaper than manual analyst time, $236K/year savings at 1,000 alerts/month
- Competitive differentiators:
  1. Domain-specific AI (network vs endpoint vs cloud)
  2. Historical memory baked into Tier 2 prompts
  3. Transparent LLM cost tracking
  4. Two-tier workflow (fast triage + deep dive)
  5. HopGraph attack reconstruction

### Common Q&A Sound Bites

- **LLM hallucinations?** Retrieval-augmented; prompts cite concrete telemetry and MITRE mappings.
- **Sensitive data?** Run local models or sanitize payloads; no raw packet capture leaves your network.
- **False positives?** Analyst feedback loops feed the historical incidents DB; future prompts show FP context.
- **Integrations?** Splunk, Sentinel, QRadar, CrowdStrike, SentinelOne, Wazuh, Suricata, Zeek.
- **Timeline to production?** Phase 1 (CSV + Tier 2) 2–3 weeks; Phase 2 (connectors, SSO, RBAC) 4–6 weeks; Phase 3 (multi-tenant HopGraph) 8–10 weeks.

---

## Fallback Assets

If live demo stalls:
1. `docs/screenshots/csv_analyzer_domain_badges.png`
2. `docs/screenshots/tier2_historical_context.png`
3. `docs/screenshots/domain_specific_tools.png`
4. `docs/screenshots/hopgraph_attack_chain.png`
5. `docs/screenshots/ai_insights_cost_tracking.png`

---

## Post-Demo Follow-Up

Send the prospect:
1. This script
2. Screenshot pack
3. Sample tier 2 prompt (`tier2_prompt_demo.txt`)
4. ROI calculator spreadsheet
5. Competitive analysis PDF
