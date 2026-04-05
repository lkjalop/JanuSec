from typing import Dict, Any


class EnhancedPortScanPromptBuilder:
    """Build context-rich prompts for port scan analysis (Tier1 and Tier2)."""

    @staticmethod
    def build_tier1_port_scan_prompt(
        scan_event: Dict[str, Any],
        factors: list,
        dread_score: Dict[str, Any],
        kill_chain_phase: str,
        diamond_cluster: Dict[str, Any],
        inferred_motivation: Dict[str, Any],
        subsequent_activity: Dict[str, Any],
    ) -> str:
        dread_breakdown = f"""
DREAD Score: {dread_score.get('composite', 0):.1f}/10
  - Damage Potential: {dread_score.get('damage','N/A')}/10
  - Reproducibility: {dread_score.get('reproducibility','N/A')}/10
  - Exploitability: {dread_score.get('exploitability','N/A')}/10
  - Affected Users: {dread_score.get('affected','N/A')}/10
  - Discoverability: {dread_score.get('discoverability','N/A')}/10
"""

        kill_chain_context = f"Cyber Kill Chain Phase: {kill_chain_phase}\n"

        adversary_context = f"Adversary Cluster: {diamond_cluster.get('cluster_id','N/A')} ({diamond_cluster.get('cluster_size',0)} related scans); Infrastructure: {diamond_cluster.get('infrastructure_type','unknown')}"

        threat_intel = ", ".join(scan_event.get('threat_intel_tags', [])) if scan_event.get('threat_intel_tags') else 'No matches'

        target_summary = f"Hosts scanned: {len(scan_event.get('destination_ips', []))}; Ports: {', '.join(map(str, scan_event.get('destination_ports', [])[:10])) if scan_event.get('destination_ports') else 'N/A'}; Business tier: {scan_event.get('business_tier','Unknown')}"

        prompt = f"""You are a senior SOC analyst providing a CRITICAL ALERT SUMMARY for Tier 1 triage.

PORT SCAN DETECTION SUMMARY:

{dread_breakdown}

Kill Chain: {kill_chain_context}

Adversary: {adversary_context}

Threat Intel: {threat_intel}

Target: {target_summary}

Top Factors:
{chr(10).join([f'- {f.get("name")}: {f.get("value","N/A")} (confidence: {f.get("confidence",0):.2f})' for f in (factors or [])[:6]])}

TASK: Provide a 3-4 sentence summary for Tier 1 covering:
1. SEVERITY: Why this is critical/high/medium (reference DREAD)
2. THREAT: What type of attacker this likely is (reference inferred motivation)
3. RISK: What could happen next (reference kill chain phase)
4. ACTION: Immediate recommended response (specific, actionable)

Keep under 120 words. Use clear, direct language suitable for an analyst to act on immediately.
"""

        return prompt

    @staticmethod
    def build_tier2_port_scan_prompt(
        scan_event: Dict[str, Any],
        all_factors: list,
        hopgraph_chains: list,
        vulnerability_matches: list,
        pasta_business_context: Dict[str, Any],
        kill_chain_full_analysis: Dict[str, Any],
        forensic_log_gaps: list,
    ) -> str:
        scan_summary = f"Scan from {scan_event.get('source_ip','unknown')} targeting {len(scan_event.get('destination_ips',[]))} hosts on ports {', '.join(map(str, scan_event.get('destination_ports',[])[:10]))}"

        dread_full = all_factors and any(f.get('name') == 'dread' for f in all_factors)

        vuln_list = '\n'.join([f"- {v.get('service')} -> {v.get('cve')} (CVSS: {v.get('cvss')})" for v in (vulnerability_matches or [])[:10]]) or 'None found.'

        hopgraph_text = '\n'.join([f"Chain {i+1}: {c.get('summary','')[:200]}" for i,c in enumerate(hopgraph_chains or [])[:5]]) or 'No chains.'

        log_gaps_text = '\n'.join([f"- {g['source']}: {g.get('status')} ({g.get('time_since_human','never seen')}) Impact: {g.get('impact')}" for g in (forensic_log_gaps or [])]) or 'No gaps detected.'

        prompt = f"""You are a Tier 3 threat analyst conducting IN-DEPTH investigation.

INCIDENT OVERVIEW:
{scan_summary}

EVIDENCE SUMMARY:
Top Factors:
{chr(10).join([f'- {f.get("name")}: {f.get("value","N/A")}' for f in (all_factors or [])[:20]])}

HOPGRAPH CHAINS:
{hopgraph_text}

VULNERABILITY CORRELATION:
{vuln_list}

PASTA BUSINESS CONTEXT:
Assets: {pasta_business_context.get('asset_criticality','N/A')}; Revenue impact: {pasta_business_context.get('revenue_impact','N/A')}

KILL CHAIN ANALYSIS:
{kill_chain_full_analysis.get('narrative','No analysis available')}

FORENSIC LOG GAPS:
{log_gaps_text}

TASK: Produce a 400-500 word comprehensive analysis covering:
1. ATTACK NARRATIVE: From reconnaissance to current state
2. TECHNICAL EVIDENCE: Reference factors, hopgraph chains, and vuln matches
3. THREAT ACTOR ASSESSMENT: sophistication, motivation, likely next steps
4. BUSINESS IMPACT: explain in business terms
5. INVESTIGATION GAPS: list missing logs and how they limit visibility
6. RECOMMENDED RESPONSE: prioritized action plan with timeline

Reference specific MITRE techniques and CVE IDs where relevant. Be thorough and precise.
"""

        return prompt
