# Detection Pipeline

The event pipeline is composed of 30 logical stages. Each stage performs a specific transformation or scoring operation. Heavy stages are computationally expensive and are gated by a per-event confidence threshold to allow adaptive skipping under load.

Sanitized stage list (descriptive):
- baseline, regex, parent_child, endpoint, email_enrichment, auth_burst, identity
- graph, adaptive_pre, packet_summary, threat_intel, supply_chain_npm, supply_chain_cicd
- binary_payload (heavy), sbom_exec, sbom_vuln, ebpf_analysis, cert_analysis, http_header
- beacon (heavy), egress (heavy), domain_novelty (heavy), rare_token, hunt_lanes
- correlation, quality_filter, mapping, cluster_dedupe, coverage_tracker, embedding

Adaptive skip example (public):

If an event reaches a configured confidence threshold early in the pipeline, heavy stages may be skipped to preserve throughput. This is a performance optimization; it does not reduce detection fidelity for lower-confidence events.
