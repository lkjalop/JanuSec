PCAP Endpoint Enterprise Roadmap

Objective: provide robust endpoint PCAP ingestion, TCP reassembly, artifact extraction, HopGraph enrichment, explainable factor mapping, and threat-model tagging.

Prioritized implementation tasks

1) Prototype TCP reassembly and sessionization (MVP)
- Implement `src/parsers/tcp_reassembly.py` using `scapy` or `dpkt`.
- Create `src/parsers/pcap_sessions.py` that groups flows into sessions and extracts basic metadata (start/end, bytes, endpoints, protocols).
- Add tests using small PCAP fixtures.

2) HTTP & TLS artifact extraction
- Extract HTTP payloads, request/response pairs, and files saved in HTTP transfers.
- Parse TLS handshakes to extract certs (SNI, SANs, JA3 fingerprint if desired).
- Map artifacts to indicators (domains, urls, file hashes).

3) HopGraph publishing
- Create nodes: `pcap_session:<id>`, `file:<sha256>`, `domain:<host>`, `process_instance:<host>:pid` (when available).
- Create edges: `participates_in`, `transfers_file`, `resolved_to`.
- Include attributes for session-level scoring and evidence pointers.

4) Explainable AI mapping
- For each detected indicator, emit a factor with supporting evidence: offsets, headers, payload snippets.
- Ensure factors include `mitre` mappings when signatures or heuristics match techniques.
- Integrate with the factor synthesis engine so session-level syntheses include PCAP evidence.

5) Threat modeling & scoring
- Use existing DREAD & STRIDE helpers to compute session threat model tags.
- Surface primary attack phase, likely techniques, and severity score in session metadata.

6) Operationalization
- Queue and worker pool for PCAP processing; provide priority, TTL, and reprocessing APIs.
- Sandbox extraction and scanning (containerized or separate process).
- Provide status endpoints and telemetry to show queue depth, processing latencies, and failure rates.

7) Security & privacy
- Redact PII where required before storing or sending to external services.
- Provide secure storage/backing for PCAP blobs and artifacts with TTL and access control.

Deliverables I can implement next
- `pcap_sessions` prototype with reassembly and HopGraph publish (heavy stage, flagged `heavy=True`).
- Example Tier-2 LLM summarizer prompt template for session summaries with evidence attachments.

If you want, I can start implementing the TCP reassembly prototype and a `pcap_session_stage` now.
