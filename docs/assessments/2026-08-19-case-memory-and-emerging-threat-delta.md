# Case memory and emerging-threat delta — 2026-08-19

## Outcome

JanusSec now has explicit case-partition and multi-resolution episode contracts.
Evidence Pack compilation can be bound to one case and one question, performs a
second corrective retrieval pass, validates graph paths against supplied
topology/authorization snapshots, and records all resulting receipts. Models are
prevented from running assessment-wide when multiple investigation partitions
exist.

## Delivered

- `janusec.case-partition/v1` with stable partition and content hashes.
- `janusec.security-episode/v1` hour, day and campaign episodes.
- `GET /api/v1/assessments/{assessment_id}/cases` and per-case lookup.
- `POST /api/v1/assessments/{assessment_id}/cases/{case_id}/evidence-pack`.
- Case/question identifiers, partition hash, episode IDs, corrective evidence and
  path-validation results in Evidence Pack 2.1.
- Append-only pack receipt history; compatibility “latest pack” pointers remain.
- Case-scoped model prompts and a 409 guard against multi-case model narration.
- Immutable failed model-run records and deterministic frontier escalation advice.
- ChronoGraph time-pyramid summaries and a decayed multi-day campaign accumulator.
- HippoRAG/PPR-inspired episode retrieval as a shadow graph that disables
  cross-case association and suppresses hub entities.
- Coverage contracts for software/AI supply-chain, AI model/agent compromise,
  ransomware/extortion and steganographic delivery/exfiltration hypotheses.

## Local context smoke benchmark

The benchmark is intentionally labelled `literal-case-partition-smoke/v1`; it is
not a substitute for Vesper/Meridian reconstruction.

| Model | 8K | 16K | 32K | 64K |
|---|---|---|---|---|
| qwen3:14b | pass, 11.6s | pass, 16.0s | pass, 38.0s | pass, 94.0s |
| qwen3.8:27b | pass, 50.9s | pass, 59.8s | empty response | HTTP 500, 330.4s |
| qwen3.6:27b | runtime unavailable | runtime unavailable | runtime unavailable | runtime unavailable |

Qwen3.8's 64K failure terminated the local Ollama service. A restart exposed an
incomplete installation: `ollama.exe` exists but its required
`lib/ollama/llama-server.exe` does not. The benchmark therefore preserves
provider/runtime failures separately from reasoning scores.

## Reordered next work

1. Repair and pin the local model runtime; add startup probes that execute a tiny
   structured response, not merely an HTTP health check.
2. Re-ingest Vesper and Meridian so persisted assessments contain the new case and
   episode contracts, then rerun browser acceptance.
3. Create one Evidence Pack and one model run for every labelled case/question.
4. Replace the literal smoke benchmark with Vesper/Meridian evidence-placement,
   non-literal association, contradiction and distractor suites at each budget.
5. Add signed topology, IAM and CMDB snapshots; until then paths remain provisional.
6. Add real artifact/model provenance, backup/recovery, sandbox/tool and content-
   analysis connectors for the emerging threat profiles.
7. Persist episode and low-and-slow state in PostgreSQL with tenant-scoped
   incremental rebuild receipts.
8. Only then compare shadow PPR, dense retrieval, TemporalRAG and temporal GNNs by
   attribution quality and analyst nodes-to-inspect.
