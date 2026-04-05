# Ingestion, Policy, Classification & Escalation Flow (MVB)

## 1. Canonical Event Schema
Fields (subset used currently):
- tenant_id
- event_id
- ts (epoch ms)
- process_name / parent_process
- command_line
- domain / dst_ip / dst_port
- bytes_out
- sbom_component (optional)
- raw (truncated or hashed)

## 2. Ingestion Paths
- `/api/v1/events` (generic legacy ingest)
- `/api/v1/events/eclipse-xdr` (light normalization -> queue)
- `/ingest/eclipse_xdr_mvb` (MVB path: normalize + policy + classification + action dispatch)

Adapter: `core/ingest/eclipse_xdr_adapter.py` produces canonical events.

## 3. Policy Engine
Env config `POLICY_CONFIG_JSON` structure:
```json
{
  "allow": {"domains": ["*.corp.local"], "process_names": ["svchost.exe"], "command_substrings": ["--healthcheck"]},
  "block": {"domains": ["*.onion", "stealer.bad"], "process_names": ["mimikatz.exe"], "command_regex": ["(?i)invoke-mimikatz"]}
}
```
Wildcard & pattern rules:
- `*` => greedy segment; `?` => single char.
- Domains, processes case-insensitive.
- Command block uses regex; allow uses substring list.

Endpoints:
- `GET /policy/status`
- `POST /policy/reload`

## 4. Classification Ladder
Order:
1. Policy block => block (skip pipeline).
2. Policy allow => allow (skip pipeline).
3. Pipeline factors → severity (confidence) + optional quality.
4. Thresholds (env):
   - `BLOCK_THRESHOLD` (default 0.90) with `MIN_BLOCK_QUALITY` (0.75)
   - `ESCALATE_THRESHOLD` (0.65) with `MIN_ESC_QUALITY` (0.5)
5. Outcomes: block | escalate | allow.

## 5. Actions & Dispatch
Components:
- `core/actions/dispatcher.py` (Slack + Eclipse sink + file audit)
- `core/actions/eclipse_sink.py` (stub outbound)
- Slack (if `SLACK_WEBHOOK_URL`) receives block & escalate.
- File audit path `AUDIT_LOG_PATH` (default `artifacts/audit/decisions.log`).

## 6. Escalation Queue
- In-memory only: `core/escalation/queue.py`
- Endpoint `GET /escalations` (tenant filter) & `POST /escalations/{id}/resolve`.
- TTL: `ESCALATION_TTL_SECONDS` (default 86400s).

## 7. Decision Rationale
Each `ActionDecision` logs: event_id, tenant_id, decision, reasons, severity, quality, top factors.
Reasons include: `policy_block`, `policy_allow`, `severity_threshold`, `severity_escalate`, `below_threshold`, `no_severity`, `pipeline_error`.

## 8. Integrity & Audit
- JSONL append-only decisions file.
- Existing DB decision + custody chain unaffected.

## 9. Extensibility Roadmap
- Persist escalation queue.
- Analyst feedback loops adjust policy suggestions.
- Per-tenant threshold overrides.
- Batch Slack digests & enrichment links.
- Enforcement plugin architecture (EDR, firewall APIs).

## 10. Environment Variables Reference
| Variable | Purpose | Default |
|----------|---------|---------|
| ECLIPSE_API_KEY | Ingest API key | (none) |
| POLICY_CONFIG_JSON | Policy allow/block config | {} |
| BLOCK_THRESHOLD | Auto-block severity | 0.9 |
| ESCALATE_THRESHOLD | Escalation severity | 0.65 |
| MIN_BLOCK_QUALITY | Quality floor for block | 0.75 |
| MIN_ESC_QUALITY | Quality floor escalate | 0.5 |
| SLACK_WEBHOOK_URL | Slack alerts | (none) |
| ECLIPSE_OUTBOUND_URL | Eclipse action callback base | (none) |
| ECLIPSE_OUTBOUND_API_KEY | Eclipse outbound auth | (none) |
| AUDIT_LOG_PATH | File audit log | artifacts/audit/decisions.log |
| ESCALATION_TTL_SECONDS | Escalation retention | 86400 |
| MAX_RAW_PAYLOAD_BYTES | Raw truncation limit | 32768 |

## 11. Severity Rollups (Planned)
Aggregate per tenant over window:
- Mean severity (all events)
- 95th percentile severity
- Block rate, Escalation rate
- Policy block vs threshold block separation
Endpoints pending: `/metrics/severity/rollup`.

## 12. Slide Deck Pointers
Sections to highlight:
1. Problem & Signal Gap
2. Architecture (Ingestion → Policy → Pipeline → Decision → Actions)
3. Detection Factor Stack & Promotion Workflow
4. Multi-Tenancy & Integrity Controls
5. Governance & ROI (coverage trends, promotion candidates)
6. Action & Escalation Flow (this doc)
7. Roadmap & Extensibility

---
Document version: 0.1 MVB
