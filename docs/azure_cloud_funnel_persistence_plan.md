## Azure Cloud Funnel Persistence Plan

### Scope
This plan covers the minimum durable state required for the Azure-only launch path.

### Records That Must Persist
- `analyst_gating`
  - State: `PENDING`, `APPROVED`, `REJECTED`, `DEFERRED`
  - Keys: `event_id`, `submitted_ts`, `updated_ts`, `tier`, `reason`, `actor`
  - Current implementation: JSON file via `ANALYST_GATE_STATE_PATH`
- `generated_playbooks`
  - State: playbook definition, generated summary, source incident/decision id
  - Keys: `playbook_id`, `created_ts`, `updated_ts`, `source_event_id`
  - Current implementation: JSON file via `GENERATED_PLAYBOOK_STORE_PATH`
- `decision_records`
  - State: `verdict`, `confidence`, `factors`, `hopgraph_context`, `dependency_status`, `evidence_summary`, `recommendation_actions`, `approval_state`
  - Keys: `event_id`, `tenant_id`, `timestamp`
  - Current implementation: existing decision persistence path plus in-memory cache hydration
- `incidents`
  - State: incident summary, evidence, recommendations, linked decisions, linked playbooks
  - Keys: `incident_id`, `tenant_id`, `created_ts`, `updated_ts`
  - Current implementation: incident aggregator persistence path
- `recommendation_actions`
  - State: `pending`, `completed`, `dismissed`
  - Keys: `id`, `incident_id`, `domain`, `action`, `priority`, `status`, `updated_ts`, `actor`
  - Current implementation: incident aggregator persistence and `POST /api/v1/incidents/{iid}/recommendations/act`

### Bare-Minimum Storage Model
- Single-tenant pilot: file-backed JSON is acceptable if writes are atomic.
- Live test target directory:
  - `data/state/analyst_gate.json`
  - `data/playbooks/generated_playbooks.json`
  - existing incident and decision persistence directories already used by the platform

### Required Guarantees
- App restart must not lose analyst approvals.
- App restart must not lose generated playbooks.
- Decision explain and recent-decision views must rehydrate recommendation actions and approval state.
- Incident recommendation actions must remain auditable after restart.

### Next Hardening Step
- Move file-backed state into the shared persistence layer already used by incidents/decisions.
- Add atomic write helper plus corruption-safe backup rotation.
- Add startup integrity check that reports missing or corrupt state in the LIVE console health panel.
