# Playbook DSL Specification

## Goals
- Deterministic, auditable, idempotent response workflows.
- Human-readable YAML with minimal primitives.

## YAML Schema (Draft)
```
playbooks:
  - id: RANSOMWARE_CONTAINMENT
    version: 1
    trigger:
      when_any_factors: [behavior:encryption_burst, attack:T1486]
      min_confidence: 0.85
    preconditions:
      not_factors: [requires_approval]
    actions:
      - type: isolate_host
        target: "{{entity.host}}"
        retries: 2
      - type: snapshot_memory
        target: "{{entity.host}}"
      - type: kill_process
        match: behavior:encryption_burst
      - type: notify_channel
        channel: security-ops
        message: "Ransomware containment executed for {{entity.host}}"
    rollback:
      - type: release_host
        target: "{{entity.host}}"
    approval:
      required: true
      roles: [sec_lead]
    timeout_s: 120
```

## Action Execution Model
- Sequential by default; MAY allow `parallel: true` group.
- Each action returns {status, latency_ms, output?} stored in execution log.
- Fail-fast policy: stop on first `critical` failure unless `continue_on_error: true` set.

## Variables & Templates
- Jinja2-like substitution over decision object & canonical entity.
- Whitelisted context only (avoid arbitrary code execution).

## Safety & Idempotency
| Action | Idempotent Strategy |
|--------|---------------------|
| isolate_host | Record isolation state; skip if already isolated |
| kill_process | Match by hash/pid; safe noop if absent |
| notify_channel | De-duplicate via (playbook_id,event_id,channel) key |

## Logging Schema
```
playbook_execution {
  id, playbook_id, version, event_id, start_ts, end_ts,
  actions: [ {name,type,status,latency_ms,error?} ],
  approval: {required, approved_by?, approved_ts?},
  outcome: success|partial|failed
}
```

## Metrics
| Metric | Purpose |
|--------|---------|
| `playbook_executions_total{result}` | Adoption & success ratio |
| `playbook_action_latency_ms{type}` | Performance tuning |
| `playbook_blocks_prevented_total` | Business value articulation |

## Approval Flow
- If `approval.required` and not pre-approved, emit decision with `pending_approval` disposition; store playbook intent; action engine watches for approval event.

## Testing Strategy
- Dry-run mode: evaluate triggers & render actions without execution.
- Unit test each action type with stub provider.
- Replay test: feed historical decisions, assert expected triggers & non-triggers.

## Extensibility
- Action registry mapping `type` → handler.
- Handlers MUST declare capability metadata (idempotent, destructive, needs_approval).

## Security Considerations
- Deny environment variable expansion in templates.
- Max total actions per playbook execution (e.g. 25) to prevent runaway automation.

## Open Questions
1. Do we support conditional branching inside playbooks? (Phase 2: simple `if factor_present`.)
2. Provide bulk approval UI endpoint? (Later after MVP.)
