# Reporting & DecisionGate Quickstart

This README describes how to use the DecisionGate endpoints and the editable NLP query patterns.

Prerequisites
- Activate your venv and install dependencies (project uses existing requirements).

Run tests (example)

```powershell
& .\.venv\Scripts\Activate.ps1
python -m pytest -q tests/test_decision_endpoints.py
```

DecisionGate API examples

- Create a decision

```bash
curl -s -X POST http://localhost:8080/api/v1/decision/create \
  -H 'Content-Type: application/json' \
  -H 'x-actor: alice' \
  -d '{"decision_type":"block_ip","persona":"soc_analyst","urgency":"normal","question":"Block IP?","context":"..."}'
```

- Approve

```bash
curl -s -X POST http://localhost:8080/api/v1/decision/approve \
  -H 'Content-Type: application/json' \
  -H 'x-actor: approver' \
  -d '{"gate_id":"dg-xxxx","approved_option":"block"}'
```

- Execute

```bash
curl -s -X POST http://localhost:8080/api/v1/decision/execute \
  -H 'Content-Type: application/json' \
  -H 'x-actor: operator' \
  -d '{"gate_id":"dg-xxxx","action_payload":{"ip":"1.2.3.4"}}'
```

- Rollback

```bash
curl -s -X POST http://localhost:8080/api/v1/decision/rollback \
  -H 'Content-Type: application/json' \
  -H 'x-actor: approver' \
  -d '{"gate_id":"dg-xxxx","reason":"false positive"}'
```

Notes
- The implementation included is intentionally minimal and intended for local testing and demos.
- `SESSION_PERSIST_DIR` controls where audit files are persisted for tests and dev. In production, replace with a secure, immutable audit store.
- RBAC is stubbed; integrate your identity provider (OIDC, SAML) and map roles to `approver`/`operator`.
