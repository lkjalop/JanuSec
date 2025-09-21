# Config Provenance & Digests

## Purpose
Guarantee reproducibility and audit integrity by embedding cryptographic fingerprints of all active configuration sets into each decision record and audit log.

## Config Sets (Initial)
| Name | File | Purpose |
|------|------|---------|
| risk_weights | `config/risk_weights.yaml` | Baseline weights & thresholds |
| taxonomy | `config/taxonomy.yaml` | Factor naming & versions |
| playbooks | `config/playbooks.yaml` | Response workflows |
| policies | `config/policies.yaml` | Governance / approval / suppression rules |
| compliance_map | `config/compliance_mapping.yaml` | Factor → framework mapping |

## Digest Algorithm
- SHA256 over canonical normalized YAML (strip comments, sort keys).
- Combined meta digest (join all `<name>:<sha256>` lines sorted, SHA256 again) stored as `config_meta`.

## Integration Points
- Load time: compute digests; store in in-memory registry with timestamp.
- Decision finalization: inject `config_digests` + `config_meta`.
- Audit log line: append same digests.

## Change Detection
If digest changes while service is live:
1. Add factor `config_changed` to next 10 decisions.
2. Emit metric `config_reload_events_total{name}`.
3. Persist a `config_change` audit entry with old/new digests & user (if available).

## APIs
| Endpoint | Function |
|----------|----------|
| `GET /config/digests` | Return current digests & load timestamps |
| `GET /config/diff?prev=<meta>` | Show which components changed vs provided meta |

## Hot Reload Strategy
- Debounce: minimum 10s between reload attempts.
- Validation hook: if new parsing fails, reject & retain old digests.

## Testing
- Unit: confirm stable digest on reformatting YAML (whitespace/comment variance).
- Integration: simulate change → verify factor injection & metrics.

## Open Questions
1. Should we sign digests with a service key for external attestation? (Phase governance.)
2. Provide rollback command endpoint? (Later, after policy DSL stable.)
