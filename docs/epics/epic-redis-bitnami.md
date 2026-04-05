Title: Replace demo Redis HA with Bitnami (prod-grade)

Context
- Current `charts/janusec/templates/redis-ha.yaml` is a minimal, demo-only Sentinel setup.
- Production needs persistence, HA, password auth, proper Sentinel, backups, and upgrade paths.

Scope
- Add Bitnami Redis chart as a dependency or subchart with values pass-through (auth, persistence, metrics, resources).
- Wire `REDIS_URL` from the service/port exposed by the subchart; preserve autoWire guards.
- Document migration steps from demo to Bitnami in `docs/infrastructure_deployment_guide.md`.

Acceptance Criteria
- Helm install with `redis.enabled=true` deploys a working, password-protected Redis master/replica with persistence.
- App connects via `REDIS_URL` when autoWire enabled; override continues to work.
- CI lint and basic smoke install pass in a kind/minikube workflow.

Risks / Notes
- Keep demo YAML for local dev (disabled by default). Use clear values flags to select Bitnami vs demo.

