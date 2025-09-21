# Pilot Deployment Checklist

## 1. Preparation
- [ ] Confirm resource availability (2 vCPU / 4GB RAM minimum for pilot)
- [ ] Install Docker & Docker Compose
- [ ] Obtain API key(s) for analysts (scopes: nlp.query, factors.search, feedback.write)
- [ ] (Optional) Slack webhook URL for alerting

## 2. Get the Code
Option A: Git Tag
```bash
git clone <repo_url>
cd Threat_thy_sniffer
git checkout pilot-2025-09-21
```
Option B: Provided archive
- Unzip package into deployment directory

## 3. Integrity Verification (Optional)
```bash
python scripts/integrity_hash.py
# Compare hash with provider value
```

## 4. Environment Variables (.env or compose override)
| Key | Example | Required |
|-----|---------|----------|
| APP_DB_DSN | postgresql://postgres:postgres@db:5432/threatsifter | No (compose default) |
| API_KEYS_JSON | [{"key":"pilot123","scopes":["nlp.query","factors.search","feedback.write"]}] | Yes |
| ACCESS_LOG_SAMPLE_RATE | 0.5 | No |
| SLACK_WEBHOOK_URL | https://hooks.slack.com/services/... | Optional |
| JWT_SECRET | supersecret | Optional |

## 5. Start Stack
```bash
docker compose up -d --build
```
Validate containers:
```bash
docker compose ps
```

## 6. Run Migrations (if not automatically run)
```bash
docker compose exec app python scripts/run_migrations.py
```
Expected: migrations through 0006 applied.

## 7. Health & Readiness
```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

## 8. Seed Test Event
```bash
curl -X POST http://localhost:8080/api/v1/events -H 'Content-Type: application/json' \
  -d '{"id":"evt-pilot-1","details":{"src_ip":"10.0.0.12"}}'
```
Check decision:
```bash
curl http://localhost:8080/api/v1/decisions/recent
```

## 9. Similarity & NLP (Requires API Key)
```bash
curl -H 'x-api-key: pilot123' \
  'http://localhost:8080/api/v1/query/factors?similar=privilege%20escalation&limit=5'

curl -X POST http://localhost:8080/api/v1/query/nlp \
  -H 'x-api-key: pilot123' -H 'Content-Type: application/json' \
  -d '{"query":"show malicious events last 1h"}'
```

## 10. Feedback Signal
```bash
curl -X POST http://localhost:8080/api/v1/feedback/factor \
  -H 'x-api-key: pilot123' -H 'Content-Type: application/json' \
  -d '{"event_id":"evt-pilot-1","factor":"suspicious_dns","vote":1}'
```
Check weights:
```bash
curl http://localhost:8080/api/v1/weights/factors
```

## 11. Drift & Embedding Metrics
After ~30 minutes:
```bash
curl http://localhost:8080/api/v1/metrics/embedding
```

## 12. React Console (Optional)
```bash
cd frontend/react
npm install
npm run dev
# Open http://localhost:5173
```
Set API key in UI bar → explore stream, similarity, stats, weights, drift, feedback.

## 13. Prometheus & Grafana
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (login admin/admin)
Add dashboard from `grafana/dashboards` directory.

## 14. Access Log Sampling Adjustments
Increase sampling:
```bash
export ACCESS_LOG_SAMPLE_RATE=1.0
```
Restart app container.

## 15. Slack Alert Test (Optional)
Send or simulate an event likely flagged malicious; verify Slack message appears.

## 16. Verification Exit Criteria
| Criteria | Target | Verify |
|----------|--------|--------|
| Event ingestion latency | <100ms p95 | Prometheus histogram |
| Decision stream live | Events appear in <=2s | React console or SSE curl |
| Similarity search | Returns JSON results | Factor query endpoint |
| Feedback adjustment | Weight changes within 10 min | `/weights/factors` |
| Drift metric emission | JS divergence present (>0 possible) | `/metrics/embedding` |

## 17. Rollback
1. Stop stack: `docker compose down`
2. Checkout previous stable tag if needed
3. Optionally restore DB from snapshot/volume backup

## 18. Reporting Change Requests
Use shared tracker referencing tag `pilot-2025-09-21` with:
- Title / description
- Reproduction (sample event / query)
- Impact / priority

---
This checklist ensures repeatable, low-friction pilot activation and evaluation.
