# JanuSec Rebrand (Formerly "Threat Sifter")

Date: 2025-09-21
Tag Introduced: `pilot-2025-09-21-janusec`

## Summary
The platform has been rebranded from **Threat Sifter** to **JanuSec** to better reflect its role as an adaptive threat decision and analyst augmentation layer. The new identity emphasizes:
- Progressive, resilient pipeline design
- Analyst-centric feedback incorporation
- Semantic & natural language access patterns
- Operational pragmatism (bounded ML + graceful degradation)

## Scope of Changes
| Area | Old | New | Notes |
|------|-----|-----|-------|
| FastAPI Title | Threat Sifter API | JanuSec API | Updated in `src/api/server.py` |
| README | Threat Sifter branding | JanuSec branding | Full rewrite applied |
| Default DB Name | `threatsifter` | `janusec` | Legacy accepted via env overrides |
| JWT Audience | `threat-sifter` | `janusec` | Update token issuance flows |
| Log Paths | `/var/log/threat-sifter/*` | `/var/log/janusec/*` | Legacy files still readable if configured |
| Vault Path | `/etc/threat-sifter/vault` | `/etc/janusec/vault` | Override with `VAULT_PATH` if needed |
| User-Agent Strings | `threat_sifter_platform` | `janusec_platform` | Updated in security + playbook components |
| Grafana Dashboard | `Threat Sifter Overview` | `JanuSec Overview` | New file added; legacy retained |

## Backward Compatibility
- Environment variable driven configuration allows retaining legacy DB (`DB_NAME=threatsifter`) and audience (`JWT_AUDIENCE=threat-sifter`).
- Existing data schemas unchanged; only default names substituted.
- Legacy log directories not auto-migrated—operations may archive and symlink if needed.
- API surface unchanged (only cosmetic title / docs adjustments).

## Migration Recommendations
1. Rotate JWT issuance to use `aud=janusec` going forward.
2. If renaming the production database, perform:
   - Create new database `janusec`.
   - Apply migrations.
   - Copy data (logical dump or table-level copy) during maintenance window.
   - Update application env `DB_NAME` / `APP_DB_DSN`.
3. Update infrastructure automation (systemd units, Kubernetes manifests, logrotate, backup scripts) to reference new paths and image names (`janusec:latest`).
4. Deploy new Grafana dashboard (`grafana/dashboards/janusec_overview.json`) and deprecate the old one after validation.
5. Re-issue any static API keys documentation referencing old branding.

## Operational Checklist
- [ ] New README visible and renders correctly
- [ ] Health endpoints verified post-deploy
- [ ] Prometheus scraping unaffected (job name updated if desired)
- [ ] Drift and embedding metrics still present
- [ ] Feedback loop functioning (factor weights endpoint returns data)
- [ ] SSE stream unchanged

## Future Branding Tasks (Optional)
- Legal trademark & domain alignment
- Public website landing copy
- Hardened multi-tenant segmentation messaging
- Visual identity (logo, palette) integration into React console

---
Questions or issues: file an internal ticket tagged `branding`.

## Phase 2 Rebrand Adjustments (2025-09-22)

| Area | Change | Notes |
|------|--------|-------|
| Frontend Static | Titles & package name updated (`janusec-react`) | Legacy wording removed from all index pages |
| SOAR Engine | `threat_sifter_platform` → `janusec_platform` | Affects request attribution & Slack footer |
| Docker / Compose | Default DB & DSN changed to `janusec` | Legacy name usable via env override |
| Prometheus Job | `threat-sifter` → `janusec` | Legacy job may still appear until config redeployed |
| Config Defaults | `database: janusec`, `bucket: janusec-archive` | Inline comments note legacy names |
| Migration Script | DSN example updated to `janusec` | Backward compatible if env still points to old DB |
| Executive Collateral | Archived originals; stubs now branded | Originals stored under `archive/` folder |
| Risk Register | Heading updated with history note | Content otherwise unchanged |
| Release Notes & Checklist | Headings rebranded | Snapshot date preserved |

### Deprecation Timeline (Suggested)
- T+0 (now): Dual support (legacy DB name & JWT audience accepted)
- T+30 days: Remove legacy job name from Prometheus configs
- T+60 days: Drop legacy DB default fallback (require explicit override if still in use)

### Verification Steps Post-Deployment
1. `curl /health` returns status & uptime
2. `curl /metrics | grep janusec` (ensure custom labels unaffected)
3. Test legacy DB override: set `DB_NAME=threatsifter` and confirm migrations skipped (already applied)
4. Hit `/api/v1/query/nlp` with new JWT `aud=janusec`; ensure old `aud=threat-sifter` still accepted if required
5. Confirm Slack playbook notifications footer now displays `JanuSec Platform`

---
