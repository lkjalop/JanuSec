# JanuSec

**Incident evidence, reviewable control assessments, and corrective-action verification.**

JanuSec is a development preview for investigating security telemetry and carrying
its evidence into a human-reviewed control assessment. The canonical LIVE Console
keeps the selected tenant, assessment, case and knowledge-time cutoff aligned with
its evidence and exports.

## Why the focus changed

The project began with alert triage and detection. Its next iteration focuses on
what a reviewer can establish from an incident: which evidence supports a claim,
what remains uncertain, which control expectations apply, and whether a reviewed
correction produced the expected result. Detection remains the foundation.

A detected technique can nominate a control concern. It does not, by itself,
establish a control failure, a legal obligation, or a compliance opinion.

## Current scope

| Capability | Status and limits |
|---|---|
| Upload, normalization and investigation | Tenant-scoped case workspace with original evidence references and explicit incomplete states. |
| Case history and exports | Captured projections have immutable receipts. UI and exports share case/time selection. States before capture remain evidence-only. |
| Control mapping | Exact factor registry and explicit mapping gaps. Pinned NIST catalog validation; other catalogs and semantic mapping review remain incomplete. |
| Connector recovery | Entra pagination, scoped checkpoints and durable delivery have regression coverage. A real customer end-to-end pilot remains outstanding. |
| Corrective action | Review and provider verification components exist. Successful fixture verification is not proof of a live customer correction. |
| Agent behavior | Offline baseline evaluation; live collection and production false-positive measurement remain future work. |
| OSCAL | Schema-validated, customer-scoped evidence export. No automatic audit opinion or authorization package. |
| Models | Deterministic conclusions with optional narration. Small local evaluations do not establish production model quality. |

## Local development

Use Python 3.11. Create a virtual environment and install the repository dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

For an isolated local demonstration, run the checked-in preview helper:

```powershell
.\.venv\Scripts\python.exe scripts/run_preview.py server
```

Open <http://127.0.0.1:8081/>. The helper binds to loopback, uses deterministic
narration, disables background collection and stores all runtime state in an
ignored local directory. Its public demonstration key is `devkey123`; it is not a
production credential. Do not expose this configuration on a public interface.
The primary console is `frontend/static/janusec-platform-complete-LIVE.html`.

Production deployment requires explicit tenant-bound authentication, external
secret management, dependency provisioning and a separately verified deployment.
Never reuse repository examples as credentials. See [Security](SECURITY.md).

## Verification

The release candidate is verified through `scripts/test_release.py` and
`scripts/browser_verify_release.py`. The browser journey covers a BOM-prefixed
negative upload, five investigation tabs, historical receipt/export agreement,
mobile layout and nine linked pages. Exact-commit CI results are recorded in
[PR #1](https://github.com/lkjalop/JanuSec/pull/1); a successful scanner execution
alone does not mean its findings are resolved.

- [Current verification summaries](docs/verification/2026-09-14-release/)
- [Release roadmap](docs/RELEASE_ROADMAP.md)
- [CI scope and manual integration suites](docs/CI_SCOPE.md)
- [File-store key rotation](docs/tenant_store_key_rotation.md)
- [Customer demo guide](docs/DEMO_GUIDE.md)
- [Full-corpus browser verification](docs/verification/2026-09-14-corpus-pilot/README.md)

The Meridian, Santos and Vesper replay stores **167,022 synthetic records** and
checks 31 explicit case assertions. Meridian has three labeled positive cases;
Vesper has one; Santos currently has suppression coverage and no positive recall
labels. Full uploads, case selection, evidence drilldown, recorded exports and
mobile layouts were exercised through Chromium. These are scoped regression
results, not a live customer pilot or a general detection-accuracy claim.

This pass also fixed missing selected-case milestones, evidence IDs changing
during enrichment, lost cumulative-transfer references, and malformed uploads
being presented as complete. Older affected assessments require re-ingestion;
their previously captured historical receipts are retained.

Run the release trust checks in isolated state:

```powershell
.\.venv\Scripts\python.exe scripts/run_preview.py pytest tests/test_release_trust_boundaries.py tests/test_fernet_key_rotation.py tests/test_case_history_and_ownership_migration.py tests/test_entra_delivery_recovery.py
```

No production throughput, uptime, recall, or false-positive reduction is claimed
from these tests. Test outcomes must identify their inputs and environment.

## License

The project retains its existing proprietary licensing designation. Public source
availability does not grant an open-source license. See [LICENSE](LICENSE).
Third-party components retain their respective licenses.

## Security configuration for integrations and optional models

Integration credentials require a durable `INTEGRATIONS_ENCRYPTION_KEY` from the
secret provider. Missing or invalid encryption fails the save; plaintext and
per-call ephemeral-key fallbacks are removed. Keep this key outside Git and
preserve it across restarts. Existing encrypted configurations require their
original key or credential re-entry. Webhooks require a configured signature
secret; missing verification cannot record a result.

Optional Hugging Face models use immutable revisions, disable remote Python code,
and require safetensors weights. Custom models need a full revision hash.
Legacy local pickle models are disabled unless their exact file and SHA256 are in
the operator-owned `JANUSEC_APPROVED_MODEL_SHA256` JSON mapping. Review the artifact
before approving it; a matching hash is not proof that arbitrary pickle code is safe.

Uploaded telemetry cannot select arbitrary local attachment files. Dedicated
offline operators may configure `JANUSEC_OFFLINE_ATTACHMENT_ROOT` and explicitly
set `JANUSEC_OFFLINE_ATTACHMENT_READS=1`; do not enable those settings on a shared
API deployment. Connector HTTP transports reject non-HTTP schemes and cross-host
redirects, disable environment proxies, and apply the public-address policy.
Internal dependency health probes use explicitly configured endpoints.

Optional syslog, NetFlow and IPFIX listeners default to loopback. Operators who
need remote collection must explicitly configure the intended listener interface
(`SYSLOG_LISTENER_HOST`, `IPFIX_LISTENER_HOST`, or the listener configuration),
network access and transport authentication for that deployment.
