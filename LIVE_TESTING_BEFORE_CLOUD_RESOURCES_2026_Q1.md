# Live Testing Before Real Cloud Resources

This is the minimum live validation order before pointing Janusec at real AWS or Azure tenants.

## Goal

Prove that the current connector, T1, checkpoint, dedupe, and replay paths are stable enough to justify real cloud credentials and real tenant data.

## Phase 0: Local Runtime Truth

Run against a local or staging Janusec instance first.

### Preconditions

- `tier2_endpoints.py` fails closed in live mode
- graph/demo fallbacks are disabled in live mode
- connector runtime status is exposed through:
  - `/api/v1/connectors/{tenant}/status`
  - `/api/v1/status/connectors`
- baseline suppression state is persisted via `BASELINE_SUPPRESSION_PATH`

### Commands

```powershell
python scripts/live_connector_validation.py --base http://127.0.0.1:8080 --tenant-id demo --scope aws --api-key devkey123
python scripts/live_connector_validation.py --base http://127.0.0.1:8080 --tenant-id demo --scope azure --api-key devkey123
```

Expected outcome:

- control-plane routes answer cleanly
- connector config reads succeed
- status and checkpoint fields are present
- runtime state includes latency, duplicate count, and circuit status

## Phase 1: Replay / Soak Before Real Tenants

Replay sanitized or synthetic corpora before any live tenant auth is configured.

### VPC / Zeek-style corpus

```powershell
python scripts/cloud_replay_soak.py --base http://127.0.0.1:8080 --tenant-id demo --mode vpcflow --input path\to\vpc_or_zeek.jsonl --batch-size 250 --iterations 5 --out reports\vpc_replay_soak.json
```

### Azure Event Hub style corpus

```powershell
python scripts/cloud_replay_soak.py --base http://127.0.0.1:8080 --tenant-id demo --mode eventhub --input path\to\eventhub_records.jsonl --batch-size 250 --iterations 5 --out reports\eventhub_replay_soak.json
```

### Endpoint / Sysmon corpus

```powershell
python scripts/cloud_replay_soak.py --base http://127.0.0.1:8080 --tenant-id demo --mode sysmon --input path\to\sysmon_events.jsonl --batch-size 250 --iterations 5 --out reports\sysmon_replay_soak.json
```

Expected outcome:

- no duplicate storm
- no checkpoint loss
- sustained ingest remains stable
- connector and ingest status stays `healthy` or clearly reports a real degraded state

## Phase 2: False-Positive Validation

Run replay packs that include:

- benign IAM admin changes
- benign Entra sign-in bursts
- benign east-west network chatter
- suspicious IAM abuse
- suspicious egress
- mixed cloud + endpoint overlap

Minimum acceptance:

- repetitive benign identity and network patterns get confidence reduction from baseline suppression state
- obvious malicious patterns still pass through T1 at meaningful confidence
- high-noise events do not automatically trigger T2

## Phase 3: Real Tenant Validation

Only after phases 0-2 pass.

### AWS

Validate:

- CloudTrail
- GuardDuty
- SecurityHub
- VPC Flow Logs

Checks:

- auth success / auth failure
- pagination
- checkpoint resume
- worker restart during poll
- duplicate suppression
- malformed event handling

### Azure

Validate:

- Event Hub
- Entra sign-in
- Entra audit
- Defender for Cloud

Checks:

- tenant config validity
- token/auth failure handling
- checkpoint resume
- worker restart during poll
- duplicate suppression

## Exit Criteria Before More Domains

Do not add eBPF, kernel, PCAP, binary, or more clouds until all of the following are true:

- T1 false positives are sane on IAM and network
- connector runtime truth is visible to operators
- replay/soak tests pass
- restart recovery is verified
- real AWS/Azure tenant validation is complete
- remaining placeholder deep/demo paths are either removed or production-disabled
