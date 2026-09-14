# Isolated pilot operations

This profile qualifies one local JanuSec instance with production authentication,
HTTPS, one ingest writer and durable state. It binds only to `127.0.0.1` and uses
synthetic data for verification. It is not a customer production certification.
The existing Kubernetes production values remain an unvalidated example; this
profile does not deploy that chart or its multiple replicas.

## Create private state outside the checkout

On Windows, create the private parent before generating any credentials:

```powershell
$pilotRoot = Join-Path $env:LOCALAPPDATA 'JanuSec-isolated-pilot'
New-Item -ItemType Directory -Path $pilotRoot -Force | Out-Null
$pilotUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $pilotRoot /inheritance:r /grant:r "${pilotUser}:(OI)(CI)F"
python scripts/pilot_state.py init --state "$pilotRoot/state" --backup-key "$pilotRoot/recovery.key" --tenant pilot-customer
python scripts/pilot_state.py serve --state "$pilotRoot/state" --port 8443
```

On Linux, use an operator-owned parent with mode `0700`. Run the same Python
commands with absolute paths. Keep state, recovery keys and archives outside Git.
Do not reset an existing directory to rerun initialization: initialization refuses
to overwrite it. Reuse `serve` or restore into a new directory instead.

Initialization generates fresh API/JWT/admin and integration encryption secrets.
It prints no credentials. The operator key is tenant-bound with full scopes; this
does not establish a complete customer role policy or SSO deployment. The generated
localhost certificate expires after seven days and is for local verification.
Customer access requires an approved TLS/access design and managed credential
rotation. Never expose the public development preview key as a customer credential.

The launcher ignores inherited application credentials and runtime paths, sets
all state paths beneath the selected directory, and runs legacy relative runtime
files there too. External models and automatic provider polling are disabled in
this qualification profile. Model completion quality and live collection remain
separate acceptance gates.

Production/staging startup rejects permissive test flags, conflicting environment
profiles, weak/unbound API keys and disabled API authentication. Production JWTs
require expiration and subject claims; test-secret and pytest bypasses are not
accepted. API paths no longer bypass production authentication merely because
their names contain `admin` or `integrations`. Existing inbound webhook clients
must have an explicitly reviewed authentication arrangement before deployment.

## Verify before and after restoration

Install optional verification dependencies in the environment used for these scripts:

```powershell
python -m pip install psutil playwright
python -m playwright install chromium
python scripts/verify_isolated_pilot.py --state "$pilotRoot/state" --output "$pilotRoot/baseline.json"
```

The API verifier checks the TLS certificate, missing/wrong/development keys,
expired JWTs, tenant-header overrides, foreign evidence, full Vesper input counts,
case truth assertions and a bounded four-client read sample. It is not a soak test.

Stop the service before running the controlled crash/restore verifier:

```powershell
python scripts/verify_pilot_recovery.py --state "$pilotRoot/state" --backup-key "$pilotRoot/recovery.key" --baseline "$pilotRoot/baseline.json" --output "$pilotRoot/recovery-results"
```

That verifier starts only its own loopback process, interrupts a synthetic upload
after derived rows have been written, makes a complete encrypted offline backup,
restores a new directory and starts recovery automatically. It checks physical
and distinct row counts, the previous completed case/history, a synthetic encrypted
canary and two checkpoint formats. The canary is not a real provider credential.
The original state is retained. Its interrupted test job can recover when that
instance is next started. The verifier stops the processes it owns before returning.

## Backup and restore commands

```powershell
python scripts/pilot_state.py backup --state "$pilotRoot/state" --backup-key "$pilotRoot/recovery.key" --archive "$pilotRoot/backup.enc"
python scripts/pilot_state.py restore --state "$pilotRoot/restored" --backup-key "$pilotRoot/recovery.key" --archive "$pilotRoot/backup.enc"
python scripts/pilot_state.py serve --state "$pilotRoot/restored" --port 8443
```

The OS lock rejects a backup while this launcher is running. Stop every writer
before an offline backup; the lock cannot coordinate an unrelated server launched
outside this profile. Backups cover the whole state directory, including the
ingest database, raw captures, content-addressed objects, ledger, histories,
checkpoints, encrypted secrets and the keys needed to decrypt them.

Archives use streaming AES-256-GCM with a separate random recovery key and a file
hash inventory. Restore authenticates the archive and checks every member before
creating the new destination. Existing destinations and symlink/junction escapes
are rejected. The original archive and state are not overwritten. Keep an encrypted
archive off the machine and escrow the recovery key separately; a successful local
restore does not prove off-host disaster recovery.

Recovered upload paths resolve against the current tenant-owned raw directory and
must match every registered file's original size/hash. Missing captures fail the
job rather than produce a partial result. Interrupted derived rows are rebuilt
without duplicating them; raw captures, completed jobs and historical receipts
are preserved. Legacy captures outside the tenant-owned layout need authoritative
migration or re-ingestion, not a guessed owner.

## Workload boundaries and remaining customer gates

The qualification profile admits up to two queued jobs, runs one ingest worker,
limits an upload to 64 MiB and twelve files, and applies a ten-minute job budget.
Application file copying reads bounded chunks. These limits do not replace a
reverse-proxy body limit, disk quota, process/container memory limit or admission
control at a customer boundary. Use measured input volumes and reject excess load.

Local Vesper runs have approached 2.7 GiB of process memory. A 1 GiB process limit
is not supported by those observations. Reserve at least 4 GiB for the qualification
experiment and measure headroom; this is a starting allocation, not a guaranteed
capacity envelope. Multi-hour load, retention/disk growth, off-host restoration,
certificate rotation, customer role policy and alert/runbook ownership remain open.

A live source still requires an approved account, read permissions and securely
configured access. Capture its provider receipts, reconcile counts, restart from
its checkpoint and verify the resulting evidence. A corrective action additionally
needs authenticated review and a later provider observation. No fixture, canary,
scanner PASS or model completion substitutes for those records.

## Retained GitHub key copy

The old exposed local key was rotated and the feature branch scrubbed. The retained
old commit still requires resolution through GitHub Support; the prepared request
is not a submitted ticket. GitHub states that removal assistance depends on whether
rotation can sufficiently mitigate the risk. Continue auditing deployment reuse
and do not promise removal before Support confirms it.
[GitHub sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
