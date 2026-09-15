# Pilot access, certificates and resource boundary

Use this profile for qualification of one local, read-only customer workflow.
It extends [isolated operations](ISOLATED_PILOT_OPERATIONS.md). It does not claim
live provider collection, public certificate issuance, off-host recovery or a
completed customer role/SSO deployment.

## Named access and rotation

Initialization creates a named bootstrap administrator that expires after seven
days. Use it only to establish access. Named credentials expire after 30 days by
default (maximum 90). Create private delivery files outside Git and the runtime
directory; apply a private parent ACL before using these commands on Windows.
Stop the service before changing credentials; the shared state lock enforces this.

```powershell
python scripts/pilot_credentials.py add --state "$pilotRoot/runtime" --subject analyst@example.test --role analyst --output "$pilotRoot/analyst.json"
python scripts/pilot_credentials.py add --state "$pilotRoot/runtime" --subject reviewer@example.test --role viewer --output "$pilotRoot/reviewer.json"
python scripts/pilot_credentials.py rotate --state "$pilotRoot/runtime" --subject reviewer@example.test --role viewer --output "$pilotRoot/reviewer-new.json"
python scripts/pilot_credentials.py revoke --state "$pilotRoot/runtime" --subject reviewer@example.test
```

Restart after the change. Rotation replaces the old key; revocation removes it.
Neither operation prints a key. Deliver the new file privately and retain an
administrator for recovery. Existing unnamed credentials are not automatically
converted; review/migrate them before treating an older profile as named access.

| Role | Pilot capabilities |
| --- | --- |
| Viewer | Read selected assessments/evidence and export reports. |
| Analyst | Viewer access plus assessment upload. |
| Administrator | Broad maintenance access; do not use as an ordinary reviewer. |

The outer pilot boundary defaults other API routes to administrator-only. It also
protects metrics/API documentation and requires header credentials; credentials
in query strings are not accepted by this boundary. Tenant ownership checks still
run in the underlying endpoints. Clients send both `x-api-key` and `x-tenant-id`.
The canonical LIVE console already does this. Existing non-pilot server entrypoints
do not automatically acquire this additional boundary.

## Install an issued certificate

```powershell
python scripts/pilot_tls.py --state "$pilotRoot/runtime" --cert C:/private/fullchain.pem --key C:/private/private-key.pem --hostname janusec.example.test
```

The stopped-service installer checks validity, exact SAN hostname and key matching,
then atomically activates a new version. Failed activation leaves the previous
version active. Prior versions remain in the private state and its backup. Wildcard
hostname matching is deliberately unsupported. Self-signed certificates require
`--local-test` and a localhost name/address. The local test flag is not a customer
trust mechanism. Validate the actual client trust chain and renewal process with
the selected CA or ingress owner; no public CA account or hostname is provisioned
by this command.

## Bounded container qualification

Initialize private runtime state with `scripts/pilot_state.py init` first. The
parent must be private and outside Git. Set `JANUSEC_PILOT_STATE_DIR` to its absolute
runtime directory, then use:

```powershell
docker compose -f deploy/pilot/compose.yaml build
docker compose -f deploy/pilot/compose.yaml up -d
```

Host access binds to `https://127.0.0.1:8445`. Inside the container the server must
listen on its container interface; host publication stays on loopback. The image
uses a pinned Python base, a non-root user and an explicit source allowlist.
Dependencies must install successfully and pass `pip check`. Runtime state,
credentials and user dump material are excluded from the build context.

The compose profile enforces 4 GiB memory, zero additional swap, two CPUs, 128 PIDs,
a read-only application filesystem, dropped capabilities, no new privileges,
a 512 MiB temporary filesystem and bounded container logs. Automatic restart is
disabled so an over-budget input cannot silently cause a restart loop.

Before multipart parsing, the application authenticates and limits active requests
to 16, simultaneous uploads to one, total request bodies to 68 MiB (including
multipart overhead), and body receipt to 60 seconds. Assessment file content still
has its separate 64 MiB/twelve-file limit. State admission reserves five body limits
of headroom, requires at least 1 GiB free afterward, and uses an 8 GiB admission
budget. **That admission budget is not a hard filesystem quota**: derived data and
other writers can grow afterward. Provision an actual bounded volume/disk quota
for customer deployment and monitor its usage; no hard volume quota was verified.

Stop the container with `docker compose -f deploy/pilot/compose.yaml stop` before
running host-side backup or credential commands. Do not assume Windows byte-range
locks and Linux file locks coordinate across a shared Docker bind mount. The lock
is an additional guard, not a substitute for stopping every writer.

Measured qualification results belong to the verification report and exact tested
image/commit. Passing a short read test does not define a production SLO or prove
multi-hour ingestion, retention, cloud deployment or multi-replica safety.

## Reproduce access and load checks

```powershell
python scripts/verify_pilot_access.py --state "$pilotRoot/runtime" --viewer "$pilotRoot/reviewer-new.json" --analyst "$pilotRoot/analyst.json" --revoked "$pilotRoot/reviewer.json" --baseline "$pilotRoot/baseline.json" --output "$pilotRoot/access.json"
python scripts/verify_pilot_load.py --state "$pilotRoot/runtime" --credential "$pilotRoot/reviewer-new.json" --baseline "$pilotRoot/baseline.json" --seconds 300 --clients 4 --output "$pilotRoot/load.json"
```

These scripts use the generated localhost certificate as their trust anchor.
Customer-issued certificate verification must use the customer's hostname and
trust configuration. Back up stopped state using the existing encrypted backup
commands, escrow the recovery key separately, and restore on an approved different
host before claiming disaster recovery. No off-host destination has been supplied.
