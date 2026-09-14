# JanusSec release acceptance — 2026-08-21

## Scope

This receipt describes what was executed locally. It is not a production certification.
It distinguishes repository fixtures, local PostgreSQL infrastructure, and unavailable
external cloud services.

## Breach reconstruction gate

Command:

```powershell
python scripts/ground_truth_gate.py
```

| Corpus | Must detect | Must separate | Must suppress | Role attribution | False network breaches |
| --- | ---: | ---: | ---: | ---: | ---: |
| Vesper | 1.0 | N/A | 1.0 | 1.0 | 0 |
| Meridian | 1.0 | 1.0 | 1.0 | 1.0 | 0 |
| Santos | N/A | N/A | 1.0 | N/A | 0 |

Santos changed from seven confirmed, unattributed network/endpoint cases to zero.
The production rule contains no Santos identities, addresses, filenames, or campaign
labels. It requires an attributable principal/host, independent source corroboration,
an evidence-backed observed-causal edge, or the bounded anonymous public-cloud
collection exception before a strong detector phase can establish a breach case.

Authorized activity with `BENIGN_EXPECTED` is now a background partition. It remains
available for audit and retrieval but cannot count as an active investigation or a
must-suppress failure.

## Generalization controls

- Fixture-only `_cluster`, `_anomaly`, `_severity`, `_note`, `_risk`, and embedded
  cluster notes are stripped by the benchmark loader.
- Random-identity mutation tests prove that unattributed one-sensor signatures remain
  contextual without relying on known names.
- Counter-tests preserve named-host cases, evidence-backed causal paths, and anonymous
  public-cloud collection so suppression cannot become an overbroad allow rule.
- Vesper, Meridian, and Santos are always rerun together. A corpus-specific gain is not
  accepted if another corpus regresses.
- The release gate measures false suspected cases and roles, not only false confirmed
  cases or cluster counts.

These controls reduce demonstrable overfitting; they cannot establish statistical
generalization from only three known corpora. A blinded fourth corpus and genuine
provider exports remain required.

## PostgreSQL durability acceptance

An isolated PostgreSQL 15 instance was exercised on `127.0.0.1:55432`.

- Alembic upgraded from an empty database to `0012_grc_evidence_bridge (head)`.
- Inserts succeeded in `evidence_ledger`, `evidence_graph_nodes`,
  `infrastructure_truth_snapshots`, and `grc_workflow_events`.
- PostgreSQL triggers rejected UPDATE operations on all four tables.
- `pg_dump -Fc` completed and `pg_restore` restored into a separate database.
- Restored row counts were `1|1|1|1`, and the restored Alembic version matched head.
- A DELETE against the restored evidence ledger was rejected by the restored trigger.

This proves migration, append-only enforcement, backup, and restore locally. It does
not prove managed-service backup policy, regional recovery, RPO/RTO, monitoring, or
production privileges.

## Browser acceptance

- Desktop drag/drop displayed the selected file and enabled assessment start.
- Mobile layout had no horizontal overflow and retained an accessible upload control.
- No browser console errors occurred in the acceptance click-through.
- Evidence Pack receipts and role-aware quality metrics are visible in the case workspace.

Screenshots are stored in the user-owned local acceptance folder:

- `dump/screenshots/new - pivot/acceptance-case-workspace-desktop.png`
- `dump/screenshots/new - pivot/acceptance-case-workspace-mobile.png`

## External dependencies and blockers

- AWS CLI, AWS region, Object-Lock bucket, and KMS key were not configured.
- Azure CLI was installed but not authenticated; no Key Vault key was configured.
- No authorized production CMDB, IAM, or topology endpoints were configured.
- AWS/Azure realish export packs exist. Genuine sanitized GCP, Alibaba, Sysmon,
  Tetragon, Suricata, firewall, Nutanix, VMware, and HPE exports were not present.
- Business impact must remain unavailable until a fresh, valid, signed asset-to-service
  mapping receipt is attached.
- Ollama was healthy and `qwen3:14b` plus `qwen3.8:27b` were installed. Context-length
  comparisons were intentionally not promoted to release evidence because genuine
  provider and infrastructure-truth gates remain incomplete.

## Deferred experiments

HippoRAG/PPR, Graphiti analyst-session memory, temporal GNN scoring, KV-cache
compression, and SNN anomaly detection remain ablations. They cannot modify evidence,
case boundaries, verdicts, containment authorization, or control findings.
