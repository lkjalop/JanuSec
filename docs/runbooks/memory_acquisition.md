Memory Acquisition Runbook
=========================

Purpose
-------
This runbook describes safe, auditable memory acquisition for Windows and Linux hosts and how to ingest artifacts into the central forensic store.

Pre-requisites
--------------
- Approvals from the incident owner (who/when).
- Network access to the `forensics` S3 bucket and KMS key for encryption.
- Local tooling: `winpmem` or `avml`/`lime` for Linux, `sha256sum` or Python for hashing.
- The `scripts/collect_memory.py` helper (in repository) available on the analyst machine.

Acquisition (Windows)
----------------------
1. Gain operator access to the target host via RDP or agent.
2. Download `winpmem` to a local temp path.
3. Run as administrator:

```
winpmem.exe -o C:\Temp\memory.raw
```

4. Compute SHA256:

```
certutil -hashfile C:\Temp\memory.raw SHA256
```

5. Upload via the helper (see below) to the `forensics` bucket with KMS encryption and record chain-of-custody:

```
python scripts/collect_memory.py --file C:\Temp\memory.raw --collector 'winpmem' --s3-bucket my-forensics-bucket --s3-prefix artifacts/memory/ --kms-key-id arn:aws:kms:... --object-lock-retain-days 365
```

Acquisition (Linux)
--------------------
1. Copy `avml` to the host and run as root:

```
sudo avml /tmp/memory.lime
```

2. Compute SHA256:

```
sha256sum /tmp/memory.lime
```

3. Upload via helper:

```
python scripts/collect_memory.py --file /tmp/memory.lime --collector 'avml' --s3-bucket my-forensics-bucket --s3-prefix artifacts/memory/ --kms-key-id arn:aws:kms:... --object-lock-retain-days 365
```

Chain-of-Custody
-----------------
- The `scripts/collect_memory.py` will compute hashes and call the ForensicStore to record collector identity, timestamp, checksum, and S3 URL.
- For high-assurance cases enable S3 Object Lock in Governance/Compliance mode and set a retention period.

Analysis notes
--------------
- After ingestion, use `volatility3`/`rekall`/custom extractors to derive indicators.
- Persist extraction output (process list, network sockets, handles, loaded modules) alongside the raw image in the `forensics` bucket.

Drill guidance
--------------
- Periodically run a replay drill: collect an artifact from a staging host, upload, run extraction pipeline, and confirm analysts can reproduce findings using the runbook.
