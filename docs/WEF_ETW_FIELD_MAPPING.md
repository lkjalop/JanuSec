# WEF/ETW Field Mapping (Deployment Guide)

This guide documents the canonical field mappings used by the unified ingest
endpoint for Windows Event Forwarding (WEF) and ETW sources. Use it when
configuring forwarders or normalizing payloads upstream.

## Ingest endpoints

- WEF: `POST /api/v1/ingest/wef`
- ETW: `POST /api/v1/ingest/etw`

Payloads should be JSON with an `events` array:

```json
{"events":[{"EventID":"4688","Computer":"host-01","SubjectUserName":"CORP\\alice"}]}
```

## Canonical fields produced

The ingest layer maps Windows fields into the canonical envelope used by
HopGraph and tiered summaries:

| Canonical field | WEF/ETW source fields (first match wins) |
| --- | --- |
| `host` | `Computer`, `ComputerName`, `WorkstationName`, `Hostname`, `host` |
| `user` | `SubjectUserName`, `TargetUserName`, `User`, `AccountName`, `username` |
| `process` | `NewProcessName`, `ProcessName`, `Image`, `Process`, `CommandLine` |
| `ip` | `IpAddress`, `SourceIp`, `SourceAddress`, `ClientAddress`, `src_ip` |
| `ip_dst` | `DestinationIp`, `DestinationAddress`, `DestAddress`, `dest_ip` |
| `domain` | `TargetDomainName`, `SubjectDomainName`, `domain` |
| `file_hash` | `sha256`, `SHA256`, `Hashes`, `hash` |
| `event_code` | `EventID`, `EventId` |

`Hashes` fields are parsed to extract `SHA256=` values when present.

## Recommended provider/channel coverage

Reference `config/windows_etw_wef_providers.json` for the canonical provider
GUIDs, channels, and event IDs. Deployments should start with:

- WEF: Security + Sysmon/Operational channels (process, auth, registry, file)
- ETW: Kernel-Process + Kernel-Network + Security-Auditing providers

## Validation checklist

- Confirm events land in `/api/v1/ingest/events/query` when filtering by user/host.
- Verify `event_code` is populated for 4688/4624/4625 flows.
- Ensure hashes normalize to lowercase SHA-256 strings.
