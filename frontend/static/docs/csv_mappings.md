# CSV Analyzer Mapping Presets

Canonical fields used by the platform:
- `ts`, `host`, `user`, `process`, `pid`, `file_hash`, `event_id`, `ip`, `ip_dst`, `domain`

## Sysmon (JSON/CSV)
- Timestamp → `ts`
- ComputerName → `host`
- Image / ProcessName → `process`
- ProcessId → `pid`
- Hashes / sha256 → `file_hash`
- EventID → `event_id`

## Suricata EVE
- `timestamp` → `ts`
- `src_ip` → `ip`
- `dst_ip` → `ip_dst`
- `alert.signature` → `process` (or `domain` if DNS)
- `proto` → `other`

## Zeek (conn)
- `ts` → `ts`
- `id.orig_h` → `ip`
- `id.resp_h` → `ip_dst`
- `uid` → `event_id`
- `service` → `process`

## CrowdStrike
- `timestamp` → `ts`
- `device.hostname` or `host` → `host`
- `actor.name` → `user`
- `raw.ImageFileName` → `process`
- `raw.sha256` → `file_hash`
- `id` → `event_id`

Use these mappings in `csv_multi_analyzer.html` by selecting columns and assigning canonical field names. Presets can be added to the page to auto-fill mappings for common sources.