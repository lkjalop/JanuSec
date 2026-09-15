# Test Matrix (Validation Phase)

| Scenario | Description | Input Pattern | Expected Factors | Correlation | Assertions | Metrics Captured |
|----------|-------------|---------------|------------------|-------------|------------|------------------|
| Benign Baseline | Typical processes & light network | Random proc names, no macro, common JA3 | None / minimal (<=1%) | None | Lane emission rate low | lane emission %, latency |
| Auth Brute Force | Rapid auth_fail events same user | 5-10 auth_fail in short window | auth_fail_burst_5m | None | Factor appears by Nth event | stage latency, factor presence |
| Office Macro PS | winword.exe -> powershell.exe + encoded | Parent=winword, child=powershell, -enc flag | office_macro_spawn_powershell, powershell_encoded_command | Possibly corr_office_ps_rare_ja3 if rare JA3 injected | Both lane factors present | lane latency, factors |
| Exfil Burst | Large outbound bytes cluster | Outbound flows: multi MB to 443 | exfil_volume_high | None | Factor appears on final large burst | packet stage latency |
| DNS Beacon/Tunnel | Periodic + long domain | 30s interval small flows + long DNS query | beacon_like_30s, dns_tunnel_pattern | None | Both appear if inputs crafted | factor presence |
| JA3 Novelty | New JA3 after baseline | Feed common set then new hash | ja3_novel, ja3_rare | None | Novel + rare emitted after warm_min | distinct JA3 gauge, baseline size |
| Correlation 1 | Macro PS + rare JA3 | Combine macro scenario + rare JA3 | lane factors + corr_office_ps_rare_ja3 | corr_office_ps_rare_ja3 | Correlation factor present | correlation hit counter |
| Correlation 2 | Encoded PS + signed→unsigned | Provide signed parent, unsigned child encoded | lane factors + corr_encoded_ps_signed_to_unsigned | corr_encoded_ps_signed_to_unsigned | Correlation factor present | correlation hit counter |
| Noise Injection | Malformed fields & random | Null parent, random fields | No crash; at most orphan_process factor | None | No exceptions; emission within bounds | pipeline errors=0 |
| Suppression Check | Introduce synthetic noisy factor | Add same fake factor across events | fake factor suppressed (manual) | None | Factor count declines over time | suppression gauge |
| Playbook A1 Lateral Pivot | Multi-stage lateral movement (auth -> proc -> net) | Auth success, suspicious lineage, outbound rare JA3 | lane_proc_parent_chain, lane_ja3_rare | (future) corr_lateral_pivot_possible | Coverage ratio >=1.0 for expected factors | first_detection_time_s, coverage_ratio |

## Harness Scenario Fields
| Field | Meaning |
|-------|---------|
| `t` | Simulated time offset (supports s,m,ms) |
| `event_type` | Semantic type (auth, proc, net, etc.) |
| `id` | Event identifier (auto-generated if omitted) |
| `labels.expected_factors` | Must-detect lane/correlation factors |
| `labels.optional_correlation` | Bonus correlation factors (do not fail if absent) |
| `sla.first_detection_within` | Maximum allowed simulated seconds to first detection |

## New Governance / Quality Endpoints Under Test
| Endpoint | Purpose | Test Assertion |
|----------|---------|----------------|
| `/api/v1/factors/promotion/status` | Factor observation + suppression readiness | Returns JSON array, sorted by observations |
| `/api/v1/factors/quality/precision_window` | Sliding TP/FP precision | Precision in [0,1]; counts.window_size matches config |

## FP Reduction Evaluation Artifacts
| File | Purpose |
|------|---------|
| `metrics/precision/benign_before.jsonl` | Pre-change benign factor emissions |
| `metrics/precision/benign_after.jsonl` | Post-change benign factor emissions |
| `metrics/precision/fp_history.json` | Density reduction summary |

Additional Captures:
- p50/p95 total latency per scenario
- Factor entropy before/after lanes for combined dataset
- Memory delta on large batch

Execution Order: Baseline → Core attack scenarios → Correlations → Noise → Suppression.
