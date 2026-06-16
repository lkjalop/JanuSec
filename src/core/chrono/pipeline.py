"""ChronoGraph pipeline stages, extracted from assessment_worker so BOTH the async
worker and the ground-truth gate run the SAME long-horizon detection code (not a
copy that drifts).

- accumulate(rows): Stage 5i — per-user/host time-bucketed metrics into ChronoGraph
  (events, bytes_out, per-destination bytes, recon sequence, behavioral counts).
- elevate_clusters(clusters, accum): Stage 5j — z-score each breach cluster's
  principals against their own history and append long-horizon factors (recon
  sequence, cumulative + per-destination exfil incl. lookalike, behavioral spikes,
  EDR telemetry gap).

This is the layer that closes VESPER's blindspots (cumulative <350MB exfil that's
benign per-row; off-hours recon over days) — which only emerge across the batch,
not in any single clustered row. Pure functions: no async, no DB, no globals beyond
the injected ChronoGraph store.
"""
from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass, field

_EXFIL_DST_BYTES_FLOOR = float(os.getenv("JANUSEC_EXFIL_DST_BYTES_FLOOR", "2000000000"))
_BREACH_VERDICTS = {"VALIDATED_BREACH", "LIKELY_BREACH", "LIKELY_COMPROMISE", "INCIDENT"}

_RECON_KEYWORDS = (
    "net group", "net user", "dsquery", "setspn", "get-aduser",
    "get-adcomputer", "get-adgroup", "nltest", "invoke-sharphound",
    "sharphound", "get-domainuser", "get-domaincomputer", "get-domaingroupmember",
)

_BEHAV_METRICS = {
    "endpoint:lolbin_count": "behavior:lolbin_spike",
    "endpoint:encoded_ps_count": "behavior:encoded_powershell_spike",
    "endpoint:wmi_exec_count": "behavior:wmi_exec_spike",
    "network:unique_dest_count": "behavior:network_fanout_spike",
    "cloud:foreign_asn_count": "behavior:foreign_asn_spike",
    "iam:pre_auth_fail_count": "behavior:auth_failure_spike",
    "email:external_send_count": "behavior:external_send_spike",
    "iam:mfa_prompt_count": "behavior:mfa_fatigue_spike",
}


@dataclass
class ChronoAccum:
    ref_ts: float = 0.0
    first_seen: dict[str, set] = field(default_factory=dict)
    offhours_recon_counts: dict[str, int] = field(default_factory=dict)
    recon_days: dict[str, set] = field(default_factory=dict)


def _chrono():
    from src.core.chrono.sketch_store import CHRONO
    return CHRONO


def accumulate(rows, chrono=None, *, tz_offset_h: int | None = None) -> ChronoAccum:
    """Stage 5i — accumulate per-entity time-bucketed metrics into ChronoGraph."""
    chrono = chrono if chrono is not None else _chrono()
    if tz_offset_h is None:
        tz_offset_h = int(os.getenv("JANUSEC_ORG_TZ_OFFSET_H", "0"))
    acc = ChronoAccum()

    def _is_recon_cmd(row: dict) -> bool:
        _seid = str(row.get("sysmon_event_id") or "").strip()
        _eid = str(row.get("event_id") or row.get("windows_event_id") or "").strip()
        if _seid != "1" and _eid not in ("1", "4688"):
            return False
        _cmd = str(row.get("command_line") or row.get("cmdline") or "").lower()
        return any(k in _cmd for k in _RECON_KEYWORDS)

    def _is_off_hours(ts_epoch: float) -> bool:
        try:
            _utc_h = _dt.datetime.utcfromtimestamp(ts_epoch).hour
            _local_h = (_utc_h + tz_offset_h) % 24
            return _local_h < 8 or _local_h >= 18
        except Exception:
            return False

    def _local_day(ts_epoch: float) -> str:
        try:
            return _dt.datetime.utcfromtimestamp(ts_epoch + (tz_offset_h * 3600)).strftime("%Y-%m-%d")
        except Exception:
            return ""

    host_users: dict[str, set[str]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        u = str(r.get("user_canonical") or r.get("user") or "").strip().lower()
        h = str(r.get("host") or r.get("hostname") or r.get("src_host") or r.get("source_host") or "").strip().lower()
        if u and h:
            host_users.setdefault(h, set()).add(u)

    for r in rows:
        if not isinstance(r, dict):
            continue
        ts = float(r.get("_ts_epoch") or 0)
        if not ts:
            continue
        if ts > acc.ref_ts:
            acc.ref_ts = ts
        u = str(r.get("user_canonical") or r.get("user") or "").strip().lower()
        h = str(r.get("host") or r.get("hostname") or r.get("src_host") or r.get("source_host") or "").strip().lower()
        if not u and h:
            mapped = host_users.get(h) or set()
            if len(mapped) == 1:
                u = next(iter(mapped))
                r["_chrono_inferred_user"] = u
        b = float(r.get("bytes_out") or r.get("bytes_sent") or r.get("orig_bytes") or r.get("bytes") or 0)
        dst = str(r.get("dst_host") or r.get("resp_h") or r.get("domain") or r.get("tls_sni") or "").strip().lower()
        st = str(r.get("_source_type") or r.get("source_type") or "").lower()

        if u:
            chrono.increment("user", u, "events", 1.0, ts=ts)
            if b > 0:
                chrono.increment("user", u, "bytes_out", b, ts=ts)
                if dst and not dst.startswith(("10.", "172.", "192.168.", "127.")):
                    chrono.increment("user", u, "cloud_bytes_out", b, ts=ts)
                    chrono.increment("user", u, f"bytes_out_dst:{dst}", b, ts=ts)
            if _is_recon_cmd(r):
                chrono.increment("user", u, "recon_events", 1.0, ts=ts)
                day = _local_day(ts)
                if day:
                    acc.recon_days.setdefault(u, set()).add(day)
                if _is_off_hours(ts):
                    chrono.increment("user", u, "off_hours_recon_events", 1.0, ts=ts)
                    acc.offhours_recon_counts[u] = acc.offhours_recon_counts.get(u, 0) + 1
            elif _is_off_hours(ts):
                chrono.increment("user", u, "off_hours_events", 1.0, ts=ts)
            if h:
                prior = chrono.window_sum("user", u, f"host_access:{h}", 0, ts - 1)
                if prior == 0.0:
                    acc.first_seen.setdefault(u, set()).add(h)
                chrono.increment("user", u, f"host_access:{h}", 1.0, ts=ts)

            if st in ("windows_security", "identity_kerberos", "iam"):
                enc = str(r.get("ticket_encryption") or "").strip()
                weid = str(r.get("windows_event_id") or r.get("event_id") or "").strip()
                if enc in ("0x17", "0x18") and weid == "4769":
                    chrono.increment("user", u, "iam:rc4_count", 1.0, ts=ts)
                if weid in ("4768", "4769"):
                    chrono.increment("user", u, "iam:ticket_volume", 1.0, ts=ts)
                if weid in ("4771", "4625"):
                    chrono.increment("user", u, "iam:pre_auth_fail_count", 1.0, ts=ts)
            if st in ("cloud_identity", "azure_ad", "entra", "cloud"):
                asn = str(r.get("asn") or r.get("src_asn") or "").strip()
                sip = str(r.get("src_ip") or r.get("source_ip") or "").strip()
                if asn and sip and not sip.startswith(("10.", "172.", "192.168.", "127.")):
                    chrono.increment("user", u, "cloud:foreign_asn_count", 1.0, ts=ts)
                et = str(r.get("event_type") or r.get("operation") or "").lower()
                if "ca_bypass" in et or "conditional_access" in et and "bypass" in et:
                    chrono.increment("user", u, "cloud:ca_bypass_count", 1.0, ts=ts)
                if "consent" in et or "grant" in et:
                    chrono.increment("user", u, "cloud:consent_grant_count", 1.0, ts=ts)
                mfa = str(r.get("mfa_result") or r.get("auth_method") or "").lower()
                if "mfa" in et or "mfa" in mfa or "strongauth" in et:
                    chrono.increment("user", u, "iam:mfa_prompt_count", 1.0, ts=ts)
            if st in ("sysmon", "endpoint_lolbins", "endpoint", "edr"):
                cmd = str(r.get("command_line") or r.get("cmdline") or "").lower()
                par = str(r.get("parent_process") or "").lower()
                if any(lb in cmd for lb in ("certutil", "bitsadmin", "mshta", "regsvr32",
                                            "rundll32", "wscript", "cscript", "msiexec", "wmic", "forfiles")):
                    chrono.increment("user", u, "endpoint:lolbin_count", 1.0, ts=ts)
                if "-enc" in cmd or "-encodedcommand" in cmd:
                    chrono.increment("user", u, "endpoint:encoded_ps_count", 1.0, ts=ts)
                if "wmiprvse.exe" in par or "wmic" in cmd:
                    chrono.increment("user", u, "endpoint:wmi_exec_count", 1.0, ts=ts)
            if st in ("network", "zeek", "vpc_flow", "flow"):
                if b > 0:
                    chrono.increment("user", u, "network:unique_dest_count", 1.0, ts=ts)
            if st in ("email", "mimecast", "proofpoint", "o365_mail"):
                ab = float(r.get("attachment_size") or r.get("attachment_bytes") or 0)
                if b > 0:
                    chrono.increment("user", u, "email:external_send_count", 1.0, ts=ts)
                if ab > 0:
                    chrono.increment("user", u, "email:attachment_bytes", ab, ts=ts)

        if h and ts:
            chrono.increment("host", h, "events", 1.0, ts=ts)
    return acc


def elevate_clusters(clusters, accum: ChronoAccum, chrono=None, *,
                     exfil_dst_floor: float = _EXFIL_DST_BYTES_FLOOR,
                     recon_seq_min: int | None = None, recon_seq_days: int | None = None) -> None:
    """Stage 5j — z-score breach clusters' principals; append long-horizon factors."""
    chrono = chrono if chrono is not None else _chrono()
    if recon_seq_min is None:
        recon_seq_min = int(os.getenv("JANUSEC_OFFHOURS_RECON_SEQUENCE_MIN", "4"))
    if recon_seq_days is None:
        recon_seq_days = int(os.getenv("JANUSEC_RECON_SEQUENCE_DAYS_MIN", "4"))
    ref = accum.ref_ts or None

    for cl in clusters:
        verd = str(cl.get("final_verdict") or cl.get("verdict") or "").upper()
        if verd not in _BREACH_VERDICTS:
            continue
        princ = list(cl.get("affected_principals") or cl.get("shared_accounts") or cl.get("shared_users") or [])
        new_f: list[str] = []
        for u in princ[:4]:
            if not u:
                continue
            u = str(u).strip().lower()
            rz = chrono.z_score("user", u, "off_hours_recon_events", window_seconds=86400 * 7, reference_ts=ref)
            if (rz.get("anomaly") or abs(float(rz.get("z") or 0)) >= 2.5
                    or accum.offhours_recon_counts.get(u, 0) >= recon_seq_min
                    or len(accum.recon_days.get(u) or set()) >= recon_seq_days):
                new_f.append("recon:sustained_offhours_sequence")
            bz = chrono.z_score("user", u, "bytes_out", window_seconds=86400 * 7, reference_ts=ref)
            if bz.get("anomaly") or abs(float(bz.get("z") or 0)) >= 2.5:
                new_f.append("exfil:cumulative_bytes_anomaly")
            cbz = chrono.z_score("user", u, "cloud_bytes_out", window_seconds=86400 * 7, reference_ts=ref)
            if (cbz.get("anomaly") or abs(float(cbz.get("z") or 0)) >= 2.5
                    and "exfil:cumulative_bytes_anomaly" not in new_f):
                new_f.append("exfil:cumulative_cloud_bytes_anomaly")
            try:
                emets = chrono.entity_metrics("user", u, window_seconds=86400 * 30, reference_ts=ref)
                dst_sums = {k.split("bytes_out_dst:", 1)[1]: float(v.get("window_sum") or 0)
                            for k, v in emets.items() if k.startswith("bytes_out_dst:")}
                if dst_sums:
                    top_dst, top_bytes = max(dst_sums.items(), key=lambda kv: kv[1])
                    mimics = None
                    try:
                        from src.core.operator_context import load_operator_context as _loc
                        mimics = _loc().lookalike_of_sanctioned(top_dst)
                    except Exception:
                        mimics = None
                    if top_bytes >= exfil_dst_floor or mimics:
                        if "exfil:cumulative_bytes_anomaly" not in new_f:
                            new_f.append("exfil:cumulative_bytes_anomaly")
                        rec = {"destination": top_dst, "cumulative_bytes": int(top_bytes)}
                        if mimics:
                            new_f.append("exfil:lookalike_destination")
                            rec["lookalike_of"] = mimics
                        cl.setdefault("_exfil_destinations", {})[u] = rec
            except Exception:
                pass
            if accum.first_seen.get(u):
                new_f.append("endpoint:first_seen_host_access")
            for bm, bf in _BEHAV_METRICS.items():
                try:
                    bz2 = chrono.z_score("user", u, bm, window_seconds=86400 * 7, reference_ts=ref)
                    if (bz2.get("anomaly") or abs(float(bz2.get("z") or 0)) >= 2.5) and bf not in new_f:
                        new_f.append(bf)
                except Exception:
                    continue
        for h in list(cl.get("shared_hosts") or [])[:4]:
            h = str(h).strip().lower()
            if not h:
                continue
            try:
                gz = chrono.z_score("host", h, "events", window_seconds=86400 * 7,
                                    reference_ts=ref, allow_population=False)
                if gz.get("source") == "temporal" and float(gz.get("z") or 0) <= -2.5:
                    if "endpoint:edr_telemetry_gap" not in new_f:
                        new_f.append("endpoint:edr_telemetry_gap")
            except Exception:
                continue
        if new_f:
            existing = cl.setdefault("factor_tags", [])
            for ff in set(new_f):
                if ff not in existing:
                    existing.append(ff)
            cl["_chrono_factors"] = list(set(new_f))
            cl["_chrono_first_seen"] = {
                _u: sorted(_hosts) for _u, _hosts in accum.first_seen.items()
                if _u in {str(p).strip().lower() for p in princ if p}
            }
