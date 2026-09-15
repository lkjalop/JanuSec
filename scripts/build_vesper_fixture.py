"""Build a multi-source VESPER fixture for reliable narrator quality testing.

Samples attack + benign rows from all 4 VESPER source files, assigns
sequential row_indices, builds 2 clusters (attack + benign), and writes
a proper fixture JSON to tests/fixtures/assessments/quality/vesper_multisource.json.

Usage:
    python scripts/build_vesper_fixture.py

The fixture intentionally includes rich attack rows:
  - Kerberos 4769+RC4 (Kerberoasting, T1558.003)
  - Kerberos 4769+no-preauth (AS-REP Roasting, T1558.004)
  - Sysmon EventID 1: wmic.exe /node:SVR-DB-01 process call create (T1047)
  - Sysmon EventID 1: powershell.exe -nop -w hidden -enc (T1059.001)
  - Network: high-byte exfil flows to external IPs
  - Cloud: OAuth consent grant (T1550.001)

These rows should produce evidence diagnostics showing attack_signal_rows >= 5
and source_diversity = 1.0 (all 4 sources), giving quality >= 0.75.
"""
from __future__ import annotations
import csv
import hashlib
import json
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).parent.parent
VESPER_DIR = ROOT / "dump" / "test files" / "Vesper"
OUT_FILE = ROOT / "tests" / "fixtures" / "assessments" / "quality" / "vesper_multisource.json"

KERBEROS_FILE = VESPER_DIR / "janusec_identity_kerberos_v3.ndjson"
LOLBINS_FILE = VESPER_DIR / "janusec_endpoint_lolbins_v3.ndjson"
NETWORK_FILE = VESPER_DIR / "janusec_network_v3.csv"
CLOUD_FILE = VESPER_DIR / "janusec_cloud_identity_v3.json"

# Attack indicator constants
ATTACK_ENC = {"0x17", "0x18", "23", "24", "rc4", "rc4-hmac", "des"}
WMI_ATTACK = "process call create"


def _hash_rows(rows: list[dict]) -> str:
    h = hashlib.md5(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()[:12]
    return h


def load_kerberos(n_attack: int = 15, n_benign: int = 10) -> list[dict]:
    """Load Kerberos rows: prefer 4769+RC4 attack rows, fill with benign."""
    attack, benign = [], []
    with open(KERBEROS_FILE) as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            enc = str(row.get("ticket_encryption", "")).strip().lower()
            eid = str(row.get("windows_event_id", ""))
            if eid == "4769" and any(a in enc for a in ("0x17", "0x18", "rc4")):
                attack.append(row)
            elif eid in ("4768", "4769", "4634", "4624"):
                benign.append(row)
            if len(attack) >= n_attack * 3 and len(benign) >= n_benign * 3:
                break
    random.seed(42)
    return random.sample(attack, min(n_attack, len(attack))) + \
           random.sample(benign, min(n_benign, len(benign)))


def load_lolbins(n_attack: int = 12, n_benign: int = 8) -> list[dict]:
    """Load Sysmon rows: prefer WMI lateral exec + encoded PS."""
    attack, benign = [], []
    with open(LOLBINS_FILE) as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            cmd = str(row.get("command_line", "")).lower()
            if WMI_ATTACK in cmd or ("-enc " in cmd and "-nop" in cmd):
                attack.append(row)
            elif row.get("process_name") in ("chrome.exe", "teams.exe", "explorer.exe", "outlook.exe"):
                benign.append(row)
            if len(attack) >= n_attack * 3 and len(benign) >= n_benign * 3:
                break
    random.seed(42)
    return random.sample(attack, min(n_attack, len(attack))) + \
           random.sample(benign, min(n_benign, len(benign)))


def load_network(n_suspicious: int = 10, n_benign: int = 8) -> list[dict]:
    """Load network rows: prefer high-byte exfil to external IPs."""
    suspicious, benign = [], []
    with open(NETWORK_FILE) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                bytes_s = int(row.get("bytes_sent", 0) or 0)
            except ValueError:
                bytes_s = 0
            dst_ip = row.get("dst_ip", "")
            is_external = not (dst_ip.startswith("10.") or dst_ip.startswith("192.168.") or
                               dst_ip.startswith("172."))
            if bytes_s > 100_000 and is_external:
                suspicious.append(row)
            elif bytes_s < 5_000 and row.get("domain"):
                benign.append(row)
            if len(suspicious) >= n_suspicious * 3 and len(benign) >= n_benign * 3:
                break
    random.seed(42)
    return random.sample(suspicious, min(n_suspicious, len(suspicious))) + \
           random.sample(benign, min(n_benign, len(benign)))


def load_cloud(n_attack: int = 8, n_benign: int = 8) -> list[dict]:
    """Load cloud identity rows: AuditLogs + high-risk SignInLogs."""
    with open(CLOUD_FILE) as f:
        data = json.load(f)
    events = data if isinstance(data, list) else data.get("value", [])
    attack, benign = [], []
    for evt in events:
        cat = str(evt.get("category", "")).lower()
        en = str(evt.get("event_name") or evt.get("activityDisplayName") or "").lower()
        risk = str(evt.get("riskLevelDuringSignIn") or evt.get("riskLevel") or "").lower()
        cond = str(evt.get("conditionalAccessStatus") or "").lower()
        # AuditLogs with consent/credential events are definite attacks
        if cat == "auditlogs" and any(kw in en for kw in ("consent", "credential", "certificate")):
            attack.append(evt)
        # High/medium risk sign-ins are suspicious
        elif risk in ("high", "medium"):
            attack.append(evt)
        # Failed conditional access (possible token theft attempt)
        elif cond == "failure" and cat == "signinlogs":
            attack.append(evt)
        # Normal successful sign-ins as benign baseline
        elif (cat == "signinlogs" and
              str(evt.get("status", {}).get("errorCode", -1)) == "0" and
              risk in ("none", "low", "")):
            benign.append(evt)
        if len(attack) >= n_attack * 3 and len(benign) >= n_benign * 3:
            break
    random.seed(42)
    return (random.sample(attack, min(n_attack, len(attack))) +
            random.sample(benign, min(n_benign, len(benign))))


def normalize_row(row: dict, row_index: int, source_file: str, source_type: str) -> dict:
    """Normalize a raw source row to standard evidence row schema."""
    normalized = dict(row)
    normalized["row_index"] = row_index
    normalized["_source"] = source_file
    normalized["_source_type"] = source_type
    normalized["source_file"] = source_file
    normalized["source_type"] = source_type  # canonical field used by _detect_source_category
    # Normalize timestamp
    ts = (row.get("timestamp") or row.get("createdDateTime") or
          row.get("EventTime") or "2026-04-01T00:00:00Z")
    normalized["timestamp"] = str(ts)[:19]
    # Add triage_score based on attack indicators
    score = 0.0
    if source_type == "windows_security":
        eid = str(row.get("windows_event_id", ""))
        enc = str(row.get("ticket_encryption", "")).lower()
        if eid == "4769" and any(a in enc for a in ("0x17", "0x18")):
            score = 0.92
        elif eid == "1102":
            score = 0.85
        elif eid in ("4769", "4768"):
            score = 0.45
    elif source_type == "sysmon":
        cmd = str(row.get("command_line", "")).lower()
        if WMI_ATTACK in cmd:
            score = 0.90
        elif "-enc " in cmd and "-nop" in cmd:
            score = 0.80
    elif source_type == "network":
        try:
            bytes_s = int(row.get("bytes_sent", 0) or 0)
            if bytes_s > 100_000_000:  # >100MB — critical exfil
                score = 0.88
            elif bytes_s > 10_000_000:  # >10MB
                score = 0.78
            elif bytes_s > 500_000:  # >500KB
                score = 0.65
            elif bytes_s > 100_000:  # >100KB
                score = 0.45
        except ValueError:
            pass
    elif source_type == "cloud_identity":
        en = str(row.get("event_name", "") or row.get("activityDisplayName", "")).lower()
        cat = str(row.get("category", "")).lower()
        risk = str(row.get("riskLevelDuringSignIn") or "").lower()
        if "consent" in en or "certificate" in en:
            score = 0.88
        elif "credential" in en or "secret" in en:
            score = 0.82
        elif risk in ("high", "medium"):
            score = 0.72
        elif str(row.get("conditionalAccessStatus", "")).lower() == "failure":
            score = 0.55
    normalized["triage_score"] = round(score, 3)
    normalized["severity"] = "high" if score >= 0.80 else ("medium" if score >= 0.40 else "low")
    return normalized


def _source_balanced_preview(rows: list[dict], cap: int = 20) -> list[dict]:
    """Select up to `cap` rows with source-type diversity, then score-ranked fill."""
    EP_CAP = cap
    by_source: dict[str, list[dict]] = {}
    for r in rows:
        src = r.get("_source_type", "generic")
        by_source.setdefault(src, []).append(r)
    for src in by_source:
        by_source[src].sort(key=lambda r: r.get("triage_score", 0), reverse=True)

    n_sources = max(len(by_source), 1)
    per_src = max(1, EP_CAP // n_sources)
    selected = []
    for src_rows in by_source.values():
        selected.extend(src_rows[:per_src])

    # Fill remaining slots from highest-score rows not already selected
    selected_idx = {id(r) for r in selected}
    all_ranked = sorted(rows, key=lambda r: r.get("triage_score", 0), reverse=True)
    for r in all_ranked:
        if len(selected) >= EP_CAP:
            break
        if id(r) not in selected_idx:
            selected.append(r)
            selected_idx.add(id(r))

    return selected[:EP_CAP]


def build_clusters(all_rows: list[dict]) -> list[dict]:
    """Build 2 clusters: attack cluster (high-score rows) + benign cluster."""
    # Include medium-score network/cloud rows in attack cluster even if below 0.70
    attack_refs = [r["row_index"] for r in all_rows if r["triage_score"] >= 0.45]
    benign_refs = [r["row_index"] for r in all_rows if r["triage_score"] < 0.20]

    # Source mix for attack cluster
    attack_sources = {}
    for r in all_rows:
        if r["row_index"] in attack_refs:
            src = r["_source_type"]
            attack_sources[src] = attack_sources.get(src, 0) + 1

    # Shared entities in attack cluster
    attack_rows = [r for r in all_rows if r["row_index"] in attack_refs]
    shared_accounts = list({
        str(r.get("account_name") or r.get("user") or r.get("userPrincipalName") or "")
        for r in attack_rows if r.get("account_name") or r.get("user")
    } - {""})[:5]
    shared_hosts = list({
        str(r.get("host") or r.get("domain_controller") or r.get("src_host") or "")
        for r in attack_rows if r.get("host") or r.get("domain_controller") or r.get("src_host")
    } - {""})[:5]

    # Source-balanced evidence preview (mirrors Stage 5y logic in assessment_worker.py)
    attack_ep = _source_balanced_preview(attack_rows, cap=20)

    attack_cluster = {
        "cluster_id": "vesper-ms-attack-cluster-01",
        "cluster_kind": "security",
        "final_verdict": "VALIDATED_BREACH",
        "verdict": "VALIDATED_BREACH",
        "confidence": 0.95,
        "severity": "CRITICAL",
        "row_count": len(attack_refs),
        "row_refs": attack_refs,
        "shared_accounts": shared_accounts,
        "shared_hosts": shared_hosts,
        "shared_ips": [],
        "shared_users": shared_accounts,
        "mitre_techniques": ["T1558.003", "T1558.004", "T1047", "T1059.001"],
        "factor_tags": {
            "iam:kerberoasting": True,
            "iam:as_rep_roasting": True,
            "endpoint:wmi_lateral_exec": True,
            "recon:sustained_offhours_sequence": True,
            "exfil:cumulative_bytes_anomaly": True,
        },
        "_chrono_factors": ["recon:sustained_offhours_sequence"],
        "_ml_scores": {
            "martin.chen": {"cross_iso": 0.91, "ewma_residual": 2.4, "ensemble_risk": 0.88}
        },
        "compliance_violations": {"NIST_CSF.DE.AE-3": True, "ISO27001.A.12.4.1": True},
        "phases": ["initial_access", "credential_access", "lateral_movement", "exfiltration"],
        "evidence_preview": attack_ep,
        "_source_counts": attack_sources,
    }

    benign_ep = [r for r in all_rows if r["row_index"] in benign_refs][:10]
    benign_cluster = {
        "cluster_id": "vesper-ms-benign-cluster-01",
        "cluster_kind": "security",
        "final_verdict": "BENIGN_EXPECTED",
        "verdict": "BENIGN_EXPECTED",
        "confidence": 0.70,
        "severity": "LOW",
        "row_count": len(benign_refs),
        "row_refs": benign_refs,
        "shared_accounts": [],
        "shared_hosts": [],
        "shared_ips": [],
        "shared_users": [],
        "mitre_techniques": [],
        "factor_tags": {},
        "evidence_preview": benign_ep,
    }

    return [attack_cluster, benign_cluster]


def main():
    for f in [KERBEROS_FILE, LOLBINS_FILE, NETWORK_FILE, CLOUD_FILE]:
        if not f.exists():
            print(f"ERROR: {f} not found. Run from repo root with VESPER files in dump/test files/Vesper/")
            sys.exit(1)

    print("Loading VESPER source files...")
    kerb_rows_raw = load_kerberos()
    lolb_rows_raw = load_lolbins()
    net_rows_raw = load_network()
    cloud_rows_raw = load_cloud()

    print(f"  Kerberos: {len(kerb_rows_raw)} rows (incl. 4769+RC4 attack rows)")
    print(f"  LOLBins:  {len(lolb_rows_raw)} rows (incl. WMI lateral exec)")
    print(f"  Network:  {len(net_rows_raw)} rows (incl. large exfil flows)")
    print(f"  Cloud:    {len(cloud_rows_raw)} rows")

    # Assign row_indices
    idx = 1000  # start above existing fixture indices to avoid collisions
    all_rows: list[dict] = []
    for row in kerb_rows_raw:
        all_rows.append(normalize_row(row, idx, KERBEROS_FILE.name, "windows_security"))
        idx += 1
    for row in lolb_rows_raw:
        all_rows.append(normalize_row(row, idx, LOLBINS_FILE.name, "sysmon"))
        idx += 1
    for row in net_rows_raw:
        all_rows.append(normalize_row(row, idx, NETWORK_FILE.name, "network"))
        idx += 1
    for row in cloud_rows_raw:
        all_rows.append(normalize_row(row, idx, CLOUD_FILE.name, "cloud_identity"))
        idx += 1

    clusters = build_clusters(all_rows)
    attack_cluster = clusters[0]

    # Evidence diagnostics preview
    from src.core.ingest.cluster_narrator import _compute_evidence_diagnostics
    diag = _compute_evidence_diagnostics(attack_cluster["evidence_preview"])
    print(f"\nEvidence diagnostics for attack cluster:")
    print(f"  quality={diag['quality']}  source_mix={diag['source_mix']}")
    print(f"  attack_signal_rows={diag['attack_signal_rows']}  event_coverage={diag['event_coverage']}")

    fixture = {
        "assessment_id": "vesper-multisource-fixture-v1",
        "org": "acme-vesper",
        "_fixture_meta": {
            "built_by": "scripts/build_vesper_fixture.py",
            "source_files": [f.name for f in [KERBEROS_FILE, LOLBINS_FILE, NETWORK_FILE, CLOUD_FILE]],
            "row_count_by_source": {
                "kerberos": len(kerb_rows_raw),
                "lolbins": len(lolb_rows_raw),
                "network": len(net_rows_raw),
                "cloud": len(cloud_rows_raw),
            },
            "fixture_hash": _hash_rows(all_rows),
        },
        "clusters": clusters,
        "rows": all_rows,
        "rows_processed": len(all_rows),
        "uploaded_row_count": len(all_rows),
        "source_counts": {
            "windows_security": len(kerb_rows_raw),
            "sysmon": len(lolb_rows_raw),
            "network": len(net_rows_raw),
            "cloud_identity": len(cloud_rows_raw),
        },
        "created_at": "2026-06-08T00:00:00Z",
        "executive_summary": {
            "verdict": "VALIDATED_BREACH",
            "confidence": 0.95,
            "breach_title": "VESPER APT: Kerberoasting + WMI Lateral + Exfil",
            "breach_subtitle": "Multi-stage intrusion via credential theft, lateral movement, and data exfiltration",
        },
    }

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w") as f:
        json.dump(fixture, f, indent=2, default=str)

    print(f"\nFixture written to {OUT_FILE}")
    print(f"  Total rows: {len(all_rows)}")
    print(f"  Attack cluster: {len(attack_cluster['row_refs'])} rows, verdict={attack_cluster['final_verdict']}")
    print(f"  Benign cluster: {len(clusters[1]['row_refs'])} rows, verdict={clusters[1]['final_verdict']}")


if __name__ == "__main__":
    main()
