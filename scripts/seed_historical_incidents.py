"""Seed the historical_incidents table with realistic sample data for demo."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo


def seed_historical_incidents():
    """Populate historical_incidents with 5 diverse sample incidents."""
    print("Seeding historical incidents database...")
    print()

    repo = HistoricalIncidentsRepo()

    # Sample incidents with realistic data
    incidents = [
        {
            "row": {
                "sha256": "9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a",
                "process_name": "powershell.exe",
                "host": "WORKSTATION-042",
                "user_account": "admin",
                "factors": ["process_injection", "unsigned_binary", "cmdline_obfuscation"],
                "mitre_tags": ["T1055", "T1059.001"],
                "_dread": {"score": 8.5},
                "_correlation": {"score": 0.82},
            },
            "outcome": "confirmed_malicious",
            "analyst_notes": "Emotet dropper. Injected into explorer.exe, established C2 to 185.220.101.45. Host isolated and reimaged.",
            "days_ago": 14,
        },
        {
            "row": {
                "sha256": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2",
                "process_name": "svchost.exe",
                "host": "SERVER-087",
                "user_account": "SYSTEM",
                "src_ip": "10.50.30.12",
                "dst_ip": "8.8.8.8",
                "factors": ["suspicious_dns", "beaconing"],
                "mitre_tags": ["T1071.001", "T1573"],
                "_dread": {"score": 7.2},
                "_correlation": {"score": 0.45},
            },
            "outcome": "false_positive",
            "analyst_notes": "Legitimate Windows Update service. DNS queries to microsoft.com CDN. Whitelisted.",
            "days_ago": 28,
        },
        {
            "row": {
                "sha256": "f3e2d1c0b9a8978665544332211ffeeddccbbaa998877665544332211ff00ee",
                "process_name": "chrome.exe",
                "host": "LAPTOP-055",
                "user_account": "jsmith",
                "dst_ip": "104.16.123.96",
                "domain": "maliciousads.tk",
                "factors": ["data_exfiltration", "c2_communication", "dga_domain"],
                "mitre_tags": ["T1071.001", "T1568.002", "T1041"],
                "_dread": {"score": 9.1},
                "_correlation": {"score": 0.91},
            },
            "outcome": "confirmed_malicious",
            "analyst_notes": "Malvertising campaign. User clicked ad, Chrome compromised, exfiltrated browser cookies. Removed via EDR.",
            "days_ago": 45,
        },
        {
            "row": {
                "sha256": "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
                "process_name": "mimikatz.exe",
                "host": "WORKSTATION-042",
                "user_account": "admin",
                "factors": ["credential_dumping", "lsass_access", "privilege_escalation"],
                "mitre_tags": ["T1003.001", "T1078"],
                "_dread": {"score": 9.8},
                "_correlation": {"score": 0.95},
            },
            "outcome": "confirmed_malicious",
            "analyst_notes": "Credential dumping via Mimikatz. Same host as Emotet incident 2 weeks prior. Credential rotation enforced.",
            "days_ago": 7,
        },
        {
            "row": {
                "sha256": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "process_name": "taskmgr.exe",
                "host": "WORKSTATION-099",
                "user_account": "helpdesk",
                "factors": ["rare_binary"],
                "mitre_tags": [],
                "_dread": {"score": 2.1},
                "_correlation": {"score": 0.15},
            },
            "outcome": "benign",
            "analyst_notes": "Task Manager launched by helpdesk during support session. Verified with ticket #12345.",
            "days_ago": 60,
        },
    ]

    # Insert incidents with offset timestamps
    for idx, incident in enumerate(incidents, 1):
        row = incident["row"]
        outcome = incident["outcome"]
        notes = incident["analyst_notes"]
        days_ago = incident["days_ago"]

        # Calculate timestamp offset
        offset_date = datetime.utcnow() - timedelta(days=days_ago)

        try:
            # Save incident (will auto-create table if not exists)
            incident_id = repo.save_incident(row, outcome=outcome, analyst_notes=notes)

            # Update timestamps to reflect historical nature
            import sqlite3
            conn = sqlite3.connect(repo.db_path)
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE historical_incidents
                SET first_seen_at = ?,
                    last_seen_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    offset_date.isoformat(),
                    offset_date.isoformat(),
                    offset_date.isoformat(),
                    incident_id,
                ),
            )
            conn.commit()
            conn.close()

            print(f"  [OK] Incident {idx}: {row['process_name']} on {row['host']} ({outcome})")

        except Exception as e:
            print(f"  [FAIL] Incident {idx}: Failed - {e}")

    print()
    print(f"[SUCCESS] Seeded {len(incidents)} historical incidents")
    print()

    # Test query
    print("Testing historical query...")
    test_row = {
        "sha256": "9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a",
        "process_name": "powershell.exe",
        "host": "WORKSTATION-042",
    }

    similar = repo.query_similar_incidents(test_row, lookback_days=90, limit=5)
    print(f"  Found {len(similar)} similar incidents for SHA256 9bf41199...")

    if similar:
        for inc in similar[:2]:
            print(f"  - Match: {inc.get('process_name')} - {inc.get('outcome')}")
    else:
        print("  WARNING: No matches found. Check database seeding.")

    print()
    print("Seeding complete!")
    return 0


if __name__ == "__main__":
    sys.exit(seed_historical_incidents())
