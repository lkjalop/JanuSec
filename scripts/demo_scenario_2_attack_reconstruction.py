#!/usr/bin/env python3
"""
Demo Scenario 2: Attack Path Reconstruction (Lateral Movement → Exfiltration)

Generates a realistic 9-event attack scenario showing:
1. Phishing email → malicious attachment
2. PowerShell spawns from Outlook
3. Reconnaissance commands
4. Lateral movement to Domain Controller
5. Credential dumping
6. Privilege escalation
7. File server access
8. Large file read
9. Data exfiltration to C2

Usage:
    python demo_scenario_2_attack_reconstruction.py

This populates the platform with events that demonstrate HopGraph visualization.
"""

import requests
import json
import time
import os
from datetime import datetime, timedelta

# Allow port override via environment variable
# Default to 8080 (simple mode) unless JANUSEC_PORT is set
API_PORT = os.getenv("JANUSEC_PORT", "8080")
API_BASE = f"http://localhost:{API_PORT}"
API_KEY = "devkey123"

print(f"[INFO] Using API endpoint: {API_BASE}")
print()

def generate_attack_events():
    """Generate 9-event APT-style attack scenario."""

    base_time = datetime.now() - timedelta(hours=2)

    events = [
        # Event 1: Phishing email attachment opened
        {
            "timestamp": (base_time + timedelta(minutes=0)).isoformat(),
            "event_type": "email",
            "source": "external-email.xyz",
            "destination": "alice@corp.com",
            "subject": "RE: Invoice #12345",
            "attachment": "invoice.docm",
            "verdict": "malicious",
            "factors": ["rare_sender", "suspicious_attachment", "macro_enabled"],
            "mitre_techniques": ["T1566.001"]  # Phishing: Spear-phishing Attachment
        },
        # Event 2: PowerShell spawns from Outlook (unusual parent-child)
        {
            "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
            "event_type": "process",
            "host": "workstation-01",
            "user": "alice@corp.com",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc <base64>",
            "parent_process": "outlook.exe",
            "factors": ["suspicious_parent", "encoded_command", "living_off_land"],
            "mitre_techniques": ["T1059.001"]  # Command and Scripting: PowerShell
        },
        # Event 3: Reconnaissance commands
        {
            "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
            "event_type": "process",
            "host": "workstation-01",
            "user": "alice@corp.com",
            "process_name": "net.exe",
            "command_line": "net user /domain",
            "factors": ["recon_command", "domain_enumeration"],
            "mitre_techniques": ["T1087.002"]  # Account Discovery: Domain Account
        },
        # Event 4: Lateral movement to DC (PSExec)
        {
            "timestamp": (base_time + timedelta(minutes=20)).isoformat(),
            "event_type": "network",
            "source": "10.0.1.50",  # workstation-01
            "destination": "10.0.2.10",  # domain-controller
            "source_host": "workstation-01",
            "dest_host": "domain-controller",
            "port": 445,  # SMB
            "protocol": "SMB",
            "bytes_sent": 5242880,  # 5MB
            "user": "alice@corp.com",
            "factors": ["lateral_movement", "smb_admin_share", "rare_connection"],
            "mitre_techniques": ["T1021.002"]  # Remote Services: SMB/Windows Admin Shares
        },
        # Event 5: Credential dumping (mimikatz)
        {
            "timestamp": (base_time + timedelta(minutes=25)).isoformat(),
            "event_type": "process",
            "host": "domain-controller",
            "user": "alice@corp.com",
            "process_name": "mimikatz.exe",
            "command_line": "sekurlsa::logonpasswords",
            "factors": ["credential_access", "lsass_read", "known_malware"],
            "mitre_techniques": ["T1003.001"]  # OS Credential Dumping: LSASS Memory
        },
        # Event 6: Privilege escalation to Domain Admin
        {
            "timestamp": (base_time + timedelta(minutes=30)).isoformat(),
            "event_type": "auth",
            "host": "domain-controller",
            "user": "alice@corp.com",
            "action": "assume_role",
            "target_role": "Domain Admins",
            "factors": ["priv_escalation", "admin_group_addition"],
            "mitre_techniques": ["T1548"]  # Abuse Elevation Control Mechanism
        },
        # Event 7: Access to file server
        {
            "timestamp": (base_time + timedelta(minutes=40)).isoformat(),
            "event_type": "network",
            "source": "10.0.2.10",  # domain-controller
            "destination": "10.0.3.50",  # file-server-prod
            "source_host": "domain-controller",
            "dest_host": "file-server-prod",
            "port": 445,
            "protocol": "SMB",
            "user": "alice@corp.com",
            "factors": ["high_value_target", "first_access"],
            "mitre_techniques": ["T1039"]  # Data from Network Shared Drive
        },
        # Event 8: Large file read (sensitive data)
        {
            "timestamp": (base_time + timedelta(minutes=45)).isoformat(),
            "event_type": "file",
            "host": "file-server-prod",
            "user": "alice@corp.com",
            "file_path": "\\\\file-server-prod\\shares\\sensitive\\customer_data.xlsx",
            "operation": "read",
            "bytes_read": 52428800,  # 50MB
            "factors": ["sensitive_data", "large_file_access"],
            "mitre_techniques": ["T1005"]  # Data from Local System
        },
        # Event 9: Data exfiltration to C2
        {
            "timestamp": (base_time + timedelta(minutes=50)).isoformat(),
            "event_type": "network",
            "source": "10.0.3.50",  # file-server-prod
            "destination": "8.8.8.8",  # External C2
            "source_host": "file-server-prod",
            "dest_host": "unknown-external",
            "port": 443,
            "protocol": "HTTPS",
            "bytes_out": 52428800,  # 50MB
            "user": "alice@corp.com",
            "factors": ["data_exfil", "large_egress", "rare_destination", "c2_callback"],
            "mitre_techniques": ["T1041"]  # Exfiltration Over C2 Channel
        }
    ]

    return events

def ingest_events(events):
    """Send events to JanuSec platform."""
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }

    print(f"[INFO] Ingesting {len(events)} events...")
    print()

    for idx, event in enumerate(events, 1):
        try:
            # Add metadata
            event["tenant_id"] = "demo"
            event["artifact_id"] = f"demo-attack-{idx}"

            r = requests.post(
                f"{API_BASE}/api/v1/events",
                headers=headers,
                json=event,
                timeout=10
            )

            if r.status_code in [200, 201]:
                print(f"[OK] Event {idx}/9: {event['event_type']} - {event.get('mitre_techniques', [''])[0]}")
            else:
                print(f"[ERROR] Event {idx}/9 failed: {r.status_code} - {r.text}")

            time.sleep(0.5)  # Small delay to allow pipeline processing

        except Exception as e:
            print(f"[ERROR] Event {idx}/9 error: {e}")

    print()
    print("[INFO] Waiting for correlation engine to process...")
    time.sleep(5)

def check_correlation_result():
    """Check if events were correlated into threat."""
    headers = {"x-api-key": API_KEY}

    try:
        r = requests.get(
            f"{API_BASE}/api/v1/decisions/recent?limit=10&tenant_id=demo",
            headers=headers,
            timeout=10
        )

        if r.status_code == 200:
            decisions = r.json().get('items', [])

            if decisions:
                print("[SUCCESS] Correlation successful!")
                print()
                print("[RESULT] Top Threat:")

                top = decisions[0]
                print(f"   Title: {top.get('title', 'Unknown')}")
                print(f"   Risk Score: {top.get('risk_score', 0):.2f}")
                print(f"   Factors: {', '.join(top.get('factors', []))}")
                print(f"   MITRE: {', '.join(top.get('mitre_techniques', []))}")
                print(f"   Artifact ID: {top.get('artifact_id')}")
                print()
                print(f"[UI] View in Browser:")
                print(f"   Main Console: {API_BASE}/static/janusec-platform-complete-LIVE.html")
                print(f"   HopGraph: {API_BASE}/static/graph_explain.html?artifact_id={top.get('artifact_id')}")
                return top.get('artifact_id')
            else:
                print("[WARN] No correlated threats found (yet)")
                print("   Events may still be processing - check UI in 30 seconds")
        else:
            print(f"[ERROR] Failed to check decisions: {r.status_code}")

    except Exception as e:
        print(f"[ERROR] Error checking correlation: {e}")

    return None

def main():
    print("="*80)
    print("Demo Scenario 2: Attack Path Reconstruction")
    print("="*80)
    print()
    print("This simulates a 9-event APT-style attack:")
    print("  1. Phishing -> 2. PowerShell -> 3. Recon -> 4. Lateral Movement")
    print("  5. Credential Dump -> 6. Privilege Escalation -> 7. File Server Access")
    print("  8. Sensitive Data Read -> 9. Exfiltration to C2")
    print()
    print("-"*80)

    # Generate events
    events = generate_attack_events()

    # Ingest
    ingest_events(events)

    # Check correlation
    artifact_id = check_correlation_result()

    print()
    print("="*80)
    print("[COMPLETE] Demo 2 Complete!")
    print("="*80)
    print()
    print("Next steps for CEO demo:")
    print(f"1. Open: {API_BASE}/static/janusec-platform-complete-LIVE.html")
    print("2. Click 'Decisions' tab -> View correlated threat")
    print("3. Click 'View HopGraph' -> See D3.js attack visualization")
    print("4. Point out: MITRE techniques, STRIDE categories, temporal decay")
    print()
    if artifact_id:
        print(f"5. Direct link to HopGraph:")
        print(f"   {API_BASE}/static/graph_explain.html?artifact_id={artifact_id}")
    print()

if __name__ == "__main__":
    main()
