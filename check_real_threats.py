#!/usr/bin/env python3
"""
Check real threats stored in the database
"""

import asyncio
import sys
import os
from pathlib import Path

# Add src to Python path
current_dir = Path(__file__).parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))
sys.path.insert(0, str(current_dir))

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from database_adapter import get_database_adapter

async def check_threats():
    """Check real threats in database"""
    print("=" * 80)
    print("REAL THREATS ANALYSIS")
    print("=" * 80)
    print()

    try:
        # Initialize database
        db = get_database_adapter()
        await db.initialize()

        print(f"Database Type: {db.db_type}")
        print()

        # Check events table
        query = "SELECT * FROM events ORDER BY timestamp DESC LIMIT 20"
        events = await db.fetch_all(query)

        print(f"Recent Events ({len(events)} found):")
        print("-" * 60)

        malicious_count = 0
        benign_count = 0

        for event in events:
            event_id = event.get('id', 'unknown')
            verdict = event.get('verdict', 'unknown')
            confidence = event.get('confidence', 0)
            timestamp = event.get('timestamp', 'unknown')

            if verdict in ['malicious', 'critical']:
                malicious_count += 1
                print(f"[THREAT] {event_id}")
                print(f"  Verdict: {verdict} (confidence: {confidence:.2f})")
                print(f"  Time: {timestamp}")

                # Parse event data if it exists
                event_data = event.get('event_data')
                if event_data:
                    import json
                    try:
                        data = json.loads(event_data) if isinstance(event_data, str) else event_data
                        proc_name = data.get('proc_name', 'unknown')
                        parent_proc = data.get('parent_proc', 'unknown')
                        command_line = data.get('command_line', '')

                        print(f"  Process: {proc_name} <- {parent_proc}")
                        if command_line:
                            print(f"  Command: {command_line[:100]}...")
                    except:
                        pass

                print()
            else:
                benign_count += 1

        print(f"Summary:")
        print(f"  Malicious/Critical: {malicious_count}")
        print(f"  Benign/Other: {benign_count}")
        print(f"  Total Events: {len(events)}")
        print()

        # Check alerts table
        query = "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10"
        alerts = await db.fetch_all(query)

        print(f"Recent Alerts ({len(alerts)} found):")
        print("-" * 60)

        for alert in alerts:
            alert_id = alert.get('id', 'unknown')
            alert_type = alert.get('alert_type', 'unknown')
            severity = alert.get('severity', 'unknown')
            message = alert.get('message', '')
            confidence = alert.get('confidence', 0)

            print(f"[ALERT] {alert_id}")
            print(f"  Type: {alert_type}")
            print(f"  Severity: {severity}")
            print(f"  Message: {message}")
            print(f"  Confidence: {confidence:.2f}")
            print()

        if not alerts:
            print("  No alerts generated yet")
            print()

    except Exception as e:
        print(f"Error checking threats: {e}")
        return

    # Generate a sample threat report
    print("=" * 80)
    print("SAMPLE THREAT REPORT")
    print("=" * 80)
    print()

    sample_threat = {
        "threat_id": "TH-2025-0925-001",
        "detection_time": "2025-09-25T11:15:32Z",
        "verdict": "CRITICAL",
        "confidence": 0.95,
        "mitre_techniques": ["T1566.001", "T1059.001"],
        "process_chain": [
            "winword.exe (PID: 2341)",
            "powershell.exe (PID: 5672)"
        ],
        "indicators": {
            "parent_process": "winword.exe",
            "child_process": "powershell.exe",
            "command_line": "powershell.exe -enc UG93ZXJTaGVsbA==",
            "destination_port": 4444,
            "external_ip": "185.220.101.32"
        },
        "threat_factors": [
            "office_macro_execution",
            "suspicious_outbound_port",
            "base64_encoded_payload",
            "external_connection"
        ],
        "risk_assessment": {
            "likelihood": "HIGH",
            "impact": "HIGH",
            "overall_risk": "CRITICAL"
        },
        "recommendations": [
            "Immediately isolate affected endpoint",
            "Analyze PowerShell execution logs",
            "Check network traffic to 185.220.101.32:4444",
            "Scan for additional macro-enabled documents"
        ]
    }

    import json
    print(json.dumps(sample_threat, indent=2))
    print()

    print("=" * 80)
    print("THREAT ANALYSIS COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(check_threats())