#!/usr/bin/env python3
"""ASCII-only test of the 9-stage pipeline"""

import json
import requests
import time

API_BASE = "http://localhost:8080"

def test_malicious_event():
    """Test a malicious PowerShell event"""
    print("\n=== TESTING MALICIOUS EVENT ===")

    event = {
        "id": f"malicious-{int(time.time())}",
        "host": "test-host",
        "proc_name": "powershell.exe",
        "parent_proc": "winword.exe",
        "dest_port": 4444,
        "command_line": "powershell.exe -enc base64_encoded_payload"
    }

    print(f"Sending: {json.dumps(event, indent=2)}")

    try:
        response = requests.post(
            f"{API_BASE}/api/v1/endpoints/log_batch",
            json={"events": [event], "classify": True, "send_alerts": True}
        )

        print(f"Response: {response.status_code}")
        print(f"Result: {response.json()}")

        # Wait and check metrics
        time.sleep(2)
        metrics = requests.get(f"{API_BASE}/metrics").text

        print("\nRelevant metrics:")
        for line in metrics.split('\n'):
            if 'rule_hits' in line or 'decisions' in line:
                if not line.startswith('#') and line.strip():
                    print(f"  {line}")

        # Check alerts
        alerts = requests.get(f"{API_BASE}/api/v1/alerts/recent").json()
        print(f"\nAlerts: {alerts}")

    except Exception as e:
        print(f"Error: {e}")

def test_zeek_dns():
    """Test Zeek DNS event"""
    print("\n=== TESTING ZEEK DNS EVENT ===")

    event = {
        "id": f"dns-{int(time.time())}",
        "host": "test-host",
        "proc_name": "cmd.exe",
        "dest_ip": "1.1.1.1",
        "dns_rcode": "NXDOMAIN"
    }

    print(f"Sending: {json.dumps(event, indent=2)}")

    try:
        response = requests.post(
            f"{API_BASE}/api/v1/endpoints/log_batch",
            json={"events": [event], "classify": True, "send_alerts": True}
        )

        print(f"Response: {response.status_code}")
        print(f"Result: {response.json()}")

    except Exception as e:
        print(f"Error: {e}")

def main():
    print("JanuSec Pipeline Test")
    print("=" * 50)

    # Test server health
    try:
        health = requests.get(f"{API_BASE}/health").json()
        print(f"Server health: {health['status']}")
        print(f"Events processed: {health.get('events_processed', 0)}")
    except Exception as e:
        print(f"Health check failed: {e}")
        return

    # Run tests
    test_malicious_event()
    test_zeek_dns()

    print("\nDone! Check the server logs for 9-stage processing details.")

if __name__ == "__main__":
    main()