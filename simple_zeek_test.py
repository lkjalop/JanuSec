#!/usr/bin/env python3
"""
Simple Zeek Pipeline Test - Verify 9-Stage Processing
"""

import json
import requests
import time

API_BASE = "http://localhost:8080"

def test_event(name, event_data):
    """Test a single event and show results"""
    print(f"\n=== Testing {name} ===")

    # Send event
    try:
        response = requests.post(
            f"{API_BASE}/api/v1/endpoints/log_batch",
            json={"events": [event_data], "classify": True, "send_alerts": True},
            timeout=10
        )

        if response.status_code == 200:
            result = response.json()
            print(f"✅ Event accepted: {result}")

            # Wait for processing
            time.sleep(2)

            # Check metrics
            metrics_response = requests.get(f"{API_BASE}/metrics", timeout=5)
            if metrics_response.status_code == 200:
                metrics = metrics_response.text
                print(f"📊 Metrics:")

                # Show relevant metrics
                for line in metrics.split('\n'):
                    if any(keyword in line for keyword in ['rule_hits', 'decisions_total', 'events_ingested']):
                        if not line.startswith('#') and line.strip():
                            print(f"   {line}")

            # Check alerts
            alerts_response = requests.get(f"{API_BASE}/api/v1/alerts/recent", timeout=5)
            if alerts_response.status_code == 200:
                alerts_data = alerts_response.json()
                alerts = alerts_data.get("alerts", [])
                print(f"🚨 Alerts generated: {len(alerts)}")

                for alert in alerts[-3:]:  # Show last 3
                    print(f"   Alert: {alert.get('verdict', 'unknown')} confidence={alert.get('confidence', 0):.3f}")

        else:
            print(f"❌ Failed: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"🔥 Error: {e}")

def main():
    print("JanuSec 9-Stage Pipeline Test")
    print("=" * 50)

    # Test 1: Benign Event (should go through fast path)
    benign_event = {
        "id": f"benign-{int(time.time())}",
        "host": "test-laptop",
        "proc_name": "notepad.exe",
        "parent_proc": "explorer.exe",
        "dest_ip": "8.8.8.8",
        "dest_port": 80,
        "tags": ["benign", "test"]
    }
    test_event("BENIGN - Notepad from Explorer", benign_event)

    # Test 2: Suspicious Event (should trigger multiple stages)
    suspicious_event = {
        "id": f"suspicious-{int(time.time())}",
        "host": "test-laptop",
        "proc_name": "powershell.exe",
        "parent_proc": "winword.exe",  # Office macro!
        "dest_ip": "192.168.1.100",   # Internal IP
        "dest_port": 443,
        "command_line": "powershell.exe -enc base64data",
        "tags": ["suspicious", "test"]
    }
    test_event("SUSPICIOUS - PowerShell from Word", suspicious_event)

    # Test 3: Malicious Event (should trigger auto-block)
    malicious_event = {
        "id": f"malicious-{int(time.time())}",
        "host": "test-laptop",
        "proc_name": "powershell.exe",
        "parent_proc": "winword.exe",
        "dest_ip": "198.51.100.10",  # External suspicious IP
        "dest_port": 4444,           # Suspicious port
        "command_line": "powershell.exe -w hidden -enc JABhAD0AJwBoAHQAdABwADoALwAvAGMAMgAuAGUAdgBpAGwALgBjAG8AbQAnAA==",
        "tags": ["malicious", "test"]
    }
    test_event("MALICIOUS - Hidden PowerShell C2", malicious_event)

    # Test 4: Zeek DNS Event (high NXDOMAIN rate)
    dns_event = {
        "id": f"dns-{int(time.time())}",
        "host": "test-laptop",
        "proc_name": "zeek:dns",
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "dns_rcode": "NXDOMAIN",
        "dns_query": "random-dga-12345.com",
        "tags": ["zeek", "dns", "nxdomain"]
    }
    test_event("ZEEK DNS - NXDOMAIN Pattern", dns_event)

    # Test 5: Zeek Connection (C2 beacon simulation)
    conn_event = {
        "id": f"conn-{int(time.time())}",
        "host": "test-laptop",
        "proc_name": "zeek:conn",
        "dest_ip": "203.0.113.50",
        "dest_port": 8080,
        "proto": "tcp",
        "duration": 300,      # Long duration
        "orig_bytes": 64,     # Low volume
        "resp_bytes": 32,     # Low volume
        "service": "unknown",
        "tags": ["zeek", "conn", "beacon"]
    }
    test_event("ZEEK CONN - C2 Beacon Pattern", conn_event)

    print(f"\n📊 Final System State:")
    print(f"View live dashboard: {API_BASE}/docs")
    print(f"Check all metrics: {API_BASE}/metrics")
    print(f"Recent alerts: {API_BASE}/api/v1/alerts/recent")

if __name__ == "__main__":
    main()