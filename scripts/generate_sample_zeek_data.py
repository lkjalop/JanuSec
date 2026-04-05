#!/usr/bin/env python3
"""
Generate sample Zeek data for testing JanuSec platform integration
Creates realistic network logs that will trigger various detection rules
"""

import json
import random
import time
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Malicious IPs and domains for testing detection
MALICIOUS_IPS = [
    "192.168.100.50",  # Internal compromised host
    "203.0.113.66",    # C2 server
    "198.51.100.88",   # Malware hosting
    "10.0.1.200",      # Lateral movement
]

MALICIOUS_DOMAINS = [
    "evil-c2-server.com",
    "malware-hosting.net",
    "phishing-site.org",
    "suspicious-domain.tk",
    "data-exfil.cc"
]

BENIGN_IPS = [
    "8.8.8.8", "8.8.4.4",           # Google DNS
    "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "192.168.1.1", "192.168.1.100",      # Internal network
]

BENIGN_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "stackoverflow.com",
    "amazon.com", "cloudflare.com", "ubuntu.com", "python.org"
]

def generate_connection_event(event_id: str, malicious: bool = False) -> dict:
    """Generate a network connection event (similar to Zeek conn.log)"""
    now = datetime.now()

    if malicious:
        src_ip = random.choice(["192.168.1.100", "10.0.1.50"])
        dst_ip = random.choice(MALICIOUS_IPS)
        dst_port = random.choice([4444, 8080, 31337, 1337, 443])
        bytes_sent = random.randint(100, 1000)
        bytes_recv = random.randint(5000, 50000)  # Suspicious download
        service = "unknown"
    else:
        src_ip = "192.168.1.100"
        dst_ip = random.choice(BENIGN_IPS)
        dst_port = random.choice([80, 443, 53, 22, 25])
        bytes_sent = random.randint(500, 2000)
        bytes_recv = random.randint(1000, 5000)
        service = random.choice(["http", "https", "dns", "ssh", "smtp"])

    return {
        "id": event_id,
        "host": "zeek-sensor-01",
        "timestamp": now.isoformat(),
        "details": {
            "zeek_log_type": "conn",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(32768, 65535),
            "dst_port": dst_port,
            "protocol": "tcp",
            "service": service,
            "duration": round(random.uniform(0.1, 300.0), 2),
            "bytes_sent": bytes_sent,
            "bytes_recv": bytes_recv,
            "connection_state": "SF" if not malicious else random.choice(["SF", "S0", "REJ"])
        }
    }

def generate_dns_event(event_id: str, malicious: bool = False) -> dict:
    """Generate a DNS query event (similar to Zeek dns.log)"""
    now = datetime.now()

    if malicious:
        query = random.choice(MALICIOUS_DOMAINS)
        rcode = random.choice([0, 3])  # NOERROR or NXDOMAIN
        answer = random.choice(MALICIOUS_IPS) if rcode == 0 else ""
    else:
        query = random.choice(BENIGN_DOMAINS)
        rcode = 0  # NOERROR
        answer = random.choice(BENIGN_IPS)

    return {
        "id": event_id,
        "host": "zeek-sensor-01",
        "timestamp": now.isoformat(),
        "details": {
            "zeek_log_type": "dns",
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "query": query,
            "query_type": "A",
            "response_code": rcode,
            "answer": answer,
            "ttl": random.randint(60, 3600)
        }
    }

def generate_http_event(event_id: str, malicious: bool = False) -> dict:
    """Generate an HTTP request event (similar to Zeek http.log)"""
    now = datetime.now()

    if malicious:
        host = random.choice(MALICIOUS_DOMAINS)
        uri = random.choice(["/exploit.php", "/shell.jsp", "/backdoor", "/admin/login.php"])
        user_agent = "python-requests/2.25.1"  # Suspicious automated tool
        status_code = random.choice([200, 404, 403])
        method = random.choice(["POST", "GET"])
    else:
        host = random.choice(BENIGN_DOMAINS)
        uri = random.choice(["/", "/index.html", "/api/v1/status", "/search?q=test"])
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        status_code = random.choice([200, 301, 404])
        method = "GET"

    return {
        "id": event_id,
        "host": "zeek-sensor-01",
        "timestamp": now.isoformat(),
        "details": {
            "zeek_log_type": "http",
            "src_ip": "192.168.1.100",
            "dst_ip": random.choice(BENIGN_IPS),
            "method": method,
            "host": host,
            "uri": uri,
            "user_agent": user_agent,
            "status_code": status_code,
            "response_body_len": random.randint(100, 10000)
        }
    }

def generate_ssl_event(event_id: str, malicious: bool = False) -> dict:
    """Generate an SSL/TLS connection event (similar to Zeek ssl.log)"""
    now = datetime.now()

    if malicious:
        server_name = random.choice(MALICIOUS_DOMAINS)
        ja3_hash = "72a589da586844d7f0818ce684948eea"  # Known malware JA3
        cert_chain_fuids = ["suspicious_cert_123"]
    else:
        server_name = random.choice(BENIGN_DOMAINS)
        ja3_hash = "769c83c776de055d5bd8d54d0bf70982"  # Common browser JA3
        cert_chain_fuids = ["valid_cert_456"]

    return {
        "id": event_id,
        "host": "zeek-sensor-01",
        "timestamp": now.isoformat(),
        "details": {
            "zeek_log_type": "ssl",
            "src_ip": "192.168.1.100",
            "dst_ip": random.choice(BENIGN_IPS if not malicious else MALICIOUS_IPS),
            "dst_port": 443,
            "version": "TLSv12",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "server_name": server_name,
            "ja3": ja3_hash,
            "cert_chain_fuids": cert_chain_fuids
        }
    }

def main():
    output_dir = Path("D:/AI/Threat_thy_sniffer/data/zeek")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate events with 20% malicious traffic
    total_events = 500
    malicious_count = int(total_events * 0.2)

    events = []

    print(f"Generating {total_events} Zeek events ({malicious_count} malicious)")

    for i in range(total_events):
        is_malicious = i < malicious_count
        event_type = random.choice(["conn", "dns", "http", "ssl"])
        event_id = f"zeek-{event_type}-{i:04d}"

        if event_type == "conn":
            event = generate_connection_event(event_id, is_malicious)
        elif event_type == "dns":
            event = generate_dns_event(event_id, is_malicious)
        elif event_type == "http":
            event = generate_http_event(event_id, is_malicious)
        else:  # ssl
            event = generate_ssl_event(event_id, is_malicious)

        events.append(event)

        # Add some time variance
        time.sleep(0.01)

    # Save events in JSON format for easy ingestion
    output_file = output_dir / "sample_events.json"
    with open(output_file, 'w') as f:
        json.dump(events, f, indent=2)

    print(f"Generated {len(events)} events saved to {output_file}")

    # Also create a batch upload script
    upload_script = output_dir / "upload_to_janusec.py"
    with open(upload_script, 'w') as f:
        f.write(f'''#!/usr/bin/env python3
"""Upload generated Zeek events to JanuSec platform"""

import json
import requests
import sys

def upload_events():
    with open("{output_file}", 'r') as f:
        events = json.load(f)

    # Split into batches of 50 events
    batch_size = 50
    api_url = "http://localhost:8080/api/v1/endpoints/log_batch"
    headers = {{
        "Content-Type": "application/json",
        "X-Tenant-ID": "demo"
    }}

    for i in range(0, len(events), batch_size):
        batch = events[i:i+batch_size]
        payload = {{
            "events": batch,
            "classify": True,
            "send_alerts": True,
            "include_rules": True,
            "tenant_id": "demo"
        }}

        try:
            response = requests.post(api_url, json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()
            print(f"Batch {{i//batch_size + 1}}: {{result['accepted']}} events accepted, {{result['alerts_emitted']}} alerts")
        except Exception as e:
            print(f"Error uploading batch {{i//batch_size + 1}}: {{e}}")

if __name__ == "__main__":
    upload_events()
''')

    print(f"Upload script created: {upload_script}")
    print(f"To upload data: python {upload_script}")

    return events

if __name__ == "__main__":
    main()