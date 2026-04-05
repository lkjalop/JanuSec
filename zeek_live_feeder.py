#!/usr/bin/env python3
"""
Live Zeek Integration Script
Feeds Zeek-like events to JanuSec Platform and monitors 9-stage progression

Usage: python zeek_live_feeder.py
"""

import json
import requests
import time
import threading
from typing import Dict, Any, List
import random

API_BASE = "http://localhost:8080"

class ZeekEventSimulator:
    """Simulates realistic Zeek network events"""

    def __init__(self):
        self.suspicious_ips = ["192.168.1.100", "10.0.0.15", "172.16.1.50"]
        self.c2_domains = ["evil-c2.com", "malware-beacon.net", "data-exfil.org"]
        self.normal_domains = ["google.com", "microsoft.com", "github.com", "stackoverflow.com"]
        self.hosts = ["DESKTOP-ABC123", "LAPTOP-XYZ789", "SERVER-DEF456"]

    def generate_benign_conn_event(self) -> Dict[str, Any]:
        """Generate normal connection event"""
        return {
            "id": f"conn-benign-{int(time.time() * 1000)}",
            "ts": time.time(),
            "host": random.choice(self.hosts),
            "user": "zeek",
            "proc_name": "zeek:http",
            "dest_ip": "8.8.8.8",
            "dest_port": 80,
            "proto": "tcp",
            "duration": random.uniform(0.1, 2.0),
            "orig_bytes": random.randint(100, 1000),
            "resp_bytes": random.randint(500, 5000),
            "tags": ["zeek", "conn", "benign"]
        }

    def generate_suspicious_dns_event(self) -> Dict[str, Any]:
        """Generate suspicious DNS with high NXDOMAIN rate"""
        return {
            "id": f"dns-suspicious-{int(time.time() * 1000)}",
            "ts": time.time(),
            "host": random.choice(self.hosts),
            "user": "zeek",
            "proc_name": "zeek:dns",
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "dns_rcode": "NXDOMAIN" if random.random() > 0.3 else "NOERROR",  # 70% NXDOMAIN
            "dns_query": random.choice(self.c2_domains + ["random-dga-" + str(random.randint(1000, 9999)) + ".com"]),
            "tags": ["zeek", "dns", "suspicious"]
        }

    def generate_malicious_beacon_event(self) -> Dict[str, Any]:
        """Generate C2 beacon connection"""
        return {
            "id": f"beacon-malicious-{int(time.time() * 1000)}",
            "ts": time.time(),
            "host": random.choice(self.hosts),
            "user": "zeek",
            "proc_name": "zeek:conn",
            "dest_ip": random.choice(self.suspicious_ips),
            "dest_port": 4444,  # Suspicious port
            "proto": "tcp",
            "duration": 300,  # Long duration
            "orig_bytes": 128,  # Low volume
            "resp_bytes": 64,   # Low volume
            "service": "unknown",
            "tags": ["zeek", "conn", "c2-beacon", "malicious"]
        }

    def generate_office_macro_attack(self) -> Dict[str, Any]:
        """Generate Office macro spawning PowerShell"""
        return {
            "id": f"macro-attack-{int(time.time() * 1000)}",
            "ts": time.time(),
            "host": random.choice(self.hosts),
            "event_type": "process_start",
            "proc_name": "powershell.exe",
            "parent_proc": "winword.exe",  # Office macro
            "command_line": "powershell.exe -enc JABhAD0AJwBoAHQAdABwADoALwAvAGMAMgAuAGUAdgBpAGwALgBjAG8AbQAnAA==",  # Base64 encoded
            "dest_ip": random.choice(self.suspicious_ips),
            "tags": ["endpoint", "macro", "powershell", "malicious"]
        }

class LiveMonitor:
    """Monitors API responses and tracks 9-stage progression"""

    def __init__(self):
        self.events_sent = 0
        self.decisions_tracked = {}
        self.running = True

    def send_event(self, event: Dict[str, Any]) -> str:
        """Send event to JanuSec API"""
        try:
            response = requests.post(
                f"{API_BASE}/api/v1/endpoints/log_batch",
                json={"events": [event], "classify": True},
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                event_id = event["id"]
                self.events_sent += 1

                print(f"✅ Event {event_id} sent successfully")

                # Track for decision monitoring
                self.decisions_tracked[event_id] = {
                    "sent_at": time.time(),
                    "event_type": event.get("tags", ["unknown"])[0],
                    "verdict": "pending"
                }

                return event_id
            else:
                print(f"❌ Failed to send event: {response.status_code}")
                return None

        except Exception as e:
            print(f"🔥 Error sending event: {e}")
            return None

    def check_decisions(self):
        """Monitor decisions and track 9-stage progression"""
        while self.running:
            try:
                # Get recent alerts instead of decisions
                response = requests.get(f"{API_BASE}/api/v1/alerts/recent", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    alerts = data.get("alerts", [])

                    for alert in alerts:
                        event_id = alert.get("event_id")
                        if event_id in self.decisions_tracked:
                            self.decisions_tracked[event_id]["verdict"] = decision.get("verdict", "unknown")
                            self.decisions_tracked[event_id]["confidence"] = decision.get("confidence", 0.0)
                            self.decisions_tracked[event_id]["factors"] = decision.get("factors", [])
                            self.decisions_tracked[event_id]["stage_timings"] = decision.get("stage_timings", {})

                            self.print_9_stage_analysis(event_id, decision)

            except Exception as e:
                print(f"🔍 Decision monitoring error: {e}")

            time.sleep(2)

    def print_9_stage_analysis(self, event_id: str, decision: Dict[str, Any]):
        """Print detailed 9-stage pipeline analysis"""
        verdict = decision.get("verdict", "unknown")
        confidence = decision.get("confidence", 0.0)
        factors = decision.get("factors", [])
        stage_timings = decision.get("stage_timings", {})

        # Determine pipeline route
        if confidence < 0.1:
            route = "🟢 BENIGN (Fast Path)"
        elif confidence > 0.9:
            route = "🔴 MALICIOUS (Auto-Block)"
        else:
            route = "🟡 SUSPICIOUS (Deep Analysis)"

        print(f"\n📊 ═══ 9-STAGE ANALYSIS ═══")
        print(f"🆔 Event: {event_id}")
        print(f"🎯 Route: {route}")
        print(f"📈 Confidence: {confidence:.3f}")
        print(f"⚖️  Verdict: {verdict.upper()}")

        print(f"🔍 Factors Detected ({len(factors)}):")
        for i, factor in enumerate(factors[:10], 1):  # Show top 10
            print(f"   {i}. {factor}")
        if len(factors) > 10:
            print(f"   ... and {len(factors) - 10} more")

        print(f"⏱️  Stage Timings:")
        total_time = 0
        for stage, timing in stage_timings.items():
            print(f"   {stage}: {timing:.1f}ms")
            total_time += timing
        print(f"   TOTAL: {total_time:.1f}ms")

        # Show which stages were involved
        stage_indicators = []
        if "baseline" in stage_timings:
            stage_indicators.append("1️⃣ Baseline")
        if "regex" in stage_timings:
            stage_indicators.append("2️⃣ Regex")
        if "parent_child" in stage_timings:
            stage_indicators.append("3️⃣ Parent-Child")
        if "endpoint_hunter" in stage_timings:
            stage_indicators.append("4️⃣ Endpoint Hunter")
        if "auth_burst" in stage_timings:
            stage_indicators.append("5️⃣ Auth Burst")
        if "hopgraph" in stage_timings:
            stage_indicators.append("6️⃣ HopGraph")
        if "adaptive_tuner" in stage_timings:
            stage_indicators.append("7️⃣ Adaptive Tuner")
        if "hunt_lanes" in stage_timings:
            stage_indicators.append("8️⃣ Hunt Lanes")
        if "correlation" in stage_timings:
            stage_indicators.append("9️⃣ Correlation")

        if stage_indicators:
            print(f"🔢 Stages: {' → '.join(stage_indicators)}")

        print("═" * 50)

    def get_metrics(self):
        """Fetch current metrics"""
        try:
            response = requests.get(f"{API_BASE}/metrics", timeout=5)
            if response.status_code == 200:
                metrics = response.text

                # Extract key metrics
                print(f"\n📈 ═══ LIVE METRICS ═══")
                for line in metrics.split('\n'):
                    if any(keyword in line for keyword in ['decisions_total', 'rule_hits_total', 'pipeline_events_total', 'nx_domain_rate_events_total']):
                        if not line.startswith('#'):
                            print(f"   {line}")
                print("═" * 30)

        except Exception as e:
            print(f"📊 Metrics error: {e}")

    def stop(self):
        """Stop monitoring"""
        self.running = False

def main():
    """Main execution loop"""
    print("JanuSec Live Zeek Integration Test")
    print("=" * 50)

    # Initialize components
    simulator = ZeekEventSimulator()
    monitor = LiveMonitor()

    # Start decision monitoring thread
    decision_thread = threading.Thread(target=monitor.check_decisions, daemon=True)
    decision_thread.start()

    # Event generation loop
    scenario_count = 0

    try:
        while True:
            scenario_count += 1
            print(f"\n🎬 Scenario {scenario_count}")

            # Send different event types in sequence
            events_to_send = []

            if scenario_count % 4 == 1:
                # Benign traffic burst
                events_to_send = [simulator.generate_benign_conn_event() for _ in range(3)]
                print("📊 Sending: 3 benign connection events")

            elif scenario_count % 4 == 2:
                # Suspicious DNS activity
                events_to_send = [simulator.generate_suspicious_dns_event() for _ in range(5)]
                print("🔍 Sending: 5 suspicious DNS events (high NXDOMAIN)")

            elif scenario_count % 4 == 3:
                # Malicious beacon
                events_to_send = [simulator.generate_malicious_beacon_event()]
                print("🚨 Sending: 1 C2 beacon event (long duration, low volume)")

            else:
                # Office macro attack
                events_to_send = [simulator.generate_office_macro_attack()]
                print("⚡ Sending: 1 Office macro PowerShell attack")

            # Send events
            for event in events_to_send:
                event_id = monitor.send_event(event)
                if event_id:
                    time.sleep(0.5)  # Brief pause between events

            # Show metrics every few scenarios
            if scenario_count % 3 == 0:
                monitor.get_metrics()

            # Wait before next scenario
            time.sleep(5)

            # Summary every 10 scenarios
            if scenario_count % 10 == 0:
                print(f"\n📊 Summary after {scenario_count} scenarios:")
                print(f"   Events sent: {monitor.events_sent}")
                print(f"   Decisions tracked: {len(monitor.decisions_tracked)}")

                # Show verdict distribution
                verdicts = {}
                for decision_data in monitor.decisions_tracked.values():
                    verdict = decision_data.get("verdict", "pending")
                    verdicts[verdict] = verdicts.get(verdict, 0) + 1

                for verdict, count in verdicts.items():
                    print(f"   {verdict}: {count}")

    except KeyboardInterrupt:
        print("\n🛑 Stopping Zeek integration test...")
        monitor.stop()
        print("✅ Test completed!")

if __name__ == "__main__":
    main()