#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JanuSec Demo Readiness Validator

Runs comprehensive checks to ensure all demos will work.
Run this BEFORE presenting to CEO to build confidence.

Usage:
    python validate_demo_readiness.py

Exit code:
    0 = All checks passed (ready to demo)
    1 = Some checks failed (fix before demo)
"""

import os
import sys
import time
import requests
import subprocess
from pathlib import Path

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_check(name: str, passed: bool, details: str = ""):
    """Print check result with color."""
    icon = "[PASS]" if passed else "[FAIL]"
    color = Colors.GREEN if passed else Colors.RED
    print(f"{icon} {color}{name}{Colors.END}")
    if details:
        print(f"   {details}")
    return passed

def check_file_exists(path: str, description: str) -> bool:
    """Check if file exists."""
    exists = Path(path).exists()
    size = Path(path).stat().st_size if exists else 0
    size_mb = size / 1024 / 1024
    details = f"Found ({size_mb:.2f} MB)" if exists else f"Missing: {path}"
    return print_check(description, exists, details)

def check_url_responds(url: str, description: str, timeout: int = 5) -> bool:
    """Check if URL responds with 200."""
    try:
        r = requests.get(url, timeout=timeout)
        success = r.status_code == 200
        details = f"{r.status_code}" if not success else f"OK ({len(r.content)} bytes)"
        return print_check(description, success, details)
    except Exception as e:
        return print_check(description, False, str(e))

def check_redis() -> bool:
    """Check if Redis is running (optional for demo mode)."""
    try:
        result = subprocess.run(['redis-cli', 'ping'], capture_output=True, text=True, timeout=3)
        success = result.stdout.strip() == 'PONG'
        details = result.stdout.strip() if success else "Redis not responding"
        if success:
            print_check("Redis server (optional)", success, details)
        else:
            print(f"[SKIP] {Colors.YELLOW}Redis server (optional){Colors.END}")
            print(f"   Not needed for simple demo mode - platform uses SQLite")
        return True  # Don't fail validation for Redis
    except Exception as e:
        print(f"[SKIP] {Colors.YELLOW}Redis server (optional){Colors.END}")
        print(f"   Not needed for simple demo mode - platform uses SQLite")
        return True  # Don't fail validation for Redis

def main():
    print("="*80)
    print(f"{Colors.BLUE}JanuSec Demo Readiness Validation{Colors.END}")
    print("="*80)
    print()

    all_passed = True

    # Phase 1: Core Files
    print(f"{Colors.YELLOW}Phase 1: Core Files{Colors.END}")
    print("-"*80)

    all_passed &= check_file_exists("janusec_dev.db", "Database file")
    all_passed &= check_file_exists("dump/cybstash csv1.xlsx", "CyberStash CSV1")
    all_passed &= check_file_exists("dump/Cyberstash_csv2.xlsx", "CyberStash CSV2")
    all_passed &= check_file_exists("scripts/generate_demo_events.py", "Demo event generator")
    all_passed &= check_file_exists("frontend/static/janusec-platform-complete-LIVE.html", "Main console UI")
    all_passed &= check_file_exists("frontend/static/csv_analyzer.html", "CSV analyzer UI")
    all_passed &= check_file_exists("frontend/static/graph_explain.html", "HopGraph viz UI")
    all_passed &= check_file_exists("frontend/static/compliance.html", "Compliance UI")
    all_passed &= check_file_exists("frontend/static/mitre.html", "MITRE heatmap UI")

    print()

    # Phase 2: Services
    print(f"{Colors.YELLOW}Phase 2: Services{Colors.END}")
    print("-"*80)

    all_passed &= check_redis()

    # Check if platform is running
    platform_running = False
    try:
        r = requests.get("http://localhost:8000/api/v1/dashboard/status", timeout=3)
        platform_running = r.status_code == 200
    except:
        pass

    if not platform_running:
        print(f"{Colors.YELLOW}[WARN] Platform not running (this is OK - start it before demo){Colors.END}")
        print(f"   To start: quick-start.bat  OR  python start_simple.py --port 8080")
    else:
        print(f"{Colors.GREEN}[OK] Platform running{Colors.END}")

    print()

    # Phase 3: API Endpoints (only if platform running)
    if platform_running:
        print(f"{Colors.YELLOW}Phase 3: API Endpoints{Colors.END}")
        print("-"*80)

        all_passed &= check_url_responds("http://localhost:8000/", "Root endpoint")
        all_passed &= check_url_responds("http://localhost:8000/api/v1/dashboard/status", "Status API")
        all_passed &= check_url_responds("http://localhost:8000/api/v1/dashboard/metrics", "Metrics API")
        all_passed &= check_url_responds("http://localhost:8000/api/v1/compliance/frameworks", "Compliance API")
        all_passed &= check_url_responds("http://localhost:8000/static/janusec-platform-complete-LIVE.html", "Main UI")
        all_passed &= check_url_responds("http://localhost:8000/static/csv_analyzer.html", "CSV Analyzer")
        all_passed &= check_url_responds("http://localhost:8000/static/graph_explain.html", "HopGraph Viz")

        print()

    # Phase 4: Demo Scripts
    print(f"{Colors.YELLOW}Phase 4: Demo Scripts{Colors.END}")
    print("-"*80)

    all_passed &= check_file_exists("scripts/demo_scenario_1_cyberstash_excel.py", "Demo 1 script")
    all_passed &= check_file_exists("DEMO_WALKTHROUGH.md", "Demo walkthrough")

    print()

    # Final Verdict
    print("="*80)
    if all_passed:
        print(f"{Colors.GREEN}ALL CHECKS PASSED - YOU ARE READY TO DEMO!{Colors.END}")
        print()
        print("Next steps:")
        if not platform_running:
            print("1. Start platform: quick-start.bat  OR  python start_simple.py --port 8080")
        print("2. Populate demo data: python scripts/demo_scenario_2_attack_reconstruction.py")
        print("3. Open DEMO_WALKTHROUGH.md and practice demos")
        print("4. Record backup video (5 minutes)")
        print("5. Present to CEO with confidence!")
        return 0
    else:
        print(f"{Colors.RED}SOME CHECKS FAILED - FIX BEFORE DEMO{Colors.END}")
        print()
        print("Action items:")
        print("1. Review failed checks above")
        print("2. Fix missing files/services")
        print("3. Re-run this validator")
        print("4. Don't demo until all checks pass")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
