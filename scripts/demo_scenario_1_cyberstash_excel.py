#!/usr/bin/env python3
"""
Demo Scenario 1: Analyze Real CyberStash Excel Files

This script processes actual CyberStash threat intelligence data
(cybstash csv1.xlsx and Cyberstash_csv2.xlsx) and demonstrates
row-by-row analysis with explainable AI.

Usage:
    python demo_scenario_1_cyberstash_excel.py

Expected output:
    - Parses Excel files
    - Applies DREAD scoring per row
    - Generates factor attributions
    - Exports analysis results
"""

import os
import sys
import json
import pandas as pd
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def load_cyberstash_excel(filepath: str) -> pd.DataFrame:
    """Load CyberStash Excel file and normalize columns."""
    print(f"📂 Loading: {filepath}")

    try:
        df = pd.read_excel(filepath)
        print(f"✅ Loaded {len(df)} rows from {Path(filepath).name}")
        print(f"Columns: {', '.join(df.columns.tolist())}")
        return df
    except Exception as e:
        print(f"❌ Error loading {filepath}: {e}")
        return None

def analyze_row(row: dict, row_index: int) -> dict:
    """
    Analyze a single row with DREAD scoring and factor attribution.

    This simulates what the CSV analyzer UI does.
    """
    result = {
        'row_number': row_index + 1,
        'original_data': row,
        'factors': [],
        'dread_score': 0.0,
        'verdict': 'unknown',
        'mitre_techniques': [],
        'stride_categories': [],
        'recommended_action': ''
    }

    # Factor detection (simplified for demo)
    factors = []

    # Check for common threat indicators
    process_name = str(row.get('process_name', row.get('Process', ''))).lower()
    file_path = str(row.get('file_path', row.get('Path', ''))).lower()
    sha256 = str(row.get('sha256', row.get('SHA256', '')))

    # Factor 1: Suspicious process names
    suspicious_processes = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32']
    if any(proc in process_name for proc in suspicious_processes):
        factors.append('suspicious_process')
        result['mitre_techniques'].append('T1059')  # Command and Scripting Interpreter

    # Factor 2: Rare/unusual paths
    suspicious_paths = ['temp', 'appdata', 'programdata', 'users\\public']
    if any(path in file_path for path in suspicious_paths):
        factors.append('suspicious_path')

    # Factor 3: No hash = unsigned/unknown
    if not sha256 or sha256 == 'nan' or len(sha256) < 64:
        factors.append('unknown_hash')

    # Factor 4: Process elevation indicators
    if 'admin' in process_name or 'elevated' in str(row).lower():
        factors.append('privilege_elevation')
        result['mitre_techniques'].append('T1548')  # Abuse Elevation Control

    # Calculate DREAD score
    dread_components = {
        'damage': 0.0,
        'reproducibility': 0.0,
        'exploitability': 0.0,
        'affected_users': 0.0,
        'discoverability': 0.0
    }

    if 'suspicious_process' in factors:
        dread_components['damage'] = 0.7
        dread_components['exploitability'] = 0.8

    if 'suspicious_path' in factors:
        dread_components['reproducibility'] = 0.6
        dread_components['discoverability'] = 0.7

    if 'privilege_elevation' in factors:
        dread_components['damage'] = 0.9
        dread_components['affected_users'] = 0.8

    if 'unknown_hash' in factors:
        dread_components['exploitability'] = 0.7

    # Average DREAD components
    dread_score = sum(dread_components.values()) / len(dread_components)

    # Determine verdict
    if dread_score >= 0.7:
        verdict = 'malicious'
    elif dread_score >= 0.4:
        verdict = 'suspicious'
    else:
        verdict = 'benign'

    # STRIDE categories
    stride = []
    if 'privilege_elevation' in factors:
        stride.append('Elevation of Privilege')
    if 'suspicious_process' in factors:
        stride.append('Spoofing')

    # Recommended action
    if verdict == 'malicious':
        recommended_action = 'BLOCK and investigate. Isolate host. Collect forensics.'
    elif verdict == 'suspicious':
        recommended_action = 'ALERT analyst. Monitor for lateral movement.'
    else:
        recommended_action = 'LOG only. Baseline normal behavior.'

    result['factors'] = factors
    result['dread_score'] = round(dread_score, 3)
    result['dread_components'] = dread_components
    result['verdict'] = verdict
    result['stride_categories'] = stride
    result['recommended_action'] = recommended_action

    return result

def main():
    print("="*80)
    print("🎯 Demo Scenario 1: CyberStash Excel Analysis")
    print("="*80)
    print()

    # File paths
    dump_dir = Path(__file__).parent.parent / "dump"
    csv1_path = dump_dir / "cybstash csv1.xlsx"
    csv2_path = dump_dir / "Cyberstash_csv2.xlsx"

    # Check files exist
    if not csv1_path.exists():
        print(f"❌ Missing: {csv1_path}")
        print("Please ensure CyberStash Excel files are in dump/ directory")
        return

    # Load CSV1
    df1 = load_cyberstash_excel(str(csv1_path))
    if df1 is None:
        return

    print()
    print("-"*80)
    print("🔍 Analyzing CSV1 (Row-by-Row)")
    print("-"*80)

    results = []
    for idx, row in df1.iterrows():
        analysis = analyze_row(row.to_dict(), idx)
        results.append(analysis)

        # Print first 5 rows detailed
        if idx < 5:
            print(f"\n📊 Row {analysis['row_number']}:")
            print(f"   Verdict: {analysis['verdict'].upper()}")
            print(f"   DREAD Score: {analysis['dread_score']}")
            print(f"   Factors: {', '.join(analysis['factors']) if analysis['factors'] else 'None'}")
            print(f"   MITRE: {', '.join(analysis['mitre_techniques']) if analysis['mitre_techniques'] else 'None'}")
            print(f"   STRIDE: {', '.join(analysis['stride_categories']) if analysis['stride_categories'] else 'None'}")
            print(f"   Action: {analysis['recommended_action']}")

    # Summary statistics
    print()
    print("-"*80)
    print("📈 Summary Statistics")
    print("-"*80)

    verdicts = [r['verdict'] for r in results]
    print(f"Total rows analyzed: {len(results)}")
    print(f"  Malicious: {verdicts.count('malicious')}")
    print(f"  Suspicious: {verdicts.count('suspicious')}")
    print(f"  Benign: {verdicts.count('benign')}")

    avg_dread = sum(r['dread_score'] for r in results) / len(results)
    print(f"\nAverage DREAD score: {avg_dread:.3f}")

    all_factors = [f for r in results for f in r['factors']]
    unique_factors = set(all_factors)
    print(f"\nFactors detected: {', '.join(unique_factors)}")

    all_mitre = [m for r in results for m in r['mitre_techniques']]
    unique_mitre = set(all_mitre)
    print(f"MITRE techniques: {', '.join(unique_mitre)}")

    # Export results
    output_file = dump_dir / "demo1_analysis_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print()
    print(f"✅ Results exported to: {output_file}")
    print()
    print("="*80)
    print("✅ Demo 1 Complete!")
    print("="*80)
    print()
    print("Next steps:")
    print("1. Open http://localhost:8000/static/csv_analyzer.html")
    print(f"2. Upload: {csv1_path.name}")
    print("3. Click 'Load' then 'Deep Analyze'")
    print("4. Compare UI results with this script output")
    print()

if __name__ == "__main__":
    main()
