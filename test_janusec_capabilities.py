#!/usr/bin/env python3
"""
JanuSec Threat Detection Capability Test
Testing against CybStash threat intelligence data
"""

import sys
import os
import json
import time
sys.path.append('src')

def simulate_janusec_analysis(event):
    """Simulate how JanuSec would analyze each event (with improved baseline logic)"""
    name = event['process']['name'].lower()
    path = event['process']['path'].lower()
    size = event.get('size', 0)
    signed = event.get('signed', False)

    # JanuSec factors that would be detected
    factors = []
    confidence = 0.1  # Start neutral

    # ENHANCED BASELINE CHECKS - Apply whitelist first to reduce false positives

    # 1. Microsoft Windows Security Components (HIGH CONFIDENCE BENIGN)
    microsoft_security_processes = {
        'mpam-d.exe', 'mpam-fe_bd.exe', 'msmpeng.exe', 'mssense.exe',
        'windefend.exe', 'mpcmdrun.exe', 'nissrv.exe', 'trustedinstaller.exe',
        'svchost.exe', 'wuauclt.exe', 'wudfhost.exe'
    }

    if name in microsoft_security_processes:
        confidence = max(0, confidence - 0.7)  # Strong benign signal
        factors.append('microsoft_security_component')

    # 2. Windows Built-in Tools
    windows_builtin_tools = {
        'snippingtool.exe', 'calc.exe', 'notepad.exe', 'mspaint.exe',
        'taskmgr.exe', 'explorer.exe', 'control.exe'
    }

    if name in windows_builtin_tools:
        confidence = max(0, confidence - 0.5)  # Good benign signal
        factors.append('windows_builtin_tool')

    # 3. Check file path patterns for legitimate software locations
    microsoft_paths = [
        'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
        'c:\\windows\\systemtemp\\', 'c:\\windows\\temp\\',
        'c:\\windows\\softwaredistribution\\'
    ]

    if any(path.startswith(mspath) for mspath in microsoft_paths):
        confidence = max(0, confidence - 0.6)  # High benign confidence for MS paths
        factors.append('microsoft_system_path')

    # 4. Known legitimate software vendors
    trusted_vendor_paths = [
        'c:\\program files\\epson\\', 'c:\\program files (x86)\\epson\\',
        'c:\\program files\\teamviewer\\', 'c:\\program files (x86)\\teamviewer\\',
        'c:\\program files\\freshdesk\\', 'c:\\program files (x86)\\freshdesk\\',
        'c:\\program files\\google\\', 'c:\\program files (x86)\\google\\'
    ]

    if any(path.startswith(tpath) for tpath in trusted_vendor_paths):
        confidence = max(0, confidence - 0.4)  # Moderate benign signal
        factors.append('trusted_vendor_path')

    # NOW APPLY SUSPICIOUS INDICATORS (only if not already marked as benign)

    if confidence > 0.05:  # Only check if not already flagged as benign

        # 1. Suspicious file locations
        if 'temp' in path and 'windows\\temp' not in path:  # Exclude Windows temp
            factors.append('suspicious_location')
            confidence += 0.3

        # 2. Unsigned executables (but less weight for known good paths)
        if not signed and name.endswith('.exe'):
            if any(path.startswith(mspath) for mspath in microsoft_paths):
                confidence += 0.1  # Lower weight for MS paths
            else:
                confidence += 0.2
            factors.append('unsigned_executable')

        # 3. Large files (potential packers)
        if size > 50000000:  # >50MB
            factors.append('large_executable')
            confidence += 0.2

        # 4. Remote access tools (but consider legitimate usage)
        remote_tools = ['teamviewer', 'rdp', 'vnc', 'remote', 'ninja']
        if any(tool in name for tool in remote_tools):
            # If in Program Files, lower confidence (legitimate install)
            if 'program files' in path:
                confidence += 0.2  # Lower weight for installed software
            else:
                confidence += 0.4  # Higher weight for suspicious locations
            factors.append('remote_access_tool')

        # 5. System utilities in suspicious locations
        sys_utils = ['nssm', 'svc', 'service']
        if any(util in name for util in sys_utils):
            factors.append('system_utility')
            confidence += 0.3

        # 6. Third-party software flagged by name (but consider context)
        suspicious_vendors = ['solarwinds', 'tftp']
        if any(vendor in name for vendor in suspicious_vendors):
            factors.append('flagged_vendor')
            confidence += 0.5

        # 7. Obfuscated or long names
        if len(name) > 30:
            factors.append('long_filename')
            confidence += 0.1

    # JanuSec decision logic
    confidence = min(confidence, 0.99)  # Cap at 99%
    confidence = max(confidence, 0.0)   # Floor at 0%

    if confidence >= 0.9:
        verdict = 'MALICIOUS'
        action = 'BLOCK'
    elif confidence >= 0.5:
        verdict = 'SUSPICIOUS'
        action = 'ESCALATE'
    else:
        verdict = 'BENIGN'
        action = 'ALLOW'

    return {
        'confidence': confidence,
        'factors': factors,
        'verdict': verdict,
        'action': action
    }

def main():
    print('=== JANUSEC THREAT DETECTION CAPABILITY TEST ===')
    print('Testing against CybStash threat intelligence data')
    print()

    # Load test data
    with open('D:/AI/Threat_thy_sniffer/dump/janusec_batch2.json', 'r') as f:
        batch_data = json.load(f)

    results = []
    for event in batch_data['events']:
        janusec_result = simulate_janusec_analysis(event)
        cybstash_suspicious = event['details']['suspicious']

        results.append({
            'name': event['process']['name'],
            'janusec_verdict': janusec_result['verdict'],
            'janusec_confidence': janusec_result['confidence'],
            'janusec_factors': janusec_result['factors'],
            'janusec_action': janusec_result['action'],
            'cybstash_suspicious': cybstash_suspicious,
            'cybstash_threat': event['details']['threat_name'],
            'av_ratio': event['details']['av_detection_ratio']
        })

    print('JANUSEC vs CYBSTASH COMPARISON:')
    print('=' * 100)
    print(f"{'STATUS':<8} | {'FILENAME':<35} | {'JANUSEC':<10} | {'CONF':<6} | {'ACTION':<8} | {'CYBSTASH':<10}")
    print('-' * 100)

    correct = 0
    total = 0
    blocked = 0
    escalated = 0
    allowed = 0

    for r in results:
        # Determine if JanuSec got it right
        janusec_flagged = r['janusec_verdict'] in ['SUSPICIOUS', 'MALICIOUS']
        cybstash_flagged = r['cybstash_suspicious']

        match = 'CORRECT' if janusec_flagged == cybstash_flagged else 'MISSED'
        if janusec_flagged == cybstash_flagged:
            correct += 1
        total += 1

        # Count actions
        if r['janusec_action'] == 'BLOCK':
            blocked += 1
        elif r['janusec_action'] == 'ESCALATE':
            escalated += 1
        else:
            allowed += 1

        cybstash_status = 'SUSPICIOUS' if r['cybstash_suspicious'] else 'CLEAN'

        print(f"{match:<8} | {r['name'][:35]:<35} | {r['janusec_verdict']:<10} | {r['janusec_confidence']:<6.2f} | {r['janusec_action']:<8} | {cybstash_status:<10}")

        if r['janusec_factors']:
            factors_str = ', '.join(r['janusec_factors'][:3])
            print(f"{'':8} | {'Factors: ' + factors_str:<35} | {'':10} | {'':6} | {'':8} | {'':10}")

    accuracy = (correct / total) * 100

    print('\n' + '=' * 100)
    print('JANUSEC PERFORMANCE SUMMARY:')
    print(f"Accuracy: {accuracy:.1f}% ({correct}/{total})")
    print(f"Actions: {blocked} BLOCKED, {escalated} ESCALATED, {allowed} ALLOWED")

    cybstash_suspicious_count = sum(1 for r in results if r['cybstash_suspicious'])
    janusec_flagged_count = sum(1 for r in results if r['janusec_verdict'] != 'BENIGN')

    print(f"CybStash found: {cybstash_suspicious_count} suspicious files")
    print(f"JanuSec flagged: {janusec_flagged_count} suspicious files")

    print('\nTOP THREATS DETECTED BY BOTH:')
    both_detected = [r for r in results if r['cybstash_suspicious'] and r['janusec_verdict'] != 'BENIGN']
    for i, r in enumerate(both_detected[:5], 1):
        print(f"{i}. {r['name']} (Conf: {r['janusec_confidence']:.2f}, Action: {r['janusec_action']})")

    print('\nMISSED THREATS (CybStash found, JanuSec missed):')
    missed = [r for r in results if r['cybstash_suspicious'] and r['janusec_verdict'] == 'BENIGN']
    for r in missed:
        print(f"- {r['name']} (AV ratio: {r['av_ratio']})")

    print('\nFALSE POSITIVES (JanuSec flagged, CybStash clean):')
    false_pos = [r for r in results if not r['cybstash_suspicious'] and r['janusec_verdict'] != 'BENIGN']
    for r in false_pos:
        print(f"- {r['name']} (Conf: {r['janusec_confidence']:.2f}, Factors: {', '.join(r['janusec_factors'][:2])})")

if __name__ == '__main__':
    main()