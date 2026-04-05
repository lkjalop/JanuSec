# Visual Output Comparison - Current vs Enhanced

**Quick visual guide:** See the difference at a glance

---

## 🔴 CURRENT OUTPUT (What Analyst Sees Now)

```
┌─────────────────────────────────────────────────────────────────┐
│ Row 1: powershell.exe                                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Summary: Mock summary for powershell.exe: likely suspicious    │
│          based on hashes and factors.                           │
│                                                                 │
│ Risk Level: High (7.0)                                          │
│ Recommendation: Quarantine                                      │
│ Playbook: 04_isolate_host                                       │
│                                                                 │
│ MITRE: T1055 (Associated factor encoded_powershell)             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

ANALYST REACTION:
❓ Why is this suspicious?
❓ What does "encoded powershell" mean?
❓ How do I quarantine it? What command?
❓ What damage can this cause?
❓ Is this a false positive?
❓ What should I do first?

⏱️ TIME TO TRIAGE: 20 minutes (Googling, manual research)
```

---

## 🟢 ENHANCED OUTPUT (What Analyst Will See)

```
╔═══════════════════════════════════════════════════════════════════╗
║ powershell.exe - CRITICAL (DREAD 9.2)                            ║
║ Confidence: 95% | Priority: P1 - Immediate Action Required       ║
║ Host: INFECTED-01 | User: user1                                  ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║ 🔴 WHAT'S SUSPICIOUS HERE                                        ║
║ • Encoded PowerShell (-e flag with Base64 payload)               ║
║   Context: Decodes to '$client' → likely C2 callback             ║
║   Why it matters: Top malware indicator, hides malicious code    ║
║                                                                   ║
║ • Execution policy bypass (-ExecutionPolicy Bypass)              ║
║   Context: Disables script signing enforcement                   ║
║   Why it matters: Attackers use this to run unsigned scripts     ║
║                                                                   ║
║ • Spawned by excel.exe (Microsoft Office)                        ║
║   Context: Excel should NEVER spawn PowerShell                   ║
║   Why it matters: #1 indicator of phishing macro attack          ║
║                                                                   ║
║ • Located in %TEMP% directory                                    ║
║   Context: C:\Users\user\AppData\Local\Temp\ps.exe              ║
║   Why it matters: Malware staging area, not legit install path   ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║ 💥 DREAD DAMAGE ANALYSIS (10/10 - CRITICAL)                      ║
║                                                                   ║
║ If this is malicious (95% confident), attacker can:              ║
║ 🔴 Steal credentials (Mimikatz, browser passwords, keylogging)   ║
║ 🔴 Exfiltrate data (documents, emails, screenshots)              ║
║ 🔴 Lateral movement (pivot to DC using stolen creds)             ║
║ 🔴 Deploy ransomware across network                              ║
║ 🔴 Install persistent backdoors (scheduled tasks, registry)      ║
║ 🔴 Disable security (AV, EDR, clear logs)                        ║
║                                                                   ║
║ Exploitability: TRIVIAL (9/10)                                   ║
║ • User opens phishing email with .xlsm attachment                ║
║ • User clicks "Enable Macros" → PowerShell executes              ║
║ • No admin rights needed (runs as user)                          ║
║ • Pre-built macro generators exist (Metasploit, Cobalt Strike)   ║
║                                                                   ║
║ Business Impact: Complete host compromise. If user1 has domain   ║
║ admin privileges → ENTIRE DOMAIN AT RISK within hours.           ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║ 🎯 FAST DECISION TREE (Est. 5-10 min)                            ║
║                                                                   ║
║ Step 1: ISOLATE HOST IMMEDIATELY ⚠️ P0 - DO THIS NOW             ║
║ ┌─────────────────────────────────────────────────────────────┐  ║
║ │ EDR Console:                                                │  ║
║ │ Isolate-Host -HostName INFECTED-01 -Reason 'Active C2'     │  ║
║ │                                                             │  ║
║ │ Purpose: Cut off attacker C2, prevent lateral movement     │  ║
║ │ [📋 Copy Command]                                           │  ║
║ └─────────────────────────────────────────────────────────────┘  ║
║ ⚠️ DO NOT SKIP - Isolation is mandatory for active C2           ║
║                                                                   ║
║ Step 2: Decode PowerShell Command                                ║
║ ┌─────────────────────────────────────────────────────────────┐  ║
║ │ PowerShell:                                                 │  ║
║ │ [System.Text.Encoding]::UTF8.GetString(                    │  ║
║ │   [System.Convert]::FromBase64String('JABjAGwAaQBlAG4AdAA') │  ║
║ │ )                                                           │  ║
║ │                                                             │  ║
║ │ Expected: Full decoded script (C2 IP/domain visible)       │  ║
║ │ Purpose: Identify C2 infrastructure for blocking           │  ║
║ │ [📋 Copy Command]                                           │  ║
║ └─────────────────────────────────────────────────────────────┘  ║
║ ✅ If C2 domain found → add to Step 3                            ║
║                                                                   ║
║ Step 3: Block C2 Infrastructure                                  ║
║ ┌─────────────────────────────────────────────────────────────┐  ║
║ │ Firewall/Proxy:                                             │  ║
║ │ Block-Domain -Domain <decoded_c2_domain> -Scope Enterprise │  ║
║ │                                                             │  ║
║ │ Purpose: Prevent other compromised hosts from calling home │  ║
║ │ [📋 Copy Command]                                           │  ║
║ └─────────────────────────────────────────────────────────────┘  ║
║                                                                   ║
║ Step 4: Collect Forensic Evidence                                ║
║ ┌─────────────────────────────────────────────────────────────┐  ║
║ │ KAPE:                                                       │  ║
║ │ kape.exe --tsource C: --tdest D:\Cases\INFECTED-01 \       │  ║
║ │          --tflush --target !SANS_Triage                     │  ║
║ │                                                             │  ║
║ │ Collects: Registry, event logs, prefetch, MFT, browser     │  ║
║ │ Duration: 10-15 minutes                                     │  ║
║ │ [📋 Copy Command]                                           │  ║
║ └─────────────────────────────────────────────────────────────┘  ║
║                                                                   ║
║ Step 5: Check Lateral Movement                                   ║
║ ┌─────────────────────────────────────────────────────────────┐  ║
║ │ PowerShell:                                                 │  ║
║ │ Get-WinEvent -FilterHashtable @{                           │  ║
║ │   LogName='Security';                                       │  ║
║ │   Id=4624,4625;                                             │  ║
║ │   StartTime=(Get-Date).AddHours(-24)                        │  ║
║ │ } | Where-Object {$_.Properties[5].Value -eq 'user1'}      │  ║
║ │                                                             │  ║
║ │ Purpose: Find all hosts user1 logged into (stolen creds)   │  ║
║ │ Red flags: Logins to DC, file servers, multiple hosts      │  ║
║ │ [📋 Copy Command]                                           │  ║
║ └─────────────────────────────────────────────────────────────┘  ║
║ ❌ If user1 logged into other hosts → ISOLATE THOSE TOO          ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║ ⚠️ MISSING TELEMETRY - COLLECT THESE LOGS                        ║
║                                                                   ║
║ 🔴 CRITICAL GAPS:                                                 ║
║ • No PowerShell Event 4104 (script block logging)                ║
║   Why critical: Can't see FULL decoded script content            ║
║   How to get: Enable via GPO → Windows PowerShell settings       ║
║   Urgency: HIGH - Critical for future PowerShell investigations  ║
║                                                                   ║
║ • No network traffic logs (firewall/proxy)                       ║
║   Why critical: Can't confirm C2 IP/domain or exfil volume       ║
║   How to get: Query firewall, proxy, Zeek/Suricata               ║
║   What to query:                                                  ║
║     - INFECTED-01 outbound connections (last 24 hours)           ║
║     - HTTPS to non-corporate domains                             ║
║     - DNS queries (DGA detection)                                ║
║   Urgency: HIGH - Needed to identify C2 infrastructure           ║
║                                                                   ║
║ • No email logs (phishing source)                                ║
║   Why critical: Can't trace malicious Excel file origin          ║
║   How to get: Query Exchange/O365 MessageTrace                   ║
║   What to query:                                                  ║
║     - Emails to user1 with .xlsm attachments                     ║
║     - Sender domain/IP (likely spoofed invoice)                  ║
║     - Subject line (likely "Invoice", "Receipt")                 ║
║   Urgency: MEDIUM - Helps identify campaign scope                ║
║                                                                   ║
║ • No registry persistence check                                  ║
║   Why critical: Attacker may have installed persistence          ║
║   How to get: Run KAPE with --target RegistryASEPs               ║
║   What to check:                                                  ║
║     - HKCU\...\Run, HKLM\...\Run                                 ║
║     - Scheduled tasks (schtasks /query /v)                       ║
║     - WMI Event Subscriptions                                    ║
║   Urgency: HIGH - If persistence exists, reimaging won't help    ║
║                                                                   ║
║ • No AD/IAM logs (credential theft check)                        ║
║   Why critical: If creds dumped, attacker pivots to other accts  ║
║   How to get: Query Active Directory or Okta                     ║
║   What to query:                                                  ║
║     - Event 4624 (Logon) for user1 on OTHER hosts                ║
║     - Event 4768 (Kerberos TGT requests)                         ║
║     - Event 4672 (Special privileges assigned)                   ║
║     - Okta: Login history - unusual IPs/countries?               ║
║   Urgency: CRITICAL - If creds stolen, entire domain at risk     ║
║                                                                   ║
║ • No EDR process tree (full execution chain)                     ║
║   Why critical: Can't see child processes spawned by PowerShell  ║
║   How to get: CrowdStrike/SentinelOne/Defender ATP timeline      ║
║   What to look for:                                               ║
║     - excel.exe → powershell.exe → ??? (what came next?)         ║
║     - Post-exploit tools: cmd, net, nltest, tasklist             ║
║     - Mimikatz: lsass.exe access, sekurlsa::logonpasswords       ║
║     - Ransomware: vssadmin, bcdedit (shadow/boot tampering)      ║
║   Urgency: CRITICAL - Tells us how far compromise went           ║
║                                                                   ║
║ 📊 COLLECTION PRIORITY:                                           ║
║ Immediate (next 1 hour):                                          ║
║   🔴 Firewall logs from INFECTED-01                               ║
║   🔴 EDR process tree                                             ║
║   🔴 Event 4688 (process creations)                               ║
║                                                                   ║
║ High Priority (next 4 hours):                                     ║
║   🟠 KAPE triage collection                                       ║
║   🟠 AD Event 4624/4768 for user1                                 ║
║   🟠 PowerShell Event 4104                                        ║
║                                                                   ║
║ Medium Priority (next 24 hours):                                  ║
║   🟡 Email logs (phishing source)                                 ║
║   🟡 Proxy/DNS logs                                               ║
║   🟡 File share access logs                                       ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║ 🛠️ REMEDIATION STEPS                                             ║
║                                                                   ║
║ P0 - RIGHT NOW:                                                   ║
║   ✅ Isolate INFECTED-01 (EDR or physically disconnect NIC)      ║
║   ✅ Decode PowerShell, block C2 domain/IP at firewall           ║
║                                                                   ║
║ P1 - Within 1 hour:                                               ║
║   ✅ Collect forensics (KAPE triage)                              ║
║   ✅ Reset user1 credentials (assume password compromised)       ║
║                                                                   ║
║ P1 - Within 2 hours:                                              ║
║   ✅ Hunt lateral movement (check user1 logins on other hosts)   ║
║                                                                   ║
║ P2 - Within 4 hours:                                              ║
║   ✅ Reimage INFECTED-01 (full wipe, rebuild from gold image)    ║
║                                                                   ║
║ P2 - Within 24 hours:                                             ║
║   ✅ Hunt campaign scope (did others get same phishing email?)   ║
║                                                                   ║
║ User Impact: user1 loses access for 4-8 hours (provide loaner)   ║
║ Estimated Total Time: 4-8 hours for full IR cycle                ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║ 📌 TL;DR RECOMMENDATION                                           ║
║                                                                   ║
║ Verdict: 🔴 ACTIVE MALWARE - Excel macro phishing → PowerShell   ║
║          C2 implant (95% confident)                               ║
║                                                                   ║
║ Immediate Action:                                                 ║
║   1. ISOLATE INFECTED-01 NOW (before reading rest of report)     ║
║   2. Decode PowerShell to find C2, block it enterprise-wide      ║
║   3. Reset user1 password + force MFA enrollment                 ║
║                                                                   ║
║ Next Steps:                                                       ║
║   1. Collect KAPE forensics + network logs                        ║
║   2. Hunt lateral movement (AD Event 4624 for user1)             ║
║   3. Reimage host (don't just "clean")                            ║
║   4. Search email for campaign scope (.xlsm attachments)          ║
║                                                                   ║
║ 📞 Need Help?                                                     ║
║   Internal Runbook: https://confluence.../SOC/RB-042             ║
║   Escalation: Slack #soc-tier2-escalations                        ║
║   External Intel: @malwrhunterteam Twitter for Excel macro IOCs  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

ANALYST REACTION:
✅ Crystal clear why it's suspicious (encoded PowerShell from Excel)
✅ Understand damage (creds, lateral movement, ransomware)
✅ Know EXACTLY what to do (5 steps with copy-paste commands)
✅ Know what logs to collect (6 critical telemetry sources)
✅ High confidence (95%) this is real malware, not false positive

⏱️ TIME TO TRIAGE: 5 minutes (no Googling needed)
💰 COST: $0.003 per alert (vs $0.00035)
💵 SAVINGS: 15 min analyst time = $12.50 saved
🎯 NET ROI: +$12.497 per alert
```

---

## 📊 Summary Table

| Metric | CURRENT | ENHANCED | Improvement |
|--------|---------|----------|-------------|
| **Lines of output** | 8 lines | 200+ lines | **Comprehensive** |
| **Clarity** | ⭐ | ⭐⭐⭐⭐⭐ | **+400%** |
| **Actionability** | ⭐ | ⭐⭐⭐⭐⭐ | **+400%** |
| **Copy-paste commands** | 0 | 5 commands | **∞** |
| **Missing telemetry guidance** | ❌ | ✅ 6 gaps | **NEW** |
| **Damage scenarios** | ❌ | ✅ 6 scenarios | **NEW** |
| **Confidence score** | ❌ | ✅ 95% | **NEW** |
| **Time to triage** | 20 min | 5 min | **-75%** |
| **Cost per alert** | $0.00035 | $0.003 | **+757%** |
| **Net value** | $0 | +$12.497 | **∞** |

---

## 🎯 Key Takeaway

**CURRENT OUTPUT:** "This is suspicious. Figure it out yourself."

**ENHANCED OUTPUT:** "This is malware. Here's why, here's the damage, here's what to do step-by-step, here's what logs you need, here's where to get help."

**The difference between useless and ACTIONABLE.**
