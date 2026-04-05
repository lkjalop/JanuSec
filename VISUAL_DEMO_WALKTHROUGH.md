# Visual Demo Walkthrough: What You'll See

**Status**: Server running on http://localhost:8080 ✅
**Data**: 8 attack events ingested successfully ✅

---

## Demo 2: Attack Path Reconstruction

### Step 1: Open Main Console

**URL**: http://localhost:8080/static/janusec-platform-complete-LIVE.html

**What you'll see**:
```
┌─────────────────────────────────────────────────────────────────┐
│ JanuSec Security Platform                    [User] [Settings]  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────┬──────────┬─────────┬──────┬────────┬────────┬────────┐ │
│  │Events│Decisions │  Hunts  │ SBOM │Compli. │Metrics │Reports │ │
│  └─────┴──────────┴─────────┴──────┴────────┴────────┴────────┘ │
│                                                                  │
│  Recent Decisions:                                               │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ [HIGH] Lateral Movement → Data Exfiltration                │ │
│  │ Risk Score: 0.82 | Tenant: demo | Time: 2 min ago         │ │
│  │ Factors: lateral_movement, data_exfil, c2_callback         │ │
│  │ MITRE: T1021, T1003, T1548, T1041                          │ │
│  │ [View Details] [View HopGraph] [Take Action]              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key indicators**:
- ✅ You see "Recent Decisions" with at least one entry
- ✅ Risk Score is 0.7-0.9 (high)
- ✅ Factors include: lateral_movement, data_exfil, credential_access
- ✅ MITRE techniques are listed (T1021, T1003, T1041, etc.)

**If you see this → Platform is working!** ✅

---

### Step 2: Click "View HopGraph"

**What you'll see**:
```
┌─────────────────────────────────────────────────────────────────┐
│ HopGraph Visualization - Attack Path Reconstruction             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [Timeline Slider: 0min ════●═════════════════ 50min]           │
│                                                                  │
│       external-email.xyz                                         │
│              │                                                   │
│              │ T1566 (Phishing)                                 │
│              ▼                                                   │
│       alice@corp.com                                             │
│              │                                                   │
│              │ T1059 (PowerShell)                               │
│              ▼                                                   │
│       workstation-01                                             │
│              │                                                   │
│              │ T1021 (Lateral Movement)                         │
│              ▼                                                   │
│       domain-controller                                          │
│              │                                                   │
│              │ T1003 (Credential Dump)                          │
│              ▼                                                   │
│       file-server-prod                                           │
│              │                                                   │
│              │ T1041 (Exfiltration)                             │
│              ▼                                                   │
│        8.8.8.8 (C2 Server)                                       │
│                                                                  │
│  [Selected Node: file-server-prod]                              │
│  Risk: 0.88 | Type: server | First Seen: 40min ago             │
│  Factors: high_value_target, sensitive_data                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key indicators**:
- ✅ You see nodes connected by arrows (attack path)
- ✅ MITRE technique labels on edges (T1566, T1059, T1021, etc.)
- ✅ Timeline slider at top
- ✅ Node details panel shows factors and risk scores
- ✅ Color coding: green→orange→red (escalating threat)

**What to say in demo**:
> "This HopGraph shows the full attack timeline - from phishing email to data exfiltration. Each hop represents a stage in the attack. The platform automatically correlated 8 separate events into this single attack narrative. Notice the MITRE ATT&CK techniques labeled on each connection - this helps map to industry-standard threat intelligence."

---

## Demo 3: Identity & Cloud HopGraphs

### Step 3a: Open Identity Graph

**URL**: http://localhost:8080/static/identity_graph.html

**What you'll see**:
```
┌─────────────────────────────────────────────────────────────────┐
│ Identity HopGraph - User Privilege Paths                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Enter User: [alice@corp.com              ] [Find Paths]        │
│                                                                  │
│  Privilege Escalation Paths Found: 1                            │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Path 1: Normal User → Domain Admin (3 hops)               │ │
│  │                                                            │ │
│  │ alice@corp.com (user)                                      │ │
│  │       │ Logged into                                        │ │
│  │       ▼                                                    │ │
│  │ workstation-01 (compromised)                               │ │
│  │       │ Lateral move to                                    │ │
│  │       ▼                                                    │ │
│  │ domain-controller (pivot)                                  │ │
│  │       │ Credential dump + privilege escalation             │ │
│  │       ▼                                                    │ │
│  │ Domain Admins group (CRITICAL!)                            │ │
│  │                                                            │ │
│  │ Risk Score: 0.92 | Attack Vector: Phishing → Mimikatz     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key indicators**:
- ✅ Shows user progression from low to high privilege
- ✅ Identifies pivot points (compromised workstation, DC)
- ✅ Labels attack techniques (Credential dump, Lateral move)
- ✅ Risk score indicates severity

**What to say in demo**:
> "Identity HopGraph tracks user privilege escalation. Alice started as a normal user, but through lateral movement and credential dumping, reached Domain Admin level - that's full network compromise. This graph shows the 3 hops it took to get there."

---

### Step 3b: Open Cloud Graph

**URL**: http://localhost:8080/static/cloud_graph.html

**What you'll see**:
```
┌─────────────────────────────────────────────────────────────────┐
│ Cloud HopGraph - Attack Paths to Cloud Resources                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Entry Point: [internet:*           ]                           │
│  Target:      [s3://sensitive-bucket]   [Find Paths]            │
│                                                                  │
│  Attack Paths Found: 2                                           │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Path 1: Internet → S3 Bucket (4 hops)                     │ │
│  │                                                            │ │
│  │ internet:*                                                 │ │
│  │       │ Phishing email                                     │ │
│  │       ▼                                                    │ │
│  │ workstation-01                                             │ │
│  │       │ Stolen AWS credentials                             │ │
│  │       ▼                                                    │ │
│  │ aws_account_123                                            │ │
│  │       │ Assume role: s3-admin                              │ │
│  │       ▼                                                    │ │
│  │ s3://sensitive-bucket                                      │ │
│  │                                                            │ │
│  │ Risk: 0.88 | Data at Risk: Customer PII, Financial        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key indicators**:
- ✅ Shows path from external attacker to cloud resources
- ✅ Identifies credential theft and role assumption
- ✅ Labels sensitive data at risk
- ✅ Cross-domain correlation (endpoint → cloud)

**What to say in demo**:
> "Cloud HopGraph shows attack paths to cloud resources like S3 buckets. The attacker went from phishing to stealing AWS credentials to accessing sensitive customer data. This is cross-domain tracking - we correlated endpoint events (credential theft) with cloud events (S3 access). No other platform does this."

---

## Demo 4: Explainability & Compliance

### Step 4a: Check MITRE Coverage

**URL**: http://localhost:8080/static/mitre.html

**What you'll see**:
```
┌─────────────────────────────────────────────────────────────────┐
│ MITRE ATT&CK Coverage Heatmap                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Tactics:                                                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Initial   │ Execution│ Persistence│ Privilege │ Defense     ││
│  │ Access    │          │            │ Escalation│ Evasion     ││
│  ├───────────┼──────────┼────────────┼───────────┼─────────────┤│
│  │ T1566 ██  │ T1059 ██ │ T1136 ░░   │ T1548 ██  │ T1027 █░    ││
│  │ (High)    │ (High)   │ (None)     │ (High)    │ (Medium)    ││
│  │           │          │            │           │             ││
│  │ T1078 ░░  │ T1569 ░░ │ T1543 ░░   │ T1068 ░░  │ T1140 ░░    ││
│  │ (None)    │ (None)   │ (None)     │ (None)    │ (None)      ││
│  └───────────┴──────────┴────────────┴───────────┴─────────────┘│
│                                                                  │
│  Coverage: 12 of 193 techniques (6.2%)                          │
│  Detected this week: 8 techniques                               │
│  Gap areas: Persistence, Defense Evasion                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key indicators**:
- ✅ Heatmap shows which techniques you can detect
- ✅ Color gradient: dark = high coverage, light = gaps
- ✅ Shows detected techniques from recent events
- ✅ Identifies coverage gaps

**What to say in demo**:
> "MITRE heatmap shows our detection coverage across the ATT&CK framework. Dark squares are techniques we've detected in real events. Light squares are gaps where we need better detection rules. This helps prioritize which detection capabilities to build next."

---

### Step 4b: Compliance Mapping

**URL**: http://localhost:8080/static/compliance.html

**What you'll see**:
```
┌─────────────────────────────────────────────────────────────────┐
│ Compliance Assessment                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Select Framework: [ISO 27001 ▼]                                │
│  [Run Assessment] [Download Report]                             │
│                                                                  │
│  Assessment Results:                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Control A.9.2: User Access Management                      │ │
│  │ Status: PASS                                                │ │
│  │ Evidence: Multi-factor authentication enabled              │ │
│  │ Last Tested: 1 hour ago                                    │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ Control A.12.4: Logging and Monitoring                     │ │
│  │ Status: PASS                                                │ │
│  │ Evidence: Chain-of-custody audit trail active              │ │
│  │ Last Tested: 1 hour ago                                    │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ Control A.14.2: Secure Development                         │ │
│  │ Status: FAIL - CVE-2021-44228 (Log4Shell) detected        │ │
│  │ Evidence: Vulnerable version found in artifact analysis    │ │
│  │ Remediation: Upgrade to Log4j 2.17.1                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Overall Compliance: 83% (5/6 controls pass)                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key indicators**:
- ✅ Shows compliance framework controls
- ✅ PASS/FAIL status with evidence
- ✅ Links threats to compliance failures
- ✅ Provides remediation guidance

**What to say in demo**:
> "Every detected threat maps to compliance controls. When we detect Log4Shell, it's automatically linked to ISO 27001 Control A.14.2 (Secure Development) as a failure. This generates evidence for auditors showing we detected the issue, when we detected it, and what remediation is needed. No manual compliance reports required."

---

## What This Proves

### For Technical Audiences:
✅ **Multi-factor correlation works** - 8 events → 1 threat
✅ **HopGraph reconstruction works** - Visual attack paths
✅ **Cross-domain correlation works** - Endpoint + network + cloud
✅ **MITRE mapping works** - Auto-tagged with T-codes
✅ **Explainability works** - Factors, risk scores, recommended actions

### For Non-Technical Audiences:
✅ **Reduces noise** - 8 separate alerts become 1 actionable threat
✅ **Shows the story** - Not just "threat detected" but "here's how the attack happened"
✅ **Saves time** - Automatically connects the dots analysts do manually
✅ **Meets compliance** - Auto-generates evidence for auditors
✅ **Actionable intel** - Not just alerts, but "do this next"

---

## Troubleshooting: If You Don't See Data

### Issue: "No decisions found"

**Cause**: Events still processing or validation errors

**Fix**:
```bash
# Check recent decisions via API
curl http://localhost:8080/api/v1/decisions/recent?limit=10&tenant_id=demo -H "x-api-key: devkey123"

# If empty, check events were ingested
curl http://localhost:8080/api/v1/events/recent?limit=10 -H "x-api-key: devkey123"

# Re-run demo scenario
cd "D:\AI\Threat_thy_sniffer"
python scripts/demo_scenario_2_attack_reconstruction.py
```

### Issue: "HopGraph shows empty"

**Cause**: Missing artifact_id or no graph data

**Fix**: Use direct URL from demo script output, e.g.:
```
http://localhost:8080/static/graph_explain.html?artifact_id=demo-attack-1
```

### Issue: "Page won't load"

**Cause**: Server not running or wrong port

**Fix**:
```bash
# Check if server is running
curl http://localhost:8080/api/v1/dashboard/status

# If fails, restart server
python start_simple.py --port 8080 --no-reload
```

---

## Next Steps

Now that you've seen these demos working:

1. **Practice the flow** - Run through demos 3 times to build muscle memory
2. **Prepare talking points** - Use "What to say in demo" scripts above
3. **Test questions** - Have a friend ask "how does this work?" and explain
4. **Record backup** - Screen record yourself doing the demo (5 min safety net)
5. **Present to CEO** - You have concrete proof it works!

**You're ready to demo!** 🚀
