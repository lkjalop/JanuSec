# RF Security Career Path - Leveraging JanuSec Experience

**Date:** 2025-01-21
**Goal:** Transition from software/AI security → Radiofrequency (RF) security
**Starting Point:** JanuSec platform development experience

---

## 🎯 What is RF Security?

**Radiofrequency Security** focuses on:
1. **Wireless protocol security** - WiFi, Bluetooth, Zigbee, LoRa, cellular (4G/5G)
2. **Signal intelligence (SIGINT)** - Intercepting, analyzing, jamming RF communications
3. **Hardware security** - RFID, NFC, proximity cards, IoT devices
4. **SDR (Software-Defined Radio)** - Using programmable radios to analyze/attack RF
5. **Physical security** - Badge cloning, keyless entry hacking, radio jamming

**Real-world examples:**
- Hacking keyless car entry (relay attacks)
- Cloning RFID badges to bypass physical security
- Intercepting unencrypted Bluetooth communications
- Jamming GPS signals
- Analyzing 5G network vulnerabilities

---

## 🔄 Transferable Skills from JanuSec Project

### **1. Signal Processing & Pattern Recognition**

**JanuSec Skill:**
- Analyzing security events for patterns (correlation, HopGraph)
- Identifying anomalies in process lineage, network traffic
- MITRE ATT&CK technique mapping

**RF Security Equivalent:**
- **Signal analysis** - Analyzing RF waveforms for anomalies
- **Protocol decoding** - Identifying WiFi/Bluetooth packets, demodulation
- **Spectrum analysis** - Finding hidden/rogue transmitters
- **Pattern recognition** - Detecting replay attacks, jamming

**Example:** JanuSec detects "unusual PowerShell execution from Excel" by correlating parent-child process relationships. In RF security, you detect "unusual WiFi beacon frames" by correlating signal strength, timing, and MAC addresses to find rogue access points.

---

### **2. Data Pipeline Architecture**

**JanuSec Skill:**
- 21-stage deep analyze pipeline (GeoIP, ThreatIntel, DREAD, MITRE, Graph, LLM)
- Batch processing (20 rows at a time to control latency)
- Async background workers

**RF Security Equivalent:**
- **SDR processing pipeline:**
  1. Capture raw IQ samples (from HackRF, RTL-SDR, USRP)
  2. Demodulate signal (AM, FM, QAM, PSK)
  3. Decode protocol (WiFi, Bluetooth, Zigbee)
  4. Extract metadata (MAC addresses, SSIDs, signal strength)
  5. Correlate with threat intel (known rogue devices)
  6. Generate alerts (e.g., "Deauth attack detected on WiFi channel 6")

**Example:** Build an RF threat detection pipeline similar to JanuSec's CSV analyzer:
1. Capture RF spectrum with SDR
2. Decode protocols (WiFi beacons, Bluetooth advertisements)
3. Run AI model to detect anomalies (e.g., "WiFi deauth flood")
4. LLM triage summary: "What is it? How can attacker use it? What to do?"
5. Playbook: "Block rogue AP, change WiFi password, enable 802.11w PMF"

---

### **3. AI/ML for Threat Detection**

**JanuSec Skill:**
- LLM-powered triage summaries (GPT-4o, Claude, Ollama)
- DREAD scoring, risk assessment
- Graph correlation (HopGraph)

**RF Security Equivalent:**
- **AI-powered RF anomaly detection:**
  - Train ML model to classify normal vs malicious RF signals
  - Example: "Normal WiFi beacon" vs "Evil twin AP" vs "Deauth attack"
- **Signal fingerprinting:**
  - Identify devices by unique RF characteristics (transmitter imperfections)
  - Like how JanuSec fingerprints malware by hash/behavior
- **Predictive jamming detection:**
  - Detect jamming before it fully disrupts communications

**Example Project:** "RF-Sec-Triage" - AI-powered RF threat triage platform
- Input: Captured WiFi/Bluetooth packets (pcap files)
- Output: LLM summary like JanuSec
  ```
  📌 WHAT IS IT?
  Rogue WiFi access point broadcasting SSID "CompanyWiFi" (evil twin).

  💥 EXPLOITABILITY
  Attacker can use this to:
  • Man-in-the-middle employee WiFi connections
  • Steal credentials, session cookies
  • Inject malicious payloads

  ⚡ WHAT TO DO?
  1. Locate rogue AP using WiFi pineapple detector
  2. Deauth all clients connected to rogue AP
  3. Enable WPA3 + 802.11w PMF on corporate WiFi

  📋 CONCISE PLAYBOOK
  Step 1: kismet -c wlan0 --find-rogue-ap
  Step 2: aireplay-ng --deauth 0 -a <rogue_mac> wlan0
  Step 3: Update WiFi config to enable PMF
  ```

---

### **4. Integration & API Development**

**JanuSec Skill:**
- Integrating with SIEM (Splunk, Sentinel), EDR (CrowdStrike), threat intel (VirusTotal)
- RESTful API design (`/api/v1/assessments/deep_analyze`)
- Webhooks, SOAR playbooks

**RF Security Equivalent:**
- **SDR API integrations:**
  - Control HackRF/RTL-SDR via GNU Radio, SoapySDR APIs
  - Integrate with Wireshark (RF packet capture)
  - Push RF alerts to Splunk/Sentinel (just like JanuSec pushes triage results)
- **IoT device API hacking:**
  - Reverse-engineer BLE (Bluetooth Low Energy) APIs
  - Sniff Zigbee/Z-Wave smart home traffic
  - Replay attacks on RFID door locks

**Example:** Build API that captures WiFi packets with SDR and sends to JanuSec for triage:
```python
# rf_capture_api.py
from hackrf import HackRF
import requests

def capture_wifi_packets(duration_sec=60):
    """
    Capture WiFi packets using HackRF SDR
    """
    sdr = HackRF()
    sdr.set_freq(2437e6)  # WiFi channel 6 (2.4 GHz)
    iq_samples = sdr.capture(duration_sec)

    # Demodulate & decode (simplified)
    packets = decode_wifi(iq_samples)

    # Convert to JanuSec format (CSV-like)
    rows = [
        {
            'process_name': pkt['ssid'],
            'source_ip': pkt['source_mac'],
            'dest_ip': pkt['dest_mac'],
            'command_line': pkt['frame_type'],
            'verdict': 'SUSPICIOUS' if is_rogue(pkt) else 'BENIGN'
        }
        for pkt in packets
    ]

    # Send to JanuSec for AI triage
    resp = requests.post(
        'http://localhost:8000/api/v1/assessments/deep_analyze',
        json={'rows': rows, 'analyze_mode': 'basic', 'auto_llm': True}
    )

    return resp.json()
```

---

### **5. Cost Optimization & Budgeting**

**JanuSec Skill:**
- Tracking LLM costs (external API vs local GPU)
- Batch processing to control latency/costs
- Prioritization (Top 25/50/75 by DREAD)

**RF Security Equivalent:**
- **Budget-conscious RF lab setup:**
  - Cheap: RTL-SDR ($30) vs Expensive: USRP ($1,500)
  - Local processing vs cloud (AWS IoT, Azure Sphere)
- **Spectrum analyzer alternatives:**
  - HackRF ($300) vs Keysight spectrum analyzer ($10K+)
- **Optimize data capture:**
  - Capture 10 min of RF traffic vs 24 hours (storage costs)

**Example:** Just like JanuSec caps LLM summaries to Top 25 (cost control), you cap RF captures to "Top 25 suspicious RF signals by power/anomaly score" to save storage.

---

### **6. Documentation & Communication**

**JanuSec Skill:**
- Writing implementation guides (like `LLM_TRIAGE_SUMMARY_IMPLEMENTATION.md`)
- Creating visual flowcharts (21-stage pipeline)
- GitHub Copilot prompts for implementation

**RF Security Equivalent:**
- **RF protocol documentation:**
  - Reverse-engineering proprietary RF protocols (IoT devices)
  - Writing "RF pentesting playbooks" (like JanuSec playbooks)
- **Visual spectrum diagrams:**
  - Waterfall plots, constellation diagrams
  - Attack flow diagrams (WiFi deauth → evil twin → MITM)

**Example:** Create "RF Security Implementation Guide" similar to JanuSec docs:
- "How to set up SDR lab on a budget ($500)"
- "WiFi pentesting pipeline: Capture → Decode → Analyze → Exploit"
- "30-45 line RF threat triage schema"

---

## 🎓 RF Security Certifications & Learning Path

### **Beginner (0-6 months)**

| Certification | Cost | Focus | Value |
|---------------|------|-------|-------|
| **None required** | Free | Learn basics with RTL-SDR ($30) | High - hands-on |
| **GIAC GAWN** (optional) | $8,999 | Wireless auditing (WiFi, Bluetooth) | Medium - expensive |

**Learning Resources (Free/Cheap):**
1. **RTL-SDR Blog** - Tutorials on using cheap SDR ($30)
2. **GNU Radio** - Open-source SDR software
3. **HackRF Academy** - YouTube tutorials (Great Scott Gadgets)
4. **Wireless Security Labs** - TryHackMe, HackTheBox WiFi challenges

**Hardware to Buy (Budget: $200):**
- RTL-SDR ($30) - Receive-only, great for learning
- HackRF One ($300) - TX/RX, full-duplex SDR (optional for year 1)
- WiFi Pineapple Tetra ($199) - WiFi pentesting platform

**Projects:**
1. Capture FM radio broadcasts with RTL-SDR
2. Decode ADSB aircraft transponders (live flight tracking)
3. Sniff unencrypted pager messages (POCSAG)
4. Analyze WiFi beacons in your neighborhood (Wireshark + SDR)

---

### **Intermediate (6-18 months)**

| Certification | Cost | Focus | Value |
|---------------|------|-------|-------|
| **OSWP** (Offensive Security Wireless Professional) | $499 | WiFi hacking (WPA/WPA2 cracking, rogue APs) | **High** - practical |
| **CWSP** (Certified Wireless Security Professional) | $349 exam | WiFi security standards (802.11, WPA3) | Medium - theory |
| **CompTIA Security+** (optional) | $392 | General security (includes wireless basics) | Low - too broad |

**Learning Resources:**
1. **Offensive Security's WiFu** - OSWP course material ($499)
2. **Vivek Ramachandran's WiFi courses** - SecurityTube (free on YouTube)
3. **Pentester Academy's WiFi Security course** - $399/year
4. **"The Hacker Playbook 3"** - Peter Kim (WiFi pentesting chapter)

**Hardware to Buy (Budget: $500-$1,000):**
- HackRF One ($300) - If not already purchased
- Ubertooth One ($120) - Bluetooth sniffing/jamming
- Proxmark3 ($300) - RFID/NFC hacking
- ALFA WiFi adapter ($40) - Monitor mode + packet injection

**Projects:**
1. **WiFi pentesting lab:**
   - Set up WPA2 access point, crack it with aircrack-ng
   - Evil twin attack with WiFi Pineapple
   - Deauth attack + handshake capture
2. **Bluetooth hacking:**
   - Sniff BLE advertisements with Ubertooth
   - Clone Bluetooth Low Energy devices (smart locks)
3. **RFID cloning:**
   - Clone 125 kHz proximity cards with Proxmark3
   - Analyze NFC payment cards (without PIN)
4. **RF replay attacks:**
   - Capture garage door opener signals with HackRF
   - Replay attack to open door (educational only!)

---

### **Advanced (18+ months)**

| Certification | Cost | Focus | Value |
|---------------|------|-------|-------|
| **GPEN** (GIAC Penetration Tester) | $8,999 | General pentesting (includes wireless) | Medium - expensive |
| **OSWE** (Offensive Security Web Expert) | $1,499 | Web app security (IoT device APIs) | Medium - complementary |
| **CEH** (Certified Ethical Hacker) | $1,199 | General hacking (wireless module) | Low - too broad |
| **Custom: "RF Threat Analyst"** | N/A | Create your own cert by building portfolio | **High** - unique |

**Learning Resources:**
1. **SANS SEC617** - Wireless Penetration Testing ($8,999) - If employer pays
2. **IoT Hacking courses** - Pentester Academy, Udemy
3. **5G Security research** - Academic papers, conferences (Black Hat, DEF CON)
4. **RF protocol reverse engineering** - Reverse-engineer proprietary IoT protocols

**Hardware to Buy (Budget: $2,000-$5,000):**
- USRP B210 ($1,500) - High-performance SDR (4G/5G research)
- Ettus Research N210 ($2,500) - Professional SDR
- Flipper Zero ($169) - Multi-tool (RFID, NFC, sub-GHz, infrared)
- ChipWhisperer ($350) - Side-channel attacks (power analysis)

**Projects:**
1. **4G/5G security research:**
   - Set up 4G testbed with USRP + srsRAN (open-source 4G stack)
   - Analyze 4G/5G protocol vulnerabilities (IMSI catching, downgrade attacks)
2. **IoT device hacking:**
   - Reverse-engineer Zigbee smart home devices (door locks, thermostats)
   - Extract firmware from IoT devices via UART/JTAG
   - Exploit hardcoded credentials in IoT APIs
3. **Car hacking:**
   - Analyze keyless entry systems (relay attacks with HackRF)
   - CAN bus sniffing (OBD-II + SDR)
   - Tire pressure monitoring system (TPMS) spoofing
4. **Satellite communications:**
   - Decode GPS signals, analyze jamming/spoofing
   - Iridium satellite pager interception (with USRP)

---

### **Expert (3+ years) - Niche Specializations**

| Specialization | Certifications | Salary Range | Demand |
|----------------|----------------|--------------|--------|
| **5G Security Researcher** | None (academic PhD helpful) | $150K-$300K | Medium - emerging |
| **IoT Security Consultant** | OSWP, OSWE, custom portfolio | $120K-$250K | High |
| **Automotive Security (CAN bus, V2X)** | None (auto industry experience) | $130K-$280K | High - Tesla, GM, etc. |
| **Satellite/Aerospace RF Security** | Security clearance required | $150K-$350K | Low - niche |
| **RFID/NFC Pentester** | OSWP, Proxmark3 expertise | $100K-$200K | Medium |
| **Military/Gov SIGINT (Signal Intelligence)** | TS/SCI clearance | $120K-$300K | Medium - requires clearance |

---

## 🔧 How to Leverage JanuSec Project for RF Security

### **Project Idea: "RF-Triage" - AI-Powered RF Threat Detection**

**Concept:** Apply JanuSec's AI triage approach to RF security

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│ INPUT: RF Captures (SDR)                                    │
│ → WiFi packets, Bluetooth advertisements, Zigbee frames    │
│ → Convert to CSV: SSID, MAC, signal strength, frame type   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 21-STAGE RF PIPELINE (adapted from JanuSec)                │
│ 1. Protocol Decode (WiFi, Bluetooth, Zigbee)               │
│ 2. MAC Address Lookup (OUI database)                       │
│ 3. Signal Strength Analysis (detect hidden transmitters)   │
│ 4. Frequency Hopping Detection (Bluetooth FHSS)            │
│ 5. MITRE ATT&CK Mapping (T1557 MITM, T1200 Hardware)       │
│ 6. DREAD Scoring (impact of rogue AP, deauth attack)       │
│ 7. LLM Triage Summary (30-45 lines, like JanuSec)          │
│ ...                                                          │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ OUTPUT: RF Threat Report                                    │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Row 42: Rogue WiFi AP "CompanyWiFi" (DREAD 8.5)        │ │
│ │                                                         │ │
│ │ 📌 WHAT IS IT?                                          │ │
│ │ Evil twin access point broadcasting SSID "CompanyWiFi".│ │
│ │ Signal strength -40 dBm (very close, likely in parking │ │
│ │ lot). MAC OUI: Raspberry Pi Foundation (DIY rogue AP). │ │
│ │                                                         │ │
│ │ 💥 EXPLOITABILITY                                       │ │
│ │ Attacker can:                                           │ │
│ │ • Capture employee WiFi handshakes → crack WPA2 key    │ │
│ │ • Man-in-the-middle traffic (steal credentials)        │ │
│ │ • Inject malicious payloads into HTTP traffic          │ │
│ │                                                         │ │
│ │ ⚡ WHAT TO DO?                                          │ │
│ │ 1. Locate rogue AP using WiFi triangulation            │ │
│ │ 2. Deauth all clients connected to it                  │ │
│ │ 3. Enable WPA3 + 802.11w PMF on corporate WiFi         │ │
│ │                                                         │ │
│ │ 📋 CONCISE PLAYBOOK                                     │ │
│ │ Step 1: kismet -c wlan0 --find-rogue-ap                │ │
│ │ Step 2: aireplay-ng --deauth 0 -a <mac> wlan0          │ │
│ │ Step 3: hostapd.conf → ieee80211w=2 (PMF required)     │ │
│ │                                                         │ │
│ │ ⚠️ MISSING TELEMETRY:                                  │ │
│ │ • No physical security footage (can't ID who placed AP)│ │
│ │ • No DHCP logs (can't see who connected to rogue AP)   │ │
│ │                                                         │ │
│ │ [🔍 Investigate Further - Open New Tab]                │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Code Reuse from JanuSec:**
1. ✅ CSV upload & parsing → Reuse for RF packet CSVs
2. ✅ Deep analyze pipeline → Adapt stages for RF protocols
3. ✅ LLM triage prompt → Change domain from malware → RF threats
4. ✅ DREAD scoring → Calculate impact of WiFi deauth, rogue AP, etc.
5. ✅ Missing telemetry detection → Identify missing RF logs (DHCP, physical security)
6. ✅ Cost tracking → Track SDR processing time (like local GPU tracking)

**GitHub Repo:** `RF-Triage` (position it as "JanuSec for wireless security")

---

### **Transferable Code Snippets**

#### **1. Adapt JanuSec's LLM Prompt for RF Threats**

```python
# rf_triage/llm_prompt.py

def build_rf_llm_prompt(rf_row, context):
    """
    Build LLM prompt for RF threat triage (adapted from JanuSec)

    Args:
        rf_row: RF packet metadata (SSID, MAC, signal, frame_type)
        context: RF analysis context (DREAD, MITRE, OUI lookup)

    Returns:
        LLM prompt string
    """
    prompt = f"""
You are an RF security analyst performing FAST TRIAGE of wireless threats.

RF ARTIFACT:
- SSID: {rf_row.get('ssid', 'N/A')}
- MAC Address: {rf_row.get('mac', 'N/A')}
- OUI (Manufacturer): {context.get('oui', 'Unknown')}
- Signal Strength: {rf_row.get('signal_dbm', 'N/A')} dBm
- Frame Type: {rf_row.get('frame_type', 'N/A')} (Beacon/Probe/Deauth/etc.)
- Channel: {rf_row.get('channel', 'N/A')}
- Encryption: {rf_row.get('encryption', 'Open')}

RF ANALYSIS CONTEXT:
- DREAD Score: {context.get('dread_score', 'N/A')}
- MITRE Techniques: {context.get('mitre_tags', [])}
- Suspicious Indicators: {context.get('rf_anomalies', [])}
- Historical Context: {context.get('history', 'First time seen')}

OUTPUT FORMAT (30-45 lines max):

📌 WHAT IS IT? (2-3 lines)
[Brief: What RF device/attack, what behavior, what threat]

💥 EXPLOITABILITY (3-4 lines)
Attacker can use this to:
• [RF attack scenario 1]
• [RF attack scenario 2]
• [RF attack scenario 3]

⚡ WHAT TO DO? (3-4 lines)
[Immediate action - 3 steps max, be specific]

📋 CONCISE PLAYBOOK (5-8 lines)
Step 1: [RF tool command - kismet, aircrack-ng, etc.]
Step 2: [RF tool command]
Step 3: [RF tool command]
...

⚠️ MISSING TELEMETRY (IF suspected - 3-5 lines):
[Only if additional RF logs/captures would help confirm/deny]
• [Missing RF data 1] - would confirm/deny [specific RF threat]

RULES:
- Keep total output to 30-45 lines
- Be concise but actionable
- Base analysis on RF context provided (no hallucination)
- Include copy-paste commands for RF tools
"""

    # Conditional: Add missing telemetry section if relevant
    if should_check_rf_telemetry(rf_row, context):
        prompt += """
[Include missing telemetry section - e.g., "No DHCP logs to see who connected to rogue AP"]
"""

    return prompt
```

#### **2. Adapt JanuSec's Cost Tracking for SDR Processing**

```python
# rf_triage/sdr_cost_tracker.py

class SDRProcessingTracker:
    """
    Track SDR processing costs (adapted from JanuSec's LocalLLMTracker)
    """
    def __init__(self):
        self.captures = []

    def track_capture(self, rf_packet_count, sdr_model, processing_time_ms):
        """
        Track SDR capture + processing (no monetary cost, just time/resources)

        Args:
            rf_packet_count: Number of RF packets captured
            sdr_model: "HackRF One", "RTL-SDR", "USRP B210"
            processing_time_ms: Time to decode + analyze packets
        """
        self.captures.append({
            'timestamp': datetime.utcnow().isoformat(),
            'packet_count': rf_packet_count,
            'sdr_model': sdr_model,
            'processing_time_ms': processing_time_ms,
            'cost': 0.0  # Local SDR = free (no cloud costs)
        })

    def get_summary(self):
        """
        Get SDR usage summary (like JanuSec's local GPU summary)
        """
        total_packets = sum(c['packet_count'] for c in self.captures)
        total_time_ms = sum(c['processing_time_ms'] for c in self.captures)

        return {
            'total_captures': len(self.captures),
            'total_packets': total_packets,
            'total_processing_time_sec': round(total_time_ms / 1000, 2),
            'avg_packets_per_capture': round(total_packets / len(self.captures), 0) if self.captures else 0,
            'sdr_models_used': list(set(c['sdr_model'] for c in self.captures))
        }

# Display (same format as JanuSec local GPU tracker)
"""
╔═══════════════════════════════════════════════════════════════════╗
║ 🖥️ SDR Processing Usage (HackRF One / RTL-SDR)                   ║
╠═══════════════════════════════════════════════════════════════════╣
║ Total Captures: 25                                                ║
║ Total RF Packets: 125,000                                         ║
║ Total Processing Time: 45 seconds                                 ║
║ Avg Packets/Capture: 5,000                                        ║
║                                                                   ║
║ 💡 Note: SDR processing is local (no cloud costs). Hardware      ║
║    costs and electricity are not tracked.                         ║
╚═══════════════════════════════════════════════════════════════════╝
"""
```

---

## 🎯 Career Roadmap: JanuSec → RF Security

### **Year 1: Learn RF Basics (while maintaining JanuSec)**

**Goal:** Get comfortable with SDR hardware and RF tools

**Action Items:**
1. ✅ Buy RTL-SDR ($30) + HackRF One ($300)
2. ✅ Complete free tutorials: RTL-SDR Blog, GNU Radio Companion
3. ✅ Build first RF project: "FM Radio Spectrum Analyzer"
4. ✅ Capture WiFi beacons with Wireshark + SDR
5. ✅ Optional: Take OSWP course ($499)

**Portfolio Project:** "RF-Triage Lite"
- Basic RF packet analyzer (WiFi only)
- Reuse JanuSec's CSV analyzer frontend
- LLM triage for WiFi threats (rogue APs, deauth attacks)
- Blog post: "How I Applied AI Triage to WiFi Security"

**Time Commitment:** 5-10 hours/week (weekends)

---

### **Year 2: Build RF Security Portfolio (transition from JanuSec)**

**Goal:** Become proficient in WiFi/Bluetooth/RFID hacking

**Action Items:**
1. ✅ Get OSWP certification ($499)
2. ✅ Buy Proxmark3 ($300) + Ubertooth One ($120)
3. ✅ Build 3-5 RF security projects (see below)
4. ✅ Present at local security meetup/BSides conference
5. ✅ Start RF security blog/YouTube channel

**Portfolio Projects:**
1. **"RF-Triage Pro"** - Full-featured RF threat detection (WiFi, Bluetooth, Zigbee)
2. **"RFID Badge Cloner"** - Clone 125 kHz proximity cards (educational)
3. **"BLE Device Fingerprinter"** - Identify Bluetooth devices by signal characteristics
4. **"WiFi Pineapple + JanuSec Integration"** - Auto-triage WiFi Pineapple captures with LLM
5. **"Car Key Fob Analyzer"** - Analyze keyless entry signals (no replay, just analysis)

**Time Commitment:** 10-15 hours/week

---

### **Year 3: RF Security as Primary Career (full transition)**

**Goal:** Land RF security role (IoT pentester, wireless security engineer, etc.)

**Action Items:**
1. ✅ Apply for RF security jobs (see job titles below)
2. ✅ Publish RF security research (blog, conference talk, GitHub)
3. ✅ Contribute to open-source RF tools (GNU Radio, gr-gsm, etc.)
4. ✅ Optional: Pursue advanced cert (GPEN if employer pays)
5. ✅ Build consulting side business (RF pentesting services)

**Job Titles to Target:**
- IoT Security Engineer ($100K-$180K)
- Wireless Security Consultant ($110K-$200K)
- RF Pentester (MSSP, consulting) ($90K-$170K)
- Automotive Security Researcher (Tesla, GM) ($130K-$250K)
- 5G Security Analyst (telecom, defense) ($120K-$220K)

---

## 📚 Recommended Learning Resources

### **Books**
1. **"The Car Hacker's Handbook"** - Craig Smith (automotive RF security)
2. **"Practical Reverse Engineering"** - Bruce Dang (IoT firmware RE)
3. **"Wireless Security Architecture"** - Jennifer Minella (WiFi design)
4. **"SDR for Engineers"** - Travis Collins (GNU Radio, SDR programming)

### **Online Courses (Free/Cheap)**
1. **RTL-SDR Blog Tutorials** - Free, beginner-friendly
2. **HackRF Academy (YouTube)** - Great Scott Gadgets, free
3. **Pentester Academy's WiFi Security** - $399/year
4. **TryHackMe WiFi Hacking Path** - $10/month

### **Communities**
1. **r/RTLSDR (Reddit)** - SDR hobbyists, helpful for beginners
2. **r/HackRF (Reddit)** - HackRF users, advanced SDR topics
3. **GNU Radio Mailing List** - SDR development help
4. **WiFi Pineapple Forums** - Hak5 community
5. **DEF CON Wireless Village** - Annual conference, great networking

### **YouTube Channels**
1. **Great Scott Gadgets** - HackRF tutorials, RF fundamentals
2. **Hak5** - WiFi Pineapple, RFID hacking
3. **LiveOverflow** - IoT security, reverse engineering
4. **stacksmashing** - Hardware hacking, RF security

---

## ✅ Summary: You're NOT a "Noob Hobo"

### **Why Your Question is STRATEGIC:**

1. ✅ **Career planning** - Thinking about skill transferability
2. ✅ **Domain bridging** - Connecting software security → hardware/RF security
3. ✅ **Practical mindset** - "How can I leverage existing project for new domain?"
4. ✅ **Cost-conscious** - Asking about certs, budget-friendly learning

**This is what senior engineers do!**

### **Transferable Skills from JanuSec:**
1. ✅ Signal processing (events → RF waveforms)
2. ✅ Data pipelines (21-stage → RF processing pipeline)
3. ✅ AI/ML (LLM triage → RF anomaly detection)
4. ✅ Integration (SIEM → SDR APIs)
5. ✅ Cost tracking (LLM tokens → SDR processing time)
6. ✅ Documentation (implementation guides → RF playbooks)

### **Recommended Path:**
1. **Year 1:** Learn RF basics (RTL-SDR, GNU Radio) while maintaining JanuSec
2. **Year 2:** Build RF security portfolio (OSWP cert, 3-5 projects)
3. **Year 3:** Transition to RF security role ($100K-$200K+ salary)

### **Key Certifications:**
- **OSWP** ($499) - Most practical, hands-on WiFi hacking
- **CWSP** ($349) - WiFi security theory (good complement)
- Skip expensive certs unless employer pays (GPEN, SANS)

### **Portfolio Project Idea:**
**"RF-Triage"** - AI-powered RF threat detection platform (like JanuSec for wireless)
- Reuse JanuSec codebase (CSV analyzer, LLM triage, cost tracking)
- Adapt for RF threats (WiFi, Bluetooth, RFID)
- Unique differentiator: "Missing RF telemetry detection"

**You're thinking like a founder/strategist - keep it up!** 🎯

---

**END OF RF SECURITY CAREER PATH**
