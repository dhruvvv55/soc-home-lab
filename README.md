# SOC Detection Engineering Lab

A detection engineering home lab simulating real-world attack scenarios using Kali Linux, Windows 11, Wazuh SIEM, Splunk, and an automated Python alert triage pipeline with VirusTotal enrichment.

---

## Architecture

```
Kali Linux (Attacker)
        │
        │  simulates attacks
        ▼
Windows 11 ARM + Sysmon ARM64 (Victim)
        │
        │  ships logs via Wazuh Agent
        ▼
Wazuh Manager 4.14.6 (native ARM64 on Kali)
        │
        │  alerts.json via SSH
        ▼
Python Pipeline (collector → triage → VT enrichment → report)
        │
        │  wazuh_to_splunk.py via HEC
        ▼
Splunk Enterprise (SPL detection queries + scheduled alerts)
```

---

## What I Built

### Detection Rules
15+ custom Wazuh detection rules mapped to MITRE ATT&CK covering:

| Technique | ID | Description |
|---|---|---|
| Credential Dumping | T1003.001 | LSASS memory access via Sysmon Event 10 |
| PowerShell Abuse | T1059.001 | Encoded commands, download cradles |
| Brute Force | T1110.001 | RDP brute force (5 failures in 60s) |
| LOLBin Abuse | T1218 | CertUtil encode/decode/download |
| HTA Execution | T1218.005 | Mshta HTA execution |
| Squiblydoo | T1218.010 | Regsvr32 proxy execution |
| UAC Bypass | T1548.002 | Fodhelper UAC bypass |
| Persistence | T1547.001 | Registry Run key modification |
| Process Injection | T1055 | CreateRemoteThread detection |
| Defense Evasion | T1562.004 | Firewall rule modification |

### Attack Simulations (Kali → Windows)
- RDP brute force via Hydra
- CertUtil LOLBin abuse (`-encode`, `-decode`, `-urlcache`)
- PowerShell encoded command execution
- Registry persistence via Run keys
- Suspicious process creation (svchost injection patterns)

### Python Alert Pipeline
Automated 4-stage pipeline:
1. **Collector** — SSH into Wazuh Manager, reads `alerts.json` directly
2. **Triager** — Deduplicates, scores severity (CRITICAL/HIGH/MEDIUM/LOW), applies analyst notes
3. **Enricher** — VirusTotal API enrichment for IPs and file hashes
4. **Reporter** — Generates structured incident summary with MITRE ATT&CK coverage

**Sample output:**
```
============================================================
  SOC INCIDENT SUMMARY
============================================================
  Generated : 2026-07-05T14:55:24Z
  Window    : Last 1h

  Total Alerts        : 10
  Critical            : 1
  High                : 4
  Medium              : 5

  Affected Agents     : HOMELAB-WIN

------------------------------------------------------------
  TOP THREATS
------------------------------------------------------------
  [CRITICAL] L15 | Executable file dropped in malware folder
             Agent: HOMELAB-WIN | MITRE: T1105
  [HIGH    ] L12 | PowerShell base64 encoded command execution
             Agent: HOMELAB-WIN | MITRE: T1059.001
  [HIGH    ] L12 | Suspicious svchost.exe process
             Agent: HOMELAB-WIN | MITRE: T1055
------------------------------------------------------------
  MITRE ATT&CK COVERAGE
------------------------------------------------------------
  T1105        2 alert(s)
  T1059.001    1 alert(s)
  T1055        1 alert(s)
  T1546.011    1 alert(s)
```

### Splunk Integration
500+ real Wazuh endpoint alerts forwarded into Splunk via HEC. SPL detection queries catching attack scenarios:

```spl
index=main source="wazuh:alerts" agent_name="HOMELAB-WIN" rule_level>=10
| table timestamp, rule_level, rule_desc, mitre_id
| sort -rule_level
```

Detected in Splunk:
- Level 15 — Executable file dropped in folder commonly used by malware
- Level 12 — PowerShell spawned a process executing a base64 encoded command

---

## Stack

| Component | Tool |
|---|---|
| Host Machine | Apple Silicon MacBook (M-series) |
| VM Platform | UTM (QEMU-based, ARM native) |
| Attacker VM | Kali Linux ARM64 |
| Victim VM | Windows 11 ARM |
| Endpoint Logging | Sysmon ARM64 `Sysmon64a.exe` (SwiftOnSecurity config) |
| SIEM | Wazuh 4.14.6 (native ARM64, installed on Kali) |
| Detection Rules | Custom Wazuh XML + Sigma rules |
| IOC Enrichment | VirusTotal API v3 |
| Log Forwarding | Splunk HEC (HTTP Event Collector) |
| SIEM 2 | Splunk Enterprise (local) + SPL detection queries |
| Pipeline | Python 3.9+ via SSH |

---

## Project Structure

```
soc-home-lab/
├── wazuh-docker/
│   ├── docker-compose.yml          # Wazuh stack config (reference)
│   └── config/
│       ├── custom_rules.xml        # 15+ detection rules (T1003, T1059, T1110...)
│       └── wazuh_cluster/
│           └── wazuh_manager.conf  # Manager config with Sysmon log collection
├── detections/
│   └── sigma-rules/
│       └── soc_lab_rules.yml       # Sigma rules for LSASS, CertUtil, PowerShell, Registry
├── pipeline/
│   ├── pipeline.py                 # Main triage + enrichment + reporting pipeline
│   ├── requirements.txt
│   └── .env.template               # Environment variable template
├── wazuh_to_splunk.py              # Wazuh alerts → Splunk HEC forwarder
├── reports/                        # Generated JSON incident reports
└── docs/
    └── SETUP.md                    # Full setup guide
```

---

## Setup

### Prerequisites
- Apple Silicon Mac (M1/M2/M3/M4)
- UTM — https://mac.getutm.app
- Kali Linux ARM64 ISO — https://www.kali.org/get-kali/#kali-installer-images
- Windows 11 ARM ISO (via crystalfetch: `brew install crystalfetch && crystalfetch`)
- Python 3.9+
- VirusTotal free API key — https://www.virustotal.com/gui/join-us
- Splunk Enterprise — https://www.splunk.com/en_us/download/splunk-enterprise.html

### Quick Start

**1. Clone the repo**
```bash
git clone https://github.com/dhruvvv55/soc-home-lab.git
cd soc-home-lab
```

**2. Install Wazuh on Kali VM**
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg \
  --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update && sudo apt-get install wazuh-manager -y
sudo systemctl enable --now wazuh-manager
```

**3. Install Sysmon on Windows VM (PowerShell as Admin)**
```powershell
New-Item -ItemType Directory -Path C:\Sysmon -Force
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile C:\Sysmon\Sysmon.zip
Expand-Archive C:\Sysmon\Sysmon.zip -DestinationPath C:\Sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile C:\Sysmon\sysmon-config.xml
C:\Sysmon\Sysmon64a.exe -accepteula -i C:\Sysmon\sysmon-config.xml
```

**4. Enroll Windows agent**
```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi" -OutFile C:\wazuh-agent.msi
msiexec.exe /i C:\wazuh-agent.msi WAZUH_MANAGER="KALI_IP" WAZUH_AGENT_NAME="HOMELAB-WIN" /q
NET START WazuhSvc
```

**5. Set up SSH key (Mac → Kali)**
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_rsa -N ""
ssh-copy-id dhruv@KALI_IP
```

**6. Run the pipeline**
```bash
cd pipeline
pip install -r requirements.txt
cp .env.template .env
python3 pipeline.py
python3 pipeline.py --hours 24 --output reports/$(date +%Y%m%d).json
```

**7. Forward to Splunk**
```bash
# Set up Splunk HEC token first (Settings → Data Inputs → HTTP Event Collector)
pip install requests
python3 wazuh_to_splunk.py --lines 500
```

**8. Splunk detection query**
```spl
index=main source="wazuh:alerts" agent_name="HOMELAB-WIN" rule_level>=10
| table timestamp, rule_level, rule_desc, mitre_id
| sort -rule_level
```

---

## Detection Engineering Notes

### True/False Positive Tuning
Each rule includes filter conditions to reduce noise:
- LSASS access: excludes known legitimate processes (MsMpEng, svchost, wininit)
- Registry Run keys: excludes software installers (MsiExec, setup.exe)
- CertUtil: no legitimate exclusions — all usage is suspicious in this lab

### Sigma Rules
Rules are written in Sigma format for portability. Convert to Splunk, Elastic, or QRadar using [sigma-cli](https://github.com/SigmaHQ/sigma-cli).

### Apple Silicon Notes
- Use `Sysmon64a.exe` (ARM64) instead of `Sysmon64.exe` on Windows ARM
- Wazuh must be installed natively on Kali ARM64 — Docker images are x86 only
- UTM with Virtualize mode (not Emulate) for native ARM performance

---

## Skills Demonstrated

- Detection engineering (custom rules, TP/FP tuning)
- MITRE ATT&CK framework mapping
- Endpoint telemetry (Sysmon configuration and log analysis)
- Alert triage and incident response workflows
- Security automation (Python, SSH, REST APIs)
- IOC enrichment (VirusTotal API)
- Splunk log ingestion via HEC and SPL detection queries
- Threat simulation (Kali Linux attack tooling)

---

## Author

**Dhruv Patel** — MS Cybersecurity Engineering, USC  