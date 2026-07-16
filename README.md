# SOC Detection Engineering Lab

A detection engineering home lab simulating real-world attack scenarios using Kali Linux, Windows 11, Wazuh SIEM, and an automated Python alert triage pipeline with VirusTotal enrichment.

---

## Architecture

```
Kali Linux (Attacker)
        │
        │  simulates attacks
        ▼
Windows 11 + Sysmon ARM64 (Victim)
        │
        │  ships logs via Wazuh Agent
        ▼
Wazuh Manager (SIEM) on Kali
        │
        │  alerts.json
        ▼
Python Pipeline (collector → triage → VT enrichment → report)
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

---

## Stack

| Component | Tool |
|---|---|
| Attacker VM | Kali Linux ARM64 (UTM on Apple Silicon) |
| Victim VM | Windows 11 ARM (UTM on Apple Silicon) |
| Endpoint Logging | Sysmon ARM64 (SwiftOnSecurity config) |
| SIEM | Wazuh 4.14.6 (native ARM64) |
| Detection Rules | Custom Wazuh XML + Sigma rules |
| IOC Enrichment | VirusTotal API v3 |
| Pipeline | Python 3.9+ |

---

## Project Structure

```
soc-home-lab/
├── wazuh-docker/
│   ├── docker-compose.yml          # Wazuh stack config
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
├── reports/                        # Generated JSON incident reports
└── docs/
    └── SETUP.md                    # Full setup guide
```

---

## Setup

### Prerequisites
- Apple Silicon Mac (or Linux host)
- UTM (for VMs) — https://mac.getutm.app
- Python 3.9+
- VirusTotal free API key — https://www.virustotal.com/gui/join-us

### Quick Start

**1. Clone the repo**
```bash
git clone https://github.com/YOUR_USERNAME/soc-home-lab.git
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
# Replace KALI_IP with your Kali VM IP
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi" -OutFile C:\wazuh-agent.msi
msiexec.exe /i C:\wazuh-agent.msi WAZUH_MANAGER="KALI_IP" WAZUH_AGENT_NAME="HOMELAB-WIN" /q
NET START WazuhSvc
```

**5. Run the pipeline**
```bash
cd pipeline
pip install -r requirements.txt
cp .env.template .env
# Edit .env with your SSH host and VirusTotal API key
python3 pipeline.py
python3 pipeline.py --hours 24 --output reports/$(date +%Y%m%d).json
```

---

## Detection Engineering Notes

### True/False Positive Tuning
Each rule includes filter conditions to reduce noise:
- LSASS access: excludes known legitimate processes (MsMpEng, svchost, wininit)
- Registry Run keys: excludes software installers (MsiExec, setup.exe)
- CertUtil: no legitimate exclusions — all usage is suspicious in this lab environment

### Sigma Rules
Rules are written in Sigma format for portability across SIEM platforms. Convert to Splunk, Elastic, or QRadar using [sigma-cli](https://github.com/SigmaHQ/sigma-cli).

---

## Skills Demonstrated

- Detection engineering (custom rules, TP/FP tuning)
- MITRE ATT&CK framework mapping
- Endpoint telemetry (Sysmon configuration and log analysis)
- Alert triage and incident response workflows
- Security automation (Python, REST APIs, SSH)
- IOC enrichment (VirusTotal API)
- Threat simulation (Kali Linux attack tooling)

---

## Author

**Dhruv Patel** — MS Cybersecurity Engineering, USC  
[LinkedIn](https://www.linkedin.com/in/dhruvvv55/) · [Portfolio](https://dhruv-ashok-patel-portfolio.vercel.app/)
