"""
SOC Home Lab — Automated Alert Triage Pipeline
================================================
Author : Dhruv Patel
Stack  : Python 3.9+, Wazuh (SSH), VirusTotal API

Pipeline stages:
  1. Collector  — Pull alerts from Wazuh via SSH
  2. Triager    — Score and prioritise alerts
  3. Enricher   — Enrich IPs/hashes via VirusTotal
  4. Reporter   — Generate structured incident summary

Usage:
  python pipeline.py                       # Run once, stdout report
  python pipeline.py --output report.json  # Save JSON report
  python pipeline.py --hours 24            # Pull last 24h of alerts
  python pipeline.py --min-level 7         # Only alerts level 7+
"""

import os
from dotenv import load_dotenv
load_dotenv('/Users/dhruvvv54/soc-home-lab/pipeline/.env')

import json
import argparse
import logging
import subprocess
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import defaultdict

import requests
from requests.auth import HTTPBasicAuth

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

WAZUH_HOST  = os.getenv("WAZUH_HOST",  "https://192.168.64.4:55000")
WAZUH_USER  = os.getenv("WAZUH_USER",  "wazuh")
WAZUH_PASS  = os.getenv("WAZUH_PASS",  "wazuh")
VT_API_KEY  = os.getenv("VT_API_KEY",  "")
VERIFY_SSL  = os.getenv("VERIFY_SSL",  "false").lower() == "true"

# SSH config to read alerts directly from Kali
SSH_HOST    = os.getenv("SSH_HOST",    "192.168.64.4")
SSH_USER    = os.getenv("SSH_USER",    "dhruv")
SSH_KEY     = os.getenv("SSH_KEY",     os.path.expanduser("~/.ssh/id_rsa"))

# Alert level thresholds
LEVEL_CRITICAL = 14
LEVEL_HIGH     = 10
LEVEL_MEDIUM   = 7

# VirusTotal
VT_MALICIOUS_THRESHOLD = 3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("soc-pipeline")


# ──────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────

@dataclass
class WazuhAlert:
    alert_id:    str
    timestamp:   str
    agent_name:  str
    agent_ip:    str
    rule_id:     str
    rule_desc:   str
    rule_level:  int
    rule_groups: list
    mitre_ids:   list
    src_ip:      Optional[str] = None
    dst_ip:      Optional[str] = None
    file_hash:   Optional[str] = None
    raw:         dict = field(default_factory=dict, repr=False)


@dataclass
class EnrichedAlert:
    alert:          WazuhAlert
    severity:       str
    vt_ip_result:   Optional[dict] = None
    vt_hash_result: Optional[dict] = None
    analyst_notes:  list = field(default_factory=list)


@dataclass
class IncidentReport:
    generated_at:       str
    window_hours:       int
    total_alerts:       int
    critical_count:     int
    high_count:         int
    medium_count:       int
    low_count:          int
    top_threats:        list
    affected_agents:    list
    enriched_alerts:    list
    mitre_coverage:     dict
    analyst_summary:    str
    recommended_actions: list


# ──────────────────────────────────────────────
# STAGE 1 — COLLECTOR (SSH-based)
# ──────────────────────────────────────────────

class WazuhCollector:
    """Reads alerts directly from Wazuh alerts.json via SSH."""

    def fetch_alerts(self, hours=1, min_level=7):
        log.info(f"Connecting to Wazuh via SSH ({SSH_USER}@{SSH_HOST})")
        try:
            cmd = [
                "ssh",
                "-i", SSH_KEY,
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                f"{SSH_USER}@{SSH_HOST}",
                "sudo cat /var/ossec/logs/alerts/alerts.json"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                log.warning(f"SSH returned error: {result.stderr.strip()}")
                log.info("Falling back to mock data")
                return _mock_alerts()

            # Parse JSON lines
            raw_alerts = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    raw_alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            log.info(f"Parsed {len(raw_alerts)} total alerts from Wazuh")

            # Filter by level and time window
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            filtered = []
            for a in raw_alerts:
                level = int(a.get("rule", {}).get("level", 0))
                if level < min_level:
                    continue
                ts_str = a.get("timestamp", "")
                try:
                    # Handle timezone format
                    ts_str = ts_str.replace("+0000", "+00:00")
                    ts = datetime.fromisoformat(ts_str)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if ts < since:
                        continue
                except Exception:
                    pass
                filtered.append(a)

            log.info(f"Filtered to {len(filtered)} alerts (level>={min_level}, last {hours}h)")

            if not filtered:
                log.warning("No alerts in window — using mock data for demo")
                return _mock_alerts()

            return [self._parse(a) for a in filtered]

        except subprocess.TimeoutExpired:
            log.warning("SSH timeout — using mock data")
            return _mock_alerts()
        except Exception as e:
            log.error(f"SSH fetch failed: {e}")
            log.info("Falling back to mock data")
            return _mock_alerts()

    def _parse(self, raw):
        rule   = raw.get("rule", {})
        agent  = raw.get("agent", {})
        data   = raw.get("data", {})
        sysmon = data.get("win", {}).get("eventdata", {})
        mitre  = rule.get("mitre", {}).get("id", [])

        return WazuhAlert(
            alert_id    = raw.get("id", ""),
            timestamp   = raw.get("timestamp", ""),
            agent_name  = agent.get("name", "unknown"),
            agent_ip    = agent.get("ip", "unknown"),
            rule_id     = str(rule.get("id", "")),
            rule_desc   = rule.get("description", ""),
            rule_level  = int(rule.get("level", 0)),
            rule_groups = rule.get("groups", []),
            mitre_ids   = mitre if isinstance(mitre, list) else ([mitre] if mitre else []),
            src_ip      = sysmon.get("sourceIp") or data.get("srcip"),
            dst_ip      = sysmon.get("destinationIp") or data.get("dstip"),
            file_hash   = sysmon.get("hashes", "").split("MD5=")[-1].split(",")[0][:32]
                          if "MD5=" in sysmon.get("hashes", "") else None,
            raw         = raw,
        )


# ──────────────────────────────────────────────
# STAGE 2 — TRIAGER
# ──────────────────────────────────────────────

class AlertTriager:

    PRIORITY_GROUPS = {
        "credential_access", "lsass", "mimikatz",
        "brute_force", "process_injection", "uac_bypass",
        "download_cradle", "lolbins",
    }

    def triage(self, alerts):
        deduped  = self._deduplicate(alerts)
        enriched = [self._score(a) for a in deduped]
        enriched.sort(key=lambda e: e.alert.rule_level, reverse=True)
        log.info(f"Triaged {len(enriched)} unique alerts")
        return enriched

    def _deduplicate(self, alerts):
        seen, unique = set(), []
        for a in alerts:
            key = f"{a.rule_id}:{a.agent_name}:{a.src_ip}"
            if key not in seen:
                seen.add(key)
                unique.append(a)
        log.info(f"Deduplication: {len(alerts)} → {len(unique)} alerts")
        return unique

    def _score(self, alert):
        level  = alert.rule_level
        groups = set(alert.rule_groups)

        if level >= LEVEL_CRITICAL:
            severity = "CRITICAL"
        elif level >= LEVEL_HIGH:
            severity = "HIGH"
        elif level >= LEVEL_MEDIUM:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        notes = []

        if groups & self.PRIORITY_GROUPS and severity == "MEDIUM":
            severity = "HIGH"
            notes.append("Severity elevated: rule group matches high-priority category")

        if "lsass" in groups or "mimikatz" in groups:
            notes.append("Investigate: LSASS memory access — check for credential theft tools")
            notes.append("Recommended: isolate host, reset passwords, check for lateral movement")
        if "brute_force" in groups:
            notes.append("Investigate: source IP for brute force — internal or external?")
            notes.append("Recommended: block source IP, review RDP exposure, enable account lockout")
        if "lolbins" in groups:
            notes.append("Investigate: parent process and full command line — likely payload staging")
        if "download_cradle" in groups:
            notes.append("Investigate: network connections from PowerShell — check for C2 traffic")
        if "persistence" in groups:
            notes.append("Investigate: registry key value and binary path — verify legitimacy")
        if "sysmon_event1" in groups:
            notes.append("Process creation event — review full command line and parent process")

        return EnrichedAlert(alert=alert, severity=severity, analyst_notes=notes)


# ──────────────────────────────────────────────
# STAGE 3 — ENRICHER (VirusTotal)
# ──────────────────────────────────────────────

class VTEnricher:

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.key     = VT_API_KEY
        self._cache  = {}
        self.enabled = bool(self.key)
        if not self.enabled:
            log.warning("VT_API_KEY not set — skipping VirusTotal enrichment")
        else:
            log.info("VirusTotal enrichment enabled")

    def enrich(self, alerts):
        if not self.enabled:
            return alerts
        for ea in alerts:
            if ea.alert.src_ip and ea.alert.src_ip not in ("127.0.0.1", "::1", "any"):
                ea.vt_ip_result = self._lookup_ip(ea.alert.src_ip)
            if ea.alert.file_hash:
                ea.vt_hash_result = self._lookup_hash(ea.alert.file_hash)
            self._annotate(ea)
        return alerts

    def _headers(self):
        return {"x-apikey": self.key}

    def _lookup_ip(self, ip):
        if ip in self._cache:
            return self._cache[ip]
        try:
            r = requests.get(f"{self.BASE}/ip_addresses/{ip}",
                             headers=self._headers(), timeout=15)
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                result = {
                    "ip":        ip,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":  stats.get("harmless", 0),
                    "flagged":   stats.get("malicious", 0) >= VT_MALICIOUS_THRESHOLD,
                    "vt_link":   f"https://www.virustotal.com/gui/ip-address/{ip}",
                }
                self._cache[ip] = result
                log.info(f"VT IP {ip}: {result['malicious']} malicious detections")
                return result
        except Exception as e:
            log.warning(f"VT IP lookup failed for {ip}: {e}")
        return None

    def _lookup_hash(self, md5):
        if md5 in self._cache:
            return self._cache[md5]
        try:
            r = requests.get(f"{self.BASE}/files/{md5}",
                             headers=self._headers(), timeout=15)
            if r.status_code == 200:
                attrs = r.json()["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})
                result = {
                    "hash":       md5,
                    "name":       attrs.get("meaningful_name", "unknown"),
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "flagged":    stats.get("malicious", 0) >= VT_MALICIOUS_THRESHOLD,
                    "vt_link":    f"https://www.virustotal.com/gui/file/{md5}",
                }
                self._cache[md5] = result
                log.info(f"VT Hash {md5}: {result['malicious']} malicious detections")
                return result
        except Exception as e:
            log.warning(f"VT hash lookup failed for {md5}: {e}")
        return None

    def _annotate(self, ea):
        if ea.vt_ip_result and ea.vt_ip_result.get("flagged"):
            ea.analyst_notes.append(
                f"⚠ VT flagged source IP {ea.alert.src_ip} as malicious "
                f"({ea.vt_ip_result['malicious']} engines) — {ea.vt_ip_result['vt_link']}"
            )
        if ea.vt_hash_result and ea.vt_hash_result.get("flagged"):
            ea.analyst_notes.append(
                f"⚠ VT flagged file hash {ea.alert.file_hash} as malicious "
                f"({ea.vt_hash_result['malicious']} engines) — {ea.vt_hash_result['vt_link']}"
            )


# ──────────────────────────────────────────────
# STAGE 4 — REPORTER
# ──────────────────────────────────────────────

class IncidentReporter:

    def generate(self, alerts, hours):
        counts     = defaultdict(int)
        mitre_freq = defaultdict(int)

        for ea in alerts:
            counts[ea.severity] += 1
            for tid in ea.alert.mitre_ids:
                if tid:
                    mitre_freq[tid] += 1

        top = [
            {
                "rule_id":   ea.alert.rule_id,
                "desc":      ea.alert.rule_desc,
                "severity":  ea.severity,
                "level":     ea.alert.rule_level,
                "agent":     ea.alert.agent_name,
                "mitre":     ea.alert.mitre_ids,
                "timestamp": ea.alert.timestamp,
            }
            for ea in alerts[:5]
        ]

        affected = list({ea.alert.agent_name for ea in alerts})
        summary  = self._build_summary(alerts, counts, mitre_freq)
        actions  = self._build_actions(alerts)

        return IncidentReport(
            generated_at        = datetime.now(timezone.utc).isoformat(),
            window_hours        = hours,
            total_alerts        = len(alerts),
            critical_count      = counts["CRITICAL"],
            high_count          = counts["HIGH"],
            medium_count        = counts["MEDIUM"],
            low_count           = counts["LOW"],
            top_threats         = top,
            affected_agents     = affected,
            enriched_alerts     = [self._serialise(ea) for ea in alerts],
            mitre_coverage      = dict(sorted(mitre_freq.items(), key=lambda x: x[1], reverse=True)),
            analyst_summary     = summary,
            recommended_actions = actions,
        )

    def _build_summary(self, alerts, counts, mitre_freq):
        lines = [
            f"Total alerts: {len(alerts)}",
            f"High Severity Alerts: {counts['CRITICAL'] + counts['HIGH']}",
        ]
        if mitre_freq:
            for tid, cnt in sorted(mitre_freq.items(), key=lambda x: x[1], reverse=True)[:3]:
                lines.append(f"  - {tid}: {cnt} alert(s)")

        groups_seen = set()
        for ea in alerts:
            groups_seen.update(ea.alert.rule_groups)

        if "lsass" in groups_seen or "mimikatz" in groups_seen:
            lines.append("\nCredential access activity detected — possible credential theft")
        if "brute_force" in groups_seen:
            lines.append("Brute force activity detected — possible password spraying or RDP attack")
        if "lolbins" in groups_seen:
            lines.append("LOLBin abuse detected — attacker likely using native binaries to evade detection")
        if "process_injection" in groups_seen:
            lines.append("Process injection detected — possible in-memory execution or evasion")
        if "persistence" in groups_seen:
            lines.append("Persistence mechanism detected — host likely compromised, check startup items")
        if not any(k in groups_seen for k in ["lsass", "brute_force", "lolbins", "process_injection", "persistence"]):
            lines.append("\nMost alerts are low-priority. Continue monitoring.")

        return "\n".join(lines)

    def _build_actions(self, alerts):
        actions = set()
        for ea in alerts:
            groups = set(ea.alert.rule_groups)
            if {"lsass", "mimikatz", "credential_access"} & groups:
                actions.add("Isolate affected host and reset all credentials")
                actions.add("Check for lateral movement from affected agent")
            if "brute_force" in groups:
                actions.add("Block brute-force source IPs at perimeter firewall")
                actions.add("Enable account lockout policy (GPO)")
                actions.add("Audit RDP exposure — disable if not required")
            if "lolbins" in groups:
                actions.add("Review full command line of flagged binaries")
                actions.add("Correlate with network events for C2 indicators")
            if "persistence" in groups:
                actions.add("Review registry Run keys on affected host")
                actions.add("Run full AV/EDR scan on affected agent")
            if "download_cradle" in groups:
                actions.add("Review outbound HTTP/S connections from affected host")
            if ea.vt_ip_result and ea.vt_ip_result.get("flagged"):
                actions.add(f"Block malicious IP {ea.alert.src_ip} at firewall and proxy")
        return sorted(actions) or ["Continue monitoring — no immediate action required"]

    def _serialise(self, ea):
        return {
            "alert_id":      ea.alert.alert_id,
            "timestamp":     ea.alert.timestamp,
            "severity":      ea.severity,
            "rule_id":       ea.alert.rule_id,
            "rule_desc":     ea.alert.rule_desc,
            "rule_level":    ea.alert.rule_level,
            "agent":         ea.alert.agent_name,
            "agent_ip":      ea.alert.agent_ip,
            "mitre":         ea.alert.mitre_ids,
            "src_ip":        ea.alert.src_ip,
            "file_hash":     ea.alert.file_hash,
            "vt_ip":         ea.vt_ip_result,
            "vt_hash":       ea.vt_hash_result,
            "analyst_notes": ea.analyst_notes,
        }

    def print_report(self, report):
        sep = "=" * 60
        print(f"\n{sep}")
        print("  SOC INCIDENT SUMMARY")
        print(sep)
        print(f"  Generated : {report.generated_at}")
        print(f"  Window    : Last {report.window_hours}h")
        print(f"\n  Total Alerts        : {report.total_alerts}")
        print(f"  Critical            : {report.critical_count}")
        print(f"  High                : {report.high_count}")
        print(f"  Medium              : {report.medium_count}")
        print(f"  Low                 : {report.low_count}")
        print(f"\n  Affected Agents     : {', '.join(report.affected_agents)}")
        print(f"\n{'-'*60}")
        print("  TOP THREATS")
        print(f"{'-'*60}")
        for t in report.top_threats:
            print(f"  [{t['severity']:<8}] L{t['level']} | {t['desc']}")
            print(f"             Agent: {t['agent']} | MITRE: {', '.join(t['mitre']) or 'N/A'}")
        print(f"\n{'-'*60}")
        print("  MITRE ATT&CK COVERAGE")
        print(f"{'-'*60}")
        for tid, cnt in list(report.mitre_coverage.items())[:8]:
            print(f"  {tid:<12} {cnt} alert(s)")
        print(f"\n{'-'*60}")
        print("  ANALYST ASSESSMENT")
        print(f"{'-'*60}")
        for line in report.analyst_summary.split("\n"):
            print(f"  {line}")
        print(f"\n{'-'*60}")
        print("  RECOMMENDED ACTIONS")
        print(f"{'-'*60}")
        for i, action in enumerate(report.recommended_actions, 1):
            print(f"  {i}. {action}")
        print(f"\n{sep}\n")


# ──────────────────────────────────────────────
# MOCK DATA
# ──────────────────────────────────────────────

def _mock_alerts():
    return [
        WazuhAlert(
            alert_id="mock-001", timestamp="2026-07-05T08:55:14.792Z",
            agent_name="HOMELAB-WIN", agent_ip="192.168.64.5",
            rule_id="100001", rule_level=14,
            rule_desc="Possible LSASS credential dumping detected (Sysmon Event 10)",
            rule_groups=["sysmon_event10", "credential_access", "lsass", "high_severity"],
            mitre_ids=["T1003.001"], src_ip="192.168.64.4",
        ),
        WazuhAlert(
            alert_id="mock-002", timestamp="2026-07-05T09:24:13.634Z",
            agent_name="HOMELAB-WIN", agent_ip="192.168.64.5",
            rule_id="100030", rule_level=12,
            rule_desc="CertUtil LOLBin abuse — encode/decode or download via certutil",
            rule_groups=["sysmon_event1", "defense_evasion", "lolbins", "certutil"],
            mitre_ids=["T1218", "T1105"], src_ip="192.168.64.4",
        ),
        WazuhAlert(
            alert_id="mock-003", timestamp="2026-07-05T09:25:14.792Z",
            agent_name="HOMELAB-WIN", agent_ip="192.168.64.5",
            rule_id="100010", rule_level=12,
            rule_desc="PowerShell encoded command execution detected — T1059.001",
            rule_groups=["sysmon_event1", "execution", "powershell", "encoded"],
            mitre_ids=["T1059.001"], src_ip=None,
        ),
        WazuhAlert(
            alert_id="mock-004", timestamp="2026-07-05T09:13:00.000Z",
            agent_name="HOMELAB-WIN", agent_ip="192.168.64.5",
            rule_id="100020", rule_level=10,
            rule_desc="RDP brute force detected — 5 failed logons in 60s",
            rule_groups=["authentication", "brute_force", "rdp"],
            mitre_ids=["T1110.001"], src_ip="192.168.64.4",
        ),
        WazuhAlert(
            alert_id="mock-005", timestamp="2026-07-05T09:30:00.000Z",
            agent_name="HOMELAB-WIN", agent_ip="192.168.64.5",
            rule_id="100050", rule_level=11,
            rule_desc="Registry Run key modified — possible persistence mechanism T1547.001",
            rule_groups=["sysmon_event13", "persistence", "registry", "run_key"],
            mitre_ids=["T1547.001"], src_ip=None,
        ),
    ]


# ──────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC Home Lab Alert Pipeline")
    parser.add_argument("--hours",     type=int, default=1,  help="Hours of alerts to pull")
    parser.add_argument("--min-level", type=int, default=7,  help="Minimum Wazuh alert level")
    parser.add_argument("--output",    type=str, default=None, help="Save report to JSON file")
    args = parser.parse_args()

    log.info("=== SOC Pipeline Starting ===")
    log.info(f"SSH: {SSH_USER}@{SSH_HOST} | VT: {'enabled' if VT_API_KEY else 'disabled'}")

    # Stage 1: Collect via SSH
    collector  = WazuhCollector()
    raw_alerts = collector.fetch_alerts(hours=args.hours, min_level=args.min_level)

    if not raw_alerts:
        log.warning("No alerts found. Exiting.")
        return

    # Stage 2: Triage
    triager  = AlertTriager()
    enriched = triager.triage(raw_alerts)

    # Stage 3: Enrich (VirusTotal)
    enricher = VTEnricher()
    enriched = enricher.enrich(enriched)

    # Stage 4: Report
    reporter = IncidentReporter()
    report   = reporter.generate(enriched, hours=args.hours)
    reporter.print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            import json as _json
            _json.dump(asdict(report), f, indent=2, default=str)
        log.info(f"Report saved to {args.output}")

    log.info("=== Pipeline Complete ===")


if __name__ == "__main__":
    main()