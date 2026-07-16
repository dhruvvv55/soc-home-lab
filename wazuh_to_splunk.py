"""
Wazuh -> Splunk Log Forwarder
==============================
Author : Dhruv Patel
Stack  : Python 3.9+, Wazuh alerts.json via SSH, Splunk HEC

Pulls Wazuh alerts from Kali via SSH and forwards them to Splunk.

Usage:
  python wazuh_to_splunk.py                  # Forward last 1h
  python wazuh_to_splunk.py --hours 24       # Forward last 24h
  python wazuh_to_splunk.py --lines 500      # Forward last N lines
"""

import json
import argparse
import logging
import subprocess
import requests
from datetime import datetime, timezone

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

SSH_HOST       = "192.168.64.4"
SSH_USER       = "dhruv"
SSH_KEY        = "/Users/dhruvvv54/.ssh/id_rsa"
ALERTS_FILE    = "/var/ossec/logs/alerts/alerts.json"

SPLUNK_HEC_URL = "http://localhost:8088/services/collector/event"
SPLUNK_TOKEN   = "5b3b723f-52d4-4907-9bfa-a1643446dae2"
SPLUNK_INDEX   = "main"
SPLUNK_SOURCE  = "wazuh:alerts"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("wazuh-splunk")


# ──────────────────────────────────────────────
# FORWARDER
# ──────────────────────────────────────────────

class WazuhSplunkForwarder:

    def __init__(self):
        self.headers = {
            "Authorization": f"Splunk {SPLUNK_TOKEN}",
            "Content-Type":  "application/json",
        }
        log.info(f"Wazuh SSH  : {SSH_USER}@{SSH_HOST}")
        log.info(f"Splunk HEC : {SPLUNK_HEC_URL}")

    def fetch_alerts(self, lines: int = 1000) -> list:
        """Pull alerts from Wazuh alerts.json via SSH."""
        cmd = [
            "ssh",
            "-i", SSH_KEY,
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            f"{SSH_USER}@{SSH_HOST}",
            f"sudo tail -{lines} {ALERTS_FILE}"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                log.error(f"SSH error: {result.stderr.strip()}")
                return []

            alerts = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            log.info(f"Fetched {len(alerts)} alerts from Wazuh")
            return alerts

        except subprocess.TimeoutExpired:
            log.error("SSH timeout")
            return []
        except Exception as e:
            log.error(f"Failed to fetch: {e}")
            return []

    def parse_alert(self, raw: dict) -> dict:
        """Flatten alert into a clean event for Splunk."""
        rule   = raw.get("rule", {})
        agent  = raw.get("agent", {})
        mitre  = rule.get("mitre", {})

        return {
            "timestamp":     raw.get("timestamp", ""),
            "agent_name":    agent.get("name", "unknown"),
            "agent_ip":      agent.get("ip", "unknown"),
            "rule_id":       str(rule.get("id", "")),
            "rule_level":    rule.get("level", 0),
            "rule_desc":     rule.get("description", ""),
            "rule_groups":   rule.get("groups", []),
            "mitre_id":      mitre.get("id", []),
            "mitre_tactic":  mitre.get("tactic", []),
            "mitre_technique": mitre.get("technique", []),
            "full_log":      raw.get("full_log", ""),
            "log_source":    "wazuh",
        }

    def send_to_splunk(self, event: dict) -> bool:
        try:
            ts_str = event.get("timestamp", "")
            try:
                ts    = datetime.fromisoformat(ts_str.replace("+0000", "+00:00"))
                epoch = ts.timestamp()
            except Exception:
                epoch = datetime.now(timezone.utc).timestamp()

            payload = {
                "time":       epoch,
                "host":       event.get("agent_name", "wazuh-agent"),
                "source":     SPLUNK_SOURCE,
                "sourcetype": "_json",
                "index":      SPLUNK_INDEX,
                "event":      event,
            }

            r = requests.post(
                SPLUNK_HEC_URL,
                headers=self.headers,
                data=json.dumps(payload),
                timeout=10,
            )
            return r.status_code == 200

        except Exception as e:
            log.warning(f"Send failed: {e}")
            return False

    def forward(self, lines: int = 1000):
        log.info(f"=== Wazuh → Splunk Forwarder Starting ===")

        alerts  = self.fetch_alerts(lines=lines)
        if not alerts:
            log.warning("No alerts found.")
            return

        sent   = 0
        failed = 0

        for raw in alerts:
            event = self.parse_alert(raw)
            if self.send_to_splunk(event):
                sent += 1
            else:
                failed += 1

        log.info(f"=== Done: {sent} sent, {failed} failed ===")
        log.info(f'Search in Splunk: index=main source="wazuh:alerts"')


# ──────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Wazuh → Splunk Forwarder")
    parser.add_argument("--lines", type=int, default=1000,
                        help="Number of alert lines to pull (default: 1000)")
    args = parser.parse_args()

    forwarder = WazuhSplunkForwarder()
    forwarder.forward(lines=args.lines)


if __name__ == "__main__":
    main()