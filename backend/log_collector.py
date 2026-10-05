"""
Log Collector — Ingest logs from multiple sources in real-time.
Supports: syslog, files, HTTP webhooks, JSON streams.

Production-ready log ingestion for live detection.
"""

import os
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable
import hashlib
import re
from sqlalchemy.orm import Session
from models import LogEntry


class LogCollector:
    """
    Collects logs from various sources and normalizes them.
    Each source returns logs in a standard format.
    """

    def __init__(self, user_id: int, db: Session):
        self.user_id = user_id
        self.db = db
        self.collected_logs = []

    @staticmethod
    def parse_csv_log(row: dict) -> dict:
        """
        Parse a CSV row into standard log format.
        Expected columns: event_time, source_ip, username, event_type, status, port, country, password_sig
        """
        return {
            "event_time": row.get("event_time", datetime.utcnow().isoformat() + "Z"),
            "source_ip": row.get("source_ip", "unknown"),
            "username": row.get("username", "unknown"),
            "event_type": row.get("event_type", "unknown"),
            "status": row.get("status", "unknown"),
            "port": int(row.get("port", 0)) if row.get("port") else 0,
            "country": row.get("country", "unknown"),
            "password_sig": row.get("password_sig", ""),
        }

    @staticmethod
    def parse_apache_log(line: str) -> Optional[dict]:
        """
        Parse Apache access log to detect suspicious activity.
        Format: 192.168.1.100 - user [05/Oct/2026:22:04:15 +0000] "POST /login HTTP/1.1" 401 512
        """
        pattern = r'(\S+) - (\S+) \[(.*?)\] "(\w+) (\S+) (\S+)" (\d+) (\S+)'
        match = re.match(pattern, line)
        if not match:
            return None

        ip, user, time_str, method, path, protocol, status, size = match.groups()

        # Infer event type from URL
        event_type = "web_request"
        if "/login" in path:
            event_type = "login"
        elif "/api/admin" in path:
            event_type = "admin_access"

        # Infer status (success/failure)
        status_code = int(status)
        req_status = "success" if 200 <= status_code < 300 else "failure"

        return {
            "event_time": datetime.utcnow().isoformat() + "Z",
            "source_ip": ip,
            "username": user if user != "-" else "unknown",
            "event_type": event_type,
            "status": req_status,
            "port": 80,  # Or extract from config
            "country": "unknown",  # Would need GeoIP lookup
            "password_sig": "",
        }

    @staticmethod
    def parse_ssh_log(line: str) -> Optional[dict]:
        """
        Parse SSH syslog entries.
        Examples:
        - "Invalid user admin from 192.168.1.100"
        - "Failed password for user from 192.168.1.100 ssh2"
        - "Accepted password for admin from 192.168.1.100 port 54321 ssh2"
        """
        # Invalid user attempt
        if "Invalid user" in line:
            match = re.search(r"Invalid user (\S+) from ([\d.]+)", line)
            if match:
                user, ip = match.groups()
                return {
                    "event_time": datetime.utcnow().isoformat() + "Z",
                    "source_ip": ip,
                    "username": user,
                    "event_type": "login",
                    "status": "failure",
                    "port": 22,
                    "country": "unknown",
                    "password_sig": "invalid_user",
                }

        # Failed password
        if "Failed password" in line or "Invalid password" in line:
            match = re.search(r"(Failed|Invalid) password for ([\w.-]+)? ?from ([\d.]+)", line)
            if match:
                _, user, ip = match.groups()
                return {
                    "event_time": datetime.utcnow().isoformat() + "Z",
                    "source_ip": ip,
                    "username": user or "unknown",
                    "event_type": "login",
                    "status": "failure",
                    "port": 22,
                    "country": "unknown",
                    "password_sig": hashlib.md5(b"ssh_failed").hexdigest(),
                }

        # Accepted password
        if "Accepted password" in line:
            match = re.search(r"Accepted password for (\S+) from ([\d.]+)", line)
            if match:
                user, ip = match.groups()
                return {
                    "event_time": datetime.utcnow().isoformat() + "Z",
                    "source_ip": ip,
                    "username": user,
                    "event_type": "login",
                    "status": "success",
                    "port": 22,
                    "country": "unknown",
                    "password_sig": hashlib.md5(b"ssh_success").hexdigest(),
                }

        return None

    @staticmethod
    def parse_firewall_log(line: str) -> Optional[dict]:
        """
        Parse firewall/IPS log entries (generic format).
        Example: "2026-10-05T22:04:15Z DROP TCP 192.168.1.100:55555 -> 10.0.0.1:443"
        """
        pattern = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) (\w+) (\w+) ([\d.]+):\d+ -> ([\d.]+):\d+"
        match = re.match(pattern, line)
        if not match:
            return None

        time_str, action, protocol, src_ip, dst_ip = match.groups()

        return {
            "event_time": time_str,
            "source_ip": src_ip,
            "username": "firewall_user",
            "event_type": f"firewall_{action.lower()}",
            "status": "drop" if action == "DROP" else "allow",
            "port": 443,  # Generic
            "country": "unknown",
            "password_sig": "",
        }

    @staticmethod
    def parse_json_log(log_obj: dict) -> Optional[dict]:
        """
        Parse structured JSON log.
        Expected fields: timestamp, src_ip, user, action, result, port, country, password_hash
        """
        return {
            "event_time": log_obj.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "source_ip": log_obj.get("src_ip") or log_obj.get("source_ip", "unknown"),
            "username": log_obj.get("user") or log_obj.get("username", "unknown"),
            "event_type": log_obj.get("action") or log_obj.get("event_type", "unknown"),
            "status": log_obj.get("result") or log_obj.get("status", "unknown"),
            "port": int(log_obj.get("port", 0)) if log_obj.get("port") else 0,
            "country": log_obj.get("country", "unknown"),
            "password_sig": log_obj.get("password_hash") or log_obj.get("password_sig", ""),
        }


class FileLogReader:
    """
    Watch a file for new logs and stream them.
    Useful for testing or reading from local log files.
    """

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.last_position = 0

    def read_new_lines(self) -> list:
        """Read only new lines since last read."""
        if not self.filepath.exists():
            return []

        with open(self.filepath, "r") as f:
            f.seek(self.last_position)
            lines = f.readlines()
            self.last_position = f.tell()

        return [line.strip() for line in lines if line.strip()]


class SyslogSimulator:
    """
    Generates fake syslog entries for testing.
    Useful for demo without needing a real syslog source.
    """

    def __init__(self):
        self.ips = ["192.168.1.100", "192.168.1.101", "10.0.0.50", "172.16.0.20"]
        self.users = ["admin", "root", "user123", "testuser"]
        self.countries = ["US", "CN", "RU", "IN", "BD"]

    def generate_ssh_logs(self, count: int = 5) -> list:
        """Generate fake SSH logs."""
        import random

        logs = []
        for i in range(count):
            user = random.choice(self.users)
            ip = random.choice(self.ips)
            choice = random.choice(["fail", "fail", "success", "invalid"])

            if choice == "fail":
                log = f"[syslog] Failed password for {user} from {ip}"
            elif choice == "invalid":
                log = f"[syslog] Invalid user {user} from {ip}"
            else:
                log = f"[syslog] Accepted password for {user} from {ip}"

            logs.append(log)

        return logs

    def generate_apache_logs(self, count: int = 5) -> list:
        """Generate fake Apache logs."""
        import random

        logs = []
        for i in range(count):
            ip = random.choice(self.ips)
            user = random.choice(self.users)
            status = random.choice([200, 200, 401, 403, 500])
            path = random.choice(["/login", "/api/users", "/admin", "/index.html"])
            method = random.choice(["GET", "POST"])

            log = f'{ip} - {user} [05/Oct/2026:22:04:{i:02d} +0000] "{method} {path} HTTP/1.1" {status} 512'
            logs.append(log)

        return logs


class WazuhConnector:
    """
    Parse Wazuh alert output.
    Useful for integrating with Wazuh as a frontend layer.
    """

    @staticmethod
    def parse_wazuh_alert(alert: dict) -> Optional[dict]:
        """
        Parse a Wazuh alert into standard log format.
        Wazuh alerts have: rule.id, rule.description, data.srcip, data.user, etc.
        """
        try:
            data = alert.get("data", {})
            rule = alert.get("rule", {})

            # Determine event type from Wazuh rule
            rule_desc = rule.get("description", "").lower()
            event_type = "unknown"
            if "login" in rule_desc or "auth" in rule_desc:
                event_type = "login"
            elif "ssh" in rule_desc:
                event_type = "ssh"
            elif "scan" in rule_desc:
                event_type = "scan"

            return {
                "event_time": alert.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "source_ip": data.get("srcip", "unknown"),
                "username": data.get("user", "unknown"),
                "event_type": event_type,
                "status": "detected",
                "port": data.get("dstport", 0),
                "country": data.get("geoip", {}).get("country_name", "unknown"),
                "password_sig": data.get("full_log", ""),
            }
        except Exception:
            return None


# Example usage functions

def create_test_logs() -> list:
    """Create realistic test logs for demo."""
    sim = SyslogSimulator()

    logs = []
    # Generate some SSH logs
    ssh = sim.generate_ssh_logs(10)
    logs.extend(ssh)

    # Generate some Apache logs
    apache = sim.generate_apache_logs(10)
    logs.extend(apache)

    return logs


if __name__ == "__main__":
    # Test the parsers
    sim = SyslogSimulator()

    print("=== SSH Logs ===")
    ssh_logs = sim.generate_ssh_logs(3)
    for log in ssh_logs:
        parsed = LogCollector.parse_ssh_log(log)
        print(f"Original: {log}")
        print(f"Parsed:   {parsed}\n")

    print("=== Apache Logs ===")
    apache_logs = sim.generate_apache_logs(3)
    for log in apache_logs:
        parsed = LogCollector.parse_apache_log(log)
        print(f"Original: {log}")
        print(f"Parsed:   {parsed}\n")
