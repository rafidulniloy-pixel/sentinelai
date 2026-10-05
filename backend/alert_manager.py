"""
Advanced Alert Manager — Deduplication, correlation, grouping, and intelligent filtering.
Makes sure the dashboard doesn't flood with duplicate alerts.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict
from sqlalchemy.orm import Session
from models import Alert
import hashlib


class AlertDeduplicator:
    """
    Prevents duplicate alerts by fingerprinting.
    Same attack from same IP → grouped together, not shown twice.
    """

    @staticmethod
    def fingerprint_alert(alert_dict: dict) -> str:
        """
        Create a fingerprint of an alert.
        Alerts with the same fingerprint are considered duplicates.
        """
        key = f"{alert_dict['attack_type']}_{alert_dict['source_ip']}_{alert_dict['username']}"
        return hashlib.md5(key.encode()).hexdigest()

    @staticmethod
    def is_duplicate(
        db: Session,
        user_id: int,
        alert_dict: dict,
        time_window_seconds: int = 60,
    ) -> bool:
        """
        Check if this alert is a duplicate of a recent one.

        Args:
            db: Database session
            user_id: User ID
            alert_dict: Alert details
            time_window_seconds: Window to check for duplicates (default 60s)

        Returns:
            True if duplicate found, False otherwise
        """
        fingerprint = AlertDeduplicator.fingerprint_alert(alert_dict)
        cutoff = datetime.utcnow() - timedelta(seconds=time_window_seconds)

        # Look for same attack from same IP in recent alerts
        recent_alert = (
            db.query(Alert)
            .filter(
                Alert.user_id == user_id,
                Alert.attack_type == alert_dict["attack_type"],
                Alert.source_ip == alert_dict["source_ip"],
                Alert.username == alert_dict["username"],
                Alert.detected_at > cutoff,
            )
            .first()
        )

        return recent_alert is not None


class AlertGrouper:
    """
    Groups related alerts together for easier visualization.
    E.g., multiple brute force attempts from same IP → one "Brute Force Campaign"
    """

    @staticmethod
    def group_alerts_by_source_ip(alerts: List[dict]) -> Dict[str, List[dict]]:
        """Group alerts by source IP."""
        grouped = {}
        for alert in alerts:
            ip = alert["source_ip"]
            if ip not in grouped:
                grouped[ip] = []
            grouped[ip].append(alert)
        return grouped

    @staticmethod
    def group_alerts_by_type(alerts: List[dict]) -> Dict[str, List[dict]]:
        """Group alerts by attack type."""
        grouped = {}
        for alert in alerts:
            attack_type = alert["attack_type"]
            if attack_type not in grouped:
                grouped[attack_type] = []
            grouped[attack_type].append(alert)
        return grouped

    @staticmethod
    def group_alerts_by_user(alerts: List[dict]) -> Dict[str, List[dict]]:
        """Group alerts by target username."""
        grouped = {}
        for alert in alerts:
            user = alert["username"]
            if user not in grouped:
                grouped[user] = []
            grouped[user].append(alert)
        return grouped

    @staticmethod
    def summarize_group(alerts: List[dict]) -> dict:
        """
        Create a summary of a group of alerts.
        Used to show "10 brute force attempts" instead of 10 individual alerts.
        """
        return {
            "count": len(alerts),
            "attack_types": list(set(a["attack_type"] for a in alerts)),
            "ips": list(set(a["source_ip"] for a in alerts)),
            "users": list(set(a["username"] for a in alerts)),
            "min_risk": min(a["risk_score"] for a in alerts),
            "max_risk": max(a["risk_score"] for a in alerts),
            "latest": max(a["detected_at"] for a in alerts),
            "alerts": alerts,
        }


class AlertCorrelator:
    """
    Detects multi-stage attack patterns.
    E.g., Brute Force → then Impossible Travel = suspicious campaign
    """

    @staticmethod
    def detect_attack_chain(db: Session, user_id: int) -> List[dict]:
        """
        Detect likely attack chains by analyzing recent alerts.
        Returns list of detected patterns.
        """
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        recent_alerts = (
            db.query(Alert)
            .filter(
                Alert.user_id == user_id,
                Alert.detected_at > cutoff,
            )
            .all()
        )

        chains = []

        # Pattern 1: Brute Force followed by successful login (compromise indicator)
        brute_forces = [a for a in recent_alerts if a.attack_type == "Brute Force"]
        off_hours = [a for a in recent_alerts if a.attack_type == "Off-Hours Login"]

        for bf in brute_forces:
            for oh in off_hours:
                # Same IP, successful login after failed attempts = likely compromise
                if bf.source_ip == oh.source_ip and oh.detected_at > bf.detected_at:
                    chains.append(
                        {
                            "pattern": "Post-Compromise Access",
                            "severity": "Critical",
                            "description": f"Brute force on {bf.username} followed by off-hours login from {bf.source_ip}",
                            "alerts": [bf.id, oh.id],
                            "recommendation": "Immediately reset password and audit account activity",
                        }
                    )

        # Pattern 2: Port Scanning followed by attacks (reconnaissance + exploitation)
        port_scans = [a for a in recent_alerts if a.attack_type == "Port Scanning"]
        attacks = [a for a in recent_alerts if a.attack_type in ["Brute Force", "Credential Stuffing"]]

        for scan in port_scans:
            for attack in attacks:
                if scan.source_ip == attack.source_ip and attack.detected_at > scan.detected_at:
                    chains.append(
                        {
                            "pattern": "Reconnaissance + Exploitation",
                            "severity": "High",
                            "description": f"Port scan from {scan.source_ip} followed by attack attempt",
                            "alerts": [scan.id, attack.id],
                            "recommendation": "Block the IP at firewall; investigate any data access",
                        }
                    )

        # Pattern 3: Impossible Travel (account compromise)
        impossible_travels = [a for a in recent_alerts if a.attack_type == "Impossible Travel"]
        for it in impossible_travels:
            chains.append(
                {
                    "pattern": "Account Compromise",
                    "severity": "Critical",
                    "description": f"User {it.username} impossible travel detected - likely compromised account",
                    "alerts": [it.id],
                    "recommendation": "Force password reset immediately; enable MFA; audit all sessions",
                }
            )

        return chains


class AlertFilter:
    """
    Smart filtering to reduce alert fatigue.
    Let analysts focus on real threats.
    """

    @staticmethod
    def filter_by_risk_level(alerts: List[dict], min_risk: int = 0) -> List[dict]:
        """Filter alerts by minimum risk score."""
        return [a for a in alerts if a["risk_score"] >= min_risk]

    @staticmethod
    def filter_by_attack_type(alerts: List[dict], attack_types: List[str]) -> List[dict]:
        """Filter by specific attack types."""
        return [a for a in alerts if a["attack_type"] in attack_types]

    @staticmethod
    def filter_by_time_range(
        alerts: List[dict],
        start_time: datetime,
        end_time: datetime,
    ) -> List[dict]:
        """Filter alerts within a time range."""
        return [
            a
            for a in alerts
            if start_time <= datetime.fromisoformat(a["detected_at"].replace("Z", "+00:00")) <= end_time
        ]

    @staticmethod
    def filter_by_ip_range(alerts: List[dict], ip_ranges: List[str]) -> List[dict]:
        """
        Filter by IP ranges (e.g., internal network, known-bad IPs).
        ip_ranges format: ["192.168.0.0/16", "10.0.0.5"]
        """
        # Simple implementation - in production use ipaddress module
        filtered = []
        for alert in alerts:
            ip = alert["source_ip"]
            for ip_range in ip_ranges:
                if ip_range in ip or ip == ip_range:
                    filtered.append(alert)
                    break
        return filtered

    @staticmethod
    def get_top_offenders(alerts: List[dict], limit: int = 10) -> List[dict]:
        """Get the most active threat sources."""
        from collections import Counter

        ip_counts = Counter(a["source_ip"] for a in alerts)
        top_ips = ip_counts.most_common(limit)

        return [
            {
                "source_ip": ip,
                "alert_count": count,
                "alerts": [a for a in alerts if a["source_ip"] == ip],
            }
            for ip, count in top_ips
        ]

    @staticmethod
    def get_trending_attacks(db: Session, user_id: int, hours: int = 1) -> dict:
        """
        Get trending attack types in the last N hours.
        Useful for spotting campaigns.
        """
        from collections import Counter

        cutoff = datetime.utcnow() - timedelta(hours=hours)
        recent = (
            db.query(Alert)
            .filter(
                Alert.user_id == user_id,
                Alert.detected_at > cutoff,
            )
            .all()
        )

        attack_counts = Counter(a.attack_type for a in recent)

        return {
            "hour": hours,
            "total_alerts": len(recent),
            "by_type": {
                attack_type: count
                for attack_type, count in attack_counts.most_common()
            },
        }


class AlertPrioritizer:
    """
    Assign priority scores to alerts based on context.
    Not all High-risk alerts are equally important.
    """

    @staticmethod
    def priority_score(alert: dict, db: Session, user_id: int) -> int:
        """
        Calculate priority (1-100).
        Takes into account: risk score, attack chain, repeated offender, time of day.
        """
        base_score = alert["risk_score"]

        # Boost for repeated offenders
        cutoff = datetime.utcnow() - timedelta(hours=24)
        repeat_count = (
            db.query(Alert)
            .filter(
                Alert.user_id == user_id,
                Alert.source_ip == alert["source_ip"],
                Alert.detected_at > cutoff,
            )
            .count()
        )
        if repeat_count > 5:
            base_score += 15
        elif repeat_count > 2:
            base_score += 10

        # Boost for impossible travel (almost certainly compromised)
        if "Impossible Travel" in alert["attack_type"]:
            base_score = min(100, base_score + 20)

        # Boost for off-hours access to critical accounts
        if alert["attack_type"] == "Off-Hours Login" and alert["username"] in ["admin", "root"]:
            base_score = min(100, base_score + 15)

        return min(100, base_score)

    @staticmethod
    def sort_by_priority(alerts: List[dict], db: Session, user_id: int) -> List[dict]:
        """Sort alerts by calculated priority."""
        alerts_with_priority = [
            (alert, AlertPrioritizer.priority_score(alert, db, user_id))
            for alert in alerts
        ]
        return [alert for alert, _ in sorted(alerts_with_priority, key=lambda x: x[1], reverse=True)]
