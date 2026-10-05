"""
Live Detection Engine — Real-time detection on incoming log streams.
Processes one log entry at a time and broadcasts alerts immediately.
"""

import json
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from models import User, LogEntry, Alert
from detection import (
    detect_brute_force,
    detect_credential_stuffing,
    detect_password_spraying,
    detect_impossible_travel,
    detect_port_scanning,
    detect_suspicious_failed_logins,
    detect_off_hours_login,
)
from explain import explain_alert


class LiveLogProcessor:
    """
    Processes individual log entries in real-time.
    Unlike batch detection, this:
    - Processes one log at a time (as it arrives)
    - Runs detectors immediately
    - Returns alerts in <1 second
    - Does NOT delete old alerts (live detection is incremental)
    """

    def __init__(self, db: Session, user_id: int):
        self.db = db
        self.user_id = user_id
        self.recent_logs_buffer = []  # Keep last N logs for windowed detectors

    def process_log_entry(self, log_data: dict) -> dict:
        """
        Process a single incoming log entry.

        Args:
            log_data: dict with keys:
                - event_time (ISO string like "2026-10-05T22:04:00Z")
                - source_ip
                - username
                - event_type (e.g., "login", "failed_login")
                - status (e.g., "success", "failure")
                - port (integer)
                - country
                - password_sig (hash of password, can be empty string)

        Returns:
            dict with keys:
                - status: "processed" or "error"
                - log_id: ID of stored log entry (if success)
                - alerts: list of alert dicts (if any fired)
                - error: error message (if status="error")
        """
        try:
            # Parse timestamp
            if isinstance(log_data.get("event_time"), str):
                # Handle ISO format: "2026-10-05T22:04:00Z"
                try:
                    event_time = datetime.fromisoformat(
                        log_data["event_time"].replace("Z", "+00:00")
                    )
                except:
                    event_time = datetime.utcnow()
            else:
                event_time = datetime.utcnow()

            # Create LogEntry in database
            log_entry = LogEntry(
                user_id=self.user_id,
                event_time=event_time,
                source_ip=log_data.get("source_ip", "unknown"),
                username=log_data.get("username", "unknown"),
                event_type=log_data.get("event_type", "unknown"),
                status=log_data.get("status", "unknown"),
                port=int(log_data.get("port", 0)) if log_data.get("port") else 0,
                country=log_data.get("country", "unknown"),
                password_sig=log_data.get("password_sig", ""),
                uploaded_at=datetime.utcnow(),
            )
            self.db.add(log_entry)
            self.db.commit()
            self.db.refresh(log_entry)

            # Keep recent logs for detector windows (15 minutes max)
            self.recent_logs_buffer.append(log_entry)
            cutoff_time = event_time - timedelta(minutes=15)
            self.recent_logs_buffer = [
                log for log in self.recent_logs_buffer
                if log.event_time >= cutoff_time
            ]

            # Run all detectors
            alerts = self._run_detectors(log_entry)

            return {
                "status": "processed",
                "log_id": log_entry.id,
                "alerts": alerts,
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }

    def _run_detectors(self, log_entry: LogEntry) -> list:
        """
        Run all 7 detectors on the new log entry.
        Returns list of alert dicts (empty if nothing triggered).
        """
        alerts = []

        # Detector 1: Brute Force
        if detect_brute_force(log_entry, self.recent_logs_buffer):
            alert_dict = self._create_alert(
                log_entry,
                attack_type="Brute Force",
                risk_level="High",
                risk_score=92,
                evidence="5+ failed logins from same IP/account within 60s",
            )
            alerts.append(alert_dict)

        # Detector 2: Credential Stuffing
        if detect_credential_stuffing(log_entry, self.recent_logs_buffer):
            alert_dict = self._create_alert(
                log_entry,
                attack_type="Credential Stuffing",
                risk_level="High",
                risk_score=85,
                evidence="5+ usernames from same IP within 600s with multiple password signatures",
            )
            alerts.append(alert_dict)

        # Detector 3: Password Spraying
        if detect_password_spraying(log_entry, self.recent_logs_buffer):
            alert_dict = self._create_alert(
                log_entry,
                attack_type="Password Spraying",
                risk_level="High",
                risk_score=82,
                evidence="5+ usernames from same IP within 600s with same password signature",
            )
            alerts.append(alert_dict)

        # Detector 4: Impossible Travel
        if detect_impossible_travel(log_entry, self.recent_logs_buffer):
            alert_dict = self._create_alert(
                log_entry,
                attack_type="Impossible Travel",
                risk_level="High",
                risk_score=88,
                evidence="User appeared in 2 countries within 3600s (impossible travel time)",
            )
            alerts.append(alert_dict)

        # Detector 5: Port Scanning
        if detect_port_scanning(log_entry, self.recent_logs_buffer):
            alert_dict = self._create_alert(
                log_entry,
                attack_type="Port Scanning",
                risk_level="Medium",
                risk_score=70,
                evidence="10+ distinct ports accessed from same IP within 120s",
            )
            alerts.append(alert_dict)

        # Detector 6: Suspicious Failed Logins
        if detect_suspicious_failed_logins(log_entry, self.recent_logs_buffer):
            alert_dict = self._create_alert(
                log_entry,
                attack_type="Suspicious Failed Logins",
                risk_level="Medium",
                risk_score=45,
                evidence="3+ failed logins within 900s",
            )
            alerts.append(alert_dict)

        # Detector 7: Off-Hours Login
        if detect_off_hours_login(log_entry, self.recent_logs_buffer):
            alert_dict = self._create_alert(
                log_entry,
                attack_type="Off-Hours Login",
                risk_level="Low",
                risk_score=20,
                evidence="Successful login between 00:00–05:00 UTC",
            )
            alerts.append(alert_dict)

        return alerts

    def _create_alert(
        self,
        log_entry: LogEntry,
        attack_type: str,
        risk_level: str,
        risk_score: int,
        evidence: str,
    ) -> dict:
        """Store an alert in the database and return it as a dict."""
        alert = Alert(
            user_id=self.user_id,
            attack_type=attack_type,
            source_ip=log_entry.source_ip,
            username=log_entry.username,
            risk_level=risk_level,
            risk_score=risk_score,
            evidence=evidence,
            recommendation="Investigate immediately",
            detected_at=datetime.utcnow(),
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)

        # Get human-readable explanation
        explanation = explain_alert(alert)

        return {
            "id": alert.id,
            "attack_type": alert.attack_type,
            "source_ip": alert.source_ip,
            "username": alert.username,
            "risk_level": alert.risk_level,
            "risk_score": alert.risk_score,
            "evidence": alert.evidence,
            "explanation": explanation,
            "detected_at": alert.detected_at.isoformat(),
        }
