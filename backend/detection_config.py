"""
Detection Configuration System

Allows operators to tune detector thresholds per deployment.
Supports live reloading without restarting the backend.

Each detector has:
- enabled: Turn detector on/off
- threshold: What constitutes an alert
- time_window: Lookback period for aggregation
- risk_level: Default severity assigned by this detector
"""

import json
from typing import Dict, Any
from datetime import datetime
from pathlib import Path


class DetectionConfig:
    """
    Centralized configuration for all detectors.
    Can be loaded from JSON file and reloaded at runtime.
    """

    def __init__(self):
        self.config = self._default_config()
        self.last_loaded = datetime.utcnow()

    @staticmethod
    def _default_config() -> Dict[str, Any]:
        """
        Default thresholds for all detectors.
        These are tuned for typical enterprise environments.
        Adjust based on your organization's baseline.
        """
        return {
            "brute_force": {
                "enabled": True,
                "description": "Multiple failed login attempts from same IP/account",
                "threshold_failed_attempts": 5,  # N failed attempts
                "time_window_seconds": 60,  # Within 60 seconds
                "risk_level": "High",
                "risk_score": 85,
                "actions": ["alert", "log"],
            },
            "credential_stuffing": {
                "enabled": True,
                "description": "Testing known username/password combos",
                "threshold_attempts": 10,  # N attempts
                "threshold_unique_users": 3,  # Trying multiple users
                "time_window_seconds": 120,
                "risk_level": "High",
                "risk_score": 75,
                "actions": ["alert", "log"],
            },
            "password_spray": {
                "enabled": True,
                "description": "Single password tried against many users",
                "threshold_targets": 5,  # Attacking N unique users
                "time_window_seconds": 300,
                "risk_level": "High",
                "risk_score": 80,
                "actions": ["alert", "log"],
            },
            "impossible_travel": {
                "enabled": True,
                "description": "User logged in from geographically impossible locations",
                "min_distance_km": 1000,  # Minimum impossible distance
                "time_window_seconds": 3600,  # Within 1 hour
                "risk_level": "Critical",
                "risk_score": 95,
                "actions": ["alert", "log", "notify"],
            },
            "port_scanning": {
                "enabled": True,
                "description": "Probing multiple ports from same source",
                "threshold_ports": 10,  # N unique ports accessed
                "time_window_seconds": 60,
                "risk_level": "Medium",
                "risk_score": 65,
                "actions": ["alert", "log"],
            },
            "suspicious_failed_logins": {
                "enabled": True,
                "description": "Failed login patterns suggesting reconnaissance",
                "threshold_failed_attempts": 3,
                "threshold_unique_users": 2,  # Trying different users
                "threshold_unique_ips": 1,  # From same IP
                "time_window_seconds": 600,
                "risk_level": "Medium",
                "risk_score": 70,
                "actions": ["alert", "log"],
            },
            "off_hours_login": {
                "enabled": True,
                "description": "Login outside normal business hours",
                "business_hours_start": 9,  # 9 AM
                "business_hours_end": 18,  # 6 PM
                "business_days": [0, 1, 2, 3, 4],  # Mon-Fri (0=Monday)
                "critical_accounts": ["admin", "root", "administrator"],  # High-value targets
                "risk_level": "Medium",
                "risk_score": 60,  # Lower if not admin
                "actions": ["alert", "log"],
            },
            "global": {
                "enabled": True,
                "description": "Global settings for all detectors",
                "deduplication_window_seconds": 60,  # Don't alert same attack twice within 60s
                "alert_priority_decay_hours": 24,  # Older alerts lose priority boost
                "whitelist_ips": [],  # IPs to ignore (internal, trusted VPNs, etc.)
                "whitelist_users": [],  # Users to ignore (service accounts, etc.)
                "alert_batch_size": 100,  # Max alerts to broadcast at once
                "log_retention_days": 90,  # Keep logs for 90 days
                "alert_retention_days": 365,  # Keep alerts for 1 year
            },
        }

    def load_from_file(self, filepath: str) -> bool:
        """
        Load configuration from JSON file.
        Returns True if successful, False if file not found.
        """
        try:
            with open(filepath, "r") as f:
                file_config = json.load(f)

            # Merge with defaults (file config overrides defaults)
            merged = self._default_config()
            merged.update(file_config)
            self.config = merged
            self.last_loaded = datetime.utcnow()

            print(f"[Config] Loaded configuration from {filepath}")
            return True
        except FileNotFoundError:
            print(f"[Config] File not found: {filepath}, using defaults")
            return False
        except json.JSONDecodeError as e:
            print(f"[Config] JSON parsing error: {e}, using defaults")
            return False

    def save_to_file(self, filepath: str) -> bool:
        """Save current configuration to JSON file."""
        try:
            with open(filepath, "w") as f:
                json.dump(self.config, f, indent=2)
            print(f"[Config] Saved configuration to {filepath}")
            return True
        except Exception as e:
            print(f"[Config] Error saving config: {e}")
            return False

    def get_detector_config(self, detector_name: str) -> Dict[str, Any]:
        """Get config for a specific detector."""
        return self.config.get(detector_name, {})

    def is_detector_enabled(self, detector_name: str) -> bool:
        """Check if a detector is enabled."""
        return self.get_detector_config(detector_name).get("enabled", False)

    def get_threshold(self, detector_name: str, threshold_key: str) -> Any:
        """Get a specific threshold value."""
        detector_config = self.get_detector_config(detector_name)
        return detector_config.get(threshold_key)

    def get_risk_level(self, detector_name: str) -> str:
        """Get risk level assigned by this detector."""
        return self.get_detector_config(detector_name).get("risk_level", "Medium")

    def get_risk_score(self, detector_name: str) -> int:
        """Get risk score assigned by this detector."""
        return self.get_detector_config(detector_name).get("risk_score", 50)

    def is_ip_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        whitelist = self.config.get("global", {}).get("whitelist_ips", [])
        return ip in whitelist

    def is_user_whitelisted(self, username: str) -> bool:
        """Check if user is whitelisted (service account, etc.)."""
        whitelist = self.config.get("global", {}).get("whitelist_users", [])
        return username in whitelist

    def to_dict(self) -> Dict[str, Any]:
        """Export entire configuration as dict."""
        return self.config.copy()


# Global config instance
_config_instance = None


def get_config() -> DetectionConfig:
    """Get or create the global config instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = DetectionConfig()
    return _config_instance


def load_config(filepath: str) -> DetectionConfig:
    """Load config from file and set as global instance."""
    global _config_instance
    _config_instance = DetectionConfig()
    _config_instance.load_from_file(filepath)
    return _config_instance


# Example configuration file for deployment
EXAMPLE_CONFIG_JSON = {
    "brute_force": {
        "enabled": True,
        "threshold_failed_attempts": 5,
        "time_window_seconds": 60,
        "risk_level": "High",
        "risk_score": 85,
    },
    "credential_stuffing": {
        "enabled": True,
        "threshold_attempts": 10,
        "threshold_unique_users": 3,
        "time_window_seconds": 120,
        "risk_level": "High",
        "risk_score": 75,
    },
    "password_spray": {
        "enabled": True,
        "threshold_targets": 5,
        "time_window_seconds": 300,
        "risk_level": "High",
        "risk_score": 80,
    },
    "impossible_travel": {
        "enabled": True,
        "min_distance_km": 1000,
        "time_window_seconds": 3600,
        "risk_level": "Critical",
        "risk_score": 95,
    },
    "port_scanning": {
        "enabled": True,
        "threshold_ports": 10,
        "time_window_seconds": 60,
        "risk_level": "Medium",
        "risk_score": 65,
    },
    "suspicious_failed_logins": {
        "enabled": True,
        "threshold_failed_attempts": 3,
        "threshold_unique_users": 2,
        "time_window_seconds": 600,
        "risk_level": "Medium",
        "risk_score": 70,
    },
    "off_hours_login": {
        "enabled": True,
        "business_hours_start": 9,
        "business_hours_end": 18,
        "critical_accounts": ["admin", "root"],
        "risk_level": "Medium",
        "risk_score": 60,
    },
    "global": {
        "enabled": True,
        "deduplication_window_seconds": 60,
        "whitelist_ips": ["192.168.1.0/24"],  # Your internal network
        "whitelist_users": ["service_account", "test_user"],
        "log_retention_days": 90,
    },
}


if __name__ == "__main__":
    # Generate example config file
    config_path = Path("detection_config.json")
    with open(config_path, "w") as f:
        json.dump(EXAMPLE_CONFIG_JSON, f, indent=2)
    print(f"Created example config at {config_path}")

    # Test loading
    config = DetectionConfig()
    config.load_from_file(str(config_path))
    print(f"\nBrute Force enabled: {config.is_detector_enabled('brute_force')}")
    print(f"Brute Force threshold: {config.get_threshold('brute_force', 'threshold_failed_attempts')}")
