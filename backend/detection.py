# detection.py
# =============================================================================
# The core detection engine: rule-based "detectives", one per attack type.
#
# SEVERITY DESIGN:
#   High   (71-100) - confirmed attack patterns needing immediate action
#   Medium (31-70)  - suspicious activity that must be reviewed
#   Low    (0-30)   - informational findings worth noting, not alarming
#
#   The lower-severity detectors at the end exist so the system reports the
#   full severity spectrum rather than only critical findings, which is how a
#   real SOC triages: not everything unusual is an emergency.
# =============================================================================

from collections import defaultdict

from sqlalchemy.orm import Session

import models

# --- Tunable thresholds ------------------------------------------------------
BRUTE_FORCE_FAILS = 5        # >= this many failed logins...
BRUTE_FORCE_WINDOW = 60      # ...within this many seconds, same IP + account
STUFFING_USERS = 5           # >= this many DIFFERENT usernames failed...
STUFFING_WINDOW = 600        # ...within 10 minutes, same IP
SPRAY_USERS = 5              # same password tried on >= this many accounts...
SPRAY_WINDOW = 600           # ...within 10 minutes
TRAVEL_WINDOW = 3600         # two-country logins within 60 minutes
PORTSCAN_PORTS = 10          # >= this many distinct ports...
PORTSCAN_WINDOW = 120        # ...within 2 minutes, same IP

# --- Lower-severity thresholds ----------------------------------------------
SUSPICIOUS_FAILS = 3         # >= this many failed logins...
SUSPICIOUS_WINDOW = 900      # ...within 15 minutes (too slow to be brute force)
OFFHOURS_START = 0           # successful logins between these hours are
OFFHOURS_END = 5             # outside normal working time


def _add_alert(db, attack_type, source_ip, username, risk_level, risk_score,
               evidence, recommendation):
    db.add(models.Alert(
        attack_type=attack_type, source_ip=source_ip, username=username,
        risk_level=risk_level, risk_score=risk_score,
        evidence=evidence, recommendation=recommendation,
    ))


# =============================================================================
# HIGH SEVERITY DETECTORS
# =============================================================================
def detect_brute_force(db, logs):
    """Same IP fails login on the SAME account many times, fast."""
    found = 0
    groups = defaultdict(list)
    for e in logs:
        if e.event_type == "login_failed" and e.username:
            groups[(e.source_ip, e.username)].append(e.event_time)
    for (ip, user), times in groups.items():
        times.sort()
        for i in range(len(times) - BRUTE_FORCE_FAILS + 1):
            span = (times[i + BRUTE_FORCE_FAILS - 1] - times[i]).total_seconds()
            if span <= BRUTE_FORCE_WINDOW:
                _add_alert(db, "Brute Force Attack", ip, user, "High", 92,
                    f"{len(times)} failed logins on account '{user}' from {ip} "
                    f"({BRUTE_FORCE_FAILS} within {int(span)}s)",
                    f"Block IP {ip} and temporarily lock account '{user}'. Enable rate-limiting.")
                found += 1
                break
    return found


def detect_credential_stuffing(db, logs):
    """Same IP fails login on MANY DIFFERENT accounts (leaked credential list)."""
    found = 0
    groups = defaultdict(list)
    for e in logs:
        if e.event_type == "login_failed" and e.username:
            groups[e.source_ip].append(e)
    for ip, events in groups.items():
        users = {e.username for e in events}
        if len(users) >= STUFFING_USERS:
            times = sorted(e.event_time for e in events)
            span = (times[-1] - times[0]).total_seconds()
            sigs = {e.password_sig for e in events if e.password_sig}
            if span <= STUFFING_WINDOW and len(sigs) > 1:
                _add_alert(db, "Credential Stuffing", ip, None, "High", 85,
                    f"{ip} attempted {len(users)} different accounts "
                    f"({', '.join(sorted(users))}) in {int(span)}s with varied passwords",
                    f"Block IP {ip}. Force password reset for targeted accounts. Enable MFA.")
                found += 1
    return found


def detect_password_spraying(db, logs):
    """The SAME password tried across many accounts (avoids lockouts)."""
    found = 0
    groups = defaultdict(list)
    for e in logs:
        if e.event_type == "login_failed" and e.password_sig:
            groups[e.password_sig].append(e)
    for sig, events in groups.items():
        users = {e.username for e in events if e.username}
        if len(users) >= SPRAY_USERS:
            times = sorted(e.event_time for e in events)
            span = (times[-1] - times[0]).total_seconds()
            if span <= SPRAY_WINDOW:
                ips = {e.source_ip for e in events}
                _add_alert(db, "Password Spraying", ", ".join(sorted(ips)), None, "High", 82,
                    f"One password tried on {len(users)} accounts "
                    f"({', '.join(sorted(users))}) within {int(span)}s",
                    "Enforce strong password policy and MFA. Block source IP(s).")
                found += 1
    return found


def detect_impossible_travel(db, logs):
    """Same user logs in from two far-apart countries within minutes."""
    found = 0
    groups = defaultdict(list)
    for e in logs:
        if e.event_type == "login_success" and e.username and e.country:
            groups[e.username].append(e)
    for user, events in groups.items():
        events.sort(key=lambda e: e.event_time)
        for a, b in zip(events, events[1:]):
            gap = (b.event_time - a.event_time).total_seconds()
            if a.country != b.country and gap <= TRAVEL_WINDOW:
                _add_alert(db, "Impossible Travel", b.source_ip, user, "High", 88,
                    f"'{user}' logged in from {a.country} then {b.country} "
                    f"only {int(gap // 60)} minutes apart",
                    f"Suspend session, verify identity of '{user}', force password reset.")
                found += 1
    return found


# =============================================================================
# MEDIUM SEVERITY DETECTORS
# =============================================================================
def detect_port_scan(db, logs):
    """Same IP touches many different ports very quickly."""
    found = 0
    groups = defaultdict(list)
    for e in logs:
        if e.event_type == "connection" and e.port:
            groups[e.source_ip].append(e)
    for ip, events in groups.items():
        ports = {e.port for e in events}
        if len(ports) >= PORTSCAN_PORTS:
            times = sorted(e.event_time for e in events)
            span = (times[-1] - times[0]).total_seconds()
            if span <= PORTSCAN_WINDOW:
                _add_alert(db, "Port Scanning", ip, None, "Medium", 70,
                    f"{ip} probed {len(ports)} different ports in {int(span)}s "
                    f"(ports: {', '.join(str(p) for p in sorted(ports))})",
                    f"Block IP {ip} at the firewall. Review exposed services.")
                found += 1
    return found


def detect_suspicious_failed_logins(db, logs):
    """
    Several failed logins on one account that are too few or too slow to be a
    brute-force attack. Often a user who forgot their password - but it can also
    be a careful attacker deliberately staying under the detection threshold,
    which is exactly why it is worth surfacing at MEDIUM rather than ignoring.
    """
    found = 0
    groups = defaultdict(list)
    for e in logs:
        if e.event_type == "login_failed" and e.username:
            groups[(e.source_ip, e.username)].append(e.event_time)

    for (ip, user), times in groups.items():
        times.sort()
        # Skip anything the brute-force detector already reported.
        already = any(
            (times[i + BRUTE_FORCE_FAILS - 1] - times[i]).total_seconds() <= BRUTE_FORCE_WINDOW
            for i in range(len(times) - BRUTE_FORCE_FAILS + 1)
        )
        if already or len(times) < SUSPICIOUS_FAILS:
            continue

        span = (times[-1] - times[0]).total_seconds()
        if span <= SUSPICIOUS_WINDOW:
            _add_alert(db, "Suspicious Failed Logins", ip, user, "Medium", 45,
                f"{len(times)} failed logins on account '{user}' from {ip} over "
                f"{int(span)}s - below the brute-force threshold but still unusual",
                f"Review recent activity for '{user}' and consider requiring MFA.")
            found += 1
    return found


# =============================================================================
# LOW SEVERITY DETECTOR
# =============================================================================
def detect_offhours_login(db, logs):
    """
    A successful login in the middle of the night. On its own this is not an
    attack - staff do work late - so it is reported as LOW and informational.
    It matters because compromised credentials are frequently used off-hours,
    and because it gives the analyst context when correlating other findings.
    One alert per account keeps the noise down.
    """
    found = 0
    seen = set()
    for e in sorted(logs, key=lambda x: x.event_time):
        if (e.event_type == "login_success" and e.username
                and OFFHOURS_START <= e.event_time.hour < OFFHOURS_END
                and e.username not in seen):
            seen.add(e.username)
            _add_alert(db, "Off-Hours Login", e.source_ip, e.username, "Low", 20,
                f"'{e.username}' signed in successfully at "
                f"{e.event_time.strftime('%H:%M')} from {e.source_ip}, "
                f"outside normal working hours",
                f"Confirm with '{e.username}' that this access was expected.")
            found += 1
    return found


# =============================================================================
def run_all(db: Session):
    """Run every detector against all stored logs. Returns a summary."""
    db.query(models.Alert).delete()      # fresh run each time (MVP behaviour)
    logs = db.query(models.LogEntry).all()
    summary = {
        "brute_force": detect_brute_force(db, logs),
        "credential_stuffing": detect_credential_stuffing(db, logs),
        "password_spraying": detect_password_spraying(db, logs),
        "impossible_travel": detect_impossible_travel(db, logs),
        "port_scan": detect_port_scan(db, logs),
        "suspicious_failed_logins": detect_suspicious_failed_logins(db, logs),
        "offhours_login": detect_offhours_login(db, logs),
    }
    db.commit()
    summary["total_alerts"] = sum(summary.values())
    summary["logs_analyzed"] = len(logs)
    return summary
