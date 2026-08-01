# ai_engine.py
# The AI layer: Isolation Forest anomaly detection + risk-score fusion.
# Design (from our CO2 report): final risk = 100 * (0.6 * anomaly + 0.4 * rule/100)
# Fusion rule: the AI can RAISE an alert's risk, but never lower a confirmed rule
# detection (the AI is an escalator, not a de-escalator).

from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

import models

W_ANOMALY = 0.6   # weight of the AI anomaly score
W_RULES = 0.4     # weight of the rule-based score
AI_ONLY_THRESHOLD = 0.80  # IPs above this with no rule alert still get flagged


def _risk_level(score: int) -> str:
    if score >= 71:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"


def _build_features(logs):
    """One 'behavior fingerprint' per source IP."""
    per_ip = defaultdict(list)
    for e in logs:
        per_ip[e.source_ip].append(e)

    ips, rows = [], []
    for ip, events in per_ip.items():
        times = sorted(e.event_time for e in events)
        span = max((times[-1] - times[0]).total_seconds(), 1.0)
        n_events = len(events)
        n_failed = sum(1 for e in events if e.event_type == "login_failed")
        n_users = len({e.username for e in events if e.username})
        n_ports = len({e.port for e in events if e.port})
        n_countries = len({e.country for e in events if e.country})
        rate = n_events / span  # events per second (speed)
        ips.append(ip)
        rows.append([n_events, n_failed, n_users, n_ports, n_countries, rate])
    return ips, np.array(rows)


def run_ai(db: Session):
    """Score every IP with Isolation Forest, fuse with rule alerts, flag AI-only anomalies."""
    logs = db.query(models.LogEntry).all()
    if len(logs) < 10:
        return {"skipped": "not enough log data for AI analysis"}

    ips, X = _build_features(logs)
    if len(ips) < 5:
        return {"skipped": "not enough distinct IPs for AI analysis"}

    forest = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    forest.fit(X)
    raw = -forest.score_samples(X)  # higher = more anomalous
    a_min, a_max = raw.min(), raw.max()
    norm = (raw - a_min) / (a_max - a_min) if a_max > a_min else np.zeros_like(raw)
    anomaly = {ip: float(s) for ip, s in zip(ips, norm)}

    # --- Fuse AI scores into existing rule-based alerts (escalate only) ---
    updated = 0
    alerts = db.query(models.Alert).all()
    alerted_ips = set()
    for alert in alerts:
        if not alert.source_ip:
            continue
        candidates = [p.strip() for p in alert.source_ip.split(",")]
        scores = [anomaly[p] for p in candidates if p in anomaly]
        alerted_ips.update(candidates)
        if not scores:
            continue
        a = max(scores)
        fused = max(
            alert.risk_score,
            round(100 * (W_ANOMALY * a + W_RULES * (alert.risk_score / 100))),
        )
        alert.risk_score = fused
        alert.risk_level = _risk_level(fused)
        alert.evidence = f"{alert.evidence} | AI anomaly score: {a:.2f}"
        updated += 1

    # --- Flag highly anomalous IPs the rules did NOT catch ---
    ai_flagged = 0
    for ip, a in anomaly.items():
        if a >= AI_ONLY_THRESHOLD and ip not in alerted_ips:
            score = round(100 * (W_ANOMALY * a))
            db.add(models.Alert(
                attack_type="Anomalous Activity (AI)",
                source_ip=ip, username=None,
                risk_level=_risk_level(score), risk_score=score,
                evidence=f"Isolation Forest flagged unusual behavior (anomaly {a:.2f}) "
                         f"not matching any known rule pattern",
                recommendation=f"Investigate {ip}: review its recent events manually.",
            ))
            ai_flagged += 1

    db.commit()
    return {
        "ips_analyzed": len(ips),
        "alerts_updated_with_ai": updated,
        "ai_only_flags": ai_flagged,
    }