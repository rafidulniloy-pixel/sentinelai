"""
SentinelAI — live streaming detection (CSE 499B).

    replay / agent  --POST /ingest/stream-->  RollingWindow
                                                   |
                                             window detectors
                                                   |
                                        dedup  -->  WebSocket /ws/live  --> browser

Notes for the report:

  * The offline path (/logs/upload -> /detect) is untouched. Batch and stream
    share the detection THRESHOLDS, not the plumbing, so a bug here can never
    break the working 499A system.

  * Thresholds below are copied from detection.py deliberately, so this file
    runs even if detection.py changes. Extracting one shared core that both
    paths import is a planned next step. State this openly in the report
    rather than hiding the duplication.

  * Deduplication is what keeps the feed readable. Without it, one brute-force
    attack produces hundreds of identical rows.
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

router = APIRouter()

# ------------------------------------------------------------------ thresholds
# Same numbers as detection.py. Keep them in sync until they are merged.

BRUTE_FORCE_FAILS, BRUTE_FORCE_WINDOW = 5, 60
STUFFING_USERS, STUFFING_WINDOW = 5, 600
SPRAY_USERS, SPRAY_WINDOW = 5, 600
PORTSCAN_PORTS, PORTSCAN_WINDOW = 10, 120
SUSPICIOUS_FAILS, SUSPICIOUS_WINDOW = 3, 900
OFFHOURS_START, OFFHOURS_END = 0, 5

# The window must be at least as long as the LONGEST detector needs.
# Impossible Travel looks back 3600s, so a 900s window silently broke it.
WINDOW_SECONDS = 3600         # how much history the window keeps
DEDUP_SECONDS = 600           # one alert per (attack, subject) per 10 minutes

MITRE = {
    "Brute Force": "T1110",
    "Password Spraying": "T1110.003",
    "Credential Stuffing": "T1110.004",
    "Impossible Travel": "T1078",
    "Port Scanning": "T1046",
}

ACTIONS = {
    "Brute Force": "Block the source IP and force a password reset on this account.",
    "Password Spraying": "Enable MFA and review the targeted accounts for a weak shared password.",
    "Credential Stuffing": "Check these accounts against known breach lists and force resets.",
    "Impossible Travel": "Treat the account as compromised. Revoke sessions, then reset.",
    "Port Scanning": "Confirm which services are exposed and close what is not needed.",
    "Suspicious Failed Logins": "Watch this IP. If the rate rises it becomes a brute-force case.",
    "Off-Hours Login": "Informational. Confirm with the user if this is unusual for them.",
}


# ----------------------------------------------------------------- data model

class StreamEvent(BaseModel):
    event_time: Optional[str] = None
    source_ip: str
    username: Optional[str] = None
    event_type: Optional[str] = None
    status: Optional[str] = None
    port: Optional[int] = None
    country: Optional[str] = None
    password_sig: Optional[str] = None


class StreamBatch(BaseModel):
    events: List[StreamEvent]


def _parse_time(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------- rolling window

class RollingWindow:
    """Keeps the most recent WINDOW_SECONDS of events in memory.

    This is the whole trick behind live detection. The detectors already work
    on time windows ("5 failures in 60 seconds"). Previously the window was
    filled by a database query. Now it is filled by whatever just arrived.
    """

    def __init__(self, seconds: int = WINDOW_SECONDS) -> None:
        self.seconds = seconds
        self._events: Deque[Dict[str, Any]] = deque()
        self.total_seen = 0

    def add(self, event: Dict[str, Any]) -> None:
        self._events.append(event)
        self.total_seen += 1
        self._evict()

    def _evict(self) -> None:
        if not self._events:
            return
        newest = self._events[-1]["ts"]
        while self._events:
            age = (newest - self._events[0]["ts"]).total_seconds()
            if age > self.seconds:
                self._events.popleft()
            else:
                break

    def within(self, seconds: int, ref: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Events in the last `seconds`, measured back from `ref`.

        `ref` defaults to the newest event. It matters during replay: if a
        whole batch is evaluated only from the batch's newest timestamp, any
        attack that completed earlier inside that batch is already outside
        the lookback and is never detected. Evaluating per event fixes it.
        """
        if not self._events:
            return []
        point = ref or self._events[-1]["ts"]
        return [
            e for e in self._events
            if 0 <= (point - e["ts"]).total_seconds() <= seconds
        ]


# -------------------------------------------------------------- the detectors

def _failed(e: Dict[str, Any]) -> bool:
    status = (e.get("status") or "").lower()
    return status in {"fail", "failed", "failure", "denied", "invalid"}


def detect_window(window: RollingWindow,
                  new_event: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Run every window detector as of `new_event`'s moment.

    Called once per arriving event, not once per batch -- see RollingWindow.within.
    """
    found: List[Dict[str, Any]] = []
    ref = new_event["ts"] if new_event else None

    # --- 1. brute force: many failures, one IP, one account, short window
    recent = window.within(BRUTE_FORCE_WINDOW, ref)
    pairs: Dict[tuple, int] = defaultdict(int)
    for e in recent:
        if _failed(e):
            pairs[(e["source_ip"], e.get("username") or "-")] += 1
    for (ip, user), n in pairs.items():
        if n >= BRUTE_FORCE_FAILS:
            found.append(_alert(
                "Brute Force", ip, user, 92,
                f"{n} failed logins in {BRUTE_FORCE_WINDOW}s from one IP against one account",
                recent, ip,
            ))

    # --- 2 and 3. spraying vs stuffing: many accounts from one IP.
    #     Same shape, told apart by the password signature.
    longer = window.within(SPRAY_WINDOW, ref)
    by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in longer:
        if _failed(e):
            by_ip[e["source_ip"]].append(e)
    for ip, events in by_ip.items():
        users = {e.get("username") for e in events if e.get("username")}
        sigs = {e.get("password_sig") for e in events if e.get("password_sig")}
        if len(users) >= SPRAY_USERS:
            if len(sigs) == 1:
                found.append(_alert(
                    "Password Spraying", ip, f"{len(users)} accounts", 82,
                    f"{len(users)} usernames tried with one identical password "
                    f"signature in {SPRAY_WINDOW // 60}m",
                    longer, ip,
                ))
            elif len(sigs) > 1:
                found.append(_alert(
                    "Credential Stuffing", ip, f"{len(users)} accounts", 85,
                    f"{len(users)} usernames, {len(sigs)} different password "
                    f"signatures, {STUFFING_WINDOW // 60}m window",
                    longer, ip,
                ))

    # --- 4. port scanning: many distinct ports from one IP
    scan = window.within(PORTSCAN_WINDOW, ref)
    ports_by_ip: Dict[str, set] = defaultdict(set)
    for e in scan:
        if e.get("port"):
            ports_by_ip[e["source_ip"]].add(e["port"])
    for ip, ports in ports_by_ip.items():
        if len(ports) >= PORTSCAN_PORTS:
            found.append(_alert(
                "Port Scanning", ip, "-", 70,
                f"{len(ports)} distinct ports probed in {PORTSCAN_WINDOW}s",
                scan, ip,
            ))

    # --- 5. impossible travel: one account, two countries, short window
    travel = window.within(3600, ref)
    countries: Dict[str, set] = defaultdict(set)
    last_ip: Dict[str, str] = {}
    for e in travel:
        user, country = e.get("username"), e.get("country")
        if user and country:
            countries[user].add(country)
            last_ip[user] = e["source_ip"]
    for user, seen in countries.items():
        if len(seen) >= 2:
            found.append(_alert(
                "Impossible Travel", last_ip.get(user, "-"), user, 88,
                f"Same account signed in from {' and '.join(sorted(seen))} "
                f"within an hour",
                travel, last_ip.get(user, "-"),
            ))

    # --- 6. suspicious failures: below brute-force, still worth a Medium.
    #
    # Two rules keep this from becoming noise, both found in rehearsal:
    #
    #   a) Suppression must look at alerts fired in an EARLIER batch too.
    #      Otherwise the loud alert is deduped away, `found` looks empty,
    #      and the Medium duplicate slips out one batch later.
    #
    #   b) It must mean SLOW failures. Firing on the first 3 failures of a
    #      fast burst raises a Medium moments before the High -- two alerts
    #      for one attack. This detector's real job is the low-and-slow
    #      attempt that the burst thresholds are designed to miss.
    loud_ips = {a["source_ip"] for a in found}
    loud_ips |= _recently_loud_ips()
    mild = window.within(SUSPICIOUS_WINDOW, ref)
    fails_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in mild:
        if _failed(e):
            fails_by_ip[e["source_ip"]].append(e)

    for ip, events in fails_by_ip.items():
        if len(events) < SUSPICIOUS_FAILS or ip in loud_ips:
            continue
        span = (events[-1]["ts"] - events[0]["ts"]).total_seconds()
        if span <= BRUTE_FORCE_WINDOW:
            continue  # a fast burst -- let the brute-force detector own it
        # Many accounts from one IP is spraying or stuffing, and those
        # detectors own it. This one is specifically about ONE account being
        # probed slowly, which is the case every other detector misses.
        users = {e.get("username") for e in events if e.get("username")}
        if len(users) > 1:
            continue
        target = next(iter(users), "-")
        found.append(_alert(
            "Suspicious Failed Logins", ip, target, 45,
            f"{len(events)} failed logins against one account spread over "
            f"{int(span // 60)}m — slow enough to stay under the "
            f"brute-force threshold",
            mild, ip,
        ))

    # --- 7. off-hours login: informational, produces the Low band.
    #
    # Only real sign-ins count. Without the event_type guard, a port scan's
    # successful TCP connects at 3am each produced their own Low alert.
    for e in ([new_event] if new_event else []):
        status = (e.get("status") or "").lower()
        kind = (e.get("event_type") or "login").lower()
        if status in {"success", "ok", "accepted"} and "login" in kind:
            hour = e["ts"].hour
            if OFFHOURS_START <= hour < OFFHOURS_END:
                found.append(_alert(
                    "Off-Hours Login", e["source_ip"], e.get("username") or "-", 20,
                    f"Successful sign-in at {e['ts'].strftime('%H:%M')}",
                    [e], e["source_ip"],
                    # Dedup on the ACCOUNT, not the IP: one person on a mobile
                    # network changes IP constantly and would otherwise
                    # generate an endless stream of identical Low alerts.
                    dedup_on=e.get("username") or e["source_ip"],
                ))

    return found


def _alert(attack: str, ip: str, user: str, score: int,
           evidence: str, pool: List[Dict[str, Any]], focus_ip: str,
           dedup_on: Optional[str] = None) -> Dict[str, Any]:
    country = next(
        (e.get("country") for e in reversed(pool)
         if e["source_ip"] == focus_ip and e.get("country")),
        None,
    )
    return {
        "attack_type": attack,
        "source_ip": ip,
        "username": user,
        "risk_score": score,
        "mitre": MITRE.get(attack),
        "evidence": evidence,
        "action": ACTIONS.get(attack, "Review this activity."),
        "country": country,
        "ai": None,   # reserved for ai_engine; escalation-only fusion
        "detected_at": datetime.now(timezone.utc).isoformat(),
        # what makes two of these "the same alert" for deduplication
        "_dedup_on": dedup_on or ip,
    }


# --------------------------------------------------------------- shared state

WINDOW = RollingWindow()
_last_fired: Dict[tuple, datetime] = {}
_hit_counts: Dict[tuple, int] = defaultdict(int)
_clients: List[WebSocket] = []
_alert_seq = 0


# Attacks that silence the low-severity "Suspicious Failed Logins" for the
# same IP.
LOUD_ATTACKS = {"Brute Force", "Password Spraying", "Credential Stuffing"}


def _recently_loud_ips() -> set:
    """IPs that raised a higher-severity alert inside the dedup window."""
    now = datetime.now(timezone.utc)
    return {
        subject
        for (attack, subject), when in _last_fired.items()
        if attack in LOUD_ATTACKS and (now - when).total_seconds() < DEDUP_SECONDS
    }


def _dedup(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One alert per (attack type, subject) per DEDUP_SECONDS, with a counter.

    The subject is usually the source IP, but Off-Hours Login dedups on the
    account instead -- see the note in detect_window.
    """
    global _alert_seq
    out: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    for a in alerts:
        key = (a["attack_type"], a.pop("_dedup_on", a["source_ip"]))
        _hit_counts[key] += 1
        last = _last_fired.get(key)
        if last and (now - last).total_seconds() < DEDUP_SECONDS:
            continue
        _last_fired[key] = now
        _alert_seq += 1
        a["id"] = f"live-{_alert_seq}"
        a["hits"] = _hit_counts[key]
        _hit_counts[key] = 0
        out.append(a)

    return out


async def _broadcast(payload: Dict[str, Any]) -> None:
    dead: List[WebSocket] = []
    message = json.dumps(payload)
    for ws in _clients:
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _clients:
            _clients.remove(ws)


# ------------------------------------------------------------------ endpoints

@router.post("/ingest/stream")
async def ingest_stream(batch: StreamBatch) -> Dict[str, Any]:
    """Accept a batch of events from an agent or the replay tool."""
    fresh: List[Dict[str, Any]] = []
    for item in batch.events:
        event = item.model_dump()
        event["ts"] = _parse_time(event.pop("event_time", None))
        WINDOW.add(event)
        # Evaluate per event. Evaluating per batch skipped attacks that
        # completed early inside the batch -- caught in rehearsal.
        fresh.extend(_dedup(detect_window(WINDOW, event)))

    for alert in fresh:
        await _broadcast({"type": "alert", "alert": alert})

    await _broadcast({"type": "stats", "events_seen": WINDOW.total_seen})

    # Feed the dashboard's raw-event ticker with the tail of this batch.
    # Real traffic, not decoration: it shows the volume the detectors are
    # filtering, which is what makes the alert count mean something.
    tail = batch.events[-4:]
    if tail:
        await _broadcast({
            "type": "events",
            "events": [
                {
                    "t": _parse_time(e.event_time).strftime("%H:%M:%S"),
                    "ip": e.source_ip,
                    "user": e.username or "-",
                    "ok": (e.status or "").lower() in {"success", "ok", "accepted"},
                }
                for e in reversed(tail)
            ],
        })

    return {
        "accepted": len(batch.events),
        "alerts": len(fresh),
        "events_seen": WINDOW.total_seen,
    }


@router.websocket("/ws/live")
async def ws_live(websocket: WebSocket) -> None:
    """Push alerts to the dashboard as they are detected."""
    await websocket.accept()
    _clients.append(websocket)
    try:
        await websocket.send_text(json.dumps({
            "type": "stats",
            "events_seen": WINDOW.total_seen,
        }))
        while True:
            # The client does not send anything; this keeps the socket open
            # and lets us notice a disconnect.
            await asyncio.wait_for(websocket.receive_text(), timeout=3600)
    except (WebSocketDisconnect, asyncio.TimeoutError, Exception):
        pass
    finally:
        if websocket in _clients:
            _clients.remove(websocket)


@router.post("/ingest/reset")
async def ingest_reset() -> Dict[str, str]:
    """Clear the window between demo runs."""
    global WINDOW
    WINDOW = RollingWindow()
    _last_fired.clear()
    _hit_counts.clear()
    return {"status": "reset"}