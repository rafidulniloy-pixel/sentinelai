"use client";
// SentinelAI — Live Attack Feed
//
// "use client" MUST stay on line 1, above every comment. If it moves below a
// comment, Next.js treats this as a server component and you get:
//   Element type is invalid... but got: object
//
// Connects to the backend over a WebSocket and prepends alerts as they fire.
// If the backend is unreachable it falls back to a clearly-labelled replay so
// a presentation never dies on stage.

import { useCallback, useEffect, useRef, useState } from "react";
import NavBar from "../NavBar";
import "./live.css";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const WS_URL = API.replace(/^http/, "ws") + "/ws/live";
const MAX_FEED = 50;
const MAX_TICKS = 6;

const band = (s) => (s >= 71 ? "high" : s >= 31 ? "medium" : "low");

function ago(iso) {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  return Math.floor(s / 3600) + "h ago";
}

// "AI anomaly score 0.88 | AI drivers: event rate (1.00), failed logins (8)"
// becomes a list of bars.
function parseDrivers(ai) {
  if (!ai) return [];
  const part = ai.split(/drivers:/i)[1];
  if (!part) return [];
  return part
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, 4)
    .map((name, i) => ({ name, weight: Math.max(28, 92 - i * 22) }));
}

function threatOf(counts) {
  if (counts.high >= 3) return { key: "critical", label: "Critical", pct: 96 };
  if (counts.high >= 1) return { key: "elevated", label: "Elevated", pct: 68 };
  if (counts.medium >= 1) return { key: "guarded", label: "Guarded", pct: 38 };
  return { key: "calm", label: "Nominal", pct: 12 };
}

/* ---------------------------------------- replay used only as a fallback */

const REPLAY = [
  { attack_type: "Brute Force", source_ip: "45.148.10.92", username: "admin",
    risk_score: 92, mitre: "T1110", country: "NL",
    evidence: "11 failed logins in 38s from one IP against one account",
    ai: "AI anomaly score 0.88 | AI drivers: event rate, failed logins",
    action: "Block the source IP and force a password reset on this account." },
  { attack_type: "Port Scanning", source_ip: "185.220.101.7", username: "-",
    risk_score: 70, mitre: "T1046", country: "DE",
    evidence: "23 distinct ports probed in 104s",
    ai: "AI anomaly score 0.74 | AI drivers: distinct ports, event rate",
    action: "Confirm which services are exposed and close what is not needed." },
  { attack_type: "Password Spraying", source_ip: "103.108.229.14", username: "8 accounts",
    risk_score: 82, mitre: "T1110.003", country: "BD",
    evidence: "8 usernames tried with one identical password signature in 9m",
    ai: "AI anomaly score 0.81 | AI drivers: distinct usernames, failed logins",
    action: "Enable MFA and review the targeted accounts for a weak shared password." },
  { attack_type: "Off-Hours Login", source_ip: "103.230.106.18", username: "r.islam",
    risk_score: 20, mitre: null, country: "BD",
    evidence: "Successful sign-in at 03:14 local time",
    ai: "AI anomaly score 0.31 | AI drivers: event rate",
    action: "Informational. Confirm with the user if this is unusual for them." },
  { attack_type: "Credential Stuffing", source_ip: "91.219.236.166", username: "6 accounts",
    risk_score: 85, mitre: "T1110.004", country: "RU",
    evidence: "6 usernames, 6 different password signatures, 7m window",
    ai: "AI anomaly score 0.79 | AI drivers: distinct usernames, failed logins",
    action: "Check these accounts against known breach lists and force resets." },
  { attack_type: "Impossible Travel", source_ip: "27.147.180.33", username: "finance.ops",
    risk_score: 88, mitre: "T1078", country: "BR",
    evidence: "Same account signed in from BD and BR 41 minutes apart",
    ai: "AI anomaly score 0.62 | AI drivers: distinct countries",
    action: "Treat the account as compromised. Revoke sessions, then reset." },
  { attack_type: "Suspicious Failed Logins", source_ip: "159.65.12.201", username: "backup",
    risk_score: 45, mitre: null, country: "SG",
    evidence: "4 failed logins against one account spread over 11m",
    ai: "AI anomaly score 0.44 | AI drivers: failed logins",
    action: "Watch this IP. If the rate rises it becomes a brute-force case." },
];

const FAKE_TICKS = [
  { ip: "103.230.106.41", u: "s.tonima", ok: true },
  { ip: "45.148.10.92", u: "admin", ok: false },
  { ip: "185.220.101.7", u: "-", ok: true },
  { ip: "91.219.236.166", u: "acct3", ok: false },
  { ip: "103.108.229.14", u: "staff5", ok: false },
];

/* ------------------------------------------------------------- component */

export default function LivePage() {
  const [alerts, setAlerts] = useState([]);
  const [ticks, setTicks] = useState([]);
  const [status, setStatus] = useState("connecting");
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("all");
  const [seen, setSeen] = useState(0);
  const [openId, setOpenId] = useState(null);
  const [, redraw] = useState(0);

  const pausedRef = useRef(false);
  const timerRef = useRef(null);
  const idxRef = useRef(0);
  const seqRef = useRef(0);

  useEffect(() => { pausedRef.current = paused; }, [paused]);

  // keep the "12s ago" labels honest
  useEffect(() => {
    const t = setInterval(() => redraw((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const push = useCallback((raw, isDemo) => {
    if (pausedRef.current) return;
    seqRef.current += 1;
    const a = {
      hits: 1,
      ...raw,
      id: raw.id ?? "a" + seqRef.current,
      detected_at: raw.detected_at ?? new Date().toISOString(),
      demo: !!isDemo,
      fresh: true,
    };
    setAlerts((prev) => [a, ...prev].slice(0, MAX_FEED));
    setTimeout(() => {
      setAlerts((prev) => prev.map((x) => (x.id === a.id ? { ...x, fresh: false } : x)));
    }, 1200);
  }, []);

  const addTicks = useCallback((rows) => {
    if (pausedRef.current || !rows || rows.length === 0) return;
    setTicks((prev) => [...rows, ...prev].slice(0, MAX_TICKS));
  }, []);

  const startDemo = useCallback(() => {
    setStatus("demo");
    if (timerRef.current) return;
    const step = () => {
      const base = REPLAY[idxRef.current % REPLAY.length];
      idxRef.current += 1;
      const ip =
        idxRef.current > REPLAY.length
          ? base.source_ip.replace(/\.\d+$/, "." + (20 + (idxRef.current * 7) % 200))
          : base.source_ip;
      push({ ...base, source_ip: ip }, true);
      setSeen((v) => v + 40 + Math.floor(Math.random() * 90));
      const f = FAKE_TICKS[idxRef.current % FAKE_TICKS.length];
      addTicks([{
        t: new Date().toLocaleTimeString("en-GB"),
        ip: f.ip, user: f.u, ok: f.ok,
      }]);
      timerRef.current = setTimeout(step, 2300 + Math.random() * 2400);
    };
    timerRef.current = setTimeout(step, 700);
  }, [push, addTicks]);

  useEffect(() => {
    let dead = false;
    let sock;

    try {
      sock = new WebSocket(WS_URL);
      const bail = setTimeout(() => {
        if (sock.readyState !== 1) {
          try { sock.close(); } catch (e) {}
          if (!dead) startDemo();
        }
      }, 2500);

      sock.onopen = () => { clearTimeout(bail); if (!dead) setStatus("live"); };

      sock.onmessage = (ev) => {
        try {
          const m = JSON.parse(ev.data);
          if (m.type === "alert") push(m.alert, false);
          if (m.type === "stats" && typeof m.events_seen === "number") setSeen(m.events_seen);
          if (m.type === "events") addTicks(m.events);
        } catch (e) {}
      };

      sock.onerror = () => { clearTimeout(bail); if (!dead) startDemo(); };
      sock.onclose = () => { clearTimeout(bail); if (!dead) startDemo(); };
    } catch (e) {
      startDemo();
    }

    return () => {
      dead = true;
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = null;
      try { if (sock) sock.close(); } catch (e) {}
    };
  }, [push, addTicks, startDemo]);

  const counts = { high: 0, medium: 0, low: 0 };
  alerts.forEach((a) => { counts[band(a.risk_score)] += 1; });
  const threat = threatOf(counts);

  const shown =
    filter === "all" ? alerts : alerts.filter((a) => band(a.risk_score) === filter);

  return (
        <>
      <NavBar />
      <main className="lv">
      {/* ------------------------------------------------------ header */}
      <header className="lv-head">
        <div>
          <h1 className="lv-title">Live attack feed</h1>
          <p className="lv-sub">
            Realtime streaming detection &middot; monitoring{" "}
            <b>{seen.toLocaleString()}</b> events &middot; no upload needed
          </p>
        </div>

        <div className={`lv-status lv-status--${status}`}>
          <span className="lv-beacon" aria-hidden="true" />
          <span>
            {status === "live"
              ? "Live — engine connected"
              : status === "demo"
              ? "Demo replay"
              : "Connecting"}
          </span>
        </div>
      </header>

      {/* ------------------------------------------------ threat meter */}
      <div className="lv-threat">
        <span className="lv-threat-label">Threat level</span>
        <span className="lv-threat-track">
          <span
            className={`lv-threat-fill lv-threat-fill--${threat.key}`}
            style={{ width: threat.pct + "%" }}
          />
        </span>
        <span className={`lv-threat-value lv-threat-value--${threat.key}`}>
          {threat.label}
        </span>
      </div>

      {status === "demo" && (
        <div className="lv-banner" role="status">
          <b>Demo replay.</b> The detection engine is not reachable, so this page is
          replaying a recorded attack sequence. Start the backend and refresh for live
          detection.
        </div>
      )}

      {/* ------------------------------------------------------- stats */}
      <section className="lv-stats" aria-label="Summary">
        <div className="lv-stat">
          <span className="lv-stat-v">{seen.toLocaleString()}</span>
          <span className="lv-stat-k">Events</span>
        </div>
        <div className="lv-stat">
          <span className="lv-stat-v">{alerts.length}</span>
          <span className="lv-stat-k">Alerts</span>
        </div>
        <div className="lv-stat lv-stat--high">
          <span className="lv-stat-v">{counts.high}</span>
          <span className="lv-stat-k">High</span>
        </div>
        <div className="lv-stat lv-stat--med">
          <span className="lv-stat-v">{counts.medium}</span>
          <span className="lv-stat-k">Medium</span>
        </div>
        <div className="lv-stat lv-stat--low">
          <span className="lv-stat-v">{counts.low}</span>
          <span className="lv-stat-k">Low</span>
        </div>
      </section>

      {/* ---------------------------------------------------- controls */}
      <section className="lv-controls">
        <div className="lv-chips" role="group" aria-label="Filter by severity">
          {[
            ["all", "All", alerts.length],
            ["high", "High", counts.high],
            ["medium", "Medium", counts.medium],
            ["low", "Low", counts.low],
          ].map(([key, label, n]) => (
            <button
              key={key}
              type="button"
              className={`lv-chip${filter === key ? " on" : ""}`}
              onClick={() => setFilter(key)}
            >
              {label}
              <span className="lv-chip-n">{n}</span>
            </button>
          ))}
        </div>

        <div className="lv-acts">
          <button
            type="button"
            className={`lv-btn${paused ? " paused" : ""}`}
            onClick={() => setPaused((p) => !p)}
          >
            {paused ? "Resume" : "Pause"}
          </button>
          <button type="button" className="lv-btn" onClick={() => setAlerts([])}>
            Clear
          </button>
        </div>
      </section>

      {/* -------------------------------------------------------- feed */}
      <section className="lv-feed" aria-live="polite" aria-label="Alert feed">
        {shown.length === 0 && (
          <div className="lv-empty">
            <div className="lv-empty-ring" aria-hidden="true" />
            <p>Watching for attacks</p>
            <span>Alerts appear here the moment a detector fires.</span>
          </div>
        )}

        {shown.map((a) => {
          const b = band(a.risk_score);
          const isOpen = openId === a.id;
          const drivers = parseDrivers(a.ai);
          return (
            <article
              key={a.id}
              className={`lv-alert lv-alert--${b}${a.fresh ? " fresh" : ""}`}
            >
              <button
                type="button"
                className="lv-row"
                onClick={() => setOpenId(isOpen ? null : a.id)}
                aria-expanded={isOpen}
              >
                <span className="lv-sev">{b}</span>

                <span className="lv-mid">
                  <span className="lv-line1">
                    <span className="lv-name">{a.attack_type}</span>
                    {a.mitre && <span className="lv-mitre">{a.mitre}</span>}
                    {a.hits > 1 && <span className="lv-rep">&times;{a.hits}</span>}
                  </span>

                  <span className="lv-line2">
                    <span className="lv-ip">{a.source_ip}</span>
                    {a.country && <span className="lv-geo">{a.country}</span>}
                    {a.username && a.username !== "-" && (
                      <span className="lv-acct">
                        account <b>{a.username}</b>
                      </span>
                    )}
                    <span className="lv-age">{ago(a.detected_at)}</span>
                  </span>

                  <span className="lv-ev">{a.evidence}</span>
                </span>

                <span className="lv-score">
                  <span className="lv-score-n">{a.risk_score}</span>
                  <span className="lv-score-k">risk</span>
                </span>
              </button>

              {isOpen && (
                <div className="lv-detail">
                  {drivers.length > 0 && (
                    <div>
                      <div className="lv-dk">Why the model agreed</div>
                      <div className="lv-drivers">
                        {drivers.map((d) => (
                          <div className="lv-driver" key={d.name}>
                            <span className="lv-driver-k">{d.name}</span>
                            <span className="lv-driver-track">
                              <span
                                className="lv-driver-fill"
                                style={{ width: d.weight + "%" }}
                              />
                            </span>
                            <span className="lv-driver-v">{d.weight}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <div className="lv-dk">Recommended action</div>
                    <div className="lv-dv">{a.action}</div>
                  </div>

                  {a.demo && (
                    <p className="lv-note">Replayed event — not a live detection.</p>
                  )}
                </div>
              )}
            </article>
          );
        })}
      </section>

      {/* ------------------------------------------------------ ticker */}
      <section className="lv-ticker" aria-label="Raw event stream">
        <div className="lv-ticker-head">
          <span className="lv-ticker-dot" aria-hidden="true" />
          <span>Raw event stream</span>
        </div>
        <div className="lv-ticker-body">
          {ticks.length === 0 && (
            <span className="lv-tick">waiting for traffic…</span>
          )}
          {ticks.map((t, i) => (
            <span className="lv-tick" key={i}>
              {t.t} &nbsp;<em>{t.ip}</em> &nbsp;{t.user} &nbsp;
              <span className={t.ok ? "ok" : "no"}>
                {t.ok ? "SUCCESS" : "FAILED"}
              </span>
            </span>
          ))}
        </div>
       </section>
      </main>
    </>
  );
}
