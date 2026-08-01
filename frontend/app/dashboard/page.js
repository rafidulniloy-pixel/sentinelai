"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

const API = "http://localhost:8000";

export default function Dashboard() {
  const router = useRouter();
  const [alerts, setAlerts] = useState([]);
  const [logCount, setLogCount] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function loadData() {
    try {
      const [aRes, cRes] = await Promise.all([
        fetch(`${API}/alerts`),
        fetch(`${API}/logs/count`),
      ]);
      setAlerts(await aRes.json());
      const c = await cRes.json();
      setLogCount(c.total_log_entries);
      setError(null);
    } catch {
      setError("Cannot reach the backend. Is it running on port 8000?");
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  async function runDetection() {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`${API}/detect`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401) {
        router.push("/");
        return;
      }
      await res.json();
      await loadData();
    } catch {
      setError("Detection failed. Is the backend running?");
    } finally {
      setBusy(false);
    }
  }

  function logout() {
    localStorage.removeItem("token");
    router.push("/");
  }

  const high = alerts.filter((a) => a.risk_level === "High").length;
  const medium = alerts.filter((a) => a.risk_level === "Medium").length;
  const pill = (lvl) =>
    lvl === "High" ? "pill p-hi" : lvl === "Medium" ? "pill p-md" : "pill p-lo";

  return (
    <>
      <div className="brand">
        <span className="m">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#04121a" strokeWidth="2.4"><path d="M12 2 4 5v6c0 5 3.5 8 8 11 4.5-3 8-6 8-11V5l-8-3Z" /></svg>
        </span>
        SentinelAI
      </div>

      <div className="dash">
        <div className="dhead">
          <div>
            <h1>Security operations dashboard</h1>
            <div className="sub">Realtime threat monitoring · rule engine + Isolation Forest AI</div>
          </div>
          <div className="toolbar">
            <button className="btnsm" onClick={runDetection} disabled={busy}>
              {busy ? "Scanning…" : "Run detection"}
            </button>
            <button className="btnghost" onClick={logout}>Log out</button>
          </div>
        </div>

        {error && <div className="errbox">{error}</div>}

        <div className="kpirow">
          <div className="kcard">
            <div className="lbl">Logs analyzed</div>
            <div className="num">{logCount}</div>
          </div>
          <div className="kcard">
            <div className="lbl">Total alerts</div>
            <div className="num">{alerts.length}</div>
          </div>
          <div className="kcard">
            <div className="lbl">High risk</div>
            <div className="num" style={{ color: "#ff8ca3" }}>{high}</div>
          </div>
          <div className="kcard">
            <div className="lbl">Medium risk</div>
            <div className="num" style={{ color: "#ffce78" }}>{medium}</div>
          </div>
        </div>

        <div className="alist">
          {alerts.length === 0 && (
            <div className="empty">
              No alerts yet. Click "Run detection" to scan the uploaded logs.
            </div>
          )}
          {alerts.map((a) => (
            <div className="acard" key={a.id}>
              <div className="top">
                <span className={pill(a.risk_level)}>{a.risk_level}</span>
                <span className="atk">{a.attack_type}</span>
                <span className="ip">{a.source_ip}{a.username ? ` · ${a.username}` : ""}</span>
                <span className="score">{a.risk_score}</span>
              </div>
              <div className="ev">{a.evidence}</div>
              <div className="rec"><b>Recommended:</b> {a.recommendation}</div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}