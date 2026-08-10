"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

// The address of our FastAPI backend.
const API = "http://localhost:8000";

export default function Dashboard() {
  const router = useRouter();

  // --- Page state -----------------------------------------------------------
  const [alerts, setAlerts] = useState([]);      // the list of detected alerts
  const [logCount, setLogCount] = useState(0);   // how many log rows are stored
  const [busy, setBusy] = useState(false);       // true while detection is running
  const [error, setError] = useState(null);      // any error message to show
  const [openId, setOpenId] = useState(null);    // which alert's explanation is open

  // --- Load alerts + log count from the backend -----------------------------
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

  // Run once when the page first opens.
  useEffect(() => {
    loadData();
  }, []);

  // --- Run the detection engine (rules + Isolation Forest AI) ---------------
  async function runDetection() {
    // This endpoint is protected, so we need the JWT saved at login.
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
      // 401 means our token expired - send the user back to log in again.
      if (res.status === 401) {
        router.push("/");
        return;
      }
      await res.json();
      await loadData();   // refresh the screen with the new alerts
    } catch {
      setError("Detection failed. Is the backend running?");
    } finally {
      setBusy(false);
    }
  }

  // --- Download the PDF incident report -------------------------------------
  async function downloadReport() {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/");
      return;
    }
    setError(null);
    try {
      const res = await fetch(`${API}/reports/pdf`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401) {
        router.push("/");
        return;
      }
      if (!res.ok) {
        setError("No report available yet - run detection first.");
        return;
      }
      // Turn the PDF response into a file the browser downloads.
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "SentinelAI_Incident_Report.pdf";
      link.click();
      window.URL.revokeObjectURL(url);
    } catch {
      setError("Could not download the report. Is the backend running?");
    }
  }

  function logout() {
    localStorage.removeItem("token");
    router.push("/");
  }

  // --- Small helpers --------------------------------------------------------
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
            <button className="btnghost" onClick={downloadReport}>Download report</button>
            <button className="btnghost" onClick={logout}>Log out</button>
          </div>
        </div>

        {error && <div className="errbox">{error}</div>}

        {/* Summary cards */}
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

        {/* Alert list */}
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
                <span className="ip">
                  {a.source_ip}{a.username ? ` · ${a.username}` : ""}
                </span>
                <span className="score">{a.risk_score}</span>
              </div>

              <div className="ev">{a.evidence}</div>
              <div className="rec"><b>Recommended:</b> {a.recommendation}</div>

              {/* Toggle button: opens/closes the AI explanation for this alert */}
              <button
                className="whybtn"
                onClick={() => setOpenId(openId === a.id ? null : a.id)}
              >
                {openId === a.id
                  ? "Hide explanation"
                  : `Why is this ${a.risk_level} risk?`}
              </button>

              {/* The AI explanation panel (only shown when this alert is open) */}
              {openId === a.id && a.explanation && (
                <div className="xp">
                  <div className="hl">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flex: "none", marginTop: 2 }}>
                      <path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1M7.7 16.3l-2.1 2.1" />
                      <circle cx="12" cy="12" r="3.2" />
                    </svg>
                    {a.explanation.headline}
                  </div>

                  <div className="row">
                    <span className="k">What is happening</span>
                    {a.explanation.what}
                  </div>

                  <div className="row">
                    <span className="k">Why it is risky</span>
                    {a.explanation.why_risky}
                  </div>

                  <div className="row">
                    <span className="k">What the AI model thought</span>
                    {a.explanation.ai_view}
                  </div>

                  <div className="row">
                    <span className="k">Recommended action</span>
                    {a.explanation.action}
                    <br />
                    <span className="urg">Urgency: {a.explanation.urgency}</span>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </>
  );
}