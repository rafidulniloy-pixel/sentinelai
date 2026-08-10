"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

// Address of our FastAPI backend.
const API = "http://localhost:8000";

export default function UploadPage() {
  const router = useRouter();

  // --- Page state -----------------------------------------------------------
  const [file, setFile] = useState(null);      // the file the user picked
  const [busy, setBusy] = useState(false);     // true while uploading
  const [result, setResult] = useState(null);  // success info from the backend
  const [error, setError] = useState(null);    // any error message to show

  // --- Send the chosen file to the backend ----------------------------------
  async function handleUpload(e) {
    e.preventDefault();   // stop the browser reloading the page

    // The user must pick a file first.
    if (!file) {
      setError("Please choose a log file first.");
      return;
    }

    // The upload endpoint is protected, so we need the JWT saved at login.
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/");
      return;
    }

    setBusy(true);
    setError(null);
    setResult(null);

    try {
      // FormData is how a browser sends a file to a server.
      const form = new FormData();
      form.append("file", file);

      const res = await fetch(`${API}/logs/upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: form,   // note: we do NOT set Content-Type; the browser does it
      });

      // Token expired - send the user back to log in.
      if (res.status === 401) {
        router.push("/");
        return;
      }

      const data = await res.json();

      if (res.ok) {
        setResult(data);   // e.g. { format_detected, rows_saved, rows_skipped }
      } else {
        setError(data.detail || `Upload failed (HTTP ${res.status}).`);
      }
    } catch {
      setError("Cannot reach the backend. Is it running on port 8000?");
    } finally {
      setBusy(false);
    }
  }

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
            <h1>Upload security logs</h1>
            <div className="sub">Supported formats: CSV · JSON · Apache/Nginx access log</div>
          </div>
          <div className="toolbar">
            <button className="btnghost" onClick={() => router.push("/dashboard")}>
              Back to dashboard
            </button>
          </div>
        </div>

        {error && <div className="errbox">{error}</div>}

        <form className="upbox" onSubmit={handleUpload}>
          {/* Hidden file input, triggered by clicking the styled label below. */}
          <input
            id="logfile"
            type="file"
            accept=".csv,.json,.jsonl,.log,.txt"
            style={{ display: "none" }}
            onChange={(e) => {
              setFile(e.target.files[0]);
              setResult(null);
              setError(null);
            }}
          />

          <label htmlFor="logfile" className="drop">
            <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
              <path d="M12 16V4m0 0 4 4m-4-4-4 4" />
              <path d="M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
            </svg>
            <span className="dt">{file ? file.name : "Choose a log file"}</span>
            <span className="ds">
              {file
                ? `${(file.size / 1024).toFixed(1)} KB ready to upload`
                : "Click to browse for a .csv, .json or .log file"}
            </span>
          </label>

          <button className="btnsm" type="submit" disabled={busy} style={{ marginTop: 18 }}>
            {busy ? "Uploading…" : "Upload and store logs"}
          </button>
        </form>

        {/* Success panel: shows the detected format and how many rows were stored. */}
        {result && (
          <div className="okbox">
            <div className="okh">Upload complete</div>
            <div className="okr">
              Format detected: <b>{result.format_detected}</b>
              <br />
              <b>{result.rows_saved}</b> log entries stored
              {result.rows_skipped > 0 && ` · ${result.rows_skipped} unreadable lines skipped`}
            </div>
            <button
              className="btnsm"
              style={{ marginTop: 14 }}
              onClick={() => router.push("/dashboard")}
            >
              Go to dashboard and run detection
            </button>
          </div>
        )}
      </div>
    </>
  );
}