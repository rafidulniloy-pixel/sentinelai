"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  // --- Form state -----------------------------------------------------------
  const [email, setEmail] = useState("rafi@example.com");
  const [password, setPassword] = useState("mysecret123");
  const [message, setMessage] = useState(null);   // success or error message
  const [loading, setLoading] = useState(false);  // true while logging in
  const router = useRouter();

  // --- Send the credentials to the backend ----------------------------------
  async function handleLogin(e) {
    e.preventDefault();   // stop the browser reloading the page
    setMessage(null);
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8000/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();

      if (res.ok) {
        // Save the JWT so protected pages (dashboard, upload) can use it.
        localStorage.setItem("token", data.access_token);
        setMessage({ type: "ok", text: "Access granted. Redirecting…" });
        setTimeout(() => router.push("/dashboard"), 800);
      } else {
        setMessage({ type: "err", text: data.detail || "Login failed." });
      }
    } catch (err) {
      setMessage({ type: "err", text: "Cannot reach the server. Is the backend running?" });
    } finally {
      setLoading(false);
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

      <div className="login">
        <form className="card" onSubmit={handleLogin}>
          {/* Biometric fingerprint scanner graphic */}
          <svg className="hud" viewBox="0 0 220 220">
            <g fill="none" stroke="var(--blue)" strokeWidth="2" strokeDasharray="4 10" opacity=".85">
              <circle cx="110" cy="110" r="100">
                <animateTransform attributeName="transform" type="rotate" from="0 110 110" to="360 110 110" dur="16s" repeatCount="indefinite" />
              </circle>
            </g>
            <g fill="none" strokeLinecap="round">
              <path d="M110,18 A92,92 0 0 1 190,70" stroke="var(--cyan)" strokeWidth="3">
                <animateTransform attributeName="transform" type="rotate" from="360 110 110" to="0 110 110" dur="10s" repeatCount="indefinite" />
              </path>
              <path d="M110,202 A92,92 0 0 1 30,150" stroke="var(--red)" strokeWidth="3">
                <animateTransform attributeName="transform" type="rotate" from="360 110 110" to="0 110 110" dur="10s" repeatCount="indefinite" />
              </path>
            </g>
            <circle cx="110" cy="110" r="74" fill="none" stroke="rgba(124,92,255,.5)" strokeWidth="1.5" />
            <g fill="none" stroke="var(--cyan)" strokeWidth="0.5" strokeLinecap="round" strokeLinejoin="round" opacity=".95" transform="translate(54.8,54.8) scale(4.6)">
              <path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4" />
              <path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2" />
              <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
              <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
              <path d="M8.65 22c.21-.66.45-1.32.57-2" />
              <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
              <path d="M2 16h.01" />
              <path d="M21.8 16c.2-2 .13-5.35 0-6" />
              <path d="M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2" />
            </g>
            {/* The red scan line sweeping over the fingerprint */}
            <line x1="72" y1="110" x2="148" y2="110" stroke="var(--red)" strokeWidth="2" opacity=".9">
              <animateTransform attributeName="transform" type="translate" values="0 -20; 0 22; 0 -20" dur="3.2s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0;.9;0" dur="3.2s" repeatCount="indefinite" />
            </line>
            <circle cx="110" cy="10" r="3.5" fill="var(--cyan)" />
            <circle cx="207" cy="140" r="3" fill="var(--red)" />
            <circle cx="14" cy="90" r="3" fill="var(--blue)" />
          </svg>

          <h2>Secure access</h2>
          <p className="s">Authenticate to enter the operations dashboard</p>

          <div className="field">
            <label>Email</label>
            <div className="inp">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="5" width="18" height="14" rx="2" /><path d="m3 7 9 6 9-6" /></svg>
              <input type="text" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
          </div>

          <div className="field">
            <label>Password</label>
            <div className="inp">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
          </div>

          <button className="btn" type="submit" disabled={loading}>
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M12 2 4 5v6c0 5 3.5 8 8 11 4.5-3 8-6 8-11V5l-8-3Z" /><path d="m9 12 2 2 4-4" /></svg>
            {loading ? "Authenticating…" : "Authenticate"}
          </button>

          {message && <p className={`msg ${message.type}`}>{message.text}</p>}

          <p className="foot">
            No account yet?{" "}
            <a onClick={() => router.push("/register")}>Request access</a>
          </p>
        </form>
      </div>
    </>
  );
}