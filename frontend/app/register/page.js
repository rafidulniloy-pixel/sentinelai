"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

// Address of our FastAPI backend.
const API = "http://localhost:8000";

export default function RegisterPage() {
  const router = useRouter();

  // --- Form state -----------------------------------------------------------
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState(null);   // success or error feedback
  const [loading, setLoading] = useState(false);

  // --- Create the account, then log the new user straight in ----------------
  async function handleRegister(e) {
    e.preventDefault();   // stop the browser reloading the page
    setMessage(null);

    // Basic client-side checks before we bother the server.
    if (!fullName.trim() || !email.trim() || !password) {
      setMessage({ type: "err", text: "Please fill in all fields." });
      return;
    }
    if (password.length < 6) {
      setMessage({ type: "err", text: "Password must be at least 6 characters." });
      return;
    }

    setLoading(true);
    try {
      // STEP 1: create the account.
      const res = await fetch(`${API}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: fullName,
          email: email,
          password: password,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        // FastAPI sends validation errors as a list, plain errors as a string.
        const detail = Array.isArray(data.detail)
          ? "Please check the details you entered."
          : data.detail || "Registration failed.";
        setMessage({ type: "err", text: detail });
        return;
      }

      // STEP 2: account created - now log in automatically so the user does
      // not have to type their password a second time.
      const loginRes = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const loginData = await loginRes.json();

      if (loginRes.ok) {
        localStorage.setItem("token", loginData.access_token);
        setMessage({ type: "ok", text: "Account created. Entering console…" });
        setTimeout(() => router.push("/dashboard"), 900);
      } else {
        // Account exists but auto-login failed - send them to the login screen.
        setMessage({ type: "ok", text: "Account created. Please sign in." });
        setTimeout(() => router.push("/"), 1200);
      }
    } catch {
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
        <form className="card" onSubmit={handleRegister}>
          {/* Shield + plus icon: "create a new protected account" */}
          <svg className="hud" viewBox="0 0 220 220">
            <g fill="none" stroke="var(--blue)" strokeWidth="2" strokeDasharray="4 10" opacity=".85">
              <circle cx="110" cy="110" r="100">
                <animateTransform attributeName="transform" type="rotate" from="0 110 110" to="360 110 110" dur="18s" repeatCount="indefinite" />
              </circle>
            </g>
            <g fill="none" strokeLinecap="round">
              <path d="M110,18 A92,92 0 0 1 190,70" stroke="var(--cyan)" strokeWidth="3">
                <animateTransform attributeName="transform" type="rotate" from="360 110 110" to="0 110 110" dur="12s" repeatCount="indefinite" />
              </path>
              <path d="M110,202 A92,92 0 0 1 30,150" stroke="var(--purple)" strokeWidth="3">
                <animateTransform attributeName="transform" type="rotate" from="360 110 110" to="0 110 110" dur="12s" repeatCount="indefinite" />
              </path>
            </g>
            <circle cx="110" cy="110" r="74" fill="none" stroke="rgba(124,92,255,.5)" strokeWidth="1.5" />
            <g fill="none" stroke="var(--cyan)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" transform="translate(110,110) scale(2.4) translate(-12,-12)">
              <path d="M12 3 5 6v5c0 4.5 3 7 7 9 4-2 7-4.5 7-9V6l-7-3Z" />
              <path d="M12 9v6M9 12h6" />
            </g>
          </svg>

          <h2>Request access</h2>
          <p className="s">Create an account to use the operations console</p>

          <div className="field">
            <label>Full name</label>
            <div className="inp">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></svg>
              <input
                type="text"
                placeholder="Rafidul Islam Niloy"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
              />
            </div>
          </div>

          <div className="field">
            <label>Email</label>
            <div className="inp">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="5" width="18" height="14" rx="2" /><path d="m3 7 9 6 9-6" /></svg>
              <input
                type="email"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>

          <div className="field">
            <label>Password</label>
            <div className="inp">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>
              <input
                type="password"
                placeholder="At least 6 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          <button className="btn" type="submit" disabled={loading}>
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2"><path d="M12 2 4 5v6c0 5 3.5 8 8 11 4.5-3 8-6 8-11V5l-8-3Z" /><path d="M12 9v6M9 12h6" /></svg>
            {loading ? "Creating account…" : "Create account"}
          </button>

          {message && <p className={`msg ${message.type}`}>{message.text}</p>}

          <p className="foot">
            Already registered?{" "}
            <a onClick={() => router.push("/")}>Sign in</a>
          </p>
        </form>
      </div>
    </>
  );
}