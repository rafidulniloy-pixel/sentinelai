"use client";

import { usePathname, useRouter } from "next/navigation";

export default function NavBar() {
  const router = useRouter();
  const pathname = usePathname();

  function logout() {
    localStorage.removeItem("token");
    router.push("/");
  }

  return (
    <nav className="nav">
      <div className="navbrand" onClick={() => router.push("/dashboard")}>
        <span className="m">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#04121a" strokeWidth="2.4">
            <path d="M12 2 4 5v6c0 5 3.5 8 8 11 4.5-3 8-6 8-11V5l-8-3Z" />
          </svg>
        </span>
        SentinelAI
      </div>

      <div className="navlinks">
        <button
          className={`navlink ${pathname === "/dashboard" ? "on" : ""}`}
          onClick={() => router.push("/dashboard")}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <rect x="3" y="3" width="7" height="9" rx="1.5" />
            <rect x="14" y="3" width="7" height="5" rx="1.5" />
            <rect x="14" y="12" width="7" height="9" rx="1.5" />
            <rect x="3" y="16" width="7" height="5" rx="1.5" />
          </svg>
          Dashboard
        </button>

        <button
          className={`navlink ${pathname === "/upload" ? "on" : ""}`}
          onClick={() => router.push("/upload")}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M12 16V4m0 0 4 4m-4-4-4 4" />
            <path d="M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
          </svg>
          Upload logs
        </button>
      </div>

      <div className="navright">
        <span className="navstatus"><span className="dot" />System online</span>
        <button className="navlink" onClick={logout}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <path d="m16 17 5-5-5-5M21 12H9" />
          </svg>
          Log out
        </button>
      </div>
    </nav>
  );
}