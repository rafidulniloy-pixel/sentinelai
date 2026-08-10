// CircuitBackground.js
// =============================================================================
// SentinelAI - premium circuit background (used on every page via layout.js)
//
// DESIGN PRINCIPLES USED HERE:
//   1. RADIAL COMPOSITION - traces flow outward from the centre, like a chip
//      die. We draw ONE quadrant and mirror it 4 ways, so the layout is
//      symmetric (like the reference image) with a quarter of the code.
//   2. FADE MASK - a radial mask hides the traces in the middle of the screen.
//      This keeps the login card / dashboard content readable and stops the
//      background competing with the UI. Detail lives at the edges.
//   3. DEPTH - three layers at different opacities (deep field, base traces,
//      accent traces) so it reads as 3D rather than flat wallpaper.
//   4. RESTRAINT - low opacity, thin strokes, only a few animated nodes.
//      A background should be felt, not noticed.
// =============================================================================

export default function CircuitBackground() {
  return (
    <svg
      aria-hidden="true"                    // decorative only
      style={{
        position: "fixed",
        inset: 0,
        width: "100%",
        height: "100%",
        zIndex: 0,                          // behind all page content
        pointerEvents: "none",              // never blocks clicks
      }}
      viewBox="0 0 1440 900"
      preserveAspectRatio="xMidYMid slice"
    >
      <defs>
        {/* ---- Soft glow used by the bright nodes ---- */}
        <filter id="nodeGlow" x="-200%" y="-200%" width="500%" height="500%">
          <feGaussianBlur stdDeviation="3.5" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        {/* ---- Radial fade: black centre = traces hidden where content sits ---- */}
        <radialGradient id="fadeGrad" cx="50%" cy="50%" r="62%">
          <stop offset="0%"   stopColor="#000000" />
          <stop offset="26%"  stopColor="#000000" />
          <stop offset="58%"  stopColor="#8a8a8a" />
          <stop offset="100%" stopColor="#ffffff" />
        </radialGradient>
        <mask id="centreFade">
          {/* White areas show the traces, black areas hide them. */}
          <rect width="1440" height="900" fill="url(#fadeGrad)" />
        </mask>

        {/* ---- Ambient colour wash (adds depth behind everything) ---- */}
        <radialGradient id="wash1" cx="18%" cy="12%" r="55%">
          <stop offset="0%" stopColor="#1d4ed8" stopOpacity="0.30" />
          <stop offset="100%" stopColor="#1d4ed8" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="wash2" cx="86%" cy="88%" r="55%">
          <stop offset="0%" stopColor="#a21caf" stopOpacity="0.22" />
          <stop offset="100%" stopColor="#a21caf" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="wash3" cx="50%" cy="50%" r="45%">
          <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.10" />
          <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
        </radialGradient>

        {/* =================================================================
            ONE QUADRANT of circuit traces, drawn from the centre outward
            toward the top-left. Mirroring this gives the full symmetric
            composition. Coordinates are relative to the centre (0,0).
            ================================================================= */}
        <g id="quadrant">
          {/* Base traces - thin, calm, structural */}
          <g fill="none" stroke="#4b7fd4" strokeOpacity="0.55" strokeWidth="1.5"
             strokeLinecap="square" strokeLinejoin="miter">
            <path d="M-150 -40 H-268 L-344 -116 H-540" />
            <path d="M-104 -112 L-186 -194 V-306 H-430" />
            <path d="M-176 -96 L-236 -156 H-368 L-448 -236 H-720" />
            <path d="M-62 -156 V-248 L-142 -328 H-306" />
            <path d="M-208 -32 H-306 L-368 -94 H-568 L-628 -154 H-760" />
            <path d="M-126 -206 L-206 -286 H-348 V-392" />
            <path d="M-268 -62 L-310 -104 V-186" />
            <path d="M-408 -146 V-228 H-536" />
            <path d="M-486 -62 H-608 L-668 -122" />
            <path d="M-84 -266 V-346 H-226 L-286 -406" />
            <path d="M-560 -260 H-660 L-720 -320" />
            <path d="M-330 -300 V-360 H-460" />
          </g>

          {/* Solder pads where traces terminate or turn */}
          <g fill="#5a8fd8" fillOpacity="0.5">
            <rect x="-270" y="-42" width="5" height="5" />
            <rect x="-188" y="-196" width="5" height="5" />
            <rect x="-370" y="-96" width="5" height="5" />
            <rect x="-450" y="-238" width="5" height="5" />
            <rect x="-350" y="-394" width="5" height="5" />
            <rect x="-538" y="-230" width="5" height="5" />
            <rect x="-670" y="-124" width="5" height="5" />
            <rect x="-228" y="-408" width="5" height="5" />
          </g>

          {/* Accent traces - brighter, the "live" circuits */}
          <g fill="none" strokeWidth="1.8" strokeLinecap="round">
            <path d="M-176 -96 L-236 -156 H-368" stroke="#38bdf8" strokeOpacity="0.75" />
            <path d="M-126 -206 L-206 -286 H-348" stroke="#8b5cf6" strokeOpacity="0.65" />
            <path d="M-486 -62 H-608" stroke="#38bdf8" strokeOpacity="0.5" />
            <path d="M-408 -146 V-228" stroke="#e879f9" strokeOpacity="0.45" />
          </g>
        </g>
      </defs>

      {/* ---------------- LAYER 1: ambient colour depth ---------------- */}
      <rect width="1440" height="900" fill="url(#wash1)" />
      <rect width="1440" height="900" fill="url(#wash2)" />
      <rect width="1440" height="900" fill="url(#wash3)" />

      {/* ---------------- LAYER 2: circuit traces, mirrored 4 ways ----------------
           The mask fades them out in the centre so UI content stays readable. */}
      <g mask="url(#centreFade)">
        <g transform="translate(720 450)">
          <use href="#quadrant" />                                {/* top-left    */}
          <use href="#quadrant" transform="scale(-1 1)" />        {/* top-right   */}
          <use href="#quadrant" transform="scale(1 -1)" />        {/* bottom-left */}
          <use href="#quadrant" transform="scale(-1 -1)" />       {/* bottom-right*/}
        </g>

        {/* Faint concentric rings tie the composition to the centre */}
        <g fill="none" stroke="#5b8ad6" strokeOpacity="0.13">
          <circle cx="720" cy="450" r="300" />
          <circle cx="720" cy="450" r="430" />
          <circle cx="720" cy="450" r="580" />
        </g>
      </g>

      {/* ---------------- LAYER 3: glowing nodes (a few gently pulse) ---------------- */}
      <g filter="url(#nodeGlow)" mask="url(#centreFade)">
        <circle cx="272" cy="214" r="2.8" fill="#7dd3fc" />
        <circle cx="1168" cy="214" r="2.8" fill="#7dd3fc" />
        <circle cx="272" cy="686" r="2.8" fill="#c4b5fd" />
        <circle cx="1168" cy="686" r="2.8" fill="#f0abfc" />

        <circle cx="534" cy="144" r="3.2" fill="#38bdf8">
          <animate attributeName="opacity" values="0.25;1;0.25" dur="4.5s" repeatCount="indefinite" />
        </circle>
        <circle cx="906" cy="756" r="3.2" fill="#a78bfa">
          <animate attributeName="opacity" values="1;0.25;1" dur="5.5s" repeatCount="indefinite" />
        </circle>
        <circle cx="1052" cy="330" r="2.6" fill="#e879f9">
          <animate attributeName="opacity" values="0.3;0.95;0.3" dur="6.5s" repeatCount="indefinite" />
        </circle>
        <circle cx="388" cy="570" r="2.6" fill="#38bdf8">
          <animate attributeName="opacity" values="0.9;0.3;0.9" dur="5s" repeatCount="indefinite" />
        </circle>
      </g>
    </svg>
  );
}