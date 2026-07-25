# SentinelAI Frontend (Next.js + Tailwind)

The part users see: login screen, dashboard, charts, alert details.

> You do **not** need to build this in Week 1. This note just tells you how to
> create it when you're ready (Sabrina owns the frontend, but everyone should know this).

## Create the frontend app (when you reach that step)

You need **Node.js (LTS)** installed first.

```bash
# From inside the main 'sentinelai' folder, run:
npx create-next-app@latest frontend

# When it asks questions, good beginner-friendly answers are:
#   TypeScript?        No  (simpler to start)
#   ESLint?            Yes
#   Tailwind CSS?      Yes  (your project uses Tailwind)
#   src/ directory?    Yes
#   App Router?        Yes
#   Import alias?      No / default
```

Then run it:

```bash
cd frontend
npm run dev
```

Open http://localhost:3000 to see your app.

## Planned screens (from your CO2 design report)

1. **Login / Register**
2. **Dashboard** — KPI cards + colour-coded risk distribution (red/amber/blue).
3. **Alert detail** — the raw detection plus the plain-language AI explanation.

Design rules: summary first (detail on demand), consistent risk colours everywhere,
and a persistent top navigation bar (Upload, Dashboard, Reports, Chat).
