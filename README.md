# SentinelAI — An AI-Powered Security Operations Assistant

**Course:** CSE 499A (Section 1) · **Group:** G-9 · **Supervisor:** Dr. Shazzad Hosain (SZZ)

SentinelAI ingests security logs, detects threats (rule-based + Isolation Forest),
assigns a Low/Medium/High risk score, and explains each alert in plain language.

> This is the **Week 1 starter skeleton**. It is intentionally minimal. Features are
> added week by week following the roadmap in `SentinelAI_Start_Guide.md`.

---

## Team

| Member | Responsibility |
|--------|----------------|
| Rafidul Islam Niloy | AI/ML detection engine (Isolation Forest, risk scoring, AI explanation) |
| Sabrina Tabassum Tonima | Frontend (React/Next.js dashboard, charts, UI/UX) |
| A K M Mohiuddin | Backend (FastAPI), database (PostgreSQL/Redis), auth, Docker/CI |

## Planned tech stack

- **Frontend:** React, Next.js, Tailwind CSS
- **Backend:** FastAPI (Python)
- **Database:** PostgreSQL + Redis
- **AI/ML:** scikit-learn, XGBoost, Isolation Forest
- **Charts:** Chart.js / ECharts
- **Deploy:** Docker, GitHub Actions

## Folder structure

```
sentinelai/
├── README.md            <- you are here
├── .gitignore           <- files Git should ignore
├── backend/             <- FastAPI backend (Python)
│   ├── main.py          <- the "hello world" API to prove setup works
│   ├── requirements.txt <- Python packages the backend needs
│   └── README.md        <- how to run the backend
└── frontend/            <- Next.js frontend (added in a later step)
    └── README.md        <- how to create the frontend app
```

## Quick start (do this after installing the tools)

1. Read `../SentinelAI_Start_Guide.md` first.
2. Run the backend: see `backend/README.md`.
3. Create the frontend: see `frontend/README.md`.

## Roadmap (short version)

Setup → Login/Register → Log upload & parsing → Detection (rules + AI) →
Dashboard & charts → AI explanation & PDF report.

Deferred to 499B: real-time streaming, SIEM/SOAR integration, Kubernetes, etc.
