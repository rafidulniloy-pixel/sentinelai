"""
SentinelAI - Backend (Week 1 starter)
======================================

This is a MINIMAL FastAPI app. Its only job right now is to prove that your
Python + FastAPI setup works. Real features (login, log upload, detection)
are added in later weeks.

HOW TO RUN (after installing Python):
    1. Open a terminal in this 'backend' folder.
    2. (First time only) create a virtual environment:
           python -m venv .venv
       Activate it:
           Windows:  .venv\\Scripts\\activate
           Mac/Linux: source .venv/bin/activate
    3. Install the packages:
           pip install -r requirements.txt
    4. Start the server:
           uvicorn main:app --reload
    5. Open your browser at http://127.0.0.1:8000
       You should see: {"status": "ok", ...}
    6. Bonus: open http://127.0.0.1:8000/docs to see the auto-generated API page.
"""

from fastapi import FastAPI

# 'app' is the main object that represents your web API.
app = FastAPI(
    title="SentinelAI API",
    description="AI-Powered Security Operations Assistant (Week 1 skeleton).",
    version="0.1.0",
)


@app.get("/")
def read_root():
    """The home endpoint. Visiting the root URL returns this message."""
    return {
        "status": "ok",
        "project": "SentinelAI",
        "message": "Backend is running. Setup successful!",
    }


@app.get("/health")
def health_check():
    """A simple health check. Useful later for Docker and deployment."""
    return {"status": "healthy"}


# --- Coming in later weeks (leave as notes for now) ---
# Week 2-3: POST /auth/register, POST /auth/login  (JWT authentication)
# Week 4:   POST /logs/upload                      (upload & parse a log file)
# Week 5:   POST /detect                           (run rule + Isolation Forest detection)
# Week 6:   GET  /dashboard, GET /alerts/{id}/explain
# Week 7:   GET  /reports/{id}/pdf
