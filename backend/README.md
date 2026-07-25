# SentinelAI Backend (FastAPI)

The engine of the app. Week 1 = a "hello world" API to confirm your setup works.

## Run it (step by step)

You need **Python 3.11+** installed first (see the main Start Guide).

```bash
# 1. Open a terminal inside this 'backend' folder.

# 2. Create a virtual environment (an isolated space for this project's packages)
python -m venv .venv

# 3. Activate it
#    Windows:
.venv\Scripts\activate
#    Mac / Linux:
source .venv/bin/activate

# 4. Install the required packages
pip install -r requirements.txt

# 5. Start the server
uvicorn main:app --reload
```

Now open your browser:

- http://127.0.0.1:8000 → you should see `{"status": "ok", ...}`
- http://127.0.0.1:8000/docs → an interactive API page (FastAPI makes this automatically)

If you see the `ok` message, **your backend setup works.** That's a real Week 1 win.

## What's here now vs. later

- **Now:** `/` and `/health` endpoints (just to prove it runs).
- **Later:** authentication, log upload, detection, dashboard data, PDF reports —
  added week by week per the roadmap.
