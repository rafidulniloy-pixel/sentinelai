# main.py
# The main entry point of our SentinelAI backend API.

import csv
import io
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

import models
import schemas
from database import Base, engine, get_db
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SentinelAI API",
    description="AI-Powered Security Operations Assistant.",
    version="0.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Basic health checks ---
@app.get("/")
def read_root():
    return {
        "status": "ok",
        "project": "SentinelAI",
        "message": "Backend is running. Setup successful!",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


# --- Authentication ---
@app.post("/auth/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = models.User(
        full_name=user.full_name,
        email=user.email,
        password_hash=hash_password(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/auth/login", response_model=schemas.Token)
def login(credentials: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == credentials.email).first()
    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_access_token(user.id)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth/me", response_model=schemas.UserOut)
def get_me(current_user: models.User = Depends(get_current_user)):
    return current_user


# --- Log upload & parsing ---
@app.post("/logs/upload")
def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Accept a CSV log file, parse each row, and store it in the database.

    Expected CSV columns (header row required):
    event_time, source_ip, username, event_type, status, port, country, password_sig
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a .csv file")

    raw = file.file.read().decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(raw))

    required = {"event_time", "source_ip", "event_type"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
        raise HTTPException(
            status_code=400,
            detail="CSV must have at least these columns: event_time, source_ip, event_type",
        )

    saved, skipped = 0, 0
    for row in reader:
        try:
            entry = models.LogEntry(
                event_time=datetime.fromisoformat(row["event_time"].strip()),
                source_ip=row["source_ip"].strip(),
                username=(row.get("username") or "").strip() or None,
                event_type=row["event_type"].strip(),
                status=(row.get("status") or "").strip() or None,
                port=int(row["port"]) if (row.get("port") or "").strip() else None,
                country=(row.get("country") or "").strip() or None,
                password_sig=(row.get("password_sig") or "").strip() or None,
            )
            db.add(entry)
            saved += 1
        except Exception:
            skipped += 1  # a malformed line never crashes the upload

    db.commit()
    return {"message": "Upload complete", "rows_saved": saved, "rows_skipped": skipped}


@app.get("/logs/count")
def count_logs(db: Session = Depends(get_db)):
    return {"total_log_entries": db.query(models.LogEntry).count()}

# --- Threat detection (the core engine) ---
import detection


import ai_engine


@app.post("/detect")
def run_detection(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Run rule-based detection, then the Isolation Forest AI layer on top."""
    rule_summary = detection.run_all(db)
    ai_summary = ai_engine.run_ai(db)
    return {"rules": rule_summary, "ai": ai_summary}


# Import our explanation engine (the ExplainabilityEngine from the CO2 design).
import explain


@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    """
    Return every alert, highest risk first.

    Each alert now also carries an 'explanation' object generated on the fly by
    explain.py, so the dashboard can answer "Why is this High risk?" instantly.
    """
    alerts = db.query(models.Alert).order_by(models.Alert.risk_score.desc()).all()
    return [
        {
            "id": a.id,
            "attack_type": a.attack_type,
            "source_ip": a.source_ip,
            "username": a.username,
            "risk_level": a.risk_level,
            "risk_score": a.risk_score,
            "evidence": a.evidence,
            "recommendation": a.recommendation,
            # NEW: the plain-language explanation for non-expert analysts.
            "explanation": explain.generate_explanation(a),
        }
        for a in alerts
    ]


@app.get("/alerts/{alert_id}/explain")
def explain_alert(alert_id: int, db: Session = Depends(get_db)):
    """
    Explain ONE specific alert.

    This matches the 'Generate AI Explanation' use case in our CO2 use-case
    diagram, which is included by both 'Inspect Alert Detail' and
    'Generate Incident Report'.
    """
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "alert_id": alert.id,
        "attack_type": alert.attack_type,
        "risk_level": alert.risk_level,
        "risk_score": alert.risk_score,
        "explanation": explain.generate_explanation(alert),
    }