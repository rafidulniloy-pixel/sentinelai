# main.py
# =============================================================================
# SentinelAI - main API entry point
#
# This file wires together every part of the backend:
#   auth.py       - password hashing + JWT tokens
#   parsers.py    - CSV / JSON / Apache log parsing
#   detection.py  - the 5 rule-based attack detectors
#   ai_engine.py  - Isolation Forest anomaly layer + risk fusion
#   explain.py    - plain-language explanation generator
#   report.py     - PDF incident report builder
# =============================================================================

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session

# --- Our own modules ---------------------------------------------------------
import ai_engine
import detection
import explain
import models
import parsers
import report
import schemas
from database import Base, engine, get_db
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)

# Create any database tables that do not exist yet.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SentinelAI API",
    description="AI-Powered Security Operations Assistant.",
    version="1.0.0",
)

# Allow our Next.js frontend (port 3000) to call this backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# HEALTH CHECKS
# =============================================================================
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


# =============================================================================
# AUTHENTICATION  (MVP Feature 1)
# =============================================================================
@app.post("/auth/register", response_model=schemas.UserOut,
          status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Create a new account. The password is hashed, never stored in plain text."""
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
    """Check the credentials and return a JWT access token if they are correct."""
    user = db.query(models.User).filter(models.User.email == credentials.email).first()
    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    token = create_access_token(user.id)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth/me", response_model=schemas.UserOut)
def get_me(current_user: models.User = Depends(get_current_user)):
    """A protected endpoint: only works with a valid token."""
    return current_user


# =============================================================================
# LOG UPLOAD AND PARSING  (MVP Feature 2)
# =============================================================================
@app.post("/logs/upload")
def upload_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Accept a log file, parse it, and store every valid line in the database.

    Supported formats:
      .csv                  - our normalized CSV export
      .json / .jsonl        - JSON array or JSON Lines
      .log / .txt           - Apache / Nginx access log
    """
    # Read the uploaded bytes and decode to text.
    # errors="ignore" means one odd byte never crashes the whole upload.
    raw_text = file.file.read().decode("utf-8", errors="ignore")

    # parsers.py picks the correct parser based on the file extension.
    try:
        rows, skipped, format_name = parsers.parse_log_file(file.filename, raw_text)
    except ValueError as e:
        # A bad file is a user mistake, so return 400 with a clear message.
        raise HTTPException(status_code=400, detail=str(e))

    # Store every successfully parsed row.
    for row in rows:
        db.add(models.LogEntry(**row))
    db.commit()

    return {
        "message": "Upload complete",
        "format_detected": format_name,
        "rows_saved": len(rows),
        "rows_skipped": skipped,
    }


@app.get("/logs/count")
def count_logs(db: Session = Depends(get_db)):
    """How many log entries are currently stored (used by the dashboard)."""
    return {"total_log_entries": db.query(models.LogEntry).count()}


# =============================================================================
# THREAT DETECTION  (MVP Feature 3) - rule engine + Isolation Forest AI
# =============================================================================
@app.post("/detect")
def run_detection(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Run the full detection pipeline:
      1. Five rule-based detectors create alerts.
      2. The Isolation Forest AI layer scores every IP and fuses its opinion
         into those alerts (escalation-only: it can raise risk, never lower it).
    """
    rule_summary = detection.run_all(db)
    ai_summary = ai_engine.run_ai(db)
    return {"rules": rule_summary, "ai": ai_summary}


# =============================================================================
# ALERTS + AI EXPLANATION  (MVP Features 4 and 5)
# =============================================================================
@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    """
    Return every alert, highest risk first.

    Each alert also carries an 'explanation' object generated on the fly, so
    the dashboard can instantly answer "Why is this High risk?".
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
            "explanation": explain.generate_explanation(a),
        }
        for a in alerts
    ]


@app.get("/alerts/{alert_id}/explain")
def explain_alert(alert_id: int, db: Session = Depends(get_db)):
    """
    Explain ONE specific alert.

    Matches the 'Generate AI Explanation' use case in our CO2 use-case diagram.
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


# =============================================================================
# PDF INCIDENT REPORT  (MVP Feature 6)
# =============================================================================
@app.get("/reports/pdf")
def download_report(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Generate the PDF incident report and send it to the browser as a download."""
    # Most dangerous first, so the report reads top-down by severity.
    alerts = db.query(models.Alert).order_by(models.Alert.risk_score.desc()).all()

    if not alerts:
        raise HTTPException(
            status_code=404,
            detail="No alerts found. Run detection before generating a report.",
        )

    total_logs = db.query(models.LogEntry).count()
    pdf_bytes = report.build_pdf(alerts, total_logs)

    # "attachment" tells the browser to download rather than display the file.
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=SentinelAI_Incident_Report.pdf"
        },
    )