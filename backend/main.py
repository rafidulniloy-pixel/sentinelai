# main.py
# The main entry point of our SentinelAI backend API.

from fastapi import FastAPI, Depends, HTTPException, status
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

# Create the database tables (if they don't exist yet).
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SentinelAI API",
    description="AI-Powered Security Operations Assistant.",
    version="0.2.0",
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
    # Don't allow two accounts with the same email.
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