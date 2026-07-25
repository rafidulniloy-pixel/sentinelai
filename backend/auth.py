# auth.py
# Password scrambling (hashing) + login tokens (JWT) + a "who is logged in" check.

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

import models
from database import get_db

# --- Settings ---
# In a real app, keep SECRET_KEY private (in a hidden file). Fine for learning now.
SECRET_KEY = "change-this-to-a-long-random-secret-string"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


# --- Password hashing ---
def hash_password(password: str) -> str:
    """Scramble a plain password into safe, unreadable text."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Check a typed password against the scrambled version in the database."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


# --- Login token (JWT) ---
def create_access_token(user_id: int) -> str:
    """Make a signed token that proves who the user is, valid for 60 minutes."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# --- "Who is logged in?" check for protected routes ---
bearer_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """Read the token, confirm it's valid, and return the matching user."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user