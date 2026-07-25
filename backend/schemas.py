# schemas.py
# These describe the SHAPE of data going in and out of our API.

from datetime import datetime
from pydantic import BaseModel, EmailStr


# Data we EXPECT when someone registers.
class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str


# Data we SEND BACK about a user (notice: no password!).
class UserOut(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True


# Data we EXPECT when someone logs in.
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# The login "wristband" (token) we send back after a successful login.
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"