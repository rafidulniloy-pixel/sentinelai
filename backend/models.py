# models.py
# This file describes our database tables as Python classes.

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from database import Base


# This class = the "users" table in the database.
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)                # unique ID per user
    full_name = Column(String, nullable=False)                        # the user's name
    email = Column(String, unique=True, index=True, nullable=False)   # login email (no duplicates)
    password_hash = Column(String, nullable=False)                    # the SCRAMBLED password (never the real one)
    created_at = Column(DateTime(timezone=True), server_default=func.now())  # signup time