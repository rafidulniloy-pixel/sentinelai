# models.py
# This file describes our database tables as Python classes.

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from database import Base


# The "users" table (accounts that can log in to SentinelAI).
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# The "log_entries" table — one row per line of an uploaded log file.
class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    event_time = Column(DateTime, index=True, nullable=False)   # when the event happened
    source_ip = Column(String, index=True, nullable=False)      # who did it (IP address)
    username = Column(String, index=True)                       # which account was targeted
    event_type = Column(String, index=True, nullable=False)     # login_failed / login_success / connection
    status = Column(String)                                     # extra status text (optional)
    port = Column(Integer)                                      # port touched (for port scans)
    country = Column(String)                                    # login country (for impossible travel)
    password_sig = Column(String)                               # password fingerprint (synthetic demo only)
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())


# The "alerts" table — one row per detected attack.
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    attack_type = Column(String, index=True, nullable=False)    # e.g. "Brute Force Attack"
    source_ip = Column(String, index=True)                      # offending IP (if applicable)
    username = Column(String)                                   # affected account (if applicable)
    risk_level = Column(String, nullable=False)                 # Low / Medium / High
    risk_score = Column(Integer, nullable=False)                # 0-100
    evidence = Column(String)                                   # short human-readable proof
    recommendation = Column(String)                             # suggested action
    detected_at = Column(DateTime(timezone=True), server_default=func.now())