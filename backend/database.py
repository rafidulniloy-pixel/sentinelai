import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Reads the setting from Docker if it exists.
# If not (on your laptop), uses the same SQLite file as always.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelai.db")

# SQLite needs this flag. PostgreSQL does not accept it.
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    connect_args = {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()