# database.py
# This file sets up the connection to our database.

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# For now we use SQLite: a simple database saved as a single file
# named "sentinelai.db" inside the backend folder. Nothing to install.
# LATER, to switch to PostgreSQL, we only change this ONE line.
DATABASE_URL = "sqlite:///./sentinelai.db"

# The "engine" is the actual connection to the database.
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# A "session" is one conversation with the database.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# "Base" is the parent that all our database tables will build on.
Base = declarative_base()

# This helper gives each request its own database session,
# then safely closes it when the request is finished.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()