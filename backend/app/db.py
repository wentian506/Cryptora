"""Database setup. MySQL in production, SQLite fallback for local dev.

Set DATABASE_URL, e.g.:
  mysql+pymysql://cryptora:SECRET@mysql:3306/cryptora
  sqlite:///./cryptora.db   (default, local dev)
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./cryptora.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401 — register models
    Base.metadata.create_all(bind=engine)
