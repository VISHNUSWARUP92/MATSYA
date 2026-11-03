from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
)
from sqlalchemy.sql import func

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from database import Base, engine


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)

    # Store a password hash, never the plain-text password.
    password_hash = Column(String(255), nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    id = Column(Integer, primary_key=True, index=True)
    case_title = Column(String(255), nullable=False)
    sender_email = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=True)
    risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(50), nullable=True)
    findings = Column(Text, nullable=True)
    evidence_hash = Column(String(64), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


def create_tables():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    create_tables()
    print("MATSYA database tables created successfully!")