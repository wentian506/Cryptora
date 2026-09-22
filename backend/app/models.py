"""Relational schema: User -> Organization -> Project -> Scan -> Finding."""
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, Column, DateTime, ForeignKey, Integer,
                        String, Text, UniqueConstraint)
from sqlalchemy.orm import relationship

from .db import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    phone = Column(String(32), unique=True, nullable=True, index=True)
    name = Column(String(120), default="")
    pw_hash = Column(String(255), nullable=True)  # pbkdf2 hex, never raw password
    google_sub = Column(String(255), unique=True, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True)
    name = Column(String(160), default="Personal")
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at = Column(DateTime, default=utcnow)
    projects = relationship("Project", cascade="all, delete-orphan", backref="org")


class OrgMember(Base):
    __tablename__ = "org_members"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role = Column(String(32), default="owner")  # owner|admin|analyst|developer|viewer
    __table_args__ = (UniqueConstraint("org_id", "user_id", name="uq_org_user"),)


class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name = Column(String(160), default="cryptora-scan")
    created_at = Column(DateTime, default=utcnow)
    scans = relationship("Scan", cascade="all, delete-orphan", backref="project")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    client_id = Column(String(64), default="")
    source = Column(String(255), default="")
    files_scanned = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    critical = Column(Integer, default=0)
    high = Column(Integer, default=0)
    quantum = Column(Integer, default=0)
    secrets = Column(Integer, default=0)
    payload = Column(JSON, nullable=True)  # full scan JSON (stats+findings+cbom summary)
    created_at = Column(DateTime, default=utcnow)
    findings = relationship("Finding", cascade="all, delete-orphan", backref="scan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    algo = Column(String(64), default="")
    algo_label = Column(String(255), default="")
    file = Column(String(512), default="")
    line = Column(Integer, default=0)
    severity = Column(String(16), default="info", index=True)
    quantum = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    evidence = Column(Text, default="")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(64), index=True)  # signup/login/project.create/scan.save/...
    detail = Column(String(512), default="")
    created_at = Column(DateTime, default=utcnow)
