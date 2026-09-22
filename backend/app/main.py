"""CRYPTORA API — auth + persistence for scan results.

Run locally:  pip install -r requirements.txt && uvicorn app.main:app --port 8000
Prod:         see /deploy (MySQL + docker compose).
"""
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .auth import (DEV_MODE, GOOGLE_CLIENT_ID, check_password, hash_password,
                   make_token, otp_request, otp_verify, parse_token,
                   verify_google_id_token)
from .db import get_db, init_db
from .models import AuditLog, Finding, Organization, OrgMember, Project, Scan, User

app = FastAPI(title="CRYPTORA API", version="1.0.0",
              description="Cryptographic Risk & Migration Intelligence — auth + persistence")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("FRONTEND_ORIGIN", "*").split(",")],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

init_db()

# ---------------- schemas ----------------
class SignupIn(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=128)
    name: str = ""


class LoginIn(BaseModel):
    email: str
    password: str


class GoogleIn(BaseModel):
    id_token: str


class OtpReqIn(BaseModel):
    phone: str = Field(min_length=7, max_length=20)


class OtpVerifyIn(BaseModel):
    phone: str
    code: str = Field(min_length=4, max_length=10)


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)


class ScanIn(BaseModel):
    client_id: str = ""
    source: str = ""
    files_scanned: int = 0
    findings: List[Dict[str, Any]] = []
    stats: Dict[str, Any] = {}
    cbom_components: int = 0


# ---------------- helpers ----------------
def log(db: Session, user_id, action: str, detail: str = ""):
    db.add(AuditLog(user_id=user_id, action=action, detail=detail[:500]))
    db.commit()


def current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")
    uid = parse_token(authorization.split(None, 1)[1])
    if not uid:
        raise HTTPException(401, "Invalid or expired token")
    u = db.get(User, uid)
    if not u:
        raise HTTPException(401, "User not found")
    return u


def user_org(db: Session, u: User) -> Organization:
    m = db.query(OrgMember).filter_by(user_id=u.id).first()
    if m:
        return db.get(Organization, m.org_id)
    org = Organization(name=f"{u.name or u.email or u.phone}'s workspace", owner_id=u.id)
    db.add(org)
    db.flush()
    db.add(OrgMember(org_id=org.id, user_id=u.id, role="owner"))
    db.commit()
    return org


def own_project(db: Session, u: User, pid: int) -> Project:
    org = user_org(db, u)
    p = db.query(Project).filter_by(id=pid, org_id=org.id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    return p


def pub(u: User) -> Dict[str, Any]:
    return {"id": u.id, "email": u.email, "phone": u.phone, "name": u.name}


# ---------------- meta ----------------
@app.get("/health")
def health():
    return {"status": "ok", "service": "cryptora-api",
            "time": datetime.now(timezone.utc).isoformat()}


@app.get("/ready")
def ready(db: Session = Depends(get_db)):
    n = db.query(User).count()
    return {"ready": True, "users": n, "dev_mode": DEV_MODE}


@app.get("/api/config")
def config():
    return {"google_configured": bool(GOOGLE_CLIENT_ID),
            "google_client_id": GOOGLE_CLIENT_ID or None,
            "otp_configured": True, "dev_mode": DEV_MODE}


# ---------------- auth ----------------
@app.post("/api/auth/signup", status_code=201)
def signup(body: SignupIn, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if "@" not in email:
        raise HTTPException(400, "Invalid email")
    if db.query(User).filter_by(email=email).first():
        raise HTTPException(409, "Email already registered — sign in instead")
    u = User(email=email, name=body.name.strip()[:120], pw_hash=hash_password(body.password))
    db.add(u)
    db.commit()
    db.refresh(u)
    user_org(db, u)
    log(db, u.id, "signup", email)
    return {"token": make_token(u.id), "user": pub(u)}


@app.post("/api/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.query(User).filter_by(email=body.email.strip().lower()).first()
    if not u or not u.pw_hash or not check_password(body.password, u.pw_hash):
        raise HTTPException(401, "Invalid email or password")
    log(db, u.id, "login", u.email or "")
    return {"token": make_token(u.id), "user": pub(u)}


@app.post("/api/auth/google")
def google(body: GoogleIn, db: Session = Depends(get_db)):
    try:
        g = verify_google_id_token(body.id_token)
    except ValueError as e:
        raise HTTPException(400 if GOOGLE_CLIENT_ID else 501, str(e))
    u = db.query(User).filter_by(google_sub=g["sub"]).first()
    if not u and g.get("email"):
        u = db.query(User).filter_by(email=g["email"].lower()).first()
        if u:
            u.google_sub = g["sub"]
            db.commit()
    if not u:
        u = User(email=(g.get("email") or "").lower() or None, name=g.get("name", ""),
                 google_sub=g["sub"])
        db.add(u)
        db.commit()
        db.refresh(u)
        user_org(db, u)
    log(db, u.id, "login", "google")
    return {"token": make_token(u.id), "user": pub(u)}


@app.post("/api/auth/otp/request")
def otp_req(body: OtpReqIn):
    try:
        return otp_request(body.phone.strip())
    except ValueError as e:
        raise HTTPException(429, str(e))


@app.post("/api/auth/otp/verify")
def otp_ver(body: OtpVerifyIn, db: Session = Depends(get_db)):
    if not otp_verify(body.phone.strip(), body.code):
        raise HTTPException(401, "Invalid or expired code")
    u = db.query(User).filter_by(phone=body.phone.strip()).first()
    if not u:
        u = User(phone=body.phone.strip(), name="")
        db.add(u)
        db.commit()
        db.refresh(u)
        user_org(db, u)
    log(db, u.id, "login", "otp")
    return {"token": make_token(u.id), "user": pub(u)}


@app.get("/api/me")
def me(u: User = Depends(current_user)):
    return pub(u)


# ---------------- projects & scans ----------------
@app.get("/api/projects")
def list_projects(u: User = Depends(current_user), db: Session = Depends(get_db)):
    org = user_org(db, u)
    return [{"id": p.id, "name": p.name, "scans": len(p.scans),
             "created_at": p.created_at.isoformat() if p.created_at else None}
            for p in db.query(Project).filter_by(org_id=org.id).order_by(desc(Project.id)).all()]


@app.post("/api/projects", status_code=201)
def create_project(body: ProjectIn, u: User = Depends(current_user), db: Session = Depends(get_db)):
    org = user_org(db, u)
    p = Project(org_id=org.id, name=body.name.strip()[:160])
    db.add(p)
    db.commit()
    db.refresh(p)
    log(db, u.id, "project.create", p.name)
    return {"id": p.id, "name": p.name}


@app.delete("/api/projects/{pid}")
def delete_project(pid: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    p = own_project(db, u, pid)
    db.delete(p)
    db.commit()
    log(db, u.id, "project.delete", str(pid))
    return {"deleted": pid}


@app.post("/api/projects/{pid}/scans", status_code=201)
def save_scan(pid: int, body: ScanIn, u: User = Depends(current_user), db: Session = Depends(get_db)):
    p = own_project(db, u, pid)
    st = body.stats or {}
    s = Scan(project_id=p.id, client_id=body.client_id[:64], source=body.source[:255],
             files_scanned=body.files_scanned, findings_count=len(body.findings),
             critical=st.get("critical", 0), high=st.get("high", 0),
             quantum=st.get("quantum", 0), secrets=st.get("secrets", 0),
             payload={"stats": st, "cbom_components": body.cbom_components,
                      "findings": body.findings[:2000]})
    db.add(s)
    db.flush()
    for f in body.findings[:2000]:
        db.add(Finding(scan_id=s.id, algo=str(f.get("algorithm", ""))[:64],
                       algo_label=str(f.get("algoLabel", ""))[:255],
                       file=str(f.get("file", ""))[:512], line=int(f.get("line") or 0),
                       severity=str(f.get("severity", "info"))[:16],
                       quantum=bool(f.get("quantum")), risk_score=int(f.get("riskScore") or 0),
                       evidence=str(f.get("evidence", ""))[:2000]))
    db.commit()
    log(db, u.id, "scan.save", f"project={pid} findings={len(body.findings)}")
    return {"id": s.id, "findings": len(body.findings)}


@app.get("/api/projects/{pid}/scans")
def list_scans(pid: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    p = own_project(db, u, pid)
    return [{"id": s.id, "source": s.source, "files": s.files_scanned,
             "findings": s.findings_count, "critical": s.critical, "high": s.high,
             "quantum": s.quantum, "created_at": s.created_at.isoformat() if s.created_at else None}
            for s in sorted(p.scans, key=lambda x: x.id, reverse=True)[:50]]


@app.get("/api/scans/{sid}")
def get_scan(sid: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.get(Scan, sid)
    if not s:
        raise HTTPException(404, "Scan not found")
    own_project(db, u, s.project_id)  # ownership check (blocks IDOR)
    return {"id": s.id, "project_id": s.project_id, "source": s.source,
            "files_scanned": s.files_scanned, "created_at": s.created_at.isoformat() if s.created_at else None,
            "payload": s.payload or {}}


@app.delete("/api/scans/{sid}")
def delete_scan(sid: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.get(Scan, sid)
    if not s:
        raise HTTPException(404, "Scan not found")
    own_project(db, u, s.project_id)
    db.delete(s)
    db.commit()
    log(db, u.id, "scan.delete", str(sid))
    return {"deleted": sid}


@app.get("/api/audit-logs")
def audit_logs(u: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(AuditLog).filter_by(user_id=u.id).order_by(desc(AuditLog.id)).limit(100).all()
    return [{"action": r.action, "detail": r.detail,
             "at": r.created_at.isoformat() if r.created_at else None} for r in rows]


@app.get("/api/recommendations/{algorithm}")
def recommend(algorithm: str):
    table = {
        "RSA": "hybrid RSA+ML-KEM-768, then ML-KEM (FIPS 203); signatures to ML-DSA (FIPS 204)",
        "ECDSA": "dual-sign ECDSA+ML-DSA, then ML-DSA-65 (FIPS 204)",
        "ECDH": "hybrid X25519+ML-KEM-768, then ML-KEM (FIPS 203)",
        "DH": "hybrid DH+ML-KEM-768, then ML-KEM (FIPS 203)",
        "MD5": "replace with SHA-384/512 or SHA3-256",
        "SHA1": "replace with SHA-384/512 or SHA3-256",
        "DES": "replace with AES-256-GCM",
        "RC4": "replace with ChaCha20-Poly1305 or AES-256-GCM",
    }
    return {"algorithm": algorithm, "path": table.get(algorithm.upper(), "review against NIST FIPS 203/204/205")}
