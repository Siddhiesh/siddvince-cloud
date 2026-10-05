from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./siddvince_cloud.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.utcnow())


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    username: Mapped[str] = mapped_column(String(120), index=True)
    display_name: Mapped[str] = mapped_column(String(180), default="")
    password_hash: Mapped[str] = mapped_column(String(500))
    role: Mapped[str] = mapped_column(String(40), default="viewer")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.utcnow())
    __table_args__ = (UniqueConstraint("company_id", "username", name="uq_company_username"),)


class SessionToken(Base):
    __tablename__ = "sessions"
    token: Mapped[str] = mapped_column(String(120), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.utcnow())


class SyncRecord(Base):
    __tablename__ = "sync_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(60), index=True)
    entity_uuid: Mapped[str] = mapped_column(String(80), index=True)
    payload_json: Mapped[str | None] = mapped_column(Text)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.utcnow())
    last_event_id: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (UniqueConstraint("company_id", "entity_type", "entity_uuid", name="uq_sync_record"),)


class SyncEvent(Base):
    __tablename__ = "sync_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    event_uuid: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(60), index=True)
    entity_uuid: Mapped[str] = mapped_column(String(80), index=True)
    action: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(String(500), default="")
    before_json: Mapped[str | None] = mapped_column(Text)
    after_json: Mapped[str | None] = mapped_column(Text)
    actor_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.utcnow())


Base.metadata.create_all(engine)
app = FastAPI(title="Siddvince Global Cloud API", version="1.0")


def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 210_000).hex()
    return f"pbkdf2_sha256$210000${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        kind, rounds, salt, digest = stored.split("$", 3)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return secrets.compare_digest(candidate, digest)
    except Exception:
        return False


class SetupIn(BaseModel):
    company_name: str = "Siddvince Global"
    username: str
    password: str = Field(min_length=8)
    display_name: str = "Owner"


class LoginIn(BaseModel):
    username: str
    password: str
    company_name: str = "Siddvince Global"


class UserCreateIn(BaseModel):
    username: str
    password: str = Field(min_length=8)
    display_name: str = ""
    role: str = "viewer"


class PushEvent(BaseModel):
    event_uuid: str
    entity_type: str
    entity_uuid: str
    action: str
    description: str = ""
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None


class PushIn(BaseModel):
    events: list[PushEvent]


ALLOWED_BY_ROLE = {
    "owner": {"*"},
    "admin": {"*"},
    "accounts": {"bill", "sale", "wastage_sale"},
    "production": {"production", "grade"},
    "sales": {"sale", "wastage_sale"},
    "viewer": set(),
}


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(db_session)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Login required")
    token = authorization.split(" ", 1)[1].strip()
    sess = db.get(SessionToken, token)
    if not sess or sess.expires_at < datetime.utcnow():
        raise HTTPException(401, "Session expired")
    user = db.get(User, sess.user_id)
    if not user or not user.active:
        raise HTTPException(403, "User disabled")
    return user


def can_write(user: User, entity_type: str) -> bool:
    allowed = ALLOWED_BY_ROLE.get(user.role, set())
    return "*" in allowed or entity_type in allowed


@app.get("/health")
def health():
    return {"ok": True, "service": "Siddvince Global Cloud", "time": datetime.utcnow().isoformat()}


@app.post("/setup")
def setup(data: SetupIn, db: Session = Depends(db_session)):
    if db.scalar(select(User.id).limit(1)) is not None:
        raise HTTPException(409, "Cloud has already been initialised")
    company = Company(name=data.company_name.strip())
    db.add(company); db.flush()
    user = User(company_id=company.id, username=data.username.strip().lower(), display_name=data.display_name.strip(), password_hash=hash_password(data.password), role="owner")
    db.add(user); db.commit()
    return {"ok": True, "company": company.name, "owner": user.username}


@app.post("/auth/login")
def login(data: LoginIn, db: Session = Depends(db_session)):
    company = db.scalar(select(Company).where(Company.name == data.company_name.strip()))
    if not company:
        raise HTTPException(401, "Company or login not found")
    user = db.scalar(select(User).where(User.company_id == company.id, User.username == data.username.strip().lower()))
    if not user or not user.active or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Invalid username or password")
    token = secrets.token_urlsafe(42)
    db.add(SessionToken(token=token, user_id=user.id, expires_at=datetime.utcnow() + timedelta(days=30)))
    db.commit()
    return {"token": token, "role": user.role, "display_name": user.display_name or user.username, "company": company.name}


@app.get("/me")
def me(user: User = Depends(current_user)):
    return {"username": user.username, "display_name": user.display_name, "role": user.role, "company_id": user.company_id}


@app.get("/users")
def list_users(user: User = Depends(current_user), db: Session = Depends(db_session)):
    if user.role not in ("owner", "admin"):
        raise HTTPException(403, "Admin access required")
    rows = db.scalars(select(User).where(User.company_id == user.company_id).order_by(User.username)).all()
    return [{"id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role, "active": u.active} for u in rows]


@app.post("/users")
def create_user(data: UserCreateIn, user: User = Depends(current_user), db: Session = Depends(db_session)):
    if user.role not in ("owner", "admin"):
        raise HTTPException(403, "Admin access required")
    if data.role not in ALLOWED_BY_ROLE:
        raise HTTPException(400, "Invalid role")
    if db.scalar(select(User.id).where(User.company_id == user.company_id, User.username == data.username.strip().lower())):
        raise HTTPException(409, "Username already exists")
    u = User(company_id=user.company_id, username=data.username.strip().lower(), display_name=data.display_name.strip(), password_hash=hash_password(data.password), role=data.role)
    db.add(u); db.commit(); db.refresh(u)
    return {"id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role, "active": u.active}


@app.post("/sync/push")
def push(data: PushIn, user: User = Depends(current_user), db: Session = Depends(db_session)):
    accepted = []
    for item in data.events:
        if not can_write(user, item.entity_type):
            raise HTTPException(403, f"Role {user.role} cannot modify {item.entity_type}")
        existing = db.scalar(select(SyncEvent.id).where(SyncEvent.event_uuid == item.event_uuid))
        if existing:
            accepted.append({"event_uuid": item.event_uuid, "event_id": existing, "duplicate": True})
            continue
        import json
        evt = SyncEvent(
            company_id=user.company_id,
            event_uuid=item.event_uuid,
            entity_type=item.entity_type,
            entity_uuid=item.entity_uuid,
            action=item.action,
            description=item.description,
            before_json=json.dumps(item.before, default=str) if item.before is not None else None,
            after_json=json.dumps(item.after, default=str) if item.after is not None else None,
            actor_user_id=user.id,
        )
        db.add(evt); db.flush()
        record = db.scalar(select(SyncRecord).where(SyncRecord.company_id == user.company_id, SyncRecord.entity_type == item.entity_type, SyncRecord.entity_uuid == item.entity_uuid))
        if not record:
            record = SyncRecord(company_id=user.company_id, entity_type=item.entity_type, entity_uuid=item.entity_uuid)
            db.add(record)
        record.deleted = item.action == "delete"
        record.payload_json = json.dumps(item.after if item.action != "delete" else item.before, default=str)
        record.updated_at = datetime.utcnow()
        record.last_event_id = evt.id
        accepted.append({"event_uuid": item.event_uuid, "event_id": evt.id, "duplicate": False})
    db.commit()
    return {"accepted": accepted}


@app.get("/sync/pull")
def pull(after: int = 0, limit: int = 1000, user: User = Depends(current_user), db: Session = Depends(db_session)):
    import json
    rows = db.scalars(select(SyncEvent).where(SyncEvent.company_id == user.company_id, SyncEvent.id > after).order_by(SyncEvent.id).limit(min(max(limit, 1), 5000))).all()
    events = []
    for e in rows:
        events.append({
            "id": e.id,
            "event_uuid": e.event_uuid,
            "entity_type": e.entity_type,
            "entity_uuid": e.entity_uuid,
            "action": e.action,
            "description": e.description,
            "before": json.loads(e.before_json) if e.before_json else None,
            "after": json.loads(e.after_json) if e.after_json else None,
            "created_at": e.created_at.isoformat(),
        })
    return {"events": events, "last_id": events[-1]["id"] if events else after}


@app.get("/sync/snapshot")
def snapshot(user: User = Depends(current_user), db: Session = Depends(db_session)):
    import json
    rows = db.scalars(select(SyncRecord).where(SyncRecord.company_id == user.company_id, SyncRecord.deleted == False)).all()  # noqa: E712
    data = []
    for r in rows:
        data.append({"entity_type": r.entity_type, "entity_uuid": r.entity_uuid, "payload": json.loads(r.payload_json) if r.payload_json else {}})
    last_id = db.scalar(select(SyncEvent.id).where(SyncEvent.company_id == user.company_id).order_by(SyncEvent.id.desc()).limit(1)) or 0
    return {"records": data, "last_id": last_id}
