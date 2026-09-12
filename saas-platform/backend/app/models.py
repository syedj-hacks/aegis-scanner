import enum
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text
)
from sqlalchemy.orm import relationship

from .database import Base


class Role(str, enum.Enum):
    user = "user"
    admin = "admin"


class Tier(str, enum.Enum):
    free = "free"
    pro = "pro"
    enterprise = "enterprise"


class SubStatus(str, enum.Enum):
    active = "active"
    cancelled = "cancelled"
    expired = "expired"


class PaymentStatus(str, enum.Enum):
    paid = "paid"
    pending = "pending"
    failed = "failed"


class JobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(Role, name="role"), default=Role.user, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

    subscription = relationship(
        "Subscription", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    payments = relationship("Payment", back_populates="user", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="user", cascade="all, delete-orphan")


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    tier = Column(Enum(Tier, name="tier"), default=Tier.free, nullable=False)
    status = Column(Enum(SubStatus, name="substatus"), default=SubStatus.active, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    renews_at = Column(DateTime, nullable=True)
    scans_used_this_period = Column(Integer, default=0, nullable=False)
    period_start_date = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="subscription")


class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Integer, nullable=False)  # cents
    tier = Column(Enum(Tier, name="tier"), nullable=False)
    # Column name kept for migration compatibility; holds the billing method
    # ("invoice", "manual", "plan change").
    simulated_method = Column(String(64), default="invoice")
    status = Column(Enum(PaymentStatus, name="paymentstatus"), default=PaymentStatus.paid, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    note = Column(String(255), nullable=True)  # e.g. "admin override"

    user = relationship("User", back_populates="payments")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target = Column(String(255), nullable=False)
    profile = Column(String(64), nullable=False)
    status = Column(Enum(JobStatus, name="jobstatus"), default=JobStatus.queued, nullable=False)
    aegis_scan_id = Column(Integer, nullable=True)  # FK into Aegis's own SQLite scans.id
    txt_report_path = Column(String(512), nullable=True)
    pdf_report_path = Column(String(512), nullable=True)
    html_report_path = Column(String(512), nullable=True)
    error = Column(Text, nullable=True)
    authorized_intrusive = Column(Boolean, default=False)  # Enterprise conditional-tools checkbox
    authorized_ip = Column(String(64), nullable=True)
    authorized_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="scan_jobs")


class AdminAction(Base):
    __tablename__ = "admin_actions"

    id = Column(Integer, primary_key=True)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String(64), nullable=False)
    # SET NULL on delete: deleting a user must not fail (or silently lose)
    # the audit trail of actions taken against them — the log entry survives,
    # just anonymized.
    target_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    detail = Column(Text, nullable=True)
