from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from .models import JobStatus, PaymentStatus, Role, SubStatus, Tier


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role
    email: EmailStr


class SubscriptionOut(BaseModel):
    tier: Tier
    status: SubStatus
    started_at: datetime
    renews_at: Optional[datetime]
    scans_used_this_period: int
    scans_limit: Optional[int]
    period_start_date: datetime

    class Config:
        from_attributes = True


class PaymentOut(BaseModel):
    id: int
    amount: int
    tier: Tier
    simulated_method: str
    status: PaymentStatus
    created_at: datetime
    note: Optional[str]

    class Config:
        from_attributes = True


class SimulateUpgradeRequest(BaseModel):
    tier: Tier


class ProfileInfo(BaseModel):
    name: str
    description: str
    locked: bool
    requires_authorization: bool


class ScanSubmitRequest(BaseModel):
    target: str
    profile: str
    auth_header: Optional[str] = None
    auth_cookie: Optional[str] = None
    authorized_intrusive: bool = False


class ScanJobOut(BaseModel):
    id: int
    target: str
    profile: str
    status: JobStatus
    aegis_scan_id: Optional[int]
    error: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]

    class Config:
        from_attributes = True


class DiffRequest(BaseModel):
    scan_id_a: int
    scan_id_b: int


class AdminSetTierRequest(BaseModel):
    tier: Tier


class AdminSetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=8)
