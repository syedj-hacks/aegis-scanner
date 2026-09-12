import os
import shutil
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import aegis_bridge, models, schemas
from ..config import AEGIS_OUTPUT_DIR
from ..database import get_db
from ..deps import require_admin
from ..security import hash_password

router = APIRouter(prefix="/admin", tags=["admin"])


def _log_action(db: Session, admin: models.User, action: str, target_user_id: int = None, detail: str = None):
    db.add(models.AdminAction(admin_id=admin.id, action=action, target_user_id=target_user_id, detail=detail))
    db.commit()


def _dir_size_bytes(path: str) -> int:
    total = 0
    if not os.path.isdir(path):
        return 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total


@router.get("/dashboard")
def dashboard(admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    total_users = db.query(models.User).count()
    per_tier = {}
    for tier in models.Tier:
        per_tier[tier.value] = (
            db.query(models.Subscription).filter(models.Subscription.tier == tier).count()
        )

    month_ago = datetime.utcnow() - timedelta(days=30)
    scans_this_month = (
        db.query(models.ScanJob).filter(models.ScanJob.created_at >= month_ago).count()
    )

    # Total findings stored: sums Aegis's own findings table across every
    # scan on record, via its own history function (no direct SQL here so a
    # schema change to Aegis's DB layer doesn't silently desync this count).
    total_findings = 0
    for scan in aegis_bridge.get_scan_history():
        total_findings += len(aegis_bridge.get_findings(scan["id"]))

    return {
        "total_users": total_users,
        "users_per_tier": per_tier,
        "scans_this_month": scans_this_month,
        "total_findings": total_findings,
        "output_dir_bytes": _dir_size_bytes(AEGIS_OUTPUT_DIR),
    }


@router.get("/users")
def list_users(admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "role": u.role.value,
            "is_active": u.is_active,
            "tier": u.subscription.tier.value if u.subscription else None,
            "scans_used_this_period": u.subscription.scans_used_this_period if u.subscription else 0,
            "last_login_at": u.last_login_at,
            "created_at": u.created_at,
        }
        for u in users
    ]


@router.post("/users/{user_id}/tier")
def set_user_tier(
    user_id: int,
    body: schemas.AdminSetTierRequest,
    admin: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).get(user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.role == models.Role.admin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot change the admin account's tier")

    old_tier = user.subscription.tier
    user.subscription.tier = body.tier
    user.subscription.scans_used_this_period = 0
    db.add(user.subscription)

    db.add(
        models.Payment(
            user_id=user.id,
            amount=0,
            tier=body.tier,
            simulated_method="admin/demo",
            status=models.PaymentStatus.paid,
            note="admin override",
        )
    )
    _log_action(db, admin, "set_tier", user.id, f"{old_tier.value} -> {body.tier.value}")
    db.commit()
    return {"ok": True}


@router.post("/users/{user_id}/reset-password")
def reset_password(
    user_id: int,
    body: schemas.AdminSetPasswordRequest,
    admin: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).get(user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    user.hashed_password = hash_password(body.new_password)
    db.add(user)
    _log_action(db, admin, "reset_password", user.id)
    db.commit()
    return {"ok": True}


@router.post("/users/{user_id}/suspend")
def suspend_user(user_id: int, admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(models.User).get(user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.role == models.Role.admin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot suspend the admin account")

    user.is_active = not user.is_active
    db.add(user)
    _log_action(db, admin, "suspend" if not user.is_active else "unsuspend", user.id)
    db.commit()
    return {"ok": True, "is_active": user.is_active}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(models.User).get(user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.role == models.Role.admin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot delete the admin account")

    _log_action(db, admin, "delete_user", user.id, user.email)
    db.delete(user)
    db.commit()
    return {"ok": True}


@router.get("/reports")
def list_reports(admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    jobs = db.query(models.ScanJob).filter(models.ScanJob.status == models.JobStatus.done).all()
    out = []
    for j in jobs:
        size = 0
        for p in (j.txt_report_path, j.pdf_report_path, j.html_report_path):
            if p and os.path.isfile(p):
                size += os.path.getsize(p)
        out.append(
            {
                "job_id": j.id,
                "user_id": j.user_id,
                "target": j.target,
                "profile": j.profile,
                "created_at": j.created_at,
                "size_bytes": size,
            }
        )
    return out


@router.delete("/reports/{job_id}")
def delete_report(job_id: int, admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    """Removes both the DB row and the report files on disk. Logged."""
    job = db.query(models.ScanJob).get(job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")

    for p in (job.txt_report_path, job.pdf_report_path, job.html_report_path):
        if p and os.path.isfile(p):
            try:
                os.remove(p)
            except OSError:
                pass

    _log_action(db, admin, "delete_report", job.user_id, f"job={job.id} target={job.target} profile={job.profile}")
    db.delete(job)
    db.commit()
    return {"ok": True}


@router.get("/audit-log")
def audit_log(admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    actions = db.query(models.AdminAction).order_by(models.AdminAction.timestamp.desc()).all()
    return [
        {
            "id": a.id,
            "admin_id": a.admin_id,
            "action": a.action,
            "target_user_id": a.target_user_id,
            "timestamp": a.timestamp,
            "detail": a.detail,
        }
        for a in actions
    ]
