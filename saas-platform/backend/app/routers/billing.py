from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models, schemas, tiers
from ..database import get_db
from ..deps import ensure_period_reset, get_current_user

router = APIRouter(prefix="/billing", tags=["billing"])


def pending_upgrade(db: Session, user_id: int):
    """The user's open upgrade request (a pending ledger row), if any."""
    return (
        db.query(models.Payment)
        .filter(models.Payment.user_id == user_id, models.Payment.status == models.PaymentStatus.pending)
        .order_by(models.Payment.created_at.desc())
        .first()
    )


def subscription_out(sub: models.Subscription, db: Session) -> schemas.SubscriptionOut:
    pending = pending_upgrade(db, sub.user_id)
    return schemas.SubscriptionOut(
        tier=sub.tier,
        status=sub.status,
        started_at=sub.started_at,
        renews_at=sub.renews_at,
        scans_used_this_period=sub.scans_used_this_period,
        scans_limit=tiers.scan_limit_for_tier(sub.tier),
        period_start_date=sub.period_start_date,
        pending_tier=pending.tier if pending else None,
    )


@router.get("/subscription", response_model=schemas.SubscriptionOut)
def my_subscription(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    sub = user.subscription
    ensure_period_reset(sub, db)
    return subscription_out(sub, db)


@router.get("/payments", response_model=list[schemas.PaymentOut])
def my_payments(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(models.Payment)
        .filter(models.Payment.user_id == user.id)
        .order_by(models.Payment.created_at.desc())
        .all()
    )


@router.post("/change-plan", response_model=schemas.SubscriptionOut)
def change_plan(
    body: schemas.PlanChangeRequest,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Downgrades apply immediately — they only remove capabilities. Upgrades
    become a pending invoice that an administrator approves in the admin
    panel. Self-service upgrades used to be instant, which let anyone who
    registered unlock Enterprise's intrusive tooling (sqlmap/hydra) for free.
    """
    sub = user.subscription
    if body.tier == sub.tier:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"You are already on the {body.tier.value} plan")

    existing = pending_upgrade(db, user.id)

    if tiers.TIER_RANK[body.tier] < tiers.TIER_RANK[sub.tier]:
        if existing:
            existing.status = models.PaymentStatus.failed
            existing.note = "Cancelled: plan downgraded"
        sub.tier = body.tier
        sub.scans_used_this_period = 0
        db.add(
            models.Payment(
                user_id=user.id,
                amount=0,
                tier=body.tier,
                simulated_method="plan change",
                status=models.PaymentStatus.paid,
                note=f"Downgraded to {body.tier.value.capitalize()}",
            )
        )
    elif existing:
        existing.tier = body.tier
        existing.amount = tiers.PRICE_CENTS[body.tier]
    else:
        db.add(
            models.Payment(
                user_id=user.id,
                amount=tiers.PRICE_CENTS[body.tier],
                tier=body.tier,
                simulated_method="invoice",
                status=models.PaymentStatus.pending,
                note="Awaiting account review",
            )
        )
    db.commit()
    db.refresh(sub)
    return subscription_out(sub, db)


@router.delete("/upgrade-request", response_model=schemas.SubscriptionOut)
def cancel_upgrade_request(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = pending_upgrade(db, user.id)
    if existing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No pending upgrade request")
    existing.status = models.PaymentStatus.failed
    existing.note = "Cancelled by customer"
    db.commit()
    return subscription_out(user.subscription, db)
