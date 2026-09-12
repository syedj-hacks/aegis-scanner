from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas, tiers
from ..database import get_db
from ..deps import ensure_period_reset, get_current_user

router = APIRouter(prefix="/billing", tags=["billing"])

# Mock price list shown in the UI's "Simulate Upgrade" flow — purely cosmetic,
# no real payment gateway (this is a demo ledger, per the project brief).
MOCK_PRICES_CENTS = {
    models.Tier.free: 0,
    models.Tier.pro: 1999,
    models.Tier.enterprise: 4999,
}


@router.get("/subscription", response_model=schemas.SubscriptionOut)
def my_subscription(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    sub = user.subscription
    ensure_period_reset(sub, db)
    return schemas.SubscriptionOut(
        tier=sub.tier,
        status=sub.status,
        started_at=sub.started_at,
        renews_at=sub.renews_at,
        scans_used_this_period=sub.scans_used_this_period,
        scans_limit=tiers.scan_limit_for_tier(sub.tier),
        period_start_date=sub.period_start_date,
    )


@router.get("/payments", response_model=list[schemas.PaymentOut])
def my_payments(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(models.Payment)
        .filter(models.Payment.user_id == user.id)
        .order_by(models.Payment.created_at.desc())
        .all()
    )


@router.post("/simulate-upgrade", response_model=schemas.SubscriptionOut)
def simulate_upgrade(
    body: schemas.SimulateUpgradeRequest,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    DEMO MODE: writes a mock payment ledger row and flips the user's tier.
    No card data is collected and no real payment gateway is contacted — the
    frontend must render this clearly as a demo action.
    """
    sub = user.subscription
    sub.tier = body.tier
    sub.status = models.SubStatus.active
    sub.scans_used_this_period = 0
    db.add(sub)

    payment = models.Payment(
        user_id=user.id,
        amount=MOCK_PRICES_CENTS.get(body.tier, 0),
        tier=body.tier,
        simulated_method="manual/demo",
        status=models.PaymentStatus.paid,
        note="self-service simulated upgrade",
    )
    db.add(payment)
    db.commit()
    db.refresh(sub)

    return schemas.SubscriptionOut(
        tier=sub.tier,
        status=sub.status,
        started_at=sub.started_at,
        renews_at=sub.renews_at,
        scans_used_this_period=sub.scans_used_this_period,
        scans_limit=None,
        period_start_date=sub.period_start_date,
    )
