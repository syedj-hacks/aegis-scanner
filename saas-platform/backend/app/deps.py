from datetime import datetime, timedelta

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import models
from .database import get_db
from .security import decode_access_token

bearer_scheme = HTTPBearer()


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    try:
        payload = decode_access_token(creds.credentials)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")

    user = db.query(models.User).get(user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or disabled")
    return user


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    """
    Protects every /admin/* route. Deliberately checks the DB row's role, not
    just that the JWT carries role=admin — a role downgrade or suspension
    takes effect on the next request, not only on next login.
    """
    if user.role != models.Role.admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    return user


def ensure_period_reset(sub: models.Subscription, db: Session) -> None:
    """
    Lazy monthly reset: called on every quota check. If the current period
    (30 days from period_start_date) has elapsed, roll it forward and zero
    the counter. Simpler than a cron job for a student deployment, and
    behaviorally identical from the user's point of view.
    """
    now = datetime.utcnow()
    if now - sub.period_start_date >= timedelta(days=30):
        sub.period_start_date = now
        sub.scans_used_this_period = 0
        db.add(sub)
        db.commit()
        db.refresh(sub)
