from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=schemas.TokenResponse)
def register(body: schemas.RegisterRequest, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == body.email).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already registered")

    # Public registration can NEVER create an admin account — role is hard-coded
    # here, not taken from the request body.
    user = models.User(
        email=body.email,
        hashed_password=hash_password(body.password),
        role=models.Role.user,
    )
    db.add(user)
    db.flush()

    sub = models.Subscription(user_id=user.id, tier=models.Tier.free)
    db.add(sub)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id, user.role.value)
    return schemas.TokenResponse(access_token=token, role=user.role, email=user.email)


@router.post("/login", response_model=schemas.TokenResponse)
def login(body: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == body.email).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account suspended")

    user.last_login_at = datetime.utcnow()
    db.commit()

    token = create_access_token(user.id, user.role.value)
    return schemas.TokenResponse(access_token=token, role=user.role, email=user.email)
