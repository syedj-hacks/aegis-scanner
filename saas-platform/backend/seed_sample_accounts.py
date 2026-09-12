"""
Creates one Free, one Pro and one Enterprise account so plan gating can be
tested without approving upgrades by hand. Run after seed_admin.py:

    python seed_sample_accounts.py

Passwords are random and printed once. Idempotent: skips accounts that
already exist. Never run this on a public deployment you don't control —
the Enterprise account can launch intrusive scans.
"""
import secrets

from app.database import Base, SessionLocal, engine
from app.models import Role, Subscription, Tier, User
from app.security import hash_password

SAMPLE_ACCOUNTS = [
    ("free@aegisshield.app", Tier.free),
    ("pro@aegisshield.app", Tier.pro),
    ("enterprise@aegisshield.app", Tier.enterprise),
]


def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for email, tier in SAMPLE_ACCOUNTS:
            if db.query(User).filter(User.email == email).first():
                print(f"Skipping {email} (already exists)")
                continue
            password = secrets.token_urlsafe(10)
            user = User(email=email, hashed_password=hash_password(password), role=Role.user)
            db.add(user)
            db.flush()
            db.add(Subscription(user_id=user.id, tier=tier))
            db.commit()
            print(f"Created {tier.value:<10} {email}  password: {password}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
