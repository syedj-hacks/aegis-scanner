"""
Seeds one Free, one Pro and one Enterprise demo user so tier gating can be
demoed immediately without simulating upgrades live. Run after seed_admin.py:

    python seed_demo_users.py

Idempotent: skips any demo account that already exists.
"""
from app.database import Base, SessionLocal, engine
from app.models import Role, Subscription, Tier, User
from app.security import hash_password

DEMO_USERS = [
    ("free@demo.aegis", "DemoFree123!", Tier.free),
    ("pro@demo.aegis", "DemoPro123!", Tier.pro),
    ("enterprise@demo.aegis", "DemoEnterprise123!", Tier.enterprise),
]


def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for email, password, tier in DEMO_USERS:
            if db.query(User).filter(User.email == email).first():
                print(f"Skipping {email} (already exists)")
                continue
            user = User(email=email, hashed_password=hash_password(password), role=Role.user)
            db.add(user)
            db.flush()
            db.add(Subscription(user_id=user.id, tier=tier))
            db.commit()
            print(f"Created {tier.value} demo user: {email} / {password}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
