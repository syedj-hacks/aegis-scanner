"""
Seeds the single admin account from ADMIN_EMAIL / ADMIN_PASSWORD in .env.
Run once, before first boot: `python seed_admin.py`.

Refuses to create a second admin — this is the only place an admin row is
ever allowed to be created (registration always hard-codes role=user).
"""
import sys

from app.config import ADMIN_EMAIL, ADMIN_PASSWORD
from app.database import Base, SessionLocal, engine
from app.models import Role, Subscription, Tier, User
from app.security import hash_password


def main():
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        print("ADMIN_EMAIL and ADMIN_PASSWORD must be set in .env", file=sys.stderr)
        sys.exit(1)

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing_admin = db.query(User).filter(User.role == Role.admin).first()
        if existing_admin:
            print(f"An admin account already exists ({existing_admin.email}). Not creating another.")
            return

        existing_email = db.query(User).filter(User.email == ADMIN_EMAIL).first()
        if existing_email:
            print(f"A user with email {ADMIN_EMAIL} already exists but is not an admin. Aborting.")
            sys.exit(1)

        admin = User(
            email=ADMIN_EMAIL,
            hashed_password=hash_password(ADMIN_PASSWORD),
            role=Role.admin,
        )
        db.add(admin)
        db.flush()
        db.add(Subscription(user_id=admin.id, tier=Tier.enterprise))
        db.commit()
        print(f"Admin account created: {ADMIN_EMAIL}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
