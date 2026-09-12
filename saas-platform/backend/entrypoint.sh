#!/bin/sh
# Production container entrypoint: migrate, seed the ONE admin account, serve.
#
# Deliberately does NOT run seed_demo_users.py — those accounts ship with
# published passwords (see SETUP.md) and, on the enterprise tier, that's a
# standing credential for triggering wpscan/sqlmap/hydra/enum4linux against
# whatever target a holder of this repo's README chooses. Fine for a local
# demo, not for a public deployment. Run it manually and rotate the passwords
# first if you actually want the tier-demo accounts live.
set -e

alembic upgrade head
python seed_admin.py  # no-op (exit 0) once the one admin row exists

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
