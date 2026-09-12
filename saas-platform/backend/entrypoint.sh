#!/bin/sh
# Production container entrypoint: migrate, seed the ONE admin account, serve.
#
# Deliberately does NOT run seed_sample_accounts.py — an Enterprise sample
# account is a standing credential for triggering wpscan/sqlmap/hydra/
# enum4linux. Run it by hand only on deployments you control.
set -e

alembic upgrade head
python seed_admin.py  # no-op (exit 0) once the one admin row exists

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
