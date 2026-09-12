#!/bin/sh
# Production container entrypoint: migrate (Postgres only), seed the ONE admin
# account, serve.
#
# Deliberately does NOT run seed_sample_accounts.py — an Enterprise sample
# account is a standing credential for triggering wpscan/sqlmap/hydra/
# enum4linux. Run it by hand only on deployments you control.
set -e

# The 0001 migration is written for Postgres (postgresql.ENUM types) and fails
# on SQLite. The launcher handles this by skipping Alembic for SQLite and
# letting the schema be created from the ORM metadata instead (seed_admin.py
# and the app's startup both call Base.metadata.create_all). Mirror that here
# so the default SQLite container boots, while real Postgres deployments still
# get proper migrations.
case "${DATABASE_URL:-sqlite}" in
    postgres*|postgresql*)
        echo "[entrypoint] Postgres detected — running Alembic migrations."
        alembic upgrade head
        ;;
    *)
        echo "[entrypoint] SQLite (or unset DATABASE_URL) — skipping Alembic; schema is created from ORM metadata."
        ;;
esac

python seed_admin.py  # creates the schema if needed; no-op once the admin row exists

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
