# Aegis Shield — Setup Guide

Aegis Shield is a subscription-gated SaaS wrapper around the Aegis Scanner engine
(`../` relative to this directory). The backend imports Aegis's Python modules
directly as a library — it never shells out to `python3 aegis.py`.

## Architecture at a glance

```
saas-platform/
  backend/    FastAPI app, Postgres (app data), imports Aegis as a library
  frontend/   React + TypeScript + Tailwind
```

- **App data** (users, subscriptions, payments, scan_jobs, admin_actions) lives in
  **Postgres**.
- **Scan/finding data** stays in Aegis's own **SQLite** (`../database/aegis.db`),
  untouched. `scan_jobs.aegis_scan_id` links a web job to the `scans.id` row Aegis's
  `insert_scan()` created.
- **Job queue**: FastAPI `BackgroundTasks`, not Celery+Redis. This keeps the student
  deployment to one process. Starlette runs a sync background task in its own
  threadpool automatically, so a long-running scan does not block other requests —
  the tradeoff is no task persistence across a backend restart (an in-flight job's
  status would need to be manually marked `failed`) and no horizontal scaling of
  workers. A production version would swap `_run_scan_job` in
  `backend/app/routers/scans.py` for a Celery task with no other code changes, since
  the Aegis-calling logic is already isolated in `app/aegis_bridge.py`.

## Prerequisites

- Python 3.11+ (matching the Aegis venv at `../venv`)
- Node.js 18+
- PostgreSQL 14+
- Aegis Scanner itself already set up and working (see `../README.md`) — its own
  tools (nmap, nikto, gobuster, ZAP, etc.) must be installed for scans to actually
  run; the web platform does not install them.

## 1. Backend setup

```bash
cd saas-platform/backend
python3 -m venv venv        # or reuse ../../venv if it already has these deps
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env:
#   AEGIS_REPO_PATH   -> absolute path to the aegis-scanner checkout (../.. from here)
#   DATABASE_URL      -> your Postgres connection string
#   JWT_SECRET        -> a long random string
#   ADMIN_EMAIL / ADMIN_PASSWORD -> the ONE admin account's credentials
```

Create the Postgres database and role (adjust to your local Postgres setup):

```bash
sudo -u postgres psql -c "CREATE USER aegis_saas WITH PASSWORD 'aegis_saas';"
sudo -u postgres psql -c "CREATE DATABASE aegis_saas OWNER aegis_saas;"
```

Run migrations, seed the admin account, and seed demo users:

```bash
alembic upgrade head
python seed_admin.py          # creates the ONE admin from .env — refuses if one already exists
python seed_demo_users.py     # free@demo.aegis / pro@demo.aegis / enterprise@demo.aegis
```

Start the API:

```bash
uvicorn app.main:app --reload --port 8000
```

On startup the app also runs Aegis's own idempotent `init_db()` against
`database/aegis.db`, and refuses to boot if more than one admin row exists in
Postgres (a tamper-detection guard — the app itself can never create a second one).

## 2. Frontend setup

```bash
cd saas-platform/frontend
npm install
cp .env.example .env   # if you need to point VITE_API_BASE somewhere other than
                        # http://localhost:8000
npm run dev
```

Open http://localhost:5173. Demo accounts (password shown in `seed_demo_users.py`'s
output):

| Email | Tier |
|---|---|
| `free@demo.aegis` | Free |
| `pro@demo.aegis` | Pro |
| `enterprise@demo.aegis` | Enterprise |
| the `ADMIN_EMAIL` from `.env` | Admin |

## 3. Demoing tier gating without touching the DB

- Log in as `free@demo.aegis`: only `quickscan`/`compliance` are runnable; every
  other profile shows a lock icon with an upgrade tooltip, but is still listed.
- Log in as `pro@demo.aegis`: `webaudit`/`stealthscan` unlock, PDF export and scan
  diff (2 scans) appear.
- Log in as `enterprise@demo.aegis`: `deepscan`/`recon` unlock, JSON export, and
  submitting `deepscan` shows the intrusive-tools authorization checkbox (only
  deepscan can trigger wpscan/sqlmap/hydra/enum4linux, and only when that box is
  checked — enforced in `backend/app/routers/scans.py`, not just hidden in the UI).
- Billing → "Simulate Upgrade" on any account writes a mock `payments` row and
  flips the tier live, for demoing the upgrade flow itself.
- Log in as the admin account → `/admin` for the dashboard, user management,
  report management and the audit log.

## 4. Notes on Aegis integration

- Every scan-submitting request is re-validated server-side against the caller's
  **current** tier and quota (`backend/app/tiers.py` + `routers/scans.py`) —
  nothing relies on the frontend having disabled a button.
- Targets are validated and normalized through Aegis's own `is_valid_target` /
  `normalize_target` (`backend/app/aegis_bridge.py`), so CIDR ranges and malformed
  hosts are rejected identically to the CLI.
- Aegis's report retention cap (5 reports per profile+target) is left alone; the
  UI just tells the user older reports are auto-pruned.
- Report downloads and the JSON findings export respect `tiers.REPORT_FORMATS` —
  Free never sees a PDF/JSON link regardless of what's on disk.

## 5. Running tests / sanity checks

```bash
cd saas-platform/backend
python -m py_compile app/*.py app/routers/*.py   # syntax sanity check, no DB needed
```

A full integration test (real Postgres + a live Aegis scan) is out of scope for
this handoff; see the Build Order in the original project brief for the intended
incremental verification sequence (wire quickscan+webaudit first, prove the
pattern, then add the rest — the code already supports all six profiles since
`aegis_bridge.run_profile_sync` is profile-agnostic).
