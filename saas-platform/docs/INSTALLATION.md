# Installation

[← Back to README](../README.md)

There are three ways to run Aegis Shield. Pick the first one unless you have a reason not to.

| Method | Best for | Needs |
|---|---|---|
| [1. One-click launcher](#1-one-click-launcher) | Running it on any Windows or Linux PC | Python 3.10+ |
| [2. Manual development setup](#2-manual-development-setup) | Changing the code, hot reload | Python 3.10+, Node.js 18+ |
| [3. Docker / Render](#3-docker-and-render) | A server deployment with PostgreSQL | Docker |

---

## 1. One-click launcher

### Prerequisites

- **Python 3.10 or newer.**
  - Windows: install from [python.org](https://www.python.org/downloads/) and tick **Add python.exe to PATH**.
  - Debian/Ubuntu/Kali: `sudo apt install python3 python3-venv`
- Internet access on the first run (to download Python packages).

### Start

```bash
git clone https://github.com/syedj-hacks/aegis-saas.git
cd aegis-saas
```

- **Windows:** double-click `Start Aegis Shield.bat`.
- **Linux/macOS:** `./start-aegis-shield.sh`

### What the first run does

1. **Python environment.** It reuses the engine's `venv/` if that already has every dependency.
   Otherwise it creates `saas-platform/backend/.venv` and installs the backend and engine
   requirements. If a pinned version has no build for your Python release, it retries with the
   latest compatible versions.
2. **Configuration.** It writes `saas-platform/backend/.env` with:
   - a SQLite database at `saas-platform/backend/data/aegis_shield.db`,
   - a random 256-bit `JWT_SECRET`,
   - the administrator account `admin@aegisshield.app` with a random password, **printed once in the window**.
3. **Engine configuration.** It copies `modules/utils/config.example.py` to `config.py` if that file is missing.
4. **Database.** Tables are created, plus the single admin account (`seed_admin.py`).
5. **Server.** It starts one server on `0.0.0.0:8000` that serves the API and the web app, waits
   until `/health` responds, prints the addresses, and opens your browser.

Later runs skip steps 1–4 and start in a few seconds.

### Options

| Option | Effect |
|---|---|
| `--port 8080` | Listen on another port (also `AEGIS_PORT=8080`). If the port is busy, the next free one is used automatically. |
| `--no-browser` | Don't open a browser tab. |
| `--install-shortcut` | Create an **Aegis Shield** launcher on the desktop (Windows) or in the desktop and application menu (Linux). |

On Windows, pass options by running `py -3 launch_aegis_shield.py --port 8080` from a terminal in the folder.

### Reaching it from other devices

The launcher prints a **Local network** address such as `http://192.168.1.24:8000`. Any phone or
laptop on the same network can open it. On Windows, allow Python through Windows Defender Firewall
when prompted.

### Stopping

Press **Ctrl+C** in the launcher window, or close it.

### Finding the admin password later

It is stored as `ADMIN_PASSWORD` in `saas-platform/backend/.env`. The password is only used to create
the account on the first run, so changing it in `.env` afterwards has no effect. Use
[Resetting the admin password](TROUBLESHOOTING.md#i-lost-the-admin-password) instead.

---

## 2. Manual development setup

Use this when you are editing the frontend and want hot reload.

### Backend

```bash
cd saas-platform/backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r ../../requirements.txt

cp .env.example .env               # then edit it (see the configuration reference below)
python seed_admin.py
uvicorn app.main:app --reload --port 8000
```

Optional: `python seed_sample_accounts.py` creates one Free, one Pro and one Enterprise account with
random passwords, which is handy for testing plan gating.

### Frontend

```bash
cd saas-platform/frontend
npm install
npm run dev                         # http://localhost:5173, talks to :8000 on the same host
```

### Rebuilding the production bundle

The launcher serves the committed build in `frontend/dist/`. **After changing anything in
`frontend/src`, rebuild and commit `dist/`:**

```bash
cd saas-platform/frontend
npm run build
```

No Node.js locally? Build inside Docker:

```bash
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app node:20 sh -c "npm install && npm run build"
```

---

## 3. Docker and Render

### PostgreSQL

Set `DATABASE_URL` to a PostgreSQL URL and run the migrations before first start:

```bash
docker run -d --name aegis-pg -p 5432:5432 \
  -e POSTGRES_USER=aegis_saas -e POSTGRES_PASSWORD=aegis_saas -e POSTGRES_DB=aegis_saas postgres:16

# in saas-platform/backend/.env
DATABASE_URL=postgresql+psycopg2://aegis_saas:aegis_saas@localhost:5432/aegis_saas

cd saas-platform/backend
alembic upgrade head
python seed_admin.py
```

The launcher detects a PostgreSQL `DATABASE_URL` and runs `alembic upgrade head` for you.

### Backend container

`saas-platform/backend/Dockerfile` builds on Kali Linux so every scanning tool is installed. Build
from the **repository root**, because the backend imports the engine:

```bash
docker build -f saas-platform/backend/Dockerfile -t aegis-shield-backend .
docker run -p 8000:8000 --env-file saas-platform/backend/.env aegis-shield-backend
```

The container entrypoint runs migrations, seeds the admin account and starts Uvicorn on `$PORT`.

### Render

`render.yaml` at the repository root provisions the backend container and a PostgreSQL database.
The Docker backend needs a paid instance type, because Render's free tier can't run the scanning
toolchain. Render prompts for `ADMIN_EMAIL` and `ADMIN_PASSWORD` and generates `JWT_SECRET`.

### GitHub Pages (static frontend)

`.github/workflows/deploy-pages.yml` publishes the frontend to
`https://syedj-hacks.github.io/aegis-saas/` on every push that touches `saas-platform/frontend`.
GitHub Pages only serves static files, so it has no backend of its own:

- With no `VITE_API_BASE` repository variable set, the hosted site talks to a backend at
  `http://localhost:8000`. It works for anyone who is running the launcher on their own machine,
  and shows "Can't reach the Aegis Shield server" for everyone else.
- To point it at a hosted backend, set the repository variable **`VITE_API_BASE`** (Settings →
  Secrets and variables → Actions → Variables) to the backend URL and re-run the workflow.

---

## Configuration reference

All settings are environment variables, normally set in `saas-platform/backend/.env`.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | SQLite at `backend/data/aegis_shield.db` | Account and billing database. Use `postgresql+psycopg2://…` in production. |
| `JWT_SECRET` | `change-me-in-production` | Signs session tokens. **Must** be long and random. |
| `JWT_EXPIRE_MINUTES` | `1440` | Session lifetime (24 hours). |
| `ADMIN_EMAIL` | — | Email of the single administrator. Must use a normal domain; `.local` and `.test` addresses fail validation at sign-in. |
| `ADMIN_PASSWORD` | — | Initial admin password, used only when the account is first created. |
| `AEGIS_REPO_PATH` | repository root | Location of the Aegis Scanner engine. |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated browser origins allowed to call the API. |
| `PUBLIC_FRONTEND_ORIGIN` | `https://syedj-hacks.github.io` | Always added to the CORS list so the hosted frontend can reach a local backend. |
| `FRONTEND_DIST` | `frontend/dist` | Built web app to serve at `/`. Nothing is served if the folder is missing. |
| `AEGIS_PORT` | `8000` | Launcher only: default port. |

Frontend build-time variable:

| Variable | Purpose |
|---|---|
| `VITE_API_BASE` | Fixed API URL. If unset, the app decides at runtime: same origin when served by the backend, `:8000` under `npm run dev`, and `http://localhost:8000` on GitHub Pages. |
