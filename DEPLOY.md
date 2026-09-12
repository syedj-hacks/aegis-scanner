# Deploying Aegis Shield live on SnapDeploy

This deploys the **same container** as the local one-click run (the
`saas-platform/backend/Dockerfile` image), so behaviour is identical to what
you tested locally with `run.sh` / `run.bat`.

> **Read the "Free-tier reality check" at the bottom first.** Aegis Shield is a
> heavy security scanner, and SnapDeploy's free tier has real limits that will
> bite before you go live. Some of them need a decision *before* you deploy.

SnapDeploy has **no config file** to commit — it is configured entirely from
its dashboard and reads your repo's Dockerfile directly. That is why there is no
`snapdeploy.yaml` in this repo; there is nothing for one to do.

---

## 1. Connect the GitHub repo

1. Sign in at <https://snapdeploy.dev/dashboard>.
2. **Settings → GitHub Integration → Connect GitHub**, and authorise SnapDeploy
   for the repository that holds this code (the full engine — the backend
   imports it as a library, so a frontend-only repo will not build).
3. **New Container → Deploy from GitHub**, pick the repo and branch.

## 2. Point it at the right Dockerfile  ← the step people get wrong

This repo contains **two** Dockerfiles:

| Path | What it is | Use for SnapDeploy? |
|---|---|---|
| `Dockerfile` (repo root) | the **CLI scanner** (`ENTRYPOINT aegis.py`) — not a web server | **No** |
| `saas-platform/backend/Dockerfile` | the **Aegis Shield web app** | **Yes** |

SnapDeploy auto-detects a Dockerfile and will almost certainly pick the root one,
which is *not* a web server and will appear to deploy but serve nothing. In the
container's build settings you must set:

- **Dockerfile path:** `saas-platform/backend/Dockerfile`
- **Build context / root:** the repository root (`.`) — the backend imports the
  engine from the repo root, so the context must not be the backend subfolder.
- **Port:** `8000` (the container also honours a `PORT` env var if SnapDeploy
  injects one — the entrypoint uses `${PORT:-8000}`).

## 3. Set environment variables (dashboard → Environment)

These are the same variables as `.env.example`; set them in SnapDeploy rather
than committing secrets. **Nothing is hardcoded** — the app reads all of it from
the environment.

| Variable | Value | Notes |
|---|---|---|
| `JWT_SECRET` | a long random string | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ADMIN_EMAIL` | e.g. `admin@aegisshield.app` | a **real** domain — `.local`/`.test` fail validation |
| `ADMIN_PASSWORD` | a strong password | the admin is re-seeded from this on every boot |
| `DATABASE_URL` | **external** Postgres URL | see the storage warning below — do **not** rely on the default SQLite here |
| `CORS_ORIGINS` | your SnapDeploy app URL | e.g. `https://your-app.snapdeploy.app` |
| `JWT_EXPIRE_MINUTES` | `1440` | optional |

## 4. Deploy and redeploy

- The first deploy builds the image and starts the container.
- **Redeploys** happen automatically on every push to the configured branch, or
  manually with **Deploy** in the dashboard (also available via their CLI / REST
  API). The free tier allows **10 deploys/day**.

---

## Free-tier reality check — read before going live

Aegis Shield is a full Kali-based scanner, not a lightweight web app. On
SnapDeploy's **free** tier, expect the following, and plan around the ones
marked **blocker**:

1. **512 MB RAM — blocker for real scans.** The image bundles nmap, nuclei,
   sqlmap, nikto, hydra, etc. A single active scan can easily exceed 512 MB and
   the container will be OOM-killed mid-scan. The UI will load, but real scans
   against anything non-trivial will fail or die. *Use a paid tier with more RAM
   for actual scanning, or keep scanning on the local `run.sh`/`run.bat` build.*

2. **Ephemeral storage — blocker for accounts & history.** Free containers lose
   all local files on every restart, sleep, or redeploy. With the default
   SQLite database that means **every registered user, scan job, and generated
   report disappears** (the admin is fine — it is re-seeded from the env vars on
   boot). To keep accounts and scan jobs, set `DATABASE_URL` to an **external
   managed Postgres** (Supabase, Neon, etc. — all have free tiers). Generated
   report files (`/app/output`) are still ephemeral; wire up external object
   storage (S3/R2) if you need them to persist.

3. **Auto-sleep when idle — scans die silently.** Free containers sleep after
   inactivity and take ~60s to wake on the next request. Scans run as background
   jobs, so if the container sleeps while a scan is running (e.g. the tab is
   closed), the scan is killed and the job is left stuck as "running".

4. **No managed database on the free tier.** Confirms (2) — bring your own
   Postgres.

5. **Large image / build time.** The Kali base plus all tools is multi-GB;
   builds are slow and you only get 10/day. Keep pushes deliberate.

6. **Authorisation / abuse policy — important.** Running active scanners
   (nmap, sqlmap, hydra, nikto) against third-party targets from shared hosting
   will likely violate SnapDeploy's acceptable-use policy and the target's. Only
   scan systems you own or are explicitly authorised to test, wherever this is
   hosted.

**Bottom line:** the free tier is fine for a *demo of the UI and workflow* if you
attach an external Postgres (item 2). For actually running scans, use a paid tier
with more memory, or run locally with `run.sh` / `run.bat` — which has none of
these limits.
