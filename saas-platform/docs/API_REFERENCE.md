# API reference

[← Back to README](../README.md)

The backend is a REST API served by FastAPI. When the server is running, interactive documentation
is available at **`/docs`** (Swagger UI) and **`/redoc`**.

- **Base URL:** the server address, for example `http://localhost:8000`
- **Format:** JSON request and response bodies
- **Auth:** `Authorization: Bearer <access_token>` from `/auth/login` or `/auth/register`
- **Errors:** `{"detail": "message"}` with a matching HTTP status

| Status | Meaning |
|---|---|
| `400` | Invalid request (for example already on that plan, invalid target) |
| `401` | Missing, invalid or expired token; wrong credentials |
| `403` | Authenticated but not allowed (plan, quota, suspended, not admin) |
| `404` | Resource doesn't exist or isn't yours |
| `409` | Resource not ready (scan still running) |
| `422` | Body failed validation (for example password too short) |
| `429` | Too many scans in progress for your plan |

Legend: 🔓 public · 🔑 signed-in user · 🛡 administrator

---

## Health

### `GET /health` 🔓
```json
{ "status": "ok" }
```

---

## Authentication

### `POST /auth/register` 🔓
Creates a user on the Free plan and signs them in.

```json
// request
{ "email": "analyst@company.com", "password": "at-least-8-chars" }
// 200 response
{ "access_token": "eyJ…", "token_type": "bearer", "role": "user", "email": "analyst@company.com" }
```
`400` if the email is already registered. `422` if the password is shorter than 8 characters or the
email is invalid.

### `POST /auth/login` 🔓
Same request and response shape as register. `401` for wrong credentials, `403` if the account is
suspended. Updates `last_login_at`.

Tokens are HS256 JWTs that carry the user ID and role, valid for `JWT_EXPIRE_MINUTES` (default 24h).

---

## Billing

### `GET /billing/subscription` 🔑
```json
{
  "tier": "free",
  "status": "active",
  "started_at": "2026-09-12T22:29:09",
  "renews_at": null,
  "scans_used_this_period": 3,
  "scans_limit": 10,
  "period_start_date": "2026-09-12T22:29:09",
  "pending_tier": "pro"
}
```
`scans_limit` is `null` for unlimited. `pending_tier` is the plan of an open upgrade request, or `null`.

### `GET /billing/payments` 🔑
Your invoices, newest first.
```json
[{ "id": 4, "amount": 1999, "tier": "pro", "simulated_method": "invoice",
   "status": "pending", "created_at": "…", "note": "Awaiting account review" }]
```
`amount` is in cents. `status` is `paid`, `pending` or `failed` (declined or cancelled; see `note`).
`simulated_method` holds the billing method (`invoice`, `manual` or `plan change`). The field name
is kept for database compatibility.

### `POST /billing/change-plan` 🔑
```json
{ "tier": "enterprise" }
```
- **Upgrade:** creates a pending invoice, or updates the existing one. The plan doesn't change yet.
- **Downgrade:** applies immediately and cancels any pending upgrade.

Returns the updated subscription. `400` if you are already on that plan.

### `DELETE /billing/upgrade-request` 🔑
Cancels your pending upgrade. Returns the subscription, or `404` if nothing is pending.

---

## Scans

### `GET /scans/profiles` 🔑
All six profiles, with whether your plan can run them.
```json
[{ "name": "deepscan", "description": "Full assessment: …", "locked": true, "requires_authorization": true }]
```

### `POST /scans/submit` 🔑
```json
{
  "target": "app.example.com",
  "profile": "webaudit",
  "auth_header": "Authorization: Bearer …",
  "auth_cookie": null,
  "authorized_intrusive": false
}
```
Checks run in this order, and each can reject the request:

| # | Check | Failure |
|---|---|---|
| 1 | Profile included in your plan | `403` |
| 2 | Monthly quota not exhausted | `403` |
| 3 | Parallel-scan limit not reached | `429` |
| 4 | Auth header/cookie allowed on your plan | `403` |
| 5 | `deepscan`: Enterprise and `authorized_intrusive: true` | `403` |
| 6 | Target is a valid single host | `400` |

On success it returns the scan job (status `queued`), and the scan starts in the background.

### `GET /scans/jobs` 🔑
Your scan jobs, newest first.
```json
[{ "id": 12, "target": "app.example.com", "profile": "webaudit", "status": "done",
   "aegis_scan_id": 88, "error": null, "created_at": "…", "started_at": "…", "finished_at": "…" }]
```
`status` is `queued`, `running`, `done` or `failed`.

### `GET /scans/jobs/{job_id}` 🔑
A single job. `404` if it isn't yours.

### `GET /scans/jobs/{job_id}/findings` 🔑
```json
[{ "id": 1, "port": 443, "service": "https", "severity": "HIGH",
   "description": "…", "finding_type": "…", "cve_id": "CVE-2023-…", "remediation": "…" }]
```
`409` while the scan is still running.

### `GET /scans/jobs/{job_id}/report?fmt=html|pdf|json` 🔑
Returns the report file (`html`, `pdf`) or the findings array (`json`). `403` if your plan doesn't
include the format, `404` if the report wasn't produced.

### `GET /scans/history?target=app.example.com` 🔑
Your jobs for one target, newest first.

### `POST /scans/diff` 🔑
```json
{ "scan_id_a": 80, "scan_id_b": 88 }
```
Both IDs are engine scan IDs (`aegis_scan_id`) from jobs you own. Returns
`{ "new": [], "fixed": [], "unverified": [], "unchanged": [], "changed": [] }`. `403` on Free,
`404` if either scan isn't yours.

---

## Administration

Every route below requires the administrator role, which is checked against the database on each
request. Other users receive `403`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/admin/dashboard` | Totals: users, users per plan, scans in the last 30 days, findings, storage bytes |
| `GET` | `/admin/users` | All users with plan, usage and last sign-in |
| `POST` | `/admin/users/{id}/tier` | Set a user's plan: `{"tier": "pro"}` |
| `POST` | `/admin/users/{id}/reset-password` | `{"new_password": "…"}` (minimum 8) |
| `POST` | `/admin/users/{id}/suspend` | Toggle suspension; returns `{"ok": true, "is_active": false}` |
| `DELETE` | `/admin/users/{id}` | Delete a user and their data |
| `GET` | `/admin/upgrade-requests` | Pending upgrades: `id, user_id, email, current_tier, requested_tier, amount, created_at` |
| `POST` | `/admin/upgrade-requests/{id}/approve` | Apply the plan and mark the invoice paid |
| `POST` | `/admin/upgrade-requests/{id}/reject` | Decline the request |
| `GET` | `/admin/reports` | Completed jobs with report size on disk |
| `DELETE` | `/admin/reports/{job_id}` | Delete report files and the job |
| `GET` | `/admin/audit-log` | Every admin action, newest first |

The administrator account itself can't be given a plan, suspended or deleted (`400`). Approving or
declining a request that is no longer pending returns `404`.
