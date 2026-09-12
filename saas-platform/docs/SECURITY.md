# Security

[← Back to README](../README.md)

Aegis Shield hands real attack tooling to people over the web. Its main job is to make sure that
tooling is used only by the right people, within their plan, against targets they have vouched for.

---

## Threat model

| # | Threat | Control | Where |
|---|---|---|---|
| T1 | Anonymous use of the scanner | Every scan, billing and admin route requires a valid JWT | `deps.get_current_user` |
| T2 | Using features above your plan by calling the API directly | Every gate is checked server-side on each request | `tiers.py`, `routers/scans.py` |
| T3 | Self-granting a paid plan | Upgrades create a pending invoice that only the admin can approve | `routers/billing.py`, `routers/admin.py` |
| T4 | Running intrusive tools against a third party | `deepscan` needs Enterprise **and** a per-scan authorization, stored with time and IP | `routers/scans.py` |
| T5 | Becoming an administrator | Registration hard-codes `role=user`; the admin is created only from `.env`; boot fails with more than one admin | `routers/auth.py`, `seed_admin.py`, `main.py` |
| T6 | Reading another user's scans | All queries are scoped to the caller; diff checks both scan IDs are owned | `routers/scans.py` |
| T7 | Keeping access after suspension | The user row is reloaded and `is_active` checked on every request | `deps.py` |
| T8 | Credential theft from the database | Passwords stored as bcrypt hashes with per-password salt | `security.py` |
| T9 | Malformed or range targets | The engine's own validator rejects anything but a single host, so no CIDR sweeps | `aegis_bridge.validate_and_normalize_target` |
| T10 | Untraceable admin actions | Every admin mutation writes an audit entry that survives user deletion | `routers/admin.py` |

---

## Controls in detail

### Authentication
- Passwords: bcrypt (`bcrypt.gensalt()`), minimum 8 characters, validated by Pydantic.
- Sessions: HS256 JWT containing `sub` (user ID), `role` and `exp`. The default lifetime is 24 hours.
- Sign-in failures return the same message whether the email or the password was wrong, so
  account existence isn't revealed.
- The launcher generates a random 256-bit `JWT_SECRET` and a random admin password on first run.

### Authorization
- `require_admin` checks the **database** role, not the role claim inside the token, so a demoted
  or deleted admin loses access on the next request.
- Order of scan gates: plan → quota → parallel limit → auth-option entitlement → intrusive-tool
  authorization → target validation. A request must pass all of them.

### Plan escalation
Enterprise unlocks `deepscan`, which can launch sqlmap, hydra, wpscan and enum4linux **from the
server's IP address**. If upgrades were instant, anyone who registered could run those tools
against any host and leave the operator legally responsible. Paid plans therefore apply only after
an administrator approves the invoice. Downgrades stay instant because they only remove capability.

### Intrusive-tool authorization
`authorized_intrusive`, `authorized_at` and `authorized_ip` are stored on the scan job, which gives
an auditable record of who claimed authorization for which target, and when.

### Browser security
- CORS is restricted to `CORS_ORIGINS` plus the hosted frontend origin, never `*`.
- The `Access-Control-Allow-Private-Network` header is sent only in response to a Private Network
  Access preflight, which lets the HTTPS-hosted frontend reach a backend on the visitor's own machine.
- Report downloads go through the authenticated API client and are always saved as files. Reports are never exposed at public URLs, and HTML reports are never opened inside the app's origin, where script in a report could read the session.
- React escapes all rendered content. No finding text is inserted as raw HTML.

---

## Known limitations

These are deliberate scope limits for this version, listed so they aren't mistaken for oversights.

| Limitation | Risk | Recommended fix for production |
|---|---|---|
| No payment processor; invoices are approved manually | No automated revenue collection | Integrate Stripe Checkout and approve on webhook |
| JWT kept in `localStorage` | Readable by injected script if an XSS bug were introduced | HttpOnly, SameSite cookies with CSRF protection |
| No sign-in rate limiting or lockout | Online password guessing | A rate limit on `/auth/login` (for example slowapi) plus lockout |
| No email verification or password reset by email | Unverified sign-ups; the admin must reset passwords | Verification and reset-link emails |
| Sessions can't be revoked before expiry | A stolen token works until it expires | Short-lived access token with a refresh token and a deny-list |
| Background jobs lost on restart | A running scan stays `running` | A persistent queue (Celery, RQ) |
| Target ownership isn't verified | Users can claim authorization falsely | DNS TXT or file-based domain verification before scanning |
| Plain HTTP when run by the launcher | Traffic readable on the local network | Put a TLS reverse proxy (Caddy, nginx) in front |

---

## Operating it safely

1. Keep `saas-platform/backend/.env` private. It holds the JWT secret and the initial admin password.
2. Only expose the server beyond your own network behind TLS, and review upgrade requests before
   approving them.
3. Don't run `seed_sample_accounts.py` on a server others can reach.
4. Scan only systems you own or have written permission to test.
