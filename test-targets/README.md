# test-targets/ — local Aegis Scanner CONDITIONAL_TOOLS verification fixtures

**These are local, isolated, intentionally-vulnerable Docker containers for
authorized testing of Aegis Scanner only. Do not expose any of these ports
beyond localhost, do not point any other tool at them, and do not leave
them running longer than needed for testing.**

## Why this exists

Aegis's four CONDITIONAL_TOOLS (wpscan, sqlmap, hydra, enum4linux) had never
been observed actually firing in any prior smoke test — neither
scanme.nmap.org nor pentest-ground.com meets any of their four trigger
conditions (see `smoke_test/smoke_test3.txt`, section 4). This stack gives
each one a real, locally-owned target that genuinely satisfies its
condition, so the conditional-dispatch path in
`modules/profiles/deepscan.py::_check_conditional_tools()` can be exercised
end-to-end with real tool output instead of remaining permanently
"ENVIRONMENT/TARGET-LIMITED."

## Bringing the stack up / down

```
cd test-targets
docker-compose up -d      # start all four targets
docker-compose ps         # check status
docker-compose down       # stop and remove (add -v to also drop the named volumes)
```

All four containers sit on a dedicated bridge network (`aegis-test-net`,
172.28.0.0/24) with static IPs, so Aegis can be pointed at each container's
own IP on its native service port — no host-port juggling between runs:

| Service            | Container IP  | Native port(s) | Host port(s)     |
|---------------------|---------------|----------------|-------------------|
| wordpress-target     | 172.28.0.10   | 80             | 8081              |
| dvwa-target           | 172.28.0.20   | 80             | 8082              |
| ssh-target             | 172.28.0.30   | 2222           | 2222              |
| smb-target             | 172.28.0.40   | 139, 445       | 139, 445          |

Run Aegis against the container IP directly, e.g.:

```
python3 aegis.py 172.28.0.10 --profile deepscan -v
```

(Conditional tools only dispatch from `deepscan` — the other four profiles
never call `_check_conditional_tools()`.)

## Per-target setup performed (one-time, not automated by compose alone)

### wordpress-target

`wordpress:latest` + `mysql:5.7`, on the shared `wp_html` volume. WordPress
is NOT just showing the install wizard — it was fully installed via a
one-shot `wordpress:cli` container:

```
docker run --rm --network test-targets_aegis-test-net \
  -v test-targets_wp_html:/var/www/html \
  -e WORDPRESS_DB_HOST=wordpress-db:3306 -e WORDPRESS_DB_USER=wordpress \
  -e WORDPRESS_DB_PASSWORD=wordpress -e WORDPRESS_DB_NAME=wordpress \
  wordpress:cli wp core install --allow-root --path=/var/www/html \
    --url="http://172.28.0.10" --title="Aegis Test Site" \
    --admin_user=admin --admin_password='AegisTestAdmin123!' \
    --admin_email=admin@example.test
```

Two plugins (Akismet, Hello Dolly) were activated afterward so wpscan's
plugin enumeration has real, non-empty output to report. Admin credentials
above are for the WP dashboard only — not needed by Aegis, which only
needs the site to be reachable and fingerprintable via its public
`/wp-admin`, `/wp-content`, `/wp-includes`, `/wp-login.php` paths.

### dvwa-target

`vulnerables/web-dvwa` (self-contained: bundles its own MariaDB + Apache,
DB creds `app`/`vulnerables`, database `dvwa`). The database was created
via an unauthenticated POST to `setup.php` (its own "Create / Reset
Database" button), then security level was set to **low** by logging in as
DVWA's own default `admin`/`password` account and POSTing to
`security.php`.

**Important architecture note — why `info.php` was added:**
DVWA's real SQLi lab page (`vulnerabilities/sqli/index.php`) sits behind
DVWA's login wall (a PHP session cookie). `modules/web/sqlmap_wrap.py`, as
of this writing, has no cookie/session support — its `run_sqlmap()` calls
plain `sqlmap -u <url> --batch --random-agent --level 1 --risk 1` with no
`--cookie`. That means Aegis's normal unauthenticated
gobuster/dirb-discovery → sqlmap flow can never reach DVWA's own lab page,
no matter how the container is configured — this is a genuine gap in the
scanner, not a container-setup problem, and is analogous to the
dirb/ZAP root-causing done in `smoke_test3.txt`.

To still give the CONDITIONAL_TOOLS dispatch path (and sqlmap specifically)
a real, unauthenticated, injectable target to confirm against, this
directory adds one small companion script, `dvwa-extra/info.php`, bind-mounted
into the DVWA container at `/var/www/html/info.php`. **It is NOT part of
stock DVWA** — it is a ~20-line script written for this test stack that
queries DVWA's own real `users` table (populated by the real
`setup.php` above) with the `id` GET parameter concatenated directly into
the SQL string, unauthenticated. Same vulnerability class as DVWA's own
lab page, just reachable without a session, so gobuster can discover it
(literal wordlist hit `info.php` in `dirb/common.txt`) and sqlmap can
confirm it exactly the way the scanner's real code path is supposed to
work end-to-end.

Verified manually before any Aegis run:
```
curl "http://localhost:8082/info.php" --data-urlencode "id=1' OR '1'='1" -G
# -> dumps all 5 DVWA users, confirming genuine boolean-based SQLi
```

**Companion `xss.php` (reflected XSS fixture) — the sibling of `info.php`:**
DVWA's own reflected-XSS lab page (`vulnerabilities/xss_r/index.php`) sits
behind the same login wall as its SQLi page, so Aegis's unauthenticated web
flow can't reach it. `dvwa-extra/xss.php`, bind-mounted at
`/var/www/html/xss.php`, is a ~20-line UNAUTHENTICATED reflected-XSS
stand-in: it echoes the `name` GET parameter straight into the HTML response
with no output encoding, so `modules/web/xss_wrap.py` (nuclei `-dast -tags
xss`) can confirm reflection end-to-end. **It is NOT part of stock DVWA.**

Verified manually before any Aegis run:
```
curl "http://localhost:8082/xss.php?name=<script>alert(1)</script>"
# -> the <script> tag is reflected unescaped inside <h1>Hello, ...</h1>
```

Discovery note: unlike `info.php` (whose name is in `dirb/common.txt`, so
Aegis's gobuster/dirb discovery reaches it unaided and deepscan's real
discovery→sqlmap chain fires against it), `xss.php` is **not** in the
wordlist, so the scanner's unauthenticated path never lands on it even
though the XSS wiring (deepscan/webaudit XSS phase) is fully in place and
does run nuclei DAST against every parameterised endpoint it *does*
discover. Confirm the XSS engine directly against the fixture with
`direct_xss_confirm.py` (the XSS sibling of `direct_sqlmap_confirm.py`),
which calls the exact production `run_xss()` the profiles call.

### ssh-target

`linuxserver/openssh-server`, one throwaway account:
  - username: `admin`
  - password: `admin`

Deliberately chosen because both strings appear early in the Kali
wordlists `hydra_wrap.py` already defaults to
(`/usr/share/wordlists/metasploit/unix_users.txt` /
`unix_passwords.txt`) — `admin` is the very first entry in
`unix_passwords.txt` — so a real hydra run (not a huge rockyou.txt-scale
brute force) finds it quickly. Verified manually via a real SSH login
(paramiko) before any Aegis run.

### smb-target

`dperson/samba`, one guest-accessible share:
  - share name: `public` (guest access, browsable, read/write, no auth
    required)
  - one throwaway SMB user also configured: `smbtest` / `smbtest123`
    (not required for the guest share, but exercises `-u` too)

Verified manually via `smbclient -L //localhost -N -p 445` and
`smbclient //localhost/public -N -p 445` (null/guest session) before any
Aegis run.

## Cleanup

```
cd test-targets
docker-compose down -v
```

This removes the containers, the dedicated network, and the named volumes
(WordPress DB/files, DVWA's own internal DB is inside its container layer
and goes with the container). Nothing here should be left running after
verification is done.
