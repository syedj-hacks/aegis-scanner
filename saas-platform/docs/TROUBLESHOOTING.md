# Troubleshooting

[← Back to README](../README.md)

### "Python 3.10 or newer is required"
- **Windows:** install Python from [python.org](https://www.python.org/downloads/) and tick
  **Add python.exe to PATH**. Close and reopen the folder, then double-click the launcher again.
- **Linux:** `sudo apt install python3 python3-venv`

### "Python could not create a virtual environment"
Debian, Ubuntu and Kali ship `venv` separately: `sudo apt install python3-venv`, then run the
launcher again.

### Dependency installation fails
- Check your internet connection. The first run downloads packages from PyPI.
- If you are on a very new Python release, the launcher retries with the latest package versions
  automatically. If that also fails, install Python 3.12 and run it with `py -3.12
  launch_aegis_shield.py` (Windows) or `python3.12 launch_aegis_shield.py` (Linux).
- To start over, delete `saas-platform/backend/.venv` and run the launcher again.

### The website says "Can't reach the Aegis Shield server"
The web app loaded but no backend answered.
- **Running locally:** make sure the launcher window is still open and printed *Aegis Shield is running*.
- **On the GitHub Pages site:** that site has no backend of its own. It connects to
  `http://localhost:8000` on *your* computer, so start the launcher first, on port 8000. Chrome may
  ask whether the site may access devices on your local network; allow it. The most reliable option
  is to use the address the launcher prints instead.

### Sign-in says "Incorrect email or password" for the admin
- The launcher prints the admin password only on the first run. Read `ADMIN_PASSWORD` in
  `saas-platform/backend/.env`.
- `ADMIN_PASSWORD` only matters when the account is **created**. Changing it later has no effect;
  see the next entry.

### I lost the admin password
From `saas-platform/backend`, using the same Python the launcher uses (`.venv` or the repository's `venv`):

```bash
python -c "
from app.database import SessionLocal
from app.models import User, Role
from app.security import hash_password
db = SessionLocal()
admin = db.query(User).filter(User.role == Role.admin).one()
admin.hashed_password = hash_password('NewStrongPassword123')
db.commit()
print('Password reset for', admin.email)
"
```

### The admin email is rejected as invalid
Addresses on reserved domains such as `.local`, `.test` or `.localhost` fail email validation at
sign-in. Use a normal domain in `ADMIN_EMAIL` **before** the first run. To change it afterwards,
delete `saas-platform/backend/data/aegis_shield.db`, which erases all accounts.

### "Port 8000 is busy; using 8001 instead"
Another program already uses port 8000. The app works on the new port. If the other program is an
earlier Aegis Shield, the launcher detects it and just shows its address instead.

### Other devices can't open the Local network address
- Both devices must be on the same network. Guest Wi-Fi often isolates devices.
- **Windows:** allow Python in *Windows Defender Firewall → Allow an app through firewall* for
  private networks.
- **Linux:** `sudo ufw allow 8000/tcp` if ufw is enabled.
- Virtual machines on NAT networking (a `10.0.2.x` address) can't be reached from the host's
  network. Switch the VM to *Bridged* networking.

### A scan finishes with few or no findings
- The security tools aren't installed. They come from the engine's `install.sh` on Kali/Debian;
  Windows machines normally don't have them.
- The target is rate-limiting or blocking scans, or sits behind a CDN or WAF challenge.
- Check the report. The engine records which tools failed or were skipped.

### A scan is stuck in "running" after a restart
Background jobs don't survive a server restart. Submit the scan again. The stale job only counts
towards the parallel-scan limit, so if it blocks new scans, set its `status` to `failed` in the
`scan_jobs` table.

### "Refusing to start: 2 admin accounts found"
Someone created an extra admin directly in the database. The server refuses to run until the
extra row is removed or changed to `role = 'user'`.

### Frontend changes don't appear
The launcher serves the prebuilt `saas-platform/frontend/dist`. Rebuild with `npm run build`
([details](INSTALLATION.md#rebuilding-the-production-bundle)), then hard-refresh the browser with
Ctrl+Shift+R.
