#!/usr/bin/env python3
"""
One-click launcher for Aegis Shield (Windows and Linux).

Double-click "Start Aegis Shield.bat" (Windows) or run ./start-aegis-shield.sh
(Linux). On first run this:

  1. finds or creates a Python virtual environment and installs dependencies,
  2. writes saas-platform/backend/.env with a SQLite database, a random JWT
     secret and a generated admin password (printed once, below),
  3. creates the database tables and the single admin account,
  4. serves the API *and* the web app from one port, and prints every
     address it can be reached on (this machine and the local network).

Later runs skip straight to step 4. Nothing here needs admin/root rights.

Options:
  --port N            listen on port N (default 8000, or AEGIS_PORT)
  --no-browser        don't open the browser automatically
  --install-shortcut  add an "Aegis Shield" launcher to the desktop/app menu
"""
import argparse
import hashlib
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "saas-platform" / "backend"
FRONTEND = ROOT / "saas-platform" / "frontend"
ENV_FILE = BACKEND / ".env"
LOCAL_VENV = BACKEND / ".venv"
ENGINE_VENV = ROOT / "venv"
IS_WINDOWS = os.name == "nt"

BACKEND_IMPORTS = "fastapi, uvicorn, sqlalchemy, alembic, bcrypt, jwt, dotenv, email_validator, multipart"
ENGINE_IMPORTS = "rich, requests, yaml"

if IS_WINDOWS:
    os.system("")  # enables ANSI colours in the classic Windows console

ORANGE, BOLD, DIM, RESET = "\033[38;5;209m", "\033[1m", "\033[2m", "\033[0m"


def say(msg: str) -> None:
    print(f"{ORANGE}>{RESET} {msg}", flush=True)


def fail(msg: str) -> "None":
    print(f"\n{ORANGE}{BOLD}Could not start Aegis Shield.{RESET}\n{msg}\n", flush=True)
    sys.exit(1)


# ---------------------------------------------------------------- python env

def venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def can_import(python: Path, modules: str) -> bool:
    if not python.exists():
        return False
    result = subprocess.run([str(python), "-c", f"import {modules}"], capture_output=True)
    return result.returncode == 0


def requirement_lines(path: Path, skip=()) -> list:
    lines = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line and not any(line.lower().startswith(s) for s in skip):
            lines.append(line)
    return lines


def unpinned(req: str) -> str:
    for sep in ("==", ">=", "<=", "~=", "<", ">"):
        req = req.split(sep, 1)[0]
    return req.strip()


def pip_install(python: Path, reqs: list) -> bool:
    cmd = [str(python), "-m", "pip", "install", "--disable-pip-version-check", "-q", *reqs]
    return subprocess.run(cmd).returncode == 0


def ensure_python_env(needs_postgres: bool) -> Path:
    required = BACKEND_IMPORTS + ", " + ENGINE_IMPORTS + (", psycopg2" if needs_postgres else "")

    # Reuse the scanner engine's own venv when it already has everything
    # (the normal case on a machine where install.sh was run).
    for candidate in (venv_python(LOCAL_VENV), venv_python(ENGINE_VENV)):
        if can_import(candidate, required):
            return candidate

    python = venv_python(LOCAL_VENV)
    if not python.exists():
        say("Creating a Python virtual environment (first run only)…")
        result = subprocess.run([sys.executable, "-m", "venv", str(LOCAL_VENV)], capture_output=True, text=True)
        if result.returncode != 0 or not python.exists():
            hint = "  sudo apt install python3-venv" if not IS_WINDOWS else "  Reinstall Python from python.org"
            fail(f"Python could not create a virtual environment:\n{result.stderr.strip()}\n\nFix:\n{hint}")

    skip = () if needs_postgres else ("psycopg2",)
    reqs = requirement_lines(BACKEND / "requirements.txt", skip) + requirement_lines(ROOT / "requirements.txt")
    stamp = LOCAL_VENV / ".aegis-requirements"
    digest = hashlib.sha256("\n".join(reqs).encode()).hexdigest()
    if stamp.exists() and stamp.read_text() == digest and can_import(python, required):
        return python

    say("Installing dependencies (first run only, this can take a few minutes)…")
    subprocess.run([str(python), "-m", "pip", "install", "-q", "--upgrade", "pip"], capture_output=True)
    if not pip_install(python, reqs):
        # Pinned versions may have no pre-built wheel for a brand-new Python
        # release; fall back to the newest compatible versions.
        say("Pinned versions failed to install on this Python; retrying with the latest releases…")
        if not pip_install(python, [unpinned(r) for r in reqs]):
            fail("Dependency installation failed. Check your internet connection and the pip output above.")
    if not can_import(python, required):
        fail("Dependencies installed but still cannot be imported. See the pip output above.")
    stamp.write_text(digest)
    return python


# ------------------------------------------------------------ configuration

def read_env() -> dict:
    values = {}
    if ENV_FILE.exists():
        for raw in ENV_FILE.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def ensure_env_file() -> None:
    if ENV_FILE.exists():
        return
    db_path = (BACKEND / "data" / "aegis_shield.db").as_posix()
    password = secrets.token_urlsafe(12)
    ENV_FILE.write_text(
        "# Generated by launch_aegis_shield.py on first run. Keep this file private.\n"
        f"AEGIS_REPO_PATH={ROOT.as_posix()}\n"
        f"DATABASE_URL=sqlite:///{db_path}\n"
        f"JWT_SECRET={secrets.token_hex(32)}\n"
        "JWT_EXPIRE_MINUTES=1440\n"
        "ADMIN_EMAIL=admin@aegisshield.app\n"
        f"ADMIN_PASSWORD={password}\n"
        "CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173\n"
    )
    print(
        f"\n{BOLD}Administrator account created{RESET}\n"
        f"  email     admin@aegisshield.app\n"
        f"  password  {password}\n"
        f"{DIM}  Saved in saas-platform/backend/.env — change it there before first sign-in if you like.{RESET}\n"
    )


def ensure_engine_config() -> None:
    config = ROOT / "modules" / "utils" / "config.py"
    example = ROOT / "modules" / "utils" / "config.example.py"
    if not config.exists() and example.exists():
        shutil.copyfile(example, config)


def ensure_frontend_build() -> None:
    if (FRONTEND / "dist" / "index.html").exists():
        return
    npm = shutil.which("npm")
    if not npm:
        fail(
            "The web app build (saas-platform/frontend/dist) is missing and Node.js is not installed.\n"
            "Install Node.js 18+ from https://nodejs.org and run the launcher again."
        )
    say("Building the web app (first run only)…")
    for args in (["install"], ["run", "build"]):
        if subprocess.run([npm, *args], cwd=FRONTEND, shell=IS_WINDOWS).returncode != 0:
            fail(f"'npm {' '.join(args)}' failed. See the output above.")


def prepare_database(python: Path, env: dict) -> None:
    if env.get("DATABASE_URL", "").startswith("postgres"):
        say("Applying database migrations…")
        if subprocess.run([str(python), "-m", "alembic", "upgrade", "head"], cwd=BACKEND).returncode != 0:
            fail("Database migration failed. Is PostgreSQL running and DATABASE_URL in .env correct?")
    result = subprocess.run([str(python), "seed_admin.py"], cwd=BACKEND, capture_output=True, text=True)
    if result.returncode != 0:
        fail(f"Could not prepare the admin account:\n{result.stdout}{result.stderr}")


# ------------------------------------------------------------------ network

def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def health_ok(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def lan_addresses() -> list:
    found = set()
    try:
        # Connecting a UDP socket sends nothing; it just asks the OS which
        # interface would route to the internet.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            found.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    return sorted(ip for ip in found if not ip.startswith("127."))


def banner(port: int, already_running: bool = False) -> str:
    line = "─" * 60
    rows = [f"  This computer   http://localhost:{port}"]
    rows += [f"  Local network   http://{ip}:{port}" for ip in lan_addresses()]
    state = "is already running" if already_running else "is running"
    print(
        f"\n{line}\n{BOLD}  Aegis Shield {state}{RESET}\n{line}\n" + "\n".join(rows) +
        f"\n\n{DIM}  Other devices on the same network can use the Local network address."
        + ("\n  Allow Python through Windows Defender Firewall if prompted." if IS_WINDOWS else "")
        + f"\n  Press Ctrl+C in this window to stop.{RESET}\n{line}\n",
        flush=True,
    )
    return f"http://localhost:{port}"


# ---------------------------------------------------------------- shortcuts

def install_shortcut() -> None:
    if IS_WINDOWS:
        desktop = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop"
        target = desktop / "Aegis Shield.bat"
        target.write_text(f'@echo off\ncall "{ROOT / "Start Aegis Shield.bat"}"\n')
        say(f"Shortcut created: {target}")
        return
    entry = (
        "[Desktop Entry]\nType=Application\nName=Aegis Shield\n"
        "Comment=Start the Aegis Shield vulnerability assessment platform\n"
        f'Exec=sh "{ROOT / "start-aegis-shield.sh"}"\nTerminal=true\nCategories=Development;Security;\n'
    )
    for folder in (Path.home() / ".local/share/applications", Path.home() / "Desktop"):
        if folder.parent.exists():
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / "aegis-shield.desktop"
            path.write_text(entry)
            path.chmod(0o755)
            say(f"Shortcut created: {path}")


# --------------------------------------------------------------------- main

def main() -> None:
    parser = argparse.ArgumentParser(description="Start Aegis Shield.")
    parser.add_argument("--port", type=int, default=int(os.environ.get("AEGIS_PORT", "8000")))
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--install-shortcut", action="store_true")
    args = parser.parse_args()

    if args.install_shortcut:
        install_shortcut()
        return

    if sys.version_info < (3, 10):
        fail(f"Python 3.10 or newer is required (found {platform_version()}).")

    print(f"\n{BOLD}Aegis Shield{RESET}{ORANGE}.{RESET} {DIM}starting…{RESET}\n", flush=True)

    port = args.port
    if not port_free(port):
        if health_ok(port):
            url = banner(port, already_running=True)
            if not args.no_browser:
                webbrowser.open(url)
            return
        original = port
        port = next((p for p in range(original + 1, original + 50) if port_free(p)), None)
        if port is None:
            fail(f"Port {original} and the next 49 ports are all in use. Try --port with a free port.")
        say(f"Port {original} is busy; using {port} instead.")

    ensure_engine_config()
    ensure_env_file()
    env = read_env()
    python = ensure_python_env(needs_postgres=env.get("DATABASE_URL", "").startswith("postgres"))
    ensure_frontend_build()
    prepare_database(python, env)

    say("Starting the server…")
    server = subprocess.Popen(
        [str(python), "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", str(port)],
        cwd=BACKEND,
    )
    try:
        deadline = time.time() + 90
        while not health_ok(port):
            if server.poll() is not None:
                fail("The server stopped during startup. See the error output above.")
            if time.time() > deadline:
                server.terminate()
                fail("The server did not respond within 90 seconds.")
            time.sleep(0.5)

        url = banner(port)
        if not args.no_browser:
            webbrowser.open(url)
        server.wait()
    except KeyboardInterrupt:
        print("\nStopping Aegis Shield…", flush=True)
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


def platform_version() -> str:
    return ".".join(str(v) for v in sys.version_info[:3])


if __name__ == "__main__":
    main()
