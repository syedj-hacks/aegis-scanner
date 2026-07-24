#!/usr/bin/env python3
"""
setup.py
Post-install environment bootstrap for Aegis Scanner.

Not a setuptools/distutils packaging file: Aegis Scanner is run in place
from a cloned repo (see README.md's `./install.sh` flow), not pip-installed,
so there is nothing here to package or distribute. install.sh calls this
script after the venv is created and requirements.txt is installed, to
handle the parts a bash script does awkwardly: dependency verification,
directory bootstrap, and prompting for the NVD API key without ever
printing it back.

Raw print() is used throughout — this runs before aegis.py's own Rich UI
layer exists (install-time, not the application), same as install.sh.
"""

import getpass
import os
import sys

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(REPO_ROOT, ".env")

# import name -> requirements.txt entry, so a failure names the pip package.
# Note: requirements.txt also lists python-nmap, but no module in this
# codebase actually imports it (port_scanner.py/service_detect.py shell out
# to the nmap binary and parse its XML output with the stdlib) — checking
# for it here would flag a false failure, so it's deliberately omitted.
REQUIRED_MODULES = {
    "rich": "rich",
    "requests": "requests",
    "scapy": "scapy",
    "weasyprint": "weasyprint",
}


def check_python_version() -> bool:
    if sys.version_info < (3, 8):
        print(f"[-] Python 3.8+ is required (found {sys.version.split()[0]})")
        return False
    print(f"[+] Python {sys.version.split()[0]} OK")
    return True


def check_dependencies() -> bool:
    missing = [pkg for mod, pkg in REQUIRED_MODULES.items() if not _importable(mod)]
    if missing:
        print(f"[-] Missing Python dependencies: {', '.join(missing)}")
        print("    Run: pip install -r requirements.txt")
        return False
    print("[+] All Python dependencies importable")
    return True


def _importable(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False


def ensure_directories():
    for path in (os.path.join(REPO_ROOT, "output"), os.path.join(REPO_ROOT, "database")):
        os.makedirs(path, exist_ok=True)
    print("[+] output/ and database/ directories ready")


def _read_env() -> dict:
    values = {}
    if not os.path.isfile(ENV_PATH):
        return values
    with open(ENV_PATH, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    return values


def _write_env(values: dict):
    lines = [f"{k}={v}" for k, v in values.items()]
    with open(ENV_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))


def ensure_env_key():
    """
    Ensure .env carries AEGIS_NVD_API_KEY. Only ever reports whether a key
    is present, never its value — matches config.py's own handling.
    """
    existing = _read_env()

    if existing.get("AEGIS_NVD_API_KEY") or os.environ.get("AEGIS_NVD_API_KEY"):
        print("[+] AEGIS_NVD_API_KEY is configured")
        return

    print("[!] AEGIS_NVD_API_KEY is not set.")
    print("    Get a free key at https://nvd.nist.gov/developers/request-an-api-key")
    print("    Without one, CVE lookups fall back to NVD's slower anonymous rate limit (5 req/30s).")

    if not sys.stdin.isatty():
        print("    Non-interactive shell — add AEGIS_NVD_API_KEY=<key> to .env manually when ready.")
        _write_env(existing)
        return

    try:
        key = getpass.getpass("    Paste your NVD API key now (input hidden, or Enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        key = ""
        print()

    if key:
        existing["AEGIS_NVD_API_KEY"] = key
        print("[+] AEGIS_NVD_API_KEY saved to .env")
    else:
        print("[!] Skipped — add AEGIS_NVD_API_KEY to .env later")

    _write_env(existing)


def main():
    print("=== Aegis Scanner setup ===")
    ok = check_python_version()
    ok = check_dependencies() and ok
    ensure_directories()
    ensure_env_key()

    if not ok:
        print("[-] Setup finished with issues — resolve the above before running aegis.py")
        sys.exit(1)

    print("[+] Setup complete — run: python3 aegis.py <target> --profile quickscan")


if __name__ == "__main__":
    main()
