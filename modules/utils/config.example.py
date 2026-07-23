"""
modules/utils/config.example.py
Template for modules/utils/config.py, which is gitignored because it holds
a real API key.

Setup (every teammate, once, after cloning):

    cp modules/utils/config.example.py modules/utils/config.py
    echo "AEGIS_NVD_API_KEY=<your-key>" >> .env && chmod 600 .env

The key belongs in the gitignored .env at the repo root (or a shell
export) — never pasted into a source file, where one `git add -f` or one
screen share discloses it. Nothing imports this file directly; the rest of
the framework imports modules.utils.config.

Keep this file in sync when you add a config key, otherwise teammates get
an AttributeError on a key they never knew existed.
"""

import os

# ---- .env loading ----
# Parsed with the stdlib so no new dependency is needed. A real shell
# export always wins over .env; a missing .env is a normal state.
_ENV_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    ".env",
)


def _load_dotenv(path: str = _ENV_PATH):
    """Populate os.environ from a KEY=value file, overriding nothing."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()

# ---- NVD API ----
# Get a free key at https://nvd.nist.gov/developers/request-an-api-key
# Raises rate limit from 5 req/30s (no key) to 50 req/30s (with key)
# Set AEGIS_NVD_API_KEY in .env or your shell. NVD_API_KEY is accepted as
# a legacy alias so older local setups keep working. NEVER paste a real
# key here — this file IS tracked. An empty key degrades gracefully: the
# scan just uses the slower anonymous rate limit.
NVD_API_KEY = os.environ.get("AEGIS_NVD_API_KEY") or os.environ.get("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_WINDOW = 30          # seconds
NVD_RATE_LIMIT_REQUESTS = 50 if NVD_API_KEY else 5

# ---- Output ----
OUTPUT_ROOT = "output"

def output_dir(target: str) -> str:
    """Returns (and creates) the per-target output directory."""
    path = os.path.join(OUTPUT_ROOT, target)
    os.makedirs(path, exist_ok=True)
    return path

# ---- Timeouts (seconds) per tool ----
TOOL_TIMEOUTS = {
    "nmap": 300,
    "nikto": 600,
    "gobuster": 300,
    "nuclei": 600,
    "whatweb": 60,
    "theharvester": 180,
    "subfinder": 120,
    "amass": 600,
    "sqlmap": 600,
    "hydra": 300,
    "dirsearch": 300,
    "wafw00f": 30,
    "sslyze": 60,
    "masscan": 180,
    "enum4linux": 180,
    "wpscan": 300,
    "feroxbuster": 300,
    "nslookup": 15,
    "zaproxy": 900,
    "default": 120,
}

def get_timeout(tool_name: str) -> int:
    return TOOL_TIMEOUTS.get(tool_name.lower(), TOOL_TIMEOUTS["default"])

# ---- Scan profile settings ----
PROFILES = {
    "quickscan": {
        "tools": ["nslookup", "nmap", "whatweb", "nuclei"],
        "nmap_args": ["-T4", "-F"],          # fast scan, top ports
        "nuclei_severity": ["critical", "high"],
    },
    "stealthscan": {
        "tools": ["nslookup", "nmap"],
        "nmap_args": ["-T1", "-p-", "--randomize-hosts", "-Pn"],
        "nuclei_severity": ["critical", "high", "medium"],
    },
    "webaudit": {
        "tools": ["nslookup", "nmap", "whatweb", "nikto", "gobuster", "zaproxy"],
        "nmap_args": ["-T4", "-p", "80,443,8080,8443"],
        "gobuster_wordlist": "/usr/share/wordlists/dirb/common.txt",
    },
    "deepscan": {
        "tools": "ALL",                       # full top-20 toolset
        "nmap_args": ["-T4", "-p-", "-sV", "-sC"],
    },
    "compliance": {
        "tools": ["nmap", "sslyze", "whatweb"],
        "nmap_args": ["-T4", "--script", "ssl-enum-ciphers,http-headers"],
    },
}

def get_profile(name: str) -> dict:
    if name not in PROFILES:
        raise ValueError(f"Unknown scan profile: {name}")
    return PROFILES[name]

# ---- Threading ----
MAX_THREADS = 10

# ---- Conditional tool triggers ----
# These map a detection condition -> tool to conditionally run.
# The flag names are the keys modules return in their result dicts, e.g.
# gobuster_wrap.run_gobuster() returns "wordpress_fingerprinted": bool.
CONDITIONAL_TOOLS = {
    "sqlmap": "injectable_param_found",
    "hydra": "login_service_found",
    "wpscan": "wordpress_fingerprinted",
    "enum4linux": "smb_service_found",
}
