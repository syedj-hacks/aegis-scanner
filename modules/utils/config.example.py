"""
modules/utils/config.example.py
Template for modules/utils/config.py, which is gitignored so a per-user
override (personal API key, tweaked timeouts, etc.) never risks being
committed over this shared template.

setup.py copies this file to modules/utils/config.py automatically on
first install — no manual step needed. Ships with a project-wide NVD API
key baked in as NVD_API_KEY's default, so CVE lookups work immediately
after `git clone` + `./install.sh` for anyone the repo is shared with.
To use a personal key instead, set AEGIS_NVD_API_KEY (or NVD_API_KEY) in
your shell or in the gitignored .env — both take priority over the
default below.

Keep this file in sync when you add a config key, otherwise teammates get
an AttributeError on a key they never knew existed.
"""

import os

# ---- .env loading ----
# Secrets live in the gitignored .env at the repo root, not in this file:
# a key pasted into source is one `git add -f` (or one screen share) away
# from being disclosed. Parsed with the stdlib so no new dependency is
# needed. A real shell export always wins over .env.
_ENV_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    ".env",
)


def _load_dotenv(path: str = _ENV_PATH):
    """
    Populate os.environ from a KEY=value file, without overriding anything
    already exported. Silently does nothing if the file is absent or
    unreadable — a missing .env is a normal state, not an error.
    """
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
# Shared project key, used unless AEGIS_NVD_API_KEY or NVD_API_KEY is set
# in the environment/.env. Raises the rate limit from 5 req/30s to
# 50 req/30s. Get your own free key at
# https://nvd.nist.gov/developers/request-an-api-key if you'd rather not
# share the project's quota.
_DEFAULT_NVD_API_KEY = "dbc5a9fc-1ce6-4ca1-a349-2382249d2c50"
NVD_API_KEY = (
    os.environ.get("AEGIS_NVD_API_KEY")
    or os.environ.get("NVD_API_KEY")
    or _DEFAULT_NVD_API_KEY
)
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
    "dirb": 300,
    "default": 120,
}

def get_timeout(tool_name: str) -> int:
    return TOOL_TIMEOUTS.get(tool_name.lower(), TOOL_TIMEOUTS["default"])

# ---- nmap dynamic timeout scaling ----
# A single TOOL_TIMEOUTS['nmap'] budget cannot fit both a top-100-port -F
# scan and a full 65535-port '-p-' sweep. port_scanner.py inspects the
# profile's own nmap_args and picks the matching budget below instead of
# always using TOOL_TIMEOUTS['nmap'].
#   full_fast : deepscan's bare '-p-' discovery pass (runs at -T4)
#   anything else falls back to TOOL_TIMEOUTS['nmap']
#
# Sized as (chunks x per-chunk budget): port_scanner.py splits '-p-' into
# 32 chunks of ~2048 ports (_FULL_RANGE_CHUNKS), so 19200 gives each chunk
# 600s. Calibrated from a live measurement of ~9.4 ports/sec against a
# heavily filtered host, not guessed — raise it if your targets are
# slower, but do not lower it below (chunks x measured per-chunk time) or
# chunks start timing out before completing even once.
NMAP_TIMEOUTS = {
    "full_fast": 19200,  # 32 x 600s — full port range at -T3 or faster
}

# ---- Per-profile wall-clock budgets ----
# Ceiling on a profile's own per-port work loop, checked between ports so
# a target with many open web ports cannot run indefinitely. Separate from
# (and much smaller than) NMAP_TIMEOUTS['full_fast'], which budgets a
# single full-port sweep: a thorough port sweep and a per-port web audit
# have very different realistic completion times.
PROFILE_TIME_BUDGET_SECONDS = {
    "webaudit": 1800,   # 30 min
    "deepscan": 3600,   # 60 min — web-module loop only
}

# ---- Skip-current-tool keybind ----
# While a tool is running, pressing SKIP_KEY terminates just that
# subprocess and advances to the next tool (see error_handler.py's
# keyboard listener). Tools in COMPULSORY_TOOLS feed data that other
# modules depend on downstream and cannot be skipped — the keypress is
# acknowledged but ignored, with a message naming what depends on it.
COMPULSORY_TOOLS = {
    "nmap": "every downstream module (service detection, web audit, CVE "
            "lookup, conditional tools) depends on its open-port list",
    "nmap-sv": "CVE lookup and severity scoring depend on the "
               "product/version it reports",
    "nslookup": "subdomain enumeration and OSINT rely on the resolved "
                "address",
    "dns_resolve": "subdomain enumeration and OSINT rely on the resolved "
                   "address",
}

SKIP_KEY = "s"

# ---- Scan profile settings ----
PROFILES = {
    "quickscan": {
        "tools": ["nslookup", "nmap", "whatweb", "nuclei"],
        "nmap_args": ["-T4", "-F"],          # fast scan, top ports
        "nuclei_severity": ["critical", "high"],
    },
    "stealthscan": {
        "tools": ["nslookup", "nmap"],
        # REDESIGNED: a full 65535-port '-p-' sweep at any quiet timing
        # template is an architectural dead end — live-measured at ~0.29
        # ports/sec at -T2 against a real filtered target (60+ hours
        # extrapolated). No amount of chunk/timeout tuning fixes that, so
        # this scans a curated port list at -T2 ("Polite") instead:
        # measured at 22.5-96.0s against two real targets.
        "nmap_args": [
            "-T2", "-Pn", "--randomize-hosts",
            "-p", "21,22,23,25,53,80,110,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443",
        ],
        "nuclei_severity": ["critical", "high", "medium"],
    },
    "webaudit": {
        "tools": ["nslookup", "nmap", "whatweb", "nikto", "gobuster", "zaproxy"],
        "nmap_args": ["-T4", "-p", "80,443,8080,8443"],
        "gobuster_wordlist": "/usr/share/wordlists/dirb/common.txt",
    },
    "deepscan": {
        "tools": "ALL",                       # full top-20 toolset
        # Bare discovery sweep — NO -sV/-sC. Combining either with a
        # 65535-port sweep is nmap's slowest possible shape and, even
        # chunked, routinely blew every chunk's budget and returned zero
        # ports (confirmed live). service_detect.py runs -sV -sC as a
        # second pass against only the ports this one found.
        "nmap_args": ["-T4", "-p-"],
    },
    "compliance": {
        "tools": ["nmap", "sslyze", "whatweb"],
        "nmap_args": ["-T4", "-p", "80,443,8443", "--script", "ssl-enum-ciphers,http-headers"],
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

# ---- Known-good targets (regression guard) ----
# Hosts whose open ports are an established fact. port_scanner.py flags
# loudly if a scan of one of these returns ZERO open ports, since that can
# only be a scanner or network fault, never a real result. Keys must be
# lowercase; values are the ports known to be open.
KNOWN_GOOD_TARGETS = {
    "scanme.nmap.org": [22, 80],
}
