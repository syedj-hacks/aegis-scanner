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
    # testssl.sh runs a long series of individual handshake probes and is
    # substantially slower than sslyze for that reason -- a full -U
    # vulnerability sweep against a live host measured ~4 minutes during
    # this project's verification, so the budget is sized well past that
    # rather than at it.
    "testssl": 900,
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

# ---- Within-scan concurrency ----
# The tools a profile runs against ONE port (nikto, gobuster, dirb, whatweb,
# sslyze) do not read each other's output — they only need the port/service
# info already resolved before the loop starts. Running them one after
# another therefore serialises five independent network waits for no reason,
# which is most of where a deepscan's wall-clock time goes.
#
# These are subprocess calls, so the work happens in other processes and the
# GIL is not a factor; a thread pool is the right tool. Only genuinely
# independent tools are pooled — see PARALLEL_WEB_TOOLS below for the ones
# deliberately left sequential and why.
#
# Set PARALLEL_WEB_TOOLS = False to fall back to fully sequential execution
# (for debugging, or a target that reacts badly to concurrent probing).
PARALLEL_WEB_TOOLS = True
MAX_CONCURRENT_WEB_TOOLS = 5

# Which profiles the per-port web-tool pool applies to. Opt-in by name, not
# "every profile that has a web loop", so adding a profile is a deliberate
# act. stealthscan is absent and must stay absent: concurrent probing is the
# exact opposite of a minimal-footprint scan, and tests/t_stealth_guard.py
# asserts it is not in here.
PARALLEL_WEB_TOOL_PROFILES = {"webaudit", "deepscan"}

# How many of deepscan's 32 full-range nmap chunks may run at once.
# Conservative by default: each chunk is a full nmap process, and three
# concurrent SYN sweeps against one host is already a noticeably heavier
# footprint than one. Set to 1 for the previous fully-sequential behaviour.
#
# ONLY applies to a '-p-' sweep, which today means deepscan alone.
# stealthscan does not sweep the full range (see PROFILES) so this value can
# never reach it, by construction.
MAX_CONCURRENT_NMAP_CHUNKS = 3

# ---- Multi-target concurrency (--targets) ----
# Distinct from the within-scan concurrency above: this is how many separate
# TARGETS run at once. Deliberately small — each target concurrently runs its
# own web-tool pool, so the real outbound request rate is roughly
# MAX_CONCURRENT_TARGETS x MAX_CONCURRENT_WEB_TOOLS.
MAX_CONCURRENT_TARGETS = 2

# ---- Per-profile rate limiting / backoff ----
# Generalises the fix applied to dirb, which was tripping a connection-count
# threshold on some targets and getting throttled into uselessness. That was
# solved for one tool by shrinking its wordlist; the general problem is that
# a profile has no way to say "go gently against this class of target".
#
# EVERY DEFAULT BELOW REPRODUCES TODAY'S BEHAVIOUR EXACTLY. gobuster already
# ran with '-t 30'; nikto, dirb and nuclei ran with no pacing flag at all,
# and None here means "do not pass the flag", not "pass zero". Nothing gets
# slower unless someone deliberately changes a value. This makes throttling
# *available* per profile; it does not impose it.
#
# Keys, and the flag each maps to:
#   gobuster_threads  -> gobuster -t <n>
#   dirb_delay_ms     -> dirb -z <ms>          (None = flag omitted)
#   nikto_pause_s     -> nikto -Pause <s>      (None = flag omitted)
#   nuclei_rate_limit -> nuclei -rate-limit <n/s>  (None = nuclei's own default)
#
# Matters more once --targets means several hosts are being probed at once:
# a profile used for bulk scanning can be throttled without touching the
# profile used for a single authorised engagement.
_DEFAULT_RATE_LIMIT = {
    "gobuster_threads": 30,
    "dirb_delay_ms": None,
    "nikto_pause_s": None,
    "nuclei_rate_limit": None,
}

PROFILE_RATE_LIMITS = {
    "quickscan":   dict(_DEFAULT_RATE_LIMIT),
    "stealthscan": dict(_DEFAULT_RATE_LIMIT),
    "webaudit":    dict(_DEFAULT_RATE_LIMIT),
    "deepscan":    dict(_DEFAULT_RATE_LIMIT),
    "compliance":  dict(_DEFAULT_RATE_LIMIT),
}


def get_rate_limits(profile: str = None) -> dict:
    """
    The resolved rate-limit settings for `profile`, falling back to the
    defaults (i.e. today's behaviour) for an unknown or absent profile.

    Always returns every key, so a caller can read a setting without
    guarding for its absence. Returns a copy — a caller that mutates the
    result must not be able to reconfigure the profile for the whole run.
    """
    resolved = dict(_DEFAULT_RATE_LIMIT)
    resolved.update(PROFILE_RATE_LIMITS.get(profile) or {})
    return resolved


# ---- Authenticated scanning (opt-in) ----
# Credentials for scanning behind a login. Sourced from the environment/.env
# so a credential never has to be typed into a shell history or committed;
# aegis.py's --auth-cookie/--auth-header flags override these when given.
#
# Omitting all of them reproduces today's behaviour exactly — every tool is
# invoked with no auth argument, byte for byte as before.
#
# The VALUE of any of these is a secret and is never logged, never written
# to scan_errors.log and never rendered into a report. Only the FACT that
# authentication was configured is recorded (see modules/utils/auth.py).
AUTH_COOKIE = os.environ.get("AEGIS_AUTH_COOKIE") or None
AUTH_HEADER = os.environ.get("AEGIS_AUTH_HEADER") or None
AUTH_BASIC_USER = os.environ.get("AEGIS_AUTH_BASIC_USER") or None
AUTH_BASIC_PASS = os.environ.get("AEGIS_AUTH_BASIC_PASS") or None

# ---- ZAP daemon location ----
# Unset (the default) means today's behaviour: zap_wrap.py spawns a local
# zap.sh daemon itself. Setting ZAP_HOST points it at an already-running
# daemon instead — typically the container in docker/zap/, whose disposable
# ~/.ZAP profile is what makes 'docker compose restart zap' a real fix for
# the add-on corruption class of failure documented in WRITEUP.md §3.1.
ZAP_HOST = os.environ.get("ZAP_HOST") or None
ZAP_PORT = int(os.environ.get("ZAP_PORT") or 8090)

# ---- Known-good targets (regression guard) ----
# Hosts whose open ports are an established fact. port_scanner.py flags
# loudly if a scan of one of these returns ZERO open ports, since that can
# only be a scanner or network fault, never a real result. Keys must be
# lowercase; values are the ports known to be open.
KNOWN_GOOD_TARGETS = {
    "scanme.nmap.org": [22, 80],
}
