"""
modules/utils/auth.py
Authenticated-scan credentials, and the rules for handling them.

Why this is its own module
--------------------------
Six tools take a credential, each with its own flag spelling (nikto -id,
gobuster -c/-H, sqlmap --cookie/--headers, nuclei -H, ZAP's replacer API).
Resolving "is auth configured, and in what form" separately at six call
sites is how one of them ends up disagreeing with the others — or worse,
how one of them ends up printing the credential.

So the credential is resolved once, here, and every wrapper asks this
module for the arguments it should add. Two rules hold everywhere:

  1. **Opt-in.** With nothing configured, describe() reports "not
     configured" and every *_args() helper returns an empty list, so every
     command is built byte-for-byte identically to before this module
     existed. Authentication is never inferred or defaulted on.

  2. **The value is never logged.** Not to scan_errors.log, not to the
     console, not into a report, not in a debug line. A session cookie is a
     live credential for someone else's application; a scan artefact that
     leaks one is worse than the finding it was collecting. Only the FACT
     of authentication is recordable — that is what describe() is for, and
     it is the only thing in this module safe to print.

Precedence: an explicit CLI flag beats the environment/.env, which beats
nothing. Basic-auth credentials are only used when BOTH user and pass are
present — half a credential pair is a misconfiguration, not a credential,
and is reported as such rather than sent as "user:None".

Tools without clean custom-auth support
---------------------------------------
whatweb and dirb are deliberately left unauthenticated. Neither takes a
custom header or cookie in a form this codebase can pass reliably (dirb's
positional/-H handling is inconsistent across builds, whatweb's
--custom-headers has had breaking syntax changes). They are LOGGED as
running unauthenticated rather than silently doing so — a fingerprint pass
that quietly ran as an anonymous user, in a scan the operator believes was
authenticated, produces findings that mean something different from what
they appear to mean. See note_unauthenticated_tools().
"""

import base64

from modules.utils.display import print_info, print_warning

try:
    from modules.utils.config import (
        AUTH_COOKIE, AUTH_HEADER, AUTH_BASIC_USER, AUTH_BASIC_PASS,
    )
except ImportError:
    # config.py is gitignored, so an older per-user copy predating the auth
    # keys is a real possibility. Absent config means "no auth", which is
    # exactly the safe default.
    AUTH_COOKIE = AUTH_HEADER = AUTH_BASIC_USER = AUTH_BASIC_PASS = None

# Tools that take part in a scan but cannot carry the credential. Named
# explicitly so the gap is stated in the run, not discovered later.
UNAUTHENTICATED_TOOLS = ("whatweb", "dirb")


class AuthConfig:
    """
    One resolved set of scan credentials, and the per-tool arguments it
    implies. Immutable in practice — built once per run and read from.

    Every *_args() method returns a list ready to '+' onto a command, and
    returns [] when auth is not configured, so a call site needs no
    conditional of its own.
    """

    def __init__(self, cookie=None, header=None, basic_user=None, basic_pass=None):
        self.cookie = (cookie or "").strip() or None
        self.header = (header or "").strip() or None
        self._basic_user = (basic_user or "").strip() or None
        self._basic_pass = basic_pass if basic_pass is not None else None

        # Half a pair is a misconfiguration. Flagged loudly, then dropped —
        # sending "user:None" as a credential would be worse than sending
        # nothing, because the scan would look authenticated and not be.
        if self._basic_user and self._basic_pass is None:
            print_warning(
                "[auth] AEGIS_AUTH_BASIC_USER is set but AEGIS_AUTH_BASIC_PASS "
                "is not — basic auth needs both. Ignoring the username and "
                "scanning unauthenticated."
            )
            self._basic_user = None
        elif self._basic_pass is not None and not self._basic_user:
            print_warning(
                "[auth] AEGIS_AUTH_BASIC_PASS is set but AEGIS_AUTH_BASIC_USER "
                "is not — basic auth needs both. Ignoring it and scanning "
                "unauthenticated."
            )
            self._basic_pass = None

    # --- state -----------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return bool(self.cookie or self.header or self._basic_user)

    @property
    def has_basic(self) -> bool:
        return bool(self._basic_user and self._basic_pass is not None)

    def describe(self) -> str:
        """
        A human-readable summary naming the auth METHODS in use and nothing
        else. This is the only representation of the credential that may be
        printed, logged or written to a report.

        Never includes the cookie value, the header value, the password, or
        the username — a username is half a credential and identifies an
        account, so it is withheld too.
        """
        if not self.enabled:
            return "not configured"
        kinds = []
        if self.cookie:
            kinds.append("session cookie")
        if self.header:
            kinds.append("custom header")
        if self.has_basic:
            kinds.append("basic auth")
        return " + ".join(kinds)

    def _header_name_value(self):
        """('Name', 'value') split of a "Name: value" header string."""
        if not self.header:
            return None, None
        name, _, value = self.header.partition(":")
        return name.strip(), value.strip()

    def _basic_header(self) -> str:
        """The 'Authorization: Basic <b64>' header for the basic-auth pair."""
        raw = f"{self._basic_user}:{self._basic_pass}".encode("utf-8")
        return "Authorization: Basic " + base64.b64encode(raw).decode("ascii")

    def headers(self) -> list:
        """
        Every credential expressed as a list of "Name: value" header
        strings — the common currency, since most tools take headers even
        when they also take a dedicated cookie flag.
        """
        out = []
        if self.cookie:
            out.append(f"Cookie: {self.cookie}")
        if self.header:
            out.append(self.header)
        if self.has_basic:
            out.append(self._basic_header())
        return out

    # --- per-tool arguments ----------------------------------------------
    # Each returns [] when auth is off, so callers stay unconditional.

    def nikto_args(self) -> list:
        """
        nikto: -id user:pass for basic auth.

        nikto's only first-class credential option is -id. It has no
        supported way to pass an arbitrary cookie or bearer header on the
        command line across the versions this project targets, so a
        cookie/header-only configuration cannot reach nikto — reported by
        unsupported_note() rather than silently ignored.
        """
        if self.has_basic:
            return ["-id", f"{self._basic_user}:{self._basic_pass}"]
        return []

    def gobuster_args(self) -> list:
        """gobuster: -c for the cookie, -H for every other header."""
        args = []
        if self.cookie:
            args += ["-c", self.cookie]
        if self.header:
            args += ["-H", self.header]
        if self.has_basic:
            # -U/-P exist, but routing basic auth through -H keeps one
            # code path for "a header this tool must send".
            args += ["-H", self._basic_header()]
        return args

    def nuclei_args(self) -> list:
        """nuclei: -H, repeatable, one per header."""
        args = []
        for header in self.headers():
            args += ["-H", header]
        return args

    def sqlmap_args(self) -> list:
        """sqlmap: --cookie for the cookie, --headers for the rest."""
        args = []
        if self.cookie:
            args.append(f"--cookie={self.cookie}")
        extra = [h for h in self.headers() if not h.startswith("Cookie: ")]
        if extra:
            # sqlmap takes multiple headers newline-separated in one flag.
            args.append("--headers=" + "\\n".join(extra))
        return args

    def unsupported_note(self):
        """
        A message naming any configured credential that a tool in this run
        genuinely cannot carry, or None when everything is deliverable.

        Returned rather than printed so the caller decides when to surface
        it; the point is that a partial-auth run says so out loud.
        """
        if not self.enabled:
            return None
        if (self.cookie or self.header) and not self.has_basic:
            return (
                "nikto supports only basic auth (-id) — this run's cookie/"
                "header credential cannot be passed to it, so nikto's "
                "findings reflect an UNAUTHENTICATED view of the target"
            )
        return None


def load_auth(cli_cookie=None, cli_header=None) -> AuthConfig:
    """
    Resolve the run's credentials: CLI flags first, then environment/.env.

    Always returns an AuthConfig — a disabled one when nothing is set — so
    callers never handle None.
    """
    return AuthConfig(
        cookie=cli_cookie or AUTH_COOKIE,
        header=cli_header or AUTH_HEADER,
        basic_user=AUTH_BASIC_USER,
        basic_pass=AUTH_BASIC_PASS,
    )


def announce(auth: AuthConfig, profile: str) -> None:
    """
    State once, at the top of a scan, whether it is authenticated and which
    tools are excluded from that. Prints methods only — never the value.
    """
    if not auth.enabled:
        return

    print_info(f"[{profile}] authenticated scan — using {auth.describe()}")
    note = auth.unsupported_note()
    if note:
        print_warning(f"[{profile}] {note}")
    note_unauthenticated_tools(profile)


def note_unauthenticated_tools(profile: str) -> None:
    """
    Say plainly which tools are running without the credential.

    The alternative — letting them run anonymously inside a scan labelled
    authenticated — makes their findings quietly mean something other than
    what the report implies. Explicit beats silent.
    """
    print_warning(
        f"[{profile}] {', '.join(UNAUTHENTICATED_TOOLS)} do not support custom "
        "auth cleanly and are running UNAUTHENTICATED — their findings "
        "describe the anonymous view of this target"
    )
