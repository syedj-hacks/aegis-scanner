"""
modules/utils/error_handler.py
Wraps subprocess execution so a failing tool never crashes the framework.
Every tool wrapper (nikto_wrap.py, gobuster_wrap.py, etc.) should call
run_tool() instead of calling subprocess directly.

Interrupt handling
-------------------
A long-running tool (nikto's 600s timeout, a full-port nmap sweep, ...) used
to mean Ctrl+C had exactly one behaviour: unwind all the way out to
aegis.py's top-level handler and abort the *entire* scan, even if the
operator only wanted to move past one stuck tool. Both run_tool() (subprocess
tools) and safe_call() (direct socket/HTTP calls) now catch KeyboardInterrupt
themselves, kill/abandon whatever was running, and return a normal
"skipped" result so the calling profile orchestrator continues with the next
tool — exactly like a timeout or a missing binary. A second Ctrl+C within
_ABORT_WINDOW seconds is treated as the operator meaning it this time, and is
re-raised so it still propagates up to aegis.py and aborts the whole scan.

Skip-current-tool keybind
--------------------------
Ctrl+C's single-press skip is a blunt instrument — it is also the universal
"I might want to abort" reflex, so using it for routine "move past this one
slow tool" needs is confusing in practice. run_tool() also watches for a
single dedicated key (config.SKIP_KEY, default 's') on stdin while a
subprocess is running, via a background cbreak-mode listener
(_SkipKeyListener below). Pressing it terminates just the current tool
(SIGTERM, same as the timeout path) and lets the profile orchestrator
continue — without arming the Ctrl+C double-tap abort window at all.

The listener only activates when stdin is a real, interactive TTY
(`sys.stdin.isatty()`); a non-interactive run (piped input, cron, CI, this
project's own smoke-test harness) simply never sees the key and the feature
is inert — never a crash, never a hang. Some tools are load-bearing for
every downstream module (nmap's port list, DNS resolution) and cannot be
skipped: config.COMPULSORY_TOOLS names them and the reason; pressing skip on
one of those is acknowledged with a message and otherwise ignored.
"""

import select
import subprocess
import sys
import threading
import time

from modules.utils.logger import (
    log_tool_start, log_tool_success, log_tool_failure, log_tool_skip,
)
from modules.utils.config import get_timeout, COMPULSORY_TOOLS, SKIP_KEY
from modules.utils.display import print_warning

try:
    import termios
    import tty
    _TTY_MODULES_AVAILABLE = True
except ImportError:
    # termios/tty are POSIX-only; on a platform without them the skip
    # keybind is simply unavailable (Ctrl+C still works everywhere).
    _TTY_MODULES_AVAILABLE = False

# Set by the listener thread when the skip key is pressed; cleared by
# run_tool() as soon as it has acted on it (skipped, or refused because the
# tool is compulsory). Module-level and shared rather than per-call because
# only one tool is ever running at a time.
_skip_requested = threading.Event()

# How often (seconds) the listener polls stdin for a keypress, and how often
# run_tool()'s wait loop checks the timeout/skip state. Small enough that a
# keypress or an expired timeout is noticed almost immediately, large enough
# to not busy-loop.
_POLL_INTERVAL = 0.2


class _SkipKeyListener:
    """
    Puts stdin into cbreak mode (no line buffering, no echo, but signals
    like Ctrl+C's SIGINT still fire — cbreak leaves ISIG alone) and watches
    for config.SKIP_KEY in a daemon thread for the lifetime of one run_tool()
    call. No-ops entirely when stdin isn't an interactive TTY.
    """

    def __init__(self, key: str = SKIP_KEY):
        self._key = (key or "s").lower()[:1]
        self._stop = threading.Event()
        self._thread = None
        self._old_settings = None
        self._active = False

    def start(self):
        if not _TTY_MODULES_AVAILABLE:
            return
        try:
            if not sys.stdin.isatty():
                return
            self._old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        except (termios.error, ValueError, OSError, AttributeError):
            self._old_settings = None
            return

        self._active = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def _listen(self):
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([sys.stdin], [], [], _POLL_INTERVAL)
            except (OSError, ValueError):
                return
            if ready:
                try:
                    ch = sys.stdin.read(1)
                except OSError:
                    return
                if ch and ch.lower() == self._key:
                    _skip_requested.set()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        if self._active and self._old_settings is not None:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._old_settings)
            except (termios.error, OSError):
                pass

# Two Ctrl+C presses within this many seconds abort the whole scan instead
# of just skipping the tool currently running. Long enough that a single
# reflexive keypress never nukes the scan, short enough that a deliberate
# double-tap doesn't feel laggy.
_ABORT_WINDOW = 2.0

# Timestamp of the last KeyboardInterrupt seen by either run_tool() or
# safe_call(), shared across both so a Ctrl+C during a subprocess tool
# followed by one during, say, a CVE lookup still counts as a double-tap.
_last_interrupt = [0.0]

# The two reasons that mean "the user deliberately skipped this tool", as
# opposed to "this tool failed".
#
# These used to be bare string literals at their two use sites, which is
# how modules that replicate run_tool()'s contract by hand came to test for
# a skip by eye — or, more often, not at all. Every profile counts a tool
# as FAILED when it carries an error and is not marked skipped, so a
# wrapper that forgets the flag turns a deliberate Ctrl+C into a reported
# failure. That has now happened three times in this codebase
# (zap_wrap.py, header_check.py, banner.py), so the reasons are named
# constants and is_user_skip() is the single place that recognises them.
SKIP_REASON_INTERRUPT = "skipped by user (Ctrl+C)"
SKIP_REASON_SKIP_KEY = "skipped by user (skip key)"
_SKIP_REASONS = (SKIP_REASON_INTERRUPT, SKIP_REASON_SKIP_KEY)


def is_user_skip(error) -> bool:
    """
    True when an error string records a deliberate user skip.

    For modules that call safe_call() directly rather than run_tool():
    safe_call reports an interrupt the same way it reports a failure, as an
    error string, so the caller has to distinguish the two before setting
    result['skipped']. This is that test.
    """
    return str(error or "") in _SKIP_REASONS


def _handle_interrupt(target: str, label: str) -> str:
    """
    Record a KeyboardInterrupt and decide whether it should be swallowed
    (skip just this tool) or re-raised (abort the whole scan).

    Returns the human-readable reason to store in the result dict; raises
    the original KeyboardInterrupt itself when this is the second interrupt
    within _ABORT_WINDOW seconds.
    """
    now = time.time()
    since_last = now - _last_interrupt[0]
    _last_interrupt[0] = now

    if since_last < _ABORT_WINDOW:
        log_tool_failure(target, label, "aborted by user (double Ctrl+C)")
        raise KeyboardInterrupt("aborted by user (double Ctrl+C)")

    reason = SKIP_REASON_INTERRUPT
    log_tool_failure(target, label, reason)
    print_warning(
        f"[{label}] skipped — press Ctrl+C again within {_ABORT_WINDOW:.0f}s "
        "to abort the whole scan instead"
    )
    return reason


def _terminate_then_kill(proc, reader_thread, grace: float = 5.0):
    """
    SIGTERM first, SIGKILL only if the process ignores it.

    A hard proc.kill() (SIGKILL) gives a tool no chance to flush anything —
    nmap in particular treats SIGTERM/SIGINT as "wrap up now" and writes a
    valid, well-formed (if incomplete) -oX document when it gets one, so a
    timeout/skip on a long nmap sweep no longer has to mean losing every
    port found so far. Applied generically since a graceful shutdown chance
    never hurts any other tool either.
    """
    proc.terminate()
    reader_thread.join(timeout=grace)
    if reader_thread.is_alive():
        proc.kill()
        reader_thread.join(timeout=2.0)


def run_tool(target: str, tool_name: str, command: list, timeout: float = None) -> dict:
    """
    Runs a shell command safely.

    Parameters
    ----------
    timeout : float | None  overrides config.get_timeout(tool_name) when
                            given — used by port_scanner.py to scale nmap's
                            budget to how heavy its actual args are (a full
                            -p- sweep needs far longer than a top-100 -F).

    Returns a structured dict, always, regardless of outcome:
    {
        "tool": str,
        "success": bool,
        "skipped": bool,          # True only when the user pressed the
                                   # skip key on a skippable tool
        "returncode": int | None,
        "stdout": str,
        "stderr": str,
        "error": str | None,     # human-readable failure reason if success=False
        "duration": float
    }

    Never raises (except on a deliberate double Ctrl+C — see module
    docstring). A failing tool is logged and returned as a dict, execution
    of the rest of the framework continues normally.
    """
    log_tool_start(target, tool_name)
    start = time.time()
    if timeout is None:
        timeout = get_timeout(tool_name)
    is_compulsory = tool_name.lower() in COMPULSORY_TOOLS

    result = {
        "tool": tool_name,
        "success": False,
        "skipped": False,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "error": None,
        "duration": 0.0,
    }

    proc = None
    listener = _SkipKeyListener()
    try:
        # Popen (rather than subprocess.run) so a Ctrl+C mid-scan, a timeout,
        # or a skip keypress can all kill the child process before this
        # function returns instead of leaving it running in the background.
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # communicate() runs on its own thread so the loop below can poll
        # elapsed time and the skip keybind at the same time — a plain
        # communicate(timeout=...) blocks this thread entirely and can't
        # notice a keypress while it waits.
        captured = {}

        def _drain():
            try:
                captured["stdout"], captured["stderr"] = proc.communicate()
            except Exception:
                captured["stdout"] = captured.get("stdout", "")
                captured["stderr"] = captured.get("stderr", "")

        reader_thread = threading.Thread(target=_drain, daemon=True)
        reader_thread.start()
        listener.start()

        outcome = None  # None (clean exit) | "timeout" | "skipped"
        while True:
            reader_thread.join(timeout=_POLL_INTERVAL)
            if not reader_thread.is_alive():
                break

            if time.time() - start > timeout:
                outcome = "timeout"
                break

            if _skip_requested.is_set():
                _skip_requested.clear()
                if is_compulsory:
                    reason = COMPULSORY_TOOLS.get(tool_name.lower(), "required by downstream modules")
                    print_warning(
                        f"[{tool_name}] cannot be skipped — {reason}. Ignoring skip request."
                    )
                    # Not broken out of the loop — the tool keeps running.
                else:
                    outcome = "skipped"
                    break

        if outcome in ("timeout", "skipped"):
            _terminate_then_kill(proc, reader_thread)

        result["returncode"] = proc.returncode
        result["stdout"] = captured.get("stdout", "") or ""
        result["stderr"] = captured.get("stderr", "") or ""
        result["duration"] = time.time() - start

        if outcome == "skipped":
            result["error"] = SKIP_REASON_SKIP_KEY
            result["skipped"] = True
            log_tool_skip(target, tool_name)
            print_warning(f"[{tool_name}] skipped by user — moving to the next tool")
        elif outcome == "timeout":
            result["error"] = f"timed out after {timeout:.0f}s"
            log_tool_failure(target, tool_name, result["error"])
        elif proc.returncode == 0:
            result["success"] = True
            log_tool_success(target, tool_name, result["duration"])
        else:
            result["error"] = f"non-zero exit code ({proc.returncode})"
            log_tool_failure(target, tool_name, f"{result['error']} | stderr: {result['stderr'][:300]}")

    except FileNotFoundError:
        result["error"] = f"binary not found on PATH: {command[0]}"
        result["duration"] = time.time() - start
        log_tool_failure(target, tool_name, result["error"])

    except KeyboardInterrupt:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                proc.communicate()
            except Exception:
                pass
        result["duration"] = time.time() - start
        result["error"] = _handle_interrupt(target, tool_name)

    except Exception as e:
        # Catch-all — guarantees the framework NEVER crashes because
        # of an unexpected exception inside a tool wrapper.
        result["error"] = f"unexpected error: {str(e)}"
        result["duration"] = time.time() - start
        log_tool_failure(target, tool_name, result["error"])

    finally:
        listener.stop()

    return result


def safe_call(func, *args, target: str = "unknown", label: str = "operation", **kwargs):
    """
    Generic guard for non-subprocess code (e.g. CVE lookups, parsing).
    Wraps any function call so an exception becomes a structured dict
    instead of crashing the calling module. A KeyboardInterrupt is handled
    the same way run_tool() handles it — see module docstring.
    """
    try:
        data = func(*args, **kwargs)
        return {"success": True, "data": data, "error": None}
    except KeyboardInterrupt:
        reason = _handle_interrupt(target, label)
        return {"success": False, "data": None, "error": reason}
    except Exception as e:
        log_tool_failure(target, label, str(e))
        return {"success": False, "data": None, "error": str(e)}