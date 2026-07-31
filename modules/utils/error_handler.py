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

# When the skip key was last pressed (time.time(), 0.0 = never).
#
# This used to be a threading.Event, on the stated assumption that "only one
# tool is ever running at a time". That assumption no longer holds:
# webaudit/deepscan now run their independent per-port web tools through a
# thread pool (config.PARALLEL_WEB_TOOLS), so several run_tool() calls are
# genuinely in flight at once. An Event cleared by whichever call noticed it
# first would have made a keypress skip one arbitrary, unpredictable member
# of the batch.
#
# A timestamp gives a rule that is well-defined no matter how many tools are
# running: a press skips every tool that was ALREADY RUNNING when the key
# went down, and no tool started afterwards. With one tool running that is
# identical to the old behaviour; with a batch it means "skip the group of
# tools running right now", which is the only reading a user watching a
# progress bar could act on deliberately.
#
# Each run_tool() call tracks which press it has already acted on in a local
# variable, so a compulsory tool that refuses a press does not consume it on
# behalf of the skippable tools running alongside it, and does not re-print
# its refusal on every poll.
_skip_press_time = [0.0]

# Whether the skip key is active at all this run.
#
# Switched off for multi-target runs (--targets). "Skip the tool running
# right now" has no single referent when six tools across three targets are
# in flight — a keypress would skip whichever set happened to be running,
# which is not a control anyone can use deliberately. It is disabled and
# said so, rather than left on and unpredictable. Ctrl+C still works.
_skip_listener_enabled = [True]


def set_skip_listener_enabled(enabled: bool) -> None:
    """Enable/disable the skip-key listener process-wide."""
    _skip_listener_enabled[0] = bool(enabled)

# How often (seconds) the listener polls stdin for a keypress, and how often
# run_tool()'s wait loop checks the timeout/skip state. Small enough that a
# keypress or an expired timeout is noticed almost immediately, large enough
# to not busy-loop.
_POLL_INTERVAL = 0.2


class _SkipKeyListener:
    """
    Puts stdin into cbreak mode (no line buffering, no echo, but signals
    like Ctrl+C's SIGINT still fire — cbreak leaves ISIG alone) and watches
    for config.SKIP_KEY in a daemon thread. No-ops entirely when stdin isn't
    an interactive TTY.

    Process-wide and reference-counted, NOT one instance per run_tool() call.
    There is only one stdin and only one terminal mode, so concurrent tools
    must not each save-and-restore it: with a thread pool running five web
    tools per port, five listeners would each call tcgetattr/tcsetattr on the
    same fd, and the first one to finish would restore "the old settings" —
    which, having been captured after an earlier listener already switched to
    cbreak, ARE cbreak. The terminal is then left with echo off after the
    scan ends, which reads to the user as a hung shell.

    So: the first acquire() captures the real pre-scan settings and starts
    one reader thread; later acquires only bump the count; the last release()
    restores. Guarded by a lock because acquire/release are now called from
    several worker threads at once.
    """

    _lock = threading.Lock()
    _refcount = 0
    _thread = None
    _stop = threading.Event()
    _old_settings = None
    _key = (SKIP_KEY or "s").lower()[:1]

    @classmethod
    def acquire(cls):
        if not _TTY_MODULES_AVAILABLE or not _skip_listener_enabled[0]:
            return
        with cls._lock:
            if cls._refcount == 0:
                try:
                    if not sys.stdin.isatty():
                        return
                    cls._old_settings = termios.tcgetattr(sys.stdin)
                    tty.setcbreak(sys.stdin.fileno())
                except (termios.error, ValueError, OSError, AttributeError):
                    cls._old_settings = None
                    return
                cls._stop.clear()
                cls._thread = threading.Thread(target=cls._listen, daemon=True)
                cls._thread.start()
            # Only counted once the terminal is genuinely ours, so a
            # non-TTY run never has a release() to unbalance.
            if cls._old_settings is not None:
                cls._refcount += 1

    @classmethod
    def _listen(cls):
        while not cls._stop.is_set():
            try:
                ready, _, _ = select.select([sys.stdin], [], [], _POLL_INTERVAL)
            except (OSError, ValueError):
                return
            if ready:
                try:
                    ch = sys.stdin.read(1)
                except OSError:
                    return
                if ch and ch.lower() == cls._key:
                    _skip_press_time[0] = time.time()

    @classmethod
    def release(cls):
        if not _TTY_MODULES_AVAILABLE:
            return
        with cls._lock:
            if cls._refcount == 0:
                return
            cls._refcount -= 1
            if cls._refcount > 0:
                return

            cls._stop.set()
            thread, cls._thread = cls._thread, None
            old, cls._old_settings = cls._old_settings, None

        # Joining outside the lock: the reader thread can be up to one
        # _POLL_INTERVAL from noticing the stop flag, and holding the lock
        # for that long would stall every other tool's acquire/release.
        if thread is not None:
            thread.join(timeout=1.0)
        if old is not None:
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
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
        _SkipKeyListener.acquire()

        # The most recent skip press this call has already acted on. Local,
        # not shared: with several tools running concurrently, one tool
        # consuming a press must not hide it from the others, and a
        # compulsory tool refusing one must not re-print that refusal on
        # every 0.2s poll for the rest of its run.
        handled_press = _skip_press_time[0]

        outcome = None  # None (clean exit) | "timeout" | "skipped"
        while True:
            reader_thread.join(timeout=_POLL_INTERVAL)
            if not reader_thread.is_alive():
                break

            if time.time() - start > timeout:
                outcome = "timeout"
                break

            # A press counts for this tool only if it happened after this
            # tool started — that is what scopes a skip to the tools running
            # at the moment the key went down, and stops a stale press from
            # instantly killing the next tool to start.
            press = _skip_press_time[0]
            if press > handled_press and press > start:
                handled_press = press
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
        # A single Ctrl+C is a deliberate user skip, and has to be recorded
        # as one. Without this flag classify_tool_outcome() sees an error
        # string with skipped=False and classifies it "failed", so the scan
        # that the user politely stepped past one tool in reports a TOOL
        # FAILURE — printed as "[Failed] nikto: skipped by user (Ctrl+C)",
        # counted in the summary panel, and persisted to scan_tools_run.
        #
        # This is the same skip-flag bug already fixed three times in this
        # codebase's wrappers (zap_wrap.py, header_check.py, banner.py) —
        # is_user_skip() and the SKIP_REASON_* constants exist precisely to
        # stop it recurring, and run_tool(), the function they were written
        # for, was itself still missing it. The skip-key path above sets the
        # flag; the Ctrl+C path did not, so two spellings of "the user
        # skipped this" were classified two different ways.
        result["skipped"] = is_user_skip(result["error"])
        if result["skipped"]:
            log_tool_skip(target, tool_name)

    except Exception as e:
        # Catch-all — guarantees the framework NEVER crashes because
        # of an unexpected exception inside a tool wrapper.
        result["error"] = f"unexpected error: {str(e)}"
        result["duration"] = time.time() - start
        log_tool_failure(target, tool_name, result["error"])

    finally:
        _SkipKeyListener.release()

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