"""
modules/utils/error_handler.py
Wraps subprocess execution so a failing tool never crashes the framework.
Every tool wrapper (nikto_wrap.py, gobuster_wrap.py, etc.) should call
run_tool() instead of calling subprocess directly.
"""

import subprocess
from modules.utils.logger import log_tool_start, log_tool_success, log_tool_failure
from modules.utils.config import get_timeout
import time


def run_tool(target: str, tool_name: str, command: list) -> dict:
    """
    Runs a shell command safely.

    Returns a structured dict, always, regardless of outcome:
    {
        "tool": str,
        "success": bool,
        "returncode": int | None,
        "stdout": str,
        "stderr": str,
        "error": str | None,     # human-readable failure reason if success=False
        "duration": float
    }

    Never raises. A failing tool is logged and returned as a dict,
    execution of the rest of the framework continues normally.
    """
    log_tool_start(target, tool_name)
    start = time.time()
    timeout = get_timeout(tool_name)

    result = {
        "tool": tool_name,
        "success": False,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "error": None,
        "duration": 0.0,
    }

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result["returncode"] = proc.returncode
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
        result["duration"] = time.time() - start

        if proc.returncode == 0:
            result["success"] = True
            log_tool_success(target, tool_name, result["duration"])
        else:
            result["error"] = f"non-zero exit code ({proc.returncode})"
            log_tool_failure(target, tool_name, f"{result['error']} | stderr: {proc.stderr[:300]}")

    except FileNotFoundError:
        result["error"] = f"binary not found on PATH: {command[0]}"
        result["duration"] = time.time() - start
        log_tool_failure(target, tool_name, result["error"])

    except subprocess.TimeoutExpired:
        result["error"] = f"timed out after {timeout}s"
        result["duration"] = time.time() - start
        log_tool_failure(target, tool_name, result["error"])

    except Exception as e:
        # Catch-all — guarantees the framework NEVER crashes because
        # of an unexpected exception inside a tool wrapper.
        result["error"] = f"unexpected error: {str(e)}"
        result["duration"] = time.time() - start
        log_tool_failure(target, tool_name, result["error"])

    return result


def safe_call(func, *args, target: str = "unknown", label: str = "operation", **kwargs):
    """
    Generic guard for non-subprocess code (e.g. CVE lookups, parsing).
    Wraps any function call so an exception becomes a structured dict
    instead of crashing the calling module.
    """
    try:
        data = func(*args, **kwargs)
        return {"success": True, "data": data, "error": None}
    except Exception as e:
        log_tool_failure(target, label, str(e))
        return {"success": False, "data": None, "error": str(e)}