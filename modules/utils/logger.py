"""
modules/utils/logger.py
File-based logging (separate from Rich console output).
Every scan gets its own scan_errors.log under output/[target]/.
"""

import logging
import os
from datetime import datetime
from modules.utils.config import output_dir

_loggers = {}

def get_logger(target: str) -> logging.Logger:
    """
    Returns a logger scoped to a specific target's output directory.
    Reuses the same logger instance if called again for the same target
    within one run (avoids duplicate handlers).
    """
    if target in _loggers:
        return _loggers[target]

    log_path = os.path.join(output_dir(target), "scan_errors.log")

    logger = logging.getLogger(f"aegis.{target}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # don't also spam the root logger / console

    if not logger.handlers:
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    _loggers[target] = logger
    return logger


def log_tool_start(target: str, tool_name: str):
    get_logger(target).info(f"Starting tool: {tool_name}")


def log_tool_success(target: str, tool_name: str, duration: float = None):
    msg = f"Tool completed: {tool_name}"
    if duration is not None:
        msg += f" ({duration:.2f}s)"
    get_logger(target).info(msg)


def log_tool_failure(target: str, tool_name: str, error: str):
    get_logger(target).error(f"Tool failed: {tool_name} — {error}")


def log_tool_skip(target: str, tool_name: str):
    """
    Distinct from log_tool_failure: this tool did not fail or time out — the
    operator deliberately pressed the skip key while it was running. Kept as
    its own log line (rather than reusing "Tool failed") so a report or a
    post-run audit can tell a genuine failure apart from a user decision.
    """
    get_logger(target).warning(f"Tool skipped by user: {tool_name}")


def log_finding(target: str, finding: dict):
    get_logger(target).debug(f"Finding recorded: {finding}")


def log_scan_start(target: str, profile: str):
    get_logger(target).info(f"=== Scan started | target={target} | profile={profile} | {datetime.now().isoformat()} ===")


def log_scan_end(target: str, stats: dict):
    get_logger(target).info(f"=== Scan finished | stats={stats} ===")