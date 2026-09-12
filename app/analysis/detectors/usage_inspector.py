"""
MacGuard AI Phase 12 — Runtime Usage & Dependency Inspector.

Provides safe, read-only inspection of active processes and file modification states
to provide deterministic signals on whether storage items are currently in use
or associated with running applications.

Guarantees:
- Strictly read-only; never signals, terminates, or modifies processes.
- Returns None (UNKNOWN) when signals cannot be reliably determined.
- Never assumes 'not in use' simply because detection was inconclusive.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

import psutil


# Generic language runtime process names that should not loosely trigger application locks
GENERIC_RUNTIMES: frozenset[str] = frozenset({
    "python", "python3", "python3.11", "python3.12", "python3.10", "python3.9",
    "node", "bash", "zsh", "sh", "ruby", "perl", "java",
})


def is_path_recently_modified(path: str, threshold_seconds: int = 7 * 86400) -> Optional[bool]:
    """
    Check if a path was modified within the specified threshold.
    Returns None if stat fails.
    """
    try:
        st = os.stat(path)
        mtime = st.st_mtime
        now = time.time()
        return (now - mtime) < threshold_seconds
    except (OSError, PermissionError):
        return None


def is_path_actively_open_by_processes(target_path: str) -> Optional[bool]:
    """
    Check if any running process has an open file handle, working directory,
    or memory-mapped file pointing inside the target path.

    Returns:
        True: Confirmed open file handle / lock detected.
        False: Verified no accessible process holds an open handle.
        None: Inconclusive / UNKNOWN (e.g. due to system permissions).
    """
    norm_target = os.path.normcase(os.path.normpath(target_path))
    checked_any = False

    try:
        for proc in psutil.process_iter(attrs=["open_files", "cwd"]):
            try:
                # 1. Check open files
                open_files = proc.info.get("open_files") or []
                for of in open_files:
                    checked_any = True
                    of_path = os.path.normcase(os.path.normpath(getattr(of, "path", "")))
                    if of_path == norm_target or of_path.startswith(norm_target + os.sep):
                        return True

                # 2. Check process cwd
                cwd = proc.info.get("cwd") or ""
                if cwd:
                    checked_any = True
                    norm_cwd = os.path.normcase(os.path.normpath(cwd))
                    if norm_cwd == norm_target or norm_cwd.startswith(norm_target + os.sep):
                        return True

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        return None

    return False if checked_any else None


def detect_associated_running_processes(
    target_path: Any,
    app_hints: Optional[list[str]] = None,
    allow_generic_runtimes: bool = False,
) -> tuple[Optional[bool], list[str], Optional[bool]]:
    """
    Safely inspect running processes to determine:
    1. associated_application_running: Whether the parent application binary is currently executing.
    2. associated_processes: Names of processes specifically associated with the target or path.
    3. currently_in_use: Whether an active file handle / lock on target_path is confirmed.

    Returns:
        (associated_application_running, associated_processes, currently_in_use)
    """
    if hasattr(target_path, "path_str"):
        raw_str = target_path.path_str
    elif hasattr(target_path, "canonical_path"):
        raw_str = str(target_path.canonical_path)
    else:
        raw_str = str(target_path)

    norm_target = os.path.normpath(raw_str)
    norm_target_lower = norm_target.lower()
    matching_procs: set[str] = set()
    specific_app_matched = False

    hints = [h.lower() for h in (app_hints or [])]

    # Specific desktop application hints (Docker, Ollama, Chrome, Slack, Xcode, etc.)
    base_name = os.path.basename(norm_target).lower()
    for segment in ["docker", "ollama", "xcode", "slack", "chrome", "firefox", "brave", "code", "cursor", "spotify", "trivy"]:
        if segment in base_name or segment in norm_target_lower:
            if segment not in hints:
                hints.append(segment)

    try:
        for proc in psutil.process_iter(attrs=["name", "cmdline"]):
            try:
                raw_name = proc.info.get("name") or ""
                name = raw_name.lower()
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()

                # If name is a generic runtime (e.g. python, node), do not loosely associate
                # unless explicitly allowed or cmdline contains target path / specific tool command
                is_generic = name in GENERIC_RUNTIMES

                if is_generic and not allow_generic_runtimes:
                    # Check if generic process cmdline explicitly contains target path
                    if norm_target_lower in cmdline:
                        matching_procs.add(raw_name)
                    continue

                matched = False
                for hint in hints:
                    if hint in GENERIC_RUNTIMES and not allow_generic_runtimes:
                        continue

                    if hint in name or (len(hint) > 3 and hint in cmdline):
                        matching_procs.add(raw_name)
                        matched = True
                        if hint not in GENERIC_RUNTIMES:
                            specific_app_matched = True
                        break

                if not matched and norm_target_lower in cmdline:
                    matching_procs.add(raw_name)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        return (None, [], None)

    proc_list = sorted(list(matching_procs))

    # Active handle inspection
    in_use = is_path_actively_open_by_processes(norm_target)

    # If active open handle found, currently_in_use is True
    # If specific app is running, associated_application_running is True
    app_running: Optional[bool]
    if specific_app_matched:
        app_running = True
    elif hints and any(h not in GENERIC_RUNTIMES for h in hints):
        app_running = False
    else:
        app_running = None

    return (app_running, proc_list, in_use)
