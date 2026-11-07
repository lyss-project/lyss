# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Locks that also work between processes: the web interface and "lyss collect --scheduled" (cron,
Task Scheduler) can run at the same time and must not interleave read-modify-write sequences on
the same file (configuration archive index, known_hosts)."""

import contextlib
import os
import threading
import time
from pathlib import Path

_thread_locks: dict[str, threading.Lock] = {}
_guard = threading.Lock()


def _thread_lock(key: str) -> threading.Lock:
    with _guard:
        return _thread_locks.setdefault(key, threading.Lock())


@contextlib.contextmanager
def file_lock(path: Path, timeout: float = 60.0):
    """Exclusive lock on <path>.lock, held by one thread of one process at a time."""
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _thread_lock(str(lock_path)):
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"{lock_path.name} is locked by another LYSS process")
                    time.sleep(0.05)
            try:
                yield
            finally:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def replace(src: Path, dst: Path, attempts: int = 20) -> None:
    """os.replace, retried briefly on Windows when the target is open in another process."""
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05 * (attempt + 1))
