# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Encryption at rest of the sensitive data files: collected configurations and device state,
archived configuration versions, and assessment results.

A sealed file starts with MAGIC, followed by the vault's file encryption: Windows DPAPI (current
Windows user) or AES-256-GCM with the master key (see vault.py). Reading is transparent: plain
files written by older versions stay readable and are sealed by seal_existing(), which every scan
runs. Encryption is on by default; Settings > Data protection can turn it off for new files.
"""

import os
import tempfile
from pathlib import Path

from . import locks, vault

MAGIC = b"LYSS-SEALED-1\n"


def enabled() -> bool:
    from . import inventory   # late import: inventory uses this module
    return inventory.load_settings().get("encrypt_data", True) is not False


def is_sealed(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(len(MAGIC)) == MAGIC


def _store(path: Path, data: bytes) -> None:
    """Atomic write through a temporary file of its own (two writers never share one), owner-only
    permissions where the OS supports them."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")   # mode 0600
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        locks.replace(Path(tmp), path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_bytes(path: Path, data: bytes, seal: bool | None = None) -> None:
    if enabled() if seal is None else seal:
        data = MAGIC + vault.protect_bytes(data)
    _store(path, data)


def write_text(path: Path, text: str, seal: bool | None = None) -> None:
    write_bytes(path, text.encode("utf-8"), seal)


def read_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    return vault.unprotect_bytes(raw[len(MAGIC):]) if raw.startswith(MAGIC) else raw


def read_text(path: Path, errors: str = "strict") -> str:
    """Like Path.read_text: universal newlines, so plain files written by older versions on
    Windows (CRLF) read exactly as before and their content hash does not change."""
    text = read_bytes(path).decode("utf-8", errors=errors)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def data_files(data_dir: Path | None = None) -> list[Path]:
    """Every file this module protects, in the data directory."""
    from . import inventory
    from .engine import ADAPTER_DIR
    root = Path(data_dir or inventory.PRIVATE)
    files: list[Path] = []
    for vendor in sorted(p.stem for p in ADAPTER_DIR.glob("*.yaml")):
        files += sorted((root / vendor).glob("*.cfg")) + sorted((root / vendor).glob("*.state.txt"))
    files += sorted((root / "history").glob("*/configs/*.cfg"))
    files += sorted((root / "results").glob("*.json"))
    return [f for f in files if f.is_file()]


def status(data_dir: Path | None = None) -> dict:
    files = data_files(data_dir)
    sealed = sum(1 for f in files if is_sealed(f))
    return {"enabled": enabled(), "backend": vault.backend(), "sealed": sealed, "plain": len(files) - sealed}


def seal_existing(data_dir: Path | None = None) -> int:
    """Encrypt the plain data files (written before encryption, or while it was off). Returns the count."""
    done = 0
    for path in data_files(data_dir):
        with locks.file_lock(path):
            if is_sealed(path):
                continue
            before = path.stat()
            data = MAGIC + vault.protect_bytes(path.read_bytes())
            after = path.stat()
            if (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
                continue   # rewritten meanwhile (a scan): never put the older content back
            _store(path, data)
            done += 1
    return done


def unseal_all(data_dir: Path | None = None) -> int:
    """Decrypt every sealed data file back to plain text (explicit administrator action only)."""
    done = 0
    for path in data_files(data_dir):
        if is_sealed(path):
            write_bytes(path, read_bytes(path), seal=False)
            done += 1
    return done
