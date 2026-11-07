# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Secret storage for switch, SMTP and API credentials.

Two backends, chosen automatically:
- Windows: DPAPI, bound to the current Windows user. Stored as plain hex, the format PowerShell's
  ConvertFrom-SecureString produces, so Export-Clixml credential files can be imported as-is
  without ever decrypting them.
- Other systems (Linux, Docker): AES-256-GCM, stored as "aesgcm:<base64>". The key comes from
  the LYSS_MASTER_KEY environment variable (base64, 32 bytes) or from <data dir>/master.key,
  created on first use with owner-only permissions. Back that key up: secrets cannot be
  recovered without it.
"""

import base64
import os
import re
import sys
from pathlib import Path

AESGCM_PREFIX = "aesgcm:"
CRYPTPROTECT_UI_FORBIDDEN = 0x1
_key_file: Path | None = None  # set by inventory.configure()


def backend() -> str:
    return "dpapi" if sys.platform == "win32" and not os.environ.get("LYSS_VAULT_AESGCM") else "aesgcm"


# ---------------- Windows DPAPI ----------------

def _dpapi(protect: bool, data: bytes, entropy: bytes = b"") -> bytes:
    """entropy: an extra secret bound into the blob. Secrets use none (PowerShell compatible);
    files use their own, so a credential blob can never be decrypted as a file and the reverse."""
    import ctypes
    import ctypes.wintypes as wt

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    func = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = Blob()
    extra = None
    if entropy:
        ebuf = ctypes.create_string_buffer(entropy, len(entropy))
        extra = ctypes.byref(Blob(len(entropy), ctypes.cast(ebuf, ctypes.POINTER(ctypes.c_char))))
    if not func(ctypes.byref(blob_in), None, extra, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


# ---------------- AES-256-GCM (portable) ----------------

def _master_key() -> bytes:
    env = os.environ.get("LYSS_MASTER_KEY")
    if env:
        key = base64.b64decode(env)
    else:
        key_file = _key_file
        if key_file is None and os.environ.get("LYSS_DATA_DIR"):
            key_file = Path(os.environ["LYSS_DATA_DIR"]) / "master.key"
        if key_file is None:
            raise RuntimeError("vault key file not configured (import lyss.inventory or set LYSS_DATA_DIR)")
        if not key_file.exists():
            if _encrypted_data_exists(key_file.parent):
                # a new key would make every stored secret and file unreadable, and anything
                # entered afterwards would use a key different from LYSS_MASTER_KEY
                raise RuntimeError("the master key is missing (LYSS_MASTER_KEY not set and no master.key) "
                                   "but data encrypted with a master key exists: restore the key")
            key_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(base64.b64encode(os.urandom(32)))
            except FileExistsError:
                pass   # created by another process at the same moment: use that one
        for _ in range(20):   # the other process may still be writing it
            raw = key_file.read_bytes().strip()
            if raw:
                break
            import time
            time.sleep(0.05)
        key = base64.b64decode(raw)
    if len(key) != 32:
        raise ValueError("vault master key must be 32 bytes (base64)")
    return key


def _encrypted_data_exists(data_dir: Path) -> bool:
    """Secrets ("aesgcm:") in the inventory or settings, or files sealed with the master key."""
    for name in ("devices.json", "settings.json"):
        p = data_dir / name
        if p.exists() and AESGCM_PREFIX in p.read_text(encoding="utf-8", errors="replace"):
            return True
    magic = b"LYSS-SEALED-1\nA"
    for p in list((data_dir / "results").glob("*.json"))[:50] + list(data_dir.glob("*/*.cfg"))[:50]:
        try:
            with p.open("rb") as f:
                if f.read(len(magic)) == magic:
                    return True
        except OSError:
            continue
    return False


def _aesgcm(protect: bool, data: bytes, aad: bytes = b"lyss-vault-v1") -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes = AESGCM(_master_key())
    if protect:
        nonce = os.urandom(12)
        return nonce + aes.encrypt(nonce, data, aad)
    return aes.decrypt(data[:12], data[12:], aad)


# ---------------- public API ----------------

def protect(secret: str) -> str:
    if backend() == "dpapi":
        return _dpapi(True, secret.encode("utf-16-le")).hex()
    return AESGCM_PREFIX + base64.b64encode(_aesgcm(True, secret.encode("utf-8"))).decode()


def unprotect(blob: str) -> str:
    if blob.startswith(AESGCM_PREFIX):
        return _aesgcm(False, base64.b64decode(blob[len(AESGCM_PREFIX):])).decode("utf-8")
    if sys.platform != "win32":
        raise RuntimeError("this secret was protected with Windows DPAPI: re-enter it on this system")
    return _dpapi(False, bytes.fromhex(blob)).decode("utf-16-le")


# Files (collected configurations, device state, results): same backends, a distinct label, so a
# protected file can never be taken for a protected secret and the other way round.
FILE_AAD = b"lyss-file-v1"


def protect_bytes(data: bytes) -> bytes:
    if backend() == "dpapi":
        return b"D" + _dpapi(True, data, FILE_AAD)
    return b"A" + _aesgcm(True, data, FILE_AAD)


def unprotect_bytes(blob: bytes) -> bytes:
    tag, body = blob[:1], blob[1:]
    if tag == b"A":
        return _aesgcm(False, body, FILE_AAD)
    if tag == b"D":
        if sys.platform != "win32":
            raise RuntimeError("this file was encrypted with Windows DPAPI: it can only be read on that Windows account")
        return _dpapi(False, body, FILE_AAD)
    raise ValueError("unknown encrypted file format")


def read_ps_credential(path: Path) -> tuple[str, str]:
    """(username, protected password) from a PowerShell Export-Clixml PSCredential file."""
    raw = path.read_bytes()
    # Windows PowerShell 5.1 writes Export-Clixml as UTF-16 LE with a BOM
    xml = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", errors="replace")
    user = re.search(r'<S N="UserName">([^<]*)</S>', xml)
    secret = re.search(r'<SS N="Password">([0-9a-fA-F]+)</SS>', xml)
    if not user or not secret:
        raise ValueError(f"{path.name}: not a PSCredential file")
    return user.group(1), secret.group(1).lower()
