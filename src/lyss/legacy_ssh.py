# SPDX-License-Identifier: AGPL-3.0-only OR MIT
# Copyright 2026 Mouad Lyaazale
#
# This file only is dual-licensed: use it under the GNU Affero General Public License v3 (as part
# of LYSS, see LICENSE and NOTICE) OR under the MIT licence below, at your choice.
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software
# and associated documentation files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
# BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# paramiko (LGPL-2.1) is used as a library: the SHA-1 key exchanges below extend paramiko 5's
# SHA-256 key exchange classes (only the name and hash differ); no paramiko code is copied.
"""Legacy SSH algorithms for old switches, on top of a current paramiko.

paramiko 5 removed what many switches still in service can only speak (Cisco Small Business
SG300, older Catalyst images): the SHA-1 key exchanges (diffie-hellman-group14-sha1,
diffie-hellman-group-exchange-sha1) and SHA-1 RSA host-key signatures ("ssh-rsa"). LYSS has to
audit those switches, so this module adds back exactly these three algorithms, and nothing else:

- they are registered last in paramiko's preference lists;
- every LYSS connection first runs with them DISABLED (MODERN_ONLY); only when a switch answers
  that it has no algorithm in common does LYSS reconnect to that switch with them allowed
  (connect_options), and the scan records it ("legacy: required" in the negotiated algorithms,
  reported by LYSS-MGMT-013);
- SHA-1 RSA signatures are accepted only when "ssh-rsa" itself was negotiated (LegacyRSAKey):
  the shared RSA key class of paramiko is not modified, so a connection that negotiated
  rsa-sha2-256/512 can never be answered with a SHA-1 signature;
- LYSS only verifies the switch's signature; it never signs with SHA-1 (it logs in with a password).
Host keys stay pinned (collector.verify_host_key), whatever the algorithms.
"""

from hashlib import sha1

import paramiko
from cryptography.hazmat.primitives import hashes
from paramiko.kex_gex import KexGexSHA256
from paramiko.kex_group14 import KexGroup14SHA256

# same order as paramiko 3.5: group exchange first (the switch may pick a group larger than 2048 bits)
LEGACY_KEX = ("diffie-hellman-group-exchange-sha1", "diffie-hellman-group14-sha1")
LEGACY_HOST_KEYS = ("ssh-rsa",)
# paramiko "disabled_algorithms" for a modern-only connection (the default for every switch)
MODERN_ONLY = {"kex": list(LEGACY_KEX), "keys": list(LEGACY_HOST_KEYS)}


class KexGroup14SHA1(KexGroup14SHA256):
    name = "diffie-hellman-group14-sha1"
    hash_algo = sha1


class KexGexSHA1(KexGexSHA256):
    name = "diffie-hellman-group-exchange-sha1"
    hash_algo = sha1


class LegacyRSAKey(paramiko.RSAKey):
    """RSA key that also verifies (and, for the simulator, signs) "ssh-rsa" SHA-1 signatures.
    Used only for connections that negotiated the "ssh-rsa" host key algorithm."""

    HASHES = {**paramiko.RSAKey.HASHES, "ssh-rsa": hashes.SHA1}

    @classmethod
    def from_rsa_key(cls, key: paramiko.RSAKey) -> "LegacyRSAKey":
        return cls(key=key.key)


def install() -> None:
    """Register the legacy algorithms with paramiko, last in preference (idempotent)."""
    t = paramiko.Transport
    if t._kex_info.get(KexGroup14SHA1.name) is KexGroup14SHA1 and t._key_info.get("ssh-rsa") is LegacyRSAKey:
        return
    t._kex_info = {**t._kex_info, KexGroup14SHA1.name: KexGroup14SHA1, KexGexSHA1.name: KexGexSHA1}
    t._key_info = {**t._key_info, "ssh-rsa": LegacyRSAKey}
    t._preferred_kex = tuple(k for k in t._preferred_kex if k not in LEGACY_KEX) + LEGACY_KEX
    t._preferred_keys = tuple(k for k in t._preferred_keys if k not in LEGACY_HOST_KEYS) + LEGACY_HOST_KEYS


def connect_options(legacy: bool) -> dict:
    """paramiko / netmiko "disabled_algorithms" for a connection: modern only unless the switch
    proved it needs the legacy algorithms."""
    return {} if legacy else {k: list(v) for k, v in MODERN_ONLY.items()}


def is_incompatible(exc: BaseException) -> bool:
    """The switch has no key exchange or host key algorithm in common with a modern-only client."""
    return isinstance(exc, paramiko.ssh_exception.IncompatiblePeer) or "Incompatible ssh peer" in str(exc)


install()
