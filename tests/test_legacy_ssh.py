# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Legacy SSH (lyss.legacy_ssh) on a current paramiko: SHA-1 key exchange and "ssh-rsa" host keys
only for switches that offer nothing better, never by default. Simulated switches on 127.0.0.1."""

import socket

import paramiko
import pytest

from lyss import collector, inventory, legacy_ssh
from lyss.sim import Simulator, load_lab


@pytest.fixture
def sim():
    simulator = Simulator(load_lab("demo"), base_port=0).start()
    yield simulator
    simulator.stop()


def _handshake(port: int, disabled: dict) -> paramiko.Transport:
    t = paramiko.Transport(socket.create_connection(("127.0.0.1", port), timeout=10), disabled_algorithms=disabled)
    t.start_client(timeout=10)
    return t


def test_paramiko_major_version_is_the_one_the_shim_targets():
    assert paramiko.__version__.split(".")[0] == "5"


def test_shared_rsa_class_never_accepts_sha1():
    # SHA-1 RSA signatures only through LegacyRSAKey, used only when "ssh-rsa" was negotiated
    assert "ssh-rsa" not in paramiko.RSAKey.HASHES
    assert legacy_ssh.LegacyRSAKey.HASHES["ssh-rsa"].name == "sha1"
    key_info = paramiko.Transport._key_info
    assert key_info["ssh-rsa"] is legacy_ssh.LegacyRSAKey
    assert key_info["rsa-sha2-256"] is paramiko.RSAKey and key_info["rsa-sha2-512"] is paramiko.RSAKey


def test_legacy_algorithms_come_last_and_are_disabled_by_default():
    t = paramiko.Transport
    assert t._preferred_kex[-len(legacy_ssh.LEGACY_KEX):] == legacy_ssh.LEGACY_KEX
    assert t._preferred_keys[-1] == "ssh-rsa"
    modern = legacy_ssh.connect_options(False)
    assert set(modern["kex"]) == set(legacy_ssh.LEGACY_KEX) and modern["keys"] == ["ssh-rsa"]
    assert legacy_ssh.connect_options(True) == {}


def test_modern_only_client_cannot_talk_to_a_legacy_switch(sim):
    legacy = sim.lab.switches["demo-sb-02"]          # SG300: SHA-1 key exchange and ssh-rsa only
    with pytest.raises(paramiko.SSHException) as exc:
        _handshake(legacy.port, legacy_ssh.connect_options(False))
    assert legacy_ssh.is_incompatible(exc.value)


def test_modern_switch_refuses_the_legacy_algorithms(sim):
    modern = sim.lab.switches["demo-core"]
    only_legacy = {"kex": [k for k in paramiko.Transport._preferred_kex if k not in legacy_ssh.LEGACY_KEX],
                   "keys": [k for k in paramiko.Transport._preferred_keys if k != "ssh-rsa"]}
    with pytest.raises(paramiko.SSHException):
        _handshake(modern.port, only_legacy)


def test_fallback_is_per_switch_and_recorded(data_dir, sim):
    creds = sim.lab.credentials
    sim.pin_host_keys()
    results = {}
    for switch_id in ("demo-core", "demo-sb-02", "demo-acc-02"):
        sw = sim.lab.switches[switch_id]
        device = {"id": sw.id, "host": "127.0.0.1", "port": sw.port, "vendor": sw.platform,
                  "username": creds["username"], "via_jump": False}
        inventory.save_device(device, creds["password"])
        collector.collect_device(inventory.get_device(sw.id), None)
        state = collector.config_paths(inventory.get_device(sw.id))[1].read_text(encoding="utf-8")
        results[switch_id] = state.split("===== ssh negotiated =====", 1)[1].split("=====", 1)[0]
    assert "legacy: required" not in results["demo-core"]
    assert "sha1" not in results["demo-core"] and "hostkey: ssh-rsa" not in results["demo-core"]
    for legacy in ("demo-sb-02", "demo-acc-02"):
        assert "legacy: required" in results[legacy], legacy
        assert "kex: diffie-hellman-group14-sha1" in results[legacy] and "hostkey: ssh-rsa" in results[legacy]


def test_jump_host_is_always_modern_only(monkeypatch):
    seen = {}

    class FakeClient:
        def load_host_keys(self, *_):
            pass

        def set_missing_host_key_policy(self, *_):
            pass

        def connect(self, *args, **kwargs):
            seen.update(kwargs)
            raise ConnectionRefusedError("stop here")

    monkeypatch.setattr(collector.paramiko, "SSHClient", FakeClient)
    jump = collector.JumpHost({"host": "192.0.2.1", "user": "lyss", "key_file": "none"})
    with pytest.raises(ConnectionRefusedError):
        jump.channel("192.0.2.10", 22)
    assert seen["disabled_algorithms"] == legacy_ssh.connect_options(False)
