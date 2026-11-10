# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""A configuration command refused to the account is a collection error, never assessed: on the
AOS-CX 10.17 virtual platform the built-in "operators" group gets "% Command incomplete." for
"show running-config", and assessing that text gave false passes. Synthetic data."""

import pytest
from conftest import load_case

from lyss import collector


@pytest.mark.parametrize("output", [
    "",
    "\n  \n",
    "% Command incomplete.",
    "Cannot execute command. Command not allowed.",
    "Invalid input: running-config",
    "% Invalid input detected at '^' marker.",
    "error: permission denied",
    "% Authorization failed / not authorized",
])
def test_refused_or_empty_configuration_is_detected(output):
    assert collector.config_refusal(output)


@pytest.mark.parametrize("case", ["cx-hardened", "cx-weak", "ios-hardened", "mikrotik-hardened", "vrp-weak", "junos-weak"])
def test_real_configurations_are_accepted(case):
    assert collector.config_refusal(load_case(case)["config"]) is None


def test_banner_quoting_an_error_is_still_a_configuration():
    config = "banner motd !\nPermission denied to unauthorised users.\n!\nhostname x\nssh server vrf mgmt\nvlan 1\ninterface mgmt\n    ip dhcp\n"
    assert collector.config_refusal(config) is None


class FakeTransport:
    remote_version = "SSH-2.0-OpenSSH_10.0"
    remote_cipher = "aes128-ctr"
    remote_mac = "hmac-sha2-256"
    host_key_type = "ssh-ed25519"


class FakeSession:
    def __init__(self, config):
        self.config, self.transport, self.ran = config, FakeTransport(), []

    def run(self, command, timeout):
        self.ran.append(command)
        return self.config if command == "show running-config" else "ok"

    def close(self):
        pass


def test_collection_with_a_refused_configuration_stores_nothing(data_dir, monkeypatch):
    session = FakeSession("% Command incomplete.")
    monkeypatch.setattr(collector, "open_session", lambda d, j: session)
    device = {"id": "cx-ro", "host": "192.0.2.9", "port": 22, "vendor": "aruba_aoscx", "via_jump": False}
    with pytest.raises(ValueError, match="refused"):
        collector.collect_device(device, None)
    cfg_path, state_path = collector.config_paths(device)
    assert not cfg_path.exists() and not state_path.exists()
    assert session.ran == ["show running-config"]  # stops before the state commands


def test_collection_with_a_configuration_is_stored(data_dir, monkeypatch):
    monkeypatch.setattr(collector, "open_session", lambda d, j: FakeSession(load_case("cx-hardened")["config"]))
    device = {"id": "cx-ok", "host": "192.0.2.9", "port": 22, "vendor": "aruba_aoscx", "via_jump": False}
    collector.collect_device(device, None)
    assert collector.config_paths(device)[0].exists()
