# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Read-only, parallel device collection over SSH (optionally through one jump host).

For each device, writes private/<vendor>/<id>.cfg (running-config) and <id>.state.txt
(collected device state, "===== command =====" sections). Only "show" commands are sent.
"""

import base64
import hashlib
import os
import re
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import paramiko

from . import inventory

# Read-only commands per adapter. Nothing here may change configuration.
COMMANDS = {
    "cisco_sb": {
        "netmiko": "cisco_s300",
        "config": "show running-config",
        "state": ["show version", "show inventory", "show system", "show ip ssh",
                  "show services tcp-udp", "show interfaces status", "show interfaces configuration",
                  "show lldp neighbors", "show cdp neighbors", "show cdp neighbors detail",
                  "show sntp status"],
    },
    "cisco_ios": {
        "netmiko": "cisco_ios",
        "config": "show running-config",
        "state": ["show version", "show inventory", "show ip ssh",
                  "show control-plane host open-ports", "show interfaces status",
                  "show lldp neighbors", "show cdp neighbors",
                  "show lldp neighbors detail", "show cdp neighbors detail", "show ntp status"],
    },
    "sonic": {
        # community SONiC: a Debian shell with "show" commands; "ss -tlnH" lists listening TCP
        # ports (read-only, no sudo). The configuration is config_db JSON.
        "netmiko": "linux",
        "config": "show runningconfiguration all",
        "state": ["show version", "show interfaces status", "show ntp", "show ssh", "show feature status",
                  "show lldp table", "ss -tlnH"],
    },
    "mikrotik": {
        # RouterOS: "/export terse" never includes secrets without "show-sensitive" (not used);
        # "print terse" = one item per line. All read-only.
        "netmiko": "mikrotik_routeros",
        "config": "/export terse",
        "state": ["/system resource print", "/ip service print terse", "/ip ssh print", "/snmp print",
                  "/snmp community print terse", "/system ntp client print",
                  "/system logging action print terse", "/system logging print terse",
                  "/user print terse", "/user aaa print", "/radius print terse", "/system note print",
                  "/interface ethernet print terse", "/interface bridge port print terse",
                  "/tool mac-server mac-winbox print", "/ip neighbor print detail"],
    },
    "hp_procurve": {
        # netmiko answers "Press any key to continue" and disables paging ("no page")
        "netmiko": "hp_procurve",
        "config": "show running-config",
        "state": ["show version", "show system", "show modules", "show ip ssh",
                  "show interfaces brief", "show lldp info remote-device", "show cdp neighbors"],
    },
}


# a configuration command was rejected (Cisco IOS "% Invalid input", Cisco SB "% Unrecognized command")
CLI_ERROR = re.compile(r"(?m)^\s*%|Invalid input|Unrecognized command|Incomplete command|Wrong number of parameters|bad parameter")

# paramiko forgets the negotiated key exchange once the handshake is done; keep its name on the
# transport so it can be reported as evidence (the switch's strongest supported algorithm).
_parse_kex_init = paramiko.Transport._parse_kex_init


def _parse_kex_init_and_record(self, m):
    _parse_kex_init(self, m)
    self.lyss_kex = getattr(self.kex_engine, "name", type(self.kex_engine).__name__)


paramiko.Transport._parse_kex_init = _parse_kex_init_and_record


# ---------------- SSH host keys: trust on first use, then pinned ----------------

class HostKeyMismatch(Exception):
    pass


_keys_lock = threading.Lock()


def known_hosts_file():
    return inventory.PRIVATE / "known_hosts"  # OpenSSH format (also read by netmiko)


def _key_name(host: str, port: int) -> str:
    return host if int(port) == 22 else f"[{host}]:{port}"


def fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def verify_host_key(host: str, port: int, key) -> str:
    """Record the key on first contact; refuse a different key afterwards (before any password
    is sent). Returns the fingerprint."""
    name = _key_name(host, port)
    with _keys_lock:
        keys = paramiko.HostKeys()
        path = known_hosts_file()
        if path.exists():
            keys.load(str(path))
        known = keys.lookup(name)
        if known:
            stored = next(iter(known.values()))
            if key.get_name() not in known or known[key.get_name()].asbytes() != key.asbytes():
                raise HostKeyMismatch(
                    f"{name}: SSH host key changed (known {fingerprint(stored)}, now {fingerprint(key)}). "
                    "Possible interception: nothing was sent. If the device was replaced or re-keyed, "
                    "forget the old key on its page in LYSS.")
        else:
            keys.add(name, key.get_name(), key)
            path.parent.mkdir(parents=True, exist_ok=True)
            keys.save(str(path))
    return fingerprint(key)


def known_fingerprint(host: str, port: int) -> str | None:
    path = known_hosts_file()
    if not path.exists():
        return None
    keys = paramiko.HostKeys(str(path))
    found = keys.lookup(_key_name(host, port))
    return fingerprint(next(iter(found.values()))) if found else None


def forget_host_key(host: str, port: int) -> None:
    with _keys_lock:
        path = known_hosts_file()
        if not path.exists():
            return
        keys = paramiko.HostKeys(str(path))
        name = _key_name(host, port)
        if name in keys:
            del keys[name]
            keys.save(str(path))


class _PinningPolicy(paramiko.MissingHostKeyPolicy):
    """For SSHClient connections (jump host): first contact records the key in LYSS's store."""

    def missing_host_key(self, client, hostname, key):
        verify_host_key(hostname, 22, key)


class JumpHost:
    """One SSH connection to the jump host, shared by all workers (one channel per device).

    With settings["source"] set, each connection is opened by "nc -s <source> <host> <port>" on the
    jump host instead of SSH port forwarding: the jump host then connects FROM that address. This is
    needed when the switches sit behind policy-based IPsec tunnels that only carry some local
    networks (e.g. a firewall whose LAN address is in the tunnel's selectors but whose default
    source is its WAN address). The jump host must provide a BSD-style nc (FreeBSD, OPNsense, pfSense).
    """

    # an OpenSSH server allows MaxSessions (default 10) exec channels per connection
    SOURCE_MAX_PARALLEL = 4

    def __init__(self, settings: dict):
        self.settings = settings
        self._client: paramiko.SSHClient | None = None
        self._lock = threading.Lock()

    @property
    def source(self) -> str:
        return (self.settings.get("source") or "").strip()

    def channel(self, host: str, port: int, timeout: float = 15, connect_timeout: int | None = None):
        """connect_timeout (source-address mode only): nc gives up and exits after that many
        seconds without a connection, or of inactivity. Only for short exchanges (banners)."""
        with self._lock:
            if self._client is None or not self._client.get_transport().is_active():
                client = paramiko.SSHClient()
                if known_hosts_file().exists():
                    client.load_host_keys(str(known_hosts_file()))  # a changed key raises BadHostKeyException
                client.set_missing_host_key_policy(_PinningPolicy())
                client.connect(self.settings["host"], port=int(self.settings.get("port") or 22),
                               username=self.settings["user"], key_filename=self.settings["key_file"],
                               timeout=15, allow_agent=False, look_for_keys=False)
                self._client = client
            transport = self._client.get_transport()
        if self.source:
            return self._nc_channel(transport, host, port, timeout, connect_timeout)
        return transport.open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=timeout)

    def _nc_channel(self, transport, host: str, port: int, timeout: float, connect_timeout: int | None = None):
        """A channel whose data is a TCP connection made by nc on the jump host, from self.source."""
        import ipaddress
        try:  # never pass raw text to a shell
            src, dst = ipaddress.ip_address(self.source), ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("with a jump host source address, switches must be given by IP address") from None
        chan = transport.open_session(timeout=timeout)
        wait = f"-w {int(connect_timeout)} " if connect_timeout else ""
        chan.exec_command(f"nc {wait}-s {src} {dst} {int(port)}")
        return chan

    def close(self):
        if self._client:
            self._client.close()


class NetmikoSession:
    def __init__(self, device: dict, cmds: dict, sock, probe_sock=None):
        from netmiko import ConnectHandler
        # netmiko authenticates inside ConnectHandler: the host key is checked first on a separate
        # key-exchange-only connection, then netmiko itself refuses any key but the pinned one
        probe = paramiko.Transport(probe_sock or (device["host"], device["port"]))
        try:
            probe.start_client(timeout=20)
            verify_host_key(device["host"], device["port"], probe.get_remote_server_key())
            # host key algorithm negotiated WITHOUT a stored-key bias: paramiko's SSHClient (netmiko)
            # prefers the stored key type ("ssh-rsa"), which would hide rsa-sha2-256/512 support
            self.probe_hostkey = probe.host_key_type
        finally:
            probe.close()
        username, password = inventory.device_credentials(device)
        # netmiko reads a private copy holding only this device's pinned key: the shared
        # known_hosts file may be rewritten by another worker meanwhile (first parallel scan)
        name = _key_name(device["host"], device["port"])
        with _keys_lock:
            found = paramiko.HostKeys(str(known_hosts_file())).lookup(name) or {}
        only = paramiko.HostKeys()
        for ktype, key in found.items():
            only.add(name, ktype, key)
        fd, snapshot = tempfile.mkstemp(suffix=".known_hosts")
        os.close(fd)
        only.save(snapshot)
        try:
            self.conn = ConnectHandler(
                device_type=cmds["netmiko"], host=device["host"], port=device["port"],
                username=username, password=password,
                sock=sock, conn_timeout=20, auth_timeout=20, fast_cli=True,
                ssh_strict=True, system_host_keys=False, alt_host_keys=True, alt_key_file=snapshot,
            )
        finally:
            os.unlink(snapshot)
        self.transport = self.conn.remote_conn.get_transport()

    def run(self, command: str, timeout: int) -> str:
        return self.conn.send_command(command, read_timeout=timeout)

    # ---- remediation only (never used by collection) ----

    def configure(self, commands: list[str]) -> list[tuple[str, str]]:
        """Send configuration commands one by one; returns (command, output) pairs, stopping at
        the first rejected command (its output starts with "%" or contains "Invalid input")."""
        done = []
        self.conn.config_mode()
        try:
            for command in commands:
                self.current = command  # reported if the session dies on this command
                out = self.conn.send_command_timing(command, read_timeout=30, strip_prompt=True, strip_command=True)
                done.append((command, out))
                if CLI_ERROR.search(out):
                    break
        finally:
            self.conn.exit_config_mode()
        return done

    def save(self) -> str:
        return self.conn.save_config()

    def close(self):
        self.conn.disconnect()


class ShellSession:
    """Cisco SB: SSH password auth is often disabled and the switch asks "User Name:" inside the
    shell after an SSH "none" authentication. Output ends when the CLI prompt comes back."""

    # a prompt may be printed twice after a terminal "erase line" code (SG300 after a banner:
    # "lab-sw(config)#\x1b[Klab-sw(config)#"); ANSI codes are stripped before matching
    PROMPT = re.compile(r"(?:^|\n)(?:[^\s#>]+[#>])+ ?$")
    ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

    def __init__(self, device: dict, cmds: dict, sock):
        self.transport = paramiko.Transport(sock or (device["host"], device["port"]))
        self.transport.start_client(timeout=20)
        # pinned host key checked before any credential is sent
        verify_host_key(device["host"], device["port"], self.transport.get_remote_server_key())
        username, password = inventory.device_credentials(device)
        try:
            self.transport.auth_none(username)
        except paramiko.BadAuthenticationType:
            self.transport.auth_password(username, password)
        self.chan = self.transport.open_session()
        self.chan.get_pty(width=250, height=200)
        self.chan.invoke_shell()

        first = self._read_until(re.compile(r"User Name:|Password:|[#>] ?$"), 30)
        if "User Name:" in first:
            self.chan.send(username + "\n")
            self._read_until(re.compile(r"Password:"), 15)
            self.chan.send(password + "\n")
            self._read_until(self.PROMPT, 30)
        self.run("terminal datadump", 10)

    def _read_until(self, pattern: re.Pattern, timeout: float) -> str:
        buf, deadline = "", time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.chan.recv_ready():
                buf += self.ANSI.sub("", self.chan.recv(65535).decode("utf-8", errors="replace").replace("\r", ""))
                if pattern.search(buf):
                    return buf
            else:
                time.sleep(0.05)
        raise TimeoutError(f"no prompt after {timeout}s")

    def run(self, command: str, timeout: int) -> str:
        self.chan.send(command + "\n")
        out = self._read_until(self.PROMPT, timeout)
        lines = out.split("\n")
        return "\n".join(lines[1:-1]).strip("\n")  # drop the echoed command and the prompt

    # ---- remediation only (never used by collection) ----

    def configure(self, commands: list[str]) -> list[tuple[str, str]]:
        done = []
        self.run("configure terminal", 15)
        try:
            for command in commands:
                self.current = command  # reported if the session dies on this command
                out = self._multiline(command) if "\n" in command else self.run(command, 30)
                done.append((command, out))
                if CLI_ERROR.search(out):
                    break
        finally:
            self.run("end", 15)
        return done

    def _drain(self, seconds: float) -> str:
        """Whatever the device prints during a fixed time (it may print nothing)."""
        out, end = "", time.monotonic() + seconds
        while time.monotonic() < end:
            if self.chan.recv_ready():
                out += self.ANSI.sub("", self.chan.recv(65535).decode("utf-8", errors="replace").replace("\r", ""))
            else:
                time.sleep(0.05)
        return out

    def _multiline(self, command: str) -> str:
        """Interactive multi-line input such as 'banner login #' + text + '#'. Cisco SB switches
        enter a text mode, possibly without printing anything (SG300 1.4), and discard input typed
        before they are ready: each line is sent after a pause, then the prompt is awaited.
        self.transcript keeps what the switch printed at each step, for the change log."""
        first, *rest = command.split("\n")
        self.transcript = []
        self.chan.send(first + "\n")
        out = self._drain(2.0)
        self.transcript.append((first, out))
        if CLI_ERROR.search(out):
            return out
        for line in rest:
            self.chan.send(line + "\n")
            part = self._drain(1.0)
            self.transcript.append((line, part))
            out += part
        if not self.PROMPT.search(out):
            try:
                out += self._read_until(self.PROMPT, 20)
            except TimeoutError:
                said = " | ".join(f"{sent!r} -> {got[-80:]!r}" for sent, got in self.transcript)
                raise TimeoutError(f"no prompt after the multi-line input; switch said: {said}"[:400])
        return out

    def save(self) -> str:
        """copy running-config startup-config, answering the overwrite confirmation."""
        self.chan.send("copy running-config startup-config\n")
        out = self._read_until(re.compile(r"\(Y/N\)|[#>] ?$"), 60)
        if "(Y/N)" in out:
            self.chan.send("Y\n")
            out += self._read_until(self.PROMPT, 120)
        if CLI_ERROR.search(out):
            raise RuntimeError(f"saving the configuration failed: {out.strip()[-200:]}")
        return out

    def close(self):
        self.transport.close()


def open_session(device: dict, jump: JumpHost | None):
    """SSH CLI session to a device (directly or through the jump host)."""
    cmds = COMMANDS.get(device["vendor"])
    if cmds is None:
        raise ValueError(f"no collector for platform '{device['vendor']}' yet")
    def new_sock():
        return jump.channel(device["host"], device["port"]) if device.get("via_jump") and jump else None
    if cmds["netmiko"] == "cisco_s300":
        return ShellSession(device, cmds, new_sock())
    return NetmikoSession(device, cmds, new_sock(), probe_sock=new_sock())


def collect_device(device: dict, jump: JumpHost | None) -> str:
    """Collect one device; returns a short status message. Raises on failure."""
    if device["vendor"] == "auto":
        device = detect_platform(device, jump)
    cmds = COMMANDS.get(device["vendor"])
    if cmds is None:
        raise ValueError(f"no collector for platform '{device['vendor']}' yet")

    started = time.monotonic()
    session = open_session(device, jump)
    try:
        transport = session.transport
        # vendor-neutral: the SSH identification string tells whether SSHv1 is still offered
        banner = transport.remote_version
        # the strongest algorithms both sides support: evidence of the switch's SSH crypto
        hostkey = getattr(session, "probe_hostkey", None) or transport.host_key_type
        negotiated = (f"kex: {getattr(transport, 'lyss_kex', 'unknown')}\ncipher: {transport.remote_cipher}\n"
                      f"mac: {transport.remote_mac}\nhostkey: {hostkey}")
        config = session.run(cmds["config"], 90)
        sections = [f"===== ssh banner =====\n{banner}", f"===== ssh negotiated =====\n{negotiated}"]
        for command in cmds["state"]:
            sections.append(f"===== {command} =====\n" + session.run(command, 45))
    finally:
        session.close()

    out_dir = inventory.PRIVATE / device["vendor"]
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    (out_dir / f"{device['id']}.cfg").write_text(config, encoding="utf-8")
    (out_dir / f"{device['id']}.state.txt").write_text(f"collected: {stamp}\n" + "\n".join(sections), encoding="utf-8")
    return f"{time.monotonic() - started:.0f}s"


def detect_platform(device: dict, jump: JumpHost | None) -> dict:
    """Platform "auto": recognise the adapter from the SSH banner and store it in the inventory."""
    from . import discovery

    banner = discovery._banner(device["host"], jump if device.get("via_jump") else None) or ""
    adapter, label = discovery.guess_platform(banner, discovery.SSH_FINGERPRINTS)
    if adapter is None:
        raise ValueError(f"platform not recognised from SSH banner '{banner or 'none'}': choose it manually")
    device = {**device, "vendor": adapter}
    inventory.set_vendor(device["id"], adapter)
    return device


def collect_many(devices: list[dict], jump_settings: dict, on_update, workers: int = 8) -> None:
    """Collect devices in parallel. on_update(device_id, status, message) is called on each change."""
    jump = JumpHost(jump_settings) if jump_settings.get("host") else None

    def work(device):
        on_update(device["id"], "running", "collecting")
        for attempt in (1, 2):
            try:
                on_update(device["id"], "collected", collect_device(device, jump))
                return
            except (TimeoutError, EOFError, ConnectionError, paramiko.ssh_exception.NoValidConnectionsError) as exc:
                # slow or busy legacy switch: one retry. Never retry authentication failures
                # (that could lock the account).
                if attempt == 2:
                    on_update(device["id"], "error", f"{type(exc).__name__}: {exc}"[:300])
                else:
                    on_update(device["id"], "running", "retrying")
            except Exception as exc:  # report and continue with the other devices
                on_update(device["id"], "error", f"{type(exc).__name__}: {exc}"[:300])
                return

    try:
        if jump and jump.source:
            workers = min(workers, JumpHost.SOURCE_MAX_PARALLEL)  # up to 2 channels per switch
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(work, devices))
    finally:
        if jump:
            jump.close()


def config_paths(device: dict) -> tuple[Path, Path]:
    base = inventory.PRIVATE / device["vendor"] / device["id"]
    return base.with_suffix(".cfg"), base.with_name(device["id"] + ".state.txt")
