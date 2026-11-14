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
import secrets
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import paramiko

from . import inventory, legacy_ssh, locks, sealed  # legacy_ssh: SHA-1 algorithms for old switches, opt-in per connection
from .config import printable

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
    "arista_eos": {
        "netmiko": "arista_eos",
        "config": "show running-config",
        "state": ["show version", "show management telnet", "show management ssh",
                  "show interfaces status", "show lldp neighbors detail", "show ntp status"],
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
    "huawei_vrp": {
        # netmiko disables paging ("screen-length 0 temporary")
        "netmiko": "huawei_vrp",
        "config": "display current-configuration",
        "state": ["display version", "display ntp-service status", "display interface brief"],
    },
    "aruba_aoscx": {
        "netmiko": "aruba_aoscx",
        "config": "show running-config",
        "state": ["show version", "show system", "show ntp status", "show interface brief"],
    },
    "juniper_junos": {
        # Junos operational mode; "display inheritance" includes settings inherited from
        # configuration groups, "display set" gives one full statement per line
        "netmiko": "juniper_junos",
        "config": "show configuration | display inheritance | display set",
        "state": ["show version", "show ntp status", "show interfaces terse"],
    },
    "hp_procurve": {
        # netmiko answers "Press any key to continue" and disables paging ("no page")
        "netmiko": "hp_procurve",
        "config": "show running-config",
        "state": ["show version", "show system", "show modules", "show ip ssh",
                  "show interfaces brief", "show lldp info remote-device", "show cdp neighbors",
                  # "Synchronization Status : Synchronized / Not Synced" (NTP mode; SNTP shows no status)
                  "show ntp status"],
    },
}


# a configuration command was rejected (Cisco IOS "% Invalid input", Cisco SB "% Unrecognized command")
CLI_ERROR = re.compile(r"(?m)^\s*%|Invalid input|Unrecognized command|Incomplete command|Wrong number of parameters|bad parameter")
# the only multi-line command LYSS sends: the Cisco SB login banner (delimiter line, text, delimiter)
BANNER_BLOCK = re.compile(r"banner (?:login|motd) #\n[^\x00-\x1f\x7f#]{1,200}\n#")
# the configuration command refused to the account (AOS-CX operators: "% Command incomplete.";
# "Cannot execute command. Command not allowed.", "Permission denied", ...)
CONFIG_REFUSED = re.compile(r"(?i)^\s*%|invalid input|unrecognized command|incomplete|not allowed|permission denied"
                            r"|not authori[sz]ed|insufficient privilege|access denied|cannot execute|unknown command")


MAX_OUTPUT = 20 * 1024 * 1024   # characters kept per command: a switch cannot fill the memory


def config_refusal(output: str) -> str | None:
    """Why a configuration command's output is not a configuration, or None. Only an empty answer or a
    short answer that starts with an error counts: a real configuration may quote such words (banners)."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return "the switch returned an empty configuration"
    if len(lines) <= 5 and CONFIG_REFUSED.search(lines[0]):
        return (f"the configuration command was refused ({printable(lines[0][:80])}): check the account's rights "
                "(docs/ACCOUNTS.md); nothing was assessed")
    return None


def check_commands(commands: list[str], banner_block: bool = False) -> None:
    """Last line of defence before configuration commands reach a switch: one command per string,
    no control characters (a new line, Ctrl-Z or Ctrl-C would start another command or leave
    configuration mode). Raises ValueError: nothing is sent."""
    for command in commands:
        if banner_block and BANNER_BLOCK.fullmatch(command):
            continue
        if not command or any(ord(c) < 0x20 or ord(c) == 0x7F for c in command):
            raise ValueError(f"refused: command with control characters {command[:60]!r}")

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


def _save_keys(keys: "paramiko.HostKeys", path) -> None:
    """Atomic rewrite: a reader (another process) never sees a truncated file, which would look
    like "no key known" and silently re-pin a switch on first use."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="known_hosts.", suffix=".tmp")
    os.close(fd)
    try:
        keys.save(tmp)
        locks.replace(Path(tmp), path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def verify_host_key(host: str, port: int, key) -> str:
    """Record the key on first contact; refuse a different key afterwards (before any password
    is sent). Returns the fingerprint. Locked across processes (web interface and scheduled
    "lyss collect")."""
    name = _key_name(host, port)
    path = known_hosts_file()
    with _keys_lock, locks.file_lock(path):
        keys = paramiko.HostKeys()
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
            _save_keys(keys, path)
    return fingerprint(key)


def known_fingerprint(host: str, port: int) -> str | None:
    path = known_hosts_file()
    if not path.exists():
        return None
    keys = paramiko.HostKeys(str(path))
    found = keys.lookup(_key_name(host, port))
    return fingerprint(next(iter(found.values()))) if found else None


def forget_host_key(host: str, port: int) -> None:
    path = known_hosts_file()
    with _keys_lock, locks.file_lock(path):
        if not path.exists():
            return
        keys = paramiko.HostKeys(str(path))
        name = _key_name(host, port)
        if name in keys:
            del keys[name]
            _save_keys(keys, path)


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
                               timeout=15, allow_agent=False, look_for_keys=False,
                               disabled_algorithms=legacy_ssh.connect_options(False))  # never legacy
                self._client = client
            transport = self._client.get_transport()
        if self.source:
            return self._nc_channel(transport, host, port, timeout, connect_timeout)
        return transport.open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=timeout)

    def _nc_channel(self, transport, host: str, port: int, timeout: float, connect_timeout: int | None = None):
        """A channel whose data is a TCP connection made by nc on the jump host, from self.source."""
        # never pass raw text to a shell: exact IP addresses only (no IPv6 scope id, no spaces)
        src, dst = inventory.strict_ip(self.source), inventory.strict_ip(host)
        if src is None or dst is None:
            raise ValueError("with a jump host source address, switches must be given by IP address")
        chan = transport.open_session(timeout=timeout)
        wait = f"-w {int(connect_timeout)} " if connect_timeout else ""
        chan.exec_command(f"nc {wait}-s {src} {dst} {int(port)}")
        return chan

    def close(self):
        if self._client:
            self._client.close()


def _start_transport(device: dict, new_sock) -> tuple[paramiko.Transport, bool]:
    """Key exchange with a switch: modern algorithms only, then (and only if the switch has no
    algorithm in common) the legacy SHA-1 set of legacy_ssh. Returns (transport, legacy)."""
    for legacy in (False, True):
        transport = paramiko.Transport(new_sock() or (device["host"], device["port"]),
                                       disabled_algorithms=legacy_ssh.connect_options(legacy))
        try:
            transport.start_client(timeout=20)
            return transport, legacy
        except paramiko.SSHException as exc:
            transport.close()
            if legacy or not legacy_ssh.is_incompatible(exc):
                raise
    raise AssertionError("unreachable")


class NetmikoSession:
    def __init__(self, device: dict, cmds: dict, new_sock):
        from netmiko import ConnectHandler
        # netmiko authenticates inside ConnectHandler: the host key is checked first on a separate
        # key-exchange-only connection, then netmiko itself refuses any key but the pinned one
        probe, self.legacy = _start_transport(device, new_sock)
        try:
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
                sock=new_sock(), conn_timeout=20, auth_timeout=20, fast_cli=True,
                ssh_strict=True, system_host_keys=False, alt_host_keys=True, alt_key_file=snapshot,
                disabled_algorithms=legacy_ssh.connect_options(self.legacy),
            )
        finally:
            os.unlink(snapshot)
        self.transport = self.conn.remote_conn.get_transport()
        self._bound_output()

    def _bound_output(self) -> None:
        """netmiko accumulates what it reads until the prompt or the timeout, without a limit: a
        hostile switch that never prints its prompt could fill the memory. Count what is read."""
        self._seen = 0
        read = self.conn.read_channel

        def bounded(*args, **kwargs):
            data = read(*args, **kwargs)
            self._seen += len(data)
            if self._seen > MAX_OUTPUT:
                raise RuntimeError("output larger than 20 MB: stopped")
            return data
        self.conn.read_channel = bounded

    def run(self, command: str, timeout: int) -> str:
        self._seen = 0
        return self.conn.send_command(command, read_timeout=timeout)

    # ---- remediation only (never used by collection) ----

    def configure(self, commands: list[str]) -> list[tuple[str, str]]:
        """Send configuration commands one by one; returns (command, output) pairs, stopping at
        the first rejected command (its output starts with "%" or contains "Invalid input")."""
        check_commands(commands)
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
        out = self.conn.save_config()
        if CLI_ERROR.search(out or ""):
            raise RuntimeError(f"saving the configuration failed: {printable(out).strip()[-200:]}")
        return out

    def close(self):
        self.conn.disconnect()


class ShellSession:
    """Cisco SB: SSH password auth is often disabled and the switch asks "User Name:" inside the
    shell after an SSH "none" authentication. Output ends when the CLI prompt comes back."""

    # a prompt may be printed twice after a terminal "erase line" code (SG300 after a banner:
    # "lab-sw(config)#\x1b[Klab-sw(config)#"); ANSI codes are stripped before matching
    PROMPT = re.compile(r"(?:^|\n)(?:[^\s#>]+[#>])+ ?$")
    ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

    def __init__(self, device: dict, cmds: dict, new_sock):
        self.transport, self.legacy = _start_transport(device, new_sock)
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
            after = self._read_until(re.compile(self.PROMPT.pattern + r"|User Name:|Password:"), 30)
            if re.search(r"User Name:|Password:\s*$", after):
                # the switch asks again: wrong credentials. Never retried (account lockout)
                raise paramiko.AuthenticationException("the switch refused the user name or password")
            last = after.rstrip().rsplit("\n", 1)[-1]
            # the switch's own prompt name: output lines that merely look like a prompt (text set
            # by a neighbour over CDP/LLDP, a banner) do not end a command's output
            name = re.match(r"([^\s#>(]+)", last)
            if name:
                self.prompt = re.compile(rf"(?:^|\n)(?:{re.escape(name.group(1))}(?:\([^)\n]*\))?[#>])+ ?$")
        self.run("terminal datadump", 10)

    MAX_OUTPUT = MAX_OUTPUT

    def _read_until(self, pattern: re.Pattern, timeout: float) -> str:
        buf, deadline = "", time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.chan.recv_ready():
                chunk = self.ANSI.sub("", self.chan.recv(65535).decode("utf-8", errors="replace").replace("\r", ""))
                buf += chunk
                if len(buf) > self.MAX_OUTPUT:
                    raise RuntimeError("output larger than 20 MB: stopped")
                if pattern.search(buf[-(len(chunk) + 4096):]):   # only the end can hold the prompt
                    return buf
            else:
                time.sleep(0.05)
        raise TimeoutError(f"no prompt after {timeout}s")

    def run(self, command: str, timeout: int) -> str:
        self.chan.send(command + "\n")
        out = self._read_until(getattr(self, "prompt", None) or self.PROMPT, timeout)
        lines = out.split("\n")
        return "\n".join(lines[1:-1]).strip("\n")  # drop the echoed command and the prompt

    # ---- remediation only (never used by collection) ----

    def configure(self, commands: list[str]) -> list[tuple[str, str]]:
        check_commands(commands, banner_block=True)
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
        prompt = getattr(self, "prompt", None) or self.PROMPT
        if not prompt.search(out):
            try:
                out += self._read_until(prompt, 20)
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
    if device.get("via_jump") and jump is None:
        # never contact such a switch directly: the same address may be another machine here, and
        # it would receive the credentials (first contact trusts the key it presents)
        raise ValueError("this switch is reached through the jump host, which is not configured (Settings > Jump host)")

    def new_sock():
        return jump.channel(device["host"], device["port"]) if device.get("via_jump") and jump else None
    if cmds["netmiko"] == "cisco_s300":
        return ShellSession(device, cmds, new_sock)
    return NetmikoSession(device, cmds, new_sock)


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
        if getattr(session, "legacy", False):
            # the switch had no modern key exchange / host key algorithm: SHA-1 had to be allowed
            negotiated += "\nlegacy: required (no modern key exchange or host key algorithm offered)"
        config = session.run(cmds["config"], 90)
        if refusal := config_refusal(config):
            # never assess an error message as if it were the configuration (false passes)
            raise ValueError(refusal)
        # section headers carry a random value the switch cannot know: text sent by a neighbour
        # (CDP/LLDP fields) that looks like a header stays plain output (config.parse_state)
        nonce = secrets.token_hex(8)
        sections = [f"===== ssh banner ===== #{nonce}\n{banner}",
                    f"===== ssh negotiated ===== #{nonce}\n{negotiated}"]
        for command in cmds["state"]:
            sections.append(f"===== {command} ===== #{nonce}\n" + session.run(command, 45))
    finally:
        session.close()

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    cfg_path, state_path = config_paths(device)
    sealed.write_text(cfg_path, config)          # encrypted at rest unless turned off in Settings
    sealed.write_text(state_path, f"collected: {stamp}\nsections: #{nonce}\n" + "\n".join(sections))
    return f"{time.monotonic() - started:.0f}s"


def detect_platform(device: dict, jump: JumpHost | None) -> dict:
    """Platform "auto": recognise the adapter from the SSH banner and store it in the inventory."""
    from . import discovery

    banner = discovery._banner(device["host"], jump if device.get("via_jump") else None,
                               int(device.get("port") or 22)) or ""
    adapter, label = discovery.guess_platform(banner, discovery.SSH_FINGERPRINTS)
    if adapter is None:
        raise ValueError(f"platform not recognised from SSH banner '{printable(banner[:120]) or 'none'}': choose it manually")
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
                    on_update(device["id"], "error", printable(f"{type(exc).__name__}: {exc}")[:300])
                else:
                    on_update(device["id"], "running", "retrying")
            except Exception as exc:  # report and continue with the other devices
                # the text may quote what the switch sent: no control character reaches a terminal
                on_update(device["id"], "error", printable(f"{type(exc).__name__}: {exc}")[:300])
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
