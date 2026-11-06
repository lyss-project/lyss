# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""SSH server for simulated switches: one listening port per switch on 127.0.0.1, a CLI that
behaves like the real platform closely enough for LYSS's collector, netmiko and the remediation
module (prompts, echo, login dialogue, configuration mode, saving)."""

import logging
import re
import socket
import threading
from pathlib import Path

import paramiko

logging.getLogger("lyss.sim.ssh").addHandler(logging.NullHandler())
logging.getLogger("lyss.sim.ssh").propagate = False

from . import render
from .config import submode
from .lab import Lab, SimSwitch

INVALID = {
    "cisco_ios": "                    ^\n% Invalid input detected at '^' marker.",
    "cisco_sb": "% Unrecognized command",
    "hp_procurve": "Invalid input: {word}",
    "mikrotik": "bad command name {word} (line 1 column 1)",
    "sonic": "-bash: {word}: command not found",
}


def login_name(sw: SimSwitch, username: str) -> str:
    # RouterOS reads console options after "+" in the user name (netmiko sends "user+ct511w4098h")
    return username.split("+", 1)[0] if sw.platform == "mikrotik" else username
LEGACY = {  # what old switches still negotiate (and nothing better)
    "kex": ("diffie-hellman-group14-sha1",),
    "ciphers": ("aes128-cbc",),
    "digests": ("hmac-sha1",),
    "key_types": ("ssh-rsa",),
}


class _Auth(paramiko.ServerInterface):
    def __init__(self, sw: SimSwitch, credentials: dict):
        self.sw, self.creds = sw, credentials
        self.shell = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        # Cisco SB: SSH "none" authentication, then "User Name:" / "Password:" inside the shell
        return "none,password" if self.sw.platform == "cisco_sb" else "password"

    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL if self.sw.platform == "cisco_sb" else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        ok = login_name(self.sw, username) == self.creds["username"] and password == self.creds["password"]
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_window_change_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.shell.set()
        return True


class Shell:
    """One interactive CLI session."""

    def __init__(self, sw: SimSwitch, chan, credentials: dict):
        self.sw, self.chan, self.creds = sw, chan, credentials
        self.pending = ""
        self.skip_lf = False
        self.mode = "exec"          # exec | config | sub
        self.block = None           # configuration block of the current sub-mode
        self.sub_name = ""

    # ---- I/O ----

    def send(self, text: str) -> None:
        self.chan.sendall(text.replace("\r\n", "\n").replace("\n", "\r\n").encode())

    def _fill(self) -> bool:
        data = self.chan.recv(4096)
        if not data:
            return False
        self.pending += data.decode("utf-8", errors="replace")
        return True

    def read_char(self) -> str | None:
        while not self.pending:
            if not self._fill():
                return None
        ch, self.pending = self.pending[0], self.pending[1:]
        return ch

    def read_line(self, echo: bool = True) -> str | None:
        line = ""
        while True:
            ch = self.read_char()
            if ch is None:
                return None
            if self.skip_lf and ch == "\n":
                self.skip_lf = False
                continue
            self.skip_lf = False
            if ch in "\r\n":
                self.skip_lf = ch == "\r"
                if echo:
                    self.send("\n")
                return line
            if ch in "\x08\x7f":
                if line:
                    line = line[:-1]
                    if echo:
                        self.send("\b \b")
                continue
            if ch < " " and ch != "\t":
                continue
            line += ch
            if echo:
                self.send(ch)

    def prompt(self) -> str:
        host = self.sw.hostname
        if self.sw.platform == "mikrotik":
            return f"[{self.creds['username']}@{host}] > "
        if self.sw.platform == "sonic":
            return f"{self.creds['username']}@{host}:~$ "
        if self.mode == "exec":
            return f"{host}# " if self.sw.platform == "hp_procurve" else f"{host}#"
        if self.mode == "config":
            return f"{host}(config)# " if self.sw.platform == "hp_procurve" else f"{host}(config)#"
        return f"{host}({self.sub_name})# " if self.sw.platform == "hp_procurve" else f"{host}({self.sub_name})#"

    # ---- dialogue ----

    def run(self) -> None:
        if not self._login():
            return
        self.send(self.prompt())
        while True:
            line = self.read_line()
            if line is None:
                return
            out = self.handle(line)
            if out is False:
                return
            if out:
                self.send(out.rstrip("\n") + "\n")
            self.send(self.prompt())

    def _login(self) -> bool:
        platform = self.sw.platform
        if platform == "cisco_sb":
            for _ in range(3):
                self.send("\nUser Name:")
                user = self.read_line()
                if user is None:
                    return False
                self.send("Password:")
                password = self.read_line(echo=False)
                if password is None:
                    return False
                self.send("\n")
                if user == self.creds["username"] and password == self.creds["password"]:
                    return True
                self.send("% Authentication failed\n")
            return False
        if platform == "hp_procurve":
            self.send(f"\nHPE {self.sw.model} Switch\n\n"
                      "  Copyright (c) 2026 Simulated device, LYSS demo lab (not a real HPE switch)\n\n"
                      "  All data on this device is fictitious.\n\n"
                      "Press any key to continue")
            ch = self.read_char()
            if ch is None:
                return False
            self.skip_lf = ch == "\r"
            self.send("\n")
            return True
        self.send("\n")
        return True

    def handle(self, line: str):
        """Output of one command line ("" for none), or False to close the session."""
        cmd = re.sub(r"\s+", " ", line.strip())
        if not cmd:
            return ""
        low = cmd.lower()
        sw = self.sw
        if sw.static:
            # read-only platforms: fixed outputs, nothing can be changed
            if low in ("exit", "logout", "quit", "/quit"):
                return False
            out = sw.static_output(cmd)
            return self._invalid(cmd) if out is None else out
        if self.mode == "exec":
            if low.startswith("terminal ") or low in ("no page", "enable"):
                return ""
            if low.startswith(("show ", "sh ")):
                try:
                    with sw.lock:
                        out = render.show(sw, cmd)
                except Exception as exc:  # a simulator bug must not hang the client
                    return f"% Simulator error: {type(exc).__name__}: {exc}"
                return self._invalid(cmd) if out is None else out
            if low in ("configure terminal", "configure", "conf t", "config"):
                self.mode = "config"
                return "Enter configuration commands, one per line.  End with CNTL/Z." if sw.platform == "cisco_ios" else ""
            if low.startswith("write") or low == "copy running-config startup-config":
                return self._save(low)
            if low in ("exit", "logout", "quit"):
                return self._logout()
            return self._invalid(cmd)

        # configuration mode
        if low == "end":
            self.mode, self.block = "exec", None
            return ""
        if low == "exit":
            if self.mode == "sub":
                self.mode, self.block = "config", None
            else:
                self.mode = "exec"
            return ""
        if low.startswith(("show ", "do ")):
            return self._invalid(cmd)
        if low.startswith("write") and sw.platform == "hp_procurve":
            return self._save(low)
        m = re.match(r"^banner (login|motd|exec) (\S)(.*)$", cmd)
        if m and self.mode == "config":
            return self._banner(m.group(1), m.group(2), m.group(3))
        with sw.lock:
            sw.log.append(cmd)
            name = submode(sw.platform, cmd)
            if name is not None:
                self.block = sw.running.open_block(cmd)
                self.mode, self.sub_name = "sub", name
                return ""
            if self.mode == "sub" and self.block is not None:
                sw.running.configure(self.block, cmd)
            else:
                sw.running.configure(None, cmd)
        return ""

    def _banner(self, kind: str, delimiter: str, rest: str):
        sw = self.sw
        if sw.platform == "hp_procurve":  # banner motd "text"
            text = (delimiter + rest).strip().strip('"')
            with sw.lock:
                sw.log.append(f"banner {kind} \"{text}\"")
                sw.running.set_banner(kind, [text], '"')
            return ""
        if delimiter in rest:  # one line: banner login #text#
            with sw.lock:
                sw.log.append(f"banner {kind} {delimiter}{rest}")
                sw.running.set_banner(kind, [rest.split(delimiter)[0]], delimiter)
            return ""
        # multi-line text mode until the delimiter (Cisco SB: no prompt meanwhile)
        body = [rest.strip()] if rest.strip() else []
        if sw.platform == "cisco_ios":
            self.send(f"Enter TEXT message.  End with the character '{delimiter}'.\n")
        while True:
            line = self.read_line()
            if line is None:
                return False
            if delimiter in line:
                if line.split(delimiter)[0].strip():
                    body.append(line.split(delimiter)[0])
                break
            body.append(line)
        with sw.lock:
            sw.log.append(f"banner {kind} {delimiter} ({len(body)} lines)")
            sw.running.set_banner(kind, body, "^" if sw.platform == "cisco_sb" else delimiter)
        return ""

    def _save(self, low: str):
        sw = self.sw
        if sw.platform == "cisco_sb":
            self.send("Overwrite file [startup-config].... (Y/N)[N] ?")
            answer = self.read_char()
            if answer is None:
                return False
            if answer in "\r\n":
                self.skip_lf = answer == "\r"
                self.send("\n")
                return "Copy operation aborted."
            self.skip_lf = False
            self.send(answer + "\n")
            # the rest of the answer line ("Y\n")
            rest = self.read_line(echo=False)
            if answer.lower() != "y" or rest is None:
                return "Copy operation aborted."
            sw.save()
            return "Copy succeeded"
        sw.save()
        if sw.platform == "cisco_ios":
            return "Building configuration...\n[OK]"
        return ""

    def _logout(self):
        if self.sw.platform == "hp_procurve":
            self.send("Do you want to log out [y/n]? ")
            self.read_char()
        return False

    def _invalid(self, cmd: str) -> str:
        return INVALID[self.sw.platform].format(word=cmd.split()[0])


class Simulator:
    """All the switches of a lab, each with its own SSH server."""

    def __init__(self, lab: Lab, host: str = "127.0.0.1", base_port: int = 2201,
                 keys_dir: Path | None = None):
        self.lab, self.host, self.base_port = lab, host, base_port
        self.keys_dir = Path(keys_dir) if keys_dir else None
        self._socks: list[socket.socket] = []
        self._transports: list[paramiko.Transport] = []
        self._running = False
        self._keys: dict[str, paramiko.PKey] = {}

    def _key(self, sw: SimSwitch) -> paramiko.PKey:
        if sw.id in self._keys:
            return self._keys[sw.id]
        # legacy switches only have an RSA host key (offered as "ssh-rsa"); modern ones ECDSA
        kind = paramiko.RSAKey if sw.legacy_ssh else paramiko.ECDSAKey

        def generate():
            return paramiko.RSAKey.generate(2048) if kind is paramiko.RSAKey else paramiko.ECDSAKey.generate()

        key = None
        if self.keys_dir:
            path = self.keys_dir / f"{sw.id}.{'rsa' if kind is paramiko.RSAKey else 'ecdsa'}.key"
            if path.exists():
                key = kind(filename=str(path))
            else:
                key = generate()
                self.keys_dir.mkdir(parents=True, exist_ok=True)
                key.write_private_key_file(str(path))
        self._keys[sw.id] = key or generate()
        return self._keys[sw.id]

    def start(self) -> "Simulator":
        self._running = True
        for i, sw in enumerate(self.lab.switches.values()):
            self._key(sw)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.base_port + i if self.base_port else 0))
            sock.listen(16)
            sw.port = sock.getsockname()[1]
            self._socks.append(sock)
            threading.Thread(target=self._accept, args=(sw, sock), daemon=True, name=f"sim-{sw.id}").start()
        return self

    def stop(self) -> None:
        self._running = False
        for sock in self._socks:
            try:
                sock.close()
            except OSError:
                pass
        for t in list(self._transports):
            try:
                t.close()
            except Exception:
                pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def _accept(self, sw: SimSwitch, sock: socket.socket) -> None:
        while self._running:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(sw, conn), daemon=True).start()

    def _serve(self, sw: SimSwitch, conn: socket.socket) -> None:
        transport = paramiko.Transport(conn)
        # server-side noise (clients probing the host key and disconnecting) stays out of the console
        transport.set_log_channel("lyss.sim.ssh")
        self._transports.append(transport)
        try:
            transport.local_version = sw.ssh_banner()
            transport.add_server_key(self._key(sw))
            if sw.legacy_ssh:
                options = transport.get_security_options()
                for name, value in LEGACY.items():
                    setattr(options, name, value)
            auth = _Auth(sw, self.lab.credentials)
            try:
                transport.start_server(server=auth)
            except (paramiko.SSHException, EOFError, OSError):
                return  # e.g. a key-exchange-only probe (host key check)
            chan = transport.accept(30)
            if chan is None:
                return
            if not auth.shell.wait(15):
                return
            try:
                Shell(sw, chan, self.lab.credentials).run()
            except (OSError, EOFError, paramiko.SSHException):
                pass
        finally:
            try:
                transport.close()
            except Exception:
                pass
            if transport in self._transports:
                self._transports.remove(transport)

    def pin_host_keys(self) -> None:
        """Record the simulated switches' host keys in LYSS's known_hosts (current data directory)
        before any collection: the simulator knows its own keys, so there is no first-contact
        guess, and parallel first collections do not all rewrite known_hosts at once."""
        from .. import collector
        for sw in self.lab.switches.values():
            key = self._key(sw)
            try:
                collector.verify_host_key(self.host, sw.port, key)
            except collector.HostKeyMismatch:
                collector.forget_host_key(self.host, sw.port)  # e.g. simulator keys regenerated
                collector.verify_host_key(self.host, sw.port, key)

    def describe(self) -> list[dict]:
        return [{"id": sw.id, "hostname": sw.hostname, "platform": sw.platform, "model": sw.model,
                 "host": self.host, "port": sw.port} for sw in self.lab.switches.values()]
