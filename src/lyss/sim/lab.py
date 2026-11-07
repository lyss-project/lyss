# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""A simulated lab: switches (platform, model, firmware, running configuration) and the cables
between them, from which each switch's LLDP/CDP neighbour tables are derived consistently."""

import re
import threading
from pathlib import Path

import yaml

from .config import RunningConfig

LABS = Path(__file__).parent / "labs"
PLATFORMS = ("cisco_ios", "cisco_sb", "hp_procurve", "mikrotik", "sonic", "arista_eos")
# read-only platforms (no LYSS remediation): fixed outputs from <switch>.cfg and <switch>.state,
# a "===== command =====" section per command, as in a LYSS state file
STATIC = ("mikrotik", "sonic", "arista_eos")


def parse_sections(text: str) -> dict[str, str]:
    out, current, lines = {}, None, []
    for line in text.splitlines():
        m = re.match(r"^===== (.+) =====$", line)
        if m:
            if current is not None:
                out[current] = "\n".join(lines).strip("\n")
            current, lines = m.group(1), []
        elif current is not None:
            lines.append(line)
    if current is not None:
        out[current] = "\n".join(lines).strip("\n")
    return out


def expand(ranges) -> set[int]:
    """"1-4,9" or [1, "5-6"] -> {1, 2, 3, 4, 9} / {1, 5, 6}."""
    out: set[int] = set()
    items = ranges if isinstance(ranges, list) else str(ranges or "").split(",")
    for item in items:
        item = str(item).strip()
        if not item:
            continue
        if "-" in item:
            a, b = item.split("-", 1)
            out |= set(range(int(a), int(b) + 1))
        else:
            out.add(int(item))
    return out


def port_name(platform: str, n: int | str, style: str = "short") -> str:
    """Native port name: Cisco IOS Gi1/0/5 (short), GigabitEthernet1/0/5 (long), Gig 1/0/5 (cdp);
    Cisco SB gi5; HP 5."""
    if isinstance(n, str) and not n.isdigit():
        return n  # external devices give their own port names
    if platform == "cisco_ios":
        return {"short": f"Gi1/0/{n}", "long": f"GigabitEthernet1/0/{n}", "cdp": f"Gig 1/0/{n}"}[style]
    if platform == "cisco_sb":
        return f"gi{n}"
    return str(n)


class SimSwitch:
    def __init__(self, switch_id: str, spec: dict, config_text: str, state_text: str = ""):
        self.id = switch_id
        self.spec = spec
        self.platform = spec["platform"]
        if self.platform not in PLATFORMS:
            raise ValueError(f"{switch_id}: unknown platform {self.platform}")
        self.static = self.platform in STATIC
        if self.static:
            self.running = None
            self.config_text = config_text
            self.outputs = parse_sections(state_text)
            self.saved = config_text
        else:
            self.running = RunningConfig(config_text, self.platform)
            self.saved = self.running.text()
        self.lock = threading.RLock()
        self.port: int | None = None      # TCP port of its SSH server
        self.lab: "Lab | None" = None
        self.log: list[str] = []          # configuration commands received (for tests and demos)

    # ---- identity ----

    @property
    def hostname(self) -> str:
        if self.static:
            return self.spec["hostname"]
        for line in self.running.top():
            m = re.match(r'^hostname\s+"?([^"\s]+)"?\s*$', line)
            if m:
                return m.group(1)
        return self.spec.get("hostname", self.id.upper())

    @property
    def mac(self) -> str:
        return self.spec["mac"]

    @property
    def model(self) -> str:
        return self.spec["model"]

    @property
    def version(self) -> str:
        return self.spec["version"]

    @property
    def legacy_ssh(self) -> bool:
        return self.spec.get("ssh", "modern") == "legacy"

    # ---- ports ----

    def port_numbers(self) -> list[int]:
        return list(range(1, int(self.spec["ports"]) + 1))

    def is_uplink_port(self, n: int) -> bool:
        return n >= int(self.spec.get("uplink_from", 10_000))

    def linked_ports(self) -> set[int]:
        return {nb["local"] for nb in (self.lab.neighbors(self.id) if self.lab else [])
                if isinstance(nb["local"], int)}

    def up_ports(self) -> set[int]:
        return expand(self.spec.get("up", "")) | self.linked_ports()

    # ---- configuration state used by the "show" outputs ----

    def has_line(self, pattern: str) -> bool:
        if self.static:
            return bool(re.search(pattern, self.config_text, re.M))
        return any(re.search(pattern, l) for l in self.running.top())

    def static_output(self, command: str) -> str | None:
        """Fixed output of a read-only platform; None for an unknown command."""
        if command == {"mikrotik": "/export terse", "sonic": "show runningconfiguration all",
                       "arista_eos": "show running-config"}[self.platform]:
            return self.config_text.rstrip("\n")
        return self.outputs.get(command)

    def ssh_banner(self) -> str:
        if self.platform == "mikrotik":
            return "SSH-2.0-ROSSSH"
        if self.platform == "sonic":
            return "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5"
        if self.platform == "arista_eos":
            return "SSH-2.0-OpenSSH_9.9"
        if self.platform == "cisco_ios":
            return "SSH-2.0-Cisco-1.25" if self.has_line(r"^ip ssh version 2$") else "SSH-1.99-Cisco-1.25"
        if self.platform == "cisco_sb":
            return "SSH-2.0-OpenSSH_7.3p1.RL"
        return "SSH-2.0-Mocana SSH 6.3"

    def save(self) -> None:
        with self.lock:
            self.saved = self.config_text if self.static else self.running.text()


class Lab:
    def __init__(self, folder: Path):
        self.folder = Path(folder)
        data = yaml.safe_load((self.folder / "lab.yaml").read_text(encoding="utf-8"))
        self.name = data["name"]
        self.description = data.get("description", "")
        self.organization = data.get("organization", "Demo")
        self.credentials = data["credentials"]
        self.switches: dict[str, SimSwitch] = {}
        for switch_id, spec in data["switches"].items():
            text = (self.folder / f"{switch_id}.cfg").read_text(encoding="utf-8")
            state_file = self.folder / f"{switch_id}.state"
            state = state_file.read_text(encoding="utf-8") if state_file.exists() else ""
            sw = SimSwitch(switch_id, spec, text, state)
            sw.lab = self
            self.switches[switch_id] = sw
        self.links = [dict(zip(("a", "a_port", "b", "b_port"), link)) for link in data.get("links", [])]
        self.externals = data.get("externals", [])
        for link in self.links:
            for side in ("a", "b"):
                if link[side] not in self.switches:
                    raise ValueError(f"link to unknown switch {link[side]}")

    def neighbors(self, switch_id: str) -> list[dict]:
        """[{local: port, peer: SimSwitch | None, external: dict | None, remote: port}]"""
        out = []
        for link in self.links:
            if link["a"] == switch_id:
                out.append({"local": link["a_port"], "peer": self.switches[link["b"]], "external": None,
                            "remote": link["b_port"]})
            if link["b"] == switch_id:
                out.append({"local": link["b_port"], "peer": self.switches[link["a"]], "external": None,
                            "remote": link["a_port"]})
        for ext in self.externals:
            if ext["attached_to"] == switch_id:
                out.append({"local": ext["port"], "peer": None, "external": ext, "remote": ext["remote_port"]})
        return sorted(out, key=lambda nb: (str(type(nb["local"])), nb["local"]))


def load_lab(name_or_path: str = "demo") -> Lab:
    path = Path(name_or_path)
    if not (path / "lab.yaml").exists():
        path = LABS / name_or_path
    if not (path / "lab.yaml").exists():
        known = ", ".join(p.name for p in LABS.iterdir() if (p / "lab.yaml").exists())
        raise ValueError(f"unknown lab '{name_or_path}' (available: {known})")
    return Lab(path)
