# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Read-only "show" outputs of a simulated switch, in the layouts of the real platforms.
Everything that depends on the configuration (Telnet/HTTP listeners, SSH version, port states)
is computed from the current running configuration, so a fix shows up in the next collection."""

import re

from .lab import SimSwitch, port_name


def _peer(nb: dict) -> dict:
    """Uniform description of a neighbour (simulated switch or external device)."""
    peer, ext = nb["peer"], nb["external"]
    if peer is not None:
        cisco = peer.platform in ("cisco_ios", "cisco_sb")
        return {
            "name": peer.hostname, "mac": peer.mac, "ip": peer.spec.get("mgmt_ip", ""),
            "model": peer.model, "version_line": _version_line(peer),
            "lldp_port": port_name(peer.platform, nb["remote"], "short"),
            "cdp_port": port_name(peer.platform, nb["remote"], "long"),
            "lldp_caps": "B", "cdp_caps": "S I", "cdp_caps_long": "Switch IGMP",
            "lldp": True, "cdp": cisco,
            "platform": {"cisco_ios": "cisco ", "cisco_sb": "Cisco ", "mikrotik": "MikroTik ",
                         "sonic": "SONiC ", "arista_eos": "Arista "}.get(peer.platform, "HPE ") + peer.model,
        }
    return {
        "name": ext["name"], "mac": ext["mac"], "ip": ext.get("ip", ""), "model": ext.get("model", ""),
        "version_line": ext.get("description", ext.get("platform", "")),
        "lldp_port": nb["remote"], "cdp_port": nb["remote"],
        "lldp_caps": ext.get("lldp_caps", "B"), "cdp_caps": ext.get("cdp_caps", "S I"),
        "cdp_caps_long": ext.get("cdp_caps_long", "Switch IGMP"),
        "lldp": "lldp" in ext.get("protocols", ["lldp"]), "cdp": "cdp" in ext.get("protocols", []),
        "platform": ext.get("platform", ""),
    }


def _version_line(sw: SimSwitch) -> str:
    if sw.platform == "cisco_ios":
        return (f"Cisco IOS Software, C1000 Software (C1000-UNIVERSALK9-M), Version {sw.version}, "
                "RELEASE SOFTWARE (fc1)")
    if sw.platform == "cisco_sb":
        return f"{sw.model} Managed Switch, firmware {sw.version}"
    if sw.platform == "mikrotik":
        return f"MikroTik RouterOS {sw.version} (stable) {sw.model}"
    if sw.platform == "sonic":
        return f"SONiC Software Version: SONiC.{sw.version} - HwSku: {sw.model}"
    if sw.platform == "arista_eos":
        return f"Arista Networks EOS version {sw.version} running on an Arista {sw.model}"
    return f"HPE {sw.model} Switch, revision {sw.version}"


def _mac_dotted(mac: str) -> str:
    h = re.sub(r"[^0-9a-f]", "", mac.lower())
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"


def _mac_spaced(mac: str) -> str:
    h = re.sub(r"[^0-9a-f]", "", mac.lower())
    return " ".join(h[i:i + 2] for i in range(0, 12, 2))


# ---------------- Cisco IOS ----------------

def _ios_shutdown(sw: SimSwitch, n: int) -> bool:
    block = sw.running.find_block(f"interface GigabitEthernet1/0/{n}")
    return bool(block and "shutdown" in block.children)


def _ios_telnet(sw: SimSwitch) -> bool:
    vty = sw.running.blocks(r"^line vty")
    return not vty or any(not any(re.match(r"^transport input (ssh|none)$", c) for c in b.children) for b in vty)


def ios_show(sw: SimSwitch, command: str) -> str | None:
    nbs = [(nb, _peer(nb)) for nb in sw.lab.neighbors(sw.id)]
    if command == "show version":
        return "\n".join([
            _version_line(sw),
            "Technical Support: http://www.cisco.com/techsupport",
            "Copyright (c) 1986-2026 by Cisco Systems, Inc.",
            "",
            "ROM: Bootstrap program is C1000 boot loader",
            f"{sw.hostname} uptime is 12 weeks, 3 days, 4 hours, 2 minutes",
            f'System image file is "flash:/c1000-universalk9-mz.{sw.version}.bin"',
            "",
            f"cisco {sw.model} (ARM) processor (revision B0) with 524288K bytes of memory.",
            f"Processor board ID {sw.spec['serial']}",
            "",
            f"Base Ethernet MAC Address          : {sw.mac}",
            f"Model number                       : {sw.model}",
            f"System serial number               : {sw.spec['serial']}",
        ])
    if command == "show inventory":
        return (f'NAME: "1", DESCR: "{sw.model}"\n'
                f"PID: {sw.model:<18}, VID: V01  , SN: {sw.spec['serial']}")
    if command == "show ip ssh":
        version = "2.0" if sw.has_line(r"^ip ssh version 2$") else "1.99"
        return (f"SSH Enabled - version {version}\n"
                "Authentication methods:publickey,keyboard-interactive,password\n"
                "Authentication timeout: 120 secs; Authentication retries: 3")
    if command == "show control-plane host open-ports":
        rows = [("22", "SSH-Server")]
        if _ios_telnet(sw):
            rows.append(("23", "Telnet"))
        if sw.has_line(r"^ip http server$"):
            rows.append(("80", "HTTP CORE"))
        if sw.has_line(r"^ip http secure-server$"):
            rows.append(("443", "HTTP CORE"))
        lines = ["Active internet connections (servers and established)",
                 "Prot               Local Address             Foreign Address                  Service    State"]
        lines += [f" tcp {'*:' + p:>28} {'*:0':>27} {svc:>18}   LISTEN" for p, svc in sorted(rows, key=lambda r: int(r[0]))]
        return "\n".join(lines)
    if command == "show interfaces status":
        linked = {nb["local"]: p for nb, p in nbs}
        up = sw.up_ports()
        lines = ["Port      Name               Status       Vlan       Duplex  Speed Type"]
        for n in sw.port_numbers():
            if _ios_shutdown(sw, n):
                status = "disabled"
            elif n in up:
                status = "connected"
            else:
                status = "notconnect"
            name = (f"to {linked[n]['name']}" if n in linked else "")[:18]
            vlan = "trunk" if n in linked and linked[n]["lldp_caps"] == "B" else str(sw.spec.get("access_vlan", 10))
            duplex, speed = ("a-full", "a-1000") if status == "connected" else ("auto", "auto")
            kind = "1000BaseSX SFP" if sw.is_uplink_port(n) else "10/100/1000BaseTX"
            lines.append(f"{port_name('cisco_ios', n):<10}{name:<19}{status:<13}{vlan:<11}{duplex:>6} {speed:>6} {kind}")
        return "\n".join(lines)
    if command == "show lldp neighbors":
        lines = ["Capability codes:",
                 "    (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device",
                 "    (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other",
                 "",
                 "Device ID           Local Intf     Hold-time  Capability      Port ID"]
        rows = [(nb, p) for nb, p in nbs if p["lldp"]]
        for nb, p in rows:
            lines.append(f"{p['name'][:20]:<20}{port_name('cisco_ios', nb['local']):<15}{'120':<11}"
                         f"{p['lldp_caps'].replace(' ', ''):<16}{p['lldp_port']}")
        lines += ["", f"Total entries displayed: {len(rows)}"]
        return "\n".join(lines)
    if command == "show cdp neighbors":
        lines = ["Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge",
                 "                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone,",
                 "                  D - Remote, C - CVTA, M - Two-port Mac Relay",
                 "",
                 "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID"]
        rows = [(nb, p) for nb, p in nbs if p["cdp"]]
        for nb, p in rows:
            name = p["name"]
            platform = p["model"][:9]
            port = _cdp_short(p["cdp_port"])
            local = port_name("cisco_ios", nb["local"], "cdp")
            if len(name) > 16:
                lines.append(name)
                name = ""
            lines.append(f"{name:<17}{local:<18}{'155':<11}{p['cdp_caps']:<12}{platform:<10}{port}")
        lines += ["", f"Total cdp entries displayed : {len(rows)}"]
        return "\n".join(lines)
    if command == "show lldp neighbors detail":
        out = []
        for nb, p in nbs:
            if not p["lldp"]:
                continue
            out += ["------------------------------------------------",
                    f"Local Intf: {port_name('cisco_ios', nb['local'])}",
                    f"Chassis id: {_mac_dotted(p['mac'])}",
                    f"Port id: {p['lldp_port']}",
                    f"Port Description: {p['cdp_port']}",
                    f"System Name: {p['name']}",
                    "",
                    "System Description: ",
                    p["version_line"],
                    "",
                    "Time remaining: 101 seconds",
                    f"System Capabilities: {p['lldp_caps']}",
                    f"Enabled Capabilities: {p['lldp_caps']}",
                    "Management Addresses:"]
            out += [f"    IP: {p['ip']}"] if p["ip"] else ["    none"]
            out.append("")
        out.append(f"Total entries displayed: {sum(1 for _, p in nbs if p['lldp'])}")
        return "\n".join(out)
    if command == "show cdp neighbors detail":
        out = []
        for nb, p in nbs:
            if not p["cdp"]:
                continue
            out += ["-------------------------",
                    f"Device ID: {p['name']}",
                    "Entry address(es): "]
            out += [f"  IP address: {p['ip']}"] if p["ip"] else []
            out += [f"Platform: {p['platform']},  Capabilities: {p['cdp_caps_long']} ",
                    f"Interface: {port_name('cisco_ios', nb['local'], 'long')},  Port ID (outgoing port): {p['cdp_port']}",
                    "Holdtime : 155 sec",
                    "",
                    "Version :",
                    p["version_line"],
                    "",
                    "advertisement version: 2",
                    ""]
        return "\n".join(out)
    if command == "show ntp status":
        # the simulated clock is synchronized as soon as a server is configured
        servers = [m.group(1) for l in sw.running.top() if (m := re.match(r"^ntp server (?:vrf \S+ )?(\S+)", l))]
        if not servers:
            return "%NTP is not enabled."
        return (f"Clock is synchronized, stratum 3, reference is {servers[0]}\n"
                "nominal freq is 286.1023 Hz, actual freq is 286.1023 Hz, precision is 2**21")
    return None


def _cdp_short(port: str) -> str:
    m = re.match(r"^GigabitEthernet(\S+)$", port)
    return f"Gig {m.group(1)}" if m else port


# ---------------- Cisco Small Business ----------------

def _sb_shutdown(sw: SimSwitch, n: int) -> bool:
    block = sw.running.find_block(f"interface GigabitEthernet{n}")
    return bool(block and "shutdown" in block.children)


def sb_show(sw: SimSwitch, command: str) -> str | None:
    nbs = [(nb, _peer(nb)) for nb in sw.lab.neighbors(sw.id)]
    legacy = sw.version.startswith("1.")
    if command == "show version":
        if legacy:
            return (f"SW version    {sw.version} ( date  14-Jun-2020 time  10:21:41 )\n"
                    "Boot version    1.3.5.06 ( date  21-Jul-2013 time  15:12:10 )\n"
                    "HW version    V02")
        return (f"Active-image: flash://system/images/image_tesla_hybrid_{sw.version}_release_cisco_signed.bin\n"
                f"  Version: {sw.version}\n"
                "  MD5 Digest: 00000000000000000000000000000000")
    if command == "show inventory":
        return (f'NAME: "1"   DESCR: "{sw.spec.get("description", sw.model)}"\n'
                f"PID: {sw.model}   VID: V01   SN: {sw.spec['serial']}")
    if command == "show system":
        return "\n".join([
            f"System Description:                       {sw.spec.get('description', sw.model)}",
            "System Up Time (days,hour:min:sec):       84,04:02:11",
            "System Contact:",
            f"System Name:                              {sw.hostname}",
            "System Location:",
            f"System MAC Address:                       {sw.mac}",
            f"System Object ID:                         {sw.spec.get('sysoid', '1.3.6.1.4.1.9.6.1.95.24.1')}",
        ])
    if command == "show ip ssh":
        return "SSH Server enabled. Port: 22\nRSA key was generated."
    if command == "show services tcp-udp":
        rows = [("22", "SSH")]
        if not sw.has_line(r"^no ip telnet server$"):
            rows.append(("23", "Telnet"))
        if not sw.has_line(r"^no ip http server$"):
            rows.append(("80", "HTTP"))
        if sw.has_line(r"^ip http secure-server$"):
            rows.append(("443", "HTTPS"))
        lines = ["Type  Local IP address       Remote IP address      Service name  State",
                 "----  ---------------------  ---------------------  ------------  -----------"]
        lines += [f"TCP   {'All:' + p:<23}{'All:0':<23}{svc:<14}listen" for p, svc in rows]
        lines.append(f"TCP6  {'All-22':<23}{'All-0':<23}{'SSH':<14}listen")
        return "\n".join(lines)
    if command == "show interfaces status":
        up = sw.up_ports()
        lines = ["                                             Flow Link          Back   Mdix",
                 "Port     Type         Duplex  Speed Neg      ctrl State       Pressure Mode",
                 "-------- ------------ ------  ----- -------- ---- ----------- -------- -------"]
        for n in sw.port_numbers():
            kind = "1G-Fiber" if sw.is_uplink_port(n) else "1G-Copper"
            if n in up and not _sb_shutdown(sw, n):
                lines.append(f"{'gi' + str(n):<9}{kind:<13}Full    1000  Enabled  Off  Up          Disabled Off")
            else:
                lines.append(f"{'gi' + str(n):<9}{kind:<13}  --      --     --     --  Down           --     --")
        return "\n".join(lines)
    if command == "show interfaces configuration":
        lines = ["                                                 Flow    Admin     Back   Mdix",
                 "Port     Type         Duplex  Speed  Neg         control State     Pressure Mode",
                 "-------- ------------ ------  -----  --------    ------- -----     -------- ----"]
        for n in sw.port_numbers():
            kind = "1G-Fiber" if sw.is_uplink_port(n) else "1G-Copper"
            admin = "Down" if _sb_shutdown(sw, n) else "Up"
            lines.append(f"{'gi' + str(n):<9}{kind:<13}Full    1000   Enabled     Off     {admin:<10}Disabled Auto")
        return "\n".join(lines)
    if command == "show lldp neighbors":
        lines = ["System capability legend:",
                 "B - Bridge; R - Router; W - Wlan Access Point; T - telephone;",
                 "D - DOCSIS Cable Device; H - Host; r - Repeater;",
                 "TP - Two Ports MAC Relay; S - S-VLAN; C - C-VLAN; O - Other",
                 "",
                 "  Port        Device ID          Port ID         System Name    Capabilities  TTL",
                 "--------- ----------------- ----------------- ----------------- ------------ -----"]
        for nb, p in nbs:
            if p["lldp"]:
                lines.append(f"{'gi' + str(nb['local']):<10}{p['mac']:<18}{p['lldp_port'][:17]:<18}"
                             f"{p['name'][:17]:<18}{p['lldp_caps'][:12]:<13}110")
        return "\n".join(lines)
    if command == "show cdp neighbors":
        lines = ["Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge",
                 "                  S - Switch, H - Host, I - IGMP, r - Repeater, P - VoIP Phone,",
                 "                  M - Remotely-Managed Device, C - CAST Phone Port, W - Two-Port MAC Relay",
                 "",
                 "    Device ID       Local      Adv  Time To Capability   Platform     Port ID",
                 "                    Interface  Ver. Live",
                 "------------------ ----------- ---- ------- ---------- ------------ -----------"]
        for nb, p in nbs:
            if p["cdp"]:
                lines.append(f"{p['name'][:18]:<19}{'gi' + str(nb['local']):<12}{'2':<5}{'135':<8}"
                             f"{p['cdp_caps'][:10]:<11}{p['model'][:12]:<13}{p['cdp_port']}")
        return "\n".join(lines)
    if command == "show cdp neighbors detail":
        out = []
        for nb, p in nbs:
            if not p["cdp"]:
                continue
            out += ["---------------------------------------------",
                    f"Device-ID: {p['name']}",
                    "Advertisement version: 2",
                    "Entry address(es):"]
            out += [f"  IP address: {p['ip']}"] if p["ip"] else []
            out += [f"Platform: {p['platform']}",
                    f"Capabilities: {p['cdp_caps_long']}",
                    f"Interface: gi{nb['local']}, Port ID (outgoing port): {p['cdp_port']}",
                    "Holdtime: 135",
                    "",
                    "Version:",
                    p["version_line"],
                    ""]
        return "\n".join(out)
    if command == "show sntp status":
        servers = [m.group(1) for l in sw.running.top() if (m := re.match(r"^sntp server (\S+)", l))]
        if not servers:
            return "Clock is not synchronized"
        return f"Clock is synchronized, stratum 2, reference is {servers[0]}, unicast"
    return None


# ---------------- HPE Aruba AOS-S (ProCurve) ----------------

def _hp_disabled(sw: SimSwitch, n: int) -> bool:
    block = sw.running.find_block(f"interface {n}")
    return bool(block and "disable" in block.children)


def _hp_trunk_ports(sw: SimSwitch) -> dict[int, str]:
    from .lab import expand
    out = {}
    for line in sw.running.top():
        m = re.match(r"^trunk (\S+) (trk\d+)\b", line, re.I)
        if m:
            for n in expand(m.group(1)):
                out[n] = m.group(2).capitalize()
    return out


def hp_show(sw: SimSwitch, command: str) -> str | None:
    nbs = [(nb, _peer(nb)) for nb in sw.lab.neighbors(sw.id)]
    if command == "show version":
        return "\n".join([
            "Image stamp:    /ws/swbuildm/rel_ukiah_qaoff/code/build/bom(swbuildm_rel_ukiah_qaoff_rel_ukiah)",
            "                Mar 14 2026 10:12:42",
            f"                {sw.version}",
            "                1201",
            "Boot Image:     Primary",
            "",
            f"Boot ROM Version:    {sw.spec.get('rom', sw.version.split('.')[0] + '.17.02.0006')}",
            "Active Boot ROM:     Primary",
        ])
    if command == "show system":
        mac = re.sub(r"[^0-9a-f]", "", sw.mac.lower())
        return "\n".join([
            " Status and Counters - General System Information",
            "",
            f"  System Name        : {sw.hostname}",
            "  System Contact     :",
            "  System Location    :",
            "",
            "  MAC Age Time (sec) : 300",
            "",
            "  Time Zone          : 0",
            "  Daylight Time Rule : None",
            "",
            f"  Software revision  : {sw.version:<20} Base MAC Addr      : {mac[:6]}-{mac[6:]}",
            f"  ROM Version        : {sw.spec.get('rom', 'WC.17.02.0006'):<20} Serial Number      : {sw.spec['serial']}",
        ])
    if command == "show modules":
        return "\n".join([
            " Status and Counters - Module Information",
            "",
            f"  Chassis: {sw.spec.get('chassis', sw.model):<32} Serial Number:   {sw.spec['serial']}",
            "",
            "  Slot  Module Description                       Serial Number    Status",
            "  ----- ---------------------------------------- ---------------- -------",
        ])
    if command == "show ip ssh":
        return "\n".join([
            "  SSH Enabled     : Yes                 Secure Copy Enabled : No",
            "  TCP Port Number : 22                  Timeout (sec)       : 120",
            "  Rekey Interval  : 0 (Disabled)        Host Key Type       : RSA",
            "  Host Key/Curve Size: 2048",
            "",
            "  Ciphers : aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
            "  MACs    : hmac-sha2-256,hmac-sha2-512",
        ])
    if command == "show interfaces brief":
        trunks = _hp_trunk_ports(sw)
        up = sw.up_ports()
        lines = [" Status and Counters - Port Status",
                 "",
                 "                          | Intrusion                           MDI   Flow Bcast",
                 "  Port         Type       | Alert     Enabled Status Mode       Mode  Ctrl Limit",
                 "  ------------ ---------- + --------- ------- ------ ---------- ----- ---- ------"]
        for n in sw.port_numbers():
            name = f"{n}-{trunks[n]}" if n in trunks else str(n)
            kind = "SFP+SR" if sw.is_uplink_port(n) else "100/1000T"
            enabled = not _hp_disabled(sw, n)
            status = "Up" if enabled and n in up else "Down"
            mode = "10GigFD" if sw.is_uplink_port(n) else "1000FDx"
            mdi = "NA" if sw.is_uplink_port(n) else ("MDIX" if status == "Up" else "Auto")
            lines.append(f"  {name:<12} {kind:<10} | No        {'Yes' if enabled else 'No':<7} {status:<6} {mode:<10} {mdi:<5} off  0")
        return "\n".join(lines)
    if command == "show lldp info remote-device":
        lines = [" LLDP Remote Devices Information",
                 "",
                 "  LocalPort | ChassisId                 PortId PortDescr SysName",
                 "  --------- + ------------------------- ------ --------- ----------------------"]
        for nb, p in nbs:
            if p["lldp"]:
                lines.append(f"  {str(nb['local']):<9} | {_mac_spaced(p['mac']):<25} {p['lldp_port']:<6} "
                             f"{p['lldp_port']:<9} {p['name']}")
        return "\n".join(lines)
    if command == "show cdp neighbors":
        return "\n".join([
            " CDP neighbors information",
            "",
            "  Port   Device ID                     | Platform                     Capability",
            "  ------ ----------------------------- + ---------------------------- -----------",
        ])
    return None


RENDERERS = {"cisco_ios": ios_show, "cisco_sb": sb_show, "hp_procurve": hp_show}


def show(sw: SimSwitch, command: str) -> str | None:
    """Output of a read-only command, or None if the platform does not know it."""
    command = re.sub(r"\s+", " ", command.strip())
    if command in ("show running-config", "show run", "sh run"):
        return running_config(sw)
    return RENDERERS[sw.platform](sw, command)


def running_config(sw: SimSwitch) -> str:
    text = sw.running.text().rstrip("\n")
    if sw.platform == "cisco_ios":
        return f"Building configuration...\n\nCurrent configuration : {len(text) + 1} bytes\n{text}"
    if sw.platform == "hp_procurve":
        return f"Running configuration:\n\n{text}"
    return text
