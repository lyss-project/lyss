# LYSS tester guide

Thank you for testing LYSS. This guide takes about 15 minutes: install, try the demo (no switch
needed), then audit one real switch, and tell me what you found.

LYSS is in preview (0.6.0). Your feedback decides what gets fixed and built next.

## 1. Get the code

On https://github.com/lyss-project/lyss, click **Code → Download ZIP**, and extract it, for
example to `C:\LYSS`. If you use git: `git clone https://github.com/lyss-project/lyss.git`.

## 2. Install Python (once)

- **Windows**: install Python 3.10 or later from https://www.python.org/downloads/ and tick
  **"Add python.exe to PATH"** during the installation.
- **Linux / macOS**: Python 3.10+ with the `venv` module (Debian/Ubuntu: `sudo apt install python3-venv`, macOS: install via Homebrew `brew install python@3.11`).

## 3. Try the demo first

The demo starts six simulated switches of a fictitious company ("Demo Corp") on your PC and the
LYSS web interface on http://127.0.0.1:8766. It never touches your network.

- **Windows**: double-click **`Start-LYSS-Demo.cmd`**. The first start installs LYSS into a
  `.venv` folder (one or two minutes, needs internet access).
- **Linux / macOS**:
  ```sh
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e .
  python -m lyss demo --open
  ```

The demo **administrator password is printed once** in the console window: keep the window open
and sign in with it. Then try:

1. **Scan all** on the Switches page.
2. Open **demo-acc-02**: every failed control shows the evidence from the switch and the fix.
3. **Topology** and **Matrix**.
4. **Remediation**: tick a few fixes for demo-acc-02 and apply them (only the simulated switch
   changes), then look at the new scan on its page.
5. **Export → report** (HTML, printable to PDF).

## 4. Audit one real switch

Use a switch **you are responsible for**, ideally a lab or non-critical one first.

**What LYSS does on the switch.** It connects over SSH and runs only `show` commands (the list is
in `src/lyss/collector.py`). It never enters configuration mode, unless you enable Remediation
yourself in Settings (it is off by default). Credentials are stored encrypted on your PC, and
nothing is sent outside your network.

**The account.** LYSS does not send `enable`: the account must see the full running configuration
as soon as it logs in. Create a **dedicated account** for the test:

- Cisco IOS / IOS-XE: `username lyss-audit privilege 15 algorithm-type scrypt secret <password>`
- Cisco Business (SG/CBS): a local user with privilege level 15.
- HPE Aruba AOS-S: a manager-level account.

That account is an administrator account, so: keep Remediation disabled, allow SSH to the switch
only from your admin network, and delete the account when you have finished testing.

**Run it.**

1. **Windows**: double-click **`Start-LYSS.cmd`** (http://127.0.0.1:8765 opens).
   **Linux / macOS**: `.venv/bin/python -m lyss ui`.
2. The first start asks you to choose the LYSS administrator password.
3. **Settings → Credential profiles**: add the switch account.
4. **Add switch**: name, IP address, platform (Cisco IOS, Cisco Business or HPE Aruba), profile.
5. **Scan**, then open the switch page.

The demo and your real data are kept apart: the demo uses a temporary folder, your real data goes
to the `private` folder inside the LYSS folder.

## 5. Send your feedback

Most useful to me:

- The platform, model and firmware of the switch.
- **Wrong verdicts**: a control marked Fail that is fine on your switch, or Pass while it should
  fail. Include the control ID (for example `LYSS-MGMT-001`) and the evidence line shown.
- **Errors**: what you clicked, and the text in the console window (the error message and the
  lines above it).
- What you missed: a check, a platform, a report you need.

Where: **Issues** on the GitHub repository, or e-mail **lyaazale@lyss.dev**.

Never paste a full configuration. LYSS hides passwords, hashes, keys and SNMP communities in its
evidence, but check what you send (IP addresses and names of your network included).

## 6. Updating

Download the new ZIP into a **new folder**, then copy the **`private`** folder from the old folder
into the new one: it holds your switches, history and encrypted credentials (including
`master.key`; keep it secret). With git: `git pull` in the LYSS folder.

## Good to know

- LYSS is free software under the GNU AGPL v3 with additional terms (see `NOTICE`): the credit
  "LYSS by Mouad Lyaazale · Made in Morocco" must be kept in any copy.
- Do not post screenshots of your real network (addresses, names); screenshots of the demo are
  welcome.
- LYSS is provided as is, without warranty. You decide what runs on your network.

Thank you!
Mouad Lyaazale · lyaazale@lyss.dev