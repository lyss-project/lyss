# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Build a fresh public repository from the current commit, without the private history.

    python tools/export_public.py --dest ../LYSS-public --email <you>@users.noreply.github.com
                                  [--name "Your Name"] [--gitleaks PATH]

What it does (nothing is pushed: the result is a local repository with one commit):
  1. exports the files of HEAD (git archive: tracked files only, so private/ never leaves);
  2. (no step: the project names no employer or sponsor; the denylist below enforces it)
  3. refuses to continue if any file matches a term of private/publish-denylist.txt (one regex per
     line: internal host names, sites, people, address plans...) or contains a private IPv4 address
     (RFC 1918) - published examples must use the documentation ranges (RFC 5737);
  4. runs gitleaks on the exported files (secrets);
  5. creates the repository with a single commit authored with the given (personal) identity.
"""

import argparse
import io
import ipaddress
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DENYLIST = ROOT / "private" / "publish-denylist.txt"
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
# real address plans (RFC 1918 + carrier-grade NAT); masks, 0.0.0.0 and RFC 5737 examples are fine
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]  # lyss-publish: allow
ALLOW = "lyss-publish: allow"  # marks a line that legitimately names a private range
TEXT_SUFFIXES = {".py", ".md", ".txt", ".yaml", ".yml", ".toml", ".cfg", ".html", ".js", ".css", ".svg",
                 ".json", ".cmd", ".ps1", ".sh", "", ".ini", ".example"}


def git(*args: str, cwd: Path = ROOT, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, **kw)


def version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else "0.0.0"


def text_files(dest: Path):
    """Every file that is text, whatever its suffix (device state captures, RouterOS exports, sample
    logs and XML carry names and addresses too); files that are not UTF-8 text are binaries."""
    for path in dest.rglob("*"):
        if path.is_file() and ".git" not in path.parts:
            try:
                yield path, path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                if path.suffix.lower() in TEXT_SUFFIXES:
                    yield path, path.read_text(encoding="utf-8", errors="replace")


def scan(dest: Path, terms: list[re.Pattern]) -> list[str]:
    problems = []
    for path, text in text_files(dest):
        rel = path.relative_to(dest).as_posix()
        problems += [f"{rel}: internal term /{term.pattern}/ in the file name" for term in terms if term.search(rel)]
        for n, line in enumerate(text.splitlines(), 1):
            for term in terms:
                if term.search(line):
                    problems.append(f"{rel}:{n}: internal term /{term.pattern}/")
            for ip in ([] if ALLOW in line else IPV4.findall(line)):
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if any(addr in net for net in PRIVATE_NETS):
                    problems.append(f"{rel}:{n}: private address {ip} (use 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", required=True, type=Path)
    ap.add_argument("--email", required=True, help="personal or GitHub no-reply address (never a company one)")
    ap.add_argument("--name", default=None, help="author name (default: git config user.name)")
    ap.add_argument("--gitleaks", default=shutil.which("gitleaks"), help="path to gitleaks (required)")
    ap.add_argument("--email-approved", action="store_true",
                    help="use --email even though it matches the denylist (the address owner approved it in writing)")
    ap.add_argument("--message", default=None, help="commit message (default: 'LYSS <version>: first public release')")
    args = ap.parse_args()

    dest = args.dest.resolve()
    if dest.exists() and any(dest.iterdir()):
        sys.exit(f"{dest} exists and is not empty: choose a new folder")
    if not DENYLIST.exists():
        sys.exit(f"missing {DENYLIST}: list the internal terms that must never be published")
    terms = [re.compile(l.strip(), re.I) for l in DENYLIST.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.lstrip().startswith("#")]
    if any(t.search(args.email) for t in terms):
        if not args.email_approved:
            sys.exit(f"refusing author e-mail {args.email}: it matches the denylist (use a personal address, "
                     "or pass --email-approved if its owner approved it)")
        print(f"note: author e-mail {args.email} matches the denylist; used because --email-approved was given")
    if not args.gitleaks or not Path(args.gitleaks).exists():
        sys.exit("gitleaks not found: pass --gitleaks <path to gitleaks.exe>")
    if git("status", "--porcelain", "--untracked-files=no").stdout.strip():
        print("warning: uncommitted changes are NOT exported (only HEAD is)")
    name = args.name or git("config", "user.name").stdout.decode().strip()

    # 1. files of HEAD only
    dest.mkdir(parents=True, exist_ok=True)
    archive = git("archive", "--format=tar", "HEAD").stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")

    # 3. internal terms and private addresses
    problems = scan(dest, terms)
    if problems:
        print("\n".join(problems[:50]))
        sys.exit(f"{len(problems)} problem(s): nothing was committed. Fix them in the private repository first.")

    # 4. secrets
    leaks = subprocess.run([args.gitleaks, "dir", str(dest), "--no-banner", "--redact", "--exit-code", "1"],
                           capture_output=True, text=True)
    if leaks.returncode != 0:
        print(leaks.stdout[-3000:], leaks.stderr[-2000:])
        sys.exit("gitleaks found possible secrets: nothing was committed")

    # 5. one commit, personal identity, no remote
    git("init", "-b", "main", cwd=dest)
    git("config", "user.name", name, cwd=dest)
    git("config", "user.email", args.email, cwd=dest)
    git("add", "-A", cwd=dest)
    git("-c", "core.hooksPath=", "commit", "-m", args.message or f"LYSS {version()}: first public release", cwd=dest)
    files = len(git("ls-files", cwd=dest).stdout.splitlines())
    print(f"OK: {dest} - 1 commit, {files} files, author {name} <{args.email}>. Nothing was pushed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
