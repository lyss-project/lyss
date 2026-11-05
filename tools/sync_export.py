# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Update a repository made by export_public.py with the current commit, as one new commit.

    python tools/sync_export.py --repo ../LYSS-private-export -m "Tester guide, first-start install"
                                [--gitleaks PATH] [--push]

The export repository keeps its own history (one commit per update, authored with the identity
configured in it) and never receives the private history. Every update goes through the same
checks as the first export:
  1. files of HEAD only (git archive: tracked files, so private/ never leaves);
  2. no term of private/publish-denylist.txt and no private IPv4 address (RFC 1918);
  3. gitleaks finds no secret;
then the export repository's files are replaced by the new ones (deleted files are removed),
and the change is committed. Nothing is pushed unless --push is given.
"""

import argparse
import io
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from export_public import DENYLIST, ROOT, git, scan, version  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True, type=Path, help="the export repository to update")
    ap.add_argument("-m", "--message", required=True, help="commit message (what changed, for testers)")
    ap.add_argument("--gitleaks", default=shutil.which("gitleaks"), help="path to gitleaks (required)")
    ap.add_argument("--push", action="store_true", help="push the new commit to the repository's remote")
    args = ap.parse_args()

    repo = args.repo.resolve()
    if not (repo / ".git").is_dir():
        sys.exit(f"{repo} is not a git repository (create it with tools/export_public.py)")
    if repo == ROOT or ROOT in repo.parents:
        sys.exit("the export repository must be outside the private repository")
    if git("status", "--porcelain", cwd=repo).stdout.strip():
        sys.exit(f"{repo} has uncommitted changes: commit or discard them first")
    # never overwrite work merged on the remote (e.g. a contributor's pull request)
    if subprocess.run(["git", "rev-parse", "--abbrev-ref", "@{u}"], cwd=repo, capture_output=True).returncode == 0:
        fetched = subprocess.run(["git", "fetch", "--quiet"], cwd=repo, capture_output=True, text=True)
        if fetched.returncode != 0:
            sys.exit(f"cannot fetch the remote of {repo}: {fetched.stderr.strip()[:300]}")
        unknown = git("rev-list", "--count", "HEAD..@{u}", cwd=repo).stdout.decode().strip()
        if unknown != "0":
            sys.exit(f"the remote has {unknown} commit(s) that are not in {repo} (merged pull requests?).\n"
                     "Bring those changes into the private repository first, then run "
                     "`git pull --ff-only` in the export repository, and sync again.")
    if not args.gitleaks or not Path(args.gitleaks).exists():
        sys.exit("gitleaks not found: pass --gitleaks <path to gitleaks.exe>")
    if git("status", "--porcelain", "--untracked-files=no").stdout.strip():
        print("warning: uncommitted changes of the private repository are NOT exported (only HEAD is)")
    terms = [re.compile(l.strip(), re.I) for l in DENYLIST.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.lstrip().startswith("#")]

    with tempfile.TemporaryDirectory(prefix="lyss-sync-") as tmp:
        new = Path(tmp)
        with tarfile.open(fileobj=io.BytesIO(git("archive", "--format=tar", "HEAD").stdout)) as tar:
            tar.extractall(new, filter="data")
        problems = scan(new, terms)
        if problems:
            print("\n".join(problems[:50]))
            sys.exit(f"{len(problems)} problem(s): nothing was changed. Fix them in the private repository first.")
        leaks = subprocess.run([args.gitleaks, "dir", str(new), "--no-banner", "--redact", "--exit-code", "1"],
                               capture_output=True, text=True)
        if leaks.returncode != 0:
            print(leaks.stdout[-3000:], leaks.stderr[-2000:])
            sys.exit("gitleaks found possible secrets: nothing was changed")

        # replace the tracked files of the export repository by the new tree
        for rel in git("ls-files", "-z", cwd=repo).stdout.decode().split("\0"):
            if rel:
                (repo / rel).unlink(missing_ok=True)
        for src in new.rglob("*"):
            if src.is_file():
                dst = repo / src.relative_to(new)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
    for d in sorted((p for p in repo.rglob("*") if p.is_dir() and ".git" not in p.parts), reverse=True):
        if not any(d.iterdir()):
            d.rmdir()

    git("add", "-A", cwd=repo)
    git("add", "--renormalize", ".", cwd=repo)  # apply .gitattributes changes (e.g. CRLF for *.cmd)
    stat =git("diff", "--cached", "--stat", cwd=repo).stdout.decode().strip()
    if not stat:
        print("No change since the last update: nothing to commit.")
        return 0
    print(stat)
    git("-c", "core.hooksPath=", "commit", "-m", f"LYSS {version()}: {args.message}", cwd=repo)
    head = git("log", "-1", "--format=%h %an <%ae>", cwd=repo).stdout.decode().strip()
    print(f"OK: committed {head} in {repo}.")
    if args.push:
        out = subprocess.run(["git", "push"], cwd=repo, capture_output=True, text=True)
        print(out.stdout + out.stderr)
        if out.returncode != 0:
            sys.exit("push failed: the commit stays local")
        print("Pushed.")
    else:
        print("Nothing was pushed (add --push, or run git push in the export repository).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
