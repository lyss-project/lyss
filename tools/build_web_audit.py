# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
"""Build the files of the in-browser audit page (site/audit.html) into site/py/:

  lyss-web.zip   the LYSS engine, adapters, spec, firmware data and fictitious example configurations
  pyodide.*      Python for the browser (Pyodide), served from lyss.dev itself: the page's security
                 policy (connect-src 'self') then forbids any other server, so a pasted
                 configuration cannot leave the browser
  pyyaml-*.whl   PyYAML for Pyodide

Pyodide comes from its npm package (checked against the registry's sha512) and the PyYAML wheel
from the Pyodide CDN; every file must also match the SHA-256 pinned below.

  python tools/build_web_audit.py [--out site/py]
then upload site/ (audit.html, audit.js, style.css, .htaccess, py/) to the web host."""

import argparse
import base64
import hashlib
import io
import json
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "lyss"

PYODIDE_VERSION = "314.0.7"
PYYAML_WHEEL = "pyyaml-6.0.3-cp314-cp314-pyemscripten_2026_0_wasm32.whl"
PYODIDE_FILES = {
    "pyodide.mjs": "6f1d60f7bf529beb300f0f47983c921d3982363640ba20af0e38efdddbc66109",
    "pyodide.asm.mjs": "f7cdc8ece80678ceb712f8e65ebe6d3a83203a180c399865f49612a051693635",
    "pyodide.asm.wasm": "cc36e3cab04fdfc9a63ff13eb52eae2b911bf46c025cc7b281f394bd3de1d5e6",
    "python_stdlib.zip": "fa1957e5777068fc4f7437f96d860ae2fbe9c19732ba06c84e004ec16dd7dd7a",
    "pyodide-lock.json": "5dc2fc119108bc148c7457dc86e7675b5c87e1cafd420b9c34c1eaef7b36c010",
    PYYAML_WHEEL: "a05d2a48c13ed72a8c60c73b30b753a25c3a591bb66c15428b7e95e69a9e806f",
}

# only what audit() needs: no collector, web interface, vault, remediation in the browser
MODULES = ("__init__.py", "engine.py", "config.py", "browser.py")
# fictitious configurations (demo lab, test fixtures), offered as "Try an example"
DEMO = SRC / "sim" / "labs" / "demo"
EXAMPLES = {
    "mikrotik.rsc": DEMO / "demo-crs-01.cfg",
    "cisco_ios.cfg": DEMO / "demo-acc-02.cfg",
    "cisco_sb.cfg": DEMO / "demo-sb-02.cfg",
    "hp_procurve.cfg": DEMO / "demo-hp-01.cfg",
    "sonic.json": DEMO / "demo-leaf-01.cfg",
    "arista_eos.cfg": ROOT / "tests" / "cases" / "arista-weak" / "config.cfg",
}
FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def _add(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, FIXED_TIME)      # same content -> same zip (stable uploads)
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, data)


def build_bundle(out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w") as zf:
        for name in MODULES:
            _add(zf, f"lyss/{name}", (SRC / name).read_bytes())
        _add(zf, "home/spec/lyss-spec.yaml", (ROOT / "spec" / "lyss-spec.yaml").read_bytes())
        _add(zf, "home/data/firmware.yaml", (ROOT / "data" / "firmware.yaml").read_bytes())
        for adapter in sorted((ROOT / "adapters").glob("*.yaml")):
            _add(zf, f"home/adapters/{adapter.name}", adapter.read_bytes())
        for name, source in EXAMPLES.items():
            _add(zf, f"examples/{name}", source.read_bytes())
    return out


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "lyss-build-web-audit"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_pyodide(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    missing = [n for n, sha in PYODIDE_FILES.items()
               if not (dest / n).exists() or _sha256((dest / n).read_bytes()) != sha]
    if not missing:
        return
    files: dict[str, bytes] = {}
    if set(missing) - {PYYAML_WHEEL}:
        meta = json.loads(_get(f"https://registry.npmjs.org/pyodide/{PYODIDE_VERSION}"))
        tgz = _get(meta["dist"]["tarball"])
        algo, digest = meta["dist"]["integrity"].split("-", 1)
        if algo != "sha512" or base64.b64decode(digest) != hashlib.sha512(tgz).digest():
            sys.exit("pyodide npm package: integrity check failed")
        with tarfile.open(fileobj=io.BytesIO(tgz)) as tf:
            for name in PYODIDE_FILES:
                if name != PYYAML_WHEEL:
                    files[name] = tf.extractfile(f"package/{name}").read()
    if PYYAML_WHEEL in missing:
        files[PYYAML_WHEEL] = _get(f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/{PYYAML_WHEEL}")
    for name, data in files.items():
        if _sha256(data) != PYODIDE_FILES[name]:
            sys.exit(f"{name}: SHA-256 differs from the pinned value, not written")
        (dest / name).write_bytes(data)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "site" / "py")
    args = parser.parse_args(argv)
    fetch_pyodide(args.out)
    build_bundle(args.out / "lyss-web.zip")
    total = sum(p.stat().st_size for p in args.out.iterdir() if p.is_file())
    print(f"{args.out}: {len(list(args.out.iterdir()))} files, {total / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
