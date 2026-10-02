#!/usr/bin/env python3
"""Build the static site for cbom.actaseal.com into web/dist/.

Everything is self-hosted: Pyodide (Python compiled to WebAssembly), the
wheels cbom_check needs, and cbom_check.py itself. The page makes no
third-party requests and the user's files never leave the browser.

Usage:  python web/build.py [--out web/dist]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

WEB = Path(__file__).resolve().parent
ROOT = WEB.parent

PYODIDE_VERSION = "314.0.7"
PYODIDE_URL = (f"https://github.com/pyodide/pyodide/releases/download/"
               f"{PYODIDE_VERSION}/pyodide-{PYODIDE_VERSION}.tar.bz2")
PYODIDE_SHA256 = "192b5864e6e6d30ab074861af800cb8b4acb0998ef0f9342c3367448aeb86645"
PYODIDE_CORE = ["pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm",
                "python_stdlib.zip", "pyodide-lock.json"]
# Requirements that Pyodide ships prebuilt (rpds-py is compiled, so it must
# come from Pyodide); their dependencies are resolved from pyodide-lock.json.
PYODIDE_PACKAGES = ["jsonschema", "jsonpointer", "sortedcontainers", "idna",
                    "python-dateutil", "tzdata", "typing-extensions"]
SITE_FILES = ["index.html", "app.js", ".htaccess"]
SAMPLES = ["clean.json", "nist_level_mismatch.json", "no_classical_algorithms.json"]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_pyodide(cache: Path) -> Path:
    tarball = cache / f"pyodide-{PYODIDE_VERSION}.tar.bz2"
    if not tarball.exists() or sha256(tarball) != PYODIDE_SHA256:
        cache.mkdir(parents=True, exist_ok=True)
        print(f"downloading {PYODIDE_URL}")
        tmp = tarball.with_suffix(".part")
        urllib.request.urlretrieve(PYODIDE_URL, tmp)
        tmp.replace(tarball)
    if sha256(tarball) != PYODIDE_SHA256:
        sys.exit(f"sha256 mismatch for {tarball}")
    return tarball


def lock_closure(lock: dict, roots: list[str]) -> list[str]:
    pkgs = lock["packages"]
    norm = {k.lower().replace("_", "-"): k for k in pkgs}
    seen: list[str] = []
    stack = list(roots)
    while stack:
        name = norm[stack.pop().lower().replace("_", "-")]
        if name not in seen:
            seen.append(name)
            stack.extend(pkgs[name]["depends"])
    return sorted(seen)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(WEB / "dist"))
    ap.add_argument("--cache", default=str(WEB / ".cache"))
    args = ap.parse_args()
    out = Path(args.out)

    if out.exists():
        shutil.rmtree(out)
    (out / "pyodide").mkdir(parents=True)
    (out / "wheels").mkdir()
    (out / "samples").mkdir()

    tarball = fetch_pyodide(Path(args.cache))
    with tarfile.open(tarball, "r:bz2") as tf:
        lock = json.load(tf.extractfile("pyodide/pyodide-lock.json"))
        names = lock_closure(lock, PYODIDE_PACKAGES)
        wanted = PYODIDE_CORE + [lock["packages"][n]["file_name"] for n in names]
        for fname in wanted:
            data = tf.extractfile(f"pyodide/{fname}").read()
            (out / "pyodide" / fname).write_bytes(data)
    for n in names:
        meta = lock["packages"][n]
        if sha256(out / "pyodide" / meta["file_name"]) != meta["sha256"]:
            sys.exit(f"sha256 mismatch for {meta['file_name']}")

    subprocess.run([sys.executable, "-m", "pip", "download", "--quiet", "--no-deps",
                    "--only-binary=:all:", "--require-hashes", "-r", str(WEB / "wheels.txt"),
                    "-d", str(out / "wheels")], check=True)
    wheels = sorted(p.name for p in (out / "wheels").glob("*.whl"))
    for w in wheels:
        if not (w.endswith("-none-any.whl")):
            sys.exit(f"{w} is not a pure-Python wheel")

    for f in SITE_FILES:
        shutil.copy(WEB / f, out / f)
    shutil.copy(ROOT / "cbom_check.py", out / "cbom_check.py")
    for f in SAMPLES:
        shutil.copy(ROOT / "fixtures" / f, out / "samples" / f)
    (out / "deps.json").write_text(json.dumps(
        {"pyodide": names, "wheels": wheels, "samples": SAMPLES}, indent=2))

    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    print(f"built {out} ({size / 1e6:.1f} MB): {len(names)} Pyodide packages, {len(wheels)} wheels")


if __name__ == "__main__":
    main()
