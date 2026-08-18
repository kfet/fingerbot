#!/usr/bin/env python3
"""Cut a release: gate, bump, tag, push.

    uv run scripts/release.py patch|minor|major

Stdlib only, same as scripts/check.py. The version lives in exactly one
place (pyproject.toml, bumped by `uv version`); the tag is derived from it,
never typed by hand. Tag push is what triggers the release workflow.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRANCH = "main"


def die(msg: str) -> None:
    print(f"release: {msg}", file=sys.stderr)
    raise SystemExit(1)


def run(*args: str, capture: bool = True) -> str:
    r = subprocess.run(args, cwd=ROOT, text=True, capture_output=capture)
    if r.returncode != 0:
        if capture:
            sys.stderr.write(r.stdout or "")
            sys.stderr.write(r.stderr or "")
        die(f"command failed: {' '.join(args)}")
    return (r.stdout or "").strip()


def version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        die("no version in pyproject.toml")
        raise AssertionError  # unreachable, keeps type checkers happy
    return m.group(1)


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("patch", "minor", "major"):
        print(__doc__)
        return 2
    bump = sys.argv[1]

    if run("git", "rev-parse", "--abbrev-ref", "HEAD") != BRANCH:
        die(f"not on {BRANCH}")
    if run("git", "status", "--porcelain"):
        die("working tree is dirty")

    print("=== gate ===")
    if subprocess.run([sys.executable, "scripts/check.py"], cwd=ROOT).returncode != 0:
        die("gate failed; nothing released")

    run("uv", "version", "--bump", bump)
    tag = f"v{version()}"
    if run("git", "tag", "--list", tag):
        die(f"tag {tag} already exists")

    run("git", "add", "pyproject.toml", "uv.lock")
    run("git", "commit", "-m", f"release {tag}")
    run("git", "tag", "-a", tag, "-m", tag)
    run("git", "push", "origin", BRANCH)
    run("git", "push", "origin", tag)

    print(f"=== released {tag} ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
