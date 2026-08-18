#!/usr/bin/env python3
"""Run the whole quality gate: ruff, ty, pyrefly, pytest.

This is the single definition of "the checks pass". CI calls it, the
pre-commit hook calls it, and you call it:

    uv run scripts/check.py

It fails fast: the first failing checker stops the run, names itself, and
sets a non-zero exit code. Standard library only -- no task runner, no
`make`, nothing to install beyond `uv sync`.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# In order. Fail fast: cheapest and most likely to fire comes first.
GATE: list[tuple[str, list[str]]] = [
    ("ruff", ["ruff", "check"]),
    ("ty", ["ty", "check"]),
    ("pyrefly", ["pyrefly", "check"]),
    ("pytest", ["pytest"]),
]

# Where `uv run` put this interpreter -- .venv/bin (or .venv\Scripts).
BIN = Path(sys.executable).parent
ROOT = Path(__file__).resolve().parent.parent


def _resolve(tool: str) -> Path | None:
    for candidate in (BIN / tool, BIN / f"{tool}.exe"):
        if candidate.exists():
            return candidate
    return None


def main() -> int:
    for name, argv in GATE:
        exe = _resolve(argv[0])
        if exe is None:
            print(f"\n=== GATE ERROR: {name} is not installed in {BIN}", file=sys.stderr)
            print("run `uv sync` first", file=sys.stderr)
            return 2

        print(f"\n=== {name} " + "=" * (60 - len(name)), flush=True)
        result = subprocess.run([str(exe), *argv[1:]], cwd=ROOT)
        if result.returncode != 0:
            print(f"\n=== GATE FAILED: {name} (exit {result.returncode})", file=sys.stderr)
            print("fix it, or re-run just that step: "
                  f"uv run {' '.join(argv)}", file=sys.stderr)
            return result.returncode

    print("\n=== GATE PASSED: ruff, ty, pyrefly, pytest all clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
