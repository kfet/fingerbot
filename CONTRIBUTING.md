# Contributing

Only the non-obvious things.

- **uv only.** `uv sync`, `uv run`, `uv add`. The build backend is `uv_build`
  and stays that way; no hatchling, no hand-rolled venvs, no `pip install`,
  no distro Python packages (distro `bleak` is 2.x, and this needs 3.x, whose
  API differs materially).
- **The test suite must never touch a radio.** `bleak`, `tuya_ble` and
  `subprocess.run` are all mocked in `tests/conftest.py`; tests pass on a host
  with no Bluetooth controller at all. If a change makes something testable
  only against real hardware, restructure the change.
- **One command runs everything**: `uv run scripts/check.py` — ruff, ty,
  pyrefly, pytest, in that order, stopping at the first failure and naming it.
  Do not add a step to CI or to the hook; add it to `scripts/check.py`, which
  both of them call. Keeping a single definition of "the checks pass" is the
  point.
- **Turn on the commit hook once per clone**:

  ```
  git config core.hooksPath .githooks
  ```

  `.githooks/pre-commit` then runs the gate before every commit. It is a
  tracked shell script — there is no hook framework to install. Bypass a
  single commit with `git commit --no-verify` (for a WIP commit on a branch,
  say); CI still runs the same gate, so nothing slips through to `main`.
  Note the hook checks the working tree, not the staged snapshot: it does not
  stash, so it can never lose your unstaged work.
- **Four checks, all of which must be clean**: `ruff check`, `ty check`,
  `pyrefly check`, `pytest`. The two type checkers are intentional — they are
  pre-1.0 and catch different things (pyrefly is flow-sensitive about
  possibly-unbound locals; ty is stricter about override signatures). Fix the
  code rather than silencing a checker; if something is genuinely a false
  positive, suppress it on the single line with a comment saying why.
- **Type annotations are expected on new code**, including in the tests, which
  are type-checked too — a fake with a wrong signature is a test that proves
  nothing.
- **Coverage is gated at 100%** (`--cov-fail-under=100` in `pyproject.toml`).
  Do not lower it, and prefer deleting untestable code to adding `# pragma:
  no cover`.
- **Do not write `dp1` to actuate.** It is the latching switch state, and
  writing it makes the arm press twice. `dp108` is the momentary click.
- **`fingerbot info` must never actuate.** There is a test asserting that no
  datapoint is assigned on the info path; keep it true.
- Scope: this tool clicks once and exits. Retries, scheduling and policy
  ("should I press?") belong to the caller.
