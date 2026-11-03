# Contributing

Only the non-obvious things.

- **The runtime is one file, standard library only, Python 3.9+.**
  `src/fingerbot/__init__.py` is deployed by copying it alone, so it may not
  import anything outside the stdlib, may not import a sibling module, and
  must parse and run on 3.9 (no `match`, no `X | Y` outside annotations, no
  `zip(strict=)`; ruff targets py39 to catch these). `dependencies = []`
  stays empty. Run the whole gate under 3.9 before merging, as CI does:

  ```
  UV_PROJECT_ENVIRONMENT=/tmp/fb-venv39 uv run --python 3.9 scripts/check.py
  ```

  The tuya-ble cross-checks skip there (it needs 3.10+), so tests must reach
  it and bleak only through `pytest.importorskip`; everything else, including
  100% coverage and both type checkers, must pass.
- **uv only for development.** `uv sync`, `uv run`, `uv add`. The build
  backend is `uv_build` and stays that way. `pycryptodome` and `tuya-ble` are
  dev-only reference implementations the tests cross-check against; never
  import them from the module.
- **The test suite must never touch a radio.** `tests/conftest.py` replaces
  the L2CAP socket with `FakeLink`, behind which `FakeFingerbot` speaks ATT
  and Tuya BLE v3 and records every frame it receives. An autouse fixture
  makes any call to the real `att_connect` fail. If a change makes something
  testable only against real hardware, restructure the change.
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
- **`fingerbot info` must never actuate.** `Session(actuate=False)` (the
  default) refuses `FUN_SENDER_DPS` and every code off a short read-only
  allow-list, before anything reaches the socket. `actuate` is keyword-only;
  only `press()` passes `actuate=True`, and an AST test fails if any other
  call site does. Tests
  also run `info` end to end against the fake device and assert it received
  no datapoint write. Keep all of that true.
- Scope: this tool clicks once and exits. Retries, scheduling and policy
  ("should I press?") belong to the caller.
