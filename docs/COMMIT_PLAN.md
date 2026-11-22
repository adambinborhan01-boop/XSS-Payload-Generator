# Proposed five-commit implementation plan

This is a prospective work plan, not a record of commits that have already happened. Create each commit only when the corresponding implementation is completed and tested. Do not backdate commits or claim planned work was completed earlier.

## Commit 1 — `chore: create Python project scaffold`

**Files:** package layout, `pyproject.toml`, `requirements.txt`, `.gitignore`, starter README.

**Acceptance checks:** fresh virtual environment installs dependencies; CLI starts and displays help.

## Commit 2 — `feat: enforce authorization and local DVWA scope`

**Files:** `security.py`, `target.py`, `test_scope.py`, `test_target.py`, Compose lab configuration, related CLI wiring.

**Acceptance checks:** authorization refusal exits; default target is loopback port 4280; remote hosts and non-approved ports are rejected; DVWA login-page fingerprint is required; target failure is handled cleanly.

## Commit 3 — `feat: add harmless DVWA reflected XSS payload generation`

**Files:** `payloads.py`, `test_payloads.py`.

**Acceptance checks:** the reflected profile returns a structured payload for the `name` parameter; unsupported profiles fail safely; the payload only displays the XSS-PG alert marker and does not collect or transmit data.

## Commit 4 — `feat: verify DVWA reflected XSS with Playwright`

**Files:** `browser_test.py`, browser guard tests, CLI integration.

**Acceptance checks:** the browser is limited to the validated local origin; the tool logs into DVWA, sets the session security level to Low, submits the payload to the Reflected XSS form, detects the expected dialog, and closes browser resources on success, failure, timeout, and interruption.

## Commit 5 — `test: harden CLI and finalize v1.0.0 release`

**Files:** expanded tests, final README / Rules of Engagement, screenshots or demo evidence, release notes.

**Acceptance checks:** unit tests pass on a clean environment; real DVWA browser demonstration succeeds; help and error paths are checked; GitHub Release `v1.0.0` is created only after the code is actually complete.

## Commit discipline

Each commit should contain only the work described by its message. Run relevant tests before committing. The final repository should show five genuine, incremental commits authored by the team members who performed the work.
