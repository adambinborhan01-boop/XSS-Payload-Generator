# XSS-PG implementation and release plan

This plan records the actual starting point and the remaining work. Create commits only after the described changes exist and their acceptance checks pass. Do not backdate commits or manufacture earlier development history.

## Commit 1 — completed

**Commit:** `chore: add DVWA XSS-PG project baseline`

**Contents:** Initial project baseline with Python CLI, local DVWA scope checks, one harmless Reflected XSS payload, Playwright browser test, README, Docker Compose lab, and initial unit tests.

## Commit 2 — current work

**Proposed message:** `fix: improve DVWA test feedback and failure handling`

**Files:** `browser_test.py`, `cli.py`, `target.py`, corresponding tests, and README updates.

**Acceptance checks:** distinguish authentication failure from unavailable security settings; show progress through the browser workflow; require Enter at operator checkpoints after Chromium launch, successful login, Low-security confirmation, and before payload preparation and again after preparation immediately before submission; keep payload preparation and form submission as separate actions; keep the successful alert open until Enter in visible mode; provide a clear timeout result; avoid misleading security-level output on early failure; close browser/context on success, failure, timeout, and Ctrl+C at a checkpoint; keep the full unit suite passing; repeat the live DVWA test.

## Commit 3 — planned: optional local test report

**Proposed message:** `feat: add opt-in local test result report`

**Scope:** Add an explicit opt-in report containing only non-sensitive test metadata (timestamp, local target, module, configured security level, and outcome). Do not store credentials, session cookies, or browser data. Default behavior remains no file output.

**Acceptance checks:** report is created only when requested; output directory is local and git-ignored; tests confirm no credentials or cookies are written.

## Commit 4 — planned: documentation and evidence

**Proposed message:** `docs: add verified setup and demonstration evidence`

**Scope:** Finalize installation and troubleshooting guidance, add screenshots captured from the team's own live run, explain limitations, and ensure the README matches actual behavior.

**Acceptance checks:** a teammate can reproduce the local setup from the README; screenshots contain no credentials or sensitive information; all claims are supported by actual tests.

## Commit 5 — planned: release readiness

**Proposed message:** `chore: prepare XSS-PG v1.0.0 release`

**Scope:** Final cleanup, version/release notes, final test run, and GitHub Release `v1.0.0` after the live demonstration succeeds.

**Acceptance checks:** all unit tests pass in a clean environment; the live DVWA test succeeds; `git status` is clean; public repository contains no secrets or generated environments; release notes accurately describe the tool's limited scope.

## Commit discipline

- Each commit should contain only the work described by its message.
- Run relevant tests before committing.
- Keep real development history; never create a commit to imitate work that did not happen.
- The final repository must show at least five meaningful commits and a `v1.0.0` release.
