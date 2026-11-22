# XSS-PG implementation and release plan

This plan records the actual Git history and remaining work. Commits are created only after the corresponding work exists and passes its acceptance checks. Do not backdate commits or manufacture earlier development history.

## Commit 1 — completed

**Commit:** `753ceda chore: add DVWA XSS-PG project baseline`

**Contents:** Initial project baseline with Python CLI, local DVWA scope checks, one harmless Reflected XSS payload, Playwright browser test, README, Docker Compose lab, and initial unit tests.

## Commit 2 — completed

**Commit:** `4c3a558 feat: add interactive XSS testing checkpoints`

**Contents:** Improved authentication and failure messages, visible browser progress, operator checkpoints, separate payload preparation and submission, visible alert acknowledgement, cleanup tests, CLI interruption handling, and genuine local screenshots.

**Verification:** The group reported 37/37 automated tests passing and confirmed the Windows DVWA workflow, including the separate Enter checkpoint before form submission.

## Commit 3 — current work: browser-origin hardening and documentation accuracy

**Proposed message:** `fix: enforce local WebSocket scope and align security documentation`

**Scope:** Extend the existing local-origin policy to WebSocket connections, correct the documented target scope so it matches the IPv4/localhost implementation, and align the Playwright minimum version with the WebSocket routing API used by the code.

**Acceptance checks:** same-origin local WebSockets are forwarded; remote or user-info WebSockets are closed; HTTP origin checks continue to pass; the full unit suite passes; a live local DVWA test still succeeds; README and dependency declarations match the implementation.

## Commit 4 — planned: final validation and reproducibility

**Proposed message:** `test: strengthen final validation and setup evidence`

**Scope:** Review edge cases, verify the documented clean installation procedure, confirm screenshots and troubleshooting steps, and run the final local DVWA demonstration from the README instructions.

**Acceptance checks:** tests pass in a clean virtual environment; the local DVWA test succeeds on the team's machine; evidence contains no credentials or sensitive information; the repository is reproducible from documented steps.

## Commit 5 — planned: release readiness

**Proposed message:** `chore: prepare XSS-PG v1.0.0 release`

**Scope:** Final cleanup, version/release notes, final test run, and GitHub Release `v1.0.0` after the live demonstration succeeds.

**Acceptance checks:** all unit tests pass in a clean environment; the live DVWA test succeeds; `git status` is clean; the public repository contains no secrets or generated environments; release notes accurately describe the tool's limited scope.

## Commit discipline

- Each commit should contain only the work described by its message.
- Run relevant tests before committing.
- Keep real development history; never create a commit to imitate work that did not happen.
- The final repository must show at least five meaningful commits and a `v1.0.0` release.
