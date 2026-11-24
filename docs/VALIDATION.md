# XSS-PG validation record

This record distinguishes automated unit-test evidence from manual end-to-end checks. XSS-PG is designed for one authorized training scenario: the local DVWA Reflected XSS module at Low security.

## Automated validation

Command:

```bash
python -m unittest discover -s tests -v
```

**Latest reported result from the project team's Windows environment: 47 tests passed.** The same 47-test suite passed in the separate release-test virtual environment described below.

The suite covers:

- local target validation and rejection of remote hosts, wrong ports, URL paths, and embedded credentials;
- DVWA login-page identification and connection error handling;
- harmless payload generation consist of four built-in variants, and support rejection for any irrelevant payloads or unknown variant names;
- local JSONL result logging, including that it degrades to give warning (not a crash) when the directory file output cannot be written;
- HTTP and WebSocket same-origin policy decisions;
- authentication failure, timeout reporting, and browser/context cleanup using mocked Playwright objects;
- operator-checkpoint order and separation of payload preparation from submission;
- clean CLI interruption handling.

The mocked browser lifecycle tests are unit tests. They do not replace the live browser test against DVWA.

## Release-test environment

The project team reported the following verification on Windows:

- Created a separate Python 3.14 virtual environment at `%TEMP%\xss-pg-release-test`.
- Installed the project from the working project directory with `python -m pip install --no-cache-dir -e .`.
- Installed Playwright Chromium with `python -m playwright install chromium`.
- Confirmed with `python -m pip show xss-pg` that the installed package version was `1.0.0`.
- Ran the full unit-test suite: **41 tests passed**.
- Launched the installed `xss-pg` command and completed the live DVWA Reflected XSS (Low) workflow.

**Scope of this check:** This was a fresh virtual environment, but the package was installed in editable mode from the existing project working tree. It was not a fresh Git clone. The DVWA instance had already been deployed and initialized locally; a clean-room Docker Compose deployment from a fresh clone was not part of this test.

## Manual checks reported by the project team

| Check | Observed result |
|---|---|
| Application startup and local DVWA identification | Passed |
| Authorization declined | Exited without testing |
| Incorrect DVWA credentials | Reported authentication failure and returned to the menu |
| DVWA stopped / connection refused | Reported that the local target was unavailable and exited cleanly |
| Ctrl+C while collecting credentials | Exited cleanly without a traceback |
| Payload generation | Displayed the fixed alert-only payload for the `name` parameter |
| Live Reflected XSS (Low) test | Browser displayed the expected `XSS-PG` alert and the tool reported verification |
| Payload preparation checkpoint | Filled the `name` field without submitting the form |
| Separate submission checkpoint | Required a second Enter before submitting the form |
| Live test after WebSocket-scope hardening | Completed successfully against the local DVWA instance |
| Release-test environment | Installed package version `1.0.0`, passed all 47 tests, and completed the live DVWA workflow |

Screenshots for the manual checks are stored in `docs/screenshots/`.

## Published release

- Package version: `1.0.0`.
- GitHub repository: https://github.com/adambinborhan01-boop/XSS-Payload-Generator
- Published GitHub Release: https://github.com/adambinborhan01-boop/XSS-Payload-Generator/releases/tag/v1.0.0
- Release tag `v1.0.0` points to commit `dc02bd5` (`release: prepare XSS-PG v1.0.0`).

## Interpretation and limitations

- Playwright lifecycle unit tests use mocks; they verify control flow and cleanup but do not themselves execute a real browser test.
- The live browser demonstration verifies one harmless proof-of-execution payload against one DVWA module and one security configuration: Reflected XSS at Low.
- A successful result does not establish that other XSS types, other applications, or other security levels are vulnerable or secure.
- A negative result does not prove that an application is free of XSS.
- The release-test procedure above verifies a fresh Python environment, not a fresh source clone or an independently initialized Docker lab.
