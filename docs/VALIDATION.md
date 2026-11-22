# XSS-PG validation record

This record distinguishes automated unit-test evidence from manual end-to-end checks. The tool is designed for the local DVWA Reflected XSS (Low) training scenario only.

## Automated validation

Command:

```bash
python -m unittest discover -s tests -v
```

Latest reported result from the project team's Windows environment: **41 tests passed**.

The suite covers:

- local target validation and rejection of remote hosts, wrong ports, URL paths, and embedded credentials;
- DVWA login-page identification and connection error handling;
- fixed harmless payload generation and rejection of unsupported payloads;
- HTTP and WebSocket same-origin policy decisions;
- authentication failure, timeout reporting, and browser/context cleanup using mocked Playwright objects;
- operator-checkpoint order and separation of payload preparation from submission;
- clean CLI interruption handling.

The mocked browser lifecycle tests are unit tests. They do not replace the live browser test against DVWA.

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

Screenshots for the manual checks are stored in `docs/screenshots/`.

## Release-candidate checks still required

Before publishing `v1.0.0`, repeat these checks from a fresh clone or clean working copy:

1. Create a fresh Python virtual environment and install `requirements.txt`.
2. Install Playwright Chromium with `python -m playwright install chromium`.
3. Start the repository's DVWA Compose lab and initialize its database.
4. Install XSS-PG in editable mode and confirm `xss-pg --help` works.
5. Run the full unit-test suite.
6. Complete one live local DVWA Reflected XSS (Low) demonstration, including the separate preparation and submission checkpoints.
7. Inspect screenshots and repository files for credentials, personal information, and generated artifacts.
8. Confirm `git status` is clean before tagging the release.

Do not describe mocked tests as a live integration test. Do not describe a live test against one DVWA scenario as proof that other XSS types or applications are secure or vulnerable.
