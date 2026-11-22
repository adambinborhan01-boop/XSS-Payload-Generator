# XSS Payload Generator & Tester (XSS-PG)

XSS-PG is a small Python command-line tool for generating one harmless proof-of-execution payload and verifying it against the **Reflected XSS (Low)** training module in a locally hosted **Damn Vulnerable Web Application (DVWA)** instance.

> **Scope:** local DVWA lab only. The tool does not scan arbitrary sites, crawl applications, test stored/DOM XSS, steal credentials, access cookies, exfiltrate data, persist, or perform filter-evasion.

## What it does

1. Requires an explicit authorization confirmation.
2. Accepts only `http://localhost:4280`, `http://127.0.0.1:4280`, or IPv6 loopback on port `4280`.
3. Checks that the service presents the DVWA login page before proceeding.
4. Generates a fixed alert-only payload for DVWA's Reflected XSS `name` parameter.
5. Uses Playwright to log in, set the session's DVWA security level to **Low**, submit the payload, and look for the expected browser alert.
6. Restricts browser requests to the validated local origin and closes the browser after the test.

A matching browser alert is the proof-of-execution signal. An HTTP response that merely contains the payload is not reported as a verified XSS finding.

## Requirements

- Python 3.10 or newer
- Docker Desktop / Docker Engine with Docker Compose v2
- Playwright Chromium

## 1. Start the DVWA lab

This repository includes a minimal Compose file based on the official `digininja/DVWA` project configuration. It publishes the DVWA web service only on the local loopback interface.

From the XSS-PG project directory:

```bash
docker compose up -d
```

Open the setup page:

```text
http://127.0.0.1:4280/setup.php
```

Select **Create / Reset Database**. Then open:

```text
http://127.0.0.1:4280/login.php
```

The standard disposable DVWA lab credentials are:

```text
Username: admin
Password: password
```

Change neither the host binding nor the port mapping to expose DVWA to a LAN or the public internet. DVWA is intentionally vulnerable.

Useful Docker commands:

```bash
docker compose ps
docker compose logs -f dvwa
docker compose down
```

`docker compose down` stops and removes the containers but leaves the named database volume. To remove the lab database as well, use `docker compose down -v`.

## 2. Install XSS-PG

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependency and browser:

```bash
python -m pip install -r requirements.txt
python -m playwright install chromium
```

## 3. Run

From the project root:

```bash
python -m pip install -e .
xss-pg
```

Alternatively, without installing the package:

**Windows PowerShell:**

```powershell
$env:PYTHONPATH = "src"
python -m xsspg.cli
```

**macOS / Linux:**

```bash
PYTHONPATH=src python -m xsspg.cli
```

The application displays the legal notice and asks for authorization before checking the target. The default target is `http://127.0.0.1:4280`.

Choose **1** to display the payload or **2** to run the browser verification. The browser opens visibly by default so the demonstration can be recorded. Enter the DVWA credentials when prompted (press Enter to use the standard lab password `password`); the password is not saved by XSS-PG. Use `--headless` to run Chromium without a visible window.

```bash
python -m xsspg.cli --target http://127.0.0.1:4280 --headless
```

## 4. Run tests

```bash
python -m unittest discover -s tests -v
```

The automated unit tests cover target-scope validation, payload generation, DVWA fingerprint recognition, and browser-origin/payload guards. A real browser integration test still requires the local DVWA Docker lab, working credentials, and Playwright Chromium.

## Test scenario

XSS-PG uses the DVWA **Reflected XSS** module and its `name` GET parameter. The tool authenticates to DVWA, sets the test browser's security cookie to `low`, then submits the alert-only proof payload. It reports a verified result only when the browser dialog contains the expected `XSS-PG` marker.

The default demonstration payload is:

```html
<script>alert("XSS-PG")</script>
```

This is intentionally limited to a visible alert. Do not replace it with payloads that access cookies, credentials, local storage, or transmit data.

## Safety controls and limitations

- **Authorization:** explicit confirmation is required at startup.
- **Scope:** target scheme, host and port are fixed to local HTTP loopback on port 4280; target paths, URL credentials and remote hosts are rejected.
- **Target identification:** the application checks for DVWA's login-page signature before starting a browser.
- **Browser egress:** Playwright requests are allowed only to the validated target origin.
- **Test scope:** only the Reflected XSS module at Low security is exercised.
- **Credentials:** requested interactively and used only for the local DVWA login session; not written to files or displayed.
- **Data handling:** no target data is collected or exported.
- **Kill switch:** select `Q` or press `Ctrl+C` to stop; Playwright resources are closed in cleanup.
- **Limitations:** this is a controlled proof-of-concept tester, not a general-purpose XSS scanner. A successful result demonstrates execution of this one test payload in this one DVWA configuration; a negative result does not prove the application is free of XSS.

## Rules of Engagement

- **Authorized scope:** the local DVWA container at `127.0.0.1:4280` only.
- **Testing window:** run during the group's planned lab or assessment session; stop when the session ends.
- **Permitted technique:** one harmless JavaScript alert payload submitted to DVWA Reflected XSS at Low security.
- **Prohibited actions:** remote targets, other hosts or ports, crawling, bulk scanning, stored payloads, credential attacks, cookie/session access, exfiltration, persistence, denial-of-service, and attempts to bypass protections on real systems.
- **Emergency stop:** select `Q`, press `Ctrl+C`, close the browser, and stop the Docker lab with `docker compose down`.
- **Evidence handling:** retain only screenshots and test output that contain no personal or sensitive information.

## Responsible disclosure

This project is designed for a local training target. No third-party vulnerability report should be created from tests against DVWA. If a separate, explicitly authorized assessment identifies a real vulnerability, follow the system owner's written reporting process, include reproducible non-destructive evidence, avoid accessing or retaining unrelated data, and coordinate remediation before public disclosure.

## Legal notice

Use only the local lab or systems covered by explicit written authorization. Unauthorized computer access or testing may engage the Malaysian Computer Crimes Act 1997 and other applicable laws. This notice is educational and is not legal advice.

## References

- DVWA official repository and documentation: https://github.com/digininja/DVWA
- DVWA Reflected XSS module source: https://github.com/digininja/DVWA/tree/master/vulnerabilities/xss_r
- Playwright Python documentation: https://playwright.dev/python/
- Malaysian Computer Crimes Act 1997: https://lom.agc.gov.my/ (refer to the official legislation portal)

## Project status

This is a development project. Run the tests and complete a real local DVWA browser demonstration before describing the project as fully verified or creating the `v1.0.0` release.
