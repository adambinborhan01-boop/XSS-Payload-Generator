"""Playwright verification for the local DVWA Reflected XSS (Low) module."""

from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from .payloads import REFLECTED_POC
from .security import ScopeError, normalize_local_target

ProgressCallback = Callable[[str], None]
CheckpointCallback = Callable[[str], None]


@dataclass(frozen=True)
class BrowserTestResult:
    verified: bool
    message: str
    target: str
    security_level: str | None = None


def _same_origin(candidate: str, target: str) -> bool:
    """Allow browser requests only to the validated target origin."""
    try:
        left = urlsplit(candidate)
        right = urlsplit(target)
        return (
            left.scheme == right.scheme
            and left.hostname == right.hostname
            and left.port == right.port
        )
    except ValueError:
        return False


def _is_dvwa_login_page(page) -> bool:
    """Return True while the DVWA login form is still present."""
    return page.locator('input[name="Login"]').count() == 1


def _report(progress_callback: ProgressCallback | None, message: str) -> None:
    if progress_callback is not None:
        progress_callback(message)


def _checkpoint(
    checkpoint_callback: CheckpointCallback | None, message: str
) -> None:
    """Pause for explicit operator acknowledgement when a callback is supplied."""
    if checkpoint_callback is not None:
        checkpoint_callback(message)


def run_reflected_xss_test(
    target: str,
    payload: str,
    username: str,
    password: str,
    timeout_ms: int = 7000,
    headless: bool = False,
    progress_callback: ProgressCallback | None = None,
    checkpoint_callback: CheckpointCallback | None = None,
    pause_for_alert: bool = False,
    input_func: Callable[[], str] | None = None,
) -> BrowserTestResult:
    """Log in, set DVWA to Low, and verify the fixed alert payload in Chromium.

    Browser requests are restricted to the validated local origin. The only
    accepted payload is the harmless XSS-PG alert proof. If ``checkpoint_callback``
    is supplied, the operator must acknowledge each major stage before the next
    action proceeds. When ``pause_for_alert`` is enabled, the browser dialog also
    remains visible until the user presses Enter. KeyboardInterrupt is allowed to
    propagate after browser cleanup so the CLI can report a clean user-initiated stop.
    """
    try:
        target = normalize_local_target(target)
    except ScopeError as exc:
        return BrowserTestResult(False, f"Blocked by local scope policy: {exc}", target)

    if payload != REFLECTED_POC:
        return BrowserTestResult(
            False,
            "Blocked: this test accepts only the built-in harmless XSS-PG payload.",
            target,
        )
    if not username.strip() or not password:
        return BrowserTestResult(False, "A DVWA username and password are required.", target)
    if timeout_ms <= 0:
        return BrowserTestResult(False, "Browser timeout must be greater than zero.", target)

    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return BrowserTestResult(
            False,
            "Playwright is not installed. Install requirements.txt and run 'playwright install chromium'.",
            target,
        )

    security_level: str | None = None
    browser = None
    context = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=headless, args=["--no-proxy-server"]
            )
            try:
                context = browser.new_context(service_workers="block")
                try:
                    def local_only(route):
                        if _same_origin(route.request.url, target):
                            route.continue_()
                        else:
                            route.abort()

                    context.route("**/*", local_only)
                    page = context.new_page()
                    page.set_default_timeout(timeout_ms)

                    _report(progress_callback, "[1/7] Local Chromium launched successfully.")
                    _checkpoint(
                        checkpoint_callback,
                        "Chromium is ready. Press ENTER to open the DVWA login page.",
                    )

                    _report(progress_callback, "[2/7] Opening the DVWA login page...")
                    page.goto(f"{target}/login.php", wait_until="domcontentloaded")
                    page.locator('input[name="username"]').fill(username.strip())
                    page.locator('input[name="password"]').fill(password)
                    page.locator('input[name="Login"]').click()
                    page.wait_for_load_state("domcontentloaded")

                    if _is_dvwa_login_page(page):
                        return BrowserTestResult(
                            False,
                            "[AUTHENTICATION FAILED] DVWA did not accept these credentials. Check the username and password.",
                            target,
                        )

                    _report(progress_callback, "[2/7] DVWA authentication successful.")
                    _checkpoint(
                        checkpoint_callback,
                        "DVWA login succeeded. Press ENTER to open security settings.",
                    )

                    _report(progress_callback, "[3/7] Opening DVWA security settings...")
                    page.goto(f"{target}/security.php", wait_until="domcontentloaded")
                    security_select = page.locator('select[name="security"]')
                    if security_select.count() != 1:
                        if _is_dvwa_login_page(page):
                            return BrowserTestResult(
                                False,
                                "[AUTHENTICATION FAILED] DVWA redirected to its login page. Check the credentials and session configuration.",
                                target,
                            )
                        return BrowserTestResult(
                            False,
                            "[SECURITY SETTINGS UNAVAILABLE] Login was accepted, but the DVWA security selector was not found. Check the DVWA version and lab setup.",
                            target,
                        )

                    security_select.select_option("low")
                    page.locator('input[name="seclev_submit"]').click()
                    page.wait_for_load_state("domcontentloaded")

                    security_cookie = next(
                        (
                            cookie["value"]
                            for cookie in context.cookies(target)
                            if cookie["name"] == "security"
                        ),
                        None,
                    )
                    if security_cookie != "low":
                        return BrowserTestResult(
                            False,
                            "[SECURITY LEVEL NOT CONFIRMED] DVWA did not confirm Low security; the XSS test was not submitted.",
                            target,
                        )
                    security_level = "low"
                    _report(progress_callback, "[3/7] DVWA security level confirmed: LOW.")
                    _checkpoint(
                        checkpoint_callback,
                        "LOW security is confirmed. Press ENTER to open the Reflected XSS module.",
                    )

                    _report(progress_callback, "[4/7] Opening the Reflected XSS module...")
                    page.goto(
                        f"{target}/vulnerabilities/xss_r/",
                        wait_until="domcontentloaded",
                    )
                    input_field = page.locator('input[name="name"]')
                    if input_field.count() != 1:
                        return BrowserTestResult(
                            False,
                            "[TEST INPUT NOT FOUND] The DVWA Reflected XSS input was not found. Confirm the installed DVWA version and login state.",
                            target,
                            security_level,
                        )

                    _report(
                        progress_callback,
                        "[4/7] Reflected XSS module loaded; the local name input is ready.",
                    )
                    _checkpoint(
                        checkpoint_callback,
                        "The local Reflected XSS form is ready. Press ENTER to place the harmless XSS-PG payload in the name field, or Ctrl+C to abort.",
                    )

                    # Prepare the proof in the form without submitting it. The
                    # next operator checkpoint deliberately separates preparation
                    # from the action that triggers the vulnerable response.
                    input_field.fill(payload)
                    _report(
                        progress_callback,
                        "[5/7] Harmless XSS-PG payload is in the name field; it has NOT been submitted.",
                    )
                    _checkpoint(
                        checkpoint_callback,
                        "The XSS-PG payload is prepared in the name field and has not been submitted. Press ENTER to submit it, or Ctrl+C to abort.",
                    )

                    _report(
                        progress_callback,
                        "[6/7] Submitting the XSS-PG proof and waiting for the browser alert...",
                    )
                    with page.expect_event("dialog", timeout=timeout_ms) as dialog_event:
                        input_field.press("Enter")

                    dialog = dialog_event.value
                    try:
                        dialog_message = dialog.message
                        if "XSS-PG" not in dialog_message:
                            return BrowserTestResult(
                                False,
                                f"[UNEXPECTED DIALOG] A browser alert appeared, but its message did not match XSS-PG: {dialog_message!r}.",
                                target,
                                security_level,
                            )

                        _report(
                            progress_callback,
                            "[7/7] Expected JavaScript alert received.",
                        )
                        _report(
                            progress_callback,
                            "[ALERT DETECTED] Browser message: XSS-PG",
                        )
                        if pause_for_alert:
                            _report(
                                progress_callback,
                                "The proof-of-execution alert is being held open. Press ENTER here to dismiss it and finish the test.",
                            )
                            (input_func or input)()
                    finally:
                        # Always dismiss the modal, including on Ctrl+C at the prompt.
                        dialog.accept()

                    return BrowserTestResult(
                        True,
                        "[VULNERABILITY VERIFIED] The browser executed the XSS-PG proof payload on DVWA Reflected XSS (Low).",
                        target,
                        security_level,
                    )
                finally:
                    if context is not None:
                        _report(progress_callback, "[*] Closing the browser context...")
                        try:
                            context.close()
                        except Exception:
                            # Browser shutdown below is still attempted if context cleanup fails.
                            pass
            finally:
                if browser is not None:
                    _report(progress_callback, "[*] Closing Chromium...")
                    try:
                        browser.close()
                    except Exception:
                        pass

    except PlaywrightTimeoutError:
        return BrowserTestResult(
            False,
            "[BROWSER TIMEOUT] The expected XSS-PG alert was not detected before the timeout. The vulnerability was not verified.",
            target,
            security_level,
        )
    except Exception as exc:
        return BrowserTestResult(
            False,
            f"[BROWSER ERROR] {type(exc).__name__}: {exc}",
            target,
            security_level,
        )
