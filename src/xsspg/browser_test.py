"""Playwright verification for the local DVWA Reflected XSS (Low) module."""

from dataclasses import dataclass
from urllib.parse import urlsplit

from .payloads import REFLECTED_POC
from .security import ScopeError, normalize_local_target


@dataclass(frozen=True)
class BrowserTestResult:
    verified: bool
    message: str
    target: str
    security_level: str = "low"


def _same_origin(candidate: str, target: str) -> bool:
    """Allow browser requests only to the validated target origin."""
    left = urlsplit(candidate)
    right = urlsplit(target)
    return (
        left.scheme == right.scheme
        and left.hostname == right.hostname
        and left.port == right.port
    )


def run_reflected_xss_test(
    target: str,
    payload: str,
    username: str,
    password: str,
    timeout_ms: int = 7000,
    headless: bool = False,
) -> BrowserTestResult:
    """Log in, set DVWA to Low, and verify the fixed alert payload in Chromium.

    Browser network requests are restricted to the already validated local
    origin. The only accepted payload is the harmless XSS-PG alert proof.
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

    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return BrowserTestResult(
            False,
            "Playwright is not installed. Run 'pip install -r requirements.txt' and 'playwright install chromium'.",
            target,
        )

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

                    page.goto(f"{target}/login.php", wait_until="domcontentloaded")
                    page.locator('input[name="username"]').fill(username.strip())
                    page.locator('input[name="password"]').fill(password)
                    page.locator('input[name="Login"]').click()

                    # An authenticated DVWA page exposes its security selector.
                    page.goto(f"{target}/security.php", wait_until="domcontentloaded")
                    security_select = page.locator('select[name="security"]')
                    if security_select.count() != 1:
                        return BrowserTestResult(
                            False,
                            "DVWA login failed or the security settings page was unavailable. Check the lab credentials and database setup.",
                            target,
                        )

                    security_select.select_option("low")
                    page.locator('input[name="seclev_submit"]').click()
                    page.wait_for_load_state("domcontentloaded")

                    security_cookie = next(
                        (cookie["value"] for cookie in context.cookies(target) if cookie["name"] == "security"),
                        None,
                    )
                    if security_cookie != "low":
                        return BrowserTestResult(
                            False,
                            "Could not confirm DVWA security level Low; test was not submitted.",
                            target,
                        )

                    page.goto(f"{target}/vulnerabilities/xss_r/", wait_until="domcontentloaded")
                    input_field = page.locator('input[name="name"]')
                    if input_field.count() != 1:
                        return BrowserTestResult(
                            False,
                            "DVWA Reflected XSS input was not found. Confirm the installed DVWA version and login state.",
                            target,
                        )

                    with page.expect_event("dialog", timeout=timeout_ms) as dialog_event:
                        input_field.fill(payload)
                        input_field.press("Enter")

                    dialog = dialog_event.value
                    dialog_message = dialog.message
                    dialog.accept()

                    if "XSS-PG" in dialog_message:
                        return BrowserTestResult(
                            True,
                            "[VULNERABILITY VERIFIED] The browser executed the XSS-PG proof payload on DVWA Reflected XSS (Low).",
                            target,
                        )
                    return BrowserTestResult(
                        False,
                        f"A browser dialog appeared, but its message did not match the expected marker: {dialog_message!r}.",
                        target,
                    )
                finally:
                    context.close()
            finally:
                browser.close()

    except PlaywrightTimeoutError:
        return BrowserTestResult(
            False,
            "No matching browser alert was detected before timeout. The vulnerability was not verified.",
            target,
        )
    except Exception as exc:  # Keep CLI failures controlled and actionable.
        return BrowserTestResult(False, f"Browser test failed: {type(exc).__name__}: {exc}", target)
