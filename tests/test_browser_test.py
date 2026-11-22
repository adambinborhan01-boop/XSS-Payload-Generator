import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from xsspg.browser_test import (
    _is_dvwa_login_page,
    _route_local_websocket,
    _same_origin,
    run_reflected_xss_test,
)
from xsspg.payloads import REFLECTED_POC


class FakePlaywrightTimeout(Exception):
    pass


class FakeLocator:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    def count(self):
        if self.selector == 'input[name="Login"]':
            return 1 if not self.page.login_ok else 0
        if self.selector == 'select[name="security"]':
            return 1 if self.page.security_selector else 0
        if self.selector == 'input[name="name"]':
            return 1
        return 1

    def fill(self, value):
        self.page.actions.append(("fill", self.selector, value))
        if self.selector == 'input[name="username"]' and self.page.interrupt_on_username:
            raise KeyboardInterrupt

    def click(self):
        self.page.actions.append(("click", self.selector))
        return None

    def select_option(self, value):
        self.page.selected_security = value
        self.page.actions.append(("select", self.selector, value))

    def press(self, key):
        self.page.actions.append(("press", self.selector, key))
        return None


class FakeDialog:
    message = "XSS-PG"

    def __init__(self):
        self.accepted = False

    def accept(self):
        self.accepted = True


class FakeDialogWaiter:
    def __init__(self, page):
        self.page = page
        self.value = self.page.dialog

    def __enter__(self):
        if self.page.timeout_on_dialog:
            raise FakePlaywrightTimeout
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class FakePage:
    def __init__(
        self,
        *,
        login_ok=True,
        security_selector=True,
        timeout_on_dialog=False,
        interrupt_on_username=False,
    ):
        self.login_ok = login_ok
        self.security_selector = security_selector
        self.timeout_on_dialog = timeout_on_dialog
        self.interrupt_on_username = interrupt_on_username
        self.dialog = FakeDialog()
        self.selected_security = None
        self.actions = []

    def goto(self, url, wait_until=None):
        self.actions.append(("goto", url))
        return None

    def locator(self, selector):
        return FakeLocator(self, selector)

    def set_default_timeout(self, timeout):
        return None

    def wait_for_load_state(self, state):
        return None

    def expect_event(self, event, timeout):
        return FakeDialogWaiter(self)


class FakeWebSocketRoute:
    def __init__(self, url):
        self.url = url
        self.connected = False
        self.closed = False
        self.close_code = None
        self.close_reason = None

    def connect_to_server(self):
        self.connected = True

    def close(self, code=None, reason=None):
        self.closed = True
        self.close_code = code
        self.close_reason = reason


class FakeContext:
    def __init__(self, page):
        self.page = page
        self.closed = False
        self.routed = False
        self.websocket_routed = False
        self.websocket_handler = None

    def route(self, pattern, handler):
        self.routed = True

    def route_web_socket(self, pattern, handler):
        self.websocket_routed = True
        self.websocket_handler = handler

    def new_page(self):
        return self.page

    def cookies(self, target):
        return [{"name": "security", "value": "low"}]

    def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self, context):
        self.context = context
        self.closed = False

    def new_context(self, service_workers=None):
        return self.context

    def close(self):
        self.closed = True


class FakePlaywrightManager:
    def __init__(self, browser):
        self.browser = browser
        self.exited = False
        self.chromium = SimpleNamespace(launch=lambda **kwargs: self.browser)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.exited = True
        return False


def fake_playwright_modules(manager):
    package = types.ModuleType("playwright")
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.TimeoutError = FakePlaywrightTimeout
    sync_api.sync_playwright = lambda: manager
    package.sync_api = sync_api
    return {"playwright": package, "playwright.sync_api": sync_api}


class BrowserTestGuardTests(unittest.TestCase):
    def test_same_origin_accepts_local_dvwa_assets(self):
        self.assertTrue(
            _same_origin(
                "http://127.0.0.1:4280/dvwa/css/main.css",
                "http://127.0.0.1:4280",
            )
        )

    def test_same_origin_rejects_remote_requests(self):
        self.assertFalse(
            _same_origin("https://example.com/script.js", "http://127.0.0.1:4280")
        )

    def test_same_origin_rejects_other_local_ports(self):
        self.assertFalse(
            _same_origin("http://127.0.0.1:80/index.php", "http://127.0.0.1:4280")
        )

    def test_same_origin_rejects_malformed_port(self):
        self.assertFalse(
            _same_origin("http://127.0.0.1:not-a-port/file", "http://127.0.0.1:4280")
        )

    def test_same_origin_accepts_local_websocket(self):
        self.assertTrue(
            _same_origin("ws://127.0.0.1:4280/socket", "http://127.0.0.1:4280")
        )

    def test_same_origin_rejects_remote_websocket(self):
        self.assertFalse(
            _same_origin("wss://example.com/socket", "http://127.0.0.1:4280")
        )

    def test_same_origin_rejects_websocket_userinfo(self):
        self.assertFalse(
            _same_origin("ws://user:pass@127.0.0.1:4280/socket", "http://127.0.0.1:4280")
        )

    def test_websocket_policy_forwards_local_and_closes_remote(self):
        local = FakeWebSocketRoute("ws://127.0.0.1:4280/socket")
        remote = FakeWebSocketRoute("wss://example.com/socket")

        _route_local_websocket(local, "http://127.0.0.1:4280")
        _route_local_websocket(remote, "http://127.0.0.1:4280")

        self.assertTrue(local.connected)
        self.assertFalse(local.closed)
        self.assertFalse(remote.connected)
        self.assertTrue(remote.closed)
        self.assertEqual(remote.close_code, 1008)

    def test_browser_test_rejects_non_project_payload(self):
        result = run_reflected_xss_test(
            "http://127.0.0.1:4280",
            '<script>alert(document.cookie)</script>',
            "admin",
            "password",
        )
        self.assertFalse(result.verified)
        self.assertIn("Blocked", result.message)

    def test_browser_test_rejects_remote_target_before_launch(self):
        result = run_reflected_xss_test(
            "http://example.com:4280", REFLECTED_POC, "admin", "password"
        )
        self.assertFalse(result.verified)
        self.assertIn("scope policy", result.message.lower())

    def test_expected_payload_is_the_project_proof_of_concept(self):
        result = run_reflected_xss_test(
            "http://127.0.0.1:4280", REFLECTED_POC, "", "password"
        )
        self.assertFalse(result.verified)
        self.assertIn("username and password", result.message)

    def test_rejects_non_positive_timeout(self):
        result = run_reflected_xss_test(
            "http://127.0.0.1:4280", REFLECTED_POC, "admin", "password", timeout_ms=0
        )
        self.assertFalse(result.verified)
        self.assertIn("greater than zero", result.message)

    def test_detects_login_form_after_failed_authentication(self):
        page = FakePage(login_ok=False)
        self.assertTrue(_is_dvwa_login_page(page))

    def test_login_form_absent_after_successful_authentication(self):
        page = FakePage(login_ok=True)
        self.assertFalse(_is_dvwa_login_page(page))


class BrowserTestLifecycleTests(unittest.TestCase):
    def _run_with_fake_browser(self, page, **kwargs):
        context = FakeContext(page)
        browser = FakeBrowser(context)
        manager = FakePlaywrightManager(browser)
        modules = fake_playwright_modules(manager)
        with patch.dict(sys.modules, modules):
            result = run_reflected_xss_test(
                "http://127.0.0.1:4280",
                REFLECTED_POC,
                "admin",
                "password",
                **kwargs,
            )
        return result, context, browser, manager, page

    def test_invalid_credentials_are_reported_specifically(self):
        result, context, browser, manager, page = self._run_with_fake_browser(
            FakePage(login_ok=False)
        )
        self.assertFalse(result.verified)
        self.assertIn("AUTHENTICATION FAILED", result.message)
        self.assertIsNone(result.security_level)
        self.assertTrue(context.closed)
        self.assertTrue(browser.closed)
        self.assertTrue(manager.exited)

    def test_missing_security_selector_has_distinct_error(self):
        result, context, browser, manager, page = self._run_with_fake_browser(
            FakePage(login_ok=True, security_selector=False)
        )
        self.assertFalse(result.verified)
        self.assertIn("SECURITY SETTINGS UNAVAILABLE", result.message)
        self.assertTrue(context.closed)
        self.assertTrue(browser.closed)

    def test_browser_timeout_is_reported_and_resources_are_closed(self):
        result, context, browser, manager, page = self._run_with_fake_browser(
            FakePage(timeout_on_dialog=True)
        )
        self.assertFalse(result.verified)
        self.assertIn("BROWSER TIMEOUT", result.message)
        self.assertEqual(result.security_level, "low")
        self.assertTrue(context.closed)
        self.assertTrue(browser.closed)
        self.assertTrue(manager.exited)

    def test_success_reports_progress_and_requires_each_operator_checkpoint(self):
        progress = []
        checkpoints = []
        alert_acknowledged = []
        page_for_run = FakePage()

        def record_checkpoint(message):
            checkpoints.append(message)
            page_for_run.actions.append(("checkpoint", message))

        result, context, browser, manager, page = self._run_with_fake_browser(
            page_for_run,
            progress_callback=progress.append,
            checkpoint_callback=record_checkpoint,
            pause_for_alert=True,
            input_func=lambda: alert_acknowledged.append(True) or "",
        )
        self.assertTrue(result.verified)
        self.assertEqual(result.security_level, "low")
        self.assertEqual(
            checkpoints,
            [
                "Chromium is ready. Press ENTER to open the DVWA login page.",
                "DVWA login succeeded. Press ENTER to open security settings.",
                "LOW security is confirmed. Press ENTER to open the Reflected XSS module.",
                "The local Reflected XSS form is ready. Press ENTER to place the harmless XSS-PG payload in the name field, or Ctrl+C to abort.",
                "The XSS-PG payload is prepared in the name field and has not been submitted. Press ENTER to submit it, or Ctrl+C to abort.",
            ],
        )
        self.assertTrue(alert_acknowledged)
        self.assertTrue(page.dialog.accepted)
        self.assertTrue(context.routed)
        self.assertTrue(context.websocket_routed)
        self.assertTrue(context.closed)
        self.assertTrue(browser.closed)
        self.assertIn("[1/7] Local Chromium launched successfully.", progress)
        self.assertIn("[2/7] DVWA authentication successful.", progress)
        self.assertIn("[3/7] DVWA security level confirmed: LOW.", progress)
        self.assertIn("[4/7] Reflected XSS module loaded; the local name input is ready.", progress)
        self.assertIn(
            "[5/7] Harmless XSS-PG payload is in the name field; it has NOT been submitted.",
            progress,
        )
        self.assertIn("[6/7] Submitting the XSS-PG proof and waiting for the browser alert...", progress)
        self.assertIn("[7/7] Expected JavaScript alert received.", progress)
        self.assertIn("[ALERT DETECTED] Browser message: XSS-PG", progress)
        checkpoints = [
            index for index, action in enumerate(page.actions) if action[0] == "checkpoint"
        ]
        payload_fill_index = page.actions.index(
            ("fill", 'input[name="name"]', REFLECTED_POC)
        )
        submit_index = page.actions.index(("press", 'input[name="name"]', "Enter"))
        # The first form checkpoint precedes payload preparation; the second
        # form checkpoint follows preparation and must precede form submission.
        self.assertLess(checkpoints[-2], payload_fill_index)
        self.assertLess(payload_fill_index, checkpoints[-1])
        self.assertLess(checkpoints[-1], submit_index)

    def test_payload_is_prepared_before_the_separate_submission_checkpoint(self):
        page_for_run = FakePage()
        actions = page_for_run.actions

        def record_checkpoint(message):
            actions.append(("checkpoint", message))

        result, context, browser, manager, page = self._run_with_fake_browser(
            page_for_run, checkpoint_callback=record_checkpoint
        )

        fill_index = actions.index(("fill", 'input[name="name"]', REFLECTED_POC))
        submission_checkpoint_index = next(
            index
            for index, action in enumerate(actions)
            if action[0] == "checkpoint"
            and "payload is prepared in the name field" in action[1]
        )
        submit_index = actions.index(("press", 'input[name="name"]', "Enter"))

        self.assertTrue(result.verified)
        self.assertLess(fill_index, submission_checkpoint_index)
        self.assertLess(submission_checkpoint_index, submit_index)
        self.assertTrue(context.closed)
        self.assertTrue(browser.closed)

    def test_keyboard_interrupt_at_pre_submission_checkpoint_leaves_prepared_payload_unsubmitted(self):
        page = FakePage()
        context = FakeContext(page)
        browser = FakeBrowser(context)
        manager = FakePlaywrightManager(browser)
        modules = fake_playwright_modules(manager)

        def stop_before_submission(message):
            if "payload is prepared in the name field and has not been submitted" in message:
                raise KeyboardInterrupt

        with patch.dict(sys.modules, modules):
            with self.assertRaises(KeyboardInterrupt):
                run_reflected_xss_test(
                    "http://127.0.0.1:4280",
                    REFLECTED_POC,
                    "admin",
                    "password",
                    checkpoint_callback=stop_before_submission,
                )

        self.assertIn(("fill", 'input[name="name"]', REFLECTED_POC), page.actions)
        self.assertNotIn(("press", 'input[name="name"]', "Enter"), page.actions)
        self.assertTrue(context.closed)
        self.assertTrue(browser.closed)
        self.assertTrue(manager.exited)

    def test_keyboard_interrupt_at_operator_checkpoint_closes_context_and_browser(self):
        def interrupt_at_checkpoint(message):
            if "security settings" in message:
                raise KeyboardInterrupt

        page = FakePage()
        context = FakeContext(page)
        browser = FakeBrowser(context)
        manager = FakePlaywrightManager(browser)
        modules = fake_playwright_modules(manager)

        with patch.dict(sys.modules, modules):
            with self.assertRaises(KeyboardInterrupt):
                run_reflected_xss_test(
                    "http://127.0.0.1:4280",
                    REFLECTED_POC,
                    "admin",
                    "password",
                    checkpoint_callback=interrupt_at_checkpoint,
                )

        self.assertTrue(context.closed)
        self.assertTrue(browser.closed)
        self.assertTrue(manager.exited)

    def test_keyboard_interrupt_closes_context_and_browser(self):
        result_page = FakePage(interrupt_on_username=True)
        context = FakeContext(result_page)
        browser = FakeBrowser(context)
        manager = FakePlaywrightManager(browser)
        modules = fake_playwright_modules(manager)

        with patch.dict(sys.modules, modules):
            with self.assertRaises(KeyboardInterrupt):
                run_reflected_xss_test(
                    "http://127.0.0.1:4280",
                    REFLECTED_POC,
                    "admin",
                    "password",
                )

        self.assertTrue(context.closed)
        self.assertTrue(browser.closed)
        self.assertTrue(manager.exited)


if __name__ == "__main__":
    unittest.main()
