import unittest

from xsspg.browser_test import _same_origin, run_reflected_xss_test
from xsspg.payloads import REFLECTED_POC


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


if __name__ == "__main__":
    unittest.main()
