import unittest
from unittest.mock import patch

from xsspg.target import check_dvwa


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, limit):
        return self.body[:limit]


class TargetIdentificationTests(unittest.TestCase):
    def test_identifies_dvwa_login_page(self):
        body = (
            '<title>Login :: Damn Vulnerable Web Application (DVWA)</title>'
            '<input name="username"><input name="password">'
        )
        fake_opener = unittest.mock.MagicMock()
        fake_opener.open.return_value = FakeResponse(body)
        with patch("xsspg.target.build_opener", return_value=fake_opener):
            ok, message = check_dvwa("http://127.0.0.1:4280")
        self.assertTrue(ok)
        self.assertIn("identified", message)

    def test_rejects_non_loopback_target_before_request(self):
        with patch("xsspg.target.build_opener") as opener_factory:
            ok, message = check_dvwa("http://example.com:4280")
        self.assertFalse(ok)
        self.assertIn("scope rejected", message.lower())
        opener_factory.assert_not_called()

    def test_rejects_unrelated_local_service(self):
        fake_opener = unittest.mock.MagicMock()
        fake_opener.open.return_value = FakeResponse("<html>hello</html>")
        with patch("xsspg.target.build_opener", return_value=fake_opener):
            ok, message = check_dvwa("http://127.0.0.1:4280")
        self.assertFalse(ok)
        self.assertIn("does not match DVWA", message)


if __name__ == "__main__":
    unittest.main()
