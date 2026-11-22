import unittest

from xsspg.security import ScopeError, normalize_local_target


class ScopeValidationTests(unittest.TestCase):
    def test_default_target_is_dvwa_loopback(self):
        self.assertEqual(normalize_local_target(""), "http://127.0.0.1:4280")

    def test_accepts_localhost(self):
        self.assertEqual(normalize_local_target("http://localhost:4280"), "http://localhost:4280")

    def test_rejects_ipv6_not_bound_by_supplied_compose_configuration(self):
        with self.assertRaises(ScopeError):
            normalize_local_target("http://[::1]:4280")

    def test_rejects_remote_host(self):
        with self.assertRaises(ScopeError):
            normalize_local_target("http://example.com:4280")

    def test_rejects_wrong_port(self):
        with self.assertRaises(ScopeError):
            normalize_local_target("http://127.0.0.1:5000")

    def test_rejects_https(self):
        with self.assertRaises(ScopeError):
            normalize_local_target("https://127.0.0.1:4280")

    def test_rejects_path_and_query(self):
        with self.assertRaises(ScopeError):
            normalize_local_target("http://127.0.0.1:4280/vulnerabilities/xss_r/?name=x")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ScopeError):
            normalize_local_target("http://admin:password@127.0.0.1:4280")

    def test_rejects_invalid_port(self):
        with self.assertRaises(ScopeError):
            normalize_local_target("http://127.0.0.1:notaport")


if __name__ == "__main__":
    unittest.main()
