import unittest

from xsspg.payloads import REFLECTED_POC, PayloadProfile, generate_payload


class PayloadGeneratorTests(unittest.TestCase):
    def test_generates_reflected_xss_profile(self):
        result = generate_payload(PayloadProfile.REFLECTED)
        self.assertEqual(result.profile, PayloadProfile.REFLECTED)
        self.assertEqual(result.parameter, "name")
        self.assertEqual(result.value, REFLECTED_POC)

    def test_payload_is_harmless_alert_marker(self):
        result = generate_payload()
        self.assertIn('alert("XSS-PG")', result.value)
        self.assertNotIn("document.cookie", result.value.lower())
        self.assertNotIn("fetch(", result.value.lower())

    def test_rejects_unsupported_profile(self):
        with self.assertRaises(ValueError):
            generate_payload("stored")


if __name__ == "__main__":
    unittest.main()
