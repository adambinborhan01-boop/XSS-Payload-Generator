import json
import os
import tempfile
import unittest

from xsspg.payloads import ALLOWED_PAYLOADS, generate_payload, list_variants
from xsspg.results_log import save_result


class PayloadVariantTests(unittest.TestCase):
    def test_lists_more_than_one_variant(self):
        variants = list_variants()
        self.assertGreaterEqual(len(variants), 2)

    def test_default_variant_is_unchanged(self):
        # No `variant` passed -> must still behave like before this change.
        result = generate_payload()
        self.assertEqual(result.value, list_variants()["script_tag"])

    def test_can_pick_a_specific_variant(self):
        result = generate_payload(variant="img_onerror")
        self.assertIn("onerror", result.value)
        self.assertIn(result.value, ALLOWED_PAYLOADS)

    def test_unknown_variant_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_payload(variant="does_not_exist")

    def test_every_variant_only_pops_the_harmless_alert(self):
        for payload in ALLOWED_PAYLOADS:
            self.assertIn("XSS-PG", payload)
            self.assertNotIn("document.cookie", payload.lower())
            self.assertNotIn("fetch(", payload.lower())


class ResultsLogTests(unittest.TestCase):
    def test_save_result_writes_local_json_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                path = save_result("http://127.0.0.1:4280", "<script>alert('x')</script>", True, "low")
                self.assertTrue(os.path.exists(path))
                with open(path, encoding="utf-8") as f:
                    record = json.loads(f.readline())
                self.assertEqual(record["target"], "http://127.0.0.1:4280")
                self.assertTrue(record["verified"])
                self.assertNotIn("password", record)
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
