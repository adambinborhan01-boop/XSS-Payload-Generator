import contextlib
import io
import unittest
from unittest.mock import patch

from xsspg.cli import _operator_checkpoint, main


class CliInterruptionTests(unittest.TestCase):
    def test_operator_checkpoint_prompts_for_enter_and_displays_reason(self):
        output = io.StringIO()
        with patch("builtins.input", return_value="") as mocked_input:
            with contextlib.redirect_stdout(output):
                _operator_checkpoint("Press ENTER before submitting the local proof.")
        self.assertIn("[OPERATOR CHECKPOINT]", output.getvalue())
        self.assertIn("before submitting the local proof", output.getvalue())
        mocked_input.assert_called_once_with("Press ENTER to continue, or Ctrl+C to abort: ")

    def test_keyboard_interrupt_returns_clean_exit_code(self):
        output = io.StringIO()
        with patch("xsspg.cli._run", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stdout(output):
                code = main()
        self.assertEqual(code, 130)
        self.assertIn("[STOP] Interrupted by user. Exiting cleanly.", output.getvalue())


if __name__ == "__main__":
    unittest.main()
