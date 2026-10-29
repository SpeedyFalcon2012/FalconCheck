"""Headless GUI integration checks; these don't verify actual window layout."""
import contextlib
import io
from pathlib import Path
import queue
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import falcon_check as scanner
import falcon_gui as gui


class WindowLogicTests(unittest.TestCase):
    def test_window_and_terminal_use_same_result(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'example.py'
            file.write_text('eval("2 + 2")\n')
            self.assertEqual(gui.inspect_file(str(file), "auto"), scanner.scan_file(str(file), "auto"))

    def test_missing_file_is_uninspected(self):
        with tempfile.TemporaryDirectory() as directory:
            result = gui.inspect_file(str(Path(directory) / "missing"), "auto")
        self.assertEqual(result["status"], "NOT INSPECTED")
        self.assertIn("did not receive a completed analysis", gui.report_text(result))
        self.assertNotIn("No selected indicators matched", gui.report_text(result))

    def test_report_contains_findings_and_escapes_controls(self):
        result = scanner.analyze_bytes(b'eval("2 + 2")\n', "fake\x1b[31m.py")
        text = gui.report_text(result)
        self.assertIn("Line 1", text)
        self.assertIn('eval("2 + 2")', text)
        self.assertIn(result["sha256"], text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", gui.display_text("a\u202eb"))

    def test_no_indicators_report_does_not_claim_safety(self):
        result = scanner.analyze_bytes(b'print("hello")\n', "ordinary.py")
        text = gui.report_text(result)
        self.assertIn("No selected indicators matched", text)
        self.assertIn("not proof", text)

    def test_missing_tk_has_actionable_message(self):
        output = io.StringIO()
        with patch.dict("sys.modules", {"tkinter": None}), contextlib.redirect_stdout(output):
            code = gui.launch()
        self.assertEqual(code, 2)
        self.assertIn("terminal scanner still works", output.getvalue())

    def test_terminal_does_not_launch_gui(self):
        with patch("sys.argv", ["falcon_check.py", "--demo"]), \
                patch.dict("sys.modules", {"tkinter": None}), \
                patch.object(gui, "launch") as launch, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.main(), 0)
        launch.assert_not_called()

    def test_gui_flag_passes_file_and_mode(self):
        with patch("sys.argv", ["falcon_check.py", "--gui", "example.py", "--mode", "text"]), \
                patch.object(gui, "launch", return_value=0) as launch:
            self.assertEqual(scanner.main(), 0)
        launch.assert_called_once_with("example.py", "text")

    def test_conflicting_demo_and_gui_rejected(self):
        with patch("sys.argv", ["falcon_check.py", "--gui", "--demo"]), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            scanner.main()
        self.assertEqual(result.exception.code, 2)

    def test_editing_selection_clears_stale_result(self):
        window = gui.FalconWindow.__new__(gui.FalconWindow)
        window.busy = False
        window.result = {"status": "NEEDS REVIEW"}
        window.path = Mock()
        window.path.get.return_value = ""
        window.copy_button = Mock()
        window.fix_button = Mock()
        window.scan_button = Mock()
        window.status = Mock()
        window.set_details = Mock()
        window.selection_changed()
        self.assertIsNone(window.result)
        self.assertEqual(window.copy_button.configure.call_args.kwargs["state"], "disabled")
        self.assertEqual(window.scan_button.configure.call_args.kwargs["state"], "disabled")

    def test_completed_worker_result_is_presented(self):
        window = gui.FalconWindow.__new__(gui.FalconWindow)
        window.closed = False
        window.messages = queue.Queue()
        result = scanner.analyze_bytes(b'print("hello")\n', "ordinary.py")
        window.messages.put(result)
        window.present = Mock()
        window.set_busy = Mock()
        window.poll()
        window.present.assert_called_once_with(result)
        window.set_busy.assert_called_once_with(False)

    def test_close_cancels_poll_and_destroys_window(self):
        window = gui.FalconWindow.__new__(gui.FalconWindow)
        window.after_id = "pending"
        window.picker = None
        window.cancel_event = threading.Event()
        window.root = Mock()
        window.close()
        self.assertTrue(window.closed)
        window.root.after_cancel.assert_called_once_with("pending")
        window.root.destroy.assert_called_once_with()

    def test_activity_hidden_when_idle_and_while_picking(self):
        window = gui.FalconWindow.__new__(gui.FalconWindow)
        for name in ("entry", "browse_button", "demo_button", "mode_box", "scan_button", "copy_button", "fix_button", "progress", "cancel_button", "update_button", "av_button"):
            setattr(window, name, Mock())
        window.result = None
        window.path = Mock()
        window.path.get.return_value = "example.py"
        window.set_busy(True)
        window.progress.start.assert_called_once()
        window.progress.pack.assert_called_once()
        window.set_busy(False)
        window.progress.stop.assert_called_once()
        window.progress.pack_forget.assert_called_once()
        window.progress.reset_mock()
        window.set_busy(True, activity=False)
        window.progress.start.assert_not_called()
        window.progress.pack_forget.assert_called_once()

    def test_picker_cancel_preserves_previous_selection(self):
        window = gui.FalconWindow.__new__(gui.FalconWindow)
        window.closed = False
        window.picker = Mock()
        window.picker.poll.return_value = 1
        window.path = Mock()
        window.set_busy = Mock()
        window.browse_fallback = Mock()
        with patch.object(gui.falcon_picker, "picker_result", return_value=""):
            window.poll_picker()
        window.path.set.assert_not_called()
        window.browse_fallback.assert_not_called()
        window.set_busy.assert_called_once_with(False)

    def test_picker_failure_opens_fallback(self):
        window = gui.FalconWindow.__new__(gui.FalconWindow)
        window.closed = False
        window.picker = Mock()
        window.picker.poll.return_value = 2
        window.set_busy = Mock()
        window.browse_fallback = Mock()
        with patch.object(gui.falcon_picker, "picker_result", return_value=None):
            window.poll_picker()
        window.browse_fallback.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
