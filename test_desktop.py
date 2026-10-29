"""Menu installation is tested in temporary directories, not your real menu."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import falcon_picker as picker
import install_launcher as installer

SOURCE = Path(__file__).parent


class PickerTests(unittest.TestCase):
    def test_missing_zenity_uses_fallback(self):
        with patch.object(picker.shutil, "which", return_value=None):
            self.assertIsNone(picker.start_picker())

    def test_helper_launch_uses_argument_array_without_shell(self):
        with patch.object(picker.shutil, "which", return_value="/usr/bin/zenity"), \
                patch.object(picker.subprocess, "Popen") as popen:
            picker.start_picker()
        self.assertEqual(popen.call_args.args[0][0], "/usr/bin/zenity")
        self.assertIn("--file-selection", popen.call_args.args[0])
        self.assertNotIn("shell", popen.call_args.kwargs)

    def test_launch_error_uses_fallback(self):
        with patch.object(picker.shutil, "which", return_value="/usr/bin/zenity"), \
                patch.object(picker.subprocess, "Popen", side_effect=OSError("unavailable")):
            self.assertIsNone(picker.start_picker())

    def test_whitespace_and_shell_characters_in_path_preserved(self):
        process = Mock(returncode=0)
        process.communicate.return_value = (b'/tmp/ space $file;name \n', None)
        self.assertEqual(picker.picker_result(process), '/tmp/ space $file;name ')

    def test_cancel_and_failure_are_distinct(self):
        process = Mock(returncode=1)
        process.communicate.return_value = (b"", None)
        self.assertEqual(picker.picker_result(process), "")
        process.returncode = 2
        self.assertIsNone(picker.picker_result(process))


class InstallerTests(unittest.TestCase):
    def test_install_copy_survives_source_folder_move(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "extracted folder"
            source.mkdir()
            for name in installer.PAYLOAD:
                (source / name).write_bytes((SOURCE / name).read_bytes())
            app, entry = installer.install(source, root / "user data", sys.executable)
            source.rename(root / "moved folder")
            completed = subprocess.run([sys.executable, str(app / "falcon_check.py"), "--demo"],
                                       capture_output=True, text=True, timeout=10)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("FALCON CHECK 0.9", completed.stdout)
            text = entry.read_text()
            self.assertIn("Terminal=false", text)
            self.assertIn(installer.exec_argument(app / "falcon_check.py"), text)
            self.assertNotIn(str(source), text)
            for name in installer.PAYLOAD:
                self.assertEqual((app / name).read_bytes(), (SOURCE / name).read_bytes())

    def test_repeat_install_updates_only_owned_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            app, entry = installer.install(SOURCE, Path(temporary))
            (app / "personal-note.txt").write_text("keep me")
            installer.install(SOURCE, Path(temporary))
            self.assertEqual((app / "personal-note.txt").read_text(), "keep me")
            self.assertTrue(entry.is_file())

    def test_unrecognized_folder_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            other = root / "falcon-check"
            other.mkdir()
            (other / "important.txt").write_text("keep me")
            with self.assertRaises(ValueError):
                installer.install(SOURCE, root)
            self.assertEqual((other / "important.txt").read_text(), "keep me")
            self.assertFalse((other / "install.json").exists())

    def test_unowned_menu_entry_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "applications").mkdir()
            desktop = root / "applications" / "falcon-check.desktop"
            desktop.write_text("another app")
            with self.assertRaises(ValueError):
                installer.install(SOURCE, root)
            self.assertEqual(desktop.read_text(), "another app")
            self.assertFalse((root / "falcon-check").exists())

    def test_symlink_destination_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (root / "falcon-check").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                installer.install(SOURCE, root)
            self.assertEqual(list(outside.iterdir()), [])

    def test_newline_in_launcher_path_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "bad\npath"
            with self.assertRaises(ValueError):
                installer.install(SOURCE, root)
            self.assertFalse(root.exists())

    def test_xdg_directory_rules(self):
        with patch.dict(os.environ, {"XDG_DATA_HOME": "/tmp/falcon-custom-data"}):
            self.assertEqual(installer.data_directory(), Path("/tmp/falcon-custom-data"))
        with patch.dict(os.environ, {"XDG_DATA_HOME": "relative"}):
            self.assertEqual(installer.data_directory(), Path.home() / ".local" / "share")

    def test_exec_escaping_keeps_paths_as_arguments(self):
        self.assertEqual(installer.exec_argument('/tmp/a b.py'), '"/tmp/a b.py"')
        self.assertEqual(installer.exec_argument('/tmp/$x.py'), '"/tmp/\\\\$x.py"')
        self.assertEqual(installer.exec_argument('/tmp/100%.py'), '"/tmp/100%%.py"')


if __name__ == "__main__":
    unittest.main()
