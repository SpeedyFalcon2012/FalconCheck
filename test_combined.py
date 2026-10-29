import unittest
from unittest.mock import patch
import falcon_check as scanner
import falcon_engine as engine
import falcon_gui as gui


def av_result(status):
    return {'status': status, 'coverage': 'Test engine coverage', 'notes': [], 'findings': []}


class CombinedTests(unittest.TestCase):
    def test_cancelling_started_av_does_not_say_it_was_never_run(self):
        with patch.object(engine, 'antivirus', side_effect=engine.Cancelled):
            result = scanner.analyze_bytes(b'print("hi")', 'file.py', 'combined')
        self.assertEqual(result['status'], 'CANCELLED')
        self.assertIn(('Malware scan (ClamAV)', 'CANCELLED'), result['checks'])

    def inspect(self, source, status):
        with patch.object(engine, 'antivirus', return_value=av_result(status)):
            return scanner.analyze_bytes(source, 'file.py', 'combined')

    def test_missing_av_never_becomes_clean_result(self):
        result = self.inspect(b'print("hi")', 'ANTIVIRUS UNAVAILABLE')
        self.assertEqual(result['status'], 'PARTIAL INSPECTION')
        self.assertIn(('Malware scan (ClamAV)', 'ANTIVIRUS UNAVAILABLE'), result['checks'])
        self.assertIn('Antivirus setup', gui.report_text(result))

    def test_av_detection_takes_priority(self):
        result = self.inspect(b'eval("2")', 'THREAT REPORTED')
        self.assertEqual(result['status'], 'THREAT REPORTED')
        self.assertEqual(result['findings'][0]['rule'], 'dynamic-code')

    def test_static_clue_remains_even_when_av_reports_none(self):
        result = self.inspect(b'eval("2")', 'NO THREATS REPORTED')
        self.assertEqual(result['status'], 'NEEDS REVIEW')
        self.assertIn(('Malware scan (ClamAV)', 'NO THREATS REPORTED'), result['checks'])

    def test_success_requires_both_requested_checks(self):
        self.assertEqual(self.inspect(b'print("hi")', 'NO THREATS REPORTED')['status'], 'NO THREATS REPORTED')
        self.assertEqual(self.inspect(b'print(', 'NO THREATS REPORTED')['status'], 'PARTIAL INSPECTION')

    def test_individual_static_mode_explicitly_says_av_not_run(self):
        result = scanner.analyze_bytes(b'print("hi")', 'file.py', 'python')
        self.assertIn('NOT RUN', gui.report_text(result))

    def test_trace_display_and_evidence_basis(self):
        result = scanner.analyze_bytes(b'p="/etc/shadow"\nopen(p)\n', 'file.py', 'python')
        text = gui.report_text(result)
        self.assertIn('Statically traced value', text)
        self.assertIn('Line 1: assigned to p', text)
        self.assertIn('Traced value: /etc/shadow', text)

    def test_engine_error_does_not_discard_static_report(self):
        with patch.object(engine, 'antivirus', side_effect=OSError('test missing library')):
            result = scanner.analyze_bytes(b'p="/etc/shadow"\nopen(p)\n', 'file.py', 'combined')
        self.assertEqual(result['status'], 'NEEDS REVIEW')
        self.assertIn('test missing library', result['coverage'])


if __name__ == '__main__':
    unittest.main()
