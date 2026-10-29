"""Large-file, archive, and antivirus-adapter tests using harmless fixtures."""
import hashlib
import io
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

import falcon_check as scanner
import falcon_engine as engine
import falcon_formats as formats
import falcon_gui as gui


class EngineTests(unittest.TestCase):
    def test_large_binary_whole_hash_and_bounded_reads(self):
        class BoundedStream(io.BytesIO):
            def read(self, size=-1):
                if size < 0 or size > engine.CHUNK:
                    raise AssertionError('Unbounded read requested')
                return super().read(size)
        data = b'\x00' * (5 * engine.CHUNK) + b'tail'
        events = []
        result = engine.inspect_stream(BoundedStream(data), len(data), 'large.bin', 'details', progress=events.append)
        self.assertEqual(result['status'], 'BASIC INSPECTION')
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(events[-1]['done'], len(data))

    def test_streaming_text_catches_match_after_old_limit(self):
        data = b'# ordinary\n' * 300000 + b'eval("2")\n'
        result = scanner.analyze_bytes(data, 'large.txt')
        self.assertEqual(result['status'], 'NEEDS REVIEW')
        self.assertEqual(result['findings'][0]['line'], 300001)

    def test_pattern_spanning_chunk_boundary(self):
        data = b'a' * (engine.CHUNK - 3) + b'\n' + b'eval("2")\n'
        result = scanner.analyze_bytes(data, 'boundary.txt')
        self.assertEqual(result['status'], 'NEEDS REVIEW')
        self.assertEqual(result['findings'][0]['line'], 2)

    def test_invalid_utf8_late_does_not_get_negative_verdict(self):
        data = b'a' * (2 * engine.CHUNK) + b'\xff'
        result = scanner.analyze_bytes(data, 'invalid.txt')
        self.assertEqual(result['status'], 'PARTIAL INSPECTION')
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())

    def test_large_python_under_new_limit(self):
        data = b'#' + b'x' * 700000 + b'\neval("2")\n'
        result = scanner.analyze_bytes(data, 'larger.py')
        self.assertEqual(result['status'], 'NEEDS REVIEW')
        self.assertEqual(result['findings'][0]['line'], 2)

    def test_python_over_limit_still_gets_hash(self):
        data = b'#' + b'x' * scanner.MAX_PYTHON_BYTES
        result = scanner.analyze_bytes(data, 'too-large.py')
        self.assertEqual(result['status'], 'NOT INSPECTED')
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())

    def test_pre_cancel_does_not_claim_a_complete_hash(self):
        cancel = threading.Event()
        cancel.set()
        result = engine.inspect_stream(io.BytesIO(b'hello'), 5, 'file.txt', cancel=cancel)
        self.assertEqual(result['status'], 'CANCELLED')
        self.assertIsNone(result['sha256'])

    def test_cancel_during_hashing(self):
        cancel = threading.Event()
        def update(event):
            if event['done']:
                cancel.set()
        data = b'\0' * (4 * engine.CHUNK)
        result = engine.inspect_stream(io.BytesIO(data), len(data), 'large.bin', cancel=cancel, progress=update)
        self.assertEqual(result['status'], 'CANCELLED')
        self.assertIsNone(result['sha256'])

    def test_elf_header_only_is_not_a_safety_verdict(self):
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<HH', header, 16, 3, 62)
        result = scanner.analyze_bytes(bytes(header), 'launcher', 'details')
        self.assertEqual(result['status'], 'BASIC INSPECTION')
        self.assertIn(('CPU architecture', 'x86-64'), result['facts'])
        self.assertIn('not a malware scan', gui.report_text(result))

    def test_windows_header_identification(self):
        header = bytearray(256)
        header[:2] = b'MZ'
        struct.pack_into('<I', header, 60, 128)
        header[128:132] = b'PE\0\0'
        struct.pack_into('<HH', header, 132, 0x8664, 3)
        result = scanner.analyze_bytes(bytes(header), 'app.exe', 'details')
        self.assertEqual(result['status'], 'BASIC INSPECTION')
        self.assertIn(('PE header', 'Present'), result['facts'])

    def test_file_changed_during_scan_is_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'file.bin'
            path.write_bytes(b'\0' * (2 * engine.CHUNK))
            changed = False
            def update(event):
                nonlocal changed
                if event['done'] and not changed:
                    with path.open('ab') as file:
                        file.write(b'changed')
                    changed = True
            result = scanner.scan_file(path, progress=update)
            self.assertEqual(result['status'], 'PARTIAL INSPECTION')
            self.assertIsNone(result['sha256'])


class ArchiveTests(unittest.TestCase):
    def make_zip(self, entries):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for name, contents in entries:
                archive.writestr(name, contents)
        return output.getvalue()

    def test_zip_inventory_not_payload_scan(self):
        data = self.make_zip([('README.txt', 'hello'), ('app.py', 'eval("2")')])
        result = scanner.analyze_bytes(data, 'app.zip')
        self.assertEqual(result['status'], 'BASIC INSPECTION')
        self.assertEqual(dict(result['facts'])['Entries inventoried'], '2')
        self.assertEqual(result['findings'], [])
        self.assertEqual(len(result['members']), 2)

    def test_zip_parent_path_is_flagged_without_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'example.zip'
            path.write_bytes(self.make_zip([('../outside.txt', 'inert text')]))
            before = set(Path(directory).iterdir())
            result = scanner.scan_file(path)
            self.assertEqual(result['status'], 'NEEDS REVIEW')
            self.assertIn('archive-path', [item['rule'] for item in result['findings']])
            self.assertEqual(set(Path(directory).iterdir()), before)

    def test_truncated_zip_is_partial(self):
        result = scanner.analyze_bytes(b'PK\x03\x04broken', 'broken.zip')
        self.assertEqual(result['status'], 'PARTIAL INSPECTION')

    def test_tar_gz_inventory(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            member = tarfile.TarInfo('example.txt')
            member.size = 5
            archive.addfile(member, io.BytesIO(b'hello'))
        result = scanner.analyze_bytes(output.getvalue(), 'example.tar.gz')
        self.assertEqual(result['status'], 'BASIC INSPECTION')
        self.assertIn('example.txt', result['members'][0])

    def test_tar_expanded_budget_reported_as_partial(self):
        member = tarfile.TarInfo('large.bin')
        member.size = formats.MAX_TAR_BYTES + 1
        data = member.tobuf(format=tarfile.USTAR_FORMAT)
        result = scanner.analyze_bytes(data, 'incomplete.tar')
        self.assertEqual(result['status'], 'PARTIAL INSPECTION')
        self.assertTrue(any('64 MiB' in note for note in result['notes']))

    def test_debian_package_top_level_inventory(self):
        def member(name, contents):
            header = (name + '/').ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6) + '100644'.ljust(8) + str(len(contents)).ljust(10) + '`\n'
            return header.encode() + contents + (b'\n' if len(contents) % 2 else b'')
        data = b'!<arch>\n' + member('debian-binary', b'2.0\n') + member('data.tar.xz', b'placeholder')
        result = scanner.analyze_bytes(data, 'launcher.deb')
        self.assertEqual(result['status'], 'BASIC INSPECTION')
        self.assertIn(('Package marker', 'Debian binary package 2.0'), result['facts'])
        self.assertTrue(any('installation scripts' in note for note in result['notes']))


class AntivirusTests(unittest.TestCase):
    def setUp(self):
        self.local_patch = patch('falcon_antivirus.local_engine', return_value=None)
        self.local_patch.start()
        self.addCleanup(self.local_patch.stop)

    def test_adapter_passes_file_as_data_to_mock_engine(self):
        # A harmless simulated engine; this does not test real malware detection.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / 'mock-clamscan'
            fake.write_text('#!/usr/bin/env python3\nimport sys, hashlib\n'
                            'if "--version" in sys.argv:\n print("Mock engine / test database")\n'
                            'else:\n'
                            ' assert not any(arg.startswith(("--remove", "--move", "--copy")) for arg in sys.argv)\n'
                            ' print("Input SHA256: " + hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\n'
                            ' print("stdin: OK\\nScanned files: 1")\n')
            fake.chmod(0o755)
            source = root / 'selected-file.txt'
            source.write_bytes(b'Harmless file data; never executed.')
            with patch.object(engine.shutil, 'which', return_value=str(fake)):
                result = scanner.scan_file(source, 'antivirus')
                memory_result = scanner.analyze_bytes(source.read_bytes(), 'memory.txt', 'antivirus')
            self.assertEqual(memory_result['status'], 'NO THREATS REPORTED')
            self.assertEqual(memory_result['sha256'], result['sha256'])
            self.assertEqual(result['status'], 'NO THREATS REPORTED')
            self.assertIn(result['sha256'], result['engine_output'])
            self.assertEqual(dict(result['facts'])['ClamAV engine / database'], 'Mock engine / test database')
            self.assertEqual(source.read_bytes(), b'Harmless file data; never executed.')

    def test_running_mock_antivirus_can_be_cancelled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / 'mock-clamscan'
            fake.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n')
            fake.chmod(0o755)
            source = root / 'source.txt'
            source.write_text('hello')
            cancel = threading.Event()
            timer = threading.Timer(0.15, cancel.set)
            timer.start()
            try:
                with patch.object(engine.shutil, 'which', return_value=str(fake)):
                    result = scanner.scan_file(source, 'antivirus', cancel=cancel)
            finally:
                timer.cancel()
            self.assertEqual(result['status'], 'CANCELLED')

    def test_missing_engine_is_explicit(self):
        with patch.object(engine.shutil, 'which', return_value=None):
            result = scanner.analyze_bytes(b'hello', 'file.txt', 'antivirus')
        self.assertEqual(result['status'], 'ANTIVIRUS UNAVAILABLE')

    def test_no_files_scanned_is_not_no_threats(self):
        result = engine.classify_antivirus(0, 'Scanned files: 0\nInfected files: 0\n')
        self.assertEqual(result['status'], 'NOT INSPECTED')

    def test_reported_detection(self):
        result = engine.classify_antivirus(1, 'stdin: Demo.Signature FOUND\nScanned files: 1\n')
        self.assertEqual(result['status'], 'THREAT REPORTED')

    def test_limits_and_encryption_are_not_malware_verdicts(self):
        for message in ('Heuristics.Limits.Exceeded.MaxFileSize', 'Heuristics.Encrypted.Zip'):
            result = engine.classify_antivirus(1, 'stdin: ' + message + ' FOUND\n')
            self.assertEqual(result['status'], 'PARTIAL INSPECTION')

    def test_success_and_error(self):
        self.assertEqual(engine.classify_antivirus(0, 'stdin: OK\nScanned files: 1\n')['status'], 'NO THREATS REPORTED')
        self.assertEqual(engine.classify_antivirus(2, 'Database unavailable\n')['status'], 'NOT INSPECTED')


if __name__ == '__main__':
    unittest.main()
