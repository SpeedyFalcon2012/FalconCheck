"""No downloads in unit tests. Real-engine integration is checked separately."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import falcon_antivirus as av


class DownloadResponse(io.BytesIO):
    def geturl(self):
        return 'https://example.invalid/package.deb'


class AntivirusSetupTests(unittest.TestCase):
    def test_download_checks_size_hash_and_saved_bytes(self):
        data = b'harmless package fixture'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'package.deb'
            with patch.object(av.urllib.request, 'urlopen', return_value=DownloadResponse(data)), \
                    patch.object(av, 'PACKAGE_BYTES', len(data)), \
                    patch.object(av, 'PACKAGE_SHA256', hashlib.sha256(data).hexdigest()):
                av.download_package(path)
            self.assertEqual(path.read_bytes(), data)

    def test_corrupted_download_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(av.urllib.request, 'urlopen', return_value=DownloadResponse(b'bad')), \
                    patch.object(av, 'PACKAGE_BYTES', 3), patch.object(av, 'PACKAGE_SHA256', '0' * 64):
                with self.assertRaisesRegex(ValueError, 'verification failed'):
                    av.download_package(Path(folder) / 'package.deb')

    def test_download_size_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(av.urllib.request, 'urlopen', return_value=DownloadResponse(b'too long')), patch.object(av, 'PACKAGE_BYTES', 1):
                with self.assertRaisesRegex(ValueError, 'size'):
                    av.download_package(Path(folder) / 'package.deb')

    def test_cancellation_stops_download(self):
        event = threading.Event()
        event.set()
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(av.urllib.request, 'urlopen', return_value=DownloadResponse(b'data')):
                with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                    av.download_package(Path(folder) / 'package.deb', event)

    def test_private_engine_and_database_survive_app_versions(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            prefix = base / 'engine-test' / 'usr' / 'local'
            (prefix / 'bin').mkdir(parents=True)
            (prefix / 'bin' / 'clamscan').touch()
            (base / 'engine.json').write_text(json.dumps({'folder': 'engine-test'}))
            with patch.object(av, 'home', return_value=base):
                config = av.configuration()
            self.assertEqual(config['database'], str(base / 'database'))
            self.assertEqual(config['executable'], str(prefix / 'bin' / 'clamscan'))
            self.assertTrue(config['local'])

    def test_invalid_local_marker_cannot_select_external_path(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base / 'engine.json').write_text(json.dumps({'folder': '../../other'}))
            with patch.object(av, 'home', return_value=base):
                with self.assertRaises(ValueError):
                    av.local_engine()

    def test_no_engine_gives_actionable_readiness(self):
        with patch.object(av, 'configuration', return_value=None):
            self.assertIn('NOT READY', av.readiness())

    def test_private_engine_without_databases_is_not_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            config = {'executable': '/fixture/clamscan', 'prefix': None, 'database': folder, 'local': True}
            with patch.object(av, 'configuration', return_value=config), patch.object(av, 'run', return_value=(0, 'ClamAV test')):
                self.assertIn('SIGNATURES MISSING', av.readiness())

    def test_run_timeout_kills_process(self):
        import sys
        with self.assertRaisesRegex(RuntimeError, 'timed out'):
            av.run([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.1)

    def test_failed_setup_does_not_publish_engine(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            with patch.object(av, 'home', return_value=base), patch.object(av.platform, 'system', return_value='Linux'), \
                    patch.object(av.platform, 'machine', return_value='x86_64'), \
                    patch.object(av.shutil, 'which', return_value='/fixture/dpkg-deb'), \
                    patch.object(av, 'download_package', side_effect=ValueError('bad checksum')):
                with self.assertRaises(ValueError):
                    av.install_engine()
            self.assertEqual(list(base.iterdir()), [])

    def test_signature_update_uses_only_private_database(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            config = {'freshclam': '/fixture/freshclam', 'database': str(base / 'database with spaces'), 'prefix': None}
            with patch.object(av, 'home', return_value=base), patch.object(av, 'local_engine', return_value=config), \
                    patch.object(av, 'run', return_value=(0, 'up to date')) as run:
                av.update_signatures()
            command = run.call_args.args[0]
            self.assertIn('--datadir=' + config['database'], command)
            self.assertNotIn('--daemon', command)
            self.assertIn('DatabaseMirror database.clamav.net', (base / 'freshclam.conf').read_text())


if __name__ == '__main__':
    unittest.main()
