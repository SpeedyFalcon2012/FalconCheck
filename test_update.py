"""Update acceptance, hostile archive rejection, and publication failure tests."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

import falcon_update as updater
import install_launcher as installer

SOURCE = Path(__file__).parent


def release_files(version='0.10'):
    files = {name: (SOURCE / name).read_bytes() for name in installer.PAYLOAD}
    files['falcon_check.py'] = files['falcon_check.py'].replace(b'VERSION = "0.9"', ('VERSION = "' + version + '"').encode())
    manifest = {'app_id': installer.APP_ID, 'format': 1, 'version': version, 'payload': list(installer.PAYLOAD),
                'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    files['release.json'] = json.dumps(manifest).encode()
    return files


def package(path, files=None, extras=()):
    files = release_files() if files is None else files
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in files.items():
            member = tarfile.TarInfo('falcon-check-v0.10/' + name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        for member, data in extras:
            archive.addfile(member, io.BytesIO(data))


class UpdateTests(unittest.TestCase):
    def test_updated_app_runs_after_download_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installer.install(SOURCE, root / 'data')
            path = root / 'release.tar.gz'
            package(path)
            release = updater.validate_package(path, '0.9')
            app, entry = updater.install_validated(release, root / 'data', '0.9')
            path.unlink()
            done = subprocess.run([sys.executable, str(app / 'falcon_check.py'), '--demo'],
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn('FALCON CHECK 0.10', done.stdout)
            self.assertIn(installer.exec_argument(app / 'falcon_check.py'), entry.read_text())

    def test_future_python_module_is_copied_from_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = release_files()
            files['new_feature.py'] = b'VALUE = 42\n'
            manifest = json.loads(files['release.json'])
            manifest['payload'].append('new_feature.py')
            manifest['files']['new_feature.py'] = hashlib.sha256(files['new_feature.py']).hexdigest()
            files['release.json'] = json.dumps(manifest).encode()
            path = root / 'release.tar.gz'
            package(path, files)
            release = updater.validate_package(path, '0.9')
            app, entry = updater.install_validated(release, root / 'data', '0.9')
            self.assertEqual((app / 'new_feature.py').read_bytes(), files['new_feature.py'])

    def test_first_install_copy_failure_can_be_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_write = installer.atomic_write
            def fail_one(path, data, mode=0o644):
                if path.name == 'falcon_gui.py':
                    raise OSError('disk error')
                return real_write(path, data, mode)
            with patch.object(installer, 'atomic_write', side_effect=fail_one):
                with self.assertRaises(OSError):
                    installer.install(SOURCE, root)
            app, entry = installer.install(SOURCE, root)
            self.assertTrue((app / 'falcon_gui.py').is_file())
            self.assertTrue(entry.is_file())

    def test_validate_does_not_execute_release_code_and_installs_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = release_files()
            # Code in the package would raise if imported or executed during validation/install.
            files['falcon_check.py'] += b'\nraise RuntimeError("Never run during update")\n'
            manifest = json.loads(files['release.json'])
            manifest['files']['falcon_check.py'] = hashlib.sha256(files['falcon_check.py']).hexdigest()
            files['release.json'] = json.dumps(manifest).encode()
            path = root / 'release.tar.gz'
            package(path, files)
            release = updater.validate_package(path, '0.9')
            app, entry = updater.install_validated(release, root / 'data', '0.9')
            self.assertEqual((app / 'falcon_check.py').read_bytes(), files['falcon_check.py'])
            self.assertIn('X-Falcon-Check-Version=0.10', entry.read_text())
            self.assertEqual(updater.current_version('0.9', root / 'data'), '0.10')

    def test_damage_rejected_without_installing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'release.tar.gz'
            files = release_files()
            files['falcon_gui.py'] += b'changed'
            package(path, files)
            with self.assertRaisesRegex(ValueError, 'Checksum mismatch'):
                updater.validate_package(path, '0.9')
            self.assertFalse((Path(directory) / 'falcon-check').exists())

    def test_same_or_older_release_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'release.tar.gz'
            package(path)
            for version in ('0.10', '0.10', '1.0'):
                with self.assertRaisesRegex(ValueError, 'newer release'):
                    updater.validate_package(path, version)

    def test_numeric_version_comparison(self):
        self.assertGreater(updater.version_key('0.10'), updater.version_key('0.9'))
        self.assertEqual(updater.version_key('0.9'), updater.version_key('0.9.0'))
        with self.assertRaises(ValueError):
            updater.version_key('../bad')

    def test_paths_links_duplicates_and_extra_files_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'release.tar.gz'
            cases = []
            for name in ('../outside', '/tmp/outside', 'falcon-check-v0.10/../../outside',
                         'falcon-check-v0.10/falcon_check.py', 'falcon-check-v0.10/unlisted.txt'):
                member = tarfile.TarInfo(name)
                member.size = 1
                cases.append((member, b'x'))
            link = tarfile.TarInfo('falcon-check-v0.10/linked.py')
            link.type = tarfile.SYMTYPE
            link.linkname = '/tmp/outside'
            cases.append((link, b''))
            for member, body in cases:
                with self.subTest(name=member.name):
                    package(path, extras=[(member, body)])
                    with self.assertRaises(ValueError):
                        updater.validate_package(path, '0.9')
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_missing_manifest_or_payload_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'release.tar.gz'
            for missing in ('release.json', 'falcon_gui.py'):
                files = release_files()
                del files[missing]
                if missing != 'release.json':
                    manifest = json.loads(files['release.json'])
                    del manifest['files'][missing]
                    files['release.json'] = json.dumps(manifest).encode()
                package(path, files)
                with self.assertRaises(ValueError):
                    updater.validate_package(path, '0.9')

    def test_compression_bomb_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'huge.tar.gz'
            path.write_bytes(gzip.compress(b'\0' * (updater.MAX_PACKAGE + 1)))
            with self.assertRaisesRegex(ValueError, 'Expanded'):
                updater.validate_package(path, '0.9')

    def test_copy_failure_preserves_previous_menu_and_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_app, entry = installer.install(SOURCE, root)
            old_menu = entry.read_bytes()
            old_source = (old_app / 'falcon_check.py').read_bytes()
            real_write = installer.atomic_write
            def fail_one(path, data, mode=0o644):
                if path.name == 'falcon_gui.py':
                    raise OSError('simulated disk failure')
                return real_write(path, data, mode)
            with patch.object(installer, 'atomic_write', side_effect=fail_one):
                with self.assertRaises(OSError):
                    installer.install(SOURCE, root)
            self.assertEqual(entry.read_bytes(), old_menu)
            self.assertEqual((old_app / 'falcon_check.py').read_bytes(), old_source)
            self.assertEqual(list(old_app.parent.iterdir()), [old_app])

    def test_failed_menu_publication_preserves_old_menu(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_app, entry = installer.install(SOURCE, root)
            old_menu = entry.read_bytes()
            real_write = installer.atomic_write
            def fail_menu(path, data, mode=0o644):
                if path == entry:
                    raise OSError('menu write failure')
                return real_write(path, data, mode)
            with patch.object(installer, 'atomic_write', side_effect=fail_menu):
                with self.assertRaises(OSError):
                    installer.install(SOURCE, root)
            self.assertEqual(entry.read_bytes(), old_menu)
            self.assertTrue((old_app / 'falcon_check.py').is_file())

    def test_migrates_old_flat_installation_without_overwriting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / 'falcon-check'
            old.mkdir()
            (old / 'install.json').write_text(json.dumps({'app_id': installer.APP_ID}))
            (old / 'falcon_check.py').write_text('old version source')
            new, entry = installer.install(SOURCE, root)
            self.assertEqual((old / 'falcon_check.py').read_text(), 'old version source')
            self.assertNotEqual(new, old)
            self.assertIn(str(new), entry.read_text())

    def test_releases_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installer.install(SOURCE, root)
            releases = root / 'falcon-check' / 'releases'
            moved = root / 'other'
            releases.rename(moved)
            releases.symlink_to(moved)
            with self.assertRaises(ValueError):
                installer.install(SOURCE, root)

    def test_ui_validation_error_never_enables_install(self):
        window = updater.UpdateWindow.__new__(updater.UpdateWindow)
        window.closed = False
        window.working = True
        window.events = updater.queue.Queue()
        window.events.put(('validate', None, 'checksum mismatch'))
        window.status = Mock()
        window.choose_button = Mock()
        window.install_button = Mock()
        window.poll()
        self.assertFalse(window.working)
        window.install_button.configure.assert_not_called()
        self.assertIn('not installed', window.status.configure.call_args.kwargs['text'])

    def test_restart_targets_installed_version_then_closes(self):
        window = updater.UpdateWindow.__new__(updater.UpdateWindow)
        window.installed = Path('/tmp/user data/falcon-check/releases/v0.10-test')
        window.close = Mock()
        window.on_restart = Mock()
        with patch.object(updater.subprocess, 'Popen') as launch:
            window.restart()
        self.assertEqual(launch.call_args.args[0][1], str(window.installed / 'falcon_check.py'))
        window.on_restart.assert_called_once()
        window.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
