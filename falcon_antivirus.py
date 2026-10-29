"""Optional ClamAV setup in the user's data directory; no sudo or services.

Only explicit setup/database-update actions use the network. Scans stay local.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
import urllib.request

from install_launcher import data_directory, atomic_write

ENGINE_VERSION = '1.4.6'
PACKAGE_URL = 'https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.4.6/clamav-1.4.6.linux.x86_64.deb'
PACKAGE_SHA256 = 'd3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2'
PACKAGE_BYTES = 94663320


def home():
    return data_directory() / 'falcon-check-antivirus'


def local_engine():
    base = home()
    marker = base / 'engine.json'
    if not marker.is_file() or marker.is_symlink():
        return None
    data = json.loads(marker.read_text())
    folder = data['folder']
    if not isinstance(folder, str) or '/' in folder or '\\' in folder or not folder.startswith('engine-'):
        raise ValueError('Invalid local antivirus location.')
    prefix = base / folder / 'usr' / 'local'
    if not (prefix / 'bin' / 'clamscan').is_file():
        raise ValueError('Local ClamAV files are missing; run antivirus setup again.')
    return {'executable': str(prefix / 'bin' / 'clamscan'), 'freshclam': str(prefix / 'bin' / 'freshclam'),
            'database': str(base / 'database'), 'prefix': str(prefix), 'local': True}


def configuration():
    configured = local_engine()
    if configured:
        return configured
    executable = shutil.which('clamscan')
    if executable:
        return {'executable': executable, 'freshclam': shutil.which('freshclam'), 'database': None, 'prefix': None, 'local': False}
    return None


def environment(config):
    env = dict(os.environ, LC_ALL='C')
    if config.get('prefix'):
        prefix = Path(config['prefix'])
        # This change applies to the child only, not the user's shell/session.
        env['LD_LIBRARY_PATH'] = os.pathsep.join(str(prefix / name) for name in ('lib', 'lib64'))
    return env


def database_args(config):
    return ['--database=' + config['database']] if config.get('database') else []


def stopped(cancel):
    if cancel is not None and cancel.is_set():
        raise RuntimeError('Operation cancelled. Previously installed engine remains available.')


def run(command, env=None, cancel=None, timeout=300, input_data=None):
    with tempfile.TemporaryFile() as log, tempfile.TemporaryFile() as source:
        if input_data is not None:
            source.write(input_data)
            source.seek(0)
        with subprocess.Popen(command, stdin=source if input_data is not None else subprocess.DEVNULL,
                              stdout=log, stderr=subprocess.STDOUT, env=env) as process:
            end = time.monotonic() + timeout
            try:
                while process.poll() is None:
                    stopped(cancel)
                    if time.monotonic() > end:
                        raise RuntimeError('Operation timed out; it was stopped.')
                    try:
                        process.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        pass
            except BaseException:
                process.kill()
                process.wait()
                raise
            log.seek(0)
            output = log.read(32000).decode('utf-8', 'replace')
            return process.returncode, output


def download_package(path, cancel=None, progress=lambda message: None):
    request = urllib.request.Request(PACKAGE_URL, headers={'User-Agent': 'FalconCheck/0.7'})
    count = 0
    digest = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=30) as response, path.open('wb') as destination:
        if not response.geturl().startswith('https://'):
            raise ValueError('Refusing a non-HTTPS download.')
        while True:
            stopped(cancel)
            data = response.read(1024 * 1024)
            if not data:
                break
            count += len(data)
            if count > PACKAGE_BYTES:
                raise ValueError('ClamAV download exceeded the expected package size.')
            destination.write(data)
            digest.update(data)
            progress('Downloading ClamAV: {:.0%} of about 90 MiB'.format(count / PACKAGE_BYTES))
        destination.flush()
        os.fsync(destination.fileno())
    if count != PACKAGE_BYTES or digest.hexdigest() != PACKAGE_SHA256:
        raise ValueError('ClamAV download verification failed. Nothing was installed; retry later.')
    # Check saved bytes as well as transport bytes before any extraction/execution.
    saved = hashlib.sha256()
    with path.open('rb') as source:
        for data in iter(lambda: source.read(1024 * 1024), b''):
            saved.update(data)
    if saved.hexdigest() != PACKAGE_SHA256:
        raise ValueError('Saved ClamAV package checksum mismatch. Nothing was installed.')


def install_engine(cancel=None, progress=lambda message: None):
    if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        raise ValueError('Built-in setup currently supports x86-64 Linux only.')
    dpkg = shutil.which('dpkg-deb')
    if not dpkg:
        raise ValueError('Setup requires dpkg-deb (normally included with Linux Mint). No system packages were changed.')
    base = home()
    if base.is_symlink():
        raise ValueError('Refusing a linked antivirus setup directory.')
    base.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='engine-', dir=str(base)))
    published = False
    try:
        package = root / 'package.deb'
        download_package(package, cancel, progress)
        stopped(cancel)
        progress('Verified download. Unpacking into your own account…')
        code, output = run([dpkg, '--extract', str(package), str(root)], cancel=cancel)
        if code:
            raise RuntimeError('Could not unpack ClamAV: ' + output[-1000:])
        package.unlink()
        prefix = root / 'usr' / 'local'
        config = {'prefix': str(prefix)}
        check_config = root / 'freshclam-check.conf'
        check_config.write_text('DatabaseMirror database.clamav.net\n')
        progress('Checking whether the ClamAV engine runs on this laptop…')
        for binary in ('clamscan', 'freshclam'):
            command = [str(prefix / 'bin' / binary), '--version']
            if binary == 'freshclam':
                command.append('--config-file=' + str(check_config))
            code, output = run(command, env=environment(config), cancel=cancel, timeout=30)
            if code or not output.startswith('ClamAV ' + ENGINE_VERSION):
                raise RuntimeError('ClamAV compatibility check failed: ' + output[-1000:])
        database = base / 'database'
        if database.is_symlink():
            raise ValueError('Refusing a linked database directory.')
        database.mkdir(exist_ok=True)
        stopped(cancel)
        atomic_write(base / 'engine.json', json.dumps({'folder': root.name, 'version': ENGINE_VERSION}).encode())
        published = True
        return 'ClamAV ' + ENGINE_VERSION + ' is installed for your account. Next click Download/update signatures before scanning.'
    finally:
        if not published:
            shutil.rmtree(root, ignore_errors=True)


def update_signatures(cancel=None, progress=lambda message: None):
    config = local_engine()
    if not config:
        raise ValueError('Set up the private engine first. System ClamAV updates remain managed by its administrator.')
    base = home()
    # Pass the database path as one argv element, supporting spaces in usernames.
    config_path = base / 'freshclam.conf'
    atomic_write(config_path, b'DatabaseMirror database.clamav.net\nMaxAttempts 1\nConnectTimeout 30\nReceiveTimeout 60\nTestDatabases yes\n')
    progress('Downloading/checking ClamAV signatures. The first download may take several minutes. No selected files are uploaded.')
    command = [config['freshclam'], '--config-file=' + str(config_path), '--datadir=' + config['database'], '--stdout']
    code, output = run(command, env=environment(config), cancel=cancel, timeout=900)
    if code:
        raise RuntimeError('Signature update did not finish. If rate-limited, wait until the time in this message; do not keep retrying.\n' + output[-5000:])
    return 'Signature update completed.\n' + output[-5000:]


def readiness(cancel=None):
    config = configuration()
    if not config:
        return 'NOT READY: ClamAV is missing. Use Download/setup engine below.'
    code, output = run([config['executable'], '--version'] + database_args(config), env=environment(config), timeout=15, cancel=cancel)
    if code:
        return 'NOT READY: engine could not start.\n' + output[-1500:]
    if config['local']:
        database = Path(config['database'])
        present = all(any((database / (name + suffix)).is_file() for suffix in ('.cvd', '.cld')) for name in ('main', 'daily'))
        if not present:
            return 'ENGINE INSTALLED; SIGNATURES MISSING. Click Download/update signatures.\n' + output
    code, scan_output = run([config['executable'], '--stdout'] + database_args(config) + ['-'],
                            env=environment(config), timeout=120, cancel=cancel, input_data=b'Falcon Check harmless engine readiness check.\n')
    if code == 0 and 'Scanned files: 1' in scan_output:
        return 'READY: engine loaded its database and scanned harmless test text.\n' + output + '\nKeep signatures updated. This is not a test of all malware detection.'
    return 'NOT READY: database/scan check did not complete.\n' + output + scan_output[-2500:]


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Private ClamAV setup for Falcon Check; no sudo')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true', help='check engine and signatures locally')
    group.add_argument('--install', action='store_true', help='download and set up the pinned ClamAV engine for this user')
    group.add_argument('--update-signatures', action='store_true', help='download/update private signatures using FreshClam')
    args = parser.parse_args()
    try:
        if args.install:
            print(install_engine(progress=lambda message: print(message, flush=True)))
        elif args.update_signatures:
            print(update_signatures(progress=lambda message: print(message, flush=True)))
        else:
            message = readiness()
            print(message)
            return 0 if message.startswith('READY:') else 2
    except (Exception, KeyboardInterrupt) as error:
        print('Operation did not complete:', str(error))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
