"""Local release updater. Validates data without importing release code."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading

import install_launcher as installer

MAX_PACKAGE = 8 * 1024 * 1024
MAX_MEMBER = 1024 * 1024


def version_key(version):
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}(?:\.[0-9]{1,4})?', version):
        raise ValueError('Unsupported release version.')
    numbers = tuple(int(part) for part in version.split('.'))
    return numbers + (0,) * (3 - len(numbers))


def current_version(fallback, data_home=None):
    home = Path(data_home) if data_home is not None else installer.data_directory()
    entry = home / 'applications' / 'falcon-check.desktop'
    versions = [fallback]
    if entry.is_file() and not entry.is_symlink():
        text = entry.read_text()
        if installer.MANAGED_KEY in text.splitlines():
            match = re.search(r'^X-Falcon-Check-Version=(.+)$', text, re.M)
            if match:
                version_key(match.group(1))
                versions.append(match.group(1))
    return max(versions, key=version_key)


def validate_package(path, installed_version):
    """Bound bytes first, then inspect tar entries in memory; never extract paths."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(str(Path(path).expanduser()), flags)
    with os.fdopen(fd, 'rb') as raw:
        info = os.fstat(raw.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PACKAGE:
            raise ValueError('Choose a regular Falcon Check .tar.gz package no larger than 8 MiB.')
        with gzip.GzipFile(fileobj=raw) as archive:
            data = archive.read(MAX_PACKAGE + 1)
        if len(data) > MAX_PACKAGE:
            raise ValueError('Expanded update package exceeds 8 MiB.')
    entries = {}
    root_name = None
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for number, member in enumerate(archive):
            if number >= 64:
                raise ValueError('Too many update archive entries.')
            parts = PurePosixPath(member.name).parts
            if '\\' in member.name or member.name.startswith('/') or '..' in parts:
                raise ValueError('Unsafe update archive path.')
            if member.isdir() and len(parts) == 1:
                continue
            if not member.isfile() or len(parts) != 2 or not 0 <= member.size <= MAX_MEMBER:
                raise ValueError('Update requires small regular files in one release folder; links are refused.')
            folder, name = parts
            if root_name is None:
                root_name = folder
            if folder != root_name or name in entries:
                raise ValueError('Mixed release folders or duplicate files.')
            if not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
                raise ValueError('Unsupported update filename.')
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError('Unreadable update entry.')
            body = handle.read(MAX_MEMBER + 1)
            if len(body) != member.size:
                raise ValueError('Truncated update member.')
            entries[name] = body
    try:
        manifest = json.loads(entries['release.json'])
        version = manifest['version']
        if manifest['app_id'] != installer.APP_ID or manifest['format'] != 1:
            raise ValueError('Not a supported Falcon Check release.')
        if version_key(version) <= version_key(installed_version):
            raise ValueError('Choose a newer release than ' + installed_version + '.')
        if root_name != 'falcon-check-v' + version:
            raise ValueError('Release folder/version mismatch.')
        hashes = manifest['files']
        if not isinstance(hashes, dict) or set(hashes) != set(entries) - {'release.json'}:
            raise ValueError('Manifest and package file lists differ.')
        for name, expected in hashes.items():
            if not isinstance(expected, str) or hashlib.sha256(entries[name]).hexdigest() != expected:
                raise ValueError('Checksum mismatch: ' + name)
        payload_names = manifest['payload']
        if not isinstance(payload_names, list) or any(not isinstance(name, str) for name in payload_names):
            raise ValueError('Invalid application file list.')
        if len(set(payload_names)) != len(payload_names) or any(
                not re.fullmatch(r'[A-Za-z0-9_-]+\.(?:py|svg)', name) for name in payload_names):
            raise ValueError('Unsupported application filename.')
        if not set(installer.PAYLOAD).issubset(payload_names) or not set(payload_names).issubset(entries):
            raise ValueError('Release is missing required app files.')
        if installer.source_version(entries['falcon_check.py']) != version:
            raise ValueError('Source version and manifest disagree.')
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError('Missing or invalid release manifest.') from error
    return {'version': version, 'payload': {name: entries[name] for name in payload_names}}


def install_validated(release, data_home=None, running_version=None):
    # Repeat the version guard in case another window updated the menu meanwhile.
    if running_version is not None and version_key(release['version']) <= version_key(current_version(running_version, data_home)):
        raise ValueError('This release is already installed or an even newer version is present.')
    with tempfile.TemporaryDirectory(prefix='falcon-update-') as directory:
        source = Path(directory)
        for name in release['payload']:
            (source / name).write_bytes(release['payload'][name])
        return installer.install(source, data_home, payload_names=release['payload'])


class UpdateWindow:
    def __init__(self, parent, running_version, on_restart):
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
        self.filedialog, self.messagebox = filedialog, messagebox
        self.running_version, self.on_restart = running_version, on_restart
        self.release = None
        self.installed = None
        self.picker = None
        self.after_id = None
        self.working = False
        self.closed = False
        self.events = queue.Queue()
        self.window = tk.Toplevel(parent)
        self.window.title('Update Falcon Check')
        self.window.geometry('660x460')
        self.window.minsize(620, 440)
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        frame = ttk.Frame(self.window, padding=22)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Install a downloaded update', font=('DejaVu Sans', 15, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Running version: ' + running_version, wraplength=500).pack(anchor='w', pady=(8, 12))
        ttk.Label(frame, text='Choose the Falcon Check .tar.gz release downloaded from our chat. No extraction or terminal needed.\n\n'
                  'Only install updates you trust. Checksums catch damaged files; they do not verify who made the package.',
                  wraplength=520, justify='left').pack(anchor='w')
        self.status = ttk.Label(frame, text='Select a newer release to review before installing.', wraplength=520, justify='left')
        self.status.pack(anchor='w', pady=18, fill='x')
        self.choose_button = ttk.Button(frame, text='Choose update…', command=self.choose)
        self.choose_button.pack(anchor='w')
        self.install_button = ttk.Button(frame, text='Install update', command=self.install, state='disabled')
        self.install_button.pack(anchor='w', pady=8)
        ttk.Button(frame, text='Close', command=self.close).pack(anchor='e')

    def choose(self):
        import falcon_picker
        if self.working:
            return
        self.release = None
        self.install_button.configure(state='disabled', text='Install update')
        self.choose_button.configure(state='disabled')
        self.picker = falcon_picker.start_picker('Choose a Falcon Check update (.tar.gz)')
        if self.picker is None:
            self.fallback_picker()
        else:
            self.after_id = self.window.after(80, self.poll_picker)

    def fallback_picker(self):
        path = self.filedialog.askopenfilename(parent=self.window, title='Choose a Falcon Check update',
                                             filetypes=[('Falcon Check release', '*.tar.gz'), ('All files', '*')])
        self.accept_path(path)

    def poll_picker(self):
        import falcon_picker
        self.after_id = None
        if self.closed:
            return
        if self.picker.poll() is None:
            self.after_id = self.window.after(80, self.poll_picker)
            return
        try:
            path = falcon_picker.picker_result(self.picker)
        except OSError:
            path = None
        self.picker = None
        if path is None:
            self.fallback_picker()
        else:
            self.accept_path(path)

    def accept_path(self, path):
        if not path:
            self.choose_button.configure(state='normal')
            self.status.configure(text='No update selected.')
            return
        self.begin(lambda: validate_package(path, current_version(self.running_version)), 'validate')
        self.status.configure(text='Checking the package contents…')

    def begin(self, operation, action):
        self.working = True
        self.choose_button.configure(state='disabled')
        self.install_button.configure(state='disabled')
        def run():
            try:
                self.events.put((action, operation(), None))
            except Exception as error:
                self.events.put((action, None, str(error)))
        # Installation may finish even if the main window closes; do not kill a
        # write halfway through. Closing this dialog while busy is refused.
        threading.Thread(target=run, daemon=False).start()
        self.after_id = self.window.after(60, self.poll)

    def poll(self):
        self.after_id = None
        if self.closed:
            return
        try:
            action, value, error = self.events.get_nowait()
        except queue.Empty:
            self.after_id = self.window.after(60, self.poll)
            return
        self.working = False
        if error:
            from falcon_gui import display_text
            self.status.configure(text='Update not installed: ' + display_text(error))
            self.choose_button.configure(state='normal')
            return
        if action == 'validate':
            self.release = value
            self.status.configure(text='Version ' + value['version'] + ' is ready. Package checksums match.\n'
                                  'Click Install update to update your menu app; the running window stays on its current version until restarted.')
            self.choose_button.configure(state='normal')
            self.install_button.configure(state='normal')
        else:
            self.installed = value[0]
            self.status.configure(text='Version ' + self.release['version'] + ' installed. Restart now, or close and open Falcon Check from the menu later.')
            self.install_button.configure(text='Restart now', command=self.restart, state='normal')

    def install(self):
        if self.release is not None and not self.working:
            self.status.configure(text='Installing the new version for your account…')
            self.begin(lambda: install_validated(self.release, running_version=self.running_version), 'install')

    def restart(self):
        try:
            subprocess.Popen([sys.executable, str(self.installed / 'falcon_check.py'), '--gui'])
        except OSError as error:
            self.messagebox.showerror('Could not restart', str(error), parent=self.window)
            return
        self.close()
        self.on_restart()

    def close(self):
        if self.working:
            self.status.configure(text='Please wait for the current update operation to finish.')
            return
        self.closed = True
        if self.after_id is not None:
            self.window.after_cancel(self.after_id)
        if self.picker is not None:
            import falcon_picker
            threading.Thread(target=falcon_picker.stop_picker, args=(self.picker,), daemon=True).start()
        self.window.destroy()
