"""Streaming inspection backend shared by the window and terminal."""
import codecs
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from falcon_formats import identify, header_facts

CHUNK = 1024 * 1024
PREFIX = 65536
OVERLAP = 4096
MODES = ('combined', 'auto', 'python', 'text', 'details', 'executable', 'archive', 'antivirus')


class Cancelled(Exception):
    pass


def check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise Cancelled()


def progress_event(progress, phase, done=None, total=None):
    if progress is not None:
        progress({'event': 'progress', 'phase': phase, 'done': done, 'total': total})


class TextChecks:
    def __init__(self):
        from falcon_check import COMPILED_RULES
        self.rules = COMPILED_RULES
        self.decoder = codecs.getincrementaldecoder('utf-8-sig')()
        self.findings = {}
        self.tail = ''
        self.newlines = 0
        self.invalid = False

    def feed(self, data, final=False):
        if self.invalid:
            return
        try:
            text = self.decoder.decode(data, final=final)
            if '\x00' in text:
                raise ValueError('NUL byte')
        except (UnicodeDecodeError, ValueError):
            self.invalid = True
            return
        window = self.tail + text
        first_line = 1 + self.newlines - self.tail.count('\n')
        for key, title, pattern, why in self.rules:
            if key in self.findings:
                continue
            match = pattern.search(window)
            if match:
                self.findings[key] = {'rule': key, 'title': title, 'why': why,
                                      'line': first_line + window.count('\n', 0, match.start()),
                                      'evidence': match.group(0)[:160]}
        self.newlines += text.count('\n')
        self.tail = window[-OVERLAP:]

    def result(self):
        findings = list(self.findings.values())
        status = 'NEEDS REVIEW' if findings else 'NO INDICATORS FOUND'
        coverage = 'Seven streaming UTF-8 text-pattern checks over the file; 4 KiB overlap, first hit per rule.'
        if self.invalid:
            status = 'NEEDS REVIEW' if findings else 'PARTIAL INSPECTION'
            coverage = 'Text checks incomplete: binary content or invalid UTF-8 encountered.'
        return {'status': status, 'findings': findings, 'coverage': coverage,
                'notes': ['Text patterns do not understand program behavior. Matches spanning more than the overlap across chunks can be missed.']}


def terminate(process):
    if process.poll() is None:
        process.kill()
    process.communicate()


def worker(stream, kind, cancel=None):
    stream.seek(0)
    temporary = None
    try:
        try:
            stream.fileno()
            source = stream
        except (io.UnsupportedOperation, AttributeError):
            temporary = tempfile.TemporaryFile()
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                temporary.write(block)
            temporary.seek(0)
            source = temporary
        script = Path(__file__).with_name('falcon_worker.py')
        with subprocess.Popen([sys.executable, '-I', str(script), kind], stdin=source,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            deadline = time.monotonic() + 25
            while True:
                try:
                    check_cancel(cancel)
                except Cancelled:
                    terminate(process)
                    raise
                if time.monotonic() > deadline:
                    terminate(process)
                    return {'status': 'NOT INSPECTED' if kind == 'python' else 'PARTIAL INSPECTION',
                            'findings': [], 'coverage': 'Parser time limit reached; analysis incomplete.'}
                try:
                    output, _ = process.communicate(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    pass
            if process.returncode != 0:
                return {'status': 'NOT INSPECTED' if kind == 'python' else 'PARTIAL INSPECTION',
                        'findings': [], 'coverage': 'Parser stopped or exceeded a resource limit; analysis incomplete.'}
            return json.loads(output)
    finally:
        if temporary is not None:
            temporary.close()


def classify_antivirus(returncode, output):
    found = [line for line in output.splitlines() if line.endswith(' FOUND')]
    limits = [line for line in found if 'Heuristics.Limits.Exceeded' in line or 'Heuristics.Encrypted' in line]
    detections = [line for line in found if line not in limits]
    if detections:
        status = 'THREAT REPORTED'
    elif limits:
        status = 'PARTIAL INSPECTION'
    elif returncode == 0 and re.search(r'Scanned files:\s*[1-9]\d*', output):
        status = 'NO THREATS REPORTED'
    else:
        status = 'NOT INSPECTED'
    notes = ['ClamAV results depend on installed signatures and engine limits; no result guarantees safety.']
    if limits:
        notes.append('Encrypted content or engine limits prevented a complete scan.')
    if returncode == 2:
        notes.append('ClamAV reported an error; inspect its output below.')
    return {'status': status, 'findings': [], 'coverage': 'External ClamAV signature/heuristic scan under its supported formats and limits.',
            'notes': notes, 'engine_output': output[:32000]}


def antivirus(stream, size, cancel=None):
    from falcon_antivirus import configuration, environment, database_args
    config = configuration()
    if config is None:
        return {'status': 'ANTIVIRUS UNAVAILABLE', 'findings': [],
                'coverage': 'ClamAV did not run. clamscan is not installed or is not on PATH.',
                'notes': ['Open Antivirus setup to install a private engine and download signatures without sudo. Scanning itself does not download or upload anything.']}
    executable = config['executable']
    if config['local']:
        database = Path(config['database'])
        if not all(any((database / (name + suffix)).is_file() for suffix in ('.cvd', '.cld')) for name in ('main', 'daily')):
            return {'status': 'NOT INSPECTED', 'findings': [],
                    'coverage': 'Engine installed, but the main/daily signature databases are missing. No malware scan ran.',
                    'notes': ['Open Antivirus setup and click Download/update signatures.']}
    if size > 1024 * 1024 * 1024:
        return {'status': 'PARTIAL INSPECTION', 'findings': [],
                'coverage': 'ClamAV was not run: this integration has a 1 GiB input limit. File fingerprinting still completed.'}
    stream.seek(0)
    try:
        stream.fileno()
    except (io.UnsupportedOperation, AttributeError):
        with tempfile.TemporaryFile() as source:
            while True:
                check_cancel(cancel)
                block = stream.read(CHUNK)
                if not block:
                    break
                source.write(block)
            source.seek(0)
            return antivirus(source, size, cancel)
    engine_environment = environment(config)
    command = [executable, '--stdout', '--max-filesize=1024M', '--max-scansize=2048M',
               '--max-recursion=16', '--max-files=10000', '--max-scantime=0',
               '--alert-exceeds-max=yes', '--alert-encrypted=yes'] + database_args(config) + ['-']
    # Only the existing antivirus program is launched. The selected file is stdin data.
    with tempfile.TemporaryFile() as log:
        with subprocess.Popen(command, stdin=stream, stdout=log, stderr=subprocess.STDOUT,
                              env=engine_environment) as process:
            deadline = time.monotonic() + 300
            while process.poll() is None:
                try:
                    check_cancel(cancel)
                except Cancelled:
                    terminate(process)
                    raise
                if time.monotonic() > deadline:
                    terminate(process)
                    return {'status': 'PARTIAL INSPECTION', 'findings': [], 'coverage': 'ClamAV exceeded five minutes; it was stopped.'}
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    pass
            log.seek(0)
            output = log.read(32001).decode('utf-8', 'replace')
            result = classify_antivirus(process.returncode, output)
            if len(output) > 32000:
                result['notes'].append('Engine output truncated to 32,000 characters.')
    try:
        version = subprocess.run([executable, '--version'] + database_args(config), capture_output=True, timeout=5,
                                 env=engine_environment).stdout.decode('utf-8', 'replace').strip()[:500]
        result.setdefault('facts', []).append(('ClamAV engine / database', version or 'Version unavailable'))
    except (OSError, subprocess.TimeoutExpired):
        pass
    return result


def inspect_stream(stream, size, name, mode='auto', cancel=None, progress=None):
    from falcon_check import MAX_PYTHON_BYTES
    if mode not in MODES:
        raise ValueError('Unknown analysis mode')
    combined = mode == 'combined'
    result = {'name': str(name), 'size': size, 'sha256': None, 'status': 'NOT INSPECTED', 'mode': mode,
              'coverage': '', 'findings': [], 'facts': [], 'notes': [], 'members': []}
    try:
        check_cancel(cancel)
        header = stream.read(min(PREFIX, size))
        kind, label = identify(header, name)
        result['facts'] = [('Detected type', label)] + header_facts(header, kind)
        selected = mode
        if mode in ('auto', 'combined'):
            if kind == 'text':
                selected = 'python' if Path(str(name)).suffix.lower() in ('.py', '.pyw') else 'text'
            elif kind in ('zip', 'tar', 'gzip', 'deb'):
                selected = 'archive'
            elif kind in ('elf', 'pe'):
                selected = 'executable'
            else:
                selected = 'details'
        checker = TextChecks() if selected == 'text' and kind == 'text' else None
        digest = hashlib.sha256()
        stream.seek(0)
        done = 0
        last_update = 0.0
        progress_event(progress, 'Reading and fingerprinting', 0, size)
        while done < size:
            check_cancel(cancel)
            block = stream.read(min(CHUNK, size - done))
            if not block:
                raise ValueError('File became shorter during the read.')
            digest.update(block)
            if checker is not None:
                checker.feed(block)
            done += len(block)
            now = time.monotonic()
            if now - last_update >= 0.1:
                progress_event(progress, 'Reading and fingerprinting', done, size)
                last_update = now
        if checker is not None:
            checker.feed(b'', final=True)
        result['sha256'] = digest.hexdigest()
        progress_event(progress, 'Reading and fingerprinting', size, size)
        check_cancel(cancel)
        if selected == 'details':
            result.update(status='BASIC INSPECTION', coverage='Whole-file SHA-256, size, and header identification only. No malware verdict.')
            if kind in ('elf', 'pe'):
                result['notes'].append('Executable behavior, bundled contents and digital signatures were not verified. Antivirus mode is available if ClamAV is installed.')
        elif selected == 'text':
            if checker is None:
                result.update(status='NOT INSPECTED', coverage='Text checks require UTF-8 text; this file appears to be a different format. Fingerprinting completed.')
            else:
                result.update(checker.result())
        elif selected == 'python':
            if kind != 'text' or size > MAX_PYTHON_BYTES:
                result.update(status='NOT INSPECTED', coverage='Python syntax requires UTF-8 source up to 2 MiB. Fingerprinting completed; use Text patterns for larger text.')
            else:
                progress_event(progress, 'Analyzing Python syntax')
                extra = worker(stream, 'python', cancel)
                result.update(extra)
        elif selected == 'executable':
            if kind not in ('elf', 'pe'):
                result.update(status='NOT INSPECTED', coverage='Executable inspection supports ELF and PE candidates only; fingerprinting completed.')
            else:
                progress_event(progress, 'Inspecting executable structure and strings')
                extra = worker(stream, 'executable-' + kind, cancel)
                facts = result['facts'] + [(label, value) for label, value in extra.pop('facts', [])]
                result.update(extra)
                result['facts'] = facts
        elif selected == 'archive':
            if kind not in ('zip', 'tar', 'gzip', 'deb'):
                result.update(status='BASIC INSPECTION', coverage='Header and fingerprint only: inventory supports ZIP/JAR, TAR/TAR.GZ, and Debian/ar packages.')
            else:
                progress_event(progress, 'Inspecting archive metadata')
                extra = worker(stream, kind, cancel)
                facts = result['facts'] + [(label, value) for label, value in extra.pop('facts', [])]
                result.update(extra)
                result['facts'] = facts
        elif selected == 'antivirus':
            progress_event(progress, 'Running ClamAV (if installed)')
            extra = antivirus(stream, size, cancel)
            facts = result['facts'] + [(label, value) for label, value in extra.pop('facts', [])]
            result.update(extra)
            result['facts'] = facts
        if combined:
            static_status = result['status']
            static_coverage = result['coverage']
            result['checks'] = [('Built-in inspection', static_status), ('Malware scan (ClamAV)', 'IN PROGRESS')]
            progress_event(progress, 'Running local ClamAV malware check')
            try:
                av = antivirus(stream, size, cancel)
            except (OSError, ValueError) as error:
                av = {'status': 'NOT INSPECTED', 'coverage': str(error), 'notes': []}
            result['checks'] = [('Built-in inspection', static_status), ('Malware scan (ClamAV)', av['status'])]
            result['coverage'] = 'Built-in: ' + static_coverage + '\nClamAV: ' + av['coverage']
            result['notes'] += av.get('notes', [])
            result['facts'] += av.get('facts', [])
            result['engine_output'] = av.get('engine_output', '')
            if av['status'] == 'THREAT REPORTED':
                result['status'] = 'THREAT REPORTED'
            elif result['findings']:
                result['status'] = 'NEEDS REVIEW'
            elif av['status'] != 'NO THREATS REPORTED' or static_status in ('NOT INSPECTED', 'PARTIAL INSPECTION'):
                result['status'] = 'PARTIAL INSPECTION'
            else:
                result['status'] = 'NO THREATS REPORTED'
        return result
    except Cancelled:
        if result.get('checks'):
            result['checks'] = [(label, 'CANCELLED' if status == 'IN PROGRESS' else status)
                                for label, status in result['checks']]
        result.update(status='CANCELLED', coverage='Inspection was cancelled; no completed analysis verdict.', findings=[])
        return result


def scan_file(filename, mode='auto', cancel=None, progress=None):
    path = Path(filename).expanduser()
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(str(path), flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('Choose a regular file, not a folder or device.')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            result = inspect_stream(stream, before.st_size, path, mode, cancel, progress)
        after = os.fstat(fd)
        result['source_is_file'] = True
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            result.update(status='PARTIAL INSPECTION', sha256=None, coverage='File changed during inspection; results may be inconsistent. Scan again when it is idle.')
        return result
    finally:
        os.close(fd)
