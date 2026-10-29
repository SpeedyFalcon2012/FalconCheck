"""Preview one supported source change; save only to a new file after approval."""
from dataclasses import dataclass
import difflib
import hashlib
import os
import re
from pathlib import Path
import stat
import tempfile

import falcon_check as scanner

REPLACEMENT = b'pass  # Falcon Check: sensitive-file upload call removed for review.'
CONSEQUENCE = ('This removes one entire standalone upload call, including evaluation of its arguments. '
               'The program continues without that upload; an intended backup or other feature may stop working. '
               'Earlier file reads and other network calls remain. This is a proposed source change, not malware removal or a safety certificate.')


@dataclass(frozen=True)
class PatchPlan:
    source: str
    original_sha256: str
    updated: bytes
    diff: str
    finding: dict
    before: dict
    after: dict


def read_source(path):
    path = Path(path).expanduser().absolute()
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(str(path), flags)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > scanner.MAX_PYTHON_BYTES:
            raise ValueError('Patch previews require a regular UTF-8 source file up to 2 MiB.')
        data = handle.read(scanner.MAX_PYTHON_BYTES + 1)
        after = os.fstat(handle.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Source changed while being read. Scan it again.')
        if len(data) != before.st_size:
            raise ValueError('Source read was incomplete.')
    data.decode('utf-8-sig')
    return str(path), data


def upload_findings(report):
    return [finding for finding in report.get('findings', []) if finding['rule'] == 'sensitive-upload']


def prepare(path, expected_sha256=None, finding_id=None):
    source, original = read_source(path)
    fingerprint = hashlib.sha256(original).hexdigest()
    if expected_sha256 is not None and fingerprint != expected_sha256:
        raise ValueError('Source has changed since the scan. Scan it again before previewing a fix.')
    before = scanner.analyze_bytes(original, source, 'python')
    candidates = [f for f in upload_findings(before) if f.get('patch_span')]
    if finding_id is not None:
        candidates = [f for f in candidates if f['id'] == finding_id]
    if not candidates:
        raise ValueError('No matching patchable standalone upload call was found. Nested calls, return values, and one-line suites require manual review.')
    finding = candidates[0]
    first, col, last, end = finding['patch_span']
    bom = b'\xef\xbb\xbf' if original.startswith(b'\xef\xbb\xbf') else b''
    body = original[len(bom):]
    # Python AST columns are UTF-8 byte offsets, not character offsets.
    lines = re.split(rb'(?<=\n)|(?<=\r)(?!\n)', body)
    start = sum(len(line) for line in lines[:first - 1]) + col
    stop = sum(len(line) for line in lines[:last - 1]) + end
    updated = bom + body[:start] + REPLACEMENT + body[stop:]
    after = scanner.analyze_bytes(updated, source + ' (proposed copy)', 'python')
    if after['status'] not in ('NO INDICATORS FOUND', 'NEEDS REVIEW'):
        raise ValueError('The proposed copy could not be rechecked; no fix is offered.')
    if len(upload_findings(after)) >= len(upload_findings(before)):
        raise ValueError('The selected flow was not reduced by this change; manual review is required.')
    diff = ''.join(difflib.unified_diff(original.decode('utf-8-sig').splitlines(keepends=True),
                                     updated.decode('utf-8-sig').splitlines(keepends=True),
                                     fromfile='original', tofile='proposed copy'))
    return PatchPlan(source, fingerprint, updated, diff, finding, before, after)


def save_copy(plan, destination):
    # Refuse stale previews and any existing destination, including symlinks.
    source, data = read_source(plan.source)
    if hashlib.sha256(data).hexdigest() != plan.original_sha256:
        raise ValueError('Original changed after preview. Nothing saved; create a new preview.')
    target = Path(destination).expanduser().absolute()
    if target == Path(source):
        raise ValueError('Choose a separate output file; the original cannot be overwritten.')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=str(target.parent), prefix='.falcon-copy-', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(plan.updated)
            handle.flush()
            os.fsync(handle.fileno())
        # Hard-link publication is atomic and refuses existing paths. No replace.
        os.link(str(temporary), str(target))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    result = scanner.scan_file(target, 'python')
    if result.get('sha256') != hashlib.sha256(plan.updated).hexdigest():
        result.update(status='PARTIAL INSPECTION', coverage='Saved copy changed or could not be fingerprinted consistently; review it again.')
    return result


def preview_text(plan):
    item = plan.finding
    return ('Proposed change: remove the upload call at line ' + str(item['line']) + '\n\n' +
            CONSEQUENCE + '\n\nEvidence:\n' + '\n'.join(item['trace']) + '\nDestination: ' + item['destination'] +
            '\n\n' + item['inference'] + '\n\nPossible legitimate use: ' + item['legitimate_use'] +
            '\n\n' + item['uncertainty'] + '\n\n' + plan.diff + '\n\nRecheck of proposed bytes: ' + plan.after['status'] +
            '\nSensitive-upload findings: {} before, {} after. Other findings: {}.\n'.format(
                len(upload_findings(plan.before)), len(upload_findings(plan.after)),
                len(plan.after['findings']) - len(upload_findings(plan.after))) +
            'Rechecking uses the same limited Python analyzer, not runtime testing or antivirus. The original is unchanged.')


def cli(path, destination=None, finding_id=None):
    plan = prepare(path, finding_id=finding_id)
    # Escape hostile terminal controls while retaining line structure.
    from falcon_gui import display_text
    print('\n'.join(display_text(line) for line in preview_text(plan).splitlines()))
    if destination is None:
        print('\nPreview only. Add --save-fixed-copy NEW_PATH to review and approve a separate saved copy.')
        return 0
    try:
        answer = input('\nSave this proposed change to a NEW file? Type SAVE to approve: ')
    except (EOFError, KeyboardInterrupt):
        print('\nNot saved.')
        return 2
    if answer != 'SAVE':
        print('Not saved.')
        return 0
    result = save_copy(plan, destination)
    print('Saved a separate copy; original unchanged.')
    scanner.show_report(result)
    return 0
