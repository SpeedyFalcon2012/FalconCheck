"""Bounded header inspection and archive inventories. Never extracts members."""
import gzip
import os
from pathlib import PurePosixPath
import re
import stat
import struct
import tarfile
import zipfile

MAX_MEMBERS = 10000
MAX_TAR_BYTES = 64 * 1024 * 1024
PREVIEW_MEMBERS = 100


def identify(header, name=''):
    if header.startswith(b'\x7fELF'):
        return 'elf', 'ELF executable or library'
    if header.startswith(b'MZ'):
        return 'pe', 'DOS/Windows executable candidate'
    if header.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')):
        return 'zip', 'ZIP / JAR / ZIP-based package'
    if header.startswith(b'!<arch>\n'):
        return 'deb', 'ar archive / Debian package candidate'
    if header[257:262] == b'ustar':
        return 'tar', 'TAR archive'
    if header.startswith(b'\x1f\x8b'):
        return 'gzip', 'gzip-compressed file (possibly TAR)'
    for magic, label in [(b'%PDF-', 'PDF document'), (b'7z\xbc\xaf\x27\x1c', '7-Zip archive'),
                         (b'Rar!', 'RAR archive'), (b'\xfd7zXZ\x00', 'XZ-compressed file'),
                         (b'BZh', 'bzip2-compressed file'), (b'\x89PNG', 'PNG image'),
                         (b'\xff\xd8\xff', 'JPEG image')]:
        if header.startswith(magic):
            return 'binary', label
    if b'\x00' in header:
        return 'binary', 'Binary / unsupported text encoding'
    try:
        import codecs
        codecs.getincrementaldecoder('utf-8-sig')().decode(header, final=False)
    except UnicodeDecodeError:
        return 'binary', 'Binary / unsupported text encoding'
    return 'text', 'UTF-8 text candidate'


def header_facts(header, kind):
    facts = []
    if kind == 'elf':
        if len(header) < 20:
            return [('Header', 'Truncated ELF header')]
        bits = {1: '32-bit', 2: '64-bit'}.get(header[4], 'unknown class')
        byte_order = {1: '<', 2: '>'}.get(header[5])
        facts.append(('ELF class', bits))
        if byte_order:
            file_type, machine = struct.unpack_from(byte_order + 'HH', header, 16)
            facts.append(('CPU architecture', {3: 'x86', 62: 'x86-64', 40: 'ARM', 183: 'AArch64', 243: 'RISC-V'}.get(machine, str(machine))))
            facts.append(('ELF object type', {1: 'relocatable', 2: 'executable', 3: 'shared object / position-independent executable'}.get(file_type, str(file_type))))
    if kind == 'pe':
        if len(header) >= 64:
            offset = struct.unpack_from('<I', header, 60)[0]
            if offset + 24 <= len(header) and header[offset:offset + 4] == b'PE\0\0':
                machine, sections = struct.unpack_from('<HH', header, offset + 4)
                facts += [('PE header', 'Present'), ('CPU architecture', {0x14c: 'x86', 0x8664: 'x86-64', 0xaa64: 'AArch64'}.get(machine, hex(machine))), ('Sections', str(sections))]
            else:
                facts.append(('PE header', 'Not verified within the first 64 KiB'))
        else:
            facts.append(('PE header', 'Truncated DOS header'))
    return facts


def archive_inventory(stream, kind):
    result = {'status': 'BASIC INSPECTION', 'findings': [], 'facts': [], 'members': [],
              'notes': ['Archive names and metadata only. Member contents were not malware-scanned or extracted.'],
              'coverage': 'Archive inventory and selected entry-name checks; no payload analysis.'}
    count = 0
    rules_seen = set()

    def finding(rule, title, evidence, why):
        if rule not in rules_seen:
            rules_seen.add(rule)
            result['findings'].append({'rule': rule, 'title': title, 'location': 'Archive entry', 'evidence': evidence[:200], 'why': why})

    def entry(name, size, link=False, encrypted=False):
        nonlocal count
        count += 1
        if count > MAX_MEMBERS:
            raise ValueError('Inventory stopped at 10,000 entries.')
        if len(result['members']) < PREVIEW_MEMBERS:
            result['members'].append(name[:180] + '  (' + str(size) + ' bytes)')
        normalized = name.replace('\\', '/')
        if normalized.startswith('/') or '..' in PurePosixPath(normalized).parts or re.match(r'^[A-Za-z]:', normalized):
            finding('archive-path', 'Entry path needs review', name, 'An absolute path or parent-directory component can be unsafe with an unsuitable extraction tool.')
        if link:
            finding('archive-link', 'Archive contains a link', name, 'Links may be legitimate. Their targets and extraction behavior require review.')
        if encrypted:
            finding('archive-encrypted', 'Encrypted archive entry', name, 'Encrypted member contents cannot be inspected without the password.')

    try:
        stream.seek(0)
        if kind == 'zip':
            # Resource limits in the worker bound even malformed central directories.
            with zipfile.ZipFile(stream) as archive:
                for member in archive.infolist():
                    entry(member.filename, member.file_size,
                          stat.S_ISLNK(member.external_attr >> 16), bool(member.flag_bits & 1))
                    if member.file_size > 10 * 1024 * 1024 and member.file_size > 1000 * max(1, member.compress_size):
                        finding('archive-ratio', 'Very high declared compression ratio', member.filename,
                                'This can be legitimate, but decompression may consume much more space than the download size.')
        elif kind in ('tar', 'gzip'):
            with tarfile.open(fileobj=stream, mode='r|*') as archive:
                for member in archive:
                    entry(member.name, member.size, member.issym() or member.islnk())
                    if member.offset_data + member.size > MAX_TAR_BYTES:
                        raise ValueError('TAR inventory stopped at the 64 MiB expanded-stream budget.')
        elif kind == 'deb':
            if stream.read(8) != b'!<arch>\n':
                raise ValueError('Invalid ar header.')
            stream.seek(0, os.SEEK_END)
            file_size = stream.tell()
            stream.seek(8)
            debian_marker = False
            while stream.tell() < file_size:
                header = stream.read(60)
                if len(header) != 60 or header[58:60] != b'`\n':
                    raise ValueError('Incomplete or invalid ar member header.')
                size = int(header[48:58].strip())
                if size < 0 or stream.tell() + size > file_size:
                    raise ValueError('Invalid ar member size.')
                raw_name = header[:16].decode('ascii', 'replace').strip()
                if raw_name.startswith('#1/') or raw_name.startswith('/'):
                    raise ValueError('Extended ar member names are not supported in this version.')
                name = raw_name.rstrip('/')
                entry(name, size)
                if name == 'debian-binary' and size == 4:
                    debian_marker = stream.read(4) == b'2.0\n'
                else:
                    stream.seek(size, os.SEEK_CUR)
                if size % 2:
                    stream.seek(1, os.SEEK_CUR)
            if debian_marker:
                result['facts'].append(('Package marker', 'Debian binary package 2.0'))
            result['notes'].append('Nested control/data archives and installation scripts were not inspected or run.')
        else:
            raise ValueError('Inventory supports ZIP/JAR, TAR/TAR.GZ, and Debian/ar packages.')
    except (ValueError, OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, MemoryError, OverflowError) as error:
        result['status'] = 'PARTIAL INSPECTION'
        result['notes'].append(str(error)[:300] or type(error).__name__)
        result['coverage'] = 'Incomplete archive inventory; no payload malware analysis.'
    result['facts'].append(('Entries inventoried', str(min(count, MAX_MEMBERS))))
    if count > PREVIEW_MEMBERS:
        result['notes'].append('Only the first 100 entry names are displayed.')
    if result['findings']:
        if result['status'] == 'PARTIAL INSPECTION':
            result['notes'].append('Inventory was incomplete despite the findings shown.')
        result['status'] = 'NEEDS REVIEW'
    return result
