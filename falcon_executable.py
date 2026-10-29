"""Bounded static ELF/PE inspection. Selected bytes are never executed."""
import os
import re
import struct

STRING_BUDGET = 64 * 1024 * 1024
BLOCK = 65536
OVERLAP = 4096
ASCII_RUN = re.compile(rb'[\x20-\x7e]{4,}')
URL = re.compile(r'https?://[^\s<>"\x27]{1,240}', re.I)


def inspect_executable(stream, kind):
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    result = {'status': 'BASIC INSPECTION', 'findings': [], 'facts': [], 'notes': [],
              'coverage': 'Selected executable structure checks and ASCII string patterns; no behavioral analysis or malware verdict.'}
    seen = set()
    partial = False

    def add(key, title, offset, evidence, why):
        if key not in seen:
            seen.add(key)
            result['findings'].append({'rule': key, 'title': title,
                                      'location': 'Byte offset 0x{:x}'.format(offset),
                                      'evidence': evidence[:200], 'why': why})

    def read_at(offset, count):
        if offset < 0 or count < 0 or count > 65536 or offset + count > size:
            raise ValueError('A requested header/table range is truncated, out of bounds, or over budget.')
        stream.seek(offset)
        data = stream.read(count)
        if len(data) != count:
            raise ValueError('File became shorter during executable inspection.')
        return data

    try:
        if kind == 'elf':
            ident = read_at(0, 16)
            if ident[:4] != b'\x7fELF' or ident[4] not in (1, 2) or ident[5] not in (1, 2) or ident[6] != 1:
                raise ValueError('Unsupported or invalid ELF identification.')
            endian = '<' if ident[5] == 1 else '>'
            wide = ident[4] == 2
            fmt = endian + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH')
            values = struct.unpack(fmt, read_at(16, struct.calcsize(fmt)))
            file_type, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, _, _, _ = values
            if version != 1 or ehsize < (64 if wide else 52):
                raise ValueError('Invalid ELF header version or size.')
            if file_type not in (2, 3):
                raise ValueError('Program-header inspection supports ELF executables/shared objects only.')
            expected = 56 if wide else 32
            if not phnum or phnum > 4096 or phsize < expected or phsize > 1024 or phoff + phnum * phsize > size:
                raise ValueError('Missing, unsupported, oversized, or truncated ELF program-header table.')
            result['facts'] += [('Program headers', str(phnum)), ('Entry address', hex(entry))]
            stack = None
            interpreter = None
            load_count = 0
            for index in range(phnum):
                offset = phoff + index * phsize
                fields = struct.unpack(endian + ('IIQQQQQQ' if wide else 'IIIIIIII'), read_at(offset, expected))
                if wide:
                    ptype, permissions, start, va, pa, length, memory, align = fields
                else:
                    ptype, start, va, pa, length, memory, permissions, align = fields
                if ptype != 0 and length and start + length > size:
                    raise ValueError('ELF segment extends beyond the file.')
                if ptype == 1:
                    load_count += 1
                    if length > memory:
                        raise ValueError('ELF load segment has more file bytes than memory bytes.')
                    if permissions & 3 == 3:
                        add('elf-wx', 'Writable and executable load segment', offset,
                            'PT_LOAD requests write + execute permissions',
                            'This permits code and writable data in the same region. Some legitimate builds do this; it is not proof of malware.')
                if ptype == 3 and interpreter is None:
                    if not 1 <= length <= 4096:
                        raise ValueError('ELF interpreter name is missing or over the 4 KiB budget.')
                    raw = read_at(start, length)
                    if not raw.endswith(b'\0'):
                        raise ValueError('ELF interpreter name is not NUL-terminated.')
                    interpreter = raw.split(b'\0', 1)[0].decode('utf-8', 'replace')
                if ptype == 0x6474e551:
                    stack = (permissions, offset)  # Linux uses the last GNU_STACK.
            result['facts'].append(('Load segments', str(load_count)))
            if not load_count:
                raise ValueError('ELF executable has no load segments.')
            if interpreter is not None:
                result['facts'].append(('Requested interpreter', interpreter))
            result['facts'].append(('GNU stack header', 'Absent; policy not inferred' if stack is None else
                                    ('Requests executable stack' if stack[0] & 1 else 'Does not request executable stack')))
            if stack and stack[0] & 1:
                add('elf-stack', 'Executable stack requested', stack[1], 'PT_GNU_STACK has execute permission',
                    'Some legitimate programs need this, but executable stacks weaken a common protection. This is a build-property clue, not a malware diagnosis.')
        elif kind == 'pe':
            dos = read_at(0, 64)
            offset = struct.unpack_from('<I', dos, 60)[0]
            header = read_at(offset, 24)
            if dos[:2] != b'MZ' or header[:4] != b'PE\0\0':
                raise ValueError('Valid PE signature not found; this may be DOS or another MZ format.')
            machine, count, timestamp, symbols, num_symbols, optional_size, flags = struct.unpack_from('<HHIIIHH', header, 4)
            if not 1 <= count <= 96 or not 2 <= optional_size <= 4096:
                raise ValueError('Missing or unsupported PE section/optional-header sizes (maximum 96 sections).')
            optional = read_at(offset + 24, optional_size)
            magic = struct.unpack_from('<H', optional)[0]
            if magic not in (0x10b, 0x20b) or optional_size < (96 if magic == 0x10b else 112):
                raise ValueError('Unsupported or truncated PE optional header.')
            start = offset + 24 + optional_size
            if start + count * 40 > size:
                raise ValueError('PE section table extends beyond the file.')
            result['facts'] += [('PE layout', 'PE32+' if magic == 0x20b else 'PE32'), ('Sections inspected', str(count))]
            names = []
            for index in range(count):
                pos = start + index * 40
                section = read_at(pos, 40)
                name = section[:8].split(b'\0', 1)[0].decode('ascii', 'replace')
                length, pointer = struct.unpack_from('<II', section, 16)
                permissions = struct.unpack_from('<I', section, 36)[0]
                if length and pointer + length > size:
                    raise ValueError('PE section data extends beyond the file.')
                if permissions & 0xa0000000 == 0xa0000000:
                    add('pe-wx', 'Writable and executable section', pos, name or '(unnamed section)',
                        'This section requests both write and execute access. Packers and legitimate programs can also use this layout.')
                names.append(name)
            result['facts'].append(('Section names', ', '.join(names)))
        else:
            result.update(status='NOT INSPECTED', coverage='Executable inspection supports ELF and PE candidates only.')
            return result
    except (ValueError, struct.error, OSError) as error:
        partial = True
        result['notes'].append('Structure checks incomplete: ' + str(error))

    # Stream printable ASCII windows. No URLs are requested or commands run.
    from falcon_check import COMPILED_RULES
    stream.seek(0)
    processed = 0
    tail = b''
    urls = set()
    url_preview = []
    while processed < min(size, STRING_BUDGET):
        block = stream.read(min(BLOCK, min(size, STRING_BUDGET) - processed))
        if not block:
            partial = True
            result['notes'].append('String read ended early.')
            break
        data = tail + block
        origin = processed - len(tail)
        for run in ASCII_RUN.finditer(data):
            text = run.group().decode('ascii')
            for key, title, pattern, why in COMPILED_RULES:
                match = pattern.search(text) if 'string-' + key not in seen else None
                if match:
                    add('string-' + key, 'Embedded text: ' + title, origin + run.start() + match.start(), match.group(),
                        'This is text embedded in the file, not evidence that the program performs the action. ' + why)
            if len(urls) < 12:
                for match in URL.finditer(text):
                    value = match.group()
                    if value not in urls and len(urls) < 12:
                        urls.add(value)
                        url_preview.append(('URL text at 0x{:x}'.format(origin + run.start() + match.start()), value))
        processed += len(block)
        tail = data[-OVERLAP:]
    result['facts'].append(('Bytes examined for ASCII string clues', '{:,} / {:,}'.format(processed, size)))
    result['facts'] += url_preview
    if size > STRING_BUDGET:
        partial = True
        result['notes'].append('String checks stopped at the first 64 MiB; whole-file fingerprinting is separate.')
    result['notes'] += ['URL text is informational; up to 12 distinct examples are shown, not contacted or reputation-checked. Long URLs may be truncated.',
                        'Only printable ASCII string patterns are checked, with 4 KiB overlap. UTF-16, encrypted/compressed strings, and runtime-built text can be missed.',
                        'Structure checks cover selected ELF program headers or PE sections, not a complete format validation. No disassembly, execution, dependency loading, signature verification, or bundled-payload analysis.']
    if partial:
        result['coverage'] = 'Incomplete executable structure/string inspection; see notes. No malware verdict.'
    result['status'] = 'NEEDS REVIEW' if result['findings'] else ('PARTIAL INSPECTION' if partial else 'BASIC INSPECTION')
    return result
