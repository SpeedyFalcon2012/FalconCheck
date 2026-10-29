"""Harmless hand-built ELF/PE fixtures. None are executed."""
import io
import struct
import unittest
from unittest.mock import patch

import falcon_check as scanner
import falcon_executable as executable
import falcon_gui as gui


def elf(wide=True, endian='<', wx=False, stack=False, strings=b''):
    hsize, psize = (64, 56) if wide else (52, 32)
    body = bytearray(hsize + 2 * psize)
    body[:7] = b'\x7fELF' + bytes([2 if wide else 1, 1 if endian == '<' else 2, 1])
    fmt = endian + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH')
    struct.pack_into(fmt, body, 16, 3, 62 if wide else 3, 1, 0, hsize, 0, 0, hsize, psize, 2, 0, 0, 0)
    size = len(body) + len(strings)
    if wide:
        struct.pack_into(endian + 'IIQQQQQQ', body, hsize, 1, 7 if wx else 5, 0, 0, 0, size, size, 4096)
        struct.pack_into(endian + 'IIQQQQQQ', body, hsize + psize, 0x6474e551, 7 if stack else 6, 0, 0, 0, 0, 0, 16)
    else:
        struct.pack_into(endian + 'IIIIIIII', body, hsize, 1, 0, 0, 0, size, size, 7 if wx else 5, 4096)
        struct.pack_into(endian + 'IIIIIIII', body, hsize + psize, 0x6474e551, 0, 0, 0, 0, 0, 7 if stack else 6, 16)
    return bytes(body) + strings


def pe(wx=False):
    body = bytearray(512)
    body[:2] = b'MZ'
    struct.pack_into('<I', body, 60, 64)
    body[64:68] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', body, 68, 0x8664, 1, 0, 0, 0, 112, 0)
    struct.pack_into('<H', body, 88, 0x20b)
    body[200:205] = b'.text'
    struct.pack_into('<II', body, 216, 16, 496)
    struct.pack_into('<I', body, 236, 0xe0000020 if wx else 0x60000020)
    return bytes(body)


class ExecutableTests(unittest.TestCase):
    def test_auto_selects_executable_without_clean_verdict(self):
        result = scanner.analyze_bytes(elf(), 'launcher')
        self.assertEqual(result['status'], 'BASIC INSPECTION')
        self.assertIn(('Program headers', '2'), result['facts'])
        self.assertIn('ASCII string', result['coverage'])

    def test_elf_classes_and_byte_orders(self):
        for wide in (False, True):
            for endian in ('<', '>'):
                with self.subTest(wide=wide, endian=endian):
                    result = executable.inspect_executable(io.BytesIO(elf(wide, endian, wx=True, stack=True)), 'elf')
                    self.assertEqual({f['rule'] for f in result['findings']}, {'elf-wx', 'elf-stack'})
                    self.assertEqual(result['status'], 'NEEDS REVIEW')

    def test_string_finding_offset_and_context(self):
        data = elf(strings=b'\0ordinary\0/etc/shadow\0')
        result = scanner.analyze_bytes(data, 'launcher')
        finding = result['findings'][0]
        self.assertEqual(finding['rule'], 'string-sensitive-path')
        self.assertEqual(finding['location'], 'Byte offset ' + hex(data.index(b'/etc/shadow')))
        self.assertIn('not evidence', finding['why'])
        self.assertIn('Byte offset', gui.report_text(result))

    def test_url_is_information_not_finding(self):
        result = scanner.analyze_bytes(elf(strings=b'\0https://example.invalid/update\0'), 'launcher')
        self.assertEqual(result['findings'], [])
        self.assertTrue(any(label.startswith('URL text') for label, value in result['facts']))
        self.assertEqual(result['status'], 'BASIC INSPECTION')

    def test_string_crosses_read_boundary(self):
        data = elf() + b'\0' * (executable.BLOCK - len(elf()) - 5) + b'/etc/shadow\0'
        result = scanner.analyze_bytes(data, 'launcher')
        self.assertIn('string-sensitive-path', [f['rule'] for f in result['findings']])

    def test_string_budget_is_explicit_partial(self):
        with patch.object(executable, 'STRING_BUDGET', 256):
            result = executable.inspect_executable(io.BytesIO(elf(strings=b'\0' * 300)), 'elf')
        self.assertEqual(result['status'], 'PARTIAL INSPECTION')
        self.assertEqual(dict(result['facts'])['Bytes examined for ASCII string clues'].split(' / ')[0], '256')

    def test_truncated_elf_still_has_string_findings_and_incomplete_coverage(self):
        result = scanner.analyze_bytes(b'\x7fELF\0/etc/shadow\0', 'broken')
        self.assertEqual(result['status'], 'NEEDS REVIEW')
        self.assertIn('Incomplete', result['coverage'])

    def test_malformed_structure_does_not_report_clean(self):
        for data in (b'\x7fELF', b'MZ', pe()[:250]):
            with self.subTest(data=data[:4]):
                result = scanner.analyze_bytes(data, 'broken')
                self.assertEqual(result['status'], 'PARTIAL INSPECTION')

    def test_pe_permissions_and_bounds(self):
        self.assertEqual(scanner.analyze_bytes(pe(), 'app.exe')['status'], 'BASIC INSPECTION')
        result = scanner.analyze_bytes(pe(wx=True), 'app.exe')
        self.assertEqual(result['findings'][0]['rule'], 'pe-wx')
        broken = bytearray(pe())
        struct.pack_into('<I', broken, 220, 999999)
        self.assertEqual(scanner.analyze_bytes(bytes(broken), 'bad.exe')['status'], 'PARTIAL INSPECTION')

    def test_wrong_mode_does_not_claim_executable_inspection(self):
        result = scanner.analyze_bytes(b'ordinary text', 'file.txt', 'executable')
        self.assertEqual(result['status'], 'NOT INSPECTED')

    def test_url_preview_and_findings_are_bounded(self):
        strings = b'\0'.join(('https://example.invalid/%s /etc/shadow' % number).encode() for number in range(1000))
        result = scanner.analyze_bytes(elf(strings=strings), 'launcher')
        self.assertEqual(len([f for f in result['facts'] if f[0].startswith('URL text')]), 12)
        self.assertEqual(len(result['findings']), 1)

    def test_last_gnu_stack_header_is_used(self):
        data = bytearray(elf(stack=True))
        data.extend(struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
        struct.pack_into('<H', data, 56, 3)
        result = executable.inspect_executable(io.BytesIO(data), 'elf')
        self.assertNotIn('elf-stack', [f['rule'] for f in result['findings']])


if __name__ == '__main__':
    unittest.main()
