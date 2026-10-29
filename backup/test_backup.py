import struct
import unittest
from macho import commands, dylib_ids, slices
from patterns import ENCODINGS, replace_aliases, alias_hits


def thin(endian='<', name=b'FridaAgent'):
    width = (24 + len(name) + 1 + 7) & ~7
    header = struct.pack(endian + '8I', 0xfeedfacf, 0x100000c, 0, 6, 1, width, 0, 0)
    command = struct.pack(endian + '6I', 13, width, 24, 0, 0, 0)
    return header + command + name + bytes(width - 24 - len(name))


def universal(wide=False, endian='>'):
    a, b = thin(), thin('>')
    width = 32 if wide else 20
    offset = 8 + 2 * width
    header = struct.pack(endian + '2I', 0xcafebabf if wide else 0xcafebabe, 2)
    fmt = endian + ('IIQQII' if wide else 'IIIII')
    first = (0x100000c, 0, offset, len(a), 0) + ((0,) if wide else ())
    second = (0x100000c, 2, offset + len(a), len(b), 0) + ((0,) if wide else ())
    return header + struct.pack(fmt, *first) + struct.pack(fmt, *second) + a + b


class ParserTest(unittest.TestCase):
    def test_mixed_case_and_encodings(self):
        data = b'|'.join(('before FrIdA FRIDA frida after').encode(encoding) for encoding in ENCODINGS)
        patched, counts = replace_aliases(data, 'q7m2x')
        self.assertEqual(len(patched), len(data))
        self.assertEqual(alias_hits(patched), [])
        self.assertEqual(sum(counts.values()), 15)
        self.assertIn(b'q7m2x', patched)
        self.assertIn('Q7M2X'.encode('utf-16-be'), patched)

    def test_thin_both_endians(self):
        for endian in ['<', '>']:
            self.assertEqual(dylib_ids(thin(endian))[0][3], 'FridaAgent')

    def test_all_universal_formats(self):
        for wide in [True, False]:
            for endian in ['<', '>']:
                data = universal(wide, endian)
                self.assertEqual(len(slices(data)), 2)
                self.assertEqual([entry[3] for entry in dylib_ids(data)], ['FridaAgent'] * 2)

    def test_truncated(self):
        for size in range(8, len(universal())):
            with self.assertRaises(ValueError):
                list(commands(universal()[:size]))

    def test_zero_command_size(self):
        data = bytearray(thin())
        struct.pack_into('<I', data, 36, 0)
        with self.assertRaises(ValueError):
            list(commands(data))

    def test_unterminated_id(self):
        data = bytearray(thin())
        data[56:] = b'x' * (len(data) - 56)
        with self.assertRaises(ValueError):
            dylib_ids(data)

    def test_cross_command_string(self):
        data = bytearray(thin())
        struct.pack_into('<I', data, 40, 0xffffffff)
        with self.assertRaises(ValueError):
            dylib_ids(data)

    def test_slice_overlap(self):
        data = bytearray(universal())
        struct.pack_into('>I', data, 36, 48)
        with self.assertRaises(ValueError):
            slices(data)

    def test_non_macho(self):
        with self.assertRaises(ValueError):
            list(commands(b'bad file'))


if __name__ == '__main__':
    unittest.main()
