import unittest

import pefile

from framework_fixtures import pe_bytes
from unveil.native.recovery import rebuild


class RecoveryTests(unittest.TestCase):
    def mapped(self, bits=64):
        original = pefile.PE(data=pe_bytes(bits), fast_load=True)
        mapped = bytearray(original.OPTIONAL_HEADER.SizeOfImage)
        mapped[:0x200] = original.__data__[:0x200]
        mapped[0x1000:0x1800] = original.__data__[0x200:0xa00]
        original.close()
        return mapped

    def test_rva_content_preserved_for_both_architectures(self):
        for bits, base in [(32, 0x500000), (64, 0x7ff600000000)]:
            with self.subTest(bits=bits):
                mapped = self.mapped(bits)
                payload, report = rebuild(bytes(mapped), base)
                pe = pefile.PE(data=payload)
                self.assertEqual(pe.get_data(0x1000, 0x800), mapped[0x1000:0x1800])
                self.assertEqual(pe.OPTIONAL_HEADER.ImageBase, base)
                self.assertFalse(report['importsReconstructed'])
                self.assertFalse(report['devirtualized'])
                pe.close()

    def test_original_unbacked_section_and_unicode_strings_recovered(self):
        mapped = self.mapped()
        import struct
        # Simulate a section stored only in the runtime image.
        struct.pack_into('<II', mapped, 0x188 + 16, 0, 0)
        value = 'Runtime string'
        encoded = value.encode('utf-16le')
        mapped[0x1700:0x1700 + len(encoded)] = encoded
        payload, report = rebuild(bytes(mapped), 0x140000000)
        pe = pefile.PE(data=payload, fast_load=True)
        self.assertEqual(pe.get_data(0x1700, len(encoded)), encoded)
        self.assertEqual(report['sections'][0]['originalRawSize'], 0)
        string = next(s for s in report['strings'] if s['value'] == value)
        self.assertEqual(string['rva'], 0x1700)
        self.assertEqual(string['va'], 0x140001700)
        pe.close()

    def test_truncated_capture_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SizeOfImage'):
            rebuild(bytes(self.mapped()[:-1]), 0x140000000)

    def test_out_of_image_section_rejected(self):
        import struct
        mapped = self.mapped()
        struct.pack_into('<I', mapped, 0x188 + 8, 0x3000)
        with self.assertRaisesRegex(ValueError, 'out-of-range'):
            rebuild(bytes(mapped), 0x140000000)
