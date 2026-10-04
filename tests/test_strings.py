"""String-pattern regression against authored data; never run PE fixtures."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from deobf.passes import candidates
from framework_fixtures import pe_bytes, class_bytes
from unveil.native.string_patterns import recover
from unveil.strings import recover_strings


def stack_xor(plain, barrier=False):
    code = b''.join(bytes([0xc6, 0x44, 0x24, i, byte ^ 0x5a]) for i, byte in enumerate(plain))
    if barrier:
        code += b'\xe8\x00\x00\x00\x00'
    code += b''.join(bytes([0x80, 0x74, 0x24, i, 0x5a]) for i in range(len(plain)))
    return code + b'\xc3'


class StringRecoveryTests(unittest.TestCase):
    def pe(self, code):
        data = bytearray(pe_bytes())
        data[0x200:0x200 + len(code)] = code
        return bytes(data)

    def test_inline_xor_recovers_terminated_text(self):
        records, scan = recover(self.pe(stack_xor(b'wallet-test\0')))
        self.assertEqual([r['plaintext'] for r in records], ['wallet-test'])
        self.assertEqual(records[0]['rva'], 0x1000)
        self.assertEqual(records[0]['confidence'], 'candidate')
        self.assertEqual(scan['status'], 'completed')

    def test_barriers_and_missing_termination_reject(self):
        for code in (stack_xor(b'webhook-test\0', barrier=True), stack_xor(b'no-null')):
            self.assertEqual(recover(self.pe(code))[0], [])

    def test_native_budget_reports_partial_scan(self):
        _, scan = recover(self.pe(stack_xor(b'bounded-test\0')), max_instructions=2)
        self.assertEqual(scan['status'], 'budget-exhausted')

    def test_export_separates_decrypted_and_visible_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'fixture.exe'
            original = self.pe(stack_xor(b'decoded\0'))
            source.write_bytes(original)
            destination = root / 'strings'
            report = recover_strings(source, destination)
            self.assertFalse(report['targetExecuted'])
            self.assertEqual(report['counts']['recovered'], 1)
            self.assertEqual((destination / 'decrypted-strings.txt').read_text(), '"decoded"\n')
            self.assertTrue((destination / 'visible-strings.txt').is_file())
            self.assertEqual(source.read_bytes(), original)
            with self.assertRaises(ValueError):
                recover_strings(source, destination)

    def test_standalone_class_is_analyzed_without_rewriting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'Example.class'
            source.write_bytes(class_bytes())
            report = recover_strings(source, root / 'strings')
            self.assertEqual(report['input']['type'], 'CLASS')
            self.assertFalse((root / 'strings/recovered.jar').exists())

    def test_jvm_detection_no_longer_requires_base64(self):
        def insn(op, arg=None):
            return SimpleNamespace(op=op, arg=arg)
        xor = SimpleNamespace(access=8, name='xor', desc='(Ljava/lang/String;)Ljava/lang/String;',
                              insns=[insn(182, ('java/lang/String', 'toCharArray', '()[C')), insn(130)])
        cipher = SimpleNamespace(access=8, name='cipher', desc='([B)Ljava/lang/String;',
                                 insns=[insn(182, ('javax/crypto/Cipher', 'doFinal', '([B)[B'))])
        found = candidates({'entry': SimpleNamespace(name='Fixture', methods=[xor, cipher])})
        self.assertEqual({row['kind'] for row in found.values()}, {'xor', 'cipher'})
